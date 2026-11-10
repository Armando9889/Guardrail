import json
import logging
import os
import re
import stat
import tempfile
from pathlib import Path

import openstack

from guardrail.database import GuardrailDatabase
from guardrail.rules import check_instance
from guardrail.quarantine import QuarantineManager

LOG = logging.getLogger("guardrail.controller")


class GuardrailController:
    """Coordina scansioni, controlli e quarantena delle istanze Nova."""

    def __init__(
        self,
        config_path=None,
        db_path=None,
        connection=None,
        quarantine_manager=None,
    ):
        base_dir = Path(__file__).resolve().parent.parent

        self.config_path = Path(
            config_path
            or os.environ.get(
                "GUARDRAIL_CONFIG",
                base_dir / "etc" / "config.json",
            )
        )

        self.db_path = (
            db_path
            or os.environ.get(
                "GUARDRAIL_DB_FILE",
                "/var/lib/guardrail/guardrail.db",
            )
        )

        self.policy = self._load_policy()
        self.database = GuardrailDatabase(self.db_path)

        self.connection = connection
        self.quarantine_manager = quarantine_manager

    @staticmethod
    def _validate_policy(policy):
        """Valida tutti i parametri della policy Guardrail."""

        if not isinstance(policy, dict):
            raise ValueError("La policy deve essere un oggetto JSON.")

        required = {
            "scan_interval_seconds",
            "max_ram_mb",
            "max_vcpus",
            "allowed_image_ids",
            "name_pattern",
            "max_name_length",
            "error_scan_threshold",
            "max_project_ram_mb",
            "max_project_vcpus",
            "auto_quarantine_rules",
            "quarantine_security_group",
            "quarantine_dry_run",
        }

        missing = required - set(policy)
        allowed = required | {"project_limits"}
        unknown = set(policy) - allowed

        if missing:
            raise ValueError(
                "Parametri mancanti: " + ", ".join(sorted(missing))
            )

        if unknown:
            raise ValueError(
                "Parametri non riconosciuti: " + ", ".join(sorted(unknown))
            )

        numeric_settings = (
            "scan_interval_seconds",
            "max_ram_mb",
            "max_vcpus",
            "max_project_ram_mb",
            "max_project_vcpus",
            "max_name_length",
            "error_scan_threshold",
        )

        for key in numeric_settings:
            value = policy[key]

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
            ):
                raise ValueError(
                    f"{key} deve essere un intero positivo."
                )

        project_limits = policy.get("project_limits", {})

        if not isinstance(project_limits, dict):
            raise ValueError("project_limits deve essere un oggetto JSON.")

        for project_id, limits in project_limits.items():
            if not isinstance(project_id, str) or not project_id.strip():
                raise ValueError("Gli ID progetto devono essere stringhe non vuote.")

            if not isinstance(limits, dict) or not limits:
                raise ValueError(
                    f"I limiti del progetto {project_id} devono essere un oggetto non vuoto."
                )

            unknown_limits = set(limits) - {"max_ram_mb", "max_vcpus"}
            if unknown_limits:
                raise ValueError(
                    f"Limiti non riconosciuti per {project_id}: "
                    f"{sorted(unknown_limits)}"
                )

            for key, value in limits.items():
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 1
                ):
                    raise ValueError(
                        f"{key} del progetto {project_id} "
                        "deve essere un intero positivo."
                    )

        allowed_images = policy["allowed_image_ids"]

        if not isinstance(allowed_images, list):
            raise ValueError("allowed_image_ids deve essere una lista.")

        if any(
            not isinstance(image_id, str) or not image_id.strip()
            for image_id in allowed_images
        ):
            raise ValueError(
                "Gli ID delle immagini devono essere stringhe non vuote."
            )

        pattern = policy["name_pattern"]

        if not isinstance(pattern, str) or not pattern:
            raise ValueError("name_pattern deve essere una stringa non vuota.")

        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"name_pattern non valida: {exc}") from exc

        auto_rules = policy["auto_quarantine_rules"]
        valid_rules = {
            "R1", "R2", "R3", "R4",
            "R5", "R6", "R7", "R8",
        }

        if not isinstance(auto_rules, list):
            raise ValueError("auto_quarantine_rules deve essere una lista.")

        if any(
            not isinstance(rule, str) or rule not in valid_rules
            for rule in auto_rules
        ):
            raise ValueError(
                "auto_quarantine_rules contiene una regola non valida."
            )

        security_group = policy["quarantine_security_group"]

        if (
            not isinstance(security_group, str)
            or not security_group.strip()
        ):
            raise ValueError(
                "quarantine_security_group deve essere una stringa non vuota."
            )

        # La modalità dry-run non può essere disattivata dalla policy API.
        if policy["quarantine_dry_run"] is not True:
            raise ValueError(
                "quarantine_dry_run deve rimanere true."
            )

        return dict(policy)

    def _load_policy(self):
        """Carica e valida la configurazione JSON."""

        try:
            with self.config_path.open("r", encoding="utf-8") as file:
                policy = json.load(file)

        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Impossibile leggere la policy {self.config_path}: {exc}"
            ) from exc

        return self._validate_policy(policy)

    def reload_policy(self):
        """Ricarica la policy dal file di configurazione."""
        self.policy = self._load_policy()
        return dict(self.policy)

    def save_policy(self, policy):
        """Valida e salva la policy tramite sostituzione atomica."""

        validated = self._validate_policy(policy)

        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        current_mode = (
            stat.S_IMODE(self.config_path.stat().st_mode)
            if self.config_path.exists()
            else 0o640
        )

        fd, temporary_path = tempfile.mkstemp(
            prefix=".guardrail-policy-",
            suffix=".json",
            dir=str(self.config_path.parent),
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(
                    validated,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )
                file.write("\n")
                file.flush()
                os.fsync(file.fileno())

            os.chmod(temporary_path, current_mode)
            os.replace(temporary_path, self.config_path)

        except Exception:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
            raise

        self.policy = validated
        return dict(self.policy)

    @staticmethod
    def _server_to_dict(server):
        """Converte un'istanza Nova in un dizionario."""

        if hasattr(server, "to_dict"):
            return server.to_dict()

        if isinstance(server, dict):
            return server.copy()

        if hasattr(server, "__dict__"):
            return vars(server).copy()

        raise TypeError(
            f"Formato istanza Nova non supportato: "
            f"{type(server).__name__}"
        )

    @staticmethod
    def _normalize_server(server):
        """Normalizza i dati Nova per il motore delle regole."""

        data = GuardrailController._server_to_dict(server)

        flavor = data.get("flavor") or {}
        image = data.get("image") or {}

        if isinstance(flavor, dict):
            data["ram_mb"] = flavor.get("ram", data.get("ram_mb"))
            data["vcpus"] = flavor.get("vcpus", data.get("vcpus"))

        if isinstance(image, dict):
            data["image_id"] = image.get("id", data.get("image_id"))

        if not data.get("project_id"):
            data["project_id"] = data.get("tenant_id")

        return data

    def _get_connection(self):
        """Restituisce la connessione OpenStack."""

        if self.connection is None:
            self.connection = openstack.connect(cloud="devstack-admin")

        return self.connection

    def _get_quarantine_manager(self):
        """Crea il gestore della quarantena quando necessario."""

        if self.quarantine_manager is None:
            self.quarantine_manager = QuarantineManager(
                connection=self._get_connection(),
                database=self.database,
                quarantine_security_group=self.policy[
                    "quarantine_security_group"
                ],
            )

        return self.quarantine_manager

    def _get_servers(self):
        """Recupera le istanze Nova visibili all'amministratore."""

        connection = self._get_connection()

        try:
            return list(
                connection.compute.servers(
                    all_projects=True,
                    details=True,
                )
            )

        except Exception:
            LOG.warning(
                "Impossibile recuperare tutte le istanze. "
                "Verranno recuperate quelle accessibili.",
                exc_info=True,
            )

            return list(
                connection.compute.servers(details=True)
            )

    def _project_totals(self, servers):
        """Calcola RAM e vCPU aggregate per progetto."""

        totals = {}

        def valid_resource(value):
            if (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            ):
                return value

            return 0

        for server in servers:
            server_data = self._normalize_server(server)

            project_id = server_data.get("project_id")

            if not project_id:
                continue

            ram = valid_resource(server_data.get("ram_mb"))
            vcpus = valid_resource(server_data.get("vcpus"))

            if project_id not in totals:
                totals[project_id] = {
                    "ram_mb": 0,
                    "vcpus": 0,
                }

            totals[project_id]["ram_mb"] += ram
            totals[project_id]["vcpus"] += vcpus

        return totals

    def _error_counts(self, servers):
        """Aggiorna e restituisce i contatori persistenti degli errori."""

        instance_statuses = {}

        for server in servers:
            server_data = self._normalize_server(server)

            instance_id = server_data.get("id")
            status = server_data.get("status")

            if instance_id:
                instance_statuses[instance_id] = status

        self.database.update_instance_error_counts(instance_statuses)

        return self.database.get_instance_error_counts()

    def _get_instance_violations(self, servers, error_counts):
        """Applica le regole a ogni istanza normalizzata."""

        violations = []

        for server in servers:
            server_data = self._normalize_server(server)

            instance_id = str(server_data.get("id", ""))

            server_data["consecutive_error_scans"] = error_counts.get(
                instance_id,
                0,
            )

            instance_violations = check_instance(
                server_data,
                self.policy,
            )

            violations.extend(instance_violations)

        return violations

    def _apply_quarantine(self, violations):
        """Applica la quarantena solo alle regole autorizzate."""

        auto_rules = set(
            self.policy.get("auto_quarantine_rules", [])
        )

        instances_to_quarantine = {}

        for violation in violations:
            rule = violation.get("rule")

            # R8 riguarda il progetto, non una singola VM.
            if rule == "R8":
                continue

            if rule not in auto_rules:
                continue

            instance_id = violation.get("instance_id")

            if not instance_id:
                continue

            if instance_id not in instances_to_quarantine:
                instances_to_quarantine[instance_id] = []

            instances_to_quarantine[instance_id].append(rule)

        quarantine_results = []

        if not instances_to_quarantine:
            return quarantine_results

        quarantine_manager = self._get_quarantine_manager()

        dry_run = self.policy.get("quarantine_dry_run", True)

        for instance_id, rules in instances_to_quarantine.items():
            reason = (
                "Violazioni automatiche: "
                + ", ".join(sorted(set(rules)))
            )

            try:
                result = quarantine_manager.quarantine_instance(
                    instance_id=instance_id,
                    reason=reason,
                    dry_run=dry_run,
                )

                if not isinstance(result, dict):
                    result = {
                        "instance_id": instance_id,
                        "result": "completed",
                    }

                quarantine_results.append(result)

            except Exception as exc:
                LOG.exception(
                    "Errore durante la quarantena dell'istanza %s.",
                    instance_id,
                )

                quarantine_results.append({
                    "instance_id": instance_id,
                    "result": "failed",
                    "error": str(exc),
                })

        return quarantine_results

    def restore_instance(self, instance_id, *, dry_run=True):
        """Ripristina i security group originali di un'istanza."""

        if not isinstance(instance_id, str) or not instance_id.strip():
            raise ValueError("instance_id non valido.")

        if not isinstance(dry_run, bool):
            raise ValueError("dry_run deve essere un valore booleano.")

        return self._get_quarantine_manager().restore_instance(
            instance_id=instance_id,
            dry_run=dry_run,
        )

    def scan(self, source="manual"):
        """Esegue una scansione completa delle istanze OpenStack."""

        # Rileva anche le modifiche effettuate dall'API o da altri processi.
        self.reload_policy()

        scan_id = self.database.start_scan(source=source)

        try:
            servers = self._get_servers()

            project_totals = self._project_totals(servers)

            error_counts = self._error_counts(servers)

            violations = self._get_instance_violations(
                servers,
                error_counts,
            )

            # Controlli aggregati per progetto.
            for project_id, totals in project_totals.items():

                if (
                    totals["ram_mb"]
                    > self.policy["max_project_ram_mb"]
                ):
                    violations.append({
                        "rule": "R8",
                        "message": (
                            f"Il progetto {project_id} supera "
                            f"il limite aggregato di RAM: "
                            f"{totals['ram_mb']} MB."
                        ),
                        "severity": "WARNING",
                        "instance_id": f"project:{project_id}:ram",
                        "instance_name": f"[PROJECT] {project_id} (RAM)",
                        "scan_id": scan_id,
                    })

                if (
                    totals["vcpus"]
                    > self.policy["max_project_vcpus"]
                ):
                    violations.append({
                        "rule": "R8",
                        "message": (
                            f"Il progetto {project_id} supera "
                            f"il limite aggregato di vCPU: "
                            f"{totals['vcpus']}."
                        ),
                        "severity": "WARNING",
                        "instance_id": f"project:{project_id}:vcpus",
                        "instance_name": f"[PROJECT] {project_id} (vCPU)",
                        "scan_id": scan_id,
                    })

            # Registrazione delle violazioni.
            for violation in violations:
                violation["scan_id"] = scan_id

                if violation.get("instance_id") is not None:
                    violation_id = self.database.record_violation(
                        violation
                    )

                    violation["violation_id"] = violation_id

            # Risoluzione delle violazioni non più presenti.
            active_keys = [
                (
                    violation["rule"],
                    violation["instance_id"],
                )
                for violation in violations
                if violation.get("instance_id") is not None
            ]

            self.database.resolve_absent_violations(active_keys)

            # Applicazione della quarantena.
            quarantine_results = self._apply_quarantine(violations)

            # Registrazione della scansione completata.
            self.database.finish_scan(
                scan_id=scan_id,
                status="completed",
                instances_checked=len(servers),
                violations_found=len(violations),
            )

            return {
                "scan_id": scan_id,
                "status": "completed",
                "instances_checked": len(servers),
                "violations_found": len(violations),
                "violations": violations,
                "quarantine_results": quarantine_results,
            }

        except Exception:
            LOG.exception(
                "Errore durante la scansione Guardrail."
            )

            self.database.finish_scan(
                scan_id=scan_id,
                status="failed",
                instances_checked=0,
                violations_found=0,
            )

            raise
