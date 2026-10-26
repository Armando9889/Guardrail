import json
import logging
from pathlib import Path

import openstack

from guardrail.database import GuardrailDatabase
from guardrail.rules import check_instance

LOG = logging.getLogger("guardrail.controller")


class GuardrailController:
    """Coordina le scansioni di conformità delle istanze Nova."""

    def __init__(self, config_path=None, db_path=None, connection=None):
        base_dir = Path(__file__).resolve().parent.parent

        self.config_path = Path(
            config_path or base_dir / "etc" / "config.json"
        )
        self.db_path = db_path or str(
            Path("/var/lib/guardrail/guardrail.db")
        )

        self.policy = self._load_policy()
        self.database = GuardrailDatabase(self.db_path)

        # La connessione può essere fornita direttamente nei test.
        # In esecuzione normale openstacksdk legge le credenziali
        # dalle variabili OS_* configurate con openrc.
        self.connection = connection

    def _load_policy(self):
        """Carica e valida la configurazione JSON."""
        try:
            with self.config_path.open("r", encoding="utf-8") as file:
                policy = json.load(file)
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"Impossibile leggere la policy {self.config_path}: {exc}"
            ) from exc

        if not isinstance(policy, dict):
            raise ValueError("La policy deve essere un oggetto JSON.")

        allowed_images = policy.get("allowed_image_ids")
        if not isinstance(allowed_images, list):
            raise ValueError("allowed_image_ids deve essere una lista.")

        for key in (
            "max_ram_mb",
            "max_vcpus",
            "max_project_ram_mb",
            "max_project_vcpus",
            "max_name_length",
            "error_scan_threshold",
        ):
            value = policy.get(key)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 1
            ):
                raise ValueError(
                    f"La policy deve contenere un intero positivo per {key}."
                )

        return policy

    def _get_connection(self):
        """Restituisce la connessione OpenStack."""
        if self.connection is None:
            self.connection = openstack.connect()
        return self.connection

    @staticmethod
    def _resource_id(resource):
        """Estrae un ID da una risorsa OpenStack o da un dizionario."""
        if resource is None:
            return None
        if isinstance(resource, dict):
            return resource.get("id")
        return getattr(resource, "id", None)

    @staticmethod
    def _metadata(server):
        """Normalizza i metadati dell'istanza."""
        metadata = getattr(server, "metadata", None)
        return dict(metadata or {})

    def _instance_data(self, server, project_totals, error_counts):
        """Converte un server Nova nel formato atteso dalle regole."""
        conn = self._get_connection()

        flavor_ref = getattr(server, "flavor", None) or {}
        flavor_id = self._resource_id(flavor_ref)

        if flavor_id is None and isinstance(flavor_ref, dict):
            flavor_id = (
                flavor_ref.get("original_name")
                or flavor_ref.get("name")
            )

        flavor = None
        if flavor_id:
            try:
                flavor = conn.compute.get_flavor(flavor_id)
            except Exception:
                LOG.exception(
                    "Impossibile recuperare il flavor della VM %s",
                    getattr(server, "id", "sconosciuta"),
                )

        ram_mb = getattr(flavor, "ram", None) if flavor else None
        vcpus = getattr(flavor, "vcpus", None) if flavor else None

        # Alcune risposte Nova contengono i dettagli del flavor
        # direttamente nella struttura flavor.
        if isinstance(flavor_ref, dict):
            ram_mb = ram_mb if ram_mb is not None else flavor_ref.get("ram")
            vcpus = vcpus if vcpus is not None else flavor_ref.get("vcpus")

        project_id = (
            getattr(server, "project_id", None)
            or getattr(server, "tenant_id", None)
            or ""
        )
        totals = project_totals.get(
            str(project_id), {"ram_mb": 0, "vcpus": 0}
        )

        image_ref = getattr(server, "image", None)
        image_id = self._resource_id(image_ref)

        status = str(getattr(server, "status", "") or "").upper()
        consecutive_errors = error_counts.get(str(server.id), 0)

        return {
            "id": str(getattr(server, "id", "")),
            "name": str(getattr(server, "name", "") or ""),
            "metadata": self._metadata(server),
            "ram_mb": ram_mb,
            "vcpus": vcpus,
            "image_id": image_id,
            "project_id": str(project_id),
            "status": status,
            "project_ram_mb": totals["ram_mb"],
            "project_vcpus": totals["vcpus"],
            "consecutive_error_scans": consecutive_errors,
        }

    def _get_servers(self, conn):
        """Recupera le istanze accessibili all'utente OpenStack."""
        try:
            return list(conn.compute.servers(details=True, all_projects=True))
        except Exception:
            LOG.warning(
                "Recupero all-projects non riuscito; "
                "verranno controllate le istanze accessibili."
            )
            return list(conn.compute.servers(details=True))

    def _project_totals(self, servers):
        """Calcola RAM e vCPU aggregate per progetto."""
        conn = self._get_connection()
        totals = {}

        for server in servers:
            project_id = (
                getattr(server, "project_id", None)
                or getattr(server, "tenant_id", None)
                or ""
            )
            project_id = str(project_id)

            flavor_ref = getattr(server, "flavor", None) or {}
            flavor_id = self._resource_id(flavor_ref)

            if flavor_id is None and isinstance(flavor_ref, dict):
                flavor_id = (
                    flavor_ref.get("original_name")
                    or flavor_ref.get("name")
                )

            ram_mb = None
            vcpus = None

            if flavor_id:
                try:
                    flavor = conn.compute.get_flavor(flavor_id)
                    ram_mb = getattr(flavor, "ram", None)
                    vcpus = getattr(flavor, "vcpus", None)
                except Exception:
                    LOG.warning(
                        "Flavor non disponibile per la VM %s",
                        getattr(server, "id", "sconosciuta"),
                    )

            if isinstance(flavor_ref, dict):
                ram_mb = (
                    ram_mb if ram_mb is not None else flavor_ref.get("ram")
                )
                vcpus = (
                    vcpus if vcpus is not None else flavor_ref.get("vcpus")
                )

            if not isinstance(ram_mb, int) or not isinstance(vcpus, int):
                continue

            totals.setdefault(
                project_id, {"ram_mb": 0, "vcpus": 0}
            )
            totals[project_id]["ram_mb"] += ram_mb
            totals[project_id]["vcpus"] += vcpus

        return totals

    def _error_counts(self, servers):
        """Conta le scansioni consecutive in stato ERROR in memoria."""
        if not hasattr(self, "_previous_error_counts"):
            self._previous_error_counts = {}

        current = {}
        for server in servers:
            instance_id = str(getattr(server, "id", ""))
            status = str(getattr(server, "status", "") or "").upper()

            if status == "ERROR":
                current[instance_id] = (
                    self._previous_error_counts.get(instance_id, 0) + 1
                )
            else:
                current[instance_id] = 0

        self._previous_error_counts = current
        return current

    def scan(self):
        """Esegue una scansione e registra il risultato nel database."""
        scan_id = self.database.start_scan()

        try:
            conn = self._get_connection()
            servers = self._get_servers(conn)
            project_totals = self._project_totals(servers)
            error_counts = self._error_counts(servers)

            violations = []
            for server in servers:
                instance = self._instance_data(
                    server, project_totals, error_counts
                )
                violations.extend(check_instance(instance, self.policy))

            active_keys = []
            for violation in violations:
                self.database.record_violation(violation)
                active_keys.append(
                    (violation["rule"], violation["instance_id"])
                )

            resolved = self.database.resolve_absent_violations(active_keys)

            self.database.finish_scan(
                scan_id=scan_id,
                instances_checked=len(servers),
                violations_found=len(violations),
                status="completed",
                details={"resolved_violations": resolved},
            )

            return {
                "scan_id": scan_id,
                "status": "completed",
                "instances_checked": len(servers),
                "violations_found": len(violations),
                "resolved_violations": resolved,
                "violations": violations,
            }

        except Exception as exc:
            LOG.exception("Scansione Guardrail fallita")
            self.database.finish_scan(
                scan_id=scan_id,
                instances_checked=0,
                violations_found=0,
                status="failed",
                details={"error": str(exc)},
            )
            raise
