import logging

LOG = logging.getLogger("guardrail.quarantine")


class QuarantineError(Exception):
    """Errore durante un'operazione di quarantena."""


class QuarantineManager:
    """Gestisce la quarantena di rete delle istanze Nova tramite Neutron."""

    def __init__(self, connection, database, quarantine_security_group):
        """
        Args:
            connection: connessione OpenStack di openstacksdk.
            database: istanza di GuardrailDatabase.
            quarantine_security_group: ID o nome del gruppo di sicurezza
                dedicato alla quarantena.
        """
        if connection is None:
            raise ValueError("La connessione OpenStack è obbligatoria.")

        if database is None:
            raise ValueError("Il database Guardrail è obbligatorio.")

        if not quarantine_security_group:
            raise ValueError(
                "È necessario specificare il gruppo di sicurezza "
                "di quarantena."
            )

        self.connection = connection
        self.database = database
        self.quarantine_security_group = quarantine_security_group

    def _get_quarantine_group(self):
        """Recupera il gruppo di sicurezza di quarantena."""
        try:
            group = self.connection.network.find_security_group(
                self.quarantine_security_group,
                ignore_missing=True,
            )
        except Exception as exc:
            raise QuarantineError(
                "Impossibile cercare il gruppo di sicurezza di quarantena."
            ) from exc

        if group is None:
            raise QuarantineError(
                "Il gruppo di sicurezza di quarantena non esiste: "
                f"{self.quarantine_security_group}"
            )

        return group

    def _get_instance_ports(self, instance_id):
        """Recupera le porte Neutron associate all'istanza."""
        try:
            ports = list(
                self.connection.network.ports(
                    device_id=str(instance_id)
                )
            )
        except Exception as exc:
            raise QuarantineError(
                f"Impossibile recuperare le porte della VM {instance_id}."
            ) from exc

        if not ports:
            raise QuarantineError(
                f"Nessuna porta Neutron trovata per la VM {instance_id}."
            )

        return ports

    def quarantine_instance(self, instance_id, reason, dry_run=True):
        """
        Prepara o applica la quarantena a una VM.

        Per impostazione predefinita dry_run=True: non modifica Neutron.
        La quarantena reale richiede dry_run=False.

        Prima di applicare la quarantena, salva gli ID dei gruppi di
        sicurezza originali nel risultato restituito dal metodo.
        """
        instance_id = str(instance_id)

        if not reason:
            raise ValueError("È obbligatorio specificare il motivo.")

        quarantine_group = self._get_quarantine_group()
        ports = self._get_instance_ports(instance_id)

        results = []

        for port in ports:
            port_id = port.id
            original_groups = list(
                getattr(port, "security_group_ids", None) or []
            )

            if quarantine_group.id in original_groups:
                results.append({
                    "port_id": port_id,
                    "status": "already_quarantined",
                    "original_security_groups": original_groups,
                })
                continue

            result = {
                "port_id": port_id,
                "status": "dry_run" if dry_run else "pending",
                "original_security_groups": original_groups,
                "quarantine_security_group": quarantine_group.id,
                "reason": reason,
            }

            if not dry_run:
                try:
                    self.connection.network.update_port(
                        port,
                        security_groups=[quarantine_group.id],
                    )
                    result["status"] = "quarantined"
                    LOG.warning(
                        "Porta %s della VM %s messa in quarantena. "
                        "Motivo: %s",
                        port_id,
                        instance_id,
                        reason,
                    )
                except Exception as exc:
                    result["status"] = "failed"
                    result["error"] = str(exc)
                    LOG.exception(
                        "Quarantena fallita per la porta %s",
                        port_id,
                    )

            results.append(result)

        return {
            "instance_id": instance_id,
            "reason": reason,
            "dry_run": dry_run,
            "ports": results,
        }

    def restore_instance(self, instance_id, original_security_groups,
                         dry_run=True):
        """
        Ripristina i gruppi di sicurezza originali.

        original_security_groups deve essere un dizionario con la forma:
            {"ID_PORTA": ["ID_SG_ORIGINALE_1", "ID_SG_ORIGINALE_2"]}

        Il ripristino è in modalità simulata per impostazione predefinita.
        I dati devono essere stati salvati in modo persistente prima
        di usare la quarantena reale.
        """
        instance_id = str(instance_id)

        if not isinstance(original_security_groups, dict):
            raise ValueError(
                "original_security_groups deve essere un dizionario."
            )

        results = []

        for port_id, group_ids in original_security_groups.items():
            if not isinstance(group_ids, list):
                raise ValueError(
                    f"I gruppi di sicurezza della porta {port_id} "
                    "devono essere una lista."
                )

            result = {
                "port_id": port_id,
                "original_security_groups": group_ids,
                "status": "dry_run" if dry_run else "pending",
            }

            if not dry_run:
                try:
                    port = self.connection.network.get_port(port_id)

                    if port is None or str(
                        getattr(port, "device_id", "")
                    ) != instance_id:
                        raise QuarantineError(
                            f"La porta {port_id} non appartiene più "
                            f"alla VM {instance_id}."
                        )

                    self.connection.network.update_port(
                        port,
                        security_groups=group_ids,
                    )
                    result["status"] = "restored"

                except Exception as exc:
                    result["status"] = "failed"
                    result["error"] = str(exc)
                    LOG.exception(
                        "Ripristino fallito per la porta %s",
                        port_id,
                    )

            results.append(result)

        return {
            "instance_id": instance_id,
            "dry_run": dry_run,
            "ports": results,
        }

