import logging

LOG = logging.getLogger("guardrail.quarantine")


class QuarantineError(Exception):
    """Errore durante un'operazione di quarantena."""


class QuarantineManager:
    """Gestisce la quarantena di rete delle istanze Nova tramite Neutron."""

    def __init__(self, connection, database, quarantine_security_group):
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
        """Recupera il gruppo di sicurezza dedicato alla quarantena."""
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
        """Recupera le porte Neutron associate alla VM."""
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

    @staticmethod
    def _event_result(results):
        """Calcola l'esito complessivo di un'operazione."""
        statuses = [item["status"] for item in results]

        if statuses and all(
            status in ("quarantined", "already_quarantined")
            for status in statuses
        ):
            return "quarantined"

        if any(
            status in ("quarantined", "already_quarantined")
            for status in statuses
        ):
            return "partial"

        if any(status == "dry_run" for status in statuses):
            return "dry_run"

        return "failed"

    def quarantine_instance(self, instance_id, reason, dry_run=True):
        """
        Prepara o applica la quarantena a una VM.

        I gruppi di sicurezza originali vengono salvati nel database
        prima di qualsiasi modifica a Neutron.
        """
        instance_id = str(instance_id)

        if not reason:
            raise ValueError("È obbligatorio specificare il motivo.")

        quarantine_group = self._get_quarantine_group()
        ports = self._get_instance_ports(instance_id)

        results = []

        for port in ports:
            port_id = str(port.id)

            original_groups = list(
                getattr(port, "security_group_ids", None) or []
            )

            result = {
                "port_id": port_id,
                "status": "already_quarantined"
                if quarantine_group.id in original_groups
                else "dry_run" if dry_run else "pending",
                "original_security_groups": original_groups,
                "quarantine_security_group": quarantine_group.id,
                "reason": reason,
            }

            results.append(result)

        # Persistenza preventiva: nessuna modifica a Neutron
        # viene effettuata se il salvataggio iniziale fallisce.
        details = {
            "reason": reason,
            "dry_run": dry_run,
            "ports": results,
        }

        try:
            event_id = self.database.record_quarantine_event(
                instance_id=instance_id,
                action="quarantine",
                result="pending",
                details=details,
            )
        except Exception as exc:
            raise QuarantineError(
                "Impossibile salvare l'evento di quarantena. "
                "Nessuna modifica è stata applicata."
            ) from exc

        # Applicazione della quarantena.
        if not dry_run:
            for result, port in zip(results, ports):
                if result["status"] == "already_quarantined":
                    continue

                try:
                    self.connection.network.update_port(
                        port,
                        security_groups=[quarantine_group.id],
                    )

                    result["status"] = "quarantined"

                    LOG.warning(
                        "Porta %s della VM %s messa in quarantena. "
                        "Motivo: %s",
                        result["port_id"],
                        instance_id,
                        reason,
                    )

                except Exception as exc:
                    result["status"] = "failed"
                    result["error"] = str(exc)

                    LOG.exception(
                        "Quarantena fallita per la porta %s",
                        result["port_id"],
                    )

        final_result = self._event_result(results)
        details["ports"] = results

        try:
            self.database.update_quarantine_event(
                event_id=event_id,
                result=final_result,
                details=details,
            )
        except Exception:
            LOG.exception(
                "Impossibile aggiornare l'evento di quarantena %s",
                event_id,
            )

        return {
            "event_id": event_id,
            "instance_id": instance_id,
            "reason": reason,
            "dry_run": dry_run,
            "result": final_result,
            "ports": results,
        }

    def _load_original_security_groups(self, instance_id):
        """Ricostruisce i gruppi originali dalle cronologie degli eventi."""
        events = self.database.get_instance_quarantine_events(
            instance_id
        )

        # Compatibilità con adapter/mock precedenti che non espongono
        # ancora la cronologia completa.
        if events is None:
            event = self.database.get_latest_quarantine_event(instance_id)

            if event is None:
                raise QuarantineError(
                    f"Nessun evento di quarantena trovato per la VM "
                    f"{instance_id}."
                )

            if event.get("result") not in ("quarantined", "partial"):
                raise QuarantineError(
                    "L'ultimo evento di quarantena non contiene "
                    "una quarantena applicata."
                )

            details = event.get("details")
            if not isinstance(details, dict):
                raise QuarantineError(
                    "I dettagli dell'evento di quarantena non sono validi."
                )

            original_groups = {
                str(port["port_id"]): port["original_security_groups"]
                for port in details.get("ports", [])
                if (
                    port.get("status") == "quarantined"
                    and port.get("port_id") is not None
                    and isinstance(
                        port.get("original_security_groups"), list
                    )
                )
            }

            restore_events = self.database.get_restore_events_after(
                instance_id,
                event["id"],
            )
            for restore_event in restore_events:
                if restore_event.get("result") not in (
                    "restored", "partial"
                ):
                    continue
                restore_details = restore_event.get("details")
                if not isinstance(restore_details, dict):
                    continue
                for port in restore_details.get("ports", []):
                    if port.get("status") == "restored":
                        port_id = port.get("port_id")
                        if port_id is not None:
                            original_groups.pop(str(port_id), None)

        else:
            if not isinstance(events, list):
                raise QuarantineError(
                    "La cronologia degli eventi di quarantena non è valida."
                )

            original_groups = {}

            for event in events:
                action = event.get("action")
                result = event.get("result")
                details = event.get("details")

                if not isinstance(details, dict):
                    continue

                ports = details.get("ports", [])
                if not isinstance(ports, list):
                    continue

                if action == "quarantine" and result in (
                    "quarantined", "partial"
                ):
                    for port in ports:
                        if not isinstance(port, dict):
                            continue

                        if port.get("status") != "quarantined":
                            continue

                        port_id = port.get("port_id")
                        groups = port.get("original_security_groups")

                        if (
                            port_id is None
                            or not isinstance(groups, list)
                            or str(port_id) in original_groups
                        ):
                            continue

                        original_groups[str(port_id)] = groups

                elif action == "quarantine" and result == "pending":
                    quarantine_group_id = None

                    for port in ports:
                        if (
                            not isinstance(port, dict)
                            or port.get("status") != "pending"
                        ):
                            continue

                        port_id = port.get("port_id")
                        groups = port.get("original_security_groups")

                        if (
                            port_id is None
                            or not isinstance(groups, list)
                        ):
                            continue

                        if quarantine_group_id is None:
                            quarantine_group_id = (
                                self._get_quarantine_group().id
                            )

                        try:
                            current_port = (
                                self.connection.network.get_port(
                                    str(port_id)
                                )
                            )
                        except Exception as exc:
                            raise QuarantineError(
                                "Impossibile verificare lo stato della "
                                f"porta {port_id} su Neutron."
                            ) from exc

                        if current_port is None:
                            continue

                        current_groups = (
                            getattr(
                                current_port,
                                "security_group_ids",
                                None,
                            )
                            or []
                        )

                        if quarantine_group_id in current_groups:
                            original_groups[str(port_id)] = groups

                elif action == "restore" and result in (
                    "restored", "partial"
                ):
                    for port in ports:
                        if (
                            isinstance(port, dict)
                            and port.get("status") == "restored"
                            and port.get("port_id") is not None
                        ):
                            original_groups.pop(
                                str(port["port_id"]), None
                            )

        if not original_groups:
            raise QuarantineError(
                "Non sono disponibili gruppi di sicurezza originali "
                "da ripristinare."
            )

        return original_groups

    def restore_instance(self, instance_id, *, dry_run=True):
        """Ripristina i gruppi originali recuperandoli dal database."""

        if not isinstance(dry_run, bool):
            raise ValueError("dry_run deve essere un valore booleano.")

        instance_id = str(instance_id)
        original_security_groups = (
            self._load_original_security_groups(instance_id)
        )

        results = []

        for port_id, group_ids in original_security_groups.items():
            if not isinstance(group_ids, list):
                raise ValueError(
                    f"I gruppi di sicurezza della porta {port_id} "
                    "devono essere una lista."
                )

            result = {
                "port_id": str(port_id),
                "original_security_groups": group_ids,
                "status": "dry_run" if dry_run else "pending",
            }

            if not dry_run:
                try:
                    port = self.connection.network.get_port(port_id)

                    if (
                        port is None
                        or str(getattr(port, "device_id", ""))
                        != instance_id
                    ):
                        raise QuarantineError(
                            f"La porta {port_id} non appartiene più "
                            f"alla VM {instance_id}."
                        )

                    self.connection.network.update_port(
                        port,
                        security_groups=group_ids,
                    )

                    result["status"] = "restored"

                    LOG.info(
                        "Porta %s della VM %s ripristinata.",
                        port_id,
                        instance_id,
                    )

                except Exception as exc:
                    result["status"] = "failed"
                    result["error"] = str(exc)

                    LOG.exception(
                        "Ripristino fallito per la porta %s",
                        port_id,
                    )

            results.append(result)

        final_result = (
            "restored"
            if results and all(
                item["status"] == "restored"
                for item in results
            )
            else "dry_run"
            if dry_run
            else "partial"
            if any(item["status"] == "restored" for item in results)
            else "failed"
        )

        details = {
            "ports": results,
        }

        event_recorded = True

        try:
            event_id = self.database.record_quarantine_event(
                instance_id=instance_id,
                action="restore",
                result=final_result,
                details=details,
            )
        except Exception:
            LOG.exception(
                "Impossibile registrare l'evento di ripristino."
            )
            event_id = None
            event_recorded = False

        return {
            "event_id": event_id,
            "event_recorded": event_recorded,
            "instance_id": instance_id,
            "dry_run": dry_run,
            "result": final_result,
            "ports": results,
        }
