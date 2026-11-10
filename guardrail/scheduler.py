import logging
import signal
import threading
import time

from guardrail.controller import GuardrailController

LOG = logging.getLogger("guardrail.scheduler")


class GuardrailScheduler:
    """Gestisce le scansioni periodiche di Guardrail."""

    def __init__(self, controller=None):
        self.controller = controller or GuardrailController()
        self.interval = self.controller.policy.get(
            "scan_interval_seconds", 300
        )

        if (
            not isinstance(self.interval, int)
            or isinstance(self.interval, bool)
            or self.interval < 1
        ):
            raise ValueError(
                "scan_interval_seconds deve essere un intero positivo."
            )

        self.stop_event = threading.Event()

    def run_once(self):
        """Esegue una singola scansione."""
        LOG.info("Avvio scansione automatica.")

        try:
            result = self.controller.scan(source="automatic")

            LOG.info(
                "Scansione completata: ID=%s, istanze=%s, violazioni=%s",
                result.get("scan_id"),
                result.get("instances_checked"),
                result.get("violations_found"),
            )

            return result

        except Exception:
            LOG.exception("Errore durante la scansione automatica.")
            return None

    def run_forever(self):
        """Esegue scansioni periodiche fino alla richiesta di arresto."""
        LOG.info(
            "Scheduler avviato. Intervallo: %s secondi.",
            self.interval,
        )

        while not self.stop_event.is_set():
            self.run_once()

            self.stop_event.wait(self.interval)

        LOG.info("Scheduler arrestato.")

    def stop(self):
        """Richiede l'arresto dello scheduler."""
        LOG.info("Richiesta di arresto dello scheduler.")
        self.stop_event.set()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    scheduler = GuardrailScheduler()

    def handle_signal(signum, frame):
        LOG.info("Ricevuto segnale %s.", signum)
        scheduler.stop()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    scheduler.run_forever()


if __name__ == "__main__":
    main()
