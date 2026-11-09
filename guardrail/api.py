import logging
import os

from flask import Flask, jsonify, request

from guardrail.controller import GuardrailController

LOG = logging.getLogger("guardrail.api")


def create_app(controller=None):
    """Crea l'applicazione REST di Guardrail."""

    app = Flask(__name__)

    guardrail = controller or GuardrailController()

    app.config["GUARDRAIL_CONTROLLER"] = guardrail

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "service": "Guardrail",
            "status": "healthy",
        }), 200

    @app.route("/scan", methods=["POST"])
    def scan():
        try:
            result = guardrail.scan()
            return jsonify(result), 200

        except Exception:
            LOG.exception("Errore durante la scansione REST")

            return jsonify({
                "status": "failed",
                "error": "Impossibile completare la scansione.",
            }), 500

    @app.route("/restore/<instance_id>", methods=["POST"])
    def restore(instance_id):
        try:
            payload = request.get_json(silent=True)

            if payload is None:
                payload = {}

            if not isinstance(payload, dict):
                return jsonify({
                    "error": "Il corpo della richiesta deve essere un oggetto JSON."
                }), 400

            dry_run = payload.get("dry_run", True)

            if not isinstance(dry_run, bool):
                return jsonify({
                    "error": "dry_run deve essere un valore booleano."
                }), 400

            result = guardrail.restore_instance(
                instance_id=instance_id,
                dry_run=dry_run,
            )

            return jsonify(result), 200

        except Exception:
            LOG.exception(
                "Errore durante il ripristino dell'istanza %s",
                instance_id,
            )

            return jsonify({
                "status": "failed",
                "error": "Impossibile ripristinare l'istanza.",
            }), 500

    @app.route("/scans", methods=["GET"])
    def scans():
        try:
            limit = request.args.get("limit", default=50, type=int)

            if limit < 1 or limit > 500:
                return jsonify({
                    "error": "Il parametro limit deve essere tra 1 e 500."
                }), 400

            result = guardrail.database.list_scans(limit=limit)

            return jsonify({
                "scans": result,
                "count": len(result),
            }), 200

        except Exception:
            LOG.exception("Errore durante il recupero delle scansioni")

            return jsonify({
                "error": "Impossibile recuperare le scansioni."
            }), 500

    @app.route("/violations", methods=["GET"])
    def violations():
        try:
            status = request.args.get("status")

            if status and status not in ("open", "resolved"):
                return jsonify({
                    "error": "status deve essere open oppure resolved."
                }), 400

            result = guardrail.database.list_violations(status=status)

            return jsonify({
                "violations": result,
                "count": len(result),
            }), 200

        except Exception:
            LOG.exception("Errore durante il recupero delle violazioni")

            return jsonify({
                "error": "Impossibile recuperare le violazioni."
            }), 500

    @app.route("/quarantine-events", methods=["GET"])
    def quarantine_events():
        try:
            limit = request.args.get("limit", default=50, type=int)

            if limit < 1 or limit > 500:
                return jsonify({
                    "error": "Il parametro limit deve essere tra 1 e 500."
                }), 400

            result = guardrail.database.list_quarantine_events(
                limit=limit
            )

            return jsonify({
                "quarantine_events": result,
                "count": len(result),
            }), 200

        except Exception:
            LOG.exception(
                "Errore durante il recupero degli eventi di quarantena"
            )

            return jsonify({
                "error": "Impossibile recuperare gli eventi di quarantena."
            }), 500

    return app


def main():
    """Avvia il server REST."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = create_app()

    host = os.environ.get("GUARDRAIL_API_HOST", "127.0.0.1")
    port = int(os.environ.get("GUARDRAIL_PORT", "9876"))

    LOG.info("Avvio API Guardrail su %s:%s", host, port)

    app.run(
        host=host,
        port=port,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
