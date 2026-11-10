import logging
import os
from functools import wraps
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request, render_template

from guardrail.controller import GuardrailController

LOG = logging.getLogger("guardrail.api")


class PublicEndpointsMiddleware:
    """Lascia pubblici solo gli endpoint esplicitamente consentiti."""

    def __init__(self, authenticated_app, public_app):
        self.authenticated_app = authenticated_app
        self.public_app = public_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path in ("/", "/health"):
            return self.public_app(environ, start_response)
        return self.authenticated_app(environ, start_response)


def create_app(controller=None, enable_auth=False):
    """Crea l'applicazione REST di Guardrail."""

    app = Flask(__name__)

    guardrail = controller or GuardrailController()

    app.config["GUARDRAIL_CONTROLLER"] = guardrail
    app.config["AUTH_ENABLED"] = enable_auth

    def require_identity(admin=False):
        """Verifica l'identità Keystone e, se richiesto, il ruolo admin."""

        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if not app.config["AUTH_ENABLED"]:
                    return view(*args, **kwargs)

                identity_status = request.headers.get("X-Identity-Status")
                user_id = request.headers.get("X-User-Id")

                if identity_status != "Confirmed" or not user_id:
                    return jsonify({
                        "error": "Autenticazione Keystone richiesta."
                    }), 401

                if admin:
                    roles = {
                        role.strip().lower()
                        for role in request.headers.get("X-Roles", "").split(",")
                    }
                    if "admin" not in roles:
                        return jsonify({
                            "error": "È richiesto il ruolo admin."
                        }), 403

                return view(*args, **kwargs)

            return wrapped
        return decorator

    def record_audit(action, resource, details=None):
        """Registra un'operazione amministrativa senza salvare il token."""

        user_id = request.headers.get("X-User-Id")
        user_name = request.headers.get("X-User-Name") or user_id

        guardrail.database.record_admin_audit_event(
            actor_id=user_id,
            actor_name=user_name,
            action=action,
            resource=resource,
            details=details,
        )

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "service": "Guardrail",
            "status": "healthy",
        }), 200

    @app.route("/auth-info", methods=["GET"])
    @require_identity()
    def auth_info():
        """Restituisce le informazioni essenziali dell'utente autenticato."""
        roles = {
            role.strip().lower()
            for role in request.headers.get("X-Roles", "").split(",")
        }

        return jsonify({
            "authenticated": True,
            "user_name": request.headers.get("X-User-Name") or "Utente",
            "is_admin": "admin" in roles,
        }), 200


    @app.route("/scan", methods=["POST"])
    @require_identity(admin=True)
    def scan():
        try:
            result = guardrail.scan()
            record_audit(
                action="manual_scan",
                resource="instances",
                details={
                    "scan_id": result.get("scan_id"),
                    "status": result.get("status"),
                },
            )
            return jsonify(result), 200

        except Exception:
            LOG.exception("Errore durante la scansione REST")

            return jsonify({
                "status": "failed",
                "error": "Impossibile completare la scansione.",
            }), 500

    @app.route("/restore/<instance_id>", methods=["POST"])
    @require_identity(admin=True)
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

            record_audit(
                action="instance_restore",
                resource=instance_id,
                details={"dry_run": dry_run},
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
    @require_identity()
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
    @require_identity()
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
    @require_identity()
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


    @app.route("/", methods=["GET"])
    def dashboard():
        """Mostra la dashboard web di Guardrail."""
        return render_template("dashboard.html")

    @app.route("/dashboard-data", methods=["GET"])
    @require_identity()
    def dashboard_data():
        """Restituisce i dati aggregati per la dashboard."""
        try:
            scans = guardrail.database.list_scans(limit=100)
            violations = guardrail.database.list_violations()
            events = guardrail.database.list_quarantine_events(limit=50)

            interval = guardrail.policy.get(
                "scan_interval_seconds", 300
            )

            automatic_scans = [
                scan for scan in scans
                if scan.get("source") == "automatic"
            ]

            latest_auto = automatic_scans[0] if automatic_scans else None
            last_auto_time = None
            next_auto_time = None
            scheduler_status = "waiting"

            if latest_auto:
                timestamp = (
                    latest_auto.get("completed_at")
                    or latest_auto.get("started_at")
                )

                if timestamp:
                    last_auto_time = datetime.fromisoformat(
                        timestamp.replace("Z", "+00:00")
                    )

                    if last_auto_time.tzinfo is None:
                        last_auto_time = last_auto_time.replace(
                            tzinfo=timezone.utc
                        )

                    next_auto_time = last_auto_time + timedelta(
                        seconds=interval
                    )

                    age = (
                        datetime.now(timezone.utc) - last_auto_time
                    ).total_seconds()

                    scheduler_status = (
                        "active" if age <= interval * 2 else "stale"
                    )

            return jsonify({
                "scans": scans,
                "violations": violations,
                "quarantine_events": events,
                "summary": {
                    "scans_count": len(scans),
                    "violations_open": sum(
                        1 for item in violations
                        if item.get("status") == "open"
                    ),
                    "violations_resolved": sum(
                        1 for item in violations
                        if item.get("status") == "resolved"
                    ),
                    "quarantine_events_count": len(events),
                },
                "scheduler": {
                    "status": scheduler_status,
                    "interval_seconds": interval,
                    "last_automatic_scan": (
                        last_auto_time.isoformat()
                        if last_auto_time else None
                    ),
                    "next_automatic_scan": (
                        next_auto_time.isoformat()
                        if next_auto_time else None
                    ),
                },
                "dry_run": guardrail.policy.get(
                    "quarantine_dry_run", True
                ),
            }), 200

        except Exception:
            LOG.exception("Errore durante il recupero dei dati dashboard")
            return jsonify({
                "error": "Impossibile recuperare i dati della dashboard."
            }), 500

    @app.route("/policy", methods=["GET"])
    @require_identity()
    def get_policy():
        try:
            policy = guardrail.reload_policy()
            return jsonify({"policy": policy}), 200
        except Exception:
            LOG.exception("Errore durante il recupero della policy")
            return jsonify({
                "error": "Impossibile recuperare la policy."
            }), 500

    @app.route("/policy", methods=["PUT"])
    @require_identity(admin=True)
    def update_policy():
        try:
            payload = request.get_json(silent=True)

            if not isinstance(payload, dict):
                return jsonify({
                    "error": "Il corpo della richiesta deve essere un oggetto JSON."
                }), 400

            old_policy = dict(guardrail.policy)
            guardrail.save_policy(payload)

            changed_keys = sorted(
                key for key in payload
                if old_policy.get(key) != payload.get(key)
            )

            record_audit(
                action="policy_update",
                resource="guardrail_policy",
                details={"changed_keys": changed_keys},
            )

            return jsonify({
                "status": "updated",
                "policy": guardrail.policy,
                "changed_keys": changed_keys,
            }), 200

        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception:
            LOG.exception("Errore durante l'aggiornamento della policy")
            return jsonify({
                "error": "Impossibile aggiornare la policy."
            }), 500

    @app.route("/audit-events", methods=["GET"])
    @require_identity(admin=True)
    def audit_events():
        try:
            limit = request.args.get("limit", default=50, type=int)

            if limit < 1 or limit > 500:
                return jsonify({
                    "error": "Il parametro limit deve essere tra 1 e 500."
                }), 400

            events = guardrail.database.list_admin_audit_events(
                limit=limit
            )

            return jsonify({
                "audit_events": events,
                "count": len(events),
            }), 200

        except Exception:
            LOG.exception("Errore durante il recupero degli eventi audit")
            return jsonify({
                "error": "Impossibile recuperare gli eventi audit."
            }), 500

    return app


def main():
    """Avvia il server REST."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = create_app(enable_auth=True)

    from keystonemiddleware.auth_token import AuthProtocol

    authenticated_app = AuthProtocol(
        app.wsgi_app,
        {
            "oslo_config_project": "nova",
            "oslo_config_file": "/etc/nova/nova.conf",
        },
    )

    app.wsgi_app = PublicEndpointsMiddleware(
        authenticated_app,
        app.wsgi_app,
    )

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
