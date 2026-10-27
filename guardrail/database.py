
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

def utc_now():
    """Restituisce un timestamp UTC ISO 8601."""
    return datetime.now(timezone.utc).isoformat()

class GuardrailDatabase:
    """Gestisce scansioni, violazioni e operazioni di quarantena."""

    def __init__(self, db_path):
        self.db_path = str(db_path)

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self.initialize()

    @contextmanager
    def connection(self):
        """Apre una connessione SQLite e gestisce commit e rollback."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row

        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self):
        """Crea le tabelle necessarie, se non esistono."""
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    instances_checked INTEGER NOT NULL DEFAULT 0,
                    violations_found INTEGER NOT NULL DEFAULT 0,
                    details TEXT
                );

                CREATE TABLE IF NOT EXISTS violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    instance_name TEXT NOT NULL DEFAULT '',
                    message TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL DEFAULT 'open',
                    quarantine_attempts INTEGER NOT NULL DEFAULT 0,
                    quarantine_result TEXT,
                    resolved_at TEXT,
                    UNIQUE(rule_id, instance_id)
                );

                CREATE TABLE IF NOT EXISTS quarantine_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    violation_id INTEGER,
                    instance_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (violation_id) REFERENCES violations(id)
                );
            """)

    def start_scan(self):
        """Registra l'inizio di una scansione e restituisce il suo ID."""
        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (started_at, status)
                VALUES (?, 'running')
                """,
                (utc_now(),),
            )
            return cursor.lastrowid

    def finish_scan(
        self,
        scan_id,
        instances_checked,
        violations_found,
        status="completed",
        details=None,
    ):
        """Registra il risultato finale di una scansione."""
        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE scans
                SET completed_at = ?,
                    status = ?,
                    instances_checked = ?,
                    violations_found = ?,
                    details = ?
                WHERE id = ?
                """,
                (
                    utc_now(),
                    status,
                    instances_checked,
                    violations_found,
                    json.dumps(details) if details is not None else None,
                    scan_id,
                ),
            )

            if cursor.rowcount == 0:
                raise ValueError(f"Scansione inesistente: {scan_id}")

    def record_violation(self, violation):
        """Inserisce o aggiorna una violazione; restituisce il suo ID."""
        now = utc_now()
        rule_id = violation["rule"]
        instance_id = str(violation["instance_id"])

        with self.connection() as conn:
            conn.execute(
                """
                INSERT INTO violations (
                    rule_id, instance_id, instance_name, message,
                    severity, first_seen, last_seen, occurrences,
                    status, resolved_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'open', NULL)
                ON CONFLICT(rule_id, instance_id) DO UPDATE SET
                    instance_name = excluded.instance_name,
                    message = excluded.message,
                    severity = excluded.severity,
                    last_seen = excluded.last_seen,
                    occurrences = violations.occurrences + 1,
                    status = 'open',
                    resolved_at = NULL
                """,
                (
                    rule_id,
                    instance_id,
                    str(violation.get("instance_name", "")),
                    str(violation["message"]),
                    str(violation.get("severity", "medium")),
                    now,
                    now,
                ),
            )

            row = conn.execute(
                """
                SELECT id FROM violations
                WHERE rule_id = ? AND instance_id = ?
                """,
                (rule_id, instance_id),
            ).fetchone()

            return row["id"]

    def resolve_absent_violations(self, active_keys):
        """Risolve le violazioni aperte che non compaiono nella scansione."""
        active = {
            (str(rule), str(instance))
            for rule, instance in active_keys
        }
        now = utc_now()

        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, rule_id, instance_id
                FROM violations
                WHERE status = 'open'
                """
            ).fetchall()

            resolved = 0

            for row in rows:
                key = (row["rule_id"], row["instance_id"])

                if key not in active:
                    conn.execute(
                        """
                        UPDATE violations
                        SET status = 'resolved', resolved_at = ?
                        WHERE id = ?
                        """,
                        (now, row["id"]),
                    )
                    resolved += 1

            return resolved

    def list_violations(self, status=None):
        """Restituisce le violazioni, eventualmente filtrate per stato."""
        with self.connection() as conn:
            if status is None:
                rows = conn.execute(
                    """
                    SELECT * FROM violations
                    ORDER BY last_seen DESC
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM violations
                    WHERE status = ?
                    ORDER BY last_seen DESC
                    """,
                    (status,),
                ).fetchall()

            return [dict(row) for row in rows]

    def list_scans(self, limit=50):
        """Restituisce le scansioni più recenti."""
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
        ):
            raise ValueError("limit deve essere un intero positivo")

        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [dict(row) for row in rows]

    def record_quarantine_event(
        self,
        instance_id,
        action,
        result,
        violation_id=None,
        details=None,
    ):
        """Registra un evento e restituisce il suo ID."""
        now = utc_now()

        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO quarantine_events (
                    violation_id, instance_id, action,
                    result, details, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    violation_id,
                    str(instance_id),
                    str(action),
                    str(result),
                    json.dumps(details) if details is not None else None,
                    now,
                ),
            )

            event_id = cursor.lastrowid

            if violation_id is not None:
                conn.execute(
                    """
                    UPDATE violations
                    SET quarantine_attempts = quarantine_attempts + 1,
                        quarantine_result = ?
                    WHERE id = ?
                    """,
                    (str(result), violation_id),
                )

            return event_id

    def update_quarantine_event(self, event_id, result, details=None):
        """Aggiorna l'esito e i dettagli di un evento."""
        if (
            not isinstance(event_id, int)
            or isinstance(event_id, bool)
            or event_id < 1
        ):
            raise ValueError("event_id deve essere un intero positivo")

        with self.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE quarantine_events
                SET result = ?, details = ?
                WHERE id = ?
                """,
                (
                    str(result),
                    json.dumps(details) if details is not None else None,
                    event_id,
                ),
            )

            if cursor.rowcount == 0:
                raise ValueError(f"Evento inesistente: {event_id}")

    def get_quarantine_event(self, event_id):
        """Recupera un evento specifico tramite ID."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM quarantine_events
                WHERE id = ?
                """,
                (event_id,),
            ).fetchone()

            if row is None:
                return None

            event = dict(row)

            if event["details"] is not None:
                event["details"] = json.loads(event["details"])

            return event

    def get_latest_quarantine_event(self, instance_id):
        """Recupera l'ultimo evento di quarantena di una VM."""
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM quarantine_events
                WHERE instance_id = ?
                  AND action = 'quarantine'
                ORDER BY id DESC
                LIMIT 1
                """,
                (str(instance_id),),
            ).fetchone()

            if row is None:
                return None

            event = dict(row)

            if event["details"] is not None:
                event["details"] = json.loads(event["details"])

            return event

    def list_quarantine_events(self, limit=50):
        """Restituisce gli eventi di quarantena più recenti."""
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or limit < 1
        ):
            raise ValueError("limit deve essere un intero positivo")

        with self.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM quarantine_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

            return [dict(row) for row in rows]
