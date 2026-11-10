import tempfile
import unittest
from pathlib import Path

from guardrail.database import GuardrailDatabase


class TestGuardrailDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_guardrail.db"
        self.db = GuardrailDatabase(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_database_initialization(self):
        self.assertEqual(self.db.list_violations(), [])
        self.assertEqual(self.db.list_scans(), [])

    def test_scan_lifecycle(self):
        scan_id = self.db.start_scan()

        self.db.finish_scan(
            scan_id,
            instances_checked=3,
            violations_found=1,
        )

        scans = self.db.list_scans()

        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["status"], "completed")
        self.assertEqual(scans[0]["instances_checked"], 3)
        self.assertEqual(scans[0]["violations_found"], 1)

    def test_record_and_update_violation(self):
        violation = {
            "rule": "R1",
            "instance_id": "vm-001",
            "instance_name": "web-server",
            "message": "Owner mancante",
            "severity": "medium",
        }

        violation_id = self.db.record_violation(violation)
        self.db.record_violation(violation)

        violations = self.db.list_violations()

        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["id"], violation_id)
        self.assertEqual(violations[0]["occurrences"], 2)
        self.assertEqual(violations[0]["status"], "open")

    def test_resolve_violation(self):
        self.db.record_violation({
            "rule": "R1",
            "instance_id": "vm-001",
            "instance_name": "web-server",
            "message": "Owner mancante",
            "severity": "medium",
        })

        resolved = self.db.resolve_absent_violations([])

        self.assertEqual(resolved, 1)
        self.assertEqual(
            self.db.list_violations(status="resolved")[0]["status"],
            "resolved",
        )

    def test_record_quarantine_event(self):
        violation_id = self.db.record_violation({
            "rule": "R4",
            "instance_id": "vm-002",
            "instance_name": "test-vm",
            "message": "Immagine non autorizzata",
            "severity": "critical",
        })

        self.db.record_quarantine_event(
            instance_id="vm-002",
            action="quarantine",
            result="success",
            violation_id=violation_id,
        )

        events = self.db.list_quarantine_events()
        violation = self.db.list_violations()[0]

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["result"], "success")
        self.assertEqual(violation["quarantine_attempts"], 1)
        self.assertEqual(violation["quarantine_result"], "success")

    def test_get_restore_events_after_quarantine(self):
        quarantine_id = self.db.record_quarantine_event(
            instance_id="vm-restore",
            action="quarantine",
            result="quarantined",
            details={"ports": []},
        )

        self.db.record_quarantine_event(
            instance_id="vm-restore",
            action="restore",
            result="dry_run",
            details={"ports": []},
        )

        restore_id = self.db.record_quarantine_event(
            instance_id="vm-restore",
            action="restore",
            result="partial",
            details={
                "ports": [
                    {"port_id": "port-1", "status": "restored"},
                    {"port_id": "port-2", "status": "failed"},
                ]
            },
        )

        self.db.record_quarantine_event(
            instance_id="another-vm",
            action="restore",
            result="restored",
            details={"ports": []},
        )

        events = self.db.get_restore_events_after(
            "vm-restore",
            quarantine_id,
        )

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["result"], "dry_run")
        self.assertEqual(events[1]["id"], restore_id)
        self.assertEqual(
            events[1]["details"]["ports"][0]["port_id"],
            "port-1",
        )

    def test_get_instance_quarantine_events_returns_chronological_history(self):
        first_id = self.db.record_quarantine_event(
            instance_id="vm-history",
            action="quarantine",
            result="quarantined",
            details={
                "ports": [
                    {
                        "port_id": "port-1",
                        "status": "quarantined",
                        "original_security_groups": ["sg-original"],
                    }
                ]
            },
        )

        second_id = self.db.record_quarantine_event(
            instance_id="vm-history",
            action="restore",
            result="partial",
            details={
                "ports": [
                    {"port_id": "port-1", "status": "restored"}
                ]
            },
        )

        self.db.record_quarantine_event(
            instance_id="another-vm",
            action="quarantine",
            result="quarantined",
            details={"ports": []},
        )

        events = self.db.get_instance_quarantine_events("vm-history")

        self.assertEqual([event["id"] for event in events],
                         [first_id, second_id])
        self.assertEqual(events[0]["action"], "quarantine")
        self.assertEqual(
            events[0]["details"]["ports"][0]["original_security_groups"],
            ["sg-original"],
        )
        self.assertEqual(events[1]["action"], "restore")

    def test_get_restore_events_after_rejects_invalid_event_id(self):
        for invalid_id in (0, -1, True, "1"):
            with self.subTest(event_id=invalid_id):
                with self.assertRaises(ValueError):
                    self.db.get_restore_events_after(
                        "vm-restore",
                        invalid_id,
                    )

    # TEST R7

    def test_error_count_increments(self):
        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        self.assertEqual(
            self.db.get_instance_error_counts()["vm-001"],
            1,
        )

        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        self.assertEqual(
            self.db.get_instance_error_counts()["vm-001"],
            2,
        )

    def test_error_count_resets_when_instance_recovers(self):
        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        self.db.update_instance_error_counts({
            "vm-001": "ACTIVE",
        })

        self.assertEqual(
            self.db.get_instance_error_counts()["vm-001"],
            0,
        )

    def test_error_count_persists_after_database_reopening(self):
        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        self.db.update_instance_error_counts({
            "vm-001": "ERROR",
        })

        # Simula la riapertura del database.
        reopened_db = GuardrailDatabase(self.db_path)

        self.assertEqual(
            reopened_db.get_instance_error_counts()["vm-001"],
            2,
        )


if __name__ == "__main__":
    unittest.main()
