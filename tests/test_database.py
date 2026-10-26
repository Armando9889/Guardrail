import tempfile
import unittest
from pathlib import Path

from guardrail.database import GuardrailDatabase


class TestGuardrailDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = Path(self.temp_dir.name) / "test_guardrail.db"
        self.db = GuardrailDatabase(db_path)

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


if __name__ == "__main__":
    unittest.main()
