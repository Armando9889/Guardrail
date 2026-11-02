import tempfile
import unittest
from pathlib import Path

from guardrail.api import create_app
from guardrail.controller import GuardrailController
from unittest.mock import Mock


class TestGuardrailAPI(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(
            Path(self.temp_dir.name) / "test.db"
        )

        controller = GuardrailController(
            db_path=self.db_path
        )

        self.app = create_app(controller)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["status"],
            "healthy",
        )

    def test_list_scans(self):
        response = self.client.get("/scans")

        self.assertEqual(response.status_code, 200)
        self.assertIn("scans", response.get_json())

    def test_list_violations(self):
        response = self.client.get("/violations")

        self.assertEqual(response.status_code, 200)
        self.assertIn("violations", response.get_json())

    def test_list_quarantine_events(self):
        response = self.client.get("/quarantine-events")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "quarantine_events",
            response.get_json(),
        )

    def test_invalid_scan_limit(self):
        response = self.client.get("/scans?limit=1000")

        self.assertEqual(response.status_code, 400)

    def test_invalid_violation_status(self):
        response = self.client.get(
            "/violations?status=invalid"
        )

        self.assertEqual(response.status_code, 400)

    def test_manual_scan(self):
        controller = Mock()

        controller.scan.return_value = {
            "scan_id": 1,
            "status": "completed",
            "instances_checked": 3,
            "violations_found": 2,
            "resolved_violations": 0,
            "violations": [],
            "quarantine_results": [],
        }

        app = create_app(controller)
        app.config["TESTING"] = True

        client = app.test_client()

        response = client.post("/scan")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["status"],
            "completed",
        )

        controller.scan.assert_called_once()

if __name__ == "__main__":
    unittest.main()
