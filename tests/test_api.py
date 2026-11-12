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

    def test_dashboard_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Guardrail",
            response.data,
        )

    def test_dashboard_data(self):
        response = self.client.get("/dashboard-data")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertIn("summary", data)
        self.assertIn("scheduler", data)
        self.assertIn("violations", data)
        self.assertIn("quarantine_events", data)
        self.assertIn("dry_run", data)

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


    def test_manual_scan_admin_audit_failure_does_not_hide_success(self):
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
        controller.database.record_admin_audit_event.side_effect = (
            RuntimeError("Errore audit")
        )

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post("/scan")

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "completed")
        self.assertFalse(data["admin_audit_recorded"])
        controller.scan.assert_called_once()

    def test_policy_update_admin_audit_failure_does_not_hide_success(self):
        controller = Mock()
        controller.policy = {
            "scan_interval_seconds": 300,
            "max_ram_mb": 4096,
        }

        updated_policy = {
            "scan_interval_seconds": 600,
            "max_ram_mb": 4096,
        }

        def save_policy(policy):
            controller.policy = policy

        controller.save_policy.side_effect = save_policy
        controller.database.record_admin_audit_event.side_effect = (
            RuntimeError("Errore audit")
        )

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.put("/policy", json=updated_policy)

        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "updated")
        self.assertEqual(data["policy"], updated_policy)
        self.assertEqual(
            data["changed_keys"],
            ["scan_interval_seconds"],
        )
        self.assertFalse(data["admin_audit_recorded"])
        controller.save_policy.assert_called_once_with(updated_policy)

    def test_restore_dry_run(self):
        controller = Mock()
        controller.restore_instance.return_value = {
            "event_id": 10,
            "instance_id": "vm-123",
            "dry_run": True,
            "result": "dry_run",
            "ports": [],
        }

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post("/restore/vm-123")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "dry_run")

        controller.restore_instance.assert_called_once_with(
            instance_id="vm-123",
            dry_run=True,
        )

    def test_restore_real(self):
        controller = Mock()
        controller.restore_instance.return_value = {
            "event_id": 11,
            "instance_id": "vm-123",
            "dry_run": False,
            "result": "restored",
            "ports": [],
        }

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post(
            "/restore/vm-123",
            json={"dry_run": False},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], "restored")

        controller.restore_instance.assert_called_once_with(
            instance_id="vm-123",
            dry_run=False,
        )

    def test_restore_invalid_dry_run(self):
        controller = Mock()

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post(
            "/restore/vm-123",
            json={"dry_run": "false"},
        )

        self.assertEqual(response.status_code, 400)
        controller.restore_instance.assert_not_called()

    def test_restore_admin_audit_failure_does_not_hide_success(self):
        controller = Mock()
        controller.restore_instance.return_value = {
            "event_id": 10,
            "event_recorded": True,
            "instance_id": "vm-123",
            "dry_run": False,
            "result": "restored",
            "ports": [],
        }

        controller.database.record_admin_audit_event.side_effect = (
            RuntimeError("Errore audit")
        )

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post(
            "/restore/vm-123",
            json={"dry_run": False},
        )

        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertEqual(data["result"], "restored")
        self.assertTrue(data["event_recorded"])
        self.assertFalse(data["admin_audit_recorded"])

    def test_restore_controller_error(self):
        controller = Mock()
        controller.restore_instance.side_effect = RuntimeError(
            "Errore di ripristino"
        )

        app = create_app(controller)
        app.config["TESTING"] = True
        client = app.test_client()

        response = client.post("/restore/vm-123")

        self.assertEqual(response.status_code, 500)


    def test_auth_info_requires_identity(self):
        app = create_app(Mock(), enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().get("/auth-info")

        self.assertEqual(response.status_code, 401)

    def test_auth_info_accepts_authenticated_user(self):
        app = create_app(Mock(), enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().get(
            "/auth-info",
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "user-123",
                "X-User-Name": "Test User",
                "X-Roles": "member",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["authenticated"])
        self.assertFalse(response.get_json()["is_admin"])

    def test_admin_scan_rejects_non_admin_user(self):
        controller = Mock()
        app = create_app(controller, enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().post(
            "/scan",
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "user-123",
                "X-Roles": "member",
            },
        )

        self.assertEqual(response.status_code, 403)
        controller.scan.assert_not_called()

    def test_admin_scan_accepts_admin_user(self):
        controller = Mock()
        controller.scan.return_value = {
            "scan_id": 1,
            "status": "completed",
            "instances_checked": 0,
            "violations_found": 0,
            "resolved_violations": 0,
            "violations": [],
            "quarantine_results": [],
        }

        app = create_app(controller, enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().post(
            "/scan",
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "admin-123",
                "X-User-Name": "Test Admin",
                "X-Roles": "member, admin",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "completed")
        controller.scan.assert_called_once()


    def test_admin_restore_rejects_non_admin_user(self):
        controller = Mock()
        app = create_app(controller, enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().post(
            "/restore/vm-123",
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "user-123",
                "X-Roles": "member",
            },
        )

        self.assertEqual(response.status_code, 403)
        controller.restore_instance.assert_not_called()

    def test_admin_policy_update_rejects_non_admin_user(self):
        controller = Mock()
        app = create_app(controller, enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().put(
            "/policy",
            json={"scan_interval_seconds": 600},
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "user-123",
                "X-Roles": "member",
            },
        )

        self.assertEqual(response.status_code, 403)
        controller.save_policy.assert_not_called()

    def test_admin_audit_events_rejects_non_admin_user(self):
        controller = Mock()
        app = create_app(controller, enable_auth=True)
        app.config["TESTING"] = True

        response = app.test_client().get(
            "/audit-events",
            headers={
                "X-Identity-Status": "Confirmed",
                "X-User-Id": "user-123",
                "X-Roles": "member",
            },
        )

        self.assertEqual(response.status_code, 403)
        controller.database.list_admin_audit_events.assert_not_called()


if __name__ == "__main__":
    unittest.main()
