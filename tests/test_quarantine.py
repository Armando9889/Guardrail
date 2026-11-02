import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from guardrail.quarantine import QuarantineManager, QuarantineError


class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        self.connection = MagicMock()
        self.database = MagicMock()

        self.manager = QuarantineManager(
            connection=self.connection,
            database=self.database,
            quarantine_security_group="guardrail-quarantine",
        )

        self.quarantine_group = SimpleNamespace(
            id="sg-quarantine"
        )

        self.connection.network.find_security_group.return_value = (
            self.quarantine_group
        )

        self.database.record_quarantine_event.return_value = 1

    def test_missing_quarantine_group(self):
        self.connection.network.find_security_group.return_value = None

        with self.assertRaises(QuarantineError):
            self.manager.quarantine_instance(
                "vm-123",
                "Immagine non autorizzata",
            )

    def test_missing_instance_ports(self):
        self.connection.network.ports.return_value = []

        with self.assertRaises(QuarantineError):
            self.manager.quarantine_instance(
                "vm-123",
                "Immagine non autorizzata",
            )

    def test_dry_run_does_not_modify_ports(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-original"],
        )

        self.connection.network.ports.return_value = [port]

        result = self.manager.quarantine_instance(
            "vm-123",
            "Immagine non autorizzata",
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["ports"][0]["status"], "dry_run")
        self.assertEqual(result["result"], "dry_run")

        self.connection.network.update_port.assert_not_called()

        self.database.record_quarantine_event.assert_called_once()

        saved_details = (
            self.database.record_quarantine_event.call_args.kwargs[
                "details"
            ]
        )

        self.assertEqual(
            saved_details["ports"][0]["original_security_groups"],
            ["sg-original"],
        )

    def test_already_quarantined_port_is_not_modified(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-quarantine"],
        )

        self.connection.network.ports.return_value = [port]

        result = self.manager.quarantine_instance(
            "vm-123",
            "Immagine non autorizzata",
            dry_run=False,
        )

        self.assertEqual(
            result["ports"][0]["status"],
            "already_quarantined",
        )

        self.connection.network.update_port.assert_not_called()

        self.database.record_quarantine_event.assert_called_once()

    def test_invalid_restore_argument(self):
        with self.assertRaises(ValueError):
            self.manager.restore_instance(
                "vm-123",
                ["sg-original"],
            )

    def test_restore_loads_original_groups_from_database(self):
        self.database.get_latest_quarantine_event.return_value = {
            "id": 1,
            "instance_id": "vm-123",
            "action": "quarantine",
            "result": "quarantined",
            "details": {
                "ports": [
                    {
                        "port_id": "port-123",
                        "status": "quarantined",
                        "original_security_groups": [
                            "sg-original"
                        ],
                    }
                ]
            },
        }

        result = self.manager.restore_instance(
            "vm-123",
        )

        self.database.get_latest_quarantine_event.assert_called_once_with(
            "vm-123"
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["ports"][0]["status"], "dry_run")
        self.assertEqual(
            result["ports"][0]["original_security_groups"],
            ["sg-original"],
        )

        self.connection.network.update_port.assert_not_called()

    def test_database_failure_prevents_quarantine(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-original"],
        )

        self.connection.network.ports.return_value = [port]

        self.database.record_quarantine_event.side_effect = (
            RuntimeError("Errore database")
        )

        with self.assertRaises(QuarantineError):
            self.manager.quarantine_instance(
                "vm-123",
                "Immagine non autorizzata",
                dry_run=False,
            )

        self.connection.network.update_port.assert_not_called()

    def test_quarantine_updates_persistent_event(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-original"],
        )

        self.connection.network.ports.return_value = [port]

        result = self.manager.quarantine_instance(
            "vm-123",
            "Immagine non autorizzata",
            dry_run=False,
        )

        self.connection.network.update_port.assert_called_once_with(
            port,
            security_groups=["sg-quarantine"],
        )

        self.assertEqual(result["result"], "quarantined")

        self.database.update_quarantine_event.assert_called_once()

        update_args = (
            self.database.update_quarantine_event.call_args.kwargs
        )

        self.assertEqual(update_args["event_id"], 1)
        self.assertEqual(update_args["result"], "quarantined")


if __name__ == "__main__":
    unittest.main()
