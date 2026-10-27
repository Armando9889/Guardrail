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
        self.connection.network.update_port.assert_not_called()

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

    def test_invalid_restore_argument(self):
        with self.assertRaises(ValueError):
            self.manager.restore_instance(
                "vm-123",
                ["sg-original"],
            )


if __name__ == "__main__":
    unittest.main()
