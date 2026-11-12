import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from guardrail.quarantine import QuarantineManager, QuarantineError


class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        self.connection = MagicMock()
        self.database = MagicMock()
        self.database.get_instance_quarantine_events.return_value = None

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

    def test_mixed_security_groups_use_original_history_for_quarantine(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-quarantine", "sg-extra"],
        )
        self.connection.network.ports.return_value = [port]
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original"],
                        }
                    ]
                },
            }
        ]

        result = self.manager.quarantine_instance(
            "vm-123",
            "Configurazione da verificare",
            dry_run=False,
        )

        self.connection.network.update_port.assert_called_once_with(
            port,
            security_groups=["sg-quarantine"],
        )
        self.assertEqual(result["result"], "quarantined")
        self.assertEqual(result["ports"][0]["status"], "quarantined")

        saved_details = (
            self.database.record_quarantine_event.call_args.kwargs["details"]
        )
        self.assertEqual(
            saved_details["ports"][0]["original_security_groups"],
            ["sg-original"],
        )

    def test_mixed_security_groups_without_history_are_not_modified(self):
        port = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-quarantine", "sg-extra"],
        )
        self.connection.network.ports.return_value = [port]
        self.database.get_instance_quarantine_events.return_value = []

        result = self.manager.quarantine_instance(
            "vm-123",
            "Configurazione da verificare",
            dry_run=False,
        )

        self.connection.network.update_port.assert_not_called()
        self.assertEqual(result["result"], "failed")
        self.assertEqual(result["ports"][0]["status"], "failed")
        self.assertIn("storico", result["ports"][0]["error"])

    def test_restore_rejects_invalid_dry_run(self):
        invalid_values = ("false", 0, 1, None)

        for value in invalid_values:
            with self.subTest(dry_run=value):
                self.database.reset_mock()
                self.connection.reset_mock()

                with self.assertRaises(ValueError):
                    self.manager.restore_instance(
                        "vm-123",
                        dry_run=value,
                    )

                self.database.get_latest_quarantine_event.assert_not_called()
                self.connection.network.assert_not_called()

    def test_restore_rejects_already_quarantined_port(self):
        self.database.get_latest_quarantine_event.return_value = {
            "id": 1,
            "instance_id": "vm-123",
            "action": "quarantine",
            "result": "quarantined",
            "details": {
                "ports": [
                    {
                        "port_id": "port-123",
                        "status": "already_quarantined",
                        "original_security_groups": ["sg-quarantine"],
                    }
                ]
            },
        }

        with self.assertRaises(QuarantineError):
            self.manager.restore_instance("vm-123")

        self.connection.network.update_port.assert_not_called()

    def test_restore_ignores_already_quarantined_ports(self):
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
                        "original_security_groups": ["sg-original"],
                    },
                    {
                        "port_id": "port-456",
                        "status": "already_quarantined",
                        "original_security_groups": ["sg-quarantine"],
                    },
                ]
            },
        }

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(
            groups,
            {"port-123": ["sg-original"]},
        )

    def test_restore_ignores_dry_run_restore_events(self):
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
                        "original_security_groups": ["sg-original"],
                    }
                ]
            },
        }
        self.database.get_restore_events_after.return_value = [
            {
                "id": 2,
                "result": "dry_run",
                "details": {
                    "ports": [
                        {"port_id": "port-123", "status": "dry_run"}
                    ]
                },
            }
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(groups, {"port-123": ["sg-original"]})

    def test_restore_excludes_already_restored_ports(self):
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
                        "original_security_groups": ["sg-original-1"],
                    },
                    {
                        "port_id": "port-456",
                        "status": "quarantined",
                        "original_security_groups": ["sg-original-2"],
                    },
                ]
            },
        }
        self.database.get_restore_events_after.return_value = [
            {
                "id": 2,
                "result": "partial",
                "details": {
                    "ports": [
                        {"port_id": "port-123", "status": "restored"},
                        {"port_id": "port-456", "status": "failed"},
                    ]
                },
            }
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(
            groups,
            {"port-456": ["sg-original-2"]},
        )

    def test_restore_rejects_when_all_ports_are_already_restored(self):
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
                        "original_security_groups": ["sg-original"],
                    }
                ]
            },
        }
        self.database.get_restore_events_after.return_value = [
            {
                "id": 2,
                "result": "restored",
                "details": {
                    "ports": [
                        {"port_id": "port-123", "status": "restored"}
                    ]
                },
            }
        ]

        with self.assertRaises(QuarantineError):
            self.manager._load_original_security_groups("vm-123")

    def test_restore_allows_retry_after_failed_restore(self):
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
                        "original_security_groups": ["sg-original"],
                    }
                ]
            },
        }
        self.database.get_restore_events_after.return_value = [
            {
                "id": 2,
                "result": "failed",
                "details": {
                    "ports": [
                        {"port_id": "port-123", "status": "failed"}
                    ]
                },
            }
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(groups, {"port-123": ["sg-original"]})

    def test_pending_history_recovers_groups_when_neutron_confirms_quarantine(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "pending",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "pending",
                            "original_security_groups": ["sg-original"],
                        }
                    ]
                },
            }
        ]

        self.connection.network.get_port.return_value = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-quarantine"],
        )

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(groups, {"port-123": ["sg-original"]})
        self.connection.network.get_port.assert_called_once_with("port-123")

    def test_pending_history_ignores_port_not_quarantined(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "pending",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "pending",
                            "original_security_groups": ["sg-original"],
                        }
                    ]
                },
            }
        ]

        self.connection.network.get_port.return_value = SimpleNamespace(
            id="port-123",
            security_group_ids=["sg-original"],
        )

        with self.assertRaises(QuarantineError):
            self.manager._load_original_security_groups("vm-123")

    def test_pending_history_fails_if_neutron_cannot_be_checked(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "pending",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "pending",
                            "original_security_groups": ["sg-original"],
                        }
                    ]
                },
            }
        ]

        self.connection.network.get_port.side_effect = RuntimeError(
            "Neutron non disponibile"
        )

        with self.assertRaises(QuarantineError):
            self.manager._load_original_security_groups("vm-123")


    def test_history_preserves_original_groups_after_repeated_quarantine(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original"],
                        }
                    ]
                },
            },
            {
                "id": 2,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "already_quarantined",
                            "original_security_groups": ["sg-quarantine"],
                        }
                    ]
                },
            },
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(groups, {"port-123": ["sg-original"]})

    def test_history_preserves_original_groups_for_mixed_ports(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original-1"],
                        }
                    ]
                },
            },
            {
                "id": 2,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "already_quarantined",
                            "original_security_groups": ["sg-quarantine"],
                        },
                        {
                            "port_id": "port-456",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original-2"],
                        },
                    ]
                },
            },
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(
            groups,
            {
                "port-123": ["sg-original-1"],
                "port-456": ["sg-original-2"],
            },
        )

    def test_history_allows_requarantine_after_restore(self):
        self.database.get_instance_quarantine_events.return_value = [
            {
                "id": 1,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original-1"],
                        }
                    ]
                },
            },
            {
                "id": 2,
                "action": "restore",
                "result": "restored",
                "details": {
                    "ports": [
                        {"port_id": "port-123", "status": "restored"}
                    ]
                },
            },
            {
                "id": 3,
                "action": "quarantine",
                "result": "quarantined",
                "details": {
                    "ports": [
                        {
                            "port_id": "port-123",
                            "status": "quarantined",
                            "original_security_groups": ["sg-original-2"],
                        }
                    ]
                },
            },
        ]

        groups = self.manager._load_original_security_groups("vm-123")

        self.assertEqual(groups, {"port-123": ["sg-original-2"]})

    def test_restore_rejects_explicit_security_groups(self):
        with self.assertRaises(TypeError):
            self.manager.restore_instance(
                "vm-123",
                ["sg-original"],
            )

        self.database.get_latest_quarantine_event.assert_not_called()

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

    def test_restore_reports_database_event_failure(self):
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
                        "original_security_groups": ["sg-original"],
                    }
                ]
            },
        }

        port = SimpleNamespace(
            id="port-123",
            device_id="vm-123",
        )
        self.connection.network.get_port.return_value = port

        self.database.record_quarantine_event.side_effect = (
            RuntimeError("Errore database")
        )

        result = self.manager.restore_instance(
            "vm-123",
            dry_run=False,
        )

        self.connection.network.update_port.assert_called_once_with(
            port,
            security_groups=["sg-original"],
        )

        self.assertEqual(result["result"], "restored")
        self.assertFalse(result["event_recorded"])
        self.assertIsNone(result["event_id"])

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
