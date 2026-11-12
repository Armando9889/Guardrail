import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from guardrail.controller import GuardrailController


class TestGuardrailController(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.temp_path = Path(self.temp_dir.name)
        self.config_path = self.temp_path / "config.json"
        self.db_path = self.temp_path / "guardrail.db"

        self.policy = {
            "scan_interval_seconds": 300,
            "max_ram_mb": 4096,
            "max_vcpus": 2,
            "allowed_image_ids": ["cirros-approved"],
            "name_pattern": "^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
            "max_name_length": 50,
            "error_scan_threshold": 3,
            "max_project_ram_mb": 8192,
            "max_project_vcpus": 8,
            "project_limits": {},
            "auto_quarantine_rules": ["R4", "R6"],
            "quarantine_security_group": "guardrail-quarantine",
            "quarantine_dry_run": True,
        }

        self._write_config()

        self.connection = MagicMock()
        self.quarantine_manager = MagicMock()

        self.controller = GuardrailController(
            config_path=self.config_path,
            db_path=str(self.db_path),
            connection=self.connection,
            quarantine_manager=self.quarantine_manager,
        )

    def _write_config(self):
        self.config_path.write_text(
            json.dumps(self.policy),
            encoding="utf-8",
        )

    def _server(
        self,
        instance_id="vm-123",
        image_id="cirros-approved",
        security_profile="general",
        status="ACTIVE",
    ):
        return SimpleNamespace(
            id=instance_id,
            name="test-vm",
            metadata={
                "owner": "admin",
                "security_profile": security_profile,
            },
            flavor={
                "id": "flavor-1",
                "ram": 1024,
                "vcpus": 1,
            },
            image={"id": image_id},
            project_id="project-123",
            status=status,
        )

    def _prepare_scan(self, servers):
        self.connection.compute.servers.return_value = servers

        self.quarantine_manager.quarantine_instance.return_value = {
            "instance_id": "vm-123",
            "result": "dry_run",
            "dry_run": True,
        }

    def test_restore_rejects_invalid_dry_run(self):
        invalid_values = ("false", 0, 1, None)

        for value in invalid_values:
            with self.subTest(dry_run=value):
                self.quarantine_manager.reset_mock()

                with self.assertRaises(ValueError):
                    self.controller.restore_instance(
                        "vm-123",
                        dry_run=value,
                    )

                self.quarantine_manager.restore_instance.assert_not_called()

    def test_project_totals_aggregate_resources_by_project(self):
        first = self._server(instance_id="vm-1")
        first.flavor = {"ram": 1024, "vcpus": 1}

        second = self._server(instance_id="vm-2")
        second.flavor = {"ram": 2048, "vcpus": 2}

        third = self._server(instance_id="vm-3")
        third.project_id = "project-456"
        third.flavor = {"ram": 512, "vcpus": 1}

        totals = self.controller._project_totals(
            [first, second, third]
        )

        self.assertEqual(
            totals,
            {
                "project-123": {"ram_mb": 3072, "vcpus": 3},
                "project-456": {"ram_mb": 512, "vcpus": 1},
            },
        )

    def test_project_totals_treat_missing_resources_as_zero(self):
        server = self._server()
        server.flavor = {}

        totals = self.controller._project_totals([server])

        self.assertEqual(
            totals,
            {"project-123": {"ram_mb": 0, "vcpus": 0}},
        )

    def test_project_totals_ignore_invalid_resource_values(self):
        invalid = self._server(instance_id="vm-invalid")
        invalid.flavor = {
            "ram": "1024",
            "vcpus": True,
        }

        negative = self._server(instance_id="vm-negative")
        negative.flavor = {
            "ram": -512,
            "vcpus": "2",
        }

        valid = self._server(instance_id="vm-valid")
        valid.flavor = {
            "ram": 2048,
            "vcpus": 2,
        }

        totals = self.controller._project_totals(
            [invalid, negative, valid]
        )

        self.assertEqual(
            totals,
            {"project-123": {"ram_mb": 2048, "vcpus": 2}},
        )

    def test_project_limits_are_optional(self):
        policy = dict(self.policy)
        policy.pop("project_limits")

        validated = GuardrailController._validate_policy(policy)

        self.assertNotIn("project_limits", policy)
        self.assertNotIn("project_limits", validated)

    def test_valid_project_limits_are_accepted(self):
        policy = dict(self.policy)
        policy["project_limits"] = {
            "project-1": {
                "max_ram_mb": 8192,
                "max_vcpus": 4,
            },
            "project-2": {
                "max_ram_mb": 4096,
            },
        }

        validated = GuardrailController._validate_policy(policy)

        self.assertEqual(validated["project_limits"], policy["project_limits"])

    def test_invalid_project_limits_are_rejected(self):
        invalid_values = [
            [],
            {"": {"max_ram_mb": 1024}},
            {"project-1": {}},
            {"project-1": {"unknown_limit": 1024}},
            {"project-1": {"max_ram_mb": 0}},
            {"project-1": {"max_vcpus": -1}},
            {"project-1": {"max_ram_mb": True}},
            {"project-1": {"max_vcpus": "2"}},
        ]

        for value in invalid_values:
            with self.subTest(project_limits=value):
                policy = dict(self.policy)
                policy["project_limits"] = value

                with self.assertRaises(ValueError):
                    GuardrailController._validate_policy(policy)

    def test_r4_auto_quarantine_allows_empty_image_allowlist(self):
        policy = dict(self.policy)
        policy["allowed_image_ids"] = []

        validated = GuardrailController._validate_policy(policy)

        self.assertEqual(validated["allowed_image_ids"], [])
        self.assertEqual(
            validated["auto_quarantine_rules"],
            ["R4", "R6"],
        )

    def test_empty_image_allowlist_allowed_without_r4_quarantine(self):
        policy = dict(self.policy)
        policy["allowed_image_ids"] = []
        policy["auto_quarantine_rules"] = ["R6"]

        validated = GuardrailController._validate_policy(policy)

        self.assertEqual(validated["allowed_image_ids"], [])

    def test_r4_triggers_quarantine(self):
        server = self._server(image_id="unauthorized-image")
        self._prepare_scan([server])

        result = self.controller.scan()

        self.quarantine_manager.quarantine_instance.assert_called_once()
        self.assertEqual(len(result["quarantine_results"]), 1)
        self.assertEqual(
            result["quarantine_results"][0]["result"],
            "dry_run",
        )

    def test_r6_triggers_quarantine(self):
        server = self._server(security_profile="invalid")
        self._prepare_scan([server])

        result = self.controller.scan()

        self.quarantine_manager.quarantine_instance.assert_called_once()
        self.assertEqual(len(result["quarantine_results"]), 1)

    def test_non_automatic_rule_does_not_trigger_quarantine(self):
        server = self._server()
        server.metadata = {"security_profile": "general"}
        server.flavor = {
            "id": "flavor-1",
            "ram": 8192,
            "vcpus": 1,
        }

        self._prepare_scan([server])

        result = self.controller.scan()

        self.quarantine_manager.quarantine_instance.assert_not_called()
        self.assertEqual(result["quarantine_results"], [])

    def test_failed_server_retrieval_preserves_open_violations(self):
        server = self._server(image_id="unauthorized-image")
        self._prepare_scan([server])

        first_result = self.controller.scan()

        self.assertEqual(first_result["status"], "completed")

        violations_before = self.controller.database.list_violations()
        self.assertTrue(
            any(
                violation["rule_id"] == "R4"
                and violation["status"] == "open"
                for violation in violations_before
            )
        )

        # Simula un errore nel recupero completo delle istanze Nova.
        self.connection.compute.servers.side_effect = RuntimeError(
            "Nova server retrieval failed"
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "Nova server retrieval failed",
        ):
            self.controller.scan()

        latest_scan = self.controller.database.list_scans(limit=1)[0]

        self.assertEqual(latest_scan["status"], "failed")
        self.assertEqual(latest_scan["instances_checked"], 0)

        violations_after = self.controller.database.list_violations()

        self.assertTrue(
            any(
                violation["rule_id"] == "R4"
                and violation["status"] == "open"
                for violation in violations_after
            )
        )

        # Deve essere stata effettuata una sola richiesta per la seconda scansione.
        self.assertEqual(
            self.connection.compute.servers.call_count,
            2,
        )

        self.assertEqual(
            self.connection.compute.servers.call_args.kwargs,
            {
                "all_projects": True,
                "details": True,
            },
        )

    def test_quarantine_failure_does_not_fail_scan(self):
        server = self._server(image_id="unauthorized-image")
        self._prepare_scan([server])

        self.quarantine_manager.quarantine_instance.side_effect = (
            RuntimeError("Quarantine error")
        )

        result = self.controller.scan()

        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["quarantine_results"]), 1)
        self.assertEqual(
            result["quarantine_results"][0]["result"],
            "failed",
        )

    def test_dry_run_is_passed_to_quarantine_manager(self):
        server = self._server(image_id="unauthorized-image")
        self._prepare_scan([server])

        self.controller.scan()

        self.quarantine_manager.quarantine_instance.assert_called_once()

        call_kwargs = (
            self.quarantine_manager.quarantine_instance.call_args.kwargs
        )

        self.assertTrue(call_kwargs["dry_run"])

    def test_false_dry_run_configuration_is_accepted(self):
        self.policy["quarantine_dry_run"] = False
        self._write_config()

        controller = GuardrailController(
            config_path=self.config_path,
            db_path=str(self.temp_path / "false-dry-run.db"),
            connection=self.connection,
        )

        self.assertIs(controller.policy["quarantine_dry_run"], False)

    def test_invalid_dry_run_configuration(self):
        invalid_values = ("true", "false", 0, 1, None)

        for value in invalid_values:
            with self.subTest(dry_run=value):
                self.policy["quarantine_dry_run"] = value
                self._write_config()

                with self.assertRaises(ValueError):
                    GuardrailController(
                        config_path=self.config_path,
                        db_path=str(self.temp_path / "invalid.db"),
                        connection=self.connection,
                    )

    def test_r8_violations_are_persisted_separately(self):
        server = self._server()
        server.flavor = {
            "id": "flavor-1",
            "ram": 9216,
            "vcpus": 9,
        }

        self._prepare_scan([server])

        result = self.controller.scan()

        r8_violations = [
            violation
            for violation in result["violations"]
            if violation["rule"] == "R8"
        ]

        self.assertEqual(len(r8_violations), 2)

        instance_ids = {
            violation["instance_id"]
            for violation in r8_violations
        }

        self.assertEqual(
            instance_ids,
            {
                "project:project-123:ram",
                "project:project-123:vcpus",
            },
        )

        stored = [
            violation
            for violation in self.controller.database.list_violations()
            if violation["rule_id"] == "R8"
        ]

        self.assertEqual(len(stored), 2)
        self.assertEqual(
            {violation["instance_id"] for violation in stored},
            instance_ids,
        )
        self.assertTrue(
            all(violation["status"] == "open" for violation in stored)
        )

        self.quarantine_manager.quarantine_instance.assert_not_called()

    def test_r8_violations_are_resolved_when_project_is_compliant(self):
        server = self._server()
        server.flavor = {
            "id": "flavor-1",
            "ram": 9216,
            "vcpus": 9,
        }

        self._prepare_scan([server])
        first_result = self.controller.scan()

        self.assertEqual(
            len([
                violation
                for violation in first_result["violations"]
                if violation["rule"] == "R8"
            ]),
            2,
        )

        server.flavor = {
            "id": "flavor-1",
            "ram": 1024,
            "vcpus": 1,
        }

        second_result = self.controller.scan()

        self.assertEqual(second_result["status"], "completed")

        stored = [
            violation
            for violation in self.controller.database.list_violations()
            if violation["rule_id"] == "R8"
        ]

        self.assertEqual(len(stored), 2)
        self.assertTrue(
            all(violation["status"] == "resolved" for violation in stored)
        )

    def test_r8_never_triggers_quarantine(self):
        self.policy["auto_quarantine_rules"] = ["R8"]
        self._write_config()

        controller = GuardrailController(
            config_path=self.config_path,
            db_path=str(self.db_path),
            connection=self.connection,
            quarantine_manager=self.quarantine_manager,
        )

        server = self._server()
        server.flavor = {
            "id": "flavor-1",
            "ram": 9216,
            "vcpus": 9,
        }

        self._prepare_scan([server])

        result = controller.scan()

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["quarantine_results"], [])
        self.quarantine_manager.quarantine_instance.assert_not_called()

    def test_r7_persists_after_controller_restart(self):
        # Prima scansione: la VM è in ERROR.
        server = self._server(status="ERROR")
        self._prepare_scan([server])

        first_result = self.controller.scan()

        self.assertEqual(first_result["status"], "completed")
        self.assertEqual(
            self.controller.database.get_instance_error_counts()["vm-123"],
            1,
        )

        # Seconda scansione: il contatore deve arrivare a 2.
        second_result = self.controller.scan()

        self.assertEqual(second_result["status"], "completed")
        self.assertEqual(
            self.controller.database.get_instance_error_counts()["vm-123"],
            2,
        )

        # Simulazione del riavvio: nuovo controller,
        # stesso database SQLite.
        restarted_controller = GuardrailController(
            config_path=self.config_path,
            db_path=str(self.db_path),
            connection=self.connection,
            quarantine_manager=self.quarantine_manager,
        )

        # Verifica che il conteggio precedente sia stato conservato.
        self.assertEqual(
            restarted_controller.database.get_instance_error_counts()[
                "vm-123"
            ],
            2,
        )

        # Terza scansione: deve scattare R7.
        third_result = restarted_controller.scan()

        self.assertEqual(third_result["status"], "completed")
        self.assertEqual(
            restarted_controller.database.get_instance_error_counts()[
                "vm-123"
            ],
            3,
        )

        r7_violations = [
            violation
            for violation in third_result["violations"]
            if violation["rule"] == "R7"
        ]

        self.assertEqual(len(r7_violations), 1)

if __name__ == "__main__":
    unittest.main()
