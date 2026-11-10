import unittest

from guardrail.rules import check_instance


class TestGuardrailRules(unittest.TestCase):

    def setUp(self):
        self.instance = {
            "id": "vm-001",
            "project_id": "project-1",
            "name": "web-server-01",
            "metadata": {
                "owner": "admin",
                "security_profile": "web",
            },
            "ram_mb": 1024,
            "vcpus": 1,
            "image_id": "cirros-image",
            "consecutive_error_scans": 0,
        }

        self.policy = {
            "max_ram_mb": 4096,
            "max_vcpus": 2,
            "allowed_image_ids": ["cirros-image"],
            "name_pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
            "max_name_length": 50,
            "error_scan_threshold": 3,
            "project_limits": {},
        }

    def test_compliant_instance_has_no_violations(self):
        violations = check_instance(self.instance, self.policy)
        self.assertEqual(violations, [])

    def test_missing_owner_triggers_r1(self):
        self.instance["metadata"].pop("owner")
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R1", [v["rule"] for v in violations])

    def test_excessive_ram_triggers_r2(self):
        self.instance["ram_mb"] = 8192
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R2", [v["rule"] for v in violations])

    def test_excessive_vcpus_triggers_r3(self):
        self.instance["vcpus"] = 4
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R3", [v["rule"] for v in violations])

    def test_project_ram_override_triggers_r2(self):
        self.policy["project_limits"] = {
            "project-1": {"max_ram_mb": 512}
        }
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R2", [v["rule"] for v in violations])

    def test_project_vcpu_override_triggers_r3(self):
        self.policy["project_limits"] = {
            "project-1": {"max_vcpus": 0 + 1}
        }
        self.instance["vcpus"] = 2
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R3", [v["rule"] for v in violations])

    def test_partial_project_override_uses_global_fallback(self):
        self.policy["project_limits"] = {
            "project-1": {"max_ram_mb": 2048}
        }
        self.instance["vcpus"] = 3
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R3", [v["rule"] for v in violations])

    def test_unconfigured_project_uses_global_limits(self):
        self.instance["project_id"] = "project-unknown"
        self.instance["ram_mb"] = 8192
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R2", [v["rule"] for v in violations])

    def test_unauthorized_image_triggers_r4(self):
        self.instance["image_id"] = "unauthorized-image"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R4", [v["rule"] for v in violations])

    def test_empty_image_allowlist_does_not_trigger_r4(self):
        self.policy["allowed_image_ids"] = []
        self.instance["image_id"] = "any-image"

        violations = check_instance(self.instance, self.policy)

        self.assertNotIn("R4", [v["rule"] for v in violations])

    def test_invalid_name_triggers_r5(self):
        self.instance["name"] = "invalid name!"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R5", [v["rule"] for v in violations])

    def test_non_dict_metadata_triggers_r1_and_r6(self):
        for metadata in ["invalid", [], 123, None]:
            with self.subTest(metadata=metadata):
                self.instance["metadata"] = metadata

                violations = check_instance(
                    self.instance,
                    self.policy,
                )

                rules = {v["rule"] for v in violations}
                self.assertIn("R1", rules)
                self.assertIn("R6", rules)

                self.instance["metadata"] = {
                    "owner": "admin",
                    "security_profile": "web",
                }

    def test_invalid_security_profile_triggers_r6(self):
        self.instance["metadata"]["security_profile"] = "unknown"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R6", [v["rule"] for v in violations])

    def test_non_string_security_profile_triggers_r6(self):
        for profile in [[], {}, 123, True, None]:
            with self.subTest(profile=profile):
                self.instance["metadata"]["security_profile"] = profile

                violations = check_instance(
                    self.instance,
                    self.policy,
                )

                self.assertIn(
                    "R6",
                    [violation["rule"] for violation in violations],
                )

    def test_persistent_error_triggers_r7(self):
        self.instance["consecutive_error_scans"] = 3
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R7", [v["rule"] for v in violations])

if __name__ == "__main__":
    unittest.main()
