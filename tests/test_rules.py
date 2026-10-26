import unittest

from guardrail.rules import check_instance


class TestGuardrailRules(unittest.TestCase):

    def setUp(self):
        self.instance = {
            "id": "vm-001",
            "name": "web-server-01",
            "metadata": {
                "owner": "admin",
                "security_profile": "web",
            },
            "ram_mb": 1024,
            "vcpus": 1,
            "image_id": "cirros-image",
            "consecutive_error_scans": 0,
            "project_ram_mb": 2048,
            "project_vcpus": 2,
        }

        self.policy = {
            "max_ram_mb": 4096,
            "max_vcpus": 2,
            "allowed_image_ids": ["cirros-image"],
            "name_pattern": r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
            "max_name_length": 50,
            "error_scan_threshold": 3,
            "max_project_ram_mb": 8192,
            "max_project_vcpus": 8,
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

    def test_unauthorized_image_triggers_r4(self):
        self.instance["image_id"] = "unauthorized-image"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R4", [v["rule"] for v in violations])

    def test_invalid_name_triggers_r5(self):
        self.instance["name"] = "invalid name!"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R5", [v["rule"] for v in violations])

    def test_invalid_security_profile_triggers_r6(self):
        self.instance["metadata"]["security_profile"] = "unknown"
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R6", [v["rule"] for v in violations])

    def test_persistent_error_triggers_r7(self):
        self.instance["consecutive_error_scans"] = 3
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R7", [v["rule"] for v in violations])

    def test_project_ram_limit_triggers_r8(self):
        self.instance["project_ram_mb"] = 16384
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R8", [v["rule"] for v in violations])

    def test_project_vcpu_limit_triggers_r8(self):
        self.instance["project_vcpus"] = 16
        violations = check_instance(self.instance, self.policy)
        self.assertIn("R8", [v["rule"] for v in violations])


if __name__ == "__main__":
    unittest.main()
