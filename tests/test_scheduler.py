import unittest
from unittest.mock import Mock

from guardrail.scheduler import GuardrailScheduler


class TestGuardrailScheduler(unittest.TestCase):

    def setUp(self):
        self.controller = Mock()
        self.controller.policy = {
            "scan_interval_seconds": 300
        }

        self.scheduler = GuardrailScheduler(
            controller=self.controller
        )

    def test_interval_configuration(self):
        self.assertEqual(self.scheduler.interval, 300)

    def test_run_once(self):
        self.controller.scan.return_value = {
            "scan_id": 1,
            "status": "completed",
            "instances_checked": 3,
            "violations_found": 2,
        }

        result = self.scheduler.run_once()

        self.assertEqual(result["status"], "completed")
        self.controller.scan.assert_called_once()

    def test_run_once_handles_exception(self):
        self.controller.scan.side_effect = RuntimeError(
            "Test error"
        )

        result = self.scheduler.run_once()

        self.assertIsNone(result)
        self.controller.scan.assert_called_once()

    def test_stop(self):
        self.scheduler.stop()

        self.assertTrue(self.scheduler.stop_event.is_set())

    def test_invalid_interval(self):
        self.controller.policy = {
            "scan_interval_seconds": 0
        }

        with self.assertRaises(ValueError):
            GuardrailScheduler(self.controller)


if __name__ == "__main__":
    unittest.main()
