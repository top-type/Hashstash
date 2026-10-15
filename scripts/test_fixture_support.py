"""Fixture issuance must be explicitly chosen, never inferred from an easy target."""
import unittest
from fixture_support import require_test_work


class FixtureModeTests(unittest.TestCase):
    def test_funded_audits_require_explicit_boolean_fixture_mode(self):
        for config in ({}, {"test_work": False}, {"test_work": 1}, {"test_work": "true"}):
            with self.assertRaises(ValueError):
                require_test_work(config)
        self.assertEqual(require_test_work({"test_work": True}), {
            "test_work": True, "issuance_mode": "accelerated test fixture",
            "expected_hashes_per_atom": "1", "production_issuance_tested": False})
