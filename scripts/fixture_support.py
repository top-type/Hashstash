"""Explicit metadata for accelerated, disposable integration-test networks.

This module never starts a process, mines, edits configuration, or funds accounts.
Production work accounting must not be inferred from a fast test's balances.
"""


def require_test_work(config):
    if config.get("test_work") is not True:
        raise ValueError("funded process audit requires an explicit test_work=true configuration and a test-fixtures build")
    return {"test_work": True, "issuance_mode": "accelerated test fixture",
            "expected_hashes_per_atom": "1", "production_issuance_tested": False}
