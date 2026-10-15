"""Isolated regression checks for rental evidence; no nodes or miners are started."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import monitor_rental_test as monitor


def manifest(count=3, independent=True):
    return {
        "format": "hashstash-rental-test-v1", "chain_id": "test-chain", "expected_hashrate": "1T",
        "initial_bits": 0x207FFFFF,
        "executable_sha256": "test-binary", "public_key": "01" * 32, "software_mining": False,
        "mining": {"advertise": "", "password_file": "must-not-read"},
        "nodes": [dict({"name": f"region-{index}", "rpc_port": 20480 + index * 10,
                        "stratum_port": 20482 + index * 10},
                       **({"public_key": f"{index + 1:02x}" * 32,
                           "mining": {"advertise": f"stratum+tcp://region-{index}.invalid:3333"}}
                          if independent else {})) for index in range(count)],
    }


class RentalMonitorTests(unittest.TestCase):
    def capture(self, selected, change=None, prior=None):
        calls = []

        def rpc(port, method, params=None):
            calls.append((port, method, params))
            node = next(node for node in selected["nodes"] if node["rpc_port"] == port)
            key = monitor.payout_key(selected, node)
            if method == "peers":
                return {"connected": 2}
            if method == "getblock":
                self.assertEqual(params, {"height": 0})
                return {"header": {"version": 1, "previous": [0] * 32, "merkle_root": [0] * 32,
                                   "timestamp": 0, "bits": selected["initial_bits"], "nonce": 0}}
            self.assertEqual(method, "snapshot")
            self.assertEqual(params, {"key": key})
            value = {"status": {"chain_id": selected["chain_id"], "height": 0, "tip": "genesis",
                                "state_root": "root", "issued": "0", "protocol_version": 26,
                                "settings": {"interval": 15}},
                     "mining": {"payout_public_key": key, "accepted_shares": "7", "blocks_found": "0"},
                     "account": {"public_key": key, "ordinary": str(port)}}
            if change:
                change(node, value)
            return value

        with tempfile.TemporaryDirectory(prefix="hashstash-monitor-test-") as directory:
            path = Path(directory) / "manifest.json"
            output = Path(directory) / "evidence.json"
            path.write_text(json.dumps(selected), encoding="utf-8")
            if prior:
                output.write_text(json.dumps(prior), encoding="utf-8")
            with patch.object(monitor, "rpc", rpc), patch("sys.argv", ["monitor", "--manifest", str(path)]), contextlib.redirect_stdout(io.StringIO()):
                monitor.main()
            return json.loads(output.read_text(encoding="utf-8")), calls

    def test_three_independent_payouts_and_read_only_provenance(self):
        report, calls = self.capture(manifest())
        sample = report["samples"][-1]
        self.assertTrue(sample["peers_match"])
        self.assertTrue(sample["complete_issuance_history_checked"])
        self.assertTrue(sample["issuance_matches_expected_work"])
        self.assertEqual(len({node["payout_public_key"] for node in sample["nodes"]}), 3)
        self.assertEqual(len({node["mining_account"]["ordinary"] for node in sample["nodes"]}), 3)
        self.assertEqual({call[0] for call in calls}, {20480, 20490, 20500})
        self.assertEqual({call[1] for call in calls}, {"snapshot", "peers", "getblock"})
        self.assertFalse(report["provenance"]["monitor_submits_work"])
        self.assertFalse(report["provenance"]["mining_source_independently_verified"])
        self.assertTrue(all(node["declared_software_mining"] is False for node in report["monitored_nodes"]))
        self.assertNotIn("must-not-read", json.dumps(report))
        self.assertEqual(report["errors"], [])

    def test_shared_payout_and_resumed_three_node_capture(self):
        report, _ = self.capture(manifest(count=2, independent=False))
        self.assertTrue(report["samples"][0]["peers_match"])
        self.assertEqual({node["payout_public_key"] for node in report["samples"][0]["nodes"]}, {"01" * 32})
        resumed, _ = self.capture(manifest(), prior=report)
        self.assertEqual([len(sample["nodes"]) for sample in resumed["samples"]], [2, 3])
        self.assertTrue(resumed["samples"][-1]["peers_match"])
        self.assertEqual(len(resumed["runs"][-1]["nodes"]), 3)

    def test_one_divergent_node_cannot_report_agreement(self):
        report, _ = self.capture(manifest(), lambda node, value: value["status"].update(state_root="other") if node["name"] == "region-2" else None)
        self.assertFalse(report["samples"][-1]["peers_match"])

    def test_wrong_payout_or_chain_cannot_report_agreement(self):
        for field in ("payout", "chain"):
            with self.subTest(field=field):
                def corrupt(node, value):
                    if node["name"] == "region-1":
                        if field == "payout":
                            value["mining"]["payout_public_key"] = "ff" * 32
                        else:
                            value["status"]["chain_id"] = "another-chain"
                report, _ = self.capture(manifest(), corrupt)
                self.assertFalse(report["samples"][-1]["peers_match"])
                self.assertIn("error", report["samples"][-1]["nodes"][1])
                self.assertEqual(len(report["errors"]), 1)

    def test_invalid_manifest_rejected_before_requests(self):
        for change in (
            lambda value: value["nodes"][1].update(name="region-0"),
            lambda value: value["nodes"][1].update(rpc_port=20480),
            lambda value: value["nodes"][1].update(rpc_port=65536),
            lambda value: value["nodes"][1].update(public_key="not-a-key"),
            lambda value: value.update(nodes=value["nodes"][:1]),
        ):
            value = copy.deepcopy(manifest())
            change(value)
            with self.assertRaises(ValueError):
                monitor.validate_manifest(value)


if __name__ == "__main__":
    unittest.main()
