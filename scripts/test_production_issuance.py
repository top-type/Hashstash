"""Normal-build issuance checks on an isolated, unfunded loopback network.

Uses only a published public mining key. No wallets, private keys or transactions
are created. Funded process tests use a different executable and configuration.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error

from monitor_rental_test import proof, issuance_totals
from test_stratum_wire import rpc

MINER = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def run(binary):
    checks, process = [], None
    report = {"passed": False, "test_work": False, "issuance_mode": "production",
              "expected_hashes_per_atom": str(10**15), "production_issuance_tested": True,
              "node_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "checks": checks}
    with tempfile.TemporaryDirectory(prefix="hashstash-production-issuance-") as name:
        directory = Path(name)
        config = directory / "network.json"
        initialized = subprocess.run([str(binary), "init", "--config", str(config), "--preset", "dev"],
                                     capture_output=True, text=True, encoding="utf-8", timeout=20)
        assert initialized.returncode == 0, initialized.stderr
        configuration = json.loads(config.read_text(encoding="utf-8"))
        assert configuration["test_work"] is False, "This suite requires the normal production build"
        assert configuration["share_scale"] == "1"
        checks.append("Normal build initializes production issuance and one-to-one opening share scale")
        accelerated = directory / "accelerated.json"
        accelerated.write_text(json.dumps(dict(configuration, test_work=True)), encoding="utf-8")
        refused = subprocess.run([str(binary), "network", "--config", str(accelerated)],
                                 capture_output=True, text=True, encoding="utf-8", timeout=20)
        assert refused.returncode != 0 and "test-fixtures" in refused.stderr
        checks.append("Normal build rejects an explicit accelerated-issuance configuration")
        configuration["network"] = "production-issuance-" + directory.name
        configuration["genesis_time"] = int(time.time()) - 1
        config.write_text(json.dumps(configuration), encoding="utf-8")
        reservations = [socket.socket() for _ in range(2)]
        for held in reservations:
            held.bind(("127.0.0.1", 0))
        rpc_port, peer_port = [held.getsockname()[1] for held in reservations]
        for held in reservations:
            held.close()
        command = [str(binary), "run", "--config", str(config), "--data", str(directory / "chain.sqlite"),
                   "--miner", MINER, "--rpc", f"127.0.0.1:{rpc_port}", "--p2p", f"127.0.0.1:{peer_port}",
                   "--no-stratum"]
        with (directory / "node.log").open("wb") as log:
            try:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                for _ in range(100):
                    assert process.poll() is None, "Isolated production node exited"
                    try:
                        initial = rpc(rpc_port, "status")
                        break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.1)
                else:
                    raise AssertionError("Isolated production node did not start")
                assert initial["height"] == 0 and initial["issued"] == "0"
                assert rpc(rpc_port, "config")["test_work"] is False
                assert "work_remainder" not in initial
                rpc(rpc_port, "mine", {"count": 3, "attempts": 1000000})
                final = rpc(rpc_port, "status")
                assert final["height"] == 3
                blocks = [dict(proof(rpc(rpc_port, "getblock", {"height": h})["header"]), height=h)
                          for h in range(1, 4)]
                assert all(b["proof_valid"] and 0 < int(b["expected_work_hash"]) < 10**15 for b in blocks)
                expected = issuance_totals(blocks, 10**15)
                assert expected["expected_issued_atoms"] == final["issued"] == "0"
                assert int(expected["physical_expected_work_hashes"]) > 0
                assert "work_remainder" not in final
                checks.append("Three valid low-work production blocks advance the chain while issuing zero atoms")
                checks.append("Physical expected work remains measurable and separate from monetary issuance")
                checks.append("No fractional-work remainder appears in status")
                report.update(blocks=blocks, totals=expected, final_height=final["height"], passed=True)
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                report["owned_process_stopped"] = process is None or process.poll() is not None
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    assert not args.report.exists(), "Do not overwrite evidence"
    report = run(args.binary.resolve(strict=True))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Production issuance: {len(report['checks'])} checks passed; owned node stopped")


if __name__ == "__main__":
    main()
