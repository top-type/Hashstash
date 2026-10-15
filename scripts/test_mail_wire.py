"""End-to-end mail wire test on one disposable localhost current-protocol chain.

Copies the supplied binary, uses published fixture private scalars, and never
opens an existing wallet/database/port. Local easy-PoW fixture mining is finite;
there is no cloud, rental, ASIC, faucet, service or external-network operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

REPO = Path(__file__).resolve().parents[1]
FLAGS = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def call(port, method, params=None):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/rpc", data=body,
                                    headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def run(args):
    source = args.binary.resolve(strict=True)
    vector = json.loads((REPO / "tests/fixtures/mail-v2.json").read_text(encoding="utf-8"))
    report = {"test": "isolated-mail-wire", "passed": False,
              "source_binary_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
              "private_keys": "published test fixture scalars only", "test_work": True, "issuance_mode": "accelerated test fixture", "expected_hashes_per_atom": "1", "production_issuance_tested": False, "checks": []}
    process = None

    def check(condition, label):
        assert condition, label
        report["checks"].append(label)

    with tempfile.TemporaryDirectory(prefix="hashstash-mail-wire-") as name:
        fixture = Path(name)
        binary = fixture / source.name
        shutil.copy2(source, binary)

        def cli(*items):
            result = subprocess.run([str(binary), *map(str, items)], capture_output=True, text=True,
                                    encoding="utf-8", timeout=30, creationflags=FLAGS)
            assert result.returncode == 0, result.stderr
            return result.stdout.strip()

        def browser(**request):
            result = subprocess.run([args.node, str(REPO / "scripts/mail_wire_crypto.cjs")],
                                    input=json.dumps(request), capture_output=True, text=True,
                                    encoding="utf-8", timeout=20, creationflags=FLAGS)
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        config = fixture / "network.json"
        cli("init", "--config", config, "--preset", "dev")
        configuration = json.loads(config.read_text(encoding="utf-8"))
        configuration["test_work"] = True
        configuration["network"] = "mail-wire-" + uuid.uuid4().hex
        save(config, configuration)
        sender, recipient = vector["identity"]["sender"], vector["identity"]["recipient"]
        key = fixture / "published-test-sender.json"
        save(key, {"secret": vector["private_keys"]["sender"], "public": sender})
        sender_address = cli("address", "--public-key", sender, "--config", config)
        recipient_address = cli("address", "--public-key", recipient, "--config", config)
        holders = [socket.socket() for _ in range(3)]
        try:
            for holder in holders:
                holder.bind(("127.0.0.1", 0))
            private_port, peer_port, public_port = [holder.getsockname()[1] for holder in holders]
        finally:
            for holder in holders:
                holder.close()
        stdout_path, stderr_path = fixture / "stdout.log", fixture / "stderr.log"
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open("w", encoding="utf-8") as stderr:
            try:
                process = subprocess.Popen([str(binary), "run", "--config", str(config),
                    "--data", str(fixture / "chain.sqlite"), "--miner", sender,
                    "--rpc", f"127.0.0.1:{private_port}", "--p2p", f"127.0.0.1:{peer_port}",
                    "--public-web", f"127.0.0.1:{public_port}", "--no-stratum"],
                    stdout=stdout, stderr=stderr, creationflags=FLAGS)
                deadline = time.monotonic() + 30
                while True:
                    assert process.poll() is None, "Isolated node failed to start"
                    try:
                        status = call(private_port, "status")
                        break
                    except (OSError, RuntimeError):
                        assert time.monotonic() < deadline, "Isolated node startup timed out"
                        time.sleep(0.05)
                report["chain_id"] = status["chain_id"]
                check(call(private_port, "mining")["stratum"]["enabled"] is False,
                      "Fixture node has no external mining listener")
                with urllib.request.urlopen(f"http://127.0.0.1:{public_port}/api/session", timeout=10) as response:
                    session = json.load(response)
                check(session.get("public_web") is True and not session.get("token"),
                      "Public browser session contains no private signing token")
                call(private_port, "mine", {"count": 8, "attempts": 10000})
                account = call(public_port, "account", {"key": sender})["account"]
                identity = {"chain_id": status["chain_id"], "sender": sender, "recipient": recipient,
                            "nonce": str(account["nonce"])}
                plaintext = {"subject": "Real signed mail", "body": "A fixture message crossed the complete transaction path.\nUnicode: café 冰"}
                data = browser(mode="encrypt", identity=identity, plaintext=plaintext)["data_hex"]
                check(data != vector["data_hex"], "Browser encrypts using this fresh chain identity")
                operation = fixture / "operation.json"
                save(operation, {"TransferExact": {"recipient": sender_address, "amount": "1"}})
                # The administrative CLI uses submittransaction; the browser's
                # public surface intentionally exposes only signed-hex broadcast.
                sent = json.loads(cli("send", "--url", f"http://127.0.0.1:{private_port}/rpc", "--key", key,
                    "--operation-file", operation, "--data-hex", data, "--nonce", identity["nonce"], "--expiry-blocks", "2"))
                txid = sent.get("transaction_id") or sent.get("txid")
                check(isinstance(txid, str) and len(txid) == 64, "Actual CLI signs and broadcasts the ordinary data transfer")
                report["txid"] = txid
                feed = call(public_port, "explorer_mail", {"limit": 20})
                check(not feed["messages"], "The common feed contains only confirmed mail")
                call(private_port, "mine", {"count": 2, "attempts": 10000})
                feed = call(public_port, "explorer_mail", {"limit": 20})
                messages = [entry for entry in feed["messages"] if entry["txid"] == txid]
                check(len(messages) == 1, "Global canonical mail contains the self-transfer exactly once")
                entry = messages[0]
                check(entry["confirmations"] >= 2 and entry["data_hex"] == data,
                      "Canonical index has real confirmations and exact signed data")
                check("recipient" not in entry and "recipient_public_key" not in entry,
                      "Global discovery has no recipient identifier")
                check(recipient not in json.dumps(entry) and recipient_address not in json.dumps(entry),
                      "Recipient is absent from public message record")
                bound = {"chain_id": status["chain_id"], "sender": entry["sender_public_key"], "nonce": entry["nonce"]}
                for role in ["sender", "recipient"]:
                    check(browser(mode="decrypt", identity=bound, data_hex=entry["data_hex"],
                                  private_key=vector["private_keys"][role]) == {"recipient": recipient, **plaintext},
                          f"{role.title()} browser discovers and decrypts the actual canonical payload")
                continued = call(public_port, "explorer_mail", {"limit":20, "after":feed["scan_cursor"], "anchor":feed["tip"]})
                check(not continued["messages"], "Incremental feed does not repeat scanned mail")
                try:
                    call(public_port, "explorer_mail", {"address": recipient_address})
                    raise AssertionError("address filtering was accepted")
                except RuntimeError:
                    check(True, "Public inbox rejects account-specific discovery")
                try:
                    recipient_account = call(public_port, "account", {"key": recipient}).get("account")
                    check(not recipient_account or recipient_account.get("ordinary", "0") == "0",
                          "Sending mail transfers no value to the hidden recipient")
                except RuntimeError as error:
                    check("account does not exist" in str(error),
                          "Sending mail creates no on-chain recipient account")
                check(call(private_port, "status")["height"] == 10, "Finite fixture mining ends at height ten")
                report["passed"] = True
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                report["owned_process_stopped"] = process is None or process.poll() is not None
                if not report["passed"]:
                    stderr.flush()
                    report["fixture_error_tail"] = stderr_path.read_text(encoding="utf-8", errors="replace")[-2000:]
                if args.report:
                    args.report.parent.mkdir(parents=True, exist_ok=True)
                    save(args.report, report)
    print(f"{len(report['checks'])} real mail wire checks passed; disposable node stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--report", type=Path)
    run(parser.parse_args())
