#!/usr/bin/env python3
"""Independent stdlib Stratum worker against the packaged Hashstash executable.

Runs only its own temporary v28 network on ephemeral loopback ports. Header,
coinbase, transaction-commitment, and SHA256d calculations are Python code; no
node template/hash/mining RPC is used. The CLI signs one transfer using the
publicly known secp256k1 scalar-one test fixture. Never fund that test key.
"""

import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid


ROOT = Path(__file__).resolve().parents[1]
U256 = (1 << 256) - 1
VERSION_MASK = 0x1FFFE000
MINER = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
RECIPIENT = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
ASSERTIONS = 0


def check(condition, message):
    global ASSERTIONS
    ASSERTIONS += 1
    if not condition:
        raise AssertionError(message)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def target(bits):
    exponent, mantissa = bits >> 24, bits & 0x7FFFFF
    check(not bits & 0x800000 and mantissa != 0, "positive compact target")
    return mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))


def share_target(difficulty):
    numerator, denominator = float(difficulty).as_integer_ratio()
    return min(U256, target(0x1D00FFFF) * denominator // numerator)


def compact_uint(value):
    """Independent bincode 1 unsigned varint encoder for protocol 28."""
    check(type(value) is int and 0 <= value < 1 << 64, "bounded unsigned wire integer")
    if value <= 250:
        return bytes([value])
    for tag, width in ((251, 2), (252, 4), (253, 8)):
        if value < 1 << (8 * width):
            return bytes([tag]) + value.to_bytes(width, "little")
    raise AssertionError("unreachable unsigned integer")


def vector(data):
    return compact_uint(len(data)) + data


def amount(value):
    number = int(value)
    check(number >= 0, "nonnegative amount")
    return vector(number.to_bytes((number.bit_length() + 7) // 8, "little"))


def transaction_bytes(tx):
    """Current protocol direct transfer and raw data, independently reconstructed."""
    body = tx["body"]
    transfer = body["operation"]["TransferExact"]
    return (bytes(body["chain_id"]) + bytes(body["sender"])
            + compact_uint(body["nonce"]) + amount(body["fee"])
            + compact_uint(body["expiry_height"]) + compact_uint(0)
            + bytes(transfer["recipient"]) + amount(transfer["amount"])
            + vector(bytes(body["data"])) + bytes(tx["signature"]))


def commitment(block):
    transactions = block["transactions"]
    data = compact_uint(len(transactions))
    data += b"".join(transaction_bytes(tx) for tx in transactions)
    data += bytes(block["state_root"])
    tag = hashlib.sha256(b"Hashstash/block-commitment/v26").digest()
    return hashlib.sha256(tag + tag + data).digest()


def previous_hash(job):
    raw = bytes.fromhex(job["params"][1])
    return b"".join(raw[n:n + 4][::-1] for n in range(0, 32, 4))


def candidate(job, extra1, extra2, ntime, rolling, nonce=0):
    p = job["params"]
    coinbase = bytes.fromhex(p[2]) + extra1 + extra2 + bytes.fromhex(p[3])
    root = sha256d(coinbase)
    for sibling in p[4]:
        root = sha256d(root + bytes.fromhex(sibling))
    version = (int(p[5], 16) & ~VERSION_MASK) | rolling
    header = (struct.pack("<I", version) + previous_hash(job) + root
              + struct.pack("<III", ntime, int(p[6], 16), nonce))
    check(len(header) == 80, "Bitcoin header is exactly 80 bytes")
    return {"header": header, "coinbase": coinbase, "extra2": extra2,
            "ntime": ntime, "rolling": rolling, "nonce": nonce}


def solve(work, accept, maximum=2_000_000):
    start = time.monotonic()
    prefix = work["header"][:76]
    for nonce in range(maximum):
        header = prefix + struct.pack("<I", nonce)
        digest = sha256d(header)
        if accept(int.from_bytes(digest, "little")):
            return dict(work, header=header, nonce=nonce, digest=digest,
                        attempts=nonce + 1, elapsed_seconds=round(time.monotonic() - start, 4))
    raise AssertionError("bounded independent nonce search exhausted")


def header_bytes(header):
    return (struct.pack("<I", header["version"]) + bytes(header["previous"])
            + bytes(header["merkle_root"])
            + struct.pack("<III", header["timestamp"], header["bits"], header["nonce"]))


def inspect_coinbase(raw, height, extra):
    """Parse the actual Bitcoin transaction framing, not just search for HST6."""
    offset = 0

    def take(count):
        nonlocal offset
        result = raw[offset:offset + count]
        offset += count
        check(len(result) == count, "complete coinbase field")
        return result

    def compact_size():
        first = take(1)[0]
        return first if first < 253 else int.from_bytes(take({253: 2, 254: 4, 255: 8}[first]), "little")

    check(take(4) == struct.pack("<I", 1), "Bitcoin coinbase version")
    check(compact_size() == 1, "one coinbase input")
    check(take(32) == bytes(32) and take(4) == b"\xff" * 4, "coinbase null outpoint")
    script = take(compact_size())
    check(script == bytes([0x50 + height, 8]) + extra, "coinbase height and 4+4 extranonce")
    check(take(4) == b"\xff" * 4, "coinbase sequence")
    check(compact_size() == 1 and take(8) == bytes(8), "one zero-value output")
    output = take(compact_size())
    check(len(output) == 70 and output[:6] == b"\x6a\x44HST6", "HST6 OP_RETURN framing")
    check(output[6:38].hex() == MINER, "authenticated configured payout key")
    check(take(4) == bytes(4) and offset == len(raw), "coinbase locktime and no trailing bytes")
    return output[38:70]


class Worker:
    def __init__(self, port):
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=8)
        self.stream = self.socket.makefile("rb")
        self.pending = collections.deque()
        self.request_id = 0
        self.last_request = 0
        self.latest_difficulty = None
        self.last_notice = None
        self.notify_count = 0

    def close(self):
        self.stream.close()
        self.socket.close()

    def read(self):
        raw = self.stream.readline(65537)
        check(bool(raw) and len(raw) <= 65536 and raw.endswith(b"\n"), "bounded complete Stratum line")
        message = json.loads(raw)
        method = message.get("method")
        if method == "mining.set_difficulty":
            self.latest_difficulty = message["params"][0]
        elif method == "mining.notify":
            check(self.last_notice == "mining.set_difficulty", "set_difficulty precedes every notify")
            check(self.latest_difficulty > 0, "positive assigned difficulty")
            message["difficulty"] = self.latest_difficulty
            self.notify_count += 1
        if method:
            self.last_notice = method
        return message

    def call(self, method, params):
        time.sleep(max(0, 0.15 - (time.monotonic() - self.last_request)))
        self.request_id += 1
        self.last_request = time.monotonic()
        self.socket.sendall((json.dumps({"id": self.request_id, "method": method, "params": params}) + "\n").encode())
        while True:
            message = self.read()
            if message.get("id") == self.request_id:
                return message
            self.pending.append(message)

    def job(self, predicate=lambda _job: True):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            message = self.pending.popleft() if self.pending else self.read()
            if message.get("method") == "mining.notify" and predicate(message):
                check(len(message["params"]) == 9, "standard nine-field notify")
                check(message["params"][4] == [], "compact protocol uses empty Merkle branch")
                return message
        raise AssertionError("expected mining job was not received")

    def submit(self, job, work):
        return self.call("mining.submit", ["wire.worker", job["params"][0], work["extra2"].hex(),
                                          f"{work['ntime']:08x}", f"{work['nonce']:08x}", f"{work['rolling']:08x}"])


def rpc(port, method, params=None):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/rpc", data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=8) as response:
        result = json.load(response)
    check("error" not in result or result["error"] is None, f"RPC {method} succeeds")
    return result["result"]


def cli(executable, *arguments):
    result = subprocess.run([str(executable), *map(str, arguments)], capture_output=True,
                            text=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    check(result.returncode == 0, "packaged CLI command succeeds: " + result.stderr.strip())
    return result.stdout.strip()


def success(result, label):
    check(result.get("result") is True and result.get("error") is None, label)


def rejection(result, code, label):
    check(result.get("result") is None and result.get("error", [None])[0] == code, label)


def verify_block(port, height, job, work, extra1):
    block = rpc(port, "getblock", {"height": height})
    check(header_bytes(block["header"]) == work["header"], "stored header exactly matches independent wire header")
    check(bytes(block["extranonce"]) == extra1 + work["extra2"], "stored extranonce matches worker bytes")
    check(bytes(block["miner"]).hex() == MINER, "stored miner matches configured payout")
    check(sha256d(work["coinbase"]) == bytes(block["header"]["merkle_root"]), "coinbase SHA256d is sole Merkle root")
    combined = inspect_coinbase(work["coinbase"], height, extra1 + work["extra2"])
    check(combined == commitment(block), "independent HST6 commitment binds stored transactions and state")
    status = rpc(port, "status")
    check(status["height"] == height and status["tip"] == work["digest"].hex(), "RPC tip equals independently hashed header")
    expected_work = (1 << 256) // (target(int(job["params"][6], 16)) + 1)
    return block, status, expected_work


def run(executable):
    started = time.monotonic()
    report = {"schema": "hashstash-stratum-wire-check-v1", "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "running", "method": "independent Python standard-library Stratum V1 client",
              "executable_version": cli(executable, "--version"),
              "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
              "scope": "isolated ephemeral localhost v28 network; no physical ASIC or external rental tested"}
    with tempfile.TemporaryDirectory(prefix="hashstash-stratum-wire-") as directory:
        temporary = Path(directory)
        config = json.loads((ROOT / "config" / "devnet.json").read_text(encoding="utf-8"))
        config["network"] = "stratum-wire-" + uuid.uuid4().hex
        config["genesis_time"] = int(time.time()) - 1
        config["initial_bits"] = config["limit_bits"] = 0x1F0FFFFF
        check(config["protocol_version"] == 28, "test runs current protocol v28")
        config_path, key_path = temporary / "network.json", temporary / "public-test-fixture.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        # Scalar one is a published, non-secret fixture; it never leaves this temporary test network.
        key_path.write_text(json.dumps({"secret": "0" * 63 + "1", "public": MINER}), encoding="utf-8")
        reservations = [socket.socket() for _ in range(3)]
        for reservation in reservations:
            reservation.bind(("127.0.0.1", 0))
        rpc_port, peer_port, stratum_port = [reservation.getsockname()[1] for reservation in reservations]
        for reservation in reservations:
            reservation.close()
        command = [str(executable), "run", "--config", str(config_path), "--data", str(temporary / "chain.sqlite"),
                   "--miner", MINER, "--rpc", f"127.0.0.1:{rpc_port}", "--p2p", f"127.0.0.1:{peer_port}",
                   "--stratum", f"127.0.0.1:{stratum_port}", "--stratum-share-difficulty", "1e-12"]
        process, worker = None, None
        with (temporary / "node.log").open("wb") as log:
            def start_node():
                nonlocal process
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                for _ in range(80):
                    if process.poll() is not None:
                        raise AssertionError("isolated node exited during startup")
                    try:
                        return process, rpc(rpc_port, "status")
                    except (urllib.error.URLError, TimeoutError, ConnectionError):
                        time.sleep(0.1)
                process.terminate()
                process.wait(timeout=10)
                raise AssertionError("isolated node startup timed out")

            try:
                process, initial = start_node()
                check(initial["height"] == 0 and initial["issued"] == "0", "fresh isolated chain")
                worker = Worker(stratum_port)
                configure = worker.call("mining.configure", [["version-rolling", "minimum-difficulty"],
                    {"version-rolling.mask": "1fffe000", "version-rolling.min-bit-count": 1,
                     "minimum-difficulty.value": 0}])
                check(configure["result"]["version-rolling"] is True
                      and configure["result"]["version-rolling.mask"] == "1fffe000"
                      and configure["result"]["minimum-difficulty"] is True, "BIP310 negotiation")
                subscribed = worker.call("mining.subscribe", ["python-stdlib-wire/1"])
                extra1 = bytes.fromhex(subscribed["result"][1])
                check(len(extra1) == 4 and subscribed["result"][2] == 4, "4-byte server and worker extranonces")
                success(worker.call("mining.authorize", ["wire.worker", "x"]), "authorize worker")
                first = worker.job()
                check(first["params"][8] is True, "initial clean job")
                block_target = target(int(first["params"][6], 16))
                initial_share_target = share_target(first["difficulty"])
                check(initial_share_target > block_target, "share target is easier than consensus target")
                first_time = int(first["params"][7], 16)
                accepted_before = rpc(rpc_port, "mining")["accepted_shares"]
                for extra, invalid_time, label in (("a0a1a2a3", 0, "past"),
                                                    ("b0b1b2b3", 0xFFFFFFFF, "future")):
                    invalid = solve(candidate(first, extra1, bytes.fromhex(extra), invalid_time, 0x2000),
                                    lambda value: value <= block_target)
                    rejection(worker.submit(first, invalid), 20, f"{label} timestamp rejected despite valid block work")
                check(rpc(rpc_port, "status")["height"] == 0, "invalid timestamps create no blocks")
                check(rpc(rpc_port, "mining")["accepted_shares"] == accepted_before,
                      "invalid timestamp work does not count as accepted shares")
                nonblock = solve(candidate(first, extra1, bytes.fromhex("00010203"), first_time, 0x2000),
                                 lambda value: block_target < value <= initial_share_target)
                success(worker.submit(first, nonblock), "accept non-block reporting share")
                check(rpc(rpc_port, "status")["height"] == 0, "reporting share creates no block")
                check(rpc(rpc_port, "status")["issued"] == "0", "reporting share creates no HASH")
                rejection(worker.submit(first, nonblock), 22, "duplicate share rejected")
                malformed = worker.call("mining.submit", ["wire.worker", first["params"][0], "00", "00000000", "00000000", "00002000"])
                rejection(malformed, 20, "malformed extranonce rejected")
                rejection(worker.call("mining.submit", ["wire.worker", "missing-job", "00010203", "00000000", "00000000", "00002000"]),
                          21, "unknown job rejected")
                # 1e-12 saturates the share target; raise it to exercise low-difficulty rejection.
                success(worker.call("mining.suggest_difficulty", [1e-8]), "change reporting difficulty")
                harder = worker.job(lambda job: job["params"][0] != first["params"][0])
                assigned_target = share_target(harder["difficulty"])
                harder_time = int(harder["params"][7], 16)
                check(block_target < assigned_target < U256, "non-saturating reporting target remains easier than blocks")
                bad = solve(candidate(harder, extra1, bytes.fromhex("04050607"), harder_time, 0x2000), lambda value: value > assigned_target)
                rejection(worker.submit(harder, bad), 23, "low-difficulty share rejected")
                ordinary_share = solve(candidate(harder, extra1, bytes.fromhex("08090a0b"), harder_time, 0x2000),
                                       lambda value: block_target < value <= assigned_target)
                success(worker.submit(harder, ordinary_share), "accept non-block share at non-saturating target")
                block_one_work = solve(candidate(harder, extra1, bytes.fromhex("10111213"), harder_time, 0x2000), lambda value: value <= block_target)
                success(worker.submit(harder, block_one_work), "accept independently mined first block")
                block_one, status_one, work_one = verify_block(rpc_port, 1, harder, block_one_work, extra1)
                check(status_one["issued"] == str(work_one), "first subsidy equals exact expected hashes")
                check(rpc(rpc_port, "account", {"key": MINER})["account"]["ordinary"] == str(work_one), "full subsidy paid to configured miner")
                check(block_one["transactions"] == [], "first block has no user transactions")
                second = worker.job(lambda job: previous_hash(job) == block_one_work["digest"])
                check(second["params"][8] is True, "new parent causes clean work switch")
                stale_share = solve(candidate(harder, extra1, bytes.fromhex("14151617"), harder_time, 0x2000),
                                    lambda value: block_target < value <= assigned_target)
                rejection(worker.submit(harder, stale_share), 21, "non-block share from old parent rejected")
                stale_block = solve(candidate(harder, extra1, bytes.fromhex("18191a1b"), harder_time, 0x2000),
                                    lambda value: value <= block_target)
                rejection(worker.submit(harder, stale_block), 21, "valid block work from old parent is not accepted as a rewarded proof")
                check(rpc(rpc_port, "status")["issued"] == str(work_one), "losing block work mints no additional HASH")
                mining = rpc(rpc_port, "mining")
                check("uncle_reward_split" not in mining and "stale_target_bps" not in mining,
                      "current mining status exposes no stale reward or stale-target controls")
                data = bytes(range(256))
                sent = json.loads(cli(executable, "transfer", "--url", f"http://127.0.0.1:{rpc_port}/rpc", "--key", key_path,
                                      "--recipient", RECIPIENT, "--amount", "7", "--extra-fee", "3", "--data-hex", data.hex()))
                check(bool(sent), "CLI signs and submits data transfer")
                transaction_job = worker.job(lambda job: previous_hash(job) == block_one_work["digest"]
                                             and job["params"][3] != second["params"][3])
                check(transaction_job["params"][8] is False, "same-parent transaction refresh retains old jobs")
                rolled_time = int(transaction_job["params"][7], 16) + 1
                a = candidate(transaction_job, extra1, bytes.fromhex("20212223"), rolled_time, 0x4000)
                b = candidate(transaction_job, extra1, bytes.fromhex("24252627"), rolled_time, 0x4000)
                check(a["header"][36:68] != b["header"][36:68], "extranonce rolling expands Merkle work space")
                block_two_target = target(int(transaction_job["params"][6], 16))
                block_two_work = solve(b, lambda value: value <= block_two_target)
                success(worker.submit(transaction_job, block_two_work), "accept rolled nTime/version/extranonce block with transaction")
                block_two, status_two, work_two = verify_block(rpc_port, 2, transaction_job, block_two_work, extra1)
                check(len(block_two["transactions"]) == 1, "signed transfer persisted once")
                tx = block_two["transactions"][0]
                check(bytes(tx["body"]["data"]) == data, "all 256 raw data bytes preserved")
                check(len(tx["signature"]) == 64, "BIP340 signature persisted")
                encoded_tx = transaction_bytes(tx)
                mandatory_fee = (len(encoded_tx) + 1024 + 1023) // 1024
                check(int(tx["body"]["fee"]) == mandatory_fee + 3, "independent encoded bytes plus creation weight sets exact fee")
                check(status_two["issued"] == str(work_one + work_two), "only expected-work subsidies issue HASH")
                percent = config["initial"]["miner_fee_percent"]
                miner_fee = (mandatory_fee + 3) * percent // 100
                revenue_fee = mandatory_fee + 3 - miner_fee
                check(status_two["revenue"] == str(revenue_fee), "complete charged fee splits with rounding retained by Revenue")
                recipient = rpc(rpc_port, "account", {"key": RECIPIENT})["account"]
                miner = rpc(rpc_port, "account", {"key": MINER})["account"]
                check(recipient["ordinary"] == "7", "recipient receives exact amount")
                expected_before_reward = work_one - 7 - mandatory_fee - 3
                check(int(miner["ordinary"]) - expected_before_reward == work_two + miner_fee, "miner receives exact subsidy plus governed share of entire fee")
                third = worker.job(lambda job: previous_hash(job) == block_two_work["digest"])
                check(third["params"][8] is True, "second clean work switch")
                check(block_one["header"]["timestamp"] == harder_time
                      and block_two["header"]["timestamp"] == rolled_time,
                      "valid job timestamps and bounded nTime rolling reach stored headers")
                check(block_one["header"]["version"] != block_two["header"]["version"], "negotiated version rolling reaches stored headers")
                telemetry = rpc(rpc_port, "mining")
                report.update({"protocol_version": config["protocol_version"], "block_target_bits": "1f0fffff", "reporting_difficulties": [first["difficulty"], harder["difficulty"]],
                               "blocks": [{"height": 1, "hash": block_one_work["digest"].hex(), "expected_work_hash": str(work_one),
                                           "nonce_attempts": block_one_work["attempts"]},
                                          {"height": 2, "hash": block_two_work["digest"].hex(), "expected_work_hash": str(work_two),
                                           "nonce_attempts": block_two_work["attempts"]}],
                               "transaction_data_bytes": len(data), "signed_transaction_bytes": len(encoded_tx),
                               "mandatory_fee_hash": str(mandatory_fee), "optional_extra_hash": "3",
                               "miner_fee_hash": str(miner_fee), "revenue_fee_hash": str(revenue_fee), "miner_fee_percent": percent,
                               "notify_messages_checked": worker.notify_count})
                check(int(telemetry["accepted_shares"]) >= 4, "mining telemetry counts accepted work")
                worker.close()
                worker = None
                process.terminate()
                process.wait(timeout=10)
                process, restored = start_node()
                check(restored["tip"] == status_two["tip"] and restored["state_root"] == status_two["state_root"], "database replay restores exact tip and state")
                check(rpc(rpc_port, "getblock", {"height": 2}) == block_two, "stored header and signed data survive process restart")
                report["checks"] = ["subscribe_authorize", "BIP310_version_rolling", "difficulty_before_notify", "4_plus_4_extranonce",
                    "Bitcoin_coinbase_HST6_empty_branch", "independent_80_byte_header_SHA256d", "non_block_reporting_shares",
                    "low_difficulty_rejected", "malformed_submit_rejected", "unknown_job_rejected", "duplicate_rejected",
                    "exact_expected_work_subsidy", "configured_payout", "timestamp_past_future_rejected", "bounded_nTime_rolling", "extranonce_and_version_rolling",
                    "clean_work_switch", "old_parent_nonblock_rejected", "old_parent_block_rejected_without_issuance",
                    "no_stale_reward_controls", "signed_arbitrary_data_transfer",
                    "independent_HST6_commitment", "governed_total_fee_payout", "database_restart_persistence"]
                report.update(status="passed", assertions=ASSERTIONS, elapsed_seconds=round(time.monotonic() - started, 3))
                return report
            finally:
                if worker is not None:
                    worker.close()
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, default=ROOT / "target" / "release" / ("hashstash.exe" if os.name == "nt" else "hashstash"))
    parser.add_argument("--report", type=Path, default=ROOT / "work" / "stratum-wire-check.json")
    options = parser.parse_args()
    report = run(options.executable.resolve())
    options.report.parent.mkdir(parents=True, exist_ok=True)
    options.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Stratum wire: {report['assertions']} assertions passed; {len(report['checks'])} checks; {report['elapsed_seconds']} seconds.")
    print(f"Report: {options.report}")


if __name__ == "__main__":
    main()
