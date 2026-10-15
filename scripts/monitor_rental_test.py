#!/usr/bin/env python3
"""Read-only evidence capture for local or SSH-forwarded rental networks; never mines.

Example: python scripts/monitor_rental_test.py --manifest PATH --samples 60 --interval 10
Writes evidence.json beside the selected manifest unless --output is supplied.
Only loopback JSON-RPC snapshot, peers, and getblock methods are used.
Regional nodes may supply their own public_key and mining.advertise fields;
otherwise the original shared manifest values apply.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import urllib.request
import urllib.parse

LAST_RPC = 0.0


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def payout_key(manifest, node):
    key = node.get("public_key", manifest.get("public_key", ""))
    if not isinstance(key, str) or len(key) != 64:
        raise ValueError("each node requires a 32-byte payout public key")
    try:
        if len(bytes.fromhex(key)) != 32:
            raise ValueError()
    except ValueError:
        raise ValueError("each node requires a 32-byte payout public key") from None
    return key.lower()


def validate_manifest(manifest):
    nodes = manifest.get("nodes", [])
    if manifest.get("format") != "hashstash-rental-test-v1" or not isinstance(nodes, list) or len(nodes) < 2:
        raise ValueError("unsupported rental manifest: at least two nodes required")
    names, ports = set(), set()
    for node in nodes:
        name, port = node.get("name"), node.get("rpc_port")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("rental node names must be nonempty and unique")
        if type(port) is not int or not 1 <= port <= 65535 or port in ports:
            raise ValueError("rental RPC ports must be valid and unique loopback ports")
        payout_key(manifest, node)
        names.add(name)
        ports.add(port)


def node_metadata(manifest, node):
    mining = dict(manifest.get("mining", {}), **node.get("mining", {}))
    # Deliberately select public fields; manifests can also contain credential paths.
    return {"name": node["name"], "rpc_port": node["rpc_port"],
            "payout_public_key": payout_key(manifest, node),
            "public_endpoint": mining.get("advertise") or None,
            "executable_sha256": node.get("executable_sha256", manifest.get("executable_sha256")),
            "declared_software_mining": node.get("software_mining", manifest.get("software_mining"))}


def relay_metadata(manifest_path, manifest):
    path = manifest_path.parent / "relay.json"
    if not path.exists():
        return None
    relay = json.loads(path.read_text(encoding="utf-8-sig"))
    expected = f"127.0.0.1:{manifest['nodes'][0]['stratum_port']}"
    if relay.get("destination") != expected:
        raise ValueError("recorded relay destination differs from selected rental network")
    parsed = urllib.parse.urlparse(relay.get("endpoint", ""))
    if parsed.scheme != "stratum+tcp" or not parsed.hostname or not parsed.port:
        raise ValueError("recorded relay endpoint is invalid")
    return {"provider": relay.get("provider"), "endpoint": relay["endpoint"],
            "destination": relay["destination"], "recorded_state": relay.get("state", "unspecified"),
            "started_utc": relay.get("started_utc"), "stopped_utc": relay.get("stopped_utc"),
            "reachability_verified_by_monitor": False}


def rpc(port, method, params=None):
    global LAST_RPC
    if method not in {"snapshot", "peers", "getblock"}:
        raise ValueError("monitor permits read-only methods only")
    # One global budget covers all nodes and historical reads: fewer than 8 calls/s.
    time.sleep(max(0, 0.15 - (time.monotonic() - LAST_RPC)))
    LAST_RPC = time.monotonic()
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{int(port)}/rpc", data=body,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        result = json.load(response)
    if result.get("error"):
        raise RuntimeError(str(result["error"]))
    return result["result"]


def save(path, report):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, suffix=".tmp", delete=False) as stream:
        temporary = Path(stream.name)
        json.dump(report, stream, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def proof(header):
    raw = (struct.pack("<I", header["version"]) + bytes(header["previous"]) + bytes(header["merkle_root"])
           + struct.pack("<III", header["timestamp"], header["bits"], header["nonce"]))
    digest = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
    exponent, mantissa = header["bits"] >> 24, header["bits"] & 0x7FFFFF
    target = mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))
    return {"hash": digest.hex(), "previous_hash": bytes(header["previous"]).hex(), "target_bits": f"{header['bits']:08x}",
            "proof_valid": target > 0 and int.from_bytes(digest, "little") <= target,
            "expected_work_hash": str((1 << 256) // (target + 1))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--max-blocks", type=int, default=64, help="maximum newly backfilled blocks per sample")
    parser.add_argument("--history-limit", type=int, default=2000, help="retain complete canonical evidence through this height")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    if options.samples < 1 or options.interval < 0.2 or options.max_blocks < 1 or options.history_limit < 1:
        parser.error("samples/max-blocks/history-limit must be positive and interval must be at least 0.2 seconds")
    manifest = json.loads(options.manifest.read_text(encoding="utf-8-sig"))
    try:
        validate_manifest(manifest)
    except ValueError as error:
        parser.error(str(error))
    output = options.output or options.manifest.parent / "evidence.json"
    report = {"format": "hashstash-rental-evidence-v1", "started_utc": utc(), "chain_id": manifest["chain_id"],
              "expected_hashrate": manifest["expected_hashrate"], "initial_bits": manifest["initial_bits"],
              "executable_sha256": manifest["executable_sha256"], "read_only": True,
              "public_endpoint": manifest["mining"]["advertise"] or None,
              "samples": [], "blocks": [], "errors": []}
    if output.exists():
        existing = json.loads(output.read_text(encoding="utf-8"))
        if existing.get("format") != report["format"] or existing.get("chain_id") != report["chain_id"]:
            parser.error("existing evidence belongs to another network or format; choose another output")
        report = existing
    report["history_limit"] = options.history_limit
    report["maximum_rpc_calls_per_second"] = 1 / 0.15
    report["monitored_nodes"] = [node_metadata(manifest, node) for node in manifest["nodes"]]
    report["provenance"] = {"monitor_submits_work": False,
                            "mining_source_independently_verified": False,
                            "scope": "PoW, issuance, node agreement, and reported Stratum counters; mining hardware/source is not authenticated by RPC"}
    captured = {int(item["height"]): item for item in report["blocks"] if int(item["height"]) <= options.history_limit}
    report.setdefault("runs", []).append({"started_utc": utc(), "requested_samples": options.samples,
                                          "interval_seconds": options.interval, "nodes": report["monitored_nodes"]})
    started = time.monotonic()
    for index in range(options.samples):
        sample = {"at_utc": utc(), "elapsed_seconds": round(time.monotonic() - started, 3), "nodes": []}
        try:
            relay = relay_metadata(options.manifest, manifest)
            endpoint = manifest["mining"]["advertise"] or None
            if relay:
                endpoint = None if relay["recorded_state"] in {"stopped", "failed"} else relay["endpoint"]
            sample["relay"] = report["relay"] = relay
            sample["public_endpoint"] = report["public_endpoint"] = endpoint
        except Exception as error:
            sample["public_endpoint"] = report["public_endpoint"] = None
            report["errors"].append({"at_utc": utc(), "node": "relay", "error": str(error)})
        for record in manifest["nodes"]:
            try:
                key = payout_key(manifest, record)
                snapshot = rpc(record["rpc_port"], "snapshot", {"key": key})
                status = snapshot["status"]
                if status["chain_id"] != manifest["chain_id"] or status["protocol_version"] != 27:
                    raise RuntimeError("RPC chain identity differs from selected rental manifest")
                if snapshot["mining"].get("payout_public_key", "").lower() != key:
                    raise RuntimeError("RPC mining payout differs from selected node manifest")
                sample["nodes"].append({"name": record["name"], "status": status,
                                        "payout_public_key": key,
                                        "mining": snapshot["mining"], "mining_account": snapshot["account"],
                                        "peers": rpc(record["rpc_port"], "peers")})
            except Exception as error:
                sample["nodes"].append({"name": record["name"], "error": str(error)})
                report["errors"].append({"at_utc": utc(), "node": record["name"], "error": str(error)})
        statuses = [node["status"] for node in sample["nodes"] if "status" in node]
        sample["peers_match"] = len(statuses) == len(manifest["nodes"]) and all(
            all(status[field] == statuses[0][field] for field in ("height", "tip", "state_root", "issued"))
            for status in statuses[1:])
        primary = sample["nodes"][0]
        if "status" in primary:
            height = int(primary["status"]["height"])
            port = manifest["nodes"][0]["rpc_port"]
            try:
                before = primary["status"]
                captured = {number: item for number, item in captured.items() if number <= height}
                if "genesis_hash" not in report:
                    report["genesis_hash"] = proof(rpc(port, "getblock", {"height": 0})["header"])["hash"]
                # Verify the cached canonical prefix at its tip. A changed ancestor
                # invalidates the cache; backfill the new branch in bounded chunks.
                if captured:
                    checkpoint = max(captured)
                    current = proof(rpc(port, "getblock", {"height": checkpoint})["header"])
                    if current["hash"] != captured[checkpoint]["hash"]:
                        captured.clear()
                        sample["history_reset_after_reorg"] = True
                first = max(captured, default=0) + 1
                last = min(height, options.history_limit, first + options.max_blocks - 1)
                for number in range(first, last + 1):
                    block = rpc(port, "getblock", {"height": number})
                    item = dict(proof(block["header"]), height=number, miner_public_key=bytes(block["miner"]).hex(),
                                transaction_count=len(block["transactions"]), observed_at_utc=utc())
                    previous = captured[number - 1]["hash"] if number > 1 else report["genesis_hash"]
                    if item["previous_hash"] != previous:
                        captured.clear()
                        sample["history_changed_during_read"] = True
                        break
                    captured[number] = item
                after = rpc(port, "snapshot", {"key": payout_key(manifest, manifest["nodes"][0])})["status"]
                stable = all(before[field] == after[field] for field in ["chain_id", "height", "tip", "state_root", "issued"])
                sample["block_read_tip_unchanged"] = stable
                sample["captured_through_height"] = max(captured, default=0)
                sample["history_limit_reached"] = height > options.history_limit
                complete = stable and len(captured) == height and (height == 0 or captured[height]["hash"] == before["tip"])
                expected = sum(int(item["expected_work_hash"]) for item in captured.values())
                sample["complete_issuance_history_checked"] = complete
                sample["issuance_matches_expected_work"] = expected == int(before["issued"]) if complete else None
                sample["observed_headers_valid"] = all(item["proof_valid"] for item in captured.values())
                sample["baseline_only"] = height == 0
            except Exception as error:
                report["errors"].append({"at_utc": utc(), "node": "primary", "error": str(error)})
        report["samples"].append(sample)
        report["blocks"] = [captured[number] for number in sorted(captured)]
        report["updated_utc"] = utc()
        save(output, report)
        print(f"Sample {index + 1}/{options.samples}: heights {[status['height'] for status in statuses]}, peers match {sample['peers_match']}", flush=True)
        if index + 1 < options.samples:
            time.sleep(options.interval)
    print(f"Evidence: {output}")


if __name__ == "__main__":
    main()
