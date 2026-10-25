#!/usr/bin/env python3
"""Local end-to-end rehearsal of scripts/launch-kit.sh (Linux; WSL 2 works).

    python3 scripts/launch_rehearsal.py --release-dir DIR [--work DIR]
        [--fixture-release-dir DIR] [--ips 127.0.0.21,127.0.0.22,127.0.0.23]
        [--joiner-ip 127.0.0.24] [--base-port 61480] [--blocks 6]

Three "servers" are loopback addresses of this machine. Everything runs from
the generated kit: the kit's own deploy/install.sh --check, and its
deploy/run-node.sh, which reads the generated node.env, starts each node. A
small shim between run-node.sh and the binary changes only what one machine
cannot share: the data path, the bind address of P2P and Stratum (one
loopback alias per server instead of 0.0.0.0) and --allow-private-peer-discovery
for those loopback addresses. node.env's PEER_KEY_FILE points to the
rehearsal's identity instead of /etc/hashstash. The kit's defaults apply:
Stratum on servers 2 and 3, the website and faucet on server 1 without it.

Phase A uses the real launch genesis (init --preset slow --hashrate 1.67P):
install checks, start, seed-to-seed discovery, convergence at height 0, Stratum
authorization, the public web listener. It is far too hard to mine on a CPU.
Phase B uses an --uncalibrated rehearsal genesis through the same kit, with
the backbone pinned: start, convergence, Stratum mining of real blocks,
outsiders joining with the kit's published command, and the faucet from the
kit's configuration with the headers nginx sets. Of the outsiders, one runs
the README's join command as published and must reach the seeds' tip; another
knows one seed and advertises itself, and the first must learn it through
gossip. A release build issues whole atoms of one petahash of expected work,
so CPU blocks issue nothing and the faucet stays unfunded. Phase C, with
--fixture-release-dir (a test-fixtures build, one atom per hash), funds the
faucet from mined coins as INSTALL.md step 11 does, prepared on the web host,
signed by hashstash-cold and broadcast, and completes three claims from three
client networks, each sent the moment a new block arrives and each paid on its
first attempt. Nothing outside
--work is touched; every process started here is stopped at the end. No
network access beyond loopback.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "scripts" / "launch-kit.sh"
DOMAIN = "wallet.rehearsal.test"
ORIGIN = "https://" + DOMAIN
# Visitors' addresses as nginx sets X-Real-IP: one client network each, so the
# per-network cooldown never delays the next claim.
FAUCET_VISITORS = ["198.51.100.23", "203.0.113.23", "192.0.2.23"]
REPORT = {"phases": {}}
PROCESSES = []


def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def run(args, cwd=None, env=None, check_status=True, timeout=180):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=timeout)
    if check_status and result.returncode != 0:
        raise AssertionError(f"command failed ({result.returncode}): {' '.join(map(str, args))}\n"
                             f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}")
    return result


def rpc(port, method, params=None, timeout=10):
    data = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/rpc", data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        reply = json.load(response)
    if reply.get("error"):
        raise RuntimeError(f"{method}: {reply['error']}")
    return reply["result"]


def balance(port, key):
    """Spendable atoms of an account; zero before it exists."""
    try:
        return int(rpc(port, "account", {"key": key})["payment_available_hash"])
    except RuntimeError as error:
        if "does not exist" in str(error):
            return 0
        raise


def http(url, method="GET", headers=None, body=None, timeout=20):
    """(status, parsed JSON or text, headers) without raising on HTTP errors."""
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status, raw, reply_headers = response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        status, raw, reply_headers = error.code, error.read(), dict(error.headers)
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text), reply_headers
    except ValueError:
        return status, text, reply_headers


# ------------------------------------------------------------------ Stratum
def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_target(bits):
    exponent, mantissa = bits >> 24, bits & 0x7FFFFF
    return mantissa << (8 * (exponent - 3)) if exponent >= 3 else mantissa >> (8 * (3 - exponent))


class Stratum:
    def __init__(self, host, port, timeout=10):
        self.socket = socket.create_connection((host, port), timeout=timeout)
        self.buffer = b""
        self.request_id = 0
        self.jobs = []
        self.extra1 = None
        self.extra2_size = 4

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass

    def read(self, timeout=10):
        """One JSON line; a timeout leaves the connection usable."""
        while b"\n" not in self.buffer:
            self.socket.settimeout(timeout)
            chunk = self.socket.recv(65536)
            if not chunk:
                raise ConnectionError("Stratum connection closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        message = json.loads(line)
        if message.get("method") == "mining.notify":
            self.jobs.append(message["params"])
        return message

    def call(self, method, params):
        self.request_id += 1
        ident = self.request_id
        self.socket.sendall((json.dumps({"id": ident, "method": method, "params": params}) + "\n").encode())
        while True:
            message = self.read()
            if message.get("id") == ident:
                return message

    def handshake(self, worker, password):
        subscribed = self.call("mining.subscribe", ["launch-rehearsal/1"])
        self.extra1 = bytes.fromhex(subscribed["result"][1])
        self.extra2_size = subscribed["result"][2]
        return self.call("mining.authorize", [worker, password])

    def wait_job(self, timeout=30, newer_than=None):
        """The latest job, once one builds on something other than `newer_than`."""
        deadline = time.monotonic() + timeout
        while True:
            if self.jobs and (newer_than is None or self.jobs[-1][1] != newer_than):
                return self.jobs[-1]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("no new Stratum job received")
            try:
                self.read(timeout=remaining)
            except (socket.timeout, TimeoutError):
                pass

    def mine_block(self, job, worker, counter):
        """Search nonces until the header meets the job's block target, then submit."""
        coinb1, coinb2, branch = bytes.fromhex(job[2]), bytes.fromhex(job[3]), job[4]
        version, bits, ntime = int(job[5], 16), int(job[6], 16), int(job[7], 16)
        previous = bytes.fromhex(job[1])
        previous = b"".join(previous[n:n + 4][::-1] for n in range(0, 32, 4))
        block_target = compact_target(bits)
        extra2 = counter.to_bytes(self.extra2_size, "big")
        root = sha256d(coinb1 + self.extra1 + extra2 + coinb2)
        for sibling in branch:
            root = sha256d(root + bytes.fromhex(sibling))
        prefix = struct.pack("<I", version) + previous + root + struct.pack("<II", ntime, bits)
        for nonce in range(1 << 32):
            if int.from_bytes(sha256d(prefix + struct.pack("<I", nonce)), "little") <= block_target:
                return self.call("mining.submit", [worker, job[0], extra2.hex(), job[7], f"{nonce:08x}"])
            if nonce > 50_000_000:
                break
        raise AssertionError("nonce search exhausted")


class Miner(threading.Thread):
    """Mines one block every `interval` seconds through Stratum until stopped."""

    def __init__(self, host, port, password, interval, limit=None):
        super().__init__(daemon=True)
        self.host, self.port, self.password, self.interval, self.limit = host, port, password, interval, limit
        self.stop_event = threading.Event()
        self.accepted = 0
        self.rejected = []
        self.error = None

    def run(self):
        session = Stratum(self.host, self.port)
        try:
            check(session.handshake("rehearsal.cpu", self.password).get("result") is True, "Stratum authorization")
            counter, last_previous = 0, None
            while not self.stop_event.is_set() and (self.limit is None or self.accepted < self.limit):
                job = session.wait_job(newer_than=last_previous)
                counter += 1
                reply = session.mine_block(job, "rehearsal.cpu", counter)
                if reply.get("result") is True:
                    self.accepted += 1
                    last_previous = job[1]
                else:
                    # A job replaced meanwhile: mine the latest one next.
                    self.rejected.append(reply.get("error"))
                    check(len(self.rejected) <= 20, f"too many rejected blocks: {self.rejected[-3:]}")
                self.stop_event.wait(self.interval)
        except Exception as error:  # reported by the phase that started it
            self.error = f"{error!r}; accepted {self.accepted}; rejected {self.rejected[-3:]}"
        finally:
            session.close()


# --------------------------------------------------------------- processes
SHIM = """#!/usr/bin/env bash
# Rehearsal shim between the kit's deploy/run-node.sh and the real binary. It
# passes run-node.sh's arguments unchanged except --data (one directory per
# server), the 0.0.0.0 bind of --p2p and --stratum (one loopback alias per
# server) and --allow-private-peer-discovery beside --peer-discovery.
set -euo pipefail
real=${REHEARSAL_BINARY:?}
if [[ "${1:-}" != run ]]; then exec "$real" "$@"; fi
args=()
while (( $# )); do
    case "$1" in
        --data) args+=(--data "${REHEARSAL_DATA:?}"); shift 2 ;;
        --p2p|--stratum) args+=("$1" "${2/#0.0.0.0:/${REHEARSAL_BIND:?}:}"); shift 2 ;;
        --peer-discovery) args+=(--peer-discovery --allow-private-peer-discovery); shift ;;
        *) args+=("$1"); shift ;;
    esac
done
printf '%s\\n' "${args[@]}" > "${REHEARSAL_DATA%/*}/argv-$$.txt"
exec "$real" "${args[@]}"
"""


def start(args, logfile, env=None, cwd=None):
    handle = open(logfile, "ab")
    process = subprocess.Popen([str(a) for a in args], stdout=handle, stderr=subprocess.STDOUT, env=env,
                               cwd=cwd, start_new_session=True)
    PROCESSES.append((process, handle))
    return process


def stop(process, timeout=90):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    return process.returncode


def stop_all():
    for process, handle in reversed(PROCESSES):
        try:
            stop(process)
        finally:
            handle.close()
    PROCESSES.clear()


def env_values(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


class Server:
    def __init__(self, number, ip, kit_dir, work, binary, password_file, peer_key):
        self.number, self.ip, self.kit_dir = number, ip, kit_dir
        self.env = env_values(kit_dir / "node.env")
        self.rpc = int(self.env["RPC_PORT"])
        self.work = work / f"server-{number}"
        self.work.mkdir(parents=True, exist_ok=True)
        self.binary, self.password_file, self.peer_key = binary, password_file, peer_key
        self.process = None

    def node_env(self):
        """The kit's node.env with only PEER_KEY_FILE pointing at the rehearsal identity."""
        text = (self.kit_dir / "node.env").read_text()
        text = re.sub(r"^PEER_KEY_FILE=.*$", f"PEER_KEY_FILE={self.peer_key}", text, flags=re.M)
        path = self.work / "node.env"
        path.write_text(text)
        return path

    def launcher_env(self, shim):
        env = dict(os.environ, REHEARSAL_BINARY=str(self.binary), REHEARSAL_DATA=str(self.work / "chain.sqlite"),
                   REHEARSAL_BIND=self.ip)
        return env

    def start(self, shim):
        args = ["bash", self.kit_dir / "deploy" / "run-node.sh", "run", self.node_env(), shim,
                self.kit_dir / "network.json", self.password_file]
        self.process = start(args, self.work / "node.log", env=self.launcher_env(shim))
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(f"server {self.number} exited: " + (self.work / "node.log").read_text()[-3000:])
            try:
                return rpc(self.rpc, "status")
            except (urllib.error.URLError, ConnectionError, TimeoutError, RuntimeError):
                time.sleep(0.25)
        raise AssertionError(f"server {self.number} did not answer RPC")

    def snapshot(self):
        result = run(["bash", self.kit_dir / "deploy" / "run-node.sh", "snapshot", self.node_env(), self.binary])
        return json.loads(result.stdout)


def install_check(server_dir, values, peer_key, password_file):
    """INSTALL.md steps 3 and 6 (--check), verbatim except for the key paths."""
    run(["sha256sum", "-c", "SHA256SUMS"], cwd=server_dir / "release")
    args = ["bash", "deploy/install.sh", "--binary", "release/hashstash", "--sha256", values["HASHSTASH_SHA256"],
            "--genesis", "network.json", "--genesis-sha256", values["GENESIS_SHA256"], "--node-env", "node.env",
            "--peer-key-file", peer_key]
    if env_values(server_dir / "node.env").get("STRATUM_ENABLED") == "true":
        args += ["--stratum-password-file", password_file]
    result = run(args + ["--check"], cwd=server_dir)
    check("Configuration and payout public key are valid" in result.stdout, "install.sh --check accepted the configuration")
    check(values["CHAIN_ID"] in result.stdout, "install.sh --check printed the chain ID")
    return result.stdout


def wait_converged(servers, label, minimum_height=0, pinned=False, timeout=180):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        statuses = [rpc(s.rpc, "status") for s in servers]
        peer = [rpc(s.rpc, "peerstatus") for s in servers]
        tips = {(st["height"], st["tip"]) for st in statuses}
        verified = [p["discovery"].get("verified", 0) for p in peer]
        reachable = [all(x.get("reachable") for x in p.get("peers", [])) and len(p.get("peers", [])) == len(servers) - 1
                     for p in peer]
        last = {"heights": [st["height"] for st in statuses], "tips": [st["tip"][:16] for st in statuses],
                "discovery_verified": verified, "configured_peers_reachable": reachable,
                "transport": [p.get("transport") for p in peer]}
        if (len(tips) == 1 and statuses[0]["height"] >= minimum_height
                and all(v >= len(servers) - 1 for v in verified) and all(reachable)):
            # INSTALL.md step 9 reads the same through run-node.sh snapshot.
            snapshot = servers[0].snapshot()
            result = dict(last, height=statuses[0]["height"], tip=statuses[0]["tip"],
                          chain_id=statuses[0].get("chain_id"),
                          state_roots_equal=len({json.dumps(st.get("state_root")) for st in statuses}) == 1,
                          run_node_snapshot={k: snapshot.get("status", {}).get(k) for k in ("height", "tip", "chain_id")},
                          peerstatus_sample={k: peer[0][k] for k in ("transport", "chain_stalled", "listeners")
                                             if k in peer[0]})
            check(result["run_node_snapshot"]["chain_id"] == result["chain_id"]
                  and result["run_node_snapshot"]["tip"] == result["tip"], "run-node.sh snapshot reads the same chain")
            log(f"{label}: converged at height {result['height']} tip {result['tip'][:16]}; "
                f"discovery verified {verified}, configured peers reachable {reachable}")
            return result
        time.sleep(1)
    raise AssertionError(f"{label}: no convergence: {last}")


# ------------------------------------------------------------------ phases
class Rehearsal:
    def __init__(self, options):
        self.options = options
        self.work = Path(options.work).resolve()
        self.ips = options.ips.split(",")
        check(len(self.ips) >= 3, "three servers: the web host and two Stratum servers")
        # The outsider running the published command listens on an alias of
        # its own. The node that advertises itself listens on 127.0.0.1: on one
        # machine every outbound connection leaves from 127.0.0.1, and a node
        # accepts an advertisement only for the address the advertiser connects
        # from (on the servers, its public address).
        check(options.joiner_ip not in self.ips and options.joiner_ip != "127.0.0.1", "an outsider address besides the servers'")
        self.joiner_binds = [f"{options.joiner_ip}:{options.base_port + 1}", f"127.0.0.1:{options.base_port + 6}"]
        self.base = options.base_port
        self.ports = {"rpc": self.base, "p2p": self.base + 1, "stratum": self.base + 2,
                      "web": self.base + 3, "faucet": self.base + 4, "cold": self.base + 5}
        check(self.base + 1000 * (len(self.ips) + 1) <= 65535, "--base-port leaves room for every RPC port")
        self.shim = self.work / "run-node-shim.sh"

    def kit(self, release_dir, out, genesis_args, extra=()):
        args = ["bash", KIT, "--rehearsal", "--seeds", ",".join(self.ips), "--web-host", self.ips[0],
                "--domain", DOMAIN, "--binary", Path(release_dir) / "hashstash",
                "--miner-prefixes", "127.0.0.0/8", "--payout-keys", self.payout_public,
                "--p2p-port", self.ports["p2p"], "--stratum-port", self.ports["stratum"],
                "--rpc-port", self.ports["rpc"], "--web-port", self.ports["web"],
                "--faucet-port", self.ports["faucet"], "--faucet-payout", "5", "--out", out,
                *genesis_args, *extra]
        result = run(args)
        log(result.stdout.strip().splitlines()[0])
        return env_values(out / "launch-values.env"), result

    def prepare(self, release_dir):
        binary = Path(release_dir) / "hashstash"
        keys = self.work / "keys"
        keys.mkdir(parents=True, exist_ok=True)
        os.chmod(keys, 0o700)
        if not (keys / "payout.key").exists():
            run([binary, "keygen", "--out", keys / "payout.key"])
        # The rehearsal's payout key stands in for the offline one; only its public key enters the kit.
        self.payout_public = run([binary, "public-key", "--key", keys / "payout.key"]).stdout.strip()
        self.peer_keys, self.passwords = [], []
        for number, ip in enumerate(self.ips, 1):
            path = keys / f"server-{number}-peer-identity.json"
            if not path.exists():
                public = run([binary, "peer-keygen", "--out", path]).stdout.strip()
            else:
                public = run([binary, "peer-keycheck", "--key-file", path, "--peer-discovery",
                              "--miner", self.payout_public]).stdout.strip()
            check(re.fullmatch(r"[0-9a-f]{64}", public), "peer public key")
            password = keys / f"server-{number}-stratum-password"
            if not password.exists():
                password.write_text(secrets.token_hex(32) + "\n")
                os.chmod(password, 0o600)
            self.peer_keys.append((path, public))
            self.passwords.append(password)
        self.shim.write_text(SHIM)
        os.chmod(self.shim, 0o755)

    def servers(self, kit_out, binary, run_dir):
        result = []
        for number, ip in enumerate(self.ips, 1):
            kit_dir = kit_out / f"server-{number}-{ip}"
            result.append(Server(number, ip, kit_dir, run_dir, binary, self.passwords[number - 1],
                                 self.peer_keys[number - 1][0]))
        return result

    def install_checks(self, kit_out, values):
        for number, ip in enumerate(self.ips, 1):
            install_check(kit_out / f"server-{number}-{ip}", values, self.peer_keys[number - 1][0],
                          self.passwords[number - 1])
        log(f"install.sh --check passed on all {len(self.ips)} servers")

    def start_all(self, servers):
        for server in servers:
            status = server.start(self.shim)
            log(f"server {server.number} {server.ip}: height {status['height']} chain {status.get('chain_id', '')[:16]}")

    def stratum_auth(self, server):
        good = Stratum(server.ip, self.ports["stratum"])
        try:
            authorized = good.handshake("rehearsal.check", server.password_file.read_text().strip())
            job = good.wait_job()
        finally:
            good.close()
        bad = Stratum(server.ip, self.ports["stratum"])
        try:
            refused = bad.handshake("rehearsal.check", "wrong-password")
        except ConnectionError:
            refused = {"result": None, "error": "connection closed"}
        finally:
            bad.close()
        check(authorized.get("result") is True, "Stratum accepts the password")
        check(refused.get("result") is not True, "Stratum refuses a wrong password")
        return {"server": server.number, "authorized": True, "job_bits": job[6],
                "wrong_password": refused.get("error") or refused.get("result")}

    def no_stratum(self, server):
        """The web host runs no Stratum listener (the kit's default)."""
        check(server.env.get("STRATUM_ENABLED") == "false", "the kit leaves Stratum off the web host")
        try:
            socket.create_connection((server.ip, self.ports["stratum"]), timeout=3).close()
        except ConnectionRefusedError:
            return {"server": server.number, "stratum_port": "connection refused"}
        raise AssertionError(f"server {server.number} accepts Stratum connections")

    def public_web(self):
        base = f"http://127.0.0.1:{self.ports['web']}"
        headers = {"Host": DOMAIN, "X-Real-IP": "198.51.100.7"}
        status, page, _ = http(base + "/", headers=headers)
        check(status == 200 and "<html" in str(page).lower(), f"public web serves the wallet page ({status})")
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "status", "params": {}}).encode()
        status, reply, _ = http(base + "/rpc", "POST", dict(headers, **{"Content-Type": "application/json"}), body)
        check(status == 200 and reply.get("result", {}).get("chain_id"), "public status works")
        body = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "peers", "params": {}}).encode()
        status, refused, _ = http(base + "/rpc", "POST", dict(headers, **{"Content-Type": "application/json"}), body)
        check(not (isinstance(refused, dict) and refused.get("result") is not None), "public web refuses peers")
        return {"page": 200, "status_chain_id": reply["result"]["chain_id"], "peers_refused": refused if isinstance(refused, dict) else status}

    def phase_a(self):
        log("Phase A: launch genesis (init --preset slow --hashrate 1.67P), discovery without pins")
        release = Path(self.options.release_dir)
        self.prepare(release)
        out = self.work / "kit-launch"
        values, result = self.kit(release, out, ["--hashrate", "1.67P"])
        check(values["EASY_TARGET"] == "false", "the launch genesis is calibrated")
        report = {"chain_id": values["CHAIN_ID"], "genesis_sha256": values["GENESIS_SHA256"],
                  "hashstash_sha256": values["HASHSTASH_SHA256"], "init": (out / "genesis" / "init-output.txt").read_text()}
        genesis = json.loads((out / "genesis" / "network.json").read_text())
        report["genesis"] = {k: genesis[k] for k in ("network", "test_work", "initial_bits", "limit_bits", "genesis_time")}
        self.install_checks(out, values)
        servers = self.servers(out, release / "hashstash", self.work / "run-launch")
        try:
            self.start_all(servers)
            report["convergence"] = wait_converged(servers, "Phase A", 0)
            check(report["convergence"]["chain_id"] == values["CHAIN_ID"], "nodes run the kit's chain ID")
            report["stratum"] = self.stratum_auth(servers[1])
            log(f"Phase A: Stratum authorization ok on server 2, wrong password refused ({report['stratum']['wrong_password']})")
            report["web_host_stratum"] = self.no_stratum(servers[0])
            log("Phase A: the web host runs no Stratum listener")
            joiner, _, _, report["published_command"] = self.join_published(out, release / "hashstash",
                                                                             self.work / "run-launch", servers, False)
            report["published_command"]["exit"] = stop(joiner["process"])
            check(report["published_command"]["exit"] == 0, "the outsider stopped cleanly")
            report["public_web"] = self.public_web()
            log("Phase A: public web listener serves the wallet and refuses private methods")
            report["argv_server_1"] = sorted(p.read_text().split("\n") for p in (self.work / "run-launch" / "server-1").glob("argv-*.txt"))[-1]
        finally:
            report["exit_codes"] = [stop(s.process) for s in servers if s.process]
            stop_all()
        log(f"Phase A: stopped (exit codes {report['exit_codes']})")
        REPORT["phases"]["A_launch_genesis"] = report

    def faucet_config(self, kit_out, run_dir, key):
        config = json.loads((kit_out / f"server-1-{self.ips[0]}" / "faucet" / "config.json").read_text())
        check(config["origins"] == [ORIGIN] and config["bind"] == f"127.0.0.1:{self.ports['faucet']}", "kit faucet config")
        config["key_file"] = str(key)
        config["database"] = str(run_dir / "faucet-claims.sqlite")
        path = run_dir / "faucet-config.json"
        path.write_text(json.dumps(config, indent=2))
        return path, config

    def faucet_request(self, path, method="GET", body=None, headers=None, ip=FAUCET_VISITORS[0]):
        base = {"Host": DOMAIN, "X-Real-IP": ip}
        if headers is not None:
            base = headers
        if method == "POST":
            base = dict(base, **{"Origin": ORIGIN, "Content-Type": "application/json"})
        return http(f"http://127.0.0.1:{self.ports['faucet']}{path}", method, base,
                    json.dumps(body).encode() if body is not None else None)

    def genesis_uncalibrated(self, binary, path):
        if not path.exists():
            run([binary, "init", "--config", path, "--preset", "slow", "--uncalibrated"])
        return path

    def mined_network(self, phase, release, kit_name, run_name):
        binary = Path(release) / "hashstash"
        genesis = self.genesis_uncalibrated(binary, self.work / f"{kit_name}-genesis.json")
        pins = ",".join(f"{ip}={self.peer_keys[i][1]}" for i, ip in enumerate(self.ips))
        out = self.work / kit_name
        values, _ = self.kit(release, out, ["--genesis", genesis], ["--peer-pins", pins])
        if values["FIXTURE_BUILD"] == "true":
            # Fixture (test_work) networks are exempt from the easy-target guard.
            check(values["EASY_TARGET"] == "false", "a fixture genesis needs no ALLOW_EASY_TARGET")
        else:
            check(values["EASY_TARGET"] == "true", "the kit marks the uncalibrated genesis ALLOW_EASY_TARGET")
        self.install_checks(out, values)
        servers = self.servers(out, binary, self.work / run_name)
        self.start_all(servers)
        converged = wait_converged(servers, f"{phase} start", 0)
        check(all(t == "authenticated-discovery" for t in converged["transport"]), "authenticated discovery transport")
        return values, out, servers, converged

    def faucet_checks(self, report, release, out, run_dir, servers, funded):
        binary = Path(release) / "hashstash"
        faucet_binary = Path(release) / "hashstash-faucet"
        key = run_dir / "faucet.key"
        if not key.exists():
            faucet_public = re.search(r"Public key: ([0-9a-f]{64})",
                                      run([binary, "keygen", "--out", key]).stdout).group(1)
        else:
            faucet_public = run([binary, "public-key", "--key", key]).stdout.strip()
        faucet_address = run([binary, "address", "--public-key", faucet_public, "--config",
                              out / "genesis" / "network.json"]).stdout.strip()
        report["faucet_address"] = faucet_address
        if funded:
            payout_balance = balance(servers[0].rpc, self.payout_public)
            amount = payout_balance // 2
            kit_faucet = json.loads((out / f"server-1-{self.ips[0]}" / "faucet" / "config.json").read_text())
            # Each claim needs the payout and the fee allowance available.
            needed = len(FAUCET_VISITORS) * (int(kit_faucet["payout"]) + int(kit_faucet["max_fee"]))
            check(amount >= needed, f"mined coins fund {len(FAUCET_VISITORS)} claims: {amount} of {needed} atoms")
            report["funding_transfer"] = dict(self.fund_offline(release, out, run_dir, faucet_address, amount),
                                              payout_balance_before=payout_balance, amount=amount)
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline and balance(servers[0].rpc, faucet_public) < amount:
                time.sleep(1)
            check(balance(servers[0].rpc, faucet_public) >= amount, "faucet funded by the transfer")
            log(f"faucet funded with {amount} atoms from mined coins")
        config_path, config = self.faucet_config(out, run_dir, key)
        faucet = start([faucet_binary, "--config", config_path], run_dir / "faucet.log")
        deadline = time.monotonic() + 30
        status = None
        while time.monotonic() < deadline:
            try:
                code, status, _ = self.faucet_request("/faucet/status")
                if code == 200:
                    break
            except (urllib.error.URLError, ConnectionError):
                pass
            time.sleep(0.5)
        check(isinstance(status, dict) and status.get("chain_id") == config["chain_id"], f"faucet status {status}")
        # The trust model of docs/FAUCET.md: an allowed Host and a proxy-set X-Real-IP.
        no_ip, _, _ = self.faucet_request("/faucet/status", headers={"Host": DOMAIN})
        wrong_host, _, _ = self.faucet_request("/faucet/status", headers={"Host": "evil.example", "X-Real-IP": "198.51.100.23"})
        check(no_ip == 403 and wrong_host == 403, "faucet refuses requests without X-Real-IP or with another Host")
        report["faucet_refusals"] = {"without_x_real_ip": no_ip, "other_host": wrong_host}
        # A funded faucet pays several visitors in turn (it keeps one payment
        # outstanding), each from its own client network. Each claim is sent
        # the moment a new block reaches the web host's node, before the
        # faucet's next three-second refresh can show it: the faucet then
        # prepares against the tip it last saw, the node refuses that anchor,
        # and the claim must refresh and prepare again instead of answering
        # 503. Every claim is sent once; none may need a retry.
        claims = []
        for index, visitor_ip in enumerate(FAUCET_VISITORS if funded else FAUCET_VISITORS[:1]):
            name = f"recipient-{index + 1}"
            recipient_public = re.search(r"Public key: ([0-9a-f]{64})",
                                         run([binary, "keygen", "--out", run_dir / f"{name}.key"]).stdout).group(1)
            recipient = run([binary, "address", "--public-key", recipient_public, "--config",
                             out / "genesis" / "network.json"]).stdout.strip()
            # The previous payment confirmed and the faucet sees mining.
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                code, status, _ = self.faucet_request(f"/faucet/status?address={recipient}", ip=visitor_ip)
                if status.get("state") not in ("waiting_for_mining", "unavailable", "pending"):
                    break
                time.sleep(1)
            log(f"faucet state before claim {index + 1}: {status.get('state')}")
            check(not funded or status.get("state") == "ready", f"faucet ready for claim {index + 1}: {status}")
            height = rpc(servers[0].rpc, "status")["height"]
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and rpc(servers[0].rpc, "status")["height"] <= height:
                time.sleep(0.05)
            arrived = time.monotonic()
            code, claim, headers = self.faucet_request("/faucet/claim", "POST", {"address": recipient},
                                                       ip=visitor_ip)
            entry = {"http": code, "reply": claim, "attempts": 1, "after_block_height": height + 1,
                     "seconds_after_block": round(time.monotonic() - arrived, 3),
                     "retry_after": headers.get("Retry-After")}
            claims.append(entry)
            log(f"claim {index + 1}: HTTP {code} on the first attempt, sent at a new block "
                f"{json.dumps(claim)[:200]}")
            if not funded:
                check(code != 200 or claim.get("status") not in ("pending", "confirmed"),
                      "an unfunded faucet pays nothing")
                check(code == 503 and claim.get("state") == "unfunded", f"an unfunded faucet says so: {code} {claim}")
                continue
            check(code == 200 and claim.get("status") in ("pending", "confirmed"),
                  f"claim {index + 1} accepted on its first attempt: HTTP {code} {claim}")
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                code, status, _ = self.faucet_request(f"/faucet/status?address={recipient}", ip=visitor_ip)
                if (status.get("claim") or {}).get("status") == "confirmed":
                    break
                time.sleep(1)
            received = balance(servers[0].rpc, recipient_public)
            entry.update(final=status.get("claim"), recipient_balance=received)
            check((status.get("claim") or {}).get("status") == "confirmed" and received == int(config["payout"]),
                  f"claim {index + 1} confirmed and paid: {status.get('claim')} balance {received}")
            log(f"claim {index + 1} confirmed; recipient balance {received} atoms")
        report["claims"] = claims
        report["faucet_exit"] = stop(faucet)

    def fund_offline(self, release, out, run_dir, faucet_address, amount):
        """INSTALL.md step 11 on the web host: the rendered prepare command through
        its private RPC (no key), hashstash-cold with the payout key as on the
        offline machine, then the rendered broadcast command."""
        web_dir = out / f"server-1-{self.ips[0]}"
        lines = (web_dir / "INSTALL.md").read_text().splitlines()
        first = next(n for n, line in enumerate(lines) if line.startswith("./release/hashstash prepare "))
        check(lines[first].endswith(" \\"), "the prepare command continues on the next line")
        prepare = lines[first][:-1].strip() + " " + lines[first + 1].strip()
        broadcast = next(line for line in lines if line.startswith("./release/hashstash broadcast "))
        check(f"--url http://127.0.0.1:{self.ports['rpc']}/rpc" in prepare and f"--sender {self.payout_public}" in prepare
              and "--expiry-blocks 240" in prepare, f"rendered prepare command: {prepare}")
        check(not any("transfer --url" in line or "payout.key" in line for line in lines),
              "INSTALL.md never puts the payout key on a networked machine")
        # The kit's 12-hash example exceeds a fixture chain's coins; the command is otherwise the rendered one.
        (web_dir / "faucet-funding.json").write_text(
            json.dumps({"TransferExact": {"recipient": faucet_address, "amount": str(amount)}}) + "\n")
        prepared = run(["bash", "-c", prepare], cwd=web_dir)
        envelope = json.loads((web_dir / "faucet-funding.unsigned.json").read_text())
        check(envelope.get("format") == "hashstash-unsigned-anchor", "an unsigned export, no signature")
        # The offline machine: the release's cold signer, network from the kit's genesis.
        cold = start([Path(release) / "hashstash-cold", "--port", self.ports["cold"], "--config", web_dir / "network.json"],
                     run_dir / "cold.log")
        try:
            deadline = time.monotonic() + 30
            launch = None
            while launch is None and time.monotonic() < deadline:
                check(cold.poll() is None, "hashstash-cold exited: " + (run_dir / "cold.log").read_text()[-2000:])
                launch = re.search(r"cold signer: (http://127\.0\.0\.1:\d+)/#token=([0-9a-f]{64})",
                                   (run_dir / "cold.log").read_text())
                time.sleep(0.2)
            check(launch is not None, "hashstash-cold printed its launch address")
            base, token = launch.group(1), launch.group(2)

            def cold_call(action, value):
                status, reply, _ = http(f"{base}/api/{action}", "POST",
                                        {"Origin": base, "Content-Type": "application/json",
                                         "X-Hashstash-Cold-Token": token}, json.dumps(value).encode())
                check(status == 200, f"cold signer {action}: HTTP {status} {reply}")
                return reply

            secret = json.loads((self.work / "keys" / "payout.key").read_text())["secret"]
            opened = cold_call("import", {"private_key": secret})
            check(opened.get("public_key") == self.payout_public, "the cold signer opened the payout key")
            review = cold_call("review", envelope)
            fields = {field["label"]: field["value"] for field in review["fields"]}
            check(fields.get("Recipient") == faucet_address, f"the review names the faucet as recipient: {fields}")
            signed = cold_call("sign", {"review_token": review["review_token"]})
            cold_call("lock", {})
        finally:
            cold_exit = stop(cold)
        (web_dir / "faucet-funding.signed.txt").write_text(signed["raw"] + "\n")
        result = run(["bash", "-c", broadcast], cwd=web_dir)
        check(json.loads(result.stdout).get("transaction_id") == signed["txid"], "broadcast reports the signed transaction")
        log(f"faucet funding prepared on the web host, signed by hashstash-cold, broadcast as {signed['txid'][:16]}")
        return {"prepare": prepare, "broadcast": broadcast, "review": fields, "txid": signed["txid"],
                "prepare_review": prepared.stderr.strip()[-800:], "cold_exit": cold_exit}

    def join_args(self, out):
        """The join command of the kit's README as published, after `hashstash`."""
        lines = [line for line in (out / "README.md").read_text().splitlines() if line.startswith("hashstash run ")]
        check(len(lines) == 1, "README.md has one join command")
        args = lines[0].split()[1:]
        check(args.count("--seed") == len(self.ips) and "--peer-discovery" in args and "--no-stratum" in args,
              f"the join command lists every seed: {lines[0]}")
        announcement = (out / "ANNOUNCEMENT.md").read_text()
        check(lines[0][len("hashstash "):] in announcement, "ANNOUNCEMENT.md gives the same command")
        return [self.payout_public if a == "YOUR_PAYOUT_PUBLIC_KEY" else a for a in args]

    def start_joiner(self, index, args, out, binary, run_dir, easy):
        """An outsider's node running `args` from a directory holding network.json,
        plus only what one machine cannot share: loopback listeners of its own and
        private-address discovery (and, on the uncalibrated rehearsal genesis,
        what the seeds' ALLOW_EASY_TARGET gives them)."""
        work = run_dir / f"joiner-{index + 1}"
        work.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / "genesis" / "network.json", work / "network.json")
        port = self.base + 1000 * (len(self.ips) + index)
        address = self.joiner_binds[index]
        extra = ["--rpc", f"127.0.0.1:{port}", "--p2p", address, "--allow-private-peer-discovery"]
        if easy:
            extra.append("--allow-easy-target")
        process = start([binary, *args, *extra], work / "node.log", cwd=work)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            check(process.poll() is None, f"joiner {index + 1} exited: " + (work / "node.log").read_text()[-3000:])
            try:
                rpc(port, "status")
                return {"process": process, "rpc": port, "address": address, "args": args, "added": extra}
            except (urllib.error.URLError, ConnectionError, TimeoutError, RuntimeError):
                time.sleep(0.25)
        raise AssertionError(f"joiner {index + 1} did not answer RPC")

    def join_published(self, out, binary, run_dir, servers, easy):
        """An outsider runs the README's join command and reaches the seeds' tip."""
        tip = rpc(servers[0].rpc, "status")
        args = self.join_args(out)
        first = self.start_joiner(0, args, out, binary, run_dir, easy)
        started = time.monotonic()
        while True:
            status, peer = rpc(first["rpc"], "status"), rpc(first["rpc"], "peerstatus")
            if (status["tip"] == tip["tip"] and peer["discovery"].get("verified", 0) >= len(self.ips)
                    and peer.get("transport") == "authenticated-discovery"):
                break
            check(time.monotonic() - started < 180, f"the published command did not join: height {status['height']} "
                  f"of {tip['height']}, discovery {peer['discovery'].get('verified')}")
            time.sleep(1)
        report = {"args": first["args"], "added": first["added"], "height": status["height"], "tip": status["tip"],
                  "discovery_verified": peer["discovery"]["verified"], "seconds": round(time.monotonic() - started, 1)}
        log(f"outsider with the published command reached height {status['height']} at the seeds' tip and verified "
            f"{peer['discovery']['verified']} seeds in {report['seconds']} s")
        return first, args, tip, report

    def outsiders(self, out, binary, run_dir, servers, easy):
        """Users join with the published command; a public node advertises itself
        to one seed, which passes it on through gossip."""
        report = {}
        first, args, tip, report["published_command"] = self.join_published(out, binary, run_dir, servers, easy)
        # A public node that knows one seed and advertises itself.
        one_seed, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a == "--seed":
                skip = True
            else:
                one_seed.append(a)
        seed = f"{self.ips[0]}:{self.ports['p2p']}"
        address = self.joiner_binds[1]
        second = self.start_joiner(1, one_seed + ["--seed", seed, "--advertise-peer", address], out, binary, run_dir,
                                   easy)
        started = time.monotonic()
        seen = {}
        while not {"seed_knows", "seed_verified", "gossiped"} <= seen.keys():
            elapsed = round(time.monotonic() - started, 1)
            book = {e["address"]: e for e in rpc(servers[0].rpc, "peerstatus")["discovery"].get("peers", [])}
            if address in book:
                seen.setdefault("seed_knows", elapsed)
                if book[address].get("last_success", 0) > 0:
                    seen.setdefault("seed_verified", elapsed)
            learned = {e["address"]: e for e in rpc(first["rpc"], "peerstatus")["discovery"].get("peers", [])}
            if address in learned:
                seen.setdefault("gossiped", elapsed)
                report["gossiped_entry"] = learned[address]
            check(elapsed < 420, f"no gossip of the advertised node within 420 s: {seen}")
            time.sleep(2)
        status = rpc(second["rpc"], "status")
        check(status["tip"] == tip["tip"], "the one-seed node synchronized")
        second_book = sorted(e["address"] for e in rpc(second["rpc"], "peerstatus")["discovery"].get("peers", []))
        report["advertised_node"] = {"args": second["args"], "added": second["added"], "seconds": seen,
                                     "its_book": second_book}
        log(f"advertised node: seed 1 knew it after {seen['seed_knows']} s, verified it after {seen['seed_verified']} s, "
            f"the first outsider learned it by gossip after {seen['gossiped']} s; its own book: {second_book}")
        report["exit_codes"] = [stop(second["process"]), stop(first["process"])]
        check(report["exit_codes"] == [0, 0], f"outsiders stopped cleanly: {report['exit_codes']}")
        return report

    def phase_mined(self, phase, release, kit_name, run_name, funded):
        log(f"Phase {phase}: uncalibrated rehearsal genesis through the same kit, backbone pinned"
            + (" (test-fixtures build, funded faucet)" if funded else ""))
        report = {}
        if funded:
            self.prepare(release)
        values, out, servers, converged = self.mined_network(phase, release, kit_name, run_name)
        report.update(chain_id=values["CHAIN_ID"], genesis_sha256=values["GENESIS_SHA256"], start=converged)
        miner = None
        # A funded faucet needs coins: a fixture block issues about two atoms,
        # and half the payout account funds three claims of 5 + up to 10 atoms.
        blocks = max(self.options.blocks, 50) if funded else self.options.blocks
        try:
            # Stratum runs on servers 2 and 3; server 1 is the web host.
            miner = Miner(self.ips[1], self.ports["stratum"], self.passwords[1].read_text().strip(), 0.5,
                          limit=blocks)
            miner.start()
            miner.join(timeout=300)
            check(miner.error is None, f"miner error: {miner.error}")
            check(miner.accepted >= blocks, f"mined {miner.accepted} blocks")
            # Server 3 mines on the tip it received from server 2.
            report["converged_after_server_2"] = wait_converged(servers, f"Phase {phase} server 2 blocks", blocks)
            second = Miner(self.ips[2], self.ports["stratum"], self.passwords[2].read_text().strip(), 0.5, limit=2)
            second.start()
            second.join(timeout=120)
            check(second.error is None and second.accepted == 2, f"third server mined: {second.error}")
            report["mined"] = {"server_2": miner.accepted, "server_3": second.accepted,
                               "rejected": miner.rejected + second.rejected}
            report["converged_after_mining"] = wait_converged(servers, f"Phase {phase} mined", blocks + 2)
            check(report["converged_after_mining"]["state_roots_equal"], "state roots agree")
            mining = rpc(servers[1].rpc, "mining")
            report["mining_rpc_server_2"] = {k: mining.get(k) for k in
                                             ("workers_connected", "accepted_shares", "rejected_shares", "blocks_found")}
            report["payout_balance_atoms"] = balance(servers[0].rpc, self.payout_public)
            status = rpc(servers[0].rpc, "status")
            report["issued_atoms"] = status.get("issued")
            log(f"Phase {phase}: mined {miner.accepted}+{second.accepted} blocks, all nodes agree at height "
                f"{report['converged_after_mining']['height']}; issued {status.get('issued')} atoms")
            if not funded:
                report["outsiders"] = self.outsiders(out, Path(release) / "hashstash", self.work / run_name, servers,
                                                     values["EASY_TARGET"] == "true")
            # Keep blocks coming so the faucet sees an active chain, a few
            # seconds apart as the faucet refreshes its snapshot every 3 s.
            miner = Miner(self.ips[1], self.ports["stratum"], self.passwords[1].read_text().strip(), 5.0)
            miner.start()
            self.faucet_checks(report, release, out, self.work / run_name, servers, funded)
        finally:
            if miner:
                miner.stop_event.set()
                miner.join(timeout=30)
            report["exit_codes"] = [stop(s.process) for s in servers if s.process]
            stop_all()
        log(f"Phase {phase}: stopped (exit codes {report['exit_codes']})")
        REPORT["phases"][f"{phase}_{kit_name}"] = report


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--release-dir", required=True, help="directory holding the release hashstash and hashstash-faucet")
    parser.add_argument("--fixture-release-dir", help="a test-fixtures build for the funded faucet phase")
    parser.add_argument("--work", help="new work directory (default: a temporary one)")
    parser.add_argument("--ips", default="127.0.0.21,127.0.0.22,127.0.0.23")
    parser.add_argument("--joiner-ip", default="127.0.0.24",
                        help="loopback address of the outsider that runs the published command")
    parser.add_argument("--base-port", type=int, default=61480)
    parser.add_argument("--blocks", type=int, default=6)
    options = parser.parse_args()
    if options.work is None:
        options.work = tempfile.mkdtemp(prefix="hashstash-launch-rehearsal-")
    Path(options.work).mkdir(parents=True, exist_ok=True)
    rehearsal = Rehearsal(options)
    REPORT.update(work=str(Path(options.work).resolve()), ips=rehearsal.ips, ports=rehearsal.ports,
                  release=run([Path(options.release_dir) / "hashstash", "--version"]).stdout.strip())
    started = time.monotonic()
    status = 0
    try:
        rehearsal.phase_a()
        rehearsal.phase_mined("B", options.release_dir, "kit-rehearsal", "run-rehearsal", funded=False)
        if options.fixture_release_dir:
            rehearsal.phase_mined("C", options.fixture_release_dir, "kit-fixture", "run-fixture", funded=True)
        REPORT["result"] = "passed"
    except Exception as error:
        REPORT["result"] = f"failed: {error}"
        status = 1
        raise
    finally:
        stop_all()
        REPORT["seconds"] = round(time.monotonic() - started, 1)
        (Path(options.work) / "report.json").write_text(json.dumps(REPORT, indent=2, default=str))
        log(f"report: {Path(options.work) / 'report.json'} ({REPORT['result']})")
    return status


if __name__ == "__main__":
    sys.exit(main())
