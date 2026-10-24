#!/usr/bin/env python3
"""Long-running chaos soak test on a disposable local fixture network. Standard library only.

The harness creates its own configuration, keys, databases and ports, starts several peered
test-fixtures nodes, and drives them with a seeded randomized workload while it kills,
restarts and partitions them. It checks consensus and service invariants on every node and
writes a JSON report. It never connects to an existing network; never point it at a live chain.

Linux (including WSL) is the supported platform: it uses SIGKILL/SIGINT, /proc for memory and
binds loopback aliases such as 127.0.0.11 so each node's peer traffic has its own source address.
"""
import argparse
import collections
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_network import rpc  # noqa: E402  shared JSON-RPC helper used by the network audits
from fixture_support import require_test_work  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[1]
TRANSACTION_TAG = 'Hashstash/anchor-only-transaction'
# Fixture difficulty floor: about 4096 expected hashes (and atoms of test HASH) per block. The
# timestamp adjustment raises difficulty while the soak mines faster than the target interval;
# this floor leaves about eight half-lives before blocks reach --max-block-hashes.
DEFAULT_BITS = 0x1f100000
PARAMETER_FIELDS = {
    'BlockBytes': 'block_bytes', 'Lead': 'lead', 'Rest': 'rest', 'DecisionBlocks': 'decision_blocks',
    'MinerFeePercent': 'miner_fee_percent', 'PassMarginBps': 'pass_margin_bps',
    'MinimumFeeRate': 'minimum_fee_rate', 'MaxPriceChangeBps': 'max_price_change_bps',
}
# Changes that keep the soak schedule and fees workable. The target interval is never changed:
# the harness paces mining against it to keep the timestamp difficulty adjustment bounded.
SAFE_PARAMETER_RANGES = {
    'BlockBytes': (16384, 49152), 'Lead': (45, 90), 'Rest': (300, 600), 'DecisionBlocks': (10, 24),
    'MinerFeePercent': (25, 75), 'PassMarginBps': (0, 300), 'MinimumFeeRate': (1, 3),
    'MaxPriceChangeBps': (500, 2500),
}
LOG_VIOLATION_MARKERS = ('panicked', 'panic', 'ERROR', 'Error:', 'fatal', 'stack backtrace', 'unavailable')

# ---------------------------------------------------------------------------------------------
# BIP340 signing over secp256k1 (fixed-base multiplication only; nodes verify every signature).

SECP_P = 2 ** 256 - 2 ** 32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _affine_double(point):
    x, y = point
    slope = 3 * x * x * pow(2 * y, -1, SECP_P) % SECP_P
    nx = (slope * slope - 2 * x) % SECP_P
    return nx, (slope * (x - nx) - y) % SECP_P


def _base_table():
    table, point = [], SECP_G
    for _ in range(256):
        table.append(point)
        point = _affine_double(point)
    return table


_G_TABLE = _base_table()


def _jacobian_add_affine(acc, point):
    """Add an affine point to a Jacobian accumulator (None is infinity)."""
    if acc is None:
        return (point[0], point[1], 1)
    x1, y1, z1 = acc
    x2, y2 = point
    z1z1 = z1 * z1 % SECP_P
    u2 = x2 * z1z1 % SECP_P
    s2 = y2 * z1 * z1z1 % SECP_P
    h = (u2 - x1) % SECP_P
    r = (s2 - y1) % SECP_P
    if h == 0:
        if r != 0:
            return None
        # Doubling the accumulator: only reachable for adversarial scalars, handled exactly.
        ax, ay = _jacobian_to_affine(acc)
        return (*_affine_double((ax, ay)), 1)
    hh = h * h % SECP_P
    hhh = h * hh % SECP_P
    v = x1 * hh % SECP_P
    x3 = (r * r - hhh - 2 * v) % SECP_P
    y3 = (r * (v - x3) - y1 * hhh) % SECP_P
    return x3, y3, z1 * h % SECP_P


def _jacobian_to_affine(point):
    x, y, z = point
    inverse = pow(z, -1, SECP_P)
    inverse2 = inverse * inverse % SECP_P
    return x * inverse2 % SECP_P, y * inverse2 * inverse % SECP_P


def base_multiply(scalar):
    if not 0 < scalar < SECP_N:
        raise ValueError('scalar out of range')
    acc = None
    for bit in range(scalar.bit_length()):
        if scalar >> bit & 1:
            acc = _jacobian_add_affine(acc, _G_TABLE[bit])
    return _jacobian_to_affine(acc)


def tagged_hash(tag, data):
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + data).digest()


def public_key(secret):
    return base_multiply(secret)[0].to_bytes(32, 'big')


def bip340_sign(secret, message, auxiliary):
    point = base_multiply(secret)
    d = secret if point[1] % 2 == 0 else SECP_N - secret
    masked = (d ^ int.from_bytes(tagged_hash('BIP0340/aux', auxiliary), 'big')).to_bytes(32, 'big')
    public = point[0].to_bytes(32, 'big')
    k0 = int.from_bytes(tagged_hash('BIP0340/nonce', masked + public + message), 'big') % SECP_N
    if k0 == 0:
        raise ValueError('nonce derivation failed')
    nonce_point = base_multiply(k0)
    k = k0 if nonce_point[1] % 2 == 0 else SECP_N - k0
    r = nonce_point[0].to_bytes(32, 'big')
    e = int.from_bytes(tagged_hash('BIP0340/challenge', r + public + message), 'big') % SECP_N
    return r + ((k + e * d) % SECP_N).to_bytes(32, 'big')


def self_test_signatures():
    """Check the signer against the repository's official BIP340 vectors before any network use."""
    checked = 0
    for line in (REPOSITORY / 'tests/data/bip340.csv').read_text().splitlines()[1:]:
        row = line.split(',')
        if len(row) < 7 or not row[1] or row[6] != 'TRUE':
            continue
        secret = int(row[1], 16)
        assert public_key(secret).hex().upper() == row[2], ('public key vector', row[0])
        signature = bip340_sign(secret, bytes.fromhex(row[4]), bytes.fromhex(row[3]))
        assert signature.hex().upper() == row[5], ('signature vector', row[0])
        checked += 1
    assert checked >= 4, 'BIP340 signing vectors not found'
    return checked


class Key:
    def __init__(self, label, seed):
        material = hashlib.sha256(f'hashstash-soak/{seed}/{label}'.encode()).digest()
        self.secret = int.from_bytes(material, 'big') % (SECP_N - 1) + 1
        self.public = public_key(self.secret)
        self.hex = self.public.hex()
        self.label = label


# ---------------------------------------------------------------------------------------------
# Canonical wire helpers (bincode varint, matching scripts/chain_activity.py).

def sha256d(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def varint(n):
    if n <= 250:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfb' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfc' + struct.pack('<I', n)
    return b'\xfd' + struct.pack('<Q', n)


def read_varint(raw, offset):
    tag = raw[offset]
    size = {251: 2, 252: 4, 253: 8}.get(tag, 0)
    if tag > 253:
        raise ValueError('unsupported varint')
    if not size:
        return tag, offset + 1
    return int.from_bytes(raw[offset + 1:offset + 1 + size], 'little'), offset + 1 + size


def encode_amount(n):
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'little')
    return varint(len(raw)) + raw


def body_fields(raw):
    """Decode the fixed transaction prefix: sender, nonce, fee, anchor and lifetime."""
    nonce, offset = read_varint(raw, 32)
    nonce_end = offset
    length, offset = read_varint(raw, offset)
    fee = int.from_bytes(raw[offset:offset + length], 'little')
    rest = offset + length
    anchor = raw[rest:rest + 32]
    expiry, end = read_varint(raw, rest + 32)
    return {'sender': raw[:32], 'nonce': nonce, 'nonce_end': nonce_end, 'fee': fee, 'fee_start': nonce_end,
            'fee_end': rest, 'anchor': anchor, 'expiry': expiry, 'expiry_start': rest + 32, 'expiry_end': end}


def with_fee(raw, fee):
    fields = body_fields(raw)
    return raw[:fields['fee_start']] + encode_amount(fee) + raw[fields['fee_end']:]


def with_nonce(raw, nonce):
    fields = body_fields(raw)
    return raw[:32] + varint(nonce) + raw[fields['nonce_end']:]


def with_anchor(raw, anchor, expiry=None):
    fields = body_fields(raw)
    lifetime = fields['expiry'] if expiry is None else expiry
    return raw[:fields['fee_end']] + anchor + varint(lifetime) + raw[fields['expiry_end']:]


def sign_body(key, body, rng):
    message = tagged_hash(TRANSACTION_TAG, body)
    return body + bip340_sign(key.secret, message, rng.randbytes(32))


def header_hash(header):
    raw = struct.pack('<I', header['version']) + bytes(header['previous']) + bytes(header['merkle_root'])
    raw += struct.pack('<III', header['timestamp'], header['bits'], header['nonce'])
    return sha256d(raw).hex()


def target_of(bits):
    exponent, mantissa = bits >> 24, bits & 0x7fffff
    return mantissa << 8 * (exponent - 3) if exponent >= 3 else mantissa >> 8 * (3 - exponent)


def target_hashes(bits):
    return (1 << 256) // (target_of(bits) + 1)


def error_text(error):
    """Return the node's error message without JSON-RPC framing."""
    if isinstance(error, RuntimeError) and error.args and isinstance(error.args[0], dict):
        return str(error.args[0].get('message', error.args[0]))
    return str(error)


def error_class(error):
    """Group rejection messages: numbers and hexadecimal identifiers are dropped."""
    text = error_text(error)
    out, digits = [], False
    for ch in text[:160]:
        if ch.isdigit():
            if not digits:
                out.append('#')
            digits = True
            continue
        digits = False
        out.append(ch)
    return ''.join(out)[:120]


def unavailable(error):
    """Connection-level failures are expected while the harness kills or restarts a node."""
    return isinstance(error, OSError)


THROTTLE_MARKERS = ('rate limit', 'cooldown', 'connection limit', 'budget exhausted', 'admission')
PROBE_SOURCE = '127.0.0.9'


# `status` reads the node's published snapshot; `getblock` takes its main state lock. Probing
# both separates a slow read path from a stalled writer.
PROBES = (('status', {}), ('getblock', {'height': 0}))


def probe_rpc(port, method, params, timeout):
    """RPC call from a dedicated loopback address, so workload admission never throttles it."""
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout, source_address=(PROBE_SOURCE, 0))
    try:
        connection.request('POST', '/rpc', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
                           {'Content-Type': 'application/json'})
        response = json.loads(connection.getresponse().read())
    finally:
        connection.close()
    if 'error' in response:
        raise RuntimeError(response['error'])
    return response['result']


def throttled(error):
    text = error_text(error).lower()
    return any(marker in text for marker in THROTTLE_MARKERS)


def compact(value, limit=400):
    text = json.dumps(value, sort_keys=True, default=str, separators=(',', ':'))
    return text if len(text) <= limit else text[:limit] + '...'


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(fraction * len(ordered)))]


def summary(values, scale=1.0, digits=3):
    if not values:
        return {'count': 0}
    return {'count': len(values), 'p50': round(percentile(values, 0.5) * scale, digits),
            'p95': round(percentile(values, 0.95) * scale, digits),
            'p99': round(percentile(values, 0.99) * scale, digits), 'max': round(max(values) * scale, digits)}


def raw_post(port, path, body, timeout=10):
    """Send arbitrary bytes to an HTTP endpoint; used only for malformed-request probes."""
    with socket.create_connection(('127.0.0.1', port), timeout=timeout) as connection:
        connection.sendall(b'POST ' + path.encode() + b' HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                           b'Content-Type: application/json\r\nConnection: close\r\n'
                           b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)
        chunks = []
        while True:
            try:
                chunk = connection.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks)


# ---------------------------------------------------------------------------------------------
# Ports, link proxies and node processes.

def node_ports(base, index):
    rpc_port = base + 10 * index
    return rpc_port, rpc_port + 1, rpc_port + 2


def proxy_port(base, count, source, target):
    return base + 10 * count + source * count + target


def source_address(index):
    return f'127.0.0.{11 + index}'


GARBAGE_SOURCE = '127.0.0.250'


def sever(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class LinkProxy:
    """One directed peer link. Disabling it drops live connections and refuses new ones."""

    def __init__(self, listen_port, target_port, source_ip, label):
        self.label, self.target_port, self.source_ip = label, target_port, source_ip
        self.enabled, self.closed = True, False
        self.lock = threading.Lock()
        self.active = set()
        self.stats = collections.Counter()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('127.0.0.1', listen_port))
        self.server.listen(64)
        self.server.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True, name=f'proxy-{label}').start()

    def _serve(self):
        while not self.closed:
            try:
                client, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self.enabled:
                self.stats['refused'] += 1
                sever(client)
                continue
            try:
                upstream = socket.create_connection(('127.0.0.1', self.target_port), timeout=5,
                                                    source_address=(self.source_ip, 0))
            except OSError:
                self.stats['target_down'] += 1
                sever(client)
                continue
            client.settimeout(None)
            upstream.settimeout(None)
            pair, state = (client, upstream), [0]
            with self.lock:
                if not self.enabled:
                    sever(client)
                    sever(upstream)
                    continue
                self.active.add(pair)
            self.stats['connections'] += 1
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(target=self._pump, args=(src, dst, pair, state), daemon=True).start()

    def _pump(self, source, destination, pair, state):
        clean = True
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                destination.sendall(data)
        except OSError:
            clean = False
        if clean:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                clean = False
        with self.lock:
            state[0] += 1
            finished = state[0] == 2 or not clean
            if finished:
                self.active.discard(pair)
        if finished:
            for sock in pair:
                sever(sock)

    def set_enabled(self, enabled):
        with self.lock:
            self.enabled = enabled
            doomed = [] if enabled else list(self.active)
            if not enabled:
                self.active.clear()
        for pair in doomed:
            for sock in pair:
                sever(sock)

    def close(self):
        self.closed = True
        self.set_enabled(False)
        sever(self.server)


class Mesh:
    """Full mesh of directed proxies: node i dials node j only through link (i, j)."""

    def __init__(self, base, count):
        self.base, self.count = base, count
        self.links = {}
        for i in range(count):
            for j in range(count):
                if i != j:
                    self.links[(i, j)] = LinkProxy(proxy_port(base, count, i, j), node_ports(base, j)[1],
                                                   source_address(i), f'{i + 1}->{j + 1}')

    def address(self, source, target):
        return f'127.0.0.1:{proxy_port(self.base, self.count, source, target)}'

    def partition(self, groups):
        group = {member: number for number, members in enumerate(groups) for member in members}
        for (i, j), link in self.links.items():
            link.set_enabled(group[i] == group[j])

    def heal(self):
        for link in self.links.values():
            link.set_enabled(True)

    def blocked(self):
        return sorted(f'{i + 1}->{j + 1}' for (i, j), link in self.links.items() if not link.enabled)

    def stats(self):
        total = collections.Counter()
        for link in self.links.values():
            total.update(link.stats)
        return dict(total)

    def close(self):
        for link in self.links.values():
            link.close()


class NodeProcess:
    def __init__(self, index, root, binary, config_path, base_port, miner):
        self.index, self.name = index, f'node-{index + 1}'
        self.directory = root / self.name
        self.directory.mkdir(parents=True, exist_ok=True)
        self.data = self.directory / 'chain.sqlite'
        self.rpc_port, self.p2p_port, self.stratum_port = node_ports(base_port, index)
        self.binary, self.config_path, self.miner = binary, config_path, miner
        self.stdout_path, self.stderr_path = self.directory / 'stdout.log', self.directory / 'stderr.log'
        self.process = None
        self.incarnation = 0
        self.started_at = time.monotonic()
        self.up = False
        self.peers = []
        self.log_offsets = {}
        self.lock = threading.Lock()
        self.start_seconds = []
        self.kills = self.interrupts = 0
        self.rss_baseline = None

    def start(self, peers):
        self.peers = list(peers)
        self.incarnation += 1
        args = [str(self.binary), 'run', '--config', str(self.config_path), '--data', str(self.data),
                '--miner', self.miner, '--rpc', f'127.0.0.1:{self.rpc_port}', '--p2p', f'127.0.0.1:{self.p2p_port}',
                '--stratum', f'127.0.0.1:{self.stratum_port}']
        for peer in self.peers:
            args += ['--peer', peer]
        banner = f'=== soak: {self.name} incarnation {self.incarnation} at {time.strftime("%H:%M:%S")} peers={self.peers}\n'
        for path in (self.stdout_path, self.stderr_path):
            with open(path, 'ab') as log:
                log.write(banner.encode())
        with open(self.stdout_path, 'ab') as out, open(self.stderr_path, 'ab') as err:
            self.process = subprocess.Popen(args, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                            start_new_session=os.name != 'nt')
        self.started_at = time.monotonic()
        self.rss_baseline = None
        self.command = args

    def port_conflict(self):
        """True when the last incarnation exited because a listening port was still taken."""
        lines = self.tail(self.stderr_path, 10)
        for index in range(len(lines) - 1, -1, -1):
            if lines[index].startswith('=== soak:'):
                return any('Address already in use' in line for line in lines[index:])
        return False

    def wait_ready(self, timeout):
        started = time.monotonic()
        while time.monotonic() - started < timeout:
            if self.process.poll() is not None:
                return False, f'exited with status {self.process.returncode}'
            try:
                status = rpc(self.rpc_port, 'status')
                with self.lock:
                    self.up = True
                self.start_seconds.append(round(time.monotonic() - started, 3))
                return True, status
            except (OSError, RuntimeError):
                time.sleep(0.2)
        return False, f'no RPC answer within {timeout} s'

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def kill9(self):
        with self.lock:
            self.up = False
        if self.alive():
            self.kills += 1
            if os.name == 'nt':
                self.process.kill()
            else:
                os.kill(self.process.pid, signal.SIGKILL)
        if self.process is not None:
            self.process.wait(timeout=60)

    def interrupt(self, timeout=60):
        """Graceful stop through the node's Ctrl+C handler; returns (exit status, seconds)."""
        with self.lock:
            self.up = False
        if not self.alive():
            return None, 0.0
        self.interrupts += 1
        started = time.monotonic()
        if os.name == 'nt':
            self.process.terminate()
        else:
            os.kill(self.process.pid, signal.SIGINT)
        try:
            return self.process.wait(timeout=timeout), round(time.monotonic() - started, 3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=30)
            return 'timeout', round(time.monotonic() - started, 3)

    def rss_bytes(self):
        if not self.alive():
            return None
        try:
            for line in Path(f'/proc/{self.process.pid}/status').read_text().splitlines():
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) * 1024
        except OSError:
            return None
        return None

    def disk_bytes(self):
        total = 0
        for path in self.directory.rglob('*'):
            try:
                if path.is_file() and path.suffix != '.log':
                    total += path.stat().st_size
            except OSError:
                pass
        return total

    def tail(self, path, lines=20):
        try:
            return path.read_text(errors='replace').splitlines()[-lines:]
        except OSError:
            return []


# ---------------------------------------------------------------------------------------------
# Results.

class Recorder:
    def __init__(self, violation_limit=200):
        self.started = time.monotonic()
        self.lock = threading.RLock()
        self.checks = {}
        self.counters = collections.defaultdict(collections.Counter)
        self.violations = []
        self.violation_total = 0
        self.violation_limit = violation_limit
        self.timeline = []
        self.recent = collections.deque(maxlen=80)
        self.latencies = collections.defaultdict(list)
        self.samples = collections.defaultdict(list)

    def elapsed(self):
        return round(time.monotonic() - self.started, 3)

    def note(self, _event, timeline=False, **fields):
        entry = {'t': self.elapsed(), 'event': _event, **fields}
        with self.lock:
            self.recent.append(entry)
            if timeline:
                self.timeline.append(entry)
        if timeline:
            print(f'[{entry["t"]:8.1f}s] {_event} {compact(fields, 300)}', flush=True)
        return entry

    def check(self, name, ok, node=None, message='', **context):
        with self.lock:
            entry = self.checks.setdefault(name, {'count': 0, 'violations': 0})
            entry['count'] += 1
            if ok:
                return True
            entry['violations'] += 1
            self.violation_total += 1
            if len(self.violations) < self.violation_limit:
                self.violations.append({'t': self.elapsed(), 'check': name, 'node': node, 'message': message,
                                        'context': context, 'recent_events': list(self.recent)[-30:]})
        print(f'[{self.elapsed():8.1f}s] VIOLATION {name} {node or ""}: {message}', flush=True)
        return False

    def count(self, group, key, n=1):
        with self.lock:
            self.counters[group][key] += n

    def latency(self, node, method, seconds):
        with self.lock:
            values = self.latencies[(node, method)]
            values.append(seconds)
            if len(values) > 50000:
                del values[:25000]

    def sample(self, node, metric, value):
        with self.lock:
            self.samples[(node, metric)].append((self.elapsed(), value))


class SetupError(Exception):
    pass


# ---------------------------------------------------------------------------------------------
# The soak run.

class Soak:
    def __init__(self, args):
        self.args = args
        self.recorder = Recorder()
        self.stop = threading.Event()
        self.mining_allowed = threading.Event()
        self.mining_lock = threading.Lock()
        self.state_lock = threading.RLock()
        self.nodes = []
        self.mesh = None
        self.keys = {}
        self.wallets = []
        self.accounts = []
        self.pending = collections.deque(maxlen=300)
        self.garbage_ids = set()
        self.proposals = {}
        self.supporters = collections.defaultdict(set)
        self.tip_history = collections.defaultdict(lambda: collections.deque(maxlen=64))
        self.last_checked = {}
        self.last_mempool_check = {}
        self.reorgs = []
        self.partitioned = False
        self.harness_errors = collections.Counter()
        self.settings_seen = []
        self.phases_seen = collections.Counter()
        self.decisions_seen = set()
        self.chain_id = None
        self.config = None
        self.root = None
        self.interrupted = False

    # -- infrastructure ------------------------------------------------------------------------

    def timed(self, node, method, params=None, record=True):
        started = time.monotonic()
        try:
            return rpc(node.rpc_port, method, params)
        finally:
            if record:
                self.recorder.latency(node.name, method, time.monotonic() - started)

    def live_nodes(self):
        return [node for node in self.nodes if node.up]

    def register(self, key, created=False):
        with self.state_lock:
            if key.hex not in self.keys:
                self.keys[key.hex] = key
                (self.accounts if created else self.wallets).append(key)
        return key

    def new_account(self):
        with self.state_lock:
            key = Key(f'account-{len(self.accounts)}', self.args.seed)
            return self.register(key, created=True)

    def tracked_keys(self):
        with self.state_lock:
            return list(self.keys)

    def check_ports(self):
        count = self.args.nodes
        ports = [p for i in range(count) for p in node_ports(self.args.base_port, i)]
        ports += [proxy_port(self.args.base_port, count, i, j) for i in range(count) for j in range(count) if i != j]
        busy = []
        for port in ports:
            # Only a live listener is a conflict. Client sockets lingering in TIME_WAIT on these
            # ports are handled by retrying the node start (see start_node).
            try:
                socket.create_connection(('127.0.0.1', port), timeout=0.5).close()
                busy.append(port)
            except OSError:
                pass
        if busy:
            raise SetupError(f'ports already in use: {busy}; choose another --base-port')
        try:
            low, high = map(int, Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split())
            if low <= max(ports) and min(ports) <= high:
                self.recorder.note('ephemeral_port_overlap', timeline=True, range=[low, high],
                                   ports=[min(ports), max(ports)],
                                   effect='a node restart may meet a TIME_WAIT client socket on its port and is retried')
        except (OSError, ValueError):
            pass
        for address in [source_address(index) for index in range(count)] + [PROBE_SOURCE, GARBAGE_SOURCE]:
            probe = socket.socket()
            try:
                probe.bind((address, 0))
            except OSError as error:
                raise SetupError(f'cannot bind loopback alias {address}: {error}') from error
            finally:
                probe.close()

    def setup(self):
        args = self.args
        vectors = self_test_signatures()
        self.recorder.note('signer_self_test', timeline=True, bip340_vectors=vectors)
        self.check_ports()
        self.root = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix='hashstash-soak-'))
        self.root.mkdir(parents=True, exist_ok=True)
        config = json.loads((REPOSITORY / 'config/testnet.json').read_text())
        config['test_work'] = True
        config['network'] = f'hashstash-soak-{args.seed}-{int(time.time())}'
        # The difficulty schedule is anchored at block 1, so the genesis time gives no credit.
        config['genesis_time'] = int(time.time()) - 1
        config['initial_bits'] = config['limit_bits'] = args.initial_bits
        config_path = self.root / 'network.json'
        config_path.write_text(json.dumps(config, indent=2) + '\n')
        described = subprocess.run([str(args.binary), 'network', '--config', str(config_path)],
                                   capture_output=True, text=True, timeout=60)
        if described.returncode != 0:
            raise SetupError(f'binary rejected the fixture configuration (test-fixtures build required): '
                             f'{described.stderr.strip() or described.stdout.strip()}')
        self.chain_id = json.loads(described.stdout)['chain_id']
        for index in range(args.wallets):
            self.register(Key(f'wallet-{index}', args.seed))
        self.mesh = Mesh(args.base_port, args.nodes)
        for index in range(args.nodes):
            node = NodeProcess(index, self.root, args.binary, config_path, args.base_port,
                               self.wallets[index % len(self.wallets)].hex)
            self.nodes.append(node)
        for node in self.nodes:
            ok, detail = self.start_node(node, self.full_peers(node))
            if not ok:
                raise SetupError(f'{node.name} did not start: {detail}; stderr: {node.tail(node.stderr_path)}')
            if detail['chain_id'] != self.chain_id:
                raise SetupError(f'{node.name} reports chain {detail["chain_id"]}, expected {self.chain_id}')
        self.config = rpc(self.nodes[0].rpc_port, 'config')
        self.fixture = require_test_work(self.config)
        self.recorder.note('network_started', timeline=True, root=str(self.root), chain_id=self.chain_id,
                           nodes=[n.rpc_port for n in self.nodes])
        for round_number in range(args.wallets * 2):
            recipient = self.wallets[round_number % len(self.wallets)].hex
            rpc(self.nodes[0].rpc_port, 'mine', {'count': 1, 'attempts': 5_000_000, 'recipient': recipient})
        self.converge('bootstrap')
        status = rpc(self.nodes[0].rpc_port, 'status')
        self.settings_seen.append({'t': self.recorder.elapsed(), 'height': status['height'], 'settings': status['settings']})

    def full_peers(self, node):
        return [self.mesh.address(node.index, other.index) for other in self.nodes if other is not node]

    def start_node(self, node, peers):
        """Start one incarnation, retrying while a node port is held by a lingering client socket.

        Linux's default ephemeral range covers the default ports, so an outgoing connection can
        briefly own a node's port in TIME_WAIT. That is an environment condition, not a node fault.
        """
        deadline = time.monotonic() + self.args.start_timeout
        while True:
            node.start(peers)
            ok, detail = node.wait_ready(max(1.0, deadline - time.monotonic()))
            if ok or not node.port_conflict() or time.monotonic() >= deadline:
                return ok, detail
            self.recorder.count('environment', f'{node.name}: start retried, port held by another socket')
            time.sleep(2)

    def restart(self, node, peers=None, reason=''):
        ok, detail = self.start_node(node, peers if peers is not None else self.full_peers(node))
        self.recorder.check('restart_ready', ok, node.name,
                            '' if ok else f'restart failed: {detail}', reason=reason,
                            stderr_tail=[] if ok else node.tail(node.stderr_path))
        if ok:
            self.recorder.note('restarted', timeline=True, node=node.name, reason=reason,
                               seconds=node.start_seconds[-1], height=detail['height'], peers=len(node.peers))
        return ok, detail

    # -- convergence and invariants ------------------------------------------------------------

    def break_tie(self, statuses, reason):
        """Extend one of several competing tips at the top height by one block.

        Nodes keep their first-seen tip when branches have equal work, so with mining paused an
        equal-height fork (for example a block mined just before a kill -9 and never relayed)
        would never resolve. One more block gives every node a strictly heavier chain to adopt.
        """
        top = max(s['height'] for s in statuses.values())
        leaders = {name: s['tip'] for name, s in statuses.items() if s['height'] == top}
        if len(set(leaders.values())) < 2:
            return False
        node = next(n for n in self.nodes if n.name == sorted(leaders)[0])
        try:
            rpc(node.rpc_port, 'mine', {'count': 1, 'attempts': 20_000_000})
        except (OSError, RuntimeError) as error:
            self.recorder.count('convergence', f'tie break failed: {error_class(error)}')
            return False
        self.recorder.count('convergence', 'equal-height tie broken by one block')
        self.recorder.note('tie_break', timeline=True, reason=reason, height=top, node=node.name,
                           tips={name: tip[:16] for name, tip in sorted(leaders.items())})
        return True

    def converge(self, reason):
        """Pause mining until every running node reports one tip and state root."""
        self.mining_allowed.clear()
        with self.mining_lock:
            pass
        started = time.monotonic()
        deadline = started + self.args.converge_timeout
        next_tie_break = started + self.args.tie_break_after
        statuses, failures, tie_breaks = {}, collections.Counter(), 0
        try:
            while time.monotonic() < deadline and not self.stop.is_set():
                statuses = {}
                for node in self.live_nodes():
                    try:
                        statuses[node.name] = rpc(node.rpc_port, 'status')
                    except (OSError, RuntimeError) as error:
                        failures[f'{node.name}: {error_class(error)}'] += 1
                if statuses and len({(s['tip'], s['state_root']) for s in statuses.values()}) == 1:
                    seconds = round(time.monotonic() - started, 3)
                    sample = next(iter(statuses.values()))
                    self.recorder.check('convergence', True)
                    self.recorder.note('converged', timeline=True, reason=reason, seconds=seconds,
                                       height=sample['height'], tip=sample['tip'][:16], nodes=len(statuses),
                                       tie_breaks=tie_breaks)
                    with self.recorder.lock:
                        longest = self.recorder.counters['convergence_seconds']
                        longest[reason] = max(longest[reason], seconds)
                    self.check_explorer_ready(reason)
                    for node in self.live_nodes():
                        self.check_node(node, force=True)
                        self.check_mempool(node)
                    return True
                if statuses and time.monotonic() >= next_tie_break:
                    next_tie_break = time.monotonic() + self.args.tie_break_after
                    tie_breaks += self.break_tie(statuses, reason)
                time.sleep(0.5)
            if self.stop.is_set():
                return False
            diagnostics = {}
            for node in self.live_nodes():
                try:
                    diagnostics[node.name] = rpc(node.rpc_port, 'peerstatus')['peers']
                except (OSError, RuntimeError) as error:
                    diagnostics[node.name] = error_text(error)
            self.recorder.check(
                'convergence', False, None, f'no common tip within {self.args.converge_timeout} s after {reason}',
                statuses={name: {'height': s['height'], 'tip': s['tip'], 'state_root': s['state_root'],
                                 'mempool': s['mempool']} for name, s in statuses.items()},
                tie_breaks=tie_breaks, status_failures=dict(failures), blocked_links=self.mesh.blocked(),
                peers=diagnostics)
            return False
        finally:
            self.mining_allowed.set()

    def check_explorer_ready(self, reason):
        for node in self.live_nodes():
            deadline = time.monotonic() + self.args.explorer_timeout
            last = None
            while time.monotonic() < deadline:
                try:
                    result = rpc(node.rpc_port, 'explorer_blocks', {'limit': 1})
                    status = rpc(node.rpc_port, 'status')
                    if result['tip'] == status['tip'] or result['height'] < status['height']:
                        last = None
                        break
                    last = 'explorer behind tip'
                except RuntimeError as error:
                    last = error_text(error)
                    if 'updating' not in last.lower():
                        break
                except OSError as error:
                    last = error_text(error)
                time.sleep(0.5)
            self.recorder.check('explorer_ready', last is None, node.name,
                                '' if last is None else f'explorer not ready {self.args.explorer_timeout} s after {reason}: {last}')

    def snapshot_all(self, node):
        """Read balances of every tracked key from one tip, splitting at the RPC's key limit."""
        keys = self.tracked_keys()
        chunks = [keys[i:i + 256] for i in range(0, len(keys), 256)]
        for _ in range(5):
            snapshots = [self.timed(node, 'snapshot', {'keys': chunk}) for chunk in chunks]
            if len({(s['status']['tip'], s['status']['state_root']) for s in snapshots}) == 1:
                balances = {}
                for snap in snapshots:
                    balances.update(snap['balances'])
                return snapshots[0], balances
        return None, None

    def check_node(self, node, force=False):
        """Conservation and world-accounting invariants for the node's current tip."""
        try:
            snap, balances = self.snapshot_all(node)
        except (OSError, RuntimeError) as error:
            self.recorder.count('invariant_skipped', f'snapshot: {error_class(error)}')
            return
        if snap is None:
            self.recorder.count('invariant_skipped', 'tip moved during multi-part snapshot')
            return
        status, governance = snap['status'], snap['governance']
        if not force and self.last_checked.get(node.name) == status['state_root']:
            return
        self.last_checked[node.name] = status['state_root']
        where = {'height': status['height'], 'tip': status['tip'], 'phase': status['phase']}
        self.phases_seen[status['phase']] += 1
        if status.get('decision'):
            self.decisions_seen.add(status['decision'])
        if self.settings_seen and status['settings'] != self.settings_seen[-1]['settings']:
            previous = self.settings_seen[-1]['settings']
            changed = {k: [previous.get(k), v] for k, v in status['settings'].items() if previous.get(k) != v}
            self.settings_seen.append({'t': self.recorder.elapsed(), 'node': node.name, 'height': status['height'],
                                       'changed': changed, 'settings': status['settings']})
            self.recorder.note('settings_changed', timeline=True, node=node.name, height=status['height'], changed=changed)
        self.recorder.check('snapshot_consistency',
                            status['state_root'] == governance['state_root'] and status['height'] == governance['height']
                            and all(status[f] == governance['world'][f] for f in ('reserve', 'shares', 'curve_mass', 'revenue', 'grant_capacity')),
                            node.name, 'status and governance disagree within one snapshot', **where)
        issued = int(status['issued'])
        escrow = int(governance['auction_escrow'])
        worlds = [('fail', 'account', governance['world'])]
        if governance['pass'] is not None:
            worlds.append(('pass', 'pass', governance['pass']))
        self.recorder.check('fail_world_grant_escrow', int(governance['world']['grant_escrow']) == 0, node.name,
                            f'FAIL/main world grant escrow {governance["world"]["grant_escrow"]}', **where)
        for name, field, world in worlds:
            held = [b[field] for b in balances.values() if b and b.get(field)]
            cash = sum(int(b['ordinary']) for b in held)
            shares = sum(int(b['shares']) for b in held)
            reserve, revenue, grants = int(world['reserve']), int(world['revenue']), int(world['grant_escrow'])
            total = cash + reserve + revenue + grants + escrow
            self.recorder.check(
                'conservation', total == issued, node.name,
                f'{name} world: accounts {cash} + reserve {reserve} + revenue {revenue} + grant escrow {grants} '
                f'+ auction escrow {escrow} = {total}, issued {issued} (difference {total - issued})',
                world=name, accounts=len(held), tracked=len(balances), **where)
            self.recorder.check('share_conservation', shares == int(world['account_shares']), node.name,
                                f'{name} world: tracked shares {shares} != account_shares {world["account_shares"]}',
                                world=name, **where)
            self.recorder.check('share_supply', int(world['account_shares']) == int(world['shares']), node.name,
                                f'{name} world: account_shares {world["account_shares"]} != shares {world["shares"]}',
                                world=name, **where)
            mass = int(world['curve_mass'])
            self.recorder.check('curve_bounds', 0 <= reserve <= mass and (reserve == 0) == (mass == 0) == (int(world['shares']) == 0),
                                node.name, f'{name} world: reserve {reserve}, curve mass {mass}, shares {world["shares"]}',
                                world=name, **where)
            self.recorder.check('grant_capacity', int(world['grant_capacity']) == revenue + max(0, reserve - 1), node.name,
                                f'{name} world: grant capacity {world["grant_capacity"]} != revenue + reserve - 1',
                                world=name, **where)

    def check_mempool(self, node):
        """Every pooled transaction must be valid for the next block on the node's tip."""
        try:
            before = rpc(node.rpc_port, 'status')
            rows, offset = [], 0
            while True:
                page = self.timed(node, 'mempool', {'format': 'hex', 'offset': offset, 'limit': 128})
                rows += page
                if len(page) < 128:
                    break
                offset += 128
            entries, anchors = [], {}
            for row in rows:
                raw = bytes.fromhex(row['raw'])
                self.recorder.check('mempool_txid', sha256d(raw).hex() == row['txid'], node.name,
                                    f'mempool txid {row["txid"]} does not hash its bytes')
                fields = body_fields(raw[:-64])
                entries.append((row['txid'], fields, len(raw)))
            nonces = {}
            for sender in {fields['sender'].hex() for _, fields, _ in entries}:
                try:
                    nonces[sender] = rpc(node.rpc_port, 'account', {'key': sender})['account']['nonce']
                except RuntimeError as error:
                    if 'does not exist' not in error_text(error):
                        raise
                    nonces[sender] = 0
            for anchor in {fields['anchor'].hex() for _, fields, _ in entries}:
                try:
                    block = rpc(node.rpc_port, 'getblock', {'hash': anchor})
                    active = rpc(node.rpc_port, 'getblock', {'height': block['height']})
                    anchors[anchor] = block['height'] if header_hash(active['header']) == anchor else 'inactive'
                except RuntimeError as error:
                    anchors[anchor] = f'unknown: {error_class(error)}'
            after = rpc(node.rpc_port, 'status')
        except (OSError, RuntimeError) as error:
            self.recorder.count('invariant_skipped', f'mempool: {error_class(error)}')
            return
        if before['tip'] != after['tip'] or len(rows) != before['mempool']:
            self.recorder.count('invariant_skipped', 'mempool changed during read')
            return
        where = {'height': after['height'], 'tip': after['tip'], 'size': len(rows)}
        next_height = after['height'] + 1
        garbage = [txid for txid, _, _ in entries if txid in self.garbage_ids]
        self.recorder.check('mempool_no_garbage', not garbage, node.name, f'invalid submissions pooled: {garbage}', **where)
        by_sender = collections.defaultdict(list)
        for txid, fields, _ in entries:
            by_sender[fields['sender'].hex()].append(fields['nonce'])
        duplicates = {s: n for s, n in by_sender.items() if len(n) != len(set(n))}
        self.recorder.check('mempool_unique_nonce', not duplicates, node.name, f'same sender and nonce pooled twice: {duplicates}', **where)
        gaps = {s: {'account_nonce': nonces[s], 'pooled': sorted(n)} for s, n in by_sender.items()
                if sorted(n) != list(range(nonces[s], nonces[s] + len(n)))}
        self.recorder.check('mempool_nonce_sequence', not gaps, node.name, f'pooled nonces are not the next sequence: {gaps}', **where)
        bad_anchors = []
        for txid, fields, _ in entries:
            height = anchors.get(fields['anchor'].hex())
            if not isinstance(height, int) or not height < next_height <= height + fields['expiry']:
                bad_anchors.append({'txid': txid, 'anchor': fields['anchor'].hex(), 'anchor_height': height,
                                    'expiry_blocks': fields['expiry']})
        self.recorder.check('mempool_anchor_valid', not bad_anchors, node.name, f'expired or off-branch anchors pooled: {bad_anchors[:5]}', **where)
        size = sum(length + len(varint(length)) for _, _, length in entries)
        capacity = int(after['settings']['block_bytes'])
        self.recorder.check('mempool_capacity', size <= capacity, node.name,
                            f'pooled records {size} bytes exceed block capacity {capacity}', **where)

    def observe_tips(self):
        """Poll every node; run invariant checks on each new tip and record reorganizations."""
        now = time.monotonic()
        for node in self.live_nodes():
            try:
                status = rpc(node.rpc_port, 'status')
            except (OSError, RuntimeError):
                continue
            history = self.tip_history[node.name]
            if not history or history[-1] != (status['height'], status['tip']):
                if history:
                    self.detect_reorg(node, history, status)
                history.append((status['height'], status['tip']))
                self.check_node(node)
            if now - self.last_mempool_check.get(node.name, 0) >= self.args.mempool_check_interval:
                self.last_mempool_check[node.name] = now
                self.check_mempool(node)

    def detect_reorg(self, node, history, status):
        old_height, old_tip = history[-1]
        if old_height < status['height']:
            try:
                block = rpc(node.rpc_port, 'getblock', {'height': old_height})
            except (OSError, RuntimeError):
                return
            if header_hash(block['header']) == old_tip:
                return
        depth = None
        for height, tip in reversed(history):
            if height > status['height']:
                continue
            try:
                block = rpc(node.rpc_port, 'getblock', {'height': height})
            except (OSError, RuntimeError):
                return
            if header_hash(block['header']) == tip:
                depth = old_height - height
                break
        if depth == 0:
            return  # The node switched back to the old tip between the two reads.
        entry = {'node': node.name, 'from_height': old_height, 'to_height': status['height'],
                 'depth_at_least': depth if depth is not None else old_height - history[0][0]}
        self.reorgs.append({'t': self.recorder.elapsed(), **entry})
        self.recorder.note('reorg', timeline=entry['depth_at_least'] >= 2, **entry)

    def idle(self, seconds):
        """Keep checking invariants while a chaos condition holds."""
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self.stop.is_set():
            self.observe_tips()
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))

    # -- background threads --------------------------------------------------------------------

    def guarded(self, name, loop):
        def run():
            try:
                loop()
            except Exception:  # A harness defect must be visible, never a silent thread death.
                self.harness_errors[f'{name} thread crashed'] += 1
                self.recorder.check('harness_thread', False, None, f'{name} thread crashed', traceback=traceback.format_exc())
        thread = threading.Thread(target=run, name=name, daemon=True)
        thread.start()
        return thread

    def miner_loop(self):
        rng = random.Random(f'{self.args.seed}/miner')
        last_block = time.monotonic()
        while not self.stop.wait(rng.uniform(0.4, 1.6) * self.args.block_interval):
            if not self.mining_allowed.is_set():
                continue
            with self.mining_lock:
                if not self.mining_allowed.is_set():
                    continue
                candidates = self.live_nodes()
                if not candidates:
                    continue
                node = rng.choice(candidates)
                try:
                    status = rpc(node.rpc_port, 'status')
                    tip = rpc(node.rpc_port, 'getblock', {'hash': status['tip']})
                    # A block's target follows its parent's timestamp, so waiting alone never
                    # lowers it. Above the bound, mine at the target interval: each such block
                    # keeps pace with the schedule and difficulty stops climbing.
                    if (target_hashes(tip['header']['bits']) > self.args.max_block_hashes
                            and time.monotonic() - last_block < status['settings']['interval']):
                        self.recorder.count('mining', 'paced to the target interval: difficulty above --max-block-hashes')
                        continue
                    params = {'count': 1, 'attempts': 50_000_000}
                    if rng.random() < 0.7:
                        params['recipient'] = rng.choice(self.wallets).hex
                    self.timed(node, 'mine', params)
                    last_block = time.monotonic()
                    self.recorder.count('mining', f'{node.name} mined')
                except (OSError, RuntimeError) as error:
                    self.recorder.count('mining', f'error: {error_class(error)}')

    def probe_loop(self):
        last_resources = last_logs = 0.0
        while not self.stop.wait(self.args.probe_interval):
            for node in self.nodes:
                with node.lock:
                    up = node.up
                if not up:
                    continue
                if not node.alive():
                    with node.lock:
                        expected = not node.up
                        node.up = False
                    if not expected:
                        self.recorder.check('node_alive', False, node.name,
                                            f'process exited unexpectedly with status {node.process.returncode}',
                                            stderr_tail=node.tail(node.stderr_path, 40))
                    continue
                for method, params in PROBES:
                    started = time.monotonic()
                    grace = started - node.started_at < self.args.startup_grace
                    try:
                        probe_rpc(node.rpc_port, method, params, max(30.0, 2 * self.args.max_rpc_latency))
                        seconds = time.monotonic() - started
                        self.recorder.latency(node.name, f'{method}_probe', seconds)
                        self.recorder.check('rpc_latency', seconds <= self.args.max_rpc_latency or grace, node.name,
                                            f'{method} took {seconds:.2f} s (bound {self.args.max_rpc_latency} s)')
                    except (OSError, RuntimeError) as error:
                        seconds = time.monotonic() - started
                        with node.lock:
                            still_up = node.up
                        if throttled(error):
                            self.recorder.count('probe', f'throttled: {error_class(error)}')
                        elif still_up and node.alive() and not grace:
                            self.recorder.check('rpc_available', False, node.name,
                                                f'{method} failed after {seconds:.2f} s: {error_text(error)}')
            now = time.monotonic()
            if now - last_resources >= self.args.resource_interval:
                last_resources = now
                self.sample_resources()
            if now - last_logs >= 5:
                last_logs = now
                for node in self.nodes:
                    self.scan_logs(node)

    def sample_resources(self):
        for node in self.nodes:
            rss = node.rss_bytes()
            if rss is not None:
                self.recorder.sample(node.name, 'rss_bytes', rss)
                limit = self.args.max_rss_mb * 1024 * 1024
                self.recorder.check('rss_bound', rss <= limit, node.name, f'RSS {rss >> 20} MiB exceeds {self.args.max_rss_mb} MiB')
                uptime = time.monotonic() - node.started_at
                if node.rss_baseline is None and uptime >= 60:
                    node.rss_baseline = rss
                elif node.rss_baseline is not None:
                    growth = rss - node.rss_baseline
                    self.recorder.check('rss_growth', growth <= self.args.max_rss_growth_mb * 1024 * 1024, node.name,
                                        f'RSS grew {growth >> 20} MiB within one incarnation (bound {self.args.max_rss_growth_mb} MiB)')
            disk = node.disk_bytes()
            self.recorder.sample(node.name, 'disk_bytes', disk)
            self.recorder.check('disk_bound', disk <= self.args.max_disk_mb * 1024 * 1024, node.name,
                                f'data directory {disk >> 20} MiB exceeds {self.args.max_disk_mb} MiB')
            history = self.tip_history.get(node.name)
            if history:
                height = max(1, history[-1][0])
                per_block = disk / height / 1024
                self.recorder.check('disk_per_block', per_block <= self.args.max_disk_per_block_kb, node.name,
                                    f'data directory uses {per_block:.1f} KiB per block (bound {self.args.max_disk_per_block_kb} KiB)')

    def scan_logs(self, node):
        for path in (node.stdout_path, node.stderr_path):
            offset = node.log_offsets.get(path, 0)
            try:
                with open(path, 'rb') as log:
                    log.seek(offset)
                    data = log.read()
            except OSError:
                continue
            end = data.rfind(b'\n') + 1
            node.log_offsets[path] = offset + end
            bad = []
            for line in data[:end].decode(errors='replace').splitlines():
                if line.startswith('=== soak:') or not any(marker in line for marker in LOG_VIOLATION_MARKERS):
                    continue
                if 'Address already in use' in line:
                    self.recorder.count('environment', 'bind conflict reported by a retried start')
                    continue
                bad.append(line)
            self.recorder.check('node_log_clean', not bad, node.name, f'{len(bad)} error lines in {path.name}: {bad[:5]}',
                                file=str(path))

    def workload_loop(self):
        rng = random.Random(f'{self.args.seed}/workload')
        while not self.stop.wait(rng.uniform(0.5, 1.5) / self.args.tx_rate):
            candidates = self.live_nodes()
            if not candidates:
                continue
            node = rng.choice(candidates)
            try:
                self.workload_step(rng, node)
            except (OSError, RuntimeError) as error:
                key = 'node unavailable' if unavailable(error) else error_class(error)
                self.recorder.count('workload_interrupted', key)
            except Exception as error:  # Harness defects are reported, not hidden.
                self.harness_errors[f'{type(error).__name__}: {error}'[:160]] += 1
                self.recorder.note('harness_error', error=repr(error), traceback=traceback.format_exc()[-1500:])

    # -- workload ------------------------------------------------------------------------------

    def workload_step(self, rng, node):
        status = rpc(node.rpc_port, 'status')
        phase = status['phase']
        weights = {'transfer': 30, 'transfer_new': 8 if len(self.accounts) < self.args.max_accounts else 0,
                   'chat': 6, 'mail': 3, 'deposit': 12, 'redeem': 8, 'bump': 6, 'garbage': 6,
                   'block_garbage': 1, 'rpc_garbage': 1, 'refund': 2 if self.proposals else 0}
        if phase == 'auction' and status['auction_round'] is not None:
            weights.update({'propose_grant': 5, 'propose_parameter': 6, 'support': 12})
        elif phase == 'governance':
            # Only sustained one-sided trading on a curve bent by a reserve-funded grant can earn
            # PASS blocks, so trade harder while a decision runs.
            weights.update({'deposit': 30, 'redeem': 10})
        kinds = list(weights)
        kind = rng.choices(kinds, [weights[k] for k in kinds])[0]
        getattr(self, f'op_{kind}')(rng, node, status)

    def account(self, node, key, outcome=None):
        params = {'key': key.hex}
        if outcome:
            params['outcome'] = outcome
        try:
            return rpc(node.rpc_port, 'account', params)['account']
        except RuntimeError as error:
            if 'does not exist' in error_text(error):
                return None
            raise

    def pick_sender(self, rng, node, minimum=1, outcome=None):
        with self.state_lock:
            pool = list(self.wallets) * 3 + list(self.accounts)
        for _ in range(4):
            key = rng.choice(pool)
            account = self.account(node, key, outcome)
            if account and int(account['ordinary']) >= minimum:
                return key, account
        return None, None

    def submit(self, rng, node, sender, operation, kind, data_hex=None, extra_fee=None, expiry=None):
        params = {'sender': sender.hex, 'operation': operation,
                  'extra_fee': str(extra_fee if extra_fee is not None else rng.choice([0, 0, 0, 1, 2, 5, rng.randint(1, 200)])),
                  'expiry_blocks': expiry or rng.randint(3, 24)}
        if data_hex is not None:
            params['data_hex'] = data_hex
        self.recorder.count('submitted', kind)
        try:
            prepared = self.timed(node, 'preparetransaction', params)
        except RuntimeError as error:
            self.recorder.count('prepare_rejected', f'{kind}: {error_class(error)}')
            return None
        body = bytes.fromhex(prepared['body'])
        fields = body_fields(body)
        self.recorder.check('prepared_body', fields['sender'] == sender.public and fields['expiry'] == params['expiry_blocks'],
                            node.name, 'prepared body differs from the requested sender or lifetime')
        raw = sign_body(sender, body, rng)
        target = node
        others = [n for n in self.live_nodes() if n is not node]
        if others and rng.random() < self.args.cross_submit:
            target = rng.choice(others)
        try:
            result = self.timed(target, 'broadcasttransaction', {'raw': raw.hex()})
        except RuntimeError as error:
            # Another node may not yet hold the sender's earlier pooled transactions.
            route = ' (cross-node)' if target is not node else ''
            self.recorder.count('rejected', f'{kind}{route}: {error_class(error)}')
            return None
        txid = sha256d(raw).hex()
        self.recorder.check('transaction_id', result.get('transaction_id') == txid, target.name,
                            f'node returned {result.get("transaction_id")} for transaction {txid}')
        self.recorder.count('accepted', kind)
        self.recorder.note('tx', kind=kind, node=target.name, txid=txid[:16], nonce=fields['nonce'], fee=fields['fee'])
        with self.state_lock:
            self.pending.append({'node': target, 'key': sender, 'body': body, 'raw': raw, 'txid': txid, 'kind': kind,
                                 'fee': fields['fee'], 'nonce': fields['nonce'], 't': time.monotonic()})
        return txid

    def op_transfer(self, rng, node, status, new=False, data_hex=None, kind='transfer'):
        sender, account = self.pick_sender(rng, node, 10)
        if sender is None:
            self.recorder.count('skipped', f'{kind}: no funded sender')
            return
        if new:
            recipient = self.new_account()
        else:
            with self.state_lock:
                recipient = rng.choice([k for k in self.keys.values() if k is not sender])
        amount = rng.randint(1, max(1, int(account['ordinary']) // 50))
        operation = {'TransferExact': {'recipient': list(recipient.public), 'amount': str(amount)}}
        self.submit(rng, node, sender, operation, kind, data_hex=data_hex)

    def op_transfer_new(self, rng, node, status):
        self.op_transfer(rng, node, status, new=True, kind='transfer_new')

    def op_chat(self, rng, node, status):
        words = ['soak', 'block', 'reorg', 'stash', 'hash', 'peer', 'fork', 'grant', 'pass', 'fail', 'ünïcode', '🌱']
        text = ' '.join(rng.choice(words) for _ in range(rng.randint(1, 40)))
        self.op_transfer(rng, node, status, data_hex=text.encode().hex(), kind='chat')

    def op_mail(self, rng, node, status):
        with self.state_lock:
            ephemeral = rng.choice(list(self.keys.values())).hex
        envelope = {'ephemeral_key': ephemeral, 'iv': rng.randbytes(12).hex(), 'ciphertext': rng.randbytes(1168).hex(),
                    'recipient_iv': rng.randbytes(12).hex(), 'recipient_key': rng.randbytes(48).hex(),
                    'sender_iv': rng.randbytes(12).hex(), 'sender_key': rng.randbytes(48).hex()}
        data = b'hashstash.mail/2\n' + json.dumps(envelope, separators=(',', ':')).encode()
        self.op_transfer(rng, node, status, data_hex=data.hex(), kind='mail')

    def world_choice(self, rng, status, favored=True):
        """Pick a side; each decision has a seeded favorite so both outcomes occur over a run."""
        if status['phase'] == 'governance' and status['decision']:
            favorite = 'Pass' if random.Random(f'{self.args.seed}/{status["decision"]}').random() < 0.6 else 'Fail'
            other = 'Fail' if favorite == 'Pass' else 'Pass'
            side = favorite if (rng.random() < 0.8) == favored else other
            return side, list(bytes.fromhex(status['decision']))
        return None, None

    def op_deposit(self, rng, node, status):
        outcome, decision = self.world_choice(rng, status)
        sender, account = self.pick_sender(rng, node, 50, outcome)
        if sender is None:
            self.recorder.count('skipped', 'deposit: no funded sender')
            return
        amount = rng.randint(1, max(1, int(account['ordinary']) // 20))
        kind = f'deposit_{(outcome or "rest").lower()}'
        self.submit(rng, node, sender, {'Deposit': {'amount': str(amount), 'decision': decision, 'outcome': outcome}}, kind)

    def op_redeem(self, rng, node, status):
        outcome, decision = self.world_choice(rng, status, favored=False)
        with self.state_lock:
            pool = list(self.keys.values())
        for _ in range(5):
            key = rng.choice(pool)
            account = self.account(node, key, outcome)
            if account and int(account['shares']) > 0 and int(account['ordinary']) > 5:
                shares = int(account['shares'])
                amount = shares if rng.random() < 0.2 else rng.randint(1, shares)
                kind = f'redeem_{(outcome or "rest").lower()}'
                self.submit(rng, node, key, {'Redeem': {'shares': str(amount), 'decision': decision, 'outcome': outcome}}, kind)
                return
        self.recorder.count('skipped', 'redeem: no shareholder found')

    def op_propose_grant(self, rng, node, status):
        sender, account = self.pick_sender(rng, node, 100)
        if sender is None:
            return
        with self.state_lock:
            candidates = list(self.keys.values())
        recipients = rng.sample(candidates, min(len(candidates), rng.randint(1, 3)))
        if rng.random() < 0.3 and len(self.accounts) < self.args.max_accounts:
            recipients.append(self.new_account())
        recipients = sorted({k.public: k for k in recipients}.values(), key=lambda k: k.public)
        # A grant covered by waiting revenue leaves both curves flat, and flat curves can never
        # earn PASS blocks. The winner's support also joins waiting revenue when it wins, so ask
        # for revenue plus that support plus part of reserve: a winning grant then bends the
        # PASS curve. Grants carry more support than parameter changes so they win auctions
        # too. Some requests exceed capacity and stay unfunded.
        capacity = max(1, int(status['grant_capacity']))
        ordinary = int(account['ordinary'])
        support = rng.randint(max(1, ordinary // 40), max(1, ordinary // 15))
        if rng.random() < 0.15:
            total = rng.randint(capacity + 1, 2 * capacity)
        else:
            reserve_part = max(1, int(int(status['reserve']) * rng.uniform(0.2, 0.6)))
            total = min(capacity, int(status['revenue']) + support + reserve_part)
        recipients = recipients[:max(1, min(len(recipients), total))]
        cuts = sorted(rng.sample(range(1, total), len(recipients) - 1)) if len(recipients) > 1 else []
        amounts = [b - a for a, b in zip([0] + cuts, cuts + [total])]
        payments = [{'recipient': list(k.public), 'amount': str(a)} for k, a in zip(recipients, amounts)]
        operation = {'Propose': {'round': status['auction_round'], 'description': list(rng.randbytes(32)),
                                 'proposal': {'Grant': {'payments': payments}}, 'support': str(support)}}
        self.submit(rng, node, sender, operation, 'propose_grant')

    def op_propose_parameter(self, rng, node, status):
        sender, account = self.pick_sender(rng, node, 100)
        if sender is None:
            return
        frozen = rpc(node.rpc_port, 'governance')['frozen']
        name = rng.choice(sorted(SAFE_PARAMETER_RANGES))
        old = frozen.get(PARAMETER_FIELDS[name])
        if old is None:
            return
        low, high = SAFE_PARAMETER_RANGES[name]
        new = old
        while new == old:
            new = rng.randint(low, high)
            if name == 'BlockBytes':
                new -= new % 1024
        support = rng.randint(1, max(1, int(account['ordinary']) // 50))
        operation = {'Propose': {'round': status['auction_round'], 'description': list(rng.randbytes(32)),
                                 'proposal': {'Parameter': {'parameter': name, 'old': old, 'new': new}},
                                 'support': str(support)}}
        self.submit(rng, node, sender, operation, 'propose_parameter')

    def op_support(self, rng, node, status):
        round_id = status['auction_round']
        rows = rpc(node.rpc_port, 'proposals', {'round': round_id})
        if not rows:
            self.recorder.count('skipped', 'support: no proposal')
            return
        grants = [r for r in rows if 'Grant' in r.get('proposal', {}).get('action', {})]
        row = rng.choice(grants if grants and rng.random() < 0.7 else rows)
        with self.state_lock:
            self.proposals[row['id']] = round_id
        sender, account = self.pick_sender(rng, node, 50)
        if sender is None:
            return
        amount = rng.randint(1, max(1, int(account['ordinary']) // 30))
        operation = {'Support': {'round': round_id, 'proposal': list(bytes.fromhex(row['id'])), 'amount': str(amount)}}
        if self.submit(rng, node, sender, operation, 'support'):
            with self.state_lock:
                self.supporters[row['id']].add(sender.hex)

    def op_refund(self, rng, node, status):
        with self.state_lock:
            proposal = rng.choice(sorted(self.proposals))
            round_id = self.proposals[proposal]
            supporters = sorted(self.supporters.get(proposal, ()))
        if not supporters:
            return
        key = self.keys[rng.choice(supporters)]
        try:
            record = rpc(node.rpc_port, 'support', {'key': key.hex, 'proposal': proposal, 'round': round_id})
        except RuntimeError as error:
            self.recorder.count('skipped', f'refund: {error_class(error)}')
            return
        if not record['refundable'] and rng.random() < 0.8:
            return
        kind = 'refund' if record['refundable'] else 'refund_early'
        self.submit(rng, node, key, {'Refund': {'round': round_id, 'proposal': list(bytes.fromhex(proposal))}}, kind)

    def op_bump(self, rng, node, status):
        """Re-sign a still-pooled transaction at the same nonce with a higher (or lower) fee."""
        try:
            pooled = {row['txid'] for row in rpc(node.rpc_port, 'mempool', {'format': 'hex', 'limit': 128})}
        except (OSError, RuntimeError):
            return
        with self.state_lock:
            recent = [p for p in self.pending if p['txid'] in pooled and p['node'] is node]
        if not recent:
            self.recorder.count('skipped', 'bump: none of our transactions pooled on this node')
            return
        original = rng.choice(recent)
        underbid = rng.random() < 0.2 and original['fee'] > 1
        fee = original['fee'] - 1 if underbid else original['fee'] + rng.randint(1, 50)
        body = with_fee(original['body'], fee)
        raw = sign_body(original['key'], body, rng)
        kind = 'fee_underbid' if underbid else 'fee_bump'
        target = original['node']
        self.recorder.count('submitted', kind)
        try:
            result = self.timed(target, 'broadcasttransaction', {'raw': raw.hex()})
        except (OSError, RuntimeError) as error:
            self.recorder.count('rejected', f'{kind}: {error_class(error)}')
            return
        txid = result.get('transaction_id')
        self.recorder.count('accepted', kind)
        self.recorder.note('tx', kind=kind, node=target.name, txid=(txid or '')[:16], replaces=original['txid'][:16], fee=fee)
        with self.state_lock:
            self.pending.append({**original, 'body': body, 'raw': raw, 'txid': txid, 'fee': fee,
                                 't': time.monotonic(), 'kind': kind})
        try:
            pooled = {row['txid'] for row in rpc(target.rpc_port, 'mempool', {'format': 'hex', 'limit': 128})}
        except (OSError, RuntimeError):
            return
        self.recorder.check('fee_replacement', not (txid in pooled and original['txid'] in pooled), target.name,
                            f'{kind} {txid} and the transaction it replaces {original["txid"]} are both pooled',
                            nonce=original['nonce'], fees=[original['fee'], fee])

    def prepared_transfer(self, rng, node):
        sender, account = self.pick_sender(rng, node, 10)
        if sender is None:
            return None, None
        with self.state_lock:
            recipient = rng.choice(self.wallets)
        operation = {'TransferExact': {'recipient': list(recipient.public), 'amount': '1'}}
        prepared = rpc(node.rpc_port, 'preparetransaction', {'sender': sender.hex, 'operation': operation,
                                                              'extra_fee': '0', 'expiry_blocks': 6})
        return sender, bytes.fromhex(prepared['body'])

    def op_garbage(self, rng, node, status):
        """Submissions that are invalid by construction; any acceptance is a violation."""
        variant = rng.choice(['random_bytes', 'truncated', 'trailing_byte', 'bad_signature', 'wrong_signer',
                              'future_nonce', 'random_anchor', 'zero_expiry', 'stale_replay', 'overspend'])
        self.recorder.count('submitted', f'garbage_{variant}')
        raw = None
        if variant == 'random_bytes':
            raw = rng.randbytes(rng.randint(1, 600))
        elif variant == 'stale_replay':
            now = time.monotonic()
            with self.state_lock:
                old = [p for p in self.pending if now - p['t'] > 120]
            if not old:
                return
            raw = rng.choice(old)['raw']
        elif variant == 'overspend':
            sender, account = self.pick_sender(rng, node, 1)
            if sender is None:
                return
            operation = {'TransferExact': {'recipient': list(rng.choice(self.wallets).public),
                                           'amount': str(int(account['ordinary']) * 4 + 1000)}}
            try:
                prepared = rpc(node.rpc_port, 'preparetransaction', {'sender': sender.hex, 'operation': operation})
            except RuntimeError:
                self.recorder.count('rejected', f'garbage_{variant}: rejected at preparation')
                return
            raw = sign_body(sender, bytes.fromhex(prepared['body']), rng)
        else:
            sender, body = self.prepared_transfer(rng, node)
            if body is None:
                return
            fields = body_fields(body)
            signer = sender
            if variant == 'future_nonce':
                body = with_nonce(body, fields['nonce'] + 1000 + rng.randint(0, 1000))
            elif variant == 'random_anchor':
                body = with_anchor(body, rng.randbytes(32))
            elif variant == 'zero_expiry':
                body = with_anchor(body, fields['anchor'], expiry=0)
            elif variant == 'wrong_signer':
                with self.state_lock:
                    signer = rng.choice([k for k in self.keys.values() if k is not sender])
            raw = bytearray(sign_body(signer, body, rng))
            if variant == 'truncated':
                raw = raw[:rng.randint(1, len(raw) - 1)]
            elif variant == 'trailing_byte':
                raw += bytes([rng.randrange(256)])
            elif variant == 'bad_signature':
                position = len(raw) - 1 - rng.randrange(64)
                raw[position] ^= 1 << rng.randrange(8)
            raw = bytes(raw)
        txid = sha256d(raw).hex()
        with self.state_lock:
            self.garbage_ids.add(txid)
        try:
            result = rpc(node.rpc_port, 'broadcasttransaction', {'raw': raw.hex()})
        except RuntimeError as error:
            self.recorder.count('rejected', f'garbage_{variant}: {error_class(error)}')
            return
        if variant in ('stale_replay', 'overspend'):
            # Valid again after a reorganization (replay) or a prior credit (overspend) is possible.
            with self.state_lock:
                self.garbage_ids.discard(txid)
            self.recorder.count('accepted', f'garbage_{variant} (state-dependent)')
            self.recorder.note('state_dependent_accept', variant=variant, node=node.name, txid=txid[:16])
            return
        self.recorder.check('garbage_rejected', False, node.name, f'{variant} transaction accepted', txid=result.get('transaction_id'),
                            raw=raw.hex()[:400])

    def op_block_garbage(self, rng, node, status):
        """Re-mined blocks with invalid bodies, plus malformed block documents."""
        variant = rng.choice(['state_root', 'miner', 'height', 'parent', 'malformed'])
        self.recorder.count('submitted', f'block_{variant}')
        block = rpc(node.rpc_port, 'getblock')
        if variant == 'malformed':
            block = {'header': {'version': 1}, 'height': 'x'}
        else:
            if variant == 'state_root':
                block['state_root'][rng.randrange(32)] ^= 1
            elif variant == 'miner':
                others = [k for k in self.keys.values() if k.public != bytes(block['miner'])]
                block['miner'] = list(rng.choice(others).public)
            elif variant == 'height':
                block['height'] += 1
            elif variant == 'parent':
                block['header']['previous'] = list(rng.randbytes(32))
            header = block['header']
            target = target_of(header['bits'])
            prefix = struct.pack('<I', header['version']) + bytes(header['previous']) + bytes(header['merkle_root'])
            prefix += struct.pack('<II', header['timestamp'], header['bits'])
            start = rng.randrange(1 << 32)
            for attempt in range(min(4 * target_hashes(header['bits']), 4_000_000)):
                nonce = (start + attempt) & 0xffffffff
                if int.from_bytes(sha256d(prefix + struct.pack('<I', nonce)), 'little') <= target:
                    header['nonce'] = nonce
                    break
            else:
                self.recorder.count('skipped', 'block garbage: proof of work not found')
                return
        try:
            result = rpc(node.rpc_port, 'submitblock', block)
        except RuntimeError as error:
            self.recorder.count('rejected', f'block_{variant}: {error_class(error)}')
            return
        self.recorder.check('garbage_block_rejected', not result.get('selected'), node.name,
                            f'{variant} block selected as tip', result=result)
        self.recorder.count('accepted', f'block_{variant} (not selected)')
        self.recorder.note('garbage_block_unselected', variant=variant, node=node.name, result=result)

    def op_rpc_garbage(self, rng, node, status):
        variant = rng.choice(['invalid_json', 'deep_json', 'unknown_method', 'wrong_types', 'odd_hex'])
        self.recorder.count('submitted', f'rpc_{variant}')
        try:
            if variant == 'invalid_json':
                raw_post(node.rpc_port, '/rpc', b'{"jsonrpc":"2.0","method":' + rng.randbytes(16))
            elif variant == 'deep_json':
                raw_post(node.rpc_port, '/rpc', b'{"jsonrpc":"2.0","id":1,"method":"status","params":' + b'[' * 200 + b']' * 200 + b'}')
            elif variant == 'unknown_method':
                rpc(node.rpc_port, 'soak_' + rng.randbytes(4).hex())
            elif variant == 'wrong_types':
                rpc(node.rpc_port, rng.choice(['account', 'snapshot', 'proposals', 'mempool', 'quote']),
                    {'key': 7, 'keys': 'x', 'round': 'y', 'limit': -1, 'amount': [1], 'kind': None})
            else:
                rpc(node.rpc_port, 'broadcasttransaction', {'raw': 'abc'})
        except (OSError, RuntimeError):
            pass
        try:
            rpc(node.rpc_port, 'status')
            survived = True
        except (OSError, RuntimeError) as error:
            survived = throttled(error)
        self.recorder.check('rpc_garbage_survived', survived, node.name, f'node stopped answering after {variant}')

    # -- chaos -----------------------------------------------------------------------------------

    CHAOS_DECK = ('kill9', 'kill9', 'kill9_while_mining', 'isolate', 'isolate', 'split', 'split', 'churn',
                  'peer_garbage', 'crash_all')

    def chaos_event(self, rng):
        """Draw from a shuffled deck so every event type recurs within each ten events."""
        if not getattr(self, 'chaos_deck', None):
            self.chaos_deck = list(self.CHAOS_DECK)
            rng.shuffle(self.chaos_deck)
        name = self.chaos_deck.pop()
        self.recorder.count('chaos', name)
        getattr(self, f'chaos_{name}')(rng)

    def ensure_all_running(self, reason):
        for node in self.nodes:
            if not node.up:
                self.restart(node, reason=f'recover after {reason}')

    def durability(self, node, before, reason):
        try:
            block = rpc(node.rpc_port, 'getblock', {'hash': before['tip']})
            ok = header_hash(block['header']) == before['tip']
            detail = ''
        except (OSError, RuntimeError) as error:
            ok, detail = False, error_text(error)
        self.recorder.check('restart_durability', ok, node.name,
                            f'tip {before["tip"]} at height {before["height"]} was lost across {reason}: {detail}',
                            height=before['height'])

    def chaos_kill9(self, rng, during_mining=False):
        if not self.live_nodes():
            return
        node = rng.choice(self.live_nodes())
        before = rpc(node.rpc_port, 'status')
        miner = None
        if during_mining:
            # A multi-block burst, killed part way, lands the SIGKILL inside block commits.
            count, recipient = rng.randint(5, 15), rng.choice(self.wallets).hex

            def mine():
                try:
                    rpc(node.rpc_port, 'mine', {'count': count, 'attempts': 20_000_000, 'recipient': recipient})
                except (OSError, RuntimeError):
                    pass
            miner = threading.Thread(target=mine, daemon=True)
            miner.start()
            time.sleep(rng.uniform(0.01, 0.15))
        node.kill9()
        if miner:
            miner.join(timeout=30)
        self.recorder.note('kill9', timeline=True, node=node.name, height=before['height'], during_mining=during_mining)
        self.idle(rng.uniform(0, 8))
        ok, _ = self.restart(node, reason='kill -9')
        if ok:
            self.durability(node, before, 'kill -9')
            self.converge('kill9_while_mining' if during_mining else 'kill9')

    def chaos_kill9_while_mining(self, rng):
        self.chaos_kill9(rng, during_mining=True)

    def chaos_isolate(self, rng):
        node = rng.choice(self.nodes)
        self.partition([[node.index], [n.index for n in self.nodes if n is not node]], rng, 'isolate')

    def chaos_split(self, rng):
        order = [n.index for n in self.nodes]
        rng.shuffle(order)
        cut = rng.randint(1, len(order) // 2)
        self.partition([order[:cut], order[cut:]], rng, 'split', crash_inside=rng.random() < 0.4)

    def partition(self, groups, rng, reason, crash_inside=False):
        seconds = rng.uniform(self.args.partition_min, self.args.partition_max)
        self.partitioned = True
        self.mesh.partition(groups)
        self.recorder.note('partition', timeline=True, reason=reason, groups=[[i + 1 for i in g] for g in groups],
                           seconds=round(seconds, 1))
        try:
            if crash_inside:
                self.idle(seconds / 2)
                victim = self.nodes[rng.choice(rng.choice(groups))]
                if victim.up:
                    before = rpc(victim.rpc_port, 'status')
                    victim.kill9()
                    self.recorder.note('kill9', timeline=True, node=victim.name, height=before['height'], during_partition=True)
                    self.idle(rng.uniform(0, 5))
                    ok, _ = self.restart(victim, reason='kill -9 during partition')
                    if ok:
                        self.durability(victim, before, 'kill -9 during partition')
                self.idle(seconds / 2)
            else:
                self.idle(seconds)
        finally:
            self.mesh.heal()
            self.partitioned = False
        self.recorder.note('healed', timeline=True, reason=reason)
        self.ensure_all_running(reason)
        self.converge(f'heal_{reason}')

    def chaos_churn(self, rng):
        if not self.live_nodes():
            return
        node = rng.choice(self.live_nodes())
        status, seconds = node.interrupt()
        self.recorder.check('graceful_shutdown', status == 0, node.name,
                            f'Ctrl+C shutdown returned {status} after {seconds} s', stderr_tail=node.tail(node.stderr_path))
        peers = self.full_peers(node)
        subset = rng.sample(peers, rng.randint(1, len(peers)))
        self.recorder.note('churn_stop', timeline=True, node=node.name, shutdown_seconds=seconds, next_peers=len(subset))
        self.idle(rng.uniform(1, 10))
        ok, _ = self.restart(node, peers=subset, reason='peer churn')
        if ok:
            self.converge('churn')

    def chaos_crash_all(self, rng):
        befores = {}
        for node in self.live_nodes():
            try:
                befores[node.name] = rpc(node.rpc_port, 'status')
            except (OSError, RuntimeError):
                pass
        self.mining_allowed.clear()
        try:
            with self.mining_lock:
                for node in self.nodes:
                    node.kill9()
            self.recorder.note('kill9_all', timeline=True, heights={k: v['height'] for k, v in befores.items()})
            time.sleep(rng.uniform(0, 3))
            for node in self.nodes:
                ok, _ = self.restart(node, reason='kill -9 of every node')
                if ok and node.name in befores:
                    self.durability(node, befores[node.name], 'kill -9 of every node')
        finally:
            self.mining_allowed.set()
        self.converge('crash_all')

    def chaos_peer_garbage(self, rng):
        if not self.live_nodes():
            return
        node = rng.choice(self.live_nodes())
        sent = 0
        for _ in range(rng.randint(1, 4)):
            try:
                with socket.create_connection(('127.0.0.1', node.p2p_port), timeout=5,
                                              source_address=(GARBAGE_SOURCE, 0)) as connection:
                    payload = rng.choice([rng.randbytes(rng.randint(1, 4096)), b'GET / HTTP/1.1\r\n\r\n',
                                          b'\xff' * 64, struct.pack('<I', 0xffffffff) + rng.randbytes(32)])
                    connection.sendall(payload)
                    sent += len(payload)
                    connection.settimeout(3)
                    try:
                        connection.recv(4096)
                    except OSError:
                        pass
            except OSError:
                pass
        self.recorder.note('peer_garbage', timeline=True, node=node.name, bytes=sent)
        time.sleep(1)
        try:
            rpc(node.rpc_port, 'status')
            ok = node.alive()
        except (OSError, RuntimeError):
            ok = False
        self.recorder.check('peer_garbage_survived', ok, node.name, 'node stopped answering after malformed peer input')

    # -- main loop and report --------------------------------------------------------------------

    def run(self):
        args = self.args
        rng = random.Random(f'{args.seed}/chaos')
        self.started = time.monotonic()
        self.setup()
        self.mining_allowed.set()
        threads = [self.guarded('miner', self.miner_loop), self.guarded('workload', self.workload_loop),
                   self.guarded('probe', self.probe_loop)]
        end = self.started + args.duration
        next_chaos = time.monotonic() + args.warmup + rng.uniform(0.5, 1.5) * args.chaos_interval
        next_converge = time.monotonic() + args.converge_interval
        try:
            while time.monotonic() < end and not self.stop.is_set():
                self.observe_tips()
                now = time.monotonic()
                if args.chaos_interval > 0 and now >= next_chaos and end - now > args.partition_max + 30:
                    self.chaos_event(rng)
                    next_chaos = time.monotonic() + rng.uniform(0.5, 1.5) * args.chaos_interval
                    next_converge = time.monotonic() + args.converge_interval
                elif now >= next_converge:
                    self.converge('periodic')
                    next_converge = time.monotonic() + args.converge_interval
                time.sleep(0.5)
            if not self.interrupted:
                self.finish()
        finally:
            self.stop.set()
            for thread in threads:
                thread.join(timeout=30)

    def finish(self):
        self.mesh.heal()
        self.ensure_all_running('final')
        self.converge('final')
        for node in self.live_nodes():
            self.check_node(node, force=True)
            self.check_mempool(node)
        self.final = {}
        node = self.live_nodes()[0] if self.live_nodes() else None
        if node:
            status = rpc(node.rpc_port, 'status')
            self.final['status'] = {k: status[k] for k in ('height', 'tip', 'state_root', 'issued', 'phase', 'reserve',
                                                         'shares', 'revenue', 'grant_capacity', 'settings', 'mempool')}
            self.settings_seen.append({'t': self.recorder.elapsed(), 'height': status['height'], 'settings': status['settings']})
            try:
                governance = rpc(node.rpc_port, 'explorer_governance', {'limit': 50})
                decisions = governance.get('decisions', [])
                self.final['decisions'] = {
                    'indexed': len(decisions),
                    'outcomes': dict(collections.Counter(str(d.get('outcome')) for d in decisions)),
                    'funded': sum(1 for d in decisions if d.get('funded')),
                }
            except (OSError, RuntimeError) as error:
                self.final['decisions'] = {'error': error_text(error)}
        self.stop.set()
        for node in self.nodes:
            if node.up:
                status, seconds = node.interrupt()
                self.recorder.check('graceful_shutdown', status == 0, node.name,
                                    f'final Ctrl+C shutdown returned {status} after {seconds} s',
                                    stderr_tail=node.tail(node.stderr_path))
        for node in self.nodes:
            self.scan_logs(node)

    def report(self, error=None):
        args, recorder = self.args, self.recorder
        binary = Path(args.binary)
        nodes = {}
        for node in self.nodes:
            rss = [v for _, v in recorder.samples.get((node.name, 'rss_bytes'), [])]
            disk = [v for _, v in recorder.samples.get((node.name, 'disk_bytes'), [])]
            nodes[node.name] = {
                'rpc_port': node.rpc_port, 'p2p_port': node.p2p_port, 'directory': str(node.directory),
                'incarnations': node.incarnation, 'kills': node.kills, 'graceful_stops': node.interrupts,
                'start_seconds': summary(node.start_seconds),
                'rss_mib': {'first': round(rss[0] / 2 ** 20, 1), 'max': round(max(rss) / 2 ** 20, 1),
                            'last': round(rss[-1] / 2 ** 20, 1)} if rss else None,
                'disk_mib': {'first': round(disk[0] / 2 ** 20, 2), 'max': round(max(disk) / 2 ** 20, 2),
                             'last': round(disk[-1] / 2 ** 20, 2)} if disk else None,
                'probe_ms': {method: summary(recorder.latencies.get((node.name, f'{method}_probe'), []), 1000, 1)
                             for method, _ in PROBES},
            }
        methods = collections.defaultdict(list)
        for (_, method), values in recorder.latencies.items():
            if not method.endswith('_probe'):
                methods[method].extend(values)
        reorg_depths = [r['depth_at_least'] for r in self.reorgs]
        final = getattr(self, 'final', {})
        passed = error is None and recorder.violation_total == 0 and not self.harness_errors and not self.interrupted
        command = ['python3', 'scripts/soak.py', '--duration', str(args.duration), '--nodes', str(args.nodes),
                   '--seed', str(args.seed), '--base-port', str(args.base_port), '--binary', str(args.binary),
                   '--report', str(args.report)]
        return {
            'tool': 'scripts/soak.py', 'passed': passed, 'error': error, 'interrupted': self.interrupted,
            'seed': args.seed, 'arguments': {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
            'binary': str(binary), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest() if binary.exists() else None,
            'elapsed_seconds': recorder.elapsed(),
            'fixture': getattr(self, 'fixture', None), 'chain_id': self.chain_id, 'directory': str(self.root) if self.root else None,
            'checks': dict(sorted(recorder.checks.items())),
            'violation_total': recorder.violation_total,
            'violations': recorder.violations,
            'harness_errors': dict(self.harness_errors),
            'workload': {group: dict(sorted(counter.items())) for group, counter in sorted(recorder.counters.items())},
            'rpc_latency_ms': {method: summary(values, 1000, 1) for method, values in sorted(methods.items())},
            'chaos_timeline': recorder.timeline,
            'reorgs': {'count': len(self.reorgs), 'max_depth_at_least': max(reorg_depths) if reorg_depths else 0,
                       'depth_histogram': dict(sorted(collections.Counter(reorg_depths).items()))},
            'governance': {'phases_observed': dict(self.phases_seen), 'decisions_observed': len(self.decisions_seen),
                           'settings_history': self.settings_seen, 'explorer_decisions': final.get('decisions')},
            'final': final.get('status'),
            'nodes': nodes,
            'proxy': self.mesh.stats() if self.mesh else None,
            'tracked_accounts': len(self.keys),
            'reproduce': {
                'command': ' '.join(shlex.quote(part) for part in command),
                'note': ('The seed fixes every randomized choice of the workload, miner and chaos schedules; '
                         'thread timing is not deterministic, so a failure may need several runs or a longer duration. '
                         'Each violation lists the chaos timeline and the transactions that preceded it.'),
            },
        }

    def shutdown(self):
        self.stop.set()
        for node in self.nodes:
            if node.alive():
                try:
                    node.kill9()
                except Exception:
                    pass
        if self.mesh:
            self.mesh.close()


def parse_duration(text):
    text = str(text).strip().lower()
    scale = {'s': 1, 'm': 60, 'h': 3600}.get(text[-1:], None)
    value = float(text[:-1] if scale else text)
    return int(value * (scale or 1))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--duration', type=parse_duration, default=1800, help='run time, e.g. 1800, 30m or 2h (default 30m)')
    parser.add_argument('--nodes', type=int, default=5, help='peered nodes to start, 2..9 (default 5)')
    parser.add_argument('--seed', type=int, default=1, help='seed for keys, workload, mining and chaos choices')
    parser.add_argument('--base-port', type=int, default=47480,
                        help='node i uses base+10i..base+10i+2; link proxies use the following block')
    parser.add_argument('--binary', type=Path, required=True, help='hashstash executable built with --features test-fixtures')
    parser.add_argument('--report', type=Path, required=True, help='JSON report path')
    parser.add_argument('--workdir', type=Path, help='empty directory for this run (default: a new temporary directory)')
    parser.add_argument('--keep', action='store_true', help='keep the run directory after a passing run')
    parser.add_argument('--wallets', type=int, default=6, help='seeded wallets receiving mining rewards (default 6)')
    parser.add_argument('--max-accounts', type=int, default=200, help='new accounts the workload may create (default 200)')
    parser.add_argument('--tx-rate', type=float, default=4.0, help='workload actions per second (default 4)')
    parser.add_argument('--cross-submit', type=float, default=0.2, help='fraction broadcast to a different node than prepared')
    parser.add_argument('--block-interval', type=float, default=2.5, help='mean seconds between mining attempts (default 2.5)')
    parser.add_argument('--initial-bits', type=lambda v: int(v, 0), default=DEFAULT_BITS,
                        help=f'fixture difficulty floor (default {DEFAULT_BITS:#x}, about 4096 hashes per block)')
    parser.add_argument('--max-block-hashes', type=int, default=1 << 20,
                        help='above this many expected hashes per block, mine only at the target interval')
    parser.add_argument('--chaos-interval', type=float, default=60, help='mean seconds between chaos events; 0 disables chaos')
    parser.add_argument('--warmup', type=float, default=45, help='seconds of plain workload before the first chaos event')
    parser.add_argument('--partition-min', type=float, default=20)
    parser.add_argument('--partition-max', type=float, default=75)
    parser.add_argument('--converge-interval', type=float, default=90, help='seconds between quiescent convergence checks')
    parser.add_argument('--converge-timeout', type=float, default=180, help='bound on convergence after healing or restart')
    parser.add_argument('--tie-break-after', type=float, default=15,
                        help='while converging, mine one block on competing equal-height tips after this many seconds')
    parser.add_argument('--explorer-timeout', type=float, default=60, help='bound on the explorer index reaching the tip')
    parser.add_argument('--start-timeout', type=float, default=120, help='bound on a node answering RPC after (re)start')
    parser.add_argument('--startup-grace', type=float, default=10, help='seconds after start excluded from latency bounds')
    parser.add_argument('--max-rpc-latency', type=float, default=5.0, help='bound on a status probe (lock stall detection)')
    parser.add_argument('--probe-interval', type=float, default=1.0)
    parser.add_argument('--resource-interval', type=float, default=10.0)
    parser.add_argument('--mempool-check-interval', type=float, default=8.0)
    parser.add_argument('--max-rss-mb', type=int, default=512, help='per-node resident memory bound')
    parser.add_argument('--max-rss-growth-mb', type=int, default=128, help='per-incarnation RSS growth bound after the first minute')
    parser.add_argument('--max-disk-mb', type=int, default=2048, help='per-node data directory bound')
    parser.add_argument('--max-disk-per-block-kb', type=float, default=1024, help='bound on data directory bytes per chain block')
    args = parser.parse_args()
    if not 2 <= args.nodes <= 9:
        parser.error('--nodes must be in 2..9')
    if args.duration < 60 or args.tx_rate <= 0 or args.block_interval <= 0 or args.wallets < 1:
        parser.error('--duration must be at least 60 s; rates, intervals and wallets must be positive')
    if args.partition_min > args.partition_max:
        parser.error('--partition-min exceeds --partition-max')
    args.binary = args.binary.resolve()
    soak = Soak(args)
    error = None

    def interrupted(*_):
        soak.interrupted = True
        soak.stop.set()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        soak.run()
    except KeyboardInterrupt:
        soak.interrupted = True
        error = 'interrupted'
    except SetupError as failure:
        error = f'setup failed: {failure}'
    except Exception:
        error = traceback.format_exc()
    finally:
        soak.shutdown()
    report = soak.report(error)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, default=str) + '\n', encoding='utf-8')
    checks = report['checks']
    print(f'Checks: {sum(c["count"] for c in checks.values())} across {len(checks)} invariants; '
          f'violations: {report["violation_total"]}; harness errors: {sum(report["harness_errors"].values())}')
    for name, entry in checks.items():
        if entry['violations']:
            print(f'  {name}: {entry["violations"]} of {entry["count"]}')
    if error:
        print('ERROR: ' + error.strip().splitlines()[-1])
    print(('PASS' if report['passed'] else 'FAIL') + f': report saved in {args.report}')
    if report['passed'] and not args.keep and not args.workdir and soak.root:
        import shutil
        shutil.rmtree(soak.root, ignore_errors=True)
    sys.exit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
