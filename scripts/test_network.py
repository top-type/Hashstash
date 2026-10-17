"""Exercise a running, fresh three-node local testnet. Uses Python's standard library.

Run Start-Testnet.ps1 -Fresh -SeedWallets -NoBrowser first, then pass its manifest path.
This intentionally spends test HASH and advances governance. No external service is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

def http(port, path, value=None, headers=None):
    data = None if value is None else json.dumps(value).encode()
    request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', data=data, headers={'Content-Type': 'application/json', **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f'HTTP {error.code}: {error.read().decode()}') from error

def rpc(port, method, params=None):
    response = http(port, '/rpc', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': {} if params is None else params})
    if 'error' in response:
        raise RuntimeError(response['error'])
    return response['result']

def quoted_miner_fee(quote):
    """Check the current whole-fee allocation independently."""
    charged = int(quote['fee'])
    percent = quote['miner_fee_percent']
    assert type(percent) is int and 0 <= percent <= 100
    assert charged == int(quote['minimum_fee']) + int(quote['extra_fee'])
    miner = charged * percent // 100
    assert int(quote['miner_fee']) == miner
    assert int(quote['revenue_fee']) == charged - miner
    return miner

def sha256d(value):
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()

def target(bits):
    exponent, mantissa = (bits >> 24, bits & 8388607)
    return mantissa << 8 * (exponent - 3) if exponent >= 3 else mantissa >> 8 * (3 - exponent)

from fixture_support import require_test_work


class Audit:

    def __init__(self, manifest):
        self.manifest = manifest
        self.nodes = manifest['nodes']
        self.port = self.nodes[0]['rpc_port']
        self.key = self.nodes[0]['public_key']
        self.session = http(self.port, '/api/session')
        # The wallet token is only in the node's owner-only file, never served.
        self.session['token'] = Path(self.nodes[0]['data_file']).with_suffix('.session-token').read_text()
        assert self.session['wallet_enabled'] and self.session['public_key'] == self.key, 'This audit needs a fresh network started with -SeedWallets.'
        self.checks = []
        self.config = rpc(self.port, 'config')
        self.fixture_mode = require_test_work(self.config)

    def check(self, description):
        self.checks.append(description)
        print('PASS: ' + description, flush=True)

    def status(self):
        return rpc(self.port, 'status')

    def account(self, key=None, outcome=None):
        params = {'key': key or self.key}
        if outcome:
            params['outcome'] = outcome
        return rpc(self.port, 'account', params)['account']

    def mine(self, count=1):
        return rpc(self.port, 'mine', {'count': count, 'attempts': 1000000})

    def transfer_operation(self, recipient, amount):
        fields = {'recipient': list(bytes.fromhex(recipient)), 'amount': str(amount)}
        return {'TransferExact': fields}

    def payment_terms(self, operation, fee='0', port=None, sender=None):
        quote = rpc(port or self.port, 'fee_quote', {'sender': sender or self.key, 'operation': operation, 'extra_fee': str(fee)})
        return {'required': int(quote['fee']), 'miner': quoted_miner_fee(quote)}

    def send(self, operation, fee='0', mine=True, expiry_blocks=None):
        fields = {'extra_fee': str(fee)}
        if expiry_blocks is not None:
            fields['expiry_blocks'] = expiry_blocks
        result = http(self.port, '/api/wallet', {'operation': operation, **fields, 'expected_sender': self.session['public_key'], 'wallet_revision': self.session['wallet_revision']}, {'X-Hashstash-Token': self.session['token']})
        if 'error' in result:
            raise RuntimeError(result['error'])
        assert len(result['transaction_id']) == 64
        if mine:
            self.mine()
        return result

    def wait_phase(self, phase):
        for _ in range(256):
            if self.status()['phase'] == phase:
                return rpc(self.port, 'governance')
            self.mine()
        raise AssertionError('phase did not become ' + phase)

    def wait_open_auction(self):
        for _ in range(512):
            governance = self.wait_phase('auction')
            state = self.status()
            lead = state['settings']['lead']
            timeout = max(self.config['auction_timeout'], lead + state['settings']['interval'])
            remaining = governance['phase']['Auction']['opened'] + timeout - state['clock']
            progress_increment = state['settings']['interval']
            if remaining > lead + 3 * progress_increment:
                return governance
            self.mine()
        raise AssertionError('no auction with sufficient proposal time')

    def proposals(self, round_id):
        return rpc(self.port, 'proposals', {'round': round_id})

    def decision(self):
        return list(bytes.fromhex(self.status()['decision']))

    def propose(self, action, support='1', description=1, mine=True):
        round_id = self.status()['auction_round']
        assert round_id is not None
        self.send({'Propose': {'round': round_id, 'description': [description] * 32, 'proposal': action, 'support': support}}, mine=mine)

    def buy_side(self, outcome, amount='20'):
        decision = self.decision()
        self.send({'Deposit': {'amount': amount, 'decision': decision, 'outcome': outcome}}, mine=False)
        self.mine()

    def agree(self):
        expected = self.status()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            states = [rpc(node['rpc_port'], 'status') for node in self.nodes]
            if all((s['tip'] == expected['tip'] and s['state_root'] == expected['state_root'] for s in states)):
                return expected
            time.sleep(0.15)
        raise AssertionError('three peers did not converge')

    def assert_supply(self):
        governance = rpc(self.port, 'governance')
        outcomes = ['Pass', 'Fail'] if governance['pass'] is not None else [None]
        for outcome in outcomes:
            world = governance['pass'] if outcome == 'Pass' else governance['world']
            balances = [self.account(node['public_key'], outcome) for node in self.nodes]
            account_total = sum((int(a['ordinary']) for a in balances))
            total = account_total + sum((int(world[field]) for field in ['reserve', 'revenue', 'grant_escrow']))
            total += int(governance['auction_escrow'])
            assert total == int(self.status()['issued']), (outcome, total, self.status()['issued'])

    def fee_probe(self):
        before, balance = (self.status(), int(self.account()['ordinary']))
        fee = 5
        operation = self.transfer_operation(self.key, 1)
        terms = self.payment_terms(operation, fee)
        self.send(operation, str(fee))
        after = self.status()
        subsidy = int(after['issued']) - int(before['issued'])
        assert int(self.account()['ordinary']) == balance + subsidy - terms['required'] + terms['miner']
        assert int(after['reserve']) + int(after['revenue']) == int(before['reserve']) + int(before['revenue']) + terms['required'] - terms['miner']
        self.assert_supply()

    @staticmethod
    def miner_cut(state, *charges):
        percent = state['settings'].get('miner_fee_percent') or 0
        return sum((charge * percent // 100 for charge in charges))

    def stratum(self):
        before = self.status()['height']
        with socket.create_connection(('127.0.0.1', self.nodes[0]['stratum_port']), timeout=10) as connection:
            stream = connection.makefile('rwb')

            def request(identity, method, params):
                stream.write(json.dumps({'id': identity, 'method': method, 'params': params}).encode() + b'\n')
                stream.flush()

            def receive():
                return json.loads(stream.readline())
            request(1, 'mining.configure', [['version-rolling'], {'version-rolling.mask': '1fffe000'}])
            assert receive()['result']['version-rolling']
            request(2, 'mining.subscribe', ['hashstash-network-audit'])
            subscription = receive()['result']
            request(3, 'mining.authorize', ['audit.worker', 'x'])
            assert receive()['result'] is True
            assert receive()['method'] == 'mining.set_difficulty'
            job = receive()['params']
            extra2 = '12345678'
            root = sha256d(bytes.fromhex(job[2] + subscription[1] + extra2 + job[3]))
            for sibling in job[4]:
                root = sha256d(root + bytes.fromhex(sibling))
            previous = bytes.fromhex(job[1])
            previous = b''.join((previous[i:i + 4][::-1] for i in range(0, 32, 4)))
            version_bits = 8192
            version = int(job[5], 16) & ~536862720 | version_bits
            bits, stamp = (int(job[6], 16), int(job[7], 16))
            prefix = struct.pack('<I', version) + previous + root + struct.pack('<II', stamp, bits)
            for nonce in range(1000000):
                if int.from_bytes(sha256d(prefix + struct.pack('<I', nonce)), 'little') <= target(bits):
                    break
            else:
                raise AssertionError('test Stratum work not found')
            request(4, 'mining.submit', ['audit.worker', job[0], extra2, job[7], f'{nonce:08x}', f'{version_bits:08x}'])
            assert receive()['result'] is True
        assert self.status()['height'] == before + 1
        self.check('External Stratum client reconstructed, mined and submitted a Bitcoin-format header with version rolling')

    def reorganization(self):
        reservations = [socket.socket() for _ in range(3)]
        for reservation in reservations:
            reservation.bind(('127.0.0.1', 0))
        ports = [reservation.getsockname()[1] for reservation in reservations]
        for reservation in reservations:
            reservation.close()
        directory = Path(self.manifest['directory']) / ('audit-fork-' + str(time.time_ns()))
        directory.mkdir()
        arguments = [self.manifest['executable'], 'run', '--config', self.manifest['config'], '--data', str(directory / 'chain.sqlite'), '--miner', self.nodes[2]['public_key'], '--rpc', f'127.0.0.1:{ports[0]}', '--p2p', f'127.0.0.1:{ports[1]}', '--stratum', f'127.0.0.1:{ports[2]}']
        with (directory / 'stdout.log').open('w') as stdout, (directory / 'stderr.log').open('w') as stderr:
            process = subprocess.Popen(arguments, stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            try:
                for _ in range(100):
                    assert process.poll() is None, 'isolated node exited'
                    try:
                        rpc(ports[0], 'status')
                        break
                    except (OSError, RuntimeError):
                        time.sleep(0.05)
                initial = self.agree()
                for height in range(1, initial['height'] + 1):
                    rpc(ports[0], 'submitblock', rpc(self.port, 'getblock', {'height': height}))
                assert rpc(ports[0], 'status')['state_root'] == initial['state_root']
                recipient = self.nodes[1]['public_key']
                initial_balance = int(self.account(recipient)['ordinary'])
                payment = self.transfer_operation(recipient, 1)
                terms = self.payment_terms(payment, 3)
                # This replay test intentionally advances a competing branch
                # by three blocks. Keep its common-ancestor anchor valid long
                # enough to isolate fee rollback/replay from ordinary expiry.
                self.send(payment, '3', expiry_blocks=10)
                self.mine()
                assert int(self.account(recipient)['ordinary']) == initial_balance + 1
                rpc(ports[0], 'mine', {'count': 3, 'attempts': 1000000})
                for height in range(initial['height'] + 1, initial['height'] + 4):
                    rpc(self.port, 'submitblock', rpc(ports[0], 'getblock', {'height': height}))
                fork = rpc(ports[0], 'status')
                assert self.status()['tip'] == fork['tip']
                assert self.status()['state_root'] == fork['state_root']
                assert int(self.account(recipient)['ordinary']) == initial_balance
                assert self.status()['mempool'] > 0
                replay_before = self.status()
                replay_balance = int(self.account()['ordinary'])
                self.mine()
                replay_after = self.status()
                subsidy = int(replay_after['issued']) - int(replay_before['issued'])
                assert int(self.account()['ordinary']) == replay_balance - 1 - terms['required'] + subsidy + terms['miner']
                assert int(replay_after['reserve']) + int(replay_after['revenue']) == int(replay_before['reserve']) + int(replay_before['revenue']) + terms['required'] - terms['miner']
                self.assert_supply()
                assert int(self.account(recipient)['ordinary']) == initial_balance + 1
                self.agree()
                self.check('A fourth isolated node causes a higher-work reorg; balances and fee allocations roll back, detached payment returns to the mempool and its fee is allocated exactly once on replay')
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8-sig'))
    started = time.monotonic()
    configuration = rpc(manifest['nodes'][0]['rpc_port'], 'config')
    from test_reserve_network import ReserveAudit
    summary = ReserveAudit(manifest).run()
    summary['elapsed_seconds'] = round(time.monotonic() - started, 2)
    report = args.report or args.manifest.parent / 'network-test-report.json'
    report.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print('Saved ' + str(report))
if __name__ == '__main__':
    main()
