"""Audit the reserve curve, buffered fees, grants and reorgs on a fresh local testnet.

Only the explicitly supplied disposable manifest is used. Temporary fork nodes
are owned by this audit and stopped on exit; existing processes are left running.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
from test_network import Audit, rpc


def pass_leads(passed, failed, margin_bps):
    """Compare M/S exactly; empty worlds have a zero price."""
    pn, pd = (int(passed['curve_mass']), int(passed['shares'])) if int(passed['shares']) else (0, 1)
    fn, fd = (int(failed['curve_mass']), int(failed['shares'])) if int(failed['shares']) else (0, 1)
    return pn * fd * 10000 > fn * pd * (10000 + margin_bps)


class Fork:

    def __init__(self, audit, height, label):
        self.audit, self.height, self.label = (audit, height, label)
        self.process = None
        self.logs = []

    def __enter__(self):
        reservations = [socket.socket() for _ in range(3)]
        try:
            for reservation in reservations:
                reservation.bind(('127.0.0.1', 0))
            ports = [reservation.getsockname()[1] for reservation in reservations]
        finally:
            for reservation in reservations:
                reservation.close()
        self.port = ports[0]
        directory = Path(self.audit.manifest['directory']) / f'reserve-{self.label}-{time.time_ns()}'
        directory.mkdir()
        self.directory = directory
        arguments = [self.audit.manifest['executable'], 'run', '--config', self.audit.manifest['config'], '--data', str(directory / 'chain.sqlite'), '--miner', self.audit.nodes[2]['public_key'], '--rpc', f'127.0.0.1:{ports[0]}', '--p2p', f'127.0.0.1:{ports[1]}', '--stratum', f'127.0.0.1:{ports[2]}']
        try:
            self.logs = [(directory / name).open('w', encoding='utf-8') for name in ('stdout.log', 'stderr.log')]
            self.process = subprocess.Popen(arguments, stdout=self.logs[0], stderr=self.logs[1], creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            deadline = time.monotonic() + 30
            while True:
                assert self.process.poll() is None, f'Isolated node exited; read {directory}'
                try:
                    rpc(self.port, 'status')
                    break
                except (OSError, RuntimeError):
                    assert time.monotonic() < deadline, f'Isolated node did not start: {directory}'
                    time.sleep(0.05)
            for height in range(1, self.height + 1):
                rpc(self.port, 'submitblock', rpc(self.audit.port, 'getblock', {'height': height}))
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        for log in self.logs:
            log.close()

    def mine(self, count=1):
        return rpc(self.port, 'mine', {'count': count, 'attempts': 1000000})

    def status(self):
        return rpc(self.port, 'status')

    def overtake(self, parent_height):
        sent = self.height
        for _ in range(64):
            height = self.status()['height']
            if height <= parent_height:
                self.mine(parent_height - height + 2)
                height = self.status()['height']
            for number in range(sent + 1, height + 1):
                rpc(self.audit.port, 'submitblock', rpc(self.port, 'getblock', {'height': number}))
            sent = height
            if self.audit.status()['tip'] == self.status()['tip']:
                return
            self.mine()
        raise AssertionError('Competing governance branch did not overtake within bounded work')


class ReserveAudit(Audit):
    def account_at(self, port, key, outcome=None):
        params = {'key': key}
        if outcome:
            params['outcome'] = outcome
        try:
            return rpc(port, 'account', params)['account']
        except RuntimeError as error:
            if 'account does not exist' not in str(error):
                raise
            return {'ordinary': '0', 'shares': '0'}

    def world_accounts(self, port, outcome=None):
        vectors = json.loads((Path(__file__).resolve().parents[1] / 'tests/data/passphrase-v1.json').read_text())['vectors']
        keys = list(dict.fromkeys([node['public_key'] for node in self.nodes] + [vectors[-1]['public_key']]))
        return [self.account_at(port, key, outcome) for key in keys]

    def assert_supply(self, port=None):
        port = port or self.port
        state, governance = rpc(port, 'status'), rpc(port, 'governance')
        assert state['time_unit'] == 'seconds' and state['clock_basis'] == 'target_interval'
        assert state['height'] <= state['clock'] <= state['height'] * 60
        for outcome in (['Pass', 'Fail'] if governance['pass'] is not None else [None]):
            world = governance['pass'] if outcome == 'Pass' else governance['world']
            accounts = self.world_accounts(port, outcome)
            cash = sum(int(a['ordinary']) for a in accounts)
            shares = sum(int(a['shares']) for a in accounts)
            assert cash + sum(int(world[f]) for f in ('reserve', 'revenue', 'grant_escrow')) + int(governance['auction_escrow']) == int(state['issued'])
            assert shares == int(world['account_shares']) == int(world['shares'])
            reserve, mass = int(world['reserve']), int(world['curve_mass'])
            assert 0 <= reserve <= mass
            assert (reserve == 0) == (shares == 0) == (mass == 0)
            capacity = int(world['revenue']) + max(0, reserve - 1)
            assert int(world['grant_capacity']) == capacity
            if shares and int(world['revenue']):
                assert reserve == mass
        for name in ('reserve', 'shares', 'curve_mass', 'revenue', 'grant_capacity'):
            assert state[name] == governance['world'][name]

    def indexed(self, method, params, predicate, port=None):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                result = rpc(port or self.port, method, params)
                if predicate(result):
                    return result
            except RuntimeError as error:
                if 'updating' not in str(error).lower():
                    raise
            time.sleep(0.05)
        raise AssertionError('Derived history did not reach the requested canonical record')

    def decision_record(self, identity, port=None):
        result = self.indexed('explorer_governance', {'limit':50},
            lambda result: any(d['id'] == identity and d.get('outcome') for d in result['decisions']), port)
        record = next(d for d in result['decisions'] if d['id'] == identity)
        assert record['observed_blocks'] == record['blocks'] and record['blocks_remaining'] == 0
        assert record['ended_height'] - record['started_height'] == record['blocks']
        assert (record['outcome'] == 'pass') == (record['funded'] and record['leading_blocks'] * 2 > record['blocks'])
        return record

    def mine_counted(self):
        before, status = rpc(self.port, 'governance'), self.status()
        decision = before['phase']['Governance']
        leads = pass_leads(before['pass'], before['world'], before['frozen']['pass_margin_bps'])
        expected = decision['leading_blocks'] + int(leads)
        self.mine()
        after = rpc(self.port, 'governance')
        if self.status()['phase'] == 'governance':
            assert after['phase']['Governance']['leading_blocks'] == expected
            assert after['progress']['observed_blocks'] == status['height'] + 1 - decision['started_height']
        else:
            record = self.decision_record(status['decision'])
            assert record['leading_blocks'] == expected
        return after

    def buy_side(self, outcome, amount='20'):
        before, account = self.status(), self.account(outcome=outcome)
        world = rpc(self.port, 'governance')['pass' if outcome == 'Pass' else 'world']
        operation = {'Deposit': {'amount':amount,'decision':self.decision(),'outcome':outcome}}
        terms = self.payment_terms(operation)
        sent = self.send(operation, mine=False)
        self.mine_counted()
        after = self.status()
        record = self.indexed('explorer_transaction', {'txid':sent['transaction_id']},
            lambda result: result['transaction'].get('status') == 'confirmed')['transaction']
        assert int(record['input_requested']) == int(amount)
        filled, unfilled, output = (int(record[field]) for field in ('input_filled','input_unfilled','output'))
        assert filled + unfilled == int(amount) and filled > 0 and output > 0
        assert record['amount'] == record['input_filled'] and record['output_asset'] == 'shares'
        holding = self.account(outcome=outcome)
        assert int(holding['shares']) - int(account['shares']) == output
        assert int(holding['ordinary']) == int(account['ordinary']) - filled - terms['required'] + terms['miner'] + int(after['issued']) - int(before['issued'])
        current = rpc(self.port, 'governance')['pass' if outcome == 'Pass' else 'world']
        lhs = int(current['curve_mass']) * int(world['shares']) * 10000
        reference = int(world['curve_mass']) * int(current['shares'])
        bound = before['settings']['max_price_change_bps']
        assert reference * max(0,10000-bound) <= lhs <= reference * (10000+bound)
        return record

    def open_curve(self):
        initial = self.status()
        assert initial['phase'] == 'rest' and int(initial['reserve']) == 0
        assert int(initial['shares']) == int(initial['curve_mass']) == 0
        self.mine(6)
        self.send(self.transfer_operation(self.nodes[1]['public_key'], 2))
        assert self.account_at(self.port, self.nodes[1]['public_key'])['ordinary'] == '2'
        self.send({'Deposit': {'amount': '4', 'decision': None, 'outcome': None}})
        after = self.status()
        assert int(after['clock']) < self.config['initial']['rest']
        assert after['phase'] == 'rest'
        assert int(after['reserve']) == 4 and after['curve_mass'] == after['reserve']
        shares = int(self.account()['shares'])
        assert shares == 4 * int(self.config['share_scale'])
        cash = int(self.account()['ordinary'])
        self.assert_supply()
        self.agree()
        self.check('Payments and voluntary Stash deposits are available during the first rest period; the first deposit starts a flat curve')
        self.wait_open_auction()
        assert int(self.account()['shares']) == shares
        assert int(self.account()['ordinary']) >= cash
        assert int(self.account_at(self.port, self.nodes[1]['public_key'])['shares']) == 0
        assert int(self.status()['reserve']) == 4
        self.check('The first auction never converts idle hashes or alters account Stash holdings')
        quote = rpc(self.port, 'stash_quote', {'key': self.key, 'kind': 'redeem', 'all': True})
        assert int(quote['input_requested']) == shares
        assert int(quote['input_filled']) + int(quote['input_unfilled']) == shares
        assert int(quote['stash_before_hash']) == 4 and 0 <= int(quote['output_hash']) <= 4
        assert quote['indicative'] is True and quote['execution'] == 'block_batch'
        self.check('The whole holding is valued separately from its bounded single-block fill, with fees quoted separately')

    def ensure_cash(self, amount):
        for _ in range(4096):
            if int(self.account()['ordinary']) >= amount:
                return
            self.mine()
        raise AssertionError('Fixture mining did not acquire the bounded test budget')

    def payments(self):
        self.ensure_cash(250)
        recipient = self.nodes[1]['public_key']
        for amount in (40, 2, 3):
            before = self.status()
            sender_before = int(self.account()['ordinary'])
            recipient_before = int(self.account_at(self.port, recipient)['ordinary'])
            operation = self.transfer_operation(recipient, amount)
            terms = self.payment_terms(operation, 1)
            self.send(operation, '1')
            after = self.status()
            minted = int(after['issued']) - int(before['issued'])
            assert int(self.account_at(self.port, recipient)['ordinary']) == recipient_before + amount
            assert int(self.account()['ordinary']) == sender_before - amount - terms['required'] + minted + terms['miner']
            assert sum(int(after[k]) - int(before[k]) for k in ('revenue', 'reserve')) == terms['required'] - terms['miner']
            self.assert_supply()
        self.agree()
        self.check('Payments, account creation, nonces and the complete fee split conserve all issued hashes')
        self.fee_probe()

    def buffered_revenue(self):
        before = rpc(self.port, 'governance')['world']
        assert before['reserve'] == before['curve_mass']
        holdings = [a['shares'] for a in self.world_accounts(self.port)]
        operation = self.transfer_operation(self.key, 1)
        terms = self.payment_terms(operation, 25)
        self.send(operation, '25')
        after = rpc(self.port, 'governance')['world']
        assert all(after[key] == before[key] for key in ('reserve', 'curve_mass', 'shares'))
        assert int(after['revenue']) - int(before['revenue']) == terms['required'] - terms['miner']
        assert [a['shares'] for a in self.world_accounts(self.port)] == holdings
        self.assert_supply()
        self.check('Fee revenue waits as cash at the flat limit without minting stash or moving the curve price')

    def flat_decision(self):
        self.ensure_cash(150)
        self.send({'Deposit': {'amount': '100', 'decision': None, 'outcome': None}})
        self.wait_open_auction()
        recipient = self.nodes[1]['public_key']
        assert int(self.status()['revenue']) >= 1
        self.propose({'Grant': {'payments': [{'recipient': list(bytes.fromhex(recipient)), 'amount': '1'}]}}, description=71)
        governance = self.wait_phase('governance')
        assert governance['pass']['grant_escrow'] == '1'
        assert governance['world']['grant_escrow'] == '0'
        for world in (governance['world'], governance['pass']):
            assert world['reserve'] == world['curve_mass']
        prior = int(self.account(recipient)['ordinary'])
        self.buy_side('Pass', '20')
        governance = rpc(self.port, 'governance')
        failed, passed = governance['world'], governance['pass']
        assert int(failed['curve_mass']) * int(passed['shares']) == int(passed['curve_mass']) * int(failed['shares'])
        while self.status()['phase'] == 'governance':
            self.mine_counted()
        assert int(self.account(recipient)['ordinary']) == prior
        self.assert_supply()
        self.check('A cash-buffered grant is reserved immediately; buying a flat PASS curve leaves a tie, so the existing decision rule resolves FAIL')

    def prepare_sloped_grant(self):
        # Fund a grant that draws from the reserve after waiting revenue.
        state = self.status()
        target_reserve = 2 * (int(state['revenue']) + 100)
        deposit = max(0, target_reserve - int(state['reserve']))
        self.ensure_cash(deposit + target_reserve + 100)
        if deposit:
            self.send({'Deposit': {'amount': str(deposit), 'decision': None, 'outcome': None}})
        self.wait_open_auction()
        state = self.status()
        grant = int(state['revenue']) + int(state['reserve']) // 2
        assert grant > int(state['revenue']) + 10
        assert rpc(self.port, 'grant_quote', {'amount': str(grant)})['feasible']
        return grant

    def governance_reorg(self):
        grant = self.prepare_sloped_grant()
        recipient = self.nodes[1]['public_key']
        vectors = json.loads((Path(__file__).resolve().parents[1] / 'tests/data/passphrase-v1.json').read_text())['vectors']
        second = vectors[-1]['public_key']
        assert second not in [node['public_key'] for node in self.nodes]
        payments = sorted([{'recipient': list(bytes.fromhex(recipient)), 'amount': str(grant - grant // 3)},
                           {'recipient': list(bytes.fromhex(second)), 'amount': str(grant // 3)}], key=lambda p: p['recipient'])
        assert all(int(p['amount']) > 0 for p in payments)
        before_payout = {bytes(p['recipient']).hex(): int(self.account_at(self.port, bytes(p['recipient']).hex())['ordinary']) for p in payments}
        self.propose({'Grant': {'payments': payments}}, description=91)
        governance = self.wait_phase('governance')
        assert int(governance['pass']['grant_escrow']) == grant
        assert int(governance['pass']['reserve']) < int(governance['pass']['curve_mass'])
        assert governance['pass']['shares'] == governance['world']['shares']
        assert governance['pass']['curve_mass'] == governance['world']['curve_mass']
        initial = self.agree()
        common_height = initial['height']
        with Fork(self, common_height, 'reject') as reject:
            assert reject.status()['state_root'] == initial['state_root']
            fill = self.buy_side('Pass', str(int(governance['world']['reserve'])))
            assert fill['fill_status'] == 'partial' and int(fill['input_unfilled']) > 0
            self.check('A capped PASS order fills partially, refunds unused cash and records actual input/output under the exact 10% closing-price bound')
            holdings = {side: [a['shares'] for a in self.world_accounts(self.port, side)] for side in ('Pass', 'Fail')}
            for _ in range(256):
                if self.status()['phase'] != 'governance':
                    break
                observed = rpc(self.port, 'governance')
                assert int(observed['pass']['grant_escrow']) == grant
                for side in ('Pass', 'Fail'):
                    assert [a['shares'] for a in self.world_accounts(self.port, side)] == holdings[side]
                self.assert_supply()
                self.mine_counted()
            else:
                raise AssertionError('Traded decision did not resolve')
            assert self.status()['phase'] == 'rest'
            for payment in payments:
                key = bytes(payment['recipient']).hex()
                assert int(self.account_at(self.port, key)['ordinary']) == before_payout[key] + int(payment['amount'])
            passed = self.agree()
            passed_world = rpc(self.port, 'governance')['world']
            blocks = [rpc(self.port, 'getblock', {'height': h}) for h in range(common_height + 1, passed['height'] + 1)]
            self.check('An unbuffered grant reduces backing without burning private stash; the sloped PASS market moves and pays every reserved grant recipient once')
            for _ in range(256):
                if reject.status()['phase'] == 'rest':
                    break
                reject.mine()
            else:
                raise AssertionError('Untraded decision did not resolve')
            for key, prior in before_payout.items():
                assert int(self.account_at(reject.port, key)['ordinary']) == prior
            rejected_decision = self.decision_record(initial['decision'], reject.port)
            assert rejected_decision['leading_blocks'] == 0 and rejected_decision['outcome'] == 'fail'
            self.assert_supply(reject.port)
            reject.overtake(passed['height'])
            rejected = reject.status()
            assert self.status()['state_root'] == rejected['state_root']
            assert rpc(self.port, 'governance')['world'] == rpc(reject.port, 'governance')['world']
            for key, prior in before_payout.items():
                assert int(self.account_at(self.port, key)['ordinary']) == prior
            self.assert_supply()
            self.agree()
            self.check('A higher-work FAIL branch rolls back the grant, trades, curve mass and buffered revenue on all peers')
        with Fork(self, common_height, 'reenact') as reenact:
            for block in blocks:
                rpc(reenact.port, 'submitblock', block)
            assert reenact.status()['state_root'] == passed['state_root']
            assert rpc(reenact.port, 'governance')['world'] == passed_world
            reenact.overtake(rejected['height'])
            assert self.status()['state_root'] == reenact.status()['state_root']
            for payment in payments:
                key = bytes(payment['recipient']).hex()
                assert int(self.account_at(self.port, key)['ordinary']) == before_payout[key] + int(payment['amount'])
            self.assert_supply()
            self.agree()
            self.check('Replaying the PASS branch restores exact reserve state and awards every grant payout exactly once')

    def run(self):
        assert self.status()['height'] == 0, 'audit requires a fresh disposable network'
        self.open_curve()
        self.payments()
        self.buffered_revenue()
        self.flat_decision()
        self.governance_reorg()
        self.stratum()
        self.reorganization()
        final = self.agree()
        self.assert_supply()
        return {**self.fixture_mode, 'passed': True, 'checks': self.checks, 'checks_passed': len(self.checks),
                'height': final['height'], 'issued_HASH': final['issued'], 'tip': final['tip'],
                'state_root': final['state_root'], 'reserve': final['reserve'],
                'curve_mass': final['curve_mass'], 'revenue': final['revenue'],

                'node_sha256': hashlib.sha256(Path(self.manifest['executable']).read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8-sig'))
    started = time.monotonic()
    report = ReserveAudit(manifest).run()
    report['elapsed_seconds'] = round(time.monotonic() - started, 2)
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Saved ' + str(args.report), flush=True)


if __name__ == '__main__':
    main()

