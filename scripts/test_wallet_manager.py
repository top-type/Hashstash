"""Live wallet-manager workflow at one node URL, using disposable local accounts.

Creates/imports hot keys, adds a watch account, signs through the separate cold
tool, switches accounts, and restarts the same node without startup wallet flags.
No user data or existing listeners are touched. Standard library only.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time
import uuid
from test_wallet_cli import REPO, transfer_operation, digest, request, rpc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, default=REPO / 'target/release' / ('hashstash.exe' if os.name == 'nt' else 'hashstash'))
    parser.add_argument('--cold', type=Path, default=REPO / 'target/release' / ('hashstash-cold.exe' if os.name == 'nt' else 'hashstash-cold'))
    parser.add_argument('--report', type=Path, default=REPO / 'work/wallet-manager-report.json')
    args = parser.parse_args()
    args.node, args.cold = (args.node.resolve(), args.cold.resolve())
    scratch = REPO / 'work'
    scratch.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='wallet-manager-', dir=scratch)).resolve()
    assert directory.is_relative_to(scratch.resolve())
    vectors = json.loads((REPO / 'tests/data/passphrase-v1.json').read_text(encoding='utf-8'))['vectors']
    primary, offline = vectors[:2]
    checks, processes, files = ([], [], [])
    started = time.monotonic()
    report = {'suite': 'runtime wallet manager', 'artifact_directory': str(directory), 'node_sha256': digest(args.node), 'cold_sha256': digest(args.cold), 'checks': checks}

    def check(message):
        checks.append(message)
        print('PASS: ' + message, flush=True)

    def cli(*arguments, success=True):
        completed = subprocess.run([str(args.node), *map(str, arguments)], cwd=directory, capture_output=True, text=True, encoding='utf-8', timeout=30, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        assert (completed.returncode == 0) == success, completed.stderr
        return completed.stdout

    def start(binary, arguments, label, pattern):
        path = directory / f'{label}.stdout.log'
        output = path.open('w', encoding='utf-8')
        error = (directory / f'{label}.stderr.log').open('w', encoding='utf-8')
        files.extend([output, error])
        process = subprocess.Popen([str(binary), *map(str, arguments)], cwd=directory, stdout=output, stderr=error, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, f'{label} exited; read {directory}'
            match = re.search(pattern, path.read_text(encoding='utf-8'))
            if match:
                return (process, match.group(1))
            time.sleep(0.05)
        raise AssertionError(f'{label} did not start')

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)
    try:
        configuration_path = directory / 'devnet.json'
        cli('init', '--config', configuration_path)
        configuration = json.loads(configuration_path.read_text(encoding='utf-8'))
        fee_fields = {'extra_fee': '0'}
        configuration['network'] = 'wallet-manager-' + uuid.uuid4().hex
        configuration['genesis_time'] = int(time.time()) - 10000
        configuration_path.write_text(json.dumps(configuration), encoding='utf-8')
        chain_path = directory / 'chain.sqlite'

        def node_arguments(address='127.0.0.1:0'):
            return ['run', '--config', configuration_path, '--data', chain_path, '--miner', primary['public_key'], '--rpc', address, '--p2p', '127.0.0.1:0', '--stratum', '127.0.0.1:0']
        node_process, base = start(args.node, node_arguments(), 'node', 'RPC: (http://127\\.0\\.0\\.1:\\d+)/rpc')
        _, session = request(base, '/api/session')
        assert session['wallet_mode'] == 'none' and (not session['wallet_enabled'])
        assert session['wallet_id'] is None and session['public_key'] is None and (session['wallets'] == [])
        assert session['address'] is None

        def manage(action, expected=200, **values):
            nonlocal session
            body = {'action': action, 'revision': session['wallet_revision'], **values}
            code, result = request(base, '/api/wallet/manage', body, session['token'])
            assert code == expected, (action, code, result)
            if code == 200 and action != 'export':
                session = {**session, **result}
            return result

        def public_only(value, secrets):
            encoded = json.dumps(value)
            assert all((secret not in encoded for secret in secrets))
            if isinstance(value, dict):
                assert not {'secret', 'private_key', 'passphrase'} & value.keys()
                for child in value.values():
                    public_only(child, secrets)
            elif isinstance(value, list):
                for child in value:
                    public_only(child, secrets)
        initial_mode = session['wallet_mode']
        created = manage('create')
        assert created['wallet_mode'] == 'hot' and created['wallet_enabled']
        assert len(created['wallets']) == 1
        assert created['wallets'][0]['name'] == ''
        created_id, created_public = (created['wallet_id'], created['public_key'])
        descriptor = manage('export', id=created_id)
        assert descriptor['format'] == 'hashstash-private-v1'
        assert descriptor['public_key'] == created_public
        private = descriptor['private_key']
        assert len(private) == 64
        backup = directory / 'created-account-backup.json'
        with backup.open('x', encoding='utf-8') as file:
            json.dump(descriptor, file)
        assert cli('public-key', '--key', backup).strip() == created_public
        mismatched_backup = directory / 'mismatched-backup.json'
        mismatched_backup.write_text(json.dumps({**descriptor, 'public_key': offline['public_key']}), encoding='utf-8')
        cli('public-key', '--key', mismatched_backup, success=False)
        count = len(session['wallets'])
        restored = manage('import', name='Duplicate backup', private_key=private)
        assert restored['wallet_id'] == created_id and len(restored['wallets']) == count
        public_only(restored, [private, primary['secret']])
        check('One running node creates a hot key, explicitly exports a backup, and restores that key without duplication')
        imported = manage('import', name='Primary', private_key=primary['secret'])
        assert imported['public_key'] == primary['public_key'] and imported['wallet_mode'] == 'hot'
        hot_id = imported['wallet_id']
        count, revision = (len(imported['wallets']), imported['wallet_revision'])
        duplicate = manage('import', name='Name must not replace Primary', private_key=primary['secret'])
        assert duplicate['wallet_revision'] == revision and len(duplicate['wallets']) == count
        assert next((wallet for wallet in duplicate['wallets'] if wallet['id'] == hot_id))['name'] == 'Primary'
        watch = manage('watch', public_key=offline['public_key'])
        watch_id = watch['wallet_id']
        assert watch['wallet_mode'] == 'watch' and (not watch['wallet_enabled'])
        assert next((wallet for wallet in watch['wallets'] if wallet['id'] == watch_id))['name'] == ''
        count, revision = (len(watch['wallets']), watch['wallet_revision'])
        duplicate = manage('watch', name='Duplicate watch', public_key=offline['public_key'])
        assert duplicate['wallet_revision'] == revision and len(duplicate['wallets']) == count
        manage('export', expected=400, id=watch_id)
        check('Private-key import and watch-account creation work in the same session; duplicate accounts are reused')
        manage('select', id=hot_id)
        cli('mine', '--url', base + '/rpc', '--count', '12')
        public_keys = [wallet['public_key'] for wallet in session['wallets']]
        balance_snapshot = rpc(base, 'snapshot', {'keys': public_keys})
        assert set(balance_snapshot['balances']) == set(public_keys)
        assert balance_snapshot['balances'][created_public]['account'] is None
        assert balance_snapshot['balances'][offline['public_key']]['account'] is None
        balance = rpc(base, 'account', {'key': primary['public_key']})['account']
        assert balance_snapshot['balances'][primary['public_key']]['account'] == {field: balance[field] for field in ('ordinary', 'shares')}
        assert 'balances' not in rpc(base, 'snapshot')
        public_only(balance_snapshot, [private, primary['secret']])
        check('Unnamed wallets and the bounded balance snapshot identify funded and unfunded accounts without exposing private keys')
        old_hot = dict(session)
        manage('select', id=watch_id)
        manage('select', id=hot_id)
        assert session['wallet_revision'] != old_hot['wallet_revision']
        payment = transfer_operation(primary['public_key'])

        def send(operation, expected=200, identity=None):
            identity = identity or session
            code, result = request(base, '/api/wallet', {'operation': operation, **fee_fields, 'expiry_blocks': 100, 'expected_sender': identity['public_key'], 'wallet_revision': identity['wallet_revision']}, session['token'])
            assert code == expected, (code, result)
            return result
        send(payment, expected=400, identity=old_hot)
        send(payment, expected=400, identity={**session, 'public_key': created_public})
        code, _ = request(base, '/api/wallet', {'operation': payment, **fee_fields}, session['token'])
        assert code == 400 and rpc(base, 'mempool') == []
        code, _ = request(base, '/api/wallet/manage', {'action': 'select', 'id': watch_id, 'revision': old_hot['wallet_revision']}, session['token'])
        assert code == 400
        check('Stale revisions, wrong sender, and missing identity cannot sign, including after returning to the same account')
        exact = True
        funding_operation = {'TransferExact': {'recipient': list(bytes.fromhex(offline['public_key'])), 'amount': '6'}}
        funding = send(funding_operation)
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': offline['public_key']})['account']['ordinary'] == '6'
        manage('select', id=watch_id)
        send(payment, expected=403)
        unsigned = rpc(base, 'preparetransaction', {'sender': offline['public_key'], 'operation': payment, **fee_fields, 'expiry_blocks': 100})
        unsigned.pop('fee_quote', None)
        _, cold_base = start(args.cold, ['--port', '0'], 'cold', 'cold signer: (http://127\\.0\\.0\\.1:\\d+)/')
        _, cold_session = request(cold_base, '/api/session')

        def cold(action, value):
            code, result = request(cold_base, '/api/' + action, value, cold_session['token'])
            assert code == 200, (code, result)
            return result
        assert cold('unlock', {'passphrase': offline['passphrase']})['public_key'] == offline['public_key']
        review = cold('review', unsigned)
        signed = cold('sign', {'review_token': review['review_token']})
        broadcast = rpc(base, 'broadcasttransaction', {'raw': signed['raw']})
        assert broadcast['transaction_id'] == signed['txid']
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': offline['public_key']})['account']['nonce'] == 1
        manage('select', id=hot_id)
        hot_send = send(payment)
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': primary['public_key']})['account']['nonce'] == 2
        check('Runtime switching supports hot transfer, watch-only preparation, cold signing, broadcast, and a return to hot signing at one URL')
        prior = dict(session)
        manage('import', expected=400, name='Invalid', private_key='00')
        manage('import', expected=400, name='Mismatched backup', private_key=primary['secret'], public_key=offline['public_key'])
        manage('watch', expected=400, name='Invalid', public_key='ff' * 32)
        assert session == prior
        code, _ = request(base, '/api/wallet/manage', {'action': 'export', 'id': hot_id, 'revision': session['wallet_revision']}, 'wrong-session-token')
        assert code == 403
        for path, value in [('/api/session', None), ('/rpc', {'jsonrpc': '2.0', 'id': 1, 'method': 'snapshot', 'params': {'key': primary['public_key']}})]:
            code, normal = request(base, path, value)
            assert code == 200
            public_only(normal, [private, primary['secret'], offline['secret']])
        check('Invalid imports leave selection intact, export requires the session token, and ordinary reads reveal no private keys')
        store_path = chain_path.with_suffix('.wallets.sqlite')
        with sqlite3.connect(store_path) as storage:
            saved = storage.execute('SELECT active,revision FROM wallet_selection').fetchone()
            wallet_count = storage.execute('SELECT COUNT(*) FROM wallets').fetchone()[0]
            storage.execute("CREATE TRIGGER test_wallet_save_failure BEFORE UPDATE ON wallet_selection BEGIN SELECT RAISE(ABORT,'wallet test write failure'); END")
            storage.commit()
            try:
                manage('create', expected=400, name='Must not be exposed')
                _, failed_session = request(base, '/api/session')
                assert failed_session['wallet_id'] == session['wallet_id']
                assert failed_session['wallet_revision'] == session['wallet_revision']
                assert failed_session['wallets'] == session['wallets']
                assert storage.execute('SELECT active,revision FROM wallet_selection').fetchone() == saved
                assert storage.execute('SELECT COUNT(*) FROM wallets').fetchone()[0] == wallet_count
            finally:
                storage.execute('DROP TRIGGER test_wallet_save_failure')
                storage.commit()
        check('A database failure between key insertion and selection rolls back both disk and displayed wallet state')
        persisted_ids = sorted((wallet['id'] for wallet in session['wallets']))
        tip = rpc(base, 'status')['tip']
        stop(node_process)
        _, restarted_base = start(args.node, node_arguments(base.removeprefix('http://')), 'node-restored', 'RPC: (http://127\\.0\\.0\\.1:\\d+)/rpc')
        assert restarted_base == base
        _, restarted = request(base, '/api/session')
        assert restarted['token'] != session['token']
        assert restarted['wallet_id'] == hot_id and restarted['public_key'] == primary['public_key']
        assert sorted((wallet['id'] for wallet in restarted['wallets'])) == persisted_ids
        assert rpc(base, 'status')['tip'] == tip
        code, _ = request(base, '/api/wallet/manage', {'action': 'export', 'id': hot_id, 'revision': restarted['wallet_revision']}, session['token'])
        assert code == 403
        session = restarted
        assert manage('export', id=created_id)['private_key'] == private
        send(payment)
        cli('mine', '--url', base + '/rpc', '--count', '1')
        check('Restart at the same URL preserves every key, selected account, and chain; saved hot signing works and the old session token fails')
        report.update({'passed': True, 'version': cli('--version').strip(), 'initial_mode': initial_mode, 'final_status': rpc(base, 'status'), 'public_wallet_ids': persisted_ids, 'included_transactions': [funding['transaction_id'], signed['txid'], hot_send['transaction_id']]})
    finally:
        for process in processes:
            stop(process)
        for file in files:
            file.close()
        report['owned_processes_stopped'] = all((process.poll() is not None for process in processes))
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"Passed {len(checks)} checks in {report['elapsed_seconds']}s; {args.report}")
if __name__ == '__main__':
    main()
