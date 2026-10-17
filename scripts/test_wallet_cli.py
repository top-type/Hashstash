"""Disposable CLI -> cold signer -> raw broadcast integration; standard library only.

Uses published test passphrases, fresh databases, and OS-selected loopback ports.
Never connects to the user's running network. Leaves logs/exports for inspection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
REPO = Path(__file__).resolve().parents[1]
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))

def request(base, path, value=None, token=None):
    headers = {'Content-Type': 'application/json', 'Origin': base}
    if token:
        headers['X-Hashstash-Cold-Token'] = token
        headers['X-Hashstash-Token'] = token
    data = None if value is None else json.dumps(value, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with HTTP.open(req, timeout=15) as response:
            return (response.status, json.load(response))
    except urllib.error.HTTPError as error:
        return (error.code, json.loads(error.read()))

def rpc(base, method, params=None):
    status, value = request(base, '/rpc', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}})
    assert status == 200 and 'error' not in value, (status, value)
    return value['result']

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def transfer_operation(recipient, amount='1'):
    """Build an ordinary transfer to an explicit test account."""
    return {'TransferExact': {'recipient': list(bytes.fromhex(recipient)), 'amount': str(amount)}}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash.exe' if os.name == 'nt' else 'hashstash'))
    parser.add_argument('--cold', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash-cold.exe' if os.name == 'nt' else 'hashstash-cold'))
    parser.add_argument('--report', type=Path, default=REPO / 'work/wallet-cli-report.json')
    parser.add_argument('--directory', type=Path, default=REPO / 'work')
    options = parser.parse_args()
    options.node, options.cold = (options.node.resolve(), options.cold.resolve())
    scratch = options.directory.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='wallet-cli-', dir=scratch)).resolve()
    assert directory.is_relative_to(scratch.resolve())
    vectors = json.loads((REPO / 'tests/data/passphrase-v1.json').read_text(encoding='utf-8'))['vectors']
    vector, other = vectors[:2]
    checks, processes, logs = ([], [], [])
    started = time.monotonic()
    report = {'suite': 'wallet CLI and standalone cold signer', 'artifact_directory': str(directory), 'node_sha256': digest(options.node), 'cold_sha256': digest(options.cold), 'test_work': True, 'issuance_mode': 'accelerated test fixture', 'expected_hashes_per_atom': '1', 'production_issuance_tested': False, 'checks': checks}

    def check(description):
        checks.append(description)
        print('PASS: ' + description, flush=True)

    def cli(*args, success=True):
        result = subprocess.run([str(options.node), *map(str, args)], capture_output=True, text=True, encoding='utf-8', cwd=directory, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        assert (result.returncode == 0) == success, (args, result.returncode, result.stdout, result.stderr)
        return result

    def start(binary, args, label, pattern):
        output = directory / f'{label}.stdout.log'
        stdout = output.open('w', encoding='utf-8')
        stderr = (directory / f'{label}.stderr.log').open('w', encoding='utf-8')
        logs.extend([stdout, stderr])
        process = subprocess.Popen([str(binary), *map(str, args)], stdout=stdout, stderr=stderr, cwd=directory, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, f'{label} stopped; inspect {directory}'
            match = re.search(pattern, output.read_text(encoding='utf-8'))
            if match:
                return (process, match.group(1))
            time.sleep(0.05)
        raise AssertionError(f'{label} did not report a listener')

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)
    try:
        config = directory / 'devnet.json'
        initialized_at = int(time.time())
        cli('init', '--config', config)
        configuration = json.loads(config.read_text(encoding='utf-8'))
        configuration["test_work"] = True
        configuration['network'] = 'wallet-cli-' + uuid.uuid4().hex

        assert initialized_at <= configuration['genesis_time'] <= int(time.time())
        assert configuration['initial']['interval'] == 15
        assert set(configuration['initial']) == {'block_bytes', 'minimum_fee_rate', 'interval', 'lead', 'rest', 'decision_blocks', 'miner_fee_percent', 'pass_margin_bps', 'max_price_change_bps'}
        # Keep the deliberately oversized --data-hex argument within Windows'
        # command-line bound; consensus still rejects it at this fixture's capacity.
        configuration['initial']['block_bytes'] = 8192
        config.write_text(json.dumps(configuration), encoding='utf-8')
        db = directory / 'watch.sqlite'
        run = ['run', '--config', config, '--data', db, '--miner', vector['public_key'], '--watch-key', vector['public_key'], '--rpc', '127.0.0.1:0', '--p2p', '127.0.0.1:0', '--stratum', '127.0.0.1:0']
        conflict = cli(*run, '--wallet-key', directory / 'not-loaded.json', success=False)
        assert 'cannot be used with' in conflict.stderr and (not db.exists())
        check('Hot and watch CLI flags conflict before loading a key or creating a database')
        _, base = start(options.node, run, 'watch', 'RPC: (http://127\\.0\\.0\\.1:\\d+)/rpc')
        cold_process, cold_base = start(options.cold, ['--port', '0'], 'cold', 'cold signer: (http://127\\.0\\.0\\.1:\\d+)/')
        status = rpc(base, 'status')
        assert status['time_unit'] == 'seconds'
        check('Default CLI creates a timestamp DAA network with block-count decisions and scheduled-second auction/rest timing')
        _, session = request(base, '/api/session')
        assert session['wallet_mode'] == 'watch' and session['wallet_enabled'] is False
        assert session['public_key'] == vector['public_key']
        payment = transfer_operation(vector['public_key'])
        status, _ = request(base, '/api/wallet', {'operation': payment, 'extra_fee': '0', 'expected_sender': session['public_key'], 'wallet_revision': session['wallet_revision']}, db.with_suffix('.session-token').read_text())
        assert status == 403
        check('Watch-only node exposes its public key and rejects hot signing')
        cli('mine', '--url', base + '/rpc', '--count', '12')
        before = rpc(base, 'account', {'key': vector['public_key']})['account']['nonce']
        operation_file = directory / 'operation.json'
        operation_file.write_text(json.dumps(payment), encoding='utf-8')

        def prepare(name, expiry=2):
            path = directory / name
            command = ['prepare', '--url', base + '/rpc', '--sender', vector['public_key'], '--operation-file', operation_file, '--expiry-blocks', expiry, '--out', path]
            cli(*command)
            return (path, command)
        unsigned, command = prepare('unsigned.json')
        envelope = json.loads(unsigned.read_text(encoding='utf-8'))
        assert envelope['format'] == 'hashstash-unsigned-anchor'
        assert envelope['chain_id'] == rpc(base, 'status')['chain_id']
        assert bytes.fromhex(envelope['body'])[:32].hex() == vector['public_key']
        original = unsigned.read_bytes()
        cli(*command, success=False)
        assert unsigned.read_bytes() == original
        assert rpc(base, 'mempool') == []
        assert rpc(base, 'account', {'key': vector['public_key']})['account']['nonce'] == before
        check('CLI prepares anchor-only bytes with separate network context without reserving a nonce or overwriting a file')
        _, cold_session = request(cold_base, '/api/session')
        token = cold_session['token']
        assert cold_session['unlocked'] is False

        def cold(action, value=None, expected=200):
            code, result = request(cold_base, '/api/' + action, value or {}, token)
            assert code == expected, (action, code, result)
            return result
        # The signer reviews only for an operator-selected network; these are legacy v1 fixtures.
        cold('network', {'chain_id': envelope['chain_id']})
        assert cold('unlock', {'passphrase': other['passphrase'], 'scheme': 'hashstash-passphrase-v1'})['public_key'] == other['public_key']
        cold('review', envelope, expected=400)
        assert cold('unlock', {'passphrase': vector['passphrase'], 'scheme': 'hashstash-passphrase-v1'})['public_key'] == vector['public_key']
        check('Published passphrase restores its exact public key; another account cannot review its transaction')
        review = cold('review', envelope)
        displayed = {field['label']: field['value'] for field in review['fields']}
        assert review['public_key'] == vector['public_key'] and displayed['Sender'] == review['address']
        assert displayed['Nonce'] == str(before) and review['watch']['format'] == 'hashstash-watch-v2'
        assert review['chain_id'] == rpc(base, 'status')['chain_id']
        assert displayed['Action'] == 'Transfer' and displayed['Recipient'] == review['address']
        assert displayed['Recipient receives · HASH'] == '1' and displayed['Fee · HASH'] == '1'
        assert 'Optional extra · HASH' not in displayed
        signed = cold('sign', {'review_token': review['review_token']})
        cold('sign', {'review_token': review['review_token']}, expected=400)
        computed_id = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed['raw'])).digest()).hexdigest()
        assert computed_id == signed['txid']
        raw_file = directory / 'signed.txt'
        with raw_file.open('x', encoding='utf-8') as file:
            file.write(signed['raw'] + '\n')
        result = json.loads(cli('broadcast', '--url', base + '/rpc', '--raw-file', raw_file).stdout)
        assert result['transaction_id'] == signed['txid']
        assert len(rpc(base, 'mempool')) == 1
        cli('mine', '--url', base + '/rpc', '--count', '1')
        block = rpc(base, 'getblock')
        assert len(block['transactions']) == 1 and block['transactions'][0]['body']['nonce'] == before
        assert 'chain_id' not in block['transactions'][0]['body']
        assert rpc(base, 'account', {'key': vector['public_key']})['account']['nonce'] == before + 1
        check('Cold review signs once; exported raw file broadcasts and is included in a mined block')
        cli('broadcast', '--url', base + '/rpc', '--raw-file', raw_file, success=False)
        assert rpc(base, 'mempool') == []
        check('Already-included transaction fails as a stale nonce without entering the pool')
        quote = rpc(base, 'transfer_quote', {'sender': vector['public_key'], 'recipient': other['public_key'], 'amount': '4', 'extra_fee': '1'})
        assert quote['recipient_receives'] == '4' and quote['account_creation_fee'] == '1'
        assert quote['total_debit'] == '7' and 'max_account_charge' not in quote
        assert quote['fee'] == '3' and quote['minimum_fee'] == '2' and 'max_fee' not in quote
        exact_operation = directory / 'exact-operation.json'
        exact_operation.write_text(json.dumps({'TransferExact': {'recipient': quote['recipient'], 'amount': '4'}}), encoding='utf-8')
        exact_unsigned = directory / 'exact-unsigned.json'
        cli('prepare', '--url', base + '/rpc', '--sender', vector['public_key'], '--operation-file', exact_operation, '--fee', '5', '--out', exact_unsigned)
        exact_review = cold('review', json.loads(exact_unsigned.read_text(encoding='utf-8')))
        exact_fields = {field['label']: field['value'] for field in exact_review['fields']}
        assert exact_fields['Recipient receives · HASH'] == '4'
        assert 'Account creation maximum · HASH' not in exact_fields
        assert exact_fields['Fee · HASH'] == '5' and 'Optional extra · HASH' not in exact_fields
        assert exact_fields['Total debit · HASH'] == '9'
        exact_signed = cold('sign', {'review_token': exact_review['review_token']})
        cli('broadcast', '--url', base + '/rpc', '--raw', exact_signed['raw'])
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': other['public_key']})['account']['ordinary'] == '4'
        check('Watch-only exact-send quote, CLI preparation, cold review, signing and broadcast deliver the full requested amount')
        key_file = directory / 'published-test-key.json'
        key_file.write_text(json.dumps({'secret': vector['secret'], 'public': vector['public_key']}), encoding='utf-8')
        transfer_args = ['transfer', '--url', base + '/rpc', '--key', key_file, '--recipient', quote['recipient'], '--amount', '3']
        cli(*transfer_args, '--min-received', '3', success=False)
        cli(*transfer_args)
        pending_record = rpc(base, 'mempool')[0]
        assert pending_record['body']['operation']['TransferExact']['amount'] == '3'
        assert pending_record['body']['data'] == [] and int(pending_record['body']['fee']) >= 1
        pending_transfer = pending_record['display_operation']['TransferExact']
        assert pending_transfer['amount'] == '3' and 'max_account_charge' not in pending_transfer
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': other['public_key']})['account']['ordinary'] == '7'
        third = vectors[2]
        cli('transfer', '--url', base + '/rpc', '--key', key_file, '--recipient', third['public_key'], '--amount', '2', '--max-account-charge', '0', success=False)
        # --max-fee is a ceiling: the quote, including account creation, exceeds 1 atom.
        ceiling = cli('transfer', '--url', base + '/rpc', '--key', key_file, '--recipient', third['public_key'], '--amount', '2', '--max-fee', '1', success=False)
        assert 'atom ceiling' in ceiling.stderr, ceiling.stderr
        cli('transfer', '--url', base + '/rpc', '--key', key_file, '--recipient', third['public_key'], '--amount', '2', '--fee', '1', success=False)
        assert rpc(base, 'mempool') == []
        cli('transfer', '--url', base + '/rpc', '--key', key_file, '--recipient', third['public_key'], '--amount', '2')
        assert 'max_account_charge' not in rpc(base, 'mempool')[0]['display_operation']['TransferExact']
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'account', {'key': third['public_key']})['account']['ordinary'] == '2'
        check('CLI transfer selects current exact amounts, signs an exact fee, and rejects obsolete arguments, quotes above its fee ceiling or insufficient fees')
        payload = (bytes(range(256)) * 12)[:3000] + b'<script>stored bytes only</script>\x00\r\n'
        data_unsigned = directory / 'data-unsigned.json'
        cli('prepare', '--url', base + '/rpc', '--sender', vector['public_key'], '--operation-file', operation_file, '--data-hex', payload.hex().upper(), '--out', data_unsigned)
        data_envelope = json.loads(data_unsigned.read_text(encoding='utf-8'))
        data_review = cold('review', data_envelope)
        data_fields = {field['label']: field['value'] for field in data_review['fields']}
        assert data_review['body'] == data_envelope['body']
        assert data_fields['Data bytes'] == str(len(payload)) and data_fields['Data hex'] == payload.hex()
        assert data_fields['Action'] == 'Transfer' and data_fields['Recipient receives · HASH'] == '1'
        assert data_fields['Recipient'] == review['address']
        data_signed = cold('sign', {'review_token': data_review['review_token']})
        broadcast = json.loads(cli('broadcast', '--url', base + '/rpc', '--raw', data_signed['raw']).stdout)
        assert broadcast['transaction_id'] == data_signed['txid']
        pending = rpc(base, 'mempool')
        assert len(pending) == 1
        data_body = pending[0]['body']
        assert bytes(data_body['data']) == payload
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'getblock')['transactions'][0]['body'] == data_body
        assert rpc(base, 'mempool') == []
        check('CLI prepares all byte values and markup as opaque data; cold review, signing, raw broadcast and mining preserve exact bytes')
        hot_payload = (bytes(reversed(range(256))) * 12)[:3000] + b'\x00hot\xff'
        received_before = int(rpc(base, 'account', {'key': other['public_key']})['account']['ordinary'])
        hot = json.loads(cli(*transfer_args, '--extra-fee', '1', '--data-hex', hot_payload.hex()).stdout)
        pending = rpc(base, 'mempool')
        assert len(pending) == 1
        hot_body = pending[0]['body']
        assert bytes(hot_body['data']) == hot_payload
        assert int(hot_body['fee']) > 1 and 'extra_fee' not in hot_body
        assert pending[0]['display_operation']['TransferExact']['amount'] == '3'
        assert re.fullmatch('[0-9a-f]{64}', hot['txid'])
        cli('mine', '--url', base + '/rpc', '--count', '1')
        assert rpc(base, 'getblock')['transactions'][0]['body'] == hot_body
        assert int(rpc(base, 'account', {'key': other['public_key']})['account']['ordinary']) == received_before + 3
        check('CLI hot transfer signs and mines opaque data while preserving the exact recipient amount and signed fee')
        data_before = rpc(base, 'status')
        for index, invalid_data in enumerate(('0', 'zz', '0x00', '00 ff', 'ff' * (data_before['settings']['block_bytes'] + 1))):
            rejected_export = directory / f'invalid-data-{index}.json'
            cli('prepare', '--url', base + '/rpc', '--sender', vector['public_key'], '--operation-file', operation_file, '--data-hex', invalid_data, '--out', rejected_export, success=False)
            cli(*transfer_args, '--data-hex', invalid_data, success=False)
            assert not rejected_export.exists()
            assert rpc(base, 'mempool') == [] and rpc(base, 'status') == data_before
        omitted_data, _ = prepare('omitted-data.json')
        empty_data = directory / 'empty-data.json'
        cli('prepare', '--url', base + '/rpc', '--sender', vector['public_key'], '--operation-file', operation_file, '--data-hex', '', '--out', empty_data)
        assert json.loads(omitted_data.read_text(encoding='utf-8')) == json.loads(empty_data.read_text(encoding='utf-8'))
        check('CLI rejects malformed and oversized data without exports or transactions; empty data preserves the ordinary encoding')
        expired_file, _ = prepare('expired-unsigned.json', expiry=1)
        expired = cold('review', json.loads(expired_file.read_text(encoding='utf-8')))
        expired = cold('sign', {'review_token': expired['review_token']})
        cli('mine', '--url', base + '/rpc', '--count', '2')
        cli('broadcast', '--url', base + '/rpc', '--raw', expired['raw'], success=False)
        assert rpc(base, 'mempool') == []
        check('Signed transaction that expires during offline transfer is rejected')
        fresh_file, _ = prepare('fresh-unsigned.json')
        fresh = json.loads(fresh_file.read_text(encoding='utf-8'))
        first = cold('review', fresh)
        second = cold('review', fresh)
        cold('sign', {'review_token': first['review_token']}, expected=400)
        cold('cancel')
        cold('sign', {'review_token': second['review_token']}, expected=400)
        check('Replacing or cancelling the review invalidates earlier approval tokens')
        old_token = token
        stop(cold_process)
        _, cold_base = start(options.cold, ['--port', '0'], 'cold-restored', 'cold signer: (http://127\\.0\\.0\\.1:\\d+)/')
        _, restarted = request(cold_base, '/api/session')
        assert restarted['unlocked'] is False and restarted['token'] != old_token
        token = restarted['token']
        assert cold('unlock', {'passphrase': vector['passphrase'], 'scheme': 'hashstash-passphrase-v1'})['public_key'] == vector['public_key']
        cold('lock')
        cold('review', fresh, expected=400)
        check('Signer restart clears keys; the same passphrase restores the same account; locking disables review')
        tip = rpc(base, 'status')['tip']
        malformed = directory / 'malformed.txt'
        malformed.write_text('00\n', encoding='utf-8')
        cli('broadcast', '--url', base + '/rpc', '--raw-file', malformed, success=False)
        cli('broadcast', '--url', base + '/rpc', '--raw-file', raw_file, '--raw', signed['raw'], success=False)
        assert rpc(base, 'status')['tip'] == tip and rpc(base, 'mempool') == []
        check('Malformed raw input and conflicting raw arguments cannot change node state')
        report.update({'passed': True, 'version': cli('--version').stdout.strip(), 'network': rpc(base, 'status'), 'included_transaction': signed['txid'], 'public_key': vector['public_key']})
    finally:
        for process in processes:
            stop(process)
        for handle in logs:
            handle.close()
        report['owned_processes_stopped'] = all((process.poll() is not None for process in processes))
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"Passed {len(checks)} checks in {report['elapsed_seconds']}s; {options.report}", flush=True)
if __name__ == '__main__':
    main()
