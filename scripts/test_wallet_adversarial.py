"""Malformed offline exports and cross-network/replay rejection on disposable nodes."""
import argparse
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from test_wallet_cli import HTTP, REPO, transfer_operation, digest, request, rpc


def compact_uint(value):
    assert 0 <= value < 1 << 64
    if value <= 250:
        return bytes([value])
    for tag, width in ((251, 2), (252, 4), (253, 8)):
        if value < 1 << (8 * width):
            return bytes([tag]) + value.to_bytes(width, 'little')
    raise AssertionError('unreachable u64')


def read_uint(raw, offset):
    first = raw[offset]
    width = {251: 2, 252: 4, 253: 8}.get(first, 0)
    assert first <= 253 and offset + 1 + width <= len(raw)
    value = int.from_bytes(raw[offset + 1:offset + 1 + width], 'little') if width else first
    end = offset + 1 + width
    assert compact_uint(value) == raw[offset:end]
    return value, end

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=REPO / 'work/wallet-adversarial')
    parser.add_argument('--base-port', type=int, default=28480)
    parser.add_argument('--report', type=Path, default=REPO / 'work/wallet-adversarial-report.json')
    parser.add_argument('--node', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash.exe' if os.name == 'nt' else 'hashstash'))
    parser.add_argument('--cold', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash-cold.exe' if os.name == 'nt' else 'hashstash-cold'))
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='adversarial-', dir=args.directory)).resolve()
    node, signer = (args.node.resolve(), args.cold.resolve())
    vectors = json.loads((REPO / 'tests/data/passphrase-v1.json').read_text(encoding='utf-8'))['vectors']
    primary, other = vectors[:2]
    processes, files, checks = ([], [], [])
    started = time.monotonic()
    report = {'passed': False, 'directory': str(directory), 'test_work': True, 'issuance_mode': 'accelerated test fixture', 'expected_hashes_per_atom': '1', 'production_issuance_tested': False, 'checks': checks, 'node_sha256': digest(node), 'cold_sha256': digest(signer)}

    def check(message):
        checks.append(message)
        print('PASS: ' + message, flush=True)

    def start(binary, values, label, pattern):
        output = directory / (label + '.stdout.log')
        stdout, stderr = (output.open('w'), (directory / (label + '.stderr.log')).open('w'))
        files.extend([stdout, stderr])
        process = subprocess.Popen([str(binary), *map(str, values)], cwd=directory, stdout=stdout, stderr=stderr, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, label + ' exited; inspect ' + str(directory)
            match = re.search(pattern, output.read_text(errors='replace'))
            if match:
                return match.group(1)
            time.sleep(0.05)
        raise AssertionError(label + ' did not start')
    try:
        configuration = json.loads((REPO / 'config/devnet.json').read_text())

        configuration["test_work"] = True
        configuration.update(network='wallet-adversarial-' + uuid.uuid4().hex)
        configuration['genesis_time'] = int(time.time()) - 1
        config = directory / 'network.json'
        config.write_text(json.dumps(configuration))
        base = start(node, ['run', '--config', config, '--data', directory / 'chain.sqlite', '--miner', primary['public_key'], '--watch-key', primary['public_key'], '--rpc', f'127.0.0.1:{args.base_port}', '--p2p', f'127.0.0.1:{args.base_port + 1}', '--stratum', f'127.0.0.1:{args.base_port + 2}'], 'node', 'RPC: (http://127\\.0\\.0\\.1:\\d+)/rpc')
        # Above the 64 MiB default, so the configurable review limit is exercised below.
        review_limit = 2 * 32 * 1024 * 1024 + 128 * 1024
        cold_base = start(signer, ['--port', args.base_port + 3, '--config', config, '--max-review-bytes', review_limit + 64 * 1024], 'cold', 'cold signer: (http://127\\.0\\.0\\.1:\\d+)/')
        status = rpc(base, 'status')
        assert status['time_unit'] == 'seconds'
        check('Adversarial wallet fixture uses canonical-only mining and immediate reserve-grant funding consensus')
        token = request(cold_base, '/api/session')[1]['token']

        def cold(action, value=None, expected=200):
            code, result = request(cold_base, '/api/' + action, {} if value is None else value, token)
            assert code == expected, (action, code, result)
            return result

        def raw_cold(action, value, headers=None):
            headers = {'Content-Type': 'application/json', 'Origin': cold_base, 'X-Hashstash-Cold-Token': token, **(headers or {})}
            req = urllib.request.Request(cold_base + '/api/' + action, data=value.encode(), headers=headers)
            try:
                with HTTP.open(req, timeout=15) as response:
                    return (response.status, response.read())
            except urllib.error.HTTPError as error:
                return (error.code, error.read())

        def reject_raw(raw):
            code, reply = request(base, '/rpc', {'jsonrpc': '2.0', 'id': 1, 'method': 'broadcasttransaction', 'params': {'raw': raw}})
            assert code in (200, 400, 413) and 'error' in reply, (code, reply)
            if code != 200:
                time.sleep(0.35)
            assert rpc(base, 'mempool') == []
            return reply['error']

        def prepare(amount='1', expiry=2):
            envelope = rpc(base, 'preparetransaction', {'sender': primary['public_key'], **{'extra_fee': '0'}, 'expiry_blocks': expiry, 'operation': transfer_operation(primary['public_key'], amount)})
            envelope.pop('fee_quote', None)
            return envelope

        def sign(envelope):
            review = cold('review', envelope)
            return cold('sign', {'review_token': review['review_token']})
        rpc(base, 'mine', {'count': 12})
        cold('unlock', {'passphrase': primary['passphrase'], 'scheme': 'hashstash-passphrase-v1'})
        original = prepare()
        body = bytes.fromhex(original['body'])
        _, fee_length_offset = read_uint(body, 32)
        fee_size, fee_offset = read_uint(body, fee_length_offset)
        anchor_offset = fee_offset + fee_size
        expiry_offset = anchor_offset + 32
        expiry, operation_offset = read_uint(body, expiry_offset)
        assert original['chain_id'] == rpc(base, 'status')['chain_id']
        assert body[:32].hex() == primary['public_key']
        assert body[anchor_offset:expiry_offset].hex() == rpc(base, 'status')['tip']
        assert expiry == 2
        for method, extra in [('preparetransaction', {'anchor': '42' * 32}),
                              ('fee_quote', {'anchor': '42' * 32}),
                              ('preparetransaction', {'expiry_height': rpc(base, 'status')['height'] + 2}),
                              ('preparetransaction', {'expiry_blocks': 0})]:
            code, reply = request(base, '/rpc', {'jsonrpc': '2.0', 'id': 1, 'method': method,
                'params': {'sender': primary['public_key'], 'operation': transfer_operation(primary['public_key']), **extra}})
            assert code in (200, 400) and 'error' in reply
        assert rpc(base, 'mempool') == []
        check('Preparation and fee quotes reject a foreign anchor; absolute expiry input and zero lifetime also reject')

        def changed(offset, value, length=None):
            return {**original, 'body': (body[:offset] + value + body[offset + (len(value) if length is None else length):]).hex()}
        invalid = {
            'unknown format': {**original, 'format': 'hashstash-unsigned-v999'},
            'extra envelope field': {**original, 'amount': '999'},
            'missing body': {'format': original['format']},
            'numeric body': {**original, 'body': 42}, 'empty body': {**original, 'body': ''},
            'odd hex': {**original, 'body': original['body'] + '0'},
            'nonhex body': {**original, 'body': 'zz'},
            'truncated body': {**original, 'body': original['body'][:-2]},
            'trailing byte': {**original, 'body': original['body'] + '00'},
            'large malformed body': {**original, 'body': '00' * 16385},
            'invalid sender': changed(0, b'\xff' * 32),
            'different sender': changed(0, bytes.fromhex(other['public_key'])),
            'exhausted nonce': changed(32, compact_uint((1 << 64) - 1), fee_length_offset - 32),
            'noncanonical nonce': changed(32, b'\xfb\x00\x00', fee_length_offset - 32),
            'forbidden integer tag': changed(32, b'\xff', fee_length_offset - 32),
            'u128 nonce': changed(32, b'\xfe' + bytes(16), fee_length_offset - 32),
            'zero expiry': changed(expiry_offset, b'\x00', operation_offset - expiry_offset),
            'noncanonical expiry': changed(expiry_offset, b'\xfd' + expiry.to_bytes(8, 'little'), operation_offset - expiry_offset),
            'unknown operation': changed(operation_offset, b'\x08'),
            'other network context': {**original, 'chain_id': '42' * 32},
            'missing network context': {key: value for key, value in original.items() if key != 'chain_id'},
            'old unsigned format': {**original, 'format': 'hashstash-unsigned-v1'},
            'old chain-prefixed body': {**original, 'body': original['chain_id'] + original['body']},
            'noncanonical fee length': changed(fee_length_offset, b'\xfb' + fee_size.to_bytes(2, 'little'), fee_offset - fee_length_offset),
            'noncanonical fee': changed(fee_length_offset, compact_uint(fee_size + 1) + body[fee_offset:anchor_offset] + b'\x00', anchor_offset - fee_length_offset),
            'fee above 512 bits': changed(fee_length_offset, compact_uint(65) + b'\xff' * 65, anchor_offset - fee_length_offset),
        }
        tag, recipient_offset = read_uint(body, operation_offset)
        assert tag == 0
        transfer_length_offset = recipient_offset + 32
        transfer_size, transfer_offset = read_uint(body, transfer_length_offset)
        data_length_offset = transfer_offset + transfer_size
        data_size, data_offset = read_uint(body, data_length_offset)
        assert data_size == 0 and data_offset == len(body)
        invalid.update({
            'removed envelope tag': changed(operation_offset, b'\x06'),
            'noncanonical operation tag': changed(operation_offset, b'\xfb\x00\x00', recipient_offset - operation_offset),
            'noncanonical transfer amount': changed(transfer_length_offset, compact_uint(transfer_size + 1) + body[transfer_offset:data_length_offset] + b'\x00', data_length_offset - transfer_length_offset),
            'noncanonical data length': changed(data_length_offset, b'\xfb\x00\x00', data_offset - data_length_offset),
            'truncated transaction data': changed(data_length_offset, b'\x01', data_offset - data_length_offset),
        })
        for name, envelope in invalid.items():
            review = cold('review', original)
            cold('review', envelope, expected=400)
            cold('sign', {'review_token': review['review_token']}, expected=400)
            check('Malformed unsigned export rejected and prior approval invalidated: ' + name)
        duplicate = json.dumps(original)[:-1] + ',"body":"00"}'
        prior = cold('review', original)
        assert raw_cold('review', duplicate)[0] == 400
        cold('sign', {'review_token': prior['review_token']}, expected=400)
        check('Duplicate JSON body keys cannot substitute or retain an approved transaction')
        for headers in ({'Origin': 'https://example.invalid'}, {'X-Hashstash-Cold-Token': 'wrong'}, {'Host': 'example.invalid'}):
            assert raw_cold('unlock', json.dumps({'passphrase': other['passphrase']}), headers)[0] == 403
        assert request(cold_base, '/api/session')[1]['public_key'] == primary['public_key']
        assert raw_cold('unlock', ' ' * (128 * 1024 + 1))[0] == 413
        assert raw_cold('review', ' ' * (128 * 1024 + 1))[0] == 400
        assert raw_cold('review', ' ' * (review_limit + 1))[0] == 400
        assert raw_cold('review', ' ' * (review_limit + 1) + json.dumps(original))[0] == 200
        assert raw_cold('review', ' ' * (review_limit + 64 * 1024 + 1))[0] == 413
        check('Review envelopes are bounded only by the signer\'s configurable review limit')
        assert request(cold_base, '/api/session')[1]['unlocked'] is True
        check('Cross-origin, wrong token/host, and oversized control inputs leave the signer available and wallet unchanged')
        signed = sign(original)
        raw = bytes.fromhex(signed['raw'])
        assert raw[:len(body)] == body and len(raw) == len(body) + 64
        invalid_signed = {
            'truncation': signed['raw'][:-2], 'trailing bytes': signed['raw'] + '00',
            'odd hex': signed['raw'] + '0', 'nonhex': 'gg', 'empty': '',
            'above block capacity': '00' * (status['settings']['block_bytes'] + 1),
            'wrong signature': (raw[:-1] + bytes([raw[-1] ^ 1])).hex(),
            'changed signed nonce': (raw[:32] + compact_uint(1) + raw[fee_length_offset:]).hex(),
            'changed signed anchor': (raw[:anchor_offset] + b'\x42' * 32 + raw[expiry_offset:]).hex(),
            'signature length prefix': (body + compact_uint(64) + raw[len(body):]).hex(),
        }
        status_before = rpc(base, 'status')
        for name, invalid_raw in invalid_signed.items():
            reject_raw(invalid_raw)
            assert rpc(base, 'status') == status_before
            check('Malformed signed export rejected without state changes: ' + name)
        foreign_chain = '42' * 32
        cold('network', {'chain_id': foreign_chain})
        cold('review', original, expected=400)
        cold('network', {'chain_id': original['chain_id']})
        assert rpc(base, 'status') == status_before
        check('Unsigned network context catches an accidental signer network mismatch without entering the signed body')
        foreign_anchor = sign(changed(anchor_offset, b'\x42' * 32))
        reject_raw(foreign_anchor['raw'])
        assert rpc(base, 'status') == status_before
        check('A valid signature anchored to an unknown block cannot enter the local mempool')
        competing = sign(prepare('2'))
        accepted = rpc(base, 'broadcasttransaction', {'raw': signed['raw']})
        assert accepted['transaction_id'] == signed['txid']
        rpc(base, 'mine', {'count': 1})
        assert rpc(base, 'account', {'key': primary['public_key']})['account']['nonce'] == 1
        reject_raw(competing['raw'])
        reject_raw(signed['raw'])
        check('Two offline exports using one nonce cannot both execute; replay also fails after inclusion')
        expires = sign(prepare(expiry=1))
        rpc(base, 'mine', {'count': 2})
        reject_raw(expires['raw'])
        check('An offline-signed transaction expires even while absent from the mempool')
        prior = cold('review', prepare())
        cold('import', {'private_key': '00'}, expected=400)
        assert request(cold_base, '/api/session')[1]['unlocked'] is False
        cold('sign', {'review_token': prior['review_token']}, expected=400)
        cold('unlock', {'passphrase': primary['passphrase'], 'scheme': 'hashstash-passphrase-v1'})
        restored = sign(prepare())
        rpc(base, 'broadcasttransaction', {'raw': restored['raw']})
        rpc(base, 'mine', {'count': 1})
        assert rpc(base, 'account', {'key': primary['public_key']})['account']['nonce'] == 2
        check('Failed private-key import clears prior approval; restoring the wallet remains functional')
        for kind, field, removed, tag in [('Deposit', 'amount', 'min_shares', 1),
                                           ('Redeem', 'shares', 'min_received', 2)]:
            account = rpc(base, 'account', {'key': primary['public_key']})['account']
            value = 4 if kind == 'Deposit' else int(account['shares']) // 2
            assert value > 0
            operation = {kind: {field: str(value), 'decision': None, 'outcome': None}}
            params = {'sender': primary['public_key'], 'operation': operation}
            envelope = rpc(base, 'preparetransaction', params)
            envelope.pop('fee_quote', None)
            encoded = bytes.fromhex(envelope['body'])
            _, offset = read_uint(encoded, 32)
            fee_size, offset = read_uint(encoded, offset)
            anchor_offset = offset + fee_size
            assert encoded[anchor_offset:anchor_offset + 32].hex() == rpc(base, 'status')['tip']
            expiry, offset = read_uint(encoded, anchor_offset + 32)
            assert expiry == 2
            magnitude = value.to_bytes((value.bit_length() + 7) // 8, 'little')
            assert encoded[offset:] == compact_uint(tag) + compact_uint(len(magnitude)) + magnitude + b'\x00\x00\x00'
            review = cold('review', envelope)
            assert not any('minimum' in item['label'].lower() for item in review['fields'])
            signed_trade = cold('sign', {'review_token': review['review_token']})
            rpc(base, 'broadcasttransaction', {'raw': signed_trade['raw']})
            rpc(base, 'mine', {'count': 1})
            current = rpc(base, 'account', {'key': primary['public_key']})['account']
            assert current['nonce'] == account['nonce'] + 1
            assert (int(current['shares']) > int(account['shares'])) == (kind == 'Deposit')
            invalid_operation = {kind: {**operation[kind], removed: '0'}}
            code, response = request(base, '/rpc', {'jsonrpc': '2.0', 'id': 1,
                'method': 'preparetransaction', 'params': {**params, 'operation': invalid_operation}})
            assert code in (200, 400) and 'error' in response
            check(kind + ' amount-only bytes use a two-block expiry, cold-sign and execute; removed minimum fields reject')
        report.update(passed=True, final_status=rpc(base, 'status'), invalid_unsigned=len(invalid) + 1, invalid_signed=len(invalid_signed))
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        for file in files:
            file.close()
        report['processes_stopped'] = all((process.poll() is not None for process in processes))
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    assert report['passed'] and report['processes_stopped']
    print(f'Passed {len(checks)} adversarial checks; {args.report}', flush=True)
if __name__ == '__main__':
    main()
