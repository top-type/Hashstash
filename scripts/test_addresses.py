"""Address -> CLI transfer -> offline review -> broadcast on disposable nodes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
from test_wallet_cli import REPO, digest, request, rpc

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash.exe' if os.name == 'nt' else 'hashstash'))
    parser.add_argument('--cold', type=Path, default=REPO / 'target/fixtures/release' / ('hashstash-cold.exe' if os.name == 'nt' else 'hashstash-cold'))
    parser.add_argument('--report', type=Path, default=REPO / 'work/address-live-report.json')
    parser.add_argument('--directory', type=Path, default=REPO / 'work')
    args = parser.parse_args()
    args.node, args.cold = (args.node.resolve(), args.cold.resolve())
    scratch = args.directory.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='addresses-', dir=scratch)).resolve()
    assert directory.is_relative_to(scratch)
    vectors = json.loads((REPO / 'tests/data/passphrase-v1.json').read_text(encoding='utf-8'))['vectors'][:2]
    processes, logs, checks = ([], [], [])
    started = time.monotonic()
    report = {'suite': 'checksummed addresses', 'passed': False, 'directory': str(directory), 'test_work': True, 'issuance_mode': 'accelerated test fixture', 'expected_hashes_per_atom': '1', 'production_issuance_tested': False, 'checks': checks, 'node_sha256': digest(args.node), 'cold_sha256': digest(args.cold)}

    def cli(*values, good=True):
        result = subprocess.run([str(args.node), *map(str, values)], cwd=directory, capture_output=True, text=True, timeout=30, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        assert (result.returncode == 0) == good, (values, result.stdout, result.stderr)
        return result.stdout.strip()

    def start(binary, values, name, pattern):
        output = directory / (name + '.stdout.log')
        stdout, stderr = (output.open('w'), (directory / (name + '.stderr.log')).open('w'))
        logs.extend([stdout, stderr])
        process = subprocess.Popen([str(binary), *map(str, values)], cwd=directory, stdout=stdout, stderr=stderr, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        processes.append(process)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, f'{name} exited; see {directory}'
            match = re.search(pattern, output.read_text(errors='replace'))
            if match:
                return match.group(1)
            time.sleep(0.05)
        raise AssertionError(f'{name} startup timed out')

    def check(description):
        checks.append(description)
        print('PASS: ' + description, flush=True)
    try:
        config = directory / 'network.json'
        cli('init', '--config', config)
        value = json.loads(config.read_text())
        value['test_work'] = True
        value['network'] = 'address-test-' + uuid.uuid4().hex
        value['genesis_time'] = int(time.time()) - 10000
        config.write_text(json.dumps(value))
        other_config = directory / 'other.json'
        other_config.write_text(json.dumps({**value, 'network': value['network'] + '-other'}))
        keys = []
        for i, vector in enumerate(vectors):
            path = directory / f'fixture-{i}.json'
            path.write_text(json.dumps({'secret': vector['secret'], 'public': vector['public_key']}))
            keys.append(path)
        addresses = [cli('address', '--key', key, '--config', config) for key in keys]
        wrong_network = cli('address', '--key', keys[1], '--config', other_config)
        network = json.loads(cli('network', '--config', config))
        other_network = json.loads(cli('network', '--config', other_config))
        assert network['format'] == 'hashstash-network-v1'
        for address, vector in zip(addresses, vectors):
            assert len(address) == 78 and address.startswith('hsh' + network['chain_id'][:16] + '1')
            assert cli('decode-address', '--address', address.upper(), '--config', config) == vector['public_key']
        typo = addresses[1][:-1] + ('q' if addresses[1][-1] != 'q' else 'p')
        for bad in [typo, wrong_network, addresses[1][:2].upper() + addresses[1][2:], vectors[1]['public_key']]:
            cli('decode-address', '--address', bad, '--config', config, good=False)
        check('CLI round trips both cases and rejects checksum errors, mixed case, wrong networks, and raw keys as addresses')
        base = start(args.node, ['run', '--config', config, '--data', directory / 'chain.sqlite', '--miner', addresses[0], '--watch-key', addresses[1], '--rpc', '127.0.0.1:0', '--p2p', '127.0.0.1:0', '--stratum', '127.0.0.1:0'], 'node', 'RPC: (http://127\\.0\\.0\\.1:\\d+)/rpc')
        session = request(base, '/api/session')[1]
        assert session['address'] == addresses[1] and session['public_key'] == vectors[1]['public_key']
        assert session['wallets'][0]['address'] == addresses[1]
        assert rpc(base, 'address', {'public_key': vectors[0]['public_key']})['address'] == addresses[0]
        assert rpc(base, 'validateaddress', {'address': addresses[1].upper()})['public_key'] == vectors[1]['public_key']
        for bad in [typo, wrong_network]:
            code, response = request(base, '/api/wallet/manage', {'action': 'watch', 'name': 'Invalid', 'public_key': bad, 'revision': session['wallet_revision']}, session['token'])
            assert code == 400, response
            assert request(base, '/api/session')[1] == session
        check('Node startup, session metadata, address RPCs and watch-only management validate network-bound addresses')
        url = base + '/rpc'
        cli('mine', '--url', url, '--recipient', addresses[0], '--count', 10)
        before = rpc(base, 'status')
        cli('transfer', '--url', url, '--key', keys[0], '--recipient', wrong_network, '--amount', 4, good=False)
        cli('transfer', '--url', url, '--key', keys[0], '--recipient', typo, '--amount', 4, good=False)
        assert rpc(base, 'status') == before
        arguments = []
        cli('transfer', '--url', url, '--key', keys[0], '--recipient', addresses[1], '--amount', 4, *arguments)
        cli('mine', '--url', url, '--recipient', addresses[0])
        assert rpc(base, 'account', {'key': addresses[1]})['account']['ordinary'] == '4'
        operation = directory / 'transfer.json'

        def transfer(recipient, amount):
            return {'TransferExact': {'recipient': recipient, 'amount': str(amount)}}
        operation.write_text(json.dumps(transfer(addresses[1], 2)))
        cli('send', '--url', url, '--key', keys[0], '--operation-file', operation)
        cli('mine', '--url', url, '--recipient', addresses[0])
        assert rpc(base, 'account', {'key': addresses[1]})['account']['ordinary'] == '6'
        check('Address-based mining, transfer and operation JSON work; invalid destinations leave node state unchanged')
        operation.write_text(json.dumps(transfer(addresses[0], 1)))
        envelope_file = directory / 'unsigned.json'
        cli('prepare', '--url', url, '--sender', addresses[1], '--operation-file', operation, '--out', envelope_file)
        envelope = json.loads(envelope_file.read_text())
        cold = start(args.cold, ['--port', '0', '--config', config], 'cold', 'cold signer: (http://127\\.0\\.0\\.1:\\d+)')
        cold_session = request(cold, '/api/session')[1]
        token = cold_session['token']
        assert cold_session['chain_id'] == network['chain_id']
        code, unlocked = request(cold, '/api/import', {'private_key': vectors[1]['secret']}, token)
        assert code == 200 and unlocked['address'] == addresses[1], unlocked
        assert unlocked['watch'] == {'format': 'hashstash-watch-v2', 'address': addresses[1], 'public_key': vectors[1]['public_key'], 'chain_id': network['chain_id']}
        code, review = request(cold, '/api/review', envelope, token)
        assert code == 200, review
        fields = {f['label']: f['value'] for f in review['fields']}
        assert fields['Sender'] == addresses[1] and fields['Recipient'] == addresses[0]
        old_review = review['review_token']
        assert request(cold, '/api/network', {'chain_id': other_network['chain_id']}, token)[0] == 200
        assert request(cold, '/api/sign', {'review_token': old_review}, token)[0] == 400
        assert request(cold, '/api/review', envelope, token)[0] == 400
        assert request(cold, '/api/network', {'chain_id': network['chain_id']}, token)[0] == 200
        code, review = request(cold, '/api/review', envelope, token)
        assert code == 200, review
        code, signed = request(cold, '/api/sign', {'review_token': review['review_token']}, token)
        assert code == 200, signed
        raw = directory / 'signed.txt'
        raw.write_text(signed['raw'])
        cli('broadcast', '--url', url, '--raw-file', raw)
        cli('mine', '--url', url, '--recipient', addresses[0])
        assert rpc(base, 'account', {'key': addresses[1]})['account']['ordinary'] == '4'
        assert request(cold, '/api/lock', {}, token)[0] == 200
        check('Cold signer matches address exports and signed-body review; network changes invalidate reviews; broadcast credits the original keys')
        report.update(passed=True, addresses=addresses, chain_id=network['chain_id'], final_status=rpc(base, 'status'))
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
        for file in logs:
            file.close()
        report['processes_stopped'] = all((p.poll() is not None for p in processes))
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
