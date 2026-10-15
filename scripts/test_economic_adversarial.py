"""Atomic rejection and replay accounting on an already funded isolated testnet.

Uses only the fixture's mining key files. It does not create/stop nodes or contact
any network other than the explicit manifest. Requires no pending
transactions. Ordinary, conditional and governance accounting is checked through
the reserve audit's independent supply reconciliation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from test_network import rpc
from test_reserve_network import Fork, ReserveAudit

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding='utf-8-sig'))
    nodes = manifest['nodes']
    audit = ReserveAudit(manifest)
    directory = Path(manifest['directory']) / ('economic-adversarial-' + str(time.time_ns()))
    directory.mkdir()
    started, checks = (time.monotonic(), [])

    def check(description):
        checks.append(description)
        print('PASS: ' + description, flush=True)

    def snapshot(port):
        result = rpc(port, 'snapshot', {'key': nodes[0]['public_key'], 'keys': [node['public_key'] for node in nodes]})
        result.pop('mining', None)
        return result

    def all_snapshots():
        return [snapshot(node['rpc_port']) for node in nodes]

    def sign(body, label):
        body = copy.deepcopy(body)
        body.setdefault('data', [])
        body_file, transaction_file = (directory / (label + '.body.json'), directory / (label + '.signed.json'))
        body_file.write_text(json.dumps(body), encoding='utf-8')
        result = subprocess.run([manifest['executable'], 'sign', '--key', nodes[0]['key_file'], '--body', str(body_file), '--out', str(transaction_file)], capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        assert result.returncode == 0, 'Fixture signing failed: ' + result.stderr
        return json.loads(transaction_file.read_text(encoding='utf-8'))

    def rejected(port, transaction):
        try:
            rpc(port, 'submittransaction', transaction)
        except RuntimeError:
            return
        raise AssertionError('Invalid transaction was accepted')

    def wait_pending(count):
        deadline = time.monotonic() + 30
        while True:
            pools = [[{'body': tx['body'], 'signature': tx['signature']} for tx in rpc(node['rpc_port'], 'mempool')] for node in nodes]
            if all((len(pool) == count for pool in pools)):
                return pools
            assert time.monotonic() < deadline, 'Pending transactions did not converge'
            time.sleep(0.05)
    audit.agree()
    wait_pending(0)
    before = all_snapshots()
    status = before[0]['status']
    account = before[0]['account']['account']
    assert int(account['ordinary']) > 20
    recipient = nodes[1]['public_key']
    body = {'chain_id': list(bytes.fromhex(status['chain_id'])), 'sender': list(bytes.fromhex(nodes[0]['public_key'])), 'nonce': account['nonce'], 'fee': '100', 'anchor': list(bytes.fromhex(status['tip'])), 'expiry_blocks': 2, 'operation': {'TransferExact': {'recipient': list(bytes.fromhex(recipient)), 'amount': '7'}}}
    # Quote before constructing the exact signed fee; later recipient creation
    # may lower the minimum, but it never reduces that signed fee.
    terms = audit.payment_terms(body['operation'], 3)
    body['fee'] = str(max(100, terms['required']))
    assert int(account['ordinary']) >= 7 + int(body['fee'])
    bad_cases = []
    overdraft = copy.deepcopy(body)
    overdraft['operation']['TransferExact']['amount'] = account['ordinary']
    overdraft['fee'] = body['fee']
    bad_cases.append(('fee-after-transfer-overdraft', sign(overdraft, 'overdraft')))
    expired = copy.deepcopy(body)
    old_block = rpc(nodes[0]['rpc_port'], 'explorer_block', {'height': status['height'] - 2, 'limit': 1})
    expired['anchor'] = list(bytes.fromhex(old_block['block']['hash']))
    expired['expiry_blocks'] = 1
    bad_cases.append(('expired', sign(expired, 'expired')))
    unknown_anchor = copy.deepcopy(body)
    unknown_anchor['anchor'] = [42] * 32
    bad_cases.append(('unknown-anchor', sign(unknown_anchor, 'unknown-anchor')))
    wrong_chain = copy.deepcopy(body)
    wrong_chain['chain_id'][0] ^= 1
    bad_cases.append(('wrong-chain', sign(wrong_chain, 'wrong-chain')))
    vectors = json.loads((Path(__file__).resolve().parents[1] / 'tests/data/passphrase-v1.json').read_text(encoding='utf-8'))['vectors']
    new_recipient = next((v['public_key'] for v in vectors if v['public_key'] not in {n['public_key'] for n in nodes}))
    underpayment = copy.deepcopy(body)
    underpayment['operation']['TransferExact']['recipient'] = list(bytes.fromhex(new_recipient))
    new_account_terms = audit.payment_terms(underpayment['operation'], 0)
    underpayment['fee'] = str(new_account_terms['required'] - 1)
    bad_cases.append(('below-minimum-fee', sign(underpayment, 'underpayment')))
    malformed = copy.deepcopy(body)
    malformed['operation'] = {'Unexpected': {}}
    malformed['data'] = []
    bad_cases.append(('unknown-operation', {'body': malformed, 'signature': [0] * 64}))
    valid = sign(body, 'valid')
    invalid_signature = copy.deepcopy(valid)
    invalid_signature['signature'][0] ^= 1
    bad_cases.append(('invalid-signature', invalid_signature))
    for label, transaction in bad_cases:
        for node in nodes:
            rejected(node['rpc_port'], transaction)
        assert all_snapshots() == before, label + ' changed committed state or the pending pool'
        check(label + ' is rejected by all peers without charging a fee, consuming a nonce or changing state')
    accepted = rpc(nodes[0]['rpc_port'], 'submittransaction', valid)
    pools = wait_pending(1)
    assert all((pool == [valid] for pool in pools))
    with ThreadPoolExecutor(max_workers=6) as executor:
        repeats = [executor.submit(rpc, nodes[index % 3]['rpc_port'], 'submittransaction', valid) for index in range(48)]
        assert all((future.result() == accepted for future in repeats))
    assert all((len(pool) == 1 and pool[0] == valid for pool in wait_pending(1)))
    pending = all_snapshots()
    for index in range(3):
        assert pending[index]['account'] == before[index]['account']
        assert pending[index]['governance'] == before[index]['governance']
    check('Forty-eight duplicate signed submissions across three peers remain one pending payment with no early debit')
    audit.mine()
    audit.agree()
    wait_pending(0)
    block = rpc(nodes[0]['rpc_port'], 'getblock')
    assert block['transactions'] == [valid]
    after = all_snapshots()
    subsidy = int(after[0]['status']['issued']) - int(status['issued'])
    charged = int(body['fee'])
    miner_cut = charged * status['settings']['miner_fee_percent'] // 100
    actual_sender = after[0]['account']['account']
    assert int(actual_sender['ordinary']) == int(account['ordinary']) - 7 - charged + subsidy + miner_cut
    assert actual_sender['nonce'] == account['nonce'] + 1
    before_recipient = before[0]['balances'][recipient]['account']
    after_recipient = after[0]['balances'][recipient]['account']
    assert int(after_recipient['ordinary']) == int(before_recipient['ordinary']) + 7
    for node in nodes:
        rejected(node['rpc_port'], valid)
    assert all_snapshots() == after
    audit.assert_supply()
    check('The payment is included once, credits the exact amount, allocates its fee once and cannot be replayed after mining')
    current = after[0]['status']
    orphan_body = copy.deepcopy(body)
    orphan_body.update(nonce=actual_sender['nonce'], anchor=list(bytes.fromhex(current['tip'])),
                       expiry_blocks=10)  # Keep time open while isolating the wrong-branch failure.
    orphaned = sign(orphan_body, 'orphan-anchor')
    rpc(nodes[0]['rpc_port'], 'submittransaction', orphaned)
    wait_pending(1)
    with Fork(audit, current['height'] - 1, 'transaction-anchor') as fork:
        fork.overtake(current['height'])
        audit.agree()
        wait_pending(0)
        reorganized = all_snapshots()
        assert reorganized[0]['status']['height'] <= current['height'] + orphan_body['expiry_blocks']
        for node in nodes:
            rejected(node['rpc_port'], orphaned)
        assert all_snapshots() == reorganized
        audit.assert_supply()
        after = reorganized
    check('A reorganization removes a pending transaction whose signed anchor is orphaned; rebroadcast cannot revive it before its lifetime ends')
    args.report.write_text(json.dumps({**audit.fixture_mode, 'passed': True, 'checks': checks, 'checks_passed': len(checks), 'duplicate_submissions': 48, 'invalid_peer_submissions': len(bad_cases) * 3, 'height': after[0]['status']['height'], 'state_root': after[0]['status']['state_root'], 'tip': after[0]['status']['tip'], 'node_sha256': hashlib.sha256(Path(manifest['executable']).read_bytes()).hexdigest(), 'elapsed_seconds': round(time.monotonic() - started, 3)}, indent=2) + '\n', encoding='utf-8')
    print('Saved ' + str(args.report), flush=True)
if __name__ == '__main__':
    main()
