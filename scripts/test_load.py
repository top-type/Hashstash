"""Bounded transaction-load and full-pool relay checks on an isolated local testnet."""
import argparse
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
# http() waits out and resends a request the node refused with 429 or 503
# (Retry-After); the report counts them, and the documented load needs none.
from test_network import admission_refusals, http, rpc, quoted_miner_fee
TRANSACTIONS_PER_WAVE = 64
PAID_FEE = 3
FEE_INTERVAL = 16

def prepare_load(port, key, rounds, block_limit, transactions=TRANSACTIONS_PER_WAVE):
    """Fund all fees plus one wave of inputs from block-opening balances."""
    initial = rpc(port, 'status')
    mined = 0

    def mine_batch():
        nonlocal mined
        assert mined < block_limit, 'Load setup exhausted --setup-block-limit before funding completed.'
        count = min(32, block_limit - mined)
        rpc(port, 'mine', {'count': count, 'attempts': 1000000})
        mined += count
    # A newly created wallet is not an on-chain account until its first reward.
    if initial['height'] == 0:
        mine_batch()
    status = initial
    priorities = len(range(0, transactions, FEE_INTERVAL)) * PAID_FEE
    minimum_rate = int(status['settings']['minimum_fee_rate'])
    operation = {'TransferExact': {'recipient': list(bytes.fromhex(key)), 'amount': '1'}}
    quote = rpc(port, 'fee_quote', {'sender': key, 'operation': operation, 'extra_fee': str(PAID_FEE)})
    # Round per-transaction charges, matching consensus; the mandatory price is
    # per 1024 weight units rather than per transaction.
    transaction_fee = (int(quote['weight']) * minimum_rate + 1023) // 1024
    # Self-payment credits arrive too late to finance another input in the block.
    required = rounds * (transactions * transaction_fee + priorities) + transactions
    while True:
        account = rpc(port, 'account', {'key': key})['account']
        ordinary = int(account['ordinary']) if account else 0
        if ordinary >= required:
            break
        mine_batch()
    status = rpc(port, 'status')
    return {'initial_height': initial['height'], 'initial_phase': initial['phase'], 'mined_blocks': mined, 'height': status['height'], 'phase': status['phase'], 'required_ordinary': str(required), 'funded_ordinary': str(ordinary)}

from fixture_support import require_test_work


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--rounds', type=int, default=12)
    parser.add_argument('--setup-block-limit', type=int, default=10000, help='Maximum blocks mined while acquiring the full fee budget.')
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--transactions-per-wave', type=int, default=TRANSACTIONS_PER_WAVE, help='Transactions queued per block, bounded by the current mempool limit.')
    parser.add_argument('--assert-high-occupancy', action='store_true', help='Require every wave above half capacity and verify that block usage cannot change the governed fee rate.')
    args = parser.parse_args()
    if args.rounds < 1 or args.setup_block_limit < 1 or (not 1 <= args.transactions_per_wave <= 4096):
        parser.error('--rounds and --setup-block-limit must be positive')
    manifest = json.loads(args.manifest.read_text(encoding='utf-8-sig'))
    nodes = manifest['nodes']
    port = nodes[0]['rpc_port']
    fixture_mode = require_test_work(rpc(port, 'config'))
    key = nodes[0]['public_key']
    session = http(port, '/api/session')
    # The wallet token is only in the node's owner-only file, never served.
    session['token'] = Path(nodes[0]['data_file']).with_suffix('.session-token').read_text()
    assert session['wallet_enabled'] and session['public_key'] == key, 'Start the audit network with -SeedWallets.'
    started = time.monotonic()
    transactions = args.transactions_per_wave
    assert rpc(port, 'status')['chain_id'] == manifest['chain_id'], 'Network differs from selected manifest'
    setup = prepare_load(port, key, args.rounds, args.setup_block_limit, transactions)
    transfer = {'TransferExact': {'recipient': list(bytes.fromhex(key)), 'amount': '1'}}
    print(f"PASS load setup: {setup['funded_ordinary']} ordinary HASH covers the fee budget", flush=True)
    batches = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        for wave in range(args.rounds):
            before = rpc(port, 'status')
            world_before = rpc(port, 'governance')['world']
            account_before = rpc(port, 'account', {'key': key})['account']
            priorities = len(range(0, transactions, FEE_INTERVAL)) * PAID_FEE
            quotes = {tip: rpc(port, 'fee_quote', {'sender': key, 'operation': transfer, 'extra_fee': str(tip)}) for tip in (0, PAID_FEE)}
            fees_paid = sum((int(quotes[PAID_FEE if index % FEE_INTERVAL == 0 else 0]['fee']) for index in range(transactions)))
            miner_fees = sum((quoted_miner_fee(quotes[PAID_FEE if index % FEE_INTERVAL == 0 else 0]) for index in range(transactions)))
            wave_weight = sum((int(quotes[PAID_FEE if index % FEE_INTERVAL == 0 else 0]['weight']) for index in range(transactions)))
            # Self-payments create no accounts, so their weight is their encoded
            # size. Reserve conservative headroom for record prefixes/coinbase.
            required_capacity = wave_weight + 9 * transactions + 256
            assert required_capacity <= before['settings']['block_bytes'], (
                'This complete-wave fixture needs a larger configured block capacity or fewer transactions per wave',
                required_capacity, before['settings']['block_bytes'],
            )
            if args.assert_high_occupancy:
                assert wave_weight > before['settings']['block_bytes'] // 2, (
                    'Increase transactions per wave to exercise high occupancy',
                    wave_weight, before['settings']['block_bytes'] // 2,
                )
            assert int(account_before['ordinary']) >= fees_paid + transactions, 'Insufficient opening HASH for this wave inputs and fees.'
            ids = set()
            for index in range(transactions):
                tip = str(PAID_FEE) if index % FEE_INTERVAL == 0 else '0'
                fees = {'extra_fee': tip}
                result = http(port, '/api/wallet', {'operation': transfer, **fees, 'expiry_blocks': 2, 'expected_sender': session['public_key'], 'wallet_revision': session['wallet_revision']}, {'X-Hashstash-Token': session['token']})
                assert 'transaction_id' in result, result
                ids.add(result['transaction_id'])
            assert len(ids) == transactions
            deadline = time.monotonic() + 30
            while True:
                counts = [rpc(n['rpc_port'], 'status')['mempool'] for n in nodes]
                if counts == [transactions] * len(nodes):
                    break
                assert time.monotonic() < deadline, counts
                time.sleep(0.1)
            mining = executor.submit(rpc, port, 'mine', {'count': 1, 'attempts': 1000000})
            snapshots = [executor.submit(rpc, n['rpc_port'], 'snapshot', {'key': key}) for n in nodes]
            mining.result()
            for future in snapshots:
                snapshot = future.result()
                assert snapshot['status']['state_root'] == snapshot['governance']['state_root']
                assert snapshot['status']['height'] == snapshot['governance']['height']
            block = rpc(port, 'getblock')
            assert len(block['transactions']) == transactions
            nonces = [tx['body']['nonce'] for tx in block['transactions']]
            assert nonces == list(range(account_before['nonce'], account_before['nonce'] + transactions))
            after = rpc(port, 'status')
            world_after = rpc(port, 'governance')['world']
            account_after = rpc(port, 'account', {'key': key})['account']
            expected = int(account_before['ordinary']) + int(after['issued']) - int(before['issued']) - fees_paid + miner_fees
            assert int(account_after['ordinary']) == expected
            if before['phase'] != 'governance' and after['phase'] != 'governance':
                public_funds_before = int(world_before['revenue']) + int(world_before['reserve'])
                public_funds_after = int(world_after['revenue']) + int(world_after['reserve'])
                assert public_funds_after - public_funds_before == fees_paid - miner_fees
            assert after['settings']['minimum_fee_rate'] == before['settings']['minimum_fee_rate']
            assert 'fee_market' not in after
            deadline = time.monotonic() + 30
            while True:
                peers = [rpc(n['rpc_port'], 'status') for n in nodes]
                if all((s['tip'] == after['tip'] and s['state_root'] == after['state_root'] and (s['mempool'] == 0) for s in peers)):
                    break
                assert time.monotonic() < deadline, peers
                time.sleep(0.1)
            batches.append({'batch': wave + 1, 'height': after['height'], 'transactions': transactions, 'transaction_weight': wave_weight, 'block_capacity': before['settings']['block_bytes'], 'occupancy_ratio': wave_weight / before['settings']['block_bytes'], 'wire_json_bytes': len(json.dumps(block)), 'fees_paid': str(fees_paid), 'miner_fees': str(miner_fees), 'before_fee_policy': before['fee_policy'], 'after_fee_policy': after['fee_policy']})
            print(f'PASS full-pool wave {wave + 1}/{args.rounds}: all {transactions} relayed, mined, and reconciled', flush=True)
    empty_rates = []
    rate = rpc(port, 'status')['settings']['minimum_fee_rate']
    for _ in range(3):
        rpc(port, 'mine', {'count': 1, 'attempts': 1000000})
        status = rpc(port, 'status')
        assert status['settings']['minimum_fee_rate'] == rate
        assert 'fee_market' not in status
        empty_rates.append(rate)
    print('PASS loaded and empty blocks preserve the governed fee rate', flush=True)
    print(f'PASS admission: {admission_refusals()} refused requests waited out and resent', flush=True)
    report = {**fixture_mode, 'passed': True, 'node_sha256': hashlib.sha256(Path(manifest['executable']).read_bytes()).hexdigest(), 'transactions': transactions * args.rounds, 'setup': setup, 'empty_block_minimum_rates': empty_rates, 'admission_refusals': admission_refusals(), 'rounds': batches, 'elapsed_seconds': round(time.monotonic() - started, 2), 'final_status': rpc(port, 'status')}
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
