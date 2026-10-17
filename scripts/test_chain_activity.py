"""Offline tests only: fake RPC, fake signer, and isolated real-CLI wire checks."""
import copy
import contextlib
import io
import http.server
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

import chain_activity as ca

CHAIN = '11' * 32
KEYS = ['22' * 32, '33' * 32, '44' * 32]


def config(root):
    return dict(binary=str(root / 'hashstash'), rpc_url='http://127.0.0.1:12345/rpc',
        faucet_url='https://192.0.2.1', chain_id=CHAIN, region='fra',
        database=str(root / 'activity.sqlite'), work_dir=str(root / 'public'),
        accounts=[dict(public_key=k, address='hsh-test-' + str(i), key_file=str(root / f'key-{i}')) for i, k in enumerate(KEYS)],
        registry={'fra': KEYS, 'sgp': ['55' * 32, '66' * 32, '77' * 32], 'ewr': ['88' * 32, '99' * 32, 'aa' * 32]})


def operation():
    return {'TransferExact': {'recipient': list(bytes.fromhex(KEYS[1])), 'amount': '1000'}}


class Planner:
    @staticmethod
    def still_valid(action, snapshot, account):
        return account['account'] is not None and account['account']['nonce'] == action['guard']['nonce'] and snapshot['status']['phase'] == action['guard']['phase']

    @staticmethod
    def plan(*_args):
        return None


class FakeNode:
    def __init__(self):
        self.height = 10
        self.chain = CHAIN
        self.phase = 'rest'
        self.receipt = None
        self.account_values = {k: dict(nonce=0, ordinary=str(10**15), shares='0') for k in KEYS}
        self.pass_account_values = {}
        self.calls = []
        self.anchor = 'cc' * 32
        self.world = {'reserve': str(10**18), 'grant_capacity': str(10**18)}
        self.proposals = []
        self.grant_feasible = True

    def snapshot(self):
        return {'status': {'chain_id': self.chain, 'height': self.height,
                          'clock': self.height * 15, 'settings': {'interval': 15, 'block_bytes': 16384},
                          'tip': f'{self.height:064x}', 'phase': self.phase, 'decision': None, 'auction_round': None},
                'balances': {k: {'account': a, 'pass': self.pass_account_values.get(k)} for k, a in self.account_values.items()}}

    def __call__(self, method, params):
        self.calls.append((method, params))
        if method == 'snapshot':
            value = self.snapshot()
            value['governance'] = {'world': self.world, 'phase': {}}
            return copy.deepcopy(value)
        if method == 'account':
            values = self.pass_account_values if params.get('outcome') == 'pass' else self.account_values
            return {'account': copy.deepcopy(values[params['key']])}
        if method == 'explorer_transaction':
            if self.receipt is None:
                raise ca.RpcError('unknown transaction')
            return {'chain_id': self.chain, 'transaction': self.receipt}
        if method == 'explorer_block':
            return {'chain_id': self.chain, 'block': {'hash': self.anchor}}
        if method == 'proposals':
            return copy.deepcopy(self.proposals)
        if method == 'grant_quote':
            return {'feasible': self.grant_feasible}
        raise AssertionError(method)


class FakeCli:
    def __init__(self, node):
        self.node = node
        self.broadcasts = []
        self.fail_broadcast = False
        self.change_after_prepare = False

    def run(self, args):
        args = list(map(str, args))
        def flag(name): return args[args.index(name) + 1]
        if args[0] == 'prepare':
            op = json.loads(Path(flag('--operation-file')).read_text())
            sender = flag('--sender')
            body, raw = ca.make_body(sender, self.node.account_values[sender]['nonce'],
                flag('--fee'), self.node.snapshot()['status']['tip'], int(flag('--expiry-blocks')), op,
                flag('--data-hex') if '--data-hex' in args else '')
            ca.save_new(flag('--out'), {'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN, 'body': raw.hex()})
            if self.change_after_prepare:
                self.node.phase = 'governance'
        elif args[0] == 'sign':
            body = json.loads(Path(flag('--body')).read_text())
            ca.save_new(flag('--out'), {'body': body, 'signature': [7] * 64})
        elif args[0] == 'broadcast':
            self.broadcasts.append(Path(flag('--raw-file')).read_text().strip())
            if self.fail_broadcast:
                raise ca.Pause('test timeout')
        else:
            raise AssertionError(args)
        return ''


class ActivityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = config(self.root)
        self.node = FakeNode()
        self.now = 100000.0
        self.cli = FakeCli(self.node)
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.snapshot, self.accounts = self.activity.observe()

    def tearDown(self):
        self.activity.ledger.db.close()
        self.tmp.cleanup()

    def action(self):
        return {'kind': 'transfer', 'sender_index': 0, 'operation': operation(),
                'guard': {'nonce': 0, 'phase': 'rest'}, 'amount_raw': '1000', 'quoted_fee_raw': '1', 'expiry_blocks': 2}

    def test_chat_rotation_uses_full_confirmed_ledger_after_512_actions_and_restart(self):
        import activity_personas as personas
        with self.activity.ledger.db:
            for index in range(1100):
                action = dict(kind='chat' if index in (0, 500, 1099) else 'transfer', sender_index=(0 if index != 1099 else 1), region='fra')
                self.activity.ledger.db.execute(
                    'INSERT INTO intents(id,sender,created,prepared_height,action,state,confirmed,txid,receipt_height) VALUES(?,?,?,?,?,?,?,?,?)',
                    (str(index), KEYS[0], index, index, json.dumps(action), 'confirmed', index + 1, f'{index:064x}', index))
        for restart in (False, True):
            if restart:
                self.activity.ledger.db.close()
                self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
            policy = self.activity.policy(self.snapshot)
            self.assertEqual(len(policy['history']), 512)
            self.assertEqual(policy['confirmed_chat_count'], 3)
            self.assertEqual(policy['confirmed_chat_counts'], [2, 1, 0])
            self.assertEqual(personas.next_speaker('fra', policy['history'], policy['confirmed_chat_count']), 0)
            self.assertEqual(personas.speaker_sequence('fra', 0, policy['history'], policy['confirmed_chat_counts']), 2)
        # A receipt removed from the canonical confirmed set cannot remain in
        # a separate counter. Existing anchor faults still prevent trading.
        self.activity.ledger.update('0', state='expired')
        policy = self.activity.policy(self.snapshot)
        self.assertEqual(policy['confirmed_chat_counts'], [1, 1, 0])

    def test_runtime_error_diagnostics_are_sanitized_bounded_and_reset_on_recovery(self):
        original = self.activity.observe
        secret = 'secret=https://user:password@host/private/signed.json'
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            for index, error in enumerate([ca.RpcError(secret), PermissionError(secret), KeyError(secret), TypeError(secret), ValueError(secret)]):
                def fail(error=error): raise error
                self.activity.observe = fail
                self.activity.tick()
                status = json.loads((self.activity.work / 'status.json').read_text())
                self.assertEqual(status['diagnostic']['consecutive_errors'], index + 1)
                self.assertNotIn(secret, json.dumps(status))
            self.assertEqual(len(output.getvalue().splitlines()), 1)
            self.now += 60
            self.activity.tick()
            self.assertEqual(len(output.getvalue().splitlines()), 2)
        self.assertNotIn(secret, output.getvalue())
        self.assertEqual(self.activity.diagnostic['category'], 'invalid_value')
        self.activity.observe = original
        self.activity.tick()
        self.assertIsNone(self.activity.diagnostic)
        self.activity.diagnostic = {'consecutive_errors': 2_147_483_647, 'first_at': self.now}
        with contextlib.redirect_stderr(io.StringIO()):
            self.activity.record_error(ca.RpcError(secret))
        self.assertEqual(self.activity.diagnostic['consecutive_errors'], 2_147_483_647)

    def test_observation_rejects_wrong_or_malformed_chain(self):
        original = self.node.snapshot
        self.activity.observe()
        for chain in ('bb' * 32, None, 'not-a-chain'):
            with self.subTest(chain=chain):
                def mismatched(chain=chain):
                    value = original()
                    value['status']['chain_id'] = chain
                    return value
                self.node.snapshot = mismatched
                with self.assertRaises(ca.Fault): self.activity.observe()

    def full_cash_governance(self):
        self.node.phase = 'governance'
        self.node.pass_account_values = copy.deepcopy(self.node.account_values)
        self.snapshot, self.accounts = self.activity.observe()

    def test_current_rejects_unaffordable_other_world_before_signing(self):
        self.full_cash_governance()
        self.snapshot, self.accounts = self.activity.observe()
        action = self.action()
        action['guard']['phase'] = 'governance'
        self.accounts[0]['pass_account']['ordinary'] = '0'
        with self.assertRaisesRegex(ca.Pause, 'cash_in_both_outcomes'):
            self.activity.submit(action, self.snapshot, self.accounts)
        self.assertFalse(self.activity.ledger.rows(('preparing', 'pending', 'abandoned')))
        self.assertFalse(self.cli.broadcasts)

    def test_current_checks_both_worlds_before_signing_without_reserving_an_intent(self):
        self.full_cash_governance()
        action = self.action()
        action['guard']['phase'] = 'governance'
        self.accounts[0]['pass_account']['ordinary'] = '1'
        with self.assertRaisesRegex(ca.Pause, 'cash_in_both_outcomes'):
            self.activity.submit(action, self.snapshot, self.accounts)
        self.assertFalse(self.activity.ledger.rows(('preparing', 'pending', 'abandoned')))
        self.assertFalse(self.cli.broadcasts)

    def test_current_rechecks_cash_after_prepare_even_with_identical_shared_nonce(self):
        self.full_cash_governance()
        action = self.action()
        action['guard']['phase'] = 'governance'
        run = self.cli.run
        def reduce_pass_cash(args):
            result = run(args)
            if args[0] == 'prepare':
                self.node.pass_account_values[KEYS[0]]['ordinary'] = '0'
            return result
        self.cli.run = reduce_pass_cash
        with self.assertRaisesRegex(ca.Pause, 'cash_in_both_outcomes'):
            self.activity.submit(action, self.snapshot, self.accounts)
        rows = self.activity.ledger.rows(('abandoned',))
        self.assertEqual(len(rows), 1)
        self.assertFalse((self.activity.work / rows[0]['id'] / 'signed.json').exists())
        self.assertFalse(self.cli.broadcasts)

    def test_current_mixed_nonce_or_missing_outcome_waits_without_latching_fault(self):
        self.full_cash_governance()
        self.node.pass_account_values[KEYS[0]]['nonce'] = 1
        self.activity.tick()
        self.assertEqual(self.activity.state, 'waiting_for_consistent_outcome_accounts')
        self.assertIsNone(self.activity.ledger.get('fault'))
        self.node.pass_account_values.clear()
        self.activity.tick()
        self.assertEqual(self.activity.state, 'waiting_for_consistent_outcome_accounts')
        self.assertFalse(self.cli.broadcasts)

    def test_current_empty_cash_and_owned_stash_idles_with_clear_fee_reason(self):
        self.full_cash_governance()
        for world in (self.node.account_values, self.node.pass_account_values):
            for account in world.values():
                account.update(ordinary='0', shares=str(10**18))
        self.activity.funding = lambda: None  # No claim or invented receipt.
        self.activity.tick()
        self.assertEqual(self.activity.state, 'waiting_for_cash_in_both_outcomes')
        self.assertFalse(self.cli.broadcasts)

    def test_removed_operations_rejected_before_signing(self):
        self.full_cash_governance()
        for kind in ('Commit', 'Merge'):
            action = self.action()
            action['operation'] = {kind: {'amount': '1', 'decision': [1] * 32}}
            with self.assertRaises(ValueError): ca.encode_operation(action['operation'])
            with self.assertRaisesRegex(ValueError, 'unsupported activity operation'):
                self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def send(self):
        self.activity.submit(self.action(), self.snapshot, self.accounts)
        return self.activity.ledger.rows(('pending',))[0]

    def test_admission_stays_pending_and_persisted_before_broadcast(self):
        self.cli.fail_broadcast = True
        with self.assertRaises(ca.Pause):
            self.send()
        row = self.activity.ledger.rows(('pending',))[0]
        self.assertEqual(row['txid'], ca.sha256d(bytes.fromhex(self.cli.broadcasts[0])))
        self.assertEqual(row['raw'], self.cli.broadcasts[0])
        self.assertEqual(row['nonce'], 0)
        self.assertEqual(len(self.activity.ledger.rows(('confirmed',))), 0)

    def test_restart_retry_identical_no_new_signature_or_nonce(self):
        row = self.send()
        original_body = json.loads(row['body'])
        self.assertEqual(original_body['anchor'], list(bytes.fromhex(self.snapshot['status']['tip'])))
        self.assertEqual(original_body['expiry_blocks'], 2)
        self.activity.ledger.db.close()
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.now += 21
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(self.cli.broadcasts, [row['raw'], row['raw']])
        self.assertEqual(len(self.activity.ledger.rows(('pending',))), 1)
        retried = self.activity.ledger.rows(('pending',))[0]
        self.assertEqual(json.loads(retried['body']), original_body)
        self.assertEqual(retried['expiry'], row['prepared_height'] + 2)

    def test_same_height_reorg_after_preparation_is_not_signed(self):
        original = self.cli.run
        snapshot = self.node.snapshot
        def run(args):
            result = original(args)
            if args[0] == 'prepare':
                def reorganized():
                    value = snapshot()
                    value['status']['tip'] = 'ef' * 32
                    return value
                self.node.snapshot = reorganized
            return result
        self.cli.run = run
        with self.assertRaisesRegex(ca.Pause, 'anchor moved before signing'):
            self.send()
        rows = self.activity.ledger.rows(('abandoned',))
        self.assertEqual(len(rows), 1)
        self.assertFalse((self.activity.work / rows[0]['id'] / 'signed.json').exists())
        self.assertFalse(self.cli.broadcasts)

    def test_receipt_depth_required_and_anchor_reorg_fault(self):
        row = self.send()
        self.node.account_values[KEYS[0]]['nonce'] = 1
        self.node.receipt = dict(txid=row['txid'], sender_public_key=KEYS[0], nonce=0,
            status='confirmed', confirmations=1, height=row['prepared_height'] + 1, block_hash=self.node.anchor)
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(len(self.activity.ledger.rows(('pending',))), 1)
        self.node.receipt['confirmations'] = 2
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(len(self.activity.ledger.rows(('confirmed',))), 1)
        self.activity.check_anchors()
        self.node.anchor = 'dd' * 32
        with self.assertRaises(ca.Fault):
            self.activity.check_anchors()

    def test_receipt_before_signed_anchor_cannot_be_accepted(self):
        row = self.send()
        self.node.receipt = dict(txid=row['txid'], sender_public_key=KEYS[0], nonce=0,
            status='confirmed', confirmations=3, height=9, block_hash=self.node.anchor)
        with self.assertRaisesRegex(ca.Fault, 'outside the signed anchor lifetime'):
            self.activity.reconcile(self.snapshot, self.accounts)
        self.assertFalse(self.activity.ledger.rows(('confirmed',)))

    def test_unknown_nonce_consumption_does_not_pay_again(self):
        self.send()
        self.node.account_values[KEYS[0]]['nonce'] = 1
        snapshot, accounts = self.activity.observe()
        with self.assertRaises(ca.Fault):
            self.activity.reconcile(snapshot, accounts)
        self.assertEqual(len(self.cli.broadcasts), 1)

    def test_expiration_does_not_reuse_original_transaction(self):
        row = self.send()
        # At the last eligible height, an absent transaction cannot enter any
        # future block. Check its canonical receipt before declaring expiry.
        self.node.height = row['expiry']
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(len(self.activity.ledger.rows(('expired',))), 1)
        self.assertEqual(len(self.cli.broadcasts), 1)

    def test_no_mining_no_rebroadcast_and_restart_requires_advance(self):
        self.send()
        self.now += 181
        self.activity.reconcile(self.snapshot, self.accounts)
        self.assertEqual(len(self.cli.broadcasts), 1)
        self.activity.tick()
        self.assertEqual(self.activity.state, 'waiting_for_mining')

    def test_wrong_chain_latches_fault_without_signing(self):
        self.node.chain = 'bb' * 32
        self.activity.tick()
        self.assertEqual(self.activity.state, 'operator_review')
        self.assertIn('another chain', self.activity.ledger.get('fault'))
        self.assertFalse(self.cli.broadcasts)

    def test_phase_change_before_signing_abandons_unsigned_only(self):
        self.cli.change_after_prepare = True
        with self.assertRaises(ca.Pause):
            self.send()
        row = self.activity.ledger.rows(('abandoned',))[0]
        self.assertFalse((self.activity.work / row['id'] / 'signed.json').exists())
        self.assertFalse(self.cli.broadcasts)

    def test_one_outstanding_per_account(self):
        self.send()
        with self.assertRaises(sqlite3.IntegrityError):
            self.activity.submit(self.action(), self.snapshot, self.accounts)
        self.assertEqual(len(self.cli.broadcasts), 1)

    def test_fixed_daily_faucet_address_and_real_proxy_headers(self):
        calls = []
        def http(url, body=None, headers=None):
            calls.append((url, body, headers))
            if body is None:
                return dict(chain_id=CHAIN, available=True, state='ready', retry_after_seconds=0)
            raise OSError('ambiguous network timeout')
        self.activity.http = http
        with self.assertRaises(OSError):
            self.activity.funding()
        self.activity.funding()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][1], {'address': self.cfg['accounts'][0]['address']})
        self.assertEqual(calls[1][2], {'Origin': self.cfg['faucet_url']})
        self.assertEqual(self.activity.ledger.db.execute('SELECT COUNT(*) FROM funding').fetchone()[0], 1)

    def test_daily_budget_includes_pending_and_survives_restart(self):
        action = self.action()
        action.update(kind='chat', data_hex=b'Automated demo'.hex())
        self.activity.c['max_consumptive_daily_raw'] = str(int(self.activity.c['max_fee_raw']) - 1)
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(action, self.accounts, self.activity.policy())
        self.assertFalse(self.cli.broadcasts)

    def test_no_arbitrary_recipient_or_parameter_proposal(self):
        action = self.action()
        action['operation']['TransferExact']['recipient'] = [9] * 32
        with self.assertRaises(ca.Fault):
            self.activity.allowed_action(action, self.accounts, self.activity.policy())
        with self.assertRaises(ValueError):
            ca.encode_operation({'Propose': {'proposal': {'Parameter': {}}}})

    def test_plaintext_messages_keep_peer_label_size_and_cadence_guards(self):
        action = self.action()
        action.update(kind='chat', data_hex='Automated Demo · observed block 10.'.encode().hex())
        action['operation']['TransferExact']['recipient'] = list(bytes.fromhex(KEYS[1]))
        policy = self.activity.policy(self.snapshot)
        self.activity.allowed_action(action, self.accounts, policy, self.snapshot)
        self.assertEqual(int(action['reserved_cost_raw']), int(self.activity.c['max_fee_raw']))
        policy['last_chat_at'] = self.now - self.activity.c['chat_seconds'] + 1
        with self.assertRaisesRegex(ca.Pause, 'chat cadence'):
            self.activity.allowed_action(action, self.accounts, policy, self.snapshot)
        policy['last_chat_at'] = 0
        action['kind'] = 'transfer'
        with self.assertRaisesRegex(ca.Fault, 'restricted to labelled transfer chat'):
            self.activity.allowed_action(action, self.accounts, policy, self.snapshot)

    def test_message_guard_excludes_encrypted_tagged_unlabelled_and_invalid_data(self):
        action = self.action()
        action.update(kind='chat')
        action['operation']['TransferExact']['recipient'] = list(bytes.fromhex(KEYS[1]))
        for data in (
            b'hashstash.mail/2\n{"body":"Automated demo"}',
            b'hashstash.mail/99\nAutomated demo',
            b'hashstash.chat/1\n{"text":"Automated demo"}',
            b'hashstash.proposal/1\n{"text":"Automated demo"}',
            b'A human wrote this', b'\xffAutomated demo',
            b'Automated demo\x00', 'Automated demo\u0085'.encode(),
            b'Automated demo ' + b'x' * 500,
        ):
            action['data_hex'] = data.hex()
            with self.subTest(data=data), self.assertRaises(ca.Fault):
                self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.assertFalse(self.cli.broadcasts)

    def test_crash_after_signing_recovers_exact_signature(self):
        row = self.send()
        self.activity.ledger.update(row['id'], state='preparing', raw=None, txid=None)
        self.activity.recover_preparing()
        restored = self.activity.ledger.rows(('pending',))[0]
        self.assertEqual(restored['raw'], row['raw'])
        self.assertEqual(restored['txid'], row['txid'])
        self.assertEqual(len(self.cli.broadcasts), 1)

    def test_unsigned_precrash_intent_never_signed_later(self):
        self.cli.change_after_prepare = True
        with self.assertRaises(ca.Pause):
            self.send()
        row = self.activity.ledger.rows(('abandoned',))[0]
        self.activity.ledger.update(row['id'], state='preparing')
        self.activity.recover_preparing()
        self.assertEqual(len(self.activity.ledger.rows(('abandoned',))), 1)
        self.assertFalse(self.cli.broadcasts)

    def test_crash_raw_artifact_mismatch_cannot_be_replaced(self):
        row = self.send()
        self.activity.ledger.update(row['id'], state='preparing', raw=None, txid=None)
        path = self.activity.work / row['id'] / 'raw.hex'
        path.write_text('00\n', encoding='utf-8')
        with self.assertRaises(ca.Fault):
            self.activity.recover_preparing()
        self.assertEqual(path.read_text(), '00\n')
        self.assertEqual(len(self.cli.broadcasts), 1)

    def test_latched_fault_keeps_status_fresh(self):
        self.activity.ledger.set('fault', 'test fault')
        self.now += 20
        self.activity.tick()
        state = json.loads((self.activity.work / 'status.json').read_text())
        self.assertEqual(state['observed_at'], self.now)
        self.assertEqual(state['state'], 'operator_review')

    def test_pending_actions_reserve_round_work_without_becoming_history(self):
        action = self.action()
        action.update(kind='propose_grant', round=9)
        self.activity.submit(action, self.snapshot, self.accounts)
        policy = self.activity.policy()
        self.assertEqual(policy['history'], [])
        self.assertEqual(policy['cursor'], 0)
        self.assertEqual(policy['pending_actions'][0]['round'], 9)

    def test_failed_rebroadcast_isolated_and_rate_limited(self):
        row = self.send()
        self.now += 21
        self.cli.fail_broadcast = True
        self.activity.reconcile(self.snapshot, self.accounts)
        self.assertEqual(len(self.cli.broadcasts), 2)
        self.activity.reconcile(self.snapshot, self.accounts)
        self.assertEqual(len(self.cli.broadcasts), 2)
        self.assertEqual(self.activity.ledger.rows(('pending',))[0]['raw'], row['raw'])
        self.assertEqual(self.activity.ledger.get('broadcast:' + row['txid'])['result'], 'uncertain')
        snapshot, accounts = self.activity.observe()
        self.assertTrue(accounts[0]['pending'])
        self.assertFalse(accounts[1]['pending'])
        second = self.action()
        second['sender_index'] = 1
        self.cli.fail_broadcast = False
        self.activity.submit(second, snapshot, accounts)
        self.assertEqual(len(self.activity.ledger.rows(('pending',))), 2)
        self.assertEqual(len(self.cli.broadcasts), 3)

    def test_ledger_chain_and_account_identity_are_immutable(self):
        other = copy.deepcopy(self.cfg)
        other['chain_id'] = 'cc' * 32
        with self.assertRaises(ca.Fault):
            ca.Ledger(self.cfg['database'], other)

    def test_registry_identity_and_expiry_arithmetic_are_checked(self):
        other = copy.deepcopy(self.cfg)
        other['registry']['sgp'][0] = KEYS[0]
        with self.assertRaises(ValueError):
            ca.config_checked(other)
        for lifetime in (21, (1 << 64) - 1):
            self.assertEqual(ca.config_checked(dict(self.cfg, expiry_blocks=lifetime))['expiry_blocks'], lifetime)
        for invalid in (0, -1, 1 << 64, True, 2.5):
            with self.subTest(lifetime=invalid), self.assertRaises(ValueError):
                ca.config_checked(dict(self.cfg, expiry_blocks=invalid))

    def test_explicit_long_lifetime_is_signed_but_height_overflow_is_not(self):
        action = self.action()
        action['expiry_blocks'] = 21
        self.activity.submit(action, self.snapshot, self.accounts)
        row = self.activity.ledger.rows(('pending',))[0]
        self.assertEqual(json.loads(row['body'])['expiry_blocks'], 21)
        self.assertEqual(row['expiry'], row['prepared_height'] + 21)
        action = self.action()
        action['sender_index'] = 1
        action['expiry_blocks'] = (1 << 64) - 1
        with self.assertRaisesRegex(ca.Pause, 'valid height range'):
            self.activity.submit(action, self.snapshot, self.accounts)
        action['expiry_blocks'] = 1 << 63
        with self.assertRaisesRegex(ca.Pause, 'SQLite ledger'):
            self.activity.submit(action, self.snapshot, self.accounts)
        self.assertEqual(len(self.activity.ledger.rows(('pending',))), 1)

    def test_funding_address_is_verified_by_public_cli_only(self):
        class IdentityCli:
            def run(inner, args):
                if args[0] == 'public-key':
                    return KEYS[0]
                return 'hsh-wrong-address'
        self.activity.cli = IdentityCli()
        with self.assertRaises(ca.Fault):
            self.activity.verify_keys()


class WireTests(unittest.TestCase):
    def test_multi_grant_compact_vector_and_strict_amount_validation(self):
        payments = [dict(recipient=[1] * 32, amount='258'), dict(recipient=[2] * 32, amount='65537')]
        grant = {'payments': payments}
        op = {'Propose': dict(round=2, description=[3] * 32, proposal={'Grant': grant}, support='1')}
        expected = (b'\x03\x02' + b'\x03' * 32 + b'\x00\x02'
                    + b'\x01' * 32 + b'\x02\x02\x01'
                    + b'\x02' * 32 + b'\x03\x01\x00\x01' + b'\x01\x01')
        self.assertEqual(ca.encode_operation(op), expected)
        for bad in ([], [None], list(reversed(payments)), [payments[0]] * 2,
                    [dict(recipient=[0] * 32, amount='1')],
                    [dict(recipient=[1] * 32, amount='01')],
                    [dict(recipient=[1] * 32, amount='0')],
                    [dict(recipient=[True] * 32, amount='1')],
                    [dict(recipient=[1] * 32, amount=str(2**511)),
                     dict(recipient=[2] * 32, amount=str(2**511))]):
            with self.subTest(payments=bad), self.assertRaises(ValueError):
                ca.validated_grant({'payments': bad})
        with self.assertRaisesRegex(ValueError, 'only payments'):
            ca.validated_grant(dict(payments=payments, amount='1'))

    def test_grant_lists_above_sixteen_use_transaction_limits(self):
        for count in (17, 115, 129):
            payments = [dict(recipient=list(n.to_bytes(32, 'big')), amount='1')
                        for n in range(1, count + 1)]
            grant = {'payments': payments}
            pairs, total = ca.validated_grant(grant)
            self.assertEqual(len(pairs), count)
            self.assertEqual(total, count)
            op = {'Propose': dict(round=2, description=[3] * 32,
                                 proposal={'Grant': grant}, support='1')}
            body, wire = ca.make_body(KEYS[0], 0, 1, 'ab' * 32, 2, op)
            prepared = {'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN, 'body': wire.hex()}
            self.assertEqual(ca.verified_prepared(
                prepared, CHAIN, KEYS[0], 0, 1, op, '', 'ab' * 32, 2), (body, wire))
            self.assertLessEqual(len(wire) + 64, 16384)
        self.assertGreater(len(wire) + 64, 4096)
        with self.assertRaisesRegex(ca.Fault, 'unsigned length'):
            ca.verified_prepared({'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN, 'body': wire.hex()},
                                 CHAIN, KEYS[0], 0, 1, op, '', 'ab' * 32, 2, max_bytes=4096)

    def test_compact_integer_boundaries_and_noncanonical_encodings(self):
        fixtures = ((0, '00'), (250, 'fa'), (251, 'fbfb00'),
                    (65535, 'fbffff'), (65536, 'fc00000100'),
                    (2**32 - 1, 'fcffffffff'), (2**32, 'fd0000000001000000'),
                    (2**64 - 1, 'fdffffffffffffffff'))
        for value, encoded in fixtures:
            raw = bytes.fromhex(encoded)
            self.assertEqual(ca.u64(value), raw)
            self.assertEqual(ca.read_u64(b'\x55' + raw, 1), (value, len(raw) + 1))
            for length in range(len(raw)):
                with self.assertRaises(ca.Fault):
                    ca.read_u64(raw[:length], 0)
        for raw in (b'\xfb\x01\x00', b'\xfc\xfb\x00\x00\x00',
                    b'\xfd\x00\x00\x01\x00\x00\x00\x00\x00',
                    b'\xfe' + bytes(16), b'\xff'):
            with self.assertRaises(ca.Fault):
                ca.read_u64(raw, 0)
        for value in (-1, 2**64):
            with self.assertRaises(ValueError):
                ca.u64(value)

    def test_zero_amount_and_fixed_signature_have_no_redundant_payload(self):
        self.assertEqual(ca.amount(0), b'\x00')
        self.assertEqual(ca.amount(256), b'\x02\x00\x01')
        body, raw = ca.make_body(KEYS[0], 0, 0, 'ab' * 32, 2, operation())
        signed = ca.signed_wire({'body': body, 'signature': [7] * 64}, body, raw)
        self.assertEqual(signed, raw + b'\x07' * 64)
        self.assertEqual(len(signed) - len(raw), 64)

    def test_anchor_only_body_keeps_network_context_out_of_signed_bytes(self):
        body, raw = ca.make_body(KEYS[0], 0, 1, 'ab' * 32, 2, operation())
        self.assertNotIn('chain_id', body)
        self.assertEqual(raw[:32], bytes.fromhex(KEYS[0]))
        self.assertEqual(len(raw) + 64, 169)
        envelope = {'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN, 'body': raw.hex()}
        args = (CHAIN, KEYS[0], 0, 1, operation(), '', 'ab' * 32, 2)
        self.assertEqual(ca.verified_prepared(envelope, *args), (body, raw))
        for bad in (
            dict(envelope, chain_id='12' * 32),
            {key: value for key, value in envelope.items() if key != 'chain_id'},
            dict(envelope, format='hashstash-unsigned-v1'),
            dict(envelope, unreviewed='metadata'),
        ):
            with self.subTest(envelope=bad), self.assertRaises(ca.Fault):
                ca.verified_prepared(bad, *args)
        # Matching export metadata alone never replaces the signed anchor check.
        changed = dict(envelope, body=(raw[:35] + bytes.fromhex('ac' * 32) + raw[67:]).hex())
        with self.assertRaises(ca.Pause):
            ca.verified_prepared(changed, *args)

    def test_old_body_layout_is_rejected_even_with_current_export_metadata(self):
        _, raw = ca.make_body(KEYS[0], 0, 1, 'ab' * 32, 2, operation())
        old = {'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN,
               'body': (bytes.fromhex(CHAIN) + raw).hex()}
        with self.assertRaises((ca.Fault, ca.Pause)):
            ca.verified_prepared(old, CHAIN, KEYS[0], 0, 1, operation(), '', 'ab' * 32, 2)

    def test_amount_only_trade_encoding_rejects_removed_output_fields(self):
        for kind, field, removed, tag in [('Deposit','amount','min_shares',1), ('Redeem','shares','min_received',2)]:
            op = {kind: {field:'256', 'decision':None, 'outcome':None}}
            self.assertEqual(ca.encode_operation(op), ca.u64(tag) + ca.amount(256) + b'\x00\x00')
            op[kind][removed] = '0'
            with self.assertRaisesRegex(ValueError, 'unexpected trade fields'):
                ca.encode_operation(op)

    def test_every_intent_field_is_compared(self):
        body, raw = ca.make_body(KEYS[0], 9, 1000, 'ab' * 32, 2, operation())
        envelope = {'format': 'hashstash-unsigned-anchor', 'chain_id': CHAIN, 'body': raw.hex()}
        parsed, encoded = ca.verified_prepared(envelope, CHAIN, KEYS[0], 9, 1000, operation(), '', 'ab' * 32, 2)
        self.assertEqual(parsed, body)
        self.assertEqual(encoded, raw)
        for offset in (0, 32, 33, 36, 37, 68, 69, len(raw) - 1):
            bad = bytearray(raw)
            bad[offset] ^= 1
            with self.assertRaises((ca.Fault, ca.Pause, ValueError)):
                ca.verified_prepared(dict(envelope, body=bad.hex()), CHAIN, KEYS[0], 9, 1000, operation(), '', 'ab' * 32, 2)

    def test_changed_signed_body_or_signature_length_rejected(self):
        body, raw = ca.make_body(KEYS[0], 0, 1, 'ab' * 32, 2, operation())
        with self.assertRaises(ca.Fault):
            ca.signed_wire({'body': dict(body, nonce=1), 'signature': [0] * 64}, body, raw)
        with self.assertRaises(ca.Fault):
            ca.signed_wire({'body': body, 'signature': [0] * 63}, body, raw)

    def test_real_cli_current_encoding_and_signature_bridge(self):
        binary = os.environ.get('HASHSTASH_TEST_BINARY')
        if not binary:
            self.skipTest('set HASHSTASH_TEST_BINARY for isolated installed-CLI compatibility')
        captured = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args): pass
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                captured.append(request)
                raw = request['params']['raw']
                result = {'jsonrpc': '2.0', 'id': 1, 'result': {'transaction_id': ca.sha256d(bytes.fromhex(raw))}}
                data = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                cli = ca.Cli(binary)
                # Generated test key stays unread; only CLI derives its public key.
                cli.run(['keygen', '--out', root / 'test.key'])
                public = cli.run(['public-key', '--key', root / 'test.key'])
                cli.run(['keygen', '--out', root / 'second.key'])
                second = cli.run(['public-key', '--key', root / 'second.key'])
                op = operation()
                ops = [op,
                    {'Deposit': dict(amount='1000', decision=None, outcome=None)},
                    {'Redeem': dict(shares='1000000', decision=[1] * 32, outcome='Pass')},
                    {'Propose': dict(round=2, description=[1] * 32, proposal={'Grant': {'payments': [dict(recipient=list(bytes.fromhex(public)), amount='10')]}}, support='1')},
                    {'Propose': dict(round=2, description=[2] * 32, proposal={'Grant': {'payments': [
                        dict(recipient=list(bytes.fromhex(key)), amount=str(i + 10))
                        for i, key in enumerate(sorted([public, second]))]}}, support='1')},
                    {'Support': dict(round=2, proposal=[1] * 32, amount='10')},
                    {'Refund': dict(round=2, proposal=[1] * 32)}]
                for i, inner in enumerate(ops):
                    # Positive/zero amounts and both empty and nonempty signed data
                    # are validated by the actual Rust wallet decoder and signer.
                    body, raw = ca.make_body(public, i, 1000000, 'ab' * 32, 2, inner,
                        b'Automated test'.hex() if i == 0 else '')
                    ca.save_new(root / f'body{i}.json', body)
                    cli.run(['sign', '--key', root / 'test.key', '--body', root / f'body{i}.json', '--out', root / f'signed{i}.json', '--chain-id', CHAIN])
                    signed = json.loads((root / f'signed{i}.json').read_text())
                    wire = ca.signed_wire(signed, body, raw)
                    ca.save_new(root / f'raw{i}.hex', wire.hex(), text=True)
                    response = json.loads(cli.run(['broadcast', '--url', f'http://127.0.0.1:{server.server_port}/rpc', '--raw-file', root / f'raw{i}.hex']))
                    self.assertEqual(response['transaction_id'], ca.sha256d(wire))
                    self.assertEqual(captured[-1]['method'], 'broadcasttransaction')
                    self.assertEqual(captured[-1]['params']['raw'], wire.hex())
                self.assertEqual(len(captured), 7)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class NativeBalanceTests(unittest.TestCase):
    tearDown = ActivityTests.tearDown
    action = ActivityTests.action

    def setUp(self):
        ActivityTests.setUp(self)
        self.activity.ledger.db.close()
        self.cfg['profile'] = ca.NATIVE_PROFILE
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.snapshot, self.accounts = self.activity.observe()
        self.node.world['curve_mass'] = self.node.world['reserve']
        self.snapshot['governance']['world']['curve_mass'] = self.node.world['reserve']

    def grant(self):
        action = self.action()
        text = ca.proposal_description('fra', 2, ca.NATIVE_PROFILE).encode()
        action.update(kind='propose_grant',
            operation={'Propose': {'round': 2, 'description': list(ca.hashlib.sha256(text).digest()),
                'proposal': {'Grant': {'payments': [{'recipient': list(bytes.fromhex(KEYS[2])), 'amount': str(5 * 10**17)}]}},
                'support': '1'}})
        return action

    def test_profile_is_explicit_idempotent_and_removes_only_value_limits(self):
        self.assertEqual(ca.config_checked(self.activity.c), self.activity.c)
        for field in ('max_consumptive_daily_raw', 'max_actions_daily'):
            self.assertIsNone(self.activity.c[field])
        policy = self.activity.policy(self.snapshot)
        self.assertNotIn('consumptive_budget_remaining_raw', policy)
        self.assertNotIn('grant_budget_remaining_raw', policy)
        for field, value in (('action_seconds', 19), ('chat_seconds', 89), ('funding_seconds', 86399), ('confirmations', 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                ca.config_checked(dict(self.cfg, **{field: value}))

    def test_large_native_grant_rechecks_capacity_registry_description_and_cash(self):
        action = self.grant()
        self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.assertEqual(action['reserved_cost_raw'], str(1 + 1))
        too_small = copy.deepcopy(self.snapshot)
        too_small['governance']['world']['grant_capacity'] = str(4 * 10**17)
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(too_small), too_small)
        changed = self.grant()
        changed['operation']['Propose']['proposal']['Grant']['payments'][0]['recipient'] = [255] * 32
        with self.assertRaises(ca.Fault):
            self.activity.allowed_action(changed, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        changed = self.grant()
        changed['data_hex'] = b'Not the reviewed experiment'.hex()
        with self.assertRaises(ca.Fault):
            self.activity.allowed_action(changed, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.accounts[0]['account']['ordinary'] = '1'
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_native_signature_recovery_preserves_the_exact_grant(self):
        action = self.grant()
        self.activity.submit(action, self.snapshot, self.accounts)
        row = self.activity.ledger.rows(('pending',))[0]
        self.assertNotIn('data_hex', json.loads(row['action']))
        body_path = self.activity.work / row['id'] / 'body.json'
        self.assertEqual(json.loads(body_path.read_text())['data'], [])
        self.activity.ledger.db.close()
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.now += 21
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(self.cli.broadcasts, [row['raw'], row['raw']])
        self.activity.write_status()
        status = json.loads((self.activity.work / 'status.json').read_text())
        self.assertEqual(json.loads(row['action'])['operation'], action['operation'])
        self.assertNotIn('grant_exposure_reserved_24h_raw', status)

    def test_native_proposal_guard_rejects_message_or_wrong_region_round_commitment(self):
        for altered in ('message', 'empty_hash', 'region', 'round', 'commitment'):
            changed = self.grant()
            op = changed['operation']['Propose']
            if altered == 'message':
                changed['data_hex'] = ca.proposal_description('fra', 2, ca.NATIVE_PROFILE).encode().hex()
            elif altered == 'empty_hash':
                op['description'] = list(ca.hashlib.sha256(b'').digest())
            elif altered == 'region':
                op['description'] = list(ca.hashlib.sha256(ca.proposal_description('sgp', 2, ca.NATIVE_PROFILE).encode()).digest())
            elif altered == 'round':
                op['round'] = 3
            else:
                op['description'][0] ^= 1
            with self.subTest(altered=altered), self.assertRaisesRegex(ca.Fault, 'empty data.*regional round commitment'):
                self.activity.allowed_action(changed, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.assertFalse(self.cli.broadcasts)


    def test_native_signing_boundary_uses_current_backing(self):
        changed = copy.deepcopy(self.snapshot)
        changed['governance']['world']['grant_capacity'] = str(4 * 10**17)
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(changed), changed)
        # Waiting revenue is also real backing; no reserve-draw threshold applies.
        changed['governance']['world'].update(reserve='0', curve_mass='0', revenue=str(6 * 10**17), grant_capacity=str(6 * 10**17))
        self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(changed), changed)


class SubstantiveTests(ActivityTests):
    # Inherit the same custody/journal/reorg suite under the opt-in profile too.
    def setUp(self):
        super().setUp()
        self.activity.ledger.db.close()
        self.cfg['profile'] = 'substantive-v1'
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.snapshot, self.accounts = self.activity.observe()

    def grant(self, n=4 * 10**16, sender=0):
        action = self.action()
        action.update(kind='propose_grant', sender_index=sender, round=2,
            operation={'Propose': {'round': 2, 'description': [8] * 32,
                'proposal': {'Grant': {'payments': [{'recipient': list(bytes.fromhex(KEYS[2])), 'amount': str(n)}]}},
                'support': '1'}})
        return action

    def described_grant(self):
        action = self.grant()
        data = b'Hashstash automated demo fra round 2'
        action['data_hex'] = data.hex()
        action['operation']['Propose']['description'] = list(ca.hashlib.sha256(data).digest())
        return action

    def test_proposal_data_is_committed_demo_text_without_widening_grant_scope(self):
        action = self.described_grant()
        policy = self.activity.policy(self.snapshot)
        self.activity.allowed_action(action, self.accounts, policy, self.snapshot)
        self.assertEqual(action['reserved_cost_raw'], str(1 + int(self.activity.c['max_fee_raw'])))
        for altered in ('text', 'commitment', 'region'):
            changed = copy.deepcopy(action)
            if altered == 'text':
                changed['data_hex'] = b'Hashstash automated demo fra round 3'.hex()
            elif altered == 'commitment':
                changed['operation']['Propose']['description'][0] ^= 1
            else:
                data = b'Hashstash automated demo sgp round 2'
                changed['data_hex'] = data.hex()
                changed['operation']['Propose']['description'] = list(ca.hashlib.sha256(data).digest())
            with self.subTest(altered=altered), self.assertRaisesRegex(ca.Fault, 'signed demo description'):
                self.activity.allowed_action(changed, self.accounts, policy, self.snapshot)
        changed = copy.deepcopy(action)
        changed['operation']['Propose']['proposal']['Grant']['payments'][0]['recipient'] = [255] * 32
        with self.assertRaisesRegex(ca.Fault, 'grant exceeds activity scope'):
            self.activity.allowed_action(changed, self.accounts, policy, self.snapshot)
        self.assertFalse(self.cli.broadcasts)

    def test_proposal_text_signed_retry_is_byte_identical_after_restart(self):
        action = self.described_grant()
        self.activity.submit(action, self.snapshot, self.accounts)
        row = self.activity.ledger.rows(('pending',))[0]
        self.assertEqual(json.loads(row['action'])['data_hex'], action['data_hex'])
        self.activity.ledger.db.close()
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.activity.observe()
        self.node.height += 1
        self.now += 21
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(self.cli.broadcasts, [row['raw'], row['raw']])
        self.assertEqual(len(self.activity.ledger.rows(('pending',))), 1)

    def test_profile_gate_keeps_bounded_limits_and_enforces_hard_ceilings(self):
        bounded = config(self.root)
        self.assertEqual(ca.config_checked(bounded)['chat_seconds'], 300)
        self.assertEqual(self.activity.c['chat_seconds'], 90)
        self.assertEqual(self.activity.c['max_consumptive_daily_raw'], '1000')
        for field, value in [('max_consumptive_daily_raw', 1001),
                ('chat_seconds', 89), ('funding_seconds', 86399)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                ca.config_checked(dict(self.cfg, **{field: value}))
        with self.assertRaises(ValueError):
            ca.config_checked(dict(bounded, chat_seconds=90))
        self.activity.c = ca.config_checked(bounded)
        self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_obsolete_grant_cap_settings_are_rejected(self):
        for profile in ('bounded-v1', 'substantive-v1', ca.NATIVE_PROFILE, ca.PASS_PROFILE):
            for field in ('max_grant_raw', 'max_grant_exposure_daily_raw'):
                with self.subTest(profile=profile, field=field), self.assertRaisesRegex(ValueError, 'not supported'):
                    ca.config_checked(dict(self.cfg, profile=profile, **{field: '1'}))

    def test_grant_current_capacity_and_feasibility_are_independent_of_metadata(self):
        action = self.grant()
        self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.assertEqual(action['reserved_cost_raw'], str(1 + 10))
        small = copy.deepcopy(self.snapshot)
        small['governance']['world']['grant_capacity'] = str(10**15)
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(small), small)
        self.node.grant_feasible = False
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(self.grant(), self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_multi_grant_scope_capacity_and_journal_use_the_total(self):
        action = self.grant()
        payments = [dict(recipient=list(bytes.fromhex(key)), amount=str(2 * 10**16)) for key in KEYS[1:]]
        action['operation']['Propose']['proposal']['Grant'] = {'payments': payments}
        action['grant_amount_raw'] = '1'
        self.activity.submit(action, self.snapshot, self.accounts)
        recorded = json.loads(self.activity.ledger.rows(('pending',))[0]['action'])
        self.assertEqual(ca.validated_grant(recorded['operation']['Propose']['proposal']['Grant'])[1], 4 * 10**16)
        self.assertNotIn('reserved_grant_raw', recorded)
        for mutation in ('outside', 'aggregate'):
            changed = copy.deepcopy(action)
            changed['sender_index'] = 1
            payouts = changed['operation']['Propose']['proposal']['Grant']['payments']
            if mutation == 'outside': payouts[1]['recipient'] = [255] * 32
            else: payouts[1]['amount'] = str(10**18)
            with self.assertRaises((ca.Fault, ca.Pause)):
                self.activity.allowed_action(changed, self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_bounded_profile_support_also_rechecks_every_registered_recipient(self):
        self.activity.c = ca.config_checked(config(self.root))
        proposal_id = 'bb' * 32
        payments = [dict(recipient=list(bytes.fromhex(key)), amount=str(4 * 10**12)) for key in KEYS[1:]]
        self.node.proposals = [{'id': proposal_id, 'proposal': {'round': 2,
            'action': {'Grant': {'payments': payments}}}}]
        action = self.action()
        action['operation'] = {'Support': {'round': 2, 'proposal': list(bytes.fromhex(proposal_id)), 'amount': '1'}}
        self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        payments[1]['recipient'] = [255] * 32
        with self.assertRaisesRegex(ca.Fault, 'outside activity registry'):
            self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_prior_proposals_do_not_reduce_current_grant_backing(self):
        for sender in range(3):
            self.activity.submit(self.grant(n=6 * 10**17, sender=sender), self.snapshot, self.accounts)
        rows = self.activity.ledger.rows(('pending',))
        self.assertEqual(len(rows), 3)
        self.activity.ledger.update(rows[0]['id'], state='confirmed', confirmed=self.now, receipt_height=10, receipt_hash=self.node.anchor)
        self.activity.ledger.db.close()
        self.activity = ca.Activity(self.cfg, Planner, self.cli, self.node, clock=lambda: self.now)
        self.assertNotIn('grant_budget_remaining_raw', self.activity.policy(self.snapshot))
        self.activity.write_status()
        status = json.loads((self.activity.work / 'status.json').read_text())
        self.assertNotIn('grant_exposure_reserved_24h_raw', status)
        self.assertNotIn('grant_exposure_is_awarded_value', status)
        self.assertEqual(len(self.activity.ledger.rows(('pending', 'confirmed'))), 3)

    def test_support_looks_up_actual_grant_instead_of_trusting_amount_hint(self):
        proposal_id = 'bb' * 32
        action = self.action()
        action.update(kind='support', grant_amount_raw='1', round=2,
                      operation={'Support': {'round': 2, 'proposal': list(bytes.fromhex(proposal_id)), 'amount': '1'}})
        grant = self.grant()['operation']['Propose']['proposal']['Grant']
        self.node.proposals = [{'id': proposal_id, 'proposal': {'round': 2, 'action': {'Grant': grant}}}]
        self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)
        self.node.proposals[0]['proposal']['action'] = {'Parameter': {'new': 5}}
        with self.assertRaises(ca.Pause):
            self.activity.allowed_action(action, self.accounts, self.activity.policy(self.snapshot), self.snapshot)

    def test_expired_fee_reservations_remain_but_unsigned_abandoned_does_not(self):
        self.activity.submit(self.grant(), self.snapshot, self.accounts)
        row = self.activity.ledger.rows(('pending',))[0]
        cost = json.loads(row['action'])['reserved_cost_raw']
        self.activity.ledger.update(row['id'], state='expired')
        self.assertEqual(self.activity.reservations()[1], int(cost))
        self.activity.ledger.update(row['id'], state='abandoned')
        self.assertEqual(self.activity.reservations()[1], 0)

    def test_context_survives_more_than512_confirmed_actions(self):
        decision = 'de' * 32
        old = self.action()
        old.update(kind='deposit_pass', decision=decision, round=1)
        with self.activity.ledger.db:
            for i in range(520):
                action = old if i == 0 else self.action()
                self.activity.ledger.db.execute('INSERT INTO intents(id,sender,created,prepared_height,action,state,confirmed) VALUES(?,?,?,?,?,?,?)',
                    (str(i), KEYS[0], self.now + i, i, ca.compact(action), 'confirmed', self.now + i))
        snap = copy.deepcopy(self.snapshot)
        snap['status']['decision'] = decision
        history = self.activity.policy(snap)['history']
        self.assertTrue(any(h.get('decision') == decision and h['kind'] == 'deposit_pass' for h in history))
        self.assertEqual(self.activity.policy(snap)['cursor'], 520)


if __name__ == '__main__':
    unittest.main()
