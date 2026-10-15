"""Offline campaign scheduling/custody tests; no network, real keys or mining."""
import copy
import hashlib
import unittest

import activity_plan as p
import activity_personas as personas
import chain_activity as ca
import test_activity_plan as plan_fixtures
import test_chain_activity as custody_fixtures
REGISTRY, DECISION = plan_fixtures.REGISTRY, plan_fixtures.DECISION


class CampaignPlanTests(unittest.TestCase):
    setUp = plan_fixtures.PlannerTest.setUp
    rpc = plan_fixtures.PlannerTest.rpc
    choose = plan_fixtures.PlannerTest.choose
    phase = plan_fixtures.PlannerTest.phase
    confirm_full_cash = plan_fixtures.PlannerTest.confirm_full_cash

    def ready(self, region='sgp'):
        self.policy.update(profile=p.PASS_PROFILE, region=region, last_chat_at=0)
        for i, actor in enumerate(self.accounts):
            actor['public_key'] = REGISTRY[region][i]
            actor['account'].update(ordinary='1000000', shares='1000000000')
        # Real snapshot accounts deliberately contain only holdings. Nonces are
        # fetched through account RPC for local signing accounts above.
        self.snapshot['balances'] = {key: {'account': dict(ordinary='1000000', shares='1000000000')}
                                     for group in REGISTRY.values() for key in group}
        self.snapshot['campaign'] = dict(checked=True, completed=False, settlement_pending=False)
        self.snapshot['governance']['world'].update(reserve='9000000', curve_mass='9000000', shares='9000000000', revenue='100', grant_capacity='9000100')
        self.phase('auction')

    def live(self, region='sgp'):
        self.ready(region)
        self.phase('governance')
        grant = {'Grant': {'payments': [{'recipient': list(bytes.fromhex(REGISTRY['fra'][0])), 'amount': '4500100'}]}}
        desc = hashlib.sha256(p.proposal_description('sgp', 0, p.PASS_PROFILE).encode()).digest()
        self.snapshot['proposals'] = [{'id': 'ab' * 32, 'proposal': dict(round=0, description=list(desc), action=grant)}]
        self.snapshot['governance']['phase'] = {'Governance': dict(round=0, proposal_id=[171]*32, proposal=grant,
                                                                   started=1500, started_height=100, blocks=60, leading_blocks=0)}
        self.snapshot['governance']['pass'] = dict(self.snapshot['governance']['world'], reserve='4500000', grant_escrow='4500100')

    def test_single_coordinator_proposes_half_reserve_empty_data(self):
        self.ready()
        a = self.choose()
        self.assertEqual((a['kind'], a['sender_index']), ('propose_grant', 0))
        self.assertEqual(a['recipient'], REGISTRY['fra'][0])
        self.assertEqual(int(a['grant_amount_raw']), 100 + int(a['amount_raw']) + 4500000 + int(a['quoted_fee_raw']))
        self.assertEqual(a['campaign_reserve_draw_raw'], '4500000')
        self.assertNotIn('data_hex', a)
        self.policy['pending_actions'] = [a]
        self.assertIsNone(self.choose())
        for region in ('fra', 'ewr'):
            self.ready(region)
            self.policy['pending_actions'] = []
            self.assertIsNone(self.choose())

    def test_waits_for_every_existing_actor_and_real_backing(self):
        for change in ('missing', 'cash', 'shares', 'reserve', 'curve', 'capacity'):
            self.ready()
            other = self.snapshot['balances'][REGISTRY['ewr'][2]]
            if change == 'missing': other['account'] = None
            elif change == 'cash': other['account']['ordinary'] = '1'
            elif change == 'shares': other['account']['shares'] = '0'
            elif change in ('reserve', 'curve'):
                self.snapshot['governance']['world']['reserve' if change == 'reserve' else 'curve_mass'] = '0'
            else: self.snapshot['governance']['world']['grant_capacity'] = '10'
            with self.subTest(change=change): self.assertIsNone(self.choose())

    def test_compact_holdings_allow_readiness_without_loosening_signing_accounts(self):
        self.ready()
        self.assertTrue(p.campaign_ready(self.snapshot, REGISTRY, 2))
        compact = self.snapshot['balances'][REGISTRY['fra'][0]]['account']
        self.assertEqual(set(compact), {'ordinary', 'shares'})
        self.assertIsNone(p._account(compact))
        self.assertIsNotNone(p._account(dict(compact, nonce=0)))
        self.assertEqual(self.choose()['kind'], 'propose_grant')

    def test_compact_holdings_reject_invalid_or_oversized_raw_amounts(self):
        invalid = (None, True, False, 1, 1.0, -1, '', '-1', '+1', ' 1', '1 ',
                   '01', '00', '1.0', '1e3', '\u0661', '9'*156, str(1 << 512))
        for field in ('ordinary', 'shares'):
            for raw in invalid:
                self.ready()
                self.snapshot['balances'][REGISTRY['ewr'][2]]['account'][field] = raw
                with self.subTest(field=field, raw=raw):
                    self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
                    self.assertIsNone(self.choose())
            self.ready()
            del self.snapshot['balances'][REGISTRY['ewr'][2]]['account'][field]
            self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
        for missing in (None, [], 'invalid'):
            self.ready()
            self.snapshot['balances'][REGISTRY['ewr'][2]]['account'] = missing
            self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
        self.assertIsNotNone(p._snapshot_holdings(dict(ordinary='0', shares=str((1 << 512)-1))))

    def test_compact_holdings_keep_cash_reserve_and_shared_liquidity_gates(self):
        self.ready()
        other = self.snapshot['balances'][REGISTRY['ewr'][2]]['account']
        other['ordinary'] = '200'
        self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
        other['ordinary'] = '201'
        self.assertTrue(p.campaign_ready(self.snapshot, REGISTRY, 2))
        other['shares'] = '0'
        self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
        self.ready()
        self.snapshot['governance']['world']['reserve'] = '1999'
        self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))
        self.snapshot['governance']['world']['reserve'] = '18000002'
        self.assertFalse(p.campaign_ready(self.snapshot, REGISTRY, 2))

    def test_preparation_builds_backing_before_proposal_or_chat(self):
        self.ready()
        self.accounts[0]['account']['shares'] = '0'
        a = self.choose()
        self.assertEqual(a['kind'], 'deposit')
        self.assertEqual(a['strategy_reason'], 'campaign_backing_and_liquidity')

    def test_nine_actors_prioritize_pass_then_exit_fail_without_chat_or_circulation(self):
        for region in REGISTRY:
            self.setUp(); self.live(region)
            self.policy['history'] = [{'kind': 'deposit', 'sender_index': 0}] * 4
            actions = []
            for _ in range(6):
                a = self.choose()
                self.assertIsNotNone(a)
                actions.append(a)
                self.confirm_full_cash(a)
            self.assertEqual([a['kind'] for a in actions], ['deposit_pass']*3 + ['redeem_fail']*3)
            self.assertEqual({a['sender_index'] for a in actions[:3]}, {0,1,2})
            self.assertTrue(all(a['preferred_outcome'] == 'Pass' for a in actions))
            self.assertTrue(all(int(actor['pass_account']['ordinary']) > 0 for actor in self.accounts))
            self.assertTrue(all(actor['account']['shares'] == '0' for actor in self.accounts))
            self.assertIsNone(self.choose())

    def test_pending_pass_buy_blocks_only_its_actor_and_uses_no_fail_sale_proceeds(self):
        self.live()
        a = self.choose()
        self.assertLess(int(a['amount_raw']), int(self.accounts[0]['pass_account']['ordinary']))
        self.policy['pending_actions'] = [a]
        b = self.choose()
        self.assertEqual(b['kind'], 'deposit_pass')
        self.assertNotEqual(b['sender_index'], a['sender_index'])

    def test_partial_quote_does_not_undervalue_existing_portfolio(self):
        self.live()
        expected = self.choose()
        original = self.rpc
        def partial(method, params):
            result = original(method, params)
            if method == 'stash_quote' and params.get('all'):
                requested = int(result['input_requested'])
                result.update(input_filled=str(requested // 10), input_unfilled=str(requested-requested // 10),
                              output_hash=str(int(result['output_hash']) // 10), output=str(int(result['output']) // 10))
            return result
        self.rpc = partial
        actual = self.choose()
        self.assertEqual(actual['operation'], expected['operation'])
        self.assertEqual(actual['expiry_blocks'], 2)

    def test_partial_fill_rechecks_actual_holdings_before_next_order(self):
        self.live()
        first = self.choose()
        self.assertEqual(first['kind'], 'deposit_pass')
        self.confirm_full_cash(first)
        actor = self.accounts[first['sender_index']]['pass_account']
        # Model an unfilled order: only the fee was paid and holdings stay short
        # of the target. A confirmed transaction alone cannot complete this leg.
        actor['ordinary'] = '1000000'
        actor['shares'] = '1000000000'
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        following = self.choose()
        self.assertEqual(following['kind'], 'deposit_pass')
        self.assertEqual(following['sender_index'], first['sender_index'])

    def test_unknown_unfunded_unrelated_or_near_end_decisions_wait(self):
        for change in ('unknown', 'unfunded', 'unrelated', 'late', 'settling'):
            self.live()
            if change == 'unknown': self.snapshot['campaign']['checked'] = False
            elif change == 'unfunded': self.snapshot['governance']['pass']['grant_escrow'] = '1'
            elif change == 'unrelated': self.snapshot['proposals'][0]['proposal']['description'][0] ^= 1
            elif change == 'late': self.snapshot['status']['height'] = 159
            else: self.snapshot['campaign']['settlement_pending'] = True
            with self.subTest(change=change): self.assertIsNone(self.choose())

    def test_success_closes_all_future_grants_but_ordinary_activity_continues(self):
        self.ready()
        self.snapshot['campaign']['completed'] = True
        a = self.choose()
        self.assertIn(a['kind'], {'transfer', 'deposit', 'redeem'})
        self.snapshot['status']['auction_round'] = 100
        self.assertNotEqual((self.choose() or {}).get('kind'), 'propose_grant')

    def test_campaign_labels_are_honest_and_preferences_do_not_flip_at_premium(self):
        for region in REGISTRY:
            for index in range(3):
                persona = personas.profile_for(region, index, p.PASS_PROFILE)
                self.assertIn('Automated · PASS campaign', persona['label'])
                metrics = dict(grant_feasible=True, grant_amount_raw='100', grant_funded_raw='100',
                               pass_price_numerator='1000', pass_price_denominator='1',
                               fail_price_numerator='1', fail_price_denominator='1')
                result = personas.evaluate({}, persona, metrics)
                self.assertTrue(result['coordinated_campaign'])
                self.assertEqual(result['preferred_outcome'], 'Pass')
                self.assertIsNone(personas.evaluate({}, persona, dict(metrics, grant_feasible=False))['preferred_outcome'])


class CampaignCustodyTests(unittest.TestCase):
    tearDown = custody_fixtures.ActivityTests.tearDown

    def setUp(self):
        custody_fixtures.ActivityTests.setUp(self)
        self.activity.ledger.db.close()
        self.cfg['profile'] = p.PASS_PROFILE
        self.cfg['database'] = str(self.root / 'campaign.sqlite')
        self.cfg['region'] = 'sgp'
        self.cfg['registry']['fra'], self.cfg['registry']['sgp'] = self.cfg['registry']['sgp'], self.cfg['registry']['fra']
        self.base_rpc = self.node
        self.decisions = []
        self.activity = ca.Activity(self.cfg, p,
                                   self.cli, self.rpc, clock=lambda: self.now)
        self.snapshot = self.node.snapshot()
        self.snapshot['governance'] = {'world': self.node.world}
        self.snapshot['campaign'] = dict(checked=True, completed=False)

    def context(self):
        height = self.snapshot['status']['height'] if hasattr(self, 'snapshot') else self.node.height
        return dict(chain_id=self.cfg['chain_id'], tip=f'{height:064x}', height=height, state_root='ee'*32)

    def rpc(self, method, params):
        if method == 'explorer_governance':
            self.assertLessEqual(params['limit'], 50)
            return dict(**self.context(), decisions=copy.deepcopy(self.decisions))
        result = self.base_rpc(method, params)
        if method == 'explorer_block': result.update(self.context())
        if method == 'snapshot' and self.node.phase == 'auction':
            result['status']['auction_round'] = 0
        return result

    def settlement(self):
        recipient = self.cfg['registry']['fra'][0]
        desc = hashlib.sha256(p.proposal_description('sgp', 0, p.PASS_PROFILE).encode()).digest()
        self.node.proposals = [dict(id='ab'*32, proposal=dict(round=0, description=list(desc),
            action={'Grant': {'payments': [dict(recipient=list(bytes.fromhex(recipient)), amount='1000')]}}))]
        self.decisions = [dict(id=DECISION, proposal='ab'*32, round=0, ended_height=self.node.height,
                              outcome='pass', funded=True, blocks=60, observed_blocks=60, blocks_remaining=0, leading_blocks=31, pass_margin_bps=0)]
        self.snapshot['status']['height'] = self.node.height

    def test_completion_needs_depth_funding_strict_majority_and_canonical_anchor(self):
        self.settlement()
        value = self.activity.observe_campaign(self.snapshot)
        self.assertFalse(value['completed']); self.assertTrue(value['settlement_pending'])
        self.snapshot['status']['height'] += 1
        self.decisions[0]['outcome'] = 'fail'
        self.assertFalse(self.activity.observe_campaign(self.snapshot)['completed'])
        self.decisions[0]['outcome'] = 'pass'
        self.decisions[0]['leading_blocks'] = 30
        with self.assertRaises(ca.Fault): self.activity.observe_campaign(self.snapshot)
        self.decisions[0]['leading_blocks'] = 31
        self.decisions[0]['funded'] = False
        with self.assertRaises(ca.Fault): self.activity.observe_campaign(self.snapshot)
        self.decisions[0]['funded'] = True
        complete = self.activity.observe_campaign(self.snapshot)
        self.assertTrue(complete['completed'])
        self.assertEqual(complete['proof']['amount_raw'], '1000')
        self.decisions = []  # persisted proof survives later explorer pagination
        self.assertTrue(self.activity.observe_campaign(self.snapshot)['completed'])
        self.node.anchor = 'ff'*32
        with self.assertRaisesRegex(ca.Fault, 'reorganized'): self.activity.observe_campaign(self.snapshot)

    def test_completion_rejects_incomplete_or_malformed_block_counts(self):
        for changed in (dict(blocks=0), dict(blocks=True), dict(observed_blocks=59),
                        dict(blocks_remaining=1), dict(leading_blocks=61), dict(leading_blocks=-1),
                        dict(leading_blocks=True), dict(leading_blocks='31')):
            self.settlement()
            self.snapshot['status']['height'] += 2
            self.decisions[0].update(changed)
            with self.subTest(changed=changed), self.assertRaises(ca.Fault):
                self.activity.observe_campaign(self.snapshot)
            self.assertIsNone(self.activity.ledger.get('pass_campaign_completion'))

    def test_unrelated_pass_is_not_campaign_completion(self):
        self.settlement()
        self.snapshot['status']['height'] += 2
        self.node.proposals[0]['proposal']['description'][0] ^= 1
        self.assertFalse(self.activity.observe_campaign(self.snapshot)['completed'])

    def test_completion_can_be_found_on_an_older_explorer_page(self):
        self.settlement()
        self.snapshot['status']['height'] += 2
        original = self.rpc
        def paged(method, params):
            if method == 'explorer_governance' and 'before_height' not in params:
                return dict(**self.context(), decisions=[], next_before_height=100)
            if method == 'explorer_governance': self.assertEqual(params['before_height'], 100)
            return original(method, params)
        self.activity.rpc = paged
        self.assertTrue(self.activity.observe_campaign(self.snapshot)['completed'])

    def test_bounded_history_scan_cannot_authorize_a_duplicate_campaign(self):
        def pages(method, params):
            self.assertEqual(method, 'explorer_governance')
            return dict(**self.context(), decisions=[], next_before_height=params.get('before_height',1000)-1)
        self.activity.rpc = pages
        result = self.activity.observe_campaign(self.snapshot)
        self.assertFalse(result['checked'])
        self.assertFalse(result['completed'])

    def test_reorg_between_decision_and_block_reads_never_sets_completion(self):
        self.settlement()
        self.snapshot['status']['height'] += 2
        original = self.rpc
        def reorg(method, params):
            result = original(method, params)
            if method == 'explorer_block':
                result.update(tip='ff'*32, state_root='ab'*32)
                result['block']['hash'] = 'ba'*32
            return result
        self.activity.rpc = reorg
        with self.assertRaisesRegex(ca.Pause, 'snapshot moved'):
            self.activity.observe_campaign(self.snapshot)
        self.assertIsNone(self.activity.ledger.get('pass_campaign_completion'))

    def test_campaign_retains_funding_cadence_confirmation_and_journal_configuration(self):
        self.assertEqual(ca.config_checked(self.activity.c), self.activity.c)
        for field, value in [('action_seconds',19), ('funding_seconds',86399), ('confirmations',1)]:
            with self.assertRaises(ValueError): ca.config_checked(dict(self.cfg, **{field:value}))

    def proposal_action(self):
        snapshot, accounts = self.activity.observe()
        snapshot['status'].update(phase='auction', auction_round=0)
        snapshot['governance']['world'].update(reserve=str(9*10**15), curve_mass=str(9*10**15), revenue='0', grant_capacity=str(9*10**15-1))
        snapshot['balances'] = {key: {'account': dict(ordinary=str(10**15), shares=str(10**15), nonce=0)}
                               for group in self.cfg['registry'].values() for key in group}
        desc = hashlib.sha256(p.proposal_description('sgp', 0, p.PASS_PROFILE).encode()).digest()
        recipient = self.cfg['registry']['fra'][0]
        action = dict(kind='propose_grant', sender_index=0, quoted_fee_raw='1', amount_raw='1000', expiry_blocks=2,
            guard=dict(nonce=0, phase='auction', chain_id=self.cfg['chain_id'], decision=None, auction_round=0,
                       height=snapshot['status']['height'], sender_public_key=self.cfg['accounts'][0]['public_key']),
            operation={'Propose': dict(round=0, description=list(desc), support='1000',
                proposal={'Grant': {'payments': [dict(recipient=list(bytes.fromhex(recipient)), amount=str(45*10**14+1001))]}})})
        return action, snapshot, accounts

    def test_signing_boundary_rechecks_coordinator_scope_and_real_backing(self):
        action, snapshot, accounts = self.proposal_action()
        self.activity.allowed_action(action, accounts, self.activity.policy(snapshot), snapshot)
        for change in ('sender', 'recipient', 'unbacked', 'missing_actor', 'settled', 'data'):
            a, s, actors = self.proposal_action()
            if change == 'sender': a['sender_index'] = 1
            elif change == 'recipient': a['operation']['Propose']['proposal']['Grant']['payments'][0]['recipient'] = [255]*32
            elif change == 'unbacked':
                a['operation']['Propose']['proposal']['Grant']['payments'][0]['amount'] = str(9*10**15)
            elif change == 'missing_actor': s['balances'].pop(self.cfg['registry']['ewr'][0])
            elif change == 'settled': s['campaign']['completed'] = True
            else: a['data_hex'] = b'undesired boilerplate'.hex()
            with self.subTest(change=change), self.assertRaises((ca.Fault, ca.Pause)):
                self.activity.allowed_action(a, actors, self.activity.policy(s), s)

    def test_campaign_accepts_backed_grants_outside_planner_target(self):
        for amount in (3 * 10**15, 8 * 10**15):
            action, snapshot, accounts = self.proposal_action()
            action['operation']['Propose']['proposal']['Grant']['payments'][0]['amount'] = str(amount)
            self.activity.allowed_action(action, accounts, self.activity.policy(snapshot), snapshot)

    def test_full_signed_campaign_intent_retries_identically_across_restart(self):
        action, snapshot, accounts = self.proposal_action()
        self.node.phase = 'auction'
        self.node.world = copy.deepcopy(snapshot['governance']['world'])
        self.node.account_values = {key: copy.deepcopy(value['account']) for key,value in snapshot['balances'].items()}
        self.activity.advanced_at = self.now
        self.activity.submit(action, snapshot, accounts)
        row = self.activity.ledger.rows(('pending',))[0]
        self.activity.ledger.db.close()
        self.activity = ca.Activity(self.cfg, p, self.cli, self.rpc, clock=lambda:self.now)
        self.activity.observe()
        self.node.height += 1
        self.now += 21
        snapshot, accounts = self.activity.observe()
        self.activity.reconcile(snapshot, accounts)
        self.assertEqual(self.cli.broadcasts, [row['raw'], row['raw']])
        self.assertNotIn('data_hex', ca.json.loads(row['action']))


if __name__ == '__main__': unittest.main()
