"""Focused planner tests: no network, signatures, transactions or mining."""

import copy
import hashlib
import json
import unittest

import activity_plan as planner


CHAIN = "aa" * 32
DECISION = "dd" * 32
REGISTRY = {region: [f"{offset + i:064x}" for i in range(3)]
            for region, offset in (("fra", 1), ("sgp", 4), ("ewr", 7))}


class PlannerTest(unittest.TestCase):
    def setUp(self):
        self.now = 1000
        self.policy = {"region": "fra", "chain_id": CHAIN, "last_action_at": 900,
                       "last_action_height": 1, "last_chat_at": 900,
                       "history": [], "cursor": 0}
        self.snapshot = {
            "status": {"chain_id": CHAIN, "height": 100, "clock": 1500,
                       "phase": "rest", "decision": None, "auction_round": None,
                       "settings": {"interval": 15}},
            "governance": {"world": {"reserve": str(10**18), "grant_capacity": str(10**17)}},
            "proposals": [],
        }
        balance = {"ordinary": str(10**15), "shares": str(10**16), "nonce": 2}
        self.accounts = [{"public_key": key, "account": dict(balance), "pending": False}
                         for key in REGISTRY["fra"]]
        self.calls = []
        self.refundable = False
        self.grant_feasible = True
        self.fee = "2"

    def rpc(self, method, params):
        self.calls.append((method, copy.deepcopy(params)))
        self.assertIn(method, planner.READ_METHODS)
        if method == "fee_quote":
            return {"fee": self.fee}
        if method == "stash_quote":
            if params.get("all"):
                actor = next(a for a in self.accounts if a["public_key"] == params["key"])
                account = actor["pass_account"] if params.get("outcome") == "pass" else actor["account"]
                amount = int(account["shares"])
            else:
                amount = int(params["amount"])
            if params["kind"] == "deposit":
                shares, output = amount * 1000, amount
            elif params["kind"] == "withdraw":
                shares, output = amount * 1000, amount
            else:
                shares, output = amount, amount // 1000
            return {"shares": str(shares), "output_hash": str(output),
                    "decision": self.snapshot["status"]["decision"] if params.get("outcome") else None}
        if method == "grant_quote":
            return {"feasible": self.grant_feasible, "funded_baseline": params["amount"]}
        if method == "support":
            return {"refundable": self.refundable, "amount": str(planner.SUPPORT)}
        if method == "proposals":
            return self.snapshot["proposals"]
        self.fail("Unreviewed RPC")

    def choose(self):
        return planner.plan(self.snapshot, self.accounts, REGISTRY, self.policy, self.now, self.rpc)

    def phase(self, name):
        self.snapshot["status"].update(phase=name, decision=DECISION if name == "governance" else None,
                                       auction_round=0 if name == "auction" else None)
        if name == "governance":
            for actor in self.accounts:
                actor["pass_account"] = dict(actor["account"])

    def substantive(self, region="fra", heavy=False):
        self.policy.update(profile="substantive-v1", region=region, last_chat_at=self.now,
                           consumptive_budget_remaining_raw=str(10**15))
        for index, actor in enumerate(self.accounts):
            actor["public_key"] = REGISTRY[region][index]
            if heavy:
                actor["account"].update(ordinary=str(2 * 10**13), shares=str(8 * 10**17))
        self.snapshot["governance"]["world"].update(shares=str(10**21), curve_mass=str(5 * 10**18))

    def substantive_governance(self, region="fra", heavy=True):
        self.substantive(region, heavy)
        self.phase("governance")
        self.snapshot["governance"]["pass"] = dict(self.snapshot["governance"]["world"], grant_escrow=str(3 * 10**15))
        self.snapshot["governance"]["phase"] = {"Governance": {
            "started": 1350, "duration": 3600, "proposal": {"Grant": {'payments': [{
                "recipient": list(bytes.fromhex(REGISTRY["sgp"][0])), "amount": str(3 * 10**15)}]}}}}

    def confirm_simulated(self, action):
        if self.snapshot['status']['phase'] == 'governance':
            return self.confirm_full_cash(action)
        actor = self.accounts[action['sender_index']]['account']
        kind, op = next(iter(action['operation'].items()))
        amount = int(action['amount_raw'])
        if kind == 'TransferExact': actor['ordinary'] = str(int(actor['ordinary']) - amount)
        elif kind == 'Deposit':
            actor['ordinary'] = str(int(actor['ordinary']) - amount)
            actor['shares'] = str(int(actor['shares']) + amount * 1000)
        elif kind == 'Redeem':
            actor['ordinary'] = str(int(actor['ordinary']) + amount)
            actor['shares'] = str(int(actor['shares']) - int(op['shares']))
        else: self.fail('Unexpected simulated operation')
        actor['ordinary'] = str(int(actor['ordinary']) - int(action['quoted_fee_raw']))
        self.assertGreaterEqual(int(actor['ordinary']), 0)
        actor['nonce'] += 1
        self.policy['history'].append(dict(action, height=self.snapshot['status']['height'], txid=f'{len(self.policy["history"])+1:064x}', confirmed_at=self.now))
        self.policy['cursor'] = len(self.policy['history'])
        self.snapshot['status']['height'] += 1
        self.snapshot['status']['clock'] += self.snapshot['status']['settings']['interval']
        self.now += 20
        self.policy['last_chat_at'] = self.now

    def test_initial_rest_allows_cross_region_transfer_and_bounded_seed(self):
        action = self.choose()
        self.assertEqual(action["kind"], "transfer")
        self.assertIn(action["recipient"], REGISTRY["sgp"] + REGISTRY["ewr"])
        self.assertLessEqual(int(action["amount_raw"]), planner.TRADE)
        self.accounts[1]["account"] = None
        seeded = self.choose()
        self.assertEqual(seeded["kind"], "seed")
        self.assertEqual(seeded["sender_index"], 0)
        self.assertEqual(seeded["recipient"], REGISTRY["fra"][1])
        self.assertLessEqual(int(seeded["amount_raw"]), planner.SEED)

    def test_chat_is_labelled_plaintext_bounded_and_rate_limited(self):
        self.policy["last_chat_at"] = 600
        action = self.choose()
        self.assertEqual(action["kind"], "chat")
        payload = bytes.fromhex(action["data_hex"])
        text = payload.decode('utf-8')
        self.assertFalse(text.startswith('hashstash.'))
        self.assertIn("Automated demo / FRA", text)
        self.assertEqual(int(action["amount_raw"]), planner.CHAT)
        self.assertEqual(action["recipient"], REGISTRY["fra"][(action["sender_index"] + 1) % 3])
        self.policy["last_chat_at"] = self.now - 299
        self.assertNotEqual(self.choose()["kind"], "chat")

    def test_cadence_chain_target_registry_and_pending_guards(self):
        for field, value in (("last_action_at", 981), ("last_action_height", 100)):
            saved = self.policy[field]
            self.policy[field] = value
            self.assertIsNone(self.choose())
            self.policy[field] = saved
        self.snapshot["status"]["chain_id"] = "bb" * 32
        self.assertIsNone(self.choose())
        self.snapshot["status"]["chain_id"] = CHAIN
        self.policy["pending_public_keys"] = REGISTRY["fra"]
        self.assertIsNone(self.choose())

    def check_timestamp_chain_outcomes(self):
        self.snapshot["status"]["settings"] = {"interval": 15}
        self.assertIsNotNone(self.choose())
        self.full_cash_governance(substantive=True)
        self.snapshot["status"]["settings"] = {"interval": 137}
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        action = self.choose()
        self.assertEqual(action["strategy_leg"], "trim_unfavored")
        for kind in ("Unknown", "NotAnOperation"):
            self.assertEqual(planner.cash_guard(self.snapshot, self.accounts[0], {kind: {}}, 1),
                             "unsupported_activity_operation")
        for invalid in ("unknown", None):
            self.snapshot["status"]["phase"] = invalid
            self.assertIsNone(self.choose())

    def test_current_timestamp_chain_preserves_outcome_rules(self):
        self.check_timestamp_chain_outcomes()


    def test_fee_cap_and_no_spending_last_fee_reserve(self):
        self.fee = "1000001"
        self.assertIsNone(self.choose())
        self.fee = "2"
        for actor in self.accounts:
            actor["account"].update(ordinary="1", shares="0")
        self.assertIsNone(self.choose())

    def test_cash_recovery_pays_fee_from_redemption(self):
        self.phase("auction")
        for actor in self.accounts:
            actor["account"]["ordinary"] = "0"
        action = self.choose()
        self.assertEqual(action["kind"], "recover_cash")
        self.assertIsNone(action["operation"]["Redeem"]["decision"])
        self.assertGreater(int(action["operation"]["Redeem"]["min_received"]), int(self.fee))

    def test_rest_deposit_and_redemption_are_quoted_and_slippage_bounded(self):
        self.phase("rest")
        for cursor, kind, field in ((1, "deposit", "min_shares"), (2, "redeem", "min_received")):
            self.policy["cursor"] = cursor
            action = self.choose()
            self.assertEqual(action["kind"], kind)
            operation = action["operation"]["Deposit" if kind == "deposit" else "Redeem"]
            self.assertGreater(int(operation[field]), 0)
            self.assertIsNone(operation["decision"])
            self.assertIsNone(operation["outcome"])

    def test_auction_proposes_only_small_feasible_grant_once_per_round(self):
        self.phase("auction")
        action = self.choose()
        self.assertEqual(action["kind"], "propose_grant")
        self.assertEqual(set(action["operation"]["Propose"]["proposal"]), {"Grant"})
        self.assertLessEqual(int(action["grant_amount_raw"]), planner.GRANT)
        self.assertEqual(action["operation"]["Propose"]["support"], str(planner.SUPPORT))
        self.policy["history"].append(action)
        self.assertNotEqual(self.choose()["kind"], "propose_grant")
        self.policy["history"].clear()
        self.grant_feasible = False
        self.assertNotEqual(self.choose()["kind"], "propose_grant")

    def test_proposal_rationale_is_plain_committed_text_and_part_of_fee_quote(self):
        for substantive in (False, True):
            self.setUp()
            if substantive:
                self.substantive()
            self.phase("auction")
            action = self.choose()
            self.assertEqual(action["kind"], "propose_grant")
            data = bytes.fromhex(action["data_hex"])
            self.assertEqual(data, b"Hashstash automated demo fra round 0")
            self.assertEqual(list(hashlib.sha256(data).digest()), action["operation"]["Propose"]["description"])
            quote = next(params for method, params in self.calls
                         if method == "fee_quote" and params["operation"] == action["operation"])
            self.assertEqual(quote["data_hex"], action["data_hex"])
            self.assertEqual(action["data_hex"], self.choose()["data_hex"])

    def test_pending_proposal_reserves_round_across_all_actors(self):
        self.phase("auction")
        proposed = self.choose()
        self.policy["pending_actions"] = [proposed]
        # A second actor must not submit the same round's deterministic proposal
        # while the first sender awaits confirmation, even without pending flags.
        action = self.choose()
        self.assertNotEqual(action["kind"], "propose_grant")
        self.assertNotEqual(action["sender_index"], proposed["sender_index"])
        self.assertEqual(self.policy["history"], [])
        # A different round is a different intent; the old sender stays occupied.
        self.snapshot["status"]["auction_round"] = 1
        action = self.choose()
        self.assertEqual(action["kind"], "propose_grant")
        self.assertEqual(action["round"], 1)
        self.assertNotEqual(action["sender_index"], proposed["sender_index"])
        # Dropping an expired intent releases its reservation, not a completion.
        self.snapshot["status"]["auction_round"] = 0
        self.policy["pending_actions"] = []
        self.assertEqual(self.choose()["kind"], "propose_grant")

    def test_auction_supports_peer_demo_grant_but_never_parameter_proposal(self):
        self.phase("auction")
        self.policy["history"] = [{"kind": "propose_grant", "round": 0, "sender_index": 0}]
        desc = hashlib.sha256(b"Hashstash automated demo sgp round 0").digest()
        row = {"id": "ac" * 32, "proposal": {"round": 0, "description": list(desc),
               "refund_height": None, "action": {"Grant": {'payments': [{"recipient": list(bytes.fromhex(REGISTRY["fra"][0])),
               "amount": str(planner.GRANT)}]}}}}
        self.snapshot["proposals"] = [row]
        self.assertEqual(self.choose()["kind"], "support")
        saved = copy.deepcopy(row)
        for recipient, amount, description in (("ff" * 32, planner.GRANT, desc),
                                               (REGISTRY["fra"][0], 10**17 + 1, desc),
                                               (REGISTRY["fra"][0], planner.GRANT, b"x" * 32)):
            row["proposal"]["description"] = list(description)
            row["proposal"]["action"]["Grant"] = {"payments": [{"recipient": list(bytes.fromhex(recipient)), "amount": str(amount)}]}
            self.assertNotEqual(self.choose()["kind"], "support")
        row.clear()
        row.update(saved)
        row["proposal"]["action"] = {"Parameter": {"parameter": "Interval", "old": 15, "new": 30}}
        self.assertNotEqual(self.choose()["kind"], "support")

    def test_pending_support_reserves_round_across_all_actors_and_proposals(self):
        self.phase("auction")
        self.policy["history"] = [{"kind": "propose_grant", "round": 0, "sender_index": 0}]
        self.snapshot["proposals"] = [
            {"id": ident * 32, "proposal": {"round": 0, "refund_height": None,
             "description": list(hashlib.sha256(f"Hashstash automated demo {region} round 0".encode()).digest()),
             "action": {"Grant": {'payments': [{"recipient": list(bytes.fromhex(REGISTRY["fra"][0])),
                                   "amount": str(planner.GRANT)}]}}}}
            for ident, region in (("ab", "sgp"), ("ac", "ewr"))]
        support = self.choose()
        self.assertEqual(support["kind"], "support")
        self.policy["pending_actions"] = [{"action": support}]
        action = self.choose()
        self.assertNotEqual(action["kind"], "support")
        self.assertNotEqual(action["sender_index"], support["sender_index"])
        self.policy["pending_actions"] = []
        self.assertEqual(self.choose()["kind"], "support")

    def test_multi_recipient_support_checks_every_recipient_and_aggregate(self):
        self.phase("auction")
        self.policy["history"] = [{"kind": "propose_grant", "round": 0, "sender_index": 0}]
        payments = [{"recipient": list(bytes.fromhex(key)), "amount": str(planner.GRANT // 2)}
                    for key in REGISTRY["fra"][:2]]
        self.snapshot["proposals"] = [{"id": "ac" * 32, "proposal": {
            "round": 0, "refund_height": None,
            "description": list(hashlib.sha256(b"Hashstash automated demo sgp round 0").digest()),
            "action": {"Grant": {"payments": payments}}}}]
        action = self.choose()
        self.assertEqual(action["kind"], "support")
        self.assertEqual(int(action["grant_amount_raw"]), planner.GRANT)
        self.assertEqual(action["recipients"], REGISTRY["fra"][:2])
        for mutation in ("outside", "aggregate", "order", "zero"):
            saved = copy.deepcopy(payments)
            if mutation == "outside": payments[1]["recipient"] = [255] * 32
            elif mutation == "aggregate": payments[1]["amount"] = str(10**17)
            elif mutation == "order": payments.reverse()
            else: payments[1]["amount"] = "0"
            self.assertNotEqual(self.choose()["kind"], "support", mutation)
            payments[:] = saved
        self.assertEqual(self.choose()["kind"], "support")

    def test_withdrawal_rounding_leaves_headroom_below_actual_output_cap(self):
        self.phase("rest")
        self.policy["cursor"] = 2
        for actor in self.accounts:
            actor["account"]["shares"] = str(10**20)
        rpc = self.rpc
        def rounded(method, params):
            result = rpc(method, params)
            if method == "stash_quote" and params["kind"] == "withdraw":
                result["output_hash"] = str(int(result["output_hash"]) + 1)
            return result
        action = planner.plan(self.snapshot, self.accounts, REGISTRY, self.policy, self.now, rounded)
        self.assertEqual(action["kind"], "redeem")
        self.assertLessEqual(int(action["amount_raw"]), planner.TRADE)

    def test_losing_support_refund_requires_rpc_eligibility(self):
        self.phase("rest")
        self.policy["history"] = [{"kind": "support", "round": 0, "proposal": "ab" * 32, "sender_index": 1}]
        self.assertNotEqual(self.choose()["kind"], "refund")
        self.refundable = True
        action = self.choose()
        self.assertEqual(action["kind"], "refund")
        self.assertEqual(action["sender_index"], 1)
        self.policy["history"].append(action)
        self.assertNotEqual(self.choose()["kind"], "refund")

    def test_pending_refund_reserves_exact_support_key_until_settled(self):
        self.phase("rest")
        supported = {"kind": "support", "round": 0, "proposal": "ab" * 32, "sender_index": 1}
        self.policy["history"] = [supported, dict(supported)]
        self.refundable = True
        refund = self.choose()
        self.assertEqual(refund["kind"], "refund")
        self.policy["pending_actions"] = [refund]
        action = self.choose()
        self.assertNotEqual(action["kind"], "refund")
        self.assertNotEqual(action["sender_index"], 1)
        # Another sender's support is a distinct refundable balance, so it is
        # neither consumed nor marked complete by sender 1's pending refund.
        self.policy["history"].append({**supported, "sender_index": 2})
        action = self.choose()
        self.assertEqual(action["kind"], "refund")
        self.assertEqual(action["sender_index"], 2)
        self.policy["pending_actions"] = []
        self.assertEqual(self.choose()["sender_index"], 1)






    def test_guard_rejects_nonce_phase_chain_and_expiry_changes(self):
        action = self.choose()
        account = self.accounts[action["sender_index"]]
        self.assertTrue(planner.still_valid(action, self.snapshot, account))
        for field, value in (("phase", "auction"), ("decision", DECISION), ("chain_id", "bb" * 32),
                             ("height", action["guard"]["height"] + 20)):
            changed = copy.deepcopy(self.snapshot)
            changed["status"][field] = value
            self.assertFalse(planner.still_valid(action, changed, account))
        account["account"]["nonce"] += 1
        self.assertFalse(planner.still_valid(action, self.snapshot, account))

    def test_only_read_rpc_and_inputs_remain_unchanged(self):
        before = copy.deepcopy((self.snapshot, self.accounts, REGISTRY, self.policy))
        first = self.choose()
        self.assertEqual(first, self.choose())
        self.assertEqual(before, (self.snapshot, self.accounts, REGISTRY, self.policy))
        self.assertTrue(set(method for method, _ in self.calls) <= planner.READ_METHODS)

    def test_substantive_profile_is_explicit_and_circulation_is_balance_sized(self):
        bounded = self.choose()
        self.assertLessEqual(int(bounded["amount_raw"]), planner.TRADE)
        self.substantive("sgp")
        self.policy["history"] = [{"kind": "deposit"}] * 3
        action = self.choose()
        spendable = int(self.accounts[0]["account"]["ordinary"]) - 10**9
        self.assertEqual(action["kind"], "transfer")
        self.assertEqual(int(action["amount_raw"]), spendable * 2500 // 10000)
        self.assertGreater(int(action["amount_raw"]), planner.TRADE * 20)
        self.assertEqual(action["persona"], "Rook")
        self.policy["profile"] = "unexpected-profile"
        self.assertIsNone(self.choose())

    def test_substantive_existing_stash_rotates_in_opposing_directions(self):
        choices = []
        for region in ("fra", "sgp"):
            self.setUp()
            self.substantive_governance(region)
            before = int(self.accounts[0]["account"]["shares"])
            action = self.choose()
            self.assertEqual(action["strategy_leg"], "trim_unfavored")
            self.assertEqual(action["operation"]["Redeem"]["outcome"],
                             "Pass" if action["preferred_outcome"] == "Fail" else "Fail")
            self.assertTrue(before * 20 // 100 <= int(action["operation"]["Redeem"]["shares"]) <= before * 60 // 100)
            self.assertGreater(int(action["amount_raw"]), planner.TRADE * 20)
            choices.append(action["preferred_outcome"])
        self.assertEqual(choices, ["Fail", "Pass"])


    def test_substantive_pending_directional_leg_does_not_advance_or_flip(self):
        self.substantive_governance("sgp")
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        action = self.choose()
        self.policy["pending_actions"] = [action]
        self.assertIsNone(self.choose())
        self.policy["pending_actions"] = []
        self.assertEqual(self.choose()["operation"], action["operation"])
        self.confirm_simulated(action)
        # Even if the next quote changes preference, finish this allocation
        # cycle coherently instead of buying both sides in successive calls.
        self.grant_feasible = False
        next_action = self.choose()
        self.assertEqual(next_action["preferred_outcome"], "Pass")
        self.assertNotEqual(next_action["strategy_leg"], "trim_unfavored")

    def test_substantive_grant_targets_scale_with_real_backing(self):
        self.substantive("sgp")
        self.phase("auction")
        action = self.choose()
        self.assertEqual(action["kind"], "propose_grant")
        self.assertEqual(int(action["grant_amount_raw"]), 5 * 10**15)
        self.assertGreater(int(action["amount_raw"]), planner.SUPPORT)
        self.policy["pending_actions"] = [action]
        self.assertNotEqual(self.choose()["kind"], "propose_grant")
        self.policy["pending_actions"] = []
        self.snapshot["governance"]["world"].update(reserve=str(10**21), grant_capacity=str(10**20))
        self.assertEqual(int(self.choose()["grant_amount_raw"]), 5 * 10**18)
        self.policy["consumptive_budget_remaining_raw"] = "0"
        self.assertNotEqual(self.choose()["kind"], "propose_grant")

    def test_substantive_support_depends_on_actual_persona_preference(self):
        def fixture(region):
            self.setUp()
            self.substantive(region)
            self.phase("auction")
            self.policy["history"] = [{"kind": "propose_grant", "round": 0, "sender_index": 0}]
            self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
            self.snapshot["proposals"] = [{"id": "ac" * 32, "proposal": {
                "round": 0, "refund_height": None,
                "description": list(hashlib.sha256(b"Hashstash automated demo ewr round 0").digest()),
                "action": {"Grant": {'payments': [{"recipient": list(bytes.fromhex(REGISTRY["fra"][0])), "amount": str(3 * 10**15)}]}}}}]
        fixture("fra")
        self.assertNotEqual(self.choose()["kind"], "support")
        fixture("sgp")
        supported = self.choose()
        self.assertEqual(supported["kind"], "support")
        self.policy["pending_actions"] = [supported]
        self.assertIsNone(self.choose())

    def test_substantive_chat_is_literal_utf8_rotates_people_and_respects_budget(self):
        self.substantive("fra")
        self.policy["last_chat_at"] = self.now - 90
        action = self.choose()
        payload = bytes.fromhex(action["data_hex"])
        self.assertIn("Automated Demo · Mara —".encode(), payload)
        self.assertNotIn(b"\\u00b7", payload)
        text = payload.decode('utf-8')
        self.assertLessEqual(len(text.encode()), 512)
        self.assertLessEqual(len(payload), 1024)
        self.assertEqual(payload, action['message'].encode('utf-8'))
        self.confirm_simulated(action)
        self.policy["last_chat_at"] = self.now - 89
        self.assertNotEqual(self.choose()["kind"], "chat")
        self.policy["last_chat_at"] = self.now - 90
        self.assertEqual(self.choose()["persona"], "Quinn")
        self.policy["consumptive_budget_remaining_raw"] = "0"
        self.assertNotEqual(self.choose()["kind"], "chat")

    def test_substantive_chat_uses_durable_counts_instead_of_truncated_context(self):
        from unittest.mock import patch
        self.substantive("fra")
        self.policy.update(last_chat_at=self.now - 90, history=[], confirmed_chat_count=514,
                           confirmed_chat_counts=[172, 171, 171])
        with patch('activity_personas.compose_message', return_value='Automated Demo · Quinn — observed facts.') as message:
            action = self.choose()
        self.assertEqual(action['sender_index'], 1)
        self.assertEqual(action['persona'], 'Quinn')
        self.assertEqual(message.call_args.kwargs['sequence'], 171)

    def test_substantive_ordinary_stash_targets_rebalance_meaningful_portions(self):
        self.substantive("fra")
        self.phase("rest")
        action = self.choose()
        self.assertEqual(action["kind"], "deposit")
        self.assertGreater(int(action["amount_raw"]), planner.TRADE * 20)
        self.setUp()
        self.substantive("sgp", heavy=True)
        self.phase("rest")
        action = self.choose()
        self.assertEqual(action["kind"], "redeem")
        self.assertGreater(int(action["amount_raw"]), planner.TRADE * 20)
        self.assertLessEqual(int(action["operation"]["Redeem"]["shares"]), int(self.accounts[0]["account"]["shares"]))

    def test_substantive_valuation_failure_and_end_of_decision_do_not_guess(self):
        self.substantive_governance()
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        rpc = self.rpc
        def no_valuation(method, params):
            return None if method == "stash_quote" else rpc(method, params)
        action = planner.plan(self.snapshot, self.accounts, REGISTRY, self.policy, self.now, no_valuation)
        self.assertEqual(action["kind"], "transfer")
        self.snapshot["governance"]["phase"]["Governance"].update(
            started=self.snapshot["status"]["clock"] - 99, duration=100)
        self.assertEqual(self.choose()["kind"], "transfer")

    def test_substantive_new_cycle_needs_six_target_intervals_remaining(self):
        # The same 120 scheduled seconds permit six observations at 15 seconds,
        # but only four at 30 seconds. Heights cannot substitute for this clock.
        for interval, remaining, can_trade in (
                (15, 120, True), (30, 120, False),
                (15, 90, True), (15, 89, False),
                (30, 180, True), (30, 179, False)):
            with self.subTest(interval=interval, remaining=remaining):
                self.setUp()
                self.full_cash_governance(substantive=True)
                self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
                self.snapshot["status"].update(clock=50000, settings={"interval": interval})
                self.snapshot["governance"]["phase"]["Governance"].update(
                    started=50000 - (3600 - remaining), duration=3600)
                action = self.choose()
                if can_trade:
                    self.assertEqual(action["strategy_leg"], "trim_unfavored")
                else:
                    self.assertEqual(action["kind"], "transfer")
                    self.assertNotIn("strategy_leg", action)

    def test_substantive_missing_clock_does_not_guess_from_height(self):
        self.full_cash_governance(substantive=True)
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        del self.snapshot["status"]["clock"]
        # Height is present and would appear to leave ample time if mistakenly
        # compared with the scheduled-seconds start and duration.
        action = self.choose()
        self.assertEqual(action["kind"], "transfer")
        self.assertNotIn("strategy_leg", action)

    def full_cash_governance(self, substantive=False):
        if substantive:
            self.substantive_governance()
        else:
            self.phase("governance")

    def confirm_full_cash(self, action):
        actor = self.accounts[action["sender_index"]]
        kind, op = next(iter(action["operation"].items()))
        worlds = [actor["account"], actor["pass_account"]]
        if kind == "TransferExact":
            for world in worlds:
                world["ordinary"] = str(int(world["ordinary"]) - int(op["amount"]))
        elif kind in {"Deposit", "Redeem"}:
            world = worlds[op["outcome"] == "Pass"]
            if kind == "Deposit":
                world["ordinary"] = str(int(world["ordinary"]) - int(op["amount"]))
                world["shares"] = str(int(world["shares"]) + int(op["amount"]) * 1000)
            else:
                world["ordinary"] = str(int(world["ordinary"]) + int(action["amount_raw"]))
                world["shares"] = str(int(world["shares"]) - int(op["shares"]))
        else:
            self.fail("Unexpected direct trade operation")
        for world in worlds:
            world["ordinary"] = str(int(world["ordinary"]) - int(action["quoted_fee_raw"]))
            world["nonce"] += 1
            self.assertGreaterEqual(int(world["ordinary"]), 0)
        self.policy["history"].append(dict(action, height=self.snapshot["status"]["height"]))
        self.snapshot["status"]["height"] += 1
        self.snapshot["status"]["clock"] += self.snapshot["status"]["settings"]["interval"]
        self.now += 20
        self.policy["last_chat_at"] = self.now

    def test_current_trade_policy_pays_full_fee_and_does_not_govern_fee_parameter(self):
        self.full_cash_governance(substantive=True)
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        rpc = self.rpc
        for percent in (0, 37, 100):
            def quoted(method, params, percent=percent):
                value = rpc(method, params)
                if method == 'fee_quote':
                    charged = int(value['fee'])
                    value.update(miner_fee=str(charged * percent // 100),
                                 revenue_fee=str(charged - charged * percent // 100),
                                 miner_fee_percent=percent)
                return value
            action = planner.plan(self.snapshot, self.accounts, REGISTRY, self.policy, self.now, quoted)
            self.assertEqual(action['strategy_leg'], 'trim_unfavored')
            self.assertEqual(int(action['quoted_fee_raw']), int(self.fee))
            self.assertIn(next(iter(action['operation'])), ('Deposit', 'Redeem'))
        for kind in ('Unknown', 'NotAnOperation'):
            self.assertEqual(planner.cash_guard(self.snapshot, self.accounts[0], {kind: {}}, 1),
                             'unsupported_activity_operation')
        self.accounts[0]['account']['ordinary'] = '0'
        self.accounts[0]['pass_account']['ordinary'] = '0'
        self.assertIsNone(self.choose())

    def test_current_four_direct_trade_stages_repeat_only_after_own_confirmation(self):
        self.full_cash_governance()
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        seen = []
        for _ in range(5):
            action = self.choose()
            if action["kind"] == "transfer":  # Real circulation is still interleaved.
                self.confirm_full_cash(action)
                action = self.choose()
            seen.append(action["kind"])
            self.confirm_full_cash(action)
        self.assertEqual(seen, ["deposit_pass", "deposit_fail", "redeem_pass", "redeem_fail", "deposit_pass"])
        self.policy["pending_actions"] = [self.choose()]
        self.assertIsNone(self.choose())

    def test_current_buys_selected_cash_without_limiting_it_to_other_world_cash(self):
        self.full_cash_governance()
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        self.accounts[0]["account"]["ordinary"] = str(2 * 10**9)
        self.accounts[0]["pass_account"]["ordinary"] = str(10**15)
        before = int(self.accounts[0]["account"]["ordinary"])
        action = self.choose()
        self.assertEqual(action["kind"], "deposit_pass")
        self.assertGreater(int(action["amount_raw"]), before)
        self.confirm_full_cash(action)
        self.assertEqual(int(self.accounts[0]["account"]["ordinary"]), before - int(self.fee))

    def test_current_shared_transfer_capacity_is_minimum_of_both_worlds(self):
        self.full_cash_governance()
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        self.policy["history"] = [{"kind": "deposit_pass"}] * 3
        self.accounts[0]["account"]["ordinary"] = str(10**16)
        self.accounts[0]["pass_account"]["ordinary"] = str(10**12)
        before = [int(self.accounts[0][field]["ordinary"]) for field in ("account", "pass_account")]
        action = self.choose()
        self.assertEqual(action["kind"], "transfer")
        self.assertLess(int(action["amount_raw"]), min(before) - 10**9)
        self.confirm_full_cash(action)
        for field, cash in zip(("account", "pass_account"), before):
            self.assertEqual(int(self.accounts[0][field]["ordinary"]), cash - int(action["amount_raw"]) - int(self.fee))

    def test_current_pair_must_have_same_nonce_nonnegative_cash_and_both_accounts(self):
        self.full_cash_governance()
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        saved = copy.deepcopy(self.accounts[0])
        for field, value in (("nonce", 3), ("ordinary", "-1")):
            self.accounts[0] = copy.deepcopy(saved)
            self.accounts[0]["pass_account"][field] = value
            self.assertIsNone(self.choose())
        self.accounts[0] = copy.deepcopy(saved)
        self.accounts[0]["pass_account"] = None
        self.assertIsNone(self.choose())

    def test_current_zero_both_cash_cannot_fund_fees_from_one_outcome_redemption(self):
        self.full_cash_governance(substantive=True)
        for actor in self.accounts:
            actor["account"]["ordinary"] = actor["pass_account"]["ordinary"] = "0"
        self.assertIsNone(self.choose())
        self.assertTrue(all(int(a["account"]["shares"]) > 0 for a in self.accounts))
        # A real shared credit to another actor enables a bounded refuel.
        self.accounts[1]["account"]["ordinary"] = self.accounts[1]["pass_account"]["ordinary"] = str(10**14)
        action = self.choose()
        self.assertEqual(action["kind"], "refuel")
        self.assertEqual(action["sender_index"], 1)

    def test_current_redemption_only_credits_selected_world_and_uses_minimum_proceeds(self):
        self.full_cash_governance()
        actor = self.accounts[0]
        actor["account"]["ordinary"] = "1000000"
        actor["pass_account"]["ordinary"] = "0"
        op = {"Redeem": {"outcome": "Pass", "shares": "1000000000", "min_received": "1000000"}}
        self.assertIsNone(planner.cash_guard(self.snapshot, actor, op, 1000000))
        op["Redeem"]["min_received"] = "999999"
        self.assertEqual(planner.cash_guard(self.snapshot, actor, op, 1000000), "waiting_for_cash_in_both_outcomes")
        op["Redeem"]["min_received"] = "99999999999999"
        actor["account"]["ordinary"] = "999999"
        self.assertEqual(planner.cash_guard(self.snapshot, actor, op, 1000000), "waiting_for_cash_in_both_outcomes")

    def test_current_substantive_cycle_trims_then_buys_and_holds_six_blocks(self):
        self.full_cash_governance(substantive=True)
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        first = self.choose()
        self.assertEqual(first["strategy_leg"], "trim_unfavored")
        self.confirm_full_cash(first)
        second = self.choose()
        self.assertEqual(second["strategy_leg"], "build_preferred")
        self.assertEqual(second["operation"]["Deposit"]["outcome"], first["preferred_outcome"])
        self.confirm_full_cash(second)
        self.assertNotIn((self.choose() or {}).get("strategy_leg"), {"trim_unfavored", "build_preferred"})
        self.snapshot["status"]["height"] += 6
        self.snapshot["status"]["clock"] += 6 * self.snapshot["status"]["settings"]["interval"]
        self.assertEqual(self.choose()["strategy_cycle"], 1)

    def native(self):
        self.substantive()
        self.policy.update(profile=planner.NATIVE_PROFILE, consumptive_budget_remaining_raw="0")

    def test_native_grant_uses_revenue_support_and_half_reserve_without_demo_caps(self):
        self.native()
        self.phase("auction")
        self.snapshot["governance"]["world"].update(reserve=str(10**18), revenue=str(2 * 10**17),
                                                     grant_capacity=str(12 * 10**17))
        action = self.choose()
        self.assertEqual(action["kind"], "propose_grant")
        support = int(action["operation"]["Propose"]["support"])
        self.assertEqual(int(action["grant_amount_raw"]), 7 * 10**17 + support + int(action['quoted_fee_raw']))
        self.assertNotIn("data_hex", action)
        text = planner.proposal_description("fra", 0, planner.NATIVE_PROFILE).encode()
        self.assertEqual(hashlib.sha256(text).digest(), bytes(action["operation"]["Propose"]["description"]))

    def test_native_grant_never_exceeds_real_backing_or_an_unfundable_quote(self):
        self.native()
        self.phase("auction")
        self.snapshot["governance"]["world"].update(reserve=str(10**18), revenue="0", grant_capacity=str(10**17))
        self.assertNotEqual((self.choose() or {}).get('kind'), 'propose_grant')
        self.grant_feasible = False
        self.assertNotEqual((self.choose() or {}).get("kind"), "propose_grant")

    def test_native_proposal_quotes_and_intent_have_no_message_data(self):
        self.native()
        self.phase("auction")
        self.snapshot["governance"]["world"].update(reserve=str(10**18), revenue="0",
                                                     grant_capacity=str(12 * 10**17))
        action = self.choose()
        self.assertEqual(action["kind"], "propose_grant")
        self.assertNotIn("data_hex", action)
        quotes = [params for method, params in self.calls
                  if method == "fee_quote" and "Propose" in params["operation"]]
        self.assertEqual(len(quotes), 2)
        self.assertTrue(all("data_hex" not in quote for quote in quotes))
        self.assertEqual(action, self.choose())

    def test_native_proposal_commitments_distinguish_regions_and_rounds(self):
        commitments = {hashlib.sha256(planner.proposal_description(region, round_id,
                       planner.NATIVE_PROFILE).encode()).digest()
                       for region in REGISTRY for round_id in (0, 1, 2)}
        self.assertEqual(len(commitments), 9)
        self.assertNotIn(hashlib.sha256(b"").digest(), commitments)

    def test_native_support_matches_peer_commitment_without_message_data(self):
        self.substantive("sgp")
        self.policy["profile"] = planner.NATIVE_PROFILE
        self.phase("auction")
        self.policy["history"] = [{"kind": "propose_grant", "round": 0, "sender_index": 0}]
        self.accounts[1]["pending"] = self.accounts[2]["pending"] = True
        commitment = hashlib.sha256(planner.proposal_description("ewr", 0, planner.NATIVE_PROFILE).encode()).digest()
        self.snapshot["proposals"] = [{"id": "ac" * 32, "proposal": {
            "round": 0, "refund_height": None, "description": list(commitment),
            "action": {"Grant": {"payments": [{"recipient": list(bytes.fromhex(REGISTRY["fra"][0])),
                                             "amount": str(3 * 10**15)}]}}}}]
        supported = self.choose()
        self.assertEqual(supported["kind"], "support")
        self.assertNotIn("data_hex", supported)
        self.snapshot["proposals"][0]["proposal"]["description"] = list(hashlib.sha256(b"").digest())
        self.assertNotEqual((self.choose() or {}).get("kind"), "support")

    def test_native_trades_use_small_available_balance_and_actual_fee(self):
        self.native()
        for actor in self.accounts:
            actor["account"].update(ordinary="10000", shares="0")
        action = self.choose()
        self.assertIsNotNone(action)
        self.assertGreater(int(action["amount_raw"]), 0)
        self.assertLess(int(action["amount_raw"]), 10000)
        self.assertEqual(int(action["max_fee_raw"]), int(self.fee))
        self.fee = "2000000"
        for actor in self.accounts:
            actor["account"]["ordinary"] = "100000000"
        action = self.choose()
        self.assertIsNotNone(action)
        self.assertEqual(action["quoted_fee_raw"], self.fee)
        self.assertLessEqual(int(action["amount_raw"]) + 3 * int(self.fee), 100000000)

    def test_native_ordinary_buy_reaches_full_persona_target_without_damping(self):
        self.native()
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        self.accounts[0]['account'].update(ordinary='10000', shares='0')
        action = self.choose()
        self.assertEqual(action['kind'], 'deposit')
        self.assertEqual(int(action['amount_raw']), (10000 - 3 * int(self.fee)) * 7500 // 10000)

    def test_native_ordinary_sale_reaches_full_gap_not_fraction_of_position(self):
        self.substantive('ewr')
        self.policy['profile'] = planner.NATIVE_PROFILE
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        self.accounts[0]['account'].update(ordinary='1000', shares='99000000')
        action = self.choose()
        target = (1000 - 3 * int(self.fee) + 99000) * 4500 // 10000
        self.assertEqual(action['kind'], 'redeem')
        self.assertEqual(int(action['amount_raw']), 99000 - target)
        self.assertGreater(int(action['amount_raw']), 99000 // 4)

    def test_native_outcome_rebalance_keeps_sable_fail_preference_and_cash(self):
        self.substantive_governance('ewr')
        self.policy['profile'] = planner.NATIVE_PROFILE
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        for world in ('account', 'pass_account'):
            self.accounts[0][world].update(ordinary='10000', shares='0')
        action = self.choose()
        self.assertEqual(action['preferred_outcome'], 'Fail')
        self.assertEqual(action['strategy_leg'], 'rebalance_preferred')
        self.assertEqual(action['operation']['Deposit']['outcome'], 'Fail')
        self.assertEqual(int(action['amount_raw']), (10000 - 3 * int(self.fee)) * 4500 // 10000)
        self.assertLess(int(action['amount_raw']), 10000 // 2)
        self.confirm_full_cash(action)
        self.assertNotIn((self.choose() or {}).get('strategy_leg'), {'trim_unfavored', 'rebalance_preferred'})

    def test_native_unfavored_fee_dust_does_not_block_favored_rebalance(self):
        self.substantive_governance('ewr')
        self.policy['profile'] = planner.NATIVE_PROFILE
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        self.accounts[0]['account'].update(ordinary='10000', shares='0')
        self.accounts[0]['pass_account'].update(ordinary='10000', shares='2000')
        action = self.choose()
        self.assertEqual(action['preferred_outcome'], 'Fail')
        self.assertEqual(action['strategy_leg'], 'rebalance_preferred')
        self.assertEqual(action['operation']['Deposit']['outcome'], 'Fail')
        self.assertEqual(action['amount_raw'], '4497')
        self.assertFalse(any(method == 'stash_quote' and params.get('kind') == 'withdraw'
                             and params.get('outcome') == 'pass' for method, params in self.calls))

    def test_native_exits_unfavored_world_then_rebalances_favored_overweight(self):
        self.substantive_governance('ewr')
        self.policy['profile'] = planner.NATIVE_PROFILE
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        shares = int(self.accounts[0]['pass_account']['shares'])
        first = self.choose()
        self.assertEqual(first['preferred_outcome'], 'Fail')
        self.assertEqual(first['operation']['Redeem']['outcome'], 'Pass')
        self.assertEqual(int(first['operation']['Redeem']['shares']), shares)
        self.confirm_full_cash(first)
        second = self.choose()
        self.assertEqual(second['strategy_leg'], 'rebalance_preferred')
        self.assertEqual(second['operation']['Redeem']['outcome'], 'Fail')
        value = int(self.accounts[0]['account']['shares']) // 1000
        cash = int(self.accounts[0]['account']['ordinary']) - 3 * int(self.fee)
        self.assertEqual(int(second['amount_raw']), value - (cash + value) * 4500 // 10000)

    def test_native_rebalancing_does_not_replace_pending_or_completed_old_cycle(self):
        self.substantive_governance('ewr')
        self.policy['profile'] = planner.NATIVE_PROFILE
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        self.policy['pending_public_keys'] = [self.accounts[0]['public_key']]
        self.assertIsNone(self.choose())
        self.policy['pending_public_keys'] = []
        self.policy['history'] = [dict(kind='deposit_fail', sender_index=0, decision=DECISION,
            profile=planner.NATIVE_PROFILE, strategy_cycle=0, strategy_leg='build_preferred',
            preferred_outcome='Fail', height=self.snapshot['status']['height'])]
        self.assertNotIn((self.choose() or {}).get('strategy_leg'), {'trim_unfavored', 'rebalance_preferred'})

    def test_native_profile_does_not_propose_during_rest_or_repeat_pending_round(self):
        self.native()
        self.assertNotEqual((self.choose() or {}).get("kind"), "propose_grant")

    def test_native_first_auction_builds_real_stash_before_any_fee_dust_proposal(self):
        self.native()
        self.phase("auction")
        self.snapshot["governance"]["world"].update(reserve="0", curve_mass="0", shares="0", revenue="3", grant_capacity="3")
        for actor in self.accounts:
            actor["account"]["shares"] = "0"
        self.accounts[0]["pending"] = True
        action = self.choose()
        self.assertEqual(action["kind"], "deposit")
        self.assertGreater(int(action["amount_raw"]), 3)
        self.assertEqual(action["strategy_reason"], "build_ordinary_backing_before_curve_proposal")
        self.assertNotIn("grant_quote", [method for method, _ in self.calls])

    def test_native_will_not_propose_a_revenue_only_clipped_grant(self):
        self.native()
        self.phase("auction")
        self.snapshot["governance"]["world"].update(reserve="100", curve_mass="100", shares="100", revenue="3", grant_capacity="50")
        action = self.choose()
        self.assertNotEqual((action or {}).get("kind"), "propose_grant")

    def test_native_does_not_clip_half_reserve_target_to_zero_draw_after_fee(self):
        self.native()
        self.phase('auction')
        self.snapshot['governance']['world'].update(reserve='100', curve_mass='100', shares='100', revenue='3', grant_capacity='83')
        self.accounts[0]['account'].update(ordinary='3954', shares='0')
        self.accounts[1]['pending'] = self.accounts[2]['pending'] = True
        self.assertNotEqual((self.choose() or {}).get('kind'), 'propose_grant')
        self.phase("auction")
        action = self.choose()
        self.policy["pending_actions"] = [action]
        self.assertNotEqual((self.choose() or {}).get("kind"), "propose_grant")



if __name__ == "__main__":
    unittest.main()
