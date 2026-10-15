"""Pure persona composition tests; no network, transactions, keys or mining."""
import copy
import unittest

import activity_personas as p


class PersonaTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {"status": {"phase": "governance", "height": 900,
                                    "auction_round": None},
                         "governance": {"phase": {"Governance": {"round": 4}},
                                        "world": {"reserve": str(20 * 1000),
                                                  "grant_capacity": str(1000)}}}
        self.metrics = {"grant_amount_raw": str(30),
                        "grant_funded_raw": str(30), "grant_feasible": True,
                        "pass_price_numerator": "100", "pass_price_denominator": "3",
                        "fail_price_numerator": "100", "fail_price_denominator": "3"}

    def test_nine_fixed_distinct_profiles_and_owned_copies(self):
        profiles = [p.profile_for(r, i) for r in p.REGIONS for i in range(3)]
        self.assertEqual(len({x["name"] for x in profiles}), 9)
        for profile in profiles:
            self.assertIn("Automated Demo · ", profile["label"])
            self.assertTrue(1500 <= profile["commitment_bps"] <= 6000)
            self.assertTrue(1000 <= profile["circulation_bps"] <= 3000)
            self.assertTrue(2000 <= profile["stash_adjustment_bps"] <= 6000)
            self.assertTrue(100 <= profile["grant_request_bps"] <= 500)
            self.assertTrue(0 < profile["stash_target_bps"] < 10000)
        profiles[0]["name"] = "changed"
        self.assertEqual(p.profile_for("fra", 0)["name"], "Mara")
        for r, i in (("bad", 0), ("fra", -1), ("ewr", 3), ("fra", True)):
            with self.assertRaises(ValueError):
                p.profile_for(r, i)

    def test_same_grant_produces_reasoned_opposing_positions(self):
        conservative = p.evaluate(self.snapshot, p.profile_for("fra", 0), self.metrics)
        builder = p.evaluate(self.snapshot, p.profile_for("sgp", 0), self.metrics)
        self.assertEqual(conservative["preferred_outcome"], "Fail")
        self.assertEqual(builder["preferred_outcome"], "Pass")
        self.assertEqual(builder["observed"]["grant_fraction_bps"], 300)
        self.assertEqual(builder["observed"]["funding_bps"], 10000)
        self.assertIn("larger than my preferred", conservative["reasons"][0])
        self.assertIn("fits", builder["reasons"][0])

    def test_native_half_backing_grant_keeps_opposing_preferences_without_cutoff(self):
        metrics = dict(self.metrics, grant_amount_raw=str(500), grant_funded_raw=str(500))
        conservative = p.evaluate(self.snapshot, p.profile_for("fra", 0, "native-balance-v1"), metrics)
        builder = p.evaluate(self.snapshot, p.profile_for("sgp", 0, "native-balance-v1"), metrics)
        self.assertEqual(conservative["preferred_outcome"], "Fail")
        self.assertEqual(builder["preferred_outcome"], "Pass")
        self.assertTrue(all("grant allocation" not in reason for reason in conservative["reasons"] + builder["reasons"]))

    def test_native_composition_preserves_native_strategy_and_short_explicit_label(self):
        metrics = dict(self.metrics, grant_amount_raw=str(500), grant_funded_raw=str(500))
        profile = p.profile_for('sgp', 0, 'native-balance-v1')
        text = p.compose_message(self.snapshot, profile, metrics=metrics)
        self.assertTrue(text.startswith('Rook · Automated — '))
        self.assertIn('favors PASS', text)
        self.assertNotIn('Demo', text)
        self.assertEqual(p.profile_for('sgp', 0)['label'], 'Automated Demo · Rook')

    def test_native_large_grant_rationale_does_not_call_it_small(self):
        self.snapshot["governance"]["world"]["grant_capacity"] = "10000"
        metrics = dict(self.metrics, grant_amount_raw="5168", grant_funded_raw="5168")
        profile = p.profile_for('fra', 0, 'native-balance-v1')
        result = p.evaluate(self.snapshot, profile, metrics)
        self.assertEqual(result['observed']['grant_fraction_bps'], 5168)
        self.assertNotIn('small cost', result['rationale'])
        self.assertIn('51.68%', p.compose_message(self.snapshot, profile, metrics=metrics))

    def test_small_grant_fail_rationale_explains_conservatism(self):
        metrics = dict(self.metrics, grant_amount_raw=str(10**13), grant_funded_raw=str(10**13))
        result = p.evaluate(self.snapshot, p.profile_for("fra", 0), metrics)
        self.assertEqual(result["preferred_outcome"], "Fail")
        self.assertIn("preserving capacity", result["rationale"])

    def test_builder_changes_position_when_request_is_large_or_unfundable(self):
        profile = p.profile_for("sgp", 0)
        self.assertEqual(p.evaluate(self.snapshot, profile, self.metrics)["preferred_outcome"], "Pass")
        for change in ({"grant_amount_raw": str(9 * 10**16)}, {"grant_feasible": False}):
            result = p.evaluate(self.snapshot, profile, dict(self.metrics, **change))
            self.assertEqual(result["preferred_outcome"], "Fail")

    def test_trader_responds_to_relative_exact_rational_prices(self):
        profile = p.profile_for("ewr", 1)
        cheap = p.evaluate(self.snapshot, profile, dict(self.metrics, pass_price_numerator="90"))
        expensive = p.evaluate(self.snapshot, profile, dict(self.metrics, pass_price_numerator="110"))
        self.assertEqual(cheap["observed"]["pass_fail_price_bps"], 9000)
        self.assertEqual(expensive["observed"]["pass_fail_price_bps"], 11000)
        self.assertEqual(cheap["preferred_outcome"], "Pass")
        self.assertEqual(expensive["preferred_outcome"], "Fail")

    def test_unknown_invalid_and_zero_denominators_are_not_fabricated(self):
        result = p.evaluate({}, p.profile_for("fra", 1),
                            {"grant_amount_raw": -3, "grant_feasible": "true",
                             "reserve_raw": 1.5, "grant_capacity_raw": True,
                             "pass_price_numerator": "10", "pass_price_denominator": "0"})
        self.assertNotIn("grant_amount_raw", result["observed"])
        self.assertNotIn("grant_feasible", result["observed"])
        self.assertNotIn("reserve_raw", result["observed"])
        self.assertNotIn("grant_capacity_raw", result["observed"])
        self.assertNotIn("pass_fail_price_bps", result["observed"])
        text = p.compose_message({}, p.profile_for("fra", 1), sequence=0)
        self.assertIn("does not establish", text)
        self.assertNotIn("confirmed", text)

    def test_message_facts_use_display_hashes_and_actual_round_funding_price(self):
        profile = p.profile_for("ewr", 1)
        messages = [p.compose_message(self.snapshot, profile, metrics=self.metrics, sequence=i) for i in range(8)]
        combined = " ".join(messages)
        self.assertIn("0.03 hashes", combined)
        self.assertIn("3% of available grant capacity", combined)
        self.assertIn("available grant capacity is", combined)
        self.assertIn("funding is 0.03 hashes", combined)
        self.assertIn("equal to FAIL's", combined)
        self.assertIn("funding round 4", combined)
        self.assertNotIn("exa", combined)
        self.assertEqual(p._hashes(1000), "1 hash")
        self.assertEqual(p._hashes(1), "0.001 hashes")
        self.assertEqual(p._hashes(1), "0.001 hashes")

    def test_nonzero_small_grant_does_not_claim_zero_percent(self):
        self.snapshot["governance"]["world"]["grant_capacity"] = "100000"
        metrics = dict(self.metrics, grant_amount_raw="1")
        text = p.compose_message(self.snapshot, p.profile_for("sgp", 0), metrics=metrics)
        self.assertIn("less than 0.01%", text)

    def test_price_gaps_below_one_basis_point_do_not_claim_equality(self):
        for numerator, direction in (("1000038", "higher"), ("999962", "lower")):
            metrics = dict(self.metrics, pass_price_numerator=numerator, fail_price_numerator="1000000")
            result = p.evaluate(self.snapshot, p.profile_for("ewr", 1), metrics)
            facts = " ".join(p._facts(self.snapshot, result))
            self.assertIn("within 0.01%", facts)
            self.assertIn("slightly " + direction, facts)
            self.assertNotIn("equal to", facts)
            self.assertNotIn("0.01% above", facts)

    def test_rounded_price_and_amount_facts_are_marked_approximate(self):
        metrics = dict(self.metrics, pass_price_numerator="103251", fail_price_numerator="100000")
        facts = " ".join(p._facts(self.snapshot, p.evaluate(self.snapshot, p.profile_for("ewr", 1), metrics)))
        self.assertIn("about 3.25% above", facts)
        self.assertTrue(p._hashes(10**30).startswith("about "))

    def test_chat_rotation_uses_only_region_confirmed_chats(self):
        history = []
        for count in range(12):
            self.assertEqual(p.next_speaker("fra", history), count % 3)
            self.assertEqual(p.speaker_sequence("fra", count % 3, history), count // 3)
            history += [{"kind": "transfer", "sender_index": 2, "state": "confirmed"},
                        {"kind": "chat", "sender_index": 0, "state": "pending"},
                        {"kind": "chat", "sender_index": 1, "region": "sgp", "state": "confirmed"}]
            self.assertEqual(p.next_speaker("fra", history), count % 3)
            history.append({"kind": "chat", "sender_index": count % 3, "txid": str(count),
                            "confirmed_at": 1000 + count, "height": 100 + count})

    def test_pending_and_planned_actions_never_claim_confirmation(self):
        profile = p.profile_for("fra", 0)
        for item in ({"kind": "deposit_pass", "sender_index": 0, "height": 899},
                     {"kind": "deposit_pass", "sender_index": 0, "height": 899,
                      "txid": "ab" * 32, "status": "pending"}):
            text = p.compose_message(self.snapshot, profile, metrics=self.metrics, history=[item], sequence=2)
            self.assertNotIn("confirmed at block", text)

    def test_personal_actions_require_own_confirmed_receipt(self):
        profile = p.profile_for("fra", 0)
        confirmed = {"kind": "deposit_pass", "sender_index": 0, "height": 899,
                     "txid": "ab" * 32, "confirmed_at": 1000}
        text = p.compose_message(self.snapshot, profile, metrics=self.metrics, history=[confirmed], sequence=2)
        self.assertIn("My demo account's PASS Stash purchase confirmed at block 899", text)
        for change in ({"sender_index": 1}, {"region": "sgp"}):
            text = p.compose_message(self.snapshot, profile, metrics=self.metrics,
                                     history=[dict(confirmed, **change)], sequence=2)
            self.assertNotIn("confirmed at block", text)

    def test_personal_action_uses_latest_confirmed_block_even_if_history_is_unordered(self):
        profile = p.profile_for("ewr", 1)
        history = [{"kind": "redeem_pass", "sender_index": 1, "height": 899, "state": "confirmed"},
                   {"kind": "deposit_pass", "sender_index": 1, "height": 870, "state": "confirmed"}]
        text = p.compose_message(self.snapshot, profile, metrics=self.metrics, history=history, sequence=2)
        self.assertIn("PASS redemption confirmed at block 899", text)

    def test_utf8_protocol_bound_whole_sentences_and_contextual_rotation(self):
        for r in p.REGIONS:
            for i in range(3):
                profile = p.profile_for(r, i)
                messages = [p.compose_message(self.snapshot, profile, metrics=self.metrics, sequence=n) for n in range(40)]
                self.assertGreaterEqual(len(set(messages)), 12)
                for text in messages:
                    self.assertLessEqual(len(text.encode("utf-8")), 512)
                    self.assertTrue(text.startswith(profile["label"] + " — "))
                    self.assertIn("automated", text.lower())
                    self.assertTrue(text.endswith((".", "?")))
                    # Decimal points do not count as sentence boundaries.
                    self.assertTrue(2 <= len(__import__('re').findall(r'[.!?](?: |$)', text)) <= 4)
                    wire = text.encode('utf-8')
                    self.assertLessEqual(len(wire), 512)
                    self.assertNotIn(b'\\u00b7', wire)
        huge = dict(self.metrics, grant_amount_raw=str(2**511), grant_funded_raw=str(2**511))
        self.assertLessEqual(len(p.compose_message(self.snapshot, p.profile_for("fra", 0), metrics=huge).encode()), 512)

    def test_named_challenges_are_arguments_not_claimed_observed_messages(self):
        profile = p.profile_for("sgp", 0)
        text = p.compose_message(self.snapshot, profile, metrics=self.metrics, sequence=1)
        self.assertIn("Quinn,", text)
        for forbidden in ("you said", "you promised", "delivered", "guaranteed profit"):
            self.assertNotIn(forbidden, text)

    def test_deterministic_and_inputs_are_not_modified(self):
        profile = p.profile_for("fra", 2)
        before = copy.deepcopy((self.snapshot, profile, self.metrics))
        first = p.compose_message(self.snapshot, profile, metrics=self.metrics, sequence=7)
        self.assertEqual(first, p.compose_message(self.snapshot, profile, metrics=self.metrics, sequence=7))
        self.assertEqual(before, (self.snapshot, profile, self.metrics))


if __name__ == "__main__":
    unittest.main()
