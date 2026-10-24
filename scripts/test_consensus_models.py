"""The committed consensus vectors are exactly what the independent models compute.

tests/data/clearing-vectors.json and tests/data/consensus-vectors.json are
checked against the node by Rust tests; these checks keep them reproducible
from scripts/clearing_model.py and scripts/consensus_model.py, which follow the
normative text in docs/SPECIFICATION.md and docs/CONSENSUS.md.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import clearing_model  # noqa: E402
import consensus_model  # noqa: E402


class ClearingModel(unittest.TestCase):
    def test_vectors_match_the_model(self):
        with open(clearing_model.VECTORS) as f:
            committed = json.load(f)["vectors"]
        self.assertEqual(committed, clearing_model.compute())

    def test_vectors_conserve_and_respect_bounds(self):
        for v in clearing_model.compute():
            w = {k: int(x) for k, x in v["world"].items()}
            e = v["expected"]
            cash = sum(int(i) for i, _ in e["buys"])
            bought = sum(int(o) for _, o in e["buys"])
            sold = sum(int(i) for i, _ in e["sells"])
            paid = sum(int(o) for _, o in e["sells"])
            if w["shares"]:
                self.assertEqual(w["reserve"] + cash, int(e["reserve"]) + paid, v["name"])
                self.assertEqual(w["shares"] + bought, int(e["shares"]) + sold, v["name"])
            self.assertLessEqual(e["curve_evaluations"], v["work_limit"], v["name"])
            for (i, _), amount in zip(e["buys"] + e["sells"], v["buys"] + v["sells"]):
                self.assertLessEqual(int(i), int(amount), v["name"])

    def test_directed_logarithms_enclose_the_exact_value(self):
        import decimal
        decimal.getcontext().prec = 500
        for n, d, bits in [(2, 1, 192), (3, 2, 384), (10 ** 6 + 7, 10 ** 6, 448), (1 << 90, 3, 1088)]:
            low, high = clearing_model.log_bounds(n, d, bits)
            exact = (decimal.Decimal(n) / decimal.Decimal(d)).ln() * (decimal.Decimal(2) ** bits)
            self.assertLessEqual(decimal.Decimal(low), exact)
            self.assertLessEqual(exact, decimal.Decimal(high))
            self.assertLess(high - low, 1 << 20)

    def test_simplest_fraction(self):
        self.assertEqual(clearing_model.simplest_fraction(20, 10, 22, 10), (2, 1))
        self.assertEqual(clearing_model.simplest_fraction(209, 100, 211, 100), (21, 10))


class ConsensusModel(unittest.TestCase):
    def test_vectors_match_the_model(self):
        with open(consensus_model.VECTORS) as f:
            committed = json.load(f)
        self.assertEqual(committed, consensus_model.compute(committed["auction"]["chain_id"]))

    def test_public_keys_are_bip340_x_coordinates(self):
        self.assertEqual(consensus_model.x_only(1), consensus_model.G[0].to_bytes(32, "big"))
        self.assertEqual(consensus_model.x_only(2).hex(),
                         "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

    def test_asert_rounds_toward_zero_and_clamps(self):
        initial = consensus_model.target_from_bits(0x1C0FFFF0)
        limit = consensus_model.target_from_bits(0x1D00FFFF)
        self.assertEqual(consensus_model.asert(initial, 0, 900, limit), initial)
        self.assertLess(consensus_model.asert(initial, -1, 900, limit), initial)
        self.assertEqual(consensus_model.asert(initial, 10 ** 9, 900, limit), limit)
        self.assertEqual(consensus_model.asert(initial, -10 ** 9, 900, limit), 1)


if __name__ == "__main__":
    unittest.main()
