"""Independent network-audit comparisons preserve exact marginal prices."""
import unittest

from test_reserve_network import pass_leads


def world(mass, shares):
    return {'curve_mass': str(mass), 'shares': str(shares)}


class PriceComparisonTests(unittest.TestCase):
    def test_sub_quote_prices_still_have_a_strict_winner(self):
        self.assertTrue(pass_leads(world(2, 10**60), world(1, 10**60), 0))
        self.assertFalse(pass_leads(world(1, 10**60), world(2, 10**60), 0))

    def test_margin_boundary_is_strict_and_fractional(self):
        self.assertFalse(pass_leads(world(11, 100), world(1, 10), 1000))
        self.assertTrue(pass_leads(world(1100001, 10000000), world(1, 10), 1000))

    def test_empty_curves_have_zero_price(self):
        empty = world(0, 0)
        self.assertFalse(pass_leads(empty, empty, 0))
        self.assertFalse(pass_leads(empty, world(1, 10**60), 0))
        self.assertTrue(pass_leads(world(1, 10**60), empty, (1 << 64) - 1))


if __name__ == '__main__':
    unittest.main()
