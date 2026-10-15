"""Load fixtures must fund each input before the block, including self-payments."""
import unittest
from unittest.mock import patch

import test_load


class LoadFundingTests(unittest.TestCase):
    def test_fee_budget_alone_cannot_finance_a_wave_of_self_payments(self):
        # Four one-atom self-payments cost seven fees in this fixture. An opening
        # balance of eight could fund the old sequential-credit assumption, but
        # cannot reserve four inputs plus those fees for the same block.
        cash, height = 8, 1
        mining_calls = []

        def rpc(_port, method, params=None):
            nonlocal cash, height
            if method == 'status':
                return {'height': height, 'phase': 'rest',
                        'settings': {'minimum_fee_rate': 1}}
            if method == 'fee_quote':
                return {'weight': '1000'}
            if method == 'account':
                return {'account': {'ordinary': str(cash)}}
            if method == 'mine':
                mining_calls.append(params['count'])
                cash += params['count']
                height += params['count']
                return {}
            self.fail('unexpected RPC method: ' + method)

        with patch.object(test_load, 'rpc', side_effect=rpc):
            result = test_load.prepare_load(1234, '11' * 32, 1, 4, 4)
        self.assertEqual(mining_calls, [4])
        self.assertEqual(result['required_ordinary'], '11')
        self.assertEqual(result['funded_ordinary'], '12')


if __name__ == '__main__':
    unittest.main()
