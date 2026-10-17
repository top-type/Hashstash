"""Independent network-audit comparisons preserve exact marginal prices, and
the shared HTTP helper waits out only explicit admission refusals."""
import http.server
import json
import threading
import unittest

import test_network
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

    def test_an_empty_curve_is_no_observation(self):
        empty = world(0, 0)
        self.assertFalse(pass_leads(empty, empty, 0))
        for margin in (0, (1 << 64) - 1):
            self.assertFalse(pass_leads(empty, world(1, 10**60), margin))
            self.assertFalse(pass_leads(world(1, 10**60), empty, margin))


class ScriptedNode(http.server.BaseHTTPRequestHandler):
    """Answers each POST with the next scripted (status, headers, body)."""
    script = []
    seen = []

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        status, headers, body = self.script.pop(0)
        self.seen.append(status)
        data = json.dumps(body).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class AdmissionRetryTests(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(('127.0.0.1', 0), ScriptedNode)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        ScriptedNode.seen = []

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_refusals_are_waited_out_and_resent(self):
        refused = {'error': {'message': 'network rate budget exhausted'}}
        ScriptedNode.script = [(429, {'Retry-After': '0'}, refused),
                               (503, {'Retry-After': '0'}, refused),
                               (200, {}, {'transaction_id': 'ab'})]
        before = test_network.admission_refusals()
        self.assertEqual(test_network.http(self.port, '/api/wallet', {}), {'transaction_id': 'ab'})
        self.assertEqual(ScriptedNode.seen, [429, 503, 200])
        self.assertEqual(test_network.admission_refusals() - before, 2)

    def test_other_failures_are_not_retried(self):
        ScriptedNode.script = [(400, {}, {'error': {'message': 'invalid'}})]
        with self.assertRaisesRegex(RuntimeError, 'HTTP 400'):
            test_network.http(self.port, '/rpc', {})
        self.assertEqual(ScriptedNode.seen, [400])

    def test_retries_end_at_the_deadline(self):
        limit = test_network.ADMISSION_RETRY_SECONDS
        test_network.ADMISSION_RETRY_SECONDS = 0.5
        try:
            ScriptedNode.script = [(429, {'Retry-After': '0'}, {})] * 50
            with self.assertRaisesRegex(RuntimeError, 'HTTP 429'):
                test_network.http(self.port, '/rpc', {})
        finally:
            test_network.ADMISSION_RETRY_SECONDS = limit
        self.assertLess(len(ScriptedNode.seen), 50)

    def test_retry_delays_are_bounded(self):
        self.assertEqual(test_network.retry_delay('2'), 2.0)
        self.assertEqual(test_network.retry_delay('0'), 0.1)
        self.assertEqual(test_network.retry_delay('86400'), 30.0)
        self.assertEqual(test_network.retry_delay(None), 1.0)
        self.assertEqual(test_network.retry_delay('Wed, 21 Oct 2015 07:28:00 GMT'), 1.0)


if __name__ == '__main__':
    unittest.main()
