"""Unit checks for the chaos soak harness's signing, wire patching and port layout."""
import random
import unittest

import soak
from chain_activity import make_body

SENDER = soak.Key('sender', 7)
RECIPIENT = soak.Key('recipient', 7)
ANCHOR = bytes(range(32))


def body(nonce=5, fee=300, expiry=12, anchor=ANCHOR):
    operation = {'TransferExact': {'recipient': RECIPIENT.hex, 'amount': '1000'}}
    return make_body(SENDER.hex, nonce, fee, anchor.hex(), expiry, operation, 'ab')[1]


class SignerTests(unittest.TestCase):
    def test_signer_reproduces_the_official_bip340_vectors(self):
        self.assertGreaterEqual(soak.self_test_signatures(), 4)

    def test_keys_are_deterministic_per_seed_and_label(self):
        self.assertEqual(soak.Key('sender', 7).public, SENDER.public)
        self.assertNotEqual(soak.Key('sender', 8).public, SENDER.public)
        self.assertNotEqual(RECIPIENT.public, SENDER.public)

    def test_signed_transactions_append_exactly_one_signature(self):
        raw = soak.sign_body(SENDER, body(), random.Random(1))
        self.assertEqual(raw[:-64], body())
        self.assertEqual(len(raw), len(body()) + 64)


class WireTests(unittest.TestCase):
    def test_prefix_fields_match_the_independent_encoder(self):
        fields = soak.body_fields(body(nonce=70000, fee=2 ** 40, expiry=300))
        self.assertEqual((fields['sender'], fields['nonce'], fields['fee'], fields['anchor'], fields['expiry']),
                         (SENDER.public, 70000, 2 ** 40, ANCHOR, 300))

    def test_patches_equal_freshly_encoded_bodies(self):
        for fee in (0, 1, 250, 251, 65536, 2 ** 70):
            self.assertEqual(soak.with_fee(body(), fee), body(fee=fee))
        for nonce in (0, 250, 251, 65535, 65536, 2 ** 40):
            self.assertEqual(soak.with_nonce(body(), nonce), body(nonce=nonce))
        other = bytes(32)
        self.assertEqual(soak.with_anchor(body(), other), body(anchor=other))
        self.assertEqual(soak.with_anchor(body(), ANCHOR, expiry=0), body(expiry=0))

    def test_varint_round_trip(self):
        for value in (0, 250, 251, 0xffff, 0x10000, 0xffffffff, 0x100000000, 2 ** 64 - 1):
            encoded = soak.varint(value)
            self.assertEqual(soak.read_varint(encoded + b'\0', 0), (value, len(encoded)))


class LayoutTests(unittest.TestCase):
    def test_node_and_link_ports_never_overlap(self):
        for count in range(2, 10):
            ports = [p for i in range(count) for p in soak.node_ports(47480, i)]
            ports += [soak.proxy_port(47480, count, i, j) for i in range(count) for j in range(count) if i != j]
            self.assertEqual(len(ports), len(set(ports)), count)
            self.assertEqual(min(ports), 47480)

    def test_durations_and_error_classes(self):
        self.assertEqual([soak.parse_duration(v) for v in ('90', '30m', '2h', '45s')], [90, 1800, 7200, 45])
        error = RuntimeError({'code': -32000, 'message': 'nonce 17 differs from 18'})
        self.assertEqual(soak.error_class(error), 'nonce # differs from #')
        self.assertTrue(soak.throttled(RuntimeError({'message': 'network rate budget exhausted'})))


if __name__ == '__main__':
    unittest.main()
