"""Unit checks for the chaos soak harness's signing, wire patching and port layout."""
import contextlib
import io
import json
import random
import types
import unittest

import soak
from chain_activity import make_body

SENDER = soak.Key('sender', 7)
RECIPIENT = soak.Key('recipient', 7)
ANCHOR = bytes(range(32))
CHAIN = '5a' * 32
# Built by independent code and checked by tests/transaction_signing_vector.rs against
# crypto::signing_message, libsecp256k1 and crypto::verify.
VECTOR = json.loads((soak.REPOSITORY / 'tests/data/transaction-signing.json').read_text())


class ZeroAuxiliary:
    """Supplies BIP340 auxiliary randomness of zero, as the shared vector uses."""

    @staticmethod
    def randbytes(count):
        return bytes(count)


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
        raw = soak.sign_body(SENDER, CHAIN, body(), random.Random(1))
        self.assertEqual(raw[:-64], body())
        self.assertEqual(len(raw), len(body()) + 64)

    def test_signatures_use_the_node_chain_bound_domain(self):
        # The node verifies tagged_hash('Hashstash/chain-bound-transaction', chain_id || body).
        raw_body = bytes.fromhex(VECTOR['body'])
        self.assertEqual(soak.signing_message(VECTOR['chain_id'], raw_body).hex(), VECTOR['message'])
        signer = types.SimpleNamespace(secret=int(VECTOR['secret_key'], 16))
        self.assertEqual(soak.public_key(signer.secret).hex(), VECTOR['public_key'])
        raw = soak.sign_body(signer, VECTOR['chain_id'], raw_body, ZeroAuxiliary())
        self.assertEqual(raw, raw_body + bytes.fromhex(VECTOR['signature']))

    def test_signatures_are_bound_to_the_chain(self):
        raw_body = bytes.fromhex(VECTOR['body'])
        other = bytearray.fromhex(VECTOR['chain_id'])
        other[31] ^= 1
        self.assertNotEqual(soak.signing_message(other.hex(), raw_body).hex(), VECTOR['message'])
        self.assertNotEqual(soak.tagged_hash('Hashstash/anchor-only-transaction', raw_body).hex(), VECTOR['message'])
        with self.assertRaises(ValueError):
            soak.signing_message('5a' * 31, raw_body)

    def test_signature_refusals_are_recognised(self):
        refused = RuntimeError({'code': -32000, 'message': 'invalid transaction signature for this network'})
        self.assertTrue(soak.signature_refused(refused))
        self.assertFalse(soak.signature_refused(RuntimeError({'message': 'nonce 17 differs from 18'})))

    def test_a_refused_harness_signature_fails_the_soak(self):
        run = soak.Soak(types.SimpleNamespace())
        run.chain_id = CHAIN
        node = types.SimpleNamespace(name='node-1')
        run.check_signature(node, 'transfer')
        run.check_signature(node, 'deposit_pass', RuntimeError({'message': 'insufficient balance'}))
        self.assertEqual(run.recorder.violation_total, 0)
        refused = RuntimeError({'message': 'invalid transaction signature for this network'})
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            run.check_signature(node, 'chat', refused)
        self.assertIn('VIOLATION signature_accepted node-1', printed.getvalue())
        self.assertEqual(run.recorder.checks['signature_accepted'], {'count': 3, 'violations': 1})
        self.assertEqual(run.recorder.violations[0]['node'], 'node-1')


class InvariantTests(unittest.TestCase):
    def test_grant_capacity_matches_consensus(self):
        # The table of consensus.rs grant_capacity_draws_at_most_half_the_reserve:
        # (reserve, revenue, capacity).
        for reserve, revenue, expected in ((0, 0, 0), (0, 5, 5), (1, 0, 0), (1, 5, 5), (2, 0, 1), (19, 0, 9),
                                           (19, 3, 12)):
            self.assertEqual(soak.grant_capacity(revenue, reserve), expected, (reserve, revenue))

    def test_pool_bound_covers_the_selection_and_its_backlog(self):
        # A 16 KiB selection plus a backlog within one more block's bytes, as 0.43.0 pools.
        self.assertEqual(soak.pool_byte_bound(16384), 32768)


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
