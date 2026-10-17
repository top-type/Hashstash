use hashstash::codec;
use num_bigint::BigUint;

/// State and world commitments encode bare `BigUint` values with num-bigint
/// 0.4's own serde format: a compact limb count followed by compact
/// little-endian u32 limbs (docs/CONSENSUS.md). These bytes are independent of
/// the `types::amount` adapter and must survive any dependency update.
#[test]
fn bare_biguint_commitment_bytes_are_frozen() {
    let cases: [(BigUint, &str); 8] = [
        (BigUint::default(), "00"),
        (1u32.into(), "0101"),
        (250u32.into(), "01fa"),
        (251u32.into(), "01fbfb00"),
        (258u32.into(), "01fb0201"),
        (u32::MAX.into(), "01fcffffffff"),
        (BigUint::from(1u64 << 32), "020001"),
        ((BigUint::from(1u8) << 64u32) + 2u32, "03020001"),
    ];
    for (value, expected) in cases {
        assert_eq!(hex::encode(codec::encode(&value)), expected, "{value}");
    }
}

/// Commitment tuples also rely on serde's fixed-array, option and tuple layout.
#[test]
fn commitment_tuple_layout_is_frozen() {
    let amount = BigUint::from(258u32);
    let encoded = codec::encode(&([7u8; 32], &amount, Some([9u8; 32]), None::<[u8; 32]>, 300u64));
    // Array, amount, Some(array), None, compact u64.
    let expected = format!("{}01fb020101{}00fb2c01", "07".repeat(32), "09".repeat(32));
    assert_eq!(hex::encode(encoded), expected);
}
