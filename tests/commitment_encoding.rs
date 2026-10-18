use hashstash::{
    codec,
    state::{Auction, Phase},
    tree::Map,
};
use num_bigint::BigUint;

/// Map roots follow the documented Patricia trie over hashed keys (audit R04;
/// docs/CONSENSUS.md, "State commitments"). The expected roots come from an
/// independent, top-down Python model of that text, not from this crate.
#[test]
fn map_roots_match_independent_trie_vectors() {
    let wide: Vec<u8> = (0..40).collect();
    let sixteen: Vec<(Vec<u8>, u64)> = (0..16u32)
        .map(|n| (n.to_be_bytes().to_vec(), u64::from(n) * 3))
        .collect();
    let cases: [(Vec<(Vec<u8>, u64)>, &str); 5] = [
        (
            vec![],
            "a20de3994c6f9d7b04da9ca1dfbf5267eeabfe589c286822c002e5fc98e94af0",
        ),
        // A lone entry's root is its leaf.
        (
            vec![(vec![7], 5)],
            "3526a25038d1927ff0141f2388822367b80df1c98a7e0898b76b693a770f17b3",
        ),
        (
            vec![(vec![7], 5), (vec![8], 300)],
            "85841309877b98252e1d2fff9c452a64a24d7530b96db0e1f772be9892116564",
        ),
        // Keys of any length, including empty; values in compact varints.
        (
            vec![(vec![1, 2], 0), (vec![], 1 << 40), (wide, 250)],
            "5966dd36912fcf58fa84d7d9ff47f6b113cc4b2b75784301dc509087c7a8e45b",
        ),
        (
            sixteen,
            "49d0ca4e1fc08f081dc2efe45d81b3d0068b7cbf4bd64d4d09d0700cd861e22b",
        ),
    ];
    for (entries, expected) in cases {
        let mut forward = Map::new();
        let mut backward = Map::new();
        for (key, value) in &entries {
            forward.insert(key.clone(), *value);
        }
        for (key, value) in entries.iter().rev() {
            backward.insert(key.clone(), *value);
        }
        assert_eq!(hex::encode(forward.root()), expected);
        assert_eq!(hex::encode(backward.root()), expected);
        let bytes = codec::encode(&forward);
        let restored: Map<u64> = codec::decode(&bytes, bytes.len()).unwrap();
        assert_eq!(hex::encode(restored.root()), expected);
        for (key, value) in &entries {
            let proof = forward.proof(key).unwrap();
            assert!(proof.verify(key, value, &restored.root()));
        }
    }
}

/// Auction phases encode, and commit, displaced leaders as a plain list even
/// though state versions share it (audit R26). Independently packed: variant
/// 0, compact round, opened, Some(leader), lead_since, replacement height,
/// then a count and each (ID, lead start).
#[test]
fn auction_phase_bytes_are_frozen() {
    let phase = Phase::Auction(Auction {
        round: 2,
        opened: 30,
        leader: Some([7; 32]),
        lead_since: 45,
        replacement_height: 4,
        displaced: vec![([8; 32], 35), ([9; 32], 300)].into(),
    });
    let expected = format!(
        "00021e01{}2d0402{}23{}fb2c01",
        "07".repeat(32),
        "08".repeat(32),
        "09".repeat(32)
    );
    assert_eq!(hex::encode(codec::encode(&phase)), expected);
    let decoded: Phase = codec::decode(&hex::decode(&expected).unwrap(), 1000).unwrap();
    let Phase::Auction(a) = decoded else {
        panic!("auction phase expected")
    };
    assert_eq!(a.displaced, vec![([8; 32], 35), ([9; 32], 300)]);
}

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
