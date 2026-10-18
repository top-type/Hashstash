use hashstash::{
    codec,
    config::{Config, Settings},
    state::{
        Auction, Decision, Phase, ProposalRecord, Rest, RoundRecord, RoundStatus, State,
        SupportRecord, World, proposal_id, rank_key, support_key,
    },
    tree::Map,
    types::{Account, GrantPayment, Hash, Parameter, Proposal},
};
use num_bigint::BigUint;
use std::sync::Arc;

/// Map roots follow the documented Patricia trie over hashed keys (audit R04;
/// docs/CONSENSUS.md, "State commitments"). The expected roots come from an
/// independent, top-down Python model of that text, not from this crate.
#[test]
fn map_roots_match_independent_trie_vectors() {
    type Entries = Vec<(Vec<u8>, u64)>;
    let wide: Vec<u8> = (0..40).collect();
    let sixteen: Entries = (0..16u32)
        .map(|n| (n.to_be_bytes().to_vec(), u64::from(n) * 3))
        .collect();
    let cases: [(Entries, &str); 5] = [
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

/// A world with these accounts (key byte, ordinary, shares, nonce, epoch)
/// whose committed scalars are, in declaration order, `scalars`.
fn world(accounts: &[(u8, u32, u32, u64, u64)], scalars: [u32; 7]) -> World {
    let mut w = World::default();
    for &(key, ordinary, shares, nonce, epoch) in accounts {
        let account = Account {
            ordinary: ordinary.into(),
            shares: shares.into(),
            nonce,
            epoch,
        };
        w.put([key; 32], account, &Config::devnet()).unwrap();
    }
    let [reserve, shares, revenue, escrow, mass, cash, account_shares] = scalars.map(BigUint::from);
    (w.reserve, w.shares, w.revenue, w.grant_escrow) = (reserve, shares, revenue, escrow);
    (w.curve_mass, w.account_cash, w.account_shares) = (mass, cash, account_shares);
    w
}

/// Whole state roots (audit R16). Nothing else pins the round-2 commitment:
/// the actions root in tuple B, the decision committed without its proposal
/// and the displaced auction leaders. The expected values come from an
/// independent model of docs/CONSENSUS.md, not from this crate. Committed
/// values differ from their neighbours, so swapping two fields, two map roots
/// or two phase fields changes a root; the states need not be reachable.
#[test]
fn state_roots_match_independent_vectors() {
    let chain: Hash = [0x11; 32];
    let payment = |recipient: u8, amount: u32| GrantPayment {
        recipient: [recipient; 32],
        amount: amount.into(),
    };
    let grant = Proposal::Grant {
        payments: vec![payment(0x61, 4_000), payment(0x62, 70_000)],
    };
    let parameter = Proposal::Parameter {
        parameter: Parameter::Lead,
        old: 45,
        new: 60,
    };
    let g = proposal_id(&chain, 1, &[0x21; 32], &[0x41; 32], &grant);
    let p = proposal_id(&chain, 1, &[0x22; 32], &[0x42; 32], &parameter);
    let support = support_key(1, &g, &[0x22; 32]);
    assert_eq!(
        hex::encode(g),
        "86d7d727cc3f7149d0ce87a2dc77cc3c00a837ed1a80b60f46e02bfcf81d3cfe"
    );
    assert_eq!(
        hex::encode(p),
        "cccb4e6bd31c1d22b3b5c22baa32efa79b32d4d33131a2173cafdaa9371e34b5"
    );
    assert_eq!(
        hex::encode(&support),
        "02ab4445675364d43ff064e76f32abb8f26e2175e5112427ce32fe5d0dcf6987"
    );
    let record = |proposer: u8, description: u8, support: u32, refund_height| ProposalRecord {
        round: 1,
        proposer: [proposer; 32],
        description: [description; 32],
        support: support.into(),
        refund_height,
    };
    let mut proposals = Map::new();
    proposals.insert(g.to_vec(), record(0x21, 0x41, 9_000, None));
    proposals.insert(p.to_vec(), record(0x22, 0x42, 300, Some(19)));
    let mut actions = Map::new();
    actions.insert(g.to_vec(), grant);
    actions.insert(p.to_vec(), parameter.clone());
    let mut supports = Map::new();
    supports.insert(
        support,
        SupportRecord {
            round: 1,
            proposal: g,
            sender: [0x22; 32],
            amount: 9_000u32.into(),
        },
    );
    let rounds = |current: RoundRecord| {
        let mut rounds = Map::new();
        let timeout = RoundRecord {
            status: RoundStatus::Timeout,
            refund_height: 10,
        };
        rounds.insert(0u64.to_be_bytes().to_vec(), timeout);
        rounds.insert(1u64.to_be_bytes().to_vec(), current);
        rounds
    };
    let mut ranking = Map::new();
    ranking.insert(rank_key(&9_000u32.into(), &g), g);
    let auction = State {
        chain_id: chain,
        height: 21,
        clock: 315,
        issued: (BigUint::from(1u8) << 40u32) + 7u32,
        settings: Settings {
            block_bytes: 16_384,
            minimum_fee_rate: 3,
            interval: 15,
            lead: 60,
            rest: 120,
            decision_blocks: 8,
            max_price_change_bps: 500,
            miner_fee_percent: Some(25),
            pass_margin_bps: Some(10),
        },
        frozen: Settings {
            block_bytes: 16_384,
            minimum_fee_rate: 2,
            interval: 15,
            lead: 45,
            rest: 120,
            decision_blocks: 6,
            max_price_change_bps: 400,
            miner_fee_percent: None,
            pass_margin_bps: Some(0),
        },
        world: world(
            &[(0x21, 1_000_000, 5_000, 3, 0), (0x22, 70_000, 0, 1, 2)],
            [40_000, 6_000, 1_234, 7, 52_000, 1_070_000, 5_000],
        ),
        alternative: None,
        phase: Phase::Auction(Auction {
            round: 1,
            opened: 240,
            leader: Some(g),
            lead_since: 300,
            replacement_height: 20,
            displaced: vec![(p, 255), ([0x33; 32], 270)].into(),
        }),
        proposals,
        actions,
        supports,
        rounds: rounds(RoundRecord {
            status: RoundStatus::Open,
            refund_height: 0,
        }),
        ranking,
        auction_escrow: 9_300u32.into(),
        last_round: 1,
        last_epoch: 2,
    };
    let governance = State {
        height: 24,
        clock: 360,
        alternative: Some(world(
            &[(0x21, 996_000, 5_500, 3, 3), (0x22, 70_000, 0, 1, 2)],
            [36_000, 5_501, 0, 74_000, 52_001, 1_066_000, 5_500],
        )),
        phase: Phase::Governance(Decision {
            id: [0x51; 32],
            epoch: 3,
            round: 1,
            proposal_id: g,
            proposal: auction.actions.get_shared(&g).unwrap().clone(),
            started: 330,
            started_height: 22,
            blocks: 6,
            leading_blocks: 2,
        }),
        rounds: rounds(RoundRecord {
            status: RoundStatus::Won(g),
            refund_height: 23,
        }),
        ranking: Map::new(),
        auction_escrow: 300u32.into(),
        last_epoch: 3,
        ..auction.clone()
    };
    let rest = State {
        phase: Phase::Rest(Rest {
            until: 600,
            pending: Some((Parameter::MinimumFeeRate, 4)),
        }),
        ..auction.clone()
    };
    for (state, expected) in [
        (
            &auction,
            "1a8e49d2cbf0f5359b90ab6ca158ae44444eaeb4fa91be825f639f9a80663368",
        ),
        (
            &governance,
            "4ff8740ba9f3eea3ba40047b22e3929ac08d6501560047216b672ac4e4cbe2c5",
        ),
        (
            &rest,
            "151f91e195ec7df9a0ae3ed9ec1d8e5d8a82c009fc8d7aacfbd3d24060050363",
        ),
    ] {
        assert_eq!(hex::encode(state.root()), expected);
        let bytes = codec::encode(state);
        let restored: State = codec::decode(&bytes, bytes.len()).unwrap();
        assert_eq!(hex::encode(restored.root()), expected);
    }
    // The decision's copy of its proposal is not committed, even when it
    // disagrees with the actions entry.
    let mut copy = governance.clone();
    let Phase::Governance(d) = &mut copy.phase else {
        unreachable!()
    };
    d.proposal = Arc::new(parameter);
    assert_eq!(copy.root(), governance.root());
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
    let encoded = codec::encode(&(
        [7u8; 32],
        &amount,
        Some([9u8; 32]),
        None::<[u8; 32]>,
        300u64,
    ));
    // Array, amount, Some(array), None, compact u64.
    let expected = format!("{}01fb020101{}00fb2c01", "07".repeat(32), "09".repeat(32));
    assert_eq!(hex::encode(encoded), expected);
}
