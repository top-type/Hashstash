//! An isolated, signed-transaction campaign can pass a material reserve grant.
//! This proves a protocol path, not a prediction about live miners or traders.
use hashstash::{
    chain::Chain,
    config::Config,
    crypto, fees,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const SECRET: [u8; 32] = [113; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn signed(c: &Config, s: &State, operation: Operation) -> Transaction {
    let mut body = TransactionBody {
        chain_id: s.chain_id,
        sender: owner(),
        nonce: s.account(&owner(), None).unwrap().nonce,
        fee: 0u32.into(),
        expiry_height: s.height + 1000,
        operation,
        data: Vec::new(),
    };
    for _ in 0..16 {
        let tx = crypto::sign(&body, &SECRET).unwrap();
        let minimum = fees::quote(c, s, &tx).unwrap().minimum_fee;
        if minimum == body.fee {
            return tx;
        }
        body.fee = minimum;
    }
    panic!("fee did not converge");
}
fn advance(chain: &mut Chain, transactions: Vec<Transaction>) {
    let timestamp = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(
        chain.template(owner(), transactions, timestamp).unwrap(),
        1_000_000,
    )
    .unwrap();
    assert!(chain.submit(block, u64::from(timestamp)).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
}

#[test]
fn signed_outcome_trades_pass_half_reserve_grant_and_keep_a_bent_curve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("half-reserve.sqlite");
    let mut c = Config::testnet();
    c.network = "isolated-half-reserve-pass".into();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c.initial.rest = 30;
    c.initial.lead = 90;
    // Two separately mined trade legs still leave a majority of observations
    // after the PASS buy; price magnitude cannot make up for tied blocks.
    c.initial.decision_blocks = 6;
    c.auction_timeout = 120;
    c.validate().unwrap();
    let mut chain = Chain::open(&path, c.clone()).unwrap();
    for _ in 0..40 {
        advance(&mut chain, vec![]);
    }
    let deposit = signed(
        &c,
        chain.tip_state(),
        Operation::Deposit {
            amount: 8000u32.into(),

            decision: None,
            outcome: None,
        },
    );
    advance(&mut chain, vec![deposit]);
    while !matches!(chain.tip_state().phase, Phase::Auction(_)) {
        advance(&mut chain, vec![]);
    }
    let reserve_before = chain.tip_state().world.reserve.clone();
    let recipient = crypto::public_key(&[114; 32]).unwrap();
    let before = chain
        .tip_state()
        .account(&recipient, None)
        .map_or_else(Amount::zero, |account| account.ordinary);
    let support: Amount = 1u32.into();
    // Proposal fees also create revenue. Construct the exact grant after fee
    // convergence so all waiting revenue and half the ordinary reserve leave
    // the PASS world; no manual state edits or forced resolution are used.
    let mut grant = &chain.tip_state().world.revenue + &support + &reserve_before / 2u32;
    let proposal = loop {
        let tx = signed(
            &c,
            chain.tip_state(),
            Operation::Propose {
                round: chain.tip_state().auction_round().unwrap(),
                description: [115; 32],
                proposal: Proposal::Grant {
                    payments: vec![GrantPayment {
                        recipient,
                        amount: grant.clone(),
                    }],
                },
                support: support.clone(),
            },
        );
        let quote = fees::quote(&c, chain.tip_state(), &tx).unwrap();
        let required = &chain.tip_state().world.revenue
            + &support
            + &reserve_before / 2u32
            + quote.revenue_fee;
        if required == grant {
            break tx;
        }
        grant = required;
    };
    advance(&mut chain, vec![proposal]);
    for _ in 0..20 {
        if matches!(chain.tip_state().phase, Phase::Governance(_)) {
            break;
        }
        advance(&mut chain, vec![]);
    }
    let s = chain.tip_state();
    assert!(matches!(s.phase, Phase::Governance(_)));
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.grant_escrow, grant);
    assert_eq!(&pass.reserve * 2u32, s.world.reserve);
    assert_eq!(pass.curve_mass, s.world.curve_mass);
    assert_eq!(pass.quote(&c), s.world.quote(&c));
    assert_eq!(
        s.account(&recipient, None)
            .map_or_else(Amount::zero, |a| a.ordinary),
        before
    );
    let sell = signed(
        &c,
        s,
        Operation::Redeem {
            shares: s.account(&owner(), Some(Outcome::Fail)).unwrap().shares * 3u32 / 4u32,

            decision: s.decision_id(),
            outcome: Some(Outcome::Fail),
        },
    );
    advance(&mut chain, vec![sell]);
    let s = chain.tip_state();
    let buy = signed(
        &c,
        s,
        Operation::Deposit {
            amount: s.account(&owner(), Some(Outcome::Pass)).unwrap().ordinary * 3u32 / 4u32,

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    advance(&mut chain, vec![buy]);
    assert!(
        chain.tip_state().alternative.as_ref().unwrap().quote(&c)
            > chain.tip_state().world.quote(&c)
    );
    for _ in 0..100 {
        if !matches!(chain.tip_state().phase, Phase::Governance(_)) {
            break;
        }
        advance(&mut chain, vec![]);
    }
    let settled = chain.tip_state();
    assert!(!matches!(settled.phase, Phase::Governance(_)));
    assert!(settled.alternative.is_none());
    assert_eq!(
        settled.account(&recipient, None).unwrap().ordinary,
        &before + &grant
    );
    assert!(settled.world.grant_escrow.is_zero());
    assert!(settled.world.reserve < settled.world.curve_mass);
    let root = settled.root();
    drop(chain);
    let replayed = Chain::open(&path, c.clone()).unwrap();
    assert_eq!(replayed.tip_state().root(), root);
    assert_eq!(
        replayed
            .tip_state()
            .account(&recipient, None)
            .unwrap()
            .ordinary,
        before + grant
    );
    replayed.tip_state().audit(&c).unwrap();
}
