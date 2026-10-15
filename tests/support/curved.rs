//! Establish a sloped curve through a real, successful reserve-funded grant.
//! Parameter-vote fixtures need this: an untouched flat curve keeps both
//! prices equal when either outcome receives an ordinary deposit.
#![allow(dead_code)]

use hashstash::{
    chain::Chain,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};

fn signed(c: &Config, s: &State, secret: &[u8; 32], operation: Operation) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    let mut body = TransactionBody {
        chain_id: s.chain_id,
        sender,
        nonce: s.account(&sender, None).unwrap().nonce,
        fee: 0u32.into(),
        expiry_height: s.height + 10_000,
        operation,
        data: vec![],
    };
    for _ in 0..16 {
        let tx = crypto::sign(&body, secret).unwrap();
        let minimum = fees::quote(c, s, &tx).unwrap().minimum_fee;
        if minimum == body.fee {
            return tx;
        }
        body.fee = minimum;
    }
    panic!("grant fixture fee did not converge");
}

fn establish(
    c: &Config,
    mut s: State,
    secret: &[u8; 32],
    mut advance: impl FnMut(&State, Vec<Transaction>) -> State,
) -> State {
    if s.world.reserve == 0u32.into() {
        let owner = crypto::public_key(secret).unwrap();
        let amount = s.account(&owner, None).unwrap().ordinary / 2u32;
        let tx = signed(
            c,
            &s,
            secret,
            Operation::Deposit {
                amount,

                decision: None,
                outcome: None,
            },
        );
        s = advance(&s, vec![tx]);
    }
    for _ in 0..500 {
        if matches!(s.phase, Phase::Auction(_)) {
            break;
        }
        s = advance(&s, vec![]);
    }
    let recipient = crypto::public_key(&[251; 32]).unwrap();
    let before = s
        .account(&recipient, None)
        .map_or(0u32.into(), |a| a.ordinary);
    let grant = &s.world.reserve / 20u32;
    assert!(
        grant > &s.world.revenue + 10u32,
        "fixture must draw reserve"
    );
    let tx = signed(
        c,
        &s,
        secret,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [251; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient,
                    amount: grant.clone(),
                }],
            },
            support: 1u32.into(),
        },
    );
    s = advance(&s, vec![tx]);
    for _ in 0..500 {
        if s.decision_id().is_some() {
            break;
        }
        s = advance(&s, vec![]);
    }
    assert!(
        matches!(s.phase, Phase::Governance(_)),
        "grant did not activate"
    );
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.grant_escrow, grant);
    assert!(pass.curve_mass > pass.reserve);
    let sender = crypto::public_key(secret).unwrap();
    let amount = s.account(&sender, Some(Outcome::Pass)).unwrap().ordinary / 2u32;
    assert!(
        amount > 20u32.into(),
        "fixture needs a substantive outcome trade"
    );
    let tx = signed(
        c,
        &s,
        secret,
        Operation::Deposit {
            amount,

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    s = advance(&s, vec![tx]);
    for _ in 0..500 {
        if matches!(s.phase, Phase::Auction(_)) {
            break;
        }
        s = advance(&s, vec![]);
    }
    assert!(matches!(s.phase, Phase::Auction(_)));
    assert_eq!(
        s.account(&recipient, None).unwrap().ordinary,
        before + grant
    );
    assert!(
        s.world.curve_mass > s.world.reserve,
        "completed grant must leave a sloped curve"
    );
    s.audit(c).unwrap();
    s
}

pub fn state(c: &Config, s: State, secret: &[u8; 32]) -> State {
    let miner = crypto::public_key(secret).unwrap();
    establish(c, s, secret, |s, txs| {
        let next = consensus::execute(c, s, &s.root(), &miner, &0u32.into(), &txs).unwrap();
        next.audit(c).unwrap();
        next
    })
}

pub fn chain(chain: &mut Chain, secret: &[u8; 32]) {
    let c = chain.config.clone();
    let start = chain.tip_state().clone();
    let miner = crypto::public_key(secret).unwrap();
    establish(&c, start, secret, |s, txs| {
        assert_eq!(chain.tip_state().root(), s.root());
        let timestamp = chain.tip_block().header.timestamp + s.settings.interval as u32;
        let block = Chain::mine(chain.template(miner, txs, timestamp).unwrap(), 1_000_000).unwrap();
        assert!(chain.submit(block, u64::from(timestamp)).unwrap());
        chain.tip_state().audit(&c).unwrap();
        chain.tip_state().clone()
    });
}
