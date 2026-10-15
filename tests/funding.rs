//! Isolated consensus fixtures: no cloud nodes, wallets, or mining connections.
use hashstash::{
    codec,
    config::Config,
    consensus, crypto,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const SECRET: [u8; 32] = [113; 32];

fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn recipient() -> PublicKey {
    crypto::public_key(&[114; 32]).unwrap()
}
fn config(duration: u64) -> Config {
    let mut c = Config::testnet();
    c.initial.lead = 2 * c.initial.interval;
    c.initial.decision_blocks = duration;
    c.initial.rest = 4 * c.initial.interval;
    c.validate().unwrap();
    c
}
fn step(c: &Config, s: &State, subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &owner(), &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn sign(s: &State, op: Operation, offset: u64) -> Transaction {
    crypto::sign(
        &TransactionBody {
            chain_id: s.chain_id,
            sender: owner(),
            nonce: s.account(&owner(), None).unwrap().nonce + offset,
            fee: 100u64.into(),
            expiry_height: s.height + 100,
            operation: op,
            data: vec![],
        },
        &SECRET,
    )
    .unwrap()
}
fn funded_curve(c: &Config) -> State {
    let mut s = step(c, &State::genesis(c), 2_000_000, &[]);
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: 1_000_000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
    );
    s = step(c, &s, 0, &[tx]);
    for _ in 0..100 {
        if matches!(s.phase, Phase::Auction(_)) {
            return s;
        }
        s = step(c, &s, 1, &[]);
    }
    panic!("auction did not open")
}
fn activate(c: &Config, action: Proposal) -> (State, State) {
    let mut s = funded_curve(c);
    let tx = sign(
        &s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [13; 32],
            proposal: action,
            support: 10u64.into(),
        },
        0,
    );
    s = step(c, &s, 1, &[tx]);
    for _ in 0..100 {
        let next = step(c, &s, 1, &[]);
        if matches!(next.phase, Phase::Governance(_)) {
            return (s, next);
        }
        s = next;
    }
    panic!("proposal did not activate")
}
fn grant(c: &Config, amount: u64) -> (State, State) {
    activate(
        c,
        Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: recipient(),
                amount: amount.into(),
            }],
        },
    )
}

#[test]
fn whole_grant_is_reserved_at_opening_and_tied_prices_fail() {
    for duration in [2, 3, 12, 240] {
        let c = config(duration);
        let amount = 1207u64;
        let (before, mut s) = grant(&c, amount);
        let Phase::Governance(d) = s.phase.clone() else {
            unreachable!()
        };
        let pass = s.alternative.as_ref().unwrap();
        assert_eq!(s.world.revenue, before.world.revenue + 10u64);
        assert_eq!(pass.grant_escrow, amount.into());
        assert_eq!(pass.curve_mass, s.world.curve_mass);
        assert_eq!(pass.shares, s.world.shares);
        assert_eq!(pass.quote(&c), s.world.quote(&c));
        assert_eq!(
            &pass.reserve + &pass.revenue + &pass.grant_escrow,
            &s.world.reserve + &s.world.revenue
        );
        let reserve = pass.reserve.clone();
        for elapsed in 0..duration {
            assert_eq!(s.clock - d.started, elapsed * c.initial.interval);
            let pass = s.alternative.as_ref().unwrap();
            assert_eq!(pass.grant_escrow, amount.into());
            assert_eq!(pass.reserve, reserve);
            assert_eq!(pass.quote(&c), s.world.quote(&c));
            assert!(matches!(&s.phase, Phase::Governance(d) if d.leading_blocks == 0));
            if elapsed + 1 < duration {
                s = step(&c, &s, 1, &[]);
            }
        }
        let invalid = sign(
            &s,
            Operation::Deposit {
                amount: 1u64.into(),

                decision: Some(d.id),
                outcome: Some(Outcome::Pass),
            },
            0,
        );
        consensus::apply_transaction(&c, &mut s.clone(), &invalid).unwrap();
        assert!(consensus::execute(&c, &s, &s.root(), &owner(), &1u64.into(), &[invalid]).is_err());
        let closed = step(&c, &s, 1, &[]);
        assert!(matches!(closed.phase, Phase::Rest(_)));
        assert!(closed.alternative.is_none());
        assert_eq!(closed.height - d.started_height, duration);
        assert!(closed.account(&recipient(), None).is_none());
        assert!(closed.world.grant_escrow.is_zero());
    }
}

#[test]
fn waiting_revenue_funds_small_grant_without_changing_either_curve() {
    let c = config(4);
    let (_, mut s) = grant(&c, 1);
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.reserve, s.world.reserve);
    assert_eq!(pass.curve_mass, s.world.curve_mass);
    assert_eq!(pass.revenue.clone() + 1u64, s.world.revenue);
    assert_eq!(pass.reserve, pass.curve_mass);
    while s.decision_id().is_some() {
        s = step(&c, &s, 1, &[]);
    }
    assert!(s.account(&recipient(), None).is_none());
}

#[test]
fn pass_trade_can_win_and_release_escrow_exactly_once() {
    let c = config(12);
    let (_, mut s) = grant(&c, 1207);
    let pass = s.alternative.as_ref().unwrap();
    assert!(pass.reserve < pass.curve_mass);
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: 100_000u64.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
        0,
    );
    s = step(&c, &s, 1, &[tx]);
    assert!(s.alternative.as_ref().unwrap().quote(&c) > s.world.quote(&c));
    while s.decision_id().is_some() {
        s = step(&c, &s, 1, &[]);
    }
    assert_eq!(
        s.account(&recipient(), None).unwrap().ordinary,
        1207u64.into()
    );
    assert!(s.world.grant_escrow.is_zero());
    let before = s.account(&recipient(), None).unwrap().ordinary;
    s = step(&c, &s, 1, &[]);
    assert_eq!(s.account(&recipient(), None).unwrap().ordinary, before);
}

#[test]
fn fee_revenue_replenishes_each_world_after_miner_split() {
    let c = config(12);
    let (_, mut s) = grant(&c, 1207);
    let before = s.alternative.as_ref().unwrap().clone();
    let tx = sign(
        &s,
        Operation::TransferExact {
            recipient: owner(),
            amount: 1u64.into(),
        },
        0,
    );
    let quote = hashstash::fees::quote(&c, &s, &tx).unwrap();
    s = step(&c, &s, 1, &[tx]);
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.reserve, &before.reserve + &quote.revenue_fee);
    assert_eq!(pass.curve_mass, before.curve_mass);
    assert_eq!(pass.shares, before.shares);
    assert_eq!(pass.quote(&c), before.quote(&c));
    assert!(pass.revenue.is_zero());
    assert_eq!(s.world.reserve, s.world.curve_mass);
    assert!(s.world.revenue >= quote.revenue_fee);
}

#[test]
fn unfunded_grant_cannot_open_or_remove_backing() {
    let c = config(4);
    let mut s = funded_curve(&c);
    let before = codec::encode(&s);
    let tx = sign(
        &s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [14; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient: recipient(),
                    amount: s.issued.clone(),
                }],
            },
            support: 10u64.into(),
        },
        0,
    );
    // Proposals are admitted, then eligibility is checked before decision opening.
    consensus::apply_transaction(&c, &mut s, &tx).unwrap();
    assert_ne!(codec::encode(&s), before);
    for _ in 0..10 {
        s = step(&c, &s, 1, &[]);
    }
    assert!(s.decision_id().is_none());
    assert!(s.alternative.is_none());
    assert!(s.world.grant_escrow.is_zero());
    s.audit(&c).unwrap();
}
