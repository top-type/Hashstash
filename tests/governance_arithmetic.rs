//! Boundary values follow the same transitions as ordinary governance.
#[path = "support/curved.rs"]
mod curved;
use hashstash::{
    codec,
    config::Config,
    consensus, crypto,
    state::{Phase, State},
    types::*,
};

const SECRET: [u8; 32] = [194; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.initial.minimum_fee_rate = 0;
    c.initial.lead = 0;
    c.initial.rest = 0;
    c.initial.duration = 45;
    c.reserve_min = 0u32.into();
    c.budget_period = 1;
    c.validate().unwrap();
    c
}
fn sign(s: &State, operation: Operation) -> Transaction {
    crypto::sign(
        &TransactionBody {
            chain_id: s.chain_id,
            sender: owner(),
            nonce: s.account(&owner(), None).unwrap().nonce,
            fee: 0u32.into(),
            expiry_height: s.height + 100,
            operation,
            data: vec![],
        },
        &SECRET,
    )
    .unwrap()
}
fn step(c: &Config, s: &State, subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &owner(), &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    let encoded = codec::encode(s);
    let restored: State = codec::decode(&encoded, encoded.len()).unwrap();
    restored.audit(c).unwrap();
    let replay = consensus::execute(
        c,
        &restored,
        &restored.root(),
        &owner(),
        &subsidy.into(),
        txs,
    )
    .unwrap();
    assert_eq!(next.root(), replay.root());
    next
}
fn funded(c: &Config) -> State {
    let s = State::genesis(c);
    s.audit(c).unwrap();
    let s = step(c, &s, 1_000_000, &[]);
    let deposit = sign(
        &s,
        Operation::Deposit {
            amount: 400_000u32.into(),
            min_shares: 1u32.into(),
            decision: None,
            outcome: None,
        },
    );
    step(c, &s, 0, &[deposit])
}
fn propose(s: &State, proposal: Proposal) -> Transaction {
    sign(
        s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [195; 32],
            proposal,
            support: 1u32.into(),
        },
    )
}

#[test]
fn zero_rest_and_lead_open_and_resolve_without_stuck_transient_phases() {
    let c = config();
    let mut s = curved::state(&c, funded(&c), &SECRET);
    assert!(matches!(s.phase, Phase::Auction(_)));
    for (parameter, value) in [
        (Parameter::Duration, 155),
        (Parameter::Interval, 77),
        (Parameter::MinimumFeeRate, 3),
    ] {
        let tx = propose(
            &s,
            Proposal::Parameter {
                parameter,
                old: s.settings.get(parameter),
                new: value,
            },
        );
        s = step(&c, &s, 0, &[tx]);
        assert!(
            matches!(s.phase, Phase::Governance(_)),
            "zero lead opens in the proposal block"
        );
        let buy = sign(
            &s,
            Operation::Deposit {
                amount: 10_000u32.into(),
                min_shares: 1u32.into(),
                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
        );
        s = step(&c, &s, 0, &[buy]);
        for _ in 0..10 {
            if matches!(s.phase, Phase::Auction(_)) {
                break;
            }
            s = step(&c, &s, 0, &[]);
        }
        assert!(
            matches!(s.phase, Phase::Auction(_)),
            "zero rest opens the next auction in the resolution block"
        );
        assert_eq!(s.settings.get(parameter), value);
    }
}

#[test]
fn sub_block_decisions_fail_ties_and_restore_grant_escrow() {
    for duration in [1, 14, 15] {
        let mut c = config();
        c.initial.duration = duration;
        let s = funded(&c);
        let tx = propose(
            &s,
            Proposal::Grant {
                payments: vec![GrantPayment {
                    recipient: owner(),
                    amount: 100u32.into(),
                }],
            },
        );
        let opened = step(&c, &s, 0, &[tx]);
        assert!(matches!(opened.phase, Phase::Governance(_)));
        assert_eq!(
            opened.alternative.as_ref().unwrap().grant_escrow,
            100u32.into()
        );
        let closed = step(&c, &opened, 0, &[]);
        assert!(matches!(closed.phase, Phase::Auction(_)));
        assert_eq!(closed.world.reserve, opened.world.reserve);
        assert!(closed.alternative.is_none());
        assert_eq!(closed.world.grant_escrow, 0u32.into());
        assert_eq!(
            &closed.world.price_integral - &opened.world.price_integral,
            opened.world.quote(&c) * c.initial.interval
        );
    }
}

#[test]
fn long_intervals_skip_empty_budget_epochs_without_looping_or_losing_reservations() {
    let c = config();
    let s = funded(&c);
    let tx = propose(
        &s,
        Proposal::Grant {
            payments: vec![GrantPayment {
                recipient: owner(),
                amount: 100u32.into(),
            }],
        },
    );
    let mut opened = step(&c, &s, 0, &[tx]);
    let records = opened.budgets.len();
    let origin = opened.budget_epoch;
    let huge_interval = 1u64 << 48;
    opened.settings.interval = huge_interval;
    opened.frozen.interval = huge_interval;
    let closed = step(&c, &opened, 0, &[]);
    assert_eq!(closed.clock, opened.clock + huge_interval);
    assert_eq!(closed.budget_epoch, origin + huge_interval);
    assert_eq!(closed.budgets.len(), records + 1);
    assert_eq!(
        closed.budgets.get(&origin.to_be_bytes()).unwrap().reserved,
        0u32.into()
    );
    assert_eq!(
        closed.budgets.get(&origin.to_be_bytes()).unwrap().spent,
        0u32.into()
    );
}

#[test]
fn proposals_that_no_longer_fit_at_activation_are_refunded_without_halting_blocks() {
    let c = config();
    let mut s = funded(&c);
    s.clock = u64::MAX - 10_000;
    if let Phase::Auction(a) = &mut s.phase {
        a.opened = s.clock;
        a.lead_since = s.clock;
    }
    s.audit(&c).unwrap();
    let new = u64::MAX - (s.clock + s.settings.interval);
    let tx = propose(
        &s,
        Proposal::Parameter {
            parameter: Parameter::Duration,
            old: s.settings.duration,
            new,
        },
    );
    let next = step(&c, &s, 0, &[tx]);
    assert!(matches!(next.phase, Phase::Auction(_)));
    assert_eq!(next.proposals.len(), 1);
    assert!(
        next.proposals
            .iter()
            .next()
            .unwrap()
            .1
            .refund_height
            .is_some()
    );
    assert_eq!(next.settings.duration, c.initial.duration);
    let advanced = step(&c, &next, 0, &[]);
    assert_eq!(advanced.clock, next.clock + c.initial.interval);
}

#[test]
fn clock_and_deadline_exhaustion_are_errors_without_mutating_parent() {
    let c = config();
    let mut s = funded(&c);
    s.clock = u64::MAX - 1;
    if let Phase::Auction(a) = &mut s.phase {
        a.opened = s.clock;
        a.lead_since = s.clock;
    }
    assert!(
        s.validate(&c).is_err(),
        "an unrepresentable active deadline is invalid"
    );
    let before = s.root();
    assert!(consensus::execute(&c, &s, &before, &owner(), &0u32.into(), &[]).is_err());
    assert_eq!(s.root(), before);
}

#[test]
fn zero_reserve_minimum_retains_the_last_atom_of_nonempty_stash() {
    let c = config();
    let s = funded(&c);
    let capacity = consensus::grant_capacity(&c, &s.world);
    assert_eq!(capacity, &s.world.revenue + &s.world.reserve - 1u32);
    let mut world = s.world.clone();
    consensus::grant_reserve(&c, &mut world, &capacity).unwrap();
    assert_eq!(world.reserve, 1u32.into());
    world.validate(&c, &s.issued, &s.auction_escrow).unwrap();
    let before = world.root();
    assert!(consensus::grant_reserve(&c, &mut world, &1u32.into()).is_err());
    assert_eq!(before, world.root());
}

#[test]
fn zero_signature_capacity_still_mines_empty_blocks_and_rejects_transactions() {
    let mut c = config();
    c.max_signatures = 0;
    c.initial.block_bytes = hashstash::fees::ACCOUNT_WEIGHT;
    c.validate().unwrap();
    let s = step(&c, &State::genesis(&c), 1_000, &[]);
    let tx = sign(
        &s,
        Operation::TransferExact {
            recipient: owner(),
            amount: 1u32.into(),
        },
    );
    assert!(consensus::execute(&c, &s, &s.root(), &owner(), &0u32.into(), &[tx]).is_err());
    step(&c, &s, 0, &[]);
}

#[test]
fn cumulative_budget_spending_can_exceed_circulating_money_range() {
    for enabled in [false, true] {
        let mut c = config();
        c.max_height = 1000;
        c.money_bits = 265;
        c.initial.miner_fee_percent = Some(0);
        c.budget_period = 10_000;
        if enabled {
            c.budget_numerator = 10;
            c.budget_denominator = 1;
        }
        c.validate().unwrap();
        let unit = Amount::from(1u32) << 255usize;
        let mut s = State::genesis(&c);
        // The largest per-block subsidy, within the configured lifetime proof.
        for _ in 0..600 {
            s = consensus::execute(&c, &s, &s.root(), &owner(), &unit, &[]).unwrap();
        }
        s.audit(&c).unwrap();
        let tx = sign(
            &s,
            Operation::Deposit {
                amount: &unit * 400u32,
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
        );
        s = step(&c, &s, 0, &[tx]);
        for _ in 0..4 {
            let tx = propose(
                &s,
                Proposal::Grant {
                    payments: vec![GrantPayment {
                        recipient: owner(),
                        amount: &unit * 300u32,
                    }],
                },
            );
            s = step(&c, &s, 0, &[tx]);
            assert!(s.decision_id().is_some());
            let buy = sign(
                &s,
                Operation::Deposit {
                    amount: unit.clone(),
                    min_shares: 1u32.into(),
                    decision: s.decision_id(),
                    outcome: Some(Outcome::Pass),
                },
            );
            s = step(&c, &s, 0, &[buy]);
            while s.decision_id().is_some() {
                s = step(&c, &s, 0, &[]);
            }
            // Return the payment through Revenue, less the outcome purchase.
            // Revenue replenishes existing backing without inflating curve mass.
            let mut tx = sign(
                &s,
                Operation::TransferExact {
                    recipient: owner(),
                    amount: 1u32.into(),
                },
            );
            tx.body.fee = &unit * 299u32;
            tx = crypto::sign(&tx.body, &SECRET).unwrap();
            s = step(&c, &s, 0, &[tx]);
        }
        let epoch = s.budget_epoch;
        assert_eq!(epoch, 0);
        let mut budget = s.budgets.get(&epoch.to_be_bytes()).unwrap().clone();
        assert_eq!(budget.spent, &unit * 1200u32);
        assert!(budget.spent.bits() > c.money_bits);
        s.audit(&c).unwrap();
        let bytes = codec::encode(&s);
        let restored: State = codec::decode(&bytes, bytes.len()).unwrap();
        assert_eq!(restored.root(), s.root());
        restored.audit(&c).unwrap();
        budget.spent = Amount::from(1u32) << (c.money_bits + 64) as usize;
        if enabled {
            budget.allowance = &budget.spent + &budget.reserved;
        }
        s.budgets.insert(epoch.to_be_bytes().to_vec(), budget);
        assert!(s.audit(&c).is_err());
    }
}

#[test]
fn active_decision_audit_checks_the_pending_value_at_its_activation_clock() {
    let c = config();
    let s = funded(&c);
    let tx = propose(
        &s,
        Proposal::Parameter {
            parameter: Parameter::Duration,
            old: s.settings.duration,
            new: 71,
        },
    );
    let mut opened = step(&c, &s, 0, &[tx]);
    let Phase::Governance(d) = &mut opened.phase else {
        panic!("missing decision")
    };
    d.proposal = Proposal::Parameter {
        parameter: Parameter::Duration,
        old: s.settings.duration,
        new: u64::MAX - d.started,
    };
    // The proposed duration fits at decision opening but not at activation.
    assert!(opened.validate(&c).is_err());
}
