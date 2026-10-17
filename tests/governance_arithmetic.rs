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
    c.initial.decision_blocks = 3;
    c.validate().unwrap();
    c
}
fn sign(s: &State, operation: Operation) -> Transaction {
    crypto::sign(
        &TransactionBody {
            sender: owner(),
            nonce: s.account(&owner(), None).unwrap().nonce,
            fee: 0u32.into(),
            anchor: [0; 32],
            expiry_blocks: s.height + 100,
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
        (Parameter::DecisionBlocks, 155),
        (Parameter::Interval, 77),
        (Parameter::MinimumFeeRate, 1),
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

                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
        );
        s = step(&c, &s, 0, &[buy]);
        for _ in 0..=s.frozen.decision_blocks {
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
fn block_count_decisions_fail_ties_and_restore_grant_escrow() {
    for duration in [1, 14, 15] {
        let mut c = config();
        c.initial.decision_blocks = duration;
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
        // FAIL opens on the same bent curve, holding the shortfall as revenue.
        let pass = opened.alternative.as_ref().unwrap();
        assert_eq!(opened.world.reserve, pass.reserve);
        assert!(opened.world.reserve < s.world.reserve);
        let mut closed = opened.clone();
        for _ in 0..duration {
            closed = step(&c, &closed, 0, &[]);
        }
        assert!(matches!(closed.phase, Phase::Auction(_)));
        assert_eq!(closed.world.reserve, s.world.reserve);
        assert!(closed.alternative.is_none());
        assert_eq!(closed.world.grant_escrow, 0u32.into());
        assert_eq!(closed.height - opened.height, duration);
    }
}

#[test]
fn long_intervals_resolve_escrow_without_losing_funds() {
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
    assert_eq!(
        opened.alternative.as_ref().unwrap().grant_escrow,
        100u32.into()
    );
    let huge_interval = 1u64 << 48;
    opened.settings.interval = huge_interval;
    opened.frozen.interval = huge_interval;
    let mut closed = opened.clone();
    for _ in 0..c.initial.decision_blocks {
        closed = step(&c, &closed, 0, &[]);
    }
    assert_eq!(
        closed.clock,
        opened.clock + huge_interval * c.initial.decision_blocks
    );
    assert!(closed.decision_id().is_none());
    assert!(closed.alternative.is_none());
    // FAIL's set-aside shortfall returns to its reserve at resolution.
    assert_eq!(closed.world.reserve, s.world.reserve);
    assert_eq!(closed.world.reserve, closed.world.curve_mass);
    assert_eq!(
        &closed.world.reserve + &closed.world.revenue,
        &opened.world.reserve + &opened.world.revenue
    );
    assert_eq!(closed.world.account_cash, opened.world.account_cash);
    assert_eq!(closed.world.grant_escrow, 0u32.into());
    assert_eq!(closed.issued, opened.issued);
}

#[test]
fn proposals_that_no_longer_fit_at_activation_are_refunded_without_halting_blocks() {
    // Each block advances the clock and uses up one remaining height alike,
    // so on most chains the lifetime bound is the same at submission and at
    // activation. A chain whose clock range ends before its height limit
    // instead nears the clock's end, where a value can fit at submission but
    // not at its projected activation one decision later.
    let mut c = config();
    c.max_height = i64::MAX as u64;
    c.validate().unwrap();
    let mut s = funded(&c);
    let interval = s.settings.interval;
    let timeout = c.auction_timeout_for(&s.settings).unwrap();
    // The including block's clock leaves 20 seconds of slack for the auction
    // timeout at submission; activation comes decision_blocks * interval later.
    s.clock = u64::MAX - timeout - 20 - interval;
    if let Phase::Auction(a) = &mut s.phase {
        a.opened = s.clock;
        a.lead_since = s.clock;
    }
    s.audit(&c).unwrap();
    let tx = propose(
        &s,
        Proposal::Parameter {
            parameter: Parameter::MinerFeePercent,
            old: 50,
            new: 40,
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
    assert_eq!(next.settings.miner_fee_percent, Some(50));
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
fn grant_draws_at_most_half_of_a_live_reserve() {
    // Audit F010: a grant of all but one reserve atom left both outcomes on
    // a curve too steep for any fill until resolution.
    let c = config();
    let s = funded(&c);
    let capacity = consensus::grant_capacity(&s.world);
    assert_eq!(capacity, &s.world.revenue + (&s.world.reserve >> 1usize));
    let mut world = s.world.clone();
    consensus::grant_reserve(&c, &mut world, &capacity).unwrap();
    assert_eq!(world.reserve, &s.world.reserve - (&s.world.reserve >> 1usize));
    world.validate(&c, &s.issued, &s.auction_escrow).unwrap();
    let before = world.root();
    assert!(consensus::grant_reserve(&c, &mut world, &1u32.into()).is_err());
    assert_eq!(before, world.root());
    let mut world = s.world.clone();
    assert!(consensus::grant_reserve(&c, &mut world, &(capacity + 1u32)).is_err());
    // One reserve atom still remains under any live Stash.
    world.reserve = 1u32.into();
    world.revenue = Amount::from(0u32);
    assert_eq!(consensus::grant_capacity(&world), Amount::from(0u32));
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
fn replenished_reserve_funds_repeated_grants_without_historical_spending_limits() {
    let mut c = config();
    c.max_height = 1000;
    c.money_bits = 265;
    c.initial.miner_fee_percent = Some(0);
    c.validate().unwrap();
    let unit = Amount::from(1u32) << 255usize;
    let mut s = State::genesis(&c);
    // Fund through normal issuance, within the configured lifetime proof.
    for _ in 0..600 {
        s = consensus::execute(&c, &s, &s.root(), &owner(), &unit, &[]).unwrap();
    }
    s.audit(&c).unwrap();
    let issued = s.issued.clone();
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: &unit * 400u32,

            decision: None,
            outcome: None,
        },
    );
    s = step(&c, &s, 0, &[tx]);
    // Half of the reserve, the most one grant may draw.
    let grant = &unit * 200u32;
    for _ in 0..4 {
        assert!(consensus::grant_capacity(&s.world) >= grant);
        let tx = propose(
            &s,
            Proposal::Grant {
                payments: vec![GrantPayment {
                    recipient: owner(),
                    amount: grant.clone(),
                }],
            },
        );
        s = step(&c, &s, 0, &[tx]);
        assert!(s.decision_id().is_some());
        assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, grant);
        let buy = sign(
            &s,
            Operation::Deposit {
                amount: unit.clone(),

                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
        );
        s = step(&c, &s, 0, &[buy]);
        let pass_cash = s.account(&owner(), Some(Outcome::Pass)).unwrap().ordinary;
        while s.decision_id().is_some() {
            s = step(&c, &s, 0, &[]);
        }
        assert_eq!(
            s.account(&owner(), None).unwrap().ordinary,
            pass_cash + &grant
        );
        assert_eq!(s.world.grant_escrow, 0u32.into());
        assert_eq!(s.issued, issued);
        // A normal fee returns cash to reserve backing for the next grant.
        let mut tx = sign(
            &s,
            Operation::TransferExact {
                recipient: owner(),
                amount: 1u32.into(),
            },
        );
        tx.body.fee = grant.clone();
        tx = crypto::sign(&tx.body, &SECRET).unwrap();
        s = step(&c, &s, 0, &[tx]);
    }
    s.audit(&c).unwrap();
    let bytes = codec::encode(&s);
    let restored: State = codec::decode(&bytes, bytes.len()).unwrap();
    assert_eq!(restored.root(), s.root());
    restored.audit(&c).unwrap();
}

#[test]
fn active_decision_audit_checks_the_pending_value_at_its_activation_clock() {
    // A clock range shorter than the height range lets the decision open
    // near the clock's end (see the test above).
    let mut c = config();
    c.max_height = i64::MAX as u64;
    c.initial.decision_blocks = 4;
    c.validate().unwrap();
    let s = funded(&c);
    let (old, new) = (c.initial.decision_blocks, 3);
    let tx = propose(
        &s,
        Proposal::Parameter {
            parameter: Parameter::DecisionBlocks,
            old,
            new,
        },
    );
    let opened = step(&c, &s, 0, &[tx]);
    let Phase::Governance(d) = &opened.phase else {
        panic!("missing decision")
    };
    let height = d.started_height;
    let length = d.blocks * opened.frozen.interval;
    let opened_at = |started| {
        let mut shifted = opened.clone();
        shifted.clock = started;
        if let Phase::Governance(d) = &mut shifted.phase {
            d.started = started;
        }
        shifted
    };
    // Activation follows one decision later and must leave the next
    // auction's timeout representable under the pending value.
    let latest = u64::MAX - c.auction_timeout_for(&opened.frozen).unwrap() - length;
    opened_at(latest).validate(&c).unwrap();
    let error = opened_at(latest + 1).validate(&c).unwrap_err();
    assert!(
        error.to_string().contains("schedule deadline overflow"),
        "{error}"
    );
    // The same governed value still fits at the decision's opening clock.
    c.parameter_change_at(
        &opened.frozen,
        Parameter::DecisionBlocks,
        old,
        new,
        latest + 1,
        height,
    )
    .unwrap();
}
