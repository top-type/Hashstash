//! Timestamps determine mining pace; policy schedules advance in nominal seconds.
mod support;
use hashstash::{
    chain::Chain,
    config::Config,
    consensus, crypto, math,
    state::{Phase, State},
    types::*,
};

const SECRET: [u8; 32] = [147; 32];
fn miner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.genesis_time = 1_700_000_000;
    c.initial_bits = 0x201fffff;
    c.limit_bits = 0x207fffff;
    c.initial.lead = 2 * 15;
    c.initial.decision_blocks = 12;
    c.initial.rest = 4 * 15;
    c.validate().unwrap();
    c
}
fn append(chain: &mut Chain, seconds: u32, txs: Vec<Transaction>) -> Block {
    let timestamp = chain.tip_block().header.timestamp + seconds;
    let template = chain.template(miner(), txs, timestamp).unwrap();
    let block = Chain::mine(template, 1_000_000).unwrap();
    assert!(chain.submit(block.clone(), u64::from(timestamp)).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
    block
}
fn sign(s: &State, operation: Operation) -> Transaction {
    support::sign_minimum(
        s,
        TransactionBody {
            chain_id: s.chain_id,
            sender: miner(),
            nonce: s.account(&miner(), None).unwrap().nonce,
            fee: 100_000u32.into(),
            expiry_height: s.height + 10_000,
            operation,
            data: vec![],
        },
        &SECRET,
        0,
    )
}

#[test]
fn current_genesis_files_match_the_canonical_work_presets() {
    for (name, expected) in [
        ("devnet", Config::devnet()),
        ("testnet", Config::testnet()),
        ("slow-testnet", Config::slow_testnet()),
    ] {
        let bytes = std::fs::read(format!("config/{name}.json")).unwrap();
        let actual: Config = serde_json::from_slice(&bytes).unwrap();
        actual.validate().unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn canonical_timing_adjusts_work() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let mut fast = Chain::open(&d.path().join("fast.sqlite"), c.clone()).unwrap();
    let mut paced = Chain::open(&d.path().join("paced.sqlite"), c.clone()).unwrap();
    let mut slow = Chain::open(&d.path().join("slow.sqlite"), c.clone()).unwrap();
    for _ in 0..64 {
        append(&mut fast, 5, vec![]);
        append(&mut paced, 15, vec![]);
        append(&mut slow, 30, vec![]);
    }
    let initial = math::target_from_bits(c.initial_bits).unwrap();
    assert!(fast.next_target().unwrap() < initial);
    assert_eq!(paced.next_target().unwrap(), initial);
    assert!(slow.next_target().unwrap() > initial);
    for chain in [&fast, &paced, &slow] {
        assert_eq!(chain.expected_elapsed_seconds(), 64 * 15);
        assert_eq!(chain.tip_state().clock, 64 * 15);
    }
}

#[test]
fn delayed_first_mining_anchors_asert_without_advancing_economic_time() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let mut timely = Chain::open(&d.path().join("timely.sqlite"), c.clone()).unwrap();
    let mut delayed = Chain::open(&d.path().join("delayed.sqlite"), c.clone()).unwrap();
    let initial = math::target_from_bits(c.initial_bits).unwrap();
    assert_eq!(delayed.next_target().unwrap(), initial);
    let first = append(&mut timely, 15, vec![]);
    let late_first = append(&mut delayed, 23 * 60 * 60, vec![]);
    assert_eq!(late_first.header.bits, c.initial_bits);
    assert_eq!(delayed.next_target().unwrap(), initial);
    assert_eq!(delayed.chain_work(), timely.chain_work());
    assert_eq!(delayed.tip_state().issued, timely.tip_state().issued);
    assert_eq!(delayed.expected_elapsed_seconds(), c.initial.interval);
    assert_eq!(delayed.tip_state().clock, c.initial.interval);
    assert!(matches!(delayed.tip_state().phase, Phase::Rest(_)));
    assert_ne!(first.header.timestamp, late_first.header.timestamp);
    // The delay before the first solution has no effect on later adjustment.
    // Subsequent fast/slow blocks still change difficulty normally.
    for seconds in [15, 5, 30, 15, 60, 5] {
        let normal = append(&mut timely, seconds, vec![]);
        let late = append(&mut delayed, seconds, vec![]);
        assert_eq!(late.header.bits, normal.header.bits);
        assert_eq!(
            delayed.next_target().unwrap(),
            timely.next_target().unwrap()
        );
        assert_eq!(delayed.chain_work(), timely.chain_work());
        assert_eq!(delayed.tip_state().issued, timely.tip_state().issued);
    }
    assert_ne!(delayed.next_target().unwrap(), initial);
}

#[test]
fn competing_first_blocks_keep_branch_anchors_across_reorg_and_reopen() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let path = d.path().join("observer.sqlite");
    let mut observer = Chain::open(&path, c.clone()).unwrap();
    let mut late = Chain::open(&d.path().join("late.sqlite"), c.clone()).unwrap();
    let mut early = Chain::open(&d.path().join("early.sqlite"), c.clone()).unwrap();
    let late_blocks = [
        append(&mut late, 23 * 60 * 60, vec![]),
        append(&mut late, 30, vec![]),
    ];
    for block in &late_blocks {
        observer
            .submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(observer.tip_hash(), late.tip_hash());
    let mut early_blocks = vec![append(&mut early, 15, vec![])];
    for _ in 0..3 {
        early_blocks.push(append(&mut early, 5, vec![]));
    }
    assert!(early.chain_work() > late.chain_work());
    for block in early_blocks {
        observer
            .submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(observer.tip_hash(), early.tip_hash());
    assert_eq!(
        observer.next_target().unwrap(),
        early.next_target().unwrap()
    );
    assert_eq!(observer.tip_state().root(), early.tip_state().root());
    drop(observer);
    let mut observer = Chain::open(&path, c.clone()).unwrap();
    assert_eq!(
        observer.next_target().unwrap(),
        early.next_target().unwrap()
    );
    // Extend the previously losing branch: it retains its original anchor,
    // including after the receiver rebuilt its derived metadata on reopen.
    while late.chain_work() <= early.chain_work() {
        let block = append(&mut late, 30, vec![]);
        observer
            .submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(observer.tip_hash(), late.tip_hash());
    assert_eq!(observer.next_target().unwrap(), late.next_target().unwrap());
    assert_eq!(observer.tip_state().root(), late.tip_state().root());
    let root = late.tip_state().root();
    let target = late.next_target().unwrap();
    drop(observer);
    let observer = Chain::open(&path, c).unwrap();
    assert_eq!(observer.tip_state().root(), root);
    assert_eq!(observer.next_target().unwrap(), target);
}

#[test]
fn median_past_time_and_future_rejection_apply_with_retryable_future_blocks() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let mut chain = Chain::open(&d.path().join("time.sqlite"), c.clone()).unwrap();
    let mut past = chain.template(miner(), vec![], c.genesis_time + 1).unwrap();
    past.header.timestamp = c.genesis_time;
    let past = Chain::mine(past, 1_000_000).unwrap();
    assert!(
        chain
            .submit(past, u64::from(c.genesis_time))
            .unwrap_err()
            .to_string()
            .contains("median")
    );
    let future = Chain::mine(
        chain
            .template(miner(), vec![], c.genesis_time + 121)
            .unwrap(),
        1_000_000,
    )
    .unwrap();
    assert!(
        chain
            .submit(future.clone(), u64::from(c.genesis_time))
            .unwrap_err()
            .to_string()
            .contains("future")
    );
    assert!(chain.submit(future, u64::from(c.genesis_time + 1)).unwrap());
    for _ in 0..11 {
        append(&mut chain, 15, vec![]);
    }
    let minimum = chain.template(miner(), vec![], 0).unwrap().header.timestamp;
    let mut bad = chain.template(miner(), vec![], minimum).unwrap();
    bad.header.timestamp = minimum - 1;
    let bad = Chain::mine(bad, 1_000_000).unwrap();
    assert!(
        chain
            .submit(bad, u64::from(chain.tip_block().header.timestamp))
            .is_err()
    );
}

#[test]
fn reorg_and_reopen_rebuild_the_correct_expected_schedule() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let path = d.path().join("main.sqlite");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&d.path().join("fork.sqlite"), c.clone()).unwrap();
    for _ in 0..3 {
        append(&mut main, 30, vec![]);
    }
    for _ in 0..8 {
        let block = append(&mut fork, 5, vec![]);
        main.submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(main.tip_hash(), fork.tip_hash());
    assert_eq!(main.expected_elapsed_seconds(), 8 * 15);
    let target = main.next_target().unwrap();
    let root = main.tip_state().root();
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.expected_elapsed_seconds(), 8 * 15);
    assert_eq!(reopened.next_target().unwrap(), target);
    assert_eq!(reopened.tip_state().root(), root);
}

#[test]
fn interval_governance_changes_future_schedule_without_accelerating_economics() {
    let d = tempfile::tempdir().unwrap();
    let mut c = config();
    c.initial_bits = 0x1f7fffff;
    let path = d.path().join("governance.sqlite");
    let mut chain = Chain::open(&path, c.clone()).unwrap();
    append(&mut chain, 23 * 60 * 60, vec![]);
    assert_eq!(
        chain.next_target().unwrap(),
        math::target_from_bits(c.initial_bits).unwrap()
    );
    for _ in 0..100 {
        append(&mut chain, 15, vec![]);
        if matches!(chain.tip_state().phase, Phase::Auction(_)) {
            break;
        }
    }
    assert!(matches!(chain.tip_state().phase, Phase::Auction(_)));
    let amount = chain.tip_state().account(&miner(), None).unwrap().ordinary / 2u32;
    let deposit = sign(
        chain.tip_state(),
        Operation::Deposit {
            amount,

            decision: None,
            outcome: None,
        },
    );
    append(&mut chain, 15, vec![deposit]);
    for _ in 0..5 {
        append(&mut chain, 15, vec![]);
    }
    // A parameter decision needs price-responsive markets. Establish their
    // slope through a real, passing grant on the mined chain first.
    let grant = &chain.tip_state().world.reserve / 20u32;
    let proposal = sign(
        chain.tip_state(),
        Operation::Propose {
            round: chain.tip_state().auction_round().unwrap(),
            description: [17; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient: miner(),
                    amount: grant.clone(),
                }],
            },
            support: 10u32.into(),
        },
    );
    append(&mut chain, 15, vec![proposal]);
    for _ in 0..30 {
        if chain.tip_state().decision_id().is_some() {
            break;
        }
        append(&mut chain, 15, vec![]);
    }
    let state = chain.tip_state();
    assert_eq!(state.alternative.as_ref().unwrap().grant_escrow, grant);
    let trade = sign(
        state,
        Operation::Deposit {
            amount: 1000u32.into(),

            decision: state.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    append(&mut chain, 15, vec![trade]);
    for _ in 0..100 {
        if matches!(chain.tip_state().phase, Phase::Auction(_)) {
            break;
        }
        append(&mut chain, 15, vec![]);
    }
    assert!(matches!(chain.tip_state().phase, Phase::Auction(_)));
    assert!(chain.tip_state().world.curve_mass > chain.tip_state().world.reserve);
    assert_eq!(chain.tip_state().world.grant_escrow, 0u32.into());
    let mut fork = Chain::open(&d.path().join("no-change.sqlite"), c.clone()).unwrap();
    for height in 1..=chain.tip_height() {
        let block = chain.block(&chain.hash_at_height(height).unwrap()).unwrap();
        fork.submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    let s = chain.tip_state();
    let tx = sign(
        s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [16; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::Interval,
                old: 15,
                new: 10,
            },
            support: 10u32.into(),
        },
    );
    append(&mut chain, 15, vec![tx]);
    for _ in 0..30 {
        if chain.tip_state().decision_id().is_some() {
            break;
        }
        append(&mut chain, 15, vec![]);
    }
    let s = chain.tip_state();
    assert!(s.decision_id().is_some());
    let tx = sign(
        s,
        Operation::Deposit {
            amount: 1000u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    append(&mut chain, 15, vec![tx]);
    for _ in 0..100 {
        if chain.tip_state().settings.interval == 10 {
            break;
        }
        append(&mut chain, 15, vec![]);
    }
    assert_eq!(chain.tip_state().settings.interval, 10);
    let before = chain.expected_elapsed_seconds();
    assert_eq!(before, chain.tip_height() * 15);
    assert_eq!(chain.tip_state().clock, before);
    assert_eq!(chain.tip_state().settings.lead, c.initial.lead);
    assert_eq!(
        chain.tip_state().settings.decision_blocks,
        c.initial.decision_blocks
    );
    assert_eq!(chain.tip_state().settings.rest, c.initial.rest);
    append(&mut chain, 10, vec![]);
    assert_eq!(chain.expected_elapsed_seconds(), before + 10);
    assert_eq!(chain.tip_state().clock, before + 10);
    let target = chain.next_target().unwrap();
    let expected = math::asert(
        &math::target_from_bits(c.initial_bits).unwrap(),
        0,
        c.daa_half_life,
        &math::target_from_bits(c.limit_bits).unwrap(),
    );
    assert_eq!(target, expected);
    drop(chain);
    let mut chain = Chain::open(&path, c.clone()).unwrap();
    assert_eq!(chain.tip_state().settings.interval, 10);
    assert_eq!(chain.expected_elapsed_seconds(), before + 10);
    assert_eq!(chain.next_target().unwrap(), target);
    while fork.chain_work() <= chain.chain_work() {
        append(&mut fork, 15, vec![]);
    }
    for height in 1..=fork.tip_height() {
        let block = fork.block(&fork.hash_at_height(height).unwrap()).unwrap();
        chain
            .submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(chain.tip_hash(), fork.tip_hash());
    assert_eq!(chain.tip_state().settings.interval, 15);
    assert_eq!(chain.expected_elapsed_seconds(), chain.tip_height() * 15);
    assert_eq!(chain.next_target().unwrap(), target);
    drop(chain);
    let chain = Chain::open(&path, c).unwrap();
    assert_eq!(chain.tip_hash(), fork.tip_hash());
    assert_eq!(chain.expected_elapsed_seconds(), chain.tip_height() * 15);
}

#[test]
fn immediate_revenue_replenishment_is_independent_of_block_interval() {
    let c = config();
    let mut s = State::genesis(&c);
    for _ in 0..30 {
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1000u32.into(), &[]).unwrap();
    }
    let deposit = sign(
        &s,
        Operation::Deposit {
            amount: 10_000u32.into(),

            decision: None,
            outcome: None,
        },
    );
    s = consensus::execute(&c, &s, &s.root(), &miner(), &0u32.into(), &[deposit]).unwrap();
    s.world.curve_mass += 500u32;
    s.world.revenue += 1000u32;
    s.issued += 1000u32;
    s.audit(&c).unwrap();
    let reserve = s.world.reserve.clone();
    let revenue = s.world.revenue.clone();
    let mass = s.world.curve_mass.clone();
    let quote = s.world.quote(&c);
    let clock = s.clock;
    for interval in [15, 60] {
        let mut before = s.clone();
        before.settings.interval = interval;
        before.frozen.interval = interval;
        let after = consensus::execute(&c, &before, &before.root(), &miner(), &1000u32.into(), &[])
            .unwrap();
        assert_eq!(after.clock, clock + interval);
        assert_eq!(after.world.reserve, &reserve + 500u32);
        assert_eq!(after.world.curve_mass, mass);
        assert_eq!(after.world.revenue, &revenue - 500u32);
        assert_eq!(after.world.quote(&c), quote);
        after.audit(&c).unwrap();
    }
}

#[test]
fn time_policies_preserve_nominal_duration_at_different_intervals() {
    let c = config();
    let initial = State::genesis(&c);
    assert!(matches!(initial.phase, Phase::Rest(_)));
    for interval in [5u64, 10, 15, 30, 60] {
        let mut s = initial.clone();
        s.settings.interval = interval;
        s.frozen.interval = interval;
        let start = s.clock;
        let mut blocks = 0;
        while matches!(s.phase, Phase::Rest(_)) {
            s = consensus::execute(&c, &s, &s.root(), &miner(), &1000u32.into(), &[]).unwrap();
            s.audit(&c).unwrap();
            blocks += 1;
        }
        assert_eq!(blocks, c.initial.rest.div_ceil(interval));
        assert_eq!(s.clock - start, c.initial.rest);
        assert_eq!(s.settings.rest, c.initial.rest);
    }
}

#[test]
fn decision_duration_is_independent_of_removed_funding_steps() {
    let c = config();
    let mut settings = c.initial.clone();
    settings.interval = 60;
    settings.decision_blocks = 4096 * 60 + 1;
    c.validate_governance_settings(&settings).unwrap();
    c.parameter_change(&settings, Parameter::Interval, 60, 30)
        .unwrap();
}

#[test]
fn immediate_grant_uses_waiting_cash_then_backing_and_keeps_price() {
    let c = config();
    let mut world = State::genesis(&c).world;
    world.reserve = 10_000u32.into();
    world.curve_mass = world.reserve.clone();
    world.shares = Amount::from(10u32).pow(30);
    world.revenue = 600u32.into();
    let before = world.quote(&c);
    consensus::grant_reserve(&c, &mut world, &1600u32.into()).unwrap();
    assert_eq!(world.reserve, 9000u32.into());
    assert_eq!(world.revenue, 0u32.into());
    assert_eq!(world.grant_escrow, 1600u32.into());
    assert_eq!(world.quote(&c), before);
}

#[test]
fn grant_decision_counts_blocks_and_reserves_upfront() {
    let mut c = config();
    c.initial.decision_blocks = 3;
    let mut s = State::genesis(&c);
    for _ in 0..30 {
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    }
    assert!(matches!(s.phase, Phase::Auction(_)));
    let reserve_deposit = sign(
        &s,
        Operation::Deposit {
            amount: 10_000_000u32.into(),

            decision: None,
            outcome: None,
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &0u32.into(),
        &[reserve_deposit],
    )
    .unwrap();
    let grant: Amount = 100_001u32.into();
    let proposal = sign(
        &s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [29; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient: miner(),
                    amount: grant.clone(),
                }],
            },
            support: 10u32.into(),
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &1_000_000u32.into(),
        &[proposal],
    )
    .unwrap();
    for _ in 0..10 {
        if s.decision_id().is_some() {
            break;
        }
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    }
    let Phase::Governance(decision) = s.phase.clone() else {
        panic!("grant decision expected")
    };
    assert_eq!(decision.blocks, 3);
    assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, grant);
    assert!(consensus::grant_capacity(&s.world) >= grant);
    s.audit(&c).unwrap();
    let deposit = sign(
        &s,
        Operation::Deposit {
            amount: 2_000_000u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &1_000_000u32.into(),
        &[deposit],
    )
    .unwrap();
    assert_eq!(s.clock - decision.started, 15);
    assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, grant);
    s.audit(&c).unwrap();
    s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    assert_eq!(s.clock - decision.started, 30);
    assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, grant);
    s.audit(&c).unwrap();
    let pass = s.alternative.as_ref().unwrap();
    let pass_cash = pass
        .account(&miner(), Some(decision.epoch))
        .unwrap()
        .ordinary;
    let pass_quote = pass.quote(&c);
    assert!(consensus::pass_beats_fail(
        &pass_quote,
        &s.world.quote(&c),
        0
    ));
    assert!(matches!(&s.phase, Phase::Governance(d) if d.leading_blocks == 1));
    s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    assert_eq!(s.clock - decision.started, 45);
    assert!(matches!(s.phase, Phase::Rest(_)));
    assert!(s.alternative.is_none());
    assert_eq!(
        s.account(&miner(), None).unwrap().ordinary,
        pass_cash + grant + 1_000_000u32
    );
    s.audit(&c).unwrap();
}

#[test]
fn shortest_decision_allows_an_outcome_trade_and_successful_governance() {
    let mut c = config();
    c.initial.decision_blocks = 3;
    c.validate().unwrap();
    let mut s = State::genesis(&c);
    for _ in 0..30 {
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    }
    let reserve_deposit = sign(
        &s,
        Operation::Deposit {
            amount: 10_000_000u32.into(),

            decision: None,
            outcome: None,
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &0u32.into(),
        &[reserve_deposit],
    )
    .unwrap();
    // Model a settled prior grant: transfer backing into the recipient's cash
    // while retaining mass and stash, rather than inventing a sloped price.
    let prior_grant = Amount::from(1_000_000u32);
    s.world.reserve -= &prior_grant;
    let mut recipient = s.account(&miner(), None).unwrap();
    recipient.ordinary += prior_grant;
    s.world.put(miner(), recipient, &c).unwrap();
    assert!(s.world.curve_mass > s.world.reserve);
    s.audit(&c).unwrap();
    let new_capacity = c.initial.block_bytes * 2;
    let proposal = sign(
        &s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [30; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: c.initial.block_bytes,
                new: new_capacity,
            },
            support: 10u32.into(),
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &1_000_000u32.into(),
        &[proposal],
    )
    .unwrap();
    for _ in 0..10 {
        if s.decision_id().is_some() {
            break;
        }
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    }
    let Phase::Governance(decision) = s.phase.clone() else {
        panic!("parameter decision expected")
    };
    assert_eq!(decision.blocks, 3);
    s.audit(&c).unwrap();
    let deposit = sign(
        &s,
        Operation::Deposit {
            amount: 2_000_000u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    s = consensus::execute(
        &c,
        &s,
        &s.root(),
        &miner(),
        &1_000_000u32.into(),
        &[deposit],
    )
    .unwrap();
    assert_eq!(s.clock - decision.started, 15);
    assert!(matches!(s.phase, Phase::Governance(_)));
    assert!(s.alternative.as_ref().unwrap().quote(&c) > s.world.quote(&c));
    s.audit(&c).unwrap();
    s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    assert_eq!(s.clock - decision.started, 30);
    assert!(matches!(&s.phase, Phase::Governance(d) if d.leading_blocks == 1));
    s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    let Phase::Rest(rest) = &s.phase else {
        panic!("resolved parameter decision expected")
    };
    assert_eq!(rest.pending, Some((Parameter::BlockBytes, new_capacity)));
    assert_eq!(s.settings.block_bytes, c.initial.block_bytes);
    for _ in 0..c.initial.rest.div_ceil(c.initial.interval) {
        s = consensus::execute(&c, &s, &s.root(), &miner(), &1_000_000u32.into(), &[]).unwrap();
    }
    assert_eq!(
        s.settings.block_bytes, new_capacity,
        "the shortest valid decision can still enact a parameter change"
    );
    s.audit(&c).unwrap();
}
