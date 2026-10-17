//! Genesis has arithmetic/construction bounds, not policy grids. Governed
//! changes add only the bounds that keep a passed change reversible.
use hashstash::{
    config::{
        Config, MAX_GOVERNED_DURATION, MIN_GOVERNED_BLOCK_BYTES, MIN_GOVERNED_DECISION_BLOCKS,
    },
    consensus, crypto, math,
    state::{Phase, State},
    types::Parameter,
};

#[test]
fn block_capacity_has_only_account_work_and_representation_bounds() {
    let c = Config::testnet();
    let mut settings = c.initial.clone();
    for capacity in [
        MIN_GOVERNED_BLOCK_BYTES,
        1_025,
        12_345,
        64 * 1024 * 1024,
        isize::MAX as u64,
    ] {
        c.parameter_change(
            &settings,
            Parameter::BlockBytes,
            settings.block_bytes,
            capacity,
        )
        .unwrap();
        settings.block_bytes = capacity;
        assert_eq!(c.transaction_bytes(&settings), capacity as usize);
    }
    for capacity in [0, MIN_GOVERNED_BLOCK_BYTES - 1, u64::MAX] {
        assert!(
            c.parameter_change(
                &settings,
                Parameter::BlockBytes,
                settings.block_bytes,
                capacity
            )
            .is_err()
        );
    }
    assert!(
        c.parameter_change(&settings, Parameter::BlockBytes, 2_048, 4_096)
            .is_err()
    );
    assert!(
        c.parameter_change(
            &settings,
            Parameter::BlockBytes,
            settings.block_bytes,
            settings.block_bytes
        )
        .is_err()
    );
    let mut config = c;
    config.max_signatures = usize::MAX;
    config.validate().unwrap();
    config.max_signatures = 0;
    config.validate().unwrap();
}

#[test]
fn parameters_accept_direct_values_and_zero_where_defined() {
    let c = Config::testnet();
    // A leader from the first half of a round must still be able to mature.
    let longest_lead = (c.auction_timeout - c.initial.interval) / 2;
    for (parameter, next) in [
        (Parameter::Lead, 3),
        (Parameter::Lead, 0),
        (Parameter::Lead, longest_lead),
        (Parameter::Rest, 7),
        (Parameter::Rest, 0),
        (Parameter::Rest, MAX_GOVERNED_DURATION),
        (Parameter::DecisionBlocks, 17),
        (Parameter::DecisionBlocks, MIN_GOVERNED_DECISION_BLOCKS),
        (
            Parameter::DecisionBlocks,
            MAX_GOVERNED_DURATION / c.initial.interval,
        ),
        (Parameter::Interval, 61),
        (Parameter::Interval, c.daa_half_life),
        (Parameter::MinimumFeeRate, 0),
        (Parameter::MinimumFeeRate, 2),
        (Parameter::MaxPriceChangeBps, 1),
        (Parameter::MaxPriceChangeBps, u64::MAX),
    ] {
        c.parameter_change(&c.initial, parameter, c.initial.get(parameter), next)
            .unwrap();
        let mut changed = c.clone();
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
    }
    for parameter in [Parameter::Interval, Parameter::DecisionBlocks] {
        assert!(
            c.parameter_change(&c.initial, parameter, c.initial.get(parameter), 0)
                .is_err()
        );
    }
    // Governance cannot select a value that no later decision could undo,
    // although genesis may still start with any representable value.
    for (parameter, next) in [
        // The first observation ties, so PASS could never reach a majority.
        (Parameter::DecisionBlocks, 1),
        (Parameter::DecisionBlocks, 2),
        // Phases that outlast any practical revision.
        (
            Parameter::DecisionBlocks,
            MAX_GOVERNED_DURATION / c.initial.interval + 1,
        ),
        (Parameter::Lead, longest_lead + 1),
        (Parameter::Lead, c.auction_timeout * 8),
        (Parameter::Rest, MAX_GOVERNED_DURATION + 1),
        (Parameter::Rest, u64::MAX - 1),
        // A step beyond the ASERT half life starves the next target.
        (Parameter::Interval, c.daa_half_life + 1),
        (Parameter::Interval, 86_400),
        (Parameter::Interval, 1 << 40),
        // Pinned prices can never produce a PASS lead.
        (Parameter::MaxPriceChangeBps, 0),
        // One decision cannot price every account out of transacting.
        (Parameter::MinimumFeeRate, 3),
        (Parameter::MinimumFeeRate, u64::MAX),
    ] {
        assert!(
            c.parameter_change(&c.initial, parameter, c.initial.get(parameter), next)
                .is_err(),
            "{parameter:?} = {next} must be rejected"
        );
        let mut changed = c.clone();
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
    }
    let mut free = c.initial.clone();
    free.minimum_fee_rate = 0;
    c.parameter_change(&free, Parameter::MinimumFeeRate, 0, 1)
        .unwrap();
    assert!(
        c.parameter_change(&free, Parameter::MinimumFeeRate, 0, 2)
            .is_err()
    );
    let mut lead = c.initial.clone();
    lead.lead = c.auction_timeout * 8;
    assert_eq!(
        c.auction_timeout_for(&lead).unwrap(),
        lead.lead + lead.interval
    );
    lead.lead = u64::MAX;
    assert!(c.validate_governance_settings(&lead).is_err());
}

#[test]
fn deadlines_are_checked_through_the_whole_height_range() {
    let c = Config::testnet();
    let settings = &c.initial;
    let decision = 100;
    let mut changed = settings.clone();
    changed.decision_blocks = decision;
    // Every later block can add one interval before a deadline is computed,
    // so the activation clock must leave room for the whole height range.
    let span = settings.interval * c.max_height
        + c.auction_timeout_for(&changed).unwrap()
        + decision * settings.interval
        + settings.rest
        + 2 * settings.interval;
    let latest = u64::MAX - span;
    let change = |clock| {
        c.parameter_change_at(
            settings,
            Parameter::DecisionBlocks,
            settings.decision_blocks,
            decision,
            clock,
        )
    };
    change(latest).unwrap();
    assert!(change(latest + 1).is_err());
    // The same value is valid without a clock, then stale late in the range.
    c.parameter_change(
        settings,
        Parameter::DecisionBlocks,
        settings.decision_blocks,
        decision,
    )
    .unwrap();
    assert!(change(latest + settings.interval).is_err());
}

#[test]
fn rest_cannot_reach_the_deadline_overflow_window_after_activation() {
    // Audit F012: a Rest checked only at its activation clock A could lie in
    // (u64::MAX - A - timeout, u64::MAX - A]. The next auction then timed out
    // into an unrepresentable rest and every candidate block was invalid.
    let c = Config::testnet();
    let settings = &c.initial;
    let activation = 1_000_000;
    let timeout = c.auction_timeout_for(settings).unwrap();
    for rest in [
        u64::MAX - activation,
        u64::MAX - activation - timeout,
        MAX_GOVERNED_DURATION + 1,
    ] {
        let mut changed = settings.clone();
        changed.rest = rest;
        // The former single-clock check accepted every one of these.
        c.validate_governance_settings_at(&changed, activation)
            .unwrap();
        assert!(
            c.parameter_change_at(settings, Parameter::Rest, settings.rest, rest, activation)
                .is_err()
        );
    }
    c.parameter_change_at(
        settings,
        Parameter::Rest,
        settings.rest,
        MAX_GOVERNED_DURATION,
        activation,
    )
    .unwrap();
}

#[test]
fn decision_block_count_can_be_one() {
    let c = Config::testnet();
    for duration in [1, c.initial.interval - 1, c.initial.interval] {
        let mut changed = c.clone();
        changed.initial.decision_blocks = duration;
        changed.validate().unwrap();
    }
    c.parameter_change(
        &c.initial,
        Parameter::Interval,
        c.initial.interval,
        c.initial.decision_blocks + 1,
    )
    .unwrap();
}

#[test]
fn pass_margin_genesis_supports_every_u64_value_and_governed_margins_stay_reachable() {
    let c = Config::testnet();
    // PASS must lead from observation ceil(N/2), after ceil(N/2)-1 traded
    // blocks that can each move the price by at most MaxPriceChangeBps.
    let reachable = (c.initial.decision_blocks.div_ceil(2) - 1) * c.initial.max_price_change_bps;
    for margin in [1, 123, reachable - 1] {
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, margin)
            .unwrap();
    }
    for margin in [reachable, 10_000, 100_000, u64::MAX] {
        assert!(
            c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, margin)
                .is_err()
        );
    }
    // Shortening the decision or tightening the bound cannot strand a margin.
    let mut wide = c.initial.clone();
    wide.pass_margin_bps = Some(reachable - 1);
    for (parameter, next) in [
        (Parameter::DecisionBlocks, c.initial.decision_blocks - 2),
        (
            Parameter::MaxPriceChangeBps,
            c.initial.max_price_change_bps - 1,
        ),
    ] {
        assert!(
            c.parameter_change(&wide, parameter, wide.get(parameter), next)
                .is_err()
        );
    }
    for margin in [1, 123, 10_000, 100_000, u64::MAX] {
        let mut changed = c.clone();
        changed.initial.pass_margin_bps = Some(margin);
        changed.validate().unwrap();
        assert_ne!(changed.chain_id(), c.chain_id());
        let mut state = State::genesis(&c);
        let root = state.root();
        state.settings.pass_margin_bps = Some(margin);
        assert_ne!(state.root(), root);
        state.settings = c.initial.clone();
        state.frozen.pass_margin_bps = Some(margin);
        assert_ne!(state.root(), root);
    }
    assert!(
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 1, 2)
            .is_err()
    );
    assert!(
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, 0)
            .is_err()
    );
    let mut missing = c.clone();
    missing.initial.pass_margin_bps = None;
    assert!(missing.validate().is_err());
}

#[test]
fn state_validation_and_audit_accept_governed_settings_outside_all_old_grids() {
    let c = Config::testnet();
    let mut state = State::genesis(&c);
    state.settings.block_bytes = 8 * 1024 * 1024;
    state.settings.lead = 1 << 20;
    state.settings.rest = 1 << 21;
    state.settings.decision_blocks = 4096;
    state.settings.pass_margin_bps = Some(u64::MAX);
    state.frozen = state.settings.clone();

    state.audit(&c).unwrap();
    state.settings.block_bytes = 1;
    assert!(state.validate(&c).is_err());
}

#[test]
fn auction_audit_uses_the_same_extended_timeout_as_consensus() {
    for mut c in [Config::testnet()] {
        c.initial.lead = c.auction_timeout * 2;
        c.validate().unwrap();
        let miner = crypto::public_key(&[7; 32]).unwrap();
        let subsidy = math::work(&math::target_from_bits(c.initial_bits).unwrap());
        let mut state = State::genesis(&c);
        for _ in 0..256 {
            if matches!(state.phase, Phase::Auction(_)) {
                break;
            }
            state = consensus::execute(&c, &state, &[0; 32], &miner, &subsidy, &[]).unwrap();
            state.audit(&c).unwrap();
        }
        let Phase::Auction(auction) = &state.phase else {
            panic!("initial rest did not finish")
        };
        let opened = auction.opened;
        let timeout = c.auction_timeout_for(&state.frozen).unwrap();
        assert!(timeout > c.auction_timeout);
        for elapsed in (c.initial.interval..=timeout).step_by(c.initial.interval as usize) {
            state = consensus::execute(&c, &state, &[0; 32], &miner, &subsidy, &[]).unwrap();
            assert_eq!(state.clock - opened, elapsed);
            state.audit(&c).unwrap();
            if elapsed < timeout {
                assert!(matches!(state.phase, Phase::Auction(_)));
            } else {
                assert!(matches!(state.phase, Phase::Rest(_)));
            }
        }
    }
}
