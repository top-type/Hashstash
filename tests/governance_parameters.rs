//! Governance has arithmetic/construction bounds, not policy grids.
use hashstash::{
    config::{Config, MIN_GOVERNED_BLOCK_BYTES},
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
    for (parameter, next) in [
        (Parameter::Lead, 3),
        (Parameter::Lead, 0),
        (Parameter::Rest, 7),
        (Parameter::Rest, 0),
        (Parameter::Duration, 17),
        (Parameter::Duration, 1),
        (Parameter::Interval, 61),
        (Parameter::Interval, 1 << 40),
        (Parameter::MinimumFeeRate, 0),
        (Parameter::MinimumFeeRate, 7),
    ] {
        c.parameter_change(&c.initial, parameter, c.initial.get(parameter), next)
            .unwrap();
        let mut changed = c.clone();
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
    }
    for parameter in [Parameter::Interval, Parameter::Duration] {
        assert!(
            c.parameter_change(&c.initial, parameter, c.initial.get(parameter), 0)
                .is_err()
        );
    }
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
fn deadlines_are_checked_at_the_actual_activation_clock() {
    let c = Config::testnet();
    let clock = 1_000;
    let duration = u64::MAX - clock;
    c.parameter_change_at(
        &c.initial,
        Parameter::Duration,
        c.initial.duration,
        duration,
        clock,
    )
    .unwrap();
    assert!(
        c.parameter_change_at(
            &c.initial,
            Parameter::Duration,
            c.initial.duration,
            duration + 1,
            clock
        )
        .is_err()
    );
    // The same value can be arithmetically valid earlier, then become stale.
    c.parameter_change(
        &c.initial,
        Parameter::Duration,
        c.initial.duration,
        duration + 1,
    )
    .unwrap();
    assert!(
        c.parameter_change_at(
            &c.initial,
            Parameter::Duration,
            c.initial.duration,
            duration,
            clock + 1
        )
        .is_err()
    );
}

#[test]
fn decision_duration_can_be_shorter_than_one_block() {
    let c = Config::testnet();
    for duration in [1, c.initial.interval - 1, c.initial.interval] {
        let mut changed = c.clone();
        changed.initial.duration = duration;
        changed.validate().unwrap();
    }
    c.parameter_change(
        &c.initial,
        Parameter::Interval,
        c.initial.interval,
        c.initial.duration + 1,
    )
    .unwrap();
}

#[test]
fn pass_margin_supports_every_u64_value_and_is_committed_in_genesis_and_frozen_state() {
    let c = Config::testnet();
    for margin in [1, 123, 10_000, 100_000, u64::MAX] {
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, margin)
            .unwrap();
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
    state.settings.duration = 4096;
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
