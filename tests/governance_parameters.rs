//! Governance has arithmetic/construction bounds, not policy grids.
use hashstash::{
    config::{Config, MAX_BLOCK_RECORD_BYTES, MAX_INTERVAL_SECONDS, MIN_GOVERNED_BLOCK_BYTES},
    consensus, crypto, math,
    state::{Phase, State},
    types::Parameter,
};

#[test]
fn block_capacity_halves_to_mandatory_weight_and_can_grow_beyond_old_transport_policy() {
    let c = Config::testnet();
    let mut settings = c.initial.clone();
    for capacity in [8_192, 4_096, 2_048] {
        c.parameter_change(
            &settings,
            Parameter::BlockBytes,
            settings.block_bytes,
            capacity,
        )
        .unwrap();
        settings.block_bytes = capacity;
    }
    assert_eq!(settings.block_bytes, MIN_GOVERNED_BLOCK_BYTES);
    assert!(
        c.parameter_change(&settings, Parameter::BlockBytes, 2_048, 1_024)
            .is_err()
    );
    while settings.block_bytes < MAX_BLOCK_RECORD_BYTES as u64 {
        let next = settings.block_bytes * 2;
        c.parameter_change(&settings, Parameter::BlockBytes, settings.block_bytes, next)
            .unwrap();
        settings.block_bytes = next;
    }
    assert!(
        c.parameter_change(&settings, Parameter::BlockBytes, settings.block_bytes, 0)
            .is_err()
    );
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
    assert_eq!(c.max_block_record_bytes(), MAX_BLOCK_RECORD_BYTES);
    assert_eq!(c.transaction_bytes(&settings), MAX_BLOCK_RECORD_BYTES);
    assert!(
        c.parameter_change(
            &settings,
            Parameter::BlockBytes,
            settings.block_bytes,
            settings.block_bytes * 2
        )
        .is_err()
    );
    let mut huge_capacity = c.clone();
    huge_capacity.initial.block_bytes = 1u64 << 63;
    assert!(huge_capacity.validate().is_err());
    let mut huge_record = c.clone();
    huge_record.max_signatures = 100_000;
    huge_record.validate().unwrap();
    huge_record.max_signatures = 100_001;
    assert!(huge_record.validate().is_err());
}

#[test]
fn phase_parameters_have_no_legacy_grid_or_configured_timeout_ceiling() {
    let c = Config::testnet();
    for parameter in [Parameter::Lead, Parameter::Rest] {
        let mut settings = c.initial.clone();
        for _ in 0..30 {
            let old = settings.get(parameter);
            c.parameter_change(&settings, parameter, old, old * 2)
                .unwrap();
            settings.set(parameter, old * 2);
        }
        c.validate_governance_settings(&settings).unwrap();
    }
    let mut odd = c.clone();
    odd.initial.lead = 3;
    odd.initial.rest = 7;
    odd.initial.duration = 17;
    odd.validate().unwrap();
    for (parameter, old, next) in [
        (Parameter::Lead, 3, 6),
        (Parameter::Rest, 7, 14),
        (Parameter::Duration, 17, 34),
    ] {
        odd.parameter_change(&odd.initial, parameter, old, next)
            .unwrap();
        assert!(
            odd.parameter_change(&odd.initial, parameter, old, next + 1)
                .is_err()
        );
    }
    let mut lead = c.initial.clone();
    lead.lead = c.auction_timeout * 8;
    c.validate_governance_settings(&lead).unwrap();
    assert_eq!(
        c.auction_timeout_for(&lead).unwrap(),
        lead.lead + lead.interval
    );
    for parameter in [Parameter::Lead, Parameter::Rest, Parameter::Duration] {
        let mut invalid = c.initial.clone();
        invalid.set(parameter, 0);
        assert!(c.validate_governance_settings(&invalid).is_err());
        invalid.set(parameter, u64::MAX);
        assert!(c.validate_governance_settings(&invalid).is_err());
    }
    let mut short = c.initial.clone();
    short.duration = 4;
    assert!(c.validate_governance_settings(&short).is_err());
    short.duration = 2;
    assert!(c.validate_governance_settings(&short).is_err());
    let mut long = c.initial.clone();
    long.duration = 1 << 20;
    c.validate_governance_settings(&long).unwrap();
    // There is no per-block grant-funding loop. Only the largest possible
    // scheduled clock plus the duration must still fit in its integer.
    long.duration = u64::MAX - c.max_height * MAX_INTERVAL_SECONDS;
    c.validate_governance_settings(&long).unwrap();
    long.duration += 1;
    assert!(c.validate_governance_settings(&long).is_err());
}

#[test]
fn governance_cannot_remove_the_outcome_trading_window() {
    let c = Config::testnet();
    let mut settings = c.initial.clone();
    for duration in [1, settings.interval - 1, settings.interval] {
        settings.duration = duration;
        assert!(c.validate_governance_settings(&settings).is_err());
        let mut invalid_genesis = c.clone();
        invalid_genesis.initial = settings.clone();
        assert!(invalid_genesis.validate().is_err());
    }
    settings.duration = settings.interval + 1;
    c.validate_governance_settings(&settings).unwrap();
    let mut minimum_genesis = c.clone();
    minimum_genesis.initial = settings.clone();
    minimum_genesis.validate().unwrap();

    // Halving a valid duration must not make the next decision untradeable.
    settings.duration = settings.interval * 2;
    assert!(
        c.parameter_change(
            &settings,
            Parameter::Duration,
            settings.duration,
            settings.interval,
        )
        .is_err()
    );
    settings.duration = (settings.interval + 1) * 2;
    c.parameter_change(
        &settings,
        Parameter::Duration,
        settings.duration,
        settings.interval + 1,
    )
    .unwrap();

    // Increasing the block interval has the same liveness constraint.
    settings.duration = 30;
    for interval in [30, 31] {
        assert!(
            c.parameter_change(&settings, Parameter::Interval, settings.interval, interval)
                .is_err()
        );
    }
    c.parameter_change(&settings, Parameter::Interval, settings.interval, 29)
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
