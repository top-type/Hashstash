use hashstash::{
    codec,
    config::{Config, PROTOCOL_VERSION},
    state::State,
    types::Parameter,
};

#[test]
fn checked_in_presets_are_exact_current_configs() {
    for (name, expected) in [
        ("devnet", Config::devnet()),
        ("testnet", Config::testnet()),
        ("slow-testnet", Config::slow_testnet()),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join(format!("{name}.json"));
        let stored: Config = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(stored, expected);
        stored.validate().unwrap();
        assert_eq!(stored.protocol_version, PROTOCOL_VERSION);
        assert_eq!(stored.initial.interval, 15);
    }
    assert_ne!(Config::devnet().chain_id(), Config::testnet().chain_id());
    assert_ne!(
        Config::testnet().chain_id(),
        Config::slow_testnet().chain_id()
    );
}

#[test]
fn protocol28_preset_chain_ids_match_independent_encoding() {
    // Independently packed from the current field order and varints.
    // Protocol and preset changes separate these chains from prior releases.
    for (c, expected) in [
        (
            Config::devnet(),
            "f1c3b5f5e8145ff107ce4637fb933037fc762c69527e55a4d33fe8b9d6fbd2b9",
        ),
        (
            Config::testnet(),
            "fd26b784e3e31ef3167bebe783ee416a0945e942ff26f502435c0d0fb91cabfd",
        ),
        (
            Config::slow_testnet(),
            "3d4c6da867563401f28fc4a9e220c71a923111fc96ecfbff12b49c9fe7023433",
        ),
    ] {
        c.validate().unwrap();
        assert_eq!(hex::encode(c.chain_id()), expected);
    }
}

#[test]
fn unsupported_protocols_and_unknown_settings_fail_closed() {
    for version in [0, PROTOCOL_VERSION - 1, PROTOCOL_VERSION + 1, u32::MAX] {
        let mut config = Config::devnet();
        config.protocol_version = version;
        assert!(config.validate().is_err());
    }
    for location in ["initial", ""] {
        let mut value = serde_json::to_value(Config::devnet()).unwrap();
        let object = if location.is_empty() {
            &mut value
        } else {
            &mut value[location]
        };
        object["unexpected_setting"] = 1.into();
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
}

#[test]
fn changed_genesis_identity_and_every_setting_are_committed() {
    let original = Config::testnet();
    let mut changed = original.clone();
    changed.network.push_str("-private");
    changed.validate().unwrap();
    assert_ne!(original.chain_id(), changed.chain_id());
    changed = original.clone();
    changed.genesis_time += 1;
    assert_ne!(original.chain_id(), changed.chain_id());
    for parameter in original.governance_parameters() {
        changed = original.clone();
        let next = match parameter {
            Parameter::MinerFeePercent => 51,
            Parameter::PassMarginBps => 1,
            Parameter::Interval => 16,
            _ => original.initial.get(parameter) * 2,
        };
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
        assert_ne!(original.chain_id(), changed.chain_id());
    }
}

#[test]
fn governance_timing_uses_arithmetic_domains() {
    let config = Config::testnet();
    for interval in [1, 15, 60, 61, 86_400, 1 << 40] {
        let mut changed = config.clone();
        changed.initial.interval = interval;
        changed.validate().unwrap();
    }
    for interval in [0, u64::MAX] {
        assert!(
            config
                .parameter_change(&config.initial, Parameter::Interval, 15, interval)
                .is_err()
        );
    }
    for duration in [1, config.initial.interval, u64::MAX] {
        let mut changed = config.clone();
        changed.initial.duration = duration;
        changed.validate().unwrap();
    }
}

#[test]
fn genesis_settings_use_defined_domains_without_policy_limits() {
    let mut c = Config::devnet();
    c.daa_half_life = 1;
    c.timestamp_window = 2;
    c.future_seconds = u32::MAX;
    c.max_signatures = usize::MAX;
    c.max_height = i64::MAX as u64;
    c.max_integer_bits = u64::MAX;
    c.quote_scale = hashstash::types::Amount::from(1u32) << 300usize;
    c.auction_timeout = 0;
    c.initial.rest = 0;
    c.initial.lead = 0;
    c.initial.minimum_fee_rate = 0;
    c.validate().unwrap();
    c.daa_half_life = u64::MAX;
    c.timestamp_window = usize::MAX;
    c.validate().unwrap();
    for field in ["timestamp_window", "daa_half_life"] {
        let mut value = serde_json::to_value(&c).unwrap();
        value[field] = 0.into();
        assert!(
            serde_json::from_value::<Config>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    c.initial.block_bytes = u64::MAX;
    assert!(c.validate().is_err());
    c = Config::devnet();
    c.genesis_time = u32::MAX;
    assert!(c.validate().is_err());
}

#[test]
fn obsolete_grant_cap_config_and_state_fields_are_rejected() {
    let config = Config::devnet();
    for (field, value) in [
        ("reserve_min", serde_json::json!("100")),
        ("grant_numerator", serde_json::json!(0)),
        ("grant_denominator", serde_json::json!(0)),
        ("budget_numerator", serde_json::json!(0)),
        ("budget_denominator", serde_json::json!(0)),
        ("budget_period", serde_json::json!(30720)),
    ] {
        let mut old = serde_json::to_value(&config).unwrap();
        old[field] = value;
        assert!(serde_json::from_value::<Config>(old).is_err(), "{field}");
    }
    let state = State::genesis(&config);
    for (field, value) in [
        ("budgets", serde_json::json!([])),
        ("budget_start", serde_json::Value::Null),
        ("budget_epoch", serde_json::json!(0)),
    ] {
        let mut old = serde_json::to_value(&state).unwrap();
        old[field] = value;
        assert!(serde_json::from_value::<State>(old).is_err(), "{field}");
    }
}

#[test]
fn prior_serialized_config_and_genesis_state_fail_closed() {
    let config = Config::devnet();
    let mut old_config = config.consensus_bytes();
    // Protocol 27 put reserve minimum, four ratio integers and the period
    // between auction_timeout and initial Settings in the canonical encoding.
    let offset = old_config.len() - codec::encode(&config.initial).len();
    let removed = codec::encode(&(vec![100u8], 0u64, 0u64, 0u64, 0u64, 30_720u64));
    old_config.splice(offset..offset, removed);
    old_config[0] = 27;
    let network_suffix = old_config.windows(3).position(|w| w == b"v28").unwrap();
    old_config[network_suffix + 2] = b'7';
    assert!(codec::decode::<Config>(&old_config, old_config.len()).is_err());

    let state = State::genesis(&config);
    let mut old_state = codec::encode(&state);
    // The old empty map, absent start, and epoch zero precede last_round and
    // last_epoch. Even an empty old snapshot must not silently lose fields.
    let offset = old_state.len() - codec::encode(&(state.last_round, state.last_epoch)).len();
    old_state.splice(offset..offset, [0u8; 3]);
    old_state[..32].copy_from_slice(
        &hex::decode("f62127c60825be20ee7c19f6d5ef79712ab2f4c525c6e179091407f5c082dac2").unwrap(),
    );
    assert!(codec::decode::<State>(&old_state, old_state.len()).is_err());
}
