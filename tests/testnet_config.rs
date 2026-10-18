use hashstash::{codec, config::Config, state::State, types::Parameter};

#[test]
fn checked_in_presets_are_exact_current_configs() {
    for (name, mut expected) in [
        ("devnet", Config::devnet()),
        ("testnet", Config::testnet()),
        ("slow-testnet", Config::slow_testnet()),
    ] {
        expected.test_work = false;
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("config")
            .join(format!("{name}.json"));
        let stored: Config = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(stored, expected);
        stored.validate().unwrap();
        assert_eq!(stored.initial.interval, 15);
    }
    assert_ne!(Config::devnet().chain_id(), Config::testnet().chain_id());
    assert_ne!(
        Config::testnet().chain_id(),
        Config::slow_testnet().chain_id()
    );
}

#[test]
fn preset_chain_ids_match_independent_encoding() {
    // Independently packed: length-prefixed network name, variable-width
    // a false fixture flag, little-endian integers in Config field order, magnitude byte vectors for
    // amounts, then Settings in declaration order: block_bytes, fee rate,
    // interval, lead, rest, decision_blocks, max_price_change_bps, and the
    // presence-prefixed miner percentage and PASS margin. These vectors were
    // packed with a separate Python integer/byte encoder, not Rust serialization.
    // Expected IDs use SHA256(SHA256(tag) || SHA256(tag) || encoded_config).
    for (mut c, encoded, expected) in [
        (
            Config::devnet(),
            "106861736873746173682d6465766e657400fc800e8069fcffff7f20fcffff7f20fb84030b78fb0010fcfffffffffb0002fb0002fb00200d00000040eaed7446d09c2c9f0c0101fb8007fb0040010f3cfbc00320fbe80301320100",
            "197183553428c9fd81631ac214b50cb63fdee0331dcddc3108b4096baeb288db",
        ),
        (
            Config::testnet(),
            "116861736873746173682d746573746e657400fc800e8069fcffff7f20fcffff7f20fb84030b78fb0010fcfffffffffb0002fb0002fb00200d00000040eaed7446d09c2c9f0c0101fbe001fb0040010f3cfbe00110fbe80301320100",
            "48a1af4cfe99364f96ba5967a02da383de85e3aa888bcd6ef3b25c1243a1b5c7",
        ),
        (
            Config::slow_testnet(),
            "166861736873746173682d736c6f772d746573746e657400fc800e8069fcffff7f20fcffff7f20fb84030b78fb0010fcfffffffffb0002fb0002fb00200d00000040eaed7446d09c2c9f0c0101fb100efb0040010ffb2c01fb302af0fbe80301320100",
            "83021890fef7119376e555a018854b30a41282721fe545174156a24f0a6fd782",
        ),
    ] {
        c.test_work = false;
        c.validate().unwrap();
        assert_eq!(c.consensus_bytes(), hex::decode(encoded).unwrap());
        assert_eq!(hex::encode(c.chain_id()), expected);
    }
}

#[test]
fn unknown_settings_fail_closed() {
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
    let mut value = serde_json::to_value(Config::devnet()).unwrap();
    assert!(value.get("protocol_version").is_none());
    value["protocol_version"] = 1.into();
    assert!(serde_json::from_value::<Config>(value).is_err());
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
    for duration in [
        1,
        config.initial.interval,
        u64::MAX / config.initial.interval,
    ] {
        let mut changed = config.clone();
        changed.initial.decision_blocks = duration;
        changed.validate().unwrap();
    }
    let mut overflowing = config.clone();
    overflowing.initial.decision_blocks = u64::MAX / config.initial.interval + 1;
    assert!(overflowing.validate().is_err());
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
    // Audit R31: these stay valid and are only reported to the operator.
    let mut warned = c.sanity_warnings();
    c.daa_half_life = u64::MAX;
    c.timestamp_window = usize::MAX;
    c.validate().unwrap();
    warned.extend(c.sanity_warnings());
    for field in [
        "timestamp_window",
        "max_signatures",
        "daa_half_life",
        "future_seconds",
    ] {
        assert!(
            warned.iter().any(|w| w.starts_with(field)),
            "{field}: {warned:?}"
        );
    }
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
fn operator_warnings_mark_each_unsafe_genesis_field_at_its_threshold() {
    for preset in [Config::devnet(), Config::testnet(), Config::slow_testnet()] {
        assert!(preset.sanity_warnings().is_empty());
    }
    // Each field at its last quiet value, then past it.
    let with = |edits: &[(&str, u64)]| {
        let mut value = serde_json::to_value(Config::devnet()).unwrap();
        for (field, setting) in edits {
            value[*field] = (*setting).into();
        }
        serde_json::from_value::<Config>(value).unwrap()
    };
    for (field, quiet, warned, expected) in [
        ("timestamp_window", 1, 0, "timestamp_window 0"),
        ("timestamp_window", 1024, 1025, "timestamp_window 1025"),
        ("max_signatures", 1, 0, "max_signatures is 0"),
        ("max_signatures", 65_535, 65_536, "max_signatures 65536"),
        ("daa_half_life", 15, 14, "daa_half_life 14"),
        ("daa_half_life", 1 << 22, 1 << 23, "daa_half_life 8388608"),
        ("future_seconds", 1, 0, "future_seconds is 0"),
        ("future_seconds", 900, 901, "future_seconds 901"),
    ] {
        // A short half-life is checked with a future allowance below it.
        let future = if field == "daa_half_life" { 1 } else { 120 };
        let c = with(&[("future_seconds", future), (field, quiet)]);
        assert!(c.sanity_warnings().is_empty(), "{:?}", c.sanity_warnings());
        let c = with(&[("future_seconds", future), (field, warned)]);
        let warnings = c.sanity_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with(expected), "{warnings:?}");
        // Warnings never change what consensus accepts.
        assert_eq!(c.validate().is_ok(), c.timestamp_window > 0);
    }
}

#[test]
fn intermediate_width_covers_exact_prices_and_display_precision_separately() {
    let mut c = Config::devnet();
    // (2^512-1)^2 * (2^64-1+10000) is just above 2^1088.
    c.max_integer_bits = 1089;
    c.validate().unwrap();
    c.max_integer_bits = 1088;
    assert!(
        c.validate()
            .unwrap_err()
            .to_string()
            .contains("marginal price comparison")
    );

    // A deliberately wider display scale has its own arithmetic requirement:
    // World::quote multiplies only Q*M: (2^512-1) * 2^600 needs 1112 bits.
    c.quote_scale = hashstash::types::Amount::from(1u32) << 600usize;
    c.max_integer_bits = 1112;
    c.validate().unwrap();
    c.max_integer_bits = 1111;
    assert!(
        c.validate()
            .unwrap_err()
            .to_string()
            .contains("display quote range")
    );
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
fn incompatible_serialized_config_and_genesis_state_fail_closed() {
    let config = Config::devnet();
    // A leading field from a different schema must not be silently ignored.
    let mut incompatible_config = codec::encode(&u64::MAX);
    incompatible_config.extend(config.consensus_bytes());
    assert!(codec::decode::<Config>(&incompatible_config, incompatible_config.len()).is_err());

    let state = State::genesis(&config);
    let mut old_state = codec::encode(&state);
    // The old empty budget map, absent start, and epoch zero precede last_round
    // and last_epoch. Even an empty old snapshot must not silently lose fields.
    let offset = old_state.len() - codec::encode(&(state.last_round, state.last_epoch)).len();
    old_state.splice(offset..offset, [0u8; 3]);
    assert!(codec::decode::<State>(&old_state, old_state.len()).is_err());
}

#[test]
fn database_reopen_requires_the_exact_genesis_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.sqlite");
    let config = Config::devnet();
    let chain = hashstash::chain::Chain::open(&path, config.clone()).unwrap();
    let genesis = chain.tip_hash();
    drop(chain);

    let mut changed = config.clone();
    changed.genesis_time += 1;
    assert!(hashstash::chain::Chain::open(&path, changed).is_err());
    let mut changed = config.clone();
    changed.initial.decision_blocks += 1;
    assert!(hashstash::chain::Chain::open(&path, changed).is_err());

    let chain = hashstash::chain::Chain::open(&path, config).unwrap();
    assert_eq!(chain.tip_hash(), genesis);
    assert_eq!(chain.tip_state().height, 0);
}
