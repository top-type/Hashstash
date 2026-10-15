use hashstash::{
    config::{Config, PROTOCOL_VERSION},
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
fn protocol27_preset_chain_ids_match_independent_encoding() {
    // Independently packed from the unchanged field order and varints.
    // Protocol and preset changes separate these chains from prior releases.
    for (c, expected) in [
        (
            Config::devnet(),
            "f62127c60825be20ee7c19f6d5ef79712ab2f4c525c6e179091407f5c082dac2",
        ),
        (
            Config::testnet(),
            "e7cea4e17c601540e5c96ae4f7b51310c53395eba5429158356e295150954567",
        ),
        (
            Config::slow_testnet(),
            "0b2613506d8bf0b0fd26c3f6c9f32ad39e22f8031eb5529b3473a6b438d53d69",
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
    c.reserve_min = 0u32.into();
    c.auction_timeout = 0;
    c.budget_period = 1;
    c.initial.rest = 0;
    c.initial.lead = 0;
    c.initial.minimum_fee_rate = 0;
    c.validate().unwrap();
    c.daa_half_life = u64::MAX;
    c.timestamp_window = usize::MAX;
    c.validate().unwrap();
    for field in ["timestamp_window", "daa_half_life", "budget_period"] {
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
