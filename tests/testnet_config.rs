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
fn legacy_preset_chain_ids_keep_the_protocol26_encoding() {
    // Independently packed from the documented v26 field order and varints;
    // accepting previously invalid 0/0 caps must not change existing identities.
    for (c, expected) in [
        (
            Config::devnet(),
            "f6a2e38a4758f1ccf50dd18c1b59db136b657fdf57e728b6a5b8f5232adb3c27",
        ),
        (
            Config::testnet(),
            "949b5f3c38f6e67b48dd569c6c113377714e582ff3a550bf3ff2e743912938e9",
        ),
        (
            Config::slow_testnet(),
            "fcb3cebcf9384d80b20277985d7cd1ad35b93d03791d9a39b3d7dcc8463f2586",
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
fn governance_interval_and_duration_limits_are_enforced() {
    let config = Config::testnet();
    for interval in 1..=60 {
        let mut changed = config.clone();
        changed.initial.interval = interval;
        changed.validate().unwrap();
        if interval != 15 {
            config
                .parameter_change(&config.initial, Parameter::Interval, 15, interval)
                .unwrap();
        }
    }
    for interval in [0, 61, u64::MAX] {
        assert!(
            config
                .parameter_change(&config.initial, Parameter::Interval, 15, interval)
                .is_err()
        );
    }
    let mut invalid = config.clone();
    invalid.initial.duration = invalid.initial.interval;
    assert!(invalid.validate().is_err());
    invalid.initial.duration = u64::MAX;
    assert!(invalid.validate().is_err());
    // Duration no longer controls a loop of funding installments.
    let mut long = config;
    long.initial.duration = 100_000;
    long.validate().unwrap();
}

#[test]
fn timestamp_safety_limits_cannot_be_disabled_by_genesis() {
    let mut c = Config::devnet();
    c.daa_half_life = 899;
    assert!(c.validate().is_err());
    c = Config::devnet();
    c.timestamp_window = 9;
    assert!(c.validate().is_err());
    c = Config::devnet();
    c.future_seconds = 121;
    assert!(c.validate().is_err());
    c = Config::devnet();
    c.initial.block_bytes = u64::MAX;
    assert!(c.validate().is_err());
    c = Config::devnet();
    c.genesis_time = u32::MAX;
    assert!(c.validate().is_err());
}
