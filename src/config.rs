use crate::{codec, crypto, math, types::*};
use anyhow::{Context, Result, ensure};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 26;
pub const MAX_INTERVAL_SECONDS: u64 = 60;
pub const MAX_BLOCK_RECORD_BYTES: usize = 32 * 1024 * 1024;
/// Leave room for an ordinary account write and the canonical miner.
pub const MIN_GOVERNED_BLOCK_BYTES: u64 = 2 * crate::fees::ACCOUNT_WEIGHT;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub block_bytes: u64,
    /// Raw hash units per 1024 transaction weight units.
    pub minimum_fee_rate: u64,
    pub interval: u64,
    /// Nominal seconds; each block advances schedules by its parent's interval.
    pub lead: u64,
    pub rest: u64,
    pub duration: u64,
    pub miner_fee_percent: Option<u64>,
    pub pass_margin_bps: Option<u64>,
}
impl Settings {
    pub fn get(&self, p: Parameter) -> u64 {
        match p {
            Parameter::BlockBytes => self.block_bytes,
            Parameter::MinimumFeeRate => self.minimum_fee_rate,
            Parameter::Interval => self.interval,
            Parameter::Lead => self.lead,
            Parameter::Rest => self.rest,
            Parameter::Duration => self.duration,
            Parameter::MinerFeePercent => self.miner_fee_percent.unwrap_or(0),
            Parameter::PassMarginBps => self.pass_margin_bps.unwrap_or(0),
        }
    }
    pub fn set(&mut self, p: Parameter, value: u64) {
        match p {
            Parameter::BlockBytes => self.block_bytes = value,
            Parameter::MinimumFeeRate => self.minimum_fee_rate = value,
            Parameter::Interval => self.interval = value,
            Parameter::Lead => self.lead = value,
            Parameter::Rest => self.rest = value,
            Parameter::Duration => self.duration = value,
            Parameter::MinerFeePercent => self.miner_fee_percent = Some(value),
            Parameter::PassMarginBps => self.pass_margin_bps = Some(value),
        }
    }
}
pub const PARAMETERS: [Parameter; 8] = [
    Parameter::BlockBytes,
    Parameter::Interval,
    Parameter::Lead,
    Parameter::Rest,
    Parameter::Duration,
    Parameter::MinerFeePercent,
    Parameter::PassMarginBps,
    Parameter::MinimumFeeRate,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub protocol_version: u32,
    pub network: String,
    pub genesis_time: u32,
    pub initial_bits: u32,
    pub limit_bits: u32,
    pub daa_half_life: u64,
    pub timestamp_window: usize,
    pub future_seconds: u32,
    pub max_signatures: usize,
    pub max_height: u64,
    pub money_bits: u64,
    pub share_bits: u64,
    pub max_integer_bits: u64,
    #[serde(with = "amount")]
    pub quote_scale: Amount,
    #[serde(with = "amount")]
    pub share_scale: Amount,
    pub auction_timeout: u64,
    #[serde(with = "amount")]
    pub reserve_min: Amount,
    /// A proper positive fraction limits each grant; exactly 0/0 disables this cap.
    pub grant_numerator: u64,
    pub grant_denominator: u64,
    /// A proper positive fraction limits each epoch; exactly 0/0 disables this cap.
    pub budget_numerator: u64,
    pub budget_denominator: u64,
    pub budget_period: u64,
    pub initial: Settings,
}
impl Config {
    /// Local test difficulty; never a public mainnet preset.
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            network: "hashstash-devnet-v26".into(),
            genesis_time: 1_770_000_000,
            initial_bits: 0x207fffff,
            limit_bits: 0x207fffff,
            daa_half_life: 900,
            timestamp_window: 11,
            future_seconds: 120,
            max_signatures: 4096,
            max_height: u32::MAX as u64,
            money_bits: 512,
            share_bits: 512,
            max_integer_bits: 8192,
            quote_scale: Amount::from(10u32).pow(30),
            share_scale: Amount::from(10u32).pow(18),
            auction_timeout: 128 * 15,
            reserve_min: 100u32.into(),
            grant_numerator: 1,
            grant_denominator: 10,
            budget_numerator: 1,
            budget_denominator: 4,
            budget_period: 2048 * 15,
            initial: Settings {
                block_bytes: 16_384,
                minimum_fee_rate: 1,
                interval: 15,
                lead: 4 * 15,
                rest: 64 * 15,
                duration: 32 * 15,
                miner_fee_percent: Some(50),
                pass_margin_bps: Some(0),
            },
        }
    }
    pub fn testnet() -> Self {
        let mut config = Self::devnet();
        config.network = "hashstash-testnet-v26".into();
        config.auction_timeout = 32 * 15;
        config.reserve_min = 20u32.into();
        config.budget_period = 128 * 15;
        config.initial.rest = 32 * 15;
        config.initial.duration = 16 * 15;
        config
    }
    pub fn slow_testnet() -> Self {
        let mut config = Self::testnet();
        config.network = "hashstash-slow-testnet-v26".into();
        config.auction_timeout = 240 * 15;
        config.budget_period = 5760 * 15;
        config.initial.lead = 20 * 15;
        config.initial.rest = 720 * 15;
        config.initial.duration = 240 * 15;
        config
    }
    pub fn progress_increment(&self, settings: &Settings) -> u64 {
        settings.interval
    }
    pub fn grant_fraction_enabled(&self) -> bool {
        (self.grant_numerator, self.grant_denominator) != (0, 0)
    }
    pub fn grant_budget_enabled(&self) -> bool {
        (self.budget_numerator, self.budget_denominator) != (0, 0)
    }
    pub fn governance_parameters(&self) -> Vec<Parameter> {
        PARAMETERS.to_vec()
    }
    pub fn validate_fee_percent(&self, settings: &Settings) -> Result<()> {
        ensure!(
            settings.miner_fee_percent.is_some_and(|v| v <= 100),
            "miner fee percentage must be in 0..100"
        );
        Ok(())
    }
    pub fn valid_block_bytes(&self, bytes: u64) -> bool {
        (MIN_GOVERNED_BLOCK_BYTES..=MAX_BLOCK_RECORD_BYTES as u64).contains(&bytes)
    }
    pub fn max_block_record_bytes(&self) -> usize {
        MAX_BLOCK_RECORD_BYTES
    }
    /// A transaction may occupy the current block capacity. Its weighted work
    /// and the complete block body's framing are checked separately at admission.
    pub fn transaction_bytes(&self, settings: &Settings) -> usize {
        settings.block_bytes.min(MAX_BLOCK_RECORD_BYTES as u64) as usize
    }
    pub fn auction_timeout_for(&self, settings: &Settings) -> Result<u64> {
        Ok(self.auction_timeout.max(
            settings
                .lead
                .checked_add(settings.interval)
                .context("auction lead overflow")?,
        ))
    }
    pub fn validate_governance_settings(&self, settings: &Settings) -> Result<()> {
        self.validate_fee_percent(settings)?;
        ensure!(
            settings.minimum_fee_rate >= 1,
            "minimum fee rate must be positive"
        );
        ensure!(
            (1..=MAX_INTERVAL_SECONDS).contains(&settings.interval),
            "target block interval must be 1..60 seconds"
        );
        ensure!(settings.pass_margin_bps.is_some(), "missing PASS margin");
        ensure!(
            self.valid_block_bytes(settings.block_bytes),
            "block capacity cannot cover mandatory account creation or fit this implementation"
        );
        for duration in [
            settings.lead,
            settings.rest,
            settings.duration,
            self.auction_timeout_for(settings)?,
        ] {
            ensure!(
                duration > 0
                    && self
                        .max_height
                        .checked_mul(MAX_INTERVAL_SECONDS)
                        .and_then(|clock| clock.checked_add(duration))
                        .is_some(),
                "phase duration must be positive with a representable deadline"
            );
        }
        // The opening block creates the two worlds after its transactions.
        // At least one later block must accept outcome trades before resolution.
        ensure!(
            settings.duration > settings.interval,
            "decision duration must exceed the target block interval"
        );
        Ok(())
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version"
        );
        ensure!(
            self.genesis_time < u32::MAX,
            "genesis timestamp is exhausted"
        );
        ensure!(
            !self.network.is_empty() && self.network.len() <= 128,
            "invalid network name"
        );
        ensure!(
            (11..=1001).contains(&self.timestamp_window) && self.timestamp_window % 2 == 1,
            "timestamp window must be odd and in 11..1001"
        );
        ensure!(
            (900..=i64::MAX as u64).contains(&self.daa_half_life),
            "difficulty half life must be at least 900 seconds"
        );
        ensure!(
            self.future_seconds <= 120,
            "timestamp future allowance exceeds 120 seconds"
        );
        let limit = math::target_from_bits(self.limit_bits)?;
        let initial = math::target_from_bits(self.initial_bits)?;
        ensure!(initial <= limit, "initial target exceeds limit");
        ensure!(
            self.max_height > 0 && self.max_height <= u32::MAX as u64,
            "invalid height range"
        );
        ensure!(
            self.money_bits >= 320
                && self.money_bits <= 512
                && self.share_bits > 0
                && self.share_bits <= 512,
            "unsupported numeric ranges"
        );
        ensure!(
            self.max_integer_bits >= self.money_bits && self.max_integer_bits <= 65536,
            "invalid intermediate range"
        );
        ensure!(
            self.money_bits + 64 <= self.max_integer_bits,
            "monetary products exceed intermediate range"
        );
        ensure!(
            !self.quote_scale.is_zero() && self.quote_scale.bits() <= 256,
            "invalid quote precision"
        );
        ensure!(
            !self.reserve_min.is_zero() && self.reserve_min.bits() <= self.money_bits,
            "invalid minimum governance reserve"
        );
        for (n, d) in [
            (self.grant_numerator, self.grant_denominator),
            (self.budget_numerator, self.budget_denominator),
        ] {
            ensure!(
                (n == 0 && d == 0) || (n > 0 && n < d),
                "fraction must be in (0,1), or exactly 0/0 to disable its cap"
            );
        }
        self.validate_governance_settings(&self.initial)?;
        ensure!(
            self.max_signatures > 0 && self.max_signatures <= 100_000,
            "invalid signature limit"
        );
        ensure!(self.auction_timeout > 0, "zero auction timeout");
        ensure!(
            self.budget_period > 1,
            "budget period must exceed one second"
        );
        let max_clock = self
            .max_height
            .checked_mul(MAX_INTERVAL_SECONDS)
            .context("maximum nominal clock overflow")?;
        let max_offset = self
            .auction_timeout_for(&self.initial)?
            .max(self.initial.duration)
            .max(self.initial.rest)
            .max(self.budget_period);
        ensure!(
            max_clock.checked_add(max_offset).is_some(),
            "deadline overflow"
        );
        let max_issued = Amount::from(self.max_height) * (Amount::one() << 255usize);
        ensure!(
            max_issued.bits() <= self.money_bits,
            "supply range too small"
        );
        ensure!(
            !self.share_scale.is_zero()
                && self.share_scale.bits() <= self.share_bits
                && (&max_issued * &self.share_scale).bits() <= self.share_bits,
            "share scale exceeds lifetime share range"
        );
        ensure!(
            self.quote_scale >= self.share_scale,
            "opening price rounds to zero at configured quote precision"
        );
        ensure!(
            (((Amount::one() << self.money_bits as usize) - 1u32)
                * &self.quote_scale
                * Amount::from(max_clock)
                * (Amount::from(u64::MAX) + Amount::from(10_000u32)))
            .bits()
                <= self.max_integer_bits,
            "price integral range too small"
        );
        Ok(())
    }
    pub fn consensus_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }
    pub fn chain_id(&self) -> Hash {
        crypto::tagged_hash("Hashstash/chain/v26", &self.consensus_bytes())
    }
    pub fn check_amount(&self, x: &Amount) -> Result<()> {
        ensure!(x.bits() <= self.money_bits, "HASH range exceeded");
        Ok(())
    }
    pub fn validate_grant(&self, payments: &[GrantPayment]) -> Result<Amount> {
        let total = grant_total(payments)?;
        for payment in payments {
            self.check_amount(&payment.amount)?;
        }
        self.check_amount(&total)?;
        Ok(total)
    }
    pub fn check_shares(&self, x: &Amount) -> Result<()> {
        ensure!(x.bits() <= self.share_bits, "share range exceeded");
        Ok(())
    }
    pub fn parameter_change(
        &self,
        settings: &Settings,
        p: Parameter,
        old: u64,
        new: u64,
    ) -> Result<()> {
        ensure!(old == settings.get(p), "stale parameter proposal");
        ensure!(new != old, "parameter must change");
        if matches!(
            p,
            Parameter::BlockBytes
                | Parameter::Lead
                | Parameter::Rest
                | Parameter::Duration
                | Parameter::MinimumFeeRate
        ) {
            ensure!(
                old.checked_mul(2) == Some(new) || new.checked_mul(2) == Some(old),
                "parameter must halve or double"
            );
        }
        let mut changed = settings.clone();
        changed.set(p, new);
        self.validate_governance_settings(&changed)
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn grant_caps_accept_only_proper_fractions_or_explicit_zero_pairs() {
        for budget in [false, true] {
            for (n, d, valid) in [
                (0, 0, true),
                (0, 1, false),
                (1, 0, false),
                (1, 1, false),
                (2, 1, false),
                (1, 10, true),
                (u64::MAX - 1, u64::MAX, true),
            ] {
                let mut c = Config::testnet();
                if budget {
                    c.budget_numerator = n;
                    c.budget_denominator = d;
                } else {
                    c.grant_numerator = n;
                    c.grant_denominator = d;
                }
                assert_eq!(c.validate().is_ok(), valid, "budget={budget}, {n}/{d}");
                if valid {
                    let bytes = c.consensus_bytes();
                    let decoded: Config = codec::decode(&bytes, bytes.len()).unwrap();
                    assert_eq!(decoded, c);
                    assert_eq!(decoded.chain_id(), c.chain_id());
                    if n == 0 {
                        assert_ne!(c.chain_id(), Config::testnet().chain_id());
                    }
                }
            }
        }
    }

    #[test]
    fn transaction_capacity_tracks_governed_block_capacity_within_record_ceiling() {
        let c = Config::devnet();
        let mut settings = c.initial.clone();
        for bytes in [
            MIN_GOVERNED_BLOCK_BYTES,
            16_384,
            65_536,
            MAX_BLOCK_RECORD_BYTES as u64,
        ] {
            settings.block_bytes = bytes;
            c.validate_governance_settings(&settings).unwrap();
            assert_eq!(c.transaction_bytes(&settings), bytes as usize);
        }
        settings.block_bytes = MAX_BLOCK_RECORD_BYTES as u64 + 1;
        assert!(c.validate_governance_settings(&settings).is_err());
        assert_eq!(c.transaction_bytes(&settings), MAX_BLOCK_RECORD_BYTES);
        assert_eq!(c.max_block_record_bytes(), MAX_BLOCK_RECORD_BYTES);
    }
}
