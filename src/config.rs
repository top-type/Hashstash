use crate::{codec, crypto, math, types::*};
use anyhow::{Context, Result, ensure};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};

/// An empty block must be able to create its miner account.
pub const MIN_GOVERNED_BLOCK_BYTES: u64 = crate::fees::ACCOUNT_WEIGHT;

/// One spendable monetary atom represents one petahash of expected work.
pub const WORK_PER_ATOM: u64 = 1_000_000_000_000_000;

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
    pub decision_blocks: u64,
    /// Maximum marginal Stash price movement in basis points per block.
    pub max_price_change_bps: u64,
    pub miner_fee_percent: Option<u64>,
    pub pass_margin_bps: Option<u64>,
}
impl Settings {
    pub fn get(&self, p: Parameter) -> u64 {
        match p {
            Parameter::BlockBytes => self.block_bytes,
            Parameter::MinimumFeeRate => self.minimum_fee_rate,
            Parameter::MaxPriceChangeBps => self.max_price_change_bps,
            Parameter::Interval => self.interval,
            Parameter::Lead => self.lead,
            Parameter::Rest => self.rest,
            Parameter::DecisionBlocks => self.decision_blocks,
            Parameter::MinerFeePercent => self.miner_fee_percent.unwrap_or(0),
            Parameter::PassMarginBps => self.pass_margin_bps.unwrap_or(0),
        }
    }
    pub fn set(&mut self, p: Parameter, value: u64) {
        match p {
            Parameter::BlockBytes => self.block_bytes = value,
            Parameter::MinimumFeeRate => self.minimum_fee_rate = value,
            Parameter::MaxPriceChangeBps => self.max_price_change_bps = value,
            Parameter::Interval => self.interval = value,
            Parameter::Lead => self.lead = value,
            Parameter::Rest => self.rest = value,
            Parameter::DecisionBlocks => self.decision_blocks = value,
            Parameter::MinerFeePercent => self.miner_fee_percent = Some(value),
            Parameter::PassMarginBps => self.pass_margin_bps = Some(value),
        }
    }
}
pub const PARAMETERS: [Parameter; 9] = [
    Parameter::BlockBytes,
    Parameter::Interval,
    Parameter::Lead,
    Parameter::Rest,
    Parameter::DecisionBlocks,
    Parameter::MinerFeePercent,
    Parameter::PassMarginBps,
    Parameter::MinimumFeeRate,
    Parameter::MaxPriceChangeBps,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network: String,
    /// Explicit fixture denomination. Rejected by builds without test-fixtures.
    /// It changes the chain identity and never changes proof of work or fork weight.
    #[serde(default)]
    pub test_work: bool,
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
    pub initial: Settings,
}
impl Config {
    /// Local test difficulty; never a public mainnet preset.
    pub fn devnet() -> Self {
        Self {
            network: "hashstash-devnet".into(),
            test_work: cfg!(feature = "test-fixtures"),
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
            share_scale: Amount::one(),
            auction_timeout: 128 * 15,
            initial: Settings {
                block_bytes: 16_384,
                minimum_fee_rate: 1,
                interval: 15,
                lead: 4 * 15,
                rest: 64 * 15,
                decision_blocks: 32,
                max_price_change_bps: 1000,
                miner_fee_percent: Some(50),
                pass_margin_bps: Some(0),
            },
        }
    }
    pub fn testnet() -> Self {
        let mut config = Self::devnet();
        config.network = "hashstash-testnet".into();
        config.auction_timeout = 32 * 15;
        config.initial.rest = 32 * 15;
        config.initial.decision_blocks = 16;
        config
    }
    pub fn slow_testnet() -> Self {
        let mut config = Self::testnet();
        config.network = "hashstash-slow-testnet".into();
        config.auction_timeout = 240 * 15;
        config.initial.lead = 20 * 15;
        config.initial.rest = 720 * 15;
        config.initial.decision_blocks = 240;
        config
    }
    pub fn progress_increment(&self, settings: &Settings) -> u64 {
        settings.interval
    }
    /// Raw expected hashes per monetary atom. The production denomination is
    /// fixed; only an explicitly different fixture chain can use one-work atoms.
    pub fn work_per_atom(&self) -> Result<Amount> {
        ensure!(
            !self.test_work || cfg!(feature = "test-fixtures"),
            "test_work requires an explicit test-fixtures build"
        );
        Ok(Amount::from(if self.test_work { 1 } else { WORK_PER_ATOM }))
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
        bytes >= MIN_GOVERNED_BLOCK_BYTES
            && usize::try_from(bytes).is_ok_and(|value| value <= isize::MAX as usize)
    }
    /// A transaction may occupy the current block capacity. Its weighted work
    /// and the complete block body's framing are checked separately at admission.
    pub fn transaction_bytes(&self, settings: &Settings) -> usize {
        usize::try_from(settings.block_bytes).expect("validated block capacity fits this platform")
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
            settings.interval > 0,
            "target block interval must be positive"
        );
        ensure!(settings.pass_margin_bps.is_some(), "missing PASS margin");
        ensure!(
            self.valid_block_bytes(settings.block_bytes),
            "block capacity cannot cover mandatory account creation or fit this implementation"
        );
        ensure!(
            settings.decision_blocks > 0,
            "decision block count must be positive"
        );
        self.auction_timeout_for(settings)?;
        Ok(())
    }
    /// Validate a new schedule where it can actually begin, not against an
    /// invented lifetime upper bound on the governed block interval.
    pub fn validate_governance_settings_at(&self, settings: &Settings, clock: u64) -> Result<()> {
        self.validate_governance_settings(settings)?;
        for duration in [
            settings.interval,
            settings
                .decision_blocks
                .checked_mul(settings.interval)
                .context("decision schedule overflow")?,
            settings.rest,
            self.auction_timeout_for(settings)?,
        ] {
            clock
                .checked_add(duration)
                .context("schedule deadline overflow")?;
        }
        Ok(())
    }
    pub fn parameter_change_at(
        &self,
        settings: &Settings,
        p: Parameter,
        old: u64,
        new: u64,
        clock: u64,
    ) -> Result<()> {
        self.parameter_change(settings, p, old, new)?;
        let mut changed = settings.clone();
        changed.set(p, new);
        self.validate_governance_settings_at(&changed, clock)
    }
    pub fn validate(&self) -> Result<()> {
        let work_per_atom = self.work_per_atom()?;
        ensure!(
            self.genesis_time < u32::MAX,
            "genesis timestamp is exhausted"
        );
        ensure!(
            !self.network.is_empty() && self.network.len() <= 128,
            "invalid network name"
        );
        ensure!(
            self.timestamp_window > 0,
            "timestamp window must be positive"
        );
        ensure!(
            self.daa_half_life > 0,
            "difficulty half life must be positive"
        );
        let limit = math::target_from_bits(self.limit_bits)?;
        let initial = math::target_from_bits(self.initial_bits)?;
        ensure!(initial <= limit, "initial target exceeds limit");
        ensure!(
            self.max_height > 0 && self.max_height <= i64::MAX as u64,
            "invalid height range"
        );
        ensure!(
            self.money_bits > 0
                && self.money_bits <= 512
                && self.share_bits > 0
                && self.share_bits <= 512,
            "unsupported numeric ranges"
        );
        ensure!(
            self.max_integer_bits >= self.money_bits,
            "invalid intermediate range"
        );
        ensure!(
            self.money_bits + 64 <= self.max_integer_bits,
            "monetary products exceed intermediate range"
        );
        ensure!(!self.quote_scale.is_zero(), "invalid quote precision");
        self.validate_governance_settings_at(&self.initial, 0)?;
        let max_issued =
            Amount::from(self.max_height) * ((Amount::one() << 255usize) / work_per_atom);
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
            (((Amount::one() << self.money_bits as usize) - 1u32) * &self.quote_scale).bits()
                <= self.max_integer_bits,
            "display quote range too small"
        );
        ensure!(
            (((Amount::one() << self.money_bits as usize) - 1u32)
                * ((Amount::one() << self.share_bits as usize) - 1u32)
                * (Amount::from(u64::MAX) + Amount::from(10_000u32)))
            .bits()
                <= self.max_integer_bits,
            "marginal price comparison range too small"
        );
        Ok(())
    }
    pub fn consensus_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }
    pub fn chain_id(&self) -> Hash {
        crypto::tagged_hash("Hashstash/chain", &self.consensus_bytes())
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
        let mut changed = settings.clone();
        changed.set(p, new);
        self.validate_governance_settings(&changed)
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn transaction_capacity_tracks_governed_capacity_without_transport_policy() {
        let c = Config::devnet();
        let mut settings = c.initial.clone();
        for bytes in [
            MIN_GOVERNED_BLOCK_BYTES,
            1_025,
            16_384,
            65_536,
            64 * 1024 * 1024,
            isize::MAX as u64,
        ] {
            settings.block_bytes = bytes;
            c.validate_governance_settings(&settings).unwrap();
            assert_eq!(c.transaction_bytes(&settings), bytes as usize);
        }
        for bytes in [0, MIN_GOVERNED_BLOCK_BYTES - 1, u64::MAX] {
            settings.block_bytes = bytes;
            assert!(c.validate_governance_settings(&settings).is_err());
        }
    }
}
