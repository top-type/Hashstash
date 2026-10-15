//! Exact transaction fees with a governed minimum price per 1024 weight units.
use crate::{codec, config::Config, state::State, types::*};
use anyhow::{Result, ensure};
use num_traits::Zero;

pub const FEE_SCALE: u64 = 1024;
pub const ACCOUNT_WEIGHT: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeQuote {
    pub weight: u64,
    pub minimum_fee: Amount,
    pub account_creation_fee: Amount,
    /// Fixed prepaid settlement work for every grant recipient.
    pub grant_recipient_fee: Amount,
    /// Signed exact full charge, including any voluntary extra.
    pub fee: Amount,
    pub extra_fee: Amount,
    pub miner_fee: Amount,
    pub revenue_fee: Amount,
    pub miner_fee_percent: Option<u64>,
}

pub fn quote(c: &Config, s: &State, t: &Transaction) -> Result<FeeQuote> {
    PreparedTransaction::new(t)?.quote(c, s)
}

/// Immutable size work may be reused; account creation is always quoted against
/// the exact pre-transaction state. This does not authenticate the transaction.
pub(crate) struct PreparedTransaction<'a> {
    transaction: &'a Transaction,
    encoded_len: usize,
}
impl<'a> PreparedTransaction<'a> {
    pub(crate) fn new(transaction: &'a Transaction) -> Result<Self> {
        Self::with_limit(transaction, usize::MAX)
    }
    pub(crate) fn with_limit(transaction: &'a Transaction, max_bytes: usize) -> Result<Self> {
        if let Operation::Propose {
            proposal: Proposal::Grant { payments },
            ..
        } = &transaction.body.operation
        {
            ensure!(
                !payments.is_empty(),
                "grant must have at least one recipient"
            );
        }
        let encoded_len = codec::encode(transaction).len();
        ensure!(encoded_len <= max_bytes, "transaction exceeds byte limit");
        Ok(Self {
            transaction,
            encoded_len,
        })
    }
    pub(crate) fn transaction(&self) -> &Transaction {
        self.transaction
    }
    pub(crate) fn operation(&self) -> &Operation {
        &self.transaction.body.operation
    }
    pub(crate) fn encoded_len(&self) -> usize {
        self.encoded_len
    }
    pub(crate) fn quote(&self, c: &Config, s: &State) -> Result<FeeQuote> {
        let t = self.transaction;
        c.check_amount(&t.body.fee)?;
        let grant_recipients = match self.operation() {
            Operation::Propose {
                proposal: Proposal::Grant { payments },
                ..
            } => {
                c.validate_grant(payments)?;
                u64::try_from(payments.len())?
            }
            _ => 0,
        };
        let creates_account = match self.operation() {
            Operation::TransferExact { recipient, .. } => {
                let missing = s.account(recipient, None).is_none();
                if s.alternative.is_some() {
                    ensure!(
                        s.account(recipient, Some(Outcome::Pass)).is_none() == missing,
                        "common account existence differs between outcomes"
                    );
                }
                missing
            }
            _ => false,
        };
        let grant_weight = grant_recipients
            .checked_mul(ACCOUNT_WEIGHT)
            .ok_or_else(|| anyhow::anyhow!("grant settlement weight overflow"))?;
        let weight = u64::try_from(self.encoded_len())?
            .checked_add(if creates_account { ACCOUNT_WEIGHT } else { 0 })
            .and_then(|n| n.checked_add(grant_weight))
            .ok_or_else(|| anyhow::anyhow!("transaction weight overflow"))?;
        let rate = Amount::from(s.settings.minimum_fee_rate);
        let minimum_fee = (Amount::from(weight) * &rate + Amount::from(FEE_SCALE - 1)) / FEE_SCALE;
        c.check_amount(&minimum_fee)?;
        let account_creation_fee = if creates_account {
            rate.clone()
        } else {
            Amount::zero()
        };
        let fee = t.body.fee.clone();
        let extra_fee = if fee >= minimum_fee {
            &fee - &minimum_fee
        } else {
            Amount::zero()
        };
        c.validate_fee_percent(&s.settings)?;
        let miner_fee_percent = s.settings.miner_fee_percent;
        let miner_fee = &fee * Amount::from(miner_fee_percent.unwrap()) / 100u32;
        let revenue_fee = &fee - &miner_fee;
        Ok(FeeQuote {
            weight,
            minimum_fee,
            account_creation_fee,
            grant_recipient_fee: rate * grant_recipients,
            fee,
            extra_fee,
            miner_fee,
            revenue_fee,
            miner_fee_percent,
        })
    }
}
