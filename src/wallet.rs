//! Wallet formats are independent of consensus and preserve every signed byte.
use crate::{codec, crypto, types::*};
use anyhow::{Result, ensure};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const UNSIGNED_FORMAT: &str = "hashstash-unsigned-v1";
pub const PASSPHRASE_SCHEME: &str = "hashstash-passphrase-v1";
pub const MAX_PASSPHRASE_BYTES: usize = 4096;

/// Exact UTF-8, followed by a little-endian u32 retry counter, starting at zero.
/// No trimming, normalization, password stretching, or strength rules.
pub fn derive_secret(passphrase: &str) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(!passphrase.is_empty(), "enter a passphrase");
    ensure!(
        passphrase.len() <= MAX_PASSPHRASE_BYTES,
        "passphrase input is too large"
    );
    let mut input = Zeroizing::new(passphrase.as_bytes().to_vec());
    input.extend_from_slice(&0u32.to_le_bytes());
    for counter in 0..=u32::MAX {
        input[passphrase.len()..].copy_from_slice(&counter.to_le_bytes());
        let candidate = Zeroizing::new(crypto::tagged_hash("Hashstash/Passphrase/v1", &input));
        if crypto::public_key(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not derive a signing key")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedEnvelope {
    pub format: String,
    pub body: String,
}

pub fn unsigned(body: &TransactionBody) -> UnsignedEnvelope {
    UnsignedEnvelope {
        format: UNSIGNED_FORMAT.into(),
        body: hex::encode(codec::encode(body)),
    }
}

fn validate_raw_length(hex_bytes: usize) -> Result<()> {
    ensure!(
        hex_bytes > 0 && hex_bytes <= isize::MAX as usize,
        "transaction length is invalid"
    );
    ensure!(
        hex_bytes.is_multiple_of(2),
        "transaction hex has an odd length"
    );
    Ok(())
}

fn validate_unsigned_length(bytes: usize) -> Result<()> {
    ensure!(
        bytes
            .checked_add(64)
            .is_some_and(|signed| signed <= isize::MAX as usize),
        "signed transaction length is not representable"
    );
    Ok(())
}

fn raw_bytes(raw: &str) -> Result<Vec<u8>> {
    let raw = raw.trim();
    validate_raw_length(raw.len())?;
    Ok(hex::decode(raw)?)
}

pub fn decode_unsigned(envelope: &UnsignedEnvelope) -> Result<TransactionBody> {
    ensure!(
        envelope.format == UNSIGNED_FORMAT,
        "unsupported unsigned transaction format"
    );
    let bytes = raw_bytes(&envelope.body)?;
    // A canonical BIP340 signature adds exactly 64 bytes. Check the actual
    // allocation boundary; block capacity is evaluated against chain state.
    validate_unsigned_length(bytes.len())?;
    let body: TransactionBody = codec::decode(&bytes, bytes.len())?;
    validate_body(&body)?;
    Ok(body)
}

pub fn signed_hex(transaction: &Transaction) -> String {
    hex::encode(codec::encode(transaction))
}

pub fn decode_signed(raw: &str) -> Result<Transaction> {
    let bytes = raw_bytes(raw)?;
    let transaction: Transaction = codec::decode(&bytes, bytes.len())?;
    validate_body(&transaction.body)?;
    crypto::verify(&transaction)?;
    Ok(transaction)
}

fn validate_body(body: &TransactionBody) -> Result<()> {
    ensure!(crypto::valid_key(&body.sender), "invalid sender public key");
    ensure!(body.nonce != u64::MAX, "nonce exhausted");
    ensure!(body.expiry_height > 0, "expiry height must be positive");
    ensure!(body.fee.bits() <= 512, "fee exceeds supported HASH range");
    let amount = |v: &Amount| -> Result<()> {
        ensure!(v.bits() <= 512, "amount exceeds supported range");
        Ok(())
    };
    let key = |v: &PublicKey| -> Result<()> {
        ensure!(crypto::valid_key(v), "invalid recipient public key");
        Ok(())
    };
    let side = |d: &Option<Hash>, o: &Option<Outcome>| -> Result<()> {
        ensure!(
            d.is_some() == o.is_some(),
            "decision and outcome must appear together"
        );
        Ok(())
    };
    let operation = &body.operation;
    match &operation {
        Operation::TransferExact {
            recipient,
            amount: a,
        } => {
            key(recipient)?;
            amount(a)?;
        }
        Operation::Deposit {
            amount: a,
            decision,
            outcome,
        } => {
            amount(a)?;
            ensure!(!a.is_zero(), "zero deposit");
            side(decision, outcome)?;
        }
        Operation::Redeem {
            shares,
            decision,
            outcome,
        } => {
            amount(shares)?;
            ensure!(!shares.is_zero(), "zero redemption");
            side(decision, outcome)?;
        }
        Operation::Support { amount: a, .. } => amount(a)?,
        Operation::Propose {
            proposal, support, ..
        } => {
            amount(support)?;
            if let Proposal::Grant { payments } = proposal {
                amount(&proposal.grant_total()?)?;
                for payment in payments {
                    key(&payment.recipient)?;
                    amount(&payment.amount)?;
                }
            }
            if let Proposal::Parameter {
                parameter: Parameter::MinerFeePercent,
                old,
                new,
            } = proposal
            {
                ensure!(
                    *old <= 100 && *new <= 100,
                    "miner fee share must be between 0 and 100%"
                );
                ensure!(old != new, "miner fee share must change");
            }
            if let Proposal::Parameter {
                parameter: Parameter::MinimumFeeRate,
                old,
                new,
            } = proposal
            {
                ensure!(old != new, "minimum fee rate must change");
            }
            if let Proposal::Parameter {
                parameter: Parameter::DecisionBlocks,
                old,
                new,
            } = proposal
            {
                ensure!(
                    *old > 0 && *new > 0,
                    "decision block count must be positive"
                );
                ensure!(old != new, "decision block count must change");
            }
            if let Proposal::Parameter {
                parameter: Parameter::MaxPriceChangeBps,
                old,
                new,
            } = proposal
            {
                ensure!(old != new, "maximum price change must change");
            }
            if let Proposal::Parameter {
                parameter: Parameter::PassMarginBps,
                old,
                new,
            } = proposal
            {
                ensure!(old != new, "PASS margin must change");
            }
        }
        Operation::Refund { .. } => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewField {
    pub label: String,
    pub value: String,
}

/// Values are strings so even u64 fields remain exact in a browser.
pub fn review(body: &TransactionBody) -> Vec<ReviewField> {
    if let Err(error) = validate_body(body) {
        return vec![ReviewField {
            label: "Invalid transaction".into(),
            value: error.to_string(),
        }];
    }
    let account = |key: &PublicKey| {
        crate::address::encode(key, &body.chain_id)
            .unwrap_or_else(|_| format!("Invalid public key: {}", hex::encode(key)))
    };
    let mut fields = Vec::new();
    let mut add = |label: &str, value: String| {
        fields.push(ReviewField {
            label: label.into(),
            value,
        })
    };
    add("Chain ID", hex::encode(body.chain_id));
    add("Sender", account(&body.sender));
    add("Nonce", body.nonce.to_string());
    add("Expiry block", body.expiry_height.to_string());
    add("Fee · HASH", body.fee.to_str_radix(10));
    let operation = &body.operation;
    match &operation {
        Operation::TransferExact { recipient, amount } => {
            add("Action", "Transfer".into());
            add("Recipient", account(recipient));
            add("Recipient receives · HASH", amount.to_str_radix(10));
            add("Total debit · HASH", (amount + &body.fee).to_str_radix(10));
        }
        Operation::Deposit {
            amount,
            decision,
            outcome,
        } => {
            add("Action", "Deposit".into());
            add("Amount · HASH", amount.to_str_radix(10));
            add("Execution", "Batch trade; full or partial fill".into());
            add(
                "Unfilled input",
                "Returned automatically; transaction fee remains payable".into(),
            );
            add("Outcome", outcome.map_or("Ordinary", outcome_name).into());
            if let Some(id) = decision {
                add("Decision ID", hex::encode(id));
            }
        }
        Operation::Redeem {
            shares,
            decision,
            outcome,
        } => {
            add("Action", "Redeem".into());
            add("Shares", shares.to_str_radix(10));
            add("Execution", "Batch trade; full or partial fill".into());
            add(
                "Unfilled input",
                "Returned automatically; transaction fee remains payable".into(),
            );
            add("Outcome", outcome.map_or("Ordinary", outcome_name).into());
            if let Some(id) = decision {
                add("Decision ID", hex::encode(id));
            }
        }
        Operation::Propose {
            round,
            description,
            proposal,
            support,
        } => {
            add("Action", "Propose".into());
            add("Auction round", round.to_string());
            add("Description hash", hex::encode(description));
            add("Support · HASH", support.to_str_radix(10));
            match proposal {
                Proposal::Grant { payments } => {
                    add("Proposal", "Grant".into());
                    for (index, payment) in payments.iter().enumerate() {
                        add(
                            &format!("Recipient {}", index + 1),
                            account(&payment.recipient),
                        );
                        add(
                            &format!("Payment {} · HASH", index + 1),
                            payment.amount.to_str_radix(10),
                        );
                    }
                    add(
                        "Total grant · HASH",
                        proposal.grant_total().unwrap().to_str_radix(10),
                    );
                }
                Proposal::Parameter {
                    parameter,
                    old,
                    new,
                } => {
                    add("Proposal", "Parameter".into());
                    if *parameter == Parameter::MinerFeePercent {
                        add("Parameter", "Miner fee share".into());
                        add("Expected miner share", format!("{old}%"));
                        add("Proposed miner share", format!("{new}%"));
                        add(
                            "Expected Revenue share",
                            format!("{}%", 100u64.saturating_sub(*old)),
                        );
                        add(
                            "Proposed Revenue share",
                            format!("{}%", 100u64.saturating_sub(*new)),
                        );
                    } else if *parameter == Parameter::MinimumFeeRate {
                        add("Parameter", "Minimum fee rate".into());
                        add(
                            "Expected value",
                            format!("{old} raw hash units per 1024 weight"),
                        );
                        add(
                            "Proposed value",
                            format!("{new} raw hash units per 1024 weight"),
                        );
                    } else if *parameter == Parameter::PassMarginBps {
                        add("Parameter", "PASS margin".into());
                        add(
                            "Expected margin",
                            format!("{}.{:02}%", old / 100, old % 100),
                        );
                        add(
                            "Proposed margin",
                            format!("{}.{:02}%", new / 100, new % 100),
                        );
                    } else if *parameter == Parameter::MaxPriceChangeBps {
                        add("Parameter", "Maximum price change per block".into());
                        add("Expected value", format!("{}.{:02}%", old / 100, old % 100));
                        add("Proposed value", format!("{}.{:02}%", new / 100, new % 100));
                    } else if *parameter == Parameter::DecisionBlocks {
                        add("Parameter", "Decision length".into());
                        add("Expected value", format!("{old} blocks"));
                        add("Proposed value", format!("{new} blocks"));
                    } else if matches!(
                        parameter,
                        Parameter::Interval | Parameter::Lead | Parameter::Rest
                    ) {
                        add("Parameter", format!("{parameter:?}"));
                        add("Expected value", format!("{old} seconds"));
                        add("Proposed value", format!("{new} seconds"));
                        add(
                            "Timing",
                            "Nominal time at the governed block interval".into(),
                        );
                    } else {
                        add("Parameter", format!("{parameter:?}"));
                        add("Expected value", old.to_string());
                        add("Proposed value", new.to_string());
                    }
                }
            }
        }
        Operation::Support {
            round,
            proposal,
            amount,
        } => {
            add("Action", "Support".into());
            add("Auction round", round.to_string());
            add("Proposal ID", hex::encode(proposal));
            add("Amount · HASH", amount.to_str_radix(10));
        }
        Operation::Refund { round, proposal } => {
            add("Action", "Refund".into());
            add("Auction round", round.to_string());
            add("Proposal ID", hex::encode(proposal));
        }
    }
    let data = &body.data;
    if !data.is_empty() {
        add("Data bytes", data.len().to_string());
        add("Data hex", hex::encode(data));
    }
    fields
}
/// Market trade estimates are short-lived; other operations retain a longer default.
pub fn default_expiry_blocks(operation: &Operation) -> u64 {
    if matches!(
        operation,
        Operation::Deposit { .. } | Operation::Redeem { .. }
    ) {
        2
    } else {
        100
    }
}

fn outcome_name(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "PASS",
        Outcome::Fail => "FAIL",
    }
}

#[cfg(test)]
mod governance_review_tests {
    use super::*;

    #[test]
    fn raw_record_bounds_reserve_signatures_and_reject_overflow_without_allocation() {
        assert!(validate_raw_length(128 * 1024 * 1024).is_ok());
        assert!(validate_raw_length(usize::MAX).is_err());
        assert!(validate_raw_length(0).is_err());
        assert!(validate_raw_length(3).is_err());
        assert!(validate_unsigned_length(isize::MAX as usize - 64).is_ok());
        assert!(validate_unsigned_length(isize::MAX as usize - 63).is_err());
        assert!(validate_unsigned_length(usize::MAX).is_err());
    }

    #[test]
    fn cold_review_labels_governed_timing_in_seconds() {
        for parameter in [Parameter::Interval, Parameter::Lead, Parameter::Rest] {
            let fields = review(&body(parameter, 30, 60));
            assert!(
                fields
                    .iter()
                    .any(|f| f.label == "Expected value" && f.value == "30 seconds")
            );
            assert!(
                fields
                    .iter()
                    .any(|f| f.label == "Proposed value" && f.value == "60 seconds")
            );
        }
    }

    #[test]
    fn cold_review_uses_blocks_and_discloses_partial_trade_execution() {
        let fields = review(&body(Parameter::DecisionBlocks, 60, 120));
        assert!(
            fields
                .iter()
                .any(|field| field.label == "Proposed value" && field.value == "120 blocks")
        );
        let fields = review(&body(Parameter::MaxPriceChangeBps, 1000, 2500));
        assert!(
            fields
                .iter()
                .any(|field| field.label == "Proposed value" && field.value == "25.00%")
        );
        assert!(validate_body(&body(Parameter::DecisionBlocks, 60, 0)).is_err());
        assert!(validate_body(&body(Parameter::MaxPriceChangeBps, 1000, 0)).is_ok());
        for operation in [
            Operation::Deposit {
                amount: 100u32.into(),
                decision: None,
                outcome: None,
            },
            Operation::Redeem {
                shares: 100u32.into(),
                decision: None,
                outcome: None,
            },
        ] {
            let mut transaction = body(Parameter::DecisionBlocks, 60, 120);
            transaction.operation = operation;
            let fields = review(&transaction);
            assert!(
                fields
                    .iter()
                    .any(|field| field.label == "Execution" && field.value.contains("partial"))
            );
            assert!(fields.iter().any(|field| field.label == "Unfilled input"
                && field.value.contains("fee remains payable")));
            assert!(
                fields
                    .iter()
                    .any(|field| field.label == "Expiry block" && field.value == "100")
            );
            assert_eq!(default_expiry_blocks(&transaction.operation), 2);
            assert_eq!(
                decode_unsigned(&unsigned(&transaction)).unwrap(),
                transaction
            );
        }
    }

    fn body(parameter: Parameter, old: u64, new: u64) -> TransactionBody {
        TransactionBody {
            data: Vec::new(),
            chain_id: [42; 32],
            sender: crypto::public_key(&[41; 32]).unwrap(),
            nonce: 0,
            fee: 10u32.into(),
            expiry_height: 100,
            operation: Operation::Propose {
                round: 0,
                description: [0; 32],
                proposal: Proposal::Parameter {
                    parameter,
                    old,
                    new,
                },
                support: 1u32.into(),
            },
        }
    }

    #[test]
    fn cold_review_preserves_full_margin_and_accepts_probability_endpoints() {
        let transaction = body(Parameter::PassMarginBps, 0, u64::MAX);
        assert_eq!(
            decode_unsigned(&unsigned(&transaction)).unwrap(),
            transaction
        );
        assert!(review(&transaction).iter().any(|field| {
            field.label == "Proposed margin" && field.value == "184467440737095516.15%"
        }));
        assert!(decode_unsigned(&unsigned(&body(Parameter::PassMarginBps, 0, 0))).is_err());
    }

    #[test]
    fn cold_review_accepts_fee_split_endpoints_and_rejects_invalid_percentages() {
        for new in [0, 100] {
            let transaction = body(Parameter::MinerFeePercent, 50, new);
            assert_eq!(
                decode_unsigned(&unsigned(&transaction)).unwrap(),
                transaction
            );
        }
        assert!(decode_unsigned(&unsigned(&body(Parameter::MinerFeePercent, 50, 101))).is_err());
    }
}
