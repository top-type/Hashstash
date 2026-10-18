//! Wallet formats are independent of consensus and preserve every signed byte.
use crate::{codec, crypto, types::*};
use anyhow::{Result, ensure};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const UNSIGNED_FORMAT: &str = "hashstash-unsigned-anchor";
/// Legacy brain-wallet derivation, kept only to restore existing accounts.
pub const PASSPHRASE_SCHEME: &str = "hashstash-passphrase-v1";
/// Stretched, network-salted derivation for passphrase accounts.
pub const PASSPHRASE_V2_SCHEME: &str = "hashstash-passphrase-v2";
pub const PASSPHRASE_V2_TAG: &str = "Hashstash/Passphrase/v2";
/// scrypt cost of v2: N = 2^17, r = 8, p = 1 (128 MiB per derivation).
pub const PASSPHRASE_V2_LOG_N: u8 = 17;
pub const PASSPHRASE_V2_R: u32 = 8;
pub const PASSPHRASE_V2_P: u32 = 1;
pub const MIN_PASSPHRASE_V2_BYTES: usize = 16;
pub const MAX_PASSPHRASE_BYTES: usize = 4096;
/// Offline lifetimes above this need an explicit confirmation in the cold signer.
pub const LONG_LIFETIME_BLOCKS: u64 = 1_000;

/// Legacy v1: exact UTF-8, followed by a little-endian u32 retry counter,
/// starting at zero. One unsalted SHA-256 per guess, identical on every
/// network: restore existing accounts only and create new keys another way.
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

/// v2: printable ASCII exactly as typed (no trimming) stretched with scrypt,
/// salted with the tag and the 32-byte chain ID, then the first valid secret
/// `tagged_hash(tag, stretched || counter_le32)`. A phrase opens a different
/// account on every network, and each guess costs one scrypt run. Other text
/// is refused: one visible Unicode phrase has several encodings (composed or
/// decomposed, by keyboard and system) that would open different accounts.
pub fn derive_secret_v2(passphrase: &str, chain_id: &Hash) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(!passphrase.is_empty(), "enter a passphrase");
    ensure!(
        passphrase.bytes().all(|b| (0x20..=0x7e).contains(&b)),
        "v2 passphrases use printable ASCII only: letters, digits, punctuation and spaces"
    );
    ensure!(
        passphrase.len() >= MIN_PASSPHRASE_V2_BYTES,
        "passphrase must contain at least {MIN_PASSPHRASE_V2_BYTES} characters"
    );
    ensure!(
        passphrase.len() <= MAX_PASSPHRASE_BYTES,
        "passphrase input is too large"
    );
    let salt = [PASSPHRASE_V2_TAG.as_bytes(), chain_id.as_slice()].concat();
    let mut input = Zeroizing::new([0u8; 36]);
    crypto::scrypt(
        passphrase.as_bytes(),
        &salt,
        PASSPHRASE_V2_LOG_N,
        PASSPHRASE_V2_R,
        PASSPHRASE_V2_P,
        &mut input[..32],
    )?;
    for counter in 0..=u32::MAX {
        input[32..].copy_from_slice(&counter.to_le_bytes());
        let candidate = Zeroizing::new(crypto::tagged_hash(PASSPHRASE_V2_TAG, input.as_slice()));
        if crypto::public_key(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    anyhow::bail!("could not derive a signing key")
}

/// A signature that stays valid long after review lets its holder choose when
/// to broadcast it.
pub fn long_lifetime(body: &TransactionBody) -> bool {
    body.expiry_blocks > LONG_LIFETIME_BLOCKS
}

/// Whether a proposal's attached data is the rationale its signed description
/// hash commits to, using the publication rule applied by the node.
fn rationale_check(body: &TransactionBody, description: &Hash) -> &'static str {
    use sha2::{Digest, Sha256};
    if body.data.is_empty() {
        return "No attached text";
    }
    if <[u8; 32]>::from(Sha256::digest(&body.data)) != *description {
        return "Does not match the description hash";
    }
    let published = body.data.len() <= crate::proposal_data::MAX_TEXT_BYTES
        && crate::proposal_data::from_transaction(&Transaction {
            body: body.clone(),
            signature: [0; 64],
        })
        .is_some();
    if published {
        "Matches the description hash"
    } else {
        "Matches the hash but is not publishable plain text"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedEnvelope {
    pub format: String,
    /// The network the export was prepared for, outside the body. A signer
    /// signs for its own selected network and rejects a differing context.
    pub chain_id: String,
    pub body: String,
}

pub fn unsigned(body: &TransactionBody, chain_id: &Hash) -> UnsignedEnvelope {
    UnsignedEnvelope {
        format: UNSIGNED_FORMAT.into(),
        chain_id: hex::encode(chain_id),
        body: hex::encode(codec::encode(body)),
    }
}

/// Decode the export's network context. Nothing authenticates it: compare it
/// with the network the signer selected, which the signature then binds.
pub fn unsigned_chain(envelope: &UnsignedEnvelope) -> Result<Hash> {
    ensure!(
        envelope.chain_id.len() == 64
            && envelope
                .chain_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid unsigned network context"
    );
    Ok(hex::decode(&envelope.chain_id)?
        .try_into()
        .expect("checked hash length"))
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
    let body = decode_unsigned_shape(envelope)?;
    validate_body(&body)?;
    Ok(body)
}

/// The canonical body of an export before `validate_body`'s per-field key
/// checks, so a caller can bound that work first (see `grant_payments`).
pub fn decode_unsigned_shape(envelope: &UnsignedEnvelope) -> Result<TransactionBody> {
    ensure!(
        envelope.format == UNSIGNED_FORMAT,
        "unsupported unsigned transaction format"
    );
    unsigned_chain(envelope)?;
    let bytes = raw_bytes(&envelope.body)?;
    // A canonical BIP340 signature adds exactly 64 bytes. Check the actual
    // allocation boundary; block capacity is evaluated against chain state.
    validate_unsigned_length(bytes.len())?;
    codec::decode(&bytes, bytes.len())
}

/// Payments listed by a grant proposal; zero for every other operation.
pub fn grant_payments(body: &TransactionBody) -> usize {
    match &body.operation {
        Operation::Propose {
            proposal: Proposal::Grant { payments },
            ..
        } => payments.len(),
        _ => 0,
    }
}

pub fn signed_hex(transaction: &Transaction) -> String {
    hex::encode(codec::encode(transaction))
}

/// Decode a signed record and verify its signature for the network `chain_id`.
pub fn decode_signed(raw: &str, chain_id: &Hash) -> Result<Transaction> {
    let transaction = decode_signed_record(raw)?;
    crypto::verify(chain_id, &transaction)
        .map_err(|_| anyhow::anyhow!("invalid transaction signature for this network"))?;
    Ok(transaction)
}

/// The canonical shape of a signed record, without its signature check. A
/// signature verifies only for one chain ID; the receiving node checks it.
pub fn decode_signed_record(raw: &str) -> Result<Transaction> {
    let bytes = raw_bytes(raw)?;
    // Hostile hex reaches this from public broadcasts and faucet claims. Walk
    // the framing first, as for peer records, so a forged collection length
    // is refused before the codec reserves memory for it.
    crate::peer_wire::preflight_transaction(&bytes, bytes.len())
        .map_err(|error| anyhow::anyhow!("malformed signed transaction: {error}"))?;
    let transaction: Transaction = codec::decode(&bytes, bytes.len())?;
    validate_body(&transaction.body)?;
    Ok(transaction)
}

/// Validate a transaction's local shape. Chain ancestry and expiry require a node.
pub fn validate_body(body: &TransactionBody) -> Result<()> {
    ensure!(crypto::valid_key(&body.sender), "invalid sender public key");
    ensure!(body.nonce != u64::MAX, "nonce exhausted");
    ensure!(body.expiry_blocks > 0, "expiry blocks must be positive");
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
pub fn review(body: &TransactionBody, chain_id: Option<&Hash>) -> Vec<ReviewField> {
    if let Err(error) = validate_body(body) {
        return vec![ReviewField {
            label: "Invalid transaction".into(),
            value: error.to_string(),
        }];
    }
    let account = |key: &PublicKey| {
        chain_id.map_or_else(
            || hex::encode(key),
            |chain| {
                crate::address::encode(key, chain)
                    .unwrap_or_else(|_| format!("Invalid public key: {}", hex::encode(key)))
            },
        )
    };
    let mut fields = Vec::new();
    let mut add = |label: &str, value: String| {
        fields.push(ReviewField {
            label: label.into(),
            value,
        })
    };
    // The signing message commits to this chain ID, so no other network
    // accepts the signature, whichever network the anchor came from.
    if let Some(chain) = chain_id {
        add("Network · signed", hex::encode(chain));
    }
    add(
        "Anchor validation",
        "Ancestry and expiry are checked by the receiving node".into(),
    );
    add("Sender", account(&body.sender));
    add("Nonce", body.nonce.to_string());
    add("Anchor block", hex::encode(body.anchor));
    add("Valid for · blocks", body.expiry_blocks.to_string());
    if long_lifetime(body) {
        let trade = matches!(
            body.operation,
            Operation::Deposit { .. } | Operation::Redeem { .. }
        );
        add(
            "Lifetime warning",
            format!(
                "Valid for {} blocks, far beyond the {}-block default. Until it expires or this nonce is used, whoever holds the signed transaction can broadcast it at a time of their choosing{}",
                body.expiry_blocks,
                default_expiry_blocks(&body.operation),
                if trade {
                    ", and the order fills at that block's price"
                } else {
                    ""
                }
            ),
        );
    }
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
            add(
                "Execution",
                "Batch trade; full, partial or zero fill".into(),
            );
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
            add(
                "Execution",
                "Batch trade; full, partial or zero fill".into(),
            );
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
            add("Rationale", rationale_check(body, description).into());
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
/// Every newly prepared transaction has a short lifetime from its signed anchor.
pub fn default_expiry_blocks(_operation: &Operation) -> u64 {
    2
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
    fn unsigned_network_context_is_canonical_metadata_outside_signed_body() {
        let transaction = body(Parameter::DecisionBlocks, 60, 120);
        let first = unsigned(&transaction, &[42; 32]);
        let second = unsigned(&transaction, &[43; 32]);
        assert_ne!(first.chain_id, second.chain_id);
        assert_eq!(first.body, second.body);
        assert_eq!(
            decode_unsigned(&first).unwrap(),
            decode_unsigned(&second).unwrap()
        );
        assert!(
            !serde_json::to_value(&transaction)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("chain_id")
        );
        let fields = review(&transaction, Some(&[42; 32]));
        assert!(
            fields
                .iter()
                .any(|field| field.label == "Network · signed"
                    && field.value == hex::encode([42; 32]))
        );
        assert!(
            fields
                .iter()
                .any(|field| field.label == "Anchor validation")
        );
        let without_context = review(&transaction, None);
        assert!(
            without_context
                .iter()
                .any(|field| field.label == "Sender"
                    && field.value == hex::encode(transaction.sender))
        );
        assert!(!without_context.iter().any(|f| f.label.starts_with("Network")));
        for malformed in [String::new(), "00".into(), "g".repeat(64), "AA".repeat(32)] {
            let mut changed = first.clone();
            changed.chain_id = malformed;
            assert!(decode_unsigned(&changed).is_err());
        }
        let mut legacy = first.clone();
        legacy.format = "hashstash-unsigned-v1".into();
        assert!(decode_unsigned(&legacy).is_err());
        let mut missing = serde_json::to_value(first).unwrap();
        missing.as_object_mut().unwrap().remove("chain_id");
        assert!(serde_json::from_value::<UnsignedEnvelope>(missing).is_err());
    }

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
            let fields = review(&body(parameter, 30, 60), Some(&[42; 32]));
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
        assert_eq!(
            default_expiry_blocks(&body(Parameter::DecisionBlocks, 60, 120).operation),
            2
        );
        let fields = review(&body(Parameter::DecisionBlocks, 60, 120), Some(&[42; 32]));
        assert!(
            fields
                .iter()
                .any(|field| field.label == "Proposed value" && field.value == "120 blocks")
        );
        let fields = review(
            &body(Parameter::MaxPriceChangeBps, 1000, 2500),
            Some(&[42; 32]),
        );
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
            let fields = review(&transaction, Some(&[42; 32]));
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
                    .any(|field| field.label == "Valid for · blocks" && field.value == "100")
            );
            assert!(fields.iter().any(|field| field.label == "Anchor block"
                && field.value == hex::encode(transaction.anchor)));
            assert_eq!(default_expiry_blocks(&transaction.operation), 2);
            assert_eq!(
                decode_unsigned(&unsigned(&transaction, &[42; 32])).unwrap(),
                transaction
            );
        }
    }

    #[test]
    fn cold_review_flags_long_lifetimes_and_names_the_signed_network() {
        let mut transaction = body(Parameter::DecisionBlocks, 60, 120);
        let fields = review(&transaction, Some(&[42; 32]));
        assert_eq!(fields[0].label, "Network · signed");
        assert!(!fields.iter().any(|f| f.label == "Lifetime warning"));
        for (lifetime, warned) in [
            (LONG_LIFETIME_BLOCKS, false),
            (LONG_LIFETIME_BLOCKS + 1, true),
            (u64::MAX, true),
        ] {
            transaction.expiry_blocks = lifetime;
            assert_eq!(long_lifetime(&transaction), warned);
            let fields = review(&transaction, Some(&[42; 32]));
            let warning = fields.iter().find(|f| f.label == "Lifetime warning");
            assert_eq!(warning.is_some(), warned, "lifetime {lifetime}");
            if let Some(warning) = warning {
                assert!(warning.value.contains(&lifetime.to_string()));
                assert!(!warning.value.contains("price"));
            }
        }
        transaction.operation = Operation::Deposit {
            amount: 100u32.into(),
            decision: None,
            outcome: None,
        };
        let fields = review(&transaction, Some(&[42; 32]));
        assert!(fields.iter().any(|f| f.label == "Lifetime warning"
            && f.value.contains("fills at that block's price")));
    }

    #[test]
    fn cold_review_checks_proposal_text_against_its_signed_commitment() {
        use sha2::{Digest, Sha256};
        let text = "Fund the shared explorer";
        let mut transaction = body(Parameter::DecisionBlocks, 60, 120);
        let check = |transaction: &TransactionBody| {
            review(transaction, Some(&[42; 32]))
                .into_iter()
                .find(|f| f.label == "Rationale")
                .unwrap()
                .value
        };
        assert_eq!(check(&transaction), "No attached text");
        transaction.data = text.as_bytes().to_vec();
        assert_eq!(check(&transaction), "Does not match the description hash");
        let Operation::Propose { description, .. } = &mut transaction.operation else {
            unreachable!()
        };
        *description = Sha256::digest(text.as_bytes()).into();
        assert_eq!(check(&transaction), "Matches the description hash");
        // Same publication rule as the node: matching bytes that are not plain
        // trimmed text are never shown as the rationale.
        let padded = format!(" {text}");
        transaction.data = padded.as_bytes().to_vec();
        let Operation::Propose { description, .. } = &mut transaction.operation else {
            unreachable!()
        };
        *description = Sha256::digest(padded.as_bytes()).into();
        assert_eq!(
            check(&transaction),
            "Matches the hash but is not publishable plain text"
        );
    }

    fn body(parameter: Parameter, old: u64, new: u64) -> TransactionBody {
        TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(&[41; 32]).unwrap(),
            nonce: 0,
            fee: 10u32.into(),
            anchor: [38; 32],
            expiry_blocks: 100,
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
            decode_unsigned(&unsigned(&transaction, &[42; 32])).unwrap(),
            transaction
        );
        assert!(review(&transaction, Some(&[42; 32])).iter().any(|field| {
            field.label == "Proposed margin" && field.value == "184467440737095516.15%"
        }));
        assert!(
            decode_unsigned(&unsigned(&body(Parameter::PassMarginBps, 0, 0), &[42; 32])).is_err()
        );
    }

    #[test]
    fn cold_review_accepts_fee_split_endpoints_and_rejects_invalid_percentages() {
        for new in [0, 100] {
            let transaction = body(Parameter::MinerFeePercent, 50, new);
            assert_eq!(
                decode_unsigned(&unsigned(&transaction, &[42; 32])).unwrap(),
                transaction
            );
        }
        assert!(
            decode_unsigned(&unsigned(
                &body(Parameter::MinerFeePercent, 50, 101),
                &[42; 32]
            ))
            .is_err()
        );
    }
}

#[cfg(test)]
mod signed_record_tests {
    use super::*;

    fn signed(operation: Operation, data: Vec<u8>) -> Transaction {
        let body = TransactionBody {
            sender: crypto::public_key(&[41; 32]).unwrap(),
            nonce: 3,
            fee: 10u32.into(),
            anchor: [38; 32],
            expiry_blocks: 100,
            operation,
            data,
        };
        crypto::sign(&[42; 32], &body, &[41; 32]).unwrap()
    }

    fn grant(payments: u8) -> Operation {
        let mut recipients: Vec<_> = (0..payments)
            .map(|i| crypto::public_key(&[43 + i; 32]).unwrap())
            .collect();
        recipients.sort();
        Operation::Propose {
            round: 1,
            description: [77; 32],
            proposal: Proposal::Grant {
                payments: recipients
                    .into_iter()
                    .map(|recipient| GrantPayment {
                        recipient,
                        amount: 5u32.into(),
                    })
                    .collect(),
            },
            support: 1u32.into(),
        }
    }

    #[test]
    fn signed_records_pass_the_structural_preflight_before_decoding() {
        let key = crypto::public_key(&[43; 32]).unwrap();
        for operation in [
            Operation::TransferExact {
                recipient: key,
                amount: 9u32.into(),
            },
            Operation::Deposit {
                amount: 9u32.into(),
                decision: Some([5; 32]),
                outcome: Some(Outcome::Fail),
            },
            Operation::Redeem {
                shares: 9u32.into(),
                decision: None,
                outcome: None,
            },
            grant(2),
            Operation::Propose {
                round: 2,
                description: [6; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::Interval,
                    old: 15,
                    new: 30,
                },
                support: 1u32.into(),
            },
            Operation::Support {
                round: 2,
                proposal: [7; 32],
                amount: 9u32.into(),
            },
            Operation::Refund {
                round: 2,
                proposal: [7; 32],
            },
        ] {
            let transaction = signed(operation, b"note".to_vec());
            let raw = signed_hex(&transaction);
            assert_eq!(decode_signed_record(&raw).unwrap(), transaction);
            assert_eq!(decode_signed(&raw, &[42; 32]).unwrap(), transaction);
        }
    }

    #[test]
    fn forged_collection_lengths_are_refused_by_the_preflight() {
        let bytes = codec::encode(&signed(grant(2), Vec::new()));
        // The description, the Grant tag and then the payment count.
        let at = bytes
            .windows(34)
            .position(|w| w[..32] == [77; 32] && w[32..] == [0, 2])
            .unwrap()
            + 33;
        for forged in [1u64 << 40, u64::MAX] {
            let mut payments = bytes[..at].to_vec();
            payments.push(253);
            payments.extend_from_slice(&forged.to_le_bytes());
            payments.extend_from_slice(&bytes[at + 1..]);
            let error = decode_signed_record(&hex::encode(&payments)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("grant count exceeds remaining transaction bytes"),
                "{error}"
            );
        }
        // Empty data is the last collection, just before the 64-byte signature.
        let plain = codec::encode(&signed(grant(1), Vec::new()));
        let data = plain.len() - 65;
        assert_eq!(plain[data], 0);
        let mut forged = plain[..data].to_vec();
        forged.push(253);
        forged.extend_from_slice(&(1u64 << 40).to_le_bytes());
        forged.extend_from_slice(&plain[data + 1..]);
        let error = decode_signed_record(&hex::encode(&forged)).unwrap_err();
        assert!(
            error.to_string().starts_with("malformed signed transaction"),
            "{error}"
        );
    }
}
