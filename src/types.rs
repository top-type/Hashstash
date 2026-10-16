use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

pub type Amount = BigUint;
pub type Hash = [u8; 32];
pub type PublicKey = [u8; 32];
pub const ZERO_HASH: Hash = [0; 32];

/// Decimal strings in JSON; minimal unsigned little-endian bytes in consensus encoding.
pub mod amount {
    use super::*;
    use serde::{Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(v: &Amount, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&v.to_str_radix(10))
        } else if v.bits() == 0 {
            Vec::<u8>::new().serialize(s)
        } else {
            v.to_bytes_le().serialize(s)
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Amount, D::Error> {
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            if s.is_empty()
                || (s.len() > 1 && s.starts_with('0'))
                || !s.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(D::Error::custom("noncanonical unsigned amount"));
            }
            Amount::parse_bytes(s.as_bytes(), 10).ok_or_else(|| D::Error::custom("invalid amount"))
        } else {
            struct Bytes;
            impl<'de> serde::de::Visitor<'de> for Bytes {
                type Value = Amount;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("a minimal unsigned integer")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Amount, A::Error> {
                    let mut bytes = Vec::new();
                    while let Some(byte) = seq.next_element::<u8>()? {
                        bytes.push(byte);
                    }
                    if bytes.last() == Some(&0) {
                        return Err(A::Error::custom("noncanonical unsigned amount"));
                    }
                    Ok(Amount::from_bytes_le(&bytes))
                }
            }
            d.deserialize_seq(Bytes)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Pass,
    Fail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Parameter {
    BlockBytes,
    Interval,
    Lead,
    Rest,
    DecisionBlocks,
    MinerFeePercent,
    PassMarginBps,
    MinimumFeeRate,
    MaxPriceChangeBps,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPayment {
    pub recipient: PublicKey,
    #[serde(with = "amount")]
    pub amount: Amount,
}

/// The total amount locked in escrow and paid on a successful grant.
pub fn grant_total(payments: &[GrantPayment]) -> anyhow::Result<Amount> {
    anyhow::ensure!(
        !payments.is_empty(),
        "grant must have at least one recipient"
    );
    let mut total = Amount::default();
    let mut previous = None;
    for payment in payments {
        anyhow::ensure!(
            crate::crypto::valid_key(&payment.recipient),
            "invalid grant recipient"
        );
        anyhow::ensure!(payment.amount.bits() != 0, "zero grant payment");
        anyhow::ensure!(
            previous.is_none_or(|key| key < payment.recipient),
            "grant recipients must be strictly increasing"
        );
        previous = Some(payment.recipient);
        total += &payment.amount;
    }
    Ok(total)
}

/// Stream actual payments without trusting an untrusted collection length for
/// allocation. The enclosing record/request byte limit bounds the input; the
/// transaction's encoded bytes and prepaid work bound its admitted capacity.
mod grant_payments {
    use super::GrantPayment;
    use serde::{
        Deserializer,
        de::{Error, SeqAccess, Visitor},
    };

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<GrantPayment>, D::Error> {
        struct Payments;
        impl<'de> Visitor<'de> for Payments {
            type Value = Vec<GrantPayment>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a nonempty grant payment list")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut payments = Vec::new();
                while let Some(payment) = seq.next_element::<GrantPayment>()? {
                    payments.push(payment);
                }
                if payments.is_empty() {
                    return Err(A::Error::custom("empty grant"));
                }
                Ok(payments)
            }
        }
        d.deserialize_seq(Payments)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Proposal {
    Grant {
        #[serde(deserialize_with = "grant_payments::deserialize")]
        payments: Vec<GrantPayment>,
    },
    Parameter {
        parameter: Parameter,
        old: u64,
        new: u64,
    },
}
impl Proposal {
    pub fn grant_total(&self) -> anyhow::Result<Amount> {
        match self {
            Self::Grant { payments } => grant_total(payments),
            Self::Parameter { .. } => anyhow::bail!("not a grant proposal"),
        }
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::{codec, config::Config, crypto};

    #[test]
    fn amount_decoding_uses_actual_record_bytes_instead_of_a_fixed_precision_ceiling() {
        let amount = Amount::from(1u32) << 70_000usize;
        let payment = GrantPayment {
            recipient: crypto::public_key(&[1; 32]).unwrap(),
            amount,
        };
        let bytes = codec::encode(&payment);
        assert!(bytes.len() > 8192);
        assert_eq!(
            codec::decode::<GrantPayment>(&bytes, bytes.len()).unwrap(),
            payment
        );
        let json = serde_json::to_string(&payment).unwrap();
        assert!(json.len() > 20_000);
        assert_eq!(
            serde_json::from_str::<GrantPayment>(&json).unwrap(),
            payment
        );
        let mut truncated = payment.recipient.to_vec();
        truncated.extend(codec::encode(&u64::MAX));
        assert!(codec::decode::<GrantPayment>(&truncated, truncated.len()).is_err());
    }

    fn payments(count: usize) -> Vec<GrantPayment> {
        let mut payments: Vec<_> = (1..=count)
            .map(|i| GrantPayment {
                recipient: crypto::public_key(&[i as u8; 32]).unwrap(),
                amount: Amount::from(i),
            })
            .collect();
        payments.sort_by_key(|p| p.recipient);
        payments
    }

    #[test]
    fn grant_decoder_streams_only_actual_payments_within_the_record_limit() {
        let valid = Proposal::Grant {
            payments: payments(100),
        };
        let bytes = codec::encode(&valid);
        assert_eq!(
            codec::decode::<Proposal>(&bytes, bytes.len()).unwrap(),
            valid
        );
        assert_eq!(bytes[0..2], [0, 100]);
        assert!(codec::decode::<Proposal>(&bytes, bytes.len() - 1).is_err());
        let mut hostile = vec![0, 253];
        hostile.extend_from_slice(&u64::MAX.to_le_bytes());
        // A forged count never becomes an allocation request. Decoding fails
        // on the missing first payment, using only the supplied input bytes.
        assert!(codec::decode::<Proposal>(&hostile, 1024).is_err());
        let mut json = serde_json::to_string(&valid).unwrap();
        assert_eq!(serde_json::from_str::<Proposal>(&json).unwrap(), valid);
        let end = json.rfind(']').unwrap();
        json.insert_str(end, ",{\"untrusted\":true}");
        assert!(serde_json::from_str::<Proposal>(&json).is_err());
        assert!(serde_json::from_str::<Proposal>(r#"{"Grant":{"payments":[]}}"#).is_err());
        assert!(codec::decode::<Proposal>(&[0, 0], 1024).is_err());
    }

    #[test]
    fn canonical_grants_validate_every_payment_and_the_aggregate() {
        let config = Config::devnet();
        let valid = payments(2);
        assert_eq!(config.validate_grant(&valid).unwrap(), 3u32.into());
        let mut bad = valid.clone();
        bad.swap(0, 1);
        assert!(config.validate_grant(&bad).is_err());
        bad = valid.clone();
        bad[1].recipient = bad[0].recipient;
        assert!(config.validate_grant(&bad).is_err());
        bad = valid.clone();
        bad[0].amount = Amount::default();
        assert!(config.validate_grant(&bad).is_err());
        bad = valid.clone();
        bad[0].recipient = [0; 32];
        assert!(config.validate_grant(&bad).is_err());
        bad = valid;
        for payment in &mut bad {
            payment.amount = Amount::from(1u32) << 511usize;
        }
        assert!(bad.iter().all(|p| config.check_amount(&p.amount).is_ok()));
        assert!(
            config.validate_grant(&bad).is_err(),
            "the total must fit even when individual payments fit"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Operation {
    /// The recipient receives the exact amount; the body authorizes the exact full fee.
    TransferExact {
        recipient: PublicKey,
        #[serde(with = "amount")]
        amount: Amount,
    },
    Deposit {
        #[serde(with = "amount")]
        amount: Amount,
        decision: Option<Hash>,
        outcome: Option<Outcome>,
    },
    Redeem {
        #[serde(with = "amount")]
        shares: Amount,
        decision: Option<Hash>,
        outcome: Option<Outcome>,
    },
    Propose {
        round: u64,
        description: Hash,
        proposal: Proposal,
        #[serde(with = "amount")]
        support: Amount,
    },
    Support {
        round: u64,
        proposal: Hash,
        #[serde(with = "amount")]
        amount: Amount,
    },
    Refund {
        round: u64,
        proposal: Hash,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionBody {
    pub sender: PublicKey,
    pub nonce: u64,
    #[serde(with = "amount")]
    pub fee: Amount,
    /// Block whose state was used to prepare this transaction. Its validated
    /// ancestry binds the transaction to the network and branch.
    pub anchor: Hash,
    /// Valid for this many blocks after the signed anchor; retries never extend it.
    pub expiry_blocks: u64,
    pub operation: Operation,
    /// Signed, uninterpreted bytes; applications define their own formats.
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub body: TransactionBody,
    /// BIP340 signatures have exactly 64 bytes, without a binary length prefix.
    #[serde(with = "fixed_bytes")]
    pub signature: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u32,
    pub previous: Hash,
    pub merkle_root: Hash,
    /// Bitcoin nTime, validated against median past time and the future allowance.
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub header: Header,
    pub height: u64,
    pub miner: PublicKey,
    pub state_root: Hash,
    /// Opaque mining-only bytes; length is fixed by the wire format.
    pub extranonce: [u8; 8],
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// Cash in this world. It may differ across governance outcomes;
    /// common payments and fees must be affordable in both worlds.
    #[serde(with = "amount")]
    pub ordinary: Amount,
    #[serde(with = "amount")]
    pub shares: Amount,
    pub nonce: u64,
    pub epoch: u64,
}
impl Default for Account {
    fn default() -> Self {
        Self {
            ordinary: 0u32.into(),
            shares: 0u32.into(),
            nonce: 0,
            epoch: 0,
        }
    }
}

/// Fixed-width bytes are tuples on the binary wire and arrays in human-readable JSON.
mod fixed_bytes {
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
        ser::SerializeTuple,
    };
    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = s.serialize_tuple(N)?;
        for byte in bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        struct Bytes<const N: usize>;
        impl<'de, const N: usize> Visitor<'de> for Bytes<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "exactly {N} bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut bytes = [0u8; N];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::invalid_length(N + 1, &self));
                }
                Ok(bytes)
            }
        }
        d.deserialize_tuple(N, Bytes::<N>)
    }
}
