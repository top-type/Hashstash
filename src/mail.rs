//! Bounded encrypted-mail discovery over signed transaction data.
//! The node validates envelope structure only; it never decrypts message content.
use crate::{config::Config, crypto, types::*};
use serde::{Deserialize, Serialize};

pub const PREFIX: &[u8] = b"hashstash.mail/2\n";
pub const MAX_DATA_BYTES: usize = 3072;
pub const MAX_CIPHERTEXT_BYTES: usize = 1168;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub ephemeral_key: String,
    pub iv: String,
    pub ciphertext: String,
    pub recipient_iv: String,
    pub recipient_key: String,
    pub sender_iv: String,
    pub sender_key: String,
}

fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn decode(data: &[u8]) -> Option<Envelope> {
    if data.len() > MAX_DATA_BYTES {
        return None;
    }
    let body = data.strip_prefix(PREFIX)?;
    let e: Envelope = serde_json::from_slice(body).ok()?;
    if !lower_hex(&e.ephemeral_key, 32)
        || [&e.iv, &e.recipient_iv, &e.sender_iv]
            .iter()
            .any(|v| !lower_hex(v, 12))
        || [&e.recipient_key, &e.sender_key]
            .iter()
            .any(|v| !lower_hex(v, 48))
        || !lower_hex(&e.ciphertext, MAX_CIPHERTEXT_BYTES)
        || serde_json::to_vec(&e).ok()?.as_slice() != body
    {
        return None;
    }
    let key: PublicKey = hex::decode(&e.ephemeral_key).ok()?.try_into().ok()?;
    crypto::valid_key(&key).then_some(e)
}

pub fn from_transaction(c: &Config, tx: &Transaction) -> Option<Envelope> {
    if tx.body.chain_id != c.chain_id() {
        return None;
    }
    // Canonical execution has already authenticated the transaction and its
    // action. Mail is an interpretation of its data, independent of that action.
    decode(&tx.body.data)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn independent_browser_crypto_fixture_has_exact_node_encoding() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/mail-v2.json")).unwrap();
        let bytes = hex::decode(fixture["data_hex"].as_str().unwrap()).unwrap();
        let envelope = decode(&bytes).unwrap();
        assert_eq!(
            [PREFIX, serde_json::to_vec(&envelope).unwrap().as_slice()].concat(),
            bytes
        );
        assert_eq!(fixture["identity"]["nonce"], u64::MAX.to_string());
    }
    pub(crate) fn fixture() -> Vec<u8> {
        let e = Envelope {
            ephemeral_key: hex::encode(crypto::public_key(&[17; 32]).unwrap()),
            iv: "01".repeat(12),
            ciphertext: "02".repeat(MAX_CIPHERTEXT_BYTES),
            recipient_iv: "03".repeat(12),
            recipient_key: "04".repeat(48),
            sender_iv: "05".repeat(12),
            sender_key: "06".repeat(48),
        };
        [PREFIX, &serde_json::to_vec(&e).unwrap()].concat()
    }
    #[test]
    fn envelope_bounds_and_canonical_encoding_are_strict() {
        let data = fixture();
        let valid = decode(&data).unwrap();
        let mut e = valid.clone();
        e.ciphertext = "ab".repeat(MAX_CIPHERTEXT_BYTES);
        assert!(decode(&[PREFIX, &serde_json::to_vec(&e).unwrap()].concat()).is_some());
        e.ciphertext.push_str("00");
        assert!(decode(&[PREFIX, &serde_json::to_vec(&e).unwrap()].concat()).is_none());
        e.ciphertext = "ab".repeat(MAX_CIPHERTEXT_BYTES - 1);
        assert!(decode(&[PREFIX, &serde_json::to_vec(&e).unwrap()].concat()).is_none());
        for field in [
            "ephemeral_key",
            "iv",
            "ciphertext",
            "recipient_iv",
            "recipient_key",
            "sender_iv",
            "sender_key",
        ] {
            let mut v = serde_json::to_value(&valid).unwrap();
            v[field] = serde_json::json!("GG");
            assert!(decode(&[PREFIX, &serde_json::to_vec(&v).unwrap()].concat()).is_none());
        }
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(decode(text.replacen('{', "{ ", 1).as_bytes()).is_none());
        assert!(
            decode(
                text.replacen("\"iv\":", "\"extra\":0,\"iv\":", 1)
                    .as_bytes()
            )
            .is_none()
        );
        assert!(
            decode(
                text.replacen("\"iv\":", "\"iv\":\"00\",\"iv\":", 1)
                    .as_bytes()
            )
            .is_none()
        );
        assert!(decode(&vec![0; MAX_DATA_BYTES + 1]).is_none());
        let mut e = valid;
        e.ephemeral_key = "ff".repeat(32);
        assert!(decode(&[PREFIX, &serde_json::to_vec(&e).unwrap()].concat()).is_none());
    }
    #[test]
    fn discovery_accepts_transaction_data_independently_of_its_action() {
        let c = Config::testnet();
        let sender = crypto::public_key(&[91; 32]).unwrap();
        let mut tx = Transaction {
            body: TransactionBody {
                chain_id: c.chain_id(),
                sender,
                nonce: 0,
                fee: 100u32.into(),
                anchor: [0; 32],
                expiry_blocks: 100,
                operation: Operation::TransferExact {
                    recipient: sender,
                    amount: 1u32.into(),
                },
                data: fixture(),
            },
            // Discovery is derived metadata; canonical execution authenticates.
            signature: [0; 64],
        };
        assert!(from_transaction(&c, &tx).is_some());
        tx.body.chain_id[0] ^= 1;
        assert!(from_transaction(&c, &tx).is_none());
        tx.body.chain_id = c.chain_id();
        for operation in [
            Operation::TransferExact {
                recipient: crypto::public_key(&[92; 32]).unwrap(),
                amount: 1u32.into(),
            },
            Operation::Deposit {
                amount: 1u32.into(),
                decision: None,
                outcome: None,
            },
            Operation::Redeem {
                shares: 1u32.into(),
                decision: Some([7; 32]),
                outcome: Some(Outcome::Pass),
            },
            Operation::Propose {
                round: 1,
                description: [8; 32],
                proposal: Proposal::Grant {
                    payments: vec![crate::types::GrantPayment {
                        recipient: crypto::public_key(&[92; 32]).unwrap(),
                        amount: 1u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
            Operation::Support {
                round: 1,
                proposal: [8; 32],
                amount: 1u32.into(),
            },
            Operation::Refund {
                round: 1,
                proposal: [8; 32],
            },
        ] {
            tx.body.operation = {
                tx.body.data = fixture();
                operation
            };
            assert!(from_transaction(&c, &tx).is_some());
        }
        tx.body.data.truncate(4);
        assert!(from_transaction(&c, &tx).is_none());
    }
}
