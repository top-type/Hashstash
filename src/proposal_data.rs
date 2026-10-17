//! Shared rationale carried by a proposal transaction and verified against its commitment.
use crate::types::*;
use sha2::{Digest, Sha256};

pub const MAX_TEXT_BYTES: usize = 2048;

pub fn from_transaction(tx: &Transaction) -> Option<String> {
    let Operation::Propose { description, .. } = tx.body.operation.clone() else {
        return None;
    };
    let data = &tx.body.data;
    if data.len() > MAX_TEXT_BYTES {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    if text.is_empty()
        || text.trim() != text
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    let digest: Hash = Sha256::digest(text.as_bytes()).into();
    (digest == description).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    #[test]
    fn rationale_requires_exact_signed_commitment_and_plain_text() {
        let secret = [22; 32];
        let text = "A shared explanation 🌱";
        let mut body = TransactionBody {
            sender: crypto::public_key(&secret).unwrap(),
            nonce: 0,
            anchor: [0; 32],
            expiry_blocks: 100,
            fee: 1u32.into(),
            operation: Operation::Propose {
                round: 1,
                description: Sha256::digest(text.as_bytes()).into(),
                proposal: Proposal::Grant {
                    payments: vec![crate::types::GrantPayment {
                        recipient: crypto::public_key(&secret).unwrap(),
                        amount: 1u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
            data: text.as_bytes().to_vec(),
        };
        assert_eq!(
            from_transaction(&crypto::sign(&[0; 32], &body, &secret).unwrap()).as_deref(),
            Some(text)
        );
        let mut operation = body.operation.clone();
        if let Operation::Propose { description, .. } = &mut operation {
            description[0] ^= 1;
        }
        body.operation = operation;
        assert!(from_transaction(&crypto::sign(&[0; 32], &body, &secret).unwrap()).is_none());
    }

    #[test]
    fn plain_rationale_retains_exact_bounds_and_does_not_unwrap_json() {
        let secret = [22; 32];
        let parse = |text: &str, data: &[u8]| {
            let transaction = crypto::sign(
                &[0; 32],
                &TransactionBody {
                    sender: crypto::public_key(&secret).unwrap(),
                    nonce: 0,
                    anchor: [0; 32],
                    expiry_blocks: 100,
                    fee: 1u32.into(),
                    operation: Operation::Propose {
                        round: 1,
                        description: Sha256::digest(text.as_bytes()).into(),
                        proposal: Proposal::Grant {
                            payments: vec![crate::types::GrantPayment {
                                recipient: crypto::public_key(&secret).unwrap(),
                                amount: 1u32.into(),
                            }],
                        },
                        support: 1u32.into(),
                    },
                    data: data.to_vec(),
                },
                &secret,
            )
            .unwrap();
            from_transaction(&transaction)
        };
        let maximum = "é".repeat(MAX_TEXT_BYTES / 2);
        assert_eq!(parse(&maximum, maximum.as_bytes()), Some(maximum.clone()));
        let excessive = format!("{maximum}x");
        assert!(parse(&excessive, excessive.as_bytes()).is_none());
        for text in [
            "",
            " ",
            " leading",
            "trailing ",
            "nul\0byte",
            "line\u{000b}break",
            "delete\u{007f}byte",
            "next\u{0085}line",
        ] {
            assert!(parse(text, text.as_bytes()).is_none());
        }
        let readable = "First line\nSecond line\r\n\tIndented.";
        assert_eq!(
            parse(readable, readable.as_bytes()).as_deref(),
            Some(readable)
        );
        assert!(parse("explanation", &[0xff]).is_none());
        assert!(parse("explanation", b"{\"text\":\"explanation\"}").is_none());
    }
}
