//! A read-only conversation view of ordinary UTF-8 transaction data, not consensus.
use crate::{config::Config, types::*};

pub fn decode(data: &[u8], max_bytes: usize) -> Option<&str> {
    if data.len() > max_bytes {
        return None;
    }
    // Encrypted-mail payloads are not public prose, even if their outer
    // envelope is printable UTF-8 or uses a later version.
    if data.starts_with(b"hashstash.mail/") {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?;
    if text.trim().is_empty()
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(text)
}

pub fn from_transaction<'a>(c: &Config, tx: &'a Transaction) -> Option<&'a str> {
    if tx.body.chain_id != c.chain_id() {
        return None;
    }
    decode(&tx.body.data, tx.body.data.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_text_is_bounded_and_excludes_encrypted_mail() {
        for text in [
            "Hello 🌱",
            "<script>literal text</script>",
            "first\r\n\tsecond",
            r#"{"ordinary":"JSON is also text"}"#,
            "hashstash.proposal/1\n{}",
            "hashstash.chat/1\n{}",
        ] {
            assert_eq!(decode(text.as_bytes(), 16_384).unwrap(), text);
        }
        for data in [
            b"".as_slice(),
            b" \r\n\t",
            b"bad\0text",
            b"bad\x1btext",
            &[0xff],
            b"hashstash.mail/1\n{}",
            b"hashstash.mail/2\nciphertext",
        ] {
            assert!(decode(data, 16_384).is_none(), "{data:?}");
        }
        assert!(decode("🌱".repeat(256).as_bytes(), 1024).is_some());
        assert!(decode("🌱".repeat(257).as_bytes(), 1024).is_none());
    }

    #[test]
    fn every_data_operation_can_carry_text_without_payment_rules() {
        let c = Config::devnet();
        let key = crate::crypto::public_key(&[22; 32]).unwrap();
        let operations = [
            Operation::TransferExact {
                recipient: key,
                amount: 1u32.into(),
            },
            Operation::Deposit {
                amount: 1u32.into(),
                decision: None,
                outcome: None,
            },
            Operation::Refund {
                round: 0,
                proposal: [0; 32],
            },
            Operation::Propose {
                round: 0,
                description: [0; 32],
                proposal: Proposal::Grant {
                    payments: vec![crate::types::GrantPayment {
                        recipient: key,
                        amount: 1u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
        ];
        for operation in operations {
            let mut tx = Transaction {
                body: TransactionBody {
                    chain_id: c.chain_id(),
                    sender: key,
                    nonce: 0,
                    fee: 1u32.into(),
                    expiry_height: 100,
                    operation,
                    data: b"ordinary note".to_vec(),
                },
                signature: [0; 64],
            };
            // Discovery does not authenticate; callers admit only validated transactions.
            assert_eq!(from_transaction(&c, &tx).unwrap(), "ordinary note");
            tx.body.chain_id[0] ^= 1;
            assert!(from_transaction(&c, &tx).is_none());
            tx.body.chain_id = c.chain_id();
            tx.body.operation = {
                tx.body.data = vec![b'a'; 32 * 1024];
                tx.body.operation.clone()
            };
            assert!(
                from_transaction(&c, &tx).is_some(),
                "historical messages survive a later capacity reduction"
            );
        }
    }
}
