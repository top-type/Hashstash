//! A read-only conversation view of ordinary UTF-8 transaction data, not consensus.
use crate::types::*;

/// Code points that display nothing on their own: Unicode White_Space plus
/// Default_Ignorable_Code_Point (zero-width spaces, joiners, bidi and
/// variation controls, fillers, tags and the BOM), merged into sorted ranges.
/// Text made only of these is blank. ui/chat.js mirrors this exact table so
/// the node never indexes a message that the browser feed treats as empty.
pub const BLANK: [(u32, u32); 23] = [
    (0x0009, 0x000D),
    (0x0020, 0x0020),
    (0x0085, 0x0085),
    (0x00A0, 0x00A0),
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x1680, 0x1680),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x2000, 0x200F),
    (0x2028, 0x202F),
    (0x205F, 0x206F),
    (0x3000, 0x3000),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
];

pub fn is_blank(c: char) -> bool {
    let c = u32::from(c);
    BLANK.iter().any(|&(low, high)| (low..=high).contains(&c))
}

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
    if text.chars().all(is_blank)
        || text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return None;
    }
    Some(text)
}

/// Interpret data only after the caller validates the transaction and its anchor.
pub fn from_transaction(tx: &Transaction) -> Option<&str> {
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
    fn invisible_only_text_is_blank_like_the_browser_feed() {
        // A BOM or other default-ignorable text must not be indexed as a
        // message that ui/chat.js then rejects as empty.
        for data in [
            b"\xef\xbb\xbf".as_slice(),
            b" \xef\xbb\xbf\n",
            "\u{00a0}\u{2007}\u{3000}".as_bytes(),
            "\u{200b}\u{200c}\u{200d}\u{2060}".as_bytes(),
            "\u{202e}\u{2066}\u{2069}\u{061c}\u{00ad}".as_bytes(),
            "\u{fe0f}\u{e0020}\u{e01ef}\u{3164}\u{ffa0}\u{115f}".as_bytes(),
        ] {
            assert!(decode(data, 16_384).is_none(), "{data:?}");
        }
        for text in ["a\u{feff}b", "\u{feff}hi", "👨\u{200d}👩", "\u{2800}"] {
            assert_eq!(decode(text.as_bytes(), 16_384).unwrap(), text);
        }
        // Every Unicode White_Space character remains blank.
        for c in (0..=0x10ffffu32).filter_map(char::from_u32) {
            if c.is_whitespace() {
                assert!(is_blank(c), "{c:?}");
            }
        }
        // The table is sorted and its ranges are disjoint.
        assert!(BLANK.windows(2).all(|pair| pair[0].1 < pair[1].0));
        assert!(BLANK.iter().all(|&(low, high)| low <= high));
    }

    #[test]
    fn every_data_operation_can_carry_text_without_payment_rules() {
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
                    sender: key,
                    nonce: 0,
                    fee: 1u32.into(),
                    anchor: [0; 32],
                    expiry_blocks: 100,
                    operation,
                    data: b"ordinary note".to_vec(),
                },
                signature: [0; 64],
            };
            // Discovery does not authenticate; callers admit only validated transactions.
            assert_eq!(from_transaction(&tx).unwrap(), "ordinary note");
            tx.body.operation = {
                tx.body.data = vec![b'a'; 32 * 1024];
                tx.body.operation.clone()
            };
            assert!(
                from_transaction(&tx).is_some(),
                "historical messages survive a later capacity reduction"
            );
        }
    }
}
