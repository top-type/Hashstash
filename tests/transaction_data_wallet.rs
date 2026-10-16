//! Wallet exports preserve arbitrary signed data without assigning it semantics.
use hashstash::{codec, crypto, types::*, wallet};
use std::collections::BTreeMap;

fn operation() -> Operation {
    Operation::TransferExact {
        recipient: crypto::public_key(&[20; 32]).unwrap(),
        amount: 101u32.into(),
    }
}

fn body(data: Vec<u8>) -> TransactionBody {
    TransactionBody {
        sender: crypto::public_key(&[19; 32]).unwrap(),
        nonce: 7,
        fee: 100u32.into(),
        anchor: [0; 32],
        expiry_blocks: 50,
        operation: operation(),
        data,
    }
}

#[test]
fn unsigned_and_signed_exports_preserve_every_data_byte_and_show_complete_hex() {
    for data in [
        Vec::new(),
        vec![0, 0, 1, 0, 255, 0],
        (0..=255).collect(),
        b"<script>alert('data')</script>\0\r\n".to_vec(),
    ] {
        let body = body(data.clone());
        let envelope = wallet::unsigned(&body, &[39; 32]);
        let exported = serde_json::to_string(&envelope).unwrap();
        let decoded = wallet::decode_unsigned(&serde_json::from_str(&exported).unwrap()).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(decoded.data, data);
        let signed = crypto::sign(&decoded, &[19; 32]).unwrap();
        assert_eq!(
            wallet::decode_signed(&wallet::signed_hex(&signed)).unwrap(),
            signed
        );
        let fields: BTreeMap<_, _> = wallet::review(&body, Some(&[39; 32]))
            .into_iter()
            .map(|field| (field.label, field.value))
            .collect();
        assert_eq!(fields["Recipient receives · HASH"], "101");
        assert_eq!(fields["Total debit · HASH"], "201");
        assert_eq!(fields["Fee · HASH"], "100");
        if data.is_empty() {
            assert!(!fields.contains_key("Data bytes"));
            assert!(!fields.contains_key("Data hex"));
            assert_eq!(body.operation, operation());
        } else {
            assert_eq!(fields["Data bytes"], data.len().to_string());
            assert_eq!(fields["Data hex"], hex::encode(data));
            assert!(!fields["Data hex"].contains('<'));
        }
    }
}

#[test]
fn signatures_bind_data_and_every_transaction_header_field() {
    let original = crypto::sign(&body((0..=255).collect()), &[19; 32]).unwrap();
    let mut variants = Vec::new();
    for mutation in 0..8 {
        let mut changed = original.clone();
        match mutation {
            0 => {
                if let Operation::TransferExact { recipient, .. } = &mut changed.body.operation {
                    *recipient = crypto::public_key(&[22; 32]).unwrap();
                }
            }
            1 => changed.body.sender = crypto::public_key(&[21; 32]).unwrap(),
            2 => changed.body.nonce += 1,
            3 => changed.body.expiry_blocks += 1,
            4 => changed.body.fee += 1u32,
            5 => changed.body.data.push(1),
            6 => {
                if let Operation::TransferExact { amount, .. } = &mut changed.body.operation {
                    *amount += 1u32;
                }
            }
            7 => changed.body.anchor[0] ^= 1,
            _ => unreachable!(),
        }
        variants.push(changed);
    }
    for index in 0..256 {
        let mut changed = original.clone();
        changed.body.data[index] ^= 1;
        variants.push(changed);
    }
    for changed in variants {
        assert!(wallet::decode_signed(&wallet::signed_hex(&changed)).is_err());
    }
    assert!(wallet::decode_signed(&wallet::signed_hex(&original)).is_ok());
}

#[test]
fn wallet_rejects_removed_operation_tags_and_oversized_fields() {
    let candidate = body(vec![0, 255]);
    let encoded = codec::encode(&candidate);
    let operation_offset = encoded.len()
        - codec::encode(&candidate.operation).len()
        - codec::encode(&candidate.data).len();
    for tag in [6, 7, 8, 255] {
        let mut malformed = encoded.clone();
        malformed[operation_offset] = tag;
        let mut exported = wallet::unsigned(&candidate, &[39; 32]);
        exported.body = hex::encode(malformed);
        assert!(wallet::decode_unsigned(&exported).is_err());
    }
    let mut candidate = body(vec![0, 255]);
    candidate.fee = Amount::from(1u32) << 512usize;
    assert!(wallet::decode_unsigned(&wallet::unsigned(&candidate, &[39; 32])).is_err());
    candidate = body(vec![0; 32 * 1024 * 1024 + 1]);
    assert!(wallet::decode_unsigned(&wallet::unsigned(&candidate, &[39; 32])).is_ok());
}
