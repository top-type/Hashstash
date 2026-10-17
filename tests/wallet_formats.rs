//! Offline export boundaries, exact review fields, and independently calculated keys.
use hashstash::{
    address, codec, crypto,
    types::{Amount, Operation, Outcome, Parameter, Proposal, TransactionBody},
    wallet::{self, UnsignedEnvelope},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn body(operation: Operation) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        sender: crypto::public_key(&[19; 32]).unwrap(),
        nonce: u64::MAX - 1,
        fee: maximum_amount(),
        anchor: [38; 32],
        expiry_blocks: u64::MAX,
        operation,
    }
}

fn maximum_amount() -> Amount {
    (Amount::from(1u32) << 512usize) - 1u32
}

fn fields(body: &TransactionBody) -> BTreeMap<String, String> {
    let result = wallet::review(body, Some(&[39; 32]));
    let count = result.len();
    let map: BTreeMap<_, _> = result.into_iter().map(|f| (f.label, f.value)).collect();
    assert_eq!(
        map.len(),
        count,
        "duplicate review labels hide signed fields"
    );
    map
}

fn expected(action: &str, entries: &[(&str, String)]) -> BTreeMap<String, String> {
    let mut result = BTreeMap::from([
        ("Network context · unsigned".into(), hex::encode([39; 32])),
        (
            "Anchor validation".into(),
            "Ancestry and expiry are checked by the receiving node".into(),
        ),
        (
            "Sender".into(),
            address::encode(&crypto::public_key(&[19; 32]).unwrap(), &[39; 32]).unwrap(),
        ),
        (
            "Network check".into(),
            "The signature does not name a network: it is valid only where the anchor block exists, which this review cannot verify. Use a separate key for each network that holds value".into(),
        ),
        ("Nonce".into(), (u64::MAX - 1).to_string()),
        ("Anchor block".into(), hex::encode([38; 32])),
        ("Valid for · blocks".into(), u64::MAX.to_string()),
        // Every fixture uses the largest lifetime, which always needs a warning.
        (
            "Lifetime warning".into(),
            format!(
                "Valid for {} blocks, far beyond the 2-block default. Until it expires or this nonce is used, whoever holds the signed transaction can broadcast it at a time of their choosing{}",
                u64::MAX,
                if matches!(action, "Deposit" | "Redeem") {
                    ", and the order fills at that block's price"
                } else {
                    ""
                }
            ),
        ),
        ("Fee · HASH".into(), maximum_amount().to_string()),
        ("Action".into(), action.into()),
    ]);
    if action == "Propose" {
        result.insert("Rationale".into(), "No attached text".into());
    }
    result.extend(entries.iter().map(|(k, v)| (k.to_string(), v.clone())));
    result
}

#[test]
fn exact_transfer_review_and_signature_preserve_recipient_amount_and_fee() {
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    let mut b = body(Operation::TransferExact {
        recipient,
        amount: 100u32.into(),
    });
    b.fee = 6u32.into();
    let original = wallet::unsigned(&b, &[39; 32]);
    assert_eq!(wallet::decode_unsigned(&original).unwrap(), b);
    let review = fields(&b);
    assert_eq!(review["Recipient receives · HASH"], "100");
    assert!(!review.contains_key("Account creation maximum · HASH"));
    assert_eq!(review["Total debit · HASH"], "106");
    assert_eq!(review["Fee · HASH"], "6");
    assert!(!review.contains_key("Minimum received · HASH"));
    assert!(!review.contains_key("Gross payment · HASH"));
    let tx = crypto::sign(&b, &[19; 32]).unwrap();
    assert_eq!(wallet::decode_signed(&wallet::signed_hex(&tx)).unwrap(), tx);
    for changed in [
        Operation::TransferExact {
            recipient,
            amount: 99u32.into(),
        },
        Operation::TransferExact {
            recipient: crypto::public_key(&[21; 32]).unwrap(),
            amount: 100u32.into(),
        },
    ] {
        let mut changed_tx = tx.clone();
        changed_tx.body.operation = changed;
        assert!(wallet::decode_signed(&wallet::signed_hex(&changed_tx)).is_err());
    }
    // Reviews use exact integers even if the conservative maximum spans the
    // largest individually accepted fields.
    b.operation = Operation::TransferExact {
        recipient,
        amount: maximum_amount(),
    };
    b.fee = maximum_amount();
    assert_eq!(
        fields(&b)["Total debit · HASH"],
        (maximum_amount() * 2u32).to_string()
    );
}

#[test]
fn independent_passphrase_vectors_preserve_utf8_and_whitespace() {
    let document: Value = serde_json::from_str(include_str!("data/passphrase-v1.json")).unwrap();
    assert_eq!(document["scheme"], wallet::PASSPHRASE_SCHEME);
    assert_eq!(document["tag"], "Hashstash/Passphrase/v1");
    let mut distinct = std::collections::BTreeSet::new();
    for vector in document["vectors"].as_array().unwrap() {
        let phrase = vector["passphrase"].as_str().unwrap();
        assert_eq!(hex::encode(phrase.as_bytes()), vector["utf8_hex"]);
        let first = wallet::derive_secret(phrase).unwrap();
        let second = wallet::derive_secret(phrase).unwrap();
        assert_eq!(*first, *second);
        assert_eq!(hex::encode(*first), vector["secret"]);
        let public = crypto::public_key(&first).unwrap();
        assert_eq!(hex::encode(public), vector["public_key"]);
        assert!(
            distinct.insert(public),
            "whitespace/Unicode normalization changed a key"
        );
    }
    assert_eq!(distinct.len(), 8);
}

#[test]
fn independent_v2_passphrase_vectors_are_stretched_and_network_specific() {
    let document: Value = serde_json::from_str(include_str!("data/passphrase-v2.json")).unwrap();
    assert_eq!(document["scheme"], wallet::PASSPHRASE_V2_SCHEME);
    assert_eq!(document["tag"], wallet::PASSPHRASE_V2_TAG);
    assert_eq!(document["kdf"]["log_n"], wallet::PASSPHRASE_V2_LOG_N);
    assert_eq!(document["kdf"]["r"], wallet::PASSPHRASE_V2_R);
    assert_eq!(document["kdf"]["p"], wallet::PASSPHRASE_V2_P);
    assert_eq!(document["minimum_bytes"], wallet::MIN_PASSPHRASE_V2_BYTES);
    let mut distinct = std::collections::BTreeSet::new();
    for vector in document["vectors"].as_array().unwrap() {
        let phrase = vector["passphrase"].as_str().unwrap();
        assert_eq!(hex::encode(phrase.as_bytes()), vector["utf8_hex"]);
        let chain: [u8; 32] = hex::decode(vector["chain_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut stretched = [0u8; 32];
        let salt = [wallet::PASSPHRASE_V2_TAG.as_bytes(), chain.as_slice()].concat();
        crypto::scrypt(phrase.as_bytes(), &salt, 17, 8, 1, &mut stretched).unwrap();
        assert_eq!(hex::encode(stretched), vector["stretched"]);
        let secret = wallet::derive_secret_v2(phrase, &chain).unwrap();
        assert_eq!(hex::encode(*secret), vector["secret"]);
        let public = crypto::public_key(&secret).unwrap();
        assert_eq!(hex::encode(public), vector["public_key"]);
        assert!(distinct.insert(public), "network, whitespace or Unicode form ignored");
        // Never the legacy key for the same phrase.
        assert_ne!(*wallet::derive_secret(phrase).unwrap(), *secret);
    }
    assert_eq!(distinct.len(), 6);
    let chain = [39; 32];
    assert!(wallet::derive_secret_v2("", &chain).is_err());
    assert!(wallet::derive_secret_v2(&"a".repeat(wallet::MIN_PASSPHRASE_V2_BYTES - 1), &chain).is_err());
    assert!(wallet::derive_secret_v2(&"é".repeat(7), &chain).is_err());
    assert!(wallet::derive_secret_v2(&"é".repeat(8), &chain).is_ok());
    assert!(
        wallet::derive_secret_v2(&"a".repeat(wallet::MAX_PASSPHRASE_BYTES + 1), &chain).is_err()
    );
}

#[test]
fn passphrase_input_limits_count_bytes_without_strength_rules() {
    assert!(wallet::derive_secret("").is_err());
    assert!(wallet::derive_secret("a").is_ok());
    assert!(wallet::derive_secret(" ").is_ok());
    assert!(wallet::derive_secret(&"a".repeat(wallet::MAX_PASSPHRASE_BYTES)).is_ok());
    assert!(wallet::derive_secret(&"a".repeat(wallet::MAX_PASSPHRASE_BYTES + 1)).is_err());
    assert!(wallet::derive_secret(&"é".repeat(wallet::MAX_PASSPHRASE_BYTES / 2)).is_ok());
    assert!(wallet::derive_secret(&"é".repeat(wallet::MAX_PASSPHRASE_BYTES / 2 + 1)).is_err());
}

#[test]
fn every_operation_roundtrips_and_reviews_every_signed_field_exactly() {
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    let amount = maximum_amount();
    let minimum = &amount - 1u32;
    let id = [41; 32];
    let mut cases = vec![(
        Operation::TransferExact {
            recipient,
            amount: amount.clone(),
        },
        expected(
            "Transfer",
            &[
                ("Recipient", address::encode(&recipient, &[39; 32]).unwrap()),
                ("Recipient receives · HASH", amount.to_string()),
                ("Total debit · HASH", (&amount * 2u32).to_string()),
            ],
        ),
    )];
    for outcome in [None, Some(Outcome::Pass), Some(Outcome::Fail)] {
        let decision = outcome.map(|_| id);
        let outcome_name = match outcome {
            None => "Ordinary",
            Some(Outcome::Pass) => "PASS",
            Some(Outcome::Fail) => "FAIL",
        };
        for (operation, action, value_label) in [
            (
                Operation::Deposit {
                    amount: amount.clone(),

                    decision,
                    outcome,
                },
                "Deposit",
                "Amount · HASH",
            ),
            (
                Operation::Redeem {
                    shares: amount.clone(),

                    decision,
                    outcome,
                },
                "Redeem",
                "Shares",
            ),
        ] {
            let mut entries = vec![
                (value_label, amount.to_string()),
                ("Outcome", outcome_name.into()),
            ];
            entries.push((
                "Execution",
                "Batch trade; full, partial or zero fill".into(),
            ));
            entries.push((
                "Unfilled input",
                "Returned automatically; transaction fee remains payable".into(),
            ));
            if let Some(decision) = decision {
                entries.push(("Decision ID", hex::encode(decision)));
            }
            cases.push((operation, expected(action, &entries)));
        }
    }
    cases.push((
        Operation::Propose {
            round: u64::MAX,
            description: [42; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient,
                    amount: amount.clone(),
                }],
            },
            support: minimum.clone(),
        },
        expected(
            "Propose",
            &[
                ("Auction round", u64::MAX.to_string()),
                ("Description hash", hex::encode([42; 32])),
                ("Support · HASH", minimum.to_string()),
                ("Proposal", "Grant".into()),
                (
                    "Recipient 1",
                    address::encode(&recipient, &[39; 32]).unwrap(),
                ),
                ("Payment 1 · HASH", amount.to_string()),
                ("Total grant · HASH", amount.to_string()),
            ],
        ),
    ));
    for parameter in [
        Parameter::BlockBytes,
        Parameter::Lead,
        Parameter::Rest,
        Parameter::DecisionBlocks,
    ] {
        let seconds = matches!(parameter, Parameter::Lead | Parameter::Rest);
        let blocks = parameter == Parameter::DecisionBlocks;
        let mut fields = vec![
            ("Auction round", u64::MAX.to_string()),
            ("Description hash", hex::encode([43; 32])),
            ("Support · HASH", amount.to_string()),
            ("Proposal", "Parameter".into()),
            (
                "Parameter",
                if blocks {
                    "Decision length".into()
                } else {
                    format!("{parameter:?}")
                },
            ),
            (
                "Expected value",
                if blocks {
                    format!("{} blocks", u64::MAX)
                } else if seconds {
                    format!("{} seconds", u64::MAX)
                } else {
                    u64::MAX.to_string()
                },
            ),
            (
                "Proposed value",
                if blocks {
                    format!("{} blocks", u64::MAX - 1)
                } else if seconds {
                    format!("{} seconds", u64::MAX - 1)
                } else {
                    (u64::MAX - 1).to_string()
                },
            ),
        ];
        if seconds {
            fields.push((
                "Timing",
                "Nominal time at the governed block interval".into(),
            ));
        }
        cases.push((
            Operation::Propose {
                round: u64::MAX,
                description: [43; 32],
                proposal: Proposal::Parameter {
                    parameter,
                    old: u64::MAX,
                    new: u64::MAX - 1,
                },
                support: amount.clone(),
            },
            expected("Propose", &fields),
        ));
    }
    for (old, new) in [(50, 0), (50, 75), (50, 100), (0, 1), (100, 60)] {
        cases.push((
            Operation::Propose {
                round: 3,
                description: [43; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::MinerFeePercent,
                    old,
                    new,
                },
                support: amount.clone(),
            },
            expected(
                "Propose",
                &[
                    ("Auction round", "3".into()),
                    ("Description hash", hex::encode([43; 32])),
                    ("Support · HASH", amount.to_string()),
                    ("Proposal", "Parameter".into()),
                    ("Parameter", "Miner fee share".into()),
                    ("Expected miner share", format!("{old}%")),
                    ("Proposed miner share", format!("{new}%")),
                    ("Expected Revenue share", format!("{}%", 100 - old)),
                    ("Proposed Revenue share", format!("{}%", 100 - new)),
                ],
            ),
        ));
    }
    cases.push((
        Operation::Support {
            round: u64::MAX,
            proposal: id,
            amount: amount.clone(),
        },
        expected(
            "Support",
            &[
                ("Auction round", u64::MAX.to_string()),
                ("Proposal ID", hex::encode(id)),
                ("Amount · HASH", amount.to_string()),
            ],
        ),
    ));
    cases.push((
        Operation::Refund {
            round: u64::MAX,
            proposal: id,
        },
        expected(
            "Refund",
            &[
                ("Auction round", u64::MAX.to_string()),
                ("Proposal ID", hex::encode(id)),
            ],
        ),
    ));
    assert_eq!(cases.len(), 19);
    for (operation, expected) in cases {
        let body = body(operation);
        let envelope = wallet::unsigned(&body, &[39; 32]);
        let serialized = serde_json::to_string(&envelope).unwrap();
        let recovered: UnsignedEnvelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(wallet::decode_unsigned(&recovered).unwrap(), body);
        assert_eq!(fields(&body), expected);
        let review_json = serde_json::to_value(wallet::review(&body, Some(&[39; 32]))).unwrap();
        assert!(
            review_json
                .as_array()
                .unwrap()
                .iter()
                .all(|field| field["value"].is_string())
        );
        let signed = crypto::sign(&body, &[19; 32]).unwrap();
        let raw = wallet::signed_hex(&signed);
        let decoded = wallet::decode_signed(&raw).unwrap();
        assert_eq!(decoded, signed);
        assert_eq!(
            codec::transaction_id(&decoded),
            codec::transaction_id(&signed)
        );
        assert!(crypto::sign(&body, &[20; 32]).is_err());
        // Mutate every byte of the signed body across all operation variants.
        // Each changed record must fail parsing, canonicality, or authorization.
        let encoded = codec::encode(&signed);
        for offset in 0..codec::encode(&body).len() {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                wallet::decode_signed(&hex::encode(changed)).is_err(),
                "accepted modified body byte {offset}: {:?}",
                body.operation
            );
        }
    }
}

#[test]
fn fee_share_exports_reject_invalid_or_unchanged_percentages() {
    for (old, new) in [(101, 75), (50, 101), (0, 0), (50, 50), (100, 100)] {
        let invalid = body(Operation::Propose {
            round: 0,
            description: [0; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::MinerFeePercent,
                old,
                new,
            },
            support: 1u32.into(),
        });
        assert!(wallet::decode_unsigned(&wallet::unsigned(&invalid, &[39; 32])).is_err());
        let transaction = crypto::sign(&invalid, &[19; 32]).unwrap();
        assert!(wallet::decode_signed(&wallet::signed_hex(&transaction)).is_err());
    }
}

fn ordinary() -> TransactionBody {
    body(Operation::Deposit {
        amount: 17u32.into(),

        decision: None,
        outcome: None,
    })
}

#[test]
fn signed_exports_reject_modified_fields_and_signatures() {
    let original = crypto::sign(&ordinary(), &[19; 32]).unwrap();
    let mut changed = Vec::new();
    let mut tx = original.clone();
    tx.body.sender = crypto::public_key(&[20; 32]).unwrap();
    changed.push(tx);
    let mut tx = original.clone();
    tx.body.nonce -= 1;
    changed.push(tx);
    let mut tx = original.clone();
    tx.body.expiry_blocks -= 1;
    changed.push(tx);
    let mut tx = original.clone();
    tx.body.anchor[0] ^= 1;
    changed.push(tx);
    let mut tx = original.clone();
    tx.body.fee -= 1u32;
    changed.push(tx);
    let mut tx = original.clone();
    let mut operation = tx.body.operation.clone();
    if let Operation::Deposit { amount, .. } = &mut operation {
        *amount += 1u32
    };
    tx.body.operation = operation;
    changed.push(tx);
    let mut tx = original.clone();
    let mut operation = tx.body.operation.clone();
    if let Operation::Deposit {
        decision, outcome, ..
    } = &mut operation
    {
        *decision = Some([1; 32]);
        *outcome = Some(Outcome::Pass)
    };
    tx.body.operation = operation;
    changed.push(tx);
    let mut tx = original.clone();
    tx.signature[31] ^= 1;
    changed.push(tx);
    let bytes = codec::encode(&original);
    assert!(wallet::decode_signed(&hex::encode(&bytes[..bytes.len() - 1])).is_err());
    assert!(wallet::decode_signed(&(hex::encode(&bytes) + "00")).is_err());
    for transaction in changed {
        assert!(wallet::decode_signed(&wallet::signed_hex(&transaction)).is_err());
    }
    let conditional = body(Operation::Redeem {
        shares: 17u32.into(),

        decision: Some([7; 32]),
        outcome: Some(Outcome::Pass),
    });
    let mut signed = crypto::sign(&conditional, &[19; 32]).unwrap();
    let mut operation = signed.body.operation.clone();
    if let Operation::Redeem { outcome, .. } = &mut operation {
        *outcome = Some(Outcome::Fail)
    }
    signed.body.operation = operation;
    assert!(wallet::decode_signed(&wallet::signed_hex(&signed)).is_err());
}

#[test]
fn malformed_envelopes_and_noncanonical_bytes_are_rejected() {
    let envelope = wallet::unsigned(&ordinary(), &[39; 32]);
    let mut value = serde_json::to_value(&envelope).unwrap();
    value["summary"] = json!("Trust this unrelated summary");
    assert!(serde_json::from_value::<UnsignedEnvelope>(value).is_err());
    for format in ["", "hashstash-unsigned-v2", "hashstash-signed-v1"] {
        let mut changed = envelope.clone();
        changed.format = format.into();
        assert!(wallet::decode_unsigned(&changed).is_err());
    }
    assert!(
        serde_json::from_str::<UnsignedEnvelope>(
            r#"{"format":"hashstash-unsigned-anchor","format":"hashstash-unsigned-anchor","chain_id":"2727272727272727272727272727272727272727272727272727272727272727","body":"00"}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<UnsignedEnvelope>(json!({"format":wallet::UNSIGNED_FORMAT}))
            .is_err()
    );
    let mut body = ordinary();
    body.fee = 1u32.into();
    let original = codec::encode(&body);
    let fee_offset = body.sender.len() + codec::encode(&body.nonce).len();
    assert_eq!(original[fee_offset], 1);
    let mut malicious_length = original.clone();
    malicious_length.splice(
        fee_offset..fee_offset + 1,
        [vec![253], u64::MAX.to_le_bytes().to_vec()].concat(),
    );
    let mut nonminimal_amount = original.clone();
    nonminimal_amount[fee_offset] = 2;
    nonminimal_amount.insert(fee_offset + 2, 0);
    let mut trailing = original.clone();
    trailing.push(0);
    let mut truncated = original;
    truncated.pop();
    for bytes in [malicious_length, nonminimal_amount, trailing, truncated] {
        let changed = UnsignedEnvelope {
            format: wallet::UNSIGNED_FORMAT.into(),
            chain_id: hex::encode([39; 32]),
            body: hex::encode(bytes),
        };
        assert!(wallet::decode_unsigned(&changed).is_err());
    }
    for invalid in ["".to_string(), "0".into(), "zz".into(), "0x01".into()] {
        let changed = UnsignedEnvelope {
            format: wallet::UNSIGNED_FORMAT.into(),
            chain_id: hex::encode([39; 32]),
            body: invalid.clone(),
        };
        assert!(wallet::decode_unsigned(&changed).is_err());
        assert!(wallet::decode_signed(&invalid).is_err());
    }
    let signed = crypto::sign(&body, &[19; 32]).unwrap();
    let bytes = codec::encode(&signed);
    let signature_offset = codec::encode(&body).len();
    assert_eq!(bytes.len() - signature_offset, 64);
    let mut prefixed = bytes.clone();
    prefixed.insert(signature_offset, 64);
    let mut altered = bytes.clone();
    altered[signature_offset] ^= 1;
    for malformed in [
        prefixed,
        altered,
        bytes[..bytes.len() - 1].to_vec(),
        [bytes, vec![0]].concat(),
    ] {
        assert!(wallet::decode_signed(&hex::encode(malformed)).is_err());
    }
}

#[test]
fn invalid_sender_recipient_limits_and_conditional_contexts_are_rejected() {
    let mut cases = Vec::new();
    let mut b = ordinary();
    b.sender = [255; 32];
    cases.push(b);
    let mut b = ordinary();
    b.nonce = u64::MAX;
    cases.push(b);
    let mut b = ordinary();
    b.expiry_blocks = 0;
    cases.push(b);
    let mut b = ordinary();
    b.fee = Amount::from(1u32) << 512usize;
    cases.push(b);
    cases.push(body(Operation::TransferExact {
        recipient: [255; 32],
        amount: 1u32.into(),
    }));
    cases.push(body(Operation::Propose {
        round: 0,
        description: [0; 32],
        proposal: Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: [255; 32],
                amount: 1u32.into(),
            }],
        },
        support: 0u32.into(),
    }));
    let large = Amount::from(1u32) << 512usize;
    cases.push(body(Operation::TransferExact {
        recipient: crypto::public_key(&[20; 32]).unwrap(),
        amount: large.clone(),
    }));
    cases.push(body(Operation::Redeem {
        shares: large.clone(),

        decision: None,
        outcome: None,
    }));
    cases.push(body(Operation::Deposit {
        amount: large.clone(),
        decision: None,
        outcome: None,
    }));
    for (decision, outcome) in [(None, Some(Outcome::Pass)), (Some([7; 32]), None)] {
        cases.push(body(Operation::Deposit {
            amount: 1u32.into(),

            decision,
            outcome,
        }));
        cases.push(body(Operation::Redeem {
            shares: 1u32.into(),

            decision,
            outcome,
        }));
    }
    for body in cases {
        assert!(
            wallet::decode_unsigned(&wallet::unsigned(&body, &[39; 32])).is_err(),
            "accepted invalid body: {body:?}"
        );
    }
}

#[test]
fn current_wallet_formats_reject_removed_operation_tags() {
    let current = ordinary();
    let raw = codec::encode(&current);
    let offset =
        raw.len() - codec::encode(&current.operation).len() - codec::encode(&current.data).len();
    for tag in [6, 7, 8, 255] {
        let mut invalid = raw.clone();
        invalid[offset] = tag;
        let mut envelope = wallet::unsigned(&current, &[39; 32]);
        envelope.body = hex::encode(invalid);
        assert!(wallet::decode_unsigned(&envelope).is_err());
    }
}

#[test]
fn offline_wallet_round_trips_transactions_larger_than_the_initial_block() {
    let operation = ordinary().operation.clone();
    let with_payload = |size| {
        let mut value = body(operation.clone());
        value.data = vec![1; size];
        value
    };
    let payload = 64 * 1024;
    let largest = with_payload(payload);
    assert!(codec::encode(&largest).len() > 16_384);
    assert_eq!(
        wallet::decode_unsigned(&wallet::unsigned(&largest, &[39; 32])).unwrap(),
        largest
    );
    let signed = crypto::sign(&largest, &[19; 32]).unwrap();
    assert_eq!(
        codec::encode(&signed).len(),
        codec::encode(&largest).len() + 64
    );
    assert_eq!(
        wallet::decode_signed(&wallet::signed_hex(&signed)).unwrap(),
        signed
    );
}
