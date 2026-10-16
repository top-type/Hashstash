use hashstash::{
    codec,
    types::{GrantPayment, Operation, Parameter, Proposal, Transaction, TransactionBody},
};

#[test]
fn canonical_transaction_matches_independent_fixed_bytes() {
    let tx = Transaction {
        body: TransactionBody {
            data: Vec::new(),
            sender: [2; 32],
            nonce: 42,
            fee: 258u32.into(),
            anchor: [3; 32],
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: [5; 32],
                amount: 65_537u32.into(),
            },
        },
        signature: [4; 64],
    };
    // Authored from the documented field layout using independent little-endian packing.
    let expected = hex::decode(include_str!("data/transaction-current.hex").trim()).unwrap();
    assert_eq!(codec::encode(&tx), expected);
    assert_eq!(
        codec::decode::<Transaction>(&expected, expected.len()).unwrap(),
        tx
    );
    assert_eq!(
        hex::encode(codec::transaction_id(&tx)),
        include_str!("data/transaction-current.sha256d").trim()
    );
    // Governance enum tags are stable, with the fixed minimum fee appended.
    let proposal = Proposal::Parameter {
        parameter: Parameter::PassMarginBps,
        old: 1,
        new: 2,
    };
    assert_eq!(hex::encode(codec::encode(&proposal)), "01060102");
    let minimum = Proposal::Parameter {
        parameter: Parameter::MinimumFeeRate,
        old: 1,
        new: 2,
    };
    assert_eq!(hex::encode(codec::encode(&minimum)), "01070102");
}

#[test]
fn anchor_only_transfer_saves_exactly_one_hash_and_rejects_legacy_records() {
    let tx = Transaction {
        body: TransactionBody {
            sender: [2; 32],
            nonce: 0,
            fee: 1u32.into(),
            anchor: [3; 32],
            expiry_blocks: 2,
            operation: Operation::TransferExact {
                recipient: [5; 32],
                amount: 1000u32.into(),
            },
            data: vec![],
        },
        signature: [4; 64],
    };
    let compact = codec::encode(&tx);
    assert_eq!(compact.len(), 169);
    assert_eq!(codec::encode(&tx.body).len(), 105);
    // The previous record's leading chain hash occupied exactly 32 bytes.
    let legacy = [vec![1; 32], compact.clone()].concat();
    assert_eq!(legacy.len(), 201);
    assert!(codec::decode::<Transaction>(&legacy, legacy.len()).is_err());
    assert_eq!(
        codec::decode::<Transaction>(&compact, compact.len()).unwrap(),
        tx
    );

    // JSON schemas reject the removed field rather than silently ignoring it.
    let mut legacy_json = serde_json::to_value(&tx).unwrap();
    legacy_json["body"]["chain_id"] = serde_json::to_value([1u8; 32]).unwrap();
    assert!(serde_json::from_value::<Transaction>(legacy_json).is_err());
}

#[test]
fn multi_grant_matches_independent_count_and_amount_bytes() {
    // The public keys are the secp256k1 generator and its double, in key order.
    // The fixture is hand-packed tag 0, count 2, key, compact magnitude, key,
    // compact magnitude: 258 = 02 01 and 65537 = 01 00 01 little-endian.
    let proposal = Proposal::Grant {
        payments: vec![
            GrantPayment {
                recipient: hex::decode(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                amount: 258u32.into(),
            },
            GrantPayment {
                recipient: hex::decode(
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                )
                .unwrap()
                .try_into()
                .unwrap(),
                amount: 65_537u32.into(),
            },
        ],
    };
    assert_eq!(proposal.grant_total().unwrap(), 65_795u32.into());
    let expected = hex::decode(include_str!("data/grant-current.hex").trim()).unwrap();
    assert_eq!(codec::encode(&proposal), expected);
    assert_eq!(
        codec::decode::<Proposal>(&expected, expected.len()).unwrap(),
        proposal
    );
}
