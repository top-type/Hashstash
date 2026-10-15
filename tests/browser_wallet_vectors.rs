//! Cross-language browser signing regression. Requires Node.js on PATH (or
//! HASHSTASH_NODE); no server, funded wallets or external network are involved.
use hashstash::{
    codec,
    config::PROTOCOL_VERSION,
    crypto,
    types::{Amount, Operation, Outcome, Parameter, Proposal, TransactionBody},
    wallet,
};
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn string_u64_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "round" | "old" | "new") && value.is_u64() {
                    *value = Value::String(value.as_u64().unwrap().to_string());
                } else {
                    string_u64_fields(value);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(string_u64_fields),
        _ => {}
    }
}

#[test]
fn browser_signatures_verify_in_rust_for_every_current_operation() {
    let secret = [19; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    let maximum = (Amount::from(1u32) << 512usize) - 1u32;
    let large = (Amount::from(1u32) << 127usize) + 65_537u32;
    let operations = vec![
        Operation::TransferExact {
            recipient,
            amount: large.clone(),
        },
        Operation::Deposit {
            amount: maximum.clone(),
            min_shares: large.clone(),
            decision: None,
            outcome: None,
        },
        Operation::Deposit {
            amount: large.clone(),
            min_shares: 0u32.into(),
            decision: Some([51; 32]),
            outcome: Some(Outcome::Pass),
        },
        Operation::Redeem {
            shares: maximum.clone(),
            min_received: large.clone(),
            decision: Some([52; 32]),
            outcome: Some(Outcome::Fail),
        },
        Operation::Redeem {
            shares: large.clone(),
            min_received: 0u32.into(),
            decision: None,
            outcome: None,
        },
        Operation::Propose {
            round: u64::MAX,
            description: [56; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient,
                    amount: maximum.clone(),
                }],
            },
            support: large.clone(),
        },
        Operation::Support {
            round: u64::MAX,
            proposal: [57; 32],
            amount: large.clone(),
        },
        Operation::Refund {
            round: u64::MAX,
            proposal: [58; 32],
        },
    ];
    let mut rows = Vec::new();
    let mut bodies = Vec::new();
    let mut add = |operation: Operation, version: u64, data: Vec<u8>| {
        let mut operation_json = serde_json::to_value(&operation).unwrap();
        string_u64_fields(&mut operation_json);
        let body = TransactionBody {
            chain_id: [39; 32],
            sender,
            nonce: u64::MAX - 1,
            fee: maximum.clone(),
            expiry_height: u64::MAX,
            operation,
            data: data.clone(),
        };
        let unsigned = wallet::unsigned(&body);
        assert_eq!(wallet::decode_unsigned(&unsigned).unwrap(), body);
        let mut expected = json!({
            "chain_id":hex::encode(body.chain_id), "sender":hex::encode(sender),
            "nonce":body.nonce.to_string(), "expiry_height":body.expiry_height.to_string(),
            "protocol_version":version, "operation":operation_json, "data_hex":hex::encode(data)
        });
        expected["fee"] = json!(body.fee.to_str_radix(10));
        rows.push(json!({"secret":hex::encode(secret),"envelope":unsigned,"expected":expected}));
        bodies.push(body);
    };
    for operation in operations {
        add(operation.clone(), u64::from(PROTOCOL_VERSION), Vec::new());
        add(
            operation,
            u64::from(PROTOCOL_VERSION),
            (0..=255).cycle().take(3000).collect(),
        );
    }
    for parameter in [
        Parameter::BlockBytes,
        Parameter::Interval,
        Parameter::Lead,
        Parameter::Rest,
        Parameter::Duration,
        Parameter::MinerFeePercent,
        Parameter::PassMarginBps,
    ] {
        let (old, new) = match parameter {
            Parameter::MinerFeePercent => (50, 51),
            Parameter::Interval => (15, 17),
            _ => (u64::MAX / 2, u64::MAX - 1),
        };
        add(
            Operation::Propose {
                round: u64::MAX,
                description: [59; 32],
                proposal: Proposal::Parameter {
                    parameter,
                    old,
                    new,
                },
                support: large.clone(),
            },
            u64::from(PROTOCOL_VERSION),
            Vec::new(),
        );
    }
    let executable = std::env::var_os("HASHSTASH_NODE").unwrap_or_else(|| "node".into());
    let mut child = Command::new(executable)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["scripts/test_browser_wallet.cjs", "--rust-vectors"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("browser wallet cross-language tests require Node.js (or HASHSTASH_NODE)");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&rows).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "browser signing failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: Vec<Value> = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(signed.len(), bodies.len());
    assert_eq!(signed.len(), 23);
    for (index, (signed, expected)) in signed.iter().zip(&bodies).enumerate() {
        let tx = wallet::decode_signed(signed["raw"].as_str().unwrap()).unwrap();
        assert_eq!(&tx.body, expected, "case {index}");
        assert_eq!(
            signed["transaction_id"],
            hex::encode(codec::transaction_id(&tx)),
            "case {index}"
        );
        crypto::verify(&tx).unwrap();
        let mut changed = tx.clone();
        changed.body.fee += 1u32;
        assert!(
            crypto::verify(&changed).is_err(),
            "fee tampering accepted in case {index}"
        );
    }
}
