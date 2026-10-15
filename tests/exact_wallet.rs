//! Offline fee authorization must remain exact without access to current chain state.
use hashstash::{
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    types::{Amount, Operation, Outcome, Parameter, Proposal, TransactionBody},
    wallet,
};
use serde_json::json;
use std::collections::BTreeMap;

fn body(operation: Operation) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        chain_id: [39; 32],
        sender: crypto::public_key(&[19; 32]).unwrap(),
        nonce: 7,
        fee: 100u32.into(),
        expiry_height: 50,
        operation,
    }
}

fn transfer() -> Operation {
    Operation::TransferExact {
        recipient: crypto::public_key(&[20; 32]).unwrap(),
        amount: 101u32.into(),
    }
}

fn fields(body: &TransactionBody) -> BTreeMap<String, String> {
    let fields = wallet::review(body);
    let count = fields.len();
    let map: BTreeMap<_, _> = fields.into_iter().map(|f| (f.label, f.value)).collect();
    assert_eq!(
        map.len(),
        count,
        "review fields must not overwrite each other"
    );
    map
}

#[test]
fn offline_review_discloses_exact_fee_for_every_operation() {
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    let operations = vec![
        (transfer(), "Transfer"),
        (
            Operation::Deposit {
                amount: 101u32.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
            "Deposit",
        ),
        (
            Operation::Redeem {
                shares: 101u32.into(),
                min_received: 1u32.into(),
                decision: Some([3; 32]),
                outcome: Some(Outcome::Pass),
            },
            "Redeem",
        ),
        (
            Operation::Deposit {
                amount: 101u32.into(),
                min_shares: 1u32.into(),
                decision: Some([3; 32]),
                outcome: Some(Outcome::Fail),
            },
            "Deposit",
        ),
        (
            Operation::Propose {
                round: 2,
                description: [4; 32],
                proposal: Proposal::Grant {
                    payments: vec![hashstash::types::GrantPayment {
                        recipient,
                        amount: 101u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
            "Propose",
        ),
        (
            Operation::Propose {
                round: 2,
                description: [4; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::Interval,
                    old: 15,
                    new: 30,
                },
                support: 1u32.into(),
            },
            "Propose",
        ),
        (
            Operation::Support {
                round: 2,
                proposal: [4; 32],
                amount: 101u32.into(),
            },
            "Support",
        ),
        (
            Operation::Refund {
                round: 2,
                proposal: [4; 32],
            },
            "Refund",
        ),
    ];
    for (operation, action) in operations {
        let tx = body(operation.clone());
        assert_eq!(wallet::decode_unsigned(&wallet::unsigned(&tx)).unwrap(), tx);
        assert_eq!(tx.operation.clone(), operation);
        let review = fields(&tx);
        assert_eq!(review["Action"], action);
        assert_eq!(review["Fee · HASH"], "100");
        assert!(!review.contains_key("Optional extra · HASH"));
        assert!(!review.contains_key("Maximum fee · HASH"));
        assert!(!review.contains_key("Account creation maximum · HASH"));
        if action == "Transfer" {
            assert_eq!(review["Recipient receives · HASH"], "101");
            assert_eq!(review["Total debit · HASH"], "201");
        }
        let signed = crypto::sign(&tx, &[19; 32]).unwrap();
        assert_eq!(
            wallet::decode_signed(&wallet::signed_hex(&signed)).unwrap(),
            signed
        );
    }
    let maximum = (Amount::from(1u32) << 512usize) - 1u32;
    let mut tx = body(Operation::TransferExact {
        recipient,
        amount: maximum.clone(),
    });
    tx.fee = maximum.clone();
    assert!(wallet::decode_unsigned(&wallet::unsigned(&tx)).is_ok());
    assert_eq!(
        fields(&tx)["Total debit · HASH"],
        (maximum * 2u32).to_string()
    );
}

#[test]
fn offline_exports_reject_invalid_values_and_removed_operation_tags() {
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    // Offline bodies do not carry a protocol number. The signer validates the
    // current parameter's values; network consensus enforces its availability.
    assert!(
        wallet::decode_unsigned(&wallet::unsigned(&body(Operation::Propose {
            round: 2,
            description: [4; 32],
            support: 1u32.into(),
            proposal: Proposal::Parameter {
                parameter: Parameter::MinerFeePercent,
                old: 50,
                new: 37
            },
        })))
        .is_ok()
    );
    for operation in [
        Operation::TransferExact {
            recipient: [255; 32],
            amount: 1u32.into(),
        },
        Operation::TransferExact {
            recipient,
            amount: Amount::from(1u32) << 512usize,
        },
        Operation::Deposit {
            amount: Amount::from(1u32) << 512usize,
            min_shares: 0u32.into(),
            decision: None,
            outcome: None,
        },
        Operation::Deposit {
            amount: 1u32.into(),
            min_shares: 0u32.into(),
            decision: Some([3; 32]),
            outcome: None,
        },
    ] {
        assert!(wallet::decode_unsigned(&wallet::unsigned(&body(operation))).is_err());
    }
    let mut tx = body(transfer());
    tx.fee = 6u32.into();
    assert!(wallet::decode_unsigned(&wallet::unsigned(&tx)).is_ok());
    tx.fee = Amount::from(1u32) << 512usize;
    assert!(wallet::decode_unsigned(&wallet::unsigned(&tx)).is_err());
    tx = body(transfer());
    let canonical = codec::encode(&tx);
    let operation_offset = 32 + 32 + 1 + 2 + 1;
    assert_eq!(canonical[operation_offset], 0);
    for tag in [6, 7, 255] {
        let mut bytes = canonical.clone();
        bytes[operation_offset] = tag;
        let export = serde_json::from_value(
            json!({"format":"hashstash-unsigned-v1","body":hex::encode(bytes)}),
        )
        .unwrap();
        assert!(wallet::decode_unsigned(&export).is_err());
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert!(
        wallet::decode_unsigned(
            &serde_json::from_value(
                json!({"format":"hashstash-unsigned-v1","body":hex::encode(trailing)})
            )
            .unwrap()
        )
        .is_err()
    );
}

#[test]
fn signatures_bind_exact_fee_direct_data_and_operation() {
    let original = crypto::sign(&body(transfer()), &[19; 32]).unwrap();
    let mut cap = original.clone();
    cap.body.fee += 1u32;
    let mut data = original.clone();
    data.body.data = vec![0, 255, 128];
    let mut payload = original.clone();
    let mut changed = transfer();
    if let Operation::TransferExact { amount, .. } = &mut changed {
        *amount += 1u32;
    }
    payload.body.operation = changed;
    for changed in [cap, data, payload] {
        assert!(wallet::decode_signed(&wallet::signed_hex(&changed)).is_err());
    }
    assert!(wallet::decode_signed(&wallet::signed_hex(&original)).is_ok());
}

async fn cli(arguments: Vec<String>) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_hashstash"));
    command.args(arguments).kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x0800_0000);
    tokio::time::timeout(std::time::Duration::from_secs(60), command.output())
        .await
        .expect("fixture CLI exceeded 60 seconds")
        .unwrap()
}

fn successful(output: std::process::Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[tokio::test]
async fn real_cli_watch_only_prepare_offline_sign_broadcast_and_hot_send_use_exact_fees() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [19; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[20; 32]).unwrap();
    let mut config = Config::testnet();
    config.initial.block_bytes = 1_000_000;
    config.initial_bits = 0x1f7fffff;
    config.limit_bits = config.initial_bits;
    config.genesis_time = node::now().saturating_sub(3600) as u32;
    let chain_id = config.chain_id();
    let node = Node::open(&directory.path().join("chain.sqlite"), config, sender)
        .unwrap()
        .with_watch_key(sender)
        .unwrap();
    for _ in 0..10 {
        node.mine(1_000_000).unwrap();
    }
    let server = node::serve(
        node.clone(),
        ServerOptions {
            rpc: "127.0.0.1:0".parse().unwrap(),
            p2p: "127.0.0.1:0".parse().unwrap(),
            stratum: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let url = format!("http://{}/rpc", server.rpc);
    let key = directory.path().join("key.json");
    std::fs::write(
        &key,
        serde_json::to_vec(&json!({"secret":hex::encode(secret),"public":hex::encode(sender)}))
            .unwrap(),
    )
    .unwrap();
    let key = key.to_str().unwrap().to_owned();
    let address = hashstash::address::encode(&recipient, &chain_id).unwrap();
    successful(
        cli(vec![
            "transfer".into(),
            "--url".into(),
            url.clone(),
            "--key".into(),
            key.clone(),
            "--recipient".into(),
            address,
            "--amount".into(),
            "5".into(),
            "--fee".into(),
            "20".into(),
        ])
        .await,
    );
    let pending = node.rpc("mempool", json!({})).unwrap();
    // RPC presentation fields are not part of the canonical transaction schema.
    let tx: hashstash::types::Transaction = serde_json::from_value(json!({
        "body": pending[0]["body"], "signature": pending[0]["signature"]
    }))
    .unwrap();
    assert_eq!(tx.body.fee, 20u32.into());
    assert!(matches!(tx.body.operation, Operation::TransferExact { .. }));
    assert!(tx.body.data.is_empty());
    node.mine(1_000_000).unwrap();
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "5"
    );

    let unsigned = directory.path().join("unsigned.json");
    let donation = serde_json::to_string(&Operation::TransferExact {
        recipient: hashstash::crypto::public_key(&[6; 32]).unwrap(),
        amount: 1u32.into(),
    })
    .unwrap();
    successful(
        cli(vec![
            "prepare".into(),
            "--url".into(),
            url.clone(),
            "--sender".into(),
            hex::encode(sender),
            "--operation".into(),
            donation.clone(),
            "--fee".into(),
            "12".into(),
            "--out".into(),
            unsigned.to_str().unwrap().into(),
        ])
        .await,
    );
    let envelope = serde_json::from_slice(&std::fs::read(unsigned).unwrap()).unwrap();
    let prepared = wallet::decode_unsigned(&envelope).unwrap();
    assert_eq!(prepared.fee, 12u32.into());
    assert!(matches!(
        &prepared.operation,
        Operation::TransferExact { .. }
    ));
    assert!(prepared.data.is_empty());
    let body_path = directory.path().join("body.json");
    let signed_path = directory.path().join("signed.json");
    std::fs::write(&body_path, serde_json::to_vec(&prepared).unwrap()).unwrap();
    successful(
        cli(vec![
            "sign".into(),
            "--key".into(),
            key.clone(),
            "--body".into(),
            body_path.to_str().unwrap().into(),
            "--out".into(),
            signed_path.to_str().unwrap().into(),
        ])
        .await,
    );
    let signed: hashstash::types::Transaction =
        serde_json::from_slice(&std::fs::read(signed_path).unwrap()).unwrap();
    assert_eq!(signed.body, prepared);
    successful(
        cli(vec![
            "broadcast".into(),
            "--url".into(),
            url.clone(),
            "--raw".into(),
            wallet::signed_hex(&signed),
        ])
        .await,
    );

    // The following send must use the pending nonce and the node's exact quote.
    successful(
        cli(vec![
            "send".into(),
            "--url".into(),
            url.clone(),
            "--key".into(),
            key.clone(),
            "--operation".into(),
            donation.clone(),
            "--extra-fee".into(),
            "1".into(),
        ])
        .await,
    );
    let pending = node.rpc("mempool", json!({})).unwrap();
    assert_eq!(pending.as_array().unwrap().len(), 2);
    let nonces: std::collections::BTreeSet<_> = pending
        .as_array()
        .unwrap()
        .iter()
        .map(|tx| tx["body"]["nonce"].as_u64().unwrap())
        .collect();
    assert_eq!(nonces, [1, 2].into_iter().collect());
    node.mine(1_000_000).unwrap();
    assert!(
        node.rpc("mempool", json!({}))
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty()
    );
    let forbidden = cli(vec![
        "send".into(),
        "--url".into(),
        url,
        "--key".into(),
        key,
        "--operation".into(),
        donation,
        "--fee".into(),
        "4".into(),
        "--extra-fee".into(),
        "1".into(),
    ])
    .await;
    assert!(!forbidden.status.success());
    assert!(String::from_utf8_lossy(&forbidden.stderr).contains("--fee"));
    server.stop().await;
}

#[tokio::test]
async fn cli_finds_pending_nonce_beyond_legacy_mempool_size() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [19; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let mut config = Config::testnet();
    config.initial.block_bytes = 1_000_000;
    config.initial_bits = 0x1f7fffff;
    config.limit_bits = config.initial_bits;
    config.genesis_time = node::now().saturating_sub(3600) as u32;
    config.initial_bits = 0x1f7fffff;
    config.limit_bits = config.initial_bits;
    let chain_id = config.chain_id();
    let node = Node::open(&directory.path().join("chain.sqlite"), config, sender).unwrap();
    for _ in 0..3 {
        node.mine(1_000_000).unwrap();
    }
    let operation = Operation::TransferExact {
        recipient: hashstash::crypto::public_key(&[6; 32]).unwrap(),
        amount: 1u32.into(),
    };
    let setup_started = std::time::Instant::now();
    for nonce in 0..260 {
        let body = TransactionBody {
            data: Vec::new(),
            chain_id,
            sender,
            nonce,
            fee: 4u32.into(),
            expiry_height: 100,
            operation: operation.clone(),
        };
        node.submit_transaction(crypto::sign(&body, &secret).unwrap())
            .unwrap();
        assert!(
            setup_started.elapsed() < std::time::Duration::from_secs(120),
            "fixture mempool setup exceeded 120 seconds"
        );
    }
    assert_eq!(node.status().unwrap()["mempool"], 260);
    let server = node::serve(
        node.clone(),
        ServerOptions {
            rpc: "127.0.0.1:0".parse().unwrap(),
            p2p: "127.0.0.1:0".parse().unwrap(),
            stratum: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let key = directory.path().join("key.json");
    std::fs::write(
        &key,
        serde_json::to_vec(&json!({"secret":hex::encode(secret)})).unwrap(),
    )
    .unwrap();
    successful(
        cli(vec![
            "send".into(),
            "--url".into(),
            format!("http://{}/rpc", server.rpc),
            "--key".into(),
            key.to_str().unwrap().into(),
            "--operation".into(),
            serde_json::to_string(&operation).unwrap(),
        ])
        .await,
    );
    assert_eq!(node.status().unwrap()["mempool"], 261);
    let page = node.rpc("mempool", json!({"offset":256})).unwrap();
    assert!(
        page.as_array()
            .unwrap()
            .iter()
            .any(|tx| tx["body"]["nonce"] == 260)
    );
    server.stop().await;
}
