use hashstash::{
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    state,
    types::*,
    wallet,
};
use serde_json::{Value, json};

fn options() -> ServerOptions {
    ServerOptions {
        rpc: "127.0.0.1:0".parse().unwrap(),
        p2p: "127.0.0.1:0".parse().unwrap(),
        stratum: "127.0.0.1:0".parse().unwrap(),
        peers: vec![],
        stratum_password: None,
        ..Default::default()
    }
}

fn prepare(node: &Node, sender: PublicKey, operation: Operation) -> TransactionBody {
    let mut value = node
        .rpc(
            "preparetransaction",
            json!({
                "sender":hex::encode(sender), "operation":operation, "extra_fee":"0"
            }),
        )
        .unwrap();
    assert!(value.as_object_mut().unwrap().remove("fee_quote").is_some());
    assert_eq!(value.as_object().unwrap().len(), 3);
    assert_eq!(value["chain_id"], node.status().unwrap()["chain_id"]);
    wallet::decode_unsigned(&serde_json::from_value::<wallet::UnsignedEnvelope>(value).unwrap())
        .unwrap()
}

/// The network the node reports, which offline signatures must bind.
fn chain_id(node: &Node) -> Hash {
    node::parse_hash(node.status().unwrap()["chain_id"].as_str().unwrap()).unwrap()
}

fn cold_submit(node: &Node, secret: &[u8; 32], operation: Operation) -> Transaction {
    let body = prepare(node, crypto::public_key(secret).unwrap(), operation);
    let tx = crypto::sign(&chain_id(node), &body, secret).unwrap();
    let raw = wallet::signed_hex(&tx);
    assert_eq!(wallet::decode_signed(&raw, &chain_id(node)).unwrap(), tx);
    let result = node
        .rpc("broadcasttransaction", json!({"raw":raw}))
        .unwrap();
    assert_eq!(
        result["transaction_id"],
        hex::encode(codec::transaction_id(&tx))
    );
    tx
}

fn donation() -> Operation {
    Operation::TransferExact {
        recipient: hashstash::crypto::public_key(&[6; 32]).unwrap(),
        amount: 1u32.into(),
    }
}

#[test]
fn preparing_uses_pending_nonces_without_reserving_them() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [61; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let node = Node::open(&dir.path().join("watch.db"), Config::devnet(), sender).unwrap();
    for _ in 0..12 {
        node.mine(100_000).unwrap();
    }
    let before = node.status().unwrap();
    let first = prepare(&node, sender, donation());
    let again = prepare(&node, sender, donation());
    assert_eq!(first, again);
    assert_eq!(first.nonce, 0);
    assert_eq!(first.expiry_blocks, 2);
    assert_eq!(hex::encode(first.anchor), before["tip"]);
    assert_eq!(node.status().unwrap(), before);
    let first = cold_submit(&node, &secret, donation());
    assert_eq!(first.body.nonce, 0);
    let second = prepare(&node, sender, donation());
    assert_eq!(second.nonce, 1);
    assert_eq!(prepare(&node, sender, donation()), second);
    cold_submit(&node, &secret, donation());
    assert_eq!(prepare(&node, sender, donation()).nonce, 2);
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(sender)}))
            .unwrap()["account"]["nonce"],
        0
    );
    node.mine(100_000).unwrap();
    assert_eq!(prepare(&node, sender, donation()).nonce, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watch_only_http_exports_and_broadcasts_but_never_signs() {
    let dir = tempfile::tempdir().unwrap();
    let miner_secret = [62; 32];
    let miner = crypto::public_key(&miner_secret).unwrap();
    let secret = wallet::derive_secret("self chosen watch wallet integration phrase").unwrap();
    let watched = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[63; 32]).unwrap();
    let node = Node::open(&dir.path().join("watch.db"), Config::devnet(), miner)
        .unwrap()
        .with_watch_key(watched)
        .unwrap();
    for _ in 0..12 {
        node.mine(100_000).unwrap();
    }
    cold_submit(
        &node,
        &miner_secret,
        Operation::TransferExact {
            recipient: watched,
            amount: 12u32.into(),
        },
    );
    node.mine(100_000).unwrap();
    let server = node::serve(node.clone(), options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    let session: Value = client
        .get(format!("{base}/api/session"))
        .header(
            "X-Hashstash-Token",
            std::fs::read_to_string(&server.session_token_file).unwrap(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["wallet_mode"], "watch");
    assert_eq!(session["wallet_enabled"], false);
    assert_eq!(session["public_key"], hex::encode(watched));
    assert_eq!(session["miner"], hex::encode(miner));
    let denied = client
        .post(format!("{base}/api/wallet"))
        .header(
            "X-Hashstash-Token",
            std::fs::read_to_string(&server.session_token_file).unwrap(),
        )
        .json(&json!({"operation":donation(),"extra_fee":"0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let package = node::call_rpc(
        &format!("{base}/rpc"),
        "preparetransaction",
        json!({
            "sender":hex::encode(watched),"extra_fee":"1","expiry_blocks":7,
            "operation":Operation::TransferExact {recipient,amount:4u32.into(),}
        }),
    )
    .await
    .unwrap();
    let mut package = package;
    package.as_object_mut().unwrap().remove("fee_quote");
    let body = wallet::decode_unsigned(&serde_json::from_value(package).unwrap()).unwrap();
    assert_eq!(body.sender, watched);
    assert_eq!(body.expiry_blocks, 7);
    let signed = crypto::sign(&chain_id(&node), &body, &secret).unwrap();
    let response = node::call_rpc(
        &format!("{base}/rpc"),
        "broadcasttransaction",
        json!({"raw":wallet::signed_hex(&signed)}),
    )
    .await
    .unwrap();
    assert_eq!(
        response["transaction_id"],
        hex::encode(codec::transaction_id(&signed))
    );
    node.mine(100_000).unwrap();
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(watched)}))
            .unwrap()["account"]["ordinary"],
        "5"
    );
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "4"
    );
    // A bounded raw field can exceed the ordinary 1 KiB JSON-string limit.
    // This reaches wallet validation (unsupported amount), not the JSON parser.
    let large = (Amount::from(1u32) << 1023usize) - 1u32;
    let mut large_body = body;
    large_body.nonce = 1;
    large_body.fee = large.clone();
    large_body.operation = Operation::Propose {
        round: 0,
        description: [1; 32],
        proposal: Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient,
                amount: large.clone(),
            }],
        },
        support: large,
    };
    let raw = wallet::signed_hex(&crypto::sign(&chain_id(&node), &large_body, &secret).unwrap());
    assert!(raw.len() > 1024);
    let rejected = client
        .post(format!("{base}/rpc"))
        .json(&json!({"jsonrpc":"2.0","id":2,"method":"broadcasttransaction","params":{"raw":raw}}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 200);
    assert!(
        rejected
            .json::<Value>()
            .await
            .unwrap()
            .get("error")
            .is_some()
    );
    assert_eq!(node.status().unwrap()["mempool"], 0);
    server.stop().await;
}

#[test]
fn every_operation_uses_the_offline_route_including_governance() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [64; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let mut config = Config::devnet();
    config.initial_bits = 0x2000ffff;
    config.limit_bits = 0x2000ffff;
    let node = Node::open(&dir.path().join("operations.db"), config.clone(), sender).unwrap();
    for _ in 0..100 {
        node.mine(100_000).unwrap();
    }
    cold_submit(
        &node,
        &secret,
        Operation::Deposit {
            amount: 150u32.into(),

            decision: None,
            outcome: None,
        },
    );
    node.mine(100_000).unwrap();
    let account = node
        .rpc("account", json!({"key":hex::encode(sender)}))
        .unwrap();
    let shares = Amount::parse_bytes(
        account["account"]["shares"].as_str().unwrap().as_bytes(),
        10,
    )
    .unwrap()
        / 100u32;
    cold_submit(
        &node,
        &secret,
        Operation::Redeem {
            shares,

            decision: None,
            outcome: None,
        },
    );
    cold_submit(&node, &secret, donation());
    node.mine(100_000).unwrap();
    let round = node.status().unwrap()["auction_round"].as_u64().unwrap();
    let first = Proposal::Parameter {
        parameter: Parameter::Rest,
        old: config.initial.rest,
        new: config.initial.rest / 2,
    };
    let second = Proposal::Parameter {
        parameter: Parameter::Interval,
        old: config.initial.interval,
        new: config.initial.interval * 2,
    };
    let chain_id = node::parse_hash(node.status().unwrap()["chain_id"].as_str().unwrap()).unwrap();
    let proposer = crypto::public_key(&secret).unwrap();
    let second_id = state::proposal_id(&chain_id, round, &proposer, &[2; 32], &second);
    for (description, proposal, support) in [(1, first, 3u32), (2, second, 1u32)] {
        cold_submit(
            &node,
            &secret,
            Operation::Propose {
                round,
                description: [description; 32],
                proposal,
                support: support.into(),
            },
        );
    }
    cold_submit(
        &node,
        &secret,
        Operation::Support {
            round,
            proposal: second_id,
            amount: 1u32.into(),
        },
    );
    node.mine(100_000).unwrap();
    for _ in 0..10 {
        if node.status().unwrap()["phase"] == "governance" {
            break;
        }
        node.mine(100_000).unwrap();
    }
    let decision = node::parse_hash(node.status().unwrap()["decision"].as_str().unwrap()).unwrap();
    cold_submit(
        &node,
        &secret,
        Operation::Deposit {
            amount: 2u32.into(),

            decision: Some(decision),
            outcome: Some(Outcome::Pass),
        },
    );
    node.mine(100_000).unwrap();
    let account = node
        .rpc(
            "account",
            json!({"key":hex::encode(sender),"outcome":"Pass"}),
        )
        .unwrap();
    let shares = Amount::parse_bytes(
        account["account"]["shares"].as_str().unwrap().as_bytes(),
        10,
    )
    .unwrap()
        / 100u32;
    cold_submit(
        &node,
        &secret,
        Operation::Redeem {
            shares,

            decision: Some(decision),
            outcome: Some(Outcome::Pass),
        },
    );
    node.mine(100_000).unwrap();
    for _ in 0..100 {
        let support = node
            .rpc(
                "support",
                json!({"round":round,"proposal":hex::encode(second_id),"key":hex::encode(sender)}),
            )
            .unwrap();
        if support["refundable"] == true {
            break;
        }
        node.mine(100_000).unwrap();
    }
    cold_submit(
        &node,
        &secret,
        Operation::Refund {
            round,
            proposal: second_id,
        },
    );
    node.mine(100_000).unwrap();
    assert_eq!(
        node.rpc(
            "support",
            json!({"round":round,"proposal":hex::encode(second_id),"key":hex::encode(sender)})
        )
        .unwrap()["amount"],
        "0"
    );
    assert_eq!(node.status().unwrap()["mempool"], 0);
}

#[test]
fn raw_broadcast_rejects_wrong_network_expiry_signature_and_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [65; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let node = Node::open(&dir.path().join("reject.db"), Config::devnet(), sender).unwrap();
    for _ in 0..8 {
        node.mine(100_000).unwrap();
    }
    let baseline = node.status().unwrap();
    let body = prepare(&node, sender, donation());
    let chain = chain_id(&node);
    let signed = crypto::sign(&chain, &body, &secret).unwrap();
    let mut other_network = body.clone();
    let mut foreign_config = Config::devnet();
    foreign_config.network.push_str("-foreign");
    other_network.anchor = codec::block_hash(&codec::genesis_block(&foreign_config).unwrap());
    // Unchanged bytes signed for the foreign network's chain ID.
    let foreign_signature = crypto::sign(&foreign_config.chain_id(), &body, &secret).unwrap();
    let mut expired = body.clone();
    expired.anchor = codec::block_hash(&codec::genesis_block(&Config::devnet()).unwrap());
    expired.expiry_blocks = 1;
    let mut altered = signed.clone();
    altered.signature[0] ^= 1;
    let mut appended = wallet::signed_hex(&signed);
    appended.push_str("00");
    for raw in [
        wallet::signed_hex(&crypto::sign(&chain, &other_network, &secret).unwrap()),
        wallet::signed_hex(&foreign_signature),
        wallet::signed_hex(&crypto::sign(&chain, &expired, &secret).unwrap()),
        wallet::signed_hex(&altered),
        appended,
        "g0".into(),
        "0".into(),
        String::new(),
        "00".repeat(32 * 1024 * 1024 + 1),
    ] {
        assert!(
            node.rpc("broadcasttransaction", json!({"raw":raw}))
                .is_err()
        );
        assert_eq!(node.status().unwrap(), baseline);
    }
    for expiry in [0, u64::MAX] {
        assert!(node.rpc("preparetransaction",json!({"sender":hex::encode(sender),"operation":donation(),"extra_fee":"0","expiry_blocks":expiry})).is_err());
    }
    assert!(
        node.rpc(
            "preparetransaction",
            json!({"sender":hex::encode([0;32]),"operation":donation(),"extra_fee":"0"})
        )
        .is_err()
    );
    assert!(node.rpc("preparetransaction",json!({"sender":hex::encode(sender),"operation":donation(),"fee":(Amount::from(1u32)<<513usize).to_string()})).is_err());
    assert!(
        node.rpc(
            "broadcasttransaction",
            json!({"raw":wallet::signed_hex(&signed),"secret":"ignored?"})
        )
        .is_err()
    );
    assert_eq!(node.status().unwrap(), baseline);
}

#[test]
fn exact_transfer_quotes_and_offline_signatures_keep_recipient_credit_exact() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [67; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[69; 32]).unwrap();
    let node = Node::open(&dir.path().join("exact.db"), Config::devnet(), sender).unwrap();
    for _ in 0..12 {
        node.mine(100_000).unwrap();
    }
    let operation = Operation::TransferExact {
        recipient,
        amount: 5u32.into(),
    };
    let body = prepare(&node, sender, operation.clone());
    assert_eq!(body.operation.clone(), operation);
    let mut underpaid = body.clone();
    underpaid.fee = 0u32.into();
    assert!(
        node.rpc(
            "broadcasttransaction",
            json!({"raw":wallet::signed_hex(&crypto::sign(&chain_id(&node),&underpaid,&secret).unwrap())})
        )
        .is_err()
    );
    cold_submit(&node, &secret, operation);
    node.mine(100_000).unwrap();
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "5"
    );
    for operation in [
        Operation::TransferExact {
            recipient: [255; 32],
            amount: 1u32.into(),
        },
        Operation::TransferExact {
            recipient,
            amount: 0u32.into(),
        },
        Operation::TransferExact {
            recipient,
            amount: Amount::from(1u32) << 512usize,
        },
    ] {
        assert!(
            node.rpc(
                "preparetransaction",
                json!({"sender":hex::encode(sender),"operation":operation,"extra_fee":"0"})
            )
            .is_err()
        );
    }
}

#[test]
fn hot_and_watch_startup_modes_are_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [66; 32];
    let public = crypto::public_key(&secret).unwrap();
    let node = Node::open(&dir.path().join("modes.db"), Config::devnet(), public).unwrap();
    assert!(
        node.clone()
            .with_wallet(secret)
            .unwrap()
            .with_watch_key(public)
            .is_err()
    );
    assert!(
        node.clone()
            .with_watch_key(public)
            .unwrap()
            .with_wallet(secret)
            .is_err()
    );
    assert!(node.with_watch_key([0; 32]).is_err());
}
