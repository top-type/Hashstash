//! Exercise signed opaque data through wallet RPC, HTTP signing, peer relay, and disk replay.
use hashstash::{
    codec,
    config::Config,
    crypto, fees,
    node::{self, Node, ServerOptions},
    types::{Block, Operation, PublicKey, Transaction, TransactionBody},
    wallet,
};
use serde_json::{Value, json};

const SECRET: [u8; 32] = [91; 32];

fn config() -> Config {
    Config::testnet()
}

fn sender() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn recipient() -> PublicKey {
    crypto::public_key(&[92; 32]).unwrap()
}
fn operation() -> Operation {
    Operation::TransferExact {
        recipient: recipient(),
        amount: 5u32.into(),
    }
}
fn request() -> Value {
    json!({"sender":hex::encode(sender()),"operation":operation(),"extra_fee":"1","expiry_blocks":20})
}
fn transfer_request() -> Value {
    let mut request = request();
    request.as_object_mut().unwrap().remove("operation");
    request["recipient"] = json!(hex::encode(recipient()));
    request["amount"] = json!("5");
    request
}
fn unsigned(mut package: Value) -> TransactionBody {
    package.as_object_mut().unwrap().remove("fee_quote");
    wallet::decode_unsigned(&serde_json::from_value(package).unwrap()).unwrap()
}
fn fund(node: &Node) {
    for _ in 0..10 {
        node.mine(1_000_000).unwrap();
    }
}

#[test]
fn quotes_charge_for_all_data_and_offline_exports_sign_the_quoted_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(&directory.path().join("node.sqlite"), config(), sender()).unwrap();
    fund(&node);
    let before = node.status().unwrap();
    let plain = unsigned(node.rpc("preparetransaction", request()).unwrap());
    let data: Vec<u8> = (0..=255).collect();
    let mut request = request();
    request["data_hex"] = json!(hex::encode_upper(&data));
    let quote = node.rpc("fee_quote", request.clone()).unwrap();
    let mut transfer = transfer_request();
    transfer["data_hex"] = request["data_hex"].clone();
    let transfer = node.rpc("transfer_quote", transfer).unwrap();
    let package = node.rpc("preparetransaction", request).unwrap();
    assert_eq!(quote["data_hex"], hex::encode(&data));
    assert_eq!(quote["data_bytes"], 256);
    for name in [
        "weight",
        "fee",
        "minimum_fee",
        "fee",
        "data_hex",
        "data_bytes",
    ] {
        assert_eq!(quote[name], transfer[name], "{name}");
        assert_eq!(quote[name], package["fee_quote"][name], "{name}");
    }
    let body = unsigned(package);
    assert_eq!(body.data, data);
    assert_eq!(body.operation.clone(), operation());
    let tx = crypto::sign(&config().chain_id(), &body, &SECRET).unwrap();
    let plain = crypto::sign(&config().chain_id(), &plain, &SECRET).unwrap();
    assert_eq!(
        codec::encode(&tx).len() - codec::encode(&plain).len(),
        data.len() + 2
    );
    let weight = codec::encode(&tx).len() as u64 + fees::ACCOUNT_WEIGHT;
    assert_eq!(quote["weight"], weight.to_string());
    assert_eq!(
        quote["minimum_fee"],
        weight.div_ceil(fees::FEE_SCALE).to_string()
    );
    let raw = wallet::signed_hex(&tx);
    assert_eq!(
        wallet::decode_signed(&raw, &config().chain_id()).unwrap(),
        tx
    );
    assert_eq!(
        node.status().unwrap(),
        before,
        "quoting and preparing do not reserve funds or nonces"
    );
    node.rpc("broadcasttransaction", json!({"raw":raw}))
        .unwrap();
    let block = node.mine(1_000_000).unwrap();
    assert!(block.transactions.contains(&tx));
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient())}))
            .unwrap()["account"]["ordinary"],
        "5"
    );
}

#[test]
fn rpc_rejects_malformed_oversized_data_and_preencoded_envelopes() {
    let directory = tempfile::tempdir().unwrap();
    let config = config();
    let node = Node::open(
        &directory.path().join("node.sqlite"),
        config.clone(),
        sender(),
    )
    .unwrap();
    fund(&node);
    let before = node.status().unwrap();
    for data in [
        json!("0"),
        json!("zz"),
        json!("0x00"),
        json!("00 ff"),
        json!("00\n"),
        json!("ff".repeat(config.transaction_bytes(&config.initial) + 1)),
        json!("ff".repeat(config.transaction_bytes(&config.initial))),
        json!([0, 255]),
        json!(1),
    ] {
        for method in ["preparetransaction", "fee_quote", "transfer_quote"] {
            let mut request = if method == "transfer_quote" {
                transfer_request()
            } else {
                request()
            };
            request["data_hex"] = data.clone();
            assert!(
                node.rpc(method, request).is_err(),
                "{method} accepted invalid/oversized data"
            );
        }
    }
    for operation in [
        json!({"FeeMarket":{"priority_fee":"0","operation":[0]}}),
        json!({"FeeMarketData":{"priority_fee":"0","operation":[0],"data":[1]}}),
    ] {
        for method in ["preparetransaction", "fee_quote"] {
            let mut request = request();
            request["operation"] = operation.clone();
            request["data_hex"] = json!("00");
            assert!(
                node.rpc(method, request).is_err(),
                "removed operation accepted"
            );
        }
    }
    assert_eq!(node.status().unwrap(), before);
}

#[test]
fn empty_data_has_one_canonical_encoding() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(&directory.path().join("node.sqlite"), config(), sender()).unwrap();
    fund(&node);
    let omitted = node.rpc("preparetransaction", request()).unwrap();
    let mut empty = request();
    empty["data_hex"] = json!("");
    assert_eq!(node.rpc("preparetransaction", empty).unwrap(), omitted);
    let body = unsigned(omitted);
    assert_eq!(body.operation, operation());
    assert!(&body.data.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hot_wallet_data_reaches_peer_mempool_mined_block_and_reopened_database() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node.sqlite");
    let config = config();
    let first = Node::open(&path, config.clone(), sender())
        .unwrap()
        .with_wallet(SECRET)
        .unwrap();
    fund(&first);
    let second = Node::open(
        &directory.path().join("peer.sqlite"),
        config.clone(),
        recipient(),
    )
    .unwrap();
    let server = node::serve(
        first.clone(),
        ServerOptions {
            rpc: "127.0.0.1:0".parse().unwrap(),
            p2p: "127.0.0.1:0".parse().unwrap(),
            stratum: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
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
    let data: Vec<u8> = (0..=255)
        .cycle()
        .take(3000)
        .chain(b"<script>alert('stored only')</script>\0".iter().copied())
        .collect();
    let mut request = request();
    request.as_object_mut().unwrap().remove("sender");
    request["expected_sender"] = json!(hex::encode(sender()));
    request["wallet_revision"] = session["wallet_revision"].clone();
    request["data_hex"] = json!(hex::encode(&data));
    let response = client
        .post(format!("{base}/api/wallet"))
        .header("Origin", &base)
        .header(
            "X-Hashstash-Token",
            std::fs::read_to_string(&server.session_token_file).unwrap(),
        )
        .json(&request)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let accepted: Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{accepted}");
    let pool = first.rpc("mempool", json!({})).unwrap();
    let transaction: Transaction =
        serde_json::from_value(json!({"body":pool[0]["body"],"signature":pool[0]["signature"]}))
            .unwrap();
    crypto::verify(&config.chain_id(), &transaction).unwrap();
    assert_eq!(transaction.body.data, data);
    assert_eq!(
        accepted["transaction_id"],
        hex::encode(codec::transaction_id(&transaction))
    );
    node::sync_peer(&second, server.p2p).await.unwrap();
    let pool = second.rpc("mempool", json!({})).unwrap();
    let relayed: Transaction =
        serde_json::from_value(json!({"body":pool[0]["body"],"signature":pool[0]["signature"]}))
            .unwrap();
    assert_eq!(relayed, transaction);
    let block = second.mine(1_000_000).unwrap();
    assert!(block.transactions.contains(&transaction));
    node::sync_peer(&second, server.p2p).await.unwrap();
    let stored: Block = serde_json::from_value(first.rpc("getblock", json!({})).unwrap()).unwrap();
    assert_eq!(stored, block);
    let expected = first.status().unwrap();
    server.stop().await;
    drop(first);
    let reopened = Node::open(&path, config, sender()).unwrap();
    assert_eq!(reopened.status().unwrap(), expected);
    let stored: Block =
        serde_json::from_value(reopened.rpc("getblock", json!({})).unwrap()).unwrap();
    assert_eq!(stored.transactions, vec![transaction]);
    assert_eq!(stored.transactions[0].body.data, data);
}
