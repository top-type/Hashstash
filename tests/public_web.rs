//! The public website never acquires the authority of the private node wallet.
use hashstash::{
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    types::Operation,
    wallet,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};

fn options() -> ServerOptions {
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        public_web: Some(zero),
        p2p: zero,
        stratum: zero,
        ..Default::default()
    }
}

fn config() -> Config {
    Config::devnet()
}

async fn request(
    client: &reqwest::Client,
    base: &str,
    method: &str,
    params: Value,
) -> reqwest::Response {
    client
        .post(format!("{base}/rpc"))
        .json(&json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}))
        .send()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_session_and_routes_never_expose_or_control_server_wallet() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[101; 32]).unwrap();
    let server_secret = [102; 32];
    let server_key = crypto::public_key(&server_secret).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), miner)
        .unwrap()
        .with_wallet(server_secret)
        .unwrap();
    let server = node::serve(node.clone(), options()).await.unwrap();
    let private = format!("http://{}", server.rpc);
    let public = format!("http://{}", server.public_web.unwrap());
    let client = reqwest::Client::new();
    let local: Value = client
        .get(format!("{private}/api/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(local["public_key"], hex::encode(server_key));
    assert_eq!(local["public_web"], false);
    let exposed: Value = client
        .get(format!("{public}/api/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(exposed["browser_wallet"], true);
    assert_eq!(exposed["public_web"], true);
    assert_eq!(exposed["chain_id"], node.status().unwrap()["chain_id"]);
    assert_eq!(exposed["miner"], hex::encode(miner));
    assert_eq!(exposed.as_object().unwrap().len(), 5);
    for field in [
        "token",
        "wallets",
        "wallet_id",
        "wallet_revision",
        "public_key",
        "private_key",
        "wallet_enabled",
    ] {
        assert!(exposed.get(field).is_none(), "leaked {field}");
    }
    for path in ["/api/wallet", "/api/wallet/manage"] {
        for action in ["create", "import", "export", "select", "remove"] {
            let response = client.post(format!("{public}{path}"))
                .header("X-Hashstash-Token", local["token"].as_str().unwrap())
                .json(&json!({"action":action,"revision":local["wallet_revision"],"id":local["wallet_id"]}))
                .send().await.unwrap();
            assert_eq!(response.status(), 403, "{path}: {action}");
            let text = response.text().await.unwrap();
            assert!(!text.contains(&hex::encode(server_secret)));
        }
    }
    for method in [
        "mine",
        "template",
        "submitblock",
        "submittransaction",
        "signtransaction",
        "dumpprivkey",
        "wallet",
        "walletmanage",
        "peers",
        "getblock",
        "future_admin_method",
    ] {
        let response = request(&client, &public, method, json!({"count":1})).await;
        assert_eq!(response.status(), 403, "{method}");
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["code"],
            -32601
        );
    }
    let batch = client
        .post(format!("{public}/rpc"))
        .json(&json!([
            {"jsonrpc":"2.0","id":1,"method":"status","params":{}},
            {"jsonrpc":"2.0","id":2,"method":"mine","params":{}}
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(batch.status(), 400);
    assert_eq!(node.status().unwrap()["height"], 0);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    let unchanged: Value = client
        .get(format!("{private}/api/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(unchanged, local);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_wallet_prepares_exact_unsigned_intent_and_broadcasts_only_signed_work() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [103; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[104; 32]).unwrap();
    let server_key = crypto::public_key(&[105; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), sender)
        .unwrap()
        .with_wallet([105; 32])
        .unwrap();
    for _ in 0..20 {
        node.mine(100_000).unwrap();
    }
    let server = node::serve(node.clone(), options()).await.unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let private = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    let private_block = request(&client, &private, "getblock", json!({"height":1}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert!(
        private_block["result"]["header"].is_object(),
        "{private_block}"
    );
    let operation = Operation::TransferExact {
        recipient,
        amount: 5u32.into(),
    };
    let mut params = json!({"operation":operation,"extra_fee":"1","nonce":0,"expiry_blocks":100,"data_hex":"ab".repeat(600)});
    // A public quote must never use the selected server wallet as sender.
    let quote = request(&client, &public, "fee_quote", params.clone())
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert!(quote.get("error").is_some());
    assert!(!quote.to_string().contains(&hex::encode(server_key)));
    let private_quote = request(&client, &private, "fee_quote", params.clone())
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        private_quote["result"]["sender_public_key"],
        hex::encode(server_key),
        "{private_quote}"
    );
    let missing_transfer_sender = request(
        &client,
        &public,
        "transfer_quote",
        json!({"recipient":hex::encode(recipient),"amount":"5"}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert!(missing_transfer_sender.get("error").is_some());
    params["sender"] = json!(hex::encode(sender));
    let quote = request(&client, &public, "fee_quote", params.clone())
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(quote["result"]["sender_public_key"], hex::encode(sender));
    let prepared = request(&client, &public, "preparetransaction", params)
        .await
        .json::<Value>()
        .await
        .unwrap();
    let mut envelope = prepared["result"].clone();
    envelope.as_object_mut().unwrap().remove("fee_quote");
    let unsigned = serde_json::from_value(envelope).unwrap();
    let body = wallet::decode_unsigned(&unsigned).unwrap();
    assert_eq!(body.sender, sender);
    assert_eq!(body.nonce, 0);
    assert_eq!(body.expiry_blocks, 100);
    assert_eq!(body.data, vec![0xab; 600]);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    let mut signed = crypto::sign(&body, &secret).unwrap();
    signed.signature[0] ^= 1;
    let invalid = request(
        &client,
        &public,
        "broadcasttransaction",
        json!({"raw":wallet::signed_hex(&signed)}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert!(invalid.get("error").is_some());
    assert_eq!(node.status().unwrap()["mempool"], 0);
    let signed = crypto::sign(&body, &secret).unwrap();
    let accepted = request(
        &client,
        &public,
        "broadcasttransaction",
        json!({"raw":wallet::signed_hex(&signed)}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(
        accepted["result"]["transaction_id"],
        hex::encode(codec::transaction_id(&signed))
    );
    assert_eq!(node.status().unwrap()["mempool"], 1);
    node.mine(100_000).unwrap();
    let account = request(
        &client,
        &public,
        "account",
        json!({"key":hex::encode(recipient)}),
    )
    .await
    .json::<Value>()
    .await
    .unwrap();
    assert_eq!(account["result"]["account"]["ordinary"], "5");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_proxy_host_is_supported_without_weakening_private_origin_checks() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[106; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let private = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{public}/rpc"))
        .header("Host", "stash.example")
        .header("Origin", "https://stash.example")
        .header("Sec-Fetch-Site", "same-origin")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["height"],
        0
    );
    for (base, origin) in [
        (&public, "https://attacker.invalid"),
        (&private, "https://stash.example"),
    ] {
        let response = client
            .get(format!("{base}/api/session"))
            .header("Host", "stash.example")
            .header("Origin", origin)
            .header("X-Forwarded-Host", "localhost")
            .header("X-Forwarded-Proto", "https")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    for path in [
        "/",
        "/app.js",
        "/style.css",
        "/vendor/noble.js",
        "/browser-wallet.js",
    ] {
        let response = client
            .get(format!("{public}{path}"))
            .header("Host", "stash.example")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["X-Frame-Options"], "DENY");
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_connections_and_malformed_cooldowns_do_not_exhaust_private_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[107; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let private = format!("http://{}", server.rpc);
    let malformed = client
        .post(format!("{public}/rpc"))
        .header("Content-Type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 400);
    // A malformed visitor behind a loopback proxy cannot cooldown every user
    // sharing that proxy address. The normal public budgets still apply.
    assert_eq!(
        client
            .get(format!("{public}/api/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("{private}/api/session"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut held = Vec::new();
    for _ in 0..8 {
        let mut stream = TcpStream::connect(server.public_web.unwrap())
            .await
            .unwrap();
        stream
            .write_all(b"GET /api/session HTTP/1.1\r\n")
            .await
            .unwrap();
        held.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = request(&client, &private, "status", json!({})).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await.unwrap()["result"]["height"],
        0
    );
    drop(held);
    server.stop().await;
}

#[tokio::test]
async fn public_web_is_opt_in_and_admin_rpc_cannot_bind_publicly() {
    assert!(ServerOptions::default().public_web.is_none());
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[108; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let mut bad = options();
    bad.rpc = "0.0.0.0:0".parse().unwrap();
    assert!(
        node::serve(node.clone(), bad)
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("loopback")
    );
    let mut local = options();
    local.public_web = None;
    let server = node::serve(node, local).await.unwrap();
    assert!(server.public_web.is_none());
    server.stop().await;
}
