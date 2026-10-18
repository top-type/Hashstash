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
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    let local: Value = client
        .get(format!("{private}/api/session"))
        .header("X-Hashstash-Token", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(local["public_key"], hex::encode(server_key));
    assert_eq!(local["public_web"], false);
    assert!(local.get("token").is_none());
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
    // The private token opens no wallet listing on the public listener.
    let presented: Value = client
        .get(format!("{public}/api/session"))
        .header("X-Hashstash-Token", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(presented, exposed);
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
                .header("X-Hashstash-Token", &token)
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
        .header("X-Hashstash-Token", &token)
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
    let chain_id = wallet::unsigned_chain(&unsigned).unwrap();
    let mut signed = crypto::sign(&chain_id, &body, &secret).unwrap();
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
    let signed = crypto::sign(&chain_id, &body, &secret).unwrap();
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
    // A pending record's minimum fee is a current quote, never a recorded charge.
    let txid = hex::encode(codec::transaction_id(&signed));
    let until = std::time::Instant::now() + Duration::from_secs(10);
    let pending = loop {
        let result = node.rpc("explorer_transaction", json!({"txid":txid}));
        match result {
            Err(error)
                if error.to_string().contains("index is updating")
                    && std::time::Instant::now() < until =>
            {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
            result => break result.unwrap(),
        }
    };
    assert_eq!(pending["transaction"]["status"], "pending");
    assert_eq!(pending["transaction"]["fee_estimated"], true);
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

/// A grant-payments list of `units` elements under an operation.
fn payments(units: usize) -> Value {
    json!({"operation":{"Propose":{"proposal":{"Grant":{"payments":vec![0; units]}}}}})
}
/// Visitor-chosen cost: a method that decodes an operation pays one work unit
/// per grant payment, before it checks its parameters.
fn priced_quote(units: usize) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"fee_quote","params":payments(units)})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_named_visitors_cannot_spend_the_shared_public_budget() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[110; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let rpc = format!("{public}/rpc");
    let client = reqwest::Client::new();
    let send = |visitor: &'static str, body: Value| {
        client
            .post(&rpc)
            .header("X-Real-IP", visitor)
            .json(&body)
            .send()
    };
    // Each request costs about half of one visitor's eighth of the shared
    // 1,048,576-unit work burst, so the third is refused for that visitor.
    let expensive = priced_quote(65_000);
    for _ in 0..2 {
        let response = send("192.0.2.10", expensive.clone()).await.unwrap();
        assert_eq!(response.status(), 200);
    }
    // Refused, not dropped: the visitor learns when its share has refilled.
    let refused = send("192.0.2.10", expensive.clone()).await.unwrap();
    assert_eq!(refused.status(), 429);
    let wait: u64 = refused.headers()["Retry-After"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=8).contains(&wait), "{wait}");
    let refused: Value = refused.json().await.unwrap();
    assert_eq!(refused["id"], 1);
    assert_eq!(refused["error"]["message"], "network rate budget exhausted");
    // Another visitor, and unnamed local tools, keep the shared budget. The
    // quote itself runs and fails: the public listener needs its sender.
    let response = send("192.0.2.11", expensive).await.unwrap();
    assert_eq!(response.status(), 200);
    let reply: Value = response.json().await.unwrap();
    assert_ne!(reply["error"]["message"], "network rate budget exhausted");
    let response = request(&client, &public, "status", json!({})).await;
    assert_eq!(response.status(), 200);
    let invalid = send("not-an-address", json!({})).await.unwrap();
    assert_eq!(invalid.status(), 400);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_named_visitors_are_cooled_down_for_their_own_framing_errors() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[111; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let public = format!("http://{}/rpc", server.public_web.unwrap());
    let client = reqwest::Client::new();
    let status = |visitor: Option<&'static str>| {
        let mut post = client
            .post(&public)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}}));
        if let Some(visitor) = visitor {
            post = post.header("X-Real-IP", visitor);
        }
        post.send()
    };
    // Three spaced violations raise the visitor's cooldown to one second.
    for wait in [300, 600, 0] {
        let response = client
            .post(&public)
            .header("X-Real-IP", "198.51.100.20")
            .header("Content-Type", "text/plain")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
    let cooled = status(Some("198.51.100.20")).await.unwrap();
    assert_eq!(cooled.status(), 429);
    assert!(cooled.headers().contains_key("Retry-After"));
    assert_eq!(
        cooled.json::<Value>().await.unwrap()["error"]["message"],
        "temporary network cooldown"
    );
    for visitor in [Some("198.51.100.21"), None] {
        assert_eq!(status(visitor).await.unwrap().status(), 200);
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_request_heads_have_a_short_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[112; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let mut stream = TcpStream::connect(server.public_web.unwrap())
        .await
        .unwrap();
    stream
        .write_all(b"GET /api/session HTTP/1.1\r\n")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(12),
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response),
    )
    .await
    .expect("an incomplete head is closed before the full request deadline")
    .unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(10));
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    assert!(response.contains("HTTP request timed out"), "{response}");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_mining_status_and_storage_errors_hide_operator_details() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[109; 32]).unwrap();
    let path = directory.path().join("chain.sqlite");
    let node = Node::open(&path, config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let private = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    let local = request(&client, &private, "mining", json!({}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    let bind = local["result"]["stratum"]["bind_address"]
        .as_str()
        .unwrap()
        .to_owned();
    // Without --stratum-advertise the local connect URL is derived from the
    // bind address.
    assert_eq!(
        local["result"]["stratum"]["connect_url"],
        format!("stratum+tcp://{bind}")
    );
    // The public mining panel keeps its workers, but never the operator's
    // Stratum bind interface, including inside a derived connect URL.
    for (method, pointer) in [
        ("mining", "/result/stratum"),
        ("snapshot", "/result/mining/stratum"),
    ] {
        let value = request(&client, &public, method, json!({}))
            .await
            .json::<Value>()
            .await
            .unwrap();
        let stratum = value.pointer(pointer).unwrap();
        assert!(stratum.get("bind_address").is_none(), "{method}");
        assert!(stratum.get("loopback_only").is_none(), "{method}");
        assert!(stratum["connect_url"].is_null(), "{method}");
        assert_eq!(stratum["password_required"], false);
        assert!(!value.to_string().contains(&bind), "{method}");
    }
    // An unopenable derived index reports a generic public error; the local
    // listener and the operator's log keep the full storage detail.
    std::fs::remove_file(path.with_extension("explorer.sqlite")).unwrap();
    let hidden = request(&client, &public, "explorer_blocks", json!({}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        hidden["error"]["message"],
        "node storage is temporarily unavailable"
    );
    assert!(
        !hidden
            .to_string()
            .contains(directory.path().to_str().unwrap())
    );
    let detailed = request(&client, &private, "explorer_blocks", json!({}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert!(
        detailed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("explorer.sqlite"),
        "{detailed}"
    );
    server.stop().await;
    // An explicitly advertised endpoint is meant for miners and stays public.
    let node = Node::open(&directory.path().join("advertised.sqlite"), config(), key).unwrap();
    let server = node::serve(
        node,
        ServerOptions {
            stratum_advertise: Some("pool.example.net:3333".into()),
            ..options()
        },
    )
    .await
    .unwrap();
    let public = format!("http://{}", server.public_web.unwrap());
    let value = request(&client, &public, "mining", json!({}))
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(
        value["result"]["stratum"]["connect_url"],
        "stratum+tcp://pool.example.net:3333"
    );
    assert!(value["result"]["stratum"].get("bind_address").is_none());
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn garbage_lists_cost_only_their_bytes_and_wallet_calls_outlast_an_explorer_flood() {
    let directory = tempfile::tempdir().unwrap();
    let key = crypto::public_key(&[113; 32]).unwrap();
    let node = Node::open(&directory.path().join("chain.sqlite"), config(), key).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let rpc = format!("http://{}/rpc", server.public_web.unwrap());
    let client = reqwest::Client::new();
    let call = |visitor: String, method: &'static str, params: Value| {
        client
            .post(&rpc)
            .header("X-Real-IP", visitor)
            .json(&json!({"jsonrpc":"2.0","id":3,"method":method,"params":params}))
            .send()
    };
    // A method that never decodes an operation ignores a grant-payments
    // list: a 75,000-element one used to cost about 75,000 units, so a
    // visitor's share admitted one such status poll; now each costs 8.
    for _ in 0..10 {
        let response = call("198.51.100.7".into(), "status", payments(75_000))
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<Value>().await.unwrap()["result"]["height"],
            0
        );
    }
    // Sixteen visitors from sixteen networks read explorer accounts at once,
    // 4,160 units each, until each is refused.
    let account = json!({"account":hex::encode(key)});
    let floods: Vec<_> = (1..=16u8)
        .map(|n| {
            let (client, rpc, account) = (client.clone(), rpc.clone(), account.clone());
            tokio::spawn(async move {
                let read = json!({
                    "jsonrpc":"2.0","id":4,"method":"explorer_account","params":account
                });
                let mut admitted = 0;
                loop {
                    let response = client
                        .post(&rpc)
                        .header("X-Real-IP", format!("203.0.{n}.1"))
                        .json(&read)
                        .send()
                        .await
                        .unwrap();
                    match response.status().as_u16() {
                        200 => admitted += 1,
                        429 => break admitted,
                        status => panic!("visitor {n}: status {status}"),
                    }
                    assert!(admitted < 64, "visitor {n} was never refused");
                }
            })
        })
        .collect();
    let mut admitted = 0;
    for flood in floods {
        admitted += flood.await.unwrap();
    }
    // They spent the shared budget outside the wallet reserve: about 189
    // such reads, and what refilled meanwhile.
    assert!(admitted >= 180, "{admitted}");
    // A seventeenth visitor's quote for a large grant costs far more than
    // refills meanwhile, but it runs from the reserve, as do its wallet poll
    // and broadcast. Each then fails for its content.
    let late = || "203.0.17.1".to_string();
    let quote = call(late(), "fee_quote", payments(50_000)).await.unwrap();
    assert_eq!(quote.status(), 200);
    let reply: Value = quote.json().await.unwrap();
    assert!(reply["error"]["message"].is_string(), "{reply}");
    assert_ne!(reply["error"]["message"], "network rate budget exhausted");
    let snapshot = call(late(), "snapshot", json!({})).await.unwrap();
    assert_eq!(snapshot.status(), 200);
    assert!(snapshot.json::<Value>().await.unwrap()["result"].is_object());
    let broadcast = call(late(), "broadcasttransaction", json!({"raw":"00"}))
        .await
        .unwrap();
    assert_eq!(broadcast.status(), 200);
    let reply: Value = broadcast.json().await.unwrap();
    assert!(reply["error"]["message"].is_string(), "{reply}");
    assert_ne!(reply["error"]["message"], "network rate budget exhausted");
    server.stop().await;
}
