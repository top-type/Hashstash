//! Local real RPC checks for ordinary transaction text and its canonical history.
use hashstash::{
    address, codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    types::*,
    wallet,
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

const SECRET: [u8; 32] = [109; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn config() -> Config {
    let mut c = Config::devnet();
    c.network = "isolated-chat-rpc-tests".into();
    c.validate().unwrap();
    c
}
fn read(node: &Node, method: &str, params: Value) -> anyhow::Result<Value> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let result = node.rpc(method, params.clone());
        if result
            .as_ref()
            .is_err_and(|e| e.to_string().contains("index is updating"))
            && Instant::now() < end
        {
            std::thread::sleep(Duration::from_millis(5));
        } else {
            return result;
        }
    }
}
fn message() -> Vec<u8> {
    "<script>literal text</script> 🌱".as_bytes().to_vec()
}
fn tx(node: &Node, c: &Config, amount: u64) -> Transaction {
    let nonce = node
        .rpc("account", json!({"key":hex::encode(owner())}))
        .unwrap()["account"]["nonce"]
        .as_u64()
        .unwrap();
    crypto::sign(
        &TransactionBody {
            chain_id: c.chain_id(),
            sender: owner(),
            nonce,
            fee: 2u64.into(),
            expiry_height: 100,
            operation: Operation::TransferExact {
                recipient: crypto::public_key(&[110; 32]).unwrap(),
                amount: amount.into(),
            },
            data: message(),
        },
        &SECRET,
    )
    .unwrap()
}

#[test]
fn genesis_revenue_and_bounded_empty_feed_are_consistent() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let node = Node::open(&dir.path().join("a.sqlite"), c.clone(), owner()).unwrap();
    let destination =
        address::encode(&crypto::public_key(&[110; 32]).unwrap(), &c.chain_id()).unwrap();
    let status = node.status().unwrap();
    assert!(status.get("treasury").is_none());
    assert_eq!(status["revenue"], "0");
    assert_eq!(status["curve_mass"], "0");
    assert!(node.rpc("account", json!({"key":destination})).is_err());
    let viewed = read(&node, "explorer_account", json!({"address":destination})).unwrap();
    assert!(viewed["account"].is_null());
    let before = node.status().unwrap()["state_root"].clone();
    let feed = read(&node, "explorer_chat", json!({})).unwrap();
    assert_eq!(feed["available"], true);
    assert_eq!(feed["ready"], true);
    assert_eq!(feed["indexed_height"], 0);
    assert!(feed.get("min_contribution").is_none());
    assert_eq!(feed["message_bytes"], c.transaction_bytes(&c.initial));
    assert!(feed["items"].as_array().unwrap().is_empty());
    assert!(feed["pending"].as_array().unwrap().is_empty());
    for p in [
        json!({"limit":0}),
        json!({"limit":51}),
        json!({"limit":"1"}),
        json!({"cursor":"1:100001"}),
        json!({"cursor":"4294967297:0"}),
        json!({"cursor":"' OR 1=1"}),
        json!({"cursor":null}),
        json!({"unknown":true}),
        json!([]),
    ] {
        assert!(read(&node, "explorer_chat", p).is_err());
    }
    assert_eq!(node.status().unwrap()["state_root"], before);
    let quote=node.rpc("transfer_quote",json!({"sender":hex::encode(owner()),"recipient":destination,"amount":"1","fee":"10","data_hex":hex::encode(message())})).unwrap();
    assert_ne!(quote["account_creation_fee"], "0");
    let forbidden=node.rpc("preparetransaction",json!({"sender":hex::encode(crypto::public_key(&[110; 32]).unwrap()),"operation":Operation::TransferExact{recipient:owner(),amount:1u64.into(),},"fee":"10"}));
    let rejection = forbidden.unwrap_err().to_string();
    assert!(
        rejection.contains("sender account has not been funded"),
        "{rejection}"
    );
}

#[test]
fn ordinary_payment_text_is_chat_and_forged_author_never_enters_mempool() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let path = dir.path().join("a.sqlite");
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    let b = Node::open(
        &dir.path().join("b.sqlite"),
        c.clone(),
        crypto::public_key(&[110; 32]).unwrap(),
    )
    .unwrap();
    for _ in 0..4 {
        b.submit_block(a.mine(100_000).unwrap()).unwrap();
    }
    let valid = tx(&a, &c, 1);
    let id = hex::encode(codec::transaction_id(&valid));
    let mut forged = tx(&a, &c, 1);
    forged.body.sender = crypto::public_key(&[111; 32]).unwrap();
    assert!(a.submit_transaction(forged).is_err());
    assert_eq!(a.status().unwrap()["mempool"], 0);
    a.submit_transaction(valid.clone()).unwrap();
    let pending = read(&a, "explorer_transaction", json!({"txid":id})).unwrap();
    assert_eq!(pending["transaction"]["status"], "pending");
    assert_eq!(
        pending["transaction"]["sender_public_key"],
        hex::encode(owner())
    );
    let feed = read(&a, "explorer_chat", json!({})).unwrap();
    assert!(feed["items"].as_array().unwrap().is_empty());
    assert_eq!(feed["pending"].as_array().unwrap().len(), 1);
    assert_eq!(
        feed["pending"][0]["text"],
        String::from_utf8(message()).unwrap()
    );
    assert_eq!(feed["pending"][0]["amount"], "1");
    a.mine(100_000).unwrap();
    let confirmed = read(&a, "explorer_transaction", json!({"txid":id})).unwrap();
    assert_eq!(confirmed["transaction"]["status"], "confirmed");
    assert_eq!(confirmed["transaction"]["data_hex"], hex::encode(message()));
    let destination =
        address::encode(&crypto::public_key(&[110; 32]).unwrap(), &c.chain_id()).unwrap();
    let account = read(&a, "explorer_account", json!({"address":destination})).unwrap();
    assert_eq!(account["account"]["ordinary"], "1");
    assert_eq!(account["history"][0]["role"], "recipient");
    assert_eq!(account["history"][0]["txid"], id);
    let feed = read(&a, "explorer_chat", json!({})).unwrap();
    assert_eq!(feed["items"].as_array().unwrap().len(), 1);
    assert_eq!(feed["items"][0]["txid"], id);
    assert_eq!(feed["items"][0]["position"], 0);
    // An older derived index omitted ordinary payment text. Reopening must
    // rebuild it from the same independently validated chain, not lose history.
    let before_reindex = a.status().unwrap()["state_root"].clone();
    drop(a);
    {
        let db = rusqlite::Connection::open(path.with_extension("explorer.sqlite")).unwrap();
        db.execute("UPDATE explorer_meta SET value='5' WHERE key='schema'", [])
            .unwrap();
        db.execute("DELETE FROM explorer_chat", []).unwrap();
    }
    let a = Node::open(&path, c.clone(), owner()).unwrap();
    assert_eq!(a.status().unwrap()["state_root"], before_reindex);
    let reindexed = read(&a, "explorer_chat", json!({})).unwrap();
    assert_eq!(reindexed["items"][0]["txid"], id);
    assert_eq!(
        reindexed["items"][0]["text"],
        String::from_utf8(message()).unwrap()
    );
    for _ in 0..3 {
        a.submit_block(b.mine(100_000).unwrap()).unwrap();
    }
    assert_eq!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    let rolled = read(&a, "explorer_transaction", json!({"txid":id})).unwrap();
    assert_ne!(rolled["transaction"]["status"], "confirmed");
    assert_eq!(rolled["transaction"]["confirmations"], 0);
    assert_eq!(a.status().unwrap()["revenue"], "0");
    let root = a.status().unwrap()["state_root"].clone();
    drop(a);
    let reopened = Node::open(&path, c.clone(), owner()).unwrap();
    assert_eq!(reopened.status().unwrap()["state_root"], root);
    let feed = read(&reopened, "explorer_chat", json!({})).unwrap();
    assert!(feed["items"].as_array().unwrap().is_empty());
    assert!(feed["pending"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_chat_and_governance_read_do_not_expose_private_node_authority() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let node = Node::open(&dir.path().join("a.sqlite"), c.clone(), owner()).unwrap();
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        node.clone(),
        ServerOptions {
            rpc: zero,
            public_web: Some(zero),
            p2p: zero,
            stratum: zero,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let url = format!("http://{}/rpc", server.public_web.unwrap());
    let client = reqwest::Client::new();
    for (method, params) in [
        ("explorer_chat", json!({})),
        ("governance", json!({})),
        ("status", json!({})),
    ] {
        let response = client
            .post(&url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success());
        let value: Value = response.json().await.unwrap();
        assert!(value.get("error").is_none(), "{value}");
        assert!(value.get("result").is_some());
        assert!(!value.to_string().contains("private_key"));
    }
    for method in ["mine", "signtransaction", "wallet", "submitblock"] {
        let response = client
            .post(&url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":{}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    let operation = Operation::TransferExact {
        recipient: owner(),
        amount: 1u64.into(),
    };
    let response=client.post(&url).json(&json!({"jsonrpc":"2.0","id":1,"method":"preparetransaction","params":{"sender":hex::encode(crypto::public_key(&[110; 32]).unwrap()),"operation":operation,"fee":"10"}})).send().await.unwrap();
    let value: Value = response.json().await.unwrap();
    let rejection = value["error"]["message"].as_str().unwrap();
    assert!(
        rejection.contains("sender account has not been funded"),
        "{value}"
    );
    let forged = Transaction {
        body: TransactionBody {
            data: Vec::new(),
            chain_id: c.chain_id(),
            sender: crypto::public_key(&[110; 32]).unwrap(),
            nonce: 0,
            fee: 10u64.into(),
            expiry_height: 100,
            operation: transfer_to_owner(),
        },
        signature: [0; 64],
    };
    let response=client.post(&url).json(&json!({"jsonrpc":"2.0","id":1,"method":"broadcasttransaction","params":{"raw":wallet::signed_hex(&forged)}})).send().await.unwrap();
    assert!(
        response
            .json::<Value>()
            .await
            .unwrap()
            .get("error")
            .is_some()
    );
    assert_eq!(node.status().unwrap()["height"], 0);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    server.stop().await;
}
fn transfer_to_owner() -> Operation {
    Operation::TransferExact {
        recipient: owner(),
        amount: 1u64.into(),
    }
}

#[test]
fn text_discovery_and_revenue_status_are_available_from_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let node = Node::open(&dir.path().join("current.sqlite"), c.clone(), owner()).unwrap();
    assert_eq!(node.status().unwrap()["revenue"], "0");
    let feed = read(&node, "explorer_chat", json!({})).unwrap();
    assert_eq!(feed["available"], true);
    assert!(feed["items"].as_array().unwrap().is_empty());
    let account = read(
        &node,
        "explorer_account",
        json!({"address":address::encode(&crypto::public_key(&[110; 32]).unwrap(),&c.chain_id()).unwrap()}),
    )
    .unwrap();
    assert!(account.get("system").is_none());
    assert!(account["account"].is_null());
}
