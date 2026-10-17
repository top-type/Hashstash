//! Node RPC data the browser wallet relies on: blank chat text agrees with
//! ui/chat.js, and the snapshot reports the selected sender's pending rows
//! and, once, its pending nonce.
use hashstash::{codec, config::Config, crypto, node::Node, types::*};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const SECRET: [u8; 32] = [121; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn recipient() -> PublicKey {
    crypto::public_key(&[122; 32]).unwrap()
}
fn config() -> Config {
    let mut c = Config::devnet();
    c.network = "isolated-wallet-feed-tests".into();
    c.validate().unwrap();
    c
}
fn funded(dir: &tempfile::TempDir, c: &Config) -> Node {
    let node = Node::open(&dir.path().join("a.sqlite"), c.clone(), owner()).unwrap();
    for _ in 0..8 {
        node.mine(100_000).unwrap();
    }
    node
}
fn payment(c: &Config, nonce: u64, data: &[u8]) -> Transaction {
    crypto::sign(
        &c.chain_id(),
        &TransactionBody {
            sender: owner(),
            nonce,
            fee: 2u64.into(),
            anchor: codec::block_hash(&codec::genesis_block(c).unwrap()),
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: recipient(),
                amount: 1u64.into(),
            },
            data: data.to_vec(),
        },
        &SECRET,
    )
    .unwrap()
}
fn read(node: &Node, method: &str, params: Value) -> Value {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        let result = node.rpc(method, params.clone());
        match result {
            Err(e) if e.to_string().contains("index is updating") && Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(5))
            }
            result => return result.unwrap(),
        }
    }
}
fn texts(rows: &Value) -> Vec<String> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| row["text"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn invisible_only_text_never_reaches_the_chat_feed() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let node = funded(&dir, &c);
    // A BOM-only message once made every browser feed fail its whole page.
    let blank: [&[u8]; 2] = [b"\xef\xbb\xbf", b" \xef\xbb\xbf\n"];
    for (nonce, data) in blank.iter().enumerate() {
        node.submit_transaction(payment(&c, nonce as u64, data))
            .unwrap();
    }
    node.submit_transaction(payment(&c, 2, "visible\u{feff}".as_bytes()))
        .unwrap();
    let feed = read(&node, "explorer_chat", json!({}));
    assert_eq!(texts(&feed["pending"]), ["visible\u{feff}"]);
    node.mine(100_000).unwrap();
    let feed = read(&node, "explorer_chat", json!({}));
    assert_eq!(texts(&feed["items"]), ["visible\u{feff}"]);
    assert!(feed["pending"].as_array().unwrap().is_empty());
}

#[test]
fn snapshot_reports_the_selected_senders_pending_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let node = funded(&dir, &c);
    let key = hex::encode(owner());
    let snapshot = node.rpc("snapshot", json!({"key":key})).unwrap();
    // A decimal string, like the account read it embeds.
    assert_eq!(snapshot["account"]["pending_nonce"], "0");
    assert!(snapshot.get("pending_nonce").is_none(), "reported once");
    assert_eq!(snapshot["sender_mempool"], json!([]));
    for nonce in 0..2 {
        node.submit_transaction(payment(&c, nonce, b"")).unwrap();
    }
    let snapshot = node.rpc("snapshot", json!({"key":key})).unwrap();
    assert_eq!(snapshot["account"]["pending_nonce"], "2");
    let rows = snapshot["sender_mempool"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| row["body"]["nonce"].as_u64().unwrap() < 2));
    // preparetransaction requires exactly the reported value.
    let operation = Operation::TransferExact {
        recipient: recipient(),
        amount: 1u64.into(),
    };
    let request = |nonce: u64| json!({"sender":key,"operation":operation,"fee":"10","nonce":nonce});
    assert!(node.rpc("preparetransaction", request(2)).is_ok());
    let stale = node.rpc("preparetransaction", request(1)).unwrap_err();
    assert!(
        stale.to_string().contains("requested nonce differs"),
        "{stale}"
    );
    // Other senders' rows and unselected snapshots carry nothing extra.
    let anonymous = node.rpc("snapshot", json!({})).unwrap();
    assert!(anonymous["account"].is_null());
    assert!(anonymous.get("sender_mempool").is_none());
    let other = node
        .rpc("snapshot", json!({"key":hex::encode(recipient())}))
        .unwrap();
    assert!(other["account"].is_null());
    assert_eq!(other["sender_mempool"], json!([]));
}
