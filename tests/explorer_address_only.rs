use hashstash::{address, codec, config::Config, crypto, node::Node, types::*};
use serde_json::{Value, json};

const SECRET: [u8; 32] = [91; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.network = "isolated-address-only-tests".into();
    c.initial_bits = 0x2003ffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    c
}
fn read(node: &Node, method: &str, params: Value) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match node.rpc(method, params.clone()) {
            Ok(value) => return value,
            Err(e)
                if e.to_string().contains("index is updating")
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("{method}: {e}"),
        }
    }
}
fn transaction(c: &Config, nonce: u64, data: &[u8]) -> Transaction {
    crypto::sign(
        &TransactionBody {
            sender: owner(),
            nonce,
            fee: 1u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
            expiry_blocks: 1000,
            operation: Operation::TransferExact {
                recipient: owner(),
                amount: 1u32.into(),
            },
            data: data.to_vec(),
        },
        &SECRET,
    )
    .unwrap()
}

#[test]
fn former_alias_payloads_are_ordinary_bytes_with_normal_nonce_and_fee_execution() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let path = dir.path().join("ordinary.sqlite");
    let n = Node::open(&path, c.clone(), owner()).unwrap();
    for _ in 0..8 {
        n.mine(1_000_000).unwrap();
    }
    let payloads: [&[u8]; 3] = [b"name:Alice", b"name:Alice", b"name:\xff"];
    let transactions: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(nonce, data)| transaction(&c, nonce as u64, data))
        .collect();
    for tx in &transactions {
        n.submit_transaction(tx.clone()).unwrap();
    }
    let mined = n.mine(1_000_000).unwrap();
    assert_eq!(mined.transactions.len(), 3);
    for (tx, data) in transactions.iter().zip(payloads) {
        let result = read(
            &n,
            "explorer_transaction",
            json!({"txid":hex::encode(codec::transaction_id(tx))}),
        );
        assert_eq!(result["transaction"]["data_hex"], hex::encode(data));
        assert_eq!(result["transaction"]["fee"], "1");
        assert_eq!(result["transaction"]["status"], "confirmed");
        assert!(result["transaction"].get("name_registration").is_none());
    }
    let account = read(
        &n,
        "explorer_account",
        json!({"address":address::encode(&owner(), &c.chain_id()).unwrap()}),
    );
    assert_eq!(account["account"]["nonce"], 3);
    assert!(account.get("name_registration").is_none());
    // Replaying the unchanged consensus history does not reinterpret data.
    let root = n.status().unwrap()["state_root"].clone();
    drop(n);
    let reopened = Node::open(&path, c, owner()).unwrap();
    assert_eq!(reopened.status().unwrap()["state_root"], root);
    assert_eq!(
        reopened
            .rpc("account", json!({"key":hex::encode(owner())}))
            .unwrap()["account"]["nonce"],
        3
    );
}

#[test]
fn old_derived_schema_is_rebuilt_without_retired_tables_or_consensus_changes() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let path = dir.path().join("migration.sqlite");
    let n = Node::open(&path, c.clone(), owner()).unwrap();
    for _ in 0..8 {
        n.mine(1_000_000).unwrap();
    }
    let tx = transaction(&c, 0, b"name:Alice");
    let txid = hex::encode(codec::transaction_id(&tx));
    n.submit_transaction(tx).unwrap();
    n.mine(1_000_000).unwrap();
    let original = read(&n, "explorer_transaction", json!({"txid":txid}));
    let root = n.status().unwrap()["state_root"].clone();
    drop(n);
    let db = rusqlite::Connection::open(path.with_extension("explorer.sqlite")).unwrap();
    db.execute_batch(
        "CREATE TABLE explorer_names(lookup_key TEXT, record TEXT);
         CREATE INDEX explorer_name_key ON explorer_names(lookup_key);
         CREATE TABLE explorer_name_attempts(txid TEXT, record TEXT);
         INSERT INTO explorer_names VALUES('alice','retired derived record');
         INSERT INTO explorer_name_attempts VALUES('retired','retired derived attempt');
         UPDATE explorer_meta SET value='23-signed-transaction-mail' WHERE key='schema';",
    )
    .unwrap();
    let mut stale = original["transaction"].clone();
    stale["name_registration"] = json!({"name":"Alice", "status":"registered"});
    db.execute(
        "UPDATE explorer_transactions SET record=?1 WHERE txid=?2",
        rusqlite::params![serde_json::to_string(&stale).unwrap(), txid],
    )
    .unwrap();
    drop(db);
    let reopened = Node::open(&path, c.clone(), owner()).unwrap();
    let rebuilt = read(&reopened, "explorer_transaction", json!({"txid":txid}));
    assert_eq!(rebuilt, original);
    assert_eq!(reopened.status().unwrap()["state_root"], root);
    assert_eq!(rebuilt["chain_id"], hex::encode(c.chain_id()));
    let db = rusqlite::Connection::open(path.with_extension("explorer.sqlite")).unwrap();
    let retired: i64 = db.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('explorer_names','explorer_name_attempts','explorer_name_key')",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(retired, 0);
    let schema: String = db
        .query_row(
            "SELECT value FROM explorer_meta WHERE key='schema'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(schema, "petahash-atoms-separate-data-ordered-events");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retired_lookup_methods_and_asset_are_not_exposed() {
    use hashstash::node::{self, ServerOptions};
    let dir = tempfile::tempdir().unwrap();
    let n = Node::open(&dir.path().join("public.sqlite"), config(), owner()).unwrap();
    for method in ["explorer_name", "explorer_names"] {
        assert!(!hashstash::explorer::METHODS.contains(&method));
        assert!(
            n.rpc(method, json!({}))
                .unwrap_err()
                .to_string()
                .contains("unknown read method")
        );
    }
    let zero = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        n.clone(),
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
    let base = format!("http://{}", server.public_web.unwrap());
    let client = reqwest::Client::new();
    for method in ["explorer_name", "explorer_names", "mine"] {
        let response = client
            .post(format!("{base}/rpc"))
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":{}}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "{method}");
    }
    assert_eq!(
        client
            .get(format!("{base}/names.js"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let mail: Value = client
        .post(format!("{base}/rpc"))
        .json(&json!({"jsonrpc":"2.0", "id":1, "method":"explorer_mail", "params":{}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mail["result"]["ready"], true);
    assert!(mail["result"]["messages"].as_array().unwrap().is_empty());
    assert_eq!(n.status().unwrap()["height"], 0);
    assert_eq!(n.status().unwrap()["mempool"], 0);
    server.stop().await;
}
