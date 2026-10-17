//! Real-node faucet coverage. Every node, key, database, listener and mined block
//! belongs to this isolated temporary devnet; no public experiment is contacted.
use hashstash::{
    address, codec,
    config::Config,
    crypto,
    faucet::{self, FaucetConfig, FaucetServer},
    math,
    node::{self, Node, ServerOptions},
    types::{Amount, Operation, PublicKey},
};
use num_traits::Zero;
use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tempfile::TempDir;
use tokio::time::{Instant, sleep};

const ORIGIN: &str = "https://faucet.integration.test";
const VISITOR_IP: &str = "192.0.2.7";

fn options() -> ServerOptions {
    let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: local,
        p2p: local,
        stratum: local,
        ..Default::default()
    }
}

fn dedicated_key(dir: &TempDir) -> (std::path::PathBuf, PublicKey) {
    let (secret, public) = loop {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).unwrap();
        if let Ok(public) = crypto::public_key(&secret) {
            break (secret, public);
        }
    };
    let path = dir.path().join("faucet.key");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "secret": hex::encode(secret), "public": hex::encode(public)
        }))
        .unwrap(),
    )
    .unwrap();
    // The faucet accepts only an owner-only key file, as `hashstash keygen` writes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    (path, public)
}

fn faucet_config(
    dir: &TempDir,
    key_file: std::path::PathBuf,
    config: &Config,
    rpc: SocketAddr,
) -> FaucetConfig {
    FaucetConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        rpc_url: format!("http://{rpc}/rpc"),
        chain_id: hex::encode(config.chain_id()),
        key_file,
        database: dir.path().join("claims.sqlite"),
        origins: vec![ORIGIN.into()],
        payout: "5".into(),
        max_fee: "20".into(),
        cooldown_seconds: 86400,
        subnet_cooldown_seconds: 60,
        subnet_daily_claims: 10,
        hourly_claims: 100,
        daily_claims: 250,
        lifetime_claims: 1000,
        recent_block_seconds: 180,
        confirmations: 2,
        expiry_blocks: 20,
    }
}

async fn status(client: &Client, server: &FaucetServer, address: Option<&str>) -> Value {
    let mut request = client
        .get(format!("http://{}/faucet/status", server.address))
        .header("host", "faucet.integration.test")
        .header("x-real-ip", VISITOR_IP);
    if let Some(address) = address {
        request = request.query(&[("address", address)]);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

async fn wait_status(
    client: &Client,
    server: &FaucetServer,
    address: Option<&str>,
    expected: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let value = status(client, server, address).await;
        if expected(&value) {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "faucet status did not converge: {value}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn claim(client: &Client, server: &FaucetServer, address: &str, ip: &str) -> Response {
    client
        .post(format!("http://{}/faucet/claim", server.address))
        .header("host", "faucet.integration.test")
        .header("origin", ORIGIN)
        .header("x-real-ip", ip)
        .json(&json!({"address": address}))
        .send()
        .await
        .unwrap()
}

fn account(node: &Node, key: PublicKey) -> Value {
    node.rpc("account", json!({"key": hex::encode(key)}))
        .unwrap()["account"]
        .clone()
}

fn amount(value: &Value) -> Amount {
    Amount::parse_bytes(value.as_str().unwrap().as_bytes(), 10).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fixed_payment_is_exact_and_durable_against_repeat_claims_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (key_file, donor) = dedicated_key(&dir);
    let recipient = crypto::public_key(&[113; 32]).unwrap();
    let mut config = Config::devnet();
    config.network = "faucet-real-node-integration".into();
    let recipient_address = address::encode(&recipient, &config.chain_id()).unwrap();
    let node = Node::open(&dir.path().join("chain.sqlite"), config.clone(), donor).unwrap();
    let node_server = node::serve(node.clone(), options()).await.unwrap();
    let mut policy = faucet_config(&dir, key_file, &config, node_server.rpc);
    let faucet_server = faucet::serve(policy.clone()).await.unwrap();
    let client = Client::new();
    assert_eq!(
        status(&client, &faucet_server, None).await["state"],
        "waiting_for_mining"
    );
    // Ensure the first poll observes genesis, then prove a real height advance.
    sleep(Duration::from_millis(3300)).await;
    for _ in 0..30 {
        node.mine(100_000).unwrap();
    }
    wait_status(&client, &faucet_server, None, |v| v["available"] == true).await;

    let donor_before = amount(&account(&node, donor)["ordinary"]);
    let quote = node
        .rpc(
            "fee_quote",
            json!({
                "sender": hex::encode(donor),
                "operation": Operation::TransferExact { recipient, amount: 5u32.into(), },
                "extra_fee": "0"
            }),
        )
        .unwrap();
    let expected_fee = amount(&quote["fee"]);
    assert!(expected_fee > Amount::zero() && expected_fee < 20u32.into());
    let response = claim(&client, &faucet_server, &recipient_address, VISITOR_IP).await;
    assert_eq!(response.status(), StatusCode::OK);
    let pending: Value = response.json().await.unwrap();
    assert_eq!(pending["status"], "pending");
    assert_eq!(pending["amount_hashes"], "5");
    assert_eq!(node.status().unwrap()["mempool"], 1);
    let duplicate: Value = claim(&client, &faucet_server, &recipient_address, "198.51.100.2")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(duplicate["txid"], pending["txid"]);
    assert_eq!(node.status().unwrap()["mempool"], 1);

    let mined = node.mine(100_000).unwrap();
    assert_eq!(mined.transactions.len(), 1);
    let transaction = &mined.transactions[0];
    assert_eq!(
        hex::encode(codec::transaction_id(transaction)),
        pending["txid"]
    );
    // Receipt checks read one canonical hash and named IDs, never a whole block.
    let receipt = node
        .rpc(
            "blockreceipt",
            json!({"height": mined.height, "txids": [pending["txid"], hex::encode([0u8; 32])]}),
        )
        .unwrap();
    assert_eq!(receipt["hash"], hex::encode(codec::block_hash(&mined)));
    assert_eq!(receipt["included"], json!([true, false]));
    assert!(
        node.rpc(
            "blockreceipt",
            json!({"height": mined.height, "txids": vec![hex::encode([0u8; 32]); 65]})
        )
        .is_err()
    );
    assert_eq!(transaction.body.sender, donor);
    assert_eq!(transaction.body.nonce, 0);
    assert_eq!(transaction.body.fee, expected_fee);
    assert!(transaction.body.fee <= 20u32.into());
    assert!(&transaction.body.data.is_empty());
    assert_eq!(
        transaction.body.operation.clone(),
        Operation::TransferExact {
            recipient,
            amount: 5u32.into(),
        }
    );
    let reward = math::work(&math::target_from_bits(mined.header.bits).unwrap());
    assert_eq!(amount(&account(&node, recipient)["ordinary"]), 5u32.into());
    assert_eq!(
        amount(&account(&node, donor)["ordinary"]),
        donor_before + reward - Amount::from(5u32) - &expected_fee + &expected_fee * 50u32 / 100u32
    );
    assert_eq!(account(&node, donor)["nonce"], 1);
    let confirmation = node.mine(100_000).unwrap();
    assert!(confirmation.transactions.is_empty());
    wait_status(&client, &faucet_server, Some(&recipient_address), |v| {
        v["claim"]["status"] == "confirmed"
    })
    .await;
    let confirmed: Value = claim(&client, &faucet_server, &recipient_address, VISITOR_IP)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(confirmed["status"], "confirmed");
    assert_eq!(confirmed["txid"], pending["txid"]);

    // A different address cannot bypass the shared client subnet cooldown.
    let second_address =
        address::encode(&crypto::public_key(&[114; 32]).unwrap(), &config.chain_id()).unwrap();
    assert_eq!(
        claim(&client, &faucet_server, &second_address, "192.0.2.99")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let unknown_amount = client
        .post(format!("http://{}/faucet/claim", faucet_server.address))
        .header("host", "faucet.integration.test")
        .header("origin", ORIGIN)
        .header("x-real-ip", "203.0.113.2")
        .json(&json!({"address":second_address,"amount":"500"}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown_amount.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    faucet_server.stop().await;

    policy.payout = "7".into();
    let restarted = faucet::serve(policy.clone()).await.unwrap();
    wait_status(&client, &restarted, Some(&recipient_address), |v| {
        v["claim"]["status"] == "confirmed"
    })
    .await;
    let repeated: Value = claim(&client, &restarted, &recipient_address, "203.0.113.4")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(repeated["txid"], pending["txid"]);
    assert_eq!(repeated["status"], "confirmed");
    assert_eq!(
        repeated["amount_hashes"], "5",
        "old receipts retain their paid amount after a configuration change"
    );
    assert_eq!(
        status(&client, &restarted, None).await["amount_hashes"],
        "7"
    );
    assert_eq!(account(&node, donor)["nonce"], 1);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    let no_duplicate = node.mine(100_000).unwrap();
    assert!(no_duplicate.transactions.is_empty());
    assert_eq!(amount(&account(&node, recipient)["ordinary"]), 5u32.into());
    let ledger = rusqlite::Connection::open(dir.path().join("claims.sqlite")).unwrap();
    assert_eq!(
        ledger
            .query_row("SELECT COUNT(*) FROM claims", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    drop(ledger);
    wait_status(&client, &restarted, None, |v| v["available"] == true).await;
    assert_eq!(
        claim(&client, &restarted, &second_address, "192.0.2.99")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS,
        "migration does not reset the subnet cooldown"
    );
    let response = claim(&client, &restarted, &second_address, "198.18.1.2").await;
    assert_eq!(response.status(), StatusCode::OK);
    let newer: Value = response.json().await.unwrap();
    assert_eq!(newer["amount_hashes"], "7");
    let payment = node.mine(100_000).unwrap();
    assert_eq!(payment.transactions.len(), 1);
    assert_eq!(payment.transactions[0].body.nonce, 1);
    assert_eq!(
        payment.transactions[0].body.operation.clone(),
        Operation::TransferExact {
            recipient: crypto::public_key(&[114; 32]).unwrap(),
            amount: 7u32.into(),
        }
    );
    node.mine(100_000).unwrap();
    wait_status(&client, &restarted, Some(&second_address), |v| {
        v["claim"]["status"] == "confirmed"
    })
    .await;
    assert_eq!(
        amount(&account(&node, crypto::public_key(&[114; 32]).unwrap())["ordinary"]),
        7u32.into()
    );
    assert_eq!(account(&node, donor)["nonce"], 2);
    restarted.stop().await;
    policy.payout = "9".into();
    let restarted = faucet::serve(policy.clone()).await.unwrap();
    wait_status(&client, &restarted, Some(&second_address), |v| {
        v["claim"]["status"] == "confirmed"
    })
    .await;
    let original_status = status(&client, &restarted, Some(&recipient_address)).await;
    let newer_status = status(&client, &restarted, Some(&second_address)).await;
    assert_eq!(original_status["amount_hashes"], "9");
    assert_eq!(original_status["claim"]["amount_hashes"], "5");
    assert_eq!(newer_status["claim"]["amount_hashes"], "7");
    assert_eq!(node.status().unwrap()["mempool"], 0);
    let ledger = rusqlite::Connection::open(dir.path().join("claims.sqlite")).unwrap();
    let amounts = ledger
        .prepare("SELECT amount_hashes FROM claims ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(amounts, vec!["5", "7"]);
    drop(ledger);
    restarted.stop().await;
    let summary = faucet::maintain(&policy, faucet::Maintenance::Inspect).unwrap();
    assert_eq!(summary["claims"]["confirmed"], 2);
    assert_eq!(summary["latest_receipt"]["nonce"], "1");
    assert!(summary["pending"].is_null());
    node_server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mined_faucet_balances_remain_liquid_across_initial_rest_and_auction() {
    let dir = tempfile::tempdir().unwrap();
    let (key_file, donor) = dedicated_key(&dir);
    let mut config = Config::devnet();
    config.network = "faucet-open-genesis-integration".into();
    let node = Node::open(&dir.path().join("chain.sqlite"), config.clone(), donor).unwrap();
    let node_server = node::serve(node.clone(), options()).await.unwrap();
    let mut policy = faucet_config(&dir, key_file, &config, node_server.rpc);
    policy.payout = "1".into();
    policy.max_fee = "2".into();
    let server = faucet::serve(policy).await.unwrap();
    let client = Client::new();
    sleep(Duration::from_millis(3300)).await;
    for _ in 0..4 {
        node.mine(100_000).unwrap();
    }
    wait_status(&client, &server, None, |v| v["state"] == "ready").await;
    let starting = amount(&account(&node, donor)["ordinary"]);
    for _ in 0..100 {
        node.mine(100_000).unwrap();
    }
    let observed = account(&node, donor);
    assert!(amount(&observed["ordinary"]) > starting);
    assert!(amount(&observed["shares"]).is_zero());
    assert_eq!(observed["nonce"], 0);
    // Let the service refresh its height before preparing a short-lived claim.
    sleep(Duration::from_millis(3300)).await;
    wait_status(&client, &server, None, |v| v["state"] == "ready").await;
    let recipient = crypto::public_key(&[115; 32]).unwrap();
    let recipient_address = address::encode(&recipient, &config.chain_id()).unwrap();
    assert_eq!(
        claim(&client, &server, &recipient_address, VISITOR_IP)
            .await
            .status(),
        StatusCode::OK
    );
    let payment = node.mine(100_000).unwrap();
    assert_eq!(payment.transactions.len(), 1);
    assert_eq!(amount(&account(&node, recipient)["ordinary"]), 1u32.into());
    assert!(amount(&account(&node, donor)["shares"]).is_zero());
    assert_eq!(account(&node, donor)["nonce"], 1);
    server.stop().await;
    node_server.stop().await;
}
