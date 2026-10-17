use hashstash::{
    address, codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
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
async fn session(url: &str) -> Value {
    reqwest::get(format!("{url}/api/session"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_wallet_metadata_and_watch_import_use_chain_checked_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let public = crypto::public_key(&[81; 32]).unwrap();
    let config = Config::devnet();
    let chain = config.chain_id();
    let encoded = address::encode(&public, &chain).unwrap();
    let node = Node::open(&dir.path().join("node.sqlite"), config, public).unwrap();
    let server = node::serve(node.clone(), options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let empty = session(&base).await;
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    assert!(empty["address"].is_null());
    assert_eq!(empty["address_hrp"], address::hrp(&chain));
    let client = reqwest::Client::new();
    let script = client
        .get(format!("{base}/address.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(script.status(), 200);
    assert_eq!(script.headers()["cache-control"], "no-store");
    assert!(
        script.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/javascript")
    );
    let watched: Value = client.post(format!("{base}/api/wallet/manage")).header("X-Hashstash-Token",&token).json(&json!({"action":"watch","name":"Address account","public_key":encoded.to_uppercase(),"revision":empty["wallet_revision"]})).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert_eq!(watched["address"], encoded);
    assert_eq!(watched["public_key"], hex::encode(public));
    assert_eq!(watched["wallets"][0]["address"], encoded);
    assert_eq!(watched["wallets"][0]["public_key"], hex::encode(public));
    let after = session(&base).await;
    let wrong_chain = [99; 32];
    let wrong = address::encode(&public, &wrong_chain).unwrap();
    let rejected = client.post(format!("{base}/api/wallet/manage")).header("X-Hashstash-Token",&token).json(&json!({"action":"watch","name":"Wrong network","public_key":wrong,"revision":watched["wallet_revision"]})).send().await.unwrap();
    assert_eq!(rejected.status(), 400);
    assert_eq!(session(&base).await, after);
    let duplicate: Value = client.post(format!("{base}/api/wallet/manage")).header("X-Hashstash-Token",&token).json(&json!({"action":"watch","name":"Raw duplicate","public_key":hex::encode(public),"revision":watched["wallet_revision"]})).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    assert_eq!(duplicate, watched);
    server.stop().await;
}

#[test]
fn rpc_addresses_keep_same_accounts_and_signed_transaction_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [82; 32];
    let public = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[83; 32]).unwrap();
    let config = Config::devnet();
    let chain = config.chain_id();
    let encoded = address::encode(&public, &chain).unwrap();
    let recipient_address = address::encode(&recipient, &chain).unwrap();
    let node = Node::open(&dir.path().join("node.sqlite"), config, public).unwrap();
    let info = node
        .rpc("address", json!({"public_key":hex::encode(public)}))
        .unwrap();
    assert_eq!(
        info,
        json!({"address":encoded,"public_key":hex::encode(public),"address_hrp":address::hrp(&chain)})
    );
    assert_eq!(
        node.rpc("validateaddress", json!({"address":encoded.to_uppercase()}))
            .unwrap(),
        info
    );
    assert!(
        node.rpc("validateaddress", json!({"address":hex::encode(public)}))
            .is_err()
    );
    for _ in 0..8 {
        node.mine(100_000).unwrap();
    }
    assert_eq!(
        node.rpc("account", json!({"key":encoded})).unwrap(),
        node.rpc("account", json!({"key":hex::encode(public)}))
            .unwrap()
    );
    assert_eq!(
        node.rpc("snapshot", json!({"key":encoded})).unwrap(),
        node.rpc("snapshot", json!({"key":hex::encode(public)}))
            .unwrap()
    );
    let operation = Operation::TransferExact {
        recipient,
        amount: 3u32.into(),
    };
    let raw = node
        .rpc(
            "preparetransaction",
            json!({"sender":hex::encode(public),"operation":operation,"extra_fee":"0"}),
        )
        .unwrap();
    let addressed = node
        .rpc(
            "preparetransaction",
            json!({"sender":encoded,"operation":operation,"extra_fee":"0"}),
        )
        .unwrap();
    assert_eq!(raw, addressed);
    let mut addressed = addressed;
    addressed.as_object_mut().unwrap().remove("fee_quote");
    let body = wallet::decode_unsigned(&serde_json::from_value(addressed).unwrap()).unwrap();
    assert_eq!(body.sender, public);
    assert!(
        !serde_json::to_value(&body)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("chain_id")
    );
    let transaction = crypto::sign(&body, &secret).unwrap();
    node.rpc(
        "broadcasttransaction",
        json!({"raw":wallet::signed_hex(&transaction)}),
    )
    .unwrap();
    node.rpc(
        "mine",
        json!({"recipient":recipient_address,"count":1,"attempts":100_000}),
    )
    .unwrap();
    let block: Block = serde_json::from_value(node.rpc("getblock", json!({})).unwrap()).unwrap();
    assert_eq!(block.miner, recipient);
    assert_eq!(
        codec::encode(&block.transactions[0]),
        codec::encode(&transaction)
    );
    let mut other = chain;
    other[0] ^= 1;
    let wrong = address::encode(&public, &other).unwrap();
    let before = node.status().unwrap();
    for method in ["account", "snapshot", "support"] {
        assert!(
            node.rpc(
                method,
                json!({"key":wrong,"proposal":hex::encode([0;32]),"round":0})
            )
            .unwrap_err()
            .to_string()
            .contains("another network")
        );
    }
    assert!(
        node.rpc(
            "preparetransaction",
            json!({"sender":wrong,"operation":operation,"extra_fee":"0"})
        )
        .is_err()
    );
    assert!(node.rpc("mine", json!({"recipient":wrong})).is_err());
    assert_eq!(node.status().unwrap(), before);
}
