//! The private listener trusts every local process, so development mining is
//! confined to development networks and to its own worker, and server-wallet
//! sends keep a worker that RPC mutations cannot take.
use super::*;

fn options() -> ServerOptions {
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        p2p: zero,
        stratum: zero,
        stratum_enabled: false,
        ..Default::default()
    }
}

#[test]
fn mine_needs_a_development_network_or_dev_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[81; 32]).unwrap();
    // Calibrated: a block at the easiest target needs about 2^32 hashes.
    let mut calibrated = Config::devnet();
    calibrated.test_work = false;
    calibrated.initial_bits = 0x1d00ffff;
    calibrated.limit_bits = 0x1d00ffff;
    assert!(!development_network(&calibrated, false));
    let node = Node::open(
        &directory.path().join("calibrated.sqlite"),
        calibrated,
        miner,
    )
    .unwrap();
    let refused = node.rpc("mine", json!({"attempts":1})).unwrap_err();
    assert!(refused.to_string().contains("--dev-rpc"), "{refused}");
    assert_eq!(node.status().unwrap()["height"], 0);
    // The operator's flag allows it; one attempt almost surely finds nothing.
    if let Err(error) = node
        .clone()
        .with_dev_rpc()
        .rpc("mine", json!({"attempts":1}))
    {
        assert!(!error.to_string().contains("--dev-rpc"), "{error}");
    }
    // The presets' development limit is a development network in any build.
    let mut easy = Config::devnet();
    easy.test_work = false;
    assert!(easy_proof_of_work(&easy) && development_network(&easy, false));
    let node = Node::open(&directory.path().join("easy.sqlite"), easy, miner).unwrap();
    node.rpc("mine", json!({"count":2})).unwrap();
    assert_eq!(node.status().unwrap()["height"], 2);
}

/// `run --allow-easy-target` exposes an easy network to untrusted peers,
/// whose hashrate can lift difficulty far above its limit: the node is then
/// no development network, and `mine` needs `--dev-rpc` as on a calibrated one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mine_on_a_node_untrusted_peers_reach_needs_dev_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[84; 32]).unwrap();
    let mut easy = Config::devnet();
    easy.test_work = false;
    assert!(!development_network(&easy, true));
    // Fixture networks need a test build and are never shared.
    let mut fixture = easy.clone();
    fixture.test_work = true;
    assert!(development_network(&fixture, true));
    let client = reqwest::Client::new();
    let exposed = ServerOptions {
        p2p: "0.0.0.0:0".parse().unwrap(),
        ..options()
    };
    for (name, dev_rpc, options, allowed) in [
        ("exposed", false, exposed.clone(), false),
        ("flagged", true, exposed, true),
        ("loopback", false, options(), true),
    ] {
        let path = directory.path().join(format!("{name}.sqlite"));
        let mut node = Node::open(&path, easy.clone(), miner).unwrap();
        if dev_rpc {
            node = node.with_dev_rpc();
        }
        let server = serve(node.clone(), options).await.unwrap();
        let reply: Value = client
            .post(format!("http://{}/rpc", server.rpc))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"mine","params":{"count":1}}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if allowed {
            assert!(reply["result"]["blocks"].is_array(), "{name}: {reply}");
        } else {
            let error = reply["error"]["message"].as_str().unwrap_or_default();
            assert!(error.contains("--dev-rpc"), "{name}: {reply}");
        }
        assert_eq!(
            node.status().unwrap()["height"],
            u64::from(allowed),
            "{name}"
        );
        server.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
async fn development_mining_and_server_wallets_have_their_own_workers() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [82; 32];
    let public = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[83; 32]).unwrap();
    let node = Node::open(
        &directory.path().join("workers.sqlite"),
        Config::devnet(),
        public,
    )
    .unwrap()
    .with_wallet(secret)
    .unwrap();
    for _ in 0..12 {
        node.mine(100_000).unwrap();
    }
    let server = serve(node.clone(), options()).await.unwrap();
    let url = format!("http://{}", server.rpc);
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    let client = reqwest::Client::new();
    let rpc = |method: &str, params: Value| {
        client
            .post(format!("{url}/rpc"))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
    };
    // Every shared mutation worker is busy, as two looping `mine` calls
    // used to keep them.
    let shared = node
        .rpc_mutations
        .clone()
        .acquire_many_owned(2)
        .await
        .unwrap();
    let mined: Value = rpc("mine", json!({"count":1}))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(mined["result"]["blocks"].is_array(), "{mined}");
    let session: Value = client
        .get(format!("{url}/api/session"))
        .header("X-Hashstash-Token", &token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sent = client
        .post(format!("{url}/api/wallet"))
        .header("X-Hashstash-Token", &token)
        .json(&json!({"operation":{"TransferExact":{"recipient":recipient,"amount":"1"}},"extra_fee":"0","expected_sender":hex::encode(public),"wallet_revision":session["wallet_revision"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(sent.status(), 200, "{}", sent.text().await.unwrap());
    drop(shared);
    // While development mining runs, sends and the faucet's RPCs still do.
    let mining = node.dev_mining.clone().acquire_owned().await.unwrap();
    let block: Value = rpc("getblock", json!({"height":1}))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(block["result"]["header"].is_object(), "{block}");
    drop(mining);
    assert_eq!(node.status().unwrap()["height"], 13);
    assert_eq!(node.status().unwrap()["mempool"], 1);
    server.stop().await;
}
