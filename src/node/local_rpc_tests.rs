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

/// `getblock` used to build a generic JSON tree of the whole block, one value
/// of tens of bytes per byte, before the response limit was even checked: a
/// block with tens of MiB of data took gigabytes per call, and blocks beyond
/// about 50 MiB could never be served. The JSON form now stays within the JSON
/// page budgets, and every valid block is served as its canonical hexadecimal
/// record, which `submitblock` accepts back.
#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn large_blocks_are_served_in_hex_instead_of_a_json_tree() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [88; 32];
    let sender = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[89; 32]).unwrap();
    let mut config = Config::testnet();
    config.initial.block_bytes = 4 << 20;
    config.initial_bits = 0x1f7fffff;
    config.limit_bits = config.initial_bits;
    config.genesis_time = now().saturating_sub(3600) as u32;
    let node = Node::open(
        &directory.path().join("large.sqlite"),
        config.clone(),
        sender,
    )
    .unwrap();
    for _ in 0..10 {
        node.mine(1_000_000).unwrap();
    }
    // An ordinary block keeps its JSON form.
    let small: Block = serde_json::from_value(node.rpc("getblock", json!({})).unwrap()).unwrap();
    assert_eq!(small.height, 10);
    // More data bytes than the JSON value budget.
    let data = vec![0xa5; 2_200_000];
    let mut prepared = node
        .rpc(
            "preparetransaction",
            json!({"sender":hex::encode(sender),"operation":Operation::TransferExact{recipient,amount:1u32.into()},"data_hex":hex::encode(&data)}),
        )
        .unwrap();
    prepared.as_object_mut().unwrap().remove("fee_quote");
    let body = wallet::decode_unsigned(&serde_json::from_value(prepared).unwrap()).unwrap();
    let transaction = crypto::sign(&config.chain_id(), &body, &secret).unwrap();
    node.rpc(
        "broadcasttransaction",
        json!({"raw":wallet::signed_hex(&transaction)}),
    )
    .unwrap();
    let block = node.mine(1_000_000).unwrap();
    assert_eq!(block.transactions, vec![transaction]);
    let refused = node.rpc("getblock", json!({})).unwrap_err().to_string();
    assert!(refused.contains("format \"hex\""), "{refused}");
    assert!(node.rpc("getblock", json!({"format":"xml"})).is_err());
    // Any block is available as its canonical record, which another node
    // accepts back through `submitblock`.
    let other = Node::open(&directory.path().join("other.sqlite"), config, sender).unwrap();
    for height in 1..=block.height {
        let reply = node
            .rpc("getblock", json!({"height":height,"format":"hex"}))
            .unwrap();
        assert_eq!(reply["height"], height);
        let raw = hex::decode(reply["raw"].as_str().unwrap()).unwrap();
        let decoded = codec::decode_block(&raw, raw.len()).unwrap();
        assert_eq!(reply["hash"], hex::encode(codec::block_hash(&decoded)));
        if height == block.height {
            assert_eq!(decoded, block);
        }
        let submitted = other.rpc("submitblock", reply.clone()).unwrap();
        assert_eq!(submitted["selected"], true, "{height}");
        assert_eq!(submitted["hash"], reply["hash"]);
    }
    assert_eq!(
        other.status().unwrap()["tip"],
        node.status().unwrap()["tip"]
    );
}

/// The private listener needs no session token, so a quote that omits its
/// sender is refused there too rather than read from the selected server
/// wallet, which would show any local process that account and its balance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quotes_never_default_to_the_selected_server_wallet() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[85; 32]).unwrap();
    let selected = crypto::public_key(&[86; 32]).unwrap();
    let recipient = crypto::public_key(&[87; 32]).unwrap();
    let node = Node::open(
        &directory.path().join("quotes.sqlite"),
        Config::devnet(),
        miner,
    )
    .unwrap()
    .with_wallet([86; 32])
    .unwrap();
    let chain_id = node.read_view().unwrap().chain.chain_id();
    let hidden = [
        hex::encode(selected),
        address::encode(&selected, &chain_id).unwrap(),
    ];
    let server = serve(node.clone(), options()).await.unwrap();
    let client = reqwest::Client::new();
    let rpc = |method: &str, params: &Value| {
        client
            .post(format!("http://{}/rpc", server.rpc))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
    };
    let operation = Operation::TransferExact {
        recipient,
        amount: 1u32.into(),
    };
    for (method, params) in [
        ("fee_quote", json!({"operation":operation})),
        (
            "transfer_quote",
            json!({"recipient":hex::encode(recipient),"amount":"1"}),
        ),
    ] {
        let reply: Value = rpc(method, &params).await.unwrap().json().await.unwrap();
        let message = reply["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("sender"), "{method}: {reply}");
        for value in &hidden {
            assert!(
                !reply.to_string().contains(value.as_str()),
                "{method}: {reply}"
            );
        }
        assert!(node.rpc(method, params.clone()).is_err(), "{method}");
        // A caller that names its sender is quoted as before.
        let mut named = params.clone();
        named["sender"] = json!(hex::encode(miner));
        let reply: Value = rpc(method, &named).await.unwrap().json().await.unwrap();
        assert_eq!(
            reply["result"]["sender_public_key"],
            hex::encode(miner),
            "{method}: {reply}"
        );
    }
    server.stop().await;
}
