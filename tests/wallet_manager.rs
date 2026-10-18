use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
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
/// The session context, with the server wallets that only a holder of the
/// owner-only session token may list.
async fn session(server: &node::Server) -> Value {
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    reqwest::Client::new()
        .get(format!("http://{}/api/session", server.rpc))
        .header("X-Hashstash-Token", token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn manage(base: &str, token: &str, value: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}/api/wallet/manage"))
        .header("X-Hashstash-Token", token)
        .json(&value)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}
fn donation(sender: &str, revision: &Value) -> Value {
    json!({"operation":{"TransferExact":{"recipient":hashstash::crypto::public_key(&[6; 32]).unwrap(),"amount":"1"}},"extra_fee":"0","expected_sender":sender,"wallet_revision":revision})
}
async fn sign(base: &str, token: &str, value: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}/api/wallet"))
        .header("X-Hashstash-Token", token)
        .json(&value)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallets_persist_and_failed_imports_preserve_selection_and_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.sqlite");
    let public = crypto::public_key(&[70; 32]).unwrap();
    let node = Node::open(&path, Config::devnet(), public).unwrap();
    let chain_before = node.status().unwrap();
    let server = node::serve(node.clone(), options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let initial = session(&server).await;
    let initial_token = std::fs::read_to_string(&server.session_token_file).unwrap();
    let token = initial_token.as_str();
    assert_eq!(initial["wallets"].as_array().unwrap().len(), 0);
    assert_eq!(initial["wallet_mode"], "none");
    assert!(initial["wallet_id"].is_null());
    assert!(initial["public_key"].is_null());
    let (code, created) = manage(
        &base,
        token,
        json!({"action":"create","name":"","revision":initial["wallet_revision"]}),
    )
    .await;
    assert_eq!(code, 200, "{created}");
    assert_eq!(created["wallet_mode"], "hot");
    assert_eq!(created["wallets"].as_array().unwrap().len(), 1);
    assert!(
        created["wallet_revision"].as_u64().unwrap() > initial["wallet_revision"].as_u64().unwrap()
    );
    let (code, backup) = manage(
        &base,
        token,
        json!({"action":"export","id":created["wallet_id"],"revision":created["wallet_revision"]}),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(backup["format"], "hashstash-private-v1");
    assert_eq!(backup.as_object().unwrap().len(), 3);
    let secret = node::parse_hash(backup["private_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        hex::encode(crypto::public_key(&secret).unwrap()),
        backup["public_key"]
    );
    let normal = session(&server).await;
    assert!(
        !normal
            .to_string()
            .contains(backup["private_key"].as_str().unwrap())
    );
    assert!(!normal.to_string().contains("private_key"));
    for request in [
        json!({"action":"import","name":"Bad","private_key":"00".repeat(32),"revision":created["wallet_revision"]}),
        json!({"action":"import","name":"Bad","private_key":backup["private_key"],"public_key":hex::encode(public),"revision":created["wallet_revision"]}),
        json!({"action":"watch","name":"Bad","public_key":"invalid","revision":created["wallet_revision"]}),
        json!({"action":"select","id":"missing","revision":created["wallet_revision"]}),
        json!({"action":"create","name":"Extra","secret":"ignored?","revision":created["wallet_revision"]}),
    ] {
        assert_eq!(manage(&base, token, request).await.0, 400);
        assert_eq!(session(&server).await, normal);
    }
    let (code,duplicate) = manage(&base,token,json!({"action":"import","name":"Replacement name","private_key":backup["private_key"],"public_key":backup["public_key"],"revision":created["wallet_revision"]})).await;
    assert_eq!(code, 200);
    assert_eq!(duplicate, created);
    let (code,watched) = manage(&base,token,json!({"action":"watch","name":"Offline","public_key":backup["public_key"],"revision":created["wallet_revision"]})).await;
    assert_eq!(code, 200);
    assert_eq!(watched["wallet_mode"], "watch");
    assert_eq!(watched["wallets"].as_array().unwrap().len(), 2);
    assert_ne!(watched["wallet_id"], created["wallet_id"]);
    assert_eq!(watched["public_key"], created["public_key"]);
    assert_eq!(manage(&base,token,json!({"action":"export","id":watched["wallet_id"],"revision":watched["wallet_revision"]})).await.0,400);
    assert_eq!(node.status().unwrap(), chain_before);
    server.stop().await;
    drop(node);
    let reopened = Node::open(&path, Config::devnet(), public)
        .unwrap()
        .with_wallet([70; 32])
        .unwrap();
    let server = node::serve(reopened, options()).await.unwrap();
    let restored = session(&server).await;
    for field in [
        "wallet_id",
        "wallet_revision",
        "wallets",
        "public_key",
        "wallet_mode",
        "wallet_enabled",
    ] {
        assert_eq!(restored[field], watched[field]);
    }
    assert!(restored.get("token").is_none());
    assert_ne!(
        std::fs::read_to_string(&server.session_token_file).unwrap(),
        initial_token
    );
    assert!(path.with_extension("wallets.sqlite").exists());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_revision_wrong_sender_and_watch_selection_never_sign() {
    let dir = tempfile::tempdir().unwrap();
    let secret = [71; 32];
    let public = crypto::public_key(&secret).unwrap();
    let public_hex = hex::encode(public);
    let node = Node::open(&dir.path().join("chain.sqlite"), Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    for _ in 0..20 {
        node.mine(100_000).unwrap();
    }
    let server = node::serve(node.clone(), options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let hot = session(&server).await;
    let token = &std::fs::read_to_string(&server.session_token_file).unwrap();
    assert_eq!(
        hot["wallets"].as_array().unwrap().len(),
        1,
        "fresh hot seed adds only the requested entry"
    );
    let (code,watch) = manage(&base,token,json!({"action":"watch","name":"Same account offline","public_key":public_hex,"revision":hot["wallet_revision"]})).await;
    assert_eq!(code, 200);
    assert_eq!(
        sign(
            &base,
            token,
            donation(&public_hex, &watch["wallet_revision"])
        )
        .await
        .0,
        403
    );
    let (code, selected) = manage(
        &base,
        token,
        json!({"action":"select","id":hot["wallet_id"],"revision":watch["wallet_revision"]}),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(
        sign(&base, token, donation(&public_hex, &hot["wallet_revision"]))
            .await
            .0,
        400
    );
    assert_eq!(
        sign(
            &base,
            token,
            donation(
                &hex::encode(crypto::public_key(&[72; 32]).unwrap()),
                &selected["wallet_revision"]
            )
        )
        .await
        .0,
        400
    );
    assert_eq!(
        manage(
            &base,
            token,
            json!({"action":"export","id":hot["wallet_id"],"revision":hot["wallet_revision"]})
        )
        .await
        .0,
        400
    );
    let mut missing = donation(&public_hex, &selected["wallet_revision"]);
    missing.as_object_mut().unwrap().remove("expected_sender");
    assert_eq!(sign(&base, token, missing).await.0, 400);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    assert_eq!(
        sign(
            &base,
            token,
            donation(&public_hex, &selected["wallet_revision"])
        )
        .await
        .0,
        200
    );
    node.mine(100_000).unwrap();
    for _ in 0..8 {
        let current = session(&server).await;
        let (signed, switched) = tokio::join!(
            sign(
                &base,
                token,
                donation(&public_hex, &current["wallet_revision"])
            ),
            manage(
                &base,
                token,
                json!({"action":"select","id":watch["wallet_id"],"revision":current["wallet_revision"]})
            )
        );
        assert_eq!(switched.0, 200);
        assert!([200, 400, 403].contains(&signed.0));
        let pool = node.rpc("mempool", json!({})).unwrap();
        for transaction in pool.as_array().unwrap() {
            assert_eq!(transaction["body"]["sender"], json!(public));
        }
        node.mine(100_000).unwrap();
        let switched = session(&server).await;
        assert_eq!(manage(&base,token,json!({"action":"select","id":hot["wallet_id"],"revision":switched["wallet_revision"]})).await.0,200);
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manager_rejects_missing_token_and_foreign_origin_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let public = crypto::public_key(&[73; 32]).unwrap();
    let node = Node::open(&dir.path().join("chain.sqlite"), Config::devnet(), public).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let before = session(&server).await;
    let request = json!({"action":"create","name":"Wallet","revision":before["wallet_revision"]});
    assert_eq!(manage(&base, "", request.clone()).await.0, 403);
    let response = reqwest::Client::new()
        .post(format!("{base}/api/wallet/manage"))
        .header("Origin", "https://foreign.invalid")
        .header(
            "X-Hashstash-Token",
            std::fs::read_to_string(&server.session_token_file).unwrap(),
        )
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(session(&server).await, before);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_store_stays_empty_across_plain_restarts_and_each_first_action_adds_one_wallet() {
    let public = crypto::public_key(&[74; 32]).unwrap();
    let imported_secret = [75; 32];
    let imported_public = hex::encode(crypto::public_key(&imported_secret).unwrap());
    for action in ["create", "import", "watch"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let node = Node::open(&path, Config::devnet(), public).unwrap();
        let snapshot = node.rpc("snapshot", json!({})).unwrap();
        assert_eq!(snapshot["status"]["height"], 0);
        for field in ["account", "pass", "fail"] {
            assert!(snapshot[field].is_null());
        }
        let server = node::serve(node, options()).await.unwrap();
        let initial = session(&server).await;
        assert_eq!(initial["wallets"], json!([]));
        assert_eq!(initial["wallet_revision"], 0);
        server.stop().await;
        // A restart without wallet flags never recreates the mining account.
        let node = Node::open(&path, Config::devnet(), public).unwrap();
        let server = node::serve(node, options()).await.unwrap();
        let base = format!("http://{}", server.rpc);
        let empty = session(&server).await;
        assert_eq!(empty["wallet_mode"], "none");
        assert_eq!(empty["wallets"], json!([]));
        assert_eq!(empty["wallet_enabled"], false);
        assert!(empty["wallet_id"].is_null() && empty["public_key"].is_null());
        let mut request = json!({"action":action,"name":"","revision":empty["wallet_revision"]});
        if action == "import" {
            request["private_key"] = json!(hex::encode(imported_secret));
        }
        if action == "watch" {
            request["public_key"] = json!(imported_public);
        }
        let token = std::fs::read_to_string(&server.session_token_file).unwrap();
        let (code, first) = manage(&base, &token, request).await;
        assert_eq!(code, 200, "{first}");
        assert_eq!(first["wallets"].as_array().unwrap().len(), 1);
        assert_eq!(first["wallet_revision"], 1);
        assert_eq!(
            first["wallet_mode"],
            if action == "watch" { "watch" } else { "hot" }
        );
        if action != "create" {
            assert_eq!(first["public_key"], imported_public);
        }
        server.stop().await;
        // Once the store holds a wallet, startup flags keep its selection.
        let node = Node::open(&path, Config::devnet(), public)
            .unwrap()
            .with_wallet([74; 32])
            .unwrap();
        let server = node::serve(node, options()).await.unwrap();
        let restored = session(&server).await;
        for field in [
            "wallet_id",
            "public_key",
            "wallet_mode",
            "wallet_revision",
            "wallets",
        ] {
            assert_eq!(restored[field], first[field]);
        }
        server.stop().await;
    }
}

/// A first start that stopped before its flags applied, or ran without
/// them, leaves an empty store; later startup flags still seed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_flags_seed_a_store_left_empty_by_an_earlier_start() {
    let secret = [79; 32];
    let public = crypto::public_key(&secret).unwrap();
    for hot in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        drop(Node::open(&path, Config::devnet(), public).unwrap());
        let node = Node::open(&path, Config::devnet(), public).unwrap();
        let node = if hot {
            node.with_wallet(secret).unwrap()
        } else {
            node.with_watch_key(public).unwrap()
        };
        let server = node::serve(node, options()).await.unwrap();
        let seeded = session(&server).await;
        assert_eq!(seeded["wallets"].as_array().unwrap().len(), 1);
        assert_eq!(seeded["public_key"], hex::encode(public));
        assert_eq!(seeded["wallet_mode"], if hot { "hot" } else { "watch" });
        assert_eq!(seeded["wallet_revision"], 1);
        server.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_fresh_hot_and_watch_seeds_remain_available() {
    let secret = [76; 32];
    let public = crypto::public_key(&secret).unwrap();
    for hot in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let node = Node::open(&path, Config::devnet(), public).unwrap();
        let node = if hot {
            node.with_wallet(secret).unwrap()
        } else {
            node.with_watch_key(public).unwrap()
        };
        let server = node::serve(node, options()).await.unwrap();
        let selected = session(&server).await;
        assert_eq!(selected["wallets"].as_array().unwrap().len(), 1);
        assert_eq!(selected["public_key"], hex::encode(public));
        assert_eq!(selected["wallet_mode"], if hot { "hot" } else { "watch" });
        server.stop().await;
        let node = Node::open(&path, Config::devnet(), public).unwrap();
        let server = node::serve(node, options()).await.unwrap();
        let restored = session(&server).await;
        assert_eq!(restored["wallets"], selected["wallets"]);
        assert_eq!(restored["wallet_id"], selected["wallet_id"]);
        server.stop().await;
    }
}

#[test]
fn rpc_mining_recipient_changes_payout_with_valid_state_but_keeps_default_miner() {
    use hashstash::{
        chain::Chain,
        codec, math,
        types::{Amount, Block},
    };
    let dir = tempfile::tempdir().unwrap();
    let configured = crypto::public_key(&[77; 32]).unwrap();
    let recipient = crypto::public_key(&[78; 32]).unwrap();
    let config = Config::devnet();
    let node = Node::open(&dir.path().join("chain.sqlite"), config.clone(), configured).unwrap();
    assert_eq!(node.template().unwrap().miner, configured);
    let before = node.status().unwrap();
    for invalid in [
        json!(null),
        json!(42),
        json!("invalid"),
        json!(hex::encode([0; 32])),
    ] {
        assert!(
            node.rpc("mine", json!({"recipient":invalid,"attempts":100_000}))
                .is_err()
        );
        assert_eq!(node.status().unwrap(), before);
    }
    node.rpc(
        "mine",
        json!({"recipient":hex::encode(recipient),"count":3,"attempts":100_000}),
    )
    .unwrap();
    let mut replica = Chain::open(&dir.path().join("replica.sqlite"), config).unwrap();
    let mut subsidy = Amount::from(0u32);
    for height in 1..=3 {
        let block: Block =
            serde_json::from_value(node.rpc("getblock", json!({"height":height})).unwrap())
                .unwrap();
        assert_eq!(block.miner, recipient);
        subsidy += math::work(&math::target_from_bits(block.header.bits).unwrap());
        assert!(replica.submit(block, node::now()).unwrap());
    }
    assert_eq!(
        node.status().unwrap()["state_root"],
        hex::encode(replica.tip_state().root())
    );
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        subsidy.to_string()
    );
    assert!(
        node.rpc("account", json!({"key":hex::encode(configured)}))
            .is_err()
    );
    assert_eq!(node.template().unwrap().miner, configured);
    let default_block = node.mine(100_000).unwrap();
    assert_eq!(default_block.miner, configured);
    assert_eq!(
        codec::block_hash(&default_block),
        node::parse_hash(node.status().unwrap()["tip"].as_str().unwrap()).unwrap()
    );
    let snapshot = node.rpc("snapshot", json!({})).unwrap();
    for field in ["account", "pass", "fail"] {
        assert!(snapshot[field].is_null());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_identity_is_never_a_saved_seeded_or_imported_server_wallet() {
    use hashstash::peer_auth::Policy;
    let dir = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[73; 32]).unwrap();
    let peer_secret = [74; 32];
    let peer = crypto::public_key(&peer_secret).unwrap();
    let identity = || Policy::discovery(peer_secret, vec![]).unwrap();

    // An account saved by an earlier start, before the identity was configured.
    let saved = dir.path().join("saved.sqlite");
    drop(
        Node::open(&saved, Config::devnet(), miner)
            .unwrap()
            .with_watch_key(peer)
            .unwrap(),
    );
    let reopened = Node::open(&saved, Config::devnet(), miner).unwrap();
    let error = reopened.with_peer_auth(identity()).err().unwrap();
    assert!(error.to_string().contains("peer identity"), "{error}");

    let node = Node::open(&dir.path().join("fresh.sqlite"), Config::devnet(), miner)
        .unwrap()
        .with_peer_auth(identity())
        .unwrap();
    assert!(node.clone().with_wallet(peer_secret).is_err());
    assert!(node.clone().with_watch_key(peer).is_err());
    let server = node::serve(node.clone(), options()).await.unwrap();
    let base = format!("http://{}", server.rpc);
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    let empty = session(&server).await;
    for request in [
        json!({"action":"import","private_key":hex::encode(peer_secret),"revision":empty["wallet_revision"]}),
        json!({"action":"watch","public_key":hex::encode(peer),"revision":empty["wallet_revision"]}),
    ] {
        let (code, reply) = manage(&base, &token, request).await;
        assert_eq!(code, 400, "{reply}");
    }
    assert_eq!(session(&server).await, empty);
    let (code, _) = manage(
        &base,
        &token,
        json!({"action":"watch","public_key":hex::encode(miner),"revision":empty["wallet_revision"]}),
    )
    .await;
    assert_eq!(code, 200);
    server.stop().await;
}
