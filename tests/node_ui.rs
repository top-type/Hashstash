use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
};
use serde_json::{Value, json};
use std::net::SocketAddr;

fn options() -> ServerOptions {
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        p2p: zero,
        stratum: zero,
        peers: vec![],
        stratum_password: None,
        ..Default::default()
    }
}

#[tokio::test]
async fn adaptive_mining_batch_is_not_rejected_as_a_thousand_full_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let public = crypto::public_key(&[74; 32]).unwrap();
    let n = Node::open(
        &directory.path().join("batch.sqlite"),
        Config::testnet(),
        public,
    )
    .unwrap();
    let server = node::serve(n.clone(), options()).await.unwrap();
    // Zero attempts guarantees a normal mining-argument error, without doing
    // work or depending on a probabilistic PoW failure. Admission must succeed.
    let response: Value = reqwest::Client::new()
        .post(format!("http://{}/rpc", server.rpc))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"mine","params":{"count":1000,"attempts":0}}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        response["error"]["message"],
        "attempts must be 1..100000000"
    );
    assert_eq!(n.status().unwrap()["height"], 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_snapshot_stays_coherent_during_mining_and_matches_quote_context() {
    let directory = tempfile::tempdir().unwrap();
    let public = crypto::public_key(&[27; 32]).unwrap();
    let n = Node::open(
        &directory.path().join("snapshot.db"),
        Config::devnet(),
        public,
    )
    .unwrap();
    let empty = n
        .rpc("snapshot", json!({"key":hex::encode(public)}))
        .unwrap();
    assert!(empty["account"].is_null());
    let server = node::serve(n.clone(), options()).await.unwrap();
    let url = format!("http://{}/rpc", server.rpc);
    let miner = n.clone();
    let mining = tokio::task::spawn_blocking(move || {
        for _ in 0..160 {
            miner.mine(100_000).unwrap();
        }
    });
    let client = reqwest::Client::new();
    for _ in 0..160 {
        let response: Value = client.post(&url).json(&json!({"jsonrpc":"2.0","id":1,"method":"snapshot","params":{"key":hex::encode(public)}})).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
        let snapshot = &response["result"];
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(
            snapshot["status"]["state_root"],
            snapshot["governance"]["state_root"]
        );
        assert_eq!(
            snapshot["status"]["height"],
            snapshot["governance"]["height"]
        );
        assert_eq!(snapshot["status"]["clock"], snapshot["governance"]["clock"]);
        assert_eq!(
            snapshot["status"]["reserve"],
            snapshot["governance"]["world"]["reserve"]
        );
        assert_eq!(
            snapshot["status"]["settings"],
            snapshot["governance"]["settings"]
        );
        assert!(snapshot["pass"].is_null());
        assert!(snapshot["fail"].is_null());
    }
    mining.await.unwrap();
    let quote = n
        .rpc("quote", json!({"kind":"deposit","amount":"10"}))
        .unwrap();
    assert_eq!(quote["height"], n.status().unwrap()["height"]);
    let funded = n.rpc("grant_quote", json!({"amount":"1"})).unwrap();
    assert_eq!(funded["feasible"], false);
    server.stop().await;
}
async fn session(url: &str) -> Value {
    reqwest::get(format!("{url}/api/session"))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
/// Wallet clients read the token from the node's owner-only file.
fn session_token(server: &node::Server) -> String {
    std::fs::read_to_string(&server.session_token_file).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn embedded_assets_session_and_atomic_pending_wallet_nonces() {
    let d = tempfile::tempdir().unwrap();
    let secret = [11; 32];
    let public = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[12; 32]).unwrap();
    let n = Node::open(&d.path().join("wallet.db"), Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    for _ in 0..12 {
        n.mine(100_000).unwrap();
    }
    let server = node::serve(n.clone(), options()).await.unwrap();
    let url = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    for (path, mime) in [
        ("/", "text/html"),
        ("/app.js", "application/javascript"),
        ("/amounts.js", "application/javascript"),
        ("/style.css", "text/css"),
    ] {
        let response = client.get(format!("{url}{path}")).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            response.headers()["content-type"]
                .to_str()
                .unwrap()
                .starts_with(mime)
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        assert!(!response.bytes().await.unwrap().is_empty());
    }
    let s = session(&url).await;
    assert_eq!(s["wallet_enabled"], true);
    assert_eq!(s["public_key"], hex::encode(public));
    assert_eq!(s["miner"], hex::encode(public));
    let token = &session_token(&server);
    assert_eq!(token.len(), 64);
    assert!(s.get("token").is_none());
    assert!(!s.to_string().contains(&hex::encode(secret)));
    let send = |amount: &str| {
        client.post(format!("{url}/api/wallet")).header("Origin",&url).header("X-Hashstash-Token",token).json(&json!({"operation":{"TransferExact":{"recipient":recipient,"amount":amount}},"extra_fee":"0","expiry_blocks":100,"expected_sender":hex::encode(public),"wallet_revision":s["wallet_revision"]})).send()
    };
    let (a, b) = tokio::join!(send("4"), send("3"));
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.status(), 200);
    assert_eq!(b.status(), 200);
    let a: Value = a.json().await.unwrap();
    let b: Value = b.json().await.unwrap();
    assert_ne!(a["transaction_id"], b["transaction_id"]);
    let mempool = n.rpc("mempool", json!({})).unwrap();
    let nonces: Vec<_> = mempool
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["body"]["nonce"].as_u64().unwrap())
        .collect();
    assert_eq!(nonces, vec![0, 1]);
    // Clients learn the next nonce without downloading raw pending records.
    let pending = n
        .rpc("account", json!({"key":hex::encode(public)}))
        .unwrap();
    assert_eq!(pending["account"]["nonce"], 0);
    assert_eq!(pending["pending_nonce"], 2);
    n.mine(100_000).unwrap();
    assert_eq!(
        n.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "7"
    );
    let rpc: Value = client
        .post(format!("{url}/rpc"))
        .header("Origin", &url)
        .header("Sec-Fetch-Site", "same-origin")
        .json(&json!({"jsonrpc":"2.0","id":9,"method":"status","params":{}}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rpc["result"]["height"], 13);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_rejects_foreign_origins_hosts_and_missing_or_wrong_tokens() {
    let d = tempfile::tempdir().unwrap();
    let secret = [13; 32];
    let public = crypto::public_key(&secret).unwrap();
    let n = Node::open(&d.path().join("secure.db"), Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    let server = node::serve(n.clone(), options()).await.unwrap();
    let url = format!("http://{}", server.rpc);
    let client = reqwest::Client::new();
    let s = session(&url).await;
    let token = &session_token(&server);
    let body = json!({"operation":{"TransferExact":{"recipient":public,"amount":"1"}},"extra_fee":"0","expected_sender":hex::encode(public),"wallet_revision":s["wallet_revision"]});
    for header in [None, Some("incorrect-session-token")] {
        let mut request = client.post(format!("{url}/api/wallet")).json(&body);
        if let Some(token) = header {
            request = request.header("X-Hashstash-Token", token);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 403);
        assert!(
            response
                .json::<Value>()
                .await
                .unwrap()
                .get("error")
                .is_some()
        );
    }
    for path in ["/api/session", "/"] {
        let response = client
            .get(format!("{url}{path}"))
            .header("Origin", "https://attacker.invalid")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let response = client
            .get(format!("{url}{path}"))
            .header("Host", format!("attacker.invalid:{}", server.rpc.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
    }
    let response = client
        .post(format!("{url}/api/wallet"))
        .header("Origin", "http://attacker.invalid")
        .header("X-Hashstash-Token", token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .post(format!("{url}/api/wallet"))
        .header("Origin", &url)
        .header("X-Hashstash-Token", token)
        .header("Sec-Fetch-Site", "same-site")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .post(format!("{url}/rpc"))
        .header("Origin", "null")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"mine","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .get(format!("{url}/api/session"))
        .header("Host", format!("localhost:{}", server.rpc.port()))
        .header("Origin", format!("http://localhost:{}", server.rpc.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response = client
        .get(format!("{url}/api/session"))
        .header("Host", format!("localhost:{}", server.rpc.port()))
        .header("Origin", &url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(n.status().unwrap()["height"], 0);
    assert_eq!(n.status().unwrap()["mempool"], 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_key_starts_without_a_wallet_and_rpc_never_binds_publicly() {
    let d = tempfile::tempdir().unwrap();
    let secret = [14; 32];
    let public = crypto::public_key(&secret).unwrap();
    let n = Node::open(&d.path().join("readonly.db"), Config::devnet(), public).unwrap();
    let server = node::serve(n.clone(), options()).await.unwrap();
    let url = format!("http://{}", server.rpc);
    let s = session(&url).await;
    assert_eq!(s["wallet_enabled"], false);
    assert!(s["public_key"].is_null());
    assert!(s["wallet_id"].is_null());
    assert_eq!(s["wallet_mode"], "none");
    assert_eq!(s["wallets"], json!([]));
    let result=reqwest::Client::new().post(format!("{url}/api/wallet")).header("X-Hashstash-Token",session_token(&server)).json(&json!({"operation":{"TransferExact":{"recipient":public,"amount":"1"}},"extra_fee":"0"})).send().await.unwrap();
    assert_eq!(result.status(), 403);
    server.stop().await;
    let n = n.with_wallet(secret).unwrap();
    let mut public_options = options();
    public_options.rpc = "0.0.0.0:0".parse().unwrap();
    let result = node::serve(n, public_options).await;
    assert!(result.is_err());
    assert!(result.err().unwrap().to_string().contains("loopback"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarting_server_rotates_token_and_unfunded_wallet_fails_cleanly() {
    let d = tempfile::tempdir().unwrap();
    let secret = [15; 32];
    let public = crypto::public_key(&secret).unwrap();
    let n = Node::open(&d.path().join("restart.db"), Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    let first = node::serve(n.clone(), options()).await.unwrap();
    let first_url = format!("http://{}", first.rpc);
    let old_session = session(&first_url).await;
    let old_token = session_token(&first);
    let body = json!({"operation":{"TransferExact":{"recipient":public,"amount":"1"}},"extra_fee":"0","expected_sender":hex::encode(public),"wallet_revision":old_session["wallet_revision"]});
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{first_url}/api/wallet"))
        .header("X-Hashstash-Token", &old_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(
        response.json::<Value>().await.unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("has not been funded")
    );
    first.stop().await;
    for _ in 0..4 {
        n.mine(100_000).unwrap();
    }
    let second = node::serve(n.clone(), options()).await.unwrap();
    let url = format!("http://{}", second.rpc);
    let new_session = session(&url).await;
    assert_eq!(old_session["wallet_revision"], new_session["wallet_revision"]);
    let new_token = session_token(&second);
    assert_ne!(old_token, new_token);
    let response = client
        .post(format!("{url}/api/wallet"))
        .header("X-Hashstash-Token", &old_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(n.status().unwrap()["mempool"], 0);
    let response = client
        .post(format!("{url}/api/wallet"))
        .header("X-Hashstash-Token", &new_token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(n.status().unwrap()["mempool"], 1);
    second.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn loopback_clients_cannot_obtain_the_wallet_token_over_http() {
    let d = tempfile::tempdir().unwrap();
    let secret = [16; 32];
    let public = crypto::public_key(&secret).unwrap();
    let path = d.path().join("cookie.db");
    let n = Node::open(&path, Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    let server = node::serve(n.clone(), options()).await.unwrap();
    assert_eq!(server.session_token_file, node::session_token_path(&path));
    let url = format!("http://{}", server.rpc);
    let token = session_token(&server);
    assert_eq!(token.len(), 64);
    let client = reqwest::Client::new();
    // Any process reaching loopback still gets the page and session context,
    // but nothing it can fetch over HTTP carries the wallet token.
    for path in ["/api/session", "/", "/app.js"] {
        let text = client
            .get(format!("{url}{path}"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(!text.contains(&token), "{path}");
    }
    let s = session(&url).await;
    let export = json!({"action":"export","id":s["wallet_id"],"revision":s["wallet_revision"]});
    let refused = client
        .post(format!("{url}/api/wallet/manage"))
        .json(&export)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    assert!(!refused.text().await.unwrap().contains(&hex::encode(secret)));
    let exported: Value = client
        .post(format!("{url}/api/wallet/manage"))
        .header("X-Hashstash-Token", &token)
        .json(&export)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(exported["private_key"], hex::encode(secret));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&server.session_token_file)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
    }
    server.stop().await;
}
