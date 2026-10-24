//! The faucet's loopback node RPC must never be relayed through an environment
//! proxy. This binary changes process-wide proxy variables, so it holds one test.
use axum::{Json, Router, extract::State, routing::post};
use hashstash::{
    crypto,
    faucet::{self, FaucetConfig},
};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

async fn node(State(calls): State<Arc<AtomicUsize>>, Json(_): Json<Value>) -> Json<Value> {
    calls.fetch_add(1, Ordering::SeqCst);
    Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"test node"}}))
}

#[test]
fn faucet_node_rpc_ignores_environment_proxies() {
    // A refused local port stands in for a proxy the operator never intended.
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        // SAFETY: set before this single-test process starts any runtime thread.
        unsafe { std::env::set_var(name, "http://127.0.0.1:9") };
    }
    for name in ["NO_PROXY", "no_proxy"] {
        // SAFETY: as above; no other thread reads the environment yet.
        unsafe { std::env::remove_var(name) };
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc = listener.local_addr().unwrap();
        let routes = Router::new()
            .route("/rpc", post(node))
            .with_state(calls.clone());
        let node_task = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let secret = [43u8; 32];
        let key_file = dir.path().join("faucet.key");
        std::fs::write(
            &key_file,
            serde_json::to_vec(&json!({
                "secret": hex::encode(secret),
                "public": hex::encode(crypto::public_key(&secret).unwrap())
            }))
            .unwrap(),
        )
        .unwrap();
        // The faucet accepts only an owner-only key file: mode 0600 on Unix,
        // an owner-only access list on Windows, where a temporary folder may
        // let other accounts in.
        hashstash::local_files::restrict_to_owner(&key_file).unwrap();
        let server = faucet::serve(FaucetConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            rpc_url: format!("http://{rpc}/rpc"),
            chain_id: hex::encode([7u8; 32]),
            key_file,
            database: dir.path().join("claims.sqlite"),
            origins: vec!["https://faucet.proxy.test".into()],
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
            expiry_blocks: 2,
        })
        .await
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while calls.load(Ordering::SeqCst) == 0 {
            assert!(
                Instant::now() < deadline,
                "faucet RPC was not sent directly to the loopback node"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        server.stop().await;
        node_task.abort();
    });
}
