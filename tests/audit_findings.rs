//! Regressions for defects reproduced by the 2026-10-07 audit.
use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn long_competing_branches_sync_to_greater_work() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let a = Node::open(
        &dir.path().join("a.db"),
        c.clone(),
        crypto::public_key(&[41; 32]).unwrap(),
    )
    .unwrap();
    let b = Node::open(
        &dir.path().join("b.db"),
        c,
        crypto::public_key(&[42; 32]).unwrap(),
    )
    .unwrap();
    for _ in 0..40 {
        a.mine(100_000).unwrap();
    }
    for _ in 0..42 {
        b.mine(100_000).unwrap();
    }
    let b_before = b.status().unwrap();
    let zero = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        b.clone(),
        ServerOptions {
            rpc: zero,
            p2p: zero,
            stratum: zero,
            peers: vec![],
            stratum_password: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for _ in 0..5 {
        node::sync_peer(&a, server.p2p).await.unwrap();
    }
    let remote_32 = b.rpc("getblock", json!({"height":32})).unwrap();
    let remote_33 = b.rpc("getblock", json!({"height":33})).unwrap();
    let block32 = serde_json::from_value(remote_32).unwrap();
    let block33 = serde_json::from_value(remote_33).unwrap();
    let hash32 = hashstash::codec::block_hash(&block32);
    let hash33 = hashstash::codec::block_hash(&block33);
    assert!(
        a.rpc("getblock", json!({"hash":hex::encode(hash32)}))
            .is_ok()
    );
    assert!(
        a.rpc("getblock", json!({"hash":hex::encode(hash33)}))
            .is_ok()
    );
    assert_eq!(a.status().unwrap()["tip"], b_before["tip"]);
    assert_eq!(b.status().unwrap()["tip"], b_before["tip"]);
    assert_eq!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    server.stop().await;
}

#[test]
fn local_config_validation_rejects_size_overflow_without_panicking() {
    let mut c = Config::devnet();
    c.initial.block_bytes = u64::MAX;
    assert!(std::panic::catch_unwind(|| c.validate()).unwrap().is_err());
}

#[test]
fn timestamp_exhausted_genesis_is_rejected() {
    let mut c = Config::devnet();
    c.genesis_time = u32::MAX;
    assert!(c.validate().unwrap_err().to_string().contains("timestamp"));
}
