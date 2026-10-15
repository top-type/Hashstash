//! Isolated loopback authenticated peer synchronization; never connects to a public node.
use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    peer_auth::{PeerPin, Policy},
};
use std::{
    net::{SocketAddr, TcpListener as ReservedPort},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

fn options(address: SocketAddr, remote: SocketAddr) -> ServerOptions {
    ServerOptions {
        rpc: "127.0.0.1:0".parse().unwrap(),
        p2p: address,
        stratum: "127.0.0.1:0".parse().unwrap(),
        peers: vec![remote],
        ..Default::default()
    }
}
fn policy(secret: u8, remote: u8, address: SocketAddr) -> std::sync::Arc<Policy> {
    Policy::new(
        [secret; 32],
        vec![PeerPin {
            address,
            public_key: crypto::public_key(&[remote; 32]).unwrap(),
        }],
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_nodes_sync_and_recover_after_hostile_legacy_and_truncated_clients() {
    let directory = tempfile::tempdir().unwrap();
    let ra = ReservedPort::bind("127.0.0.1:0").unwrap();
    let rb = ReservedPort::bind("127.0.0.1:0").unwrap();
    let aa = ra.local_addr().unwrap();
    let ab = rb.local_addr().unwrap();
    let a = Node::open(
        &directory.path().join("a.db"),
        Config::devnet(),
        crypto::public_key(&[91; 32]).unwrap(),
    )
    .unwrap()
    .with_peer_auth(policy(81, 82, ab))
    .unwrap();
    let b = Node::open(
        &directory.path().join("b.db"),
        Config::devnet(),
        crypto::public_key(&[92; 32]).unwrap(),
    )
    .unwrap()
    .with_peer_auth(policy(82, 81, aa))
    .unwrap();
    a.mine(100_000).unwrap();
    a.mine(100_000).unwrap();
    drop(ra);
    drop(rb);
    let sa = node::serve(a.clone(), options(aa, ab)).await.unwrap();
    let sb = node::serve(b.clone(), options(ab, aa)).await.unwrap();
    timeout(Duration::from_secs(8), async {
        loop {
            if a.status().unwrap()["tip"] == b.status().unwrap()["tip"]
                && a.peer_status().unwrap()["peers"][0]["reachable"] == true
                && b.peer_status().unwrap()["peers"][0]["reachable"] == true
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(a.peer_status().unwrap()["transport"], "pinned-signed");
    assert_eq!(a.peer_status().unwrap()["encrypted"], false);
    let before = a.status().unwrap();
    let mut attacker = TcpStream::connect(sa.p2p).await.unwrap();
    attacker.write_all(&[b'{'; 104]).await.unwrap();
    let mut byte = [0];
    let closed = timeout(Duration::from_secs(2), attacker.read(&mut byte))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    drop(attacker);
    assert_eq!(a.status().unwrap()["tip"], before["tip"]);
    // A partial unauthenticated greeting closes on disconnect; it never reaches block decoding.
    let mut partial = TcpStream::connect(sa.p2p).await.unwrap();
    partial.write_all(b"HSP2PAUT").await.unwrap();
    drop(partial);
    b.mine(100_000).unwrap();
    timeout(Duration::from_secs(8), async {
        loop {
            if a.status().unwrap()["tip"] == b.status().unwrap()["tip"] {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        a.peer_status().unwrap()["peers"][0]["consecutive_failures"],
        0
    );
    sa.stop().await;
    sb.stop().await;
}

#[tokio::test]
async fn authenticated_startup_rejects_partial_pin_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let address = "127.0.0.1:12345".parse().unwrap();
    let node = Node::open(
        &directory.path().join("a.db"),
        Config::devnet(),
        crypto::public_key(&[91; 32]).unwrap(),
    )
    .unwrap()
    .with_peer_auth(policy(81, 82, address))
    .unwrap();
    let result = node::serve(
        node,
        ServerOptions {
            rpc: "127.0.0.1:0".parse().unwrap(),
            p2p: "127.0.0.1:0".parse().unwrap(),
            stratum: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        },
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn observer_mode_never_binds_stratum_and_still_serves_and_stops_cleanly() {
    let directory = tempfile::tempdir().unwrap();
    let node = Node::open(
        &directory.path().join("observer.db"),
        Config::devnet(),
        crypto::public_key(&[91; 32]).unwrap(),
    )
    .unwrap();
    // This port is already occupied. Observer startup must not try to bind it.
    let occupied = ReservedPort::bind("127.0.0.1:0").unwrap();
    let options = ServerOptions {
        rpc: "127.0.0.1:0".parse().unwrap(),
        p2p: "127.0.0.1:0".parse().unwrap(),
        stratum: occupied.local_addr().unwrap(),
        stratum_enabled: false,
        ..Default::default()
    };
    let server = node::serve(node.clone(), options.clone()).await.unwrap();
    assert!(!server.stratum_enabled);
    let status = node::call_rpc(
        &format!("http://{}/rpc", server.rpc),
        "status",
        serde_json::json!({}),
    )
    .await
    .unwrap();
    assert_eq!(status["height"], 0);
    assert!(node::serve(node.clone(), options.clone()).await.is_err());
    server.stop().await;
    let restarted = node::serve(node, options).await.unwrap();
    assert!(!restarted.stratum_enabled);
    restarted.stop().await;
}
