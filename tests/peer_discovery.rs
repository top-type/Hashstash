//! Discovery fixtures use fresh disposable databases and local listeners only.
use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    peer_auth::{PeerPin, Policy},
    peer_discovery::{self, Options},
};
use std::{
    net::{SocketAddr, TcpListener},
    path::Path,
    time::Duration,
};
use tokio::time::{sleep, timeout};

fn reserve() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}
fn options(address: SocketAddr) -> ServerOptions {
    ServerOptions {
        rpc: "127.0.0.1:0".parse().unwrap(),
        p2p: address,
        stratum_enabled: false,
        ..Default::default()
    }
}
fn open(path: &Path, id: u8, address: SocketAddr, seeds: Vec<String>) -> Node {
    Node::open(
        path,
        Config::devnet(),
        crypto::public_key(&[id + 100; 32]).unwrap(),
    )
    .unwrap()
    .with_peer_auth(Policy::discovery([id; 32], vec![]).unwrap())
    .unwrap()
    .with_discovery(Options {
        enabled: true,
        seeds,
        advertise: Some(address),
        allow_private: true,
    })
    .unwrap()
}
async fn until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(15), async {
        while !condition() {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("discovery fixture convergence");
}
fn verified(node: &Node, address: SocketAddr) -> bool {
    node.peer_status().unwrap()["discovery"]["peers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["address"] == address.to_string() && e["last_success"].as_u64().unwrap() > 0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_from_one_dns_seed_learn_another_survive_seed_loss_and_restart_without_seed() {
    let dir = tempfile::tempdir().unwrap();
    let (ra, aa) = reserve();
    let (rb, ab) = reserve();
    let (rc, ac) = reserve();
    let b = open(&dir.path().join("b.sqlite"), 42, ab, vec![]);
    drop(rb);
    let sb = node::serve(b.clone(), options(ab)).await.unwrap();
    let a = open(&dir.path().join("a.sqlite"), 41, aa, vec![ab.to_string()]);
    drop(ra);
    let sa = node::serve(a.clone(), options(aa)).await.unwrap();
    until(|| verified(&a, ab)).await;
    let cp = dir.path().join("c.sqlite");
    let c = open(&cp, 43, ac, vec![format!("localhost:{}", aa.port())]);
    drop(rc);
    let sc = node::serve(c.clone(), options(ac)).await.unwrap();
    until(|| verified(&c, ab)).await;
    assert_eq!(
        c.peer_status().unwrap()["transport"],
        "authenticated-discovery"
    );
    sa.stop().await;
    drop(a);
    b.mine(100_000).unwrap();
    until(|| c.status().unwrap()["tip"] == b.status().unwrap()["tip"]).await;
    sc.stop().await;
    drop(c);
    let book = peer_discovery::path_for(&cp, Config::devnet().chain_id());
    assert!(book.is_file());
    let c = open(&cp, 43, ac, vec![]);
    let sc = node::serve(c.clone(), options(ac)).await.unwrap();
    b.mine(100_000).unwrap();
    until(|| c.status().unwrap()["tip"] == b.status().unwrap()["tip"] && verified(&c, ab)).await;
    sc.stop().await;
    sb.stop().await;
}

#[tokio::test]
async fn closed_pins_cannot_be_accidentally_opened_by_discovery_options() {
    let dir = tempfile::tempdir().unwrap();
    let (_, addr) = reserve();
    let n = Node::open(
        &dir.path().join("closed.sqlite"),
        Config::devnet(),
        crypto::public_key(&[90; 32]).unwrap(),
    )
    .unwrap()
    .with_peer_auth(
        Policy::new(
            [91; 32],
            vec![PeerPin {
                address: addr,
                public_key: crypto::public_key(&[92; 32]).unwrap(),
            }],
        )
        .unwrap(),
    )
    .unwrap()
    .with_discovery(Options {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    let mut opt = options("127.0.0.1:0".parse().unwrap());
    opt.peers.push(addr);
    assert!(node::serve(n, opt).await.is_err());
}

#[tokio::test]
async fn discovery_requires_authenticated_policy_and_public_advertisement() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(
        &dir.path().join("plain.sqlite"),
        Config::devnet(),
        crypto::public_key(&[90; 32]).unwrap(),
    )
    .unwrap()
    .with_discovery(Options {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    assert!(
        node::serve(node, options("127.0.0.1:0".parse().unwrap()))
            .await
            .is_err()
    );
    assert!(
        Options {
            enabled: true,
            advertise: Some("127.0.0.1:18481".parse().unwrap()),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}
