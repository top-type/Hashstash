//! The private RPC answers a request it refuses on admission grounds with a
//! status and a time to retry (a connection refused before its session
//! starts, once per address and wait), the documented local wallet load fits
//! its budgets, and other loopback addresses cannot multiply them.
use hashstash::{
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    time::timeout,
};

fn options() -> ServerOptions {
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        p2p: zero,
        stratum: zero,
        ..Default::default()
    }
}

fn retry_after(response: &reqwest::Response) -> u64 {
    response.headers()["Retry-After"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// A fee quote priced by its client-chosen grant-payments list, one work unit
/// per element, charged before the list is validated (and refused).
fn priced_quote(units: usize) -> Value {
    json!({"jsonrpc":"2.0","id":7,"method":"fee_quote","params":{
        "operation":{"Propose":{"proposal":{"Grant":{"payments":vec![0; units]}}}}
    }})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_documented_wallet_load_is_never_refused_by_rpc_admission() {
    // test_load.py's waves: 64 wallet-signed self-payments, then a block.
    // Each submission used to be charged a full 4,096-entry pool selection,
    // so about 260 of them spent the whole 1,048,576-unit work burst and the
    // node closed the next connection without an answer.
    let directory = tempfile::tempdir().unwrap();
    let secret = [121; 32];
    let public = crypto::public_key(&secret).unwrap();
    let database = directory.path().join("chain.sqlite");
    let node = Node::open(&database, Config::devnet(), public)
        .unwrap()
        .with_wallet(secret)
        .unwrap();
    const WAVES: usize = 10;
    const PER_WAVE: usize = 64;
    // Every wave's inputs and fees come from its block's opening balance.
    let required = (PER_WAVE * (2 + WAVES)) as u64;
    let ordinary = || {
        node.rpc("account", json!({"key":hex::encode(public)}))
            .ok()
            .and_then(|a| a["account"]["ordinary"].as_str()?.parse::<u64>().ok())
            .unwrap_or(0)
    };
    for _ in 0..5000 {
        if ordinary() >= required {
            break;
        }
        node.mine(100_000).unwrap();
    }
    assert!(
        ordinary() >= required,
        "fixture mining did not fund the waves"
    );
    let server = node::serve(node.clone(), options()).await.unwrap();
    let url = format!("http://{}", server.rpc);
    let token = std::fs::read_to_string(&server.session_token_file).unwrap();
    let client = reqwest::Client::new();
    let session: Value = client
        .get(format!("{url}/api/session"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = json!({"operation":{"TransferExact":{"recipient":public,"amount":"1"}},
        "extra_fee":"0","expiry_blocks":100,"expected_sender":hex::encode(public),
        "wallet_revision":session["wallet_revision"]});
    for wave in 0..WAVES {
        for index in 0..PER_WAVE {
            let response = client
                .post(format!("{url}/api/wallet"))
                .header("X-Hashstash-Token", &token)
                .json(&body)
                .send()
                .await
                .unwrap_or_else(|e| panic!("wave {wave} submission {index} dropped: {e}"));
            let status = response.status();
            let reply: Value = response.json().await.unwrap();
            assert_eq!(status, 200, "wave {wave} submission {index}: {reply}");
            assert!(reply["transaction_id"].is_string(), "{reply}");
        }
        assert_eq!(node.status().unwrap()["mempool"], PER_WAVE);
        node.mine(100_000).unwrap();
        assert_eq!(node.status().unwrap()["mempool"], 0);
        // Waves are paced by relay and mining; the request budget of 512
        // units per second (two per HTTP request) is not under test here.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exhausted_rpc_budget_is_answered_with_429_and_a_time_to_retry() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[122; 32]).unwrap();
    let database = directory.path().join("chain.sqlite");
    let node = Node::open(&database, Config::devnet(), miner).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let rpc = format!("http://{}/rpc", server.rpc);
    let client = reqwest::Client::new();
    // About 60,000 units each: the 1,048,576-unit burst admits about 17.
    let expensive = priced_quote(60_000);
    let mut admitted = 0;
    let refused = loop {
        let response = client
            .post(&rpc)
            .json(&expensive)
            .send()
            .await
            .expect("an admission refusal is answered, never dropped");
        if response.status() != 200 {
            break response;
        }
        admitted += 1;
        assert!(admitted < 64, "the work budget never refused");
    };
    let refused_at = Instant::now();
    assert!(admitted >= 16, "{admitted}");
    assert_eq!(refused.status(), 429);
    // The charge refills in under half a second; whole seconds round up.
    let wait = retry_after(&refused);
    assert!((1..=2).contains(&wait), "{wait}");
    let reply: Value = refused.json().await.unwrap();
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["error"]["message"], "network rate budget exhausted");
    assert!(reply.get("result").is_none());
    // The refusal started the address's first 250 ms cooldown. A new
    // connection during it is answered before its request is read.
    let cooled = client
        .post(&rpc)
        .json(&json!({"jsonrpc":"2.0","id":8,"method":"status","params":{}}))
        .send()
        .await
        .expect("a cooldown refusal is answered, never dropped");
    if refused_at.elapsed() < Duration::from_millis(200) {
        assert_eq!(cooled.status(), 429);
        assert_eq!(retry_after(&cooled), 1);
        let reply: Value = cooled.json().await.unwrap();
        assert_eq!(reply["error"]["message"], "temporary network cooldown");
    }
    // A client that waits as told is served.
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let served = client
        .post(&rpc)
        .json(&json!({"jsonrpc":"2.0","id":9,"method":"status","params":{}}))
        .send()
        .await
        .unwrap();
    assert_eq!(served.status(), 200);
    assert_eq!(served.json::<Value>().await.unwrap()["result"]["height"], 0);
    server.stop().await;
}

/// An unfinished request from `host`, which holds one private RPC session.
async fn hold_session(rpc: SocketAddr, host: u8) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::from(([127, 0, 0, host], 0)))
        .unwrap();
    let mut stream = socket.connect(rpc).await.unwrap();
    stream.write_all(b"POST /rpc HTTP/1.1\r\n").await.unwrap();
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_refused_before_their_session_starts_are_answered() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[123; 32]).unwrap();
    let database = directory.path().join("chain.sqlite");
    let node = Node::open(&database, Config::devnet(), miner).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let rpc = format!("http://{}/rpc", server.rpc);
    // Eight other loopback addresses hold every private RPC session, so
    // 127.0.0.1 is refused for busy sessions, not for its own quota.
    let mut held = Vec::new();
    for host in 2..=9 {
        held.push(hold_session(server.rpc, host).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Without a well-formed request line, nothing is answered.
    let mut bare = TcpStream::connect(server.rpc).await.unwrap();
    bare.write_all(b"\r\n").await.unwrap();
    let mut answer = Vec::new();
    let _ = timeout(Duration::from_secs(5), bare.read_to_end(&mut answer))
        .await
        .expect("an unanswered refusal is closed");
    assert!(answer.is_empty(), "{}", String::from_utf8_lossy(&answer));
    // That attempt used this address's answer for the next second.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let client = reqwest::Client::new();
    let status = json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}});
    let busy = client
        .post(&rpc)
        .json(&status)
        .send()
        .await
        .expect("a busy listener answers instead of resetting the connection");
    assert_eq!(busy.status(), 503);
    assert_eq!(retry_after(&busy), 1);
    assert_eq!(
        busy.json::<Value>().await.unwrap()["error"]["message"],
        "HTTP sessions busy"
    );
    // One answer per address and Retry-After: an attempt before it has
    // passed is closed unanswered, as every refusal used to be.
    assert!(client.post(&rpc).json(&status).send().await.is_err());
    // The command-line client reports the node's message and wait.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let cli = node::RpcClient::new(&rpc, false).unwrap();
    let error = cli
        .call("status", json!({}), node::RpcLimits::SMALL)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("HTTP 503, retry after 1 s") && error.contains("HTTP sessions busy"),
        "{error}"
    );
    drop(held);
    // A client that waits as told is answered each time, and served once
    // the closed sessions have returned their slots.
    let mut served = None;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let response = client.post(&rpc).json(&status).send().await.unwrap();
        if response.status() == 200 {
            served = Some(response);
            break;
        }
        assert_eq!(response.status(), 503);
    }
    let served = served.expect("sessions were released");
    assert_eq!(served.json::<Value>().await.unwrap()["result"]["height"], 0);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_address_past_its_connection_quota_is_told_when_to_return() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[124; 32]).unwrap();
    let database = directory.path().join("chain.sqlite");
    let node = Node::open(&database, Config::devnet(), miner).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let rpc = format!("http://{}/rpc", server.rpc);
    // Admission runs before session capacity is taken, so an address
    // holding its eight connections hears about its own quota.
    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(hold_session(server.rpc, 1).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let status = json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}});
    let client = reqwest::Client::new();
    let refused = client.post(&rpc).json(&status).send().await.unwrap();
    assert_eq!(refused.status(), 429);
    assert_eq!(retry_after(&refused), 1);
    assert_eq!(
        refused.json::<Value>().await.unwrap()["error"]["message"],
        "per-address connection limit"
    );
    drop(held);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let served = client.post(&rpc).json(&status).send().await.unwrap();
    assert_eq!(served.status(), 200);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn other_loopback_addresses_share_one_rpc_budget() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[125; 32]).unwrap();
    let database = directory.path().join("chain.sqlite");
    let node = Node::open(&database, Config::devnet(), miner).unwrap();
    let server = node::serve(node, options()).await.unwrap();
    let rpc = format!("http://{}/rpc", server.rpc);
    // A local process that binds 127.0.0.2 and beyond gets four address
    // budgets for all of loopback, not one per address. Each request costs
    // about 75,000 units, so one address's burst admits 13 and loopback's 55,
    // plus what refills meanwhile.
    let expensive = priced_quote(75_000);
    let mut admitted = Vec::new();
    let mut fresh_refused = false;
    for host in 2..=12u8 {
        let client = reqwest::Client::builder()
            .local_address(std::net::IpAddr::from([127, 0, 0, host]))
            .build()
            .unwrap();
        let mut count = 0;
        let refused = loop {
            let response = client.post(&rpc).json(&expensive).send().await.unwrap();
            if response.status() != 200 {
                break response;
            }
            count += 1;
            assert!(count < 32, "127.0.0.{host} was never refused");
        };
        assert_eq!(refused.status(), 429);
        let reply: Value = refused.json().await.unwrap();
        assert_eq!(reply["error"]["message"], "network rate budget exhausted");
        fresh_refused |= count == 0;
        admitted.push(count);
    }
    // Separate budgets would admit about as many from every address. The
    // shared one admits about four addresses' worth and its refill, so an
    // address whose own budget is untouched is refused at its first request.
    let total: usize = admitted.iter().sum();
    assert!(total < 8 * admitted[0], "{admitted:?}");
    assert!(fresh_refused, "{admitted:?}");
    // The operator's own requests wait for that refill, without a cooldown.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let status = json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}});
    let served = reqwest::Client::new().post(&rpc).json(&status).send().await.unwrap();
    assert_eq!(served.status(), 200);
    server.stop().await;
}
