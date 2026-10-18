use hashstash::{
    codec,
    config::Config,
    crypto, math,
    node::{self, Node, ServerOptions},
    types::*,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

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
fn signed(
    c: &Config,
    secret: &[u8; 32],
    nonce: u64,
    recipient: PublicKey,
    amount: u32,
) -> Transaction {
    crypto::sign(
        &c.chain_id(),
        &TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(secret).unwrap(),
            nonce,
            fee: 2u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
            expiry_blocks: 1000,
            operation: Operation::TransferExact {
                recipient,
                amount: amount.into(),
            },
        },
        secret,
    )
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_peer_propagation_reorg_mempool_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let secret = [1u8; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[3u8; 32]).unwrap();
    let other = crypto::public_key(&[2u8; 32]).unwrap();
    let a_path = dir.path().join("a.sqlite");
    let a = Node::open(&a_path, c.clone(), miner).unwrap();
    let b = Node::open(&dir.path().join("b.sqlite"), c.clone(), other).unwrap();
    let sa = node::serve(a.clone(), options()).await.unwrap();
    let sb = node::serve(b.clone(), options()).await.unwrap();
    let url = format!("http://{}/rpc", sa.rpc);
    node::call_rpc(&url, "mine", json!({"count":12}))
        .await
        .unwrap();
    node::sync_peer(&b, sa.p2p).await.unwrap();
    assert_eq!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    let tx = signed(&c, &secret, 0, recipient, 10);
    node::call_rpc(&url, "submittransaction", serde_json::to_value(tx).unwrap())
        .await
        .unwrap();
    node::sync_peer(&b, sa.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["mempool"], 1);
    b.mine(100_000).unwrap();
    node::sync_peer(&a, sb.p2p).await.unwrap();
    assert_eq!(
        a.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "10"
    );
    // Both nodes fork from height 13. The shorter fork's transfer must return to the pool.
    a.submit_transaction(signed(&c, &secret, 1, recipient, 4))
        .unwrap();
    a.mine(100_000).unwrap();
    b.mine(100_000).unwrap();
    b.mine(100_000).unwrap();
    assert_ne!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    node::sync_peer(&a, sb.p2p).await.unwrap();
    assert_eq!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    assert_eq!(a.status().unwrap()["mempool"], 1);
    assert_eq!(
        a.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "10"
    );
    a.mine(100_000).unwrap();
    node::sync_peer(&b, sa.p2p).await.unwrap();
    assert_eq!(
        b.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "14"
    );
    let expected = a.status().unwrap();
    sa.stop().await;
    sb.stop().await;
    drop(a);
    drop(b);
    let reopened = Node::open(&a_path, c, miner).unwrap();
    assert_eq!(reopened.status().unwrap()["tip"], expected["tip"]);
    assert_eq!(
        reopened.status().unwrap()["state_root"],
        expected["state_root"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_sync_crosses_batches_and_equal_height_fork() {
    let d = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let a = Node::open(
        &d.path().join("a.db"),
        c.clone(),
        crypto::public_key(&[4; 32]).unwrap(),
    )
    .unwrap();
    let b = Node::open(
        &d.path().join("b.db"),
        c,
        crypto::public_key(&[5; 32]).unwrap(),
    )
    .unwrap();
    let server = node::serve(a.clone(), options()).await.unwrap();
    for _ in 0..40 {
        a.mine(100_000).unwrap();
    }
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["height"], 32);
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["tip"], a.status().unwrap()["tip"]);
    a.mine(100_000).unwrap();
    b.mine(100_000).unwrap();
    let old = b.status().unwrap()["tip"].clone();
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(
        b.status().unwrap()["tip"],
        old,
        "equal work retains each local tip"
    );
    a.mine(100_000).unwrap();
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["tip"], a.status().unwrap()["tip"]);
    server.stop().await;
}

async fn read_json<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Value {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), r.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    serde_json::from_str(&line).unwrap()
}
async fn send<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, v: Value) {
    let mut b = serde_json::to_vec(&v).unwrap();
    b.push(b'\n');
    w.write_all(&b).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stratum_external_header_construction_version_rolling_and_submission() {
    let d = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let miner = crypto::public_key(&[6; 32]).unwrap();
    let n = Node::open(&d.path().join("stratum.db"), c, miner).unwrap();
    let server = node::serve(n.clone(), options()).await.unwrap();
    let stream = TcpStream::connect(server.stratum).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    send(&mut write,json!({"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":2}]})).await;
    let configure = read_json(&mut read).await;
    assert_eq!(configure["result"]["version-rolling"], true);
    send(
        &mut write,
        json!({"id":2,"method":"mining.subscribe","params":["hashstash-test"]}),
    )
    .await;
    let subscribe = read_json(&mut read).await;
    let extra1 = hex::decode(subscribe["result"][1].as_str().unwrap()).unwrap();
    assert_eq!(subscribe["result"][2], 4);
    send(
        &mut write,
        json!({"id":3,"method":"mining.authorize","params":["test.worker","x"]}),
    )
    .await;
    assert_eq!(read_json(&mut read).await["result"], true);
    assert_eq!(
        read_json(&mut read).await["method"],
        "mining.set_difficulty"
    );
    let notify = read_json(&mut read).await;
    assert_eq!(notify["method"], "mining.notify");
    let p = notify["params"].as_array().unwrap();
    // Reconstruct everything from the public Stratum wire data, without a node template.
    let extra2 = [0x12, 0x34, 0x56, 0x78];
    let mut coinbase = hex::decode(p[2].as_str().unwrap()).unwrap();
    coinbase.extend(extra1);
    coinbase.extend(extra2);
    coinbase.extend(hex::decode(p[3].as_str().unwrap()).unwrap());
    let mut root = crypto::sha256d(&coinbase);
    for sibling in p[4].as_array().unwrap() {
        let mut pair = root.to_vec();
        pair.extend(hex::decode(sibling.as_str().unwrap()).unwrap());
        root = crypto::sha256d(&pair);
    }
    let mut previous: Hash = hex::decode(p[1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for word in previous.chunks_exact_mut(4) {
        word.reverse();
    }
    let number = |v: &Value| u32::from_str_radix(v.as_str().unwrap(), 16).unwrap();
    let version_bits = 0x00002000;
    let mut header = Header {
        version: (number(&p[5]) & !0x1fffe000) | version_bits,
        previous,
        merkle_root: root,
        timestamp: number(&p[7]),
        bits: number(&p[6]),
        nonce: 0,
    };
    let target = math::target_from_bits(header.bits).unwrap();
    while math::check_pow(&header, &target).is_err() {
        header.nonce += 1;
    }
    send(&mut write,json!({"id":4,"method":"mining.submit","params":["test.worker",p[0],hex::encode(extra2),format!("{:08x}",header.timestamp),format!("{:08x}",header.nonce),format!("{:08x}",version_bits)]})).await;
    let result = read_json(&mut read).await;
    assert_eq!(result["result"], true, "{result}");
    assert_eq!(n.status().unwrap()["height"], 1);
    assert_eq!(
        n.status().unwrap()["tip"],
        hex::encode(crypto::sha256d(&codec::header_bytes(&header)))
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn different_genesis_and_browser_rpc_are_rejected() {
    let d = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let key = crypto::public_key(&[7; 32]).unwrap();
    let a = Node::open(&d.path().join("a"), c.clone(), key).unwrap();
    let mut other = c;
    other.network = "different-devnet".into();
    let b = Node::open(&d.path().join("b"), other, key).unwrap();
    let server = node::serve(a, options()).await.unwrap();
    assert!(node::sync_peer(&b, server.p2p).await.is_err());
    let events = b.rpc("peers", json!({})).unwrap();
    assert_eq!(events[0]["ok"], false);
    assert!(events[0]["error"].as_str().is_some_and(|s| !s.is_empty()));
    let response: Value = reqwest::Client::new()
        .post(format!("http://{}/rpc", server.rpc))
        .header("Origin", "https://untrusted.invalid")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"mine","params":{}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(response.get("error").is_some());
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn complete_mempool_relays_and_cached_template_tracks_every_revision() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262144;
    let secret = [81; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let a = Node::open(&dir.path().join("relay-a.db"), c.clone(), miner).unwrap();
    let b = Node::open(&dir.path().join("relay-b.db"), c.clone(), miner).unwrap();
    let server = node::serve(a.clone(), options()).await.unwrap();
    a.mine(100_000).unwrap();
    node::sync_peer(&b, server.p2p).await.unwrap();
    let empty = a.template().unwrap();
    assert!(empty.transactions.is_empty());
    for nonce in 0..node::MAX_MEMPOOL as u64 {
        a.submit_transaction(signed(&c, &secret, nonce, miner, 1))
            .unwrap();
    }
    let full = a.template().unwrap();
    assert_eq!(full.transactions.len(), node::MAX_MEMPOOL);
    assert_ne!(full.state_root, empty.state_root);
    assert_eq!(a.template().unwrap().state_root, full.state_root);
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["mempool"], node::MAX_MEMPOOL);
    assert_eq!(b.template().unwrap().state_root, full.state_root);
    a.mine(100_000).unwrap();
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["tip"], a.status().unwrap()["tip"]);
    assert_eq!(b.status().unwrap()["mempool"], 0);
    assert!(b.template().unwrap().transactions.is_empty());
    let events = b.rpc("peers", json!({})).unwrap();
    assert!(events.as_array().unwrap().iter().all(|e| e["ok"] == true));
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lagging_peer_does_not_reset_a_deep_branch_download() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let local = Node::open(
        &dir.path().join("local.db"),
        c.clone(),
        crypto::public_key(&[84; 32]).unwrap(),
    )
    .unwrap();
    let remote = Node::open(
        &dir.path().join("remote.db"),
        c.clone(),
        crypto::public_key(&[85; 32]).unwrap(),
    )
    .unwrap();
    let lagging = Node::open(
        &dir.path().join("lagging.db"),
        c,
        crypto::public_key(&[86; 32]).unwrap(),
    )
    .unwrap();
    for _ in 0..80 {
        local.mine(100_000).unwrap();
    }
    for height in 1..=100 {
        let block = remote.mine(100_000).unwrap();
        if height <= 16 {
            lagging.submit_block(block).unwrap();
        }
    }
    let full_server = node::serve(remote.clone(), options()).await.unwrap();
    let lag_server = node::serve(lagging.clone(), options()).await.unwrap();
    for _ in 0..4 {
        node::sync_peer(&local, full_server.p2p).await.unwrap();
        node::sync_peer(&local, lag_server.p2p).await.unwrap();
    }
    assert_eq!(
        local.status().unwrap()["tip"],
        remote.status().unwrap()["tip"]
    );
    full_server.stop().await;
    lag_server.stop().await;
}

#[test]
fn evicted_states_replay_for_deep_reorg_and_restart() {
    use hashstash::chain::{Chain, MAX_CACHED_STATES};
    fn advance(chain: &mut Chain, miner: PublicKey) -> Block {
        let timestamp =
            chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
        let block =
            Chain::mine(chain.template(miner, vec![], timestamp).unwrap(), 100_000).unwrap();
        chain.submit(block.clone(), timestamp as u64).unwrap();
        block
    }
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let miner = crypto::public_key(&[82; 32]).unwrap();
    let other = crypto::public_key(&[83; 32]).unwrap();
    let path = dir.path().join("cache-a.db");
    let mut a = Chain::open(&path, c.clone()).unwrap();
    let mut b = Chain::open(&dir.path().join("cache-b.db"), c.clone()).unwrap();
    for _ in 0..10 {
        let block = advance(&mut a, miner);
        b.submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    let fork_hash = a.tip_hash();
    let fork_root = a.tip_state().root();
    for _ in 0..MAX_CACHED_STATES * 2 {
        advance(&mut a, miner);
    }
    assert!(a.cached_state_count() <= MAX_CACHED_STATES);
    assert_eq!(a.state_at(&fork_hash).unwrap().root(), fork_root);
    assert!(a.cached_state_count() <= MAX_CACHED_STATES);
    let old_tip = a.tip_hash();
    for index in 0..MAX_CACHED_STATES * 2 + 1 {
        let block = advance(&mut b, other);
        a.submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        if index < MAX_CACHED_STATES * 2 {
            assert_eq!(a.tip_hash(), old_tip);
        }
    }
    assert_eq!(a.tip_hash(), b.tip_hash());
    assert_eq!(a.tip_state().root(), b.tip_state().root());
    a.tip_state().audit(&c).unwrap();
    assert!(a.cached_state_count() <= MAX_CACHED_STATES);
    let expected = a.tip_hash();
    let root = a.tip_state().root();
    drop(a);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.tip_hash(), expected);
    assert_eq!(reopened.tip_state().root(), root);
    assert_eq!(reopened.state_at(&fork_hash).unwrap().root(), fork_root);
    assert!(reopened.cached_state_count() <= MAX_CACHED_STATES);
}

/// Read one unpinned peer frame's payload.
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut length = [0u8; 4];
    r.read_exact(&mut length).await.ok()?;
    let mut payload = vec![0; u32::from_be_bytes(length) as usize];
    r.read_exact(&mut payload).await.ok()?;
    Some(payload)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn version_1_peers_keep_block_synchronization_and_reject_header_requests_clearly() {
    use hashstash::peer_wire::{self, Limits, Message, Sync};
    use std::sync::{Arc, Mutex};
    let dir = tempfile::tempdir().unwrap();
    let c = Config::devnet();
    let a = Node::open(
        &dir.path().join("a.db"),
        c.clone(),
        crypto::public_key(&[87; 32]).unwrap(),
    )
    .unwrap();
    let b = Node::open(
        &dir.path().join("b.db"),
        c.clone(),
        crypto::public_key(&[88; 32]).unwrap(),
    )
    .unwrap();
    for _ in 0..3 {
        a.mine(100_000).unwrap();
    }
    let server = node::serve(a.clone(), options()).await.unwrap();
    let limits = Limits::from_config(&c);
    let genesis = codec::block_hash(&codec::genesis_block(&c).unwrap());

    // A version 1 client's exchange is unchanged: Sync request, Sync reply,
    // Sync push, acknowledgment.
    let mut stream = TcpStream::connect(server.p2p).await.unwrap();
    let request = |locator| Sync {
        chain: c.chain_id(),
        locator,
        blocks: vec![],
        transactions: vec![],
    };
    let hello = peer_wire::encode(&Message::Sync(request(vec![genesis])), limits).unwrap();
    stream
        .write_all(&peer_wire::frame(&hello, limits.frame_bytes()).unwrap())
        .await
        .unwrap();
    let reply = read_frame(&mut stream).await.unwrap();
    let Message::Sync(reply) = peer_wire::decode(&reply, limits).unwrap() else {
        panic!("a version 1 request is answered by a synchronization reply")
    };
    assert_eq!(reply.blocks.len(), 3);
    let push = peer_wire::encode(&Message::Sync(request(vec![genesis])), limits).unwrap();
    stream
        .write_all(&peer_wire::frame(&push, limits.frame_bytes()).unwrap())
        .await
        .unwrap();
    let ack = read_frame(&mut stream).await.unwrap();
    assert_eq!(peer_wire::decode(&ack, limits).unwrap(), Message::Ack);

    // A version 1 server closes on the header request's unknown message type.
    // Simulate one in front of the node: it records each session's first
    // message type and forwards only the ones version 1 knows.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let legacy = listener.local_addr().unwrap();
    let tags = Arc::new(Mutex::new(Vec::new()));
    let seen = tags.clone();
    let upstream = server.p2p;
    let proxy = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let Some(first) = read_frame(&mut client).await else {
                continue;
            };
            seen.lock().unwrap().push(first[8]);
            if first[8] > 3 {
                continue;
            }
            let mut server = TcpStream::connect(upstream).await.unwrap();
            let mut framed = (first.len() as u32).to_be_bytes().to_vec();
            framed.extend(first);
            server.write_all(&framed).await.unwrap();
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    let error = node::sync_peer(&b, legacy).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("peer transport version 1"),
        "{error:#}"
    );
    let status = b.rpc("peerstatus", json!({})).unwrap();
    assert_eq!(status["transport_version"], 2);
    assert_eq!(status["version1_peers"], json!([legacy.to_string()]));
    // The next session, once the closed read's short cooldown has passed,
    // uses block synchronization only, and succeeds.
    tokio::time::sleep(Duration::from_millis(300)).await;
    node::sync_peer(&b, legacy).await.unwrap();
    assert_eq!(b.status().unwrap()["tip"], a.status().unwrap()["tip"]);
    assert_eq!(*tags.lock().unwrap(), [4, 0]);
    // A version 2 server answers header requests directly.
    a.mine(100_000).unwrap();
    node::sync_peer(&b, server.p2p).await.unwrap();
    assert_eq!(b.status().unwrap()["tip"], a.status().unwrap()["tip"]);
    proxy.abort();
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_legal_loose_transaction_relays_alongside_blocks_without_stalling_cursor() {
    use hashstash::peer_wire::{self, Limits, Message, Sync};
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.max_signatures = 2;
    config.initial.block_bytes = 4 * 1024 * 1024;
    config.initial_bits = 0x1f00ffff;
    config.limit_bits = config.initial_bits;
    config.validate().unwrap();
    let key = [121; 32];
    let miner = crypto::public_key(&key).unwrap();
    let source = Node::open(
        &directory.path().join("large-source.db"),
        config.clone(),
        miner,
    )
    .unwrap();
    let target = Node::open(
        &directory.path().join("large-target.db"),
        config.clone(),
        miner,
    )
    .unwrap();
    source.mine(2_000_000).unwrap();
    let chain_id = config.chain_id();
    let make = |nonce, data| {
        crypto::sign(
            &chain_id,
            &TransactionBody {
                sender: miner,
                nonce,
                fee: 2000u32.into(),
                anchor: hashstash::codec::block_hash(
                    &hashstash::codec::genesis_block(&config).unwrap(),
                ),
                expiry_blocks: 100,
                operation: Operation::TransferExact {
                    recipient: miner,
                    amount: 1u32.into(),
                },
                data,
            },
            &key,
        )
        .unwrap()
    };
    let included = make(0, vec![255; 1280 * 1024]);
    source.submit_transaction(included.clone()).unwrap();
    let block = source.mine(2_000_000).unwrap();
    let large = make(1, vec![10; 1280 * 1024]);
    let small = make(2, vec![]);
    source.submit_transaction(large.clone()).unwrap();
    source.submit_transaction(small.clone()).unwrap();
    let limits = Limits::from_config(&config);
    assert!(codec::encode(&large).len() > peer_wire::TRANSACTION_BATCH_BYTES);
    let packet = Sync {
        chain: config.chain_id(),
        locator: vec![block.header.previous],
        blocks: vec![block],
        transactions: vec![large.clone(), small.clone()],
    };
    let binary = peer_wire::encode(&Message::Sync(packet.clone()), limits).unwrap();
    let json=serde_json::to_vec(&json!({"chain":packet.chain,"locator":packet.locator,"blocks":packet.blocks,"transactions":packet.transactions})).unwrap();
    assert!(binary.len() < json.len());
    eprintln!(
        "valid block plus large loose relay: binary={} bytes, former JSON={} bytes",
        binary.len(),
        json.len()
    );
    let server = node::serve(source.clone(), options()).await.unwrap();
    node::sync_peer(&target, server.p2p).await.unwrap();
    assert_eq!(
        source.status().unwrap()["tip"],
        target.status().unwrap()["tip"]
    );
    assert_eq!(
        source.status().unwrap()["state_root"],
        target.status().unwrap()["state_root"]
    );
    assert_eq!(target.status().unwrap()["mempool"], 2);
    node::sync_peer(&target, server.p2p).await.unwrap();
    assert_eq!(target.status().unwrap()["mempool"], 2);
    assert_eq!(
        source.template().unwrap().transactions,
        target.template().unwrap().transactions
    );
    assert_eq!(
        codec::transaction_id(&source.template().unwrap().transactions[0]),
        codec::transaction_id(&large)
    );
    server.stop().await;
}
