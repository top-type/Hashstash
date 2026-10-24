//! Finite defensive tests against isolated localhost listeners. These fixtures
//! never connect to a configured/public peer or the user's running testnet.
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    crypto, math, network_guard,
    node::{self, Node, Server, ServerOptions},
    peer_wire::{self, Limits, Message as PeerPacket, Sync as PeerMessage},
    types::*,
};
use serde_json::{Value, json};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    time::{Instant, timeout, timeout_at},
};

const RESPONSE_LIMIT: u64 = 256 * 1024;
const FAST_DEADLINE: Duration = Duration::from_secs(3);
const SEED: u64 = 0xd475_928c_310b_a6e1;

#[test]
fn address_aliases_cannot_bypass_quotas_and_peer_limits_do_not_apply_to_rpc() {
    use network_guard::{NetworkGuard, Surface};
    let guard = Arc::new(NetworkGuard::default());
    let ipv4: IpAddr = "127.0.0.1".parse().unwrap();
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
    let mut held = Vec::new();
    for address in [ipv4, mapped, ipv4, mapped] {
        held.push(guard.admit(address, Surface::Peer).unwrap());
    }
    assert!(guard.admit(ipv4, Surface::Peer).is_err());
    assert!(guard.admit(mapped, Surface::Peer).is_err());
    assert!(guard.admit(mapped, Surface::Rpc).is_ok());
    assert!(guard.admit(mapped, Surface::Stratum).is_ok());
    // Churn cannot evict an active accounting entry and reset its quota.
    for n in 0..network_guard::MAX_TRACKED_IPS + 32 {
        let address = IpAddr::from([10, (n / 256) as u8, (n % 256) as u8, 1]);
        drop(guard.admit(address, Surface::Peer).unwrap());
    }
    assert!(guard.tracked_addresses() <= network_guard::MAX_TRACKED_IPS);
    assert!(guard.admit(mapped, Surface::Peer).is_err());
    let byte_burst = 66 * 1024 * 1024;
    assert!(held[0].bytes(byte_burst + 1).is_err());
    assert!(held[1].request().is_err());
    assert!(guard.admit(ipv4, Surface::Rpc).is_ok());
    drop(held);
    for failures in 0..128 {
        let min = network_guard::retry_delay(failures, 0);
        let jittered = network_guard::retry_delay(failures, u64::MAX);
        assert!(min >= Duration::from_secs(1));
        assert!(jittered >= min);
        assert!(jittered < Duration::from_secs(75));
    }
}

#[test]
fn seeded_json_corpus_is_bounded_and_preserves_valid_escaped_strings() {
    let mut rng = SEED;
    let mut parsed = 0;
    let mut rejected = 0;
    for index in 0..512u64 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let original = json!({"id":index,"values":[rng,rng%17,{"text":format!("escaped \\\" value {}",rng%100)}],"enabled":rng&1==0});
        let wire = serde_json::to_vec(&original).unwrap();
        assert_eq!(network_guard::parse_json(&wire).unwrap(), original);
        parsed += 1;
        let mut malformed = wire.clone();
        match index % 4 {
            0 => {
                malformed.truncate((rng as usize % (wire.len() - 1)) + 1);
            }
            1 => malformed.extend_from_slice(b" trailing"),
            2 => malformed[0] = b']',
            _ => malformed.insert(1, 0xff),
        }
        assert!(
            network_guard::parse_json(&malformed).is_err(),
            "accepted malformed case {index}"
        );
        rejected += 1;
    }
    for n in [0, 1, 127, 1023, 1024] {
        let escaped = format!("\"{}\"", "\\u0061".repeat(n));
        assert_eq!(
            network_guard::parse_json(escaped.as_bytes()).unwrap(),
            json!("a".repeat(n))
        );
        parsed += 1;
    }
    let escaped_too_large = format!("\"{}\"", "\\u0061".repeat(1025));
    assert!(network_guard::parse_json(escaped_too_large.as_bytes()).is_err());
    let at_depth = format!(
        "{}0{}",
        "[".repeat(network_guard::MAX_JSON_DEPTH),
        "]".repeat(network_guard::MAX_JSON_DEPTH)
    );
    assert!(network_guard::parse_json(at_depth.as_bytes()).is_ok());
    let too_deep = format!("[{at_depth}]");
    assert!(network_guard::parse_json(too_deep.as_bytes()).is_err());
    let valid = format!("[{}]", vec!["0"; 100_000].join(","));
    assert!(network_guard::parse_json(valid.as_bytes()).is_ok());
    let too_many = format!("[{}]", vec!["0"; 100_001].join(","));
    assert!(network_guard::parse_json(too_many.as_bytes()).is_err());
    let oversized_key = format!("{{\"{}\":0}}", "k".repeat(129));
    assert!(network_guard::parse_json(oversized_key.as_bytes()).is_err());
    // Duplicate keys still count toward the pre-allocation object budget.
    let duplicate_keys = format!("{{{}}}", vec!["\"key\":0"; 129].join(","));
    assert!(network_guard::preflight_json(duplicate_keys.as_bytes()).is_err());
    let across_containers = format!("[{}]", vec![valid; 21].join(","));
    assert!(network_guard::preflight_json(across_containers.as_bytes()).is_err());
    eprintln!(
        "JSON corpus: seed={SEED:#x}, {parsed} valid cases, {rejected} seeded malformed cases, depth/string/array boundaries checked"
    );
}

fn options() -> ServerOptions {
    let zero = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        p2p: zero,
        stratum: zero,
        peers: vec![],
        stratum_password: Some("fixture-password".into()),
        ..Default::default()
    }
}

fn configuration() -> Config {
    let mut config = Config::devnet();
    config.initial_bits = 0x1f1fffff;
    config.limit_bits = config.initial_bits;
    config.initial.block_bytes = 262144;
    config
}

async fn isolated() -> (TempDir, Node, Server) {
    let dir = tempfile::tempdir().unwrap();
    let config = configuration();
    let node = Node::open(
        &dir.path().join("node.sqlite"),
        config,
        crypto::public_key(&[101; 32]).unwrap(),
    )
    .unwrap();
    let server = node::serve(node.clone(), options()).await.unwrap();
    (dir, node, server)
}

#[tokio::test]
async fn rpc_rejects_public_bind_even_without_a_local_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(
        &dir.path().join("node.sqlite"),
        configuration(),
        crypto::public_key(&[105; 32]).unwrap(),
    )
    .unwrap();
    for address in ["0.0.0.0:0", "[::]:0"] {
        let mut config = options();
        config.rpc = address.parse().unwrap();
        assert!(node::serve(node.clone(), config).await.is_err());
    }
}

async fn connect(address: SocketAddr, group: u8, host: u8) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket
        .bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, group, host)),
            0,
        ))
        .unwrap();
    timeout(FAST_DEADLINE, socket.connect(address))
        .await
        .unwrap()
        .unwrap()
}

async fn read_closed(stream: &mut TcpStream, deadline: Instant) -> Vec<u8> {
    let mut bytes = Vec::new();
    let result = timeout_at(
        deadline,
        stream.take(RESPONSE_LIMIT).read_to_end(&mut bytes),
    )
    .await
    .expect("bounded request was not closed by its deadline");
    if let Err(error) = result {
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            "unexpected socket failure: {error}"
        );
    }
    assert!(
        bytes.len() < RESPONSE_LIMIT as usize,
        "unbounded response to a small invalid request"
    );
    bytes
}

async fn exchange(address: SocketAddr, group: u8, host: u8, bytes: &[u8]) -> Vec<u8> {
    let mut stream = connect(address, group, host).await;
    if let Err(error) = stream.write_all(bytes).await {
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            "{error}"
        );
    }
    let _ = stream.shutdown().await;
    read_closed(&mut stream, Instant::now() + FAST_DEADLINE).await
}

fn rpc_request(address: SocketAddr, body: &[u8]) -> Vec<u8> {
    let mut wire = format!("POST /rpc HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    wire.extend_from_slice(body);
    wire
}

async fn healthy(server: &Server, expected: &Value) {
    let status = timeout(
        FAST_DEADLINE,
        node::call_rpc(&format!("http://{}/rpc", server.rpc), "status", json!({})),
    )
    .await
    .expect("RPC became unresponsive")
    .unwrap();
    for field in ["tip", "state_root", "height", "issued", "mempool"] {
        assert_eq!(
            status[field], expected[field],
            "unexpected state mutation: {field}"
        );
    }
}

fn hello(node: &Node) -> PeerMessage {
    let status = node.status().unwrap();
    PeerMessage {
        chain: hex::decode(status["chain_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        locator: vec![
            hex::decode(status["tip"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        ],
        blocks: vec![],
        transactions: vec![],
    }
}

fn line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

async fn read_json_or_closed<R: tokio::io::AsyncBufRead + Unpin>(
    read: &mut R,
) -> io::Result<Option<Value>> {
    let mut bytes = Vec::new();
    let length = timeout(FAST_DEADLINE, read.read_until(b'\n', &mut bytes))
        .await
        .expect("protocol response timed out")?;
    if length == 0 {
        return Ok(None);
    }
    assert!(length < RESPONSE_LIMIT as usize, "oversized response");
    Ok(Some(serde_json::from_slice(&bytes).unwrap()))
}

async fn read_json<R: tokio::io::AsyncBufRead + Unpin>(read: &mut R) -> Value {
    read_json_or_closed(read)
        .await
        .unwrap()
        .expect("missing protocol response")
}

fn peer_bytes(value: &PeerMessage) -> Vec<u8> {
    let limits = Limits::from_config(&configuration());
    peer_wire::frame(
        &peer_wire::encode(&PeerPacket::Sync(value.clone()), limits).unwrap(),
        limits.frame_bytes(),
    )
    .unwrap()
}
async fn read_peer_or_closed<R: tokio::io::AsyncBufRead + Unpin>(
    read: &mut R,
) -> io::Result<Option<PeerPacket>> {
    let mut header = [0u8; 4];
    if let Err(error) = timeout(FAST_DEADLINE, read.read_exact(&mut header))
        .await
        .expect("peer response timed out")
    {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(error);
    }
    let length = u32::from_be_bytes(header) as usize;
    assert!(length < RESPONSE_LIMIT as usize, "oversized response");
    let mut bytes = vec![0; length];
    timeout(FAST_DEADLINE, read.read_exact(&mut bytes))
        .await
        .expect("peer payload timed out")?;
    Ok(Some(
        peer_wire::decode(&bytes, Limits::from_config(&configuration())).unwrap(),
    ))
}
async fn read_peer<R: tokio::io::AsyncBufRead + Unpin>(read: &mut R) -> PeerPacket {
    read_peer_or_closed(read)
        .await
        .unwrap()
        .expect("missing peer response")
}
async fn valid_peer(address: SocketAddr, value: &PeerMessage, group: u8, host: u8) {
    let stream = connect(address, group, host).await;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write.write_all(&peer_bytes(value)).await.unwrap();
    let reply = read_peer(&mut read).await;
    let PeerPacket::Sync(reply) = reply else {
        panic!("expected sync reply")
    };
    assert_eq!(reply.chain, value.chain);
    write.write_all(&peer_bytes(value)).await.unwrap();
    assert_eq!(read_peer(&mut read).await, PeerPacket::Ack);
}

async fn hostile_batch_with_bounded_retries(
    address: SocketAddr,
    value: &PeerMessage,
    group: u8,
    host: u8,
) -> usize {
    // Eight reconnecting workers fill the eight inbound peer slots. A previous
    // response can reach Windows before that server task releases its permit,
    // so admission may close a replacement connection. Retry only transport
    // closure, requiring the same completed workload and strict protocol replies.
    for retry in 0..4 {
        let stream = connect(address, group, host).await;
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        let result: io::Result<bool> = async {
            timeout(FAST_DEADLINE, write.write_all(&peer_bytes(value)))
                .await
                .expect("hostile batch write timed out")?;
            let Some(reply) = read_peer_or_closed(&mut read).await? else {
                return Ok(false);
            };
            let PeerPacket::Sync(reply) = reply else {
                panic!("expected sync reply")
            };
            assert_eq!(reply.chain, value.chain);
            timeout(FAST_DEADLINE, write.write_all(&peer_bytes(value)))
                .await
                .expect("hostile batch write timed out")?;
            let Some(reply) = read_peer_or_closed(&mut read).await? else {
                return Ok(false);
            };
            assert_eq!(reply, PeerPacket::Ack);
            Ok(true)
        }
        .await;
        match result {
            Ok(true) => return retry,
            Ok(false) => {}
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ),
                "unexpected hostile-batch socket failure: {error}"
            ),
        }
        drop(read);
        drop(write);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("hostile batch could not complete within four connection attempts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_http_and_json_fail_closed_without_changing_state_or_listener_health() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let host = server.rpc;
    let mut cases = vec![
        b"not-an-http-request\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\nHost: ignored\n\n".to_vec(),
        format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{{}}").into_bytes(),
        format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").into_bytes(),
        format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", node::MAX_FRAME + 1).into_bytes(),
        format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{}}").into_bytes(),
        format!("POST /rpc HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{{}}").into_bytes(),
        format!("GET /{} HTTP/1.1\r\nHost: {host}\r\n\r\n", "x".repeat(4096)).into_bytes(),
    ];
    for body in [
        b"{".to_vec(), b"null trailing".to_vec(), vec![0xff, 0xfe, 0],
        format!("{}0{}", "[".repeat(80), "]".repeat(80)).into_bytes(),
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"status","params":{"padding":"x".repeat(1025)}})).unwrap(),
        b"{\"jsonrpc\":\"2.0\",\"id\":1e999,\"method\":\"status\"}".to_vec(),
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"status\",\"params\":{\"a\":1,}}".to_vec(),
    ] { cases.push(rpc_request(host, &body)); }
    let mut too_many = serde_json::Map::new();
    for i in 0..129 {
        too_many.insert(format!("field{i}"), json!(i));
    }
    cases.push(rpc_request(
        host,
        &serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"status","params":too_many}))
            .unwrap(),
    ));
    for (i, wire) in cases.iter().enumerate() {
        let reply = exchange(server.rpc, 1, i as u8 + 2, wire).await;
        if !reply.is_empty() {
            let text = String::from_utf8_lossy(&reply);
            assert!(
                !text.starts_with("HTTP/1.1 200"),
                "case {i} unexpectedly succeeded: {text}"
            );
        }
        healthy(&server, &before).await;
    }
    // Web clients cannot push peer synchronization errors out of the
    // operator's peer diagnostics.
    let events = node.rpc("peers", json!({})).unwrap();
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .all(|e| !e["peer"].as_str().unwrap().starts_with("inbound/0/")),
        "{events}"
    );
    eprintln!(
        "HTTP malformed corpus: {} isolated requests; state and RPC health preserved",
        cases.len()
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_seeded_peer_mutations_and_invalid_transactions_preserve_state() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let valid = hello(&node);
    let secret = [102; 32];
    let invalid = crypto::sign(
        &configuration().chain_id(),
        &TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(&secret).unwrap(),
            nonce: 0,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&configuration()).unwrap(),
            ),
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: crypto::public_key(&[103; 32]).unwrap(),
                amount: 1u32.into(),
            },
        },
        &secret,
    )
    .unwrap();
    let mut rng = SEED;
    let mut bytes_tested = 0;
    for i in 0..48u8 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let limits = Limits::from_config(&configuration());
        let mut payload = peer_wire::encode(&PeerPacket::Sync(valid.clone()), limits).unwrap();
        match i % 8 {
            0 => payload[rng as usize % 8] ^= 1, // wrong transport magic
            1 => payload[41] = 129,              // excessive locators, before reading their bytes
            2 => payload[74] = 33,               // excessive blocks, before reading any record
            3 => {
                payload.splice(75..76, codec::encode(&257u64));
            }
            4 => payload[9..41].fill(0), // wrong chain
            5 => {
                let mut tx = invalid.clone();
                tx.body.data.clear();
                let mut raw = codec::encode(&tx);
                let at = raw.len() - 65;
                raw.splice(at..at + 1, codec::encode(&u64::MAX));
                payload[75] = 1;
                payload.extend(codec::encode(&(raw.len() as u64)));
                payload.extend(raw);
            }
            6 => {
                let mut candidate = valid.clone();
                candidate.transactions.push(invalid.clone());
                payload = peer_wire::encode(&PeerPacket::Sync(candidate), limits).unwrap();
            }
            _ => payload.push(0), // trailing bytes
        }
        let wire = peer_wire::frame(&payload, limits.frame_bytes()).unwrap();
        bytes_tested += wire.len();
        exchange(server.p2p, 3, i + 2, &wire).await;
        assert_eq!(node.status().unwrap()["tip"], before["tip"]);
        assert_eq!(node.status().unwrap()["state_root"], before["state_root"]);
        assert_eq!(node.status().unwrap()["mempool"], 0);
    }
    valid_peer(server.p2p, &valid, 4, 1).await;
    healthy(&server, &before).await;
    eprintln!(
        "Peer mutation corpus: seed={SEED:#x}, cases=48, bytes={bytes_tested}; valid handshake recovered"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_peer_frame_is_closed_without_blocking_rpc_or_future_peers() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let bytes = ((Limits::from_config(&configuration()).frame_bytes() + 1) as u32)
        .to_be_bytes()
        .to_vec();
    let response = timeout(Duration::from_secs(20), exchange(server.p2p, 13, 1, &bytes))
        .await
        .expect("oversized peer frame did not terminate");
    assert!(response.is_empty());
    healthy(&server, &before).await;
    valid_peer(server.p2p, &hello(&node), 13, 2).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_peer_blocks_cannot_change_committed_state_then_valid_sync_succeeds() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let valid = hello(&node);
    let d = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&d.path().join("source.sqlite"), configuration()).unwrap();
    let timestamp = chain.config.genesis_time + 2;
    let block = Chain::mine(
        chain
            .template(crypto::public_key(&[104; 32]).unwrap(), vec![], timestamp)
            .unwrap(),
        100_000,
    )
    .unwrap();
    for i in 0..8u8 {
        let mut bad = block.clone();
        match i {
            0 => bad.header.previous = [0; 32],
            1 => bad.height += 1,
            2 => bad.header.bits = 0,
            3 => bad.state_root = [0; 32],
            4 => bad.header.merkle_root = [0; 32],
            5 => bad.extranonce[0] ^= 1,
            6 => bad.header.version = 0,
            _ => bad.miner = [0; 32],
        }
        // First message is a valid locator request; invalid block data arrives
        // only in the push phase where a normal peer would submit its blocks.
        let stream = connect(server.p2p, 5, i + 2).await;
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        write.write_all(&peer_bytes(&valid)).await.unwrap();
        read_peer(&mut read).await;
        let mut push = valid.clone();
        push.blocks = vec![bad];
        write.write_all(&peer_bytes(&push)).await.unwrap();
        write.shutdown().await.unwrap();
        let mut discarded = Vec::new();
        let _ = timeout(FAST_DEADLINE, read.read_to_end(&mut discarded))
            .await
            .expect("invalid block session did not close");
        healthy(&server, &before).await;
    }
    chain.submit(block.clone(), timestamp as u64).unwrap();
    let source = Node::open(&d.path().join("peer.sqlite"), configuration(), block.miner).unwrap();
    source.submit_block(block).unwrap();
    let peer = node::serve(source, options()).await.unwrap();
    node::sync_peer(&node, peer.p2p).await.unwrap();
    assert_eq!(node.status().unwrap()["tip"], hex::encode(chain.tip_hash()));
    assert_eq!(
        node.status().unwrap()["state_root"],
        hex::encode(chain.tip_state().root())
    );
    peer.stop().await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_admission_saturation_does_not_starve_rpc_or_a_different_peer() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(
        &dir.path().join("node.sqlite"),
        configuration(),
        crypto::public_key(&[101; 32]).unwrap(),
    )
    .unwrap();
    // A configured peer address keeps reserved inbound capacity. Its own
    // outbound target is closed, so that retry loop only backs off.
    let mut config = options();
    config.peers = vec!["127.0.6.9:9".parse().unwrap()];
    let server = node::serve(node.clone(), config).await.unwrap();
    let before = node.status().unwrap();
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut stream = connect(server.p2p, 6, 1).await;
        stream.write_all(b"{").await.unwrap();
        held.push(stream);
    }
    let mut excess = connect(server.p2p, 6, 1).await;
    let reply = read_closed(&mut excess, Instant::now() + FAST_DEADLINE).await;
    assert!(
        reply.is_empty(),
        "over-limit peer should be closed before parsing"
    );
    valid_peer(server.p2p, &hello(&node), 6, 2).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Loopback addresses keep per-address limits only, so four of them fill
    // every general inbound slot, while the RPC budget stays independent.
    // Public sources are additionally limited per network group.
    for host in 2..=4 {
        for _ in 0..4 {
            let mut stream = connect(server.p2p, 6, host).await;
            stream.write_all(b"{").await.unwrap();
            held.push(stream);
        }
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    // A fifth address cannot take over a session admitted less than one read
    // allowance ago (`EVICTION_GRACE`), so sources that keep reconnecting
    // cannot displace an honest session before it finishes its exchange.
    // While every unprotected session is that young the newcomer is closed
    // before parsing, and the sessions keep their slots. Which session a
    // newcomer takes over once they are older is covered by the slot tests
    // in `network_guard`.
    let mut newcomer = connect(server.p2p, 6, 5).await;
    assert!(
        read_closed(&mut newcomer, Instant::now() + FAST_DEADLINE)
            .await
            .is_empty(),
        "a newcomer is refused while every unprotected session is in its grace period"
    );
    let mut probe = [0u8; 1];
    let newest = held.last_mut().unwrap();
    assert!(
        timeout(Duration::from_millis(500), newest.read(&mut probe))
            .await
            .is_err(),
        "the newest session keeps its slot"
    );
    for _ in 0..8 {
        healthy(&server, &before).await;
    }
    // A configured peer still synchronizes through reserved capacity.
    valid_peer(server.p2p, &hello(&node), 6, 9).await;
    drop((held, newcomer));
    // Admission alone should not permanently ban an address. Allow tasks to
    // observe the closed sockets, and any first cooldown (250 ms) to pass,
    // then retry a well-formed local handshake from the refused address.
    tokio::time::sleep(Duration::from_millis(400)).await;
    healthy(&server, &before).await;
    valid_peer(server.p2p, &hello(&node), 6, 5).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn first_peer_message_is_bounded_before_its_body_is_read() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let limits = Limits::from_config(&configuration());
    // A first message is a locator request: a declared length beyond that
    // allowance closes at once instead of buffering a full block frame.
    let mut stream = connect(server.p2p, 16, 1).await;
    stream
        .write_all(&((limits.locator_request_bytes() + 1) as u32).to_be_bytes())
        .await
        .unwrap();
    assert!(
        read_closed(&mut stream, Instant::now() + FAST_DEADLINE)
            .await
            .is_empty()
    );
    // Blocks are never accepted in a first message.
    let d = tempfile::tempdir().unwrap();
    let chain = Chain::open(&d.path().join("source.sqlite"), configuration()).unwrap();
    let block = Chain::mine(
        chain
            .template(
                crypto::public_key(&[104; 32]).unwrap(),
                vec![],
                chain.config.genesis_time + 2,
            )
            .unwrap(),
        100_000,
    )
    .unwrap();
    let mut request = hello(&node);
    request.blocks.push(block);
    assert!(
        exchange(server.p2p, 16, 2, &peer_bytes(&request))
            .await
            .is_empty()
    );
    assert_eq!(node.status().unwrap()["tip"], before["tip"]);
    valid_peer(server.p2p, &hello(&node), 16, 3).await;
    healthy(&server, &before).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_peer_cooldown_is_temporary_and_isolated_from_rpc() {
    let (_dir, node, server) = isolated().await;
    let valid = hello(&node);
    let before = node.status().unwrap();
    let started = Instant::now();
    assert!(exchange(server.p2p, 10, 1, b"{\n").await.is_empty());
    let mut retry = connect(server.p2p, 10, 1).await;
    let _ = retry.write_all(&peer_bytes(&valid)).await;
    let _ = retry.shutdown().await;
    let retry_bytes = read_closed(&mut retry, Instant::now() + FAST_DEADLINE).await;
    if started.elapsed() < Duration::from_millis(200) {
        assert!(
            retry_bytes.is_empty(),
            "malformed-peer cooldown was not applied"
        );
    }
    let request = rpc_request(
        server.rpc,
        br#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#,
    );
    let rpc = exchange(server.rpc, 10, 1, &request).await;
    assert!(
        rpc.starts_with(b"HTTP/1.1 200"),
        "P2P cooldown blocked the same address's RPC request"
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    valid_peer(server.p2p, &valid, 10, 1).await;
    healthy(&server, &before).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_invalid_signature_batches_leave_coherent_rpc_snapshots_responsive() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let secret = [106; 32];
    let original = crypto::sign(
        &configuration().chain_id(),
        &TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(&secret).unwrap(),
            nonce: 0,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&configuration()).unwrap(),
            ),
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: crypto::public_key(&[107; 32]).unwrap(),
                amount: 1u32.into(),
            },
        },
        &secret,
    )
    .unwrap();
    let mut workers = tokio::task::JoinSet::new();
    for worker in 0..8u8 {
        let mut request = hello(&node);
        let candidates: Vec<_> = (0..256u64)
            .map(|index| {
                let mut transaction = original.clone();
                // Changing the signed nonce makes each item distinct and invalid.
                transaction.body.nonce = 1 + u64::from(worker) * 256 + index;
                transaction
            })
            .collect();
        request.transactions = candidates;
        let address = server.p2p;
        workers.spawn(async move {
            let mut retries = 0;
            for _ in 0..4 {
                retries +=
                    hostile_batch_with_bounded_retries(address, &request, 11, worker + 1).await;
            }
            retries
        });
    }
    let url = format!("http://{}/rpc", server.rpc);
    let mut worst = Duration::ZERO;
    for _ in 0..32 {
        let start = Instant::now();
        let snapshot = timeout(FAST_DEADLINE, node::call_rpc(&url, "snapshot", json!({})))
            .await
            .expect("peer validation blocked the published RPC snapshot")
            .unwrap();
        worst = worst.max(start.elapsed());
        assert_eq!(snapshot["status"]["tip"], before["tip"]);
        assert_eq!(snapshot["status"]["state_root"], before["state_root"]);
        assert_eq!(
            snapshot["status"]["state_root"],
            snapshot["governance"]["state_root"]
        );
        assert_eq!(snapshot["status"]["mempool"], 0);
    }
    let mut retries = 0;
    while let Some(result) = workers.join_next().await {
        retries += result.unwrap();
    }
    healthy(&server, &before).await;
    valid_peer(server.p2p, &hello(&node), 12, 1).await;
    eprintln!(
        "Concurrent invalid signatures: 32 completed peer exchanges (at least 16,384 transaction submissions), {retries} retried transport closures, 32 coherent snapshots, maximum observed RPC latency {:.3}s",
        worst.as_secs_f64(),
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trickled_partial_requests_expire_on_absolute_deadlines_and_leave_rpc_live() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let started = Instant::now();
    let mut peer = connect(server.p2p, 7, 1).await;
    let mut http = connect(server.rpc, 7, 2).await;
    let mut stratum = connect(server.stratum, 7, 3).await;
    peer.write_all(b"{").await.unwrap();
    http.write_all(b"POST /rpc HTTP/1.1\r\n").await.unwrap();
    stratum.write_all(b"{").await.unwrap();
    healthy(&server, &before).await;
    tokio::time::sleep(Duration::from_secs(10)).await;
    let _ = peer.write_all(b" ").await;
    let _ = http.write_all(b"X").await;
    let _ = stratum.write_all(b" ").await;
    let deadline = started + Duration::from_secs(18);
    let (p, _, s) = tokio::join!(
        read_closed(&mut peer, deadline),
        read_closed(&mut http, deadline),
        read_closed(&mut stratum, deadline)
    );
    assert!(p.is_empty());
    assert!(s.is_empty());
    healthy(&server, &before).await;
    eprintln!(
        "Slow partial request deadlines: three sockets expired within {:.2}s",
        started.elapsed().as_secs_f64()
    );
    server.stop().await;
}

async fn reply_id<R: tokio::io::AsyncBufRead + Unpin>(read: &mut R, id: u64) -> Value {
    for _ in 0..8 {
        let value = read_json(read).await;
        if value["id"] == id {
            return value;
        }
    }
    panic!("missing response id {id}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stratum_rejects_bounded_invalid_submissions_and_continues_serving_valid_requests() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut rejected = 0;
    for batch in 0..4u8 {
        let stream = connect(server.stratum, 8, batch + 2).await;
        let (read, mut write) = stream.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(&line(
                &json!({"id":1,"method":"mining.subscribe","params":["bounded-fixture"]}),
            ))
            .await
            .unwrap();
        assert!(reply_id(&mut read, 1).await["error"].is_null());
        write.write_all(&line(&json!({"id":2,"method":"mining.authorize","params":["fixture.worker","fixture-password"]}))).await.unwrap();
        assert_eq!(reply_id(&mut read, 2).await["result"], true);
        let difficulty = read_json(&mut read).await;
        assert_eq!(difficulty["method"], "mining.set_difficulty");
        let job = read_json(&mut read).await;
        assert_eq!(job["method"], "mining.notify");
        let job_id = job["params"][0].clone();
        let time = job["params"][7].clone();
        for i in 0..10u64 {
            let mut params = json!(["fixture.worker", job_id, "00000000", time, "00000000"]);
            match i % 5 {
                0 => params = json!([]),
                1 => params[0] = json!("wrong.worker"),
                2 => params[1] = json!("unknown-job"),
                3 => params[2] = json!("0000"),
                _ => params[4] = json!("not-hex"),
            }
            write
                .write_all(&line(
                    &json!({"id":100+i,"method":"mining.submit","params":params}),
                ))
                .await
                .unwrap();
            let reply = reply_id(&mut read, 100 + i).await;
            assert!(!reply["error"].is_null(), "invalid submit {i} accepted");
            rejected += 1;
        }
        write
            .write_all(&line(
                &json!({"id":999,"method":"mining.suggest_difficulty","params":[1]}),
            ))
            .await
            .unwrap();
        assert_eq!(reply_id(&mut read, 999).await["result"], true);
    }
    for (i, bytes) in [
        format!("{}0{}\n", "[".repeat(80), "]".repeat(80)).into_bytes(),
        vec![b' '; 16_385],
        b"{\"id\":\n".to_vec(),
        vec![0xff, b'\n'],
    ]
    .iter()
    .enumerate()
    {
        exchange(server.stratum, 9, i as u8 + 2, bytes).await;
    }
    healthy(&server, &before).await;
    eprintln!(
        "Stratum defensive corpus: {rejected} semantic rejections, 4 parser/size rejections; no mined blocks"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stratum_wrong_password_and_request_floods_close_without_affecting_rpc() {
    let (_dir, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut requests = line(&json!({"id":1,"method":"mining.subscribe","params":[]}));
    requests.extend(line(
        &json!({"id":2,"method":"mining.authorize","params":["denied.worker","incorrect"]}),
    ));
    let rejected = exchange(server.stratum, 15, 1, &requests).await;
    let replies: Vec<Value> = rejected
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[1]["id"], 2);
    assert_eq!(replies[1]["result"], false);
    let flood: Vec<u8> = (0..64)
        .flat_map(|id| line(&json!({"id":id,"method":"mining.suggest_difficulty","params":[1]})))
        .collect();
    let responses = exchange(server.stratum, 15, 2, &flood).await;
    let count = responses.iter().filter(|byte| **byte == b'\n').count();
    assert!(
        count > 0 && count < 64,
        "session request limit was not enforced"
    );
    let request = rpc_request(
        server.rpc,
        br#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#,
    );
    assert!(
        exchange(server.rpc, 15, 2, &request)
            .await
            .starts_with(b"HTTP/1.1 200")
    );
    healthy(&server, &before).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stratum_admits_and_mines_a_complete_256_transaction_job() {
    let (_dir, node, server) = isolated().await;
    let secret = [101; 32];
    let public = crypto::public_key(&secret).unwrap();
    node.mine(100_000).unwrap();
    let chain_id = configuration().chain_id();
    let candidates: Vec<_> = (0..node::MAX_MEMPOOL as u64)
        .map(|nonce| {
            crypto::sign(
                &chain_id,
                &TransactionBody {
                    data: Vec::new(),
                    sender: public,
                    nonce,
                    fee: 1u32.into(),
                    anchor: hashstash::codec::block_hash(
                        &hashstash::codec::genesis_block(&configuration()).unwrap(),
                    ),
                    expiry_blocks: 100,
                    operation: Operation::TransferExact {
                        recipient: public,
                        amount: 1u32.into(),
                    },
                },
                &secret,
            )
            .unwrap()
        })
        .collect();
    let mut request = hello(&node);
    request.transactions = candidates;
    valid_peer(server.p2p, &request, 14, 1).await;
    assert_eq!(node.status().unwrap()["mempool"], node::MAX_MEMPOOL);

    let stream = connect(server.stratum, 14, 2).await;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write
        .write_all(&line(
            &json!({"id":1,"method":"mining.subscribe","params":["full-job-test"]}),
        ))
        .await
        .unwrap();
    let subscribe = reply_id(&mut read, 1).await;
    let extra1 = hex::decode(subscribe["result"][1].as_str().unwrap()).unwrap();
    assert_eq!(subscribe["result"][2], 4);
    write
        .write_all(&line(&json!({"id":2,"method":"mining.authorize","params":["full.worker","fixture-password"]})))
        .await
        .unwrap();
    assert_eq!(reply_id(&mut read, 2).await["result"], true);
    assert_eq!(
        read_json(&mut read).await["method"],
        "mining.set_difficulty"
    );
    let notify = read_json(&mut read).await;
    assert_eq!(notify["method"], "mining.notify");
    let params = notify["params"].as_array().unwrap();
    // A miner needs only the public wire data, including the coinbase Merkle path.
    let extra2 = [0x12, 0x34, 0x56, 0x78];
    let mut coinbase = hex::decode(params[2].as_str().unwrap()).unwrap();
    coinbase.extend(extra1);
    coinbase.extend(extra2);
    coinbase.extend(hex::decode(params[3].as_str().unwrap()).unwrap());
    let mut root = crypto::sha256d(&coinbase);
    for sibling in params[4].as_array().unwrap() {
        let mut pair = root.to_vec();
        pair.extend(hex::decode(sibling.as_str().unwrap()).unwrap());
        root = crypto::sha256d(&pair);
    }
    let mut previous: Hash = hex::decode(params[1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for word in previous.chunks_exact_mut(4) {
        word.reverse();
    }
    let number = |value: &Value| u32::from_str_radix(value.as_str().unwrap(), 16).unwrap();
    let mut header = Header {
        version: number(&params[5]),
        previous,
        merkle_root: root,
        timestamp: number(&params[7]),
        bits: number(&params[6]),
        nonce: 0,
    };
    let target = math::target_from_bits(header.bits).unwrap();
    while math::check_pow(&header, &target).is_err() {
        header.nonce += 1;
        assert!(
            header.nonce < 100_000,
            "fixture mining attempt limit reached"
        );
    }
    write
        .write_all(&line(&json!({"id":3,"method":"mining.submit","params":["full.worker",params[0],hex::encode(extra2),format!("{:08x}",header.timestamp),format!("{:08x}",header.nonce)]})))
        .await
        .unwrap();
    let result = reply_id(&mut read, 3).await;
    assert_eq!(result["result"], true, "{result}");
    let status = node.status().unwrap();
    assert_eq!(status["height"], 2);
    assert_eq!(status["mempool"], 0);
    assert_eq!(
        status["tip"],
        hex::encode(crypto::sha256d(&codec::header_bytes(&header)))
    );
    let block = node.rpc("getblock", json!({})).unwrap();
    assert_eq!(
        block["transactions"].as_array().unwrap().len(),
        node::MAX_MEMPOOL
    );
    assert_eq!(
        node.rpc("account", json!({"key":hex::encode(public)}))
            .unwrap()["account"]["nonce"],
        256
    );
    server.stop().await;
}
