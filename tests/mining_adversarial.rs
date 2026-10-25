//! Bounded adversarial mining tests against disposable localhost nodes only.
//! Workers reconstruct every proof from public Stratum wire messages.
use hashstash::{
    codec,
    config::Config,
    crypto, math,
    node::{self, Node, Server, ServerOptions},
    types::{Amount, Header, Operation, TransactionBody},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream, tcp::OwnedReadHalf, tcp::OwnedWriteHalf},
    time::timeout,
};

const DEADLINE: Duration = Duration::from_secs(5);
const FLOOR: f64 = 1e-8;
const PASSWORD: &str = "isolated-mining-fixture";
const SEED: u64 = 0x859c_06e2_8417_a33b;

fn options() -> ServerOptions {
    let address = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: address,
        p2p: address,
        stratum: address,
        stratum_password: Some(PASSWORD.into()),
        stratum_share_difficulty: FLOOR,
        ..Default::default()
    }
}
async fn isolated() -> (TempDir, Config, Node, Server) {
    isolated_with_bits(0x1f7fffff).await
}
async fn isolated_with_bits(bits: u32) -> (TempDir, Config, Node, Server) {
    isolated_with(bits, options()).await
}
/// An isolated node whose `--stratum-trusted` prefix holds 127.0.89.0/24.
async fn isolated_trusting_farm() -> (TempDir, Config, Node, Server) {
    let options = ServerOptions {
        stratum_trusted: vec!["127.0.89.0/24".parse().unwrap()],
        ..options()
    };
    isolated_with(0x1f7fffff, options).await
}
async fn isolated_with(bits: u32, options: ServerOptions) -> (TempDir, Config, Node, Server) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        - 1;
    config.initial_bits = bits;
    let node = Node::open(
        &dir.path().join("node.sqlite"),
        config.clone(),
        crypto::public_key(&[121; 32]).unwrap(),
    )
    .unwrap();
    let server = node::serve(node.clone(), options).await.unwrap();
    (dir, config, node, server)
}
async fn connect(address: SocketAddr, host: u8) -> TcpStream {
    connect_from(address, Ipv4Addr::new(127, 0, 88, host)).await
}
async fn connect_from(address: SocketAddr, source: Ipv4Addr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(IpAddr::V4(source), 0)).unwrap();
    let stream = timeout(DEADLINE, socket.connect(address))
        .await
        .unwrap()
        .unwrap();
    stream.set_nodelay(true).unwrap();
    stream
}
fn line(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
/// An unauthenticated socket that subscribed, if the node kept it waiting for
/// authorization. A refused socket is closed at once without a reply.
async fn pending_socket(address: SocketAddr, host: u8) -> Option<TcpStream> {
    let mut stream = connect(address, host).await;
    let _ = stream
        .write_all(&line(
            &json!({"id":1,"method":"mining.subscribe","params":[]}),
        ))
        .await;
    let mut reply = [0u8; 1024];
    match timeout(DEADLINE, stream.read(&mut reply))
        .await
        .expect("waiting socket was neither answered nor closed")
    {
        Ok(size) if size > 0 => Some(stream),
        _ => None,
    }
}
struct Worker {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    notices: VecDeque<Value>,
    id: u64,
    extra: Vec<u8>,
    name: String,
}
impl Worker {
    async fn connect(address: SocketAddr, host: u8) -> Self {
        Self::connect_from(address, Ipv4Addr::new(127, 0, 88, host)).await
    }
    async fn connect_from(address: SocketAddr, source: Ipv4Addr) -> Self {
        let (read, write) = connect_from(address, source).await.into_split();
        Self {
            read: BufReader::new(read),
            write,
            notices: VecDeque::new(),
            id: 0,
            extra: vec![],
            name: format!("honest.worker.{}", source.octets()[3]),
        }
    }
    async fn read(&mut self) -> Value {
        let mut bytes = Vec::new();
        let size = timeout(DEADLINE, self.read.read_until(b'\n', &mut bytes))
            .await
            .expect("mining server stopped responding")
            .unwrap();
        assert!((1..65536).contains(&size), "closed or oversized response");
        serde_json::from_slice(&bytes).unwrap()
    }
    async fn call(&mut self, method: &str, params: Value) -> Value {
        tokio::time::sleep(Duration::from_millis(130)).await;
        self.id += 1;
        self.write
            .write_all(&line(
                &json!({"id":self.id,"method":method,"params":params}),
            ))
            .await
            .unwrap();
        loop {
            let reply = self.read().await;
            if reply["id"] == self.id {
                return reply;
            }
            self.notices.push_back(reply);
            assert!(
                self.notices.len() < 128,
                "unbounded unsolicited notifications"
            );
        }
    }
    async fn job(&mut self) -> Value {
        loop {
            let value = match self.notices.pop_front() {
                Some(value) => value,
                None => self.read().await,
            };
            if value["method"] == "mining.notify" {
                return value;
            }
        }
    }
    async fn current_job(&mut self, tip: &Value) -> Value {
        for _ in 0..32 {
            let job = self.job().await;
            if hex::encode(header(&job, &self.extra, [0; 4]).previous) == tip.as_str().unwrap() {
                return job;
            }
        }
        panic!("no job for selected tip");
    }
    async fn authorize(&mut self) -> Value {
        let reply = self
            .call("mining.subscribe", json!(["adversarial-audit/1"]))
            .await;
        assert!(reply["error"].is_null(), "{reply}");
        self.extra = hex::decode(reply["result"][1].as_str().unwrap()).unwrap();
        assert_eq!(reply["result"][2], 4);
        let reply = self
            .call("mining.authorize", json!([self.name, PASSWORD]))
            .await;
        assert_eq!(reply["result"], true, "{reply}");
        self.job().await
    }
    fn submission(&self, job: &Value, header: &Header, extra2: [u8; 4]) -> Value {
        json!([
            self.name,
            job["params"][0],
            hex::encode(extra2),
            format!("{:08x}", header.timestamp),
            format!("{:08x}", header.nonce)
        ])
    }
    async fn submit(&mut self, job: &Value, header: &Header, extra2: [u8; 4]) -> Value {
        self.call("mining.submit", self.submission(job, header, extra2))
            .await
    }
}
fn header(job: &Value, extra1: &[u8], extra2: [u8; 4]) -> Header {
    let p = &job["params"];
    let number = |value: &Value| u32::from_str_radix(value.as_str().unwrap(), 16).unwrap();
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
    let mut previous: [u8; 32] = hex::decode(p[1].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    for word in previous.chunks_exact_mut(4) {
        word.reverse();
    }
    Header {
        version: number(&p[5]),
        previous,
        merkle_root: root,
        timestamp: number(&p[7]),
        bits: number(&p[6]),
        nonce: 0,
    }
}
fn proof(header: &Header) -> Amount {
    Amount::from_bytes_le(&crypto::sha256d(&codec::header_bytes(header)))
}
fn solve(mut header: Header, accept: impl Fn(&Amount) -> bool) -> Header {
    for nonce in 0..2_000_000 {
        header.nonce = nonce;
        if accept(&proof(&header)) {
            return header;
        }
    }
    panic!("fixture proof search exhausted");
}
fn reporting_target() -> Amount {
    // This slightly conservative integer target is below the exact f64 target.
    math::target_from_bits(0x1d00ffff).unwrap() * 99_999_999u64
}
fn reporting_share(job: &Value, worker: &Worker, extra2: [u8; 4]) -> Header {
    let header = header(job, &worker.extra, extra2);
    let block = math::target_from_bits(header.bits).unwrap();
    let reporting = reporting_target();
    solve(header, |hash| hash <= &reporting && hash > &block)
}
fn block_solution(job: &Value, worker: &Worker, extra2: [u8; 4]) -> Header {
    let header = header(job, &worker.extra, extra2);
    let target = math::target_from_bits(header.bits).unwrap();
    solve(header, |hash| hash <= &target)
}
async fn assert_snapshot(server: &Server, expected: &Value) {
    let snapshot = timeout(
        DEADLINE,
        node::call_rpc(&format!("http://{}/rpc", server.rpc), "snapshot", json!({})),
    )
    .await
    .expect("hostile mining traffic blocked RPC")
    .unwrap();
    for field in ["height", "tip", "state_root", "issued", "mempool"] {
        assert_eq!(
            snapshot["status"][field], expected[field],
            "changed {field}"
        );
    }
    assert_eq!(
        snapshot["status"]["state_root"],
        snapshot["governance"]["state_root"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_version_bits_require_valid_work_and_respect_later_negotiation() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut worker = Worker::connect(server.stratum, 31).await;
    let job = worker.authorize().await;
    let mut candidate = header(&job, &worker.extra, [31; 4]);
    candidate.version |= 0x046d4000;
    let block_target = math::target_from_bits(candidate.bits).unwrap();
    let reporting = reporting_target();
    let valid = solve(candidate, |hash| hash <= &reporting && hash > &block_target);
    let mut params = worker.submission(&job, &valid, [31; 4]);
    params.as_array_mut().unwrap().push(json!("046d4000"));
    assert_eq!(
        worker.call("mining.submit", params.clone()).await["result"],
        true
    );
    assert_eq!(
        worker.call("mining.submit", params.clone()).await["error"][0],
        22
    );
    params[5] = json!("20000005");
    assert!(
        worker.call("mining.submit", params).await["error"][1]
            .as_str()
            .unwrap()
            .contains("outside negotiated mask")
    );

    let mut invalid = header(&job, &worker.extra, [32; 4]);
    invalid.version |= 0x046d4000;
    let invalid = solve(invalid, |hash| hash > &(&reporting + &reporting / 100u32));
    let mut params = worker.submission(&job, &invalid, [32; 4]);
    params.as_array_mut().unwrap().push(json!("046d4000"));
    assert_eq!(worker.call("mining.submit", params).await["error"][0], 23);

    let denied = worker
        .call(
            "mining.configure",
            json!([["version-rolling"], {"version-rolling.min-bit-count":32}]),
        )
        .await;
    assert_eq!(denied["result"]["version-rolling"], false);
    let mut params = worker.submission(&job, &valid, [31; 4]);
    params.as_array_mut().unwrap().push(json!("046d4000"));
    assert!(
        worker.call("mining.submit", params).await["error"][1]
            .as_str()
            .unwrap()
            .contains("not enabled")
    );
    let ordinary = reporting_share(&job, &worker, [33; 4]);
    assert_eq!(
        worker.submit(&job, &ordinary, [33; 4]).await["result"],
        true
    );

    let configured = worker.call("mining.configure", json!([["version-rolling"], {"version-rolling.mask":"00002000", "version-rolling.min-bit-count":1}])).await;
    assert_eq!(configured["result"]["version-rolling.mask"], "00002000");
    let mut params = worker.submission(&job, &valid, [31; 4]);
    params.as_array_mut().unwrap().push(json!("046d4000"));
    assert!(
        worker.call("mining.submit", params).await["error"][1]
            .as_str()
            .unwrap()
            .contains("outside negotiated mask")
    );
    assert!(!worker.submit(&job, &ordinary, [33; 4]).await["error"].is_null());
    assert_snapshot(&server, &before).await;

    let mut candidate = header(&job, &worker.extra, [34; 4]);
    candidate.version |= 0x2000;
    let valid_block = solve(candidate, |hash| hash <= &block_target);
    let mut params = worker.submission(&job, &valid_block, [34; 4]);
    params.as_array_mut().unwrap().push(json!("00002000"));
    assert_eq!(worker.call("mining.submit", params).await["result"], true);
    assert_eq!(node.status().unwrap()["height"], 1);
    assert_eq!(
        node.rpc("getblock", json!({})).unwrap()["header"]["version"],
        valid_block.version
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_negotiations_and_seeded_fields_do_not_mutate_worker_or_chain() {
    let (_dir, config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut worker = Worker::connect(server.stratum, 1).await;
    let job = worker.authorize().await;
    // Version negotiation must remain atomic when a later extension fails.
    for bad in [json!("bad"), json!(-1), json!(1e19), json!([]), json!(null)] {
        let reply = worker
            .call(
                "mining.configure",
                json!([
                    ["version-rolling", "minimum-difficulty"],
                    {"version-rolling.mask":"00002000", "minimum-difficulty.value":bad}
                ]),
            )
            .await;
        assert!(!reply["error"].is_null(), "{reply}");
        assert_eq!(
            node.rpc("mining", json!({})).unwrap()["workers"][0]["share_difficulty"],
            FLOOR
        );
    }
    let good = reporting_share(&job, &worker, [1; 4]);
    assert_eq!(
        worker.submit(&job, &good, [1; 4]).await["result"],
        true,
        "failed configure unexpectedly enabled six-argument submissions"
    );
    let mut rng = SEED;
    for index in 0..40u32 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let extra2 = index.to_le_bytes();
        let mut candidate = header(&job, &worker.extra, extra2);
        let mut params = worker.submission(&job, &candidate, extra2);
        match index % 10 {
            0 => {
                // Names are checked after the proof of work, so a share,
                // never a block, under an unauthorized name is refused.
                candidate = reporting_share(&job, &worker, extra2);
                params = worker.submission(&job, &candidate, extra2);
                params[0] = json!(format!("other.{rng}"));
            }
            1 => params[1] = json!(format!("unknown-{rng:x}")),
            2 => params[2] = json!(format!("{:06x}", rng & 0xffffff)),
            3 => params[2] = json!(format!("{:010x}", rng & 0xffffffffff)),
            4 => params[3] = json!(rng),
            5 => params[4] = json!("fffffffff"),
            6 => params.as_array_mut().unwrap().push(json!("00000000")),
            7 => {
                candidate.timestamp = config.genesis_time.saturating_sub(1);
                params = worker.submission(&job, &candidate, extra2);
            }
            8 => {
                candidate.timestamp = u32::MAX;
                params = worker.submission(&job, &candidate, extra2);
            }
            _ => params = json!({"not":"an argument array"}),
        }
        let reply = worker.call("mining.submit", params).await;
        assert!(
            !reply["error"].is_null(),
            "mutation {index} accepted: {reply}"
        );
    }
    let good = reporting_share(&job, &worker, [88; 4]);
    assert_eq!(worker.submit(&job, &good, [88; 4]).await["result"], true);
    let configure = worker.call("mining.configure", json!([
        ["version-rolling"], {"version-rolling.mask":"ffffffff","version-rolling.min-bit-count":16}
    ])).await;
    assert_eq!(configure["result"]["version-rolling.mask"], "1fffe000");
    let mut params = worker.submission(&job, &good, [88; 4]);
    params.as_array_mut().unwrap().push(json!("80000000"));
    assert!(
        worker.call("mining.submit", params).await["error"][1]
            .as_str()
            .unwrap()
            .contains("outside negotiated mask")
    );
    assert_snapshot(&server, &before).await;
    let stats = node.rpc("mining", json!({})).unwrap();
    assert_eq!(stats["accepted_shares"], "2");
    assert_eq!(stats["rejected_shares"], "41");
    // Exercise the actual consensus header path with every permitted rolling
    // bit enabled; an error must not leave valid later work unusable.
    let mut rolled = header(&job, &worker.extra, [89; 4]);
    rolled.version |= 0x1fffe000;
    let target = math::target_from_bits(rolled.bits).unwrap();
    let rolled = solve(rolled, |hash| hash <= &target);
    let mut params = worker.submission(&job, &rolled, [89; 4]);
    params.as_array_mut().unwrap().push(json!("1fffe000"));
    assert_eq!(worker.call("mining.submit", params).await["result"], true);
    assert_eq!(node.status().unwrap()["height"], 1);
    assert_eq!(
        node.rpc("getblock", json!({})).unwrap()["header"]["version"],
        rolled.version
    );
    eprintln!(
        "seed={SEED:#x}: five atomic configure failures, 40 mutated submissions, version boundary, recovery"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abrupt_listener_restarts_keep_extranonces_unique_and_new_workers_registered() {
    let (_dir, _config, node, mut server) = isolated().await;
    let before = node.status().unwrap();
    let mut previous = Worker::connect(server.stratum, 7).await;
    previous.authorize().await;
    let mut assigned = vec![previous.extra.clone()];
    for _ in 0..4 {
        // Deliberately use Drop rather than graceful stop, so old connection
        // destructors can run after the replacement listener has started.
        drop(server);
        server = node::serve(node.clone(), options()).await.unwrap();
        let mut current = Worker::connect(server.stratum, 7).await;
        let job = current.authorize().await;
        assert!(
            !assigned.contains(&current.extra),
            "reused extranonce after restart"
        );
        assigned.push(current.extra.clone());
        drop(previous);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            node.rpc("mining", json!({})).unwrap()["workers_connected"],
            1
        );
        let share = reporting_share(&job, &current, [71; 4]);
        assert_eq!(current.submit(&job, &share, [71; 4]).await["result"], true);
        assert_eq!(
            node.rpc("mining", json!({})).unwrap()["workers"][0]["accepted_shares"],
            "1"
        );
        previous = current;
    }
    assert_snapshot(&server, &before).await;
    server.stop().await;
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers_connected"],
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_protection_survives_job_eviction_and_connection_reuse() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut worker = Worker::connect(server.stratum, 2).await;
    let first = worker.authorize().await;
    let accepted = reporting_share(&first, &worker, [17; 4]);
    assert_eq!(
        worker.submit(&first, &accepted, [17; 4]).await["result"],
        true
    );
    let old_extra = worker.extra.clone();
    let mut latest = first.clone();
    let mut issued = Vec::new();
    for index in 0..12 {
        // Alternating reporting difficulty generates distinct IDs for the same work.
        let difficulty = if index % 2 == 0 { FLOOR * 2.0 } else { FLOOR };
        assert_eq!(
            worker
                .call("mining.suggest_difficulty", json!([difficulty]))
                .await["result"],
            true
        );
        latest = worker.job().await;
        // Exceeding eight jobs on one parent retires the oldest job only. A
        // clean flush would discard work the miner may still be returning.
        assert_eq!(latest["params"][8], false, "same-parent job flushed work");
        issued.push(latest.clone());
        assert_eq!(
            worker.submit(&latest, &accepted, [17; 4]).await["error"][0],
            22
        );
    }
    assert_eq!(
        worker.submit(&first, &accepted, [17; 4]).await["error"][0],
        21
    );
    // Thirteen jobs were issued: the oldest five are retired, the newest eight remain.
    let retired = &issued[issued.len() - 9];
    let share = reporting_share(retired, &worker, [19; 4]);
    assert_eq!(
        worker.submit(retired, &share, [19; 4]).await["error"][0],
        21
    );
    let oldest_retained = &issued[issued.len() - 8];
    let bits = header(oldest_retained, &worker.extra, [0; 4]).bits;
    let block = math::target_from_bits(bits).unwrap();
    let doubled = reporting_target() / 2u32;
    let share = solve(header(oldest_retained, &worker.extra, [20; 4]), |hash| {
        hash <= &doubled && hash > &block
    });
    assert_eq!(
        worker.submit(oldest_retained, &share, [20; 4]).await["result"],
        true
    );
    let fresh = reporting_share(&latest, &worker, [18; 4]);
    assert_eq!(
        worker.submit(&latest, &fresh, [18; 4]).await["result"],
        true
    );
    worker.write.shutdown().await.unwrap();
    drop(worker);
    let mut reconnected = Worker::connect(server.stratum, 2).await;
    let current = reconnected.authorize().await;
    assert_ne!(reconnected.extra, old_extra);
    assert_ne!(
        header(&current, &reconnected.extra, [17; 4]).merkle_root,
        accepted.merkle_root
    );
    let fresh = reporting_share(&current, &reconnected, [17; 4]);
    assert_eq!(
        reconnected.submit(&current, &fresh, [17; 4]).await["result"],
        true
    );
    assert_snapshot(&server, &before).await;
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["accepted_shares"],
        "4"
    );
    server.stop().await;
}

async fn hostile_exchange(address: SocketAddr, host: u8, bytes: Vec<u8>) -> usize {
    let mut stream = connect(address, host).await;
    let _ = stream.write_all(&bytes).await;
    let _ = stream.shutdown().await;
    let mut reply = Vec::new();
    let result = timeout(DEADLINE, (&mut stream).take(131072).read_to_end(&mut reply))
        .await
        .expect("hostile connection did not close");
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
        ));
    }
    assert!(reply.len() < 131072);
    reply.len()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_workers_and_rpc_continue_during_concurrent_hostile_miners() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut alice = Worker::connect(server.stratum, 3).await;
    let a_job = alice.authorize().await;
    let mut bob = Worker::connect(server.stratum, 4).await;
    let b_job = bob.authorize().await;
    assert_ne!(alice.extra, bob.extra);
    let address = server.stratum;
    let attacks = tokio::spawn(async move {
        let mut completed = 0;
        for round in 0..8u8 {
            let mut tasks = tokio::task::JoinSet::new();
            for kind in 0..4u8 {
                let payload = match kind {
                    0 => vec![0xff, b'\n'],
                    1 => format!("{}0{}\n", "[".repeat(80), "]".repeat(80)).into_bytes(),
                    2 => vec![b' '; 16385],
                    _ => (0..64).flat_map(|id| line(&json!({"id":id,"method":"mining.suggest_difficulty","params":[FLOOR]}))).collect(),
                };
                tasks.spawn(hostile_exchange(address, 100 + round * 4 + kind, payload));
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
                completed += 1;
            }
            tokio::time::sleep(Duration::from_millis(180)).await;
        }
        completed
    });
    let a = tokio::spawn(async move {
        for index in 0..20u32 {
            let extra = (index + 100).to_le_bytes();
            let share = reporting_share(&a_job, &alice, extra);
            assert_eq!(alice.submit(&a_job, &share, extra).await["result"], true);
        }
        alice
    });
    let b = tokio::spawn(async move {
        for index in 0..20u32 {
            let extra = (index + 200).to_le_bytes();
            let share = reporting_share(&b_job, &bob, extra);
            assert_eq!(bob.submit(&b_job, &share, extra).await["result"], true);
        }
        bob
    });
    for _ in 0..20 {
        assert_snapshot(&server, &before).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (alice, bob, attacks) = tokio::join!(a, b, attacks);
    let (_alice, _bob) = (alice.unwrap(), bob.unwrap());
    assert_eq!(attacks.unwrap(), 32);
    assert_snapshot(&server, &before).await;
    let mining = node.rpc("mining", json!({})).unwrap();
    assert_eq!(mining["workers_connected"], 2);
    assert_eq!(mining["accepted_shares"], "40");
    assert_eq!(mining["blocks_found"], "0");
    eprintln!(
        "two honest workers: 40 accepted shares during 32 hostile sessions and 20 coherent RPC snapshots"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_mining_socket_budget_preserves_existing_workers_and_reclaims_capacity() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let mut alice = Worker::connect(server.stratum, 8).await;
    let a_job = alice.authorize().await;
    let mut bob = Worker::connect(server.stratum, 9).await;
    let b_job = bob.authorize().await;
    let mut held = Vec::new();
    for index in 0..node::MAX_CONNECTIONS {
        // A source waits in at most four slots. Unauthenticated sockets equal
        // to the whole authorized worker capacity must not lock out a new miner.
        let mut stream = connect(server.stratum, 50 + (index / 4) as u8).await;
        stream.write_all(b"{").await.unwrap();
        held.push(stream);
    }
    let mut carol = Worker::connect(server.stratum, 10).await;
    let c_job = carol.authorize().await;
    for index in 0..node::MAX_CONNECTIONS {
        // The general pre-authorization slots hold twice the worker capacity.
        let mut stream = connect(server.stratum, 66 + (index / 4) as u8).await;
        stream.write_all(b"{").await.unwrap();
        held.push(stream);
    }
    assert!(
        hostile_exchange(
            server.stratum,
            82,
            line(&json!({
                "id":1,"method":"mining.subscribe","params":[]
            }))
        )
        .await
            == 0,
        "mining connection limit was not enforced"
    );
    // An address that has authorized keeps reserved slots, so the operator's
    // miners can still reconnect while the general slots are full.
    let mut again = Worker::connect(server.stratum, 8).await;
    let d_job = again.authorize().await;
    let share = reporting_share(&d_job, &again, [8; 4]);
    assert_eq!(again.submit(&d_job, &share, [8; 4]).await["result"], true);
    for index in 0..5u32 {
        let extra = (index + 300).to_le_bytes();
        let a_share = reporting_share(&a_job, &alice, extra);
        let b_share = reporting_share(&b_job, &bob, extra);
        let c_share = reporting_share(&c_job, &carol, extra);
        let (a, b, c) = tokio::join!(
            alice.submit(&a_job, &a_share, extra),
            bob.submit(&b_job, &b_share, extra),
            carol.submit(&c_job, &c_share, extra),
        );
        assert_eq!(a["result"], true);
        assert_eq!(b["result"], true);
        assert_eq!(c["result"], true);
        assert_snapshot(&server, &before).await;
    }
    drop(held);
    // Let the accept loop observe closure of the deliberately incomplete frames.
    // Their source addresses retain penalties; an unrelated worker can reconnect.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut fresh = Worker::connect(server.stratum, 83).await;
    let job = fresh.authorize().await;
    let share = reporting_share(&job, &fresh, [66; 4]);
    assert_eq!(fresh.submit(&job, &share, [66; 4]).await["result"], true);
    assert_snapshot(&server, &before).await;
    let mining = node.rpc("mining", json!({})).unwrap();
    assert_eq!(mining["workers_connected"], 5);
    assert_eq!(mining["accepted_shares"], "17");
    eprintln!(
        "128 hostile partial connections from 32 sources filled the general pre-authorization slots; a known address reconnected; miners and RPC remained live; capacity recovered"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn competing_blocks_and_repeated_reorgs_refresh_all_workers_without_double_issuance() {
    let (dir, config, node, server) = isolated().await;
    let mut alice = Worker::connect(server.stratum, 5).await;
    let mut bob = Worker::connect(server.stratum, 6).await;
    let a_job = alice.authorize().await;
    let b_job = bob.authorize().await;
    let a_block = block_solution(&a_job, &alice, [1; 4]);
    let b_block = block_solution(&b_job, &bob, [1; 4]);
    assert_ne!(a_block.merkle_root, b_block.merkle_root);
    let (a_reply, b_reply) = tokio::join!(
        alice.submit(&a_job, &a_block, [1; 4]),
        bob.submit(&b_job, &b_block, [1; 4])
    );
    let replies = [a_reply, b_reply];
    let accepted = replies.iter().filter(|v| v["result"] == true).count();
    // Equal-work siblings cannot both become the tip. The loser is stale even
    // when it passed the parent check before the winner was connected.
    assert_eq!(accepted, 1, "{replies:?}");
    assert!(replies.iter().any(|v| v["error"][0] == 21), "{replies:?}");
    assert_eq!(node.rpc("mining", json!({})).unwrap()["blocks_found"], "1");
    let status = node.status().unwrap();
    assert_eq!(status["height"], 1);
    assert_eq!(
        status["issued"],
        math::work(&math::target_from_bits(a_block.bits).unwrap()).to_str_radix(10)
    );
    let mut a_job = alice.current_job(&status["tip"]).await;
    let mut b_job = bob.current_job(&status["tip"]).await;
    for round in 0..3u8 {
        let rival = Node::open(
            &dir.path().join(format!("rival-{round}.sqlite")),
            config.clone(),
            crypto::public_key(&[130 + round; 32]).unwrap(),
        )
        .unwrap();
        let target_height = node.status().unwrap()["height"].as_u64().unwrap() + 2;
        for _ in 0..target_height {
            rival.mine(2_000_000).unwrap();
        }
        let rival_server = node::serve(rival.clone(), options()).await.unwrap();
        timeout(DEADLINE, node::sync_peer(&node, rival_server.p2p))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            node.status().unwrap()["tip"],
            rival.status().unwrap()["tip"]
        );
        let stale_a = header(&a_job, &alice.extra, [2; 4]);
        let stale_b = header(&b_job, &bob.extra, [2; 4]);
        let (a, b) = tokio::join!(
            alice.submit(&a_job, &stale_a, [2; 4]),
            bob.submit(&b_job, &stale_b, [2; 4])
        );
        assert_eq!(a["error"][0], 21);
        assert_eq!(b["error"][0], 21);
        let current = node.status().unwrap();
        a_job = alice.current_job(&current["tip"]).await;
        b_job = bob.current_job(&current["tip"]).await;
        assert_eq!(a_job["params"][8], true);
        assert_eq!(b_job["params"][8], true);
        for field in ["state_root", "issued", "height"] {
            assert_eq!(current[field], rival.status().unwrap()[field]);
        }
        rival_server.stop().await;
    }
    let final_block = block_solution(&a_job, &alice, [44; 4]);
    assert_eq!(
        alice.submit(&a_job, &final_block, [44; 4]).await["result"],
        true
    );
    let expected = node.status().unwrap();
    let bob_job = bob.current_job(&expected["tip"]).await;
    assert_eq!(bob_job["params"][8], true);
    server.stop().await;
    drop(node);
    let reopened = Node::open(
        &dir.path().join("node.sqlite"),
        config,
        crypto::public_key(&[121; 32]).unwrap(),
    )
    .unwrap();
    for field in ["height", "tip", "state_root", "issued"] {
        assert_eq!(
            reopened.status().unwrap()[field],
            expected[field],
            "replay changed {field}"
        );
    }
    eprintln!(
        "simultaneous block submissions: {accepted} acknowledged; three fresh-branch reorgs; both workers refreshed; replay identical"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_parent_template_churn_neither_flushes_nor_evicts_inflight_jobs() {
    let (_dir, config, node, server) = isolated().await;
    let secret = [121; 32];
    let public = crypto::public_key(&secret).unwrap();
    node.mine(2_000_000).unwrap();
    let mut worker = Worker::connect(server.stratum, 41).await;
    let first = worker.authorize().await;
    let issued = Instant::now();
    let anchor = codec::block_hash(&codec::genesis_block(&config).unwrap());
    // Each transaction changes the template on the same parent, as cheap
    // fee-bump replacement churn would.
    for nonce in 0..12u64 {
        let body = TransactionBody {
            data: Vec::new(),
            sender: public,
            nonce,
            fee: 1u32.into(),
            anchor,
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: public,
                amount: 1u32.into(),
            },
        };
        node.submit_transaction(crypto::sign(&config.chain_id(), &body, &secret).unwrap())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.status().unwrap()["mempool"], 12);
    let refreshed = worker.job().await;
    assert!(
        issued.elapsed() >= Duration::from_millis(1500),
        "same-parent template changes were not coalesced"
    );
    assert_eq!(refreshed["params"][1], first["params"][1]);
    assert_ne!(refreshed["params"][3], first["params"][3]);
    assert_eq!(
        refreshed["params"][8], false,
        "same-parent refresh flushed in-flight work"
    );
    // Work on the first job still produces a valid block on the unchanged parent.
    let solution = block_solution(&first, &worker, [41; 4]);
    let reply = worker.submit(&first, &solution, [41; 4]).await;
    assert_eq!(reply["result"], true, "{reply}");
    assert_eq!(node.status().unwrap()["height"], 2);
    let next = worker.job().await;
    assert_eq!(next["params"][8], true, "a new tip replaces work at once");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unauthorized_mining_sockets_expire_quickly_and_charge_their_address() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    let started = Instant::now();
    let mut idle = Vec::new();
    for _ in 0..4 {
        let mut stream = connect(server.stratum, 70).await;
        stream
            .write_all(&line(
                &json!({"id":1,"method":"mining.subscribe","params":[]}),
            ))
            .await
            .unwrap();
        idle.push(stream);
    }
    for stream in &mut idle {
        let mut reply = Vec::new();
        let _ = timeout(
            Duration::from_secs(14),
            (&mut *stream).take(65536).read_to_end(&mut reply),
        )
        .await
        .expect("unauthorized socket outlived the authorization window");
        assert!(!reply.is_empty(), "subscribe was not answered");
    }
    assert!(started.elapsed() >= Duration::from_secs(9));
    // Every expired socket spent a whole window of its address's waiting
    // budget, so idle sockets cannot hold slots by reconnecting at no cost.
    assert!(
        pending_socket(server.stratum, 70).await.is_none(),
        "expired address was not charged for its wait"
    );
    let mut honest = Worker::connect(server.stratum, 71).await;
    let job = honest.authorize().await;
    let share = reporting_share(&job, &honest, [70; 4]);
    assert_eq!(honest.submit(&job, &share, [70; 4]).await["result"], true);
    assert_snapshot(&server, &before).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worker_capacity_is_enforced_at_registration_without_penalty() {
    let (_dir, _config, node, server) = isolated().await;
    let address = server.stratum;
    // Without trusted prefixes no worker slot is held back for them.
    let capacity = node::MAX_CONNECTIONS;
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..capacity {
        tasks.spawn(async move {
            let mut worker = Worker::connect(address, 80 + (index / 4) as u8).await;
            worker.authorize().await;
            worker
        });
    }
    let mut workers = Vec::new();
    while let Some(worker) = tasks.join_next().await {
        workers.push(worker.unwrap());
    }
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers_connected"],
        capacity
    );
    // Pending connections have their own pool, so a full registry is reported
    // at authorization. The session never becomes an unregistered worker.
    let mut extra = Worker::connect(address, 96).await;
    let reply = extra.call("mining.subscribe", json!(["capacity/1"])).await;
    assert!(reply["error"].is_null(), "{reply}");
    let name = extra.name.clone();
    let reply = extra
        .call("mining.authorize", json!([name, PASSWORD]))
        .await;
    assert!(
        reply["error"][1].as_str().unwrap().contains("capacity"),
        "{reply}"
    );
    let mut rest = Vec::new();
    let _ = timeout(DEADLINE, extra.read.read_to_end(&mut rest))
        .await
        .expect("capacity failure left the session open");
    drop(workers.pop());
    for _ in 0..100 {
        if node.rpc("mining", json!({})).unwrap()["workers_connected"] == capacity - 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Capacity is not misbehaviour: the same address may retry at once.
    let mut retry = Worker::connect(address, 96).await;
    let job = retry.authorize().await;
    let share = reporting_share(&job, &retry, [96; 4]);
    assert_eq!(retry.submit(&job, &share, [96; 4]).await["result"], true);
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers_connected"],
        capacity
    );
    server.stop().await;
}

/// Workers authorized at once, one from each of `sources`, which may repeat
/// an address, with the job each received.
async fn authorize_from(address: SocketAddr, sources: Vec<Ipv4Addr>) -> Vec<(Worker, Value)> {
    let mut tasks = tokio::task::JoinSet::new();
    for source in sources {
        tasks.spawn(async move {
            let mut worker = Worker::connect_from(address, source).await;
            let job = worker.authorize().await;
            (worker, job)
        });
    }
    let mut workers = Vec::new();
    while let Some(worker) = tasks.join_next().await {
        workers.push(worker.unwrap());
    }
    workers
}
async fn refused_for_capacity(address: SocketAddr, source: Ipv4Addr) {
    let mut worker = Worker::connect_from(address, source).await;
    let reply = worker.call("mining.subscribe", json!(["capacity/1"])).await;
    assert!(reply["error"].is_null(), "{reply}");
    let name = worker.name.clone();
    let reply = worker
        .call("mining.authorize", json!([name, PASSWORD]))
        .await;
    assert!(
        reply["error"][1].as_str().unwrap().contains("capacity"),
        "{reply}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trusted_prefixes_keep_reserved_worker_slots_when_others_fill_theirs() {
    let (_dir, _config, node, server) = isolated_trusting_farm().await;
    let address = server.stratum;
    let general = node::MAX_CONNECTIONS - node::STRATUM_TRUSTED_WORKERS;
    // Holders of the password outside the trusted prefix fill their slots.
    let others = (0..general).map(|index| Ipv4Addr::new(127, 0, 88, 100 + (index / 4) as u8));
    let mut workers = authorize_from(address, others.collect()).await;
    refused_for_capacity(address, Ipv4Addr::new(127, 0, 88, 150)).await;
    // The operator's farm still connects every reserved worker, from one address.
    let farm = vec![Ipv4Addr::new(127, 0, 89, 1); node::STRATUM_TRUSTED_WORKERS];
    workers.extend(authorize_from(address, farm).await);
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers_connected"],
        node::MAX_CONNECTIONS
    );
    refused_for_capacity(address, Ipv4Addr::new(127, 0, 89, 2)).await;
    let (farmer, job) = workers.last_mut().unwrap();
    let share = reporting_share(job, farmer, [89; 4]);
    assert_eq!(farmer.submit(job, &share, [89; 4]).await["result"], true);
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trusted_proxy_address_connects_more_workers_than_the_per_address_limit() {
    let (_dir, _config, node, server) = isolated_trusting_farm().await;
    let address = server.stratum;
    let proxy = Ipv4Addr::new(127, 0, 89, 7);
    // A marketplace proxy opens one upstream connection per rented rig from
    // one address. Authorized, they stop counting toward its 16 connections;
    // only connections awaiting authorization still do.
    let mut workers = authorize_from(address, vec![proxy; 12]).await;
    // Admission still spends the address's connection rate.
    tokio::time::sleep(Duration::from_secs(1)).await;
    workers.extend(authorize_from(address, vec![proxy; 12]).await);
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers_connected"],
        24
    );
    for (index, (worker, job)) in workers.iter_mut().enumerate().step_by(5) {
        let extra = (index as u32 + 500).to_le_bytes();
        let share = reporting_share(job, worker, extra);
        assert_eq!(worker.submit(job, &share, extra).await["result"], true);
    }
    // Other addresses keep their limit.
    let crowd = vec![Ipv4Addr::new(127, 0, 88, 160); 4];
    authorize_from(address, crowd).await;
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_connection_authorizes_several_names_and_never_drops_a_block_for_its_name() {
    let (_dir, _config, node, server) = isolated().await;
    let mut proxy = Worker::connect(server.stratum, 33).await;
    let job = proxy.authorize().await;
    // A proxy authorizes each miner behind it on its one upstream connection;
    // each name needs the password, and a wrong one keeps the connection.
    let reply = proxy
        .call("mining.authorize", json!(["rig.2", PASSWORD]))
        .await;
    assert_eq!(reply["result"], true, "{reply}");
    let reply = proxy
        .call("mining.authorize", json!(["rig.3", "wrong"]))
        .await;
    assert_eq!(reply["result"], false, "{reply}");
    let share = reporting_share(&job, &proxy, [33; 4]);
    let mut params = proxy.submission(&job, &share, [33; 4]);
    params[0] = json!("rig.2");
    assert_eq!(proxy.call("mining.submit", params).await["result"], true);
    // A share under a name never authorized is refused.
    let share = reporting_share(&job, &proxy, [34; 4]);
    let mut params = proxy.submission(&job, &share, [34; 4]);
    params[0] = json!("rig.3");
    let reply = proxy.call("mining.submit", params).await;
    assert_eq!(reply["error"][1], "worker mismatch", "{reply}");
    // A solved block is checked before the name and always submitted.
    let block = block_solution(&job, &proxy, [35; 4]);
    let mut params = proxy.submission(&job, &block, [35; 4]);
    params[0] = json!("rig.3");
    assert_eq!(proxy.call("mining.submit", params).await["result"], true);
    assert_eq!(node.status().unwrap()["height"], 1);
    let mining = node.rpc("mining", json!({})).unwrap();
    assert_eq!(mining["workers_connected"], 1);
    assert_eq!(mining["workers"][0]["worker"], proxy.name);
    assert_eq!(mining["blocks_found"], "1");
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_reporting_streams_raise_their_own_difficulty_instead_of_disconnecting() {
    // Network difficulty well above the floor, so raised reporting
    // difficulty is not capped at block difficulty.
    let (_dir, _config, node, server) = isolated_with_bits(0x1e7fffff).await;
    let mut worker = Worker::connect(server.stratum, 42).await;
    let job = worker.authorize().await;
    // A miner far above the session rate sends its shares without waiting
    // for replies, as an ASIC with too low a difficulty would.
    const SHARES: u32 = 48;
    let mut burst = Vec::new();
    for index in 0..SHARES {
        let extra = (index + 400).to_le_bytes();
        let share = reporting_share(&job, &worker, extra);
        worker.id += 1;
        burst.extend(line(&json!({
            "id":worker.id,"method":"mining.submit","params":worker.submission(&job, &share, extra)
        })));
    }
    worker.write.write_all(&burst).await.unwrap();
    let (mut accepted, mut limited, mut replies) = (0, 0, 0);
    let mut raised = FLOOR;
    while replies < SHARES {
        let message = worker.read().await;
        if message["method"] == "mining.set_difficulty" {
            raised = raised.max(message["params"][0].as_f64().unwrap());
            continue;
        }
        if message["method"] == "mining.notify" {
            worker.notices.push_back(message);
            continue;
        }
        replies += 1;
        if message["result"] == true {
            accepted += 1;
        } else {
            // Past the session rate a share is refused, not disconnected.
            assert_eq!(message["error"][0], 20, "{message}");
            assert!(
                message["error"][1].as_str().unwrap().contains("rate limit"),
                "{message}"
            );
            limited += 1;
        }
    }
    assert!(limited > 0, "the burst never exceeded the session rate");
    // One measurement raised difficulty by a power of two at once. The wire
    // value is compared after rounding, since JSON float parsing may differ
    // from the exact value by one unit in the last place.
    let factor = (raised / FLOOR).round();
    assert!(factor >= 8.0 && factor.log2().fract() == 0.0, "{factor}");
    let notices = std::mem::take(&mut worker.notices);
    let current = notices
        .iter()
        .rev()
        .find(|message| message["method"] == "mining.notify")
        .expect("raised difficulty arrived without a job")
        .clone();
    assert_eq!(current["params"][1], job["params"][1]);
    assert_eq!(current["params"][8], false);
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["workers"][0]["share_difficulty"],
        FLOOR * factor
    );
    // Once its session budget refills, the same connection mines the raised
    // job, and work already assigned keeps its original difficulty.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let header = header(&current, &worker.extra, [42; 4]);
    let block = math::target_from_bits(header.bits).unwrap();
    let hard = math::target_from_bits(0x1d00ffff).unwrap() * ((1e8 / factor) as u64 - 1);
    let share = solve(header, |hash| hash <= &hard && hash > &block);
    assert_eq!(
        worker.submit(&current, &share, [42; 4]).await["result"],
        true
    );
    let extra = 999u32.to_le_bytes();
    let share = reporting_share(&job, &worker, extra);
    assert_eq!(worker.submit(&job, &share, extra).await["result"], true);
    assert_eq!(
        node.rpc("mining", json!({})).unwrap()["accepted_shares"],
        (accepted + 2).to_string()
    );
    eprintln!(
        "{SHARES} pipelined shares: {accepted} accepted, {limited} refused past the session rate, difficulty raised x{factor}, connection kept"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotating_clean_closing_sockets_cannot_hold_the_pre_authorization_slots() {
    let (_dir, _config, node, server) = isolated().await;
    let before = node.status().unwrap();
    // Eight addresses try to keep sixteen sockets each waiting. Each socket
    // subscribes, never authorizes and closes cleanly just before the
    // authorization window would expire it, ready to reconnect.
    let mut held = Vec::new();
    for index in 0..128usize {
        let opened = Instant::now();
        if let Some(stream) = pending_socket(server.stratum, 140 + (index / 16) as u8).await {
            held.push((opened, stream));
        }
    }
    assert_eq!(held.len(), 32, "a source waited in more than four slots");
    // An honest miner from another address still connects and mines.
    let mut honest = Worker::connect(server.stratum, 150).await;
    let job = honest.authorize().await;
    let share = reporting_share(&job, &honest, [150; 4]);
    assert_eq!(honest.submit(&job, &share, [150; 4]).await["result"], true);
    for (opened, mut stream) in held {
        tokio::time::sleep_until((opened + Duration::from_millis(9_700)).into()).await;
        let _ = stream.shutdown().await;
    }
    // The clean closes still paid for the time waited, so the same sources
    // cannot take the slots again at once.
    let mut reopened = 0;
    for index in 0..128usize {
        if pending_socket(server.stratum, 140 + (index / 16) as u8)
            .await
            .is_some()
        {
            reopened += 1;
        }
    }
    assert_eq!(reopened, 0, "rotating before the window avoided its cost");
    let mut later = Worker::connect(server.stratum, 151).await;
    let job = later.authorize().await;
    let share = reporting_share(&job, &later, [151; 4]);
    assert_eq!(later.submit(&job, &share, [151; 4]).await["result"], true);
    assert_snapshot(&server, &before).await;
    server.stop().await;
}
