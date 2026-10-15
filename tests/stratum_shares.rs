//! External worker tests: build work only from Stratum messages, honor share
//! difficulty, and distinguish pool acknowledgements from consensus rewards.
use hashstash::{
    codec,
    config::Config,
    crypto, math,
    node::{self, Node, ServerOptions},
    types::{Amount, Header},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::timeout,
};

fn options(difficulty: f64) -> ServerOptions {
    ServerOptions {
        rpc: "127.0.0.1:0".parse().unwrap(),
        p2p: "127.0.0.1:0".parse().unwrap(),
        stratum: "127.0.0.1:0".parse().unwrap(),
        stratum_share_difficulty: difficulty,
        ..Default::default()
    }
}

struct Worker {
    read: BufReader<OwnedReadHalf>,
    write: OwnedWriteHalf,
    notices: VecDeque<Value>,
    id: u64,
    extra: Vec<u8>,
    difficulty: f64,
}
impl Worker {
    async fn connect(address: std::net::SocketAddr) -> Self {
        let (read, write) = TcpStream::connect(address).await.unwrap().into_split();
        Self {
            read: BufReader::new(read),
            write,
            notices: VecDeque::new(),
            id: 0,
            extra: vec![],
            difficulty: 0.0,
        }
    }
    async fn read(&mut self) -> Value {
        let mut line = String::new();
        let count = timeout(Duration::from_secs(5), self.read.read_line(&mut line))
            .await
            .expect("Stratum response timeout")
            .unwrap();
        assert!(count > 0, "Stratum disconnected");
        let mut message: Value = serde_json::from_str(&line).unwrap();
        if message["method"] == "mining.set_difficulty" {
            // serde_json's default fast float parser can move a small number
            // by one ULP. Use Rust's correctly rounded parser for the raw wire
            // token so the exact target check measures the advertised value.
            let token = line
                .split_once("\"params\":[")
                .unwrap()
                .1
                .split_once(']')
                .unwrap()
                .0;
            message["params"][0] = json!(token.parse::<f64>().unwrap());
        }
        message
    }
    async fn call(&mut self, method: &str, params: Value) -> Value {
        // Stay within the real public-facing session request policy.
        tokio::time::sleep(Duration::from_millis(130)).await;
        self.id += 1;
        let mut bytes =
            serde_json::to_vec(&json!({"id":self.id,"method":method,"params":params})).unwrap();
        bytes.push(b'\n');
        self.write.write_all(&bytes).await.unwrap();
        loop {
            let value = self.read().await;
            if value["id"] == self.id {
                return value;
            }
            self.notices.push_back(value);
        }
    }
    async fn job(&mut self) -> Value {
        loop {
            let notice = if let Some(value) = self.notices.pop_front() {
                value
            } else {
                self.read().await
            };
            if notice["method"] == "mining.set_difficulty" {
                self.difficulty = notice["params"][0].as_f64().unwrap();
            } else if notice["method"] == "mining.notify" {
                return notice;
            }
        }
    }
    async fn authorize(&mut self, zero_mask: bool) -> Value {
        if zero_mask {
            let result = self.call("mining.configure", json!([["version-rolling"],{"version-rolling.mask":"00000000","version-rolling.min-bit-count":0}])).await;
            assert_eq!(result["result"]["version-rolling"], true);
            assert_eq!(result["result"]["version-rolling.mask"], "00000000");
        }
        let subscribe = self
            .call("mining.subscribe", json!(["independent-worker/1"]))
            .await;
        self.extra = hex::decode(subscribe["result"][1].as_str().unwrap()).unwrap();
        assert_eq!(subscribe["result"][2], 4);
        assert_eq!(
            self.call("mining.authorize", json!(["rental.worker", "x"]))
                .await["result"],
            true
        );
        self.job().await
    }
    async fn submit(
        &mut self,
        job: &Value,
        header: &Header,
        extra2: [u8; 4],
        zero_mask: bool,
    ) -> Value {
        let mut params = vec![
            json!("rental.worker"),
            job["params"][0].clone(),
            json!(hex::encode(extra2)),
            json!(format!("{:08x}", header.timestamp)),
            json!(format!("{:08x}", header.nonce)),
        ];
        if zero_mask {
            params.push(json!("00000000"));
        }
        self.call("mining.submit", json!(params)).await
    }
}

fn header(job: &Value, extra1: &[u8], extra2: [u8; 4]) -> Header {
    let p = &job["params"];
    let number = |v: &Value| u32::from_str_radix(v.as_str().unwrap(), 16).unwrap();
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

fn solve(mut header: Header, accept: impl Fn(&Amount) -> bool) -> Header {
    for nonce in 0..5_000_000 {
        header.nonce = nonce;
        let hash = Amount::from_bytes_le(&crypto::sha256d(&codec::header_bytes(&header)));
        if accept(&hash) {
            return header;
        }
    }
    panic!("test target was not solved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn compact_worker_mines_transactions_with_empty_branch_and_rolls_extranonce() {
    compact_transaction_worker_roundtrip(Config::testnet(), vec![]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_worker_mines_signed_bytes_with_empty_branch_and_rolls_extranonce() {
    compact_transaction_worker_roundtrip(Config::testnet(), (0u8..=255).collect()).await;
}

async fn compact_transaction_worker_roundtrip(mut c: Config, data: Vec<u8>) {
    use hashstash::types::{Block, Operation, TransactionBody};
    let dir = tempfile::tempdir().unwrap();
    let secret = [61; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let recipient = crypto::public_key(&[62; 32]).unwrap();
    c.initial_bits = 0x2000ffff;
    c.limit_bits = c.initial_bits;
    let path = dir.path().join("compact-tx.db");
    let n = Node::open(&path, c.clone(), miner).unwrap();
    n.mine(1_000_000).unwrap();
    let tx = crypto::sign(
        &TransactionBody {
            chain_id: c.chain_id(),
            sender: miner,
            nonce: 0,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(&c).unwrap()),
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient,
                amount: 7u32.into(),
            },
            data: data.clone(),
        },
        &secret,
    )
    .unwrap();
    n.submit_transaction(tx.clone()).unwrap();
    assert_eq!(n.template().unwrap().transactions, vec![tx.clone()]);
    let server = node::serve(n.clone(), options(65536.0)).await.unwrap();
    let mut worker = Worker::connect(server.stratum).await;
    let job = worker.authorize(true).await;
    assert!(job["params"][4].as_array().unwrap().is_empty());
    let suffix = hex::decode(job["params"][3].as_str().unwrap()).unwrap();
    assert!(suffix.windows(4).any(|p| p == b"HST!"));
    let target = math::target_from_bits(c.initial_bits).unwrap();
    let a = header(&job, &worker.extra, [1; 4]);
    let b = header(&job, &worker.extra, [2; 4]);
    assert_ne!(a.merkle_root, b.merkle_root);
    let a = solve(a, |h| h <= &target);
    let b = solve(b, |h| h <= &target);
    assert_eq!(worker.submit(&job, &a, [1; 4], true).await["result"], true);
    assert_eq!(n.status().unwrap()["height"], 2);
    let mined: Block =
        serde_json::from_value(n.rpc("getblock", json!({"height":2})).unwrap()).unwrap();
    assert_eq!(mined.header, a);
    assert_eq!(mined.transactions, vec![tx.clone()]);
    assert_eq!(mined.transactions[0].body.data, data);
    assert_eq!(
        n.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "7"
    );
    assert_eq!(worker.submit(&job, &b, [2; 4], true).await["error"][0], 21);
    assert!(n.template().unwrap().transactions.is_empty());
    n.mine(1_000_000).unwrap();
    assert_eq!(n.status().unwrap()["height"], 3);
    assert_eq!(
        n.rpc("account", json!({"key":hex::encode(recipient)}))
            .unwrap()["account"]["ordinary"],
        "7",
        "rejected old work does not execute the transfer again"
    );
    let status = n.status().unwrap();
    drop(worker);
    server.stop().await;
    drop(n);
    let reopened = Node::open(&path, c, miner).unwrap();
    assert_eq!(reopened.status().unwrap()["tip"], status["tip"]);
    assert_eq!(
        reopened.status().unwrap()["state_root"],
        status["state_root"]
    );
    let persisted: Block =
        serde_json::from_value(reopened.rpc("getblock", json!({"height":2})).unwrap()).unwrap();
    assert_eq!(
        persisted, mined,
        "Stratum-mined block survives database replay"
    );
    assert_eq!(persisted.transactions[0].body.data, data);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shares_difficulty_changes_duplicates_blocks_and_reorgs() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::devnet();
    c.genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        - 1;
    c.initial_bits = 0x1f7fffff; // About 512 hashes/block; shares below take about 43.
    let miner = crypto::public_key(&[41; 32]).unwrap();
    let a = Node::open(&dir.path().join("a.db"), c.clone(), miner).unwrap();
    let server = node::serve(a.clone(), options(1e-8)).await.unwrap();
    let mut worker = Worker::connect(server.stratum).await;
    let job = worker.authorize(true).await;
    let initial = a.status().unwrap();
    let share_target = math::target_from_bits(0x1d00ffff).unwrap() * 100_000_000u64;
    let first = header(&job, &worker.extra, [1; 4]);
    let block_target = math::target_from_bits(first.bits).unwrap();
    let first = solve(first, |hash| hash <= &share_target && hash > &block_target);
    assert_eq!(
        worker.submit(&job, &first, [1; 4], true).await["result"],
        true
    );
    assert_eq!(a.status().unwrap()["height"], initial["height"]);
    assert_eq!(
        a.status().unwrap()["issued"],
        initial["issued"],
        "reporting shares must not mint HASH"
    );
    assert_eq!(
        worker.submit(&job, &first, [1; 4], true).await["error"][0],
        22
    );
    let bad = solve(header(&job, &worker.extra, [2; 4]), |hash| {
        hash > &share_target
    });
    assert_eq!(
        worker.submit(&job, &bad, [2; 4], true).await["error"][0],
        23
    );

    assert_eq!(
        worker
            .call("mining.suggest_difficulty", json!([2e-8]))
            .await["result"],
        true
    );
    let harder_job = worker.job().await;
    // The same header under a new job ID must not be credited twice.
    assert_eq!(
        worker.submit(&harder_job, &first, [1; 4], true).await["error"][0],
        22
    );
    let old_only = solve(header(&job, &worker.extra, [3; 4]), |hash| {
        hash <= &share_target && hash > &(&share_target / 2u32) && hash > &block_target
    });
    assert_eq!(
        worker.submit(&job, &old_only, [3; 4], true).await["result"],
        true,
        "retained jobs keep their original difficulty"
    );
    let mut future = header(&harder_job, &worker.extra, [4; 4]);
    future.timestamp += c.future_seconds + 3600;
    let future = solve(future, |hash| {
        hash <= &(&share_target / 2u32) && hash > &block_target
    });
    assert!(
        !worker.submit(&harder_job, &future, [4; 4], true).await["error"].is_null(),
        "invalid timestamp must not count as a share"
    );

    let minimum = worker
        .call(
            "mining.configure",
            json!([["minimum-difficulty"],{"minimum-difficulty.value":65536.0}]),
        )
        .await;
    assert_eq!(minimum["result"]["minimum-difficulty"], false);
    assert_eq!(
        worker
            .call("mining.suggest_difficulty", json!([1e-8]))
            .await["result"],
        true
    );
    let block_job = worker.job().await;
    assert_eq!(
        a.rpc("mining", json!({})).unwrap()["workers"][0]["share_difficulty"],
        1e-8
    );
    let base = header(&block_job, &worker.extra, [5; 4]);
    let target = math::target_from_bits(base.bits).unwrap();
    let winning = solve(base, |hash| hash <= &target);
    assert_eq!(
        worker.submit(&block_job, &winning, [5; 4], true).await["result"],
        true,
        "a network block is valid even below reporting difficulty"
    );
    assert_eq!(a.status().unwrap()["height"], 1);
    assert_eq!(
        a.status().unwrap()["tip"],
        hex::encode(crypto::sha256d(&codec::header_bytes(&winning)))
    );
    let next = worker.job().await;
    assert_eq!(next["params"][8], true);
    assert_eq!(
        worker.submit(&block_job, &winning, [5; 4], true).await["error"][0],
        21
    );

    let b = Node::open(
        &dir.path().join("b.db"),
        c,
        crypto::public_key(&[42; 32]).unwrap(),
    )
    .unwrap();
    for _ in 0..3 {
        b.mine(1_000_000).unwrap();
    }
    let other_server = node::serve(b.clone(), options(1e-8)).await.unwrap();
    node::sync_peer(&a, other_server.p2p).await.unwrap();
    assert_eq!(a.status().unwrap()["tip"], b.status().unwrap()["tip"]);
    let reorg_job = worker.job().await;
    assert_eq!(reorg_job["params"][8], true);
    assert_ne!(reorg_job["params"][1], next["params"][1]);
    let stale = header(&next, &worker.extra, [6; 4]);
    assert_eq!(
        worker.submit(&next, &stale, [6; 4], true).await["error"][0],
        21
    );
    let base = header(&reorg_job, &worker.extra, [7; 4]);
    let target = math::target_from_bits(base.bits).unwrap();
    let winning = solve(base, |hash| hash <= &target);
    assert_eq!(
        worker.submit(&reorg_job, &winning, [7; 4], true).await["result"],
        true
    );
    assert_eq!(a.status().unwrap()["height"], 4);
    let mining = a.rpc("mining", json!({})).unwrap();
    assert_eq!(mining["workers_connected"], 1);
    assert_eq!(mining["accepted_shares"], "4");
    assert_eq!(mining["blocks_found"], "2");
    assert_eq!(mining["payout_public_key"], hex::encode(miner));
    assert_eq!(mining["stratum"]["loopback_only"], true);
    assert_eq!(
        a.rpc("snapshot", json!({})).unwrap()["mining"]["blocks_found"],
        "2"
    );
    drop(worker);
    for _ in 0..50 {
        if a.rpc("mining", json!({})).unwrap()["workers_connected"] == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(a.rpc("mining", json!({})).unwrap()["workers_connected"], 0);
    server.stop().await;
    other_server.stop().await;
}

#[tokio::test]
async fn mining_endpoint_metadata_does_not_expose_password_or_wildcard_url() {
    let dir = tempfile::tempdir().unwrap();
    let n = Node::open(
        &dir.path().join("node.db"),
        Config::devnet(),
        crypto::public_key(&[43; 32]).unwrap(),
    )
    .unwrap();
    let mut opts = options(65536.0);
    opts.stratum = "0.0.0.0:0".parse().unwrap();
    opts.stratum_password = Some("private-mining-password".into());
    let server = node::serve(n.clone(), opts).await.unwrap();
    let metadata = n.rpc("mining", json!({})).unwrap();
    assert_eq!(metadata["stratum"]["password_required"], true);
    assert_eq!(metadata["stratum"]["loopback_only"], false);
    assert!(metadata["stratum"]["connect_url"].is_null());
    assert!(!metadata.to_string().contains("private-mining-password"));
    server.stop().await;
    let mut opts = options(65536.0);
    opts.stratum_advertise = Some("mining.example.org:3333".into());
    let server = node::serve(n.clone(), opts).await.unwrap();
    assert_eq!(
        n.rpc("mining", json!({})).unwrap()["stratum"]["connect_url"],
        "stratum+tcp://mining.example.org:3333"
    );
    server.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_work_jobs_reject_losing_work_and_pay_only_the_winning_chain() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::testnet();
    c.genesis_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
        - 1;
    c.initial_bits = 0x2000ffff;
    c.limit_bits = c.initial_bits;
    let miner = crypto::public_key(&[53; 32]).unwrap();
    let other = crypto::public_key(&[54; 32]).unwrap();
    let a = Node::open(&dir.path().join("a.db"), c.clone(), miner).unwrap();
    let b = Node::open(&dir.path().join("b.db"), c.clone(), other).unwrap();
    let sa = node::serve(a.clone(), options(65536.0)).await.unwrap();
    let sb = node::serve(b.clone(), options(65536.0)).await.unwrap();
    let mut wa = Worker::connect(sa.stratum).await;
    let mut wb = Worker::connect(sb.stratum).await;
    let ja = wa.authorize(true).await;
    let jb = wb.authorize(true).await;
    let target = math::target_from_bits(c.initial_bits).unwrap();
    let ha = solve(header(&ja, &wa.extra, [2; 4]), |hash| hash <= &target);
    let hb = solve(header(&jb, &wb.extra, [3; 4]), |hash| hash <= &target);
    assert_eq!(wa.submit(&ja, &ha, [2; 4], true).await["result"], true);
    node::sync_peer(&b, sa.p2p).await.unwrap();
    assert_eq!(wb.submit(&jb, &hb, [3; 4], true).await["error"][0], 21);
    node::sync_peer(&a, sb.p2p).await.unwrap();
    let template = a.template().unwrap();
    let block_work = math::work(&math::target_from_bits(template.header.bits).unwrap());
    a.mine(1_000_000).unwrap();
    node::sync_peer(&b, sa.p2p).await.unwrap();
    assert_eq!(
        a.status().unwrap()["state_root"],
        b.status().unwrap()["state_root"]
    );
    assert_eq!(
        a.status().unwrap()["issued"],
        (math::work(&target) + block_work).to_string()
    );
    let info = a.rpc("mining", json!({})).unwrap();
    assert_eq!(info["target_block_seconds"], 15);
    assert!(info.get("uncle_reward_split").is_none());
    assert!(info.get("stale_target_bps").is_none());
    assert!(info.get("minimum_work").is_some());
    assert!(
        a.rpc("account", json!({"key":hex::encode(other)}))
            .unwrap_err()
            .to_string()
            .contains("account does not exist"),
        "losing work must not create or fund an account"
    );
    sa.stop().await;
    sb.stop().await;
}
