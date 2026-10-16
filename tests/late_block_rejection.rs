//! A valid header and Merkle tree must not let a failing transaction commit an
//! earlier transaction's effects, either in memory or in the persisted chain.
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    consensus, crypto, math,
    node::{self, Node, ServerOptions},
    peer_wire::{self, Limits, Message, Sync},
    types::*,
};
use serde_json::json;
use std::{fs, io, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

const SECRET: [u8; 32] = [111; 32];
const DEADLINE: Duration = Duration::from_secs(5);

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}

fn options() -> ServerOptions {
    let zero = "127.0.0.1:0".parse().unwrap();
    ServerOptions {
        rpc: zero,
        p2p: zero,
        stratum: zero,
        ..Default::default()
    }
}

fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(
        chain.template(key(&SECRET), transactions, time).unwrap(),
        100_000,
    )
    .unwrap();
    assert!(chain.submit(block.clone(), time as u64).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
    block
}

fn transfer(chain: &Chain, recipient: PublicKey, amount: u32, nonce: u64) -> Transaction {
    crypto::sign(
        &TransactionBody {
            data: Vec::new(),
            sender: key(&SECRET),
            nonce,
            fee: 2u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&chain.config).unwrap(),
            ),
            expiry_blocks: chain.tip_height() + 100,
            operation: Operation::TransferExact {
                recipient,
                amount: amount.into(),
            },
        },
        &SECRET,
    )
    .unwrap()
}

fn frame(sync: Sync, limits: Limits) -> Vec<u8> {
    let payload = peer_wire::encode(&Message::Sync(sync), limits).unwrap();
    peer_wire::frame(&payload, limits.frame_bytes()).unwrap()
}

// SQLite uses exclusive locking. Comparing the database and WAL bytes while
// open catches persisted writes without opening a competing database handle.
fn database_bytes(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let wal = path.with_file_name(format!(
        "{}-wal",
        path.file_name().unwrap().to_str().unwrap()
    ));
    (fs::read(path).unwrap(), fs::read(wal).unwrap_or_default())
}

async fn push_invalid(node: &Node, server: &node::Server, block: &Block, config: &Config) {
    let status = node.status().unwrap();
    let limits = Limits::from_config(config);
    let hello = Sync {
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
    };
    let stream = timeout(DEADLINE, TcpStream::connect(server.p2p))
        .await
        .unwrap()
        .unwrap();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write
        .write_all(&frame(hello.clone(), limits))
        .await
        .unwrap();
    let response = timeout(DEADLINE, async {
        let length = read.read_u32().await.unwrap() as usize;
        assert!(length <= limits.frame_bytes());
        let mut payload = vec![0; length];
        read.read_exact(&mut payload).await.unwrap();
        peer_wire::decode(&payload, limits).unwrap()
    })
    .await
    .unwrap();
    let Message::Sync(response) = response else {
        panic!("expected peer synchronization reply")
    };
    assert_eq!(response.chain, hello.chain);
    let mut push = hello;
    push.blocks.push(block.clone());
    write.write_all(&frame(push, limits)).await.unwrap();
    write.shutdown().await.unwrap();
    let mut reply = Vec::new();
    let result = timeout(DEADLINE, read.take(16_384).read_to_end(&mut reply))
        .await
        .unwrap();
    if let Err(error) = result {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        ));
    }
    assert!(
        reply.is_empty(),
        "invalid block was acknowledged: {reply:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2p_late_transaction_failures_are_atomic_on_disk_then_valid_sync_and_restart_work() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.network = "late-block-rejection".into();
    config.validate().unwrap();
    let mut source = Chain::open(&directory.path().join("source.sqlite"), config.clone()).unwrap();
    for _ in 0..12 {
        append(&mut source, vec![]);
    }
    let target_path = directory.path().join("target.sqlite");
    let target = Node::open(&target_path, config.clone(), key(&SECRET)).unwrap();
    for height in 1..=source.tip_height() {
        target
            .submit_block(
                source
                    .block(&source.hash_at_height(height).unwrap())
                    .unwrap(),
            )
            .unwrap();
    }
    let server = node::serve(target.clone(), options()).await.unwrap();
    let first_recipient = key(&[112; 32]);
    let second_recipient = key(&[113; 32]);
    let nonce = source
        .tip_state()
        .account(&key(&SECRET), None)
        .unwrap()
        .nonce;
    let first = transfer(&source, first_recipient, 2, nonce);
    let second = transfer(&source, second_recipient, 3, nonce + 1);
    // Prove the prefix is executable and creates an account before each fault.
    let mut prefix = source.tip_state().clone();
    consensus::apply_transaction(&config, &mut prefix, &first).unwrap();
    assert_eq!(
        prefix.account(&first_recipient, None).unwrap().ordinary,
        2u32.into()
    );
    assert_ne!(prefix.root(), source.tip_state().root());
    let timestamp =
        source.tip_block().header.timestamp + source.tip_state().settings.interval as u32;
    let valid = source
        .template(key(&SECRET), vec![first.clone(), second.clone()], timestamp)
        .unwrap();
    let before_state = codec::encode(source.tip_state());
    let before_status = target.status().unwrap();
    let before_disk = database_bytes(&target_path);
    let mut invalid_hashes = Vec::new();

    for case in 0..3 {
        let mut bad = valid.clone();
        let transaction = &mut bad.transactions[1];
        let expected = match case {
            0 => {
                transaction.signature[0] ^= 1;
                crypto::verify(transaction).unwrap_err().to_string()
            }
            1 => {
                transaction.body.nonce += 1;
                *transaction = crypto::sign(&transaction.body, &SECRET).unwrap();
                "invalid or exhausted nonce".into()
            }
            _ => {
                transaction.body.fee = 0u32.into();
                *transaction = crypto::sign(&transaction.body, &SECRET).unwrap();
                "signed fee is below the mandatory minimum".into()
            }
        };
        // Recommit and mine each mutated body: early Merkle/PoW rejection must
        // not accidentally make the transaction atomicity assertions pass.
        bad.header.merkle_root = codec::merkle_root(&bad).unwrap();
        bad = Chain::mine(bad, 100_000).unwrap();
        math::check_pow(
            &bad.header,
            &math::target_from_bits(bad.header.bits).unwrap(),
        )
        .unwrap();
        assert_eq!(bad.header.merkle_root, codec::merkle_root(&bad).unwrap());
        let error = source
            .submit(bad.clone(), timestamp as u64)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(&expected),
            "wrong validation stage: {error}; wanted {expected}"
        );
        assert_eq!(codec::encode(source.tip_state()), before_state);
        push_invalid(&target, &server, &bad, &config).await;
        let live = timeout(
            DEADLINE,
            node::call_rpc(&format!("http://{}/rpc", server.rpc), "status", json!({})),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            live, before_status,
            "balances, fee pools, issuance, nonce root or mempool changed"
        );
        for recipient in [first_recipient, second_recipient] {
            assert_eq!(
                target
                    .rpc("account", json!({"key":hex::encode(recipient)}))
                    .unwrap_err()
                    .to_string(),
                "account does not exist"
            );
        }
        let hash = codec::block_hash(&bad);
        assert!(
            target
                .rpc("getblock", json!({"hash":hex::encode(hash)}))
                .is_err()
        );
        assert_eq!(
            database_bytes(&target_path),
            before_disk,
            "invalid block wrote persistent chain data"
        );
        invalid_hashes.push(hash);
    }
    server.stop().await;
    drop(target);
    let reopened = Chain::open(&target_path, config.clone()).unwrap();
    assert_eq!(codec::encode(reopened.tip_state()), before_state);
    assert!(
        invalid_hashes
            .iter()
            .all(|hash| reopened.block(hash).is_none())
    );
    drop(reopened);

    append(&mut source, vec![first, second]);
    let expected_state = codec::encode(source.tip_state());
    let expected_tip = source.tip_hash();
    let honest = Node::open(
        &directory.path().join("honest.sqlite"),
        config.clone(),
        key(&SECRET),
    )
    .unwrap();
    for height in 1..=source.tip_height() {
        honest
            .submit_block(
                source
                    .block(&source.hash_at_height(height).unwrap())
                    .unwrap(),
            )
            .unwrap();
    }
    let target = Node::open(&target_path, config.clone(), key(&SECRET)).unwrap();
    let peer = node::serve(honest.clone(), options()).await.unwrap();
    timeout(DEADLINE, node::sync_peer(&target, peer.p2p))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(target.status().unwrap()["tip"], hex::encode(expected_tip));
    assert_eq!(
        target.status().unwrap()["state_root"],
        hex::encode(source.tip_state().root())
    );
    assert_eq!(
        target
            .rpc("account", json!({"key":hex::encode(first_recipient)}))
            .unwrap()["account"]["ordinary"],
        "2"
    );
    assert_eq!(
        target
            .rpc("account", json!({"key":hex::encode(second_recipient)}))
            .unwrap()["account"]["ordinary"],
        "3"
    );
    assert_eq!(
        target
            .rpc("account", json!({"key":hex::encode(key(&SECRET))}))
            .unwrap()["account"]["nonce"],
        nonce + 2
    );
    peer.stop().await;
    drop(honest);
    drop(target);
    let restored = Chain::open(&target_path, config).unwrap();
    assert_eq!(restored.tip_hash(), expected_tip);
    assert_eq!(codec::encode(restored.tip_state()), expected_state);
    assert!(
        invalid_hashes
            .iter()
            .all(|hash| restored.block(hash).is_none())
    );
    restored.tip_state().audit(&restored.config).unwrap();
}
