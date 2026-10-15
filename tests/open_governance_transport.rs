//! Governed capacity above historical limits must work on the actual peer wire.
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    peer_wire::{self, Limits, Message, Sync},
    types::{Operation, TransactionBody},
};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_governed_block_relays_compactly_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let destination_path = directory.path().join("destination.sqlite");
    let secret = [123; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let mut config = Config::testnet();
    config.initial_bits = 0x1f00ffff;

    config.initial.block_bytes = 32 * 1024 * 1024;
    config.validate().unwrap();

    // Build and fund directly, avoiding repeated mempool-prefix validation.
    let mut chain = Chain::open(&source_path, config.clone()).unwrap();
    let funding = Chain::mine(
        chain
            .template(miner, vec![], config.genesis_time + 15)
            .unwrap(),
        2_000_000,
    )
    .unwrap();
    chain
        .submit(funding, u64::from(config.genesis_time + 15))
        .unwrap();
    let transactions: Vec<_> = (0..3_500)
        .map(|nonce| {
            let transaction = crypto::sign(
                &TransactionBody {
                    chain_id: config.chain_id(),
                    sender: miner,
                    nonce,
                    fee: 4u32.into(),
                    expiry_height: 100,
                    operation: Operation::TransferExact {
                        recipient: miner,
                        amount: 1u32.into(),
                    },
                    data: vec![255; 3_600],
                },
                &secret,
            )
            .unwrap();
            assert!(codec::encode(&transaction).len() <= config.transaction_bytes(&config.initial));
            transaction
        })
        .collect();
    let block = Chain::mine(
        chain
            .template(miner, transactions, config.genesis_time + 30)
            .unwrap(),
        2_000_000,
    )
    .unwrap();
    let body_bytes = codec::body_size(&block).unwrap();
    let record_bytes = codec::encode(&block).len();
    let packet = Sync {
        chain: config.chain_id(),
        locator: vec![chain.tip_hash()],
        blocks: vec![block.clone()],
        transactions: vec![],
    };
    let binary =
        peer_wire::encode(&Message::Sync(packet.clone()), Limits::from_config(&config)).unwrap();
    let wire_bytes = serde_json::to_vec(&json!({"chain":packet.chain,"locator":packet.locator,"blocks":packet.blocks,"transactions":packet.transactions})).unwrap().len();
    assert!(binary.len() < wire_bytes / 2);
    let Message::Sync(decoded) = peer_wire::decode(&binary, Limits::from_config(&config)).unwrap()
    else {
        panic!()
    };
    assert_eq!(codec::encode(&decoded.blocks[0]), codec::encode(&block));
    assert_eq!(
        codec::block_hash(&decoded.blocks[0]),
        codec::block_hash(&block)
    );
    assert_eq!(decoded.blocks[0].state_root, block.state_root);
    assert!(body_bytes > 4 * 1024 * 1024);
    assert!(wire_bytes > 32 * 1024 * 1024);
    assert!(record_bytes <= config.max_block_record_bytes());
    let expected_tip = hex::encode(codec::block_hash(&block));
    let expected_root = hex::encode(block.state_root);
    drop(chain);

    let source = Node::open(&source_path, config.clone(), miner).unwrap();
    assert!(source.submit_block(block).unwrap());
    let destination = Node::open(&destination_path, config.clone(), miner).unwrap();
    let loopback = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        source.clone(),
        ServerOptions {
            rpc: loopback,
            p2p: loopback,
            stratum: loopback,
            peers: vec![],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    node::sync_peer(&destination, server.p2p).await.unwrap();
    for node in [&source, &destination] {
        let status = node.status().unwrap();
        assert_eq!(status["tip"], expected_tip);
        assert_eq!(status["state_root"], expected_root);
        assert_eq!(status["height"], 2);
        assert_eq!(
            node.rpc("account", json!({"key":hex::encode(miner)}))
                .unwrap()["account"]["nonce"],
            3_500
        );
    }
    server.stop().await;
    drop(source);
    drop(destination);
    for path in [&source_path, &destination_path] {
        let reopened = Node::open(path, config.clone(), miner).unwrap();
        assert_eq!(reopened.status().unwrap()["tip"], expected_tip);
        assert_eq!(reopened.status().unwrap()["state_root"], expected_root);
    }
    eprintln!(
        "large valid block: {body_bytes} body bytes / {record_bytes} canonical bytes / {} binary peer payload bytes / {wire_bytes} former JSON peer bytes with 3500 signed data transactions",
        binary.len()
    );
}
