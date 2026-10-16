//! Governed capacity above historical limits must work on the actual peer wire.
#[path = "support/curved.rs"]
mod curved;
mod support;
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    peer_wire::{self, Limits, Message, Sync},
    types::{Block, Operation, Outcome, Parameter, Proposal, Transaction, TransactionBody},
};
use serde_json::json;

fn append(chain: &mut Chain, miner: [u8; 32], transactions: Vec<Transaction>) -> Block {
    let timestamp = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(
        chain.template(miner, transactions, timestamp).unwrap(),
        2_000_000,
    )
    .unwrap();
    chain.submit(block.clone(), u64::from(timestamp)).unwrap();
    block
}

fn signed(chain: &Chain, secret: &[u8; 32], operation: Operation) -> Transaction {
    let state = chain.tip_state();
    let sender = crypto::public_key(secret).unwrap();
    support::sign_minimum(
        state,
        TransactionBody {
            sender,
            nonce: state.account(&sender, None).unwrap().nonce,
            fee: 0u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&chain.config).unwrap(),
            ),
            expiry_blocks: 10_000,
            operation,
            data: vec![],
        },
        secret,
        0,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_governed_block_relays_compactly_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let destination_path = directory.path().join("destination.sqlite");
    let secret = [123; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let mut config = Config::testnet();
    config.initial_bits = 0x1f00ffff;

    config.initial.rest = 30;
    config.initial.lead = 15;
    config.initial.decision_blocks = 4;
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
    curved::chain(&mut chain, &secret);
    let shared: Vec<_> = (1..=chain.tip_height())
        .map(|height| chain.block(&chain.hash_at_height(height).unwrap()).unwrap())
        .collect();
    // Enact the larger, deliberately non-power-of-two capacity through the
    // real auction and outcome trades. A lagging peer must learn this change
    // before it receives a block above its previous admission allowance.
    let capacity = 40 * 1024 * 1024 + 173;
    let proposal = signed(
        &chain,
        &secret,
        Operation::Propose {
            round: chain.tip_state().auction_round().unwrap(),
            description: [125; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: config.initial.block_bytes,
                new: capacity,
            },
            support: 1u32.into(),
        },
    );
    append(&mut chain, miner, vec![proposal]);
    while chain.tip_state().decision_id().is_none() {
        append(&mut chain, miner, vec![]);
    }
    let buy = signed(
        &chain,
        &secret,
        Operation::Deposit {
            amount: chain
                .tip_state()
                .account(&miner, Some(Outcome::Pass))
                .unwrap()
                .ordinary
                / 2u32,

            decision: chain.tip_state().decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    append(&mut chain, miner, vec![buy]);
    for _ in 0..32 {
        if chain.tip_state().settings.block_bytes == capacity {
            break;
        }
        append(&mut chain, miner, vec![]);
    }
    assert_eq!(chain.tip_state().settings.block_bytes, capacity);
    assert_eq!(chain.max_known_block_bytes(), capacity);
    let nonce_before = chain.tip_state().account(&miner, None).unwrap().nonce;
    let expected_height = chain.tip_height() + 1;
    let timestamp = chain.tip_block().header.timestamp + config.initial.interval as u32;
    let transactions: Vec<_> = (0..3_500)
        .map(|nonce| {
            let transaction = crypto::sign(
                &TransactionBody {
                    sender: miner,
                    nonce: nonce_before + nonce,
                    fee: 12u32.into(),
                    anchor: hashstash::codec::block_hash(
                        &hashstash::codec::genesis_block(&chain.config).unwrap(),
                    ),
                    expiry_blocks: 10_000,
                    operation: Operation::TransferExact {
                        recipient: miner,
                        amount: 1u32.into(),
                    },
                    data: vec![255; 10_000],
                },
                &secret,
            )
            .unwrap();
            assert!(
                codec::encode(&transaction).len()
                    <= config.transaction_bytes(&chain.tip_state().settings)
            );
            transaction
        })
        .collect();
    let block = Chain::mine(
        chain.template(miner, transactions, timestamp).unwrap(),
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
    let binary = peer_wire::encode(
        &Message::Sync(packet.clone()),
        Limits::for_capacity(&config, capacity),
    )
    .unwrap();
    let Message::Sync(decoded) =
        peer_wire::decode(&binary, Limits::for_capacity(&config, capacity)).unwrap()
    else {
        panic!()
    };
    assert_eq!(codec::encode(&decoded.blocks[0]), codec::encode(&block));
    assert_eq!(
        codec::block_hash(&decoded.blocks[0]),
        codec::block_hash(&block)
    );
    assert_eq!(decoded.blocks[0].state_root, block.state_root);
    assert!(body_bytes > 32 * 1024 * 1024);
    assert!(record_bytes > 32 * 1024 * 1024);
    assert!(record_bytes <= capacity as usize);
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
    for _ in 0..8 {
        node::sync_peer(&destination, server.p2p).await.unwrap_or_else(|error| {
            panic!("large sync failed: {error:#}; source events={}; destination events={}; destination height={}",
                source.rpc("peers", json!({})).unwrap(), destination.rpc("peers", json!({})).unwrap(),
                destination.status().unwrap()["height"]);
        });
        if destination.status().unwrap()["tip"] == expected_tip {
            break;
        }
    }
    for node in [&source, &destination] {
        let status = node.status().unwrap();
        assert_eq!(status["tip"], expected_tip);
        assert_eq!(status["state_root"], expected_root);
        assert_eq!(status["height"], expected_height);
        assert_eq!(
            node.rpc("account", json!({"key":hex::encode(miner)}))
                .unwrap()["account"]["nonce"],
            nonce_before + 3_500
        );
    }

    // A higher-work branch never adopted the larger capacity. Reorganizing to
    // it must not forget an already validated historical transport allowance.
    let mut alternate =
        Chain::open(&directory.path().join("alternate.sqlite"), config.clone()).unwrap();
    for block in shared {
        let timestamp = u64::from(block.header.timestamp);
        alternate.submit(block, timestamp).unwrap();
    }
    while alternate.tip_height() <= expected_height {
        let block = append(&mut alternate, miner, vec![]);
        source.submit_block(block).unwrap();
    }
    assert_eq!(
        alternate.tip_state().settings.block_bytes,
        config.initial.block_bytes
    );
    let expected_tip = hex::encode(alternate.tip_hash());
    let expected_root = hex::encode(alternate.tip_state().root());
    assert_eq!(source.status().unwrap()["tip"], expected_tip);
    for _ in 0..8 {
        node::sync_peer(&destination, server.p2p).await.unwrap();
        if destination.status().unwrap()["tip"] == expected_tip {
            break;
        }
    }
    assert_eq!(destination.status().unwrap()["tip"], expected_tip);
    server.stop().await;
    drop(source);
    drop(destination);
    for path in [&source_path, &destination_path] {
        let replayed = Chain::open(path, config.clone()).unwrap();
        assert_eq!(
            replayed.tip_state().settings.block_bytes,
            config.initial.block_bytes
        );
        assert_eq!(
            replayed.max_known_block_bytes(),
            capacity,
            "capacity learned from a losing branch must survive restart"
        );
        drop(replayed);
        let reopened = Node::open(path, config.clone(), miner).unwrap();
        assert_eq!(reopened.status().unwrap()["tip"], expected_tip);
        assert_eq!(reopened.status().unwrap()["state_root"], expected_root);
    }
    eprintln!(
        "large valid block: {body_bytes} body bytes / {record_bytes} canonical bytes / {} binary peer payload bytes with 3500 signed data transactions",
        binary.len()
    );
}
