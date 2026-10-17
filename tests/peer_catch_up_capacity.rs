//! Regression test for audit finding F002: once a recipient has validated a
//! governed capacity increase, catch-up replies use that capacity instead of
//! ending at the first block larger than the first one sent.
#[path = "support/curved.rs"]
mod curved;
mod support;
use hashstash::{
    chain::Chain,
    config::Config,
    crypto,
    node::{self, Node, ServerOptions},
    types::{Block, Operation, Outcome, Parameter, Proposal, Transaction, TransactionBody},
};

fn append(chain: &mut Chain, miner: [u8; 32], transactions: Vec<Transaction>) -> Block {
    let timestamp = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(
        chain
            .template(crypto::public_key(&miner).unwrap(), transactions, timestamp)
            .unwrap(),
        2_000_000,
    )
    .unwrap();
    assert!(chain.submit(block.clone(), u64::from(timestamp)).unwrap());
    block
}

fn signed(chain: &Chain, secret: &[u8; 32], operation: Operation, data: Vec<u8>) -> Transaction {
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
            data,
        },
        secret,
        0,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catch_up_after_a_capacity_increase_sends_full_batches_of_mixed_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let secret = [123; 32];
    let miner = crypto::public_key(&secret).unwrap();
    let mut config = Config::testnet();
    config.initial_bits = 0x1f00ffff;
    config.initial.rest = 30;
    config.initial.lead = 15;
    config.initial.decision_blocks = 4;
    config.validate().unwrap();
    let initial = config.initial.block_bytes;

    // Enact a larger capacity through real governance.
    let source_path = directory.path().join("source.sqlite");
    let mut chain = Chain::open(&source_path, config.clone()).unwrap();
    append(&mut chain, secret, vec![]);
    curved::chain(&mut chain, &secret);
    let capacity = 1024 * 1024 + 173;
    let proposal = signed(
        &chain,
        &secret,
        Operation::Propose {
            round: chain.tip_state().auction_round().unwrap(),
            description: [125; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: initial,
                new: capacity,
            },
            support: 1u32.into(),
        },
        vec![],
    );
    append(&mut chain, secret, vec![proposal]);
    while chain.tip_state().decision_id().is_none() {
        append(&mut chain, secret, vec![]);
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
        vec![],
    );
    append(&mut chain, secret, vec![buy]);
    for _ in 0..32 {
        if chain.tip_state().settings.block_bytes == capacity {
            break;
        }
        append(&mut chain, secret, vec![]);
    }
    assert_eq!(chain.tip_state().settings.block_bytes, capacity);
    let validated = chain.tip_height();
    let history: Vec<_> = (1..=validated)
        .map(|height| chain.block(&chain.hash_at_height(height).unwrap()).unwrap())
        .collect();

    // Then small blocks alternate with ever larger ones, all above the
    // genesis capacity. Previously each reply ended at the first block more
    // than 1 KiB larger than the first block sent, about two per reply.
    let batch = hashstash::peer_wire::MAX_BLOCKS as u64;
    for n in 0..2 * batch as usize {
        let transactions = if n % 2 == 1 {
            vec![signed(
                &chain,
                &secret,
                Operation::TransferExact {
                    recipient: miner,
                    amount: 1u32.into(),
                },
                vec![n as u8; initial as usize + 1024 * n],
            )]
        } else {
            vec![]
        };
        append(&mut chain, secret, transactions);
    }
    let target = chain.tip_height();
    assert_eq!(target, validated + 2 * batch);
    drop(chain);

    // The recipient has validated the increase but none of the later blocks.
    let destination_path = directory.path().join("destination.sqlite");
    let mut lagging = Chain::open(&destination_path, config.clone()).unwrap();
    for block in history {
        let timestamp = u64::from(block.header.timestamp);
        assert!(lagging.submit(block, timestamp).unwrap());
    }
    assert_eq!(lagging.max_known_block_bytes(), capacity);
    drop(lagging);

    let source = Node::open(&source_path, config.clone(), miner).unwrap();
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
    for round in 1..=2 {
        node::sync_peer(&destination, server.p2p).await.unwrap();
        assert_eq!(
            destination.status().unwrap()["height"],
            validated + round * batch,
            "each catch-up reply carries a full batch"
        );
    }
    assert_eq!(destination.status().unwrap()["height"], target);
    server.stop().await;
}
