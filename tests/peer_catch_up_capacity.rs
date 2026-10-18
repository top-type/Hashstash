//! Regression test for audit finding F002: once a recipient has validated a
//! governed capacity increase, catch-up replies use that capacity instead of
//! ending at the first block larger than the first one sent. Also R09: a
//! branch that raised its capacity while far behind is followed once its
//! headers claim more work than the tip, and only then.
#[path = "support/curved.rs"]
mod curved;
mod support;
use hashstash::{
    chain::{CAPACITY_BRANCH_MARGIN_BLOCKS, Chain},
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

/// Enact `capacity` on `chain` through real governance; the blocks it took.
fn enact(chain: &mut Chain, secret: &[u8; 32], capacity: u64) -> Vec<Block> {
    let miner = crypto::public_key(secret).unwrap();
    let initial = chain.tip_state().settings.block_bytes;
    let proposal = signed(
        chain,
        secret,
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
    let mut blocks = vec![append(chain, *secret, vec![proposal])];
    while chain.tip_state().decision_id().is_none() {
        blocks.push(append(chain, *secret, vec![]));
    }
    let buy = signed(
        chain,
        secret,
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
    blocks.push(append(chain, *secret, vec![buy]));
    for _ in 0..32 {
        if chain.tip_state().settings.block_bytes == capacity {
            break;
        }
        blocks.push(append(chain, *secret, vec![]));
    }
    assert_eq!(chain.tip_state().settings.block_bytes, capacity);
    blocks
}

fn serve(source: &Node) -> impl std::future::Future<Output = node::Server> {
    let loopback = "127.0.0.1:0".parse().unwrap();
    let source = source.clone();
    async move {
        node::serve(
            source,
            ServerOptions {
                rpc: loopback,
                p2p: loopback,
                stratum: loopback,
                peers: vec![],
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }
}

/// The greatest block capacity the node admits from peers.
fn allowance(node: &Node) -> serde_json::Value {
    node.rpc("peerstatus", serde_json::json!({})).unwrap()["capacity_allowance"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_branch_that_raised_capacity_far_behind_is_followed_once_its_headers_claim_more_work() {
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

    // A private branch enacts a larger capacity.
    let source_path = directory.path().join("private.sqlite");
    let mut private = Chain::open(&source_path, config.clone()).unwrap();
    append(&mut private, secret, vec![]);
    curved::chain(&mut private, &secret);
    let shared: Vec<_> = (1..=private.tip_height())
        .map(|height| private.block(&private.hash_at_height(height).unwrap()).unwrap())
        .collect();
    let capacity = 1024 * 1024 + 173;
    let branch = enact(&mut private, &secret, capacity);

    // The victim stores that branch while its own chain is further ahead
    // than the capacity allowance follows losing branches.
    let victim_path = directory.path().join("victim.sqlite");
    let mut victim = Chain::open(&victim_path, config.clone()).unwrap();
    for block in &shared {
        assert!(victim.submit(block.clone(), u64::from(block.header.timestamp)).unwrap());
    }
    let lead = branch.len() + CAPACITY_BRANCH_MARGIN_BLOCKS as usize + 2;
    for _ in 0..lead {
        append(&mut victim, [124; 32], vec![]);
    }
    for block in &branch {
        assert!(!victim.submit(block.clone(), u64::from(block.header.timestamp)).unwrap());
    }
    assert_eq!(victim.max_known_block_bytes(), initial);
    let light_tip = hex::encode(victim.tip_hash());
    drop(victim);

    // The branch continues with blocks above the victim's allowance while
    // it is still lighter than the victim's chain.
    let large = |chain: &Chain, n: usize| {
        vec![signed(
            chain,
            &secret,
            Operation::TransferExact {
                recipient: miner,
                amount: 1u32.into(),
            },
            vec![n as u8; initial as usize + 4096],
        )]
    };
    let lighter = 3;
    for n in 0..lighter {
        let transactions = large(&private, n);
        append(&mut private, secret, transactions);
    }
    // Each exchange pushes the victim's heavier chain to its server. Serve
    // the private branch from a fresh copy every time, so it stays served.
    let replica = |private: &Chain, name: &str| {
        let path = directory.path().join(name);
        let mut copy = Chain::open(&path, config.clone()).unwrap();
        for height in 1..=private.tip_height() {
            let block = private.block(&private.hash_at_height(height).unwrap()).unwrap();
            copy.submit(block.clone(), u64::from(block.header.timestamp)).unwrap();
        }
        assert_eq!(copy.tip_hash(), private.tip_hash());
        drop(copy);
        Node::open(&path, config.clone(), miner).unwrap()
    };
    let victim = Node::open(&victim_path, config.clone(), miner).unwrap();
    // A lighter header chain raises nothing: its larger blocks are not sent,
    // and each exchange still succeeds. Block synchronization alone failed
    // the second exchange, which resumes at the branch's stored tip, on a
    // frame above the allowance, and every exchange with that peer after it.
    for round in 0..2 {
        let source = replica(&private, &format!("lighter-{round}.sqlite"));
        let server = serve(&source).await;
        node::sync_peer(&victim, server.p2p).await.unwrap();
        server.stop().await;
    }
    assert_eq!(victim.status().unwrap()["tip"], light_tip);
    assert_eq!(allowance(&victim), initial);

    // Once the branch claims more work, its headers raise the allowance to
    // the capacity it validated, and its larger blocks follow.
    for n in lighter..lead - branch.len() + 1 {
        let transactions = large(&private, n);
        append(&mut private, secret, transactions);
    }
    let heavy_tip = hex::encode(private.tip_hash());
    let source = replica(&private, "heavier.sqlite");
    let server = serve(&source).await;
    for _ in 0..3 {
        node::sync_peer(&victim, server.p2p).await.unwrap();
        if victim.status().unwrap()["tip"] == heavy_tip {
            break;
        }
    }
    assert_eq!(victim.status().unwrap()["tip"], heavy_tip);
    assert_eq!(allowance(&victim), capacity);
    server.stop().await;
}
