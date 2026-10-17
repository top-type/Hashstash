//! Regression test for audit finding F004: a losing branch raises the peer
//! capacity allowance only while it stays competitive with the active chain.
#[path = "support/curved.rs"]
mod curved;
mod support;
use hashstash::{
    chain::{CAPACITY_BRANCH_MARGIN_BLOCKS, Chain},
    config::Config,
    crypto,
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

fn submit(chain: &mut Chain, block: &Block) -> bool {
    chain
        .submit(block.clone(), u64::from(block.header.timestamp))
        .unwrap()
}

#[test]
fn losing_branch_capacity_counts_only_while_the_branch_is_competitive() {
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

    // The private branch enacts a larger capacity through real governance.
    let private_path = directory.path().join("private.sqlite");
    let mut private = Chain::open(&private_path, config.clone()).unwrap();
    let funding = Chain::mine(
        private
            .template(miner, vec![], config.genesis_time + 15)
            .unwrap(),
        2_000_000,
    )
    .unwrap();
    private
        .submit(funding, u64::from(config.genesis_time + 15))
        .unwrap();
    curved::chain(&mut private, &secret);
    let shared: Vec<_> = (1..=private.tip_height())
        .map(|height| private.block(&private.hash_at_height(height).unwrap()).unwrap())
        .collect();
    let capacity = 1024 * 1024 + 173;
    let proposal = signed(
        &private,
        &secret,
        Operation::Propose {
            round: private.tip_state().auction_round().unwrap(),
            description: [125; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: initial,
                new: capacity,
            },
            support: 1u32.into(),
        },
    );
    let mut branch = vec![append(&mut private, secret, vec![proposal])];
    while private.tip_state().decision_id().is_none() {
        branch.push(append(&mut private, secret, vec![]));
    }
    let buy = signed(
        &private,
        &secret,
        Operation::Deposit {
            amount: private
                .tip_state()
                .account(&miner, Some(Outcome::Pass))
                .unwrap()
                .ordinary
                / 2u32,
            decision: private.tip_state().decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    branch.push(append(&mut private, secret, vec![buy]));
    for _ in 0..32 {
        if private.tip_state().settings.block_bytes == capacity {
            break;
        }
        branch.push(append(&mut private, secret, vec![]));
    }
    assert_eq!(private.max_known_block_bytes(), capacity);

    // The victim's active chain is well ahead of the private branch.
    let path = directory.path().join("victim.sqlite");
    let mut victim = Chain::open(&path, config.clone()).unwrap();
    for block in &shared {
        submit(&mut victim, block);
    }
    let lead = branch.len() + CAPACITY_BRANCH_MARGIN_BLOCKS as usize + 2;
    for _ in 0..lead {
        append(&mut victim, [124; 32], vec![]);
    }
    for block in &branch {
        assert!(!submit(&mut victim, block));
    }
    assert_eq!(victim.tip_state().settings.block_bytes, initial);
    // Previously every validated branch raised this permanently.
    assert_eq!(victim.max_known_block_bytes(), initial);
    drop(victim);
    let mut victim = Chain::open(&path, config.clone()).unwrap();
    assert_eq!(victim.max_known_block_bytes(), initial);

    // Once the branch is about to overtake, its larger blocks must be receivable.
    let behind = victim.tip_height() - private.tip_height();
    for _ in 0..behind - 1 {
        let block = append(&mut private, secret, vec![]);
        assert!(!submit(&mut victim, &block));
    }
    assert_eq!(victim.max_known_block_bytes(), capacity);
    let block = append(&mut private, secret, vec![]);
    submit(&mut victim, &block);
    let block = append(&mut private, secret, vec![]);
    assert!(submit(&mut victim, &block));
    assert_eq!(victim.tip_hash(), private.tip_hash());
    assert_eq!(victim.max_known_block_bytes(), capacity);
}
