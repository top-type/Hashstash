#[path = "support/curved.rs"]
mod curved;
mod support;
// Reproducible honest-fork workloads. Every branch has valid signatures, work,
// and transactions; selected history must agree byte-for-byte with clean replay.
use hashstash::{
    chain::Chain,
    codec,
    config::{Config, PARAMETERS},
    crypto,
    node::{self, Node, ServerOptions},
    state::{self, Phase},
    types::*,
};
use serde_json::json;
use std::net::SocketAddr;
use tempfile::TempDir;

const MINER: [u8; 32] = [41; 32];
const PLAYERS: usize = 12;

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}

fn player(index: usize) -> [u8; 32] {
    [50 + index as u8; 32]
}

fn fresh(c: Config) -> (TempDir, Chain) {
    let d = tempfile::tempdir().unwrap();
    let chain = Chain::open(&d.path().join("chain.sqlite"), c).unwrap();
    (d, chain)
}

fn sign(
    chain: &Chain,
    secret: &[u8; 32],
    operation: Operation,
    fee: u32,
    offset: u64,
) -> Transaction {
    let sender = key(secret);
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            data: Vec::new(),
            sender,
            nonce: chain.tip_state().account(&sender, None).unwrap().nonce + offset,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&chain.config).unwrap(),
            ),
            expiry_blocks: chain.tip_height() + 10_000,
            operation,
        },
        secret,
        u64::from(fee),
    )
}

fn append(chain: &mut Chain, transactions: Vec<Transaction>, salt: u64) -> Block {
    let timestamp = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    append_at(chain, transactions, salt, timestamp)
}

fn append_at(
    chain: &mut Chain,
    transactions: Vec<Transaction>,
    salt: u64,
    timestamp: u32,
) -> Block {
    let mut candidate = chain
        .template(key(&MINER), transactions, timestamp)
        .unwrap();
    candidate.extranonce = salt.to_le_bytes();
    candidate.header.merkle_root = codec::merkle_root(&candidate).unwrap();
    let block = Chain::mine(candidate, 1_000_000).unwrap();
    assert!(
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap()
    );
    chain.tip_state().audit(&chain.config).unwrap();
    assert_eq!(chain.tip_state().root(), block.state_root);
    block
}

fn empty(chain: &mut Chain, count: usize, salt: u64) {
    for _ in 0..count {
        append(chain, vec![], salt);
    }
}

fn until(chain: &mut Chain, phase: &str, salt: u64) {
    for _ in 0..400 {
        if chain.tip_state().phase_name() == phase {
            return;
        }
        append(chain, vec![], salt);
    }
    panic!("phase {phase} not reached");
}

fn funded_current_protocol() -> (TempDir, Chain) {
    let mut c = Config::testnet();
    c.network = "hashstash-seeded-reorg-tests".into();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262144;
    c.validate().unwrap();
    let (d, mut chain) = fresh(c);
    empty(&mut chain, 32, 0);
    let transfers = (0..PLAYERS)
        .map(|i| {
            sign(
                &chain,
                &MINER,
                Operation::TransferExact {
                    recipient: key(&player(i)),
                    amount: 800u32.into(),
                },
                1,
                i as u64,
            )
        })
        .collect();
    append(&mut chain, transfers, 0);
    let deposits = (0..PLAYERS)
        .map(|i| {
            sign(
                &chain,
                &player(i),
                Operation::Deposit {
                    amount: 400u32.into(),

                    decision: None,
                    outcome: None,
                },
                1,
                0,
            )
        })
        .collect();
    append(&mut chain, deposits, 0);
    until(&mut chain, "auction", 0);
    empty(&mut chain, 16, 0);
    (d, chain)
}

fn blocks(chain: &Chain, after: u64) -> Vec<Block> {
    (after + 1..=chain.tip_height())
        .map(|h| chain.block(&chain.hash_at_height(h).unwrap()).unwrap())
        .collect()
}

fn fork(source: &Chain) -> (TempDir, Chain) {
    let (d, mut chain) = fresh(source.config.clone());
    for block in blocks(source, 0) {
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    same(&chain, source);
    (d, chain)
}

fn fork_at(source: &Chain, mut tip: Hash) -> (TempDir, Chain) {
    let (d, mut chain) = fresh(source.config.clone());
    let mut ancestry = Vec::new();
    while let Some(block) = source.block(&tip) {
        if block.height == 0 {
            break;
        }
        tip = block.header.previous;
        ancestry.push(block);
    }
    for block in ancestry.into_iter().rev() {
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    (d, chain)
}

fn same(actual: &Chain, expected: &Chain) {
    assert_eq!(actual.tip_hash(), expected.tip_hash());
    assert_eq!(actual.tip_state().root(), expected.tip_state().root());
    // This includes raw lazy account epochs, refund records, frozen
    // settings, accumulated TWAP, reserve and revenue, not only displayed balances.
    assert_eq!(
        codec::encode(actual.tip_state()),
        codec::encode(expected.tip_state())
    );
    actual.tip_state().audit(&actual.config).unwrap();
}

fn switch_to(target: &mut Chain, source: &Chain, after: u64) {
    for block in blocks(source, after) {
        target
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        target.tip_state().audit(&target.config).unwrap();
    }
    same(target, source);
}

fn replay_and_reopen(d: TempDir, chain: Chain) {
    let (_replay_dir, mut replay) = fresh(chain.config.clone());
    for block in blocks(&chain, 0) {
        replay
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        replay.tip_state().audit(&replay.config).unwrap();
    }
    same(&replay, &chain);
    let config = chain.config.clone();
    let expected_tip = chain.tip_hash();
    let expected = codec::encode(chain.tip_state());
    drop(chain);
    let reopened = Chain::open(&d.path().join("chain.sqlite"), config).unwrap();
    assert_eq!(reopened.tip_hash(), expected_tip);
    assert_eq!(codec::encode(reopened.tip_state()), expected);
    reopened.tip_state().audit(&reopened.config).unwrap();
}

fn propose(chain: &mut Chain, proposal: Proposal, tag: u8, support: u32) -> (u64, Hash) {
    until(chain, "auction", 0);
    let round = chain.tip_state().auction_round().unwrap();
    let id = state::proposal_id(
        &chain.chain_id(),
        round,
        &key(&MINER),
        &[tag; 32],
        &proposal,
    );
    let tx = sign(
        chain,
        &MINER,
        Operation::Propose {
            round,
            description: [tag; 32],
            proposal,
            support: support.into(),
        },
        2,
        0,
    );
    append(chain, vec![tx], tag as u64);
    (round, id)
}

fn buy(chain: &mut Chain, outcome: Outcome, salt: u64) {
    let decision = chain.tip_state().decision_id().unwrap();
    let txs = vec![sign(
        chain,
        &MINER,
        Operation::Deposit {
            amount: 800u32.into(),

            decision: Some(decision),
            outcome: Some(outcome),
        },
        3,
        0,
    )];
    append(chain, txs, salt);
}

fn node_import(node: &Node, chain: &Chain, after: u64) {
    for block in blocks(chain, after) {
        node.submit_block(block).unwrap();
    }
}

fn funded() -> (TempDir, Chain) {
    funded_current_protocol()
}

#[test]
fn every_parameter_activation_can_be_reorged_through_resolution_and_rest() {
    for (index, parameter) in PARAMETERS.into_iter().enumerate() {
        let (d, mut pass) = funded();
        curved::chain(&mut pass, &MINER);
        let old = pass.tip_state().settings.get(parameter);
        let new = match parameter {
            Parameter::MinerFeePercent => 25,
            Parameter::PassMarginBps => 100,
            Parameter::Interval => 30,
            _ => old * 2,
        };
        propose(
            &mut pass,
            Proposal::Parameter {
                parameter,
                old,
                new,
            },
            index as u8 + 110,
            3,
        );
        until(&mut pass, "governance", 0);
        let fork_height = pass.tip_height();
        let (_fail_dir, mut fail) = fork(&pass);
        buy(&mut pass, Outcome::Pass, 1);
        buy(&mut fail, Outcome::Fail, 2);
        until(&mut pass, "rest", 1);
        until(&mut fail, "rest", 2);
        assert!(
            matches!(&pass.tip_state().phase, Phase::Rest(r) if r.pending == Some((parameter, new)))
        );
        assert!(matches!(&fail.tip_state().phase, Phase::Rest(r) if r.pending.is_none()));
        assert_eq!(pass.tip_state().settings.get(parameter), old);
        until(&mut pass, "auction", 1);
        assert_eq!(pass.tip_state().settings.get(parameter), new);
        let activated_tip = pass.tip_hash();
        until(&mut fail, "auction", 2);
        assert_eq!(fail.tip_state().settings.get(parameter), old);
        while fail.chain_work() <= pass.chain_work() {
            append(&mut fail, vec![], 2);
        }
        switch_to(&mut pass, &fail, fork_height);
        assert_eq!(pass.tip_state().settings.get(parameter), old);
        let (_restore_dir, mut restored) = fork_at(&pass, activated_tip);
        while restored.chain_work() <= pass.chain_work() {
            append(&mut restored, vec![], 3);
        }
        switch_to(&mut pass, &restored, fork_height);
        assert_eq!(pass.tip_state().settings.get(parameter), new);
        replay_and_reopen(d, pass);
    }
}

#[test]
fn auction_lead_changes_refunds_and_timeouts_are_branch_local() {
    let (d, mut chain) = funded();
    let (round, first) = propose(
        &mut chain,
        Proposal::Parameter {
            parameter: Parameter::Lead,
            old: Config::testnet().initial.lead,
            new: Config::testnet().initial.lead * 2,
        },
        120,
        4,
    );
    let (_, second) = propose(
        &mut chain,
        Proposal::Parameter {
            parameter: Parameter::Rest,
            old: Config::testnet().initial.rest,
            new: Config::testnet().initial.rest * 2,
        },
        121,
        5,
    );
    let fork_height = chain.tip_height();
    let (_alt_dir, mut alternate) = fork(&chain);
    let support = sign(
        &chain,
        &player(1),
        Operation::Support {
            round,
            proposal: first,
            amount: 3u32.into(),
        },
        2,
        0,
    );
    append(&mut chain, vec![support], 1);
    until(&mut chain, "governance", 1);
    until(&mut alternate, "governance", 2);
    assert!(matches!(&chain.tip_state().phase, Phase::Governance(g) if g.proposal_id == first));
    assert!(
        matches!(&alternate.tip_state().phase, Phase::Governance(g) if g.proposal_id == second)
    );
    let refund = sign(
        &chain,
        &MINER,
        Operation::Refund {
            round,
            proposal: second,
        },
        1,
        0,
    );
    append(&mut chain, vec![refund], 1);
    let refund = sign(
        &alternate,
        &MINER,
        Operation::Refund {
            round,
            proposal: first,
        },
        1,
        0,
    );
    append(&mut alternate, vec![refund], 2);
    while alternate.chain_work() <= chain.chain_work() {
        append(&mut alternate, vec![], 2);
    }
    switch_to(&mut chain, &alternate, fork_height);
    let nonexistent_refund = sign(
        &chain,
        &player(1),
        Operation::Refund {
            round,
            proposal: first,
        },
        0,
        0,
    );
    assert!(chain.validate_transaction(&nonexistent_refund).is_err());
    until(&mut chain, "rest", 2);
    until(&mut chain, "auction", 2);
    let empty_round = chain.tip_state().auction_round().unwrap();
    let timeout_fork = chain.tip_height();
    let (_live_dir, mut live) = fork(&chain);
    until(&mut chain, "rest", 3);
    assert!(matches!(
        chain
            .tip_state()
            .rounds
            .get(&empty_round.to_be_bytes())
            .unwrap()
            .status,
        state::RoundStatus::Timeout
    ));
    propose(
        &mut live,
        Proposal::Parameter {
            parameter: Parameter::Lead,
            old: Config::testnet().initial.lead,
            new: Config::testnet().initial.lead * 2,
        },
        122,
        2,
    );
    until(&mut live, "governance", 4);
    while live.chain_work() <= chain.chain_work() {
        append(&mut live, vec![], 4);
    }
    switch_to(&mut chain, &live, timeout_fork);
    assert!(matches!(
        chain
            .tip_state()
            .rounds
            .get(&empty_round.to_be_bytes())
            .unwrap()
            .status,
        state::RoundStatus::Won(_)
    ));
    replay_and_reopen(d, chain);
}

#[test]
fn reorg_filters_hundreds_of_conflicting_detached_transactions_before_pool_cap() {
    let (_base_dir, mut base) = funded();
    // Every self-payment commits principal and fee from opening cash; its
    // same-block receipt cannot fund the next transaction in the nonce chain.
    let top_up = sign(
        &base,
        &MINER,
        Operation::TransferExact {
            recipient: key(&player(0)),
            amount: 400u32.into(),
        },
        1,
        0,
    );
    append(&mut base, vec![top_up], 0);
    let fork_height = base.tip_height();
    let (_old_dir, mut old) = fork(&base);
    let (_new_dir, mut new) = fork(&base);
    for (branch, chain) in [&mut old, &mut new].into_iter().enumerate() {
        let txs = (0..300)
            .map(|offset| {
                sign(
                    chain,
                    &player(0),
                    Operation::TransferExact {
                        recipient: key(&player(0)),
                        amount: 1u32.into(),
                    },
                    0,
                    offset,
                )
            })
            .collect();
        append(chain, txs, branch as u64 + 1);
    }
    // Distinguish the otherwise identical same-nonce transfers on the new fork.
    empty(&mut old, 1, 11);
    empty(&mut new, 1, 12);
    let d = tempfile::tempdir().unwrap();
    let node = Node::open(
        &d.path().join("node.sqlite"),
        base.config.clone(),
        key(&MINER),
    )
    .unwrap();
    node_import(&node, &old, 0);
    let pending = sign(
        &old,
        &player(2),
        Operation::TransferExact {
            recipient: key(&player(3)),
            amount: 2u32.into(),
        },
        1,
        0,
    );
    let pending_id = node.submit_transaction(pending.clone()).unwrap();
    empty(&mut new, 1, 12);
    node_import(&node, &new, fork_height);
    assert_eq!(node.status().unwrap()["tip"], hex::encode(new.tip_hash()));
    let pool: Vec<Transaction> = node
        .rpc("mempool", json!({}))
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::from_value(json!({"body":v["body"],"signature":v["signature"]})).unwrap()
        })
        .collect();
    assert_eq!(pool.len(), 1);
    assert_eq!(codec::transaction_id(&pool[0]), pending_id);
    assert_eq!(node.template().unwrap().transactions, vec![pending]);
}

#[test]
fn reorg_drops_expired_conditional_transactions_and_recovers_valid_common_transfer() {
    let (_base_dir, mut base) = funded();
    propose(
        &mut base,
        Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: key(&[93; 32]),
                amount: 20u32.into(),
            }],
        },
        93,
        2,
    );
    until(&mut base, "governance", 0);
    let fork_height = base.tip_height();
    let (_old_dir, mut old) = fork(&base);
    let (_new_dir, mut new) = fork(&base);
    let decision = old.tip_state().decision_id().unwrap();
    let conditional = sign(
        &old,
        &player(0),
        Operation::Deposit {
            amount: 10u32.into(),

            decision: Some(decision),
            outcome: Some(Outcome::Pass),
        },
        1,
        0,
    );
    let common = sign(
        &old,
        &player(1),
        Operation::TransferExact {
            recipient: key(&player(2)),
            amount: 9u32.into(),
        },
        1,
        0,
    );
    append(&mut old, vec![conditional, common.clone()], 1);
    buy(&mut old, Outcome::Pass, 1);
    buy(&mut new, Outcome::Fail, 2);
    until(&mut old, "rest", 1);
    until(&mut new, "rest", 2);
    let d = tempfile::tempdir().unwrap();
    let node = Node::open(
        &d.path().join("node.sqlite"),
        old.config.clone(),
        key(&MINER),
    )
    .unwrap();
    node_import(&node, &old, 0);
    empty(&mut new, 1, 2);
    node_import(&node, &new, fork_height);
    let pool: Vec<Transaction> = node
        .rpc("mempool", json!({}))
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            serde_json::from_value(json!({"body":v["body"],"signature":v["signature"]})).unwrap()
        })
        .collect();
    assert_eq!(pool, vec![common]);
    assert_eq!(
        node.status().unwrap()["state_root"],
        hex::encode(new.tip_state().root())
    );
}

#[test]
fn pending_nonce_dependencies_survive_equal_work_then_recover_across_detached_blocks() {
    let (_base_dir, base) = funded();
    let fork_height = base.tip_height();
    let (_old_dir, mut old) = fork(&base);
    let (_new_dir, mut new) = fork(&base);
    let transfer = || Operation::TransferExact {
        recipient: key(&player(1)),
        amount: 3u32.into(),
    };
    let first = sign(&old, &player(0), transfer(), 1, 0);
    append(&mut old, vec![first.clone()], 1);
    let second = sign(&old, &player(0), transfer(), 1, 0);
    append(&mut old, vec![second.clone()], 1);
    let pending = sign(&old, &player(0), transfer(), 1, 0);
    let d = tempfile::tempdir().unwrap();
    let node = Node::open(
        &d.path().join("node.sqlite"),
        base.config.clone(),
        key(&MINER),
    )
    .unwrap();
    node_import(&node, &old, 0);
    node.submit_transaction(pending.clone()).unwrap();
    empty(&mut new, 2, 2);
    node_import(&node, &new, fork_height);
    assert_eq!(node.status().unwrap()["tip"], hex::encode(old.tip_hash()));
    assert_eq!(node.template().unwrap().transactions, vec![pending.clone()]);
    append(&mut new, vec![], 2);
    node_import(&node, &new, fork_height);
    assert_eq!(node.status().unwrap()["tip"], hex::encode(new.tip_hash()));
    assert_eq!(
        node.template().unwrap().transactions,
        vec![first, second, pending]
    );
    let mined = node.mine(1_000_000).unwrap();
    new.submit(mined.clone(), mined.header.timestamp as u64)
        .unwrap();
    new.tip_state().audit(&new.config).unwrap();
    assert_eq!(
        node.status().unwrap()["state_root"],
        hex::encode(new.tip_state().root())
    );
    assert_eq!(
        new.tip_state()
            .account(&key(&player(0)), None)
            .unwrap()
            .nonce,
        base.tip_state()
            .account(&key(&player(0)), None)
            .unwrap()
            .nonce
            + 3
    );
}

#[test]
fn a_recovered_spend_whose_account_only_a_recovered_transfer_creates_confirms_after_it() {
    let (_base_dir, base) = funded();
    let fork_height = base.tip_height();
    let (_old_dir, mut old) = fork(&base);
    let (_new_dir, mut new) = fork(&base);
    // On the old branch a transfer creates an account, which spends in the
    // next block: consensus reserves inputs from the block opening, so the
    // two can never share a block.
    let fresh = [97; 32];
    let funding = sign(
        &old,
        &MINER,
        Operation::TransferExact {
            recipient: key(&fresh),
            amount: 500u32.into(),
        },
        1,
        0,
    );
    append(&mut old, vec![funding.clone()], 1);
    let spend = support::sign_minimum(
        old.tip_state(),
        TransactionBody {
            data: Vec::new(),
            sender: key(&fresh),
            nonce: 0,
            fee: 0u32.into(),
            anchor: codec::block_hash(&codec::genesis_block(&old.config).unwrap()),
            expiry_blocks: old.tip_height() + 10_000,
            operation: Operation::TransferExact {
                recipient: key(&player(1)),
                amount: 3u32.into(),
            },
        },
        &fresh,
        1,
    );
    append(&mut old, vec![spend.clone()], 1);
    let d = tempfile::tempdir().unwrap();
    let node = Node::open(
        &d.path().join("node.sqlite"),
        base.config.clone(),
        key(&MINER),
    )
    .unwrap();
    node_import(&node, &old, 0);
    // A heavier branch without either detaches both.
    empty(&mut new, 3, 2);
    node_import(&node, &new, fork_height);
    assert_eq!(node.status().unwrap()["tip"], hex::encode(new.tip_hash()));
    // The transfer is pending again, and the spend, whose sender has no
    // account on this branch, waits for it rather than being dropped.
    assert_eq!(node.template().unwrap().transactions, vec![funding.clone()]);
    let first = node.mine(1_000_000).unwrap();
    assert_eq!(first.transactions, vec![funding]);
    assert_eq!(node.template().unwrap().transactions, vec![spend.clone()]);
    let second = node.mine(1_000_000).unwrap();
    assert_eq!(second.transactions, vec![spend]);
    for block in [first, second] {
        assert!(
            new.submit(block.clone(), block.header.timestamp as u64)
                .unwrap()
        );
    }
    new.tip_state().audit(&new.config).unwrap();
    assert_eq!(
        node.status().unwrap()["state_root"],
        hex::encode(new.tip_state().root())
    );
    assert_eq!(
        new.tip_state().account(&key(&fresh), None).unwrap().nonce,
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multi_batch_peer_reorg_crosses_opposite_resolution_and_rest_then_restarts() {
    let (_base_dir, mut base) = funded();
    let grant = &base.tip_state().world.reserve / 20u32;
    assert!(grant > base.tip_state().world.revenue);
    propose(
        &mut base,
        Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: key(&[94; 32]),
                amount: grant,
            }],
        },
        94,
        2,
    );
    until(&mut base, "governance", 0);
    let fork_height = base.tip_height();
    let (_left_dir, mut left) = fork(&base);
    let (_right_dir, mut right) = fork(&base);
    buy(&mut left, Outcome::Pass, 1);
    buy(&mut right, Outcome::Fail, 2);
    empty(&mut left, 44, 1);
    empty(&mut right, 46, 2);
    assert!(left.tip_state().account(&key(&[94; 32]), None).is_some());
    assert!(right.tip_state().account(&key(&[94; 32]), None).is_none());
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("left.sqlite");
    let a = Node::open(&path, left.config.clone(), key(&MINER)).unwrap();
    let b = Node::open(
        &d.path().join("right.sqlite"),
        right.config.clone(),
        key(&MINER),
    )
    .unwrap();
    node_import(&a, &left, 0);
    node_import(&b, &right, 0);
    let zero: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = node::serve(
        b.clone(),
        ServerOptions {
            rpc: zero,
            p2p: zero,
            stratum: zero,
            peers: vec![],
            stratum_password: None,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    node::sync_peer(&a, server.p2p).await.unwrap();
    assert_eq!(
        a.status().unwrap()["tip"],
        hex::encode(left.tip_hash()),
        "the first partial branch has less work"
    );
    for _ in 0..4 {
        node::sync_peer(&a, server.p2p).await.unwrap();
        if a.status().unwrap()["tip"] == hex::encode(right.tip_hash()) {
            break;
        }
    }
    assert_eq!(
        a.status().unwrap()["tip"],
        hex::encode(right.tip_hash()),
        "must advance the downloaded branch beyond its first 32 blocks"
    );
    assert_eq!(
        a.status().unwrap()["state_root"],
        hex::encode(right.tip_state().root())
    );
    let retained: Block = serde_json::from_value(
        a.rpc(
            "getblock",
            json!({"hash":hex::encode(left.hash_at_height(fork_height + 40).unwrap())}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(retained.height, fork_height + 40);
    server.stop().await;
    drop(a);
    drop(b);
    let reopened = Node::open(&path, right.config.clone(), key(&MINER)).unwrap();
    assert_eq!(
        reopened.status().unwrap()["tip"],
        hex::encode(right.tip_hash())
    );
    assert_eq!(
        reopened.status().unwrap()["state_root"],
        hex::encode(right.tip_state().root())
    );
}
