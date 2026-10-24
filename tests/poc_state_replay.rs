//! Regression tests for historical state reconstruction and side-branch
//! admission (audit findings F001, F003 and F017).
//!
//! * Reconstruction starts from the nearest retained active-chain checkpoint,
//!   so an ancestor costs about its depth below the tip, never the chain height.
//!   Checkpoints are never evicted by side-branch traffic or by unrelated
//!   reconstructions, and deferred progress survives cache churn.
//! * A block that would not become the tip is validated and stored only if its
//!   branch is competitive when it arrives: low-work blocks are refused before
//!   any anchor walk, state reconstruction or storage, and are never cached as
//!   invalid. Their headers are held instead, so a heavier branch whose first
//!   blocks are declined is still adopted once its held headers claim more
//!   work than the tip.

mod support;

use hashstash::{
    chain::{
        Chain, DENSE_STATE_CHECKPOINTS, MAX_CACHED_STATES, SIDE_BRANCH_CATCH_UP_BLOCKS,
        SideBranchRefused, ValidationDeferred,
    },
    codec,
    config::Config,
    crypto, math,
    types::*,
};

const SECRET: [u8; 32] = [61; 32];

fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}

/// `initial_bits == limit_bits`, mirroring every real preset.
fn configuration() -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262_144;
    c
}

/// A calibrated network whose ASERT limit is 1024 times easier than its
/// initial target, so timestamp error can make side blocks cheap.
fn calibrated() -> Config {
    let mut c = configuration();
    c.limit_bits = 0x207fffff;
    c
}

/// A minimum-fee self-payment anchored at genesis (valid on every branch).
fn self_payment(chain: &Chain, nonce: u64) -> Transaction {
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            sender: key(),
            nonce,
            fee: 0u32.into(),
            anchor: codec::block_hash(&codec::genesis_block(&chain.config).unwrap()),
            expiry_blocks: 10_000_000,
            operation: Operation::TransferExact {
                recipient: key(),
                amount: 1u32.into(),
            },
            data: Vec::new(),
        },
        &SECRET,
        0,
    )
}

/// Mine one block on the current tip at `time`, salted so equal templates on
/// different branches remain distinct records.
fn mine_at(chain: &Chain, transactions: Vec<Transaction>, time: u32, salt: u64) -> Block {
    let mut candidate = chain.template(key(), transactions, time).unwrap();
    candidate.extranonce = salt.to_le_bytes();
    candidate.header.merkle_root = codec::merkle_root(&candidate).unwrap();
    Chain::mine(candidate, 1_000_000).unwrap()
}

fn next_time(chain: &Chain) -> u32 {
    chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32
}

/// Mine and submit one on-schedule block extending the tip.
fn append(chain: &mut Chain, transactions: Vec<Transaction>, salt: u64) -> Block {
    let time = next_time(chain);
    let block = mine_at(chain, transactions, time, salt);
    assert!(chain.submit(block.clone(), time as u64).unwrap());
    block
}

/// A separate chain holding `source`'s active history up to `height`.
fn fork_at(directory: &std::path::Path, name: &str, source: &Chain, height: u64) -> Chain {
    let mut fork = Chain::open(&directory.join(name), source.config.clone()).unwrap();
    for h in 1..=height {
        let block = source.block(&source.hash_at_height(h).unwrap()).unwrap();
        let time = block.header.timestamp as u64;
        assert!(fork.submit(block, time).unwrap());
    }
    fork
}

/// Submit with a replay budget until validation stops deferring.
fn submit_budgeted(chain: &mut Chain, block: &Block, steps: usize) -> (bool, usize) {
    let mut deferred = 0;
    loop {
        match chain.submit_with_replay_budget(block.clone(), block.header.timestamp as u64, steps) {
            Ok(best) => return (best, deferred),
            Err(error) if error.is::<ValidationDeferred>() => {
                assert_eq!(chain.cached_invalid_count(), 0);
                deferred += 1;
                assert!(deferred < 64, "reconstruction made no progress");
            }
            Err(error) => panic!("{error:#}"),
        }
    }
}

/// Distinct side blocks off a recent active-chain ancestor; each enters the
/// recent-state cache like any accepted side-branch block.
fn churn(chain: &mut Chain, fork: &Chain, count: u64, salt: u64) {
    let time = next_time(fork);
    for n in 0..count {
        let block = mine_at(fork, vec![], time, salt + n);
        assert!(!chain.submit(block, time as u64).unwrap());
    }
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn deep_ancestor_reconstruction_costs_its_depth_not_the_chain_height() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("canonical.sqlite");
    let config = configuration();
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    for height in 1..=600u64 {
        // Each replayed block also executes signed transactions.
        let transactions = if height > 2 {
            let nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
            vec![self_payment(&chain, nonce), self_payment(&chain, nonce + 1)]
        } else {
            vec![]
        };
        append(&mut chain, transactions, 0);
    }
    let tip = chain.tip_hash();
    drop(chain);
    // The clean stop saved a state checkpoint, which a start from it would
    // retain alone below its height; without one this build saved, as at
    // the first start after an upgrade, startup replays all history.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DELETE FROM state_checkpoint_parts; DELETE FROM state_checkpoints;")
        .unwrap();
    // A freshly started node answers from the checkpoints its startup replay kept.
    let mut chain = Chain::open(&path, config).unwrap();
    assert_eq!(chain.tip_hash(), tip);
    let bound = DENSE_STATE_CHECKPOINTS as usize + 2 * 10 + 2;
    assert!(
        chain.checkpoint_state_count() <= bound,
        "{} checkpoints",
        chain.checkpoint_state_count()
    );
    for depth in [40u64, 150, 280] {
        let height = chain.tip_height() - depth;
        let fork = fork_at(
            directory.path(),
            &format!("fork-{depth}.sqlite"),
            &chain,
            height,
        );
        let competitor = mine_at(&fork, vec![], next_time(&fork), 0x5eed + depth);
        // The parent state is reachable within a budget of its depth; replaying
        // from genesis or a recent-only cache would need the full height.
        let budget = depth as usize + 2;
        assert!(chain.tip_height() - depth > budget as u64);
        let (best, deferred) = submit_budgeted(&mut chain, &competitor, budget);
        assert!(!best);
        assert_eq!(
            deferred, 0,
            "depth {depth} needed more than {budget} replays"
        );
        assert_eq!(chain.tip_hash(), tip);
        assert!(chain.block(&codec::block_hash(&competitor)).is_some());
    }
    assert!(chain.cached_state_count() <= MAX_CACHED_STATES);
}

#[test]
fn fork_point_state_survives_side_branch_and_replay_cache_churn() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration();
    let mut chain = Chain::open(&directory.path().join("victim.sqlite"), config).unwrap();
    for _ in 0..300 {
        append(&mut chain, vec![], 0);
    }
    let tip = chain.tip_hash();
    let parent = chain.tip_height() - 1;
    let honest = fork_at(directory.path(), "honest.sqlite", &chain, parent);
    let near = fork_at(directory.path(), "near.sqlite", &chain, parent - 2);
    // Flood the recent-state cache with valid side states and with old
    // active-chain reconstructions, the cheap eviction tools in the finding.
    churn(&mut chain, &near, 2 * MAX_CACHED_STATES as u64, 1_000);
    for height in [5, 90, 150] {
        assert!(
            chain
                .state_at(&chain.hash_at_height(height).unwrap())
                .is_some()
        );
    }
    assert_eq!(chain.cached_state_count(), MAX_CACHED_STATES);
    // The competing block and its child validate at once: the fork point is a
    // retained active-chain checkpoint, so no reconstruction is needed.
    let mut honest = honest;
    let sibling = mine_at(&honest, vec![], next_time(&honest), 77);
    assert!(
        honest
            .submit(sibling.clone(), sibling.header.timestamp as u64)
            .unwrap()
    );
    let child = mine_at(&honest, vec![], next_time(&honest), 78);
    let time = sibling.header.timestamp as u64;
    assert!(!chain.submit_with_replay_budget(sibling, time, 1).unwrap());
    assert_eq!(chain.tip_hash(), tip);
    let time = child.header.timestamp as u64;
    assert!(
        chain
            .submit_with_replay_budget(child.clone(), time, 1)
            .unwrap()
    );
    assert_eq!(chain.tip_hash(), codec::block_hash(&child));
}

#[test]
fn deferred_side_branch_reconstruction_resumes_across_cache_churn() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration();
    let mut chain = Chain::open(&directory.path().join("victim.sqlite"), config).unwrap();
    for _ in 0..400 {
        append(&mut chain, vec![], 0);
    }
    let fork_height = chain.tip_height() - 200;
    let mut branch = fork_at(directory.path(), "branch.sqlite", &chain, fork_height);
    for n in 0..199 {
        let block = append(&mut branch, vec![], 9_000 + n);
        assert!(
            !chain
                .submit(block, branch.tip_block().header.timestamp as u64)
                .unwrap()
        );
    }
    let near = fork_at(
        directory.path(),
        "near.sqlite",
        &chain,
        chain.tip_height() - 2,
    );
    // Evict every side-branch state, then keep evicting between retries.
    churn(&mut chain, &near, MAX_CACHED_STATES as u64 + 1, 20_000);
    let overtaking = [
        append(&mut branch, vec![], 9_500),
        append(&mut branch, vec![], 9_501),
    ];
    let mut deferred = 0;
    let mut round = 0;
    for block in &overtaking {
        loop {
            let time = block.header.timestamp as u64;
            match chain.submit_with_replay_budget(block.clone(), time, 64) {
                Ok(_) => break,
                Err(error) if error.is::<ValidationDeferred>() => {
                    deferred += 1;
                    assert!(deferred < 16, "replay progress was lost to cache churn");
                    round += 1;
                    churn(
                        &mut chain,
                        &near,
                        MAX_CACHED_STATES as u64 + 1,
                        30_000 + 1_000 * round,
                    );
                }
                Err(error) => panic!("{error:#}"),
            }
        }
    }
    assert!(deferred > 0);
    assert_eq!(chain.tip_hash(), branch.tip_hash());
    assert_eq!(chain.tip_state().root(), branch.tip_state().root());
}

#[test]
fn cheap_side_blocks_are_refused_before_validation_and_storage() {
    let directory = tempfile::tempdir().unwrap();
    let config = calibrated();
    let mut chain = Chain::open(&directory.path().join("victim.sqlite"), config.clone()).unwrap();
    for _ in 0..40 {
        append(&mut chain, vec![], 0);
    }
    let tip = chain.tip_hash();
    // Fork from an old block with timestamps a day ahead of the schedule. The
    // first fork block has its parent's difficulty; ASERT then makes every
    // child about 1024 times cheaper than the active chain's blocks.
    let mut fork = fork_at(directory.path(), "fork.sqlite", &chain, 2);
    let now = config.genesis_time as u64 + 86_400;
    let first = mine_at(&fork, vec![], now as u32, 1);
    assert!(fork.submit(first.clone(), now).unwrap());
    assert!(!chain.submit(first.clone(), now).unwrap());
    assert!(chain.block(&codec::block_hash(&first)).is_some());
    let initial = math::target_from_bits(config.initial_bits).unwrap();
    assert!(fork.next_target().unwrap() > initial * 512u32);
    for salt in 0..64 {
        let cheap = mine_at(&fork, vec![], now as u32 + 1, 100 + salt);
        let error = chain.submit(cheap.clone(), now + 1).unwrap_err();
        assert!(error.is::<SideBranchRefused>(), "{error:#}");
        assert!(chain.block(&codec::block_hash(&cheap)).is_none());
    }
    // Refusal is local policy, not an invalidity verdict.
    assert_eq!(chain.cached_invalid_count(), 0);
    assert_eq!(chain.tip_hash(), tip);
    // A competitive branch at the active chain's difficulty still reorganizes.
    let mut rival = fork_at(directory.path(), "rival.sqlite", &chain, 35);
    for n in 0..6 {
        let block = append(&mut rival, vec![], 500 + n);
        chain
            .submit(block, rival.tip_block().header.timestamp as u64)
            .unwrap();
    }
    assert_eq!(chain.tip_hash(), rival.tip_hash());
}

#[test]
fn branches_that_cannot_catch_up_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let config = calibrated();
    let mut chain = Chain::open(&directory.path().join("victim.sqlite"), config).unwrap();
    for _ in 0..260 {
        append(&mut chain, vec![], 0);
    }
    // Blocks 32 times cheaper than the tip pass the work-ratio rule, but a
    // branch must still be able to overtake within the catch-up allowance.
    let allowance = SIDE_BRANCH_CATCH_UP_BLOCKS as u64 / 32;
    for (depth, admitted) in [(allowance + 72, false), (allowance - 28, true)] {
        let height = chain.tip_height() - depth;
        let mut fork = fork_at(
            directory.path(),
            &format!("fork-{depth}.sqlite"),
            &chain,
            height,
        );
        // A first block 4,500 seconds late eases its children by 2^5.
        let late = next_time(&fork) + 4_500;
        let first = mine_at(&fork, vec![], late, depth);
        assert!(fork.submit(first.clone(), late as u64).unwrap());
        assert!(!chain.submit(first, late as u64).unwrap());
        let cheaper = mine_at(&fork, vec![], next_time(&fork), depth + 1);
        let result = chain.submit(cheaper.clone(), cheaper.header.timestamp as u64);
        if admitted {
            assert!(!result.unwrap());
        } else {
            let error = result.unwrap_err();
            assert!(error.is::<SideBranchRefused>(), "{error:#}");
            assert!(chain.block(&codec::block_hash(&cheaper)).is_none());
        }
    }
    assert_eq!(chain.cached_invalid_count(), 0);
}

#[test]
fn a_long_light_chain_cannot_strand_a_node_off_a_heavier_branch() {
    let directory = tempfile::tempdir().unwrap();
    // The presets' target: every block at the initial target costs two hashes.
    let mut config = configuration();
    config.initial_bits = 0x207fffff;
    config.limit_bits = config.initial_bits;
    let mut victim = Chain::open(&directory.path().join("victim.sqlite"), config.clone()).unwrap();
    // A node first synchronizes a light chain slightly longer than the
    // catch-up allowance, such as one served to it during initial download.
    for n in 0..SIDE_BRANCH_CATCH_UP_BLOCKS as u64 + 4 {
        append(&mut victim, vec![], n);
    }
    // The honest chain from genesis mines one-second blocks, so ASERT raises
    // its work per block and far fewer blocks carry more work.
    let mut honest = Chain::open(&directory.path().join("honest.sqlite"), config).unwrap();
    let mut blocks = Vec::new();
    while honest.chain_work() <= victim.chain_work() {
        let time = honest.tip_block().header.timestamp + 1;
        let block = mine_at(&honest, vec![], time, 7);
        assert!(honest.submit(block.clone(), time as u64).unwrap());
        blocks.push(block);
    }
    assert!(blocks.len() < 1_000);
    // Block 1 alone cannot catch up within the allowance. It used to be
    // refused for good, leaving every later honest block an unknown parent.
    let tip = victim.tip_hash();
    for (index, block) in blocks.iter().enumerate() {
        let hash = codec::block_hash(block);
        let error = victim
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap_err();
        assert!(error.is::<SideBranchRefused>(), "{error:#}");
        assert!(victim.block(&hash).is_none());
        assert_eq!(victim.held_header_count(), index + 1);
        // Presync continues after each held header until the branch overtakes.
        let cursor = victim.download_cursor(&hash).unwrap();
        if index + 1 < blocks.len() {
            assert_eq!(cursor, Some(hash));
        } else {
            assert_eq!(cursor, victim.hash_at_height(0));
        }
    }
    assert_eq!(victim.tip_hash(), tip);
    // Resent bodies bypass the admission policy and the heavier branch wins.
    for block in &blocks {
        victim
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    assert_eq!(victim.tip_hash(), honest.tip_hash());
    assert_eq!(victim.tip_state().root(), honest.tip_state().root());
    assert_eq!(victim.held_header_count(), 0);
    assert_eq!(victim.cached_invalid_count(), 0);
}

#[test]
fn a_reorganization_beneath_deferred_replay_restarts_it() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration();
    let mut chain = Chain::open(&directory.path().join("victim.sqlite"), config).unwrap();
    for _ in 0..300 {
        append(&mut chain, vec![], 0);
    }
    // A side block whose canonical parent at height 250 is rebuilt from the
    // checkpoint at 240, one block per budgeted attempt.
    let parent = fork_at(directory.path(), "side.sqlite", &chain, 250);
    let side = mine_at(&parent, vec![], next_time(&parent), 1);
    let time = side.header.timestamp as u64;
    let error = chain
        .submit_with_replay_budget(side.clone(), time, 1)
        .unwrap_err();
    assert!(error.is::<ValidationDeferred>(), "{error:#}");
    // The active chain now forks at 245, above the retained progress but
    // below the replay's target, so the parent is on a losing branch.
    let mut rival = fork_at(directory.path(), "rival.sqlite", &chain, 245);
    while chain.tip_hash() != rival.tip_hash() {
        let block = append(&mut rival, vec![], 2);
        chain
            .submit(block, rival.tip_block().header.timestamp as u64)
            .unwrap();
    }
    // Resuming used to replay the new branch up to height 250 and fail with
    // an error that was neither invalidity nor deferral.
    let mut deferred = 0;
    loop {
        match chain.submit_with_replay_budget(side.clone(), time, 1) {
            Ok(best) => {
                assert!(!best);
                break;
            }
            Err(error) if error.is::<ValidationDeferred>() => {
                deferred += 1;
                assert!(deferred < 64, "reconstruction made no progress");
            }
            Err(error) => panic!("{error:#}"),
        }
    }
    assert!(chain.block(&codec::block_hash(&side)).is_some());
    assert_eq!(chain.cached_invalid_count(), 0);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn deep_side_branch_anchors_resolve_through_skip_links() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration();
    let mut chain = Chain::open(&directory.path().join("main.sqlite"), config).unwrap();
    for _ in 0..320 {
        append(&mut chain, vec![], 0);
    }
    // A long losing branch forked from height 10; its own blocks anchor below.
    let mut branch = fork_at(directory.path(), "branch.sqlite", &chain, 10);
    let mut anchors = Vec::new();
    for n in 0..305 {
        let block = append(&mut branch, vec![], 40_000 + n);
        anchors.push(codec::block_hash(&block));
        let time = block.header.timestamp as u64;
        assert!(!chain.submit(block, time).unwrap());
    }
    let nonce = branch.tip_state().account(&key(), None).unwrap().nonce;
    let mut deep = self_payment(&branch, nonce).body;
    deep.anchor = anchors[2];
    let deep = crypto::sign(&branch.chain_id(), &deep, &SECRET).unwrap();
    let block = append(&mut branch, vec![deep], 99_000);
    assert!(
        !chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap()
    );
    assert!(chain.block(&codec::block_hash(&block)).is_some());
    // An anchor from the active chain above the fork is not on this branch.
    let nonce = branch.tip_state().account(&key(), None).unwrap().nonce;
    let mut foreign = self_payment(&branch, nonce).body;
    foreign.anchor = chain.hash_at_height(15).unwrap();
    let foreign = crypto::sign(&branch.chain_id(), &foreign, &SECRET).unwrap();
    let mut invalid = branch.template(key(), vec![], next_time(&branch)).unwrap();
    invalid.transactions = vec![foreign];
    invalid.header.merkle_root = codec::merkle_root(&invalid).unwrap();
    let invalid = Chain::mine(invalid, 1_000_000).unwrap();
    let error = chain
        .submit(invalid, next_time(&branch) as u64)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not on the candidate parent branch"),
        "{error}"
    );
}
