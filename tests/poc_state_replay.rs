//! Proof-of-concept: unbounded historical state replay + free low-work side
//! branches (findings H1 / H2 / H3).
//!
//! ## Findings reproduced
//!
//! * **H2 (remote-triggerable unbounded replay).** `src/node.rs::blocks_after`
//!   (lines ~1005-1028) serves a peer's sync request by taking the highest
//!   canonical locator hash and calling `chain.state_at(&ancestor)`.
//!   `Chain::state_at` (src/chain.rs:363) -> `load_state` (src/chain.rs:490-550)
//!   reconstructs that ancestor's state by replaying every block from the
//!   nearest cached state or from genesis, with **no work/step budget** on the
//!   normal (`submit`) path. The historical-state cache is a 128-entry FIFO
//!   (`MAX_CACHED_STATES`, src/chain.rs:13; evicted in `cache_state`,
//!   src/chain.rs:475-489), so the retained states are only a short contiguous
//!   window near the tip. Any peer can put a single *old* canonical hash in a
//!   locator (`node.rs::locator` legitimately emits such sparse locators) and
//!   force an O(height) replay. `peer_snapshot` holds `self.locked()` while this
//!   runs, so each request stalls the node. The cost is per-request and
//!   repeatable.
//!
//! * **H1 (reorg parent states only from the FIFO cache).** The same FIFO is the
//!   only fast source of parent states; anything below the window replays from
//!   genesis. This PoC measures that replay cost directly via `state_at` for
//!   ancestors far below the 128-entry window.
//!
//! * **H3 (free, permanently stored low-work side branches).** `Chain::submit`
//!   (src/chain.rs:720-764) fully validates and *permanently stores* every
//!   structurally valid block (INSERT into `blocks` + `entry_index`) even when
//!   it never becomes tip (`best == false`); there is no minimum-work / minimum
//!   cumulative-work admission rule. Because every preset sets
//!   `initial_bits == limit_bits` (see `Config::devnet/testnet/slow_testnet` in
//!   src/config.rs and the `config/*.json` presets), difficulty never rises and
//!   blocks are ~free to mine, so an attacker can cheaply fill disk with
//!   accepted-but-losing branches.
//!
//! ## How to run
//!
//! ```text
//! cargo test --release --features test-fixtures --test poc_state_replay -- --nocapture
//! ```
//!
//! Tunables (env vars):
//!   * `POC_BLOCKS` - canonical chain length N (default 2000).
//!   * `POC_SIDE`   - number of low-work side-branch blocks M (default 500).
//!
//! `--release` matters: `[profile.release]` enables `overflow-checks`, and the
//! replay/mining loops are far too slow in a debug build. `--features
//! test-fixtures` is REQUIRED (see the Cargo.toml stanza below): the fixture
//! build sets `Config.test_work = true` so `work_per_atom() == 1`, which is what
//! lets the coinbase subsidy fund the few self-payments embedded in each
//! canonical block (without it the subsidy rounds to 0 atoms and the miner
//! cannot pay fees). Without the feature the test is marked `ignore`.
//!
//! ## Cargo.toml stanza (add under the other `[[test]]` entries; do NOT commit a
//! change from this PoC task, this is informational):
//!
//! ```toml
//! [[test]]
//! name = "poc_state_replay"
//! required-features = ["test-fixtures"]
//! ```
//!
//! ## Interpreting the output
//!
//! The `state_at(height h)` lines print both absolute ms and ms-per-replayed
//! block `r = ms / h`. Because nothing between genesis and the 128-block tip
//! window is cached, a sync request whose locator resolves to a common ancestor
//! at height `h` costs about `r * h` ms of single-threaded work while the node
//! lock is held, and a peer can repeat it at will. Extrapolate linearly to a
//! real deployment: at a mainnet-scale height `H` the per-request cost is
//! `~= r * H` ms. For example, with a measured `r` of ~0.05 ms/block a request
//! pinned near genesis on a chain of height 1,000,000 costs ~50,000 ms (~50 s)
//! of CPU per request; at height 10,000,000 it is ~500 s. The `Chain::open`
//! line shows the same O(N) replay paid once at every node startup (full
//! revalidation of stored history). The side-branch line shows M blocks mined
//! essentially for free and left permanently in the `blocks` table despite
//! never being tip.

mod support;

use hashstash::{chain::Chain, codec, config::Config, crypto, types::*};
use std::time::Instant;

const SECRET: [u8; 32] = [61; 32];

fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}

/// Limit-difficulty fixture: `initial_bits == limit_bits`, mirroring every real
/// preset. These exact bits are the ones `tests/selection_budget.rs` uses, so
/// `Chain::mine(_, 1_000_000)` reliably finds a nonce (~2048 attempts/block).
fn configuration() -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262_144;
    c
}

fn genesis_anchor(config: &Config) -> Hash {
    codec::block_hash(&codec::genesis_block(config).unwrap())
}

/// A minimum-fee self-payment anchored at genesis (valid on every branch).
/// `sign_minimum` overwrites `fee` with the exact minimum, so the value passed
/// here is irrelevant.
fn self_payment(chain: &Chain, nonce: u64) -> Transaction {
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            sender: key(),
            nonce,
            fee: 0u32.into(),
            anchor: genesis_anchor(&chain.config),
            // Far beyond any N this PoC builds, so transactions never expire.
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

/// Mine and submit one block on the current tip with the given transactions.
fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let template = chain.template(key(), transactions, time).unwrap();
    let block = Chain::mine(template, 1_000_000).unwrap();
    assert!(
        chain.submit(block.clone(), time as u64).unwrap(),
        "canonical block must extend the tip"
    );
    block
}

/// Mine and submit an empty block carrying a distinct `extranonce` salt so the
/// resulting hash can never coincide with the canonical block at the same
/// height (which is mined with the default zero extranonce). This guarantees
/// each side-branch block is a genuinely new, distinct record. Mirrors the
/// salted `append_at` helper in `tests/reorg_stress.rs`.
fn append_salted(chain: &mut Chain, salt: u64) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let mut candidate = chain.template(key(), Vec::new(), time).unwrap();
    candidate.extranonce = salt.to_le_bytes();
    candidate.header.merkle_root = codec::merkle_root(&candidate).unwrap();
    let block = Chain::mine(candidate, 1_000_000).unwrap();
    assert!(
        chain.submit(block.clone(), time as u64).unwrap(),
        "side block must extend the fork tip"
    );
    block
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn state_replay_and_low_work_side_branch_costs() {
    let blocks = env_u64("POC_BLOCKS", 2000).max(4);
    let side = env_u64("POC_SIDE", 500).max(1);
    println!("POC_BLOCKS={blocks} POC_SIDE={side}");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("canonical.sqlite");
    let config = configuration();

    // ---- Phase 1: build a canonical chain of `blocks` blocks ---------------
    // A short warmup lets the miner accrue coinbase before it starts paying
    // fees; thereafter every block carries a couple of self-payments so that
    // replaying each block does real consensus work (signature checks + state
    // transitions), not just an empty coinbase.
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    let warmup = 2u64;
    let build_start = Instant::now();
    for height in 1..=blocks {
        let txs = if height > warmup {
            let nonce = chain
                .tip_state()
                .account(&key(), None)
                .map(|a| a.nonce)
                .unwrap_or(0);
            vec![self_payment(&chain, nonce), self_payment(&chain, nonce + 1)]
        } else {
            vec![]
        };
        append(&mut chain, txs);
    }
    let build_ms = build_start.elapsed().as_secs_f64() * 1000.0;
    let tip = chain.tip_hash();
    println!(
        "[build] {blocks} canonical blocks mined+submitted in {build_ms:.1} ms; tip height = {}",
        chain.tip_height()
    );
    // After a live build the FIFO already holds only the most recent states.
    println!(
        "[build] cached_state_count after live build = {} (cap MAX_CACHED_STATES=128)",
        chain.cached_state_count()
    );

    // ---- Phase 2: startup revalidation cost (Chain::open) ------------------
    // Reopening replays every stored block from genesis to rebuild derived
    // indexes and states; this is the per-restart O(N) cost. It also leaves the
    // historical-state cache as a clean, contiguous ~128-block window near the
    // tip, which is exactly the state a freshly started node answers peers from.
    drop(chain);
    let open_start = Instant::now();
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    let open_ms = open_start.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(chain.tip_hash(), tip, "reopened tip must match");
    println!(
        "[open] Chain::open revalidated {blocks} blocks in {open_ms:.1} ms ({:.4} ms/block)",
        open_ms / blocks as f64
    );
    println!(
        "[open] cached_state_count after reopen = {} (bounded by 128; everything below the window replays from genesis)",
        chain.cached_state_count()
    );

    // ---- Phase 3: state_at for ancestors far below the FIFO window ---------
    // These are the `state_at` calls node.rs::blocks_after makes for a peer
    // locator's common ancestor. We query in DESCENDING height order: the FIFO
    // only ever retains a single recent contiguous window, so after replaying a
    // higher ancestor the lower ones still find no usable checkpoint and replay
    // from genesis again. Cost is therefore ~proportional to the queried height.
    let mut heights = vec![1u64, blocks / 2, blocks.saturating_sub(200)];
    heights.sort_unstable();
    heights.dedup();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    for h in heights {
        let hash = chain
            .hash_at_height(h)
            .expect("canonical height must be present");
        let start = Instant::now();
        let state = chain.state_at(&hash);
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        // Only required assertion for this phase.
        assert!(state.is_some(), "state_at returned None for height {h}");
        println!(
            "[state_at] height {h}: {ms:.1} ms total, {:.4} ms/block (≈{h} blocks replayed from genesis)",
            ms / h.max(1) as f64
        );
    }

    // ---- Phase 4: free, permanently stored low-work side branch (H3) -------
    // Fork from an old ancestor (height 1), mine `side` empty low-work blocks on
    // that fork, and feed each to the big chain. They are fully validated and
    // stored forever, yet never approach the canonical tip's cumulative work.
    let fork_height = 1u64;
    let fork_dir = tempfile::tempdir().unwrap();
    let mut fork = Chain::open(&fork_dir.path().join("fork.sqlite"), config.clone()).unwrap();
    for h in 1..=fork_height {
        let ancestor = chain.block(&chain.hash_at_height(h).unwrap()).unwrap();
        assert!(
            fork.submit(ancestor.clone(), ancestor.header.timestamp as u64)
                .unwrap()
        );
    }

    let tip_before_side = chain.tip_hash();
    let mut stored = 0u64;
    let mut submit_ms = 0f64;
    for n in 0..side {
        // Mine the next low-work block on the fork branch, salted so it is a
        // distinct record from any canonical block at the same height.
        let block = append_salted(&mut fork, 0x5A5A_5A5A_0000_0000 ^ n);
        let hash = codec::block_hash(&block);

        let start = Instant::now();
        let became_tip = chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        submit_ms += start.elapsed().as_secs_f64() * 1000.0;

        // Required assertions: accepted (stored) but not canonical tip.
        assert!(!became_tip, "a low-work side block became the tip");
        assert!(
            chain.block(&hash).is_some(),
            "accepted side block was not persisted"
        );
        stored += 1;
    }
    assert_eq!(
        chain.tip_hash(),
        tip_before_side,
        "canonical tip changed despite only low-work side blocks"
    );
    println!(
        "[side] {stored} low-work side blocks (forked from height {fork_height}) validated + permanently stored; avg submit = {:.4} ms/block; canonical tip unchanged at height {}",
        submit_ms / stored as f64,
        chain.tip_height()
    );
    println!(
        "[side] fork branch height reached {} vs canonical height {} (never close to overtaking)",
        fork.tip_height(),
        chain.tip_height()
    );
}
