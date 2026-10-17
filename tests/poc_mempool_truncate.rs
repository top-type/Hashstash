//! Regression tests for audit finding F009: candidates that can never execute
//! must not use up the selection work available to honest transactions.
//!
//! * A fee the sender's opening balance cannot cover can never apply, because
//!   only opening funds can be committed. Such candidates are dropped before
//!   ranking, whatever fee they declare, and are never charged an attempt.
//! * Candidates that are affordable but keep failing are charged to their own
//!   sender's attempt budget, so they cannot exhaust anyone else's.
//!
//! `Node::receive_peer` replaces its mempool with this selection, so honest
//! pending transactions survive one peer message full of such candidates.
//!
//! A related prior finding: one forged transaction used to force a selection
//! over the whole mempool, re-verifying every signature, before it was refused.

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

/// Miner key; also the honest payer (funded by coinbase).
const SECRET: [u8; 32] = [61; 32];
/// The single funded attacker account.
const ATTACKER: [u8; 32] = [200; 32];

fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}

fn configuration(block_bytes: u64) -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = block_bytes;
    c
}

fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(chain.template(key(), transactions, time).unwrap(), 100_000).unwrap();
    chain.submit(block.clone(), time as u64).unwrap();
    block
}

fn body(chain: &Chain, secret: &[u8; 32], nonce: u64, operation: Operation) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        sender: crypto::public_key(secret).unwrap(),
        nonce,
        fee: 0u32.into(),
        anchor: codec::block_hash(&codec::genesis_block(&chain.config).unwrap()),
        expiry_blocks: chain.tip_height() + 10_000,
        operation,
    }
}

/// A valid, applyable honest transaction: a 1-atom self-payment.
fn self_payment(chain: &Chain, secret: &[u8; 32], nonce: u64) -> Transaction {
    let recipient = crypto::public_key(secret).unwrap();
    support::sign_minimum(
        chain.tip_state(),
        body(
            chain,
            secret,
            nonce,
            Operation::TransferExact {
                recipient,
                amount: 1u32.into(),
            },
        ),
        secret,
        0,
    )
}

/// Ranks first with a 2^500 fee the sender can never pay. `salt` varies the
/// lifetime so every copy has a distinct transaction ID.
fn unpayable(chain: &Chain, secret: &[u8; 32], nonce: u64, salt: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    let mut body = body(
        chain,
        secret,
        nonce,
        Operation::TransferExact {
            recipient: sender,
            amount: 1u32.into(),
        },
    );
    body.fee = Amount::from(1u32) << 500usize;
    body.expiry_blocks += salt;
    crypto::sign(&chain.chain_id(), &body, secret).unwrap()
}

/// Affordable and well ranked, but the zero-amount operation always fails.
fn failing(chain: &Chain, secret: &[u8; 32], nonce: u64, salt: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    let mut body = body(
        chain,
        secret,
        nonce,
        Operation::TransferExact {
            recipient: sender,
            amount: 0u32.into(),
        },
    );
    body.fee = 40u32.into();
    body.expiry_blocks += salt;
    crypto::sign(&chain.chain_id(), &body, secret).unwrap()
}

/// Fund the attacker and return the chain with `honest` pending payments.
fn setup(block_bytes: u64, honest: usize) -> (tempfile::TempDir, Chain, Vec<Transaction>) {
    let directory = tempfile::tempdir().unwrap();
    let mut chain =
        Chain::open(&directory.path().join("selection.db"), configuration(block_bytes)).unwrap();
    for _ in 0..10 {
        append(&mut chain, vec![]);
    }
    let attacker = crypto::public_key(&ATTACKER).unwrap();
    let nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
    let fund = support::sign_minimum(
        chain.tip_state(),
        body(
            &chain,
            &SECRET,
            nonce,
            Operation::TransferExact {
                recipient: attacker,
                amount: 1_000u32.into(),
            },
        ),
        &SECRET,
        0,
    );
    append(&mut chain, vec![fund]);
    let start = chain.tip_state().account(&key(), None).unwrap().nonce;
    let honest = (0..honest as u64)
        .map(|n| self_payment(&chain, &SECRET, start + n))
        .collect();
    (directory, chain, honest)
}

fn attacker_nonce(chain: &Chain) -> u64 {
    let attacker = crypto::public_key(&ATTACKER).unwrap();
    chain.tip_state().account(&attacker, None).unwrap().nonce
}

/// One 256-transaction peer message of unpayable fees leaves the honest
/// selection, and therefore the node's replacement mempool, unchanged.
#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn unpayable_high_fee_candidates_cannot_truncate_selection() {
    for (block_bytes, honest_count) in [(1024 * 1024, 1024), (16 * 1024, 160)] {
        let (_directory, chain, honest) = setup(block_bytes, honest_count);
        let nonce = attacker_nonce(&chain);
        let attack: Vec<_> = (0..256)
            .map(|salt| unpayable(&chain, &ATTACKER, nonce, salt))
            .collect();
        let baseline = chain.select_transactions(key(), &honest, 4096).unwrap();
        let mut combined = honest.clone();
        combined.extend(attack);
        let attacked = chain.select_transactions(key(), &combined, 4096).unwrap();
        assert!(baseline.transactions.len() >= 40);
        assert_eq!(attacked.transactions, baseline.transactions);
        // Unpayable candidates are never attempted, so they burn no budget.
        assert_eq!(attacked.execution_attempts, baseline.execution_attempts);
        assert!(!attacked.budget_exhausted);
        assert_eq!(attacked.signatures_checked, combined.len());
    }
}

/// Affordable candidates that always fail are retried only within their own
/// sender's budget; every honest transaction is still selected.
#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn persistent_failures_use_only_their_senders_budget() {
    let (_directory, chain, honest) = setup(1024 * 1024, 512);
    let nonce = attacker_nonce(&chain);
    let attack: Vec<_> = (0..256)
        .map(|salt| failing(&chain, &ATTACKER, nonce, salt))
        .collect();
    let baseline = chain.select_transactions(key(), &honest, 4096).unwrap();
    assert_eq!(baseline.transactions.len(), honest.len());
    let mut combined = attack.clone();
    combined.extend(honest.iter().cloned());
    let attacked = chain.select_transactions(key(), &combined, 4096).unwrap();
    assert_eq!(attacked.transactions, baseline.transactions);
    assert!(attacked.budget_exhausted);
    // Every attacker candidate was tried and failed, so a node's pool counts
    // them as refused rather than leaving them undecided in its backlog.
    assert!(attacked.exhausted_senders.is_empty());
    assert!(!attacked.truncated);
    // The attacker's candidates spend exactly their own allowance.
    assert_eq!(
        attacked.execution_attempts,
        honest.len() + attack.len() * SELECTION_ATTEMPTS_PER_CANDIDATE
    );
    // The resulting template is a valid block.
    let time = chain.tip_block().header.timestamp + 15;
    let (selected, template) = chain.select_template(key(), &combined, 4096, time).unwrap();
    assert_eq!(selected.transactions, baseline.transactions);
    let mined = Chain::mine(template, 1_000_000).unwrap();
    let mut chain = chain;
    assert!(chain.submit(mined, time as u64).unwrap());
}

/// Config-only transaction builder for the `Node` (no `Chain` handle): a
/// genesis-anchored self-payment at a fixed fee above the minimum.
fn node_self_payment(c: &Config, secret: &[u8; 32], nonce: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    crypto::sign(
        &c.chain_id(),
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

/// Related prior finding: one bad-signature transaction used to force a
/// full-mempool signature re-verification on the public `submit_transaction`
/// path (the same path `receive_peer` uses), under the node lock. Submission
/// and relay now authenticate a transaction before taking the node lock, so a
/// forged record is refused without any selection; this asserts the fix.
#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn h9_bad_signature_is_refused_before_selection() {
    let dir = tempfile::tempdir().unwrap();
    let config = configuration(1024 * 1024); // hold a full mempool
    let node = Node::open(&dir.path().join("timing.db"), config.clone(), key()).unwrap();

    // Fund the miner via coinbase.
    for _ in 0..10 {
        node.mine(100_000).unwrap();
    }

    // Fill the mempool with honest self-payments.
    let target = node::MAX_MEMPOOL; // 256
    for nonce in 0..target as u64 {
        node.submit_transaction(node_self_payment(&config, &SECRET, nonce))
            .unwrap();
    }
    let filled = node.status().unwrap()["mempool"].as_u64().unwrap() as usize;

    // Resubmitting an existing transaction short-circuits before any
    // selection or signature work.
    let dup = node_self_payment(&config, &SECRET, 0);
    let t0 = Instant::now();
    let _ = node.submit_transaction(dup);
    let dup_elapsed = t0.elapsed();

    // One transaction with a bad signature cannot short-circuit (its id differs).
    // Before the fix submit_locked re-ran selection over the whole mempool,
    // re-verifying every signature before rejecting it.
    let mut bad = node_self_payment(&config, &SECRET, 0);
    bad.signature[0] ^= 1;
    let before = node.rpc("mempool", serde_json::json!({"format":"hex"})).unwrap();
    let t1 = Instant::now();
    let rejected = node.submit_transaction(bad);
    let bad_elapsed = t1.elapsed();

    println!("=== H9 related: forged transaction refused before selection ===");
    println!("mempool size:                         {filled}");
    println!("duplicate resubmit (short-circuit):   {dup_elapsed:?}");
    println!("bad-signature resubmit (one verify):  {bad_elapsed:?}");
    println!("bad transaction rejected:             {}", rejected.is_err());

    assert!(filled >= 1, "mempool should have been filled");
    // The forged record is refused by its own authentication, never by a
    // selection over the pool, and the pool is untouched.
    let error = rejected.expect_err("bad signature must be rejected").to_string();
    assert!(error.contains("invalid transaction signature"), "{error}");
    assert_eq!(
        node.rpc("mempool", serde_json::json!({"format":"hex"})).unwrap(),
        before
    );
}
