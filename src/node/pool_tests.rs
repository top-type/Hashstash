//! Pool selection, recovery and lock-isolation regressions that need node internals.
use super::*;
use std::collections::BTreeSet;

const SECRET: [u8; 32] = [61; 32];
const OTHER: [u8; 32] = [62; 32];

fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn other() -> PublicKey {
    crypto::public_key(&OTHER).unwrap()
}
fn configuration(block_bytes: u64) -> Config {
    let mut config = Config::devnet();
    // Coinbase work funds every fixture account under test-fixtures.
    config.initial_bits = 0x1f1fffff;
    config.limit_bits = config.initial_bits;
    config.initial.block_bytes = block_bytes;
    config
}
/// A genesis-anchored payment paying the exact minimum fee plus `extra`.
fn payment(
    config: &Config,
    state: &State,
    secret: &[u8; 32],
    nonce: u64,
    recipient: PublicKey,
    amount: u64,
    extra: u64,
) -> Transaction {
    let mut body = TransactionBody {
        data: Vec::new(),
        sender: crypto::public_key(secret).unwrap(),
        nonce,
        fee: Amount::zero(),
        anchor: codec::block_hash(&codec::genesis_block(config).unwrap()),
        expiry_blocks: 1_000_000,
        operation: Operation::TransferExact {
            recipient,
            amount: amount.into(),
        },
    };
    loop {
        let tx = crypto::sign(&state.chain_id, &body, secret).unwrap();
        let fee = fees::quote(config, state, &tx).unwrap().minimum_fee + extra;
        if tx.body.fee == fee {
            return tx;
        }
        body.fee = fee;
    }
}
fn funded_node(directory: &Path, block_bytes: u64) -> Node {
    let node = Node::open(
        &directory.join("node.sqlite"),
        configuration(block_bytes),
        key(),
    )
    .unwrap();
    for _ in 0..8 {
        node.mine(1_000_000).unwrap();
    }
    node
}
fn snapshot(node: &Node) -> Arc<ReadView> {
    node.read_view().unwrap()
}
fn nonce(node: &Node, account: &PublicKey) -> u64 {
    snapshot(node)
        .chain
        .tip_state()
        .account(account, None)
        .unwrap()
        .nonce
}
/// Copy the pool out. Tests never panic while holding the node lock: a
/// poisoned node lock ends the whole process.
fn pool(node: &Node) -> (Vec<Transaction>, Vec<Transaction>, Hash) {
    let i = node.locked().unwrap();
    (i.mempool.clone(), i.backlog.clone(), i.pool_tip)
}
fn published(node: &Node) -> u64 {
    *node.work_updates.borrow()
}
fn signatures() -> usize {
    POOL_SIGNATURES.with(|count| count.replace(0))
}
fn selections() -> usize {
    POOL_SELECTIONS.with(|count| count.replace(0))
}
fn ids(transactions: &[Transaction]) -> BTreeSet<Hash> {
    transactions.iter().map(codec::transaction_id).collect()
}
/// Fund `other()` from the miner and confirm it.
fn fund_other(node: &Node) {
    let view = snapshot(node);
    let config = view.chain.config.as_ref();
    node.submit_transaction(payment(
        config,
        view.chain.tip_state(),
        &SECRET,
        nonce(node, &key()),
        other(),
        5_000,
        0,
    ))
    .unwrap();
    node.mine(1_000_000).unwrap();
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn runtime_reads_preparation_and_wallet_status_do_not_wait_for_the_node_lock() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024)
        .with_wallet(SECRET)
        .unwrap();
    let job = node.template().unwrap();
    let revision = node.wallets_locked().unwrap().status()["wallet_revision"]
        .as_u64()
        .unwrap();
    let operation = Operation::TransferExact {
        recipient: other(),
        amount: 1u32.into(),
    };
    let held = node.locked().unwrap();
    let (sender, receiver) = mpsc::channel();
    let reader = node.clone();
    let request = json!({"sender":hex::encode(key()),"operation":operation});
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            reader.peer_limits()?;
            reader.peer_exchange_timeout()?;
            ensure!(reader.mining_job_eligible(&job)?, "current job is eligible");
            reader.rpc("preparetransaction", request)?;
            Ok(())
        })();
        let _ = sender.send(result.map_err(|error| error.to_string()));
    });
    // Never panic while holding the node lock: a poisoned lock ends the process.
    let reads = receiver.recv_timeout(Duration::from_secs(10));
    // A hot-wallet submission waiting for chain state has released the store.
    let submitter = node.clone();
    let submission = std::thread::spawn(move || {
        submitter.wallet_submit(
            serde_json::from_value(json!({
                "operation":operation,
                "expected_sender":hex::encode(key()),
                "wallet_revision":revision
            }))
            .unwrap(),
        )
    });
    std::thread::sleep(Duration::from_millis(300));
    let wallet_free = node.wallets.try_lock().is_ok();
    drop(held);
    reads
        .expect("transport, mining-job and preparation reads waited for the node lock")
        .unwrap();
    assert!(
        wallet_free,
        "wallet store stays locked while the submission waits for chain state"
    );
    let id = submission.join().unwrap().unwrap();
    assert!(ids(&snapshot(&node).mempool).contains(&id));
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn relay_selects_and_publishes_only_for_new_admissible_entries() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    // Use one nonce, so a stale replay of it is cheaply refused.
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    assert!(start > 0);
    let pooled = payment(config, state, &SECRET, start, key(), 1, 10);
    node.submit_transaction(pooled.clone()).unwrap();
    let revision = published(&node);
    // Rebuilding a template for an unchanged selection publishes nothing.
    node.template().unwrap();
    assert_eq!(published(&node), revision);
    let deliver = |transactions: Vec<Transaction>| {
        signatures();
        selections();
        node.receive_peer(
            &PeerMessage {
                chain: config.chain_id(),
                locator: Vec::new(),
                blocks: Vec::new(),
                transactions,
            },
            "127.0.0.1".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(signatures(), 0, "selection never re-verifies an authenticated entry");
        selections()
    };
    let mut forged = pooled.clone();
    forged.signature[0] ^= 1;
    let used = payment(config, state, &SECRET, start - 1, key(), 2, 0);
    // Valid shape, signature, anchor and nonce, but the sender cannot pay it.
    let unpayable = payment(config, state, &SECRET, start + 1, other(), 1 << 60, 0);
    let underpriced = {
        let mut body = payment(config, state, &SECRET, start + 1, other(), 1, 0).body;
        body.fee = Amount::zero();
        crypto::sign(&state.chain_id, &body, &SECRET).unwrap()
    };
    assert_eq!(
        deliver(vec![forged.clone(), used.clone(), unpayable.clone(), underpriced.clone()]),
        0
    );
    assert_eq!(published(&node), revision, "refused records do not publish");
    let tip = view.chain.tip_hash();
    let pool_revision = snapshot(&node).pool_revision;
    {
        let rejected = node.rejected_locked();
        assert!(rejected.contains(&codec::transaction_id(&forged), &[0; 32], 0));
        assert!(rejected.contains(&codec::transaction_id(&used), &tip, pool_revision + 1));
        assert!(!rejected.contains(&codec::transaction_id(&used), &[0; 32], pool_revision));
        assert!(rejected.contains(&codec::transaction_id(&unpayable), &tip, pool_revision + 1));
        assert!(rejected.contains(&codec::transaction_id(&underpriced), &tip, pool_revision + 1));
    }
    assert!(
        node.submit_transaction(unpayable.clone())
            .unwrap_err()
            .to_string()
            .contains("opening balance does not cover")
    );
    // A lower bid at the pooled nonce cannot replace it: refused at once.
    let outbid = payment(config, state, &SECRET, start, other(), 1, 0);
    assert_eq!(deliver(vec![outbid.clone()]), 0, "a replacement must raise the fee rate");
    assert_eq!(published(&node), revision, "an unchanged selection does not publish");
    // A newcomer only execution refuses costs one selection, then loses it.
    let support = Operation::Support {
        round: 0,
        proposal: [9; 32],
        amount: 1u32.into(),
    };
    let body = unsigned(config, &OTHER, nonce(&node, &other()), support);
    let lost = exact(config, state, &OTHER, body, 0);
    assert_eq!(deliver(vec![lost.clone()]), 1, "one selection for one new candidate");
    assert_eq!(published(&node), revision, "an unchanged selection does not publish");
    assert_eq!(deliver(vec![lost]), 0, "a lost selection is remembered");
    for _ in 0..3 {
        assert_eq!(
            deliver(vec![forged.clone(), used.clone(), unpayable.clone(), outbid.clone()]),
            0,
            "replayed refusals never reach selection"
        );
    }
    assert_eq!(published(&node), revision);
    assert_eq!(snapshot(&node).mempool, vec![pooled.clone()]);
    // A pool change ends a pool-scoped refusal, never a stale-state one; the
    // underbid replacement is refused again by its rule alone.
    let other_payment = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
    node.submit_transaction(other_payment).unwrap();
    assert_eq!(deliver(vec![used, unpayable, outbid.clone()]), 0);
    assert!(!ids(&snapshot(&node).mempool).contains(&codec::transaction_id(&outbid)));
    // An RPC resubmission of a refused identity is answered from the cache.
    selections();
    assert!(node.submit_transaction(outbid).is_err());
    assert_eq!(selections(), 0);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn the_opening_screen_allows_a_recipient_an_earlier_transaction_may_create() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let fresh = crypto::public_key(&[77; 32]).unwrap();
    let creating = payment(config, state, &SECRET, nonce(&node, &key()), fresh, 10, 0);
    let quote = fees::quote(config, state, &creating).unwrap();
    assert!(!quote.account_creation_fee.is_zero());
    let paying = |fee: Amount| {
        let mut body = creating.body.clone();
        body.fee = fee;
        crypto::sign(&state.chain_id, &body, &SECRET).unwrap()
    };
    // Exactly the minimum without account creation, and one atom less.
    let least = paying(&quote.minimum_fee - &quote.account_creation_fee);
    let below = paying(&quote.minimum_fee - &quote.account_creation_fee - 1u32);
    let i = node.locked().unwrap();
    let screened = i.chain.opening_screen(node.miner, &[&creating, &least, &below]);
    drop(i);
    let screened = screened.unwrap();
    assert!(screened[0].is_ok() && screened[1].is_ok());
    assert!(screened[2].is_err());
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_relayed_nonce_gap_is_not_remembered_and_its_chain_is_admitted_together() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let first = payment(config, state, &SECRET, start, key(), 1, 0);
    let second = payment(config, state, &SECRET, start + 1, key(), 1, 0);
    let deliver = |transactions: Vec<Transaction>| {
        selections();
        node.receive_peer(
            &PeerMessage {
                chain: config.chain_id(),
                locator: Vec::new(),
                blocks: Vec::new(),
                transactions,
            },
            "127.0.0.1".parse().unwrap(),
        )
        .unwrap();
        selections()
    };
    // The later nonce alone cannot be selected; it costs no selection and is
    // not remembered, because its predecessor may still arrive on this tip.
    assert_eq!(deliver(vec![second.clone()]), 0);
    assert!(!node.rejected_locked().entries.contains_key(&codec::transaction_id(&second)));
    assert_eq!(deliver(vec![first.clone(), second.clone()]), 1);
    assert_eq!(snapshot(&node).mempool, vec![first, second]);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn reorg_recovery_is_one_selection_without_rechecking_reincluded_transactions() {
    fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
        let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
        let block =
            Chain::mine(chain.template(key(), transactions, time).unwrap(), 1_000_000).unwrap();
        chain.submit(block.clone(), time as u64).unwrap();
        block
    }
    let directory = tempfile::tempdir().unwrap();
    let config = configuration(16 * 1024);
    let mut old = Chain::open(&directory.path().join("old.sqlite"), config.clone()).unwrap();
    let mut base = Vec::new();
    for _ in 0..8 {
        base.push(append(&mut old, vec![]));
    }
    let mut new = Chain::open(&directory.path().join("new.sqlite"), config.clone()).unwrap();
    for block in &base {
        new.submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    let start = old.tip_state().account(&key(), None).unwrap().nonce;
    let detached_blocks = 5;
    let mut detached = Vec::new();
    let mut old_blocks = Vec::new();
    for block in 0..detached_blocks {
        let transactions: Vec<_> = (0..10)
            .map(|offset| {
                payment(
                    &config,
                    old.tip_state(),
                    &SECRET,
                    start + block * 10 + offset,
                    key(),
                    1,
                    0,
                )
            })
            .collect();
        detached.extend(transactions.iter().cloned());
        old_blocks.push(append(&mut old, transactions));
    }
    // The heavier branch includes every detached transaction at once.
    let mut new_blocks = vec![append(&mut new, detached.clone())];
    for _ in 0..detached_blocks {
        new_blocks.push(append(&mut new, vec![]));
    }
    let node = Node::open(&directory.path().join("node.sqlite"), config.clone(), key()).unwrap();
    for block in base.iter().chain(&old_blocks) {
        assert!(node.submit_block(block.clone()).unwrap());
    }
    let pending = payment(
        &config,
        old.tip_state(),
        &SECRET,
        start + detached.len() as u64,
        key(),
        1,
        0,
    );
    node.submit_transaction(pending.clone()).unwrap();
    signatures();
    selections();
    for block in &new_blocks {
        node.submit_block(block.clone()).unwrap();
    }
    assert_eq!(snapshot(&node).chain.tip_hash(), new.tip_hash());
    // Re-included detached entries fail the nonce check before selection, and
    // recovery runs one selection. Pending entries were authenticated when
    // pooled and detached ones when their blocks executed: none is rechecked.
    assert_eq!(selections(), 1);
    assert_eq!(signatures(), 0);
    assert_eq!(snapshot(&node).mempool, vec![pending.clone()]);
    assert_eq!(node.template().unwrap().transactions, vec![pending]);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_failed_recovery_still_reports_the_block_and_keeps_pending_entries() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let pending = payment(
        view.chain.config.as_ref(),
        view.chain.tip_state(),
        &SECRET,
        nonce(&node, &key()),
        key(),
        1,
        0,
    );
    node.submit_transaction(pending.clone()).unwrap();
    let candidate = {
        let i = node.locked().unwrap();
        i.chain
            .template(node.miner, Vec::new(), Node::timestamp(&i.chain))
    };
    let block = Chain::mine(candidate.unwrap(), 1_000_000).unwrap();
    FAIL_RECOVERY.with(|fail| fail.set(true));
    assert!(
        node.submit_block(block.clone()).unwrap(),
        "a committed block is accepted even when recovery fails"
    );
    let tip = codec::block_hash(&block);
    assert_eq!(snapshot(&node).chain.tip_hash(), tip);
    assert_eq!(snapshot(&node).mempool, vec![pending.clone()]);
    assert_ne!(pool(&node).2, tip);
    // The next selection revalidates the kept entries for the new tip.
    assert_eq!(node.template().unwrap().transactions, vec![pending]);
    assert_eq!(pool(&node).2, tip);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn capacity_displaced_entries_wait_in_the_backlog_for_the_next_block() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let mut low = Vec::new();
    loop {
        let tx = payment(config, state, &SECRET, start + low.len() as u64, key(), 1, 0);
        if node.submit_transaction(tx.clone()).is_err() {
            break;
        }
        low.push(tx);
    }
    assert!(low.len() > 20, "a block holds many payments");
    assert!(pool(&node).1.is_empty());
    let other_start = nonce(&node, &other());
    let high: Vec<_> = (0..4)
        .map(|offset| payment(config, state, &OTHER, other_start + offset, other(), 1, 1_000))
        .collect();
    for tx in &high {
        node.submit_transaction(tx.clone()).unwrap();
    }
    let (selected, backlog, _) = pool(&node);
    assert!(ids(&high).is_subset(&ids(&selected)));
    assert!(!backlog.is_empty(), "outbid entries wait instead of vanishing");
    // Every displaced entry is a suffix of the low-fee nonce chain.
    let kept = selected.len() - high.len();
    assert_eq!(ids(&backlog), ids(&low[kept..]));
    assert_eq!(ids(&snapshot(&node).mempool), &ids(&low) | &ids(&high));
    // Preparation continues the sender's nonce after the backlog.
    let operation = Operation::TransferExact {
        recipient: key(),
        amount: 1u32.into(),
    };
    let request = json!({"sender":hex::encode(key()),"operation":operation});
    let mut prepared = node.rpc("preparetransaction", request).unwrap();
    prepared.as_object_mut().unwrap().remove("fee_quote");
    let body = wallet::decode_unsigned(&serde_json::from_value(prepared).unwrap()).unwrap();
    assert_eq!(body.nonce, start + low.len() as u64);
    // That nonce cannot be selected before its waiting predecessors, so it
    // waits behind them instead of being refused.
    let queued = crypto::sign(&state.chain_id, &body, &SECRET).unwrap();
    node.submit_transaction(queued.clone()).unwrap();
    assert!(pool(&node).1.contains(&queued));
    node.mine(1_000_000).unwrap();
    let (selected, backlog, _) = pool(&node);
    assert_eq!(
        ids(&selected),
        &ids(&low[kept..]) | &ids(&[queued]),
        "the backlog fills the next block"
    );
    assert!(backlog.is_empty());
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn weight_displaced_account_creations_also_wait_in_the_backlog() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let fresh = |seed: u8| crypto::public_key(&[seed; 32]).unwrap();
    let start = nonce(&node, &key());
    // Each payment creates an account, so weight binds long before bytes.
    let mut low = Vec::new();
    loop {
        let recipient = fresh(100 + low.len() as u8);
        let tx = payment(config, state, &SECRET, start + low.len() as u64, recipient, 10, 0);
        if node.submit_transaction(tx.clone()).is_err() {
            break;
        }
        low.push(tx);
    }
    assert!((2..40).contains(&low.len()), "{}", low.len());
    let other_start = nonce(&node, &other());
    let high = payment(config, state, &OTHER, other_start, fresh(99), 10, 1_000);
    node.submit_transaction(high.clone()).unwrap();
    let (selected, backlog, _) = pool(&node);
    assert!(selected.contains(&high));
    assert!(!backlog.is_empty(), "a weight-displaced creation is kept");
    assert_eq!(&ids(&selected) | &ids(&backlog), &ids(&low) | &ids(&[high]));
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_count_full_pool_still_admits_a_better_bid() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 2 * 1024 * 1024);
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let limit = mempool_limit(config).min(config.max_signatures);
    let start = nonce(&node, &key());
    let full: Vec<_> = (0..limit as u64)
        .map(|offset| payment(config, state, &SECRET, start + offset, key(), 1, 0))
        .collect();
    let installed = {
        let mut i = node.locked().unwrap();
        Node::select_pool(&i.chain, node.miner, &full, &HashSet::new(), &HashSet::new())
            .and_then(|selected| node.install_pool(&mut i, selected))
    };
    installed.unwrap();
    assert_eq!(pool(&node).0.len(), limit);
    let bid = payment(config, state, &OTHER, nonce(&node, &other()), other(), 1, 1_000);
    node.submit_transaction(bid.clone()).unwrap();
    let (selected, backlog, _) = pool(&node);
    assert!(selected.contains(&bid));
    assert_eq!(selected.len(), limit);
    // The backlog is bounded on its own: a count-saturated selection keeps
    // the entry it displaced instead of dropping it.
    assert_eq!(backlog, vec![full[limit - 1].clone()]);
    assert_eq!(snapshot(&node).mempool.len(), limit + 1);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_new_tip_is_published_once_together_with_its_recovered_pool() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let pending = payment(
        view.chain.config.as_ref(),
        view.chain.tip_state(),
        &SECRET,
        nonce(&node, &key()),
        key(),
        1,
        0,
    );
    node.submit_transaction(pending.clone()).unwrap();
    let candidate = {
        let i = node.locked().unwrap();
        i.chain
            .template(node.miner, Vec::new(), Node::timestamp(&i.chain))
    };
    let block = Chain::mine(candidate.unwrap(), 1_000_000).unwrap();
    let revision = published(&node);
    assert!(node.submit_block(block.clone()).unwrap());
    // No reader ever sees the new tip without the still-pending entry.
    assert_eq!(published(&node), revision + 1);
    let view = snapshot(&node);
    assert_eq!(view.chain.tip_hash(), codec::block_hash(&block));
    assert_eq!(view.mempool, vec![pending]);
}

#[test]
fn a_launch_on_the_wrong_network_leaves_the_wallet_store_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.sqlite");
    let config = configuration(16 * 1024);
    drop(Node::open(&path, config.clone(), key()).unwrap());
    let mut other_network = config.clone();
    other_network.genesis_time += 1;
    assert_ne!(other_network.chain_id(), config.chain_id());
    let error = Node::open(&path, other_network, key()).err().unwrap();
    assert!(error.to_string().contains("different network"), "{error:#}");
    let recorded: String = rusqlite::Connection::open(path.with_extension("wallets.sqlite"))
        .unwrap()
        .query_row("SELECT chain_id FROM wallet_network", [], |row| row.get(0))
        .unwrap();
    assert_eq!(recorded, hex::encode(config.chain_id()));
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn an_entry_that_failed_every_attempt_is_dropped_rather_than_kept_undecided() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 1024 * 1024);
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let honest: Vec<_> = (0..8)
        .map(|offset| payment(config, state, &SECRET, start + offset, key(), 1, 0))
        .collect();
    for tx in &honest {
        node.submit_transaction(tx.clone()).unwrap();
    }
    // An affordable, high-fee zero transfer that can never apply, retained
    // in the pool as if it had become invalid after admission.
    let failing = payment(config, state, &OTHER, nonce(&node, &other()), other(), 0, 1_000);
    node.locked().unwrap().mempool.push(failing.clone());
    // Reselection retries it after every acceptance until its sender's own
    // budget is spent, which used to mark the whole selection saturated and
    // keep it in the backlog ahead of entries that lost only to capacity.
    let newcomer = payment(config, state, &SECRET, start + 8, key(), 1, 0);
    node.submit_transaction(newcomer.clone()).unwrap();
    let (selected, backlog, _) = pool(&node);
    assert_eq!(ids(&selected), &ids(&honest) | &ids(&[newcomer]));
    assert!(backlog.is_empty(), "a refused entry is not capacity-displaced");
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_block_finishing_failure_truncates_only_the_template() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 1024 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let pending: Vec<_> = (0..6)
        .map(|offset| payment(config, state, &SECRET, start + offset, key(), 1, 0))
        .collect();
    for tx in &pending[..5] {
        node.submit_transaction(tx.clone()).unwrap();
    }
    // Finishing now fails for more than two transactions. Admission never
    // finishes the block, so the relay accepts the newcomer and cuts nothing.
    crate::chain::FAIL_FINISH_ABOVE.with(|limit| limit.set(Some(2)));
    let relayed = node.receive_peer(
        &PeerMessage {
            chain: config.chain_id(),
            locator: Vec::new(),
            blocks: Vec::new(),
            transactions: vec![pending[5].clone()],
        },
        "127.0.0.1".parse().unwrap(),
    );
    let (selected, backlog, _) = pool(&node);
    let revision = published(&node);
    let template = node.template();
    crate::chain::FAIL_FINISH_ABOVE.with(|limit| limit.set(None));
    relayed.unwrap();
    assert_eq!(selected, pending);
    assert!(backlog.is_empty());
    // Only the template keeps the finishing prefix. The cut tail was never
    // judged invalid: it stays selected, and nothing is published.
    assert_eq!(template.unwrap().transactions, pending[..2]);
    assert_eq!(published(&node), revision);
    assert_eq!(pool(&node).0, pending);
    let block = node.mine(1_000_000).unwrap();
    assert_eq!(block.transactions, pending[..2]);
    assert_eq!(node.template().unwrap().transactions, pending[2..]);
}

#[test]
fn a_damaged_wallet_store_stops_startup_before_history_replay() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("chain.sqlite");
    std::fs::write(path.with_extension("wallets.sqlite"), b"not a wallet database").unwrap();
    assert!(Node::open(&path, configuration(16 * 1024), key()).is_err());
    assert!(!path.exists(), "the chain is not opened before the wallet check");
}

#[test]
fn rejected_transaction_memory_is_bounded_and_scoped() {
    let mut rejected = RejectedTransactions::default();
    for value in 0..=MAX_REJECTED_TRANSACTIONS as u32 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&value.to_le_bytes());
        rejected.insert(
            id,
            match value % 3 {
                0 => Refusal::Permanent,
                1 => Refusal::Tip([1; 32]),
                _ => Refusal::Pool([1; 32], 5),
            },
        );
    }
    assert_eq!(rejected.entries.len(), MAX_REJECTED_TRANSACTIONS);
    assert!(!rejected.contains(&[0; 32], &[1; 32], 5), "the oldest identity is forgotten");
    let mut id = [0; 32];
    id[0] = 3;
    assert!(rejected.contains(&id, &[9; 32], 0), "permanent refusals hold on any tip");
    id[0] = 4;
    assert!(rejected.contains(&id, &[1; 32], 0));
    assert!(!rejected.contains(&id, &[9; 32], 5), "state refusals end with their tip");
    id[0] = 5;
    assert!(rejected.contains(&id, &[1; 32], 5));
    assert!(!rejected.contains(&id, &[1; 32], 6), "lost selections end with their pool");
    assert!(!rejected.contains(&id, &[9; 32], 5));
}

// ---------------------------------------------------------------------------
// Batch clearing and the node lock (audit F006).

/// A transaction paying the exact minimum fee plus `extra`.
fn exact(
    config: &Config,
    state: &State,
    secret: &[u8; 32],
    mut body: TransactionBody,
    extra: u64,
) -> Transaction {
    loop {
        let tx = crypto::sign(&state.chain_id, &body, secret).unwrap();
        let fee = fees::quote(config, state, &tx).unwrap().minimum_fee + extra;
        if tx.body.fee == fee {
            return tx;
        }
        body.fee = fee;
    }
}
fn unsigned(
    config: &Config,
    secret: &[u8; 32],
    nonce: u64,
    operation: Operation,
) -> TransactionBody {
    TransactionBody {
        data: Vec::new(),
        sender: crypto::public_key(secret).unwrap(),
        nonce,
        fee: Amount::zero(),
        anchor: codec::block_hash(&codec::genesis_block(config).unwrap()),
        expiry_blocks: 1_000_000,
        operation,
    }
}
fn extend(chain: &mut Chain, transactions: Vec<Transaction>) {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(chain.template(key(), transactions, time).unwrap(), 1_000_000).unwrap();
    assert!(chain.submit(block, time as u64).unwrap());
}
/// A node in its second governance decision. The first, a reserve grant
/// (as in tests/support/curved.rs), left a sloped curve, so both outcome
/// worlds start sloped and clearing a trade in either costs curve
/// evaluations. `other()` is funded as well.
fn decision_node(directory: &Path, block_bytes: u64) -> Node {
    let config = configuration(block_bytes);
    let path = directory.join("node.sqlite");
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    let signed = |chain: &Chain, operation: Operation| {
        let state = chain.tip_state();
        let nonce = state.account(&key(), None).unwrap().nonce;
        exact(&config, state, &SECRET, unsigned(&config, &SECRET, nonce, operation), 0)
    };
    let until = |chain: &mut Chain, reached: &dyn Fn(&State) -> bool| {
        for _ in 0..500 {
            if reached(chain.tip_state()) {
                return;
            }
            extend(chain, Vec::new());
        }
        panic!("fixture phase not reached");
    };
    for _ in 0..8 {
        extend(&mut chain, Vec::new());
    }
    let funding = signed(
        &chain,
        Operation::TransferExact {
            recipient: other(),
            amount: 5_000u32.into(),
        },
    );
    extend(&mut chain, vec![funding]);
    let amount = chain.tip_state().account(&key(), None).unwrap().ordinary / 2u32;
    let deposit = signed(
        &chain,
        Operation::Deposit {
            amount,
            decision: None,
            outcome: None,
        },
    );
    extend(&mut chain, vec![deposit]);
    until(&mut chain, &|s| matches!(s.phase, crate::state::Phase::Auction(_)));
    let state = chain.tip_state();
    let grant = &state.world.reserve / 20u32;
    assert!(grant > &state.world.revenue + 10u32, "the grant draws reserve");
    let proposal = signed(
        &chain,
        Operation::Propose {
            round: state.auction_round().unwrap(),
            description: [251; 32],
            proposal: Proposal::Grant {
                payments: vec![GrantPayment {
                    recipient: crypto::public_key(&[251; 32]).unwrap(),
                    amount: grant,
                }],
            },
            support: 1u32.into(),
        },
    );
    extend(&mut chain, vec![proposal]);
    until(&mut chain, &|s| s.decision_id().is_some());
    // A substantive PASS-world deposit decides the grant.
    let state = chain.tip_state();
    let amount = state.account(&key(), Some(Outcome::Pass)).unwrap().ordinary / 2u32;
    let deposit = signed(
        &chain,
        Operation::Deposit {
            amount,
            decision: state.decision_id(),
            outcome: Some(Outcome::Pass),
        },
    );
    extend(&mut chain, vec![deposit]);
    until(&mut chain, &|s| matches!(s.phase, crate::state::Phase::Auction(_)));
    let state = chain.tip_state();
    assert!(state.world.curve_mass > state.world.reserve, "the grant left a sloped curve");
    let proposal = signed(
        &chain,
        Operation::Propose {
            round: state.auction_round().unwrap(),
            description: [70; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::Lead,
                old: state.settings.lead,
                new: state.settings.lead * 2,
            },
            support: 1u32.into(),
        },
    );
    extend(&mut chain, vec![proposal]);
    until(&mut chain, &|s| s.decision_id().is_some());
    let state = chain.tip_state();
    let pass = state.alternative.as_ref().unwrap();
    assert!(state.world.curve_mass > state.world.reserve && pass.curve_mass > pass.reserve);
    drop(chain);
    Node::open(&path, config, key()).unwrap()
}
/// A deposit into one outcome world of the current decision.
fn decision_trade(
    config: &Config,
    state: &State,
    secret: &[u8; 32],
    nonce: u64,
    outcome: Outcome,
    amount: u32,
) -> Transaction {
    let operation = Operation::Deposit {
        amount: amount.into(),
        decision: state.decision_id(),
        outcome: Some(outcome),
    };
    exact(config, state, secret, unsigned(config, secret, nonce, operation), 0)
}
fn relay(node: &Node, transactions: Vec<Transaction>) {
    node.receive_peer(
        &PeerMessage {
            chain: snapshot(node).chain.chain_id(),
            locator: Vec::new(),
            blocks: Vec::new(),
            transactions,
        },
        "127.0.0.1".parse().unwrap(),
    )
    .unwrap();
}
/// What one call cost on this thread: curve evaluations in all, those run
/// while holding the node lock, and how long it held that lock.
#[derive(Clone, Copy, Debug, Default)]
struct Cost {
    evaluations: u64,
    under_lock: u64,
    held: Duration,
}
fn metered<T>(call: impl FnOnce() -> T) -> (T, Cost) {
    let evaluations = crate::batch::thread_curve_evaluations();
    let under_lock = CLEARING_UNDER_INNER.with(std::cell::Cell::get);
    let held = INNER_HELD.with(std::cell::Cell::get);
    let result = call();
    let cost = Cost {
        evaluations: crate::batch::thread_curve_evaluations() - evaluations,
        under_lock: CLEARING_UNDER_INNER.with(std::cell::Cell::get) - under_lock,
        held: INNER_HELD.with(std::cell::Cell::get) - held,
    };
    (result, cost)
}
/// An empty child of the tip, mined.
fn empty_block(node: &Node) -> Block {
    let candidate = {
        let i = node.locked().unwrap();
        i.chain
            .template(node.miner, Vec::new(), Node::timestamp(&i.chain))
    };
    Chain::mine(candidate.unwrap(), 1_000_000).unwrap()
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn admission_spends_no_curve_work_under_the_node_lock() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024)
        .with_wallet(SECRET)
        .unwrap();
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let trade = |nonce: u64, outcome: Outcome, amount: u32| {
        decision_trade(config, state, &SECRET, nonce, outcome, amount)
    };
    let wallet_trade = |outcome: Outcome, amount: u32| {
        let revision = node.wallets_locked().unwrap().status()["wallet_revision"]
            .as_u64()
            .unwrap();
        let operation = Operation::Deposit {
            amount: amount.into(),
            decision: state.decision_id(),
            outcome: Some(outcome),
        };
        // Outlive the trade-free blocks below; the default lifetime is short.
        let request = json!({
            "operation":operation,
            "expected_sender":hex::encode(key()),
            "wallet_revision":revision,
            "expiry_blocks":1000
        });
        node.wallet_submit(serde_json::from_value(request).unwrap())
            .unwrap()
    };
    let pooled = |id: &Hash| ids(&snapshot(&node).mempool).contains(id);
    let mut steps: Vec<(&str, usize, Cost, usize)> = Vec::new();
    let mut step = |name: &'static str, call: &dyn Fn() -> Option<Hash>| {
        selections();
        let (accepted, cost) = metered(call);
        steps.push((name, selections(), cost, snapshot(&node).mempool.len()));
        if let Some(id) = accepted {
            assert!(pooled(&id), "{name}: the newcomer is pending");
        }
    };
    let fail = trade(start, Outcome::Fail, 101);
    let pass = trade(start + 1, Outcome::Pass, 102);
    let future = trade(start + 2, Outcome::Fail, 103);
    let unrelated = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
    let submitted = trade(start + 3, Outcome::Pass, 104);
    for (name, tx) in [
        ("relay: new FAIL-world trade", fail),
        ("relay: new PASS-world trade", pass),
        ("relay: future-nonce trade", future),
        ("relay: unrelated payment", unrelated),
    ] {
        step(name, &|| {
            relay(&node, vec![tx.clone()]);
            Some(codec::transaction_id(&tx))
        });
    }
    step("RPC submission: trade", &|| {
        Some(node.submit_transaction(submitted.clone()).unwrap())
    });
    step("hot wallet submission: trade", &|| {
        Some(wallet_trade(Outcome::Fail, 105))
    });
    let block = empty_block(&node);
    step("trade-free block, pool recovery", &|| {
        assert!(node.submit_block(block.clone()).unwrap());
        None
    });
    let block = empty_block(&node);
    step("trade-free block, failed recovery", &|| {
        FAIL_RECOVERY.with(|fail| fail.set(true));
        assert!(node.submit_block(block.clone()).unwrap());
        None
    });
    step("hot wallet submission after failed recovery", &|| {
        Some(wallet_trade(Outcome::Pass, 106))
    });
    let pending = snapshot(&node).mempool.clone();
    let ((), template) = metered(|| {
        assert_eq!(node.template().unwrap().transactions, pending);
    });
    for (name, selected, cost, pending) in &steps {
        eprintln!(
            "{name:<44} pending {pending} selections {selected} curve evaluations {:>4} (under the node lock {:>4}) lock held {:?}",
            cost.evaluations, cost.under_lock, cost.held
        );
    }
    eprintln!(
        "{:<44} pending {} selections 0 curve evaluations {:>4} (under the node lock {:>4}) lock held {:?}",
        "template",
        pending.len(),
        template.evaluations,
        template.under_lock,
        template.held
    );
    assert_eq!(pending.len(), 7);
    let expected = [1, 1, 1, 1, 1, 1, 1, 0, 2];
    for ((name, selected, cost, _), expected) in steps.iter().zip(expected) {
        assert_eq!(*selected, expected, "{name}: one selection per change");
        assert_eq!(cost.under_lock, 0, "{name}: curve work under the node lock");
        assert_eq!(cost.evaluations, 0, "{name}: admission needs no clearing");
    }
    assert!(template.evaluations > 0, "the fixture's trades cost curve work");
    assert_eq!(template.under_lock, 0, "templates clear off the node lock");
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn equal_rate_replacement_churn_is_refused_without_a_selection() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    // Same nonce, fee and weight: only the data byte differs. Equal bids go
    // to the smaller txid, so in descending txid order each one used to
    // replace the last without any fee bump, each costing a selection, a
    // publication and a template rebuild that clears a different trade set.
    let variant = |salt: u8, extra: u64| {
        let operation = Operation::Deposit {
            amount: 201u32.into(),
            decision: state.decision_id(),
            outcome: Some(Outcome::Fail),
        };
        let mut body = unsigned(config, &SECRET, start, operation);
        body.data = vec![salt];
        exact(config, state, &SECRET, body, extra)
    };
    // A voluntary extra fee leaves room for raises below an eighth.
    let base = 1000;
    let mut variants: Vec<_> = (0..32u8).map(|salt| variant(salt, base)).collect();
    assert!(variants.iter().all(|tx| tx.body.fee == variants[0].body.fee));
    variants.sort_by_key(|tx| std::cmp::Reverse(codec::transaction_id(tx)));
    let revision = published(&node);
    selections();
    let mut churn = Cost::default();
    for tx in &variants {
        let ((), cost) = metered(|| relay(&node, vec![tx.clone()]));
        churn.evaluations += cost.evaluations;
        churn.under_lock += cost.under_lock;
        churn.held += cost.held;
    }
    let selected = selections();
    eprintln!(
        "32 equal-rate replacements: {selected} selections, {} publishes, lock held {:?} in all",
        published(&node) - revision,
        churn.held
    );
    // Only the first entered the pool; every equal-rate replacement was
    // refused before any selection, and is not reconsidered when resent.
    assert_eq!(selected, 1);
    assert_eq!(published(&node), revision + 1);
    assert_eq!(snapshot(&node).mempool, vec![variants[0].clone()]);
    assert_eq!((churn.under_lock, churn.evaluations), (0, 0));
    relay(&node, variants[1..].to_vec());
    assert!(node.submit_transaction(variants[1].clone()).is_err());
    assert_eq!(selections(), 0);
    let (block, template) = metered(|| node.template().unwrap());
    assert_eq!(block.transactions, vec![variants[0].clone()]);
    assert!(template.evaluations > 0);
    assert_eq!(template.under_lock, 0);
    // A replacement raising the fee rate by less than an eighth is refused
    // too; one raising it by an eighth and the minimum fee rate replaces.
    let fee = variants[0].body.fee.to_u64().unwrap();
    let small = variant(40, base + fee / 16);
    assert!(!replaces(config, state, &small, &variants[0]));
    assert!(node.submit_transaction(small).is_err());
    assert_eq!(selections(), 0);
    let raised = variant(41, base + fee / 8 + 2);
    assert!(replaces(config, state, &raised, &variants[0]));
    node.submit_transaction(raised.clone()).unwrap();
    assert_eq!(selections(), 1);
    assert_eq!(snapshot(&node).mempool, vec![raised.clone()]);
    let (block, _) = metered(|| node.template().unwrap());
    assert_eq!(block.transactions, vec![raised]);
}
#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn template_clearing_runs_off_the_node_lock() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let first = decision_trade(config, state, &SECRET, start, Outcome::Fail, 301);
    let newcomer = decision_trade(config, state, &SECRET, start + 1, Outcome::Pass, 302);
    node.submit_transaction(first.clone()).unwrap();
    let (paused, pause) = mpsc::channel();
    let (resume, resumed) = mpsc::channel::<()>();
    let builder = node.clone();
    let building = std::thread::spawn(move || {
        crate::chain::TEMPLATE_BUILD_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                paused.send(()).unwrap();
                resumed.recv().unwrap();
            }));
        });
        metered(|| builder.template())
    });
    pause
        .recv_timeout(Duration::from_secs(10))
        .expect("the template build started");
    // While the build is paused before clearing, the node lock is free and
    // a relayed trade is admitted. The submission above may have woken the
    // explorer worker, which holds the lock for a moment, so keep trying for
    // a while: a build holding the lock would hold it until it resumes.
    let deadline = Instant::now() + Duration::from_secs(5);
    let free = loop {
        if node.inner.try_lock().is_ok() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    relay(&node, vec![newcomer.clone()]);
    resume.send(()).unwrap();
    let (stale, cost) = building.join().unwrap();
    let stale = stale.unwrap();
    assert!(free, "a template build held the node lock");
    assert_eq!(pool(&node).0, vec![first.clone(), newcomer.clone()]);
    assert_eq!(stale.transactions, vec![first.clone()]);
    assert!(cost.evaluations > 0);
    assert_eq!(cost.under_lock, 0);
    let (stored, revision) = {
        let i = node.locked().unwrap();
        (i.template.as_ref().map(|entry| entry.selection), i.selection_revision)
    };
    assert!(stored.is_some_and(|selection| selection != revision), "kept, but outdated");
    let fresh = node.template().unwrap();
    assert_eq!(fresh.transactions, vec![first, newcomer]);
    // Both are the blocks consensus execution builds, and both mine.
    for block in [&stale, &fresh] {
        let expected = {
            let i = node.locked().unwrap();
            i.chain.template(
                node.miner,
                block.transactions.clone(),
                block.header.timestamp,
            )
        };
        assert_eq!(codec::encode(&expected.unwrap()), codec::encode(block));
        Chain::mine(block.clone(), 1_000_000).unwrap();
    }
    assert!(node.submit_block(Chain::mine(fresh, 1_000_000).unwrap()).unwrap());
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn node_templates_match_consensus_execution_byte_for_byte() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let mut amount = 400;
    for round in 0..2 {
        let view = snapshot(&node);
        let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
        let start = nonce(&node, &key());
        for offset in 0..4 {
            let outcome = if offset % 2 == 0 {
                Outcome::Fail
            } else {
                Outcome::Pass
            };
            amount += 1;
            let trade = decision_trade(config, state, &SECRET, start + offset, outcome, amount);
            node.submit_transaction(trade).unwrap();
        }
        let paid = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
        node.submit_transaction(paid).unwrap();
        let block = node.template().unwrap();
        assert_eq!(block.transactions, pool(&node).0);
        assert_eq!(block.transactions.len(), 5);
        let expected = {
            let i = node.locked().unwrap();
            i.chain.template(
                node.miner,
                block.transactions.clone(),
                block.header.timestamp,
            )
        };
        assert_eq!(codec::encode(&expected.unwrap()), codec::encode(&block));
        let mined = if round == 0 {
            let mined = Chain::mine(block, 1_000_000).unwrap();
            assert!(node.submit_block(mined.clone()).unwrap());
            mined
        } else {
            // Another payout key builds its own template the same way.
            node.mine_to(1_000_000, other()).unwrap()
        };
        assert_eq!(snapshot(&node).chain.tip_hash(), codec::block_hash(&mined));
        assert_eq!(mined.transactions.len(), 5);
        assert!(pool(&node).0.is_empty());
    }
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn same_parent_rebuilds_wait_for_the_previous_build_time() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let first = decision_trade(config, state, &SECRET, start, Outcome::Fail, 501);
    let second = decision_trade(config, state, &SECRET, start + 1, Outcome::Pass, 502);
    node.submit_transaction(first.clone()).unwrap();
    let (built, retry) = node.template_shared(Freshness::Throttled).unwrap();
    assert_eq!((built.transactions.clone(), retry), (vec![first.clone()], None));
    // As if that build had taken a minute.
    let finished = {
        let mut i = node.locked().unwrap();
        let entry = i.template.as_mut().unwrap();
        entry.cost = Duration::from_secs(60);
        entry.finished
    };
    node.submit_transaction(second.clone()).unwrap();
    let ((block, retry), cost) = metered(|| node.template_shared(Freshness::Throttled).unwrap());
    assert!(Arc::ptr_eq(&block, &built), "the same-parent template is served");
    assert_eq!(retry, Some(finished + Duration::from_secs(60)));
    assert_eq!(cost.evaluations, 0, "nothing is built inside the window");
    // Local mining and RPC are never throttled.
    let ((block, retry), cost) = metered(|| node.template_shared(Freshness::Current).unwrap());
    assert_eq!((block.transactions.clone(), retry), (vec![first, second], None));
    assert!(cost.evaluations > 0);
    assert_eq!(cost.under_lock, 0);
    let ((again, retry), cost) = metered(|| node.template_shared(Freshness::Throttled).unwrap());
    assert!(Arc::ptr_eq(&again, &block) && retry.is_none() && cost.evaluations == 0);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_new_tip_template_is_never_throttled() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    let first = decision_trade(config, state, &SECRET, start, Outcome::Fail, 601);
    node.submit_transaction(first).unwrap();
    node.template_shared(Freshness::Throttled).unwrap();
    node.locked().unwrap().template.as_mut().unwrap().cost = Duration::from_secs(60);
    let mined = node.mine(1_000_000).unwrap();
    let second = decision_trade(config, state, &SECRET, start + 1, Outcome::Pass, 602);
    node.submit_transaction(second.clone()).unwrap();
    let ((block, retry), cost) = metered(|| node.template_shared(Freshness::Throttled).unwrap());
    assert_eq!(block.header.previous, codec::block_hash(&mined));
    assert_eq!((block.transactions.clone(), retry), (vec![second], None));
    assert!(cost.evaluations > 0);
    assert_eq!(cost.under_lock, 0);
}

#[test]
fn deferred_stratum_refreshes_wait_for_the_interval_and_the_template_throttle() {
    let last = tokio::time::Instant::now();
    let interval = last + STRATUM_REFRESH_INTERVAL;
    assert_eq!(stratum_refresh_at(last, None), interval);
    assert_eq!(stratum_refresh_at(last, Some(last + Duration::from_millis(1))), interval);
    let later = last + STRATUM_REFRESH_INTERVAL + Duration::from_secs(3);
    assert_eq!(stratum_refresh_at(last, Some(later)), later);
}

#[test]
fn same_parent_changes_wait_while_a_stratum_refresh_is_scheduled() {
    let (tip, next) = ([1; 32], [2; 32]);
    let job = Some((tip, [3; 32]));
    let late = STRATUM_REFRESH_INTERVAL + Duration::from_secs(1);
    // Within the interval, a same-parent change always waits.
    assert!(stratum_defers(job, tip, false, Duration::ZERO));
    assert!(!stratum_defers(job, tip, false, late));
    // After it, a change still waits while a refresh is scheduled, as when
    // the last template lagged: that refresh fetches the latest template
    // once the node may rebuild it, so each change need not ask again.
    assert!(stratum_defers(job, tip, true, late));
    // A new tip, or a connection without work, is served at once.
    assert!(!stratum_defers(job, next, true, Duration::ZERO));
    assert!(!stratum_defers(None, tip, true, Duration::ZERO));
}

#[test]
fn a_template_request_builds_at_most_three_times_while_the_tip_moves() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 64 * 1024);
    // A new tip arrives during each of the first seven builds.
    let builds = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let (counter, mover) = (builds.clone(), node.clone());
    crate::chain::TEMPLATE_BUILD_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            counter.set(counter.get() + 1);
            if counter.get() <= 7 {
                assert!(mover.submit_block(empty_block(&mover)).unwrap());
            }
        }));
    });
    let tip = || snapshot(&node).chain.tip_hash();
    let height = || snapshot(&node).chain.tip_height();
    let stored = || node.locked().unwrap().template.is_some();
    // Each build was overtaken by a new tip. The third is returned for its
    // own parent, a sibling of the tip, as if the tip had moved just after it
    // was served, rather than rebuilding for as long as the tip moves.
    let block = node.template().unwrap();
    assert_eq!(builds.get(), 3);
    assert_ne!(block.header.previous, tip());
    assert_eq!(block.height, height());
    // Stratum is told to ask again at once. Nothing is stored.
    let (block, retry) = node.template_shared(Freshness::Throttled).unwrap();
    assert_eq!(builds.get(), 6);
    assert_ne!(block.header.previous, tip());
    assert!(retry.is_some_and(|retry| retry <= Instant::now()));
    assert!(!stored());
    // A build overtaken once is rebuilt for the new tip and stored.
    let (block, retry) = node.template_shared(Freshness::Throttled).unwrap();
    assert_eq!(builds.get(), 8);
    assert_eq!((block.header.previous, retry), (tip(), None));
    assert!(stored());
    let (again, _) = node.template_shared(Freshness::Throttled).unwrap();
    assert!(Arc::ptr_eq(&again, &block));
    assert_eq!(builds.get(), 8);
    crate::chain::TEMPLATE_BUILD_HOOK.with(|hook| hook.borrow_mut().take());
}

#[test]
#[ignore = "benchmark: cargo test --release --features test-fixtures --lib admission_lock_hold -- --ignored --nocapture"]
fn admission_lock_hold_at_full_pool() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 2 * 1024 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let limit = mempool_limit(config).min(config.max_signatures);
    let start = nonce(&node, &key());
    let full: Vec<_> = (0..limit as u64)
        .map(|offset| {
            let outcome = if offset % 2 == 0 {
                Outcome::Fail
            } else {
                Outcome::Pass
            };
            let amount = 3 + (offset % 16) as u32;
            decision_trade(config, state, &SECRET, start + offset, outcome, amount)
        })
        .collect();
    let (installed, fill) = metered(|| {
        let mut i = node.locked().unwrap();
        Node::select_pool(&i.chain, node.miner, &full, &HashSet::new(), &HashSet::new())
            .and_then(|selected| node.install_pool(&mut i, selected))
    });
    installed.unwrap();
    assert_eq!(pool(&node).0.len(), limit);
    // Newcomer trades that outbid the weakest entry, so each changes the
    // included trade set; alternately submitted over RPC and relayed.
    let other_start = nonce(&node, &other());
    let rounds = 16u64;
    let mut submitted = Vec::new();
    let mut relayed = Vec::new();
    for offset in 0..2 * rounds {
        let outcome = if offset % 2 == 0 {
            Outcome::Fail
        } else {
            Outcome::Pass
        };
        let operation = Operation::Deposit {
            amount: (40 + offset as u32).into(),
            decision: state.decision_id(),
            outcome: Some(outcome),
        };
        let body = unsigned(config, &OTHER, other_start + offset, operation);
        let tx = exact(config, state, &OTHER, body, 10);
        let id = codec::transaction_id(&tx);
        let cost = if offset % 2 == 0 {
            let (accepted, cost) = metered(|| node.submit_transaction(tx.clone()));
            accepted.unwrap();
            submitted.push(cost);
            cost
        } else {
            let ((), cost) = metered(|| relay(&node, vec![tx.clone()]));
            relayed.push(cost);
            cost
        };
        assert!(ids(&pool(&node).0).contains(&id), "{cost:?}");
    }
    let (block, template) = metered(|| node.template().unwrap());
    let summary = |costs: &[Cost]| {
        let held: Vec<f64> = costs
            .iter()
            .map(|c| c.held.as_secs_f64() * 1000.0)
            .collect();
        format!(
            "lock held mean {:.2} ms, max {:.2} ms; curve evaluations under the lock {} in all",
            held.iter().sum::<f64>() / held.len() as f64,
            held.iter().copied().fold(0.0, f64::max),
            costs.iter().map(|c| c.under_lock).sum::<u64>()
        )
    };
    eprintln!(
        "\npool of {limit} curved trades over both worlds; filling it: {} evaluations, lock held {:?}",
        fill.evaluations, fill.held
    );
    eprintln!("RPC submission x{rounds}: {}", summary(&submitted));
    eprintln!("peer relay     x{rounds}: {}", summary(&relayed));
    eprintln!(
        "template of {} transactions: {} curve evaluations ({} under the lock), lock held {:?}",
        block.transactions.len(),
        template.evaluations,
        template.under_lock,
        template.held
    );
    assert!(
        submitted
            .iter()
            .chain(&relayed)
            .all(|cost| cost.evaluations == 0)
    );
    assert_eq!(template.under_lock, 0);
}

// ---------------------------------------------------------------------------
// Scheduling the node lock: the node-wide admission budget, block validation
// outside the lock, template builds and spends awaiting their funding.

fn relay_from(node: &Node, source: &str, transactions: Vec<Transaction>, blocks: Vec<Block>) {
    node.receive_peer(
        &PeerMessage {
            chain: snapshot(node).chain.chain_id(),
            locator: Vec::new(),
            blocks,
            transactions,
        },
        source.parse().unwrap(),
    )
    .unwrap();
}
fn queued(node: &Node) -> usize {
    node.admission.unpoisoned().queue.entries.len()
}
fn awaiting(node: &Node) -> Vec<Hash> {
    node.locked()
        .unwrap()
        .awaiting
        .iter()
        .map(|entry| entry.id)
        .collect()
}
fn stored(node: &Node, block: &Block) -> bool {
    let hash = codec::block_hash(block);
    let i = node.locked().unwrap();
    i.chain.block_height(&hash).unwrap().is_some()
}
/// A mined child of the tip, distinguished by `salt`.
fn child(node: &Node, salt: u64) -> Block {
    let mut candidate = {
        let i = node.locked().unwrap();
        i.chain
            .template(node.miner, Vec::new(), Node::timestamp(&i.chain))
            .unwrap()
    };
    candidate.extranonce = salt.to_le_bytes();
    candidate.header.merkle_root = codec::merkle_root(&candidate).unwrap();
    Chain::mine(candidate, 1_000_000).unwrap()
}
/// Submit `block` on another thread whose execution of it pauses until the
/// returned sender is used or dropped.
fn parked_submission(
    node: &Node,
    block: Block,
) -> (std::thread::JoinHandle<Result<bool>>, mpsc::Sender<()>) {
    let (paused, pause) = mpsc::channel();
    let (resume, resumed) = mpsc::channel::<()>();
    let submitter = node.clone();
    let thread = std::thread::spawn(move || {
        crate::chain::BLOCK_EXECUTION_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let _ = paused.send(());
                let _ = resumed.recv();
            }));
        });
        submitter.submit_block(block)
    });
    pause
        .recv_timeout(Duration::from_secs(10))
        .expect("block execution started");
    (thread, resume)
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn admission_from_many_sources_stays_within_the_node_wide_selection_budget() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 64 * 1024);
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let (start, other_start) = (nonce(&node, &key()), nonce(&node, &other()));
    // Charge every admission 900 ms of the one-second burst, whatever it took,
    // so the budget is seconds in debt after two.
    SELECTION_CHARGE.with(|charge| charge.set(Some(Duration::from_millis(900))));
    selections();
    // Eight sources each relay four newcomers, one per message, at once.
    let mut sent = Vec::new();
    for round in 0..4u64 {
        for source in 0..8u64 {
            let (secret, nonce) = if source % 2 == 0 {
                (&SECRET, start + round * 4 + source / 2)
            } else {
                (&OTHER, other_start + round * 4 + source / 2)
            };
            let tx = payment(config, state, secret, nonce, key(), 1, 0);
            relay_from(&node, &format!("127.0.0.{}", source + 1), vec![tx.clone()], Vec::new());
            sent.push(tx);
        }
    }
    // Two admissions spent the burst; the other 30 newcomers wait, costing
    // nothing, however many sources sent them.
    assert_eq!(selections(), 2);
    assert_eq!(queued(&node), 30);
    assert_eq!(pool(&node).0.len(), 2);
    // Once the budget has refilled, the next message admits all of them
    // with one selection.
    node.admission.unpoisoned().budget =
        TimeBudget::new(SELECTION_TIME_PER_SECOND, SELECTION_TIME_BURST);
    relay_from(&node, "127.0.0.9", Vec::new(), Vec::new());
    assert_eq!(selections(), 1);
    assert_eq!(queued(&node), 0);
    assert_eq!(ids(&pool(&node).0), ids(&sent));
    SELECTION_CHARGE.with(|charge| charge.set(None));
    // A spent budget refuses public broadcasts until it has refilled.
    node.admission.unpoisoned().budget.spend(SELECTION_TIME_BURST * 2, Instant::now());
    let wait = node.selection_wait().expect("the budget is spent");
    assert!(wait > Duration::from_secs(3) && wait <= Duration::from_secs(8), "{wait:?}");
}

#[test]
fn the_admission_queue_keeps_each_source_a_fair_share() {
    let transaction = Transaction {
        body: unsigned(&configuration(16 * 1024), &SECRET, 0, Operation::Refund {
            round: 0,
            proposal: [0; 32],
        }),
        signature: [0; 64],
    };
    let newcomer = |n: u32, source: &str| {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&n.to_le_bytes());
        Newcomer {
            id,
            transaction: transaction.clone(),
            source: Some(source.parse().unwrap()),
            authenticated: true,
        }
    };
    let mut queue = AdmissionQueue::default();
    for n in 0..MAX_QUEUED_ADMISSIONS as u32 {
        queue.push(newcomer(n, "127.0.0.1"));
    }
    assert_eq!(queue.entries.len(), MAX_QUEUED_ADMISSIONS);
    // The flooding source cannot add more; another source displaces its
    // oldest entry, and a repeated identity is ignored.
    queue.push(newcomer(5_000, "127.0.0.1"));
    assert!(!queue.ids.contains(&newcomer(5_000, "127.0.0.1").id));
    queue.push(newcomer(6_000, "127.0.0.2"));
    assert!(queue.ids.contains(&newcomer(6_000, "127.0.0.2").id));
    assert!(!queue.ids.contains(&newcomer(0, "127.0.0.1").id));
    queue.push(newcomer(6_000, "127.0.0.3"));
    assert_eq!(queue.entries.len(), MAX_QUEUED_ADMISSIONS);
    assert_eq!(queue.held[&Some("127.0.0.2".parse().unwrap())], 1);
    assert_eq!(queue.take().len(), MAX_QUEUED_ADMISSIONS);
    assert!(queue.is_empty() && queue.held.is_empty());
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_low_bid_at_a_count_full_pool_is_refused_without_a_selection() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration(64 * 1024);
    config.max_signatures = 4;
    let node = Node::open(&directory.path().join("node.sqlite"), config, key()).unwrap();
    for _ in 0..8 {
        node.mine(1_000_000).unwrap();
    }
    fund_other(&node);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let start = nonce(&node, &key());
    for offset in 0..4 {
        node.submit_transaction(payment(config, state, &SECRET, start + offset, key(), 1, 10))
            .unwrap();
    }
    assert_eq!(pool(&node).0.len(), 4, "the selection is count-full");
    selections();
    // A newcomer that does not outbid the weakest entry cannot enter, so it
    // is refused before any selection, relayed or submitted.
    let low = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
    let refused = node.submit_transaction(low.clone()).unwrap_err().to_string();
    assert!(refused.contains("does not outbid its weakest entry"), "{refused}");
    relay(&node, vec![low]);
    assert_eq!(selections(), 0);
    // One that does outbid it costs one selection and displaces it.
    let high = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 100);
    node.submit_transaction(high.clone()).unwrap();
    assert_eq!(selections(), 1);
    let (selection, backlog, _) = pool(&node);
    assert!(ids(&selection).contains(&codec::transaction_id(&high)));
    assert_eq!(selection.len(), 4);
    assert_eq!(backlog.len(), 1, "the displaced entry waits for capacity");
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_waiting_block_submission_goes_ahead_of_queued_admissions() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let newcomer = payment(config, state, &SECRET, nonce(&node, &key()), key(), 1, 0);
    // As if a block submission were waiting for the node lock.
    node.blocks_waiting.fetch_add(1, Ordering::AcqRel);
    selections();
    relay(&node, vec![newcomer.clone()]);
    assert_eq!(selections(), 0, "admission yields to the block");
    assert_eq!(queued(&node), 1);
    assert!(pool(&node).0.is_empty());
    node.blocks_waiting.fetch_sub(1, Ordering::AcqRel);
    // The block is stored first; the newcomer then enters the new tip's
    // pool, once its recovery selection has run.
    let block = empty_block(&node);
    assert!(node.submit_block(block.clone()).unwrap());
    assert_eq!(selections(), 2);
    let (selection, _, tip) = pool(&node);
    assert_eq!((selection, tip), (vec![newcomer], codec::block_hash(&block)));
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn block_execution_runs_off_the_node_lock() {
    let directory = tempfile::tempdir().unwrap();
    let node = decision_node(directory.path(), 64 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let trade = decision_trade(config, state, &SECRET, nonce(&node, &key()), Outcome::Fail, 301);
    node.submit_transaction(trade.clone()).unwrap();
    let block = Chain::mine(node.template().unwrap(), 1_000_000).unwrap();
    let (submission, resume) = parked_submission(&node, block.clone());
    // While the block executes, the node lock is free: admission, template
    // capture and status reads complete. (The explorer worker may hold it
    // briefly.)
    let free = (0..100).any(|_| {
        let free = node.inner.try_lock().is_ok();
        if !free {
            std::thread::sleep(Duration::from_millis(10));
        }
        free
    });
    let paid = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
    let admitted = node.submit_transaction(paid.clone());
    let template = node.template();
    let status = node.status();
    drop(resume);
    assert!(submission.join().unwrap().unwrap(), "the block became the tip");
    assert!(free, "block execution held the node lock");
    admitted.unwrap();
    let template = template.unwrap();
    assert_eq!(template.header.previous, view.chain.tip_hash());
    assert_eq!(ids(&template.transactions), ids(&[trade, paid.clone()]));
    assert_eq!(status.unwrap()["tip"], hex::encode(view.chain.tip_hash()));
    assert_eq!(snapshot(&node).chain.tip_hash(), codec::block_hash(&block));
    assert_eq!(pool(&node).0, vec![paid]);
}

#[test]
fn concurrently_validated_siblings_commit_as_tip_and_side_branch() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let (first, second) = (child(&node, 1), child(&node, 2));
    // Both pass their checks against the same tip, then execute at once.
    let (a, resume_a) = parked_submission(&node, first.clone());
    let (b, resume_b) = parked_submission(&node, second.clone());
    drop(resume_a);
    assert!(a.join().unwrap().unwrap(), "the first to finish becomes the tip");
    drop(resume_b);
    assert!(!b.join().unwrap().unwrap(), "its sibling is stored on a side branch");
    let check = |node: &Node| {
        let i = node.locked().unwrap();
        let (one, two) = (codec::block_hash(&first), codec::block_hash(&second));
        let stored = (i.chain.tip_hash(), i.chain.block_height(&two).unwrap());
        let active = i.chain.hash_at_height(second.height);
        drop(i);
        assert_eq!(stored, (one, Some(second.height)));
        assert_eq!(active, Some(one));
    };
    check(&node);
    // Startup replay reconstructs the same history.
    drop(node);
    let node = Node::open(
        &directory.path().join("node.sqlite"),
        configuration(16 * 1024),
        key(),
    )
    .unwrap();
    check(&node);
}

#[test]
fn a_side_branch_flood_from_one_source_spends_only_its_own_share() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    // Children of one parent: the first becomes the tip, and each later one
    // is a side block of equal work.
    let count = SIDE_SOURCE_BLOCKS as usize + 3;
    let siblings: Vec<Block> = (0..count as u64).map(|salt| child(&node, salt)).collect();
    assert!(node.submit_block(siblings[0].clone()).unwrap());
    let flood = &siblings[1..count - 1];
    for blocks in flood.chunks(MAX_BATCH) {
        relay_from(&node, "127.0.0.1", Vec::new(), blocks.to_vec());
    }
    let (kept, declined) = flood.split_at(SIDE_SOURCE_BLOCKS as usize);
    assert!(kept.iter().all(|block| stored(&node, block)));
    assert!(declined.iter().all(|block| !stored(&node, block)));
    // The flooding source spent only its own share: another source's side
    // block is still validated and stored.
    let other = &siblings[count - 1];
    relay_from(&node, "127.0.0.2", Vec::new(), vec![other.clone()]);
    assert!(stored(&node, other));
    assert_eq!(snapshot(&node).chain.tip_hash(), codec::block_hash(&siblings[0]));
}

#[test]
fn a_new_tip_template_never_waits_for_a_build_of_the_old_tip() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 64 * 1024);
    let (paused, pause) = mpsc::channel();
    let (resume, resumed) = mpsc::channel::<()>();
    let builder = node.clone();
    let building = std::thread::spawn(move || {
        crate::chain::TEMPLATE_BUILD_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let _ = paused.send(());
                let _ = resumed.recv();
            }));
        });
        builder.template_shared(Freshness::Throttled)
    });
    pause
        .recv_timeout(Duration::from_secs(10))
        .expect("the template build started");
    // A new tip arrives while that build is paused. Its template is built
    // at once, without waiting for the old build.
    assert!(node.submit_block(empty_block(&node)).unwrap());
    let tip = snapshot(&node).chain.tip_hash();
    let (block, retry) = node.template_shared(Freshness::Throttled).unwrap();
    assert_eq!((block.header.previous, retry), (tip, None));
    // The old build stops at its next step, and that request is served the
    // new tip's template too.
    drop(resume);
    let (served, _) = building.join().unwrap().unwrap();
    assert!(Arc::ptr_eq(&served, &block));
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn a_spend_from_an_account_a_pending_transfer_creates_waits_for_its_funding() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let fresh = [78; 32];
    let funding = payment(
        config,
        state,
        &SECRET,
        nonce(&node, &key()),
        crypto::public_key(&fresh).unwrap(),
        5_000,
        0,
    );
    node.submit_transaction(funding.clone()).unwrap();
    // The spend cannot share a block with its funding, so it is held rather
    // than refused, and not relayed.
    let spend = payment(config, state, &fresh, 0, key(), 1, 0);
    let id = node.submit_transaction(spend.clone()).unwrap();
    assert_eq!(awaiting(&node), vec![id]);
    assert_eq!(snapshot(&node).mempool, vec![funding.clone()]);
    // Without a pending transfer creating its account, a spend is refused.
    let stranger = payment(config, state, &[79; 32], 0, key(), 1, 0);
    let refused = node.submit_transaction(stranger).unwrap_err().to_string();
    assert!(refused.contains("sender account does not exist"), "{refused}");
    // The funding confirms first; the spend then enters the pool and
    // confirms in the next block.
    assert_eq!(node.mine(1_000_000).unwrap().transactions, vec![funding]);
    assert!(awaiting(&node).is_empty());
    assert_eq!(pool(&node).0, vec![spend.clone()]);
    assert_eq!(node.mine(1_000_000).unwrap().transactions, vec![spend]);
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn spends_awaiting_funding_are_bounded_and_expire() {
    let directory = tempfile::tempdir().unwrap();
    let node = funded_node(directory.path(), 16 * 1024);
    let view = snapshot(&node);
    let (config, state) = (view.chain.config.as_ref(), view.chain.tip_state());
    let fresh = [80; 32];
    let funding = payment(
        config,
        state,
        &SECRET,
        nonce(&node, &key()),
        crypto::public_key(&fresh).unwrap(),
        5_000,
        0,
    );
    node.submit_transaction(funding).unwrap();
    for nonce in 0..AWAITING_PER_SENDER as u64 {
        node.submit_transaction(payment(config, state, &fresh, nonce, key(), 1, 0))
            .unwrap();
    }
    let beyond = payment(config, state, &fresh, AWAITING_PER_SENDER as u64, key(), 1, 0);
    assert!(node.submit_transaction(beyond).is_err());
    assert_eq!(awaiting(&node).len(), AWAITING_PER_SENDER);
    // Blocks that leave the funding pending: the spends wait AWAITING_TIPS
    // new tips, then are dropped.
    for _ in 0..AWAITING_TIPS {
        assert!(node.submit_block(empty_block(&node)).unwrap());
    }
    assert_eq!(awaiting(&node).len(), AWAITING_PER_SENDER);
    assert!(node.submit_block(empty_block(&node)).unwrap());
    assert!(awaiting(&node).is_empty());
}
