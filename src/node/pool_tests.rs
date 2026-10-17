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
    // A lower bid at the pooled nonce needs a selection, then loses it.
    let outbid = payment(config, state, &SECRET, start, other(), 1, 0);
    assert_eq!(deliver(vec![outbid.clone()]), 1, "one selection for one new candidate");
    assert_eq!(published(&node), revision, "an unchanged selection does not publish");
    for _ in 0..3 {
        assert_eq!(
            deliver(vec![forged.clone(), used.clone(), unpayable.clone(), outbid.clone()]),
            0,
            "replayed refusals never reach selection"
        );
    }
    assert_eq!(published(&node), revision);
    assert_eq!(snapshot(&node).mempool, vec![pooled.clone()]);
    // A pool change ends a lost-selection refusal, never a stale-state one.
    let other_payment = payment(config, state, &OTHER, nonce(&node, &other()), key(), 1, 0);
    node.submit_transaction(other_payment).unwrap();
    assert_eq!(deliver(vec![used, unpayable, outbid.clone()]), 1);
    assert!(!ids(&snapshot(&node).mempool).contains(&codec::transaction_id(&outbid)));
}

#[test]
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
fn a_selection_cut_short_by_block_finishing_keeps_its_tail_pending() {
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
    // Finishing now fails for more than two transactions, so the relay's
    // reselection keeps a finishing prefix of the accepted set.
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
    crate::chain::FAIL_FINISH_ABOVE.with(|limit| limit.set(None));
    relayed.unwrap();
    let (selected, backlog, _) = pool(&node);
    assert_eq!(ids(&selected), ids(&pending[..2]));
    // The cut tail was never judged invalid; it used to be dropped as refused.
    assert_eq!(ids(&backlog), ids(&pending[2..5]));
    let block = node.mine(1_000_000).unwrap();
    assert_eq!(ids(&block.transactions), ids(&pending[..5]));
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
