//! Signed preparation references are enforced at chain trust boundaries.
use hashstash::{chain::Chain, codec, config::Config, consensus, crypto, math, types::*};
use rusqlite::{Connection, params};
const SECRET: [u8; 32] = [173; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn append(chain: &mut Chain, txs: Vec<Transaction>, salt: u64) -> Block {
    let mut block = chain.template(owner(), txs, 0).unwrap();
    block.extranonce = salt.to_le_bytes();
    block.header.merkle_root = codec::merkle_root(&block).unwrap();
    let block = Chain::mine(block, 100_000).unwrap();
    chain
        .submit(block.clone(), u64::from(block.header.timestamp))
        .unwrap();
    block
}
fn payment(chain: &Chain, anchor: Hash, expiry_blocks: u64) -> Transaction {
    crypto::sign(
        &TransactionBody {
            chain_id: chain.chain_id(),
            sender: owner(),
            nonce: chain.tip_state().account(&owner(), None).unwrap().nonce,
            fee: 1u32.into(),
            anchor,
            expiry_blocks,
            operation: Operation::TransferExact {
                recipient: owner(),
                amount: 1u32.into(),
            },
            data: vec![],
        },
        &SECRET,
    )
    .unwrap()
}
// Construct economic execution and valid PoW without using Chain::template's
// anchor gate: received blocks and persisted history must reject these too.
fn unchecked_candidate(chain: &Chain, tx: Transaction, salt: u64) -> Block {
    let mut block = chain.template(owner(), vec![], 0).unwrap();
    block.transactions = vec![tx];
    let work = math::work(&math::target_from_bits(block.header.bits).unwrap());
    block.state_root = consensus::execute(
        &chain.config,
        chain.tip_state(),
        &chain.tip_hash(),
        &owner(),
        &work,
        &block.transactions,
    )
    .unwrap()
    .root();
    block.extranonce = salt.to_le_bytes();
    block.header.merkle_root = codec::merkle_root(&block).unwrap();
    Chain::mine(block, 100_000).unwrap()
}
#[test]
fn two_block_lifetime_is_fixed_to_the_signed_anchor_and_retry_bytes_do_not_change() {
    let d = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&d.path().join("chain.db"), Config::devnet()).unwrap();
    append(&mut chain, vec![], 1);
    let tx = payment(&chain, chain.tip_hash(), 2);
    let bytes = codec::encode(&tx);
    assert_eq!(chain.validate_transaction_anchor(&tx).unwrap(), 3);
    chain.validate_transaction(&tx).unwrap(); // candidate height2
    append(&mut chain, vec![], 2);
    assert_eq!(chain.validate_transaction_anchor(&tx).unwrap(), 3);
    chain.validate_transaction(&tx).unwrap(); // candidate height3, inclusive boundary
    append(&mut chain, vec![], 3);
    assert!(
        chain
            .validate_transaction(&tx)
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
    assert!(chain.template(owner(), vec![tx.clone()], 0).is_err());
    assert!(
        chain
            .select_transactions(owner(), std::slice::from_ref(&tx), 10)
            .unwrap()
            .transactions
            .is_empty()
    );
    assert_eq!(codec::encode(&tx), bytes);
    let forged = unchecked_candidate(&chain, tx, 4);
    assert!(
        chain
            .submit(forged.clone(), u64::from(forged.header.timestamp))
            .unwrap_err()
            .to_string()
            .contains("expired")
    );
}
#[test]
fn genesis_long_lifetimes_zero_unknown_and_arithmetic_boundaries() {
    let d = tempfile::tempdir().unwrap();
    let mut config = Config::devnet();
    config.max_height = 10;
    let mut chain = Chain::open(&d.path().join("chain.db"), config).unwrap();
    let genesis = chain.tip_hash();
    append(&mut chain, vec![], 1);
    // A redundant expiry beyond the network's terminal height is representable
    // and accepted; the actual including block remains subject to max_height.
    let genesis_tx = payment(&chain, genesis, u64::MAX);
    assert_eq!(
        chain.validate_transaction_anchor(&genesis_tx).unwrap(),
        u64::MAX
    );
    chain.validate_transaction(&genesis_tx).unwrap();
    let long = payment(&chain, chain.tip_hash(), 10_000);
    assert_eq!(chain.validate_transaction_anchor(&long).unwrap(), 10_001);
    chain.validate_transaction(&long).unwrap();
    for (tx, message) in [
        (payment(&chain, chain.tip_hash(), 0), "positive"),
        (payment(&chain, chain.tip_hash(), u64::MAX), "overflows"),
        (payment(&chain, [119; 32], 2), "unknown"),
    ] {
        let error = chain.validate_transaction(&tx).unwrap_err().to_string();
        assert!(error.contains(message), "{error}");
    }
}
#[test]
fn reorg_rejects_detached_references_and_accepts_shared_and_side_branch_ancestors() {
    let d = tempfile::tempdir().unwrap();
    let config = Config::devnet();
    let path = d.path().join("main.db");
    let mut main = Chain::open(&path, config.clone()).unwrap();
    let mut fork = Chain::open(&d.path().join("fork.db"), config.clone()).unwrap();
    let shared = append(&mut main, vec![], 1);
    fork.submit(shared.clone(), u64::from(shared.header.timestamp))
        .unwrap();
    let shared_hash = codec::block_hash(&shared);
    let detached = append(&mut main, vec![], 2);
    let detached_tx = payment(&main, codec::block_hash(&detached), 100);
    let shared_tx = payment(&main, shared_hash, 100);
    let side = append(&mut fork, vec![], 3);
    main.submit(side.clone(), u64::from(side.header.timestamp))
        .unwrap();
    let side_tx = payment(&fork, codec::block_hash(&side), 100);
    assert!(main.validate_transaction_anchor(&side_tx).is_err());
    // A valid side-branch transaction is judged against its own parent, not the
    // current canonical tip. On success the longer branch becomes canonical.
    let winner = append(&mut fork, vec![side_tx], 4);
    main.submit(winner.clone(), u64::from(winner.header.timestamp))
        .unwrap();
    assert_eq!(main.tip_hash(), fork.tip_hash());
    assert!(
        main.validate_transaction_anchor(&detached_tx)
            .unwrap_err()
            .to_string()
            .contains("not on")
    );
    assert_eq!(main.validate_transaction_anchor(&shared_tx).unwrap(), 101);
    let current_nonce = main.tip_state().account(&owner(), None).unwrap().nonce;
    let mut body = shared_tx.body.clone();
    body.nonce = current_nonce;
    let shared_tx = crypto::sign(&body, &SECRET).unwrap();
    let mut body = detached_tx.body.clone();
    body.nonce = current_nonce;
    let detached_tx = crypto::sign(&body, &SECRET).unwrap();
    let selected = main
        .select_transactions(owner(), &[detached_tx, shared_tx.clone()], 10)
        .unwrap();
    assert_eq!(selected.transactions, vec![shared_tx]);
    let root = main.tip_state().root();
    drop(main);
    let reopened = Chain::open(&path, config).unwrap();
    assert_eq!(reopened.tip_hash(), fork.tip_hash());
    assert_eq!(reopened.tip_state().root(), root);
}
#[test]
fn received_blocks_cannot_reference_known_later_blocks_or_unknown_anchors() {
    let d = tempfile::tempdir().unwrap();
    let config = Config::devnet();
    let mut observer = Chain::open(&d.path().join("observer.db"), config.clone()).unwrap();
    let mut past = Chain::open(&d.path().join("past.db"), config).unwrap();
    let shared = append(&mut observer, vec![], 1);
    past.submit(shared.clone(), u64::from(shared.header.timestamp))
        .unwrap();
    append(&mut observer, vec![], 2);
    append(&mut observer, vec![], 3);
    for (anchor, message) in [(observer.tip_hash(), "precede"), ([222; 32], "unknown")] {
        let tx = payment(&past, anchor, 20);
        let forged = unchecked_candidate(&past, tx, 7);
        let error = observer
            .submit(forged.clone(), u64::from(forged.header.timestamp))
            .unwrap_err()
            .to_string();
        assert!(error.contains(message), "{error}");
    }
}
#[test]
fn persisted_history_rechecks_signed_references_independently() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("chain.db");
    let config = Config::devnet();
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    append(&mut chain, vec![], 1);
    let invalid = unchecked_candidate(&chain, payment(&chain, [222; 32], 2), 2);
    drop(chain);
    let db = Connection::open(&path).unwrap();
    db.execute(
        "INSERT INTO blocks(hash,bytes,accepted_at) VALUES(?1,?2,?3)",
        params![
            codec::block_hash(&invalid).as_slice(),
            codec::encode(&invalid),
            u64::from(invalid.header.timestamp)
        ],
    )
    .unwrap();
    drop(db);
    let error = Chain::open(&path, config)
        .err()
        .expect("invalid persisted anchor accepted");
    assert!(format!("{error:#}").contains("unknown transaction anchor"));
}
