//! Data is signed block history, never an operation or account-state payload.
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};

const ALICE: [u8; 32] = [91; 32];
const BOB: [u8; 32] = [92; 32];
const MINER: [u8; 32] = [93; 32];

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}

fn config() -> Config {
    let c = Config::testnet();
    c.validate().unwrap();
    c
}

fn transfer(recipient: PublicKey) -> Operation {
    Operation::TransferExact {
        recipient,
        amount: 10u32.into(),
    }
}

fn signed(c: &Config, s: &State, operation: Operation, data: Vec<u8>, offset: u64) -> Transaction {
    crypto::sign(
        &TransactionBody {
            chain_id: s.chain_id,
            sender: key(&ALICE),
            nonce: s.account(&key(&ALICE), None).map_or(0, |a| a.nonce) + offset,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
            expiry_blocks: s.height + 1_000,
            operation,
            data,
        },
        &ALICE,
    )
    .unwrap()
}

fn step(c: &Config, s: &State, miner: &[u8; 32], subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &key(miner), &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}

fn funded(c: &Config) -> State {
    let s = step(c, &State::genesis(c), &ALICE, 1_000_000, &[]);
    step(c, &s, &MINER, 1_000, &[])
}

fn balance(s: &State, who: &[u8; 32]) -> Amount {
    s.account(&key(who), None).unwrap().ordinary
}

fn rejected(c: &Config, s: &State, tx: &Transaction) -> String {
    let mut copy = s.clone();
    let message = consensus::apply_transaction(c, &mut copy, tx)
        .unwrap_err()
        .to_string();
    assert_eq!(
        copy.root(),
        s.root(),
        "invalid data transaction mutated state"
    );
    message
}

#[test]
fn empty_data_has_one_canonical_encoding_and_arbitrary_bytes_round_trip() {
    let c = config();
    let s = funded(&c);
    let empty = signed(&c, &s, transfer(key(&BOB)), vec![], 0);
    assert!(empty.body.data.is_empty());
    assert_eq!(codec::encode(&empty.body.operation)[0], 0);
    for data in [
        vec![0],
        vec![255, 0, 128, 0],
        (0..=255).collect(),
        vec![255; 3_500],
    ] {
        let tx = signed(&c, &s, transfer(key(&BOB)), data.clone(), 0);
        assert_eq!(codec::encode(&tx.body.operation)[0], 0);
        let encoded = codec::encode(&tx);
        let decoded: Transaction =
            codec::decode(&encoded, c.transaction_bytes(&s.settings)).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.body.data, data);
        assert_eq!(decoded.body.operation.clone(), transfer(key(&BOB)));
        assert_eq!(
            serde_json::from_str::<Transaction>(&serde_json::to_string(&tx).unwrap()).unwrap(),
            tx
        );
        step(&c, &s, &MINER, 0, &[tx]);
    }
}

#[test]
fn data_does_not_execute_even_when_it_encodes_a_valid_operation() {
    let c = config();
    let s = funded(&c);
    let encoded_operation = codec::encode(&Operation::TransferExact {
        recipient: key(&BOB),
        amount: 800_000u32.into(),
    });
    let other = vec![255; encoded_operation.len()];
    let a = signed(&c, &s, transfer(key(&BOB)), encoded_operation, 0);
    let b = signed(&c, &s, transfer(key(&BOB)), other, 0);
    assert_ne!(codec::transaction_id(&a), codec::transaction_id(&b));
    let first = step(&c, &s, &MINER, 0, &[a]);
    let second = step(&c, &s, &MINER, 0, &[b]);
    assert_eq!(first.root(), second.root());
    assert_eq!(balance(&first, &BOB), 10u32.into());
    assert!(balance(&first, &ALICE) > 999_000u32.into());
}

#[test]
fn data_bytes_are_fully_charged_and_fee_distribution_is_unchanged() {
    let c = config();
    let s = funded(&c);
    let plain = signed(&c, &s, transfer(key(&BOB)), vec![], 0);
    let tx = signed(&c, &s, transfer(key(&BOB)), vec![0; 2_048], 0);
    let old_quote = fees::quote(&c, &s, &plain).unwrap();
    let quote = fees::quote(&c, &s, &tx).unwrap();
    assert_eq!(
        quote.weight,
        codec::encode(&tx).len() as u64 + fees::ACCOUNT_WEIGHT
    );
    // Data uses its compact length plus every byte, with no discount.
    assert_eq!(quote.weight - old_quote.weight, 2_048 + 2);
    assert!(quote.minimum_fee > old_quote.minimum_fee);
    let next = step(&c, &s, &MINER, 17, &[tx]);
    assert_eq!(
        balance(&next, &ALICE),
        balance(&s, &ALICE) - 10u32 - &quote.fee
    );
    assert_eq!(balance(&next, &BOB), 10u32.into());
    assert_eq!(
        balance(&next, &MINER),
        balance(&s, &MINER) + 17u32 + &quote.miner_fee
    );
    assert_eq!(next.world.revenue, &s.world.revenue + &quote.revenue_fee);
    assert_eq!(next.issued, &s.issued + 17u32);

    let mut inadequate = plain.body.clone();
    inadequate.fee = old_quote.minimum_fee;
    inadequate.operation = {
        inadequate.data = vec![0; 2_048];
        transfer(key(&BOB))
    };
    assert!(rejected(&c, &s, &crypto::sign(&inadequate, &ALICE).unwrap()).contains("minimum"));
}

#[test]
fn mutation_removal_and_reordering_invalidate_signature_and_do_not_charge() {
    let c = config();
    let s = funded(&c);
    let original = signed(&c, &s, transfer(key(&BOB)), vec![0, 1, 2, 255], 0);
    for data in [
        vec![0, 1, 3, 255],
        vec![0, 1, 2],
        vec![0, 1, 2, 255, 0],
        vec![255, 2, 1, 0],
        vec![],
    ] {
        let mut changed = original.clone();
        changed.body.operation = {
            changed.body.data = data;
            transfer(key(&BOB))
        };
        assert!(crypto::verify(&changed).is_err());
        rejected(&c, &s, &changed);
    }
    crypto::verify(&original).unwrap();
    let mut next = s.clone();
    consensus::apply_transaction(&c, &mut next, &original).unwrap();
    assert!(rejected(&c, &next, &original).contains("nonce"));
}

#[test]
fn transaction_size_boundary_includes_data_without_a_separate_data_limit() {
    let c = config();
    let s = funded(&c);
    let first = signed(&c, &s, transfer(key(&ALICE)), vec![0; 1024], 0);
    let overhead = codec::encode(&first).len() - 1024;
    let max_data = c.transaction_bytes(&s.settings) - overhead;
    assert!(max_data > 3_000);
    let full = signed(&c, &s, transfer(key(&ALICE)), vec![0; max_data], 0);
    assert_eq!(codec::encode(&full).len(), c.transaction_bytes(&s.settings));
    step(&c, &s, &MINER, 0, &[full]);
    let oversized = signed(&c, &s, transfer(key(&ALICE)), vec![0; max_data + 1], 0);
    assert_eq!(
        codec::encode(&oversized).len(),
        c.transaction_bytes(&s.settings) + 1
    );
    assert!(rejected(&c, &s, &oversized).contains("byte limit"));
    assert!(
        codec::decode::<Transaction>(&codec::encode(&oversized), c.transaction_bytes(&s.settings))
            .is_err()
    );
}

#[test]
fn removed_envelope_tags_cannot_be_decoded_as_operations() {
    for tag in [6, 7, 8, 255] {
        let mut raw = vec![tag];
        raw.extend(vec![0; 1024]);
        assert!(codec::decode::<Operation>(&raw, 4096).is_err());
    }
}

fn append(chain: &mut Chain, transactions: Vec<Transaction>, opaque: u32) -> Block {
    let block = Chain::mine(
        chain.template(key(&ALICE), transactions, opaque).unwrap(),
        1_000_000,
    )
    .unwrap();
    chain
        .submit(block.clone(), u64::from(block.header.timestamp))
        .unwrap();
    chain.tip_state().audit(&chain.config).unwrap();
    block
}

#[test]
fn data_consumes_block_capacity_and_invalid_candidates_do_not_block_selection() {
    let mut c = config();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&dir.path().join("capacity.db"), c.clone()).unwrap();
    for _ in 0..4 {
        append(&mut chain, vec![], 0);
    }
    let s = chain.tip_state();
    let valid: Vec<_> = (0..10)
        .map(|n| signed(&c, s, transfer(key(&ALICE)), vec![n as u8; 3_000], n))
        .collect();
    let oversized = signed(
        &c,
        s,
        transfer(key(&ALICE)),
        vec![0; c.transaction_bytes(&s.settings)],
        0,
    );
    let mut modified = valid[0].clone();
    modified.body.data[0] ^= 1;
    let mut candidates = vec![oversized, modified];
    candidates.extend(valid.clone());
    let selected = chain
        .select_transactions(key(&ALICE), &candidates, 100)
        .unwrap();
    let count = selected.transactions.len();
    assert!(count > 0 && count < valid.len());
    assert_eq!(selected.transactions, valid[..count]);
    let weight: u64 = selected
        .transactions
        .iter()
        .map(|tx| codec::encode(tx).len() as u64)
        .sum();
    assert!(weight > c.initial.block_bytes / 2);
    assert!(weight <= c.initial.block_bytes);
    assert!(
        chain
            .template(key(&ALICE), valid[..count + 1].to_vec(), 0)
            .is_err()
    );
    let block = append(&mut chain, selected.transactions, 0);
    assert!(codec::body_size(&block).unwrap() <= c.initial.block_bytes as usize);

    assert_eq!(chain.tip_state().settings.minimum_fee_rate, 1);
}

#[test]
fn data_is_committed_in_blocks_and_preserved_across_reorg_and_database_replay() {
    let mut c = config();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&dir.path().join("fork.db"), c.clone()).unwrap();
    for _ in 0..4 {
        let block = append(&mut main, vec![], 0);
        fork.submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    let transactions: Vec<_> = (0..3)
        .map(|n| {
            signed(
                &c,
                main.tip_state(),
                transfer(key(&ALICE)),
                vec![n as u8; 3_000],
                n,
            )
        })
        .collect();
    let block = append(&mut main, transactions.clone(), 11);
    let old_hash = codec::block_hash(&block);
    let old_root = main.tip_state().root();
    assert_eq!(main.tip_state().settings.minimum_fee_rate, 1);
    let mut corrupted = block.clone();
    corrupted.transactions[0].body.data[0] ^= 1;
    assert_ne!(
        codec::merkle_root(&corrupted).unwrap(),
        block.header.merkle_root
    );
    assert!(
        fork.submit(corrupted.clone(), u64::from(corrupted.header.timestamp))
            .is_err()
    );
    let competing = append(&mut fork, vec![], 22);
    main.submit(competing.clone(), u64::from(competing.header.timestamp))
        .unwrap();
    assert_eq!(main.tip_hash(), old_hash);
    let winner = append(&mut fork, vec![], 22);
    main.submit(winner.clone(), u64::from(winner.header.timestamp))
        .unwrap();
    assert_eq!(main.tip_hash(), fork.tip_hash());
    assert_eq!(main.tip_state().root(), fork.tip_state().root());
    assert_eq!(main.tip_state().settings.minimum_fee_rate, 1);
    assert_eq!(
        main.tip_state().account(&key(&ALICE), None).unwrap().nonce,
        0
    );
    assert_eq!(main.block(&old_hash).unwrap(), block);
    assert_eq!(main.state_at(&old_hash).unwrap().root(), old_root);
    // The unchanged signatures remain usable after their old branch is undone.
    let replayed_block = append(&mut main, transactions.clone(), 33);
    assert_eq!(replayed_block.transactions, transactions);
    let tip = main.tip_hash();
    let root = main.tip_state().root();
    assert!(matches!(main.tip_state().phase, Phase::Rest(_)));
    drop(main);
    let reopened = Chain::open(&path, c.clone()).unwrap();
    assert_eq!(reopened.tip_hash(), tip);
    assert_eq!(reopened.tip_state().root(), root);
    assert_eq!(
        reopened.block(&old_hash).unwrap().transactions,
        transactions
    );
    assert_eq!(reopened.block(&tip).unwrap().transactions, transactions);
    reopened.tip_state().audit(&c).unwrap();
}
