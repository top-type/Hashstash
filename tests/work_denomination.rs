//! Production work denomination, per-block truncation, fork replay, and fixture isolation.
//! Arithmetic execution tests below supply work directly; they do not claim PoW.
use hashstash::{
    chain::Chain,
    codec,
    config::{Config, WORK_PER_ATOM},
    consensus, crypto, math,
    state::State,
    types::*,
};
use num_traits::{One, Zero};

fn production() -> Config {
    let mut c = Config::devnet();
    c.test_work = false;
    c.validate().unwrap();
    c
}
fn key(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn step(c: &Config, s: &State, miner: u8, work: Amount, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &key(miner), &work, txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn append(chain: &mut Chain, miner: u8) -> Block {
    let stamp = chain.tip_block().header.timestamp + 15;
    let block = Chain::mine(chain.template(key(miner), vec![], stamp).unwrap(), 100_000).unwrap();
    assert!(chain.submit(block.clone(), stamp.into()).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
    block
}

#[test]
fn fixed_production_denomination_and_explicit_fixture_identity() {
    let c = production();
    assert_eq!(WORK_PER_ATOM, 1_000_000_000_000_000);
    assert_eq!(c.work_per_atom().unwrap(), Amount::from(WORK_PER_ATOM));
    assert_eq!(c.share_scale, Amount::one());
    let mut json = serde_json::to_value(&c).unwrap();
    json.as_object_mut().unwrap().remove("test_work");
    let omitted: Config = serde_json::from_value(json).unwrap();
    assert!(
        !omitted.test_work,
        "omitted JSON flag must always mean production"
    );
    assert_eq!(omitted.chain_id(), c.chain_id());
    let mut fixture = c.clone();
    fixture.test_work = true;
    assert_ne!(fixture.chain_id(), c.chain_id());
    assert_ne!(fixture.consensus_bytes(), c.consensus_bytes());
    #[cfg(feature = "test-fixtures")]
    {
        fixture.validate().unwrap();
        assert_eq!(fixture.work_per_atom().unwrap(), Amount::one());
    }
    #[cfg(not(feature = "test-fixtures"))]
    {
        assert!(fixture.validate().is_err());
        assert!(fixture.work_per_atom().is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(Chain::open(&dir.path().join("forbidden.sqlite"), fixture.clone()).is_err());
        assert!(
            consensus::execute(
                &fixture,
                &State::genesis(&fixture),
                &ZERO_HASH,
                &key(1),
                &2u32.into(),
                &[],
            )
            .is_err()
        );
    }
}

#[test]
fn per_block_conversion_discards_fractions_and_handles_wide_work() {
    let q = Amount::from(WORK_PER_ATOM);
    for (work, expected) in [
        (Amount::zero(), Amount::zero()),
        (&q - 1u32, Amount::zero()),
        (q.clone(), Amount::one()),
        (&q + 1u32, Amount::one()),
        (&q * 7u32 + 13u32, Amount::from(7u32)),
        (&q * 1000u32, Amount::from(1000u32)),
    ] {
        assert_eq!(math::issuance(&work, &q).unwrap(), expected);
    }
    let split =
        math::issuance(&(&q - 1u32), &q).unwrap() + math::issuance(&1u32.into(), &q).unwrap();
    assert!(
        split.is_zero(),
        "separate block fractions must never accumulate"
    );
    assert_eq!(math::issuance(&q, &q).unwrap(), Amount::one());
    let maximum = math::work(&Amount::one());
    let payout = math::issuance(&maximum, &q).unwrap();
    assert_eq!(&payout * &q + &maximum % &q, maximum);
    assert!(math::issuance(&1u32.into(), &0u32.into()).is_err());
}

#[test]
fn discarded_fractions_do_not_create_accounts_state_fields_or_later_atoms() {
    let c = production();
    let q = c.work_per_atom().unwrap();
    let genesis = State::genesis(&c);
    let mut before = genesis;
    for _ in 0..5 {
        before = step(&c, &before, 1, &q - 1u32, &[]);
    }
    assert!(before.issued.is_zero());
    assert!(before.world.accounts.is_empty());
    assert!(before.account(&key(1), None).is_none());
    let json = serde_json::to_value(&before).unwrap();
    assert!(json.get("work_remainder").is_none());
    let encoded = codec::encode(&before);
    let decoded: State = codec::decode(&encoded, encoded.len()).unwrap();
    assert_eq!(decoded.root(), before.root());
    let still_zero = step(&c, &before, 2, Amount::one(), &[]);
    assert!(still_zero.issued.is_zero());
    assert!(still_zero.world.accounts.is_empty());
    let later = step(&c, &still_zero, 1, &q + 17u32, &[]);
    assert_eq!(later.issued, Amount::one());
    assert_eq!(
        later.account(&key(1), None).unwrap().ordinary,
        Amount::one()
    );
}

#[test]
fn zero_subsidy_charges_miner_creation_only_when_fees_pay_it() {
    let mut c = production();
    c.initial.minimum_fee_rate = 0;
    c.initial.miner_fee_percent = Some(100);
    c.initial.block_bytes = hashstash::config::MIN_GOVERNED_BLOCK_BYTES;
    c.validate().unwrap();
    let q = c.work_per_atom().unwrap();
    let funded = step(&c, &State::genesis(&c), 1, &q * 100u32, &[]);
    // The payment's data leaves less than one account write of capacity.
    // Changing the configuration below changes the chain ID the payment binds.
    let payment = |chain: &Hash, fee: u32| {
        crypto::sign(
            chain,
            &TransactionBody {
                sender: key(1),
                nonce: 0,
                fee: fee.into(),
                anchor: ZERO_HASH,
                expiry_blocks: 2,
                operation: Operation::TransferExact {
                    recipient: key(1),
                    amount: 1u32.into(),
                },
                data: vec![0; 3_000],
            },
            &[1; 32],
        )
        .unwrap()
    };
    let free = step(&c, &funded, 2, 2u32.into(), &[payment(&funded.chain_id, 0)]);
    assert_eq!(free.issued, funded.issued);
    assert!(free.account(&key(2), None).is_none());
    // A new fee recipient needs one account write in addition to the transaction.
    assert!(
        consensus::execute(
            &c,
            &funded,
            &funded.root(),
            &key(2),
            &2u32.into(),
            &[payment(&funded.chain_id, 1)]
        )
        .is_err()
    );
    c.initial.block_bytes = 16_384;
    let funded = step(&c, &State::genesis(&c), 1, &q * 100u32, &[]);
    let paid = payment(&funded.chain_id, 1);
    let next = step(&c, &funded, 2, 2u32.into(), &[paid]);
    assert_eq!(next.issued, funded.issued);
    assert_eq!(next.account(&key(2), None).unwrap().ordinary, Amount::one());
    assert_eq!(next.world.accounts.len(), 2);
}

#[test]
fn real_easy_pow_preserves_raw_fork_weight_and_zero_issuance_through_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let c = production();
    let path = dir.path().join("main.sqlite");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&dir.path().join("fork.sqlite"), c.clone()).unwrap();
    append(&mut main, 1);
    let old_tip = main.tip_hash();
    let old_state = main.tip_state().clone();
    let side = append(&mut fork, 2);
    assert!(
        !main
            .submit(side.clone(), side.header.timestamp.into())
            .unwrap()
    );
    assert_eq!(main.tip_hash(), old_tip);
    let child = append(&mut fork, 2);
    assert!(
        main.submit(child.clone(), child.header.timestamp.into())
            .unwrap()
    );
    assert_eq!(main.tip_hash(), fork.tip_hash());
    let total = math::work(&math::target_from_bits(side.header.bits).unwrap())
        + math::work(&math::target_from_bits(child.header.bits).unwrap());
    assert_eq!(main.chain_work(), &total);
    assert!(main.tip_state().issued.is_zero());
    assert!(main.tip_state().world.accounts.is_empty());
    assert_eq!(main.state_at(&old_tip).unwrap().root(), old_state.root());
    let root = main.tip_state().root();
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.chain_work(), &total);
    assert_eq!(reopened.tip_state().root(), root);
    assert_eq!(
        reopened.state_at(&old_tip).unwrap().root(),
        old_state.root()
    );
}

#[test]
fn valid_pow_cannot_claim_an_unearned_atom() {
    let dir = tempfile::tempdir().unwrap();
    let c = production();
    let mut chain = Chain::open(&dir.path().join("chain.sqlite"), c.clone()).unwrap();
    let stamp = c.genesis_time + 15;
    let actual = chain.template(key(1), vec![], stamp).unwrap();
    let mut bad = actual.clone();
    bad.state_root = step(&c, chain.tip_state(), 1, c.work_per_atom().unwrap(), &[]).root();
    bad.header.merkle_root = codec::merkle_root(&bad).unwrap();
    bad = Chain::mine(bad, 100_000).unwrap();
    assert!(chain.submit(bad, stamp.into()).is_err());
    assert_eq!(chain.tip_height(), 0);
    let valid = Chain::mine(actual, 100_000).unwrap();
    assert!(chain.submit(valid, stamp.into()).unwrap());
}

#[test]
fn one_displayed_hash_or_stash_is_one_thousand_compact_atoms() {
    #[derive(serde::Serialize)]
    struct Quantity(#[serde(with = "hashstash::types::amount")] Amount);
    let quantity = Quantity(1000u32.into());
    assert_eq!(hex::encode(codec::encode(&quantity)), "02e803");
    let c = production();
    assert_eq!(&quantity.0 * &c.share_scale, Amount::from(1000u32));
}
