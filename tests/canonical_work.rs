//! Canonical-work issuance, branch replay, and governed fee invariants.
use hashstash::{
    chain::Chain, config::Config, consensus, crypto, fees, math, state::State, types::*,
};

fn miner(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.genesis_time = 1_700_000_000;
    c.initial_bits = 0x201fffff;
    c.limit_bits = 0x207fffff;
    c.validate().unwrap();
    c
}
fn append(chain: &mut Chain, miner: PublicKey, seconds: u32) -> Block {
    let timestamp = chain.tip_block().header.timestamp + seconds;
    let block = Chain::mine(chain.template(miner, vec![], timestamp).unwrap(), 1_000_000).unwrap();
    assert!(chain.submit(block.clone(), u64::from(timestamp)).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
    block
}
fn work(block: &Block) -> Amount {
    math::work(&math::target_from_bits(block.header.bits).unwrap())
}

#[test]
fn current_presets_govern_block_time_and_the_whole_fee_split() {
    for c in [Config::devnet(), Config::testnet(), Config::slow_testnet()] {
        c.validate().unwrap();
        assert_eq!(c.initial.interval, 15);
        assert_eq!(c.progress_increment(&c.initial), c.initial.interval);
        for p in [
            Parameter::Interval,
            Parameter::PassMarginBps,
            Parameter::MinerFeePercent,
        ] {
            assert!(c.governance_parameters().contains(&p));
        }
        for seconds in 0..=61 {
            assert_eq!(
                c.parameter_change(&c.initial, Parameter::Interval, 15, seconds)
                    .is_ok(),
                seconds > 0 && seconds != 15
            );
        }
        assert!(
            c.parameter_change(&c.initial, Parameter::MinerFeePercent, 50, 25)
                .is_ok()
        );
    }
}

#[test]
fn each_canonical_block_mints_its_own_work_and_only_creates_its_miner() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let mut chain = Chain::open(&d.path().join("mint.sqlite"), c).unwrap();
    let first = append(&mut chain, miner(171), 15);
    let first_state = chain.tip_state();
    assert_eq!(first_state.issued, work(&first));
    assert_eq!(first_state.world.accounts.len(), 1);
    assert_eq!(
        first_state.account(&miner(171), None).unwrap().ordinary,
        work(&first)
    );

    let second = append(&mut chain, miner(172), 15);
    assert_eq!(chain.tip_state().issued, work(&first) + work(&second));
    assert_eq!(chain.tip_state().world.accounts.len(), 2);
    assert_eq!(
        chain
            .tip_state()
            .account(&miner(172), None)
            .unwrap()
            .ordinary,
        work(&second)
    );
}

#[test]
fn competing_blocks_are_normal_forks_with_no_extra_issuance_after_reorg_and_reopen() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let path = d.path().join("main.sqlite");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&d.path().join("fork.sqlite"), c.clone()).unwrap();
    append(&mut main, miner(171), 15);
    let side = append(&mut fork, miner(172), 15);
    assert!(
        !main
            .submit(side.clone(), u64::from(side.header.timestamp))
            .unwrap()
    );
    assert!(main.tip_state().account(&miner(172), None).is_none());
    let child = append(&mut fork, miner(172), 15);
    assert!(
        main.submit(child.clone(), u64::from(child.header.timestamp))
            .unwrap()
    );
    assert_eq!(main.tip_hash(), fork.tip_hash());
    assert_eq!(main.tip_state().issued, work(&side) + work(&child));
    assert_eq!(main.tip_state().world.accounts.len(), 1);
    assert!(main.tip_state().account(&miner(171), None).is_none());
    let root = main.tip_state().root();
    drop(main);
    let main = Chain::open(&path, c).unwrap();
    assert_eq!(main.tip_state().root(), root);
    assert_eq!(main.tip_state().issued, work(&side) + work(&child));
}

#[test]
fn canonical_work_network_keeps_timestamp_difficulty_and_scheduled_second_economic_progress() {
    let d = tempfile::tempdir().unwrap();
    let c = config();
    let mut fast = Chain::open(&d.path().join("fast.sqlite"), c.clone()).unwrap();
    let mut paced = Chain::open(&d.path().join("paced.sqlite"), c.clone()).unwrap();
    let mut slow = Chain::open(&d.path().join("slow.sqlite"), c.clone()).unwrap();
    for _ in 0..32 {
        append(&mut fast, miner(171), 5);
        append(&mut paced, miner(171), 15);
        append(&mut slow, miner(171), 30);
    }
    let initial = math::target_from_bits(c.initial_bits).unwrap();
    assert!(fast.next_target().unwrap() < initial);
    assert_eq!(paced.next_target().unwrap(), initial);
    assert!(slow.next_target().unwrap() > initial);
    for chain in [&fast, &paced, &slow] {
        assert_eq!(chain.tip_state().clock, 32 * 15);
        assert_eq!(chain.expected_elapsed_seconds(), 32 * 15);
    }
}

#[test]
fn whole_actual_fee_obeys_the_governed_split() {
    for percent in [0, 25, 50, 100] {
        let mut c = config();
        c.initial.miner_fee_percent = Some(percent);
        c.initial.minimum_fee_rate = 17;
        c.validate().unwrap();
        let owner = miner(171);
        let recipient = miner(172);
        let producer = miner(173);
        let s = consensus::execute(
            &c,
            &State::genesis(&c),
            &ZERO_HASH,
            &owner,
            &1_000_000u32.into(),
            &[],
        )
        .unwrap();
        let s = consensus::execute(&c, &s, &s.root(), &producer, &1000u32.into(), &[]).unwrap();
        let tx = crypto::sign(
            &TransactionBody {
                chain_id: s.chain_id,
                sender: owner,
                nonce: s.account(&owner, None).unwrap().nonce,
                fee: 100_000u32.into(),
                expiry_height: s.height + 10,
                operation: Operation::TransferExact {
                    recipient,
                    amount: 1u32.into(),
                },
                data: vec![],
            },
            &[171; 32],
        )
        .unwrap();
        let quote = fees::quote(&c, &s, &tx).unwrap();
        assert_eq!(quote.fee, 100_000u32.into());
        assert_eq!(quote.miner_fee, &quote.fee * percent / 100u32);
        assert_eq!(&quote.miner_fee + &quote.revenue_fee, quote.fee);
        let next = consensus::execute(&c, &s, &s.root(), &producer, &11u32.into(), &[tx]).unwrap();
        next.audit(&c).unwrap();
        assert_eq!(next.issued, &s.issued + 11u32);
        assert_eq!(next.world.revenue, &s.world.revenue + &quote.revenue_fee);
        assert_eq!(
            next.account(&producer, None).unwrap().ordinary,
            s.account(&producer, None).unwrap().ordinary + 11u32 + &quote.miner_fee
        );
        assert_eq!(
            next.account(&owner, None).unwrap().ordinary,
            s.account(&owner, None).unwrap().ordinary - 1u32 - &quote.fee
        );
        assert_eq!(
            next.account(&recipient, None).unwrap().ordinary,
            1u32.into()
        );
    }
}
