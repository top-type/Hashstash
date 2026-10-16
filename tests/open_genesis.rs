//! Trading opens with the chain; mining never converts an account implicitly.
mod support;
use hashstash::{
    chain::Chain,
    config::Config,
    consensus, crypto,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const ALICE: [u8; 32] = [71; 32];
const BOB: [u8; 32] = [72; 32];
fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn step(c: &Config, s: &State, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &key(&ALICE), &1000u32.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn signed(c: &Config, s: &State, secret: &[u8; 32], operation: Operation) -> Transaction {
    support::sign_minimum(
        s,
        TransactionBody {
            sender: key(secret),
            nonce: s.account(&key(secret), None).unwrap().nonce,
            fee: 0u32.into(),
            anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
            expiry_blocks: s.height + 1000,
            operation,
            data: vec![],
        },
        secret,
        0,
    )
}
fn deposit(amount: u32) -> Operation {
    Operation::Deposit {
        amount: amount.into(),

        decision: None,
        outcome: None,
    }
}

#[test]
fn genesis_opens_payments_and_flat_stash_before_first_auction() {
    let c = Config::testnet();
    let mut s = State::genesis(&c);
    assert!(matches!(s.phase,Phase::Rest(ref r) if r.until==c.initial.rest));
    assert!(s.world.reserve.is_zero() && s.world.shares.is_zero());
    s = step(&c, &s, &[]);
    let tx = signed(
        &c,
        &s,
        &ALICE,
        Operation::TransferExact {
            recipient: key(&BOB),
            amount: 200u32.into(),
        },
    );
    s = step(&c, &s, &[tx]);
    let tx = signed(&c, &s, &BOB, deposit(100));
    s = step(&c, &s, &[tx]);
    assert!(s.clock < c.initial.rest);
    assert!(matches!(s.phase, Phase::Rest(_)));
    assert_eq!(s.world.reserve, 100u32.into());
    assert_eq!(s.world.curve_mass, s.world.reserve);
    assert_eq!(
        s.account(&key(&BOB), None).unwrap().shares,
        Amount::from(100u32) * &c.share_scale
    );
    assert!(s.account(&key(&ALICE), None).unwrap().shares.is_zero());
    let before = s.account(&key(&BOB), None).unwrap();
    let tx = signed(
        &c,
        &s,
        &BOB,
        Operation::Redeem {
            shares: before.shares.clone() / 2u32,

            decision: None,
            outcome: None,
        },
    );
    s = step(&c, &s, &[tx]);
    assert_eq!(s.world.reserve, 50u32.into());
    assert_eq!(s.world.curve_mass, s.world.reserve);
    assert!(s.account(&key(&BOB), None).unwrap().ordinary > before.ordinary);
}

#[test]
fn first_rest_expiry_never_converts_idle_hash_balances() {
    let c = Config::testnet();
    let mut s = State::genesis(&c);
    let blocks = c.initial.rest.div_ceil(c.initial.interval) + 100;
    for _ in 0..blocks {
        s = step(&c, &s, &[]);
    }
    assert_eq!(s.account(&key(&ALICE), None).unwrap().ordinary, s.issued);
    assert!(s.world.shares.is_zero() && s.world.reserve.is_zero() && s.world.curve_mass.is_zero());
    assert!(s.account(&key(&ALICE), None).unwrap().shares.is_zero());
}

#[test]
fn share_scale_is_bounded_required_and_network_committed() {
    let c = Config::testnet();
    let mut changed = c.clone();
    changed.share_scale = 0u32.into();
    assert!(changed.validate().is_err());
    changed = c.clone();
    changed.share_scale *= 2u32;
    changed.validate().unwrap();
    assert_ne!(c.chain_id(), changed.chain_id());
    changed = c.clone();
    changed.share_scale = Amount::from(1u32) << 512usize;
    assert!(changed.validate().is_err());
    let mut serialized = serde_json::to_value(&c).unwrap();
    serialized.as_object_mut().unwrap().remove("share_scale");
    assert!(serde_json::from_value::<Config>(serialized).is_err());
}

#[test]
fn early_explicit_deposit_reorg_and_restart_restore_exact_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = Config::testnet();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    let path = dir.path().join("main.sqlite");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&dir.path().join("fork.sqlite"), c.clone()).unwrap();
    fn append(chain: &mut Chain, miner: PublicKey, txs: Vec<Transaction>) -> Block {
        let stamp = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
        let block = Chain::mine(chain.template(miner, txs, stamp).unwrap(), 1_000_000).unwrap();
        assert!(chain.submit(block.clone(), u64::from(stamp)).unwrap());
        block
    }
    let first = append(&mut main, key(&ALICE), vec![]);
    fork.submit(first.clone(), u64::from(first.header.timestamp))
        .unwrap();
    let tx = signed(&c, main.tip_state(), &ALICE, deposit(100));
    append(&mut main, key(&ALICE), vec![tx]);
    assert!(!main.tip_state().world.shares.is_zero());
    for _ in 0..2 {
        let block = append(&mut fork, key(&BOB), vec![]);
        main.submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap();
    }
    assert_eq!(main.tip_state().root(), fork.tip_state().root());
    assert!(main.tip_state().world.shares.is_zero());
    assert!(
        main.tip_state()
            .account(&key(&ALICE), None)
            .unwrap()
            .shares
            .is_zero()
    );
    let root = main.tip_state().root();
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.tip_state().root(), root);
    reopened.tip_state().audit(&reopened.config).unwrap();
}
