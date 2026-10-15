mod support;
// Isolated state transitions only; these tests never contact a running node.
use hashstash::{
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const SECRET: [u8; 32] = [81; 32];
fn owner() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.initial.lead = 2 * c.initial.interval;
    c.initial.decision_blocks = 12;
    c.initial.rest = 4 * c.initial.interval;
    c.validate().unwrap();
    c
}
fn step(c: &Config, s: &State, miner: PublicKey, subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &miner, &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn transfer(recipient: PublicKey, amount: u64) -> Operation {
    Operation::TransferExact {
        recipient,
        amount: amount.into(),
    }
}
fn sign(s: &State, op: Operation, priority: u64, data: &[u8], offset: u64) -> Transaction {
    support::sign_minimum(
        s,
        TransactionBody {
            chain_id: s.chain_id,
            sender: owner(),
            nonce: s.account(&owner(), None).unwrap().nonce + offset,
            fee: 1_000_000u64.into(),
            expiry_height: s.height + 100,
            operation: op,
            data: data.to_vec(),
        },
        &SECRET,
        priority,
    )
}
fn funded(c: &Config) -> State {
    step(c, &State::genesis(c), owner(), 1_000_000, &[])
}
fn funded_curve(c: &Config) -> State {
    let mut s = funded(c);
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: 800_000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
        &[],
        0,
    );
    s = step(c, &s, owner(), 1_000_000, &[tx]);
    for _ in 0..100 {
        if matches!(s.phase, Phase::Auction(_)) {
            return s;
        }
        s = step(c, &s, owner(), 1, &[]);
    }
    panic!("auction did not open")
}
#[test]
fn fee_revenue_waits_at_flat_without_creating_an_account() {
    let c = config();
    let s = funded_curve(&c);
    let recipient = crypto::public_key(&[82; 32]).unwrap();
    assert!(s.account(&recipient, None).is_none());
    let tx = sign(&s, transfer(recipient, 100), 7, b"hello", 0);
    let quote = fees::quote(&c, &s, &tx).unwrap();
    assert_eq!(
        quote.weight,
        codec::encode(&tx).len() as u64 + fees::ACCOUNT_WEIGHT
    );
    let before = s.world.clone();
    let next = step(&c, &s, owner(), 1, &[tx]);
    assert_eq!(next.world.revenue, &before.revenue + &quote.revenue_fee);
    assert_eq!(next.world.reserve, before.reserve);
    assert_eq!(next.world.curve_mass, before.curve_mass);
    assert_eq!(next.world.shares, before.shares);
    assert_eq!(
        next.account(&recipient, None).unwrap().ordinary,
        100u64.into()
    );
    assert_eq!(next.world.accounts.len(), before.accounts.len() + 1);
}

#[test]
fn explicit_deposits_keep_accumulated_fees_outside_private_reserve_and_shares() {
    let c = config();
    let mut s = funded(&c);
    let tx = sign(&s, transfer(owner(), 1), 7, &[], 0);
    let fee = fees::quote(&c, &s, &tx).unwrap().revenue_fee;
    s = step(&c, &s, owner(), 1, &[tx]);
    assert!(s.world.reserve.is_zero() && s.world.shares.is_zero());
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: 1000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
        &[],
        0,
    );
    let deposit_fee = fees::quote(&c, &s, &tx).unwrap().revenue_fee;
    s = step(&c, &s, owner(), 1, &[tx]);
    assert_eq!(s.world.revenue, fee + deposit_fee);
    assert_eq!(s.world.reserve, 1000u32.into());
    assert_eq!(s.world.curve_mass, s.world.reserve);
    assert_eq!(s.world.shares, &s.world.reserve * &c.share_scale);
    assert_eq!(s.world.account_shares, s.world.shares);
    assert_eq!(s.world.accounts.len(), 1);
}

#[test]
fn empty_reserve_keeps_revenue_and_reopens_flat_only_with_a_real_deposit() {
    let mut c = config();
    // Emptying makes the quote zero, so this fixture explicitly permits a
    // complete downward move while testing revenue retention and reopening.
    c.initial.max_price_change_bps = 10_000;
    let mut s = funded_curve(&c);
    let tx = sign(
        &s,
        Operation::Redeem {
            shares: s.world.shares.clone(),

            decision: None,
            outcome: None,
        },
        0,
        &[],
        0,
    );
    s = step(&c, &s, owner(), 1, &[tx]);
    assert!(s.world.reserve.is_zero() && s.world.shares.is_zero() && s.world.curve_mass.is_zero());
    assert!(!s.world.revenue.is_zero());
    let waiting = s.world.revenue.clone();
    s = step(&c, &s, owner(), 1, &[]);
    assert!(s.world.reserve.is_zero());
    assert_eq!(s.world.revenue, waiting);
    let tx = sign(
        &s,
        Operation::Deposit {
            amount: 100u64.into(),

            decision: None,
            outcome: None,
        },
        0,
        &[],
        0,
    );
    s = step(&c, &s, owner(), 1, &[tx]);
    assert_eq!(s.world.reserve, 100u64.into());
    assert_eq!(s.world.curve_mass, s.world.reserve);
    assert_eq!(s.world.shares, Amount::from(100u64) * &c.share_scale);
}
#[test]
fn fee_buffer_reorg_and_reopen_restore_the_selected_committed_balance() {
    use hashstash::chain::Chain;
    fn append(chain: &mut Chain, txs: Vec<Transaction>) -> hashstash::types::Block {
        let candidate = chain
            .template(owner(), txs, chain.tip_height() as u32 + 1)
            .unwrap();
        let block = Chain::mine(candidate, 1_000_000).unwrap();
        assert!(
            chain
                .submit(block.clone(), u64::from(block.header.timestamp))
                .unwrap()
        );
        chain.tip_state().audit(&chain.config).unwrap();
        block
    }
    let directory = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let c = config();
    let path = directory.path().join("chain.sqlite");
    let mut chain = Chain::open(&path, c.clone()).unwrap();
    let mut fork = Chain::open(&other.path().join("chain.sqlite"), c.clone()).unwrap();
    for _ in 0..4 {
        let block = append(&mut chain, vec![]);
        assert!(
            fork.submit(block.clone(), u64::from(block.header.timestamp))
                .unwrap()
        );
    }
    let tx = sign(
        chain.tip_state(),
        transfer(owner(), 1),
        0,
        b"chat\0reorg",
        0,
    );
    append(&mut chain, vec![tx]);
    assert!(chain.tip_state().world.revenue > Amount::zero());
    let detached_root = chain.tip_state().root();
    let a = append(&mut fork, vec![]);
    let b = append(&mut fork, vec![]);
    chain
        .submit(a.clone(), u64::from(a.header.timestamp))
        .unwrap();
    assert!(
        chain
            .submit(b.clone(), u64::from(b.header.timestamp))
            .unwrap()
    );
    assert_eq!(chain.tip_state().root(), fork.tip_state().root());
    assert_ne!(chain.tip_state().root(), detached_root);
    assert!(chain.tip_state().world.revenue.is_zero());
    let tip = chain.tip_hash();
    let root = chain.tip_state().root();
    drop(chain);
    let reopened = Chain::open(&path, c.clone()).unwrap();
    assert_eq!(reopened.tip_hash(), tip);
    assert_eq!(reopened.tip_state().root(), root);
    reopened.tip_state().audit(&c).unwrap();
}
