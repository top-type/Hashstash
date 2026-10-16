//! Whole-fee miner governance; isolated consensus and selection fixtures.
#[path = "support/curved.rs"]
mod curved;
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const OWNER: [u8; 32] = [131; 32];
const BOB: [u8; 32] = [132; 32];
const MINER: [u8; 32] = [133; 32];
fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn config(percent: u64) -> Config {
    let mut c = Config::testnet();
    c.initial.miner_fee_percent = Some(percent);
    c.initial.lead = 2 * c.initial.interval;
    c.initial.decision_blocks = 12;
    c.initial.rest = 4 * c.initial.interval;
    c.validate().unwrap();
    c
}
fn sign(
    context: (&Config, &State),
    secret: &[u8; 32],
    op: Operation,
    extra: u64,
    cap: u64,
    offset: u64,
    data: Vec<u8>,
) -> Transaction {
    let (c, s) = context;
    let mut body = TransactionBody {
        sender: key(secret),
        nonce: s.account(&key(secret), None).map_or(0, |a| a.nonce) + offset,
        fee: 0u32.into(),
        anchor: hashstash::codec::block_hash(&hashstash::codec::genesis_block(c).unwrap()),
        expiry_blocks: s.height + 10000,
        operation: op,
        data,
    };
    for _ in 0..16 {
        let tx = crypto::sign(&body, secret).unwrap();
        let quote = fees::quote(&Config::testnet(), s, &tx).unwrap();
        let exact = (quote.minimum_fee + extra).min(cap.into());
        if body.fee == exact {
            return tx;
        }
        body.fee = exact;
    }
    panic!("fee fixture did not converge")
}
fn transfer(c: &Config, s: &State, recipient: PublicKey, extra: u64, offset: u64) -> Transaction {
    sign(
        (c, s),
        &OWNER,
        Operation::TransferExact {
            recipient,
            amount: 1u32.into(),
        },
        extra,
        100000,
        offset,
        vec![],
    )
}
fn step(c: &Config, s: &State, miner: &[u8; 32], subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &key(miner), &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn balance(s: &State, secret: &[u8; 32]) -> Amount {
    s.account(&key(secret), None).unwrap().ordinary
}
fn funded(c: &Config) -> State {
    let s = step(c, &State::genesis(c), &OWNER, 1_000_000, &[]);
    step(c, &s, &MINER, 1000, &[])
}
fn funded_curve(c: &Config) -> State {
    let mut s = funded(c);
    let tx = sign(
        (c, &s),
        &OWNER,
        Operation::Deposit {
            amount: 800_000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
        100,
        0,
        vec![],
    );
    s = step(c, &s, &OWNER, 1_000_000, &[tx]);
    for _ in 0..100 {
        if matches!(s.phase, Phase::Auction(_)) {
            return s;
        }
        s = step(c, &s, &OWNER, 1, &[]);
    }
    panic!("auction did not open")
}

#[test]
fn full_actual_fee_including_creation_weight_and_extra_is_split_once() {
    for percent in [0, 1, 50, 99, 100] {
        for extra in [0, 7, 100] {
            let c = config(percent);
            let mut s = funded(&c);
            s.settings.minimum_fee_rate = 17;
            s.frozen.minimum_fee_rate = 17;
            let tx = transfer(&c, &s, key(&BOB), extra, 0);
            let q = fees::quote(&c, &s, &tx).unwrap();
            assert_eq!(q.miner_fee_percent, Some(percent));
            assert_eq!(
                q.weight,
                codec::encode(&tx).len() as u64 + fees::ACCOUNT_WEIGHT
            );
            assert_eq!(q.fee, &q.minimum_fee + extra);
            assert_eq!(q.miner_fee, &q.fee * percent / 100u32);
            assert_eq!(&q.miner_fee + &q.revenue_fee, q.fee);
            assert_eq!(q.fee, tx.body.fee);
            let next = step(&c, &s, &MINER, 11, &[tx]);
            assert_eq!(balance(&next, &OWNER), balance(&s, &OWNER) - 1u32 - &q.fee);
            assert_eq!(balance(&next, &BOB), 1u32.into());
            assert_eq!(
                balance(&next, &MINER),
                balance(&s, &MINER) + 11u32 + &q.miner_fee
            );
            assert_eq!(next.world.revenue, &s.world.revenue + &q.revenue_fee);
            assert_eq!(next.issued, &s.issued + 11u32);
            assert_eq!(next.settings.minimum_fee_rate, 17);
        }
    }
}

#[test]
fn creation_cost_is_requoted_once_and_each_paid_fee_rounds_separately() {
    let c = config(50);
    let s = funded(&c);
    let first = transfer(&c, &s, key(&BOB), 0, 0);
    let second = transfer(&c, &s, key(&BOB), 0, 1);
    let q1 = fees::quote(&c, &s, &first).unwrap();
    let mut staged = s.clone();
    consensus::apply_transaction(&c, &mut staged, &first).unwrap();
    let q2 = fees::quote(&c, &staged, &second).unwrap();
    assert!(q2.account_creation_fee.is_zero());
    assert_eq!(q2.weight, codec::encode(&second).len() as u64);
    let next = step(&c, &s, &MINER, 0, &[first, second]);
    assert_eq!(
        balance(&next, &MINER),
        balance(&s, &MINER) + &q1.miner_fee + &q2.miner_fee
    );
    assert_eq!(
        next.world.revenue,
        &s.world.revenue + &q1.revenue_fee + &q2.revenue_fee
    );
    assert_eq!(next.settings.minimum_fee_rate, s.settings.minimum_fee_rate);
    let one = transfer(&c, &next, key(&OWNER), 0, 0);
    let two = transfer(&c, &next, key(&OWNER), 0, 1);
    let q = fees::quote(&c, &next, &one).unwrap();
    assert_eq!(q.fee, 1u32.into());
    assert!(q.miner_fee.is_zero());
    let after = step(&c, &next, &MINER, 0, &[one, two]);
    assert_eq!(balance(&after, &MINER), balance(&next, &MINER));
    assert_eq!(after.world.revenue, &next.world.revenue + 2u32);
    let bad = sign(
        (&c, &after),
        &OWNER,
        Operation::TransferExact {
            recipient: key(&BOB),
            amount: 1u32.into(),
        },
        100,
        0,
        0,
        vec![],
    );
    let mut unchanged = after.clone();
    assert!(consensus::apply_transaction(&c, &mut unchanged, &bad).is_err());
    assert_eq!(codec::encode(&unchanged), codec::encode(&after));
}

fn activate(c: &Config, mut s: State, new: u64) -> State {
    let op = Operation::Propose {
        round: s.auction_round().unwrap(),
        description: [15; 32],
        proposal: Proposal::Parameter {
            parameter: Parameter::MinerFeePercent,
            old: s.settings.miner_fee_percent.unwrap(),
            new,
        },
        support: 10u32.into(),
    };
    let tx = sign((c, &s), &OWNER, op, 0, 100, 0, vec![]);
    s = step(c, &s, &OWNER, 1, &[tx]);
    for _ in 0..100 {
        if s.decision_id().is_some() {
            return s;
        }
        s = step(c, &s, &OWNER, 1, &[]);
    }
    panic!("activation failed")
}

#[test]
fn the_same_fee_allocation_is_conserved_in_both_automatic_outcomes() {
    for percent in [0, 50, 100] {
        let c = config(percent);
        let mut s = activate(
            &c,
            funded_curve(&c),
            if percent == 100 { 99 } else { percent + 1 },
        );
        let op = Operation::Deposit {
            amount: 100_000u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        };
        let tx = sign((&c, &s), &OWNER, op, 5, 100, 0, vec![]);
        let q = fees::quote(&c, &s, &tx).unwrap();
        let baseline = step(&c, &s, &MINER, 0, &[]);
        s = step(&c, &s, &MINER, 0, &[tx]);
        for outcome in [Outcome::Pass, Outcome::Fail] {
            let b = baseline.account(&key(&MINER), Some(outcome)).unwrap();
            assert_eq!(
                s.account(&key(&MINER), Some(outcome)).unwrap().ordinary,
                b.ordinary + &q.miner_fee
            );
            let world = if outcome == Outcome::Pass {
                s.alternative.as_ref().unwrap()
            } else {
                &s.world
            };
            let base = if outcome == Outcome::Pass {
                baseline.alternative.as_ref().unwrap()
            } else {
                &baseline.world
            };
            assert_eq!(world.revenue, &base.revenue + &q.revenue_fee);
        }
        assert_eq!(s.issued, baseline.issued);
        assert_eq!(
            s.account(&key(&OWNER), Some(Outcome::Fail))
                .unwrap()
                .ordinary
                - s.account(&key(&OWNER), Some(Outcome::Pass))
                    .unwrap()
                    .ordinary,
            100_000u32.into()
        );
    }
}

#[test]
fn a_winning_percentage_stays_frozen_through_rest_and_activates_after_its_last_block() {
    let c = config(50);
    let prior = curved::state(&c, funded_curve(&c), &OWNER);
    let mut s = activate(&c, prior, 100);
    let buy = sign(
        (&c, &s),
        &OWNER,
        Operation::Deposit {
            amount: 200_000u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
        0,
        100,
        0,
        vec![],
    );
    s = step(&c, &s, &OWNER, 1, &[buy]);
    while s.decision_id().is_some() {
        assert_eq!(s.settings.miner_fee_percent, Some(50));
        assert_eq!(s.frozen.miner_fee_percent, Some(50));
        s = step(&c, &s, &OWNER, 1, &[]);
    }
    let until = match &s.phase {
        Phase::Rest(r) => {
            assert_eq!(r.pending, Some((Parameter::MinerFeePercent, 100)));
            r.until
        }
        _ => panic!("not resting"),
    };
    while s.clock + s.settings.interval < until {
        s = step(&c, &s, &OWNER, 1, &[]);
    }
    let tx = transfer(&c, &s, key(&OWNER), 6, 0);
    let old_quote = fees::quote(&c, &s, &tx).unwrap();
    assert_eq!(old_quote.miner_fee_percent, Some(50));
    let miner_before = balance(&s, &MINER);
    s = step(&c, &s, &MINER, 1, &[tx]);
    assert_eq!(
        balance(&s, &MINER),
        miner_before + 1u32 + old_quote.miner_fee
    );
    assert_eq!(s.settings.miner_fee_percent, Some(100));
    assert_eq!(s.frozen.miner_fee_percent, Some(100));
    let next = fees::quote(&c, &s, &transfer(&c, &s, key(&OWNER), 6, 0)).unwrap();
    assert_eq!(next.miner_fee, next.fee);
    assert!(next.revenue_fee.is_zero());
}

fn append(chain: &mut Chain, txs: Vec<Transaction>, salt: u64) {
    let mut b = chain.template(key(&OWNER), txs, 0).unwrap();
    b.extranonce = salt.to_le_bytes();
    b.header.merkle_root = codec::merkle_root(&b).unwrap();
    let b = Chain::mine(b, 1_000_000).unwrap();
    assert!(
        chain
            .submit(b.clone(), u64::from(b.header.timestamp))
            .unwrap()
    );
    chain.tip_state().audit(&chain.config).unwrap();
}
fn chain_config(percent: u64) -> Config {
    let mut c = config(percent);
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    c
}

#[test]
fn selection_ranks_whole_exact_miner_earnings_per_weight() {
    let d = tempfile::tempdir().unwrap();
    let c = chain_config(50);
    let mut chain = Chain::open(&d.path().join("selection.sqlite"), c.clone()).unwrap();
    append(&mut chain, vec![], 0);
    let s = chain.tip_state();
    let op = Operation::TransferExact {
        recipient: key(&OWNER),
        amount: 1u32.into(),
    };
    let tiny = sign((&c, s), &OWNER, op.clone(), 0, 1_000_000, 0, vec![]);
    let larger = sign((&c, s), &OWNER, op, 0, 100, 0, vec![7; 1100]);
    let tinyq = fees::quote(&c, s, &tiny).unwrap();
    let largerq = fees::quote(&c, s, &larger).unwrap();
    assert!(tinyq.miner_fee.is_zero());
    assert!(largerq.miner_fee > 0u32.into());
    assert!(tinyq.extra_fee.is_zero() && largerq.extra_fee.is_zero());
    let chosen = chain
        .select_transactions(key(&OWNER), &[tiny, larger.clone()], 1)
        .unwrap();
    assert_eq!(chosen.transactions, vec![larger]);
}

#[test]
fn zero_percent_selection_has_deterministic_nonmonetary_ties() {
    let d = tempfile::tempdir().unwrap();
    let c = chain_config(0);
    let mut chain = Chain::open(&d.path().join("zero.sqlite"), c.clone()).unwrap();
    append(&mut chain, vec![], 0);
    let s = chain.tip_state();
    let small = transfer(&c, s, key(&OWNER), 0, 0);
    let big = transfer(&c, s, key(&OWNER), 50, 0);
    assert!(balance(s, &OWNER) > fees::quote(&c, s, &big).unwrap().fee);
    assert!(fees::quote(&c, s, &small).unwrap().miner_fee.is_zero());
    assert!(fees::quote(&c, s, &big).unwrap().miner_fee.is_zero());
    let expected = if codec::transaction_id(&small) < codec::transaction_id(&big) {
        small.clone()
    } else {
        big.clone()
    };
    for candidates in [[small.clone(), big.clone()], [big, small]] {
        assert_eq!(
            chain
                .select_transactions(key(&OWNER), &candidates, 1)
                .unwrap()
                .transactions,
            vec![expected.clone()]
        );
    }
}

#[test]
fn selection_reweights_new_accounts_without_changing_fees_and_revisits_nonces() {
    let d = tempfile::tempdir().unwrap();
    let c = chain_config(50);
    let mut chain = Chain::open(&d.path().join("dependencies.sqlite"), c.clone()).unwrap();
    append(&mut chain, vec![], 0);
    let s = chain.tip_state();
    let create = transfer(&c, s, key(&BOB), 100, 0);
    let to_bob = transfer(&c, s, key(&BOB), 0, 1);
    let alternative = sign(
        (&c, s),
        &OWNER,
        Operation::TransferExact {
            recipient: key(&OWNER),
            amount: 1u32.into(),
        },
        0,
        100,
        1,
        vec![7; 2000],
    );
    let old = fees::quote(&c, s, &to_bob).unwrap();
    let alt = fees::quote(&c, s, &alternative).unwrap();
    assert!(&old.miner_fee * alt.weight > &alt.miner_fee * old.weight);
    let mut staged = s.clone();
    consensus::apply_transaction(&c, &mut staged, &create).unwrap();
    let revised = fees::quote(&c, &staged, &to_bob).unwrap();
    assert_eq!(revised.miner_fee, old.miner_fee);
    assert_eq!(revised.fee, old.fee);
    assert_eq!(old.weight - revised.weight, fees::ACCOUNT_WEIGHT);
    assert!(alt.miner_fee > 0u32.into());
    let (selected, template) = chain
        .select_template(
            key(&OWNER),
            &[to_bob.clone(), alternative.clone(), create.clone()],
            2,
            0,
        )
        .unwrap();
    assert_eq!(selected.transactions, vec![create, to_bob.clone()]);
    assert_eq!(
        template,
        chain
            .template(key(&OWNER), selected.transactions.clone(), 0)
            .unwrap()
    );
    let first = transfer(&c, s, key(&OWNER), 1, 0);
    let later = transfer(&c, s, key(&OWNER), 50, 1);
    let (selected, template) = chain
        .select_template(key(&OWNER), &[later.clone(), first.clone()], 2, 0)
        .unwrap();
    assert_eq!(selected.transactions, vec![first, later]);
    assert_eq!(
        template,
        chain
            .template(key(&OWNER), selected.transactions, 0)
            .unwrap()
    );
}

#[test]
fn governed_fee_activation_reorg_and_database_reopen_are_exact() {
    fn copy(source: &Chain, target: &mut Chain, after: u64) {
        for height in after + 1..=source.tip_height() {
            let block = source
                .block(&source.hash_at_height(height).unwrap())
                .unwrap();
            target
                .submit(block.clone(), u64::from(block.header.timestamp))
                .unwrap();
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.sqlite");
    let c = chain_config(50);
    let mut main = Chain::open(&path, c.clone()).unwrap();
    for n in 0..100 {
        if matches!(main.tip_state().phase, Phase::Auction(_)) {
            break;
        }
        append(&mut main, vec![], n);
    }
    for n in 0..6 {
        append(&mut main, vec![], 100 + n);
    }
    curved::chain(&mut main, &OWNER);
    let s = main.tip_state();
    let tx = sign(
        (&c, s),
        &OWNER,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [15; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::MinerFeePercent,
                old: 50,
                new: 100,
            },
            support: 10u32.into(),
        },
        0,
        100,
        0,
        vec![],
    );
    append(&mut main, vec![tx], 200);
    for n in 0..100 {
        if main.tip_state().decision_id().is_some() {
            break;
        }
        append(&mut main, vec![], 201 + n);
    }
    let fork_height = main.tip_height();
    assert!(main.tip_state().decision_id().is_some());
    let mut fail = Chain::open(&dir.path().join("fail.sqlite"), c.clone()).unwrap();
    copy(&main, &mut fail, 0);
    let s = main.tip_state();
    let tx = sign(
        (&c, s),
        &OWNER,
        Operation::Deposit {
            amount: 1900u32.into(),

            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
        6,
        100,
        0,
        vec![],
    );
    append(&mut main, vec![tx], 300);
    for n in 0..100 {
        if matches!(main.tip_state().phase, Phase::Auction(_)) {
            break;
        }
        append(&mut main, vec![], 400 + n);
    }
    assert_eq!(main.tip_state().settings.miner_fee_percent, Some(100));
    let tx = transfer(&c, main.tip_state(), key(&OWNER), 17, 0);
    let q = fees::quote(&c, main.tip_state(), &tx).unwrap();
    assert_eq!(q.miner_fee, q.fee);
    assert!(q.revenue_fee.is_zero());
    append(&mut main, vec![tx], 600);
    let pass_root = main.tip_state().root();
    let mut saved = Chain::open(&dir.path().join("pass.sqlite"), c.clone()).unwrap();
    copy(&main, &mut saved, 0);
    while fail.chain_work() <= main.chain_work() {
        append(&mut fail, vec![], 700);
    }
    assert_eq!(fail.tip_state().settings.miner_fee_percent, Some(50));
    copy(&fail, &mut main, fork_height);
    assert_eq!(main.tip_state().root(), fail.tip_state().root());
    assert_ne!(main.tip_state().root(), pass_root);
    assert_eq!(main.tip_state().settings.miner_fee_percent, Some(50));
    while saved.chain_work() <= main.chain_work() {
        append(&mut saved, vec![], 800);
    }
    copy(&saved, &mut main, fork_height);
    assert_eq!(main.tip_state().root(), saved.tip_state().root());
    assert_eq!(main.tip_state().settings.miner_fee_percent, Some(100));
    let tip = main.tip_hash();
    let state = codec::encode(main.tip_state());
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.tip_hash(), tip);
    assert_eq!(codec::encode(reopened.tip_state()), state);
    reopened.tip_state().audit(&reopened.config).unwrap();
}
