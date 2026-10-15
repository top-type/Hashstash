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

const ALICE: [u8; 32] = [61; 32];
const BOB: [u8; 32] = [62; 32];
const MINER: [u8; 32] = [63; 32];
fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn config() -> Config {
    let c = Config::testnet();
    c.validate().unwrap();
    c
}
fn sign(
    s: &State,
    secret: &[u8; 32],
    operation: Operation,
    fee: u64,
    extra: u64,
    offset: u64,
) -> Transaction {
    crypto::sign(
        &TransactionBody {
            data: Vec::new(),
            chain_id: s.chain_id,
            sender: key(secret),
            nonce: s.account(&key(secret), None).map_or(0, |a| a.nonce) + offset,
            fee: (fee + extra).into(),
            expiry_height: s.height + 10_000,
            operation,
        },
        secret,
    )
    .unwrap()
}
fn transfer(
    s: &State,
    recipient: PublicKey,
    amount: u64,
    fee: u64,
    extra: u64,
    offset: u64,
) -> Transaction {
    sign(
        s,
        &ALICE,
        Operation::TransferExact {
            recipient,
            amount: amount.into(),
        },
        fee,
        extra,
        offset,
    )
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
fn balance(s: &State, owner: &[u8; 32]) -> Amount {
    s.account(&key(owner), None).unwrap().ordinary
}
fn rejected_unchanged(c: &Config, s: &State, tx: &Transaction) {
    let mut copy = s.clone();
    assert!(consensus::apply_transaction(c, &mut copy, tx).is_err());
    assert_eq!(copy.root(), s.root());
}

#[test]
fn whole_exact_paid_fee_is_split_without_automatic_discount() {
    let c = config();
    let s = funded(&c);
    let tx = transfer(&s, key(&BOB), 100, 100_000, 7, 0);
    let quote = fees::quote(&c, &s, &tx).unwrap();
    assert_eq!(
        quote.weight,
        codec::encode(&tx).len() as u64 + fees::ACCOUNT_WEIGHT
    );
    assert_eq!(quote.account_creation_fee, 1u32.into());
    assert_eq!(quote.fee, 100_007u32.into());
    assert_eq!(quote.extra_fee, &quote.fee - &quote.minimum_fee);
    let next = step(&c, &s, &MINER, 11, &[tx]);
    assert_eq!(
        balance(&next, &ALICE),
        balance(&s, &ALICE) - 100u32 - &quote.fee
    );
    assert_eq!(balance(&next, &BOB), 100u32.into());
    assert_eq!(
        balance(&next, &MINER),
        balance(&s, &MINER) + 11u32 + &quote.miner_fee
    );
    assert_eq!(next.world.revenue, &s.world.revenue + &quote.revenue_fee);
    assert_eq!(next.issued, &s.issued + 11u32);
    assert_eq!(next.settings.minimum_fee_rate, s.settings.minimum_fee_rate);
    let repeated = transfer(&next, key(&BOB), 100, 100_000, 0, 0);
    let quote = fees::quote(&c, &next, &repeated).unwrap();
    assert!(quote.account_creation_fee.is_zero());
    assert_eq!(quote.weight, codec::encode(&repeated).len() as u64);
}

#[test]
fn increasing_governed_rate_rejects_underpayment_without_partial_state() {
    let c = config();
    let s = funded(&c);
    let tx = transfer(&s, key(&BOB), 100, 2, 0, 0);
    assert!(fees::quote(&c, &s, &tx).unwrap().fee <= tx.body.fee);
    let mut high = s.clone();
    high.settings.minimum_fee_rate = 1000;
    rejected_unchanged(&c, &high, &tx);
    assert!(high.account(&key(&BOB), None).is_none());
    let insufficient = transfer(&s, key(&BOB), 1_000_000, 100_000, 0, 0);
    rejected_unchanged(&c, &s, &insufficient);
    let below_minimum = transfer(&s, key(&BOB), 1, 1, 0, 0);
    rejected_unchanged(&c, &s, &below_minimum);
}

#[test]
fn account_creation_minimum_is_recomputed_but_exact_fee_stays_paid() {
    let c = config();
    let s = funded(&c);
    let pending = transfer(&s, key(&BOB), 100, 100, 0, 0);
    let original = fees::quote(&c, &s, &pending).unwrap();
    let earlier = sign(
        &s,
        &MINER,
        Operation::TransferExact {
            recipient: key(&BOB),
            amount: 1u32.into(),
        },
        100,
        0,
        0,
    );
    let mut copy = s.clone();
    consensus::apply_transaction(&c, &mut copy, &earlier).unwrap();
    let revised = fees::quote(&c, &copy, &pending).unwrap();
    assert_eq!(original.weight - revised.weight, fees::ACCOUNT_WEIGHT);
    assert_eq!(original.minimum_fee - &revised.minimum_fee, 1u32.into());
    assert_eq!(original.fee, revised.fee);
    let before = balance(&copy, &ALICE);
    consensus::apply_transaction(&c, &mut copy, &pending).unwrap();
    assert_eq!(balance(&copy, &BOB), 101u32.into());
    assert_eq!(balance(&copy, &ALICE), before - 100u32 - revised.fee);
    copy.audit(&c).unwrap();
}

#[test]
fn invalid_transfer_operations_are_rejected_atomically_and_direct_data_is_bound() {
    let c = config();
    let s = funded(&c);
    let tx = transfer(&s, key(&BOB), 1, 100, 0, 0);
    for operation in [
        Operation::TransferExact {
            recipient: key(&BOB),
            amount: 0u32.into(),
        },
        Operation::TransferExact {
            recipient: [255; 32],
            amount: 1u32.into(),
        },
    ] {
        let mut body = tx.body.clone();
        body.operation = operation;
        rejected_unchanged(&c, &s, &crypto::sign(&body, &ALICE).unwrap());
    }
    let mut changed = tx.clone();
    changed.body.data = vec![0, 255, 128];
    rejected_unchanged(&c, &s, &changed);
    let valid = crypto::sign(&changed.body, &ALICE).unwrap();
    let next = step(&c, &s, &MINER, 0, &[valid]);
    assert_eq!(balance(&next, &BOB), 1u32.into());
    assert_eq!(c.governance_parameters().len(), 8);
    assert!(
        c.governance_parameters()
            .contains(&Parameter::MinimumFeeRate)
    );
}

#[test]
fn empty_blocks_preserve_every_governed_rate_including_zero() {
    let mut c = config();
    for rate in [0, 1, 2, 1024, u64::MAX] {
        c.initial.minimum_fee_rate = rate;
        c.validate().unwrap();
        let mut s = State::genesis(&c);
        for _ in 0..4 {
            s = step(&c, &s, &ALICE, 100, &[]);
            assert_eq!(s.settings.minimum_fee_rate, rate);
        }
        let tx = transfer(&s, key(&BOB), 1, 0, 0, 0);
        let q = fees::quote(&c, &s, &tx).unwrap();
        assert_eq!(
            q.minimum_fee,
            (Amount::from(q.weight) * rate + 1023u32) / 1024u32
        );
    }
    c.initial.minimum_fee_rate = 0;
    c.validate().unwrap();
}

#[test]
fn new_miner_is_fee_exempt_at_maximum_governed_rate() {
    let c = config();
    let mut s = funded(&c);
    s.settings.minimum_fee_rate = u64::MAX;
    s.frozen.minimum_fee_rate = u64::MAX;
    let next = step(&c, &s, &BOB, 1, &[]);
    assert_eq!(balance(&next, &BOB), 1u32.into());
    assert_eq!(next.world.revenue, s.world.revenue);
    assert_eq!(next.world.accounts.len(), s.world.accounts.len() + 1);
    let again = step(&c, &next, &BOB, 1, &[]);
    assert_eq!(again.world.accounts.len(), next.world.accounts.len());
    assert_eq!(again.settings.minimum_fee_rate, u64::MAX);
}

fn funded_curve(c: &Config) -> State {
    let mut s = step(c, &State::genesis(c), &ALICE, 1_000_000, &[]);
    let tx = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 999_900u32.into(),
            min_shares: 1u32.into(),
            decision: None,
            outcome: None,
        },
        100,
        0,
        0,
    );
    s = step(c, &s, &[65; 32], 0, &[tx]);
    for _ in 0..100 {
        if matches!(s.phase, Phase::Auction(_)) {
            return s;
        }
        s = step(c, &s, &[65; 32], 0, &[]);
    }
    panic!("auction did not open")
}

#[test]
fn redemption_can_pay_from_proceeds_when_sender_has_no_liquid_hash() {
    let c = config();
    let s = funded_curve(&c);
    assert!(balance(&s, &ALICE).is_zero());
    let shares = s.account(&key(&ALICE), None).unwrap().shares / 100u32;
    let tx = sign(
        &s,
        &ALICE,
        Operation::Redeem {
            shares,
            min_received: 1u32.into(),
            decision: None,
            outcome: None,
        },
        100,
        3,
        0,
    );
    let quote = fees::quote(&c, &s, &tx).unwrap();
    let next = step(&c, &s, &MINER, 0, &[tx]);
    assert!(!balance(&next, &ALICE).is_zero());
    assert_eq!(balance(&next, &MINER), quote.miner_fee);
}

fn decision(c: &Config, grant: bool) -> State {
    let mut s = funded_curve(c);
    s = step(c, &s, &ALICE, 1_000_000, &[]);
    let action = if grant {
        Proposal::Grant {
            payments: vec![hashstash::types::GrantPayment {
                recipient: key(&BOB),
                amount: 1_000u32.into(),
            }],
        }
    } else {
        Proposal::Parameter {
            parameter: Parameter::Interval,
            old: s.settings.interval,
            new: s.settings.interval * 2,
        }
    };
    let tx = sign(
        &s,
        &ALICE,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [5; 32],
            proposal: action,
            support: 10u32.into(),
        },
        100,
        0,
        0,
    );
    s = step(c, &s, &ALICE, 0, &[tx]);
    while !matches!(s.phase, Phase::Governance(_)) {
        s = step(c, &s, &ALICE, 0, &[]);
    }
    s
}

#[test]
fn conditional_trades_pay_one_common_fee_and_both_outcomes_preserve_account_state() {
    let c = config();
    let s = decision(&c, false);
    let id = s.decision_id().unwrap();
    let before = balance(&s, &ALICE);
    let tx = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 500u32.into(),
            min_shares: Amount::zero(),
            decision: Some(id),
            outcome: Some(Outcome::Pass),
        },
        100,
        3,
        0,
    );
    let quote = fees::quote(&c, &s, &tx).unwrap();
    let next = step(&c, &s, &MINER, 0, &[tx]);
    let fail = next.account(&key(&ALICE), Some(Outcome::Fail)).unwrap();
    let pass = next.account(&key(&ALICE), Some(Outcome::Pass)).unwrap();
    assert_eq!(fail.ordinary, before - &quote.fee);
    assert_eq!(pass.ordinary, &fail.ordinary - 500u32);
    assert_eq!(pass.nonce, fail.nonce);
    assert!(pass.shares > fail.shares);
    assert_eq!(
        next.account(&key(&MINER), Some(Outcome::Pass))
            .unwrap()
            .ordinary,
        quote.miner_fee
    );
    assert_eq!(
        next.account(&key(&MINER), Some(Outcome::Fail))
            .unwrap()
            .ordinary,
        quote.miner_fee
    );
}

#[test]
fn successful_grant_creates_recipient_even_when_minimum_rate_exceeds_grant_amount() {
    let c = config();
    let mut s = decision(&c, true);
    let id = s.decision_id().unwrap();
    let tx = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 100_000u32.into(),
            min_shares: Amount::zero(),
            decision: Some(id),
            outcome: Some(Outcome::Pass),
        },
        100,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[tx]);
    s.settings.minimum_fee_rate = 1_000_000;
    s.frozen.minimum_fee_rate = 1_000_000;
    while matches!(s.phase, Phase::Governance(_)) {
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    assert_eq!(balance(&s, &BOB), 1_000u32.into());
    assert_eq!(s.settings.minimum_fee_rate, 1_000_000);
}

fn append(chain: &mut Chain, txs: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(chain.template(key(&ALICE), txs, time).unwrap(), 1_000_000).unwrap();
    chain.submit(block.clone(), time as u64).unwrap();
    chain.tip_state().audit(&chain.config).unwrap();
    block
}
fn small_chain_config() -> Config {
    let mut c = config();
    c.initial.block_bytes = 65_536;
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c.validate().unwrap();
    c
}

#[test]
fn weighted_selection_reserves_miner_space_and_prefers_higher_exact_fee() {
    let c = small_chain_config();
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&dir.path().join("chain.sqlite"), c.clone()).unwrap();
    for _ in 0..4 {
        append(&mut chain, vec![]);
    }
    let s = chain.tip_state();
    let low = transfer(s, key(&BOB), 1, 2, 0, 0);
    let high = transfer(s, key(&BOB), 1, 7, 0, 0);
    let selected = chain
        .select_transactions(key(&MINER), &[low, high.clone()], 1)
        .unwrap();
    assert_eq!(selected.transactions, vec![high]);
    let batch: Vec<_> = (0..100u64)
        .map(|n| {
            let mut secret = [0u8; 32];
            secret[0] = 1;
            secret[31] = n as u8;
            transfer(s, key(&secret), 1, 2, 0, n)
        })
        .collect();
    let selected = chain.select_transactions(key(&MINER), &batch, 100).unwrap();
    assert!(!selected.transactions.is_empty() && selected.transactions.len() < batch.len());
    let sum: u64 = selected
        .transactions
        .iter()
        .map(|t| fees::quote(&c, s, t).unwrap().weight)
        .sum();
    assert!(sum + fees::ACCOUNT_WEIGHT <= c.initial.block_bytes);
    assert!(
        sum + fees::ACCOUNT_WEIGHT
            + fees::quote(&c, s, &batch[selected.transactions.len()])
                .unwrap()
                .weight
            > c.initial.block_bytes
    );
    let template = chain
        .template(
            key(&MINER),
            selected.transactions,
            chain.tip_block().header.timestamp + 1,
        )
        .unwrap();
    assert!(codec::body_size(&template).unwrap() < c.initial.block_bytes as usize);
    assert!(
        chain
            .template(key(&MINER), batch, chain.tip_block().header.timestamp + 1)
            .is_err()
    );
}

#[test]
fn reorg_and_database_replay_restore_fee_charges_and_created_accounts() {
    let c = small_chain_config();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.sqlite");
    let mut main = Chain::open(&path, c.clone()).unwrap();
    let mut alternate = Chain::open(&dir.path().join("fork.sqlite"), c.clone()).unwrap();
    for _ in 0..4 {
        let block = append(&mut main, vec![]);
        alternate
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
    }
    let s = main.tip_state();
    let txs: Vec<_> = (0..30u64)
        .map(|n| {
            let mut secret = [0u8; 32];
            secret[0] = 2;
            secret[31] = n as u8;
            transfer(s, key(&secret), 1, 2, 0, n)
        })
        .collect();
    let heavy = append(&mut main, txs);
    assert_eq!(main.tip_state().settings.minimum_fee_rate, 1);
    let empty = append(&mut alternate, vec![]);
    main.submit(empty.clone(), empty.header.timestamp as u64)
        .unwrap();
    assert_eq!(main.tip_hash(), codec::block_hash(&heavy));
    let winner = append(&mut alternate, vec![]);
    main.submit(winner.clone(), winner.header.timestamp as u64)
        .unwrap();
    assert_eq!(main.tip_state().settings.minimum_fee_rate, 1);
    assert_eq!(main.tip_state().root(), alternate.tip_state().root());
    assert_eq!(main.tip_state().world.accounts.len(), 1);
    let root = main.tip_state().root();
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.tip_state().root(), root);
    let mut altered = reopened.tip_state().clone();
    altered.settings.minimum_fee_rate += 1;
    assert_ne!(altered.root(), root);
}

#[test]
fn ordinary_heavy_transaction_queue_does_not_change_minimum_fee_rate() {
    let mut c = config();
    c.initial.block_bytes = 1_000_000;
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    let dir = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&dir.path().join("large-queue.sqlite"), c.clone()).unwrap();
    for _ in 0..8 {
        append(&mut chain, vec![]);
    }
    let s = chain.tip_state();
    let transactions: Vec<_> = (0..3000u64)
        .map(|nonce| transfer(s, key(&ALICE), 1, 1, 0, nonce))
        .collect();
    let started = std::time::Instant::now();
    let selection = chain
        .select_transactions(key(&ALICE), &transactions, 4096)
        .unwrap();
    assert_eq!(selection.transactions.len(), 3000);
    assert_eq!(selection.signatures_checked, 3000);
    assert_eq!(selection.execution_attempts, 3000);
    assert!(!selection.budget_exhausted);
    let weight: u64 = selection
        .transactions
        .iter()
        .map(|t| fees::quote(&c, s, t).unwrap().weight)
        .sum();
    assert!(weight > c.initial.block_bytes / 2 && weight < c.initial.block_bytes);
    append(&mut chain, selection.transactions);
    assert_eq!(chain.tip_state().settings.minimum_fee_rate, 1);
    eprintln!(
        "3000 ordinary transactions selected, mined, validated, and audited in {:?}",
        started.elapsed()
    );
}

#[test]
fn governed_capacity_change_applies_next_block_without_repricing_activation_transactions() {
    let c = config();
    let mut s = funded_curve(&c);
    s = step(&c, &s, &ALICE, 1_000_000, &[]);
    s = curved::state(&c, s, &ALICE);
    let old_limit = s.settings.block_bytes;
    let new_limit = old_limit / 2;
    let tx = sign(
        &s,
        &ALICE,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [12; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: old_limit,
                new: new_limit,
            },
            support: 10u32.into(),
        },
        100,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[tx]);
    while !matches!(s.phase, Phase::Governance(_)) {
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let id = s.decision_id().unwrap();
    let tx = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 100_000u32.into(),
            min_shares: Amount::zero(),
            decision: Some(id),
            outcome: Some(Outcome::Pass),
        },
        100,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[tx]);
    while matches!(s.phase, Phase::Governance(_)) {
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let Phase::Rest(rest) = &s.phase else {
        panic!("missing rest")
    };
    assert_eq!(rest.pending, Some((Parameter::BlockBytes, new_limit)));
    let activation = rest.until;
    while s.clock + s.settings.interval < activation {
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let transactions: Vec<_> = (0..10u64)
        .map(|n| {
            let mut secret = [0u8; 32];
            secret[0] = 3;
            secret[30..].copy_from_slice(&(n as u16).to_be_bytes());
            transfer(&s, key(&secret), 1, 100, 0, n)
        })
        .collect();
    let weight: u64 = transactions
        .iter()
        .map(|t| fees::quote(&c, &s, t).unwrap().weight)
        .sum();
    assert!(weight > new_limit && weight < old_limit);
    let activated = step(&c, &s, &ALICE, 0, &transactions);
    assert_eq!(activated.settings.block_bytes, new_limit);
    assert_eq!(activated.settings.minimum_fee_rate, 1);
    let mut too_many = transactions.clone();
    let nonce = activated.account(&key(&ALICE), None).unwrap().nonce;
    for (offset, tx) in too_many.iter_mut().enumerate() {
        tx.body.nonce = nonce + offset as u64;
        *tx = crypto::sign(&tx.body, &ALICE).unwrap();
    }
    // Recipients now exist, so make distinct new accounts to retain the weight.
    for (offset, tx) in too_many.iter_mut().enumerate() {
        let mut secret = [4u8; 32];
        secret[31] = offset as u8;
        tx.body.operation = Operation::TransferExact {
            recipient: key(&secret),
            amount: 1u32.into(),
        };
        *tx = crypto::sign(&tx.body, &ALICE).unwrap();
    }
    assert!(
        consensus::execute(
            &c,
            &activated,
            &activated.root(),
            &key(&ALICE),
            &0u32.into(),
            &too_many
        )
        .is_err()
    );
    let next = step(&c, &activated, &ALICE, 0, &[]);
    assert_eq!(next.settings.block_bytes, new_limit);
    assert_eq!(next.settings.minimum_fee_rate, 1);
}

#[test]
fn governed_minimum_rate_changes_only_after_rest_and_leaves_signed_fee_exact() {
    let c = config();
    let mut s = funded_curve(&c);
    s = step(&c, &s, &ALICE, 1_000_000, &[]);
    s = curved::state(&c, s, &ALICE);
    let propose = sign(
        &s,
        &ALICE,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [42; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::MinimumFeeRate,
                old: 1,
                new: 2,
            },
            support: 10u32.into(),
        },
        1,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[propose]);
    while s.decision_id().is_none() {
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let buy = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 100_000u32.into(),
            min_shares: 1u32.into(),
            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
        1,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[buy]);
    while s.decision_id().is_some() {
        assert_eq!(s.settings.minimum_fee_rate, 1);
        assert_eq!(s.frozen.minimum_fee_rate, 1);
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let until = match &s.phase {
        Phase::Rest(rest) => {
            assert_eq!(rest.pending, Some((Parameter::MinimumFeeRate, 2)));
            rest.until
        }
        _ => panic!("missing rest"),
    };
    while s.clock + s.settings.interval < until {
        assert_eq!(s.settings.minimum_fee_rate, 1);
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    let tx = transfer(&s, key(&BOB), 1, 2, 0, 0);
    assert_eq!(fees::quote(&c, &s, &tx).unwrap().minimum_fee, 2u32.into());
    let before = balance(&s, &ALICE);
    let activated = step(&c, &s, &MINER, 0, &[tx]);
    assert_eq!(activated.settings.minimum_fee_rate, 2);
    assert_eq!(activated.frozen.minimum_fee_rate, 2);
    assert_eq!(balance(&activated, &ALICE), before - 3u32);
    let tx = transfer(&activated, key(&[64; 32]), 1, 2, 0, 0);
    assert!(fees::quote(&c, &activated, &tx).unwrap().minimum_fee > tx.body.fee);
    rejected_unchanged(&c, &activated, &tx);
    let next = step(&c, &activated, &MINER, 0, &[]);
    assert_eq!(next.settings.minimum_fee_rate, 2);
}

#[test]
fn prepaid_grant_settlement_leaves_capacity_but_new_miner_still_counts() {
    let mut c = config();
    c.initial.block_bytes = 2048;
    c.validate().unwrap();
    let mut s = decision(&c, true);
    let buy = sign(
        &s,
        &ALICE,
        Operation::Deposit {
            amount: 100_000u32.into(),
            min_shares: 1u32.into(),
            decision: s.decision_id(),
            outcome: Some(Outcome::Pass),
        },
        2,
        0,
        0,
    );
    s = step(&c, &s, &ALICE, 0, &[buy]);
    loop {
        let Phase::Governance(d) = &s.phase else {
            panic!("early resolution")
        };
        if s.clock + s.settings.interval >= d.started + d.duration {
            break;
        }
        s = step(&c, &s, &ALICE, 0, &[]);
    }
    assert!(s.account(&key(&BOB), None).is_none());
    assert!(s.account(&key(&MINER), None).is_none());
    let payment = transfer(&s, key(&ALICE), 1, 2, 0, 0);
    // Grant work was prepaid. Only the new miner consumes mandatory capacity.
    let quote = fees::quote(&c, &s, &payment).unwrap();
    let both = step(&c, &s, &MINER, 1, std::slice::from_ref(&payment));
    assert_eq!(balance(&both, &BOB), 1_000u32.into());
    assert_eq!(balance(&both, &MINER), Amount::from(1u32) + quote.miner_fee);
    // A separate new payment recipient plus the new miner still exceeds 2048.
    let new_account = transfer(&s, key(&[64; 32]), 1, 2, 0, 0);
    assert!(
        consensus::execute(
            &c,
            &s,
            &s.root(),
            &key(&MINER),
            &1u32.into(),
            &[new_account]
        )
        .is_err()
    );
    // A grant recipient can also mine; its new account counts only once as miner weight.
    let paid_miner = step(&c, &s, &BOB, 1, std::slice::from_ref(&payment));
    assert_eq!(
        balance(&paid_miner, &BOB),
        1_001u32 + fees::quote(&c, &s, &payment).unwrap().miner_fee
    );
    let existing = step(&c, &s, &ALICE, 1, &[payment]);
    assert_eq!(balance(&existing, &BOB), 1_000u32.into());
}
