//! Automatic outcome balances. All fixtures are local and isolated.
mod support;
use hashstash::{
    chain::Chain,
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const OWNER: [u8; 32] = [121; 32];
const SAVER: [u8; 32] = [122; 32];
const RECIPIENT: [u8; 32] = [123; 32];
const MINER: [u8; 32] = [124; 32];
const FINDER: [u8; 32] = [125; 32];
fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.initial.lead = 2 * c.initial.interval;
    c.initial.duration = 12 * c.initial.interval;
    c.initial.rest = 4 * c.initial.interval;
    c.validate().unwrap();
    c
}
fn step(c: &Config, s: &State, subsidy: u64, txs: &[Transaction]) -> State {
    let s = consensus::execute(c, s, &s.root(), &key(&OWNER), &subsidy.into(), txs).unwrap();
    s.audit(c).unwrap();
    s
}
fn sign(s: &State, secret: &[u8; 32], op: Operation) -> Transaction {
    support::sign_minimum(
        s,
        TransactionBody {
            chain_id: s.chain_id,
            sender: key(secret),
            nonce: s.account(&key(secret), None).unwrap().nonce,
            fee: 100u64.into(),
            expiry_height: s.height + 100,
            operation: op,
            data: vec![],
        },
        secret,
        0,
    )
}
fn apply(c: &Config, s: &mut State, secret: &[u8; 32], op: Operation) -> Amount {
    let tx = sign(s, secret, op);
    let fee = fees::quote(c, s, &tx).unwrap().fee;
    consensus::apply_transaction(c, s, &tx).unwrap();
    s.audit(c).unwrap();
    fee
}
fn rejected(c: &Config, s: &mut State, secret: &[u8; 32], op: Operation) {
    let tx = sign(s, secret, op);
    let before = codec::encode(s);
    assert!(consensus::apply_transaction(c, s, &tx).is_err());
    assert_eq!(
        codec::encode(s),
        before,
        "rejected transaction mutated state"
    );
}
fn transfer(recipient: PublicKey, amount: impl Into<Amount>) -> Operation {
    Operation::TransferExact {
        recipient,
        amount: amount.into(),
    }
}
fn buy(s: &State, outcome: Outcome, amount: impl Into<Amount>) -> Operation {
    Operation::Deposit {
        amount: amount.into(),
        min_shares: 1u32.into(),
        decision: s.decision_id(),
        outcome: Some(outcome),
    }
}
fn sell(s: &State, outcome: Outcome, shares: Amount) -> Operation {
    Operation::Redeem {
        shares,
        min_received: 1u32.into(),
        decision: s.decision_id(),
        outcome: Some(outcome),
    }
}
fn funded_curve(c: &Config) -> State {
    let mut s = step(c, &State::genesis(c), 1_000_000, &[]);
    let tx = sign(&s, &OWNER, transfer(key(&SAVER), 10_000u32));
    s = step(c, &s, 1, &[tx]);
    for (secret, amount) in [(&OWNER, 800_000u32), (&SAVER, 9_999u32)] {
        let tx = sign(
            &s,
            secret,
            Operation::Deposit {
                amount: amount.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
        );
        s = step(c, &s, 0, &[tx]);
    }
    s = step(c, &s, 1_000_000, &[]);
    for _ in 0..100 {
        if matches!(s.phase, Phase::Auction(_)) {
            return s;
        }
        s = step(c, &s, 1, &[]);
    }
    panic!("auction did not open")
}
fn activate(c: &Config, mut s: State) -> State {
    assert!(matches!(s.phase, Phase::Auction(_)));
    let tx = sign(
        &s,
        &OWNER,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [14; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::Duration,
                old: s.settings.duration,
                new: s.settings.duration * 2,
            },
            support: 10u32.into(),
        },
    );
    s = step(c, &s, 1, &[tx]);
    for _ in 0..100 {
        if s.decision_id().is_some() {
            return s;
        }
        s = step(c, &s, 1, &[]);
    }
    panic!("proposal did not activate")
}
fn active(c: &Config) -> State {
    activate(c, funded_curve(c))
}
fn account(s: &State, secret: &[u8; 32], outcome: Outcome) -> Account {
    s.account(&key(secret), Some(outcome)).unwrap()
}

#[test]
fn decision_opening_makes_full_balances_available_for_outcome_trades() {
    let c = config();
    let mut s = active(&c);
    let initial = account(&s, &OWNER, Outcome::Fail);
    assert_eq!(account(&s, &OWNER, Outcome::Pass), initial);

    let issued = s.issued.clone();
    let op = buy(&s, Outcome::Pass, 100_000u32);
    let fee = apply(&c, &mut s, &OWNER, op);
    let pass = account(&s, &OWNER, Outcome::Pass);
    let fail = account(&s, &OWNER, Outcome::Fail);
    assert_eq!(pass.ordinary, &initial.ordinary - 100_000u32 - &fee);
    assert_eq!(fail.ordinary, &initial.ordinary - &fee);
    assert!(pass.shares > initial.shares);
    assert_eq!(fail.shares, initial.shares);
    assert_eq!(pass.nonce, initial.nonce + 1);
    assert_eq!(fail.nonce, pass.nonce);
    assert_eq!(
        s.common_spendable(&key(&OWNER)),
        Some(pass.ordinary.clone())
    );
    assert_eq!(s.issued, issued);

    let burn = &pass.shares / 100u32;
    let reserve_before = s.alternative.as_ref().unwrap().reserve.clone();
    let op = sell(&s, Outcome::Pass, burn);
    let fee = apply(&c, &mut s, &OWNER, op);
    let payout = reserve_before - &s.alternative.as_ref().unwrap().reserve;
    assert_eq!(
        account(&s, &OWNER, Outcome::Pass).ordinary,
        pass.ordinary + payout - &fee
    );
    assert_eq!(
        account(&s, &OWNER, Outcome::Fail).ordinary,
        fail.ordinary - &fee
    );
    assert_eq!(s.issued, issued);
    rejected(
        &c,
        &mut s,
        &OWNER,
        Operation::TransferExact {
            recipient: [255; 32],
            amount: 1u32.into(),
        },
    );
    let malformed = Operation::Deposit {
        amount: 1u32.into(),
        min_shares: 0u32.into(),
        decision: None,
        outcome: None,
    };
    rejected(&c, &mut s, &OWNER, malformed);
}

#[test]
fn common_payments_and_fees_use_the_lesser_outcome_and_fail_atomically() {
    for lower in [Outcome::Pass, Outcome::Fail] {
        let c = config();
        let mut s = active(&c);
        let op = buy(&s, lower, 400_000u32);
        apply(&c, &mut s, &OWNER, op);
        let before_pass = account(&s, &OWNER, Outcome::Pass);
        let before_fail = account(&s, &OWNER, Outcome::Fail);
        let common = s.common_spendable(&key(&OWNER)).unwrap();
        assert_eq!(
            common,
            before_pass
                .ordinary
                .clone()
                .min(before_fail.ordinary.clone())
        );
        // The amount alone fits the poorer world, but its common fee does not.
        rejected(&c, &mut s, &OWNER, transfer(key(&RECIPIENT), common));
        assert!(s.account(&key(&RECIPIENT), None).is_none());
        assert!(s.account(&key(&RECIPIENT), Some(Outcome::Pass)).is_none());
        let fee = apply(&c, &mut s, &OWNER, transfer(key(&RECIPIENT), 50u32));
        for (outcome, before) in [(Outcome::Pass, before_pass), (Outcome::Fail, before_fail)] {
            let now = account(&s, &OWNER, outcome);
            assert_eq!(now.ordinary, before.ordinary - 50u32 - &fee);
            assert_eq!(now.nonce, before.nonce + 1);
            assert_eq!(account(&s, &RECIPIENT, outcome).ordinary, 50u32.into());
        }
        // Self-payments are neither a cross-world bridge nor new money.
        let pass = account(&s, &OWNER, Outcome::Pass);
        let fail = account(&s, &OWNER, Outcome::Fail);
        let fee = apply(&c, &mut s, &OWNER, transfer(key(&OWNER), 10u32));
        assert_eq!(
            account(&s, &OWNER, Outcome::Pass).ordinary,
            pass.ordinary - &fee
        );
        assert_eq!(
            account(&s, &OWNER, Outcome::Fail).ordinary,
            fail.ordinary - &fee
        );
        assert!(s.common_spendable(&key(&FINDER)).is_none());
    }
}

#[test]
fn fee_reserve_is_required_in_both_worlds_and_incoming_cash_recovers_it() {
    let c = config();
    let mut s = active(&c);
    let saver = account(&s, &SAVER, Outcome::Pass);
    assert!(saver.ordinary.is_zero() && saver.shares > 0u32.into());
    let op = sell(&s, Outcome::Pass, &saver.shares / 2u32);
    rejected(&c, &mut s, &SAVER, op);
    apply(&c, &mut s, &OWNER, transfer(key(&SAVER), 10u32));
    let op = sell(&s, Outcome::Pass, &saver.shares / 2u32);
    let fee = apply(&c, &mut s, &SAVER, op);
    let pass = account(&s, &SAVER, Outcome::Pass);
    let fail = account(&s, &SAVER, Outcome::Fail);
    assert!(pass.ordinary > fail.ordinary);
    assert_eq!(fail.ordinary, Amount::from(10u32) - &fee);
    assert_eq!(s.common_spendable(&key(&SAVER)), Some(fail.ordinary));
    // Spending all selected-world cash cannot leave its fee unpaid either.
    let op = buy(&s, Outcome::Pass, pass.ordinary);
    rejected(&c, &mut s, &SAVER, op);
}

#[test]
fn canonical_mining_credits_both_worlds_without_duplicate_issuance() {
    let c = config();
    let mut s = active(&c);
    let op = buy(&s, Outcome::Pass, 100_000u32);
    apply(&c, &mut s, &OWNER, op);
    let gap =
        account(&s, &OWNER, Outcome::Fail).ordinary - account(&s, &OWNER, Outcome::Pass).ordinary;
    let next = consensus::execute(&c, &s, &s.root(), &key(&MINER), &1000u32.into(), &[]).unwrap();
    next.audit(&c).unwrap();
    assert_eq!(next.issued, &s.issued + 1000u32);
    for outcome in [Outcome::Pass, Outcome::Fail] {
        let miner = account(&next, &MINER, outcome);
        assert_eq!(miner.ordinary, 1000u32.into());

        assert_eq!(miner.nonce, 0);
    }
    assert_eq!(
        account(&next, &OWNER, Outcome::Fail).ordinary
            - account(&next, &OWNER, Outcome::Pass).ordinary,
        gap
    );
}

#[test]
fn selected_world_settles_directly_and_next_decision_clones_it_again() {
    for winner in [Outcome::Pass, Outcome::Fail] {
        let c = config();
        let mut prior = funded_curve(&c);
        // Model a previously approved reserve-funded grant. Parameter decisions
        // are deliberately inert at the flat limit, so use an already curved state.
        prior.world.curve_mass = &prior.world.reserve * 2u32;
        let mut s = activate(&c, prior);
        // Buying only the chosen side raises its integrated price.
        let op = buy(&s, winner, 200_000u32);
        apply(&c, &mut s, &OWNER, op);
        let old_id = s.decision_id().unwrap();
        let end = match &s.phase {
            Phase::Governance(d) => d.started + d.duration,
            _ => unreachable!(),
        };
        while s.clock + s.settings.interval < end {
            s = step(&c, &s, 1, &[]);
        }
        let selected = account(&s, &OWNER, winner);
        let closing =
            consensus::execute(&c, &s, &s.root(), &key(&MINER), &1u32.into(), &[]).unwrap();
        closing.audit(&c).unwrap();
        assert!(
            matches!(&closing.phase, Phase::Rest(r) if r.pending.is_some() == (winner == Outcome::Pass))
        );
        let settled = closing.account(&key(&OWNER), None).unwrap();
        assert_eq!(settled.ordinary, selected.ordinary);
        assert_eq!(settled.shares, selected.shares);
        assert_eq!(settled.nonce, selected.nonce);

        assert_eq!(
            closing.common_spendable(&key(&OWNER)),
            Some(settled.ordinary)
        );
        let invalid = sign(&s, &OWNER, buy(&s, winner, 1u32));
        assert!(
            consensus::execute(&c, &s, &s.root(), &key(&MINER), &1u32.into(), &[invalid]).is_err()
        );
        s = closing;
        while !matches!(s.phase, Phase::Auction(_)) {
            s = step(&c, &s, 1, &[]);
        }
        let next = activate(&c, s);
        assert_ne!(next.decision_id(), Some(old_id));
        assert_eq!(
            account(&next, &OWNER, Outcome::Pass),
            account(&next, &OWNER, Outcome::Fail)
        );
    }
}

#[test]
fn audits_reject_divergent_nonces_but_allow_cash_differences() {
    let c = config();
    let mut s = active(&c);
    let op = buy(&s, Outcome::Pass, 100u32);
    apply(&c, &mut s, &OWNER, op);
    s.audit(&c).unwrap();
    let mut s = active(&c);
    let mut other = account(&s, &OWNER, Outcome::Pass);
    other.nonce += 1;
    s.alternative
        .as_mut()
        .unwrap()
        .put(key(&OWNER), other, &c)
        .unwrap();
    assert!(s.audit(&c).is_err());
    rejected(&c, &mut s, &OWNER, transfer(key(&RECIPIENT), 1u32));
}

#[test]
fn automatic_outcomes_grant_payment_reorg_and_reopen_are_exact() {
    fn append(chain: &mut Chain, txs: Vec<Transaction>, salt: u64) {
        let mut candidate = chain.template(key(&OWNER), txs, 0).unwrap();
        candidate.extranonce = salt.to_le_bytes();
        candidate.header.merkle_root = codec::merkle_root(&candidate).unwrap();
        let block = Chain::mine(candidate, 1_000_000).unwrap();
        assert!(
            chain
                .submit(block.clone(), u64::from(block.header.timestamp))
                .unwrap()
        );
        chain.tip_state().audit(&chain.config).unwrap();
    }
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
    let mut c = config();
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
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
    let deposit = sign(
        main.tip_state(),
        &OWNER,
        Operation::Deposit {
            amount: 1500u32.into(),
            min_shares: 1u32.into(),
            decision: None,
            outcome: None,
        },
    );
    append(&mut main, vec![deposit], 150);
    let s = main.tip_state();
    let tx = sign(
        s,
        &OWNER,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [19; 32],
            proposal: Proposal::Grant {
                payments: vec![hashstash::types::GrantPayment {
                    recipient: key(&RECIPIENT),
                    amount: 100u32.into(),
                }],
            },
            support: 10u32.into(),
        },
    );
    append(&mut main, vec![tx], 200);
    for n in 0..20 {
        if main.tip_state().decision_id().is_some() {
            break;
        }
        append(&mut main, vec![], 201 + n);
    }
    let fork_height = main.tip_height();
    let mut fail = Chain::open(&dir.path().join("fail.sqlite"), c.clone()).unwrap();
    copy(&main, &mut fail, 0);
    let s = main.tip_state();
    let tx = sign(s, &OWNER, buy(s, Outcome::Pass, 1900u32));
    append(&mut main, vec![tx], 300);
    let after_trade_pass = main
        .tip_state()
        .account(&key(&OWNER), Some(Outcome::Pass))
        .unwrap();
    let after_trade_fail = main
        .tip_state()
        .account(&key(&OWNER), Some(Outcome::Fail))
        .unwrap();
    assert_eq!(
        after_trade_fail.ordinary - after_trade_pass.ordinary,
        1900u32.into()
    );
    while main.tip_state().decision_id().is_some() {
        append(&mut main, vec![], 400);
    }
    assert_eq!(
        main.tip_state()
            .account(&key(&RECIPIENT), None)
            .unwrap()
            .ordinary,
        100u32.into()
    );
    let pass_root = main.tip_state().root();
    let mut saved_pass = Chain::open(&dir.path().join("pass.sqlite"), c.clone()).unwrap();
    copy(&main, &mut saved_pass, 0);
    while fail.chain_work() <= main.chain_work() {
        append(&mut fail, vec![], 500);
    }
    assert!(fail.tip_state().account(&key(&RECIPIENT), None).is_none());
    copy(&fail, &mut main, fork_height);
    assert_eq!(main.tip_state().root(), fail.tip_state().root());
    assert_ne!(main.tip_state().root(), pass_root);
    while saved_pass.chain_work() <= main.chain_work() {
        append(&mut saved_pass, vec![], 600);
    }
    copy(&saved_pass, &mut main, fork_height);
    assert_eq!(main.tip_state().root(), saved_pass.tip_state().root());
    let tip = main.tip_hash();
    let state = codec::encode(main.tip_state());
    drop(main);
    let reopened = Chain::open(&path, c).unwrap();
    assert_eq!(reopened.tip_hash(), tip);
    assert_eq!(codec::encode(reopened.tip_state()), state);
    reopened.tip_state().audit(&reopened.config).unwrap();
}
