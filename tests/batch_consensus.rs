use hashstash::{
    codec,
    config::Config,
    consensus, crypto,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const A: [u8; 32] = [101; 32];
const B: [u8; 32] = [102; 32];
const C: [u8; 32] = [103; 32];
fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn fixture() -> (Config, State) {
    let mut c = Config::testnet();
    c.initial.rest = 0;
    c.initial.lead = 0;
    c.initial.decision_blocks = 5;
    let mut s = consensus::execute(
        &c,
        &State::genesis(&c),
        &[0; 32],
        &key(&A),
        &0u32.into(),
        &[],
    )
    .unwrap();
    s.world.reserve = 1_000_000u32.into();
    s.world.curve_mass = 2_000_000u32.into();
    s.world.shares = 1_000_000u32.into();
    for secret in [&A, &B, &C] {
        s.world
            .put(
                key(secret),
                Account {
                    ordinary: 1_000_000u32.into(),
                    shares: if secret == &A {
                        1_000_000u32.into()
                    } else {
                        Amount::zero()
                    },
                    ..Account::default()
                },
                &c,
            )
            .unwrap();
    }
    s.issued = 4_000_000u32.into();
    s.audit(&c).unwrap();
    (c, s)
}
fn sign(s: &State, secret: &[u8; 32], nonce_offset: u64, operation: Operation) -> Transaction {
    crypto::sign(
        &TransactionBody {
            sender: key(secret),
            nonce: s.account(&key(secret), None).unwrap().nonce + nonce_offset,
            fee: 20u32.into(),
            anchor: [0; 32],
            expiry_blocks: s.height + 2,
            operation,
            data: vec![],
        },
        secret,
    )
    .unwrap()
}
fn buy(s: &State, amount: u32, outcome: Option<Outcome>) -> Operation {
    Operation::Deposit {
        amount: amount.into(),
        decision: s.decision_id(),
        outcome,
    }
}
fn sell(s: &State, amount: u32, outcome: Option<Outcome>) -> Operation {
    Operation::Redeem {
        shares: amount.into(),
        decision: s.decision_id(),
        outcome,
    }
}
fn run(c: &Config, s: &State, tx: &[Transaction]) -> (State, Vec<consensus::TradeFill>) {
    let result =
        consensus::execute_with_fills(c, s, &s.root(), &key(&A), &0u32.into(), tx).unwrap();
    result.0.audit(c).unwrap();
    result
}

#[test]
fn every_permutation_clears_identically_and_refunds_partial_inputs() {
    let (c, s) = fixture();
    let tx = [
        sign(&s, &B, 0, buy(&s, 800_000, None)),
        sign(&s, &C, 0, buy(&s, 400_000, None)),
        sign(&s, &A, 0, sell(&s, 20_000, None)),
    ];
    let (expected, mut fills) = run(&c, &s, &tx);
    fills.sort_by_key(|f| f.transaction_id);
    assert!(
        fills
            .iter()
            .any(|f| f.is_buy && !f.input_unfilled.is_zero())
    );
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let (actual, mut f) = run(&c, &s, &order.map(|i| tx[i].clone()));
        f.sort_by_key(|v| v.transaction_id);
        assert_eq!(actual.root(), expected.root());
        assert_eq!(f, fills);
    }
    for (secret, t) in [(&B, &tx[0]), (&C, &tx[1])] {
        let f = fills
            .iter()
            .find(|f| f.transaction_id == codec::transaction_id(t))
            .unwrap();
        let a = expected.account(&key(secret), None).unwrap();
        assert_eq!(
            a.ordinary,
            Amount::from(1_000_000u32) - &f.input_filled - 20u32
        );
        assert_eq!(a.shares, f.output);
    }
    assert!(
        &expected.world.curve_mass * &s.world.shares * 10_000u32
            <= &s.world.curve_mass * &expected.world.shares * 11_000u32
    );
}

#[test]
fn incoming_cash_and_newly_bought_stash_cannot_fund_same_block_orders() {
    let (c, s) = fixture();
    let transfer = sign(
        &s,
        &A,
        0,
        Operation::TransferExact {
            recipient: key(&B),
            amount: 500_000u32.into(),
        },
    );
    let overdraw = sign(&s, &B, 0, buy(&s, 1_200_000, None));
    for tx in [
        vec![transfer.clone(), overdraw.clone()],
        vec![overdraw, transfer],
    ] {
        assert!(consensus::execute(&c, &s, &s.root(), &key(&A), &0u32.into(), &tx).is_err());
    }
    let buys = sign(&s, &B, 0, buy(&s, 10_000, None));
    let sells = sign(&s, &B, 1, sell(&s, 1, None));
    assert!(consensus::execute(&c, &s, &s.root(), &key(&A), &0u32.into(), &[buys, sells]).is_err());
}

fn decision(c: &Config, s: &State) -> State {
    let proposal = sign(
        s,
        &A,
        0,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [44; 32],
            proposal: Proposal::Grant {
                payments: vec![GrantPayment {
                    recipient: key(&A),
                    amount: 500_000u32.into(),
                }],
            },
            support: 1u32.into(),
        },
    );
    let opened = run(c, s, &[proposal]).0;
    assert!(opened.decision_id().is_some());
    opened
}

#[test]
fn pass_and_fail_clear_independently_without_order_priority() {
    let (c, s) = fixture();
    let s = decision(&c, &s);
    let tx = [
        sign(&s, &B, 0, buy(&s, 800_000, Some(Outcome::Pass))),
        sign(&s, &C, 0, buy(&s, 500_000, Some(Outcome::Fail))),
        sign(&s, &A, 0, sell(&s, 10_000, Some(Outcome::Pass))),
    ];
    let expected = run(&c, &s, &tx).0;
    assert_eq!(
        expected.root(),
        run(&c, &s, &[tx[2].clone(), tx[1].clone(), tx[0].clone()])
            .0
            .root()
    );
    assert_ne!(
        expected.world.shares,
        expected.alternative.as_ref().unwrap().shares
    );
}

#[test]
fn governance_counts_leads_not_the_size_or_timestamp_of_a_price_spike() {
    for leads in [0, 1, 2, 3, 5] {
        let (c, s) = fixture();
        let mut s = decision(&c, &s);
        let opening = s.height;
        for observation in 0..5 {
            // Controlled valid parent states isolate the observation rule: one
            // huge lead still gets only one vote; equality gets none.
            let mass = s.world.curve_mass.clone();
            s.alternative.as_mut().unwrap().curve_mass = if observation < leads {
                mass * 1_000_000u32
            } else {
                mass
            };
            let before = s.clone();
            s = run(&c, &s, &[]).0;
            if observation < 4 {
                let Phase::Governance(d) = &s.phase else {
                    panic!("early resolution")
                };
                assert_eq!(d.leading_blocks, (observation + 1).min(leads));
            } else {
                assert!(s.decision_id().is_none());
                let expected = if leads > 2 {
                    before
                        .alternative
                        .unwrap()
                        .account(&key(&A), Some(before.last_epoch))
                        .unwrap()
                        .ordinary
                        + 500_000u32
                } else {
                    before.account(&key(&A), None).unwrap().ordinary
                };
                assert_eq!(s.account(&key(&A), None).unwrap().ordinary, expected);
            }
        }
        assert_eq!(s.height - opening, 5);
    }
}

#[test]
fn governance_counts_actual_price_leads_when_both_displayed_quotes_are_zero() {
    let (c, s) = fixture();
    let mut s = decision(&c, &s);
    let epoch = s.epoch();
    let supply = Amount::from(1u32) << 500usize;
    for world in [&mut s.world, s.alternative.as_mut().unwrap()] {
        let mut account = world.account(&key(&A), epoch).unwrap();
        account.shares = supply.clone();
        world.put(key(&A), account, &c).unwrap();
        world.shares = supply.clone();
    }
    s.alternative.as_mut().unwrap().curve_mass += 1u32;
    s.audit(&c).unwrap();
    assert!(s.world.quote(&c).is_zero());
    assert!(s.alternative.as_ref().unwrap().quote(&c).is_zero());
    for observed in 1..=4 {
        s = run(&c, &s, &[]).0;
        let Phase::Governance(d) = &s.phase else {
            panic!("early settlement")
        };
        assert_eq!(d.leading_blocks, observed);
    }
    let pass_cash = s.account(&key(&A), Some(Outcome::Pass)).unwrap().ordinary;
    s = run(&c, &s, &[]).0;
    assert!(s.alternative.is_none());
    assert_eq!(
        s.account(&key(&A), None).unwrap().ordinary,
        pass_cash + 500_000u32
    );
}

#[test]
fn closing_block_cannot_trade_in_an_already_settled_decision() {
    let (c, s) = fixture();
    let mut s = decision(&c, &s);
    for _ in 0..4 {
        s = run(&c, &s, &[]).0;
    }
    let tx = sign(&s, &B, 0, buy(&s, 100_000, Some(Outcome::Pass)));
    assert!(consensus::execute(&c, &s, &s.root(), &key(&A), &0u32.into(), &[tx]).is_err());
    assert!(run(&c, &s, &[]).0.decision_id().is_none());
}

#[test]
fn zero_price_bound_refunds_unmatched_principal_but_preserves_matching() {
    let (c, mut s) = fixture();
    // Model an already governed zero movement bound.
    s.settings.max_price_change_bps = 0;
    s.frozen.max_price_change_bps = 0;
    let tx = sign(&s, &B, 0, buy(&s, 100_000, None));
    let (result, fills) = run(&c, &s, &[tx]);
    assert_eq!(fills.len(), 1);
    assert!(fills[0].input_filled.is_zero() && fills[0].output.is_zero());
    assert_eq!(fills[0].input_unfilled, Amount::from(100_000u32));
    assert_eq!(
        result.account(&key(&B), None).unwrap().ordinary,
        Amount::from(999_980u32)
    );
    assert_eq!(
        result.account(&key(&B), None).unwrap().nonce,
        s.account(&key(&B), None).unwrap().nonce + 1
    );
    assert_eq!(result.world.curve_mass, s.world.curve_mass);
    assert_eq!(result.world.shares, s.world.shares);

    let tx = [
        sign(&s, &B, 0, buy(&s, 20_000, None)),
        sign(&s, &A, 0, sell(&s, 10_000, None)),
    ];
    let (result, fills) = run(&c, &s, &tx);
    assert!(
        fills
            .iter()
            .all(|fill| fill.input_unfilled.is_zero() && !fill.output.is_zero())
    );
    assert_eq!(result.world.curve_mass, s.world.curve_mass);
    assert_eq!(result.world.shares, s.world.shares);
}

#[test]
fn passed_price_bound_activates_after_rest_and_applies_to_the_next_block() {
    let (c, mut s) = fixture();
    s.settings.rest = 2 * s.settings.interval;
    s.frozen.rest = s.settings.rest;
    let proposal = sign(
        &s,
        &A,
        0,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [73; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::MaxPriceChangeBps,
                old: 1000,
                // Governance cannot pin prices at zero (audit F028): PASS
                // could then never lead again to undo it.
                new: 1,
            },
            support: 1u32.into(),
        },
    );
    s = run(&c, &s, &[proposal]).0;
    let start = s.height;
    let pass_buy = sign(&s, &B, 0, buy(&s, 800_000, Some(Outcome::Pass)));
    s = run(&c, &s, &[pass_buy]).0;
    for _ in 0..3 {
        s = run(&c, &s, &[]).0;
    }
    assert_eq!(s.height - start, 4);
    // Settlement begins this block; ordinary trades use its opening setting.
    let ordinary_buy = |state: &State| {
        sign(
            state,
            &C,
            0,
            Operation::Deposit {
                amount: 100_000u32.into(),
                decision: None,
                outcome: None,
            },
        )
    };
    let tx = ordinary_buy(&s);
    let (settled, fills) = run(&c, &s, &[tx]);
    assert!(fills[0].input_filled > Amount::zero());
    assert_eq!(settled.height - start, 5);
    assert_eq!(settled.settings.max_price_change_bps, 1000);
    assert!(
        matches!(&settled.phase, Phase::Rest(r) if r.pending == Some((Parameter::MaxPriceChangeBps, 1)))
    );
    s = settled;
    for expected_bound in [1000, 1] {
        let tx = ordinary_buy(&s);
        let (next, fills) = run(&c, &s, &[tx]);
        assert!(fills[0].input_filled > Amount::zero());
        assert_eq!(next.settings.max_price_change_bps, expected_bound);
        s = next;
    }
    assert_eq!(s.frozen.max_price_change_bps, 1);
    let tx = ordinary_buy(&s);
    let (_, fills) = run(&c, &s, &[tx]);
    assert!(fills[0].input_filled < Amount::from(1_000u32));
    assert!(fills[0].input_unfilled > Amount::from(99_000u32));
}
