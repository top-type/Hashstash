use hashstash::{
    batch::{self, Clearing, Order},
    config::Config,
    math,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};
use std::collections::BTreeMap;

fn curve(reserve: u64, shares: u64, mass: u64) -> World {
    World {
        reserve: reserve.into(),
        shares: shares.into(),
        curve_mass: mass.into(),
        ..World::default()
    }
}
fn order(id: u8, amount: u64) -> Order {
    Order {
        id: [id; 32],
        amount: amount.into(),
    }
}
fn next(w: &World, result: &Clearing) -> World {
    World {
        reserve: result.reserve.clone(),
        shares: result.shares.clone(),
        curve_mass: result.curve_mass.clone(),
        ..w.clone()
    }
}
fn conserved(w: &World, r: &Clearing) {
    let cash: Amount = r.buys.iter().map(|f| &f.input).sum();
    let paid: Amount = r.sells.iter().map(|f| &f.output).sum();
    let bought: Amount = r.buys.iter().map(|f| &f.output).sum();
    let sold: Amount = r.sells.iter().map(|f| &f.input).sum();
    assert_eq!(&w.reserve + cash, &r.reserve + paid);
    assert_eq!(&w.shares + bought, &r.shares + sold);
    assert_eq!(r.reserve.is_zero(), r.shares.is_zero());
    assert_eq!(r.reserve.is_zero(), r.curve_mass.is_zero());
    assert!(r.curve_mass >= r.reserve);
}
fn bounded(w: &World, r: &Clearing, bps: u64) {
    if r.shares.is_zero() {
        assert!(bps >= 10_000);
        return;
    }
    let after = &r.curve_mass * &w.shares * 10_000u32;
    assert!(after <= &w.curve_mass * &r.shares * (Amount::from(bps) + 10_000u32));
    if bps < 10_000 {
        assert!(after >= &w.curve_mass * &r.shares * (10_000 - bps));
    }
}

#[test]
fn exact_uniform_example_and_order_permutation() {
    let c = Config::devnet();
    let w = curve(100, 100, 200);
    let buys = [order(1, 21), order(2, 21)];
    let sells = [order(3, 5), order(4, 5)];
    // Individual seller cash has a half-atom remainder, retained in the reserve.
    let r = batch::clear(&c, &w, &buys, &sells, u64::MAX).unwrap();
    let reversed = batch::clear(
        &c,
        &w,
        &[buys[1].clone(), buys[0].clone()],
        &[sells[1].clone(), sells[0].clone()],
        u64::MAX,
    )
    .unwrap();
    let map = |r: &Clearing| {
        r.buys
            .iter()
            .chain(&r.sells)
            .map(|f| (f.id, (f.input.clone(), f.output.clone())))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(map(&r), map(&reversed));
    assert_eq!(
        (&r.reserve, &r.shares, &r.curve_mass),
        (&reversed.reserve, &reversed.shares, &reversed.curve_mass)
    );
    let exact = batch::clear(&c, &w, &[order(1, 42)], &[order(2, 10)], u64::MAX).unwrap();
    assert_eq!(exact.buys[0].output, 20u32.into());
    assert_eq!(exact.sells[0].output, 21u32.into());
    assert_eq!(
        (
            exact.reserve.clone(),
            exact.shares.clone(),
            exact.curve_mass.clone()
        ),
        (121u32.into(), 110u32.into(), 242u32.into())
    );
    conserved(&w, &r);
    conserved(&w, &exact);
}

#[test]
fn upward_and_downward_limits_restrict_actual_quote_and_refund_inputs() {
    let c = Config::devnet();
    let w = curve(10_000, 10_000, 20_000);
    for (buys, sells) in [
        (
            vec![order(1, 10_000), order(2, 10_000)],
            vec![order(3, 500)],
        ),
        (vec![order(1, 100)], vec![order(2, 4000), order(3, 4000)]),
    ] {
        let r = batch::clear(&c, &w, &buys, &sells, 1000).unwrap();
        conserved(&w, &r);
        bounded(&w, &r, 1000);
        assert!(r.buys.iter().chain(&r.sells).any(|f| !f.input.is_zero()));
        assert!(
            r.buys.iter().zip(&buys).any(|(f, o)| f.input < o.amount)
                || r.sells.iter().zip(&sells).any(|(f, o)| f.input < o.amount)
        );
        if r.buys.len() == 2 {
            assert_eq!(r.buys[0].input, r.buys[1].input);
        }
        if r.sells.len() == 2 {
            assert_eq!(r.sells[0].input, r.sells[1].input);
        }
    }
}

#[test]
fn zero_bound_allows_matching_but_never_a_price_move() {
    let c = Config::devnet();
    let w = curve(100, 100, 200);
    let r = batch::clear(&c, &w, &[order(1, 20)], &[order(2, 10)], 0).unwrap();
    assert_eq!(r.buys[0].output, 10u32.into());
    assert_eq!(r.sells[0].output, 20u32.into());
    assert_eq!(
        (r.reserve.clone(), r.shares.clone(), r.curve_mass.clone()),
        (w.reserve.clone(), w.shares.clone(), w.curve_mass.clone())
    );
    let unbalanced = batch::clear(&c, &w, &[order(1, 70)], &[], 0).unwrap();
    bounded(&w, &unbalanced, 0);
    conserved(&w, &unbalanced);
    assert!(unbalanced.buys[0].input.is_zero());
}

#[test]
fn flat_curve_exact_lots_bootstrap_and_empty_boundary() {
    let mut c = Config::devnet();
    c.share_scale = 100u32.into();
    let w = World::default();
    let start = batch::clear(&c, &w, &[order(1, 11)], &[], 0).unwrap();
    assert_eq!(start.shares, 1100u32.into());
    conserved(&w, &start);
    let w = next(&w, &start);
    let r = batch::clear(&c, &w, &[order(1, 4)], &[order(2, 255)], 0).unwrap();
    assert_eq!(r.sells[0].input, 200u32.into());
    assert_eq!(r.sells[0].output, 2u32.into());
    bounded(&w, &r, 0);
    conserved(&w, &r);
    let retained = batch::clear(&c, &w, &[], &[order(2, 1100)], 9999).unwrap();
    assert!(!retained.shares.is_zero());
    bounded(&w, &retained, 9999);
    let emptied = batch::clear(&c, &w, &[], &[order(2, 1100)], 10_000).unwrap();
    assert!(emptied.shares.is_zero());
    assert_eq!(emptied.sells[0].output, 11u32.into());
    conserved(&w, &emptied);
}

#[test]
fn pure_trades_match_directed_curve_and_cannot_profit_on_round_trip() {
    let c = Config::devnet();
    for w in [
        curve(100, 100, 200),
        curve(137, 125, 411),
        curve(137, 125, 413),
        curve(1000, 2000, 3000),
    ] {
        for deposit in [1u64, 3, 21, 53] {
            let r = batch::clear(&c, &w, &[order(1, deposit)], &[], u64::MAX).unwrap();
            conserved(&w, &r);
            if r.buys[0].input.is_zero() {
                continue;
            }
            let direct =
                math::dynamic_deposit_total(&w.reserve, &w.shares, &deposit.into(), &w.curve_mass)
                    .unwrap();
            assert_eq!(r.shares, direct);
            let n = next(&w, &r);
            let sale = Order {
                id: [2; 32],
                amount: r.buys[0].output.clone(),
            };
            let back = batch::clear(&c, &n, &[], &[sale], u64::MAX).unwrap();
            conserved(&n, &back);
            assert!(back.sells[0].output <= r.buys[0].input);
        }
    }
}

#[test]
fn splitting_does_not_award_rounding_dust_or_hash_priority() {
    let c = Config::devnet();
    let w = curve(1000, 1000, 2000);
    let merged = batch::clear(&c, &w, &[order(1, 42)], &[], u64::MAX).unwrap();
    let split = batch::clear(&c, &w, &[order(8, 21), order(9, 21)], &[], u64::MAX).unwrap();
    assert!(split.buys.iter().map(|f| &f.output).sum::<Amount>() <= merged.buys[0].output);
    let renamed = batch::clear(&c, &w, &[order(199, 21), order(17, 21)], &[], u64::MAX).unwrap();
    assert_eq!(split.buys[0].input, renamed.buys[0].input);
    assert_eq!(split.buys[0].output, renamed.buys[0].output);
    conserved(&w, &split);
}

#[test]
fn dust_and_full_redemption_never_strand_cash_without_stash() {
    let c = Config::devnet();
    for w in [curve(1, 1, 2), curve(3, 10, 6), curve(99, 100, 198)] {
        let a = &w.shares / 2u32;
        let b = &w.shares - &a;
        let sells: Vec<Order> = [a, b]
            .into_iter()
            .enumerate()
            .filter(|(_, n)| !n.is_zero())
            .map(|(i, amount)| Order {
                id: [i as u8 + 2; 32],
                amount,
            })
            .collect();
        let r = batch::clear(&c, &w, &[], &sells, u64::MAX).unwrap();
        conserved(&w, &r);
        for fill in r.buys.iter().chain(&r.sells) {
            assert!(fill.input.is_zero() || !fill.output.is_zero());
        }
    }
}

#[test]
fn wide_amounts_and_maximum_basis_points_use_integer_cross_products() {
    let c = Config::devnet();
    let reserve = Amount::one() << 510usize;
    let w = World {
        reserve: reserve.clone(),
        shares: reserve.clone(),
        curve_mass: &reserve * 2u32,
        ..World::default()
    };
    let buy = Order {
        id: [1; 32],
        amount: &reserve / 64u32,
    };
    let sell = Order {
        id: [2; 32],
        amount: &reserve / 128u32,
    };
    let r = batch::clear(&c, &w, &[buy], &[sell], u64::MAX).unwrap();
    conserved(&w, &r);
    bounded(&w, &r, u64::MAX);
}

#[test]
fn general_ratio_wide_price_limit_and_tiny_partial_fills() {
    let c = Config::devnet();
    let reserve = (Amount::one() << 80usize) + 137u32;
    let w = World {
        reserve: reserve.clone(),
        shares: reserve.clone(),
        curve_mass: &reserve * 2u32 + 1u32,
        ..World::default()
    };
    let r = batch::clear(
        &c,
        &w,
        &[Order {
            id: [1; 32],
            amount: reserve.clone(),
        }],
        &[Order {
            id: [2; 32],
            amount: &reserve / 128u32,
        }],
        1000,
    )
    .unwrap();
    conserved(&w, &r);
    bounded(&w, &r, 1000);
    for reserve in 1..=5u64 {
        for sold in 1..=reserve {
            let w = curve(reserve, reserve, reserve * 2);
            for cap in [0, 1, 1000, 9999, 10000] {
                let buys = [order(1, 1), order(2, 5)];
                let sells = [order(3, sold)];
                let r = batch::clear(&c, &w, &buys, &sells, cap).unwrap();
                conserved(&w, &r);
                bounded(&w, &r, cap);
                for (fill, order) in r.buys.iter().zip(&buys).chain(r.sells.iter().zip(&sells)) {
                    assert!(fill.input <= order.amount);
                }
            }
        }
    }
}

#[test]
fn joint_numeric_overflow_refunds_surplus_instead_of_rejecting_orders() {
    let c = Config::devnet();
    let reserve = Amount::one() << 510usize;
    let w = World {
        reserve: reserve.clone(),
        shares: reserve.clone(),
        curve_mass: &reserve * 3u32,
        ..World::default()
    };
    let orders = [
        Order {
            id: [1; 32],
            amount: &reserve / 4u32,
        },
        Order {
            id: [2; 32],
            amount: &reserve / 4u32,
        },
    ];
    let individually = batch::clear(&c, &w, &orders[..1], &[], u64::MAX).unwrap();
    assert_eq!(individually.buys[0].input, orders[0].amount);
    let jointly = batch::clear(&c, &w, &orders, &[], u64::MAX).unwrap();
    conserved(&w, &jointly);
    assert!(jointly.curve_mass.bits() <= 512);
    assert!(jointly.buys[0].input < orders[0].amount);
    assert_eq!(jointly.buys[0].input, jointly.buys[1].input);

    let max = (Amount::one() << 512usize) - 1u32;
    let w = World {
        reserve: 1u32.into(),
        shares: max.clone(),
        curve_mass: 1u32.into(),
        ..World::default()
    };
    let result = batch::clear(&c, &w, &[order(1, 1)], &[], u64::MAX).unwrap();
    conserved(&w, &result);
    assert!(result.buys[0].input.is_zero());

    let orders = [
        Order {
            id: [1; 32],
            amount: max.clone(),
        },
        Order {
            id: [2; 32],
            amount: max,
        },
    ];
    let w = World::default();
    let result = batch::clear(&c, &w, &orders, &[], 1000).unwrap();
    conserved(&w, &result);
    assert!(result.reserve.bits() <= 512 && result.shares.bits() <= 512);
    assert!(result.buys[0].input < orders[0].amount);
    assert_eq!(result.buys[0].input, result.buys[1].input);
}

#[test]
fn widest_general_curve_price_bound_and_zero_bound() {
    let c = Config::devnet();
    let reserve = (Amount::one() << 510usize) + 137u32;
    let w = World {
        reserve: reserve.clone(),
        shares: reserve.clone(),
        curve_mass: &reserve * 2u32 + 1u32,
        ..World::default()
    };
    for cap in [1000, 0] {
        let started = std::time::Instant::now();
        let result = batch::clear(
            &c,
            &w,
            &[Order {
                id: [1; 32],
                amount: reserve.clone(),
            }],
            &[Order {
                id: [2; 32],
                amount: &reserve / 128u32,
            }],
            cap,
        )
        .unwrap();
        eprintln!("512-bit general curve, cap {cap}: {:?}", started.elapsed());
        conserved(&w, &result);
        bounded(&w, &result, cap);
    }
}
