//! Regressions for audit F111 and F047: batch clearing shares the documented
//! mass rounding rule with the math helpers, round trips in both directions
//! cannot profit, and an exact price root on the search grid of a general
//! curve costs a neighbour probe rather than a bisection of the bracket.
use hashstash::{
    batch::{self, Clearing, Order},
    config::Config,
    math,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};

fn curve(reserve: u64, shares: u64, mass: u64) -> World {
    World {
        reserve: reserve.into(),
        shares: shares.into(),
        curve_mass: mass.into(),
        ..World::default()
    }
}

fn order(id: u8, amount: Amount) -> Order {
    Order { id: [id; 32], amount }
}

fn next(w: &World, r: &Clearing) -> World {
    World {
        reserve: r.reserve.clone(),
        shares: r.shares.clone(),
        curve_mass: r.curve_mass.clone(),
        ..w.clone()
    }
}

/// Non-integer mass ratios, so floor and ceiling mass differ.
fn worlds() -> Vec<World> {
    vec![
        curve(137, 125, 411 + 2),
        curve(1_000, 2_000, 3_001),
        curve(997, 10_001, 7_919),
        curve(4_599, 1 << 20, 5_110),
        curve(1 << 40, 3 << 38, (1 << 41) + 12_345),
    ]
}

#[test]
fn consensus_mass_matches_the_math_helpers_in_both_directions() {
    let c = Config::devnet();
    for w in worlds() {
        for n in [1u64, 3, 21, 997] {
            let buy = batch::clear(&c, &w, &[order(1, n.into())], &[], u64::MAX).unwrap();
            if !buy.buys[0].input.is_zero() {
                let mass = math::deposit_mass(&w.reserve, &w.curve_mass, &buy.reserve).unwrap();
                assert_eq!(buy.curve_mass, mass);
            }
            let sale = Amount::from(n).min(&w.shares - 1u32);
            let sell = batch::clear(&c, &w, &[], &[order(2, sale)], u64::MAX).unwrap();
            if !sell.sells[0].input.is_zero() {
                let mass =
                    math::remaining_mass(&w.reserve, &w.curve_mass, &sell.reserve).unwrap();
                assert_eq!(sell.curve_mass, mass);
            }
        }
    }
}

#[test]
fn sell_then_buy_round_trips_through_clearing_cannot_profit() {
    let c = Config::devnet();
    for w in worlds() {
        for fraction in [1000u32, 37, 5, 2] {
            let sale = (&w.shares / fraction).max(Amount::one());
            let sell = batch::clear(&c, &w, &[], &[order(1, sale)], u64::MAX).unwrap();
            if sell.sells[0].input.is_zero() {
                continue;
            }
            let after = next(&w, &sell);
            // Spend every hash received back on the curve.
            let cash = sell.sells[0].output.clone();
            let buy = batch::clear(&c, &after, &[order(2, cash)], &[], u64::MAX).unwrap();
            assert!(
                buy.buys[0].output <= sell.sells[0].input,
                "sell/buy round trip gained Stash on {}:{}:{}",
                w.reserve,
                w.shares,
                w.curve_mass
            );
            assert!(buy.curve_mass >= buy.reserve);
        }
    }
}

#[test]
fn exact_grid_root_on_a_general_curve_needs_one_neighbour_probe() {
    let c = Config::devnet();
    // R/M = 9/10 has denominator ten, so the logarithm path runs. Depositing
    // 1023*R makes (R+D)/R = 2^10, so S'/S = 2^9 exactly and the price
    // 9207/2^m lies on the search grid, where directed bounds cannot decide.
    for m in [40usize, 120, 200] {
        let shares = Amount::one() << m;
        let w = World {
            reserve: 4_599u32.into(),
            shares: shares.clone(),
            curve_mass: 5_110u32.into(),
            ..World::default()
        };
        let deposit = Amount::from(1_023u32 * 4_599);
        let (r, work) = batch::clear_with_work(
            &c,
            &w,
            &[order(1, deposit)],
            &[],
            u64::MAX,
            batch::CLEARING_WORK,
        )
        .unwrap();
        let exact = &shares * 511u32;
        assert!(r.buys[0].output <= exact);
        assert!(&exact - &r.buys[0].output <= Amount::one());
        assert!(work <= 24, "2^{m}: {work} curve evaluations");
    }
}
