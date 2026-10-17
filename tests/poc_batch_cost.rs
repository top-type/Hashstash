//! Regression benchmark for audit findings F006/F047 (formerly the H6 + M8
//! proof of concept): batch clearing on a *curved* world must have a
//! deterministic work bound.
//!
//! WHAT THE FINDING SAID
//! ---------------------
//! `batch::clear` prices a curved world (reserve R < curve mass M) whose ratio
//! is not a small rational with directed logarithms. Each comparison evaluated
//! two fixed 2048-bit, 683-term series; the root search had no progress
//! safeguard; and a batch breaking MaxPriceChangeBps re-ran the whole price
//! search inside a stalled regula falsi. One curved clear measured ~15 ms, a
//! price-cap-breaking deposit ~1.5 s and a near-2^512 quote ~1.2 s, none of it
//! bounded or charged.
//!
//! WHAT IS NOW ASSERTED
//! --------------------
//! Clearing spends at most `batch::CLEARING_WORK` curve evaluations per world
//! (`batch::clear_with_work` reports the deterministic count). Logarithm
//! precision follows the input width, one-sided batches evaluate their fixed
//! logarithm once, Newton probes are capped and start at the previous price,
//! the bracket starts at analytic bounds near the root, and the budget search
//! uses Illinois interpolation with geometric bisection. The scenarios below
//! assert work ceilings far below the limit, plus a generous wall-clock bound
//! that only catches order-of-magnitude regressions.
//!
//!   (a) flat world (R == M): no curve evaluation, for K = 1, 16, 128 orders;
//!   (b) curved world, K small deposits + redeems: one cheap price search;
//!   (c) curved ~2^511 world, one deposit breaking the default price bound;
//!   (d) curved 2^256 world, a single near-(2^512-1) deposit (the quote RPC);
//!   (e) curved ~2^511 world, a wide mixed batch breaking the bound;
//!   (f) flat world at price 3/2 and a zero bound: inexact sales are reduced
//!       while exact buys fill, still without curve evaluation.
//!
//! Run: `cargo test --release --test poc_batch_cost -- --nocapture`

use hashstash::{
    batch::{self, Order},
    config::Config,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};
use std::time::{Duration, Instant};

/// Generous per-clear wall-clock ceiling in release builds; the deterministic
/// work ceilings below are the precise assertions.
const WALL_CLOCK: Duration = Duration::from_secs(10);

fn world(reserve: Amount, shares: Amount, curve_mass: Amount) -> World {
    World {
        reserve,
        shares,
        curve_mass,
        ..World::default()
    }
}

/// A batch order with a unique 32-byte id derived from `n`.
fn order(n: u32, amount: Amount) -> Order {
    let mut id = [0u8; 32];
    id[0..4].copy_from_slice(&n.to_be_bytes());
    Order { id, amount }
}

fn pow2(bits: usize) -> Amount {
    Amount::one() << bits
}

/// Clear once and check the work ceiling, the wall-clock ceiling and that some
/// input filled. Returns the curve evaluations spent.
fn measured(
    label: &str,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    cap: u64,
    ceiling: u64,
) -> u64 {
    let c = Config::devnet();
    let started = Instant::now();
    let (result, work) =
        batch::clear_with_work(&c, w, buys, sells, cap, batch::CLEARING_WORK).unwrap();
    let elapsed = started.elapsed();
    let filled = result
        .buys
        .iter()
        .chain(&result.sells)
        .any(|f| !f.input.is_zero());
    println!(
        "{label:<44} {:>6} {:>10.3} {:>6}",
        buys.len() + sells.len(),
        elapsed.as_secs_f64() * 1000.0,
        work
    );
    assert!(filled, "{label}: nothing filled");
    assert!(work <= ceiling, "{label}: {work} curve evaluations > {ceiling}");
    assert!(work <= batch::CLEARING_WORK);
    assert!(elapsed < WALL_CLOCK, "{label}: {elapsed:?}");
    work
}

#[test]
fn batch_clearing_work_is_bounded_on_curved_worlds() {
    let cap = Config::devnet().initial.max_price_change_bps;
    println!(
        "\n{:<44} {:>6} {:>10} {:>6}",
        "scenario", "orders", "wall (ms)", "work"
    );

    // (a) Flat worlds use the exact flat price: no curve evaluation at all.
    let base = pow2(256);
    let w = world(base.clone(), base.clone(), base);
    for k in [1u32, 16, 128] {
        let buys: Vec<Order> = (0..k).map(|n| order(n, 1_000_000u32.into())).collect();
        assert_eq!(measured("(a) flat 2^256", &w, &buys, &[], u64::MAX, 0), 0);
    }

    // (b) curve_mass = 2R+1 has no small reduced ratio, so the logarithm path
    // runs. The opening marginal price bounds the root tightly for small net
    // trades, so the search needs a handful of evaluations for any K.
    let reserve = pow2(256);
    let w = world(reserve.clone(), reserve.clone(), &reserve * 2u32 + 1u32);
    for k in [1u32, 16, 128] {
        let buys: Vec<Order> = (0..k).map(|n| order(n, 1_000_000u32.into())).collect();
        let sells: Vec<Order> = (0..k)
            .map(|n| order(500_000 + n, 1_000_000u32.into()))
            .collect();
        let label = "(b) curved 2^256, deposits + redeems";
        measured(label, &w, &buys, &sells, u64::MAX, 16);
    }

    // (c) Depositing a whole reserve roughly doubles R, far past the default
    // 10% bound, so the budget search runs.
    let reserve = pow2(510) + 137u32;
    let w = world(reserve.clone(), reserve.clone(), &reserve * 2u32 + 1u32);
    let label = "(c) curved ~2^511, bound-breaking deposit";
    measured(label, &w, &[order(0, reserve)], &[], cap, 400);

    // (d) The quote RPC shape: one near-(2^512-1) deposit, beyond the numeric
    // range as well as the price bound.
    let reserve = pow2(256);
    let w = world(reserve.clone(), reserve.clone(), &reserve * 2u32 + 1u32);
    let buy = order(0, pow2(512) - 1u32);
    measured("(d) curved 2^256, near-2^512 deposit", &w, &[buy], &[], cap, 600);

    // (e) A wide mixed batch whose buys break the bound: both logarithms vary
    // with the probe at full 2048-bit precision.
    let reserve = pow2(510) + 137u32;
    let w = world(reserve.clone(), &reserve * 3u32, &reserve * 2u32 + 1u32);
    let buys: Vec<Order> = (0..64).map(|n| order(n, &reserve / (n + 3))).collect();
    let sells: Vec<Order> = (0..64)
        .map(|n| order(1_000 + n, &reserve / (n + 5)))
        .collect();
    measured("(e) curved ~2^511, wide mixed batch", &w, &buys, &sells, cap, 600);

    // (f) Odd sales raise a flat price of 3/2, so even a zero bound searches
    // the sale budget; buys of multiples of 3 are exact and fill in full.
    let reserve = pow2(256) * 3u32;
    let w = world(reserve.clone(), pow2(257), reserve);
    let buys: Vec<Order> = (0..16).map(|n| order(n, (3 * (n + 1)).into())).collect();
    let sells: Vec<Order> = (0..16).map(|n| order(100 + n, (2 * n + 1).into())).collect();
    let label = "(f) flat 3/2, inexact sales at a zero bound";
    assert_eq!(measured(label, &w, &buys, &sells, 0, 0), 0);
    let (r, _) =
        batch::clear_with_work(&Config::devnet(), &w, &buys, &sells, 0, batch::CLEARING_WORK)
            .unwrap();
    assert!(r.buys.iter().zip(&buys).all(|(f, o)| f.input == o.amount));
}
