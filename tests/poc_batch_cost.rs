//! Proof-of-concept benchmark for findings H6 + M8: unmetered, super-linear
//! batch-clearing cost on a *curved* world.
//!
//! WHAT THE FINDING SAYS
//! ---------------------
//! `batch::clear` (src/batch.rs:462) clears a world's amount-only orders by
//! calling `price` (src/batch.rs:114-295). On a *curved* world -- one where the
//! reserve R is strictly less than the curve mass M (the state a reserve grant
//! leaves behind, see tests/half_reserve_grant.rs) -- and whose reduced ratio
//! R/M does not simplify to a denominator <= 8 (so `math::small_ratio`,
//! src/math.rs:159, returns `None`), each price comparison runs the general
//! logarithm path `math::curve_log_evaluation` (src/math.rs:192). That evaluates
//! `log_atanh` (src/math.rs:43-76) as a 2048-bit fixed-point series of
//! LOG_TERMS = ceil(2048/3) = 683 terms (src/math.rs:14-15), twice per
//! comparison. `price` wraps those comparisons in a bisection whose width is
//! `scale = 1 << (2*bits + 32)` (src/batch.rs:126), i.e. ~2*bits iterations for
//! inputs of `bits` width (bits <= 512). So a single `clear` on a wide curved
//! world performs on the order of (2*512) * 2 * 683 big-integer multiplies.
//!
//! Two amplifiers make it worse:
//!   * Breaking the price-move limit (MaxPriceChangeBps) turns the single
//!     `candidate`/`price` evaluation into an *outer* budget bisection
//!     (src/batch.rs:539-567) that re-runs the whole curved `price` ~log2(budget)
//!     (~512) more times.
//!   * None of this cost is charged as transaction weight, and it is recomputed
//!     on every mempool selection pass (src/node.rs select_transactions), and the
//!     public `quote` RPC (src/node.rs:1500) runs it for only 8 work units
//!     (src/node.rs:3635) on deposit amounts up to 2^512-1 (bound at
//!     src/node.rs:1522). The RPC path is `quote` -> `preview_trade`
//!     (src/node.rs:1843) -> `batch::clear` with a single order and
//!     `cap = max_price_change_bps` (default 1000, src/config.rs:121).
//!
//! WHAT THIS BENCHMARK DOES
//! ------------------------
//! It calls the lowest public entry point, `hashstash::batch::clear`, directly
//! (exactly as `preview_trade`/the quote RPC and the mempool selector do) and
//! measures wall time with `std::time::Instant` for four scenarios:
//!   (a) flat world  (R == M): the cheap early-return baseline (src/batch.rs:116),
//!       for K = 1, 16, 128 orders;
//!   (b) curved world (R < M, interval path) with K small deposits + redeems,
//!       for K = 1, 16, 128 -- one expensive `price` per clear;
//!   (c) curved world with one deposit large enough to breach the default
//!       MaxPriceChangeBps, forcing the outer budget search;
//!   (d) curved world with a single near-(2^512-1) deposit -- the `quote` case.
//!
//! Curved worlds are built directly as `state::World` struct literals (every
//! field is public and `World: Default`), the same construction used throughout
//! tests/batch_clearing.rs; no consensus run and no `test-fixtures` feature is
//! required, so this test auto-discovers and needs NO Cargo.toml change. Using
//! `curve_mass = reserve*2 + 1` forces the general interval path: gcd(reserve,
//! 2*reserve+1) = 1, so the reduced denominator 2*reserve+1 is far above 8 and
//! `small_ratio` returns `None` (see the note at tests/dynamic_curve.rs:50).
//!
//! HOW TO RUN
//! ----------
//!   cargo test --release --test poc_batch_cost -- --nocapture
//!
//! Use --release: the unoptimized debug build is roughly an order of magnitude
//! slower (the release profile keeps overflow-checks on, so only opt-level
//! differs), so scenarios (c)/(d) can take tens of seconds unoptimized.
//! --nocapture lets the printed table through.
//!
//! HOW TO INTERPRET
//! ----------------
//! Compare the flat baseline (a) against the curved rows (b). The flat clear
//! returns in microseconds regardless of K; a single curved clear (b) costs
//! milliseconds -- that is one order's worth of work, unpriced and unbilled.
//! Rows (c) and (d) show the budget-search amplifier: a single attacker order
//! costs hundreds of milliseconds to seconds. Because the mempool selector
//! re-runs `clear` for every candidate and the `quote` RPC exposes (d) for 8
//! work units, an attacker can pin a validator/node CPU with a trickle of
//! cheap-to-submit orders or quote requests. The assertions here are
//! deliberately weak (each clear must simply return `Ok`); the numbers in the
//! printed table are the actual result of interest.

use hashstash::{
    batch::{self, Order},
    config::Config,
    state::World,
    types::Amount,
};
use num_traits::One;
use std::time::{Duration, Instant};

/// Build a world from raw reserve / shares / curve_mass. All other `World`
/// fields are irrelevant to `batch::clear`, which reads only these three.
fn world(reserve: Amount, shares: Amount, curve_mass: Amount) -> World {
    World {
        reserve,
        shares,
        curve_mass,
        ..World::default()
    }
}

/// A batch order with a unique 32-byte id derived from `n` (clear rejects
/// duplicate ids), carrying `amount` as its input.
fn order(n: u32, amount: Amount) -> Order {
    let mut id = [0u8; 32];
    id[0..4].copy_from_slice(&n.to_be_bytes());
    Order { id, amount }
}

/// 2^bits as an Amount.
fn pow2(bits: usize) -> Amount {
    Amount::one() << bits
}

/// Time a single `batch::clear` call; returns (ok?, filled-first-input, elapsed).
fn time_clear(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    cap: u64,
) -> (bool, Amount, Duration) {
    let started = Instant::now();
    let result = batch::clear(c, w, buys, sells, cap);
    let elapsed = started.elapsed();
    let ok = result.is_ok();
    // A representative "did it do anything" readout: the first filled input.
    let filled = result
        .ok()
        .and_then(|r| {
            r.buys
                .into_iter()
                .chain(r.sells)
                .map(|f| f.input)
                .find(|i| !is_zero(i))
        })
        .unwrap_or_else(Amount::default);
    (ok, filled, elapsed)
}

fn is_zero(a: &Amount) -> bool {
    a.bits() == 0
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn header() {
    println!(
        "\n{:<34} {:>6} {:>14} {:>7}",
        "scenario", "K", "wall (ms)", "ok"
    );
    println!("{}", "-".repeat(64));
}

fn row(label: &str, k: usize, elapsed: Duration, ok: bool) {
    println!("{:<34} {:>6} {:>14.3} {:>7}", label, k, ms(elapsed), ok);
}

#[test]
fn poc_batch_cost_timings() {
    let c = Config::devnet();
    let default_cap = c.initial.max_price_change_bps; // 1000 bps = 10%, the live default
    let mut all_ok = true;

    header();

    // (a) FLAT world baseline: reserve == curve_mass triggers the early return in
    // price (src/batch.rs:116), so cost stays flat regardless of K.
    {
        let base = pow2(256);
        let w = world(base.clone(), base.clone(), base.clone()); // R == M (flat)
        let per_order = Amount::from(1_000_000u64);
        for k in [1usize, 16, 128] {
            let buys: Vec<Order> = (0..k as u32).map(|n| order(n, per_order.clone())).collect();
            let (ok, _filled, elapsed) = time_clear(&c, &w, &buys, &[], u64::MAX);
            all_ok &= ok;
            row("(a) flat baseline, 2^256", k, elapsed, ok);
        }
    }

    // (b) CURVED world (R < M), interval/log path, K small deposits + redeems.
    // curve_mass = 2*reserve + 1 => reduced denominator 2*reserve+1 >> 8 =>
    // small_ratio == None => the 683-term log series runs on every comparison.
    // cap = u64::MAX so no budget search: this isolates ONE expensive `price`.
    {
        let reserve = pow2(256);
        let curve_mass = &reserve * 2u32 + 1u32;
        let shares = reserve.clone();
        let w = world(reserve, shares, curve_mass);
        let deposit = Amount::from(1_000_000u64); // tiny vs 2^256: still full cost
        let redeem = Amount::from(1_000_000u64); // share units, << total shares
        for k in [1usize, 16, 128] {
            let buys: Vec<Order> = (0..k as u32).map(|n| order(n, deposit.clone())).collect();
            let sells: Vec<Order> = (0..k as u32)
                .map(|n| order(500_000 + n, redeem.clone()))
                .collect();
            let (ok, _filled, elapsed) = time_clear(&c, &w, &buys, &sells, u64::MAX);
            all_ok &= ok;
            row("(b) curved 2^256, deposits+redeems", k, elapsed, ok);
        }
    }

    // (c) CURVED world, one deposit large enough to breach MaxPriceChangeBps,
    // forcing the OUTER budget bisection (src/batch.rs:539-567): the full curved
    // `price` is re-evaluated ~log2(budget) times. ~511-bit magnitudes, same
    // shape as tests/batch_clearing.rs::widest_general_curve_price_bound_and_zero_bound.
    {
        let reserve = pow2(510) + 137u32;
        let curve_mass = &reserve * 2u32 + 1u32; // ~2^511, <= 512 bits
        let shares = reserve.clone();
        let w = world(reserve.clone(), shares, curve_mass);
        // Depositing a whole reserve roughly doubles R: a >10% marginal move,
        // well past the 1000 bps default cap -> budget search engages.
        let buy = order(0, reserve);
        let (ok, filled, elapsed) = time_clear(&c, &w, std::slice::from_ref(&buy), &[], default_cap);
        all_ok &= ok;
        println!(
            "\n(c) curved ~2^511, one price-cap-breaking deposit (cap = {default_cap} bps):"
        );
        println!(
            "    wall = {:.3} ms   ok = {ok}   input_filled_nonzero = {}",
            ms(elapsed),
            !is_zero(&filled)
        );
    }

    // (d) CURVED world, single near-(2^512-1) deposit: the exact shape of the
    // public `quote` RPC (quote -> preview_trade -> batch::clear with one order,
    // cap = max_price_change_bps). Amount has 512 bits, the maximum c.check_amount
    // allows. reserve + cash overflows 512 bits, so within_range fails and the
    // budget search engages here too.
    {
        let reserve = pow2(256);
        let curve_mass = &reserve * 2u32 + 1u32;
        let shares = reserve.clone();
        let w = world(reserve, shares, curve_mass);
        let near_max = pow2(512) - 1u32; // 2^512 - 1, bits() == 512
        let buy = order(0, near_max);
        let (ok, filled, elapsed) = time_clear(&c, &w, std::slice::from_ref(&buy), &[], default_cap);
        all_ok &= ok;
        println!("\n(d) curved 2^256, single near-2^512-1 deposit (the quote RPC case):");
        println!(
            "    wall = {:.3} ms   ok = {ok}   input_filled_nonzero = {}",
            ms(elapsed),
            !is_zero(&filled)
        );
    }

    println!(
        "\nNote: (a)/(b) measure ONE batch clear. The real amplification is at the\n\
         node layer -- the mempool selector re-runs clear per candidate order and\n\
         the quote RPC exposes case (d) for 8 work units -- which this micro-\n\
         benchmark deliberately does not simulate.\n"
    );

    // Weak assertion only: the point is the printed timings, not any threshold.
    assert!(all_ok, "every batch::clear call should return Ok");
}
