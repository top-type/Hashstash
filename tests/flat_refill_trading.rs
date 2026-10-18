//! Regression for audit F005 (H5): once fee revenue refills a curved world so
//! that reserve == curve_mass, supply S is unrelated to the reserve R. Exact
//! reduced-price lots of R/gcd(R,S) cash or S/gcd(R,S) Stash then reached the
//! whole reserve or supply, so ordinary deposits and redemptions filled zero
//! while still paying fees. Flat orders now pay the least input for their
//! rounded-down output and stay tradeable at any reduced price. Sales then
//! raise such a price too, so a bound the sales alone break reduces the sales,
//! not every order.
use hashstash::{
    batch::{self, Clearing, Order},
    config::Config,
    consensus,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};

fn flat(reserve: &Amount, shares: &Amount) -> World {
    World {
        reserve: reserve.clone(),
        shares: shares.clone(),
        curve_mass: reserve.clone(),
        ..World::default()
    }
}

fn order(id: u8, amount: u64) -> Order {
    Order {
        id: [id; 32],
        amount: amount.into(),
    }
}

fn gcd(mut a: Amount, mut b: Amount) -> Amount {
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

fn ceil(n: &Amount, d: &Amount) -> Amount {
    (n + d - 1u32) / d
}

fn apply(w: &World, r: &Clearing) -> World {
    World {
        reserve: r.reserve.clone(),
        shares: r.shares.clone(),
        curve_mass: r.curve_mass.clone(),
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
    assert!(r.curve_mass >= r.reserve);
}

/// Every flat fill gets the full rounded-down output of its order at the exact
/// price M/S and pays only the least input for it; the price never falls and
/// rises by less than one input atom per order; the world stays flat.
fn exact_flat_fills(w: &World, r: &Clearing, buys: &[Order], sells: &[Order]) {
    conserved(w, r);
    let (m, s) = (&w.curve_mass, &w.shares);
    for (fill, o) in r.buys.iter().zip(buys) {
        assert_eq!(fill.output, &o.amount * s / m);
        assert_eq!(fill.input, ceil(&(&fill.output * m), s));
        assert!(fill.input <= o.amount);
    }
    for (fill, o) in r.sells.iter().zip(sells) {
        assert_eq!(fill.output, &o.amount * m / s);
        assert_eq!(fill.input, ceil(&(&fill.output * s), m));
        assert!(fill.input <= o.amount);
    }
    assert_eq!(r.curve_mass, r.reserve, "flat trading keeps the curve flat");
    let before = m * &r.shares;
    let after = &r.curve_mass * s;
    assert!(after >= before, "flat trading never lowers the price");
    // Reserve beyond exact backing: under one cash atom per buy and one share's
    // worth per sale.
    assert!(&after - &before < s * buys.len() as u32 + m * sells.len() as u32);
}

#[test]
fn drifted_flat_world_keeps_filling_ordinary_orders() {
    let mut scaled = Config::devnet();
    scaled.share_scale = 100u32.into();
    for c in [Config::devnet(), Config::testnet(), scaled] {
        let reserve = Amount::from(1_000_003u64);
        let genesis_shares = &reserve * &c.share_scale;
        // After curved trading the supply is unrelated to the reserve.
        let drifted_shares = &genesis_shares + Amount::one();
        assert_eq!(gcd(reserve.clone(), drifted_shares.clone()), Amount::one());
        let buys = [order(1, 1_000), order(2, 50_000)];
        let sells = [order(3, 1_000), order(4, 50_000)];
        for shares in [&genesis_shares, &drifted_shares] {
            let w = flat(&reserve, shares);
            let r = batch::clear(&c, &w, &buys, &sells, u64::MAX).unwrap();
            assert!(r.buys.iter().chain(&r.sells).all(|f| !f.output.is_zero()));
            exact_flat_fills(&w, &r, &buys, &sells);
            let (work, bounded) = (
                batch::clear_with_work(&c, &w, &buys, &sells, 1000, batch::CLEARING_WORK)
                    .unwrap()
                    .1,
                batch::clear(&c, &w, &buys, &sells, 1000).unwrap(),
            );
            assert_eq!(work, 0);
            assert_eq!(bounded, r);
        }
        // The genesis exchange rate has unit reduced numerator, so its trades
        // remain exact: flat governance prices cannot be nudged there.
        let w = flat(&reserve, &genesis_shares);
        let r = batch::clear(&c, &w, &buys, &sells, 0).unwrap();
        assert_eq!(&r.curve_mass * &w.shares, &w.curve_mass * &r.shares);
        assert!(r.buys.iter().chain(&r.sells).all(|f| !f.output.is_zero()));
    }
}

#[test]
fn zero_price_bound_on_a_drifted_flat_world_moves_nothing() {
    let c = Config::devnet();
    let reserve = Amount::from(1_000_003u64);
    let w = flat(&reserve, &(&reserve + 1u32));
    let buys = [order(1, 1_000), order(2, 50_000)];
    let sells = [order(3, 1_000), order(4, 50_000)];
    let r = batch::clear(&c, &w, &buys, &sells, 0).unwrap();
    conserved(&w, &r);
    assert_eq!(&r.curve_mass * &w.shares, &w.curve_mass * &r.shares);
    for (fill, o) in r.buys.iter().zip(&buys).chain(r.sells.iter().zip(&sells)) {
        assert!(fill.input <= o.amount);
    }
}

/// Small deterministic xorshift generator; no external randomness.
struct Rng(u64);
impl Rng {
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}

fn bounded(w: &World, r: &Clearing, bps: u64) {
    let after = &r.curve_mass * &w.shares * 10_000u32;
    assert!(after <= &w.curve_mass * &r.shares * (Amount::from(bps) + 10_000u32));
}

/// At a flat price whose reduced numerator and denominator both differ from
/// one, a sale also raises the price. Reducing only the buys could then never
/// meet a small upper bound, so every order, exact buys included, filled zero.
#[test]
fn inexact_sale_cannot_refuse_exact_buys_at_a_small_bound() {
    let c = Config::devnet();
    // Price 3/2: buys of a multiple of 3 hash and sales of an even amount of
    // Stash are exact. Selling 1 or 3 Stash raises the price by about 17 bps.
    let w = flat(&300u32.into(), &200u32.into());
    let buys = [order(1, 30), order(2, 3)];
    let sells = [order(3, 1), order(4, 3)];
    for bps in [0, 1, 10] {
        let r = batch::clear(&c, &w, &buys, &sells, bps).unwrap();
        conserved(&w, &r);
        bounded(&w, &r, bps);
        assert_eq!(r.curve_mass, r.reserve);
        for (fill, (input, output)) in r.buys.iter().zip([(30u32, 20u32), (3, 2)]) {
            assert_eq!(fill.input, Amount::from(input), "bps {bps}");
            assert_eq!(fill.output, Amount::from(output), "bps {bps}");
        }
        for (fill, o) in r.sells.iter().zip(&sells) {
            assert!(fill.input <= o.amount);
        }
    }
    // The mirror case already reduced the inexact buys and kept exact sales.
    let r = batch::clear(&c, &w, &[order(1, 2)], &[order(3, 2), order(4, 4)], 0).unwrap();
    assert_eq!(r.buys[0].output, Amount::zero());
    let paid: Amount = r.sells.iter().map(|f| &f.output).sum();
    assert_eq!(paid, Amount::from(9u32));
}

/// On random small flat worlds at non-unit prices and small bounds, an exact
/// side moves no price, so it fills completely whatever the other side's
/// rounding does. With neither side exact both may be reduced together. Every
/// result stays within the bound and conserves.
#[test]
fn exact_side_fills_whatever_the_other_sides_rounding_on_flat_worlds() {
    let c = Config::devnet();
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..600 {
        let (u, v) = (2 + rng.below(9), 2 + rng.below(9));
        if gcd(u.into(), v.into()) != Amount::one() {
            continue;
        }
        let k = 1 + rng.below(400);
        let w = flat(&(u * k).into(), &(v * k).into());
        let bps = rng.below(60);
        // 0: exact buys, 1: exact sales, 2: neither side exact.
        let exact = rng.below(3);
        let (mut buys, mut sells) = (Vec::new(), Vec::new());
        let mut offered = 0;
        for n in 0..1 + rng.below(4) as u8 {
            let any = 1 + rng.below(6 * u.max(v));
            buys.push(order(
                n,
                if exact == 0 {
                    u * (1 + rng.below(6))
                } else {
                    any
                },
            ));
        }
        for n in 0..1 + rng.below(4) as u8 {
            let any = 1 + rng.below(6 * u.max(v));
            let amount = if exact == 1 {
                v * (1 + rng.below(6))
            } else {
                any
            };
            if offered + amount < v * k {
                offered += amount;
                sells.push(order(100 + n, amount));
            }
        }
        let r = batch::clear(&c, &w, &buys, &sells, bps).unwrap();
        conserved(&w, &r);
        bounded(&w, &r, bps);
        assert_eq!(r.curve_mass, r.reserve);
        assert!(&r.curve_mass * &w.shares >= &w.curve_mass * &r.shares);
        let (side, fills, scale) = match exact {
            0 => (&buys, &r.buys, (&w.shares, &w.curve_mass)),
            1 => (&sells, &r.sells, (&w.curve_mass, &w.shares)),
            _ => continue,
        };
        for (fill, o) in fills.iter().zip(side) {
            assert_eq!(
                fill.input, o.amount,
                "R={} S={} bps={bps}",
                w.reserve, w.shares
            );
            assert_eq!(fill.output, &o.amount * scale.0 / scale.1);
        }
    }
}

#[test]
fn refill_after_reserve_grant_and_curved_trade_leaves_a_tradeable_flat_world() {
    let c = Config::devnet();
    let bps = c.initial.max_price_change_bps;
    // Genesis deposit, then a reserve-funded grant curves the world.
    let empty = World::default();
    let start = batch::clear(&c, &empty, &[order(1, 1_000_000)], &[], bps).unwrap();
    let mut w = apply(&empty, &start);
    consensus::grant_reserve(&c, &mut w, &100_000u32.into()).unwrap();
    assert!(w.reserve < w.curve_mass);
    // A trade on the curved world moves the supply off the reserve's lattice.
    let curved = batch::clear(&c, &w, &[order(2, 12_345)], &[], bps).unwrap();
    assert!(!curved.buys[0].output.is_zero());
    let mut w = apply(&w, &curved);
    // Fee revenue refills the reserve to the curve mass: flat again.
    w.revenue = &w.curve_mass - &w.reserve + 1u32;
    consensus::replenish_reserve(&c, &mut w).unwrap();
    assert_eq!(w.reserve, w.curve_mass);
    let lot = &w.reserve / gcd(w.reserve.clone(), w.shares.clone());
    assert!(
        lot > 50_000u32.into(),
        "the old reduced-price lot would refuse every order below"
    );
    let buys = [order(3, 1_000), order(4, 50_000)];
    let sells = [order(5, 1_000), order(6, 50_000)];
    let r = batch::clear(&c, &w, &buys, &sells, bps).unwrap();
    assert!(r.buys.iter().chain(&r.sells).all(|f| !f.output.is_zero()));
    exact_flat_fills(&w, &r, &buys, &sells);
    // A full holder can still exit when the bound allows emptying.
    let all = Order {
        id: [7; 32],
        amount: w.shares.clone(),
    };
    let exit = batch::clear(&c, &w, &[], &[all], 10_000).unwrap();
    assert!(exit.shares.is_zero() && exit.reserve.is_zero());
    assert_eq!(exit.sells[0].output, w.reserve);
}
