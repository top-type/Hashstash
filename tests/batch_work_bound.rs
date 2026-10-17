//! Deterministic work bound for batch clearing (audit F006/F047).
//!
//! Every clearing spends at most `batch::CLEARING_WORK` curve evaluations, and
//! ordinary batches over a wide range of curve shapes, sizes and price bounds
//! stay far below it, so the exhausted-budget fallback never decides them.
use hashstash::{
    batch::{self, Clearing, Order},
    config::Config,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};

/// Small deterministic xorshift generator; no external randomness.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn bits(&mut self, bits: u64) -> Amount {
        let mut value = Amount::zero();
        for _ in 0..bits.div_ceil(64) {
            value = (value << 64usize) + self.next();
        }
        let value = value >> (bits.div_ceil(64) * 64 - bits) as usize;
        value | (Amount::one() << (bits as usize - 1))
    }
}

fn order(id: u32, amount: Amount) -> Order {
    let mut key = [0u8; 32];
    key[..4].copy_from_slice(&id.to_be_bytes());
    Order { id: key, amount }
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

fn within_orders(r: &Clearing, buys: &[Order], sells: &[Order]) {
    for (fill, o) in r.buys.iter().zip(buys).chain(r.sells.iter().zip(sells)) {
        assert_eq!(fill.id, o.id);
        assert!(fill.input <= o.amount);
    }
}

/// A random nonempty world: flat, nearly flat, exact small ratio or general.
fn world(rng: &mut Rng) -> World {
    let reserve_bits = 1 + rng.below(240);
    let reserve = rng.bits(reserve_bits);
    let curve_mass = match rng.below(5) {
        0 => reserve.clone(),
        1 => &reserve + 1u32,
        2 => {
            let v = 2 + rng.below(7) as u32;
            let u = 1 + rng.below(u64::from(v - 1)) as u32;
            let reserve = &reserve * u;
            return World {
                shares: shares_for(rng, &reserve),
                curve_mass: &reserve / u * v,
                reserve,
                ..World::default()
            };
        }
        _ => &reserve + &reserve * rng.below(7) + rng.bits(reserve_bits) % &reserve,
    };
    World {
        shares: shares_for(rng, &reserve),
        reserve,
        curve_mass,
        ..World::default()
    }
}

fn shares_for(rng: &mut Rng, reserve: &Amount) -> Amount {
    let shift = rng.below(41) as usize;
    let shares = if rng.below(2) == 0 {
        reserve << shift
    } else {
        reserve >> shift
    };
    shares.max(Amount::one())
}

fn amount_near(rng: &mut Rng, base: &Amount) -> Amount {
    let shift = rng.below(48) as usize;
    let scaled = if rng.below(4) == 0 {
        base << rng.below(3) as usize
    } else {
        base >> shift
    };
    (scaled + rng.below(1000)).max(Amount::one())
}

#[test]
fn ordinary_batches_never_reach_the_clearing_work_limit() {
    let c = Config::devnet();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let caps = [0, 1, 50, 1000, 9999, 10_000, u64::MAX];
    let (mut most, mut total, mut cases) = (0u64, 0u64, 0u64);
    for case in 0..500u32 {
        let w = world(&mut rng);
        let count = [1, 2, 3, 8, 32, 100][rng.below(6) as usize];
        let (mut buys, mut sells) = (Vec::new(), Vec::new());
        let mut offered = Amount::zero();
        for n in 0..count {
            if rng.below(2) == 0 {
                buys.push(order(n, amount_near(&mut rng, &w.reserve)));
            } else {
                let amount = amount_near(&mut rng, &w.shares).min(&w.shares - &offered);
                if !amount.is_zero() {
                    offered += &amount;
                    sells.push(order(n, amount));
                }
            }
        }
        let cap = caps[rng.below(caps.len() as u64) as usize];
        let (r, work) =
            batch::clear_with_work(&c, &w, &buys, &sells, cap, batch::CLEARING_WORK).unwrap();
        conserved(&w, &r);
        bounded(&w, &r, cap);
        within_orders(&r, &buys, &sells);
        if w.reserve == w.curve_mass {
            assert_eq!(work, 0, "flat clearing needs no curve evaluation");
        }
        assert!(
            work * 3 <= batch::CLEARING_WORK * 2,
            "case {case}: {work} curve evaluations, R={} S={} M={} cap={cap} buys={:?} sells={:?}",
            w.reserve,
            w.shares,
            w.curve_mass,
            buys.iter().map(|o| o.amount.to_string()).collect::<Vec<_>>(),
            sells.iter().map(|o| o.amount.to_string()).collect::<Vec<_>>(),
        );
        (most, total, cases) = (most.max(work), total + work, cases + 1);
    }
    println!("random batches: {cases}, most work {most}, mean work {}", total / cases);
}

#[test]
fn exhausted_work_keeps_valid_conservative_results() {
    let c = Config::devnet();
    let reserve = (Amount::one() << 200usize) + 137u32;
    let w = World {
        reserve: reserve.clone(),
        shares: &reserve * 3u32,
        curve_mass: &reserve * 2u32 + 1u32,
        ..World::default()
    };
    let buys = [order(1, reserve.clone()), order(2, &reserve / 3u32)];
    let sells = [order(3, &reserve / 5u32), order(4, Amount::from(7u32))];
    let (full, full_work) =
        batch::clear_with_work(&c, &w, &buys, &sells, 1000, batch::CLEARING_WORK).unwrap();
    assert!(full_work < batch::CLEARING_WORK);
    for limit in [0, 1, 2, 3, 5, 8, 13, full_work / 2, full_work] {
        let (r, work) = batch::clear_with_work(&c, &w, &buys, &sells, 1000, limit).unwrap();
        assert!(work <= limit);
        conserved(&w, &r);
        bounded(&w, &r, 1000);
        within_orders(&r, &buys, &sells);
        // A shorter search keeps a wider proven bracket around the same price,
        // so the same inputs can only receive less.
        let fills = |r: &Clearing| r.buys.iter().chain(&r.sells).cloned().collect::<Vec<_>>();
        if fills(&r).iter().zip(fills(&full)).all(|(a, b)| a.input == b.input) {
            for (cut, whole) in fills(&r).iter().zip(fills(&full)) {
                assert!(cut.output <= whole.output);
            }
        }
        if limit == full_work {
            assert_eq!(r, full);
        }
    }
}
