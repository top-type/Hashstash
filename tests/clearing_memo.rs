//! Regression for audit F006 (node side): every mempool reselection reran
//! batch clearing under the node lock, so a relayed transaction that changes
//! no included order, such as a payment or a future-nonce trade, repeated the
//! full curve work of the pending trades. Block execution now clears through
//! `batch::clear_memoized`, which keeps recent results that spent curve work
//! by all of their inputs and returns them unchanged.
//!
//! The memo is process-wide, so this binary holds a single test.
use hashstash::{
    batch::{self, Order},
    config::Config,
    state::World,
    types::Amount,
};
use num_traits::One;

fn order(n: u32, amount: Amount) -> Order {
    let mut id = [0u8; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    Order { id, amount }
}

#[test]
fn repeated_clearing_reuses_the_memoized_result() {
    let c = Config::devnet();
    let bps = c.initial.max_price_change_bps;
    // A curved world and a deposit that breaks the bound: the budget search
    // spends tens of curve evaluations.
    let reserve = (Amount::one() << 300usize) + 137u32;
    let w = World {
        reserve: reserve.clone(),
        shares: reserve.clone(),
        curve_mass: &reserve * 2u32 + 1u32,
        ..World::default()
    };
    let buys = [order(1, reserve.clone()), order(2, &reserve / 7u32)];
    let sells = [order(3, &reserve / 11u32)];
    let (uncached, work) =
        batch::clear_with_work(&c, &w, &buys, &sells, bps, batch::CLEARING_WORK).unwrap();
    assert!(work > 8, "{work} curve evaluations");
    // One-order estimates use the plain clearing and never fill the memo.
    assert_eq!(batch::clear(&c, &w, &buys, &sells, bps).unwrap(), uncached);
    assert_eq!(batch::memo_peek(&c, &w, &buys, &sells, bps), None);

    let first = batch::clear_memoized(&c, &w, &buys, &sells, bps).unwrap();
    assert_eq!(first, uncached);
    assert_eq!(batch::memo_peek(&c, &w, &buys, &sells, bps), Some(first.clone()));
    assert_eq!(batch::clear_memoized(&c, &w, &buys, &sells, bps).unwrap(), first);

    // Any changed input is a different clearing.
    let mut other_world = w.clone();
    other_world.shares += 1u32;
    let mut other_config = c.clone();
    other_config.share_scale += 1u32;
    let reordered = [buys[1].clone(), buys[0].clone()];
    assert_eq!(batch::memo_peek(&c, &w, &buys, &sells, bps + 1), None);
    assert_eq!(batch::memo_peek(&c, &other_world, &buys, &sells, bps), None);
    assert_eq!(batch::memo_peek(&other_config, &w, &buys, &sells, bps), None);
    assert_eq!(batch::memo_peek(&c, &w, &reordered, &sells, bps), None);
    assert_eq!(batch::memo_peek(&c, &w, &buys[..1], &sells, bps), None);
    assert_eq!(batch::memo_peek(&c, &w, &sells, &buys[..1], bps), None);

    // A flat clearing spends no curve work and is not kept.
    let flat = World {
        curve_mass: reserve.clone(),
        ..w.clone()
    };
    batch::clear_memoized(&c, &flat, &buys, &sells, bps).unwrap();
    assert_eq!(batch::memo_peek(&c, &flat, &buys, &sells, bps), None);

    // The memo is bounded and keeps recently used entries: alternating with
    // the first clearing keeps it while many others pass through.
    for n in 0..64u32 {
        let small = [order(10 + n, &reserve / (100u32 + n))];
        let r = batch::clear_memoized(&c, &w, &small, &[], bps).unwrap();
        assert_eq!(batch::memo_peek(&c, &w, &small, &[], bps), Some(r.clone()));
        assert_eq!(r, batch::clear(&c, &w, &small, &[], bps).unwrap());
        assert_eq!(batch::clear_memoized(&c, &w, &buys, &sells, bps).unwrap(), first);
    }
    let oldest = [order(10, &reserve / 100u32)];
    assert_eq!(batch::memo_peek(&c, &w, &oldest, &[], bps), None);
    assert!(batch::memo_peek(&c, &w, &buys, &sells, bps).is_some());
}
