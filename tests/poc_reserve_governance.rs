//! Regression for audit M4 (an empty FAIL world priced at zero).
//!
//! Run: `cargo test --release --test poc_reserve_governance -- --nocapture`
//! The flat-refill lot freeze (H5) is covered with the batch clearing fix.
use hashstash::{config::Config, consensus, state::World, types::Amount};
use num_traits::One;

fn flat(reserve: &Amount, shares: &Amount) -> World {
    World {
        reserve: reserve.clone(),
        shares: shares.clone(),
        curve_mass: reserve.clone(),
        ..World::default()
    }
}

/// M4: `pass_beats_fail` treated an empty FAIL world as price zero, so a PASS
/// world holding a single bootstrap atom led every observation, even with the
/// largest margin. An empty world is now no observation in either direction.
#[test]
fn m4_empty_fail_world_does_not_lose_to_one_atom() {
    let c = Config::devnet();
    let one = Amount::one();
    let pass = flat(&one, &(&one * &c.share_scale));
    let fail = World::default();
    for margin in [0, 1, 10_000, u64::MAX] {
        assert!(!consensus::pass_beats_fail(&pass, &fail, margin));
        assert!(!consensus::pass_beats_fail(&fail, &pass, margin));
    }
    // Two nonempty worlds still compare exactly.
    let higher = World {
        curve_mass: 2u32.into(),
        ..pass.clone()
    };
    assert!(consensus::pass_beats_fail(&higher, &pass, 0));
}
