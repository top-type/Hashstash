//! Audit PoC for H5 (flat-refill lot freeze) and M4 (empty FAIL world prices at zero).
//!
//! Run: `cargo test --release --test poc_reserve_governance -- --nocapture`
//! Each test asserts the vulnerable behaviour, so a PASS means the issue is present.
use hashstash::{
    batch::{self, Order},
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

/// H5: once revenue refills a curved world so reserve == curve_mass, `candidate()`
/// floors every order to a multiple of R/gcd(R,S) or S/gcd(R,S) (src/batch.rs:373-385).
/// After curved trading, S is no longer R * share_scale, so gcd is usually tiny and
/// one lot becomes the whole reserve or supply.
#[test]
fn h5_flat_refill_freezes_trading() {
    for c in [Config::devnet(), Config::testnet()] {
        let reserve = Amount::from(1_000_003u64);
        // Genesis-like flat world: S = R * share_scale, gcd = R, lot = 1 atom.
        let genesis_shares = &reserve * &c.share_scale;
        // Post-refill world: same reserve, supply drifted by curved trades.
        let drifted_shares = &genesis_shares + Amount::one();
        assert_eq!(gcd(reserve.clone(), drifted_shares.clone()), Amount::one());

        let buys = [order(1, 1_000), order(2, 50_000)];
        let sells = [order(3, 1_000), order(4, 50_000)];

        let healthy = batch::clear(&c, &flat(&reserve, &genesis_shares), &buys, &sells, u64::MAX)
            .unwrap();
        let frozen = batch::clear(&c, &flat(&reserve, &drifted_shares), &buys, &sells, u64::MAX)
            .unwrap();

        println!(
            "share_scale={} healthy: buy outputs {:?}, sell outputs {:?}",
            c.share_scale,
            healthy.buys.iter().map(|f| f.output.to_string()).collect::<Vec<_>>(),
            healthy.sells.iter().map(|f| f.output.to_string()).collect::<Vec<_>>(),
        );
        println!(
            "share_scale={} frozen:  buy outputs {:?}, sell outputs {:?}",
            c.share_scale,
            frozen.buys.iter().map(|f| f.output.to_string()).collect::<Vec<_>>(),
            frozen.sells.iter().map(|f| f.output.to_string()).collect::<Vec<_>>(),
        );
        assert!(healthy.buys.iter().all(|f| !f.output.is_zero()));
        // Vulnerable: every ordinary-size order fills nothing on the drifted flat world.
        assert!(frozen.buys.iter().chain(&frozen.sells).all(|f| f.output.is_zero()));
        assert_eq!(frozen.reserve, reserve);
    }
}

/// M4: `pass_beats_fail` (src/consensus.rs:759-768) treats an empty FAIL world as
/// price zero, so a PASS world holding a single atom leads every observation,
/// even with the largest possible margin.
#[test]
fn m4_empty_fail_world_loses_to_one_atom() {
    let c = Config::devnet();
    let one = Amount::one();
    let pass = flat(&one, &(&one * &c.share_scale));
    let fail = World::default();
    assert!(consensus::pass_beats_fail(&pass, &fail, 0));
    assert!(consensus::pass_beats_fail(&pass, &fail, u64::MAX));
    println!("1-atom PASS world beats empty FAIL world at any margin");
}
