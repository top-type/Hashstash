//! Cross-implementation clearing vectors (audit L016). The expected fills,
//! closing curve and curve-evaluation counts come from scripts/clearing_model.py,
//! an independent model of the normative clearing algorithm in
//! docs/SPECIFICATION.md ("Reference clearing algorithm"), not from this crate.
//! They cover the flat and curved paths, one- and two-sided batches, dust
//! removal, bound- and range-binding budget searches, full redemption and
//! clearings whose evaluation limit binds. A two-sided net buy's D/B cap
//! never binds, so no vector can exercise it; the last test checks that claim.
use hashstash::{
    batch::{self, Order},
    config::Config,
    state::World,
    types::Amount,
};
use serde_json::Value;

fn amount(v: &Value) -> Amount {
    v.as_str().unwrap().parse().unwrap()
}

fn orders(v: &Value, side: u8) -> Vec<Order> {
    v.as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let mut id = [side; 32];
            id[31] = i as u8;
            Order {
                id,
                amount: amount(a),
            }
        })
        .collect()
}

fn fills(v: &Value) -> Vec<(Amount, Amount)> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|pair| (amount(&pair[0]), amount(&pair[1])))
        .collect()
}

#[test]
fn clearing_matches_the_independent_model() {
    let data: Value = serde_json::from_str(include_str!("data/clearing-vectors.json")).unwrap();
    let vectors = data["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 20);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let mut c = Config::devnet();
        c.money_bits = v["config"]["money_bits"].as_u64().unwrap();
        c.share_bits = v["config"]["share_bits"].as_u64().unwrap();
        c.share_scale = amount(&v["config"]["share_scale"]);
        let w = World {
            reserve: amount(&v["world"]["reserve"]),
            shares: amount(&v["world"]["shares"]),
            curve_mass: amount(&v["world"]["mass"]),
            ..World::default()
        };
        let (buys, sells) = (orders(&v["buys"], 0xb0), orders(&v["sells"], 0x5e));
        let (result, work) = batch::clear_with_work(
            &c,
            &w,
            &buys,
            &sells,
            v["max_price_change_bps"].as_u64().unwrap(),
            v["work_limit"].as_u64().unwrap(),
        )
        .unwrap();
        let expected = &v["expected"];
        let got = |side: &[batch::Fill]| -> Vec<(Amount, Amount)> {
            side.iter()
                .map(|f| (f.input.clone(), f.output.clone()))
                .collect()
        };
        assert_eq!(got(&result.buys), fills(&expected["buys"]), "{name}: buys");
        assert_eq!(
            got(&result.sells),
            fills(&expected["sells"]),
            "{name}: sells"
        );
        assert_eq!(
            result.reserve,
            amount(&expected["reserve"]),
            "{name}: reserve"
        );
        assert_eq!(result.shares, amount(&expected["shares"]), "{name}: shares");
        assert_eq!(result.curve_mass, amount(&expected["mass"]), "{name}: mass");
        assert_eq!(
            work,
            expected["curve_evaluations"].as_u64().unwrap(),
            "{name}: curve evaluations"
        );
        // Identifiers never select a result: the fills follow order positions.
        for (fill, order) in result.buys.iter().zip(&buys) {
            assert_eq!(fill.id, order.id);
        }
    }
}

/// The specification lets an implementation omit a two-sided net buy's D/B
/// cap (audit L016): on the search's own grid, ceil(D*scale/B) is never below
/// the closing bound ceil(M(R+D)*scale/(RS+MB)), because D/B exceeds
/// M(R+D)/(RS+MB) exactly when D*S > B*M. Curved worlds (R < M) of widths up
/// to 192 bits, including the smallest net buy for each sale.
#[test]
fn the_d_over_b_cap_never_binds_a_net_buy() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut random = |bits: usize| -> Amount {
        let mut x = Amount::from(0u32);
        for _ in 0..bits.div_ceil(64) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            x = (x << 64usize) + seed;
        }
        x >> (bits.div_ceil(64) * 64 - bits)
    };
    let ceil = |n: &Amount, d: &Amount| (n + d - 1u32) / d;
    for i in 0..4_000usize {
        let width = |k: usize| 1 + (i * 37 + k * 101) % 192;
        let reserve = random(width(0)) + 1u32;
        let mass = &reserve + random(width(1)) + 1u32;
        let shares = random(width(2)) + 1u32;
        let sold = random(width(3)) % &shares + 1u32;
        // The least buy cash with cash*S > sold*M, plus a random excess on
        // all but every fourth case, which stays at the boundary.
        let excess = if i % 4 == 0 {
            Amount::from(0u32)
        } else {
            random(width(4))
        };
        let cash = &sold * &mass / &shares + 1u32 + excess;
        assert!(&cash * &shares > &sold * &mass);
        let bits = [&reserve, &shares, &mass, &cash, &sold]
            .into_iter()
            .map(|n| n.bits())
            .max()
            .unwrap() as usize;
        let scale = Amount::from(1u32) << (2 * bits + 32);
        let closing = ceil(
            &(&mass * (&reserve + &cash) * &scale),
            &(&reserve * &shares + &mass * &sold),
        );
        let cap = ceil(&(&cash * &scale), &sold);
        assert!(cap >= closing, "case {i}: the D/B cap binds");
    }
}
