//! Cross-implementation clearing vectors (audit L016). The expected fills,
//! closing curve and curve-evaluation counts come from scripts/clearing_model.py,
//! an independent model of the normative clearing algorithm in
//! docs/SPECIFICATION.md ("Reference clearing algorithm"), not from this crate.
//! They cover the flat and curved paths, dust removal, the D/B cap of a
//! two-sided net buy, bound- and range-binding budget searches, full
//! redemption and clearings whose evaluation limit binds.
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
