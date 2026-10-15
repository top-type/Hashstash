//! Deterministic cross-platform vectors and timing for the general curve path.
//! Computes quotes only; does not open a wallet, network connection, or chain.
use hashstash::{crypto, math, types::Amount};
use num_traits::One;
use serde_json::json;
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let started = Instant::now();
    let mut transcript = Vec::new();
    for i in 1..=64u32 {
        let reserve = (Amount::one() << (64 + 6 * i as usize)) + i;
        let supply = &reserve * 1_000_000_000_000_000_000u64 + 17u32;
        let mass = &reserve * 3u32 + 2u32;
        let deposit = &reserve / (i + 2);
        let next_reserve = &reserve + &deposit;
        let next_supply = math::dynamic_deposit_total(&reserve, &supply, &deposit, &mass)?;
        let next_mass = math::deposit_mass(&reserve, &mass, &next_reserve)?;
        let returned = &next_reserve
            - math::dynamic_remaining_reserve(
                &next_reserve,
                &next_supply,
                &(&next_supply - &supply),
                &next_mass,
            )?;
        assert!(returned <= deposit);
        let payout = &reserve / (i + 3);
        let burn = math::dynamic_withdrawal_shares(&reserve, &supply, &payout, &mass)?;
        let retained = math::dynamic_remaining_reserve(&reserve, &supply, &burn, &mass)?;
        let before = math::dynamic_remaining_reserve(&reserve, &supply, &(&burn - 1u32), &mass)?;
        assert!(&reserve - &retained >= payout && &reserve - before < payout);
        for value in [next_supply, next_mass, returned, burn, retained] {
            transcript.extend(value.to_str_radix(16).as_bytes());
            transcript.push(b'\n');
        }
    }
    println!(
        "{}",
        json!({
            "cases": 64,
            "passed": true,
            "digest": hex::encode(crypto::sha256d(&transcript)),
            "elapsed_ms": started.elapsed().as_millis(),
        })
    );
    Ok(())
}
