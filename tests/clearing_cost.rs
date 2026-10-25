//! Bent-curve batch clearing cost (soak finding S001) and a pinned reference
//! for its results.
//!
//! A world whose reserve is below its curve mass and whose ratio has no small
//! reduced form (any grant paid partly from reserve leaves one) clears through
//! directed logarithms. The soak measured 30 to 170 ms per clearing on 0.42.0,
//! whose logarithms always took 2048 bits; 0.43.0 sizes them to the inputs
//! (F006). Most of the remaining cost was the atanh series: a lower and an
//! upper chain of arbitrary-precision products, each term with a long division
//! by its small divisor. It now runs on 64-bit limbs with one product and one
//! division pass per term, derives the upper chain from the lower and divides
//! through reciprocals, with identical floors and ceilings: about twice as fast
//! at every magnitude.
//!
//! * `clearing_results_match_the_pinned_reference` clears a deterministic
//!   corpus (soak shapes, random worlds and batches, every price bound,
//!   exhausted work limits and the widest 2048-bit search) and compares a
//!   digest of every fill, closing curve and curve-evaluation count with the
//!   one the previous implementation produced. Matching implementations must
//!   reproduce clearing step for step, so this pins consensus.
//! * `bent_curve_soak_batches_stay_cheap` clears the soak shapes on every bent
//!   ratio with work ceilings and a generous wall-clock ceiling, so a return to
//!   wide logarithms or a longer search fails.
//! * `bench_clearing_cost` (ignored) prints the best time of each soak shape,
//!   of wider magnitudes up to 2^500 and of the work-capped 2048-bit search.
//!
//! Run: `cargo test --release --test clearing_cost -- --nocapture`, and for
//! the benchmark add `--ignored bench_clearing_cost --test-threads 1`.
use hashstash::{
    batch::{self, Clearing, Order},
    config::Config,
    crypto,
    state::World,
    types::Amount,
};
use num_traits::{One, Zero};
use std::time::{Duration, Instant};

/// Digest of the corpus below under the reference implementation (0.43.0 at
/// commit cbe0fe2).
const REFERENCE: &str = "50f85a21b8f62f460cfd1495de8da805b61ef522f33aae21b10cd4f2c8cbb91b";

/// Curve evaluations one soak batch may spend, and all of them together, at
/// the default 10% bound. The largest spends 63 and all of them 1,729.
const SOAK_WORK: u64 = 80;
const SOAK_TOTAL_WORK: u64 = 2_000;
/// All soak batches, each the best of a few runs in a release build. They
/// take about 7 ms together on a loaded development machine; the fixed
/// 2048-bit logarithms of 0.42.0 cost 30 to 170 ms for each one.
const SOAK_TIME: Duration = Duration::from_millis(300);

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

fn world(reserve: Amount, shares: Amount, curve_mass: Amount) -> World {
    World {
        reserve,
        shares,
        curve_mass,
        ..World::default()
    }
}

/// One clearing case: a world, its orders, a price bound and a work limit.
struct Case {
    w: World,
    buys: Vec<Order>,
    sells: Vec<Order>,
    cap: u64,
    limit: u64,
}

/// The batches of the soak repro (scratchpad zz_curve_cost): reserve at a
/// fraction of mass, from flat to 1%, a few ordinary orders, plus single
/// small orders. Mass and supply share one magnitude.
fn soak_batches(magnitude: &Amount, ratio: u32) -> Vec<(World, Vec<Order>, Vec<Order>)> {
    let mass = magnitude.clone();
    let shares = magnitude.clone();
    let w = world(&mass * ratio / 100u32, shares.clone(), mass.clone());
    let buys = |count: u32, divisor: u32| -> Vec<Order> {
        (0..count)
            .map(|i| order(i, &mass / divisor + i + 1u32))
            .collect()
    };
    let sells = |count: u32, divisor: u32| -> Vec<Order> {
        (0..count)
            .map(|i| order(100 + i, &shares / (2 * divisor) + i + 1u32))
            .collect()
    };
    vec![
        (w.clone(), buys(4, 100), vec![]),
        (w.clone(), vec![], sells(2, 100)),
        (w.clone(), buys(4, 100), sells(2, 100)),
        (w.clone(), buys(1, 100_000), vec![]),
        (w, vec![], sells(1, 100_000)),
    ]
}

fn soak_magnitudes() -> Vec<Amount> {
    vec![
        Amount::from(100_000u64),
        Amount::from(10_000_000u64),
        Amount::from(1_000_000_000_000u64),
    ]
}

/// A random nonempty world: flat, nearly flat, exact small ratio or general.
fn random_world(rng: &mut Rng, widest: u64) -> World {
    let reserve_bits = 1 + rng.below(widest);
    let reserve = rng.bits(reserve_bits);
    let shares_for = |rng: &mut Rng, reserve: &Amount| {
        let shift = rng.below(41) as usize;
        let shares = if rng.below(2) == 0 {
            reserve << shift
        } else {
            reserve >> shift
        };
        shares.max(Amount::one())
    };
    let curve_mass = match rng.below(5) {
        0 => reserve.clone(),
        1 => &reserve + 1u32,
        2 => {
            let v = 2 + rng.below(7) as u32;
            let u = 1 + rng.below(u64::from(v - 1)) as u32;
            let reserve = &reserve * u;
            return world(reserve.clone(), shares_for(rng, &reserve), &reserve / u * v);
        }
        _ => &reserve + &reserve * rng.below(7) + rng.bits(reserve_bits) % &reserve,
    };
    world(reserve.clone(), shares_for(rng, &reserve), curve_mass)
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

fn random_batch(rng: &mut Rng, w: &World) -> (Vec<Order>, Vec<Order>) {
    let count = [1, 2, 3, 8, 32][rng.below(5) as usize];
    let (mut buys, mut sells) = (Vec::new(), Vec::new());
    let mut offered = Amount::zero();
    for n in 0..count {
        if rng.below(2) == 0 {
            buys.push(order(n, amount_near(rng, &w.reserve)));
        } else {
            let amount = amount_near(rng, &w.shares).min(&w.shares - &offered);
            if !amount.is_zero() {
                offered += &amount;
                sells.push(order(n, amount));
            }
        }
    }
    (buys, sells)
}

/// The slowest consensus-reachable batch of tests/f006_worst_case.rs: it
/// spends the whole budget at 2048-bit precision.
fn exhausting() -> Case {
    let n = |digits: &str| Amount::parse_bytes(digits.as_bytes(), 10).unwrap();
    let w = world(
        n(
            "1046910856945786926135766216973404930149887412359447427230483204038670955895759989292925655395454035721195533867190631022567686945113448499898587751",
        ),
        n("2427005118627969996894781934602136172342131597135460309739253780490190456825445"),
        n(
            "3351951982485649274893506249551461531869841455148098344430890360930441007518444853385108568344480391590541069758393851473835465640169980512381401083406622",
        ),
    );
    let buys = [
        "166420478717023",
        "66219402273999340604678136594611511663873619119707011700950738620234912995",
        "42433232606505723169789018172126612642611119592702809503775861510868875168143705184574794711332178948680800341804008",
    ];
    let sells = [
        "1139270276131891503103229164446424354205988474586713072833019682092642678465916",
        "149061986698280255793054108398984965315087961377476286007443",
        "66056313732550255080236227521453",
        "63154186460603324916258013179930720772287638015910101158776909670693480336970",
        "7552639243972355830900883937253965197269262611722351917249569220384631828321",
        "52884316685951531731422149931260212826",
    ];
    Case {
        w,
        buys: buys
            .iter()
            .enumerate()
            .map(|(i, a)| order(i as u32, n(a)))
            .collect(),
        sells: sells
            .iter()
            .enumerate()
            .map(|(i, a)| order(100 + i as u32, n(a)))
            .collect(),
        cap: u64::MAX,
        limit: batch::CLEARING_WORK,
    }
}

fn corpus() -> Vec<Case> {
    let mut cases = Vec::new();
    let full = batch::CLEARING_WORK;
    for magnitude in soak_magnitudes() {
        for ratio in [100u32, 50, 20, 10, 5, 2, 1] {
            for (w, buys, sells) in soak_batches(&magnitude, ratio) {
                for cap in [1000, 679, 0, 9999, 10_000, u64::MAX] {
                    cases.push(Case {
                        w: w.clone(),
                        buys: buys.clone(),
                        sells: sells.clone(),
                        cap,
                        limit: full,
                    });
                }
            }
        }
    }
    let mut rng = Rng(0x5eed_c1ea_2026_0043);
    let caps = [0, 1, 50, 679, 1000, 9999, 10_000, u64::MAX];
    for widest in [24, 64, 128, 240, 510] {
        for _ in 0..60 {
            let w = random_world(&mut rng, widest);
            let (buys, sells) = random_batch(&mut rng, &w);
            let cap = caps[rng.below(caps.len() as u64) as usize];
            // Most cases use the consensus limit; some stop early, so the
            // exhausted fallback is pinned as well.
            let limit = if rng.below(4) == 0 {
                rng.below(40)
            } else {
                full
            };
            cases.push(Case {
                w,
                buys,
                sells,
                cap,
                limit,
            });
        }
    }
    cases.push(exhausting());
    cases
}

fn put(bytes: &mut Vec<u8>, n: &Amount) {
    let data = n.to_bytes_be();
    bytes.extend_from_slice(&(data.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&data);
}

fn record(bytes: &mut Vec<u8>, result: &anyhow::Result<(Clearing, u64)>) {
    match result {
        Ok((r, work)) => {
            bytes.push(1);
            bytes.extend_from_slice(&work.to_be_bytes());
            for fill in r.buys.iter().chain(&r.sells) {
                bytes.extend_from_slice(&fill.id);
                put(bytes, &fill.input);
                put(bytes, &fill.output);
            }
            for n in [&r.reserve, &r.shares, &r.curve_mass] {
                put(bytes, n);
            }
        }
        Err(error) => {
            bytes.push(0);
            bytes.extend_from_slice(error.to_string().as_bytes());
        }
    }
}

#[test]
fn clearing_results_match_the_pinned_reference() {
    let c = Config::devnet();
    let mut bytes = Vec::new();
    let started = Instant::now();
    let cases = corpus();
    let (mut spent, mut exhausted) = (0u64, 0usize);
    for case in &cases {
        let result =
            batch::clear_with_work(&c, &case.w, &case.buys, &case.sells, case.cap, case.limit);
        if let Ok((_, work)) = &result {
            spent += work;
            exhausted += usize::from(*work == case.limit);
        }
        record(&mut bytes, &result);
    }
    let digest = hex::encode(crypto::tagged_hash(
        "Hashstash/test/clearing-corpus",
        &bytes,
    ));
    println!(
        "{} clearings, {spent} curve evaluations, {exhausted} at their limit, {:.1} s: {digest}",
        cases.len(),
        started.elapsed().as_secs_f64()
    );
    assert!(exhausted >= 10, "the corpus must reach work limits");
    assert_eq!(digest, REFERENCE);
}

#[test]
fn bent_curve_soak_batches_stay_cheap() {
    let c = Config::devnet();
    let (mut total_work, mut most, mut total_time) = (0u64, 0u64, Duration::ZERO);
    for magnitude in soak_magnitudes() {
        for ratio in [50u32, 20, 10, 5, 2, 1] {
            for (w, buys, sells) in soak_batches(&magnitude, ratio) {
                let mut best = Duration::MAX;
                let mut work = 0;
                for _ in 0..5 {
                    let started = Instant::now();
                    work =
                        batch::clear_with_work(&c, &w, &buys, &sells, 1000, batch::CLEARING_WORK)
                            .unwrap()
                            .1;
                    best = best.min(started.elapsed());
                }
                assert!(
                    (1..=SOAK_WORK).contains(&work),
                    "R={} M={} {} buys {} sells: {work} curve evaluations",
                    w.reserve,
                    w.curve_mass,
                    buys.len(),
                    sells.len()
                );
                (total_work, most, total_time) =
                    (total_work + work, most.max(work), total_time + best);
            }
        }
    }
    println!(
        "soak batches: {total_work} curve evaluations, at most {most}, {:.2} ms",
        total_time.as_secs_f64() * 1000.0
    );
    assert!(
        total_work <= SOAK_TOTAL_WORK,
        "{total_work} curve evaluations"
    );
    assert!(total_time < SOAK_TIME, "{total_time:?}");
}

#[test]
#[ignore = "benchmark: run with --ignored --nocapture --test-threads 1"]
fn bench_clearing_cost() {
    let c = Config::devnet();
    let best = |w: &World, buys: &[Order], sells: &[Order], cap: u64, runs: usize| {
        let mut best = Duration::MAX;
        let mut work = 0;
        for _ in 0..runs {
            let started = Instant::now();
            work = batch::clear_with_work(&c, w, buys, sells, cap, batch::CLEARING_WORK)
                .unwrap()
                .1;
            best = best.min(started.elapsed());
        }
        (work, best.as_secs_f64() * 1000.0)
    };
    let kinds = [
        "4 buys",
        "2 sells",
        "4 buys + 2 sells",
        "1 small buy",
        "1 small sale",
    ];
    let mut magnitudes = soak_magnitudes();
    magnitudes.extend([100usize, 256, 500].map(|bits| (Amount::one() << bits) + 12_345u32));
    let mut total = 0.0;
    for magnitude in magnitudes {
        for ratio in [100u32, 50, 20, 10, 5, 2, 1] {
            for (kind, (w, buys, sells)) in kinds.iter().zip(soak_batches(&magnitude, ratio)) {
                let (work, ms) = best(&w, &buys, &sells, 1000, 5);
                total += ms;
                println!(
                    "{:>4} bits R/M {ratio:>3}% {kind:<17} {work:>5} evaluations {ms:>9.3} ms",
                    magnitude.bits()
                );
            }
        }
    }
    let case = exhausting();
    let (work, ms) = best(&case.w, &case.buys, &case.sells, case.cap, 1);
    println!("work-capped 2048-bit search: {work} evaluations {ms:.1} ms");
    println!("all shapes: {total:.1} ms");
}
