//! Integer proof of work, ASERT, and reserve conversion arithmetic.
use crate::{
    codec, crypto,
    types::{Amount, Header},
};
use anyhow::{Result, ensure};
use num_traits::{One, ToPrimitive, Zero};
use std::sync::OnceLock;

// All public curve inputs are at most 512 bits. The additional precision keeps
// errors in the directed bounds far below one output atom even after the largest
// supported exponent. These are consensus constants, not machine precision.
const CURVE_BITS: usize = 2048;
const LOG_TERMS: usize = CURVE_BITS.div_ceil(3);
const EXP_TERMS: usize = 512;
const EXP_SQUARES: usize = 10;

#[derive(Clone)]
struct Bounds {
    low: Amount,
    high: Amount,
}

fn ceil_div(n: &Amount, d: &Amount) -> Amount {
    assert!(!d.is_zero());
    if n.is_zero() {
        Amount::zero()
    } else {
        (n - 1u32) / d + 1u32
    }
}

fn curve_scale() -> Amount {
    Amount::one() << CURVE_BITS
}

// ln(x) = 2 * atanh((x-1)/(x+1)). The supplied z is in [0,1/3].
// After N terms the omitted tail is at most
// 9 / (4(2N+1)3^(2N+1)). Since 9>8 and 3N>=CURVE_BITS,
// one fixed-point unit bounds this tail. Each arithmetic operation below also
// rounds outwards, so the returned interval encloses the exact logarithm.
fn log_atanh(z_numerator: &Amount, z_denominator: &Amount) -> Bounds {
    if z_numerator.is_zero() {
        return Bounds {
            low: Amount::zero(),
            high: Amount::zero(),
        };
    }
    let scale = curve_scale();
    let numerator = z_numerator << CURVE_BITS;
    let z = Bounds {
        low: &numerator / z_denominator,
        high: ceil_div(&numerator, z_denominator),
    };
    let square = Bounds {
        low: (&z.low * &z.low) >> CURVE_BITS,
        high: ceil_div(&(&z.high * &z.high), &scale),
    };
    let mut power = z;
    let mut sum = Bounds {
        low: Amount::zero(),
        high: Amount::zero(),
    };
    for index in 0..LOG_TERMS {
        let divisor = Amount::from(2 * index + 1);
        sum.low += &power.low / &divisor;
        sum.high += ceil_div(&power.high, &divisor);
        power.low = (&power.low * &square.low) >> CURVE_BITS;
        power.high = ceil_div(&(&power.high * &square.high), &scale);
    }
    Bounds {
        low: sum.low << 1usize,
        high: (sum.high << 1usize) + 1u32,
    }
}

fn log_two() -> &'static Bounds {
    static VALUE: OnceLock<Bounds> = OnceLock::new();
    VALUE.get_or_init(|| log_atanh(&Amount::one(), &Amount::from(3u32)))
}

/// Enclose ln(numerator/denominator), with numerator >= denominator > 0.
fn log_ratio(numerator: &Amount, denominator: &Amount) -> Bounds {
    assert!(!denominator.is_zero() && numerator >= denominator);
    let mut shift = (numerator.bits() - denominator.bits()) as usize;
    let mut normalized_denominator = denominator << shift;
    if normalized_denominator > *numerator {
        shift -= 1;
        normalized_denominator >>= 1usize;
    }
    let mut result = log_atanh(
        &(numerator - &normalized_denominator),
        &(numerator + &normalized_denominator),
    );
    if shift != 0 {
        result.low += &log_two().low * shift;
        result.high += &log_two().high * shift;
    }
    result
}

fn scale_bounds(value: Bounds, numerator: &Amount, denominator: &Amount) -> Bounds {
    Bounds {
        low: value.low * numerator / denominator,
        high: ceil_div(&(value.high * numerator), denominator),
    }
}

/// Enclose exp(value), where 0<=value<=512. Divide by 1024 so x<=1/2,
/// evaluate the positive Taylor series, then square ten times. For 512 terms
/// the tail is below one fixed-point unit: the final 256 factorial factors
/// alone exceed 2^2048, in addition to x^513 <= 2^-513.
fn exp_bounds(value: &Bounds) -> Result<Bounds> {
    let scale = curve_scale();
    ensure!(
        value.high <= &scale * 512u32,
        "curve exponential outside bounded range"
    );
    let divisor = Amount::one() << EXP_SQUARES;
    let x = Bounds {
        low: &value.low >> EXP_SQUARES,
        high: ceil_div(&value.high, &divisor),
    };
    let mut sum = Bounds {
        low: scale.clone(),
        high: scale.clone(),
    };
    let mut term = sum.clone();
    for index in 1..=EXP_TERMS {
        let denominator = &scale * index;
        term.low = &term.low * &x.low / &denominator;
        term.high = ceil_div(&(&term.high * &x.high), &denominator);
        sum.low += &term.low;
        sum.high += &term.high;
    }
    sum.high += 1u32;
    for _ in 0..EXP_SQUARES {
        sum.low = (&sum.low * &sum.low) >> CURVE_BITS;
        sum.high = ceil_div(&(&sum.high * &sum.high), &scale);
    }
    Ok(sum)
}

fn check_dynamic_curve(reserve: &Amount, supply: &Amount, mass: &Amount) -> Result<()> {
    ensure!(
        !reserve.is_zero() && !supply.is_zero() && mass >= reserve,
        "invalid reserve curve"
    );
    ensure!(
        reserve.bits() <= 512 && supply.bits() <= 512 && mass.bits() <= 512,
        "reserve curve outside supported range"
    );
    Ok(())
}

// An exact fast path covers common rational curves and their perfect-power
// boundaries. Eight bounds intermediate integer powers below 8192 bits.
fn small_ratio(reserve: &Amount, mass: &Amount) -> Option<(u32, u32)> {
    let mut a = reserve.clone();
    let mut b = mass.clone();
    while !b.is_zero() {
        let remainder = &a % &b;
        a = b;
        b = remainder;
    }
    let numerator = (reserve / &a).to_u32()?;
    let denominator = (mass / a).to_u32()?;
    (denominator <= 8).then_some((numerator, denominator))
}

/// Conservative new total stash supply for a deposit. The instantaneous curve
/// exponent is reserve/mass. Flat curves use exact rational arithmetic; general
/// powers use a proven lower bound, never over-issuing stash.
pub fn dynamic_deposit_total(
    reserve: &Amount,
    supply: &Amount,
    deposit: &Amount,
    mass: &Amount,
) -> Result<Amount> {
    check_dynamic_curve(reserve, supply, mass)?;
    let next_reserve = reserve + deposit;
    ensure!(
        next_reserve.bits() <= 512,
        "deposit reserve outside supported range"
    );
    if deposit.is_zero() {
        return Ok(supply.clone());
    }
    let total = if mass == reserve {
        supply * &next_reserve / reserve
    } else if let Some((u, v)) = small_ratio(reserve, mass) {
        deposit_total(reserve, supply, deposit, u, v)
    } else {
        let exponent = scale_bounds(log_ratio(&next_reserve, reserve), reserve, mass);
        let factor = exp_bounds(&exponent)?;
        ((supply * factor.low) >> CURVE_BITS).max(supply.clone())
    };
    ensure!(total.bits() <= 512, "deposit stash outside supported range");
    Ok(total)
}

/// Conservative retained reserve after burning stash. Rounding is toward the
/// reserve, so a withdrawal never exceeds the exact power-curve quote.
pub fn dynamic_remaining_reserve(
    reserve: &Amount,
    supply: &Amount,
    burn: &Amount,
    mass: &Amount,
) -> Result<Amount> {
    check_dynamic_curve(reserve, supply, mass)?;
    ensure!(burn <= supply, "burn exceeds stash supply");
    if burn.is_zero() {
        return Ok(reserve.clone());
    }
    if burn == supply {
        return Ok(Amount::zero());
    }
    let remaining_supply = supply - burn;
    if mass == reserve {
        return Ok(ceil_div(&(reserve * remaining_supply), supply));
    }
    if let Some((u, v)) = small_ratio(reserve, mass) {
        return Ok(remaining_reserve(reserve, supply, burn, u, v));
    }
    let exponent = scale_bounds(log_ratio(supply, &remaining_supply), mass, reserve);
    // For any positive remaining stash, the exact retained reserve is positive.
    // Above this threshold it is below one atom; avoid evaluating huge powers.
    if exponent.low >= &log_two().high * 512u32 {
        return Ok(Amount::one());
    }
    let factor = exp_bounds(&exponent)?;
    Ok(ceil_div(&(reserve << CURVE_BITS), &factor.low).min(reserve.clone()))
}

/// Required burn for at least `target` payout under the conservative quote.
/// An analytical bound normally needs at most one atom of correction. Bounded
/// binary search is a defensive fallback and preserves exact quote semantics.
pub fn dynamic_withdrawal_shares(
    reserve: &Amount,
    supply: &Amount,
    target: &Amount,
    mass: &Amount,
) -> Result<Amount> {
    check_dynamic_curve(reserve, supply, mass)?;
    ensure!(
        !target.is_zero() && target <= reserve,
        "withdrawal amount outside reserve"
    );
    if target == reserve {
        return Ok(supply.clone());
    }
    if mass == reserve {
        return Ok(ceil_div(&(supply * target), reserve));
    }
    if let Some((u, v)) = small_ratio(reserve, mass) {
        return withdrawal_shares(reserve, supply, target, u, v);
    }
    let retained = reserve - target;
    let exponent = scale_bounds(log_ratio(reserve, &retained), reserve, mass);
    let factor = exp_bounds(&exponent)?;
    let remaining_supply = (supply << CURVE_BITS) / factor.high;
    let estimate = supply - remaining_supply;
    let pays = |burn: &Amount| -> Result<bool> {
        Ok(dynamic_remaining_reserve(reserve, supply, burn, mass)? <= retained)
    };
    if pays(&estimate)? {
        if estimate.is_one() || !pays(&(&estimate - 1u32))? {
            return Ok(estimate);
        }
    } else if estimate < *supply && pays(&(&estimate + 1u32))? {
        return Ok(estimate + 1u32);
    }
    let mut low = Amount::zero();
    let mut high = supply.clone();
    while &high - &low > Amount::one() {
        let middle = (&low + &high) >> 1usize;
        if pays(&middle)? {
            high = middle;
        } else {
            low = middle;
        }
    }
    Ok(high)
}

/// Scale mass after a buy, rounding down so reversing that buy cannot benefit
/// from a steeper curve caused only by rounding. Arguments: old R, old M, new R.
pub fn deposit_mass(reserve: &Amount, mass: &Amount, next_reserve: &Amount) -> Result<Amount> {
    ensure!(
        !reserve.is_zero() && mass >= reserve && next_reserve >= reserve,
        "invalid deposit mass"
    );
    ensure!(
        reserve.bits() <= 512 && mass.bits() <= 512 && next_reserve.bits() <= 512,
        "deposit mass outside supported range"
    );
    let result = mass * next_reserve / reserve;
    ensure!(result.bits() <= 512, "deposit mass exceeds supported range");
    Ok(result)
}

/// Scale mass after a sale, rounding up so reversing that sale cannot benefit
/// from a flatter curve caused only by rounding. Empty curves have zero mass.
pub fn remaining_mass(reserve: &Amount, mass: &Amount, next_reserve: &Amount) -> Result<Amount> {
    ensure!(
        !reserve.is_zero() && mass >= reserve && next_reserve <= reserve,
        "invalid remaining mass"
    );
    ensure!(
        reserve.bits() <= 512 && mass.bits() <= 512 && next_reserve.bits() <= 512,
        "remaining mass outside supported range"
    );
    Ok(ceil_div(&(mass * next_reserve), reserve))
}

pub fn target_from_bits(bits: u32) -> Result<Amount> {
    let size = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    ensure!(bits & 0x0080_0000 == 0, "negative compact target");
    ensure!(mantissa != 0, "zero compact target");
    let target = if size <= 3 {
        Amount::from(mantissa >> (8 * (3 - size)))
    } else {
        Amount::from(mantissa) << (8 * (size - 3)) as usize
    };
    ensure!(
        !target.is_zero() && target.bits() <= 256,
        "target outside positive uint256 range"
    );
    ensure!(
        bits_from_target(&target) == bits,
        "noncanonical compact target"
    );
    Ok(target)
}

/// Bitcoin GetCompact: discard low bytes, using one extra byte for the sign bit.
pub fn bits_from_target(target: &Amount) -> u32 {
    if target.is_zero() {
        return 0;
    }
    let mut size = target.bits().div_ceil(8) as u32;
    assert!(size <= 255, "target does not fit compact exponent");
    let mut mantissa = if size <= 3 {
        target.to_u32().unwrap() << (8 * (3 - size))
    } else {
        (target >> (8 * (size - 3)) as usize).to_u32().unwrap()
    };
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        size += 1;
    }
    (size << 24) | mantissa
}

/// Largest canonical compact target that fits a SHA256 digest.
pub const MAX_TARGET_BITS: u32 = 0x2100_ffff;

pub fn work(target: &Amount) -> Amount {
    (Amount::one() << 256usize) / (target + 1u32)
}

pub fn check_pow(header: &Header, target: &Amount) -> Result<()> {
    ensure!(
        target_from_bits(header.bits)? == *target,
        "header does not use required target"
    );
    let hash = crypto::sha256d(&codec::header_bytes(header));
    // Bitcoin interprets the raw digest as a little-endian uint256.
    ensure!(
        Amount::from_bytes_le(&hash) <= *target,
        "insufficient proof of work"
    );
    Ok(())
}

/// ASERT's exact integer polynomial, with Hashstash's cumulative schedule error.
/// Preconditions are fixed at genesis: 0 < initial <= limit <= 2^256-1,
/// compact-canonical initial and limit, and half_life > 0.
pub fn asert(initial: &Amount, error: i128, half_life: u64, limit: &Amount) -> Amount {
    assert!(half_life > 0 && !initial.is_zero() && !limit.is_zero());
    assert!(initial <= limit && limit.bits() <= 256);
    // Saturate BEFORE multiplying to avoid signed overflow or enormous shifts.
    let cutoff = i128::from(half_life) * 512;
    if error >= cutoff {
        return target_from_bits(bits_from_target(limit)).unwrap();
    }
    if error <= -cutoff {
        return Amount::one();
    }
    let exponent = error * 65_536 / i128::from(half_life); // Rust signed division truncates toward zero.
    let shifts = exponent >> 16; // arithmetic right shift, i.e. floor(exponent/65536)
    let fraction = (exponent - shifts * 65_536) as u128;
    let factor = 65_536u128
        + ((195_766_423_245_049u128 * fraction
            + 971_821_376u128 * fraction * fraction
            + 5_127u128 * fraction * fraction * fraction
            + (1u128 << 47))
            >> 48);
    let mut target = initial * Amount::from(factor);
    if shifts < 0 {
        target >>= (-shifts) as usize;
    } else {
        target <<= shifts as usize;
    }
    target >>= 16usize;
    if target.is_zero() {
        target = Amount::one();
    }
    if &target > limit {
        target = limit.clone();
    }
    // The header can encode only a compact target; issuance uses this same value.
    target_from_bits(bits_from_target(&target)).expect("positive uint256 quantized target")
}

/// Greatest new total share supply satisfying R^u*n^v <= (R+d)^u*B^v.
/// Callers enforce range/resource limits and nonzero output before committing.
fn deposit_total(r: &Amount, b: &Amount, d: &Amount, u: u32, v: u32) -> Amount {
    assert!(u > 0 && u < v && !r.is_zero() && !b.is_zero());
    (((r + d).pow(u) * b.pow(v)) / r.pow(u)).nth_root(v)
}

/// Smallest retained reserve m satisfying m^u*B^v >= R^u*(B-burn)^v.
fn remaining_reserve(r: &Amount, b: &Amount, burn: &Amount, u: u32, v: u32) -> Amount {
    assert!(u > 0 && u < v && !r.is_zero() && !b.is_zero() && burn <= b);
    let numerator = r.pow(u) * (b - burn).pow(v);
    let denominator = b.pow(v);
    let mut retained = (&numerator / &denominator).nth_root(u);
    if retained.pow(u) * denominator < numerator {
        retained += 1u32;
    }
    retained
}

/// Least shares whose exact, downward-rounded redemption pays at least `target`.
/// Retaining reserve R-target permits at most floor(((R-target)^u*B^v/R^u)^(1/v))
/// outstanding shares. This inverse therefore needs one bounded integer root,
/// rather than repeatedly quoting the curve in a search over share precision.
fn withdrawal_shares(r: &Amount, b: &Amount, target: &Amount, u: u32, v: u32) -> Result<Amount> {
    ensure!(u > 0 && u < v && v <= 32, "invalid reserve ratio");
    ensure!(
        !r.is_zero() && !b.is_zero() && r.bits() <= 512 && b.bits() <= 512,
        "withdrawal curve outside supported range"
    );
    ensure!(
        !target.is_zero() && target <= r,
        "withdrawal amount outside reserve"
    );
    let retained_shares = (((r - target).pow(u) * b.pow(v)) / r.pow(u)).nth_root(v);
    Ok(b - retained_shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_targets_and_expected_work() {
        for (bits, n) in [(0x01010000, 1u32), (0x02008000, 128), (0x03010000, 65536)] {
            assert_eq!(target_from_bits(bits).unwrap(), Amount::from(n));
            assert_eq!(bits_from_target(&Amount::from(n)), bits);
        }
        for bits in [
            0, 0x01810000, 0x01000000, 0x01123456, 0x02000100, 0x23010000, 0xff7fffff,
        ] {
            assert!(target_from_bits(bits).is_err(), "{bits:08x}");
        }
        let target = target_from_bits(0x1d00ffff).unwrap();
        assert_eq!(work(&target), Amount::from(4_295_032_833u64));
        assert_eq!(work(&Amount::one()), Amount::one() << 255usize);
        for exp in 0..256 {
            let target = (Amount::one() << exp) + 17u32;
            let rounded = target_from_bits(bits_from_target(&target)).unwrap();
            assert!(rounded <= target);
        }
    }
    #[test]
    fn asert_halves_doubles_extremes_and_signed_fraction() {
        let limit = target_from_bits(0x1d00ffff).unwrap();
        let initial = target_from_bits(0x1c0ffff0).unwrap();
        assert_eq!(asert(&initial, 0, 172800, &limit), initial);
        assert_eq!(asert(&initial, 172800, 172800, &limit), &initial * 2u32);
        assert_eq!(asert(&initial, -172800, 172800, &limit), &initial / 2u32);
        assert_eq!(asert(&initial, i128::MAX, 172800, &limit), limit);
        assert_eq!(asert(&initial, i128::MIN, 172800, &limit), Amount::one());
        assert_eq!(asert(&initial, -1, 172800, &limit), initial);
        assert!(asert(&initial, -3, 172800, &limit) < initial);
    }
    #[test]
    fn asert_supports_every_positive_half_life_without_intermediate_overflow() {
        let limit = target_from_bits(0x1d00ffff).unwrap();
        let initial = target_from_bits(0x1c0ffff0).unwrap();
        for half_life in [1, 899, 900, i64::MAX as u64 + 1, u64::MAX] {
            let half_life_i128 = i128::from(half_life);
            assert_eq!(asert(&initial, 0, half_life, &limit), initial);
            assert_eq!(
                asert(&initial, half_life_i128, half_life, &limit),
                &initial * 2u32
            );
            assert_eq!(
                asert(&initial, -half_life_i128, half_life, &limit),
                &initial / 2u32
            );
            assert_eq!(asert(&initial, i128::MAX, half_life, &limit), limit);
            assert_eq!(asert(&initial, i128::MIN, half_life, &limit), Amount::one());
            for error in [half_life_i128 * 512 - 1, -half_life_i128 * 512 + 1] {
                let target = asert(&initial, error, half_life, &limit);
                assert!(!target.is_zero() && target <= limit);
            }
        }
    }
    #[test]
    fn curve_inequalities_and_no_profitable_round_trip() {
        for (u, v) in [(1, 2), (1, 3), (1, 5), (2, 3), (3, 7)] {
            for r0 in 1..=19u32 {
                for b0 in 1..=17u32 {
                    let r = Amount::from(r0);
                    let b = Amount::from(b0);
                    for d0 in 1..=7u32 {
                        let d = Amount::from(d0);
                        let n = deposit_total(&r, &b, &d, u, v);
                        let rhs = (&r + &d).pow(u) * b.pow(v);
                        assert!(r.pow(u) * n.pow(v) <= rhs);
                        assert!(r.pow(u) * (&n + 1u32).pow(v) > rhs);
                        let retained = remaining_reserve(&(&r + &d), &n, &(&n - &b), u, v);
                        assert!(&r + &d - retained <= d);
                    }
                    for burn0 in 0..=b0 {
                        let burn = Amount::from(burn0);
                        let m = remaining_reserve(&r, &b, &burn, u, v);
                        let rhs = r.pow(u) * (&b - &burn).pow(v);
                        assert!(m.pow(u) * b.pow(v) >= rhs);
                        if !m.is_zero() {
                            assert!((&m - 1u32).pow(u) * b.pow(v) < rhs);
                        }
                        assert!(m <= r);
                    }
                }
            }
        }
    }
    #[test]
    fn withdrawal_inverse_is_exact_and_minimal() {
        for (u, v) in [(1, 2), (1, 3), (1, 5), (2, 3), (3, 7)] {
            for reserve in 1..=29u32 {
                for supply in 1..=19u32 {
                    let r = Amount::from(reserve);
                    let b = Amount::from(supply);
                    for requested in 1..=reserve {
                        let target = Amount::from(requested);
                        let burn = withdrawal_shares(&r, &b, &target, u, v).unwrap();
                        assert!(!burn.is_zero() && burn <= b);
                        assert!(&r - remaining_reserve(&r, &b, &burn, u, v) >= target);
                        assert!(&r - remaining_reserve(&r, &b, &(&burn - 1u32), u, v) < target);
                    }
                }
            }
        }
        let max = (Amount::one() << 512usize) - 1u32;
        for target in [Amount::one(), &max / 2u32, max.clone()] {
            let burn = withdrawal_shares(&max, &max, &target, 1, 5).unwrap();
            assert!(&max - remaining_reserve(&max, &max, &burn, 1, 5) >= target);
            assert!(&max - remaining_reserve(&max, &max, &(&burn - 1u32), 1, 5) < target);
        }
        for (r, b, target, u, v) in [
            (1u32.into(), 1u32.into(), 0u32.into(), 1, 5),
            (1u32.into(), 1u32.into(), 2u32.into(), 1, 5),
            (0u32.into(), 1u32.into(), 1u32.into(), 1, 5),
            (1u32.into(), 0u32.into(), 1u32.into(), 1, 5),
            (1u32.into(), 1u32.into(), 1u32.into(), 5, 5),
            (1u32.into(), 1u32.into(), 1u32.into(), 1, 33),
            (Amount::one() << 512usize, 1u32.into(), 1u32.into(), 1, 5),
        ] {
            assert!(withdrawal_shares(&r, &b, &target, u, v).is_err());
        }
    }
    #[test]
    fn official_asert_vectors() {
        let vectors = [
            include_str!("../tests/data/asert-run01"),
            include_str!("../tests/data/asert-run02"),
            include_str!("../tests/data/asert-run03"),
            include_str!("../tests/data/asert-run04"),
            include_str!("../tests/data/asert-run05"),
            include_str!("../tests/data/asert-run06"),
            include_str!("../tests/data/asert-run07"),
            include_str!("../tests/data/asert-run08"),
            include_str!("../tests/data/asert-run09"),
            include_str!("../tests/data/asert-run10"),
            include_str!("../tests/data/asert-run11"),
            include_str!("../tests/data/asert-run12"),
        ];
        let limit = target_from_bits(0x1d00ffff).unwrap();
        let mut count = 0;
        for (i, data) in vectors.iter().enumerate() {
            let mut anchor_height = 0i128;
            let mut anchor_time = 0i128;
            let mut initial = Amount::zero();
            for line in data.lines() {
                let label = line.trim_start_matches('#').trim();
                if let Some(n) = label.strip_prefix("anchor height: ") {
                    anchor_height = n.parse().unwrap();
                } else if let Some(n) = label
                    .strip_prefix("anchor parent time: ")
                    .or_else(|| label.strip_prefix("anchor ancestor time: "))
                {
                    anchor_time = n.parse().unwrap();
                } else if let Some(n) = label.strip_prefix("anchor nBits: ") {
                    initial = target_from_bits(
                        u32::from_str_radix(n.trim_start_matches("0x"), 16).unwrap(),
                    )
                    .unwrap();
                } else if !line.starts_with('#') && !line.trim().is_empty() {
                    let row: Vec<_> = line.split_whitespace().collect();
                    let height: i128 = row[1].parse().unwrap();
                    let time: i128 = row[2].parse().unwrap();
                    let expected =
                        u32::from_str_radix(row[3].trim_start_matches("0x"), 16).unwrap();
                    let error = time - anchor_time - 600 * (height - anchor_height + 1);
                    assert_eq!(
                        bits_from_target(&asert(&initial, error, 172800, &limit)),
                        expected,
                        "run {} row {}",
                        i + 1,
                        row[0]
                    );
                    count += 1;
                }
            }
        }
        assert!(count > 10_000);
    }
}
