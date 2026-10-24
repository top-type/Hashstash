//! Integer proof of work, ASERT, and reserve conversion arithmetic.
use crate::{
    codec, crypto,
    types::{Amount, Header},
};
use anyhow::{Result, ensure};
use num_traits::{One, ToPrimitive, Zero};
use std::cmp::Ordering;
use std::sync::OnceLock;

// All public curve inputs are at most 512 bits. The additional precision keeps
// errors in the directed bounds far below one output atom even after the largest
// supported exponent. These are consensus constants, not machine precision.
const CURVE_BITS: usize = 2048;
const EXP_TERMS: usize = 512;
const EXP_SQUARES: usize = 10;
// Batch clearing sizes its logarithm precision to its inputs in steps of this
// many fractional bits, never above CURVE_BITS.
const PRECISION_STEP: usize = 64;

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

/// Exactly ceil_div(n, 2^bits), without a long division.
fn ceil_shift(n: &Amount, bits: usize) -> Amount {
    let floor = n >> bits;
    if n.trailing_zeros().is_some_and(|zeros| zeros < bits as u64) {
        floor + 1u32
    } else {
        floor
    }
}

fn curve_scale() -> Amount {
    Amount::one() << CURVE_BITS
}

// ln(x) = 2 * atanh((x-1)/(x+1)). The supplied z is in [0,1/3].
// After N terms the omitted tail is at most
// 9 / (4(2N+1)3^(2N+1)). Since 9>8 and 3N>=bits,
// one fixed-point unit bounds this tail. Each arithmetic operation below also
// rounds outwards, so the returned interval encloses the exact logarithm.
//
// Every precision is a whole number of 64-bit limbs, so each shift by it is a
// limb offset and the series runs on limb vectors that reuse their buffers.
// The upper power and square exceed the lower ones by a few units, so each
// upper step is derived from the lower one: with high = low + g and low =
// q*d + r, ceil(high/d) = q + ceil((r+g)/d), and with square_high =
// square_low + h, high*square_high = low*square_low + low*h + g*square_high.
// One long product and one division pass by the small term divisor, through
// its reciprocal, therefore serve both bounds; a gap of 2^64 or more, which
// these bounds do not reach, would take the direct steps. Each step takes
// exactly the floors and ceilings of the arbitrary-precision definition kept
// as the reference in the tests, so the bounds, and every clearing they
// decide, are unchanged.
fn log_atanh(z_numerator: &Amount, z_denominator: &Amount, bits: usize) -> Bounds {
    assert!(
        bits.is_multiple_of(64) && bits <= CURVE_BITS,
        "unsupported logarithm precision"
    );
    if z_numerator.is_zero() {
        return Bounds {
            low: Amount::zero(),
            high: Amount::zero(),
        };
    }
    let terms = bits.div_ceil(3);
    let unit = bits / 64;
    let numerator = z_numerator << bits;
    // One long division gives both directed quotients: the ceiling exceeds
    // the floor exactly when the division is inexact.
    let z = &numerator / z_denominator;
    let exact = &z * z_denominator == numerator;
    let mut low = z.to_u64_digits();
    let mut high = low.clone();
    if !exact {
        add_limbs(&mut high, &[1]);
    }
    let mut product = Vec::with_capacity(2 * unit + 3);
    let mut quotient = Vec::with_capacity(unit + 1);
    let mut next = Vec::with_capacity(unit + 2);
    let (mut square_low, mut square_high) = (Vec::new(), Vec::new());
    multiply(&low, &low, &mut product);
    shifted(&product, unit, false, &mut square_low);
    multiply(&high, &high, &mut product);
    shifted(&product, unit, true, &mut square_high);
    let square_gap = gap(&square_high, &square_low);
    let mut sum_low = Vec::with_capacity(unit + 2);
    let mut sum_high = Vec::with_capacity(unit + 2);
    for index in 0..terms {
        if low.is_empty() && high == [1] {
            // A fixed point: 0 < square.high <= 2^bits keeps the upper power at
            // one unit, so each remaining term adds exactly zero below and one
            // unit above. Adding them directly gives the identical bounds.
            add_limbs(&mut sum_high, &[(terms - index) as u64]);
            break;
        }
        let divisor = SmallDivisor::new(2 * index as u64 + 1);
        let power_gap = gap(&high, &low);
        let remainder = divide(&low, divisor, &mut quotient);
        add_limbs(&mut sum_low, &quotient);
        match power_gap {
            Some(power_gap) => {
                // remainder + power_gap < 2^65, so the extra quotient is
                // below 2^64 for every divisor above one, and for one the
                // remainder is zero.
                let extra = (u128::from(remainder) + u128::from(power_gap))
                    .div_ceil(u128::from(divisor.divisor));
                add_limbs(&mut quotient, &[extra as u64]);
            }
            None => {
                if divide(&high, divisor, &mut quotient) != 0 {
                    add_limbs(&mut quotient, &[1]);
                }
            }
        }
        add_limbs(&mut sum_high, &quotient);
        multiply(&low, &square_low, &mut product);
        shifted(&product, unit, false, &mut next);
        match (power_gap, square_gap) {
            (Some(power_gap), Some(square_gap)) => {
                add_scaled(&mut product, &low, square_gap);
                add_scaled(&mut product, &square_high, power_gap);
            }
            _ => multiply(&high, &square_high, &mut product),
        }
        shifted(&product, unit, true, &mut high);
        std::mem::swap(&mut low, &mut next);
    }
    Bounds {
        low: from_limbs(&sum_low) << 1usize,
        high: (from_limbs(&sum_high) << 1usize) + 1u32,
    }
}

/// The value of little-endian 64-bit limbs.
fn from_limbs(limbs: &[u64]) -> Amount {
    Amount::new(
        limbs
            .iter()
            .flat_map(|&limb| [limb as u32, (limb >> 32) as u32])
            .collect(),
    )
}

fn trim(limbs: &mut Vec<u64>) {
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
}

/// high - low when it is below 2^64 and high >= low.
fn gap(high: &[u64], low: &[u64]) -> Option<u64> {
    if high.len() > low.len() + 1 || low.len() > high.len() {
        return None;
    }
    let mut borrow = false;
    let mut result = 0;
    for (index, &limb) in high.iter().enumerate() {
        let (partial, first) = limb.overflowing_sub(low.get(index).copied().unwrap_or(0));
        let (difference, second) = partial.overflowing_sub(u64::from(borrow));
        borrow = first || second;
        if index == 0 {
            result = difference;
        } else if difference != 0 {
            return None;
        }
    }
    (!borrow).then_some(result)
}

/// sum += addend.
fn add_limbs(sum: &mut Vec<u64>, addend: &[u64]) {
    if sum.len() < addend.len() {
        sum.resize(addend.len(), 0);
    }
    let mut carry = false;
    for (index, limb) in sum.iter_mut().enumerate() {
        if index >= addend.len() && !carry {
            break;
        }
        let (partial, first) = limb.overflowing_add(addend.get(index).copied().unwrap_or(0));
        let (total, second) = partial.overflowing_add(u64::from(carry));
        *limb = total;
        carry = first || second;
    }
    if carry {
        sum.push(1);
    }
}

/// sum += value * factor.
fn add_scaled(sum: &mut Vec<u64>, value: &[u64], factor: u64) {
    if factor == 0 || value.is_empty() {
        return;
    }
    if sum.len() < value.len() + 1 {
        sum.resize(value.len() + 1, 0);
    }
    let mut carry = 0u64;
    for (limb, &v) in sum.iter_mut().zip(value) {
        let t = u128::from(v) * u128::from(factor) + u128::from(*limb) + u128::from(carry);
        *limb = t as u64;
        carry = (t >> 64) as u64;
    }
    add_limbs_at(sum, value.len(), carry);
}

/// sum += carry * 2^(64 * at).
fn add_limbs_at(sum: &mut Vec<u64>, at: usize, mut carry: u64) {
    let mut index = at;
    while carry != 0 {
        if index == sum.len() {
            sum.push(0);
        }
        let (total, overflow) = sum[index].overflowing_add(carry);
        sum[index] = total;
        carry = u64::from(overflow);
        index += 1;
    }
}

/// product = a * b.
fn multiply(a: &[u64], b: &[u64], product: &mut Vec<u64>) {
    product.clear();
    product.resize(a.len() + b.len(), 0);
    for (i, &x) in a.iter().enumerate() {
        let row = &mut product[i..=i + b.len()];
        let mut carry = 0u64;
        for (limb, &y) in row.iter_mut().zip(b) {
            let t = u128::from(x) * u128::from(y) + u128::from(*limb) + u128::from(carry);
            *limb = t as u64;
            carry = (t >> 64) as u64;
        }
        row[b.len()] = carry;
    }
}

/// result = floor(value / 2^(64 * unit)), or the ceiling.
fn shifted(value: &[u64], unit: usize, ceiling: bool, result: &mut Vec<u64>) {
    let split = unit.min(value.len());
    result.clear();
    result.extend_from_slice(&value[split..]);
    trim(result);
    if ceiling && value[..split].iter().any(|&limb| limb != 0) {
        add_limbs(result, &[1]);
    }
}

/// A series divisor below 2^11 with m = ceil(2^54 / d). For n < 2^43,
/// floor(n * m / 2^54) = floor(n / d): with e = m*d - 2^54 < d, n*m/2^54 =
/// n/d + n*e/(d*2^54), and n*e < 2^54 keeps that excess below 1/d, which
/// never carries the fraction of n/d, at most (d-1)/d, past the next integer
/// (Granlund and Montgomery). A multiplication replaces each division.
#[derive(Clone, Copy)]
struct SmallDivisor {
    divisor: u64,
    reciprocal: u64,
}

impl SmallDivisor {
    const BITS: u32 = 11;
    fn new(divisor: u64) -> Self {
        assert!(divisor != 0 && divisor >> Self::BITS == 0);
        Self {
            divisor,
            reciprocal: (1u64 << 54).div_ceil(divisor),
        }
    }
    /// The quotient and remainder of n < 2^43.
    fn div_rem(self, n: u64) -> (u64, u64) {
        debug_assert!(n >> 43 == 0);
        let quotient = ((u128::from(n) * u128::from(self.reciprocal)) >> 54) as u64;
        (quotient, n - quotient * self.divisor)
    }
}

/// quotient = floor(value / divisor); returns the remainder. Each step
/// divides a remainder below 2^11 and 32 more bits.
fn divide(value: &[u64], divisor: SmallDivisor, quotient: &mut Vec<u64>) -> u64 {
    quotient.clear();
    quotient.resize(value.len(), 0);
    let mut remainder = 0u64;
    for (index, &limb) in value.iter().enumerate().rev() {
        let (upper, rest) = divisor.div_rem((remainder << 32) | (limb >> 32));
        let (lower, rest) = divisor.div_rem((rest << 32) | (limb & 0xffff_ffff));
        quotient[index] = (upper << 32) | lower;
        remainder = rest;
    }
    trim(quotient);
    remainder
}

fn log_two(bits: usize) -> &'static Bounds {
    const LEVELS: usize = CURVE_BITS / PRECISION_STEP + 1;
    static VALUES: [OnceLock<Bounds>; LEVELS] = [const { OnceLock::new() }; LEVELS];
    assert!(bits.is_multiple_of(PRECISION_STEP) && bits <= CURVE_BITS);
    VALUES[bits / PRECISION_STEP]
        .get_or_init(|| log_atanh(&Amount::one(), &Amount::from(3u32), bits))
}

/// Enclose ln(numerator/denominator), with numerator >= denominator > 0, in
/// units of 2^-bits. The bounds depend only on the rational value.
fn log_ratio(numerator: &Amount, denominator: &Amount, bits: usize) -> Bounds {
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
        bits,
    );
    if shift != 0 {
        result.low += &log_two(bits).low * shift;
        result.high += &log_two(bits).high * shift;
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
    let x = Bounds {
        low: &value.low >> EXP_SQUARES,
        high: ceil_shift(&value.high, EXP_SQUARES),
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
        sum.high = ceil_shift(&(&sum.high * &sum.high), CURVE_BITS);
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
// boundaries. The direct quotes below use unscaled operands of at most 512 bits,
// so their eighth powers and products stay below 8192 bits. Batch clearing
// compares scaled operands instead; see compare_curve_powers.
pub(crate) fn small_ratio(reserve: &Amount, mass: &Amount) -> Option<(u32, u32)> {
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

/// Fractional bits of the directed logarithms used to clear a batch whose
/// widest input has `input_bits` bits. On its 2^(2*input_bits+32) price grid a
/// comparison at precision P stays undecided only within roughly
/// 2^(4*input_bits+52-P) grid units of the root, so 4*input_bits+128 bits keep
/// that band far below one unit. Rounded up to whole steps and never above the
/// 2048-bit precision of the direct quotes.
pub(crate) fn clearing_precision(input_bits: u64) -> usize {
    let wanted = usize::try_from(input_bits)
        .unwrap_or(usize::MAX)
        .saturating_mul(4)
        .saturating_add(128);
    wanted
        .div_ceil(PRECISION_STEP)
        .saturating_mul(PRECISION_STEP)
        .min(CURVE_BITS)
}

/// Directed bounds on ln(numerator/denominator) at a fixed precision.
pub(crate) struct CurveLog {
    bounds: Bounds,
    bits: usize,
}

/// Enclose ln(numerator/denominator), with numerator >= denominator > 0. The
/// precision must come from clearing_precision. The bounds depend only on the
/// rational value, so equal ratios may share one evaluation.
pub(crate) fn curve_log(numerator: &Amount, denominator: &Amount, bits: usize) -> CurveLog {
    CurveLog {
        bounds: log_ratio(numerator, denominator, bits),
        bits,
    }
}

/// Exact comparison of `u * ln(a/b)` with `v * ln(c/d)` for a reduced curve
/// ratio u/v with v <= 8, as `a^u * d^v` against `b^u * c^v`. With operands of
/// at most w bits, the products have at most (u+v)*w <= 15*w bits; batch
/// clearing's scaled operands have w of about 3*input_bits+36 here.
pub(crate) fn compare_curve_powers(
    (u, v): (u32, u32),
    a: &Amount,
    b: &Amount,
    c: &Amount,
    d: &Amount,
) -> Ordering {
    assert!(!b.is_zero() && !d.is_zero() && a >= b && c >= d);
    (a.pow(u) * d.pow(v)).cmp(&(b.pow(u) * c.pow(v)))
}

/// Compare `reserve * ln(a/b)` with `mass * ln(c/d)` from directed bounds of
/// the two logarithms, without floating point. `None` means the proven
/// intervals overlap; callers must retain both sides of their root bracket.
/// The midpoint proposes a safeguarded root-search step. Only the separately
/// returned directed comparison can establish a root bracket or an output.
pub(crate) fn curve_log_evaluation(
    reserve: &Amount,
    mass: &Amount,
    left: &CurveLog,
    right: &CurveLog,
) -> (Option<Ordering>, num_bigint::BigInt, Amount) {
    use num_bigint::BigInt;
    assert_eq!(left.bits, right.bits, "curve logarithm precision mismatch");
    let (left, right, bits) = (&left.bounds, &right.bounds, left.bits);
    let lower = BigInt::from(&left.low * reserve) - BigInt::from(&right.high * mass);
    let upper = BigInt::from(&left.high * reserve) - BigInt::from(&right.low * mass);
    let comparison = if upper < BigInt::zero() {
        Some(Ordering::Less)
    } else if lower > BigInt::zero() {
        Some(Ordering::Greater)
    } else if left.high.is_zero() && right.high.is_zero() {
        // Only a ratio of exactly one has a zero upper logarithm bound.
        Some(Ordering::Equal)
    } else {
        None
    };
    (comparison, (lower + upper) / 2u32, Amount::one() << bits)
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
        let exponent = scale_bounds(log_ratio(&next_reserve, reserve, CURVE_BITS), reserve, mass);
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
    let exponent = scale_bounds(
        log_ratio(supply, &remaining_supply, CURVE_BITS),
        mass,
        reserve,
    );
    // For any positive remaining stash, the exact retained reserve is positive.
    // Above this threshold it is below one atom; avoid evaluating huge powers.
    if exponent.low >= &log_two(CURVE_BITS).high * 512u32 {
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
    let exponent = scale_bounds(log_ratio(reserve, &retained, CURVE_BITS), reserve, mass);
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

/// The consensus mass rule shared by batch clearing and the checked helpers
/// below: scale mass with reserve, rounding down when the reserve grows and up
/// when it shrinks, so reversing a trade cannot benefit from a curve shape
/// caused only by rounding. Range checks are the caller's; batch clearing keeps
/// oversized intermediate results so that it can refund them.
pub(crate) fn scaled_mass(reserve: &Amount, mass: &Amount, next_reserve: &Amount) -> Amount {
    assert!(!reserve.is_zero());
    if next_reserve >= reserve {
        mass * next_reserve / reserve
    } else {
        ceil_div(&(mass * next_reserve), reserve)
    }
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
    let result = scaled_mass(reserve, mass, next_reserve);
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
    Ok(scaled_mass(reserve, mass, next_reserve))
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

/// Convert this block's exact expected work into whole monetary atoms.
/// Any fractional atom is discarded; it is never carried into another block.
/// When block work is only a few multiples of `work_per_atom`, this discards a
/// large share of work-implied issuance and makes reward per hash a sawtooth;
/// genesis calibration should keep expected block work far above one atom.
pub fn issuance(block_work: &Amount, work_per_atom: &Amount) -> Result<Amount> {
    ensure!(!work_per_atom.is_zero(), "zero work denomination");
    Ok(block_work / work_per_atom)
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
    fn logarithm_shortcuts_match_the_full_series() {
        // The original evaluation: every term, with long-division ceilings.
        fn full_series(z_numerator: &Amount, z_denominator: &Amount, bits: usize) -> Bounds {
            if z_numerator.is_zero() {
                return Bounds {
                    low: Amount::zero(),
                    high: Amount::zero(),
                };
            }
            let scale = Amount::one() << bits;
            let numerator = z_numerator << bits;
            let z = Bounds {
                low: &numerator / z_denominator,
                high: ceil_div(&numerator, z_denominator),
            };
            let square = Bounds {
                low: (&z.low * &z.low) >> bits,
                high: ceil_div(&(&z.high * &z.high), &scale),
            };
            let mut power = z;
            let mut sum = Bounds {
                low: Amount::zero(),
                high: Amount::zero(),
            };
            for index in 0..bits.div_ceil(3) {
                let divisor = Amount::from(2 * index + 1);
                sum.low += &power.low / &divisor;
                sum.high += ceil_div(&power.high, &divisor);
                power.low = (&power.low * &square.low) >> bits;
                power.high = ceil_div(&(&power.high * &square.high), &scale);
            }
            Bounds {
                low: sum.low << 1usize,
                high: (sum.high << 1usize) + 1u32,
            }
        }
        for n in [0u64, 1, 2, 3, 5, 1 << 20, (1 << 63) + 1] {
            for bits in [0, 1, 63, 64, 65, 300] {
                let n = Amount::from(n) << 7usize;
                assert_eq!(ceil_shift(&n, bits), ceil_div(&n, &(Amount::one() << bits)));
            }
        }
        let zs = [
            (1u32, 3u32),
            (1, 1_000),
            (1, 7),
            (2, 7),
            (999, 3_000),
            (1, u32::MAX),
        ];
        for bits in [192, 448, 1088, CURVE_BITS] {
            for (n, d) in zs {
                let (n, d) = (Amount::from(n), Amount::from(d));
                let fast = log_atanh(&n, &d, bits);
                let slow = full_series(&n, &d, bits);
                assert_eq!(
                    (fast.low, fast.high),
                    (slow.low, slow.high),
                    "{n}/{d} at {bits}"
                );
            }
        }
        // Every series divisor's reciprocal against hardware division, at the
        // ends of the operand range and around each multiple's boundary.
        for divisor in 1..1u64 << SmallDivisor::BITS {
            let small = SmallDivisor::new(divisor);
            let top = (1u64 << 43) - 1;
            let high = top / divisor * divisor;
            for n in [
                0,
                1,
                divisor - 1,
                divisor,
                divisor + 1,
                high - 1,
                high,
                top - 1,
                top,
            ]
            .into_iter()
            .chain((0..64).map(|k| (top >> k).wrapping_mul(0x9e37_79b9) & top))
            {
                assert_eq!(
                    small.div_rem(n),
                    (n / divisor, n % divisor),
                    "{n}/{divisor}"
                );
            }
        }
        // The limb series against the reference at every precision step, on
        // random operands from tiny to maximal z and on all-ones limbs, whose
        // products and sums carry through every limb.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut random = |bits: usize| {
            let mut value = Amount::zero();
            for _ in 0..bits.div_ceil(64) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                value = (value << 64usize) + state;
            }
            (value >> (bits.div_ceil(64) * 64 - bits)).max(Amount::one())
        };
        for bits in (PRECISION_STEP..=CURVE_BITS).step_by(PRECISION_STEP) {
            let mut cases = Vec::new();
            for width in [1, 63, 64, 65, 200, 700] {
                let d = random(width + 2);
                for shift in [1usize, 2, 9, width / 2 + 1, width + 1] {
                    cases.push(((&d >> shift).max(Amount::one()).min(&d / 2u32), d.clone()));
                }
            }
            for limbs in [1usize, 2, 5, 33] {
                let ones = (Amount::one() << (64 * limbs)) - 1u32;
                cases.push((&ones / 3u32, ones.clone()));
                cases.push((&ones / 3u32 - 1u32, ones.clone()));
                cases.push((Amount::one(), ones.clone()));
                cases.push((&ones >> 70usize, ones));
            }
            for (n, d) in cases {
                if n.is_zero() || n > d {
                    continue;
                }
                let fast = log_atanh(&n, &d, bits);
                let slow = full_series(&n, &d, bits);
                assert_eq!(
                    (fast.low, fast.high),
                    (slow.low, slow.high),
                    "{n}/{d} at {bits}"
                );
            }
        }
        // Callers keep z below one, where the upper chain stays within a few
        // units of the lower. Above one the powers grow and the gaps pass
        // 2^64 (for the squares too, from z near 2^64), so these take the
        // direct upper steps.
        for bits in [64, 128, 192] {
            for (n, d) in [(2u32, 1u32), (7, 3), (1 << 31, 3), (u32::MAX, 7)] {
                let (n, d) = (Amount::from(n) << 40usize, Amount::from(d));
                let fast = log_atanh(&n, &d, bits);
                let slow = full_series(&n, &d, bits);
                assert_eq!(
                    (fast.low, fast.high),
                    (slow.low, slow.high),
                    "{n}/{d} at {bits}"
                );
            }
        }
        assert_eq!(clearing_precision(1), 192);
        assert_eq!(clearing_precision(64), 384);
        assert_eq!(clearing_precision(237), 1088);
        assert_eq!(clearing_precision(480), CURVE_BITS);
        assert_eq!(clearing_precision(u64::MAX), CURVE_BITS);
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
