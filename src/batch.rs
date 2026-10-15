//! Simultaneous amount-only reserve trading. Order identifiers associate results;
//! they never select a price, a fill fraction, or a rounding beneficiary.
use crate::{
    config::Config,
    math,
    state::World,
    types::{Amount, Hash},
};
use anyhow::{Result, ensure};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::{cell::RefCell, cmp::Ordering, collections::BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub id: Hash,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub id: Hash,
    pub input: Amount,
    pub output: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Clearing {
    pub buys: Vec<Fill>,
    pub sells: Vec<Fill>,
    pub reserve: Amount,
    pub shares: Amount,
    pub curve_mass: Amount,
}

fn ceil(n: &Amount, d: &Amount) -> Amount {
    if n.is_zero() {
        Amount::zero()
    } else {
        (n - 1u32) / d + 1u32
    }
}

fn sum(values: &[Amount]) -> Amount {
    values.iter().sum()
}

fn gcd(mut a: Amount, mut b: Amount) -> Amount {
    while !b.is_zero() {
        let next = &a % &b;
        a = b;
        b = next;
    }
    a
}

fn simplest_fraction(
    mut a: Amount,
    mut b: Amount,
    mut c: Amount,
    mut d: Amount,
) -> (Amount, Amount) {
    let mut terms = Vec::new();
    let (mut n, mut denominator) = loop {
        let floor = &a / &b;
        if (&a % &b).is_zero() {
            break (floor, Amount::one());
        }
        if floor < &c / &d {
            break (floor + 1u32, Amount::one());
        }
        let low_remainder = &a - &floor * &b;
        let high_remainder = &c - &floor * &d;
        terms.push(floor);
        (a, b, c, d) = (d, high_remainder, b, low_remainder);
    };
    for term in terms.into_iter().rev() {
        (n, denominator) = (&term * &n + denominator, n);
    }
    (n, denominator)
}

fn empty(w: &World, buys: &[Order], sells: &[Order]) -> Clearing {
    let fill = |o: &Order| Fill {
        id: o.id,
        input: Amount::zero(),
        output: Amount::zero(),
    };
    Clearing {
        buys: buys.iter().map(fill).collect(),
        sells: sells.iter().map(fill).collect(),
        reserve: w.reserve.clone(),
        shares: w.shares.clone(),
        curve_mass: w.curve_mass.clone(),
    }
}

fn proportional(orders: &[Order], budget: &Amount, total: &Amount) -> Vec<Amount> {
    orders
        .iter()
        .map(|o| {
            if total.is_zero() {
                Amount::zero()
            } else {
                &o.amount * budget / total
            }
        })
        .collect()
}

/// A bracket enclosing the ideal uniform execution price, in units of `scale`.
/// Exact small-rational curves use integer powers; other curves use directed
/// logarithm bounds. The two searches deliberately retain unresolved comparisons.
fn price(w: &World, cash: &Amount, sold: &Amount) -> Result<(Amount, Amount, Amount)> {
    let balance = (cash * &w.shares).cmp(&(sold * &w.curve_mass));
    if balance == Ordering::Equal || w.reserve == w.curve_mass {
        return Ok((w.curve_mass.clone(), w.curve_mass.clone(), w.shares.clone()));
    }
    let bits = [&w.reserve, &w.shares, &w.curve_mass, cash, sold]
        .into_iter()
        .map(|n| n.bits())
        .max()
        .unwrap_or(1);
    // More than twice the input width resolves an output atom even for tiny
    // prices. It is arithmetic precision, independent of order identifiers.
    let scale = Amount::one() << (2 * bits as usize + 32);
    let buying = balance == Ordering::Greater;
    let mut lower = if buying {
        &w.curve_mass * &scale / &w.shares
    } else {
        &w.reserve * &scale / &w.shares
    };
    let mut upper = if buying {
        ceil(
            &(&w.curve_mass * (&w.reserve + cash) * &scale),
            &(&w.shares * &w.reserve),
        )
    } else {
        ceil(&(&w.curve_mass * &scale), &w.shares)
    };
    if buying && !sold.is_zero() {
        upper = upper.min(ceil(&(cash * &scale), sold));
    }
    let exact_powers = math::small_ratio(&w.reserve, &w.curve_mass).is_some();
    let last_log = RefCell::new(None::<(Amount, Amount, BigInt, Amount)>);
    let compare_fraction = |p: &Amount, denominator: &Amount| -> Option<Ordering> {
        if p.is_zero() {
            return Some(Ordering::Less);
        }
        let cash_scaled = cash * denominator;
        let sale_scaled = sold * p;
        if buying && cash_scaled <= sale_scaled {
            return Some(Ordering::Greater);
        }
        if !buying && cash_scaled >= sale_scaled {
            return Some(Ordering::Less);
        }
        let reserve_base = &w.reserve * denominator;
        let reserve_total = (&w.reserve + cash) * denominator;
        if reserve_total <= sale_scaled {
            return Some(
                if reserve_total == sale_scaled && sold == &w.shares && cash.is_zero() {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                },
            );
        }
        let next_reserve = reserve_total - sale_scaled;
        let supply_base = &w.shares * p;
        let next_supply = (&w.shares - sold) * p + cash_scaled;
        if next_supply.is_zero() {
            return Some(Ordering::Less);
        }
        let (a, b, c, d) = if buying {
            (next_reserve, reserve_base, next_supply, supply_base)
        } else {
            (reserve_base, next_reserve, supply_base, next_supply)
        };
        if exact_powers {
            math::compare_curve_logs(&w.reserve, &w.curve_mass, &a, &b, &c, &d)
        } else {
            let (comparison, midpoint, log_scale) =
                math::curve_log_evaluation(&w.reserve, &w.curve_mass, &a, &b, &c, &d);
            *last_log.borrow_mut() = Some((p.clone(), denominator.clone(), midpoint, log_scale));
            comparison
        }
    };
    let compare = |p: &Amount| compare_fraction(p, &scale);
    let newton = |p: &Amount| -> Option<Amount> {
        if exact_powers || p.is_zero() {
            return None;
        }
        let cash_scaled = cash * &scale;
        let sale_scaled = sold * p;
        if (buying && cash_scaled <= sale_scaled) || (!buying && cash_scaled >= sale_scaled) {
            return None;
        }
        let reserve_total = (&w.reserve + cash) * &scale;
        if reserve_total <= sale_scaled {
            return None;
        }
        let rn = reserve_total - sale_scaled;
        let sn = (&w.shares - sold) * p + cash_scaled;
        if sn.is_zero() {
            return None;
        }
        let cached = last_log.borrow();
        let (previous_p, previous_scale, difference, log_scale) = cached.as_ref()?;
        if previous_p != p || previous_scale != &scale {
            return None;
        }
        let mut derivative = BigInt::from(&w.curve_mass * cash * &scale * &rn)
            - BigInt::from(&w.reserve * sold * p * &sn);
        if !buying {
            derivative = -derivative;
        }
        if derivative <= BigInt::zero() {
            return None;
        }
        let step =
            difference * BigInt::from(rn * p * sn) / (BigInt::from(log_scale.clone()) * derivative);
        drop(cached);
        let proposal = BigInt::from(p.clone()) - step;
        let proposal = proposal.to_biguint()?;
        if proposal == *p {
            match compare(p) {
                Some(Ordering::Less) => Some(p + 1u32),
                Some(Ordering::Greater) => Some(p - 1u32),
                _ => None,
            }
        } else {
            Some(proposal)
        }
    };
    let mut proposal = None;
    while &upper - &lower > Amount::one() {
        let mid = proposal
            .take()
            .filter(|p| p > &lower && p < &upper)
            .unwrap_or_else(|| (&lower + &upper) >> 1usize);
        match compare(&mid) {
            Some(Ordering::Less) => {
                lower = mid.clone();
                proposal = newton(&mid);
            }
            Some(Ordering::Greater) => {
                upper = mid.clone();
                proposal = newton(&mid);
            }
            Some(Ordering::Equal) => return Ok((mid.clone(), mid, scale)),
            None => {
                if mid > &lower + 1u32
                    && &mid + 1u32 < upper
                    && compare(&(&mid - 1u32)) == Some(Ordering::Less)
                    && compare(&(&mid + 1u32)) == Some(Ordering::Greater)
                {
                    lower = &mid - 1u32;
                    upper = &mid + 1u32;
                    break;
                }
                // Locate the last proven lower bound and first proven upper
                // bound independently; never assume the sign of an overlap.
                let mut hi = mid.clone();
                while &hi - &lower > Amount::one() {
                    let probe = (&lower + &hi) >> 1usize;
                    match compare(&probe) {
                        Some(Ordering::Less) => lower = probe,
                        Some(Ordering::Equal) => return Ok((probe.clone(), probe, scale)),
                        _ => hi = probe,
                    }
                }
                let mut lo = mid;
                while &upper - &lo > Amount::one() {
                    let probe = (&lo + &upper) >> 1usize;
                    match compare(&probe) {
                        Some(Ordering::Greater) => upper = probe,
                        Some(Ordering::Equal) => return Ok((probe.clone(), probe, scale)),
                        _ => lo = probe,
                    }
                }
                break;
            }
        }
    }
    // Recover exact rational boundaries such as 21/10. A dyadic approximation
    // alone would conservatively lose an atom even when every exact output is
    // integral. Equality is accepted only after the curve comparison proves it.
    let (n, d) = simplest_fraction(lower.clone(), scale.clone(), upper.clone(), scale.clone());
    if compare_fraction(&n, &d) == Some(Ordering::Equal) {
        return Ok((n.clone(), n, d));
    }
    ensure!(!upper.is_zero(), "zero batch price");
    Ok((lower, upper, scale))
}

fn within_upper(w: &World, result: &Clearing, bps: u64) -> bool {
    result.shares.is_zero()
        || &result.curve_mass * &w.shares * 10_000u32
            <= &w.curve_mass * &result.shares * (Amount::from(bps) + 10_000u32)
}

fn within_lower(w: &World, result: &Clearing, bps: u64) -> bool {
    bps >= 10_000
        || (!result.shares.is_zero()
            && &result.curve_mass * &w.shares * 10_000u32
                >= &w.curve_mass * &result.shares * (10_000 - bps))
}

fn within_range(c: &Config, result: &Clearing) -> bool {
    result.reserve.bits() <= c.money_bits
        && result.curve_mass.bits() <= c.money_bits
        && result.shares.bits() <= c.share_bits
}

/// Signed relative distance from the active constraints. This only chooses a
/// search probe; every retained result still passes the exact inequalities.
fn constraint_gap(
    c: &Config,
    w: &World,
    result: &Clearing,
    bps: u64,
    reduce_buys: bool,
) -> (BigInt, Amount) {
    let max_money = (Amount::one() << c.money_bits as usize) - 1u32;
    let max_shares = (Amount::one() << c.share_bits as usize) - 1u32;
    let (numerator, denominator) = if reduce_buys {
        if result.shares.is_zero() {
            (Amount::zero(), Amount::one())
        } else {
            (
                &result.curve_mass * &w.shares * 10_000u32,
                &w.curve_mass * &result.shares * (Amount::from(bps) + 10_000u32),
            )
        }
    } else if bps >= 10_000 {
        (Amount::zero(), Amount::one())
    } else if result.shares.is_zero() {
        (Amount::from(2u32), Amount::one())
    } else {
        (
            &w.curve_mass * &result.shares * (10_000 - bps),
            &result.curve_mass * &w.shares * 10_000u32,
        )
    };
    let mut gap = BigInt::from(numerator) - BigInt::from(denominator.clone());
    let mut divisor = denominator;
    for (value, limit) in [
        (&result.reserve, &max_money),
        (&result.curve_mass, &max_money),
        (&result.shares, &max_shares),
    ] {
        let next = BigInt::from(value.clone()) - BigInt::from(limit.clone());
        if &next * BigInt::from(divisor.clone()) > &gap * BigInt::from(limit.clone()) {
            gap = next;
            divisor = limit.clone();
        }
    }
    (gap, divisor)
}

fn candidate(
    w: &World,
    buys: &[Order],
    sells: &[Order],
    buy_budget: &Amount,
    sell_budget: &Amount,
    total_cash: &Amount,
    total_sold: &Amount,
) -> Result<Clearing> {
    let mut input_buys = proportional(buys, buy_budget, total_cash);
    let mut input_sells = proportional(sells, sell_budget, total_sold);
    if w.reserve == w.curve_mass {
        // Exact reduced-price lots avoid altering a flat quote solely through
        // integer dust. Unusable input atoms are refunded, not donated.
        let divisor = gcd(w.reserve.clone(), w.shares.clone());
        let cash_lot = &w.reserve / &divisor;
        let share_lot = &w.shares / divisor;
        for n in &mut input_buys {
            *n = (&*n / &cash_lot) * &cash_lot;
        }
        for n in &mut input_sells {
            *n = (&*n / &share_lot) * &share_lot;
        }
    }
    loop {
        let cash = sum(&input_buys);
        let sold = sum(&input_sells);
        if cash.is_zero() && sold.is_zero() {
            return Ok(empty(w, buys, sells));
        }
        let (low, high, scale) = price(w, &cash, &sold)?;
        let output_buys: Vec<Amount> = input_buys.iter().map(|n| n * &scale / &high).collect();
        let output_sells: Vec<Amount> = input_sells.iter().map(|n| n * &low / &scale).collect();
        // A dust order does not pay its principal for zero output. All such
        // orders leave together, so array order cannot select the remaining set.
        let mut removed = false;
        for (input, output) in input_buys
            .iter_mut()
            .zip(&output_buys)
            .chain(input_sells.iter_mut().zip(&output_sells))
        {
            if !input.is_zero() && output.is_zero() {
                *input = Amount::zero();
                removed = true;
            }
        }
        if removed {
            continue;
        }
        let paid = sum(&output_sells);
        ensure!(paid <= &w.reserve + &cash, "batch exceeds funded reserve");
        let reserve = &w.reserve + cash - paid;
        let shares = &w.shares + sum(&output_buys) - sold;
        if shares.is_zero() && !reserve.is_zero() {
            // Full redemption cannot strand rounding dust without Stash owners.
            // Retain an input atom proportionally and clear the remaining sale.
            let sold = sum(&input_sells);
            let next = &sold - 1u32;
            for input in &mut input_sells {
                *input = &*input * &next / &sold;
            }
            continue;
        }
        ensure!(
            reserve.is_zero() == shares.is_zero(),
            "batch empty curve invariant"
        );
        // Intermediate candidates may exceed the state width. Keep the exact
        // integer result so clearing can refund the surplus instead of making
        // individually valid orders poison their entire block.
        let mass = if reserve >= w.reserve {
            &w.curve_mass * &reserve / &w.reserve
        } else {
            ceil(&(&w.curve_mass * &reserve), &w.reserve)
        };
        let fill = |orders: &[Order], inputs: Vec<Amount>, outputs: Vec<Amount>| {
            orders
                .iter()
                .zip(inputs)
                .zip(outputs)
                .map(|((o, input), output)| Fill {
                    id: o.id,
                    input,
                    output,
                })
                .collect()
        };
        return Ok(Clearing {
            buys: fill(buys, input_buys, output_buys),
            sells: fill(sells, input_sells, output_sells),
            reserve,
            shares,
            curve_mass: mass,
        });
    }
}

/// Clear one world's included amount-only orders. Fees are outside this function.
/// Price bounds apply to the actual final mass/supply ratio, including rounding.
/// Bootstrap has the fixed genesis price; emptying needs a 100% downward bound.
pub fn clear(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    max_price_change_bps: u64,
) -> Result<Clearing> {
    let mut ids = BTreeSet::new();
    for o in buys.iter().chain(sells) {
        ensure!(ids.insert(o.id), "duplicate batch order identifier");
        ensure!(!o.amount.is_zero(), "zero batch order");
    }
    for o in buys {
        c.check_amount(&o.amount)?;
    }
    for o in sells {
        c.check_shares(&o.amount)?;
    }
    let cash: Amount = buys.iter().map(|o| &o.amount).sum();
    let sold: Amount = sells.iter().map(|o| &o.amount).sum();
    ensure!(sold <= w.shares, "batch sells exceed existing Stash");
    ensure!(
        w.reserve.is_zero() == w.shares.is_zero()
            && w.curve_mass.is_zero() == w.reserve.is_zero()
            && w.curve_mass >= w.reserve,
        "invalid opening batch curve"
    );
    c.check_amount(&w.reserve)?;
    c.check_amount(&w.curve_mass)?;
    c.check_shares(&w.shares)?;
    if w.shares.is_zero() {
        let mut result = empty(w, buys, sells);
        let max_money = (Amount::one() << c.money_bits as usize) - 1u32;
        let max_shares = (Amount::one() << c.share_bits as usize) - 1u32;
        let budget = cash.clone().min(max_money).min(max_shares / &c.share_scale);
        let inputs = proportional(buys, &budget, &cash);
        for (fill, input) in result.buys.iter_mut().zip(inputs) {
            fill.output = &input * &c.share_scale;
            fill.input = input;
        }
        result.reserve = result.buys.iter().map(|f| &f.input).sum();
        result.curve_mass = result.reserve.clone();
        result.shares = &result.reserve * &c.share_scale;
        c.check_shares(&result.shares)?;
        return Ok(result);
    }
    let full = candidate(w, buys, sells, &cash, &sold, &cash, &sold)?;
    let bps = max_price_change_bps;
    let result =
        if within_range(c, &full) && within_upper(w, &full, bps) && within_lower(w, &full, bps) {
            full
        } else {
            let reduce_buys = !within_upper(w, &full, bps) || !within_range(c, &full);
            let mut low = Amount::zero();
            let mut high = if reduce_buys {
                cash.clone()
            } else {
                sold.clone()
            };
            let mut best = empty(w, buys, sells);
            let evaluate = |budget: &Amount| {
                if reduce_buys {
                    candidate(w, buys, sells, budget, &sold, &cash, &sold)
                } else {
                    candidate(w, buys, sells, &cash, budget, &cash, &sold)
                }
            };
            let initial = evaluate(&low)?;
            let (mut low_gap, mut low_divisor) = constraint_gap(c, w, &initial, bps, reduce_buys);
            let (mut high_gap, mut high_divisor) = constraint_gap(c, w, &full, bps, reduce_buys);
            if low_gap <= BigInt::zero()
                && within_upper(w, &initial, bps)
                && within_lower(w, &initial, bps)
            {
                best = initial;
            }
            let mut iteration = 0usize;
            while low_gap <= BigInt::zero() && &high - &low > Amount::one() {
                // Rational interpolation usually reaches a smooth curve boundary
                // quickly. Regular bisection guarantees bounded progress when dust
                // removal makes the integer fill function discontinuous.
                let mid = if iteration % 4 != 3 && low_gap < BigInt::zero() {
                    let a = (-&low_gap).to_biguint().unwrap() * &high_divisor;
                    let b = high_gap.to_biguint().unwrap() * &low_divisor;
                    (&low + (&high - &low) * &a / (a + b))
                        .max(&low + 1u32)
                        .min(&high - 1u32)
                } else {
                    (&low + &high) >> 1usize
                };
                iteration += 1;
                let next = evaluate(&mid)?;
                let (gap, divisor) = constraint_gap(c, w, &next, bps, reduce_buys);
                if gap <= BigInt::zero() {
                    if within_upper(w, &next, bps) && within_lower(w, &next, bps) {
                        best = next;
                    }
                    low = mid;
                    low_gap = gap;
                    low_divisor = divisor;
                } else {
                    high = mid;
                    high_gap = gap;
                    high_divisor = divisor;
                }
            }
            best
        };
    c.check_amount(&result.reserve)?;
    c.check_amount(&result.curve_mass)?;
    c.check_shares(&result.shares)?;
    ensure!(
        within_upper(w, &result, bps) && within_lower(w, &result, bps),
        "batch price move limit"
    );
    Ok(result)
}
