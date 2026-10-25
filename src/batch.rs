//! Simultaneous amount-only reserve trading. Order identifiers associate results;
//! they never select a price, a fill fraction, or a rounding beneficiary.
use crate::{
    config::Config,
    crypto, math,
    state::World,
    types::{Amount, Hash},
};
use anyhow::{Result, ensure};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use std::{
    cell::{Cell, OnceCell, RefCell},
    cmp::Ordering,
    collections::{BTreeSet, VecDeque},
    sync::{Mutex, PoisonError},
};

/// Curve evaluations (each a pair of directed logarithms, or one exact power
/// comparison) that clearing one world may perform. An exhausted budget stops
/// refining: price brackets keep their proven bounds and the budget search
/// keeps its best proven candidate.
///
/// It bounds curve evaluations only, not all clearing work (audit L067).
/// Comparisons decided by integer checks, the simplest-fraction step, each
/// candidate's O(n) allocation and its dust and full-redemption loops are
/// not charged (the price searches those loops repeat are, until the limit
/// is reached). A flat world spends no evaluations at all, so its budget
/// search ends only through its own convergence rule. These costs are
/// polynomial in the order count; charging them would change consensus
/// (docs/SPECIFICATION.md, "Reference clearing algorithm").
pub const CLEARING_WORK: u64 = 1024;
/// Root-search probes taken from Newton steps before plain bisection resumes.
const NEWTON_PROBES: usize = 64;
/// A budget search wider than one atom stops within this relative precision.
const BUDGET_PRECISION_BITS: usize = 64;
/// Most recent consensus clearings that spent curve work, kept by
/// [clear_memoized]. The fill bound caps the memory held and leaves room for
/// both worlds of a block at the signature limit.
const MEMO_ENTRIES: usize = 16;
const MEMO_FILLS: usize = 16_384;

/// [clear] is a pure function of the configuration, the opening curve, the
/// ordered orders and the bound, so block execution memoizes its results by a
/// hash of all of them. A reselection whose included orders and opening curve
/// did not change, such as one for an unrelated transaction or a future nonce,
/// reuses the clearing instead of repeating its curve work. Results never
/// depend on what the memo holds.
static MEMO: Mutex<VecDeque<(Hash, Clearing)>> = Mutex::new(VecDeque::new());

#[cfg(any(test, feature = "test-fixtures"))]
thread_local! {
    /// Curve evaluations spent by clearings run on this thread. A memo hit
    /// spends none. Test instrumentation only; it never affects a result.
    static CURVE_EVALUATIONS: Cell<u64> = const { Cell::new(0) };
}

/// Test instrumentation: the curve evaluations clearing has spent on the
/// calling thread so far, memo hits excluded.
#[cfg(any(test, feature = "test-fixtures"))]
#[doc(hidden)]
pub fn thread_curve_evaluations() -> u64 {
    CURVE_EVALUATIONS.with(Cell::get)
}

/// Deterministic count of the curve evaluations spent by one clearing, and the
/// last price it found as (units, scale): candidates of one clearing have
/// nearby prices, so each price search starts there.
struct Work {
    used: Cell<u64>,
    limit: u64,
    last_price: RefCell<Option<(Amount, Amount)>>,
}
impl Work {
    fn spend(&self) -> bool {
        let used = self.used.get();
        if used >= self.limit {
            return false;
        }
        self.used.set(used + 1);
        true
    }
    fn exhausted(&self) -> bool {
        self.used.get() >= self.limit
    }
}

/// The inputs a bound-constrained budget search reduces.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Buys,
    Sells,
    Both,
}

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

/// A bisection probe strictly inside a bracket wider than one unit. While the
/// bracket spans more than a factor of two it uses the integer geometric mean,
/// so a price range of many octaves needs only logarithmically many probes.
fn bisect(lower: &Amount, upper: &Amount) -> Amount {
    if !lower.is_zero() && upper > &(lower << 1usize) {
        (lower * upper).sqrt().max(lower + 1u32).min(upper - 1u32)
    } else {
        (lower + upper) >> 1usize
    }
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
/// Directed logarithm bounds decide most comparisons; exact small-rational
/// curves settle the rest with integer powers. The search deliberately retains
/// unresolved comparisons, and every curve evaluation spends clearing work.
fn price(w: &World, cash: &Amount, sold: &Amount, work: &Work) -> Result<(Amount, Amount, Amount)> {
    let (low, high, scale) = search_price(w, cash, sold, work)?;
    *work.last_price.borrow_mut() = Some(((&low + &high) >> 1usize, scale.clone()));
    Ok((low, high, scale))
}

fn search_price(
    w: &World,
    cash: &Amount,
    sold: &Amount,
    work: &Work,
) -> Result<(Amount, Amount, Amount)> {
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
    // prices. It is arithmetic precision, independent of order identifiers,
    // and a consensus constant: outputs are computed on this grid.
    let scale = Amount::one() << (2 * bits as usize + 32);
    let precision = math::clearing_precision(bits);
    let buying = balance == Ordering::Greater;
    // The ideal price is a chord slope of the convex reserve-by-supply curve, so
    // it lies between the opening and closing marginal prices. The closing
    // price is at most M*R'/(R*S) when supply grows and at least that when it
    // shrinks, with R' = R+D-B*P; solving for P gives M(R+D)/(RS+MB). It bounds
    // a buy from above and a sale from below, close to the root for small net
    // trades, which keeps Newton steps inside the bracket from the start.
    let closing_numerator = &w.curve_mass * (&w.reserve + cash) * &scale;
    let closing_denominator = &w.reserve * &w.shares + &w.curve_mass * sold;
    let mut lower = if buying {
        &w.curve_mass * &scale / &w.shares
    } else {
        (&w.reserve * &scale / &w.shares).max(&closing_numerator / &closing_denominator)
    };
    let mut upper = if buying {
        ceil(&closing_numerator, &closing_denominator)
    } else {
        ceil(&(&w.curve_mass * &scale), &w.shares)
    };
    if buying && !sold.is_zero() {
        upper = upper.min(ceil(&(cash * &scale), sold));
    }
    let exact_ratio = math::small_ratio(&w.reserve, &w.curve_mass);
    // A one-sided batch has one logarithm independent of the probe: ln((R+D)/R)
    // for pure buys and ln(S/(S-B)) for pure sales. Bounds depend only on the
    // ratio, so evaluating it once gives the same comparisons.
    let fixed_log = OnceCell::new();
    let fixed = || {
        fixed_log.get_or_init(|| {
            if buying {
                math::curve_log(&(&w.reserve + cash), &w.reserve, precision)
            } else {
                math::curve_log(&w.shares, &(&w.shares - sold), precision)
            }
        })
    };
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
        if !work.spend() {
            return None;
        }
        let (first, second);
        let (left, right) = if buying && sold.is_zero() {
            first = math::curve_log(&c, &d, precision);
            (fixed(), &first)
        } else if !buying && cash.is_zero() {
            first = math::curve_log(&a, &b, precision);
            (&first, fixed())
        } else {
            first = math::curve_log(&a, &b, precision);
            second = math::curve_log(&c, &d, precision);
            (&first, &second)
        };
        let (comparison, midpoint, log_scale) =
            math::curve_log_evaluation(&w.reserve, &w.curve_mass, left, right);
        *last_log.borrow_mut() = Some((p.clone(), denominator.clone(), midpoint, log_scale));
        match (comparison, exact_ratio) {
            // A proven logarithm comparison already agrees with the exact one.
            (None, Some(ratio)) if work.spend() => {
                Some(math::compare_curve_powers(ratio, &a, &b, &c, &d))
            }
            _ => comparison,
        }
    };
    let compare = |p: &Amount| compare_fraction(p, &scale);
    let newton = |p: &Amount, comparison: Option<Ordering>| -> Option<Amount> {
        if p.is_zero() {
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
            // Reuse the comparison just made at p and step to its neighbour.
            match comparison {
                Some(Ordering::Less) => Some(p + 1u32),
                Some(Ordering::Greater) => Some(p - 1u32),
                _ => None,
            }
        } else {
            Some(proposal)
        }
    };
    // Begin where the previous search of this clearing ended, when that lies
    // inside the bracket; later probes come from Newton steps or bisection.
    let mut proposal = work
        .last_price
        .borrow()
        .as_ref()
        .map(|(p, from)| p * &scale / from);
    let mut newton_probes = 0;
    while &upper - &lower > Amount::one() && !work.exhausted() {
        // Newton proposals must lie strictly inside the bracket, and only a
        // fixed number are used. Bisection then guarantees bounded progress.
        let mid = match proposal.take().filter(|p| p > &lower && p < &upper) {
            Some(p) if newton_probes < NEWTON_PROBES => {
                newton_probes += 1;
                p
            }
            _ => bisect(&lower, &upper),
        };
        let comparison = compare(&mid);
        match comparison {
            Some(Ordering::Less) => {
                lower = mid.clone();
                proposal = newton(&mid, comparison);
            }
            Some(Ordering::Greater) => {
                upper = mid.clone();
                proposal = newton(&mid, comparison);
            }
            Some(Ordering::Equal) => return Ok((mid.clone(), mid, scale)),
            None => {
                // A bracket edge next to mid needs no further proof, so a root
                // on the grid costs one neighbour probe rather than a bisection.
                let below = &mid - 1u32;
                let above = &mid + 1u32;
                if (below == lower || compare(&below) == Some(Ordering::Less))
                    && (above == upper || compare(&above) == Some(Ordering::Greater))
                {
                    lower = below;
                    upper = above;
                    break;
                }
                // Locate the last proven lower bound and first proven upper
                // bound independently; never assume the sign of an overlap.
                let mut hi = mid.clone();
                while &hi - &lower > Amount::one() && !work.exhausted() {
                    let probe = (&lower + &hi) >> 1usize;
                    match compare(&probe) {
                        Some(Ordering::Less) => lower = probe,
                        Some(Ordering::Equal) => return Ok((probe.clone(), probe, scale)),
                        _ => hi = probe,
                    }
                }
                let mut lo = mid;
                while &upper - &lo > Amount::one() && !work.exhausted() {
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
    // Logarithm bounds prove equality only without net movement, which the
    // early comparisons exclude, so only exact power curves and an exact full
    // redemption (decided without curve work) can recover a boundary here.
    if !work.exhausted() && (exact_ratio.is_some() || (sold == &w.shares && cash.is_zero())) {
        let (n, d) = simplest_fraction(lower.clone(), scale.clone(), upper.clone(), scale.clone());
        if compare_fraction(&n, &d) == Some(Ordering::Equal) {
            return Ok((n.clone(), n, d));
        }
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

/// Signed relative distance from the active constraints: the upper price bound
/// when `upward`, otherwise the lower one, and the numeric range. This only
/// chooses a search probe; every retained result still passes the exact
/// inequalities.
fn constraint_gap(
    c: &Config,
    w: &World,
    result: &Clearing,
    bps: u64,
    upward: bool,
) -> (BigInt, Amount) {
    let max_money = (Amount::one() << c.money_bits as usize) - 1u32;
    let max_shares = (Amount::one() << c.share_bits as usize) - 1u32;
    let (numerator, denominator) = if upward {
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

#[allow(clippy::too_many_arguments)]
fn candidate(
    w: &World,
    buys: &[Order],
    sells: &[Order],
    buy_budget: &Amount,
    sell_budget: &Amount,
    total_cash: &Amount,
    total_sold: &Amount,
    work: &Work,
) -> Result<Clearing> {
    let mut input_buys = proportional(buys, buy_budget, total_cash);
    let mut input_sells = proportional(sells, sell_budget, total_sold);
    let flat = w.reserve == w.curve_mass;
    loop {
        let cash = sum(&input_buys);
        let sold = sum(&input_sells);
        if cash.is_zero() && sold.is_zero() {
            return Ok(empty(w, buys, sells));
        }
        let (low, high, scale) = price(w, &cash, &sold, work)?;
        let output_buys: Vec<Amount> = input_buys.iter().map(|n| n * &scale / &high).collect();
        let output_sells: Vec<Amount> = input_sells.iter().map(|n| n * &low / &scale).collect();
        if flat {
            // The flat price M/S is exact and independent of volume. Each order
            // pays only the least input that buys its rounded-down output and the
            // unusable remainder is refunded, not donated. Exact outputs, such as
            // every trade at a unit-numerator or unit-denominator price like the
            // genesis rate, leave the price unchanged; any other order raises it
            // by less than one atom of its input asset, so no reduced-price lot
            // can grow to the whole reserve or supply.
            for (input, output) in input_buys.iter_mut().zip(&output_buys) {
                *input = ceil(&(output * &high), &scale);
            }
            for (input, output) in input_sells.iter_mut().zip(&output_sells) {
                *input = ceil(&(output * &scale), &low);
            }
        }
        let cash = sum(&input_buys);
        let sold = sum(&input_sells);
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
        let mass = math::scaled_mass(&w.reserve, &w.curve_mass, &reserve);
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
    Ok(clear_with_work(c, w, buys, sells, max_price_change_bps, CLEARING_WORK)?.0)
}

/// [clear] through the memo of recent results. Block execution uses it for
/// selection, templates and validation; one-order estimates use [clear], so
/// they cannot displace the clearings that reselection reuses.
pub fn clear_memoized(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    max_price_change_bps: u64,
) -> Result<Clearing> {
    let key = memo_key(c, w, buys, sells, max_price_change_bps);
    if let Some(result) = memo_hit(&key) {
        return Ok(result);
    }
    let (result, work) = clear_with_work(c, w, buys, sells, max_price_change_bps, CLEARING_WORK)?;
    let fills = result.buys.len() + result.sells.len();
    // Clearing without curve work is as cheap as hashing its inputs.
    if work > 0 && fills <= MEMO_FILLS {
        let mut memo = MEMO.lock().unwrap_or_else(PoisonError::into_inner);
        // Another thread may have cleared the same inputs meanwhile.
        memo.retain(|(k, _)| *k != key);
        memo.push_front((key, result.clone()));
        let mut held = 0;
        let kept = memo
            .iter()
            .take(MEMO_ENTRIES)
            .take_while(|(_, r)| {
                held += r.buys.len() + r.sells.len();
                held <= MEMO_FILLS
            })
            .count();
        memo.truncate(kept);
    }
    Ok(result)
}

/// Test and diagnostic helper: the result [clear_memoized] holds for these
/// inputs, if any. It does not change the memo.
#[doc(hidden)]
pub fn memo_peek(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    max_price_change_bps: u64,
) -> Option<Clearing> {
    let key = memo_key(c, w, buys, sells, max_price_change_bps);
    let memo = MEMO.lock().unwrap_or_else(PoisonError::into_inner);
    memo.iter().find(|(k, _)| *k == key).map(|(_, r)| r.clone())
}

/// A hit moves to the front, so alternating worlds and repeated reselections
/// keep their entries.
fn memo_hit(key: &Hash) -> Option<Clearing> {
    let mut memo = MEMO.lock().unwrap_or_else(PoisonError::into_inner);
    let index = memo.iter().position(|(k, _)| k == key)?;
    let entry = memo.remove(index)?;
    let result = entry.1.clone();
    memo.push_front(entry);
    Some(result)
}

/// Every input of [clear], length-prefixed: the whole encoded configuration,
/// the opening curve, the bound, and each side's orders in their given order.
fn memo_key(c: &Config, w: &World, buys: &[Order], sells: &[Order], bps: u64) -> Hash {
    fn put(bytes: &mut Vec<u8>, data: &[u8]) {
        bytes.extend_from_slice(&(data.len() as u64).to_be_bytes());
        bytes.extend_from_slice(data);
    }
    let mut bytes = Vec::new();
    put(&mut bytes, &c.consensus_bytes());
    for n in [&w.reserve, &w.shares, &w.curve_mass] {
        put(&mut bytes, &n.to_bytes_be());
    }
    bytes.extend_from_slice(&bps.to_be_bytes());
    for side in [buys, sells] {
        bytes.extend_from_slice(&(side.len() as u64).to_be_bytes());
        for o in side {
            bytes.extend_from_slice(&o.id);
            put(&mut bytes, &o.amount.to_bytes_be());
        }
    }
    crypto::tagged_hash("Hashstash/clearing-memo", &bytes)
}

/// [clear] with an explicit curve-evaluation limit, also returning the work
/// spent. Consensus always uses [CLEARING_WORK]; other limits exercise the
/// deterministic fallback.
pub fn clear_with_work(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    max_price_change_bps: u64,
    limit: u64,
) -> Result<(Clearing, u64)> {
    let work = Work {
        used: Cell::new(0),
        limit,
        last_price: RefCell::new(None),
    };
    let result = clear_metered(c, w, buys, sells, max_price_change_bps, &work);
    #[cfg(any(test, feature = "test-fixtures"))]
    CURVE_EVALUATIONS.with(|spent| spent.set(spent.get() + work.used.get()));
    Ok((result?, work.used.get()))
}

fn clear_metered(
    c: &Config,
    w: &World,
    buys: &[Order],
    sells: &[Order],
    max_price_change_bps: u64,
    work: &Work,
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
    let full = candidate(w, buys, sells, &cash, &sold, &cash, &sold, work)?;
    let bps = max_price_change_bps;
    let result =
        if within_range(c, &full) && within_upper(w, &full, bps) && within_lower(w, &full, bps) {
            full
        } else {
            let upward = !within_upper(w, &full, bps) || !within_range(c, &full);
            // Buys raise the price and the reserve; sales lower the price. On a
            // flat world a sale raises the price as well whenever its output is
            // inexact, and nothing lowers it. There, when removing all of the
            // usual side's input still breaks the bound, the other side is
            // reduced while the first keeps its full input, and when that fails
            // too, both sides by the same fraction. The chosen side then starts
            // from a passing candidate, so one side's rounding cannot refuse
            // every order of the other. A curved sale raises the price only
            // through rounding, and searching the opposite side there would
            // spend curve work on candidates its own movement then refuses.
            let usual = if upward { Side::Buys } else { Side::Sells };
            let other = if upward { Side::Sells } else { Side::Buys };
            let families: &[Side] = if w.reserve == w.curve_mass {
                &[other, Side::Both]
            } else {
                &[]
            };
            let evaluate = |side: Side, budget: &Amount| match side {
                Side::Buys => candidate(w, buys, sells, budget, &sold, &cash, &sold, work),
                Side::Sells => candidate(w, buys, sells, &cash, budget, &cash, &sold, work),
                Side::Both => {
                    let sale = if cash.is_zero() {
                        Amount::zero()
                    } else {
                        &sold * budget / &cash
                    };
                    candidate(w, buys, sells, budget, &sale, &cash, &sold, work)
                }
            };
            let mut side = usual;
            let mut initial = evaluate(side, &Amount::zero())?;
            let (mut low_gap, mut low_divisor) = constraint_gap(c, w, &initial, bps, upward);
            // The opening curve itself meets every bound, so Both always starts.
            for &next in families {
                if low_gap <= BigInt::zero() {
                    break;
                }
                side = next;
                initial = evaluate(side, &Amount::zero())?;
                (low_gap, low_divisor) = constraint_gap(c, w, &initial, bps, upward);
            }
            let mut low = Amount::zero();
            let mut high = if side == Side::Sells {
                sold.clone()
            } else {
                cash.clone()
            };
            let mut best = empty(w, buys, sells);
            let (mut high_gap, mut high_divisor) = constraint_gap(c, w, &full, bps, upward);
            if low_gap <= BigInt::zero()
                && within_upper(w, &initial, bps)
                && within_lower(w, &initial, bps)
            {
                best = initial;
            }
            // Consecutive moves of the same end; the other end's weight halves.
            let (mut low_retained, mut high_retained) = (0usize, 0usize);
            // Bisections owed after an interpolation that failed to halve the
            // moved end's relative gap; consecutive failures double them.
            let (mut failures, mut bisections) = (0usize, 0usize);
            // Search to one atom, or to a 2^-BUDGET_PRECISION_BITS fraction of a
            // wider retained budget. Exhausted clearing work keeps the best
            // proven candidate so far.
            while low_gap <= BigInt::zero()
                && &high - &low > (&low >> BUDGET_PRECISION_BITS).max(Amount::one())
                && !work.exhausted()
            {
                // Rational interpolation usually reaches a smooth curve boundary
                // quickly; the Illinois weighting stops a convex boundary from
                // pinning one end. Bisection after failed interpolation bounds
                // progress when dust removal makes the integer fill function
                // discontinuous or a nearly flat curve makes it a step.
                let interpolated = bisections == 0 && low_gap < BigInt::zero();
                let mid = if interpolated {
                    let a = ((-&low_gap).to_biguint().unwrap() * &high_divisor)
                        >> low_retained.saturating_sub(1);
                    let b = (high_gap.to_biguint().unwrap() * &low_divisor)
                        >> high_retained.saturating_sub(1);
                    let (a, b) = (a.max(Amount::one()), b.max(Amount::one()));
                    (&low + (&high - &low) * &a / (a + b))
                        .max(&low + 1u32)
                        .min(&high - 1u32)
                } else {
                    // A zero-gap or price-free side often ends a few atoms above
                    // zero, so bisect geometrically from one atom.
                    bisect(&low.clone().max(Amount::one()), &high).max(&low + 1u32)
                };
                let next = evaluate(side, &mid)?;
                let (gap, divisor) = constraint_gap(c, w, &next, bps, upward);
                let passed = gap <= BigInt::zero();
                let (old, old_divisor) = if passed {
                    (&low_gap, &low_divisor)
                } else {
                    (&high_gap, &high_divisor)
                };
                // Whether the moved end's relative gap at least halved.
                let halved = gap.magnitude() * old_divisor * 2u32 <= old.magnitude() * &divisor;
                if passed {
                    if within_upper(w, &next, bps) && within_lower(w, &next, bps) {
                        best = next;
                    }
                    low = mid;
                    low_gap = gap;
                    low_divisor = divisor;
                    (low_retained, high_retained) = (0, high_retained + 1);
                } else {
                    high = mid;
                    high_gap = gap;
                    high_divisor = divisor;
                    (low_retained, high_retained) = (low_retained + 1, 0);
                }
                if !interpolated {
                    bisections = bisections.saturating_sub(1);
                } else if halved {
                    failures = 0;
                } else {
                    bisections = 1 << failures.min(16);
                    failures += 1;
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
