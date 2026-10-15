use hashstash::{math, types::Amount};
use num_traits::{One, Zero};

fn amount(value: u32) -> Amount {
    value.into()
}

// Independent exact rational oracles for small exponents. The production
// general algorithm does not exponentiate by these arbitrary denominators.
fn exact_deposit(r: &Amount, s: &Amount, d: &Amount, u: u32, v: u32) -> Amount {
    (((r + d).pow(u) * s.pow(v)) / r.pow(u)).nth_root(v)
}

fn exact_retained(r: &Amount, s: &Amount, burn: &Amount, u: u32, v: u32) -> Amount {
    let numerator = r.pow(u) * (s - burn).pow(v);
    let denominator = s.pow(v);
    let mut result = (&numerator / &denominator).nth_root(u);
    if result.pow(u) * denominator < numerator {
        result += 1u32;
    }
    result
}

#[test]
fn dynamic_flat_curve_is_exact_in_both_directions() {
    for (r0, s0) in [(1, 7), (7, 1), (17, 103), (103, 17)] {
        let r = amount(r0);
        let s = amount(s0);
        for d0 in [0, 1, 7, 101] {
            let d = amount(d0);
            assert_eq!(
                math::dynamic_deposit_total(&r, &s, &d, &r).unwrap(),
                &s * (&r + &d) / &r
            );
        }
        for b0 in [0, 1, s0 / 2, s0] {
            let b = amount(b0);
            let expected = (&r * (&s - &b) + &s - 1u32) / &s;
            assert_eq!(
                math::dynamic_remaining_reserve(&r, &s, &b, &r).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn directed_general_powers_enclose_exact_rational_quotes() {
    // Denominators above eight force the interval path.
    for (u, v) in [(1, 3), (2, 11), (7, 13), (11, 17), (29, 31)] {
        let r = amount(u * 3);
        let m = amount(v * 3);
        for s0 in [7, 128, 10_000] {
            let s = amount(s0);
            for d0 in [1, 5, 31] {
                let d = amount(d0);
                let exact = exact_deposit(&r, &s, &d, u, v);
                let actual = math::dynamic_deposit_total(&r, &s, &d, &m).unwrap();
                assert!(actual <= exact, "over-issued stash at {u}/{v}");
                assert!(
                    &exact - &actual <= Amount::one(),
                    "excessive deposit error at {u}/{v}"
                );
            }
            for b0 in [1, s0 / 2, s0 - 1, s0] {
                let burn = amount(b0);
                let exact = exact_retained(&r, &s, &burn, u, v);
                let actual = math::dynamic_remaining_reserve(&r, &s, &burn, &m).unwrap();
                assert!(actual >= exact, "overpaid withdrawal at {u}/{v}");
                assert!(
                    &actual - &exact <= Amount::one(),
                    "excessive withdrawal error at {u}/{v}"
                );
            }
        }
    }
}

#[test]
fn mass_rounding_prevents_profitable_trade_reversals() {
    for (r0, m0, s0) in [
        (2, 11, 997),
        (7, 13, 113),
        (11, 17, 10_001),
        (29, 31, 101),
        (17, 17, 103),
    ] {
        let r = amount(r0);
        let m = amount(m0);
        let s = amount(s0);
        for d0 in [1, 5, 31] {
            let d = amount(d0);
            let next_r = &r + &d;
            let next_s = math::dynamic_deposit_total(&r, &s, &d, &m).unwrap();
            let next_m = math::deposit_mass(&r, &m, &next_r).unwrap();
            let retained =
                math::dynamic_remaining_reserve(&next_r, &next_s, &(&next_s - &s), &next_m)
                    .unwrap();
            assert!(&next_r - retained <= d, "profitable buy/sell at {r0}/{m0}");
            assert!(next_m >= next_r);
        }
        for b0 in [1, s0 / 3, s0 / 2] {
            let burn = amount(b0);
            let next_r = math::dynamic_remaining_reserve(&r, &s, &burn, &m).unwrap();
            let next_s = &s - &burn;
            let next_m = math::remaining_mass(&r, &m, &next_r).unwrap();
            let bought_s =
                math::dynamic_deposit_total(&next_r, &next_s, &(&r - &next_r), &next_m).unwrap();
            assert!(bought_s <= s, "profitable sell/buy at {r0}/{m0}");
            assert!(next_m >= next_r);
        }
    }
}

#[test]
fn inverse_matches_the_actual_conservative_quote() {
    for (r0, m0, s0) in [(6, 33, 97), (21, 39, 113), (33, 51, 1_003), (17, 17, 103)] {
        let r = amount(r0);
        let m = amount(m0);
        let s = amount(s0);
        for target0 in [1, r0 / 2, r0 - 1, r0] {
            let target = amount(target0);
            let burn = math::dynamic_withdrawal_shares(&r, &s, &target, &m).unwrap();
            assert!(&r - math::dynamic_remaining_reserve(&r, &s, &burn, &m).unwrap() >= target);
            assert!(
                &r - math::dynamic_remaining_reserve(&r, &s, &(&burn - 1u32), &m).unwrap() < target
            );
        }
    }
}

#[test]
fn extreme_precisions_and_exponents_are_bounded() {
    let max = (Amount::one() << 512usize) - 1u32;
    let r = &max / 4u32;
    let s = &max / 8u32;
    let m = &r + 1u32;
    let d = amount(11);
    let next_s = math::dynamic_deposit_total(&r, &s, &d, &m).unwrap();
    assert!(next_s >= s && next_s <= &s * (&r + &d) / &r);
    let next_m = math::deposit_mass(&r, &m, &(&r + &d)).unwrap();
    assert!(
        &r + &d
            - math::dynamic_remaining_reserve(&(&r + &d), &next_s, &(&next_s - &s), &next_m)
                .unwrap()
            <= d
    );

    // M/R can be nearly 2^512. A nonempty curve keeps one reserve atom rather
    // than allocating memory or iterations proportional to that exponent.
    assert_eq!(
        math::dynamic_remaining_reserve(&amount(3), &amount(100), &amount(1), &max).unwrap(),
        Amount::one()
    );
    assert_eq!(
        math::dynamic_remaining_reserve(&amount(3), &amount(100), &amount(100), &max).unwrap(),
        Amount::zero()
    );
    assert_eq!(
        math::dynamic_deposit_total(&amount(3), &s, &amount(1), &max).unwrap(),
        s
    );
    assert!(math::deposit_mass(&amount(3), &max, &amount(4)).is_err());

    let too_large = Amount::one() << 512usize;
    assert!(math::dynamic_deposit_total(&amount(1), &too_large, &amount(1), &amount(1)).is_err());
    assert!(math::dynamic_deposit_total(&max, &amount(1), &amount(1), &max).is_err());
    assert!(
        math::dynamic_remaining_reserve(&amount(2), &amount(3), &amount(4), &amount(2)).is_err()
    );
    assert!(
        math::dynamic_remaining_reserve(&amount(2), &amount(3), &amount(1), &amount(1)).is_err()
    );
}
