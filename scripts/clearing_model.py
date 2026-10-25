"""Independent model of the normative batch-clearing algorithm.

Written from docs/SPECIFICATION.md ("Reference clearing algorithm") and
docs/CONSENSUS.md, not translated from src/batch.rs or src/math.rs. It
computes the cross-implementation vectors in tests/data/clearing-vectors.json,
which tests/clearing_vectors.rs checks against the Rust node and
scripts/test_consensus_models.py checks against this model.

    python3 scripts/clearing_model.py --write   # regenerate the vectors
    python3 scripts/clearing_model.py --check   # compare with the file

Only integers are used. `//` is floor division of non-negative values;
`tdiv` truncates signed quotients toward zero, as the specification says.
"""
import json
import math
import os
import sys

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data",
                       "clearing-vectors.json")

CLEARING_WORK = 1024
NEWTON_PROBES = 64
BUDGET_PRECISION_BITS = 64
MAX_LOG_BITS = 2048
PRECISION_STEP = 64

LESS, EQUAL, GREATER = -1, 0, 1


def ceil_div(n, d):
    assert d > 0 and n >= 0
    return 0 if n == 0 else (n - 1) // d + 1


def tdiv(n, d):
    """Signed division truncated toward zero."""
    q = abs(n) // abs(d)
    return q if (n >= 0) == (d >= 0) else -q


def cmp(a, b):
    return (a > b) - (a < b)


# ---- directed logarithms ------------------------------------------------
def atanh_bounds(zn, zd, bits):
    """2*atanh(zn/zd) enclosed in units of 2^-bits, every step rounded outwards."""
    if zn == 0:
        return (0, 0)
    terms = ceil_div(bits, 3)
    unit = 1 << bits
    z_low, z_high = (zn << bits) // zd, ceil_div(zn << bits, zd)
    sq_low, sq_high = (z_low * z_low) >> bits, ceil_div(z_high * z_high, unit)
    p_low, p_high, s_low, s_high = z_low, z_high, 0, 0
    for k in range(terms):
        s_low += p_low // (2 * k + 1)
        s_high += ceil_div(p_high, 2 * k + 1)
        p_low = (p_low * sq_low) >> bits
        p_high = ceil_div(p_high * sq_high, unit)
    return (2 * s_low, 2 * s_high + 1)


_LN2 = {}


def ln2(bits):
    if bits not in _LN2:
        _LN2[bits] = atanh_bounds(1, 3, bits)
    return _LN2[bits]


def log_bounds(n, d, bits):
    """Directed bounds of ln(n/d) for n >= d > 0."""
    assert n >= d > 0
    shift = n.bit_length() - d.bit_length()
    nd = d << shift
    if nd > n:
        shift -= 1
        nd >>= 1
    low, high = atanh_bounds(n - nd, n + nd, bits)
    if shift:
        low += ln2(bits)[0] * shift
        high += ln2(bits)[1] * shift
    return (low, high)


def precision(n_bits):
    return min(ceil_div(4 * n_bits + 128, PRECISION_STEP) * PRECISION_STEP, MAX_LOG_BITS)


def small_ratio(r, m):
    g = math.gcd(r, m)
    u, v = r // g, m // g
    return (u, v) if v <= 8 else None


def bisect(lower, upper):
    if lower > 0 and upper > 2 * lower:
        return min(max(math.isqrt(lower * upper), lower + 1), upper - 1)
    return (lower + upper) >> 1


def simplest_fraction(a, b, c, d):
    terms = []
    while True:
        f = a // b
        if a % b == 0:
            n, den = f, 1
            break
        if f < c // d:
            n, den = f + 1, 1
            break
        terms.append(f)
        a, b, c, d = d, c - f * d, b, a - f * b
    for t in reversed(terms):
        n, den = t * n + den, n
    return n, den


# ---- clearing ------------------------------------------------------------
class Work:
    def __init__(self, limit):
        self.used, self.limit, self.last_price = 0, limit, None

    def spend(self):
        if self.used >= self.limit:
            return False
        self.used += 1
        return True

    def exhausted(self):
        return self.used >= self.limit


def search_price(w, cash, sold, work):
    R, S, M = w["reserve"], w["shares"], w["mass"]
    balance = cmp(cash * S, sold * M)
    if balance == EQUAL or R == M:
        return M, M, S
    n = max(x.bit_length() for x in (R, S, M, cash, sold))
    scale = 1 << (2 * n + 32)
    bits = precision(n)
    buying = balance == GREATER
    cn = M * (R + cash) * scale
    cd = R * S + M * sold
    lower = M * scale // S if buying else max(R * scale // S, cn // cd)
    upper = ceil_div(cn, cd) if buying else ceil_div(M * scale, S)
    if buying and sold:
        upper = min(upper, ceil_div(cash * scale, sold))
    exact = small_ratio(R, M)
    fixed = {}
    last_log = [None]

    def fixed_log():
        if "v" not in fixed:
            fixed["v"] = log_bounds(R + cash, R, bits) if buying else log_bounds(S, S - sold, bits)
        return fixed["v"]

    def compare_fraction(p, den):
        if p == 0:
            return LESS
        cs, ss = cash * den, sold * p
        if buying and cs <= ss:
            return GREATER
        if not buying and cs >= ss:
            return LESS
        rb, rt = R * den, (R + cash) * den
        if rt <= ss:
            return EQUAL if (rt == ss and sold == S and cash == 0) else GREATER
        nr = rt - ss
        sb = S * p
        ns = (S - sold) * p + cs
        if ns == 0:
            return LESS
        a, b, c, d = (nr, rb, ns, sb) if buying else (rb, nr, sb, ns)
        if not work.spend():
            return None
        if buying and sold == 0:
            left, right = fixed_log(), log_bounds(c, d, bits)
        elif not buying and cash == 0:
            left, right = log_bounds(a, b, bits), fixed_log()
        else:
            left, right = log_bounds(a, b, bits), log_bounds(c, d, bits)
        lo = left[0] * R - right[1] * M
        hi = left[1] * R - right[0] * M
        if hi < 0:
            result = LESS
        elif lo > 0:
            result = GREATER
        elif left[1] == 0 and right[1] == 0:
            result = EQUAL
        else:
            result = None
        last_log[0] = (p, den, tdiv(lo + hi, 2), 1 << bits)
        if result is None and exact is not None and work.spend():
            u, v = exact
            result = cmp(a ** u * d ** v, b ** u * c ** v)
        return result

    def compare(p):
        return compare_fraction(p, scale)

    def newton(p, comparison):
        if p == 0:
            return None
        cs, ss = cash * scale, sold * p
        if (buying and cs <= ss) or (not buying and cs >= ss):
            return None
        rt = (R + cash) * scale
        if rt <= ss:
            return None
        rn = rt - ss
        sn = (S - sold) * p + cs
        if sn == 0:
            return None
        if last_log[0] is None:
            return None
        lp, lden, difference, log_scale = last_log[0]
        if lp != p or lden != scale:
            return None
        derivative = M * cash * scale * rn - R * sold * p * sn
        if not buying:
            derivative = -derivative
        if derivative <= 0:
            return None
        step = tdiv(difference * (rn * p * sn), log_scale * derivative)
        proposal = p - step
        if proposal < 0:
            return None
        if proposal == p:
            return p + 1 if comparison == LESS else p - 1 if comparison == GREATER else None
        return proposal

    proposal = None
    if work.last_price is not None:
        lp, ls = work.last_price
        proposal = lp * scale // ls
    newton_probes = 0
    while upper - lower > 1 and not work.exhausted():
        if proposal is not None and lower < proposal < upper and newton_probes < NEWTON_PROBES:
            mid = proposal
            newton_probes += 1
        else:
            mid = bisect(lower, upper)
        proposal = None
        c = compare(mid)
        if c == LESS:
            lower = mid
            proposal = newton(mid, c)
        elif c == GREATER:
            upper = mid
            proposal = newton(mid, c)
        elif c == EQUAL:
            return mid, mid, scale
        else:
            below, above = mid - 1, mid + 1
            if (below == lower or compare(below) == LESS) and \
                    (above == upper or compare(above) == GREATER):
                lower, upper = below, above
                break
            hi = mid
            while hi - lower > 1 and not work.exhausted():
                probe = (lower + hi) >> 1
                pc = compare(probe)
                if pc == LESS:
                    lower = probe
                elif pc == EQUAL:
                    return probe, probe, scale
                else:
                    hi = probe
            lo = mid
            while upper - lo > 1 and not work.exhausted():
                probe = (lo + upper) >> 1
                pc = compare(probe)
                if pc == GREATER:
                    upper = probe
                elif pc == EQUAL:
                    return probe, probe, scale
                else:
                    lo = probe
            break
    if not work.exhausted() and (exact is not None or (sold == S and cash == 0)):
        n_, d_ = simplest_fraction(lower, scale, upper, scale)
        if compare_fraction(n_, d_) == EQUAL:
            return n_, n_, d_
    if upper == 0:
        raise ValueError("zero batch price")
    return lower, upper, scale


def price(w, cash, sold, work):
    low, high, scale = search_price(w, cash, sold, work)
    work.last_price = ((low + high) >> 1, scale)
    return low, high, scale


def scaled_mass(r, m, r2):
    return m * r2 // r if r2 >= r else ceil_div(m * r2, r)


def no_fill(w, buys, sells):
    return {"buys": [(0, 0)] * len(buys), "sells": [(0, 0)] * len(sells),
            "reserve": w["reserve"], "shares": w["shares"], "mass": w["mass"]}


def proportional(orders, budget, total):
    return [0 if total == 0 else a * budget // total for a in orders]


def candidate(w, buys, sells, buy_budget, sell_budget, total_cash, total_sold, work):
    R, S, M = w["reserve"], w["shares"], w["mass"]
    in_b = proportional(buys, buy_budget, total_cash)
    in_s = proportional(sells, sell_budget, total_sold)
    flat = R == M
    while True:
        cash, sold = sum(in_b), sum(in_s)
        if cash == 0 and sold == 0:
            return no_fill(w, buys, sells)
        low, high, scale = price(w, cash, sold, work)
        out_b = [x * scale // high for x in in_b]
        out_s = [x * low // scale for x in in_s]
        if flat:
            in_b = [ceil_div(o * high, scale) for o in out_b]
            in_s = [ceil_div(o * scale, low) for o in out_s]
        cash, sold = sum(in_b), sum(in_s)
        removed = False
        for ins, outs in ((in_b, out_b), (in_s, out_s)):
            for i, (x, o) in enumerate(zip(ins, outs)):
                if x and not o:
                    ins[i] = 0
                    removed = True
        if removed:
            continue
        paid = sum(out_s)
        if paid > R + cash:
            raise ValueError("batch exceeds funded reserve")
        r2 = R + cash - paid
        s2 = S + sum(out_b) - sold
        if s2 == 0 and r2 != 0:
            total = sum(in_s)
            in_s = [x * (total - 1) // total for x in in_s]
            continue
        if (r2 == 0) != (s2 == 0):
            raise ValueError("batch empty curve invariant")
        return {"buys": list(zip(in_b, out_b)), "sells": list(zip(in_s, out_s)),
                "reserve": r2, "shares": s2, "mass": scaled_mass(R, M, r2)}


def within_upper(w, x, bps):
    return x["shares"] == 0 or x["mass"] * w["shares"] * 10_000 <= w["mass"] * x["shares"] * (bps + 10_000)


def within_lower(w, x, bps):
    return bps >= 10_000 or (x["shares"] != 0 and
                             x["mass"] * w["shares"] * 10_000 >= w["mass"] * x["shares"] * (10_000 - bps))


def within_range(cfg, x):
    return (x["reserve"].bit_length() <= cfg["money_bits"] and x["mass"].bit_length() <= cfg["money_bits"]
            and x["shares"].bit_length() <= cfg["share_bits"])


def constraint_gap(cfg, w, x, bps, upward):
    max_money = (1 << cfg["money_bits"]) - 1
    max_shares = (1 << cfg["share_bits"]) - 1
    if upward:
        num, den = (0, 1) if x["shares"] == 0 else (
            x["mass"] * w["shares"] * 10_000, w["mass"] * x["shares"] * (bps + 10_000))
    elif bps >= 10_000:
        num, den = 0, 1
    elif x["shares"] == 0:
        num, den = 2, 1
    else:
        num, den = w["mass"] * x["shares"] * (10_000 - bps), x["mass"] * w["shares"] * 10_000
    gap, div = num - den, den
    for value, limit in ((x["reserve"], max_money), (x["mass"], max_money), (x["shares"], max_shares)):
        nxt = value - limit
        if nxt * div > gap * limit:
            gap, div = nxt, limit
    return gap, div


def clear(cfg, w, buys, sells, bps, limit=CLEARING_WORK):
    """Returns (clearing, curve evaluations spent)."""
    R, S, M = w["reserve"], w["shares"], w["mass"]
    assert all(a > 0 for a in buys + sells)
    assert all(a.bit_length() <= cfg["money_bits"] for a in buys)
    assert all(a.bit_length() <= cfg["share_bits"] for a in sells)
    D, B = sum(buys), sum(sells)
    assert B <= S and (R == 0) == (S == 0) == (M == 0) and M >= R
    if S == 0:
        q = cfg["share_scale"]
        budget = min(D, (1 << cfg["money_bits"]) - 1, ((1 << cfg["share_bits"]) - 1) // q)
        inputs = proportional(buys, budget, D)
        r2 = sum(inputs)
        result = {"buys": [(x, x * q) for x in inputs], "sells": [(0, 0)] * len(sells),
                  "reserve": r2, "shares": r2 * q, "mass": r2}
        assert result["shares"].bit_length() <= cfg["share_bits"]
        return result, 0
    work = Work(limit)
    full = candidate(w, buys, sells, D, B, D, B, work)
    if within_range(cfg, full) and within_upper(w, full, bps) and within_lower(w, full, bps):
        result = full
    else:
        upward = not within_upper(w, full, bps) or not within_range(cfg, full)
        usual, other = ("buys", "sells") if upward else ("sells", "buys")
        families = [other, "both"] if R == M else []

        def evaluate(side, budget):
            if side == "buys":
                return candidate(w, buys, sells, budget, B, D, B, work)
            if side == "sells":
                return candidate(w, buys, sells, D, budget, D, B, work)
            sale = 0 if D == 0 else B * budget // D
            return candidate(w, buys, sells, budget, sale, D, B, work)

        side = usual
        initial = evaluate(side, 0)
        low_gap, low_div = constraint_gap(cfg, w, initial, bps, upward)
        for nxt in families:
            if low_gap <= 0:
                break
            side = nxt
            initial = evaluate(side, 0)
            low_gap, low_div = constraint_gap(cfg, w, initial, bps, upward)
        low, high = 0, (B if side == "sells" else D)
        best = no_fill(w, buys, sells)
        high_gap, high_div = constraint_gap(cfg, w, full, bps, upward)
        if low_gap <= 0 and within_upper(w, initial, bps) and within_lower(w, initial, bps):
            best = initial
        low_kept = high_kept = 0
        failures = bisections = 0
        while low_gap <= 0 and high - low > max(low >> BUDGET_PRECISION_BITS, 1) and not work.exhausted():
            interpolated = bisections == 0 and low_gap < 0
            if interpolated:
                a = max(((-low_gap) * high_div) >> max(low_kept - 1, 0), 1)
                b = max((high_gap * low_div) >> max(high_kept - 1, 0), 1)
                mid = min(max(low + (high - low) * a // (a + b), low + 1), high - 1)
            else:
                mid = max(bisect(max(low, 1), high), low + 1)
            nxt = evaluate(side, mid)
            gap, div = constraint_gap(cfg, w, nxt, bps, upward)
            passed = gap <= 0
            old, old_div = (low_gap, low_div) if passed else (high_gap, high_div)
            halved = abs(gap) * old_div * 2 <= abs(old) * div
            if passed:
                if within_upper(w, nxt, bps) and within_lower(w, nxt, bps):
                    best = nxt
                low, low_gap, low_div = mid, gap, div
                low_kept, high_kept = 0, high_kept + 1
            else:
                high, high_gap, high_div = mid, gap, div
                low_kept, high_kept = low_kept + 1, 0
            if not interpolated:
                bisections = max(bisections - 1, 0)
            elif halved:
                failures = 0
            else:
                bisections = 1 << min(failures, 16)
                failures += 1
        result = best
    assert within_range(cfg, result), "range exceeded"
    assert within_upper(w, result, bps) and within_lower(w, result, bps), "batch price move limit"
    return result, work.used


# ---- vector cases ------------------------------------------------------
DEFAULT = {"money_bits": 128, "share_bits": 128, "share_scale": 1}


def case(name, reserve, shares, mass, buys, sells, bps, limit=CLEARING_WORK, cfg=None):
    return {"name": name, "config": dict(DEFAULT, **(cfg or {})),
            "world": {"reserve": reserve, "shares": shares, "mass": mass},
            "buys": buys, "sells": sells, "max_price_change_bps": bps, "work_limit": limit}


CASES = [
    case("bootstrap at the genesis exchange rate", 0, 0, 0, [1_000, 2_500], [], 1_000,
         cfg={"share_scale": 3}),
    case("bootstrap capped by the share range", 0, 0, 0, [700, 300], [], 1_000,
         cfg={"share_bits": 10, "share_scale": 2}),
    case("flat genesis rate, exact two-sided", 10 ** 6, 10 ** 6, 10 ** 6, [300, 700], [200], 1_000),
    case("flat 3/1 price with dust buys and sales", 3_000, 1_000, 3_000, [1, 2, 10, 1_000], [1, 7], 1_000),
    case("flat 7/3 price at a zero bound falls back to the Both family", 7, 3, 7, [5, 9], [1, 2], 0),
    case("flat 7/3 price reduces the other side's sales", 7, 3, 7, [5, 9], [1, 2], 300),
    case("balanced two-sided batch settles without curve work", 500_000, 1_000_000, 1_000_000,
         [2_000], [2_000], 1_000),
    case("near-total drain of a net sale", 700_001, 1_000_000, 1_000_000, [3], [999_990], 10_000),
    case("small-ratio curve, buys only", 500_000, 1_000_000, 1_000_000, [10_000, 20_000], [], 1_000),
    case("small-ratio curve, sales only", 500_000, 1_000_000, 1_000_000, [], [7_000, 50_000], 1_000),
    case("small-ratio 3/7 curve, exact boundary search", 3 * 2 ** 40, 5 * 2 ** 41, 7 * 2 ** 40,
         [2 ** 36 + 5, 3 ** 20], [2 ** 30], 1_000),
    case("curved two-sided net buy", 700_001, 1_000_000, 1_000_000, [40_000, 25_000], [30_000, 1], 1_000),
    case("curved two-sided net sale", 700_001, 1_000_000, 1_000_000, [5_000], [30_000, 12_345], 1_000),
    case("curved net buy reduced by the upper price bound", 700_001, 1_000_000, 1_000_000,
         [400_000, 100_000], [10_000], 100),
    case("curved net sale reduced by the lower price bound", 700_001, 1_000_000, 1_000_000,
         [1_000], [300_000, 100_001], 100),
    case("numeric range binds a curved buy", 700_001, 1_000_000, 1_000_000, [600_000, 500_000], [], 9_000,
         cfg={"money_bits": 21}),
    case("full redemption with an unbounded downward move", 600_000, 900_000, 1_000_000,
         [], [400_000, 500_000], 10_000),
    case("full redemption of a small-ratio curve", 500_000, 900_000, 1_000_000, [], [900_000], 10_000),
    case("large operands, wide price grid", 2 ** 100 + 12_345, 3 * 2 ** 99, 2 ** 101 + 7,
         [2 ** 90, 2 ** 88 + 1], [2 ** 87], 1_000),
    case("exhausted after one evaluation", 700_001, 1_000_000, 1_000_000, [40_000, 25_000], [30_000, 1],
         1_000, limit=1),
    case("exhausted after three evaluations, net sale", 700_001, 1_000_000, 1_000_000, [5_000],
         [30_000, 12_345], 1_000, limit=3),
    case("exhausted during the budget search", 700_001, 1_000_000, 1_000_000, [400_000, 100_000],
         [10_000], 100, limit=12),
    case("exhausted small-ratio search", 500_000, 1_000_000, 1_000_000, [], [7_000, 50_000], 1_000,
         limit=2),
]


def to_json(c, result, used):
    out = dict(c)
    out["world"] = {k: str(v) for k, v in c["world"].items()}
    out["buys"] = [str(a) for a in c["buys"]]
    out["sells"] = [str(a) for a in c["sells"]]
    out["config"] = {"money_bits": c["config"]["money_bits"], "share_bits": c["config"]["share_bits"],
                     "share_scale": str(c["config"]["share_scale"])}
    out["expected"] = {
        "buys": [[str(i), str(o)] for i, o in result["buys"]],
        "sells": [[str(i), str(o)] for i, o in result["sells"]],
        "reserve": str(result["reserve"]), "shares": str(result["shares"]),
        "mass": str(result["mass"]), "curve_evaluations": used,
    }
    return out


def compute():
    vectors = []
    for c in CASES:
        result, used = clear(c["config"], c["world"], c["buys"], c["sells"], c["max_price_change_bps"],
                             c["work_limit"])
        vectors.append(to_json(c, result, used))
    return vectors


def main(argv):
    vectors = compute()
    text = json.dumps({"comment": "Generated by scripts/clearing_model.py from the normative "
                                  "clearing algorithm in docs/SPECIFICATION.md; checked against "
                                  "the node by tests/clearing_vectors.rs.",
                       "vectors": vectors}, indent=1) + "\n"
    if "--write" in argv:
        with open(VECTORS, "w", newline="\n") as f:
            f.write(text)
    elif "--check" in argv:
        with open(VECTORS) as f:
            if f.read() != text:
                print("clearing vectors differ from the model")
                return 1
        print(f"{len(vectors)} clearing vectors match the model")
    else:
        for v in vectors:
            print(v["name"], json.dumps(v["expected"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
