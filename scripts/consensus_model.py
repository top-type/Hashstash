"""Independent model of documented Hashstash consensus transitions.

Written from docs/CONSENSUS.md ("Canonical encoding", "State commitments",
"Auction evaluation", "Timestamps, difficulty and forks") without reference to
the Rust implementation. It computes the known-answer vectors in
tests/data/consensus-vectors.json:

- auction transitions: state roots and committed auction fields after each
  block of a scripted chain (genesis, rest, auction rounds with displaced and
  cancelled leaders, a decision, a timeout and the following rests), checked
  by the auction_transition_vectors test in src/consensus.rs;
- ASERT: targets of the fixed integer approximation, checked by the
  asert_matches_the_documented_pseudocode test in src/math.rs.

    python3 scripts/consensus_model.py --write   # regenerate the vectors
    python3 scripts/consensus_model.py --check   # compare with the file

The scripted blocks carry no signed transactions and pay no reward. Their
"transactions" are direct state changes with the effects the specification
gives them (a Propose or Support moves support from account cash into auction
escrow; a sale on the flat genesis-rate curve pays its Stash amount in cash),
so the vectors pin
the auction, decision and rest transitions themselves.
"""
import hashlib
import json
import os
import sys

VECTORS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data",
                       "consensus-vectors.json")


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


# ---- canonical encoding -------------------------------------------------
def uint(n):
    assert 0 <= n < 1 << 64
    if n <= 250:
        return bytes([n])
    if n < 1 << 16:
        return b"\xfb" + n.to_bytes(2, "little")
    if n < 1 << 32:
        return b"\xfc" + n.to_bytes(4, "little")
    return b"\xfd" + n.to_bytes(8, "little")


def arr(b):
    assert len(b) == 32
    return b


def bytevec(b):
    return uint(len(b)) + b


def option(v, enc):
    return b"\x00" if v is None else b"\x01" + enc(v)


def amount(n):
    if n == 0:
        return bytevec(b"")
    return bytevec(n.to_bytes((n.bit_length() + 7) // 8, "little"))


def bare(n):
    limbs = []
    while n:
        limbs.append(n & 0xFFFFFFFF)
        n >>= 32
    return uint(len(limbs)) + b"".join(uint(x) for x in limbs)


PARAMETER = ["BlockBytes", "Interval", "Lead", "Rest", "DecisionBlocks",
             "MinerFeePercent", "PassMarginBps", "MinimumFeeRate", "MaxPriceChangeBps"]


def settings_bytes(s):
    return (uint(s["block_bytes"]) + uint(s["minimum_fee_rate"]) + uint(s["interval"])
            + uint(s["lead"]) + uint(s["rest"]) + uint(s["decision_blocks"])
            + uint(s["max_price_change_bps"]) + option(s["miner_fee_percent"], uint)
            + option(s["pass_margin_bps"], uint))


def proposal_bytes(p):
    if p[0] == "Grant":
        return b"\x00" + uint(len(p[1])) + b"".join(arr(r) + amount(x) for r, x in p[1])
    _, parameter, old, new = p
    return b"\x01" + uint(PARAMETER.index(parameter)) + uint(old) + uint(new)


def proposal_record(r):
    return (uint(r["round"]) + arr(r["proposer"]) + arr(r["description"]) + amount(r["support"])
            + option(r["refund_height"], uint))


def support_record(r):
    return uint(r["round"]) + arr(r["proposal"]) + arr(r["sender"]) + amount(r["amount"])


def round_record(r):
    status, refund = r
    if status == "Open":
        s = b"\x00"
    elif status == "Timeout":
        s = b"\x02"
    else:
        s = b"\x01" + arr(status[1])
    return s + uint(refund)


def bit(path, b):
    return (path[b // 8] >> (7 - b % 8)) & 1


def map_root(entries):
    if not entries:
        return tagged("Hashstash/TrieEmpty", b"")
    nodes = [(tagged("Hashstash/TriePath", k), tagged("Hashstash/TrieLeaf", bytevec(k) + v))
             for k, v in entries]

    def build(nodes):
        if len(nodes) == 1:
            return nodes[0][1]
        b = next(i for i in range(256) if len({bit(p, i) for p, _ in nodes}) == 2)
        return tagged("Hashstash/TrieBranch", bytes([b]) + build([n for n in nodes if bit(n[0], b) == 0])
                      + build([n for n in nodes if bit(n[0], b) == 1]))

    return build(nodes)


def proposal_id(chain, rnd, proposer, description, p):
    return tagged("Hashstash/proposal", arr(chain) + uint(rnd) + arr(proposer) + arr(description)
                  + proposal_bytes(p))


def support_key(rnd, pid, sender):
    return tagged("Hashstash/support", uint(rnd) + arr(pid) + arr(sender))


def rank_key(support, pid):
    return support.to_bytes(64, "big") + bytes(255 - x for x in pid)


WORLD_FIELDS = ("reserve", "shares", "revenue", "grant_escrow", "mass", "account_cash", "account_shares")


def world_root(w):
    assert not w["accounts"], "the scripted chain creates no accounts"
    return tagged("Hashstash/world", map_root([]) + b"".join(bare(w[f]) for f in WORLD_FIELDS))


def phase_commitment(kind, v):
    if kind == "Auction":
        return (b"\x00" + uint(v["round"]) + uint(v["opened"]) + option(v["leader"], arr)
                + uint(v["lead_since"]) + uint(v["replacement_height"]) + uint(len(v["displaced"]))
                + b"".join(arr(i) + uint(t) for i, t in v["displaced"]))
    if kind == "Governance":
        return (b"\x01" + arr(v["id"]) + uint(v["epoch"]) + uint(v["round"]) + arr(v["proposal_id"])
                + uint(v["started"]) + uint(v["started_height"]) + uint(v["blocks"])
                + uint(v["leading_blocks"]))
    return b"\x02" + uint(v["until"]) + option(v["pending"], lambda p: uint(PARAMETER.index(p[0])) + uint(p[1]))


def state_root(s):
    a = (arr(s["chain_id"]) + uint(s["height"]) + uint(s["clock"]) + bare(s["issued"])
         + settings_bytes(s["settings"]) + settings_bytes(s["frozen"]) + world_root(s["world"])
         + option(s["alternative"], world_root) + phase_commitment(*s["phase"]))
    b = (map_root([(k, proposal_record(r)) for k, r in s["proposals"].items()])
         + map_root([(k, proposal_bytes(p)) for k, p in s["actions"].items()])
         + map_root([(k, support_record(r)) for k, r in s["supports"].items()])
         + map_root([(k.to_bytes(8, "big"), round_record(r)) for k, r in s["rounds"].items()])
         + map_root([(k, arr(v)) for k, v in s["ranking"].items()])
         + bare(s["auction_escrow"]) + uint(s["last_round"]) + uint(s["last_epoch"]))
    return tagged("Hashstash/state", a + b)


# ---- BIP340 x-only public keys -----------------------------------------
P = 2 ** 256 - 2 ** 32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def x_only(k):
    result, addend = None, G
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result[0].to_bytes(32, "big")


def public_key(secret_byte):
    """The x-only key of the secret made of 32 copies of one byte."""
    return x_only(int.from_bytes(bytes([secret_byte]) * 32, "big"))


# ---- auction, decision and rest transitions ----------------------------
def grant_total(p):
    return sum(x for _, x in p[1])


def can_open(s, action):
    """Representability holds at these magnitudes; the scripted parameter
    changes are valid at every projected activation. Grants need capacity."""
    if action[0] == "Grant":
        w = s["world"]
        return 0 < grant_total(action) <= w["revenue"] + w["reserve"] // 2
    return True


def top(s):
    if not s["ranking"]:
        return None
    return s["ranking"][max(s["ranking"])]


def evaluate(s, parent_hash):
    kind, a = s["phase"]
    if kind != "Auction":
        return
    h, t = s["height"], s["clock"]
    if h >= a["replacement_height"]:
        while True:
            first = top(s)
            if first is None:
                best = None
                break
            if a["leader"] is not None:
                incumbent = a["leader"]
            else:
                a["displaced"] = [e for e in a["displaced"] if s["proposals"][e[0]]["refund_height"] is None]
                incumbent = a["displaced"][-1][0] if a["displaced"] else None
            candidate = first
            if (incumbent is not None and incumbent != first
                    and s["proposals"][incumbent]["refund_height"] is None
                    and s["proposals"][incumbent]["support"] == s["proposals"][first]["support"]):
                candidate = incumbent
            if can_open(s, s["actions"][candidate]):
                best = candidate
                break
            record = s["proposals"][candidate]
            record["refund_height"] = h + 1
            del s["ranking"][rank_key(record["support"], candidate)]
            if a["leader"] == candidate:
                a["leader"] = None
        if best != a["leader"]:
            if a["leader"] is not None:
                old = a["leader"]
                a["displaced"] = [e for e in a["displaced"] if e[0] != old] + [(old, a["lead_since"])]
                a["lead_since"] = t
            elif a["displaced"] and best == a["displaced"][-1][0]:
                a["lead_since"] = a["displaced"].pop()[1]
            else:
                a["lead_since"] = t
            a["leader"] = best
    timed_out = t - a["opened"] >= max(s["auction_timeout"], s["frozen"]["lead"] + s["frozen"]["interval"])
    if a["leader"] is not None and (t - a["lead_since"] >= s["frozen"]["lead"] or timed_out):
        open_decision(s, a, parent_hash)
    elif timed_out:
        s["rounds"][a["round"]] = ("Timeout", h + 1)
        s["ranking"] = {}
        s["phase"] = ("Rest", {"until": t + s["frozen"]["rest"], "pending": None})


def open_decision(s, a, parent_hash):
    pid, h, t = a["leader"], s["height"], s["clock"]
    support = s["proposals"][pid]["support"]
    s["auction_escrow"] -= support
    s["rounds"][a["round"]] = (("Won", pid), h + 1)
    s["ranking"] = {}
    s["last_epoch"] += 1
    decision = {"id": tagged("Hashstash/decision", arr(s["chain_id"]) + uint(a["round"]) + arr(pid)
                             + uint(h) + arr(parent_hash)),
                "epoch": s["last_epoch"], "round": a["round"], "proposal_id": pid, "started": t,
                "started_height": h, "blocks": s["frozen"]["decision_blocks"], "leading_blocks": 0}
    fail, action = s["world"], s["actions"][pid]
    passing = dict(fail)
    if action[0] == "Grant":
        total = grant_total(action)
        cash = min(passing["revenue"], total)
        shortfall = total - cash
        passing["revenue"] -= cash
        passing["reserve"] -= shortfall
        passing["grant_escrow"] = total
        fail["reserve"] -= shortfall
        fail["revenue"] += shortfall
    fail["revenue"] += support
    passing["revenue"] += support
    s["alternative"] = passing
    s["phase"] = ("Governance", decision)


def pass_beats_fail(passing, fail, margin):
    if passing["shares"] == 0 or fail["shares"] == 0:
        return False
    return passing["mass"] * fail["shares"] * 10_000 > fail["mass"] * passing["shares"] * (10_000 + margin)


def replenish(w):
    if w["shares"]:
        fill = min(w["revenue"], w["mass"] - w["reserve"])
        w["reserve"] += fill
        w["revenue"] -= fill


def block(s, ops):
    """One scripted block: the documented block order with no reward."""
    parent_hash = bytes([s["height"] % 256]) * 32
    parent_world, parent_pass = dict(s["world"]), s["alternative"] and dict(s["alternative"])
    s["height"] += 1
    s["clock"] += s["settings"]["interval"]
    kind, d = s["phase"]
    if kind == "Governance":
        if pass_beats_fail(parent_pass, parent_world, s["frozen"]["pass_margin_bps"] or 0):
            d["leading_blocks"] += 1
        if s["height"] - d["started_height"] == d["blocks"]:
            won = d["leading_blocks"] > d["blocks"] // 2
            assert not won, "the scripted decisions resolve FAIL"
            s["alternative"] = None
            s["phase"] = ("Rest", {"until": s["clock"] + s["frozen"]["rest"], "pending": None})
    for op in ops:
        apply(s, op)
    if s["alternative"] is None:
        replenish(s["world"])
    evaluate(s, parent_hash)
    kind, r = s["phase"]
    if kind == "Rest" and s["clock"] >= r["until"]:
        assert r["pending"] is None
        s["frozen"] = dict(s["settings"])
        if s["rounds"]:
            s["last_round"] += 1
        s["phase"] = ("Auction", {"round": s["last_round"], "opened": s["clock"], "leader": None,
                                  "lead_since": s["clock"], "replacement_height": s["height"] + 1,
                                  "displaced": []})
        s["rounds"][s["last_round"]] = ("Open", 0)
        s["ranking"] = {}


def grant(payments):
    return ("Grant", sorted((public_key(k), x) for k, x in payments))


def apply(s, op):
    kind, a = s["phase"]
    if "propose" in op:
        o = op["propose"]
        proposer, description = public_key(o["proposer"]), bytes([o["description"]]) * 32
        action = grant(o["grant"]) if "grant" in o else ("Parameter", *o["parameter"])
        pid = proposal_id(s["chain_id"], a["round"], proposer, description, action)
        assert pid not in s["proposals"]
        s["actions"][pid] = action
        s["proposals"][pid] = {"round": a["round"], "proposer": proposer, "description": description,
                               "support": 0, "refund_height": None}
        s["ids"].append(pid)
        add_support(s, a["round"], pid, proposer, o["support"])
    elif "support" in op:
        o = op["support"]
        add_support(s, a["round"], s["ids"][o["proposal"]], public_key(o["sender"]), o["amount"])
    else:
        # A sale of x Stash on the flat genesis-rate curve: it pays x atoms.
        w, x = s["world"], op["sell"]
        assert w["reserve"] == w["mass"] == w["shares"] and kind == "Auction"
        for field in ("reserve", "mass", "shares", "account_shares"):
            w[field] -= x
        w["account_cash"] += x


def add_support(s, rnd, pid, sender, n):
    record = s["proposals"][pid]
    assert record["round"] == rnd and record["refund_height"] is None
    if record["support"]:
        del s["ranking"][rank_key(record["support"], pid)]
    record["support"] += n
    s["ranking"][rank_key(record["support"], pid)] = pid
    key = support_key(rnd, pid, sender)
    entry = s["supports"].setdefault(key, {"round": rnd, "proposal": pid, "sender": sender, "amount": 0})
    entry["amount"] += n
    s["auction_escrow"] += n
    s["world"]["account_cash"] -= n


# ---- the scripted chain -------------------------------------------------
SETTINGS = {"block_bytes": 16_384, "minimum_fee_rate": 1, "interval": 15, "lead": 45, "rest": 30,
            "decision_blocks": 3, "max_price_change_bps": 1_000, "miner_fee_percent": 50,
            "pass_margin_bps": 0}
CONFIG = {"network": "hashstash-auction-vectors", "auction_timeout": 240, "settings": SETTINGS}
FUNDS = 1_000_000_000
WORLD = {"reserve": 1_000_000, "shares": 1_000_000, "mass": 1_000_000, "revenue": 0,
         "grant_escrow": 0, "account_cash": FUNDS - 1_000_000, "account_shares": 1_000_000}


def script():
    lead_change = ["Lead", 45, 60]
    return [
        ("block 1: inside the genesis rest", []),
        ("block 2: rest ends; round 0 opens with lead_since = clock, replacement_height = h + 1", []),
        ("block 3: a parameter change leads from the block's clock",
         [{"propose": {"proposer": 0x21, "description": 0x41, "parameter": lead_change, "support": 10}}]),
        ("block 4: a higher grant displaces it", [{"propose": {"proposer": 0x22, "description": 0x42,
                                                               "grant": [[0x61, 450_000]], "support": 20}}]),
        ("block 5: a second grant displaces the first", [{"propose": {"proposer": 0x23, "description": 0x43,
                                                                      "grant": [[0x62, 300_000]], "support": 30}}]),
        ("block 6: case (a): the displaced grant outbids the leader but cannot open; it is cancelled "
         "while the leader stays, and its entry stays in displaced",
         [{"sell": 200_000}, {"support": {"proposal": 1, "sender": 0x24, "amount": 15}}]),
        ("block 7: the leader cannot open; the filter drops the cancelled entry, the parameter change "
         "resumes its recorded lead start, already mature, and opens its decision",
         [{"sell": 300_000}]),
        ("block 8: first decision observation (a tie)", []),
        ("block 9: second observation", []),
        ("block 10: FAIL resolves before transactions; rest until clock + rest", []),
        ("block 11: rest", []),
        ("block 12: rest ends; round 1 opens because rounds is not empty", []),
        ("block 13: a grant leads", [{"propose": {"proposer": 0x25, "description": 0x45,
                                                  "grant": [[0x63, 200_000], [0x64, 50_000]], "support": 5}}]),
        ("block 14: a higher grant displaces it", [{"propose": {"proposer": 0x26, "description": 0x46,
                                                                "grant": [[0x65, 240_000]], "support": 9}}]),
        ("block 15: case (b): both grants become unfundable; the leader and then the displaced "
         "incumbent are cancelled, the ranking empties, displaced keeps the cancelled entry and "
         "lead_since keeps the cancelled leader's start", [{"sell": 100_000}]),
        ("block 16: no leader", []),
        ("block 17: a new proposal leads; the filter empties displaced and its lead starts now",
         [{"propose": {"proposer": 0x27, "description": 0x47, "grant": [[0x66, 100_000]], "support": 4}}]),
        ("block 18: an equal bid does not take the lead from the incumbent",
         [{"propose": {"proposer": 0x28, "description": 0x48, "parameter": lead_change, "support": 4}}]),
        ("block 19", []),
        ("block 20: the grant matures and opens: escrow from revenue then reserve, FAIL holds the "
         "shortfall as revenue, the bid becomes revenue in both", []),
        ("block 21", []),
        ("block 22", []),
        ("block 23: FAIL resolves; FAIL replenishes its reserve from the shortfall", []),
        ("block 24", []),
        ("block 25: round 2 opens", []),
        ("block 26: a grant leads", [{"propose": {"proposer": 0x29, "description": 0x49,
                                                  "grant": [[0x67, 150_000]], "support": 2}}]),
        ("block 27: a higher grant displaces it", [{"propose": {"proposer": 0x2a, "description": 0x4a,
                                                                "grant": [[0x68, 180_000]], "support": 3}}]),
        ("block 28: the displaced grant outbids the leader and leads again from the block's clock; "
         "its own older entry is not the last, so it stays in displaced",
         [{"support": {"proposal": 7, "sender": 0x2b, "amount": 2}}]),
        ("block 29: the other grant outbids it back; the old leader's entries are replaced by one, "
         "and the new leader keeps its own older entry",
         [{"support": {"proposal": 8, "sender": 0x2b, "amount": 2}}]),
        ("block 30: a sale makes both grants unfundable; the leader and then the displaced incumbent "
         "are cancelled, the ranking empties, displaced keeps the cancelled entry", [{"sell": 150_000}]),
    ] + [(f"block {h}: round 2 waits for its timeout", []) for h in range(31, 41)] + [
        ("block 41: round 2 times out with no leader: Timeout refundable from h + 1, rest", []),
        ("block 42", []),
        ("block 43: round 3 opens", []),
    ]


def initial_state(chain_id):
    return {"chain_id": chain_id, "height": 0, "clock": 0, "issued": FUNDS,
            "settings": dict(SETTINGS), "frozen": dict(SETTINGS),
            "world": dict(WORLD, accounts=[]), "alternative": None,
            "phase": ("Rest", {"until": SETTINGS["rest"], "pending": None}),
            "proposals": {}, "actions": {}, "supports": {}, "rounds": {}, "ranking": {},
            "auction_escrow": 0, "last_round": 0, "last_epoch": 0,
            "auction_timeout": CONFIG["auction_timeout"], "ids": []}


def summary(s):
    kind, v = s["phase"]
    out = {"height": s["height"], "clock": s["clock"], "phase": kind, "root": state_root(s).hex()}
    if kind == "Auction":
        out.update(round=v["round"], opened=v["opened"], leader=s["ids"].index(v["leader"])
                   if v["leader"] is not None else None, lead_since=v["lead_since"],
                   replacement_height=v["replacement_height"],
                   displaced=[[s["ids"].index(i), t] for i, t in v["displaced"]])
    elif kind == "Governance":
        out.update(proposal=s["ids"].index(v["proposal_id"]), started=v["started"],
                   started_height=v["started_height"], leading_blocks=v["leading_blocks"],
                   decision_id=v["id"].hex())
    else:
        out.update(until=v["until"])
    out["cancelled"] = [[i, s["proposals"][p]["refund_height"]] for i, p in enumerate(s["ids"])
                        if s["proposals"][p]["refund_height"] is not None]
    out["rounds"] = [[k, r[0] if isinstance(r[0], str) else ["Won", s["ids"].index(r[0][1])], r[1]]
                     for k, r in sorted(s["rounds"].items())]
    return out


def auction_vectors(chain_id_hex):
    s = initial_state(bytes.fromhex(chain_id_hex))
    blocks = [{"note": "funded genesis", "ops": [], "expected": summary(s)}]
    for note, ops in script():
        block(s, ops)
        blocks.append({"note": note, "ops": ops, "expected": summary(s)})
    return {"config": CONFIG, "funds": FUNDS, "world": WORLD, "chain_id": chain_id_hex, "blocks": blocks}


# ---- ASERT ----------------------------------------------------------------
def target_from_bits(bits):
    size, mantissa = bits >> 24, bits & 0x007FFFFF
    return mantissa >> (8 * (3 - size)) if size <= 3 else mantissa << (8 * (size - 3))


def bits_from_target(target):
    size = (target.bit_length() + 7) // 8
    mantissa = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    if mantissa & 0x00800000:
        mantissa >>= 8
        size += 1
    return (size << 24) | mantissa


def asert(initial, error, half_life, limit):
    cutoff = half_life * 512
    if error >= cutoff:
        return target_from_bits(bits_from_target(limit))
    if error <= -cutoff:
        return 1
    q = abs(error) * 65_536 // half_life
    exponent = q if error >= 0 else -q           # truncated toward zero
    shifts = exponent >> 16                       # floor
    fraction = exponent - shifts * 65_536
    factor = 65_536 + ((195_766_423_245_049 * fraction + 971_821_376 * fraction ** 2
                        + 5_127 * fraction ** 3 + (1 << 47)) >> 48)
    target = initial * factor
    target = target >> -shifts if shifts < 0 else target << shifts
    target >>= 16
    target = max(target, 1)
    target = min(target, limit)
    return target_from_bits(bits_from_target(target))


ASERT_CASES = [
    # (initial bits, limit bits, half_life, error): Hashstash-specific edges.
    (0x1c0ffff0, 0x1d00ffff, 900, 0),
    (0x1c0ffff0, 0x1d00ffff, 900, -1),
    (0x1c0ffff0, 0x1d00ffff, 900, 1),
    (0x1c0ffff0, 0x1d00ffff, 900, -899),
    (0x1c0ffff0, 0x1d00ffff, 900, -901),
    (0x1c0ffff0, 0x1d00ffff, 900, 450),
    (0x1c0ffff0, 0x1d00ffff, 900, -450),
    (0x1c0ffff0, 0x1d00ffff, 900, 3_333),
    (0x1c0ffff0, 0x1d00ffff, 900, 3_600),
    (0x1c0ffff0, 0x1d00ffff, 900, 900 * 512 - 1),
    (0x1c0ffff0, 0x1d00ffff, 900, 900 * 512),
    (0x1c0ffff0, 0x1d00ffff, 900, -900 * 512 + 1),
    (0x1c0ffff0, 0x1d00ffff, 900, -900 * 512),
    (0x207fffff, 0x207fffff, 900, 77),
    (0x207fffff, 0x207fffff, 900, -12_345),
    (0x01010000, 0x207fffff, 900, -1_800),
    (0x1d00ffff, 0x1d00ffff, 7, 5),
    (0x1b0404cb, 0x1d00ffff, 172_800, -1_000_000),
]


def asert_vectors():
    out = []
    for initial, limit, half_life, error in ASERT_CASES:
        target = asert(target_from_bits(initial), error, half_life, target_from_bits(limit))
        out.append({"initial_bits": f"{initial:08x}", "limit_bits": f"{limit:08x}",
                    "half_life": half_life, "error": error, "bits": f"{bits_from_target(target):08x}"})
    return out


CHAIN_ID = "see tests/data/consensus-vectors.json"


def compute(chain_id_hex):
    return {"comment": "Generated by scripts/consensus_model.py from docs/CONSENSUS.md; checked "
                       "against the node by src/consensus.rs (auction_transition_vectors) and "
                       "src/math.rs (asert_matches_the_documented_pseudocode).",
            "auction": auction_vectors(chain_id_hex), "asert": asert_vectors()}


def main(argv):
    # The chain ID hashes the whole encoded genesis configuration, which this
    # model does not re-encode; it is an input recorded with the vectors and
    # checked by the Rust test.
    with open(VECTORS) as f:
        chain_id = json.load(f)["auction"]["chain_id"]
    if "--chain-id" in argv:
        chain_id = argv[argv.index("--chain-id") + 1]
    text = json.dumps(compute(chain_id), indent=1) + "\n"
    if "--write" in argv:
        with open(VECTORS, "w", newline="\n") as f:
            f.write(text)
    elif "--check" in argv:
        with open(VECTORS) as f:
            if f.read() != text:
                print("consensus vectors differ from the model")
                return 1
        print("consensus vectors match the model")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
