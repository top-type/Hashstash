"""Deterministic, explicitly fictional demo viewpoints; no I/O or model calls.

Only observed chain values are described as facts. Profiles express policy
preferences, never promises about delivered work or real people's opinions.
Display hashes contain 10**18 raw atoms; this module does not format Stash.
"""
from copy import deepcopy
from decimal import Decimal, localcontext

MAX_TEXT_BYTES = 512
REGIONS = ("fra", "sgp", "ewr")

# name, role, commitment, circulation, ordinary Stash target, grant ask,
# preferred grant/capacity fraction, base PASS bias, price sensitivity
_ROWS = {
    "fra": (
        ("Mara", "Reserve guardian", 2500, 1000, 6000, 100, 100, -22, 8),
        ("Quinn", "Auditor", 3000, 1500, 4000, 150, 200, -12, 12),
        ("Ivo", "Long-horizon saver", 4000, 1000, 6000, 100, 150, -18, 15),
    ),
    "sgp": (
        ("Rook", "Builder", 6000, 2500, 3500, 500, 800, 26, 10),
        ("Sana", "Commons advocate", 5000, 2000, 5500, 350, 500, 18, 8),
        ("Mika", "UX advocate", 4500, 3000, 3000, 250, 350, 12, 12),
    ),
    "ewr": (
        ("Sable", "Skeptic", 2000, 1500, 2500, 100, 150, -28, 12),
        ("Vega", "Market trader", 5000, 2500, 4500, 300, 500, 0, 40),
        ("Flint", "Miner", 3500, 2000, 5000, 200, 250, -10, 15),
    ),
}

_VOICES = {
    "Mara": (
        ("Available funding is an option on future choices, so spending it needs a reason stronger than motion.",
         "A reserve that survives a bad decision can still fund the next good one.",
         "Stash ownership can outlast issuance, but it does not promise a stable exit price.",
         "I would rather fund one reversible experiment than make a permanent spending habit."),
        ("Rook, speed is useful only if the remaining reserve can absorb mistakes.",
         "Sana, common ownership still needs a credible spending limit.",
         "Vega, a lower quote is not proof that the underlying decision is sound.")),
    "Quinn": (
        ("An affordable grant and a justified grant are different tests.",
         "Funding feasibility proves the mechanism can pay, not that anyone delivered value.",
         "I want the grant amount, funding path and recipient visible before taking a side.",
         "My audit starts with what the chain records and stops before inventing a success story."),
        ("Rook, a plausible plan still needs an observable result.",
         "Mara, refusing every experiment would leave nothing new to audit.",
         "Mika, a simpler interface must still expose the trade-off.")),
    "Ivo": (
        ("My horizon is several funding rounds, not the next price move.",
         "Owning a share of the system is different from owning a fixed quantity of spending power.",
         "I accept volatility for continued participation, but I still need some liquid hashes.",
         "A larger stash balance means little if everyone needs to exit at once."),
        ("Vega, I care more about surviving the cycle than timing its cheapest quote.",
         "Rook, growth should repay the patience of existing holders.",
         "Flint, fresh mining can replenish flow without making every grant worthwhile.")),
    "Rook": (
        ("A living system needs experiments; a perfectly untouched reserve cannot discover demand.",
         "I would spend a bounded slice on a prototype before funding a grand promise.",
         "Circulation is useful when it exposes a real failure mode and teaches us something.",
         "My builder bias favors a testable next step over an indefinitely deferred plan."),
        ("Mara, preserving every hash also has an opportunity cost.",
         "Quinn, I agree the proposal should describe a test, not pretend the work already exists.",
         "Sable, skepticism is more useful with a condition that could change your mind.")),
    "Sana": (
        ("I want grants to build shared capability, not just enrich whoever already holds the most.",
         "A commons needs both contributions and a defensible way to spend them.",
         "Circulating hashes can serve many users while Stash records who bears the system's risk.",
         "I favor grants whose possible benefit can be reused rather than fenced off."),
        ("Mara, a shared reserve should eventually support shared use.",
         "Vega, a favorable price alone says nothing about who benefits.",
         "Rook, a prototype is stronger when others can inspect and reuse it.")),
    "Mika": (
        ("A system visitors cannot understand is expensive even when its transaction fee is small.",
         "I would fund a narrow usability experiment with a result people can actually inspect.",
         "People need to see what they give up when hashes become Stash.",
         "A clear failure message can be worth more than another impressive-looking dashboard."),
        ("Quinn, clarity should reveal risk rather than hide it behind technical detail.",
         "Rook, shipping faster is not enough if the next visitor gets stuck.",
         "Ivo, a patient holder still deserves an understandable exit quote.")),
    "Sable": (
        ("I treat a grant as a hypothesis, not an achievement.",
         "A working payment path is not evidence of useful work at the other end.",
         "I want to know what would falsify the proposal before I help it pass.",
         "The easiest story to sell is growth with the uncertainty left out."),
        ("Rook, what observation would make you stop this experiment?",
         "Sana, a public benefit still needs a concrete way to be evaluated.",
         "Mara, conserving everything forever is also a choice that needs defending.")),
    "Vega": (
        ("I compare the two conditional prices before choosing which risk to hold.",
         "A discount can compensate for uncertainty; it does not remove uncertainty.",
         "The interesting question is whether the price already includes the cost of the grant.",
         "I keep some hashes liquid because a quoted price is not my guaranteed exit price."),
        ("Mara, caution can become expensive when everyone buys the same protection.",
         "Rook, enthusiasm matters less to me when PASS already carries a premium.",
         "Ivo, a long horizon still benefits from paying attention to entry price.")),
    "Flint": (
        ("Mining supplies the flow; grant decisions still determine what that flow should support.",
         "More hashes entering the system do not make poor allocation disappear.",
         "I favor experiments that make participation more useful for the people supplying work.",
         "A miner can replenish hashes, but cannot promise a stable Stash price."),
        ("Rook, useful demand matters more than activity for its own sake.",
         "Sana, a commons still needs a reason for contributors to keep returning.",
         "Vega, transaction throughput and token price answer different questions.")),
}


def profile_for(region, index, strategy="substantive-v1"):
    """Return a fresh strategy descriptor for one of nine fixed demo accounts."""
    if region not in REGIONS or type(index) is not int or not 0 <= index < 3:
        raise ValueError("unknown demo persona")
    fields = ("name", "role", "commitment_bps", "circulation_bps", "stash_adjustment_bps",
              "grant_request_bps", "grant_fraction_preference_bps", "base_pass_bias", "price_sensitivity")
    result = dict(zip(fields, _ROWS[region][index]))
    result.update(region=region, index=index, label="Automated Demo · " + result["name"])
    result["minimum_funding_bps"] = 8000 if region == "sgp" else 10000
    result["stash_target_bps"] = {"fra": (7500, 6000, 8000), "sgp": (4500, 6500, 4000),
                                  "ewr": (4500, 3000, 6000)}[region][index]
    if strategy in {"native-balance-v1", "pass-campaign-v1"}:
        result["native_balance_strategy"] = True
        result["label"] = result["name"] + " · Automated"
        # A continuous preference cost replaces the old tiny allocation cutoff.
        # It influences the persona's trades, never proposal eligibility.
        result["grant_cost_sensitivity"] = {"fra": (50, 35, 45), "sgp": (20, 25, 25),
                                             "ewr": (60, 20, 35)}[region][index]
    if strategy == "pass-campaign-v1":
        result.update(pass_campaign=True, label=result["name"] + " · Automated · PASS campaign",
                      role="Coordinated PASS campaign", stash_target_bps=5000)
    return result


def _int(value):
    if type(value) not in (int, str):
        return None
    try:
        n = int(value)
        return n if n >= 0 else None
    except (TypeError, ValueError):
        return None


def _phase_details(snapshot):
    phase = snapshot.get("governance", {}).get("phase", {})
    return phase.get("Governance", {}) if isinstance(phase, dict) else {}


def evaluate(snapshot, profile, metrics=None):
    """Score a policy preference from actual values; unknown values stay unknown.

    Optional metrics are raw integer amounts and rational quote numerators and
    denominators. PASS/FAIL is an illustrative strategy preference, not a price
    forecast, delivered-work claim, or prediction of governance settlement.
    """
    supplied = metrics or {}
    world = snapshot.get("governance", {}).get("world", {})
    observed = {}
    for key, fallback in (("reserve_raw", world.get("reserve")),
                          ("grant_capacity_raw", world.get("grant_capacity"))):
        value = _int(supplied.get(key, fallback))
        if value is not None:
            observed[key] = value
    for key in ("grant_amount_raw", "grant_funded_raw", "pass_price_numerator",
                "pass_price_denominator", "fail_price_numerator", "fail_price_denominator"):
        value = _int(supplied.get(key))
        if value is not None:
            observed[key] = value
    if type(supplied.get("grant_feasible")) is bool:
        observed["grant_feasible"] = supplied["grant_feasible"]
    grant, capacity = observed.get("grant_amount_raw"), observed.get("grant_capacity_raw")
    if grant is not None and capacity:
        observed["grant_fraction_bps"] = grant * 10000 // capacity
    funded = observed.get("grant_funded_raw")
    if grant and funded is not None:
        observed["funding_bps"] = min(10000, funded * 10000 // grant)
    pn, pd, fn, fd = (observed.get(key) for key in ("pass_price_numerator", "pass_price_denominator",
                                                   "fail_price_numerator", "fail_price_denominator"))
    if pn is not None and pd and fn and fd:
        observed["pass_fail_price_bps"] = pn * fd * 10000 // (pd * fn)
    if profile.get("pass_campaign"):
        eligible = observed.get("grant_feasible") is True and observed.get("funding_bps", 10000) >= 10000
        reason = ("the coordinated campaign supports this funded proposal" if eligible else
                  "the campaign waits for verified funding")
        return {"preferred_outcome": "Pass" if eligible else None, "pass_score": 1 if eligible else 0,
                "reasons": [reason], "rationale": reason, "observed": observed,
                "coordinated_campaign": True}
    score, reasons = int(profile["base_pass_bias"]), []
    fraction = observed.get("grant_fraction_bps")
    if fraction is not None:
        if profile.get("native_balance_strategy"):
            score -= fraction * profile["grant_cost_sensitivity"] // 10000
            reasons.append("the request uses " + str(fraction / 100) + "% of available grant backing")
        elif fraction > profile["grant_fraction_preference_bps"]:
            score -= 40
            reasons.append("the request is larger than my preferred grant allocation")
        else:
            score += 12
            reasons.append("the request fits my preferred grant allocation")
    if observed.get("grant_feasible") is False:
        score -= 65
        reasons.append("the current funding quote cannot cover the request")
    elif observed.get("grant_feasible") is True:
        score += 8
        reasons.append("the current funding quote covers the request")
    funding = observed.get("funding_bps")
    if funding is not None and funding < profile["minimum_funding_bps"]:
        score -= 25
        reasons.append("the observed funding is below my required coverage")
    ratio = observed.get("pass_fail_price_bps")
    if ratio is not None:
        # A discount tilts toward PASS and a premium toward FAIL; clamp influence.
        score += max(-profile["price_sensitivity"], min(profile["price_sensitivity"],
                     (10000 - ratio) * profile["price_sensitivity"] // 1000))
        reasons.append("PASS is cheaper than FAIL" if ratio < 10000 else
                       "PASS is dearer than FAIL" if ratio > 10000 else "the conditional quotes are equal")
    if not reasons:
        reasons.append("the available data leaves the grant trade-off unmeasured")
    side = "Pass" if score > 0 else "Fail"
    opposed = [reason for reason in reasons if any(word in reason for word in
               ("exceeds", "cannot", "below my", "dearer", "unmeasured"))]
    favorable = [reason for reason in reasons if any(word in reason for word in ("fits", "covers", "cheaper"))]
    if side == "Fail":
        rationale = opposed[0] if opposed else {
            "Mara": ("preserving capacity for later choices outweighs this grant's expected benefit"
                     if profile.get("native_balance_strategy") else
                     "preserving capacity for later choices outweighs this small cost"),
            "Quinn": "funding ability alone does not demonstrate the proposed benefit",
            "Ivo": "retained grant capacity matters more to my long-horizon strategy",
            "Sable": "I still need a falsifiable case for the benefit",
            "Flint": "I need a stronger link between spending and useful participation",
        }.get(profile["name"], "the observed trade-off does not clear my risk threshold")
    else:
        rationale = favorable[0] if favorable else "my strategy favors a bounded experiment despite the remaining uncertainty"
    return {"preferred_outcome": side, "pass_score": score,
            "reasons": reasons, "rationale": rationale, "observed": observed}


def _hashes(raw):
    raw = int(raw)
    if raw == 0:
        return "0 hashes"
    with localcontext() as ctx:
        ctx.prec = 180
        value = Decimal(raw) / Decimal(10**18)
        text = format(value, ".8f").rstrip("0").rstrip(".")
        if text == "0":
            return "less than 0.00000001 hashes"
        if len(text) > 18:
            text = format(value, ".5E")
            text = "about " + text
        elif raw % (10**10):
            text = "about " + text
    return text + (" hash" if raw == 10**18 else " hashes")


def _percent(bps):
    whole, fraction = divmod(bps, 100)
    return str(whole) + (("." + str(fraction).zfill(2).rstrip("0")) if fraction else "") + "%"


def _facts(snapshot, result):
    o = result["observed"]
    facts = []
    if "grant_amount_raw" in o:
        text = "The request is " + _hashes(o["grant_amount_raw"])
        if "grant_fraction_bps" in o:
            pct = _percent(o["grant_fraction_bps"])
            if o["grant_amount_raw"] and not o["grant_fraction_bps"]:
                pct = "less than 0.01%"
            if o["grant_amount_raw"] * 10000 % o["grant_capacity_raw"] and o["grant_fraction_bps"]:
                pct = "about " + pct
            text += ", " + pct + " of available grant capacity"
        facts.append(text + ".")
    if "grant_funded_raw" in o:
        facts.append("Observed grant funding is " + _hashes(o["grant_funded_raw"]) + ".")
    if "pass_fail_price_bps" in o:
        pass_cross = o["pass_price_numerator"] * o["fail_price_denominator"]
        fail_cross = o["fail_price_numerator"] * o["pass_price_denominator"]
        difference = pass_cross - fail_cross
        if difference == 0:
            comparison = "equal to FAIL's"
        elif abs(difference) * 10000 < fail_cross:
            comparison = "within 0.01% of FAIL's, slightly " + ("lower" if difference < 0 else "higher")
        else:
            bps, remainder = divmod(abs(difference) * 10000, fail_cross)
            comparison = ("about " if remainder else "") + _percent(bps)
            comparison += (" below" if difference < 0 else " above") + " FAIL"
        facts.append("PASS's quoted price is " + comparison + ".")
    if "reserve_raw" in o:
        facts.append("The observed reserve holds " + _hashes(o["reserve_raw"]) + ".")
    if "grant_capacity_raw" in o:
        facts.append("available grant capacity is " + _hashes(o["grant_capacity_raw"]) + ".")
    round_id = snapshot.get("status", {}).get("auction_round")
    if round_id is None:
        round_id = _phase_details(snapshot).get("round")
    if _int(round_id) is not None:
        facts.append("This is funding round " + str(int(round_id)) + ".")
    return facts


def _confirmed(item):
    return bool(item.get("state") == "confirmed" or item.get("status") == "confirmed"
                or (item.get("txid") and item.get("confirmed_at") is not None))


def _confirmed_chats(region, history):
    for item in history:
        if not isinstance(item, dict) or not _confirmed(item):
            continue
        entry = item.get("action", item)
        if (isinstance(entry, dict) and entry.get("kind") == "chat"
                and entry.get("region", region) == region
                and type(entry.get("sender_index")) is int
                and 0 <= entry["sender_index"] < 3):
            yield entry


def confirmed_chat_counts(region, history):
    """Counts come only from canonical confirmed entries in the durable ledger."""
    if region not in REGIONS:
        raise ValueError("unknown demo region")
    counts = [0, 0, 0]
    for entry in _confirmed_chats(region, history):
        counts[entry['sender_index']] += 1
    return counts


def next_speaker(region, history, confirmed_chat_count=None):
    """Rotate using this region's confirmed chat count, never global activity."""
    if region not in REGIONS:
        raise ValueError("unknown demo region")
    if confirmed_chat_count is None:
        confirmed_chat_count = sum(confirmed_chat_counts(region, history))
    if type(confirmed_chat_count) is not int or confirmed_chat_count < 0:
        raise ValueError("invalid confirmed chat count")
    return confirmed_chat_count % 3


def speaker_sequence(region, index, history, confirmed_counts=None):
    profile_for(region, index)
    counts = confirmed_chat_counts(region, history) if confirmed_counts is None else confirmed_counts
    if (not isinstance(counts, (list, tuple)) or len(counts) != 3
            or any(type(n) is not int or n < 0 for n in counts)):
        raise ValueError("invalid confirmed persona counts")
    return counts[index]


def _own_action(history, profile):
    names = {"deposit_pass": "PASS Stash purchase",
             "deposit_fail": "FAIL Stash purchase", "redeem_pass": "PASS redemption",
             "redeem_fail": "FAIL redemption",
             "deposit": "Stash purchase", "redeem": "Stash redemption",
             "transfer": "transfer", "propose_grant": "grant proposal", "support": "support payment"}
    ordered = [item for item in history if isinstance(item, dict)]
    ordered.sort(key=lambda item: _int(item.get("height", item.get("receipt_height"))) or 0, reverse=True)
    for item in ordered:
        if not isinstance(item, dict):
            continue
        entry = item.get("action", item)
        if not isinstance(entry, dict) or entry.get("sender_index") != profile["index"]:
            continue
        # The planner supplies only this region's history; reject explicit mismatch.
        if entry.get("region", profile["region"]) != profile["region"]:
            continue
        confirmed = _confirmed(item)
        height = _int(item.get("height", item.get("receipt_height")))
        if not confirmed or height is None or entry.get("kind") not in names:
            continue
        return "My demo account's " + names[entry["kind"]] + " confirmed at block " + str(height) + "."
    return None


def compose_message(snapshot, profile, *, metrics=None, history=(), sequence=0, evaluation=None):
    """Compose 2–4 whole sentences within this demo's 512-byte text limit."""
    if profile.get("pass_campaign"):
        return profile["label"] + " — Coordinated PASS attempt; settlement pending."
    strategy = "native-balance-v1" if profile.get("native_balance_strategy") else "substantive-v1"
    profile = profile_for(profile["region"], profile["index"], strategy)
    result = deepcopy(evaluation) if evaluation is not None else evaluate(snapshot, profile, metrics)
    seq = max(0, int(sequence))
    theses, challenges = _VOICES[profile["name"]]
    thesis = theses[seq % len(theses)]
    challenge = challenges[(seq // len(theses) + seq) % len(challenges)]
    facts = _facts(snapshot, result)
    fact = facts[seq % len(facts)] if facts else "The available snapshot does not establish this grant's funding or price trade-off."
    side = result["preferred_outcome"].upper()
    phase = snapshot.get("status", {}).get("phase")
    stance = ("My demo strategy currently favors " + side + "; " + result.get("rationale", result["reasons"][0]) + "."
              if phase == "governance" else challenge)
    own = _own_action(history, profile)
    # Alternate direct policy argument and named counterargument. Historical
    # statements only appear with a supplied confirmed receipt, never a plan.
    tail = own if own and seq % 3 == 2 else (challenge if seq % 2 else stance)
    prefix = profile["label"] + " — "
    sentences = [thesis, fact, tail]
    if len((prefix + " ".join(sentences)).encode("utf-8")) > MAX_TEXT_BYTES:
        sentences = [thesis, fact]
    if len((prefix + " ".join(sentences)).encode("utf-8")) > MAX_TEXT_BYTES:
        sentences = ["I favor bounded experiments with visible costs.", "Current data needs careful interpretation before choosing exposure."]
    text = prefix + " ".join(sentences)
    assert len(text.encode("utf-8")) <= MAX_TEXT_BYTES
    return text
