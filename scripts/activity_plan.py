"""Deterministic, explicitly profiled activity planning; never signs or submits.

``rpc(method, params)`` is supplied by the daemon and may only make the read-only
calls below. Amounts are raw integer units, not display hashes or display Stash.
Confirmed action metadata belongs in policy['history']; a plan is not a receipt.
Preparing and pending metadata belongs in policy['pending_actions'] and reserves
an intent without advancing any confirmed governance stage.
"""

import hashlib


CHAT = 10**12
SUPPORT = 10**12
TRADE = 10**13
GRANT = 10**13
SEED = 10**14
READ_METHODS = frozenset({"fee_quote", "stash_quote", "grant_quote", "proposals", "support"})
NATIVE_PROFILE = "native-balance-v1"
PASS_PROFILE = "pass-campaign-v1"
NATIVE_PROFILES = frozenset({NATIVE_PROFILE, PASS_PROFILE})
CAMPAIGN_COORDINATOR = "sgp"
CAMPAIGN_RECIPIENT = "fra"


def proposal_description(region, round_id, profile):
    # Stable regional/round identity for proposal and support matching. Native
    # proposals commit this identity without attaching explanatory message data.
    if profile == PASS_PROFILE:
        return f"Hashstash coordinated PASS campaign v1 {CAMPAIGN_COORDINATOR} round {round_id}"
    return f"Hashstash automated demo {region} round {round_id}"


def campaign_proposal(record, registry):
    """Recognize only the shared campaign commitment and registered recipient."""
    try:
        expected = hashlib.sha256(proposal_description(CAMPAIGN_COORDINATOR, record["round"], PASS_PROFILE).encode()).digest()
        payments, amount = validated_grant(record["action"]["Grant"])
        recipient = _key(registry[CAMPAIGN_RECIPIENT][0])
        return (bytes(record["description"]) == expected and payments == [(recipient, amount)]
                and set(record["action"]) == {"Grant"})
    except (KeyError, ValueError, TypeError):
        return False


def campaign_ready(snapshot, registry, fee):
    """Nine existing accounts must own real Stash and retain campaign liquidity."""
    world = snapshot.get("governance", {}).get("world", {})
    reserve = _number(world.get("reserve"))
    if reserve < fee * 1000 or not _number(world.get("curve_mass")):
        return False
    cash = 0
    for group in registry.values():
        for entry in group:
            account = _snapshot_holdings(snapshot.get("balances", {}).get(_key(entry), {}).get("account"))
            if account is None or _number(account.get("ordinary")) <= fee * 100 or not _number(account.get("shares")):
                return False
            cash += _number(account["ordinary"])
    return cash >= reserve // 2


def _snapshot_holdings(value):
    """Compact snapshot holdings omit nonce; they are never signing accounts."""
    if not isinstance(value, dict):
        return None
    for field in ("ordinary", "shares"):
        raw = value.get(field)
        if (not isinstance(raw, str) or not raw or len(raw) > 155
                or not raw.isascii() or not raw.isdecimal()
                or (len(raw) > 1 and raw[0] == "0") or int(raw).bit_length() > 512):
            return None
    return value


def _number(value, default=0):
    try:
        number = int(value)
        return number if number >= 0 else default
    except (TypeError, ValueError):
        return default


def _key(value):
    value = value.get("public_key", value.get("key")) if isinstance(value, dict) else value
    if not isinstance(value, str) or len(value) != 64:
        return None
    try:
        bytes.fromhex(value)
    except ValueError:
        return None
    return value.lower()


def _bytes(value):
    return list(bytes.fromhex(value))


def validated_grant(grant):
    """Return canonical recipient/amount pairs and their bounded aggregate."""
    if not isinstance(grant, dict) or set(grant) != {"payments"}:
        raise ValueError("grant requires only payments")
    payments = grant["payments"]
    if not isinstance(payments, list) or not payments:
        raise ValueError("grant requires at least one payment")
    previous, total, result = None, 0, []
    for payment in payments:
        if not isinstance(payment, dict) or set(payment) != {"recipient", "amount"}:
            raise ValueError("unexpected grant payment fields")
        key, value = payment["recipient"], payment["amount"]
        if (not isinstance(key, list) or len(key) != 32
                or any(type(byte) is not int or not 0 <= byte <= 255 for byte in key)):
            raise ValueError("invalid grant recipient")
        raw = bytes(key)
        if raw == bytes(32) or previous is not None and raw <= previous:
            raise ValueError("grant recipients must be nonzero and strictly increasing")
        if (not isinstance(value, str) or not value or len(value) > 155
                or not value.isascii() or not value.isdigit() or value.startswith("0")):
            raise ValueError("grant payment must be a positive canonical amount")
        n = int(value)
        total += n
        if total.bit_length() > 512:
            raise ValueError("grant aggregate exceeds amount range")
        result.append((raw.hex(), n))
        previous = raw
    return result, total


def _account(value):
    if not isinstance(value, dict):
        return None
    if "account" in value and "ordinary" not in value:
        return _account(value["account"])
    return value if "ordinary" in value and "nonce" in value else None


def full_cash_governance(snapshot):
    status = snapshot.get("status", {})
    return status.get("phase") == "governance"


def world_cash(actor):
    """Return independent FAIL/PASS cash only for a coherent automatic-outcome account pair."""
    failed, passed = _account(actor.get("account")), _account(actor.get("pass_account"))
    if failed is None or passed is None:
        return None
    try:
        values = tuple(int(a["ordinary"]) for a in (failed, passed))
        if min(values) < 0 or int(failed["nonce"]) != int(passed["nonce"]):
            return None
        return values
    except (KeyError, TypeError, ValueError):
        return None


def common_cash(snapshot, actor):
    if full_cash_governance(snapshot):
        cash = world_cash(actor)
        return min(cash) if cash is not None else 0
    return _number((_account(actor.get("account")) or {}).get("ordinary"))


def cash_guard(snapshot, actor, operation, max_fee, reserve=0):
    """Conservative automatic-outcome pre-sign check; no quotes, invented proceeds or writes.

    Selected redemption can fund its own world's fee using min_received, but
    cannot fund the other world. Shared transfers pay in both worlds. A maximum
    fee budget is retained so changing minimum requirements cannot strand cash.
    """
    kind, fields = next(iter(operation.items()))
    if kind not in {"TransferExact", "Deposit", "Redeem", "Propose", "Support", "Refund"}:
        return "unsupported_activity_operation"
    if not full_cash_governance(snapshot):
        return None
    cash = world_cash(actor)
    if cash is None:
        return "waiting_for_consistent_outcome_accounts"
    after = list(cash)
    debit = False
    if kind in {"Deposit", "Redeem"}:
        if fields.get("outcome") not in {"Pass", "Fail"}:
            return "outcome_required_during_governance"
        side = 1 if fields["outcome"] == "Pass" else 0
        if kind == "Deposit":
            after[side] -= int(fields["amount"])
            debit = True
        else:
            after[side] += int(fields["min_received"])
    elif kind == "TransferExact":
        cost = int(fields["amount"])
        after = [amount - cost for amount in after]
        debit = True
    # Refunds are conservatively checked without credit: only canonical state,
    # never planner metadata, proves their amount at the signing boundary.
    floor = int(max_fee) + (int(reserve) if debit else 0)
    if min(after) < floor:
        return "waiting_for_cash_in_both_outcomes"
    return None


def _read(rpc, method, params):
    if method not in READ_METHODS:
        raise ValueError("activity planner RPC must be read-only")
    try:
        return rpc(method, params)
    except Exception:
        # A quote failure or a moving phase means wait/re-plan, never widen intent.
        return None


def _entry(record):
    return record.get("action", record) if isinstance(record, dict) else {}


def _history(policy):
    return [_entry(item) for item in policy.get("history", []) if isinstance(item, dict)]


def _fraction(value, bps):
    return _number(value) * _number(bps) // 10000


def _bounded_bps(profile, field, low, high):
    return min(high, max(low, _number(profile.get(field), low)))


def still_valid(action, snapshot, account):
    """Recheck the observed chain, phase, decision and nonce before signing."""
    try:
        status, guard = snapshot["status"], action["guard"]
        balance = _account(account)
        return bool(balance is not None
                    and status["chain_id"] == guard["chain_id"]
                    and status["phase"] == guard["phase"]
                    and status.get("decision") == guard["decision"]
                    and status.get("auction_round") == guard["auction_round"]
                    and int(balance["nonce"]) == guard["nonce"]
                    and guard["height"] <= int(status["height"])
                    < guard["height"] + action["expiry_blocks"]
                    and (_key(account) in (None, guard["sender_public_key"])))
    except (KeyError, TypeError, ValueError):
        return False


def plan(snapshot, accounts, registry, policy, now, rpc):
    """Return one reviewed action or None; no writes, signing or submission.

    accounts: exactly three {public_key, account, pass_account?, pending?} rows;
    account values include ordinary/shares/nonce. registry maps the
    three region names to their three public keys (or {public_key} descriptors).
    policy supplies region/chain_id, confirmed history, cursor, last_action_at,
    last_action_height, last_chat_at, and optional fee limits/pending keys/actions.
    """
    status = snapshot.get("status", {})
    profile_name = policy.get("profile", "bounded-v1")
    if profile_name not in {"bounded-v1", "substantive-v1", *NATIVE_PROFILES}:
        return None
    campaign = profile_name == PASS_PROFILE
    native = profile_name in NATIVE_PROFILES
    substantive = native or profile_name == "substantive-v1"
    phase = status.get("phase")
    chain = _key(status.get("chain_id"))
    region = policy.get("region")
    if (chain is None or chain != policy.get("chain_id")
            or status.get("protocol_version") != 28
            or phase not in {"auction", "governance", "rest"}
            or region not in registry or len(accounts) != 3):
        return None
    height = _number(status.get("height"))
    if (height <= _number(policy.get("last_action_height"))
            or (policy.get("last_action_at") is not None
                and now - float(policy["last_action_at"]) < 20)):
        return None
    registry_keys = {r: [_key(a) for a in values] for r, values in registry.items()}
    if (len(registry_keys) != 3 or any(len(keys) != 3 or None in keys for keys in registry_keys.values())
            or len({key for keys in registry_keys.values() for key in keys}) != 9
            or [_key(a) for a in accounts] != registry_keys[region]):
        return None
    decision = status.get("decision")
    if (phase == "governance") != bool(_key(decision)):
        return None
    max_fee = max(1, _number(policy.get("max_fee_raw"), 10**6))
    reserve = max(max_fee * 2, _number(policy.get("fee_reserve_raw"), 10**9))
    if native:
        # Use a current ordinary transfer quote to keep enough real liquidity
        # for the next operations; each candidate still obtains its exact quote.
        # There is no fixed hash-denominated fee or trade ceiling.
        sender = next((a for a in accounts if _account(a.get("account")) is not None), None)
        if sender is None:
            return None
        fee_quote = _read(rpc, "fee_quote", {"sender": sender["public_key"],
            "operation": {"TransferExact": {"recipient": _bytes(registry_keys[region][1]), "amount": "1"}},
            "extra_fee": "0", "expiry_blocks": 20})
        if not isinstance(fee_quote, dict) or _number(fee_quote.get("fee")) < 1:
            return None
        max_fee = _number(fee_quote["fee"])
        reserve = max_fee * 2
    history = _history(policy)
    pending_actions = [_entry(item) for item in policy.get("pending_actions", [])
                       if isinstance(item, dict)]
    pending = set(policy.get("pending_public_keys", []))
    pending_indices = {h.get("sender_index") for h in pending_actions
                       if isinstance(h.get("sender_index"), int)}
    pending.update(h.get("guard", {}).get("sender_public_key") for h in pending_actions)
    balances = [_account(a.get("account")) for a in accounts]
    full_cash = full_cash_governance(snapshot)
    cursor = _number(policy.get("cursor"))
    order = [(cursor + step) % 3 for step in range(3)]
    other_regions = sorted(r for r in registry_keys if r != region)
    peer_keys = {key for r in other_regions for key in registry_keys[r]}
    personas = []
    if substantive:
        # The higher-volume strategy is opt-in. Existing configurations retain
        # their original limits even if this module is updated in place.
        from activity_personas import profile_for, evaluate, compose_message, next_speaker, speaker_sequence
        personas = [profile_for(region, index, profile_name) for index in range(3)]
    minimum_trade = max(max_fee * 100, CHAT) if substantive and not native else 1
    direct_remaining = _number(policy.get("consumptive_budget_remaining_raw"), 10**15)
    quotes = {}

    def usable(index):
        return (balances[index] is not None and not accounts[index].get("pending")
                and (not full_cash or world_cash(accounts[index]) is not None)
                and index not in pending_indices
                and accounts[index]["public_key"] not in pending)

    def spendable(index):
        return max(0, common_cash(snapshot, accounts[index]) - reserve - (max_fee if full_cash else 0))

    def outcome_spendable(index, outcome):
        cash = world_cash(accounts[index])
        return max(0, cash[1 if outcome == "Pass" else 0] - reserve - max_fee) if cash else 0

    def confirmed(kind, index=None, **context):
        return any(h.get("kind") == kind
                   and (index is None or h.get("sender_index") == index)
                   and all(h.get(k) == v for k, v in context.items()) for h in history)

    def reserved(kind, index=None, **context):
        # These are durable signed/preparing intents, not confirmed effects. In
        # particular, do not add them to the governance stage history below.
        return any(h.get("kind") == kind
                   and (index is None or h.get("sender_index") == index)
                   and all(h.get(k) == v for k, v in context.items()) for h in pending_actions)

    def completed_or_reserved(kind, index=None, **context):
        return confirmed(kind, index, **context) or reserved(kind, index, **context)

    def emit(index, operation, kind, amount, debit=0, ordinary_credit=0, **metadata):
        if not usable(index):
            return None
        data = metadata.pop("data_hex", None)
        request = {"sender": accounts[index]["public_key"], "operation": operation,
                   "extra_fee": "0", "expiry_blocks": 20}
        if data:
            request["data_hex"] = data
        quote = _read(rpc, "fee_quote", request)
        if not isinstance(quote, dict) or "fee" not in quote:
            return None
        if native:
            try:
                if int(quote["fee"]) < 0:
                    return None
            except (TypeError, ValueError):
                return None
        fee = _number(quote["fee"], max_fee + 1)
        fee_budget = max(max_fee, fee) if native else max_fee
        cash_reserve = fee_budget * 2 if native else reserve
        cash_after = _number(balances[index]["ordinary"]) + ordinary_credit - debit
        if (not native and fee > max_fee) or (full_cash and cash_guard(snapshot, accounts[index], operation, fee_budget, cash_reserve)):
            return None
        if not full_cash and (cash_after < fee or (debit and cash_after < cash_reserve + (fee if native else 0))):
            return None
        guard = {"chain_id": chain, "phase": phase, "decision": decision,
                 "auction_round": status.get("auction_round"), "height": height,
                 "sender_public_key": accounts[index]["public_key"],
                 "nonce": _number(balances[index]["nonce"])}
        result = {"sender_index": index, "kind": kind, "operation": operation,
                  "amount_raw": str(amount), "max_fee_raw": str(fee_budget),
                  "quoted_fee_raw": str(fee), "expiry_blocks": 20,
                  "guard": guard, **metadata}
        if substantive:
            result.update(profile=profile_name, persona=personas[index]["name"], region=region)
        if data:
            result["data_hex"] = data
        return result

    def transfer(index, recipient, amount, kind, **metadata):
        if amount < 1:
            return None
        return emit(index, {"TransferExact": {"recipient": _bytes(recipient),
                    "amount": str(amount)}}, kind,
                    amount, debit=amount, recipient=recipient, **metadata)

    def circulate(index):
        recipient = registry_keys[other_regions[(cursor // 3) % 2]][cursor % 3]
        amount = (_fraction(spendable(index), _bounded_bps(personas[index], "circulation_bps", 1000, 3000))
                  if substantive else min(TRADE, spendable(index) // 10))
        return transfer(index, recipient, amount, "transfer") if amount >= minimum_trade else None

    def deposit(index, amount, outcome=None):
        if amount < 1:
            return None
        request = {"key": accounts[index]["public_key"], "kind": "deposit", "amount": str(amount)}
        if outcome:
            request["outcome"] = outcome.lower()
        quote = _read(rpc, "stash_quote", request)
        if not isinstance(quote, dict) or _number(quote.get("shares")) < 1:
            return None
        if quote.get("decision") != (decision if outcome else None):
            return None
        minimum = max(1, _number(quote["shares"]) * 99 // 100)
        return emit(index, {"Deposit": {"amount": str(amount), "min_shares": str(minimum),
                    "decision": _bytes(decision) if outcome else None, "outcome": outcome}},
                    "deposit_" + outcome.lower() if outcome else "deposit", amount,
                    debit=0 if outcome else amount, decision=decision if outcome else None)

    def redeem(index, outcome=None, recovery=False, fraction_bps=None, target_output=None):
        account = _account(accounts[index].get("pass_account")) if outcome == "Pass" else balances[index]
        shares = _number((account or {}).get("shares"))
        if not shares:
            return None
        fraction_bps = (_bounded_bps(personas[index], "stash_adjustment_bps", 2000, 6000)
                        if substantive and fraction_bps is None else (fraction_bps or 1000))
        request = {"key": accounts[index]["public_key"], "kind": "redeem", "amount": str(max(1, _fraction(shares, fraction_bps)))}
        if substantive and target_output is not None:
            if target_output < minimum_trade:
                return None
            request.update(kind="withdraw", amount=str(target_output))
        if outcome:
            request["outcome"] = outcome.lower()
        quote = _read(rpc, "stash_quote", request)
        if not isinstance(quote, dict) or _number(quote.get("output_hash")) < 1:
            return None
        if not substantive and _number(quote["output_hash"]) > TRADE:
            # Share rounding can pay slightly more than the requested withdrawal.
            # Leave headroom while still checking the actual quote against the cap.
            request.update(kind="withdraw", amount=str(TRADE * 99 // 100))
            quote = _read(rpc, "stash_quote", request)
        if (not isinstance(quote, dict) or _number(quote.get("shares")) < 1
                or _number(quote.get("output_hash")) < 1
                or quote.get("decision") != (decision if outcome else None)):
            return None
        output = _number(quote["output_hash"])
        if (not substantive and output > TRADE) or _number(quote["shares"]) > shares:
            return None
        if substantive and not recovery and output < minimum_trade:
            return None
        minimum = max(1, output * 99 // 100)
        return emit(index, {"Redeem": {"shares": str(quote["shares"]), "min_received": str(minimum),
                    "decision": _bytes(decision) if outcome else None, "outcome": outcome}},
                    "redeem_" + outcome.lower() if outcome else ("recover_cash" if recovery else "redeem"),
                    output, ordinary_credit=minimum if outcome is None else 0,
                    decision=decision if outcome else None)

    def withdrawal_value(index, outcome=None):
        cache_key = (index, outcome)
        if cache_key not in quotes:
            account = _account(accounts[index].get("pass_account")) if outcome == "Pass" else balances[index]
            if not _number((account or {}).get("shares")):
                quotes[cache_key] = 0
            else:
                request = {"key": accounts[index]["public_key"], "kind": "redeem", "all": True}
                if outcome:
                    request["outcome"] = outcome.lower()
                quote = _read(rpc, "stash_quote", request)
                quotes[cache_key] = (_number(quote.get("output_hash"))
                                     if isinstance(quote, dict) and quote.get("decision") == (decision if outcome else None)
                                     else None)
        return quotes[cache_key]

    def native_rebalance(index, outcome=None, target_bps=None, recovery=False):
        """Move the whole cash-valued portfolio gap, retaining only actual fees.

        Each conditional world owns its cash and shares independently. An
        unfavored-world target of zero exits that exposure; the favored world
        keeps the persona's usual Stash allocation, rather than going all-in.
        """
        value = withdrawal_value(index, outcome)
        if value is None:
            return None
        cash = (outcome_spendable(index, outcome) if outcome else
                max(0, common_cash(snapshot, accounts[index]) - max_fee * 3))
        allocation = (_bounded_bps(personas[index], "stash_target_bps", 2000, 8000)
                      if target_bps is None else target_bps)
        target = _fraction(cash + value, allocation)
        gap = target - value
        # Fee-sized rounding drift is not a fresh portfolio decision.
        if gap > max_fee:
            return deposit(index, min(cash, gap), outcome)
        if gap < -max_fee:
            return redeem(index, outcome, recovery=recovery, target_output=min(value, -gap))
        return None

    def metrics_for(grant=None):
        governance = snapshot.get("governance", {})
        world, alternative = governance.get("world", {}), governance.get("pass") or {}
        result = {"reserve_raw": _number(world.get("reserve")),
                  "grant_capacity_raw": _number(world.get("grant_capacity"))}
        active = governance.get("phase", {}).get("Governance", {})
        if grant is None:
            grant = active.get("proposal", {}).get("Grant")
        try:
            _, requested = validated_grant(grant)
        except ValueError:
            requested = 0
        if requested:
            result["grant_amount_raw"] = requested
            funding = _read(rpc, "grant_quote", {"amount": str(result["grant_amount_raw"])})
            if isinstance(funding, dict) and isinstance(funding.get("feasible"), bool):
                result["grant_feasible"] = funding["feasible"]
            if active and alternative:
                result["grant_funded_raw"] = _number(alternative.get("grant_escrow"))
        for outcome, current in (("pass", alternative), ("fail", world)):
            if _number(current.get("shares")) and _number(current.get("curve_mass")):
                result[outcome + "_price_numerator"] = _number(current["curve_mass"])
                result[outcome + "_price_denominator"] = _number(current["shares"])
        return result

    def paid_support(index):
        if not substantive:
            return SUPPORT
        fraction = _bounded_bps(personas[index], "circulation_bps", 1000, 3000) // 5
        paid = _fraction(spendable(index), fraction)
        return paid if native else min(paid, max(0, direct_remaining - max_fee))

    # First make a small, finite actor set. Reusing funded accounts prevents churn.
    if usable(0):
        for index in (1, 2):
            if balances[index] is None and not accounts[index].get("pending"):
                amount = _fraction(spendable(0), 3000) if substantive else min(SEED, spendable(0) // 5)
                action = transfer(0, accounts[index]["public_key"], amount, "seed")
                if action:
                    return action

    # Ordinary redemption can recover spending liquidity and pay its fee from proceeds.
    if phase in {"auction", "rest"}:
        for index in order:
            if usable(index) and _number(balances[index]["ordinary"]) < reserve * 2:
                action = (native_rebalance(index, recovery=True) if native else redeem(index, recovery=True))
                if action:
                    return action

    if full_cash and not campaign:
        for index in order:
            if not usable(index):
                continue
            for outcome, cash in zip(("Fail", "Pass"), world_cash(accounts[index])):
                if cash < reserve * 2:
                    action = (native_rebalance(index, outcome, recovery=True) if native
                              else redeem(index, outcome, recovery=True))
                    if action:
                        return action

    # Keep independently owned actors able to pay fees during a decision.
    for index in order:
        if usable(index) and common_cash(snapshot, accounts[index]) < reserve:
            for donor in order:
                if donor != index and usable(donor) and spendable(donor) > reserve * 10:
                    amount = (_fraction(spendable(donor), 1000) if substantive
                              else min(TRADE, spendable(donor) // 10))
                    action = transfer(donor, accounts[index]["public_key"], amount, "refuel")
                    if action:
                        return action

    if campaign:
        # One explicit campaign, not nine purportedly independent opinions.
        # No chat or circulation competes with the time-integrated decision.
        progress = snapshot.get("campaign", {})
        if not progress.get("checked") or progress.get("settlement_pending"):
            return None
        if progress.get("completed"):
            # Canonical, two-confirmation settlement has closed the experiment.
            # Continue ordinary portfolio/transfer activity; never another grant.
            if phase in {"rest", "auction"}:
                for index in order:
                    if usable(index):
                        action = native_rebalance(index, target_bps=5000)
                        if action:
                            return action
                        action = circulate(index)
                        if action:
                            return action
            return None
        if phase == "governance":
            active = snapshot.get("governance", {}).get("phase", {}).get("Governance", {})
            rows = _read(rpc, "proposals", {"round": active.get("round"), "limit": 128})
            proposal_id = bytes(active.get("proposal_id", [])).hex()
            matched = next((row.get("proposal") for row in rows or [] if row.get("id") == proposal_id), None)
            if (not matched or not campaign_proposal(matched, registry)
                    or matched["action"] != active.get("proposal")):
                return None
            grant = validated_grant(active["proposal"]["Grant"])[1]
            if _number((snapshot.get("governance", {}).get("pass") or {}).get("grant_escrow")) != grant:
                return None
            timing = (active.get("started"), active.get("duration"), status.get("clock"), status.get("settings", {}).get("interval"))
            if (not all(type(n) is int and n >= 0 for n in timing) or timing[3] <= 0
                    or not timing[0] <= timing[2] < timing[0] + timing[1]
                    or timing[0] + timing[1] - timing[2] < 2 * timing[3]):
                return None
            # Buy PASS first across all three local actors, so its higher price
            # contributes early to the integral. Retain 10% portfolio liquidity.
            # A world owns its own cash: selling FAIL never finances PASS.
            for index in order:
                if not usable(index) or completed_or_reserved("deposit_pass", index, decision=decision, campaign_leg="buy_pass"):
                    continue
                value = withdrawal_value(index, "Pass")
                if value is None:
                    continue
                cash = outcome_spendable(index, "Pass")
                gap = (cash + value) * 9000 // 10000 - value
                if gap > max_fee:
                    action = deposit(index, min(cash, gap), "Pass")
                    if action:
                        action.update(campaign_leg="buy_pass", preferred_outcome="Pass", strategy_reason="coordinated_pass_campaign")
                        return action
            for index in order:
                if not usable(index) or completed_or_reserved("redeem_fail", index, decision=decision, campaign_leg="exit_fail"):
                    continue
                action = native_rebalance(index, "Fail", target_bps=0)
                if action:
                    action.update(campaign_leg="exit_fail", preferred_outcome="Pass", strategy_reason="coordinated_pass_campaign")
                    return action
            return None
        if phase in {"rest", "auction"}:
            round_id = status.get("auction_round")
            rows = (_read(rpc, "proposals", {"round": round_id, "limit": 128}) if phase == "auction" else [])
            if rows is None:
                return None
            if any(campaign_proposal(row.get("proposal", {}), registry) for row in rows):
                return None
            # Establish Stash before scheduling the campaign, while preserving
            # roughly half of each actor's value as actual buying power.
            for index in order:
                if usable(index):
                    value = withdrawal_value(index)
                    cash = spendable(index)
                    target = (cash + (value or 0)) // 2
                    # A 2% preparation band prevents tiny rebalancing churn.
                    if value is not None and abs(target - value) > max(max_fee, (cash + value) // 50):
                        action = native_rebalance(index, target_bps=5000)
                        if action:
                            action["strategy_reason"] = "campaign_backing_and_liquidity"
                            return action
            if (phase != "auction" or type(round_id) is not int or region != CAMPAIGN_COORDINATOR
                    or not usable(0) or not campaign_ready(snapshot, registry, max_fee)
                    or completed_or_reserved("propose_grant", round=round_id)):
                return None
            world = snapshot["governance"]["world"]
            support = max(1, spendable(0) * 200 // 10000)
            requested = _number(world.get("revenue")) + support + _number(world["reserve"]) // 2
            destination = registry_keys[CAMPAIGN_RECIPIENT][0]
            description = hashlib.sha256(proposal_description(region, round_id, profile_name).encode()).hexdigest()
            operation = {"Propose": {"round": round_id, "description": _bytes(description),
                "proposal": {"Grant": {"payments": [{"recipient": _bytes(destination), "amount": str(requested)}]}},
                "support": str(support)}}
            # Account for the entire exact fee conservatively as waiting revenue.
            action = emit(0, operation, "propose_grant", support, debit=support, round=round_id,
                          description=description, recipient=destination, grant_amount_raw=str(requested))
            if not action:
                return None
            fee_allowance = int(action["quoted_fee_raw"])
            requested += fee_allowance
            if requested > _number(world.get("grant_capacity")):
                return None
            quote = _read(rpc, "grant_quote", {"amount": str(requested)})
            if not isinstance(quote, dict) or quote.get("feasible") is not True:
                return None
            operation["Propose"]["proposal"]["Grant"]["payments"][0]["amount"] = str(requested)
            action = emit(0, operation, "propose_grant", support, debit=support, round=round_id,
                          description=description, recipient=destination, grant_amount_raw=str(requested),
                          campaign_reserve_draw_raw=str(_number(world["reserve"]) // 2))
            return action if action and int(action["quoted_fee_raw"]) <= fee_allowance else None
        return None

    # Recover only support proven refundable by the node, once per support key.
    for entry in history:
        if entry.get("kind") not in {"support", "propose_grant"}:
            continue
        index, round_id = entry.get("sender_index"), entry.get("round")
        if not isinstance(index, int) or not 0 <= index < 3 or not usable(index):
            continue
        proposal = entry.get("proposal")
        if proposal is None and entry.get("description"):
            records = _read(rpc, "proposals", {"round": round_id, "limit": 128})
            for row in records if isinstance(records, list) else []:
                if row.get("proposal", {}).get("description") == _bytes(entry["description"]):
                    proposal = row.get("id")
                    break
        if not _key(proposal) or completed_or_reserved("refund", index, round=round_id, proposal=proposal):
            continue
        quote = _read(rpc, "support", {"key": accounts[index]["public_key"], "round": round_id, "proposal": proposal})
        if isinstance(quote, dict) and quote.get("refundable") is True and _number(quote.get("amount")):
            amount = _number(quote["amount"])
            action = emit(index, {"Refund": {"round": round_id, "proposal": _bytes(proposal)}},
                          "refund", amount, ordinary_credit=amount, round=round_id, proposal=proposal)
            if action:
                return action

    # Label bots visibly and limit permanent chat messages independently.
    if native and phase in {"auction", "rest"}:
        world = snapshot.get("governance", {}).get("world", {})
        # A curve experiment needs ordinary Stash backing first. Fee revenue
        # alone can fund a grant but cannot bend a nonexistent curve. Build
        # real backing from the same accounts before discussing/proposing it.
        if (_number(world.get("reserve")) == 0 or _number(world.get("curve_mass")) == 0
                or _number(world.get("grant_capacity")) <= _number(world.get("revenue"))):
            for index in order:
                if usable(index):
                    action = native_rebalance(index)
                    if action:
                        action["strategy_reason"] = "build_ordinary_backing_before_curve_proposal"
                        return action

    # Label bots visibly and limit permanent chat messages independently.
    last_chat = policy.get("last_chat_at")
    chat_seconds = max(90 if substantive else 300, _number(policy.get("chat_seconds")))
    if (last_chat is None or now - float(last_chat) >= chat_seconds) and (native or not substantive or direct_remaining >= CHAT + max_fee):
        if registry_keys[region]:
            chat_order = [next_speaker(region, history, policy.get('confirmed_chat_count'))] if substantive else order
            for index in chat_order:
                chat_amount = max(1, spendable(index) // 10000) if native else CHAT
                if usable(index) and spendable(index) >= chat_amount:
                    if substantive:
                        metrics = metrics_for()
                        evaluation = evaluate(snapshot, personas[index], metrics=metrics)
                        sequence = speaker_sequence(region, index, history, policy.get('confirmed_chat_counts'))
                        text = compose_message(snapshot, personas[index], metrics=metrics, history=history,
                                               sequence=sequence, evaluation=evaluation)
                    else:
                        text = f"Automated demo / {region.upper()}: observing block {height}, {phase} phase."
                    # The public feed reads the signed text directly. Keep the
                    # demo's tighter message bound and visible automation label.
                    payload = text.encode("utf-8")
                    if not 0 < len(payload) <= 512 or "automated" not in text.lower():
                        continue
                    data = payload.hex()
                    recipient = registry_keys[region][(index + 1) % 3]
                    action = transfer(index, recipient, chat_amount, "chat", data_hex=data, message=text)
                    if action:
                        return action

    if phase == "auction":
        round_id = status.get("auction_round")
        if not isinstance(round_id, int):
            return None
        gov = snapshot.get("governance", {})
        world = gov.get("world", {})
        capacity = _number(world.get("grant_capacity"))
        # Profiles choose proposal amounts; eligibility follows actual backing.
        grant = capacity if substantive else min(GRANT, capacity // 1000)
        if grant and not completed_or_reserved("propose_grant", round=round_id):
            rationale = proposal_description(region, round_id, profile_name).encode("utf-8")
            description = hashlib.sha256(rationale).hexdigest()
            proposal_data = "" if native else rationale.hex()
            destination = registry_keys[other_regions[cursor % 2]][0]
            for index in order:
                support = paid_support(index)
                if not usable(index) or support < (minimum_trade if substantive else SUPPORT) or spendable(index) < support:
                    continue
                requested = (min(grant, _fraction(capacity,
                                                  _bounded_bps(personas[index], "grant_request_bps", 100, 500)))
                             if substantive else grant)
                if native:
                    # Half the current reserve is a strategy target, not an
                    # eligibility cap. Support enters waiting revenue first.
                    requested = (_number(world.get("revenue")) + support
                                 + _number(world.get("reserve")) // 2)
                    if (_number(world.get("reserve")) == 0 or _number(world.get("curve_mass")) == 0
                            or requested > capacity or requested <= _number(world.get("revenue")) + support):
                        # Do not clip the experiment to fee dust or a grant
                        # entirely covered by waiting revenue/support.
                        continue
                if not requested:
                    continue
                quote = _read(rpc, "grant_quote", {"amount": str(requested)})
                if not isinstance(quote, dict) or quote.get("feasible") is not True:
                    continue
                operation = {"Propose": {"round": round_id, "description": _bytes(description),
                             "proposal": {"Grant": {"payments": [{"recipient": _bytes(destination), "amount": str(requested)}]}},
                             "support": str(support)}}
                action = emit(index, operation, "propose_grant", support, debit=support,
                              round=round_id, description=description, grant_amount_raw=str(requested),
                              recipient=destination, data_hex=proposal_data)
                if native and action:
                    # The proposal fee also adds waiting revenue. Include its
                    # entire exact quote conservatively, then quote the final
                    # immutable amount again; never shrink the reserve target.
                    fee_allowance = int(action["quoted_fee_raw"])
                    funded_target = requested + fee_allowance
                    if funded_target > capacity:
                        continue
                    funding = _read(rpc, "grant_quote", {"amount": str(funded_target)})
                    if not isinstance(funding, dict) or funding.get("feasible") is not True:
                        continue
                    operation["Propose"]["proposal"]["Grant"]["payments"][0]["amount"] = str(funded_target)
                    action = emit(index, operation, "propose_grant", support, debit=support,
                                  round=round_id, description=description, grant_amount_raw=str(funded_target),
                                  recipient=destination, data_hex=proposal_data)
                    if action and int(action["quoted_fee_raw"]) > fee_allowance:
                        continue
                if action:
                    return action
        if not completed_or_reserved("support", round=round_id):
            proposals = snapshot.get("proposals")
            if not isinstance(proposals, list):
                proposals = _read(rpc, "proposals", {"round": round_id, "limit": 128})
            own_descriptions = {h.get("description") for h in history if h.get("kind") == "propose_grant" and h.get("round") == round_id}
            peer_descriptions = {hashlib.sha256(proposal_description(r, round_id, profile_name).encode()).hexdigest()
                                 for r in registry_keys if r != region}
            allowed_recipients = {key for keys in registry_keys.values() for key in keys}
            for row in sorted(proposals or [], key=lambda p: str(p.get("id", ""))):
                record, proposal = row.get("proposal", {}), row.get("id")
                desc = bytes(record.get("description", [])).hex()
                grant_action = record.get("action", {}).get("Grant", {})
                try:
                    payments, total = validated_grant(grant_action)
                except ValueError:
                    continue
                # Do not amplify an unrelated parameter proposal or expired bid.
                if (not _key(proposal) or "Grant" not in record.get("action", {})
                        or record.get("round") != round_id or record.get("refund_height") is not None
                        or desc in own_descriptions or desc not in peer_descriptions
                        or any(recipient not in allowed_recipients for recipient, _ in payments)
                        or total > capacity):
                    continue
                funding = _read(rpc, "grant_quote", {"amount": str(total)})
                if not isinstance(funding, dict) or funding.get("feasible") is not True:
                    continue
                for index in order:
                    support = paid_support(index)
                    if substantive and evaluate(snapshot, personas[index], metrics=metrics_for(grant_action))["preferred_outcome"] != "Pass":
                        continue
                    if usable(index) and support >= (minimum_trade if substantive else SUPPORT) and spendable(index) >= support:
                        action = emit(index, {"Support": {"round": round_id, "proposal": _bytes(proposal), "amount": str(support)}},
                                      "support", support, debit=support, round=round_id, proposal=proposal,
                                      grant_amount_raw=str(total), recipients=[recipient for recipient, _ in payments])
                        if action:
                            return action

    if phase == "governance" or (substantive and phase in {"auction", "rest"}):
        # Keep cross-region circulation present throughout the decision. Funding
        # and recovery above remain urgent, and never consume this action budget.
        since_transfer = 0
        for entry in reversed(history):
            if entry.get("kind") == "transfer" and entry.get("recipient") in peer_keys:
                break
            if entry.get("kind") not in {"seed", "refuel", "recover_cash", "refund"}:
                since_transfer += 1
        if since_transfer >= 3:
            for index in order:
                if usable(index):
                    action = circulate(index)
                    if action:
                        return action

    if phase == "governance" and substantive:
        metrics = metrics_for()
        active = snapshot.get("governance", {}).get("phase", {}).get("Governance", {})
        # Scheduled seconds and height are different units. Missing timing must
        # never be guessed from height when starting another outcome cycle.
        timing = (active.get("started"), active.get("duration"), status.get("clock"),
                  status.get("settings", {}).get("interval"))
        valid_timing = (all(type(value) is int and value >= 0 for value in timing)
                        and timing[1] > 0 and timing[3] > 0
                        and timing[0] <= timing[2] < timing[0] + timing[1])
        remaining = timing[0] + timing[1] - timing[2] if valid_timing else None
        minimum_cycle_seconds = 6 * timing[3] if valid_timing else None
        for index in order:
            if not usable(index):
                continue
            current = balances[index]
            passed = _account(accounts[index].get("pass_account"))
            if passed is None:
                continue
            evaluation = evaluate(snapshot, personas[index], metrics=metrics)
            actor_history = [h for h in history if h.get("sender_index") == index and h.get("decision") == decision
                             and h.get("profile") == profile_name and isinstance(h.get("strategy_cycle"), int)]
            cycle = max((h["strategy_cycle"] for h in actor_history), default=0)
            cycle_history = [h for h in actor_history if h["strategy_cycle"] == cycle]
            done = {h.get("strategy_leg") for h in cycle_history}
            if "build_preferred" in done or "rebalance_preferred" in done:
                last_height = max((_number(h.get("height", h.get("guard", {}).get("height")))
                                   for h in cycle_history), default=height)
                if height - last_height < 6 or remaining is None or remaining < minimum_cycle_seconds:
                    continue
                cycle += 1
                cycle_history, done = [], set()
            elif not cycle_history and (remaining is None or remaining < minimum_cycle_seconds):
                continue
            preferred = (cycle_history[0].get("preferred_outcome") if cycle_history
                         else evaluation["preferred_outcome"])
            if preferred not in {"Pass", "Fail"}:
                continue
            other = "Fail" if preferred == "Pass" else "Pass"
            preferred_account, other_account = (passed, current) if preferred == "Pass" else (current, passed)
            preferred_value, other_value = withdrawal_value(index, preferred), withdrawal_value(index, other)
            if preferred_value is None or other_value is None:
                continue

            def describe(action, leg):
                if action:
                    action.update(strategy_cycle=cycle, strategy_leg=leg, preferred_outcome=preferred,
                                  pass_score=evaluation["pass_score"], strategy_reasons=evaluation["reasons"])
                return action

            # Existing portfolios may be almost entirely Stash. Rotate a real
            # share of that exposure first instead of relying on tiny cash dust.
            if ("trim_unfavored" not in done and other_value >= minimum_trade
                    and (not native or other_value > max_fee)):
                action = describe(native_rebalance(index, other, target_bps=0) if native
                                  else redeem(index, other), "trim_unfavored")
                if action:
                    return action
                continue

            if full_cash:
                if native:
                    if "rebalance_preferred" not in done and "build_preferred" not in done:
                        action = describe(native_rebalance(index, preferred), "rebalance_preferred")
                        if action:
                            return action
                    continue
                # Each outcome already has the actor's full cash. Sell or buy
                # only the chosen world; there is nothing to Commit or Merge.
                # Recover the favored world's cash only when the other world
                # can pay its own fee. Both-zero cash deliberately waits for a
                # real shared receipt/refuel instead of fictional liquidity.
                preferred_cash = _number(preferred_account.get("ordinary"))
                if preferred_cash < reserve * 2 and preferred_value >= minimum_trade:
                    action = describe(redeem(index, preferred), "liquidity_favored")
                    if action:
                        return action
                amount = _fraction(outcome_spendable(index, preferred),
                                   _bounded_bps(personas[index], "stash_adjustment_bps", 2000, 6000))
                if "build_preferred" not in done and amount >= minimum_trade:
                    action = describe(deposit(index, amount, preferred), "build_preferred")
                    if action:
                        return action
                continue

    if phase == "governance" and not substantive:
        stages = ("deposit_pass", "deposit_fail", "redeem_pass", "redeem_fail")
        for index in order:
            if not usable(index):
                continue
            done = set()
            for entry in history:
                if entry.get("sender_index") != index or entry.get("decision") != decision:
                    continue
                # Only this actor's confirmed final withdrawal closes its cycle.
                if entry.get("kind") == "redeem_fail":
                    done.clear()
                else:
                    done.add(entry.get("kind"))
            stage = next((kind for kind in stages if kind not in done), None)
            account = balances[index]
            pass_account = _account(accounts[index].get("pass_account"))
            if pass_account is None:
                continue
            action = None
            if stage in {"deposit_pass", "deposit_fail"}:
                outcome = "Pass" if stage.endswith("pass") else "Fail"
                cash = outcome_spendable(index, outcome)
                action = deposit(index, min(TRADE, cash // 3), outcome)
            elif stage in {"redeem_pass", "redeem_fail"}:
                action = redeem(index, "Pass" if stage.endswith("pass") else "Fail")
            if action:
                return action

    # Normal circulation continues while governance waits for real mined blocks.
    for step, index in enumerate(order):
        if not usable(index):
            continue
        action = None
        if native and phase in {"auction", "rest"}:
            action = native_rebalance(index)
        elif substantive and phase in {"auction", "rest"}:
            value = withdrawal_value(index)
            if value is not None:
                cash = spendable(index)
                total = cash + value
                target = _fraction(total, _bounded_bps(personas[index], "stash_target_bps", 2000, 8000))
                tolerance = max(minimum_trade, total // 20)
                adjustment = _bounded_bps(personas[index], "stash_adjustment_bps", 2000, 6000)
                if value + tolerance < target:
                    amount = min(_fraction(cash, adjustment), target - value)
                    if amount >= minimum_trade:
                        action = deposit(index, amount)
                elif value > target + tolerance:
                    action = redeem(index, target_output=min(_fraction(value, adjustment), value - target))
        elif not substantive:
            selection = (cursor + step) % 3 if phase in {"auction", "rest"} else 0
            if selection == 1:
                action = deposit(index, min(TRADE, spendable(index) // 10))
            elif selection == 2:
                action = redeem(index)
        if action:
            return action
        action = circulate(index)
        if action:
            return action
    return None
