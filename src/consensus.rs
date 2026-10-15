use crate::{codec, config::Config, crypto, fees, math, state::*, types::*};
use anyhow::{Result, bail, ensure};
use num_traits::Zero;
use std::collections::BTreeMap;

type AccountWrites = BTreeMap<PublicKey, Account>;

/// A transaction observes its own writes but updates each authenticated account
/// leaf once. World totals are finalized before returning to block execution.
#[derive(Default)]
struct AccountChanges {
    main: AccountWrites,
    pass: AccountWrites,
}

fn pending_account(
    w: &World,
    pending: &AccountWrites,
    key: &PublicKey,
    epoch: Option<u64>,
) -> Option<Account> {
    pending.get(key).cloned().or_else(|| w.account(key, epoch))
}

fn stage_account(
    pending: &mut AccountWrites,
    key: PublicKey,
    account: Account,
    c: &Config,
) -> Result<()> {
    // Check bounds before staging: a later fee must not hide an overflowing credit.
    World::validate_account_update(&account, c)?;
    pending.insert(key, account);
    Ok(())
}

impl AccountChanges {
    fn world(&mut self, outcome: Option<Outcome>) -> &mut AccountWrites {
        if outcome == Some(Outcome::Pass) {
            &mut self.pass
        } else {
            &mut self.main
        }
    }

    fn each(
        &mut self,
        s: &mut State,
        mut f: impl FnMut(&mut World, &mut AccountWrites, Option<u64>) -> Result<()>,
    ) -> Result<()> {
        let epoch = s.epoch();
        f(&mut s.world, &mut self.main, epoch)?;
        if let Some(w) = &mut s.alternative {
            f(w, &mut self.pass, epoch)?;
        }
        Ok(())
    }

    fn debit(&mut self, s: &mut State, key: &PublicKey, n: &Amount, c: &Config) -> Result<()> {
        self.each(s, |w, pending, epoch| {
            let mut a = pending_account(w, pending, key, epoch)
                .ok_or_else(|| anyhow::anyhow!("sender account does not exist"))?;
            ensure!(a.ordinary >= *n, "insufficient ordinary HASH");
            a.ordinary -= n;
            stage_account(pending, *key, a, c)
        })
    }

    fn credit(&mut self, s: &mut State, key: &PublicKey, n: &Amount, c: &Config) -> Result<Amount> {
        let epoch = s.epoch();
        let result = credit_world(&mut s.world, key, n, epoch, c, Some(&mut self.main))?;
        if let Some(w) = &mut s.alternative {
            let alternative = credit_world(w, key, n, epoch, c, Some(&mut self.pass))?;
            ensure!(
                alternative == result,
                "common account creation or credit differs between outcomes"
            );
        }
        Ok(result)
    }

    fn flush(self, s: &mut State, c: &Config) -> Result<()> {
        for (key, a) in self.main {
            s.world.put(key, a, c)?;
        }
        if let Some(w) = &mut s.alternative {
            for (key, a) in self.pass {
                w.put(key, a, c)?;
            }
        }
        Ok(())
    }
}

fn each_world(
    s: &mut State,
    mut f: impl FnMut(&mut World, Option<u64>) -> Result<()>,
) -> Result<()> {
    let epoch = s.epoch();
    f(&mut s.world, epoch)?;
    if let Some(w) = &mut s.alternative {
        f(w, epoch)?;
    }
    Ok(())
}
fn credit_world(
    w: &mut World,
    key: &PublicKey,
    n: &Amount,
    epoch: Option<u64>,
    c: &Config,
    pending: Option<&mut AccountWrites>,
) -> Result<Amount> {
    ensure!(crypto::valid_key(key), "invalid recipient key");
    let existing = pending.as_ref().map_or_else(
        || w.account(key, epoch),
        |pending| pending_account(w, pending, key, epoch),
    );
    let (mut a, net) = if let Some(a) = existing {
        (a, n.clone())
    } else {
        (
            Account {
                epoch: epoch.unwrap_or(0),
                ..Account::default()
            },
            n.clone(),
        )
    };
    a.ordinary += &net;
    if let Some(pending) = pending {
        stage_account(pending, *key, a, c)?;
    } else {
        w.put(*key, a, c)?;
    }
    Ok(net)
}
/// Ordinary credits create the same account in each possible world.
fn credit(s: &mut State, key: &PublicKey, n: &Amount, c: &Config) -> Result<Amount> {
    let epoch = s.epoch();
    let result = credit_world(&mut s.world, key, n, epoch, c, None)?;
    if let Some(w) = &mut s.alternative {
        let alternative = credit_world(w, key, n, epoch, c, None)?;
        ensure!(
            alternative == result,
            "common account creation or credit differs between outcomes"
        );
    }
    Ok(result)
}
fn context(s: &State, decision: Option<Hash>, outcome: Option<Outcome>) -> Result<Option<Outcome>> {
    match (s.decision_id(), decision, outcome) {
        (None, None, None) => Ok(None),
        (Some(active), Some(id), Some(o)) if active == id => Ok(Some(o)),
        _ => bail!("wrong decision context or outcome"),
    }
}
fn world_mut(s: &mut State, o: Option<Outcome>) -> &mut World {
    if o == Some(Outcome::Pass) {
        s.alternative.as_mut().expect("checked governance context")
    } else {
        &mut s.world
    }
}

/// Apply an atomic, conserving transaction. Charges are staged in Revenue;
/// BlockExecution tracks and settles the miner share of the whole fee.
pub fn apply_transaction(c: &Config, s: &mut State, t: &Transaction) -> Result<()> {
    let prepared = fees::PreparedTransaction::with_limit(t, c.transaction_bytes(&s.settings))?;
    crypto::verify(t)?;
    let quote = Some(prepared.quote(c, s)?);
    apply_prepared_transaction(c, s, &prepared, quote.as_ref())
}

fn apply_prepared_transaction(
    c: &Config,
    s: &mut State,
    prepared: &fees::PreparedTransaction<'_>,
    quote: Option<&fees::FeeQuote>,
) -> Result<()> {
    let mut next = s.clone();
    transaction_inner(c, &mut next, prepared, quote)?;
    *s = next;
    Ok(())
}
fn transaction_inner(
    c: &Config,
    s: &mut State,
    prepared: &fees::PreparedTransaction<'_>,
    quote: Option<&fees::FeeQuote>,
) -> Result<()> {
    let t = prepared.transaction();
    let b = &t.body;
    let quote = quote.expect("execution supplies a quote for its unchanged pre-state");
    ensure!(
        quote.minimum_fee <= b.fee,
        "signed fee is below the mandatory minimum"
    );
    let charged_fee = &b.fee;
    let operation = prepared.operation();
    let mut accounts = AccountChanges::default();
    ensure!(
        b.chain_id == s.chain_id,
        "transaction belongs to another network"
    );
    ensure!(b.expiry_height >= s.height, "expired transaction");
    c.check_amount(&b.fee)?;
    let sender = s
        .account(&b.sender, None)
        .ok_or_else(|| anyhow::anyhow!("sender account does not exist"))?;
    ensure!(
        sender.nonce == b.nonce && b.nonce < u64::MAX,
        "invalid or exhausted nonce"
    );
    if s.alternative.is_some() {
        let other = s
            .account(&b.sender, Some(Outcome::Pass))
            .ok_or_else(|| anyhow::anyhow!("missing PASS sender"))?;
        ensure!(other.nonce == sender.nonce, "common account state differs");
    }
    match operation {
        Operation::TransferExact { recipient, amount } => {
            c.check_amount(amount)?;
            ensure!(!amount.is_zero(), "zero transfer");
            accounts.debit(s, &b.sender, amount, c)?;
            let net = accounts.credit(s, recipient, amount, c)?;
            ensure!(
                net == *amount,
                "recipient credit differs from signed amount"
            );
        }
        Operation::Deposit {
            amount,
            min_shares,
            decision,
            outcome,
        } => {
            c.check_amount(amount)?;
            c.check_shares(min_shares)?;
            ensure!(!amount.is_zero(), "zero deposit");
            let o = context(s, *decision, *outcome)?;
            let epoch = s.epoch();
            let w = world_mut(s, o);
            let pending = accounts.world(o);
            let mut a = pending_account(w, pending, &b.sender, epoch).unwrap();
            let cash = &mut a.ordinary;
            ensure!(*cash >= *amount, "insufficient deposit balance");
            let new_r = &w.reserve + amount;
            c.check_amount(&new_r)?;
            let (n, mass) = if w.shares.is_zero() {
                let scale = &c.share_scale;
                (amount * scale, new_r.clone())
            } else {
                (
                    math::dynamic_deposit_total(&w.reserve, &w.shares, amount, &w.curve_mass)?,
                    math::deposit_mass(&w.reserve, &w.curve_mass, &new_r)?,
                )
            };
            c.check_amount(&mass)?;
            c.check_shares(&n)?;
            ensure!(n > w.shares, "deposit rounds to zero shares");
            let minted = &n - &w.shares;
            ensure!(minted >= *min_shares, "minimum minted shares not met");
            *cash -= amount;
            a.shares += &minted;
            w.reserve = new_r;
            w.curve_mass = mass;
            w.shares = n;
            stage_account(pending, b.sender, a, c)?;
        }
        Operation::Redeem {
            shares,
            min_received,
            decision,
            outcome,
        } => {
            c.check_shares(shares)?;
            c.check_amount(min_received)?;
            ensure!(!shares.is_zero(), "zero redemption");
            let o = context(s, *decision, *outcome)?;
            let epoch = s.epoch();
            let w = world_mut(s, o);
            let pending = accounts.world(o);
            let mut a = pending_account(w, pending, &b.sender, epoch).unwrap();
            ensure!(a.shares >= *shares, "insufficient shares");
            let m = math::dynamic_remaining_reserve(&w.reserve, &w.shares, shares, &w.curve_mass)?;
            let payout = &w.reserve - &m;
            ensure!(
                !payout.is_zero() && payout >= *min_received,
                "redemption output too small"
            );
            w.curve_mass = math::remaining_mass(&w.reserve, &w.curve_mass, &m)?;
            w.reserve = m;
            w.shares -= shares;
            a.shares -= shares;
            a.ordinary += payout;
            stage_account(pending, b.sender, a, c)?;
        }
        Operation::Propose {
            round,
            description,
            proposal,
            support,
        } => {
            ensure!(s.auction_round() == Some(*round), "wrong auction round");
            c.check_amount(support)?;
            ensure!(!support.is_zero(), "positive support required");
            match proposal {
                Proposal::Grant { payments } => {
                    c.validate_grant(payments)?;
                }
                Proposal::Parameter {
                    parameter,
                    old,
                    new,
                } => c.parameter_change(&s.frozen, *parameter, *old, *new)?,
            }
            let id = proposal_id(&s.chain_id, *round, description, proposal);
            ensure!(
                s.proposals.get(&id).is_none(),
                "proposal already registered"
            );
            s.proposals.insert(
                id.to_vec(),
                ProposalRecord {
                    round: *round,
                    description: *description,
                    action: proposal.clone(),
                    support: Amount::zero(),
                    refund_height: None,
                },
            );
            add_support(c, s, &mut accounts, *round, id, b.sender, support)?;
        }
        Operation::Support {
            round,
            proposal,
            amount,
        } => {
            ensure!(s.auction_round() == Some(*round), "wrong auction round");
            c.check_amount(amount)?;
            ensure!(!amount.is_zero(), "positive support required");
            add_support(c, s, &mut accounts, *round, *proposal, b.sender, amount)?;
        }
        Operation::Refund { round, proposal } => {
            let p = s
                .proposals
                .get(proposal)
                .ok_or_else(|| anyhow::anyhow!("unknown proposal"))?;
            ensure!(p.round == *round, "wrong proposal round");
            let r = s
                .rounds
                .get(&round.to_be_bytes())
                .ok_or_else(|| anyhow::anyhow!("unknown round"))?;
            let allowed = match &r.status {
                RoundStatus::Won(winner) => winner != proposal && s.height >= r.refund_height,
                RoundStatus::Timeout => s.height >= r.refund_height,
                RoundStatus::Open => p.refund_height.is_some_and(|h| s.height >= h),
            };
            ensure!(allowed, "support is not refundable");
            let key = support_key(*round, proposal, &b.sender);
            let record = s
                .supports
                .remove(&key)
                .ok_or_else(|| anyhow::anyhow!("no unclaimed support"))?;
            s.auction_escrow -= &record.amount;
            accounts.credit(s, &b.sender, &record.amount, c)?;
        }
    }
    // A redeem can pay from its resulting ordinary proceeds.
    // During governance the fee must be affordable in both worlds:
    // proceeds in one outcome cannot pay the other's fee.
    accounts.each(s, |w, pending, epoch| {
        let mut a = pending_account(w, pending, &b.sender, epoch).unwrap();
        ensure!(a.ordinary >= *charged_fee, "insufficient ordinary HASH");
        a.ordinary -= charged_fee;
        w.revenue += charged_fee;
        ensure!(a.nonce == b.nonce, "nonce mismatch between outcomes");
        a.nonce += 1;
        stage_account(pending, b.sender, a, c)
    })?;
    accounts.flush(s, c)
}
fn add_support(
    c: &Config,
    s: &mut State,
    accounts: &mut AccountChanges,
    round: u64,
    id: Hash,
    sender: PublicKey,
    n: &Amount,
) -> Result<()> {
    let mut p = s
        .proposals
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("unknown proposal"))?
        .clone();
    ensure!(
        p.round == round && p.refund_height.is_none(),
        "inactive proposal"
    );
    accounts.debit(s, &sender, n, c)?;
    if !p.support.is_zero() {
        s.ranking.remove(&rank_key(&p.support, &id));
    }
    p.support += n;
    c.check_amount(&p.support)?;
    s.ranking.insert(rank_key(&p.support, &id), id);
    s.proposals.insert(id.to_vec(), p);
    let key = support_key(round, &id, &sender);
    let mut old = s.supports.get(&key).cloned().unwrap_or(SupportRecord {
        round,
        proposal: id,
        sender,
        amount: Amount::zero(),
    });
    old.amount += n;
    c.check_amount(&old.amount)?;
    s.supports.insert(key, old);
    s.auction_escrow += n;
    Ok(())
}

/// Revenue replenishes only existing curve backing. At the flat limit, or
/// without outstanding stash, it remains spendable cash in the revenue buffer.
pub fn replenish_reserve(c: &Config, w: &mut World) -> Result<()> {
    ensure!(w.curve_mass >= w.reserve, "reserve exceeds curve mass");
    if w.shares.is_zero() {
        return Ok(());
    }
    let fill = w.revenue.clone().min(&w.curve_mass - &w.reserve);
    w.reserve += &fill;
    w.revenue -= fill;
    c.check_amount(&w.reserve)?;
    Ok(())
}

/// Spendable cash plus backing above the mandatory retained reserve.
pub fn grant_capacity(c: &Config, w: &World) -> Amount {
    &w.revenue
        + if w.reserve > c.reserve_min {
            &w.reserve - &c.reserve_min
        } else {
            Amount::zero()
        }
}

/// Set aside the whole grant at decision opening. Shares and curve mass remain
/// unchanged, so the marginal quote is identical across the two initial worlds.
pub fn grant_reserve(c: &Config, w: &mut World, amount: &Amount) -> Result<()> {
    c.check_amount(amount)?;
    ensure!(!amount.is_zero(), "empty grant");
    ensure!(w.grant_escrow.is_zero(), "grant already reserved");
    ensure!(
        *amount <= grant_capacity(c, w),
        "insufficient grant backing"
    );
    let cash = w.revenue.clone().min(amount.clone());
    let shortfall = amount - &cash;
    w.revenue -= cash;
    w.reserve -= shortfall;
    w.grant_escrow = amount.clone();
    Ok(())
}
fn new_budget(c: &Config, s: &mut State, epoch: u64, reserve: &Amount) {
    s.budgets.insert(
        epoch.to_be_bytes().to_vec(),
        Budget {
            // Disabled budgets retain exact reservation/spending history. Zero is
            // metadata for an absent cap, not a spendable or replenished allowance.
            allowance: if c.grant_budget_enabled() {
                reserve * Amount::from(c.budget_numerator) / Amount::from(c.budget_denominator)
            } else {
                Amount::zero()
            },
            reserved: Amount::zero(),
            spent: Amount::zero(),
        },
    );
    s.budget_epoch = epoch;
}

fn remaining_budget(c: &Config, s: &State) -> Option<Amount> {
    if !c.grant_budget_enabled() {
        return None;
    }
    Some(if s.budget_start.is_none() {
        &s.world.reserve * Amount::from(c.budget_numerator) / Amount::from(c.budget_denominator)
    } else {
        let b = s.budgets.get(&s.budget_epoch.to_be_bytes()).unwrap();
        &b.allowance - &b.reserved - &b.spent
    })
}
fn eligible(c: &Config, s: &State, p: &Proposal) -> Result<()> {
    ensure!(
        s.world.reserve >= c.reserve_min,
        "reserve below governance minimum"
    );
    match p {
        Proposal::Grant { payments } => {
            let amount = c.validate_grant(payments)?;
            ensure!(!amount.is_zero(), "empty grant");
            if c.grant_fraction_enabled() {
                ensure!(
                    amount
                        <= &s.world.reserve * Amount::from(c.grant_numerator)
                            / Amount::from(c.grant_denominator),
                    "grant fraction exceeded"
                );
            }
            ensure!(
                amount <= grant_capacity(c, &s.world),
                "insufficient grant backing"
            );
            if let Some(remaining) = remaining_budget(c, s) {
                ensure!(amount <= remaining, "grant budget exhausted");
            }
        }
        Proposal::Parameter {
            parameter,
            old,
            new,
        } => c.parameter_change(&s.frozen, *parameter, *old, *new)?,
    }
    Ok(())
}
fn rest(s: &mut State, pending: Option<(Parameter, u64)>) {
    s.phase = Phase::Rest(Rest {
        until: s.clock + s.frozen.rest,
        pending,
    });
}
fn timeout(s: &mut State, round: u64) {
    s.rounds.insert(
        round.to_be_bytes().to_vec(),
        RoundRecord {
            status: RoundStatus::Timeout,
            refund_height: s.height + 1,
        },
    );
    s.ranking = crate::tree::Map::new();
    rest(s, None);
}
fn auction(c: &Config, s: &mut State, parent_hash: &Hash) -> Result<()> {
    let Phase::Auction(mut a) = s.phase.clone() else {
        return Ok(());
    };
    if s.height >= a.replacement_height {
        let mut best = s.ranking.last().map(|(_, id)| *id);
        if let (Some(inc), Some(top)) = (a.leader, best) {
            let ip = s.proposals.get(&inc).unwrap();
            let tp = s.proposals.get(&top).unwrap();
            if ip.refund_height.is_none() && ip.support == tp.support {
                best = Some(inc);
            }
        }
        if best != a.leader {
            a.leader = best;
            a.lead_since = s.clock;
        }
    }
    s.phase = Phase::Auction(a.clone());
    if let Some(id) = a.leader
        && s.clock - a.lead_since >= s.frozen.lead
    {
        let p = s.proposals.get(&id).unwrap().clone();
        if eligible(c, s, &p.action).is_ok() {
            if s.budget_start.is_none() {
                s.budget_start = Some(s.clock);
                let r = s.world.reserve.clone();
                new_budget(c, s, 0, &r);
            }
            if let Proposal::Grant { payments } = &p.action {
                let amount = c.validate_grant(payments)?;
                let mut budget = s
                    .budgets
                    .get(&s.budget_epoch.to_be_bytes())
                    .unwrap()
                    .clone();
                budget.reserved += amount;
                s.budgets
                    .insert(s.budget_epoch.to_be_bytes().to_vec(), budget);
            }
            s.auction_escrow -= &p.support;
            s.world.revenue += &p.support;
            replenish_reserve(c, &mut s.world)?;
            s.rounds.insert(
                a.round.to_be_bytes().to_vec(),
                RoundRecord {
                    status: RoundStatus::Won(id),
                    refund_height: s.height + 1,
                },
            );
            s.ranking = crate::tree::Map::new();
            let pre = s.root();
            let decision_id = crypto::tagged_hash(
                "Hashstash/decision/v1",
                &codec::encode(&(s.chain_id, a.round, &p.action, s.height, parent_hash, pre)),
            );
            s.last_epoch = s
                .last_epoch
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("decision counter overflow"))?;
            let d = Decision {
                id: decision_id,
                epoch: s.last_epoch,
                round: a.round,
                proposal_id: id,
                proposal: p.action,
                started: s.clock,
                duration: s.frozen.duration,
                start_integral: s.world.price_integral.clone(),
                budget_epoch: s.budget_epoch,
            };
            let mut pass = s.world.clone();
            if let Proposal::Grant { payments } = &d.proposal {
                grant_reserve(c, &mut pass, &c.validate_grant(payments)?)?;
            }
            s.alternative = Some(pass);
            s.phase = Phase::Governance(d);
            return Ok(());
        } else {
            let mut cancelled = p;
            cancelled.refund_height = Some(s.height + 1);
            s.ranking.remove(&rank_key(&cancelled.support, &id));
            s.proposals.insert(id.to_vec(), cancelled);
            a.leader = None;
            a.replacement_height = s.height + 1;
            s.phase = Phase::Auction(a.clone());
        }
    }
    if s.clock - a.opened >= c.auction_timeout_for(&s.frozen)? {
        timeout(s, a.round);
    }
    Ok(())
}
/// Equal full-window durations cancel; compare the integrals with exact integers.
/// Equality at the threshold remains FAIL, including when both integrals are zero.
pub fn pass_beats_fail(pass: &Amount, fail: &Amount, margin_bps: u64) -> bool {
    pass * Amount::from(10_000u32) > fail * (Amount::from(10_000u32) + Amount::from(margin_bps))
}

#[cfg(test)]
mod margin_tests {
    use super::*;

    #[test]
    fn pass_margin_uses_exact_strict_comparison_and_all_u64_values() {
        assert!(!pass_beats_fail(&100u32.into(), &100u32.into(), 0));
        assert!(pass_beats_fail(&101u32.into(), &100u32.into(), 0));
        assert!(!pass_beats_fail(&105u32.into(), &100u32.into(), 500));
        assert!(pass_beats_fail(&106u32.into(), &100u32.into(), 500));
        assert!(!pass_beats_fail(&0u32.into(), &0u32.into(), u64::MAX));
        assert!(pass_beats_fail(&1u32.into(), &0u32.into(), u64::MAX));
        let fail = Amount::from(10_000u32) << 400usize;
        let threshold = (Amount::from(u64::MAX) + 10_000u32) << 400usize;
        assert!(!pass_beats_fail(&threshold, &fail, u64::MAX));
        assert!(pass_beats_fail(&(threshold + 1u32), &fail, u64::MAX));
    }

    fn resolution(margin: u64, pass: u32, fail: u32) -> (Config, State) {
        let mut c = Config::testnet();
        c.initial.pass_margin_bps = Some(margin);
        let mut state = State::genesis(&c);
        state.clock = 100;
        state.world.price_integral = fail.into();
        let mut alternative = state.world.clone();
        alternative.price_integral = pass.into();
        state.alternative = Some(alternative);
        state.phase = Phase::Governance(Decision {
            id: [1; 32],
            epoch: 1,
            round: 1,
            proposal_id: [2; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::PassMarginBps,
                old: margin,
                new: 20_000,
            },
            started: 0,
            duration: 100,
            start_integral: Amount::zero(),
            budget_epoch: 0,
        });
        (c, state)
    }

    #[test]
    fn resolution_uses_existing_margin_and_defers_the_proposed_margin() {
        for (margin, pass, expected) in [(0, 101, true), (500, 105, false), (500, 106, true)] {
            let (c, mut state) = resolution(margin, pass, 100);
            assert_eq!(resolve(&c, &mut state).unwrap(), expected);
            let Phase::Rest(rest) = state.phase else {
                panic!("rest expected")
            };
            assert_eq!(
                rest.pending,
                expected.then_some((Parameter::PassMarginBps, 20_000))
            );
            assert_eq!(state.settings.pass_margin_bps, Some(margin));
        }
    }

    #[test]
    fn resolution_clips_the_final_price_observation_to_its_deadline() {
        let (mut c, mut state) = resolution(0, 1500, 1450);
        c.quote_scale = 1u32.into();
        state.clock = 108;
        // These quotes apply for only the final seven seconds. Counting the
        // complete 15-second interval would incorrectly change FAIL to PASS.
        state.world.reserve = 90u32.into();
        state.world.curve_mass = 90u32.into();
        state.world.shares = 1u32.into();
        let pass = state.alternative.as_mut().unwrap();
        pass.reserve = 100u32.into();
        pass.curve_mass = 100u32.into();
        pass.shares = 1u32.into();
        assert_eq!(state.world.quote(&c), 90u32.into());
        assert_eq!(pass.quote(&c), 100u32.into());
        assert!(pass_beats_fail(
            &pass.price_integral,
            &state.world.price_integral,
            0
        ));
        assert!(!resolve(&c, &mut state).unwrap());
    }
}

fn resolve(c: &Config, s: &mut State) -> Result<bool> {
    let Phase::Governance(d) = s.phase.clone() else {
        bail!("resolution outside governance");
    };
    let pass = s.alternative.as_ref().unwrap();
    let excess = s.clock - (d.started + d.duration);
    let pass_score =
        &pass.price_integral - pass.quote(c) * Amount::from(excess) - &d.start_integral;
    let fail_score =
        &s.world.price_integral - s.world.quote(c) * Amount::from(excess) - &d.start_integral;
    let funded = match &d.proposal {
        Proposal::Grant { payments } => pass.grant_escrow == c.validate_grant(payments)?,
        Proposal::Parameter { .. } => true,
    };
    let margin = s.frozen.pass_margin_bps.unwrap_or(0);
    let won = funded && pass_beats_fail(&pass_score, &fail_score, margin);
    let alternative = s.alternative.take().unwrap();
    if won {
        s.world = alternative;
    }
    let mut pending = None;
    if let Proposal::Grant { payments } = &d.proposal {
        let amount = c.validate_grant(payments)?;
        let mut b = s
            .budgets
            .get(&d.budget_epoch.to_be_bytes())
            .unwrap()
            .clone();
        b.reserved -= &amount;
        if won {
            b.spent += amount;
        }
        s.budgets.insert(d.budget_epoch.to_be_bytes().to_vec(), b);
    }
    // Clear the conditional context before interpreting a paid recipient's settled balance.
    rest(s, None);
    if won {
        match d.proposal {
            Proposal::Grant { payments } => {
                ensure!(
                    s.world.grant_escrow == c.validate_grant(&payments)?,
                    "grant escrow mismatch"
                );
                s.world.grant_escrow = Amount::zero();
                for payment in payments {
                    credit(s, &payment.recipient, &payment.amount, c)?;
                }
            }
            Proposal::Parameter { parameter, new, .. } => pending = Some((parameter, new)),
        }
    }
    rest(s, pending);
    Ok(won)
}

/// Executes the state transition independently of nonce/extranonce/timestamp mining fields.
pub fn execute(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    subsidy: &Amount,
    transactions: &[Transaction],
) -> Result<State> {
    ensure!(crypto::valid_key(miner), "invalid miner key");
    ensure!(
        transactions.len() <= c.max_signatures,
        "signature limit exceeded"
    );
    let mut execution = prepare_block(c, parent, miner)?;
    for t in transactions {
        let prepared =
            fees::PreparedTransaction::with_limit(t, c.transaction_bytes(&parent.settings))?;
        crypto::verify(t)?;
        execution.apply_prepared_transaction(c, &prepared)?;
    }
    finish_block(c, parent, parent_hash, miner, subsidy, execution)
}

/// Completed time/phase transitions before the first user transaction.
/// A single prepared state can admit independent atomic transaction attempts.
pub(crate) struct BlockExecution {
    pub state: State,
    miner_fees: Amount,
    used_weight: u64,
    weight_limit: u64,
    miner: PublicKey,
    reward_accounts: Vec<PublicKey>,
}
impl BlockExecution {
    /// Charge accounting is updated only after an atomic transaction succeeds.
    pub(crate) fn apply_verified_transaction(&mut self, c: &Config, t: &Transaction) -> Result<()> {
        self.apply_prepared_transaction(
            c,
            &fees::PreparedTransaction::with_limit(t, c.transaction_bytes(&self.state.settings))?,
        )
    }

    fn apply_prepared_transaction(
        &mut self,
        c: &Config,
        prepared: &fees::PreparedTransaction<'_>,
    ) -> Result<()> {
        let quote = prepared.quote(c, &self.state)?;
        let creates = match prepared.operation() {
            Operation::TransferExact { recipient, .. } => Some(*recipient),
            _ => None,
        };
        let reserved_accounts = self
            .reward_accounts
            .iter()
            .filter(|key| self.state.account(key, None).is_none() && creates.as_ref() != Some(*key))
            .count() as u64;
        let used = self
            .used_weight
            .checked_add(quote.weight)
            .and_then(|n| n.checked_add(reserved_accounts * fees::ACCOUNT_WEIGHT))
            .ok_or_else(|| anyhow::anyhow!("block weight overflow"))?;
        ensure!(used <= self.weight_limit, "block exceeds weighted capacity");
        apply_prepared_transaction(c, &mut self.state, prepared, Some(&quote))?;
        self.used_weight += quote.weight;
        self.miner_fees += quote.miner_fee;
        Ok(())
    }
}
pub(crate) fn prepare_block(
    c: &Config,
    parent: &State,
    miner: &PublicKey,
) -> Result<BlockExecution> {
    c.validate_fee_percent(&parent.settings)?;
    c.validate_governance_settings(&parent.settings)?;
    ensure!(crypto::valid_key(miner), "invalid miner key");
    let reward_accounts = vec![*miner];
    let mut s = parent.clone();
    s.height = parent
        .height
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("height overflow"))?;
    ensure!(s.height <= c.max_height, "height range exhausted");
    let tau = c.progress_increment(&parent.settings);
    s.clock = parent
        .clock
        .checked_add(tau)
        .ok_or_else(|| anyhow::anyhow!("clock overflow"))?;
    s.world.price_integral += parent.world.quote(c) * Amount::from(tau);
    if let Some(w) = &mut s.alternative {
        w.price_integral += parent.alternative.as_ref().unwrap().quote(c) * Amount::from(tau);
    }
    if let Some(start) = s.budget_start {
        let epoch = (s.clock - start) / c.budget_period;
        // A short budget period can cross more than one epoch in one block.
        // Keep the history contiguous without granting carry-over spending.
        // With intervals <= 60 and periods > 1 this creates at most 30 entries.
        for next in s.budget_epoch + 1..=epoch {
            let reserve = if let Some(w) = &parent.alternative {
                parent.world.reserve.clone().min(w.reserve.clone())
            } else {
                parent.world.reserve.clone()
            };
            new_budget(c, &mut s, next, &reserve);
        }
    }
    if let Phase::Governance(d) = &parent.phase
        && s.clock >= d.started + d.duration
    {
        resolve(c, &mut s)?;
    }
    // Grant settlement writes were paid for when proposed. The miner's account
    // still consumes ordinary capacity if settlement happened to create it.
    let miner_fees = Amount::zero();
    let used_weight = if parent.account(miner, None).is_none() && s.account(miner, None).is_some() {
        fees::ACCOUNT_WEIGHT
    } else {
        0
    };
    let weight_limit = parent.settings.block_bytes;
    ensure!(
        used_weight
            + reward_accounts
                .iter()
                .filter(|key| s.account(key, None).is_none())
                .count() as u64
                * fees::ACCOUNT_WEIGHT
            <= weight_limit,
        "protocol account creation exceeds weighted capacity"
    );
    Ok(BlockExecution {
        state: s,
        miner_fees,
        used_weight,
        weight_limit,
        miner: *miner,
        reward_accounts,
    })
}

pub(crate) fn finish_block(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    subsidy: &Amount,
    execution: BlockExecution,
) -> Result<State> {
    ensure!(crypto::valid_key(miner), "invalid miner key");
    let BlockExecution {
        state: mut s,
        miner_fees,
        mut used_weight,
        weight_limit,
        miner: prepared_miner,
        reward_accounts: _,
    } = execution;
    ensure!(
        *miner == prepared_miner,
        "block payout changed during execution"
    );
    c.check_amount(subsidy)?;
    let accounts_before = s.world.accounts.len();
    credit(&mut s, miner, subsidy, c)?;
    used_weight += (s.world.accounts.len() - accounts_before) as u64 * fees::ACCOUNT_WEIGHT;
    ensure!(
        used_weight <= weight_limit,
        "block exceeds weighted capacity"
    );
    s.issued += subsidy;
    if !miner_fees.is_zero() {
        each_world(&mut s, |w, _| {
            ensure!(
                w.revenue >= miner_fees,
                "miner fee entitlement exceeds staged Revenue"
            );
            w.revenue -= &miner_fees;
            Ok(())
        })?;
        // The subsidy credit already created the miner, so this cannot charge again.
        credit(&mut s, miner, &miner_fees, c)?;
    }
    each_world(&mut s, |w, _| replenish_reserve(c, w))?;
    auction(c, &mut s, parent_hash)?;
    if let Phase::Rest(r) = &parent.phase
        && s.clock >= r.until
    {
        if let Some((p, v)) = r.pending {
            c.parameter_change(&parent.frozen, p, parent.frozen.get(p), v)?;
            s.settings.set(p, v);
        }
        c.validate_governance_settings(&s.settings)?;
        s.frozen = s.settings.clone();
        if !s.rounds.is_empty() {
            s.last_round = s
                .last_round
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("auction counter overflow"))?;
        }
        s.phase = Phase::Auction(Auction {
            round: s.last_round,
            opened: s.clock,
            leader: None,
            lead_since: s.clock,
            replacement_height: s.height + 1,
        });
        s.rounds.insert(
            s.last_round.to_be_bytes().to_vec(),
            RoundRecord {
                status: RoundStatus::Open,
                refund_height: 0,
            },
        );
        s.ranking = crate::tree::Map::new();
    }
    s.validate(c)?;
    Ok(s)
}

#[cfg(test)]
mod transaction_batch_tests {
    use super::*;

    const SECRET: [u8; 32] = [71; 32];
    #[test]
    fn preparation_bounds_before_decoding_and_reprices_against_current_accounts() {
        let c = Config::devnet();
        let mut s = funded(&c);
        let recipient = crypto::public_key(&[72; 32]).unwrap();
        let tx = payment(&c, &s, recipient, 10);
        let prepared =
            fees::PreparedTransaction::with_limit(&tx, c.transaction_bytes(&s.settings)).unwrap();
        let before = prepared.quote(&c, &s).unwrap();
        s.world.put(recipient, Account::default(), &c).unwrap();
        let after = prepared.quote(&c, &s).unwrap();
        assert_eq!(before.weight - after.weight, fees::ACCOUNT_WEIGHT);
        assert!(after.minimum_fee < before.minimum_fee);
        assert_eq!(after.fee, before.fee);

        let mut malformed = tx.clone();
        malformed.body.data = vec![255; c.transaction_bytes(&s.settings)];
        let error = fees::PreparedTransaction::with_limit(&malformed, 1)
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "transaction exceeds byte limit");
        assert!(
            fees::PreparedTransaction::with_limit(&malformed, c.transaction_bytes(&s.settings))
                .is_err()
        );
    }
    fn sender() -> PublicKey {
        crypto::public_key(&SECRET).unwrap()
    }
    fn configs() -> Vec<Config> {
        vec![Config::devnet(), Config::testnet(), Config::slow_testnet()]
    }
    fn funded(c: &Config) -> State {
        let mut s = State::genesis(c);
        s.world
            .put(
                sender(),
                Account {
                    ordinary: 10_000u32.into(),
                    ..Account::default()
                },
                c,
            )
            .unwrap();
        s.issued = 10_000u32.into();
        s
    }
    fn payment(_c: &Config, s: &State, recipient: PublicKey, amount: u32) -> Transaction {
        let op = Operation::TransferExact {
            recipient,
            amount: amount.into(),
        };
        crypto::sign(
            &TransactionBody {
                data: Vec::new(),
                chain_id: s.chain_id,
                sender: sender(),
                nonce: s.account(&sender(), None).unwrap().nonce,
                fee: 20u32.into(),
                expiry_height: 100,
                operation: op,
            },
            &SECRET,
        )
        .unwrap()
    }
    /// The former eager account-write sequence, used only as a root-equivalence
    /// oracle. Fee and nonce writes stay deliberately separate here.
    fn sequential_payment(c: &Config, s: &mut State, tx: &Transaction) {
        let fee = fees::quote(c, s, tx).unwrap().fee;
        let op = tx.body.operation.clone();
        let (recipient, gross) = match op {
            Operation::TransferExact {
                recipient, amount, ..
            } => (recipient, amount),
            _ => unreachable!(),
        };
        each_world(s, |w, epoch| {
            let mut a = w.account(&sender(), epoch).unwrap();
            a.ordinary -= &gross;
            w.put(sender(), a, c)
        })
        .unwrap();
        credit(s, &recipient, &gross, c).unwrap();
        each_world(s, |w, epoch| {
            let mut a = w.account(&sender(), epoch).unwrap();
            a.ordinary -= &fee;
            w.put(sender(), a, c)
        })
        .unwrap();
        each_world(s, |w, epoch| {
            w.revenue += &fee;
            let mut a = w.account(&sender(), epoch).unwrap();
            a.nonce += 1;
            w.put(sender(), a, c)
        })
        .unwrap();
    }

    #[test]
    fn batched_payments_preserve_eager_roots_across_presets_and_self_alias() {
        let recipient = crypto::public_key(&[72; 32]).unwrap();
        for c in configs() {
            for both in [false, true] {
                for to in [sender(), recipient] {
                    let mut s = funded(&c);
                    if both {
                        s.alternative = Some(s.world.clone());
                    }
                    // First payment creates the recipient; the second exercises
                    // an existing recipient and sender.
                    for _ in 0..2 {
                        let tx = payment(&c, &s, to, 10);
                        let mut expected = s.clone();
                        sequential_payment(&c, &mut expected, &tx);
                        apply_transaction(&c, &mut s, &tx).unwrap();
                        assert_eq!(s.root(), expected.root(), "protocol {}", c.protocol_version);
                        assert_eq!(codec::encode(&s), codec::encode(&expected));
                    }
                }
            }
        }
    }

    #[test]
    fn self_payment_still_requires_gross_funds_and_failed_other_world_is_atomic() {
        let c = Config::devnet();
        let mut s = funded(&c);
        let tx = payment(&c, &s, sender(), 10_001);
        let before = codec::encode(&s);
        assert!(apply_transaction(&c, &mut s, &tx).is_err());
        assert_eq!(codec::encode(&s), before);

        let mut pass = s.world.clone();
        let mut a = pass.account(&sender(), None).unwrap();
        a.ordinary = 10u32.into();
        pass.put(sender(), a, &c).unwrap();
        s.alternative = Some(pass);
        let tx = payment(&c, &s, crypto::public_key(&[72; 32]).unwrap(), 10);
        let before = codec::encode(&s);
        assert!(apply_transaction(&c, &mut s, &tx).is_err());
        assert_eq!(
            codec::encode(&s),
            before,
            "FAIL and new recipient writes must roll back when PASS cannot pay fee"
        );
    }

    #[test]
    fn staged_accounts_preserve_intermediate_overflow_checks_and_credits() {
        let c = Config::devnet();
        let mut pending = AccountWrites::new();
        let a = Account {
            ordinary: Amount::from(1u32) << c.money_bits as usize,
            ..Account::default()
        };
        assert!(stage_account(&mut pending, sender(), a, &c).is_err());
        assert!(pending.is_empty());

        let mut s = funded(&c);
        let mut expected = s.clone();
        credit(&mut expected, &sender(), &100u32.into(), &c).unwrap();
        let mut changes = AccountChanges::default();
        changes
            .credit(&mut s, &sender(), &100u32.into(), &c)
            .unwrap();
        changes.flush(&mut s, &c).unwrap();
        assert_eq!(codec::encode(&s), codec::encode(&expected));
        assert_eq!(
            s.world.account(&sender(), None).unwrap().shares,
            Amount::zero()
        );
        assert_eq!(s.world.account_cash, 10_100u32.into());
    }
}

#[cfg(test)]
mod reserve_model_tests {
    use super::*;
    const SECRET: [u8; 32] = [7; 32];
    fn owner() -> PublicKey {
        crypto::public_key(&SECRET).unwrap()
    }
    fn config() -> Config {
        let mut c = Config::testnet();
        c.initial.rest = 4 * c.initial.interval;
        c.validate().unwrap();
        c
    }
    fn advance(c: &Config, s: &State, subsidy: u32, txs: &[Transaction]) -> State {
        let next = execute(c, s, &s.root(), &owner(), &Amount::from(subsidy), txs).unwrap();
        next.audit(c).unwrap();
        next
    }
    fn funded_curve(c: &Config) -> State {
        let mut s = advance(c, &State::genesis(c), 1_000_000, &[]);
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 800_000u32.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
            0,
        );
        s = advance(c, &s, 0, &[deposit]);
        for _ in 0..40 {
            if matches!(s.phase, Phase::Auction(_)) {
                return s;
            }
            s = advance(c, &s, 0, &[]);
        }
        panic!("initial rest did not end");
    }
    fn signed(s: &State, operation: Operation, offset: u64) -> Transaction {
        let fee = match &operation {
            Operation::Propose {
                proposal: Proposal::Grant { payments },
                ..
            } => 1 + payments.len() as u32,
            _ => 1,
        };
        crypto::sign(
            &TransactionBody {
                data: Vec::new(),
                chain_id: s.chain_id,
                sender: owner(),
                nonce: s.account(&owner(), None).unwrap().nonce + offset,
                fee: fee.into(),
                expiry_height: s.height + 100,
                operation,
            },
            &SECRET,
        )
        .unwrap()
    }
    fn decision(c: &Config) -> State {
        let mut s = advance(c, &funded_curve(c), 100_000, &[]);
        let tx = signed(
            &s,
            Operation::Propose {
                round: s.auction_round().unwrap(),
                description: [19; 32],
                proposal: Proposal::Grant {
                    payments: vec![GrantPayment {
                        recipient: owner(),
                        amount: 10u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
            0,
        );
        s = advance(c, &s, 100_000, &[tx]);
        for _ in 0..16 {
            if matches!(s.phase, Phase::Governance(_)) {
                return s;
            }
            s = advance(c, &s, 100_000, &[]);
        }
        panic!("grant decision did not start");
    }
    #[test]
    fn immediate_deposit_sets_flat_price_and_keeps_other_hashes_spendable() {
        let c = config();
        let s = funded_curve(&c);
        assert_eq!(s.world.shares, Amount::from(800_000u32) * &c.share_scale);
        assert_eq!(s.world.shares, s.world.account_shares);
        assert_eq!(s.world.reserve, 800_000u32.into());
        assert_eq!(s.world.curve_mass, s.world.reserve);
        assert_eq!(
            s.account(&owner(), None).unwrap().ordinary,
            199_999u32.into()
        );
    }
    #[test]
    fn genesis_stash_redeems_completely_and_reopens_without_balance_conversion() {
        let c = config();
        let genesis = State::genesis(&c);
        genesis.audit(&c).unwrap();
        assert!(matches!(&genesis.phase, Phase::Rest(r) if r.until == c.initial.rest));
        assert!(genesis.rounds.is_empty() && genesis.budgets.is_empty());
        let mut s = advance(&c, &genesis, 1_000, &[]);
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 300u32.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
            0,
        );
        s = advance(&c, &s, 0, &[deposit]);
        assert!(matches!(s.phase, Phase::Rest(_)));
        assert_eq!(s.world.shares, Amount::from(300u32) * &c.share_scale);
        assert_eq!(s.account(&owner(), None).unwrap().ordinary, 699u32.into());
        let redeem = signed(
            &s,
            Operation::Redeem {
                shares: s.world.shares.clone(),
                min_received: 300u32.into(),
                decision: None,
                outcome: None,
            },
            0,
        );
        s = advance(&c, &s, 0, &[redeem]);
        assert!(
            s.world.reserve.is_zero() && s.world.shares.is_zero() && s.world.curve_mass.is_zero()
        );
        assert_eq!(s.account(&owner(), None).unwrap().ordinary, 998u32.into());
        for _ in 0..40 {
            s = advance(&c, &s, 10, &[]);
        }
        assert!(
            s.world.shares.is_zero(),
            "block rewards never convert automatically"
        );
        assert_eq!(s.account(&owner(), None).unwrap().ordinary, 1398u32.into());
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 30u32.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
            0,
        );
        s = advance(&c, &s, 0, &[deposit]);
        assert_eq!(s.world.shares, Amount::from(30u32) * &c.share_scale);
        assert_eq!(s.world.reserve, 30u32.into());
        assert_eq!(s.world.curve_mass, s.world.reserve);
    }
    #[test]
    fn initial_rest_defers_governance_but_not_trading_and_opens_round_zero() {
        let mut c = config();
        c.initial.rest = 2 * c.initial.interval + 1;
        c.validate().unwrap();
        let mut s = advance(&c, &State::genesis(&c), 1000, &[]);
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 300u32.into(),
                min_shares: 1u32.into(),
                decision: None,
                outcome: None,
            },
            0,
        );
        s = advance(&c, &s, 0, &[deposit]);
        assert!(matches!(s.phase, Phase::Rest(_)) && s.auction_round().is_none());
        let proposal = signed(
            &s,
            Operation::Propose {
                round: 0,
                description: [55; 32],
                proposal: Proposal::Grant {
                    payments: vec![GrantPayment {
                        recipient: owner(),
                        amount: 10u32.into(),
                    }],
                },
                support: 1u32.into(),
            },
            0,
        );
        assert!(
            execute(
                &c,
                &s,
                &s.root(),
                &owner(),
                &0u32.into(),
                std::slice::from_ref(&proposal)
            )
            .is_err()
        );
        s = advance(&c, &s, 0, &[]);
        assert_eq!(s.auction_round(), Some(0));
        assert_eq!(s.rounds.len(), 1);
        assert!(s.budget_start.is_none() && s.budgets.is_empty());
        s = advance(&c, &s, 0, &[proposal]);
        for _ in 0..10 {
            if s.decision_id().is_some() {
                break;
            }
            s = advance(&c, &s, 0, &[]);
        }
        assert!(s.decision_id().is_some());
        assert_eq!(s.budgets.len(), 1);
        assert_eq!(
            s.budgets.get(&0u64.to_be_bytes()).unwrap().allowance,
            75u32.into()
        );
    }
    #[test]
    fn revenue_waits_at_flat_then_restores_backing_without_changing_price_or_supply() {
        let c = config();
        let s = funded_curve(&c);
        let mut w = s.world.clone();
        w.revenue = 12u32.into();
        let original = w.clone();
        replenish_reserve(&c, &mut w).unwrap();
        assert_eq!(w.revenue, 12u32.into());
        assert_eq!(w.reserve, original.reserve);
        grant_reserve(&c, &mut w, &20u32.into()).unwrap();
        assert!(w.revenue.is_zero());
        assert_eq!(w.reserve, &original.reserve - 8u32);
        assert_eq!(w.quote(&c), original.quote(&c));
        assert_eq!(w.shares, original.shares);
        assert_eq!(w.accounts.root(), original.accounts.root());
        w.revenue = 10u32.into();
        replenish_reserve(&c, &mut w).unwrap();
        assert_eq!(w.revenue, 2u32.into());
        assert_eq!(w.reserve, original.reserve);
        assert_eq!(w.curve_mass, original.curve_mass);
        assert_eq!(w.shares, original.shares);
    }
    #[test]
    fn grant_is_fully_reserved_before_first_price_observation() {
        let c = config();
        let s = decision(&c);
        let pass = s.alternative.as_ref().unwrap();
        assert_eq!(pass.grant_escrow, 10u32.into());
        assert!(s.world.grant_escrow.is_zero());
        assert_eq!(pass.quote(&c), s.world.quote(&c));
        assert_eq!(pass.accounts.root(), s.world.accounts.root());
        assert_eq!(pass.shares, s.world.shares);
        assert!(pass.reserve < s.world.reserve);
        s.audit(&c).unwrap();
    }
    #[test]
    fn grant_can_never_exhaust_reserve_and_rejection_is_nonmutating() {
        let c = config();
        let s = funded_curve(&c);
        let mut w = s.world.clone();
        let before = w.root();
        assert!(grant_reserve(&c, &mut w, &s.world.reserve).is_err());
        assert_eq!(w.root(), before);
        let capacity = grant_capacity(&c, &w);
        grant_reserve(&c, &mut w, &capacity).unwrap();
        assert_eq!(w.reserve, c.reserve_min);
        assert_eq!(w.curve_mass, s.world.curve_mass);
    }
    #[test]
    fn pass_and_fail_discard_only_the_other_world_and_settle_reserved_grant_once() {
        let c = config();
        let start = decision(&c);
        let mut fail = start.clone();
        while matches!(fail.phase, Phase::Governance(_)) {
            fail = advance(&c, &fail, 0, &[]);
        }
        assert!(fail.world.grant_escrow.is_zero());
        assert!(
            fail.budgets
                .get(&0u64.to_be_bytes())
                .unwrap()
                .spent
                .is_zero()
        );
        let mut pass = start;
        let tx = signed(
            &pass,
            Operation::Deposit {
                amount: 100_000u32.into(),
                min_shares: 0u32.into(),
                decision: pass.decision_id(),
                outcome: Some(Outcome::Pass),
            },
            0,
        );
        pass = advance(&c, &pass, 0, &[tx]);
        while matches!(pass.phase, Phase::Governance(_)) {
            pass = advance(&c, &pass, 0, &[]);
        }
        assert_eq!(
            pass.budgets.get(&0u64.to_be_bytes()).unwrap().spent,
            10u32.into()
        );
        assert!(pass.world.grant_escrow.is_zero());
        assert_ne!(pass.root(), fail.root());
    }

    fn without_grant_caps() -> Config {
        let mut c = config();
        c.grant_numerator = 0;
        c.grant_denominator = 0;
        c.budget_numerator = 0;
        c.budget_denominator = 0;
        c.initial.lead = c.initial.interval;
        c.initial.duration = 3 * c.initial.interval;
        c.validate().unwrap();
        c
    }
    fn grant(amount: u32) -> Proposal {
        Proposal::Grant {
            payments: vec![GrantPayment {
                recipient: owner(),
                amount: amount.into(),
            }],
        }
    }
    fn replayed_step(c: &Config, s: &State, txs: &[Transaction]) -> State {
        let next = advance(c, s, 0, txs);
        // Replay from a serialized checkpoint, including epochs already beyond
        // the old allowance. Both execution and full audit must still agree.
        let bytes = codec::encode(s);
        let checkpoint: State = codec::decode(&bytes, bytes.len()).unwrap();
        checkpoint.audit(c).unwrap();
        let replay = advance(c, &checkpoint, 0, txs);
        assert_eq!(next.root(), replay.root());
        next
    }
    fn open_large_grant(c: &Config, mut s: State, amount: u32) -> State {
        while !matches!(s.phase, Phase::Auction(_)) {
            s = replayed_step(c, &s, &[]);
        }
        let tx = signed(
            &s,
            Operation::Propose {
                round: s.auction_round().unwrap(),
                description: [29; 32],
                proposal: grant(amount),
                support: 1u32.into(),
            },
            0,
        );
        s = replayed_step(c, &s, &[tx]);
        for _ in 0..8 {
            if matches!(s.phase, Phase::Governance(_)) {
                assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, amount.into());
                return s;
            }
            s = replayed_step(c, &s, &[]);
        }
        panic!("large backed grant did not open");
    }
    fn pass_large_grant(c: &Config, mut s: State) -> State {
        let tx = signed(
            &s,
            Operation::Deposit {
                amount: 100_000u32.into(),
                min_shares: 0u32.into(),
                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
            0,
        );
        s = replayed_step(c, &s, &[tx]);
        while matches!(s.phase, Phase::Governance(_)) {
            s = replayed_step(c, &s, &[]);
        }
        s
    }
    #[test]
    fn disabled_grant_caps_accept_large_funded_grants_and_replay_over_old_epoch_limit() {
        let c = without_grant_caps();
        let start = funded_curve(&c);
        let old_fraction = &start.world.reserve / 10u32;
        let old_budget = &start.world.reserve / 4u32;
        assert!(Amount::from(150_000u32) > old_fraction);
        let first = open_large_grant(&c, start, 150_000);
        assert!(remaining_budget(&c, &first).is_none());
        let first = pass_large_grant(&c, first);
        assert_eq!(
            first.budgets.get(&0u64.to_be_bytes()).unwrap().spent,
            150_000u32.into()
        );
        let second = open_large_grant(&c, first, 150_000);
        let b = second.budgets.get(&0u64.to_be_bytes()).unwrap();
        assert_eq!(&b.reserved + &b.spent, 300_000u32.into());
        assert!(&b.reserved + &b.spent > old_budget);
        let settled = pass_large_grant(&c, second);
        let b = settled.budgets.get(&0u64.to_be_bytes()).unwrap();
        assert!(b.allowance.is_zero() && b.reserved.is_zero());
        assert_eq!(b.spent, 300_000u32.into());
        assert!(settled.world.grant_escrow.is_zero());
        replayed_step(&c, &settled, &[]).audit(&c).unwrap();
    }
    #[test]
    fn disabled_budget_rollover_keeps_originating_reservation_and_spending() {
        let mut c = without_grant_caps();
        c.budget_period = 2;
        c.validate().unwrap();
        let start = open_large_grant(&c, funded_curve(&c), 200_000);
        let next = replayed_step(&c, &start, &[]);
        assert!(next.budget_epoch >= 7);
        assert_eq!(
            next.budgets.get(&0u64.to_be_bytes()).unwrap().reserved,
            200_000u32.into()
        );
        for (key, b) in next.budgets.iter() {
            assert!(b.allowance.is_zero());
            if key != 0u64.to_be_bytes() {
                assert!(b.reserved.is_zero() && b.spent.is_zero());
            }
        }
        let settled = pass_large_grant(&c, next);
        assert!(settled.budget_epoch > 7);
        let b = settled.budgets.get(&0u64.to_be_bytes()).unwrap();
        assert!(b.reserved.is_zero());
        assert_eq!(b.spent, 200_000u32.into());
        replayed_step(&c, &settled, &[]).audit(&c).unwrap();
    }
    #[test]
    fn disabled_grant_caps_keep_backing_and_accounting_invariants() {
        let c = without_grant_caps();
        let s = funded_curve(&c);
        let capacity = grant_capacity(&c, &s.world);
        let too_large = Proposal::Grant {
            payments: vec![GrantPayment {
                recipient: owner(),
                amount: &capacity + 1u32,
            }],
        };
        assert!(
            eligible(&c, &s, &too_large)
                .unwrap_err()
                .to_string()
                .contains("backing")
        );
        let mut world = s.world.clone();
        let before = world.root();
        assert!(grant_reserve(&c, &mut world, &(&capacity + 1u32)).is_err());
        assert_eq!(before, world.root());
        grant_reserve(&c, &mut world, &capacity).unwrap();
        assert_eq!(world.reserve, c.reserve_min);

        let opened = open_large_grant(&c, s, 200_000);
        for (allowance, reserved, spent) in [
            (Amount::from(1u32), Amount::from(200_000u32), Amount::zero()),
            (Amount::zero(), Amount::from(199_999u32), Amount::zero()),
            (
                Amount::zero(),
                Amount::from(200_000u32),
                Amount::from(1u32) << c.money_bits as usize,
            ),
        ] {
            let mut corrupt = opened.clone();
            corrupt.budgets.insert(
                0u64.to_be_bytes().to_vec(),
                Budget {
                    allowance,
                    reserved,
                    spent,
                },
            );
            assert!(corrupt.audit(&c).is_err());
        }
    }
    #[test]
    fn grant_caps_remain_independent_and_legacy_limits_still_reject() {
        let c = config();
        let s = funded_curve(&c);
        assert!(eligible(&c, &s, &grant(80_000)).is_ok());
        assert!(
            eligible(&c, &s, &grant(80_001))
                .unwrap_err()
                .to_string()
                .contains("fraction")
        );
        let mut budget_disabled = c.clone();
        budget_disabled.budget_numerator = 0;
        budget_disabled.budget_denominator = 0;
        assert!(eligible(&budget_disabled, &s, &grant(80_001)).is_err());
        let mut fraction_disabled = c.clone();
        fraction_disabled.grant_numerator = 0;
        fraction_disabled.grant_denominator = 0;
        assert!(eligible(&fraction_disabled, &s, &grant(200_000)).is_ok());
        assert!(
            eligible(&fraction_disabled, &s, &grant(200_001))
                .unwrap_err()
                .to_string()
                .contains("budget")
        );
        let mut accounted = s;
        accounted.budget_start = Some(accounted.clock);
        new_budget(&fraction_disabled, &mut accounted, 0, &800_000u32.into());
        let mut b = accounted.budgets.get(&0u64.to_be_bytes()).unwrap().clone();
        b.spent = 150_000u32.into();
        accounted.budgets.insert(0u64.to_be_bytes().to_vec(), b);
        assert!(eligible(&fraction_disabled, &accounted, &grant(50_000)).is_ok());
        assert!(eligible(&fraction_disabled, &accounted, &grant(50_001)).is_err());
    }
}
