use crate::{batch, codec, config::Config, crypto, fees, math, state::*, types::*};
use anyhow::{Context, Result, bail, ensure};
use num_traits::Zero;
use std::collections::BTreeMap;

type AccountWrites = BTreeMap<PublicKey, Account>;

#[derive(Clone, Debug)]
struct PendingTrade {
    id: Hash,
    sender: PublicKey,
    outcome: Option<Outcome>,
    amount: Amount,
    is_buy: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradeFill {
    pub transaction_id: Hash,
    pub outcome: Option<Outcome>,
    pub input_requested: Amount,
    pub input_filled: Amount,
    pub output: Amount,
    pub input_unfilled: Amount,
    pub is_buy: bool,
}

type Spending = BTreeMap<(PublicKey, bool), (Amount, Amount)>;
type Reservations = Vec<((PublicKey, bool), (Amount, Amount))>;

/// Only opening funds can be committed. This prevents a miner from changing
/// the batch by moving a transfer, refund, or redemption ahead of another order.
fn reserve_inputs(opening: &State, spent: &Spending, t: &Transaction) -> Result<Reservations> {
    let mut reservations = Vec::new();
    for pass in [false, true] {
        if pass && opening.alternative.is_none() {
            continue;
        }
        let outcome = pass.then_some(Outcome::Pass);
        let a = opening
            .account(&t.body.sender, outcome)
            .context("sender must exist at block opening")?;
        let key = (t.body.sender, pass);
        let (mut cash, mut shares) = spent.get(&key).cloned().unwrap_or_default();
        cash += &t.body.fee;
        match &t.body.operation {
            Operation::TransferExact { amount, .. } | Operation::Support { amount, .. } => {
                cash += amount
            }
            Operation::Propose { support, .. } => cash += support,
            Operation::Deposit {
                amount, outcome, ..
            } if (*outcome == Some(Outcome::Pass)) == pass => cash += amount,
            Operation::Redeem {
                shares: n, outcome, ..
            } if (*outcome == Some(Outcome::Pass)) == pass => shares += n,
            _ => {}
        }
        ensure!(
            cash <= a.ordinary,
            "insufficient opening HASH for inputs and fees"
        );
        ensure!(shares <= a.shares, "insufficient opening Stash for orders");
        reservations.push((key, (cash, shares)));
    }
    Ok(reservations)
}

/// Each world clears once. Account credits are accumulated and each affected
/// leaf is updated once, without recalculating all accounts for each order.
fn settle_trades(
    c: &Config,
    opening: &State,
    s: &mut State,
    trades: &[PendingTrade],
) -> Result<Vec<TradeFill>> {
    let mut fills = Vec::new();
    for pass in [false, true] {
        let initial = if pass {
            let Some(w) = opening.alternative.as_ref() else {
                continue;
            };
            w
        } else {
            &opening.world
        };
        let orders: Vec<_> = trades
            .iter()
            .filter(|t| (t.outcome == Some(Outcome::Pass)) == pass)
            .collect();
        if orders.is_empty() {
            continue;
        }
        let buys: Vec<_> = orders
            .iter()
            .filter(|t| t.is_buy)
            .map(|t| batch::Order {
                id: t.id,
                amount: t.amount.clone(),
            })
            .collect();
        let sells: Vec<_> = orders
            .iter()
            .filter(|t| !t.is_buy)
            .map(|t| batch::Order {
                id: t.id,
                amount: t.amount.clone(),
            })
            .collect();
        let clearing = batch::clear(
            c,
            initial,
            &buys,
            &sells,
            opening.settings.max_price_change_bps,
        )?;
        let allocations: BTreeMap<_, _> = clearing
            .buys
            .iter()
            .chain(&clearing.sells)
            .map(|f| (f.id, f))
            .collect();
        let epoch = s.epoch();
        let w = if pass {
            s.alternative.as_mut().unwrap()
        } else {
            &mut s.world
        };
        let mut accounts = AccountWrites::new();
        for t in orders {
            let f = allocations.get(&t.id).context("missing batch allocation")?;
            ensure!(f.input <= t.amount, "batch overfilled input");
            let unfilled = &t.amount - &f.input;
            let a = accounts
                .entry(t.sender)
                .or_insert_with(|| w.account(&t.sender, epoch).unwrap());
            if t.is_buy {
                a.ordinary += &unfilled;
                a.shares += &f.output;
            } else {
                a.shares += &unfilled;
                a.ordinary += &f.output;
            }
            fills.push(TradeFill {
                transaction_id: t.id,
                outcome: t.outcome,
                input_requested: t.amount.clone(),
                input_filled: f.input.clone(),
                output: f.output.clone(),
                input_unfilled: unfilled,
                is_buy: t.is_buy,
            });
        }
        w.reserve = clearing.reserve;
        w.shares = clearing.shares;
        w.curve_mass = clearing.curve_mass;
        for (key, a) in accounts {
            w.put(key, a, c)?;
        }
    }
    Ok(fills)
}

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

/// Simulate one atomic transaction as its own batch. Repeated calls are not a
/// block: use execute/BlockExecution to share opening funds and clear once.
/// Charges are staged in Revenue; block execution settles the miner fee share.
/// This economic simulation has no header history: Chain additionally validates
/// the signed anchor's ancestry and lifetime before admitting a transaction.
pub fn apply_transaction(c: &Config, s: &mut State, t: &Transaction) -> Result<()> {
    let prepared = fees::PreparedTransaction::with_limit(t, c.transaction_bytes(&s.settings))?;
    crypto::verify(t)?;
    let quote = Some(prepared.quote(c, s)?);
    let opening = s.clone();
    let mut next = s.clone();
    let mut trades = Vec::new();
    reserve_inputs(&opening, &BTreeMap::new(), t)?;
    apply_prepared_transaction(c, &mut next, &prepared, quote.as_ref(), &mut trades)?;
    settle_trades(c, &opening, &mut next, &trades)?;
    *s = next;
    Ok(())
}

fn apply_prepared_transaction(
    c: &Config,
    s: &mut State,
    prepared: &fees::PreparedTransaction<'_>,
    quote: Option<&fees::FeeQuote>,
    trades: &mut Vec<PendingTrade>,
) -> Result<()> {
    let mut next = s.clone();
    let mut added = Vec::new();
    transaction_inner(c, &mut next, prepared, quote, &mut added)?;
    trades.extend(added);
    *s = next;
    Ok(())
}
fn transaction_inner(
    c: &Config,
    s: &mut State,
    prepared: &fees::PreparedTransaction<'_>,
    quote: Option<&fees::FeeQuote>,
    trades: &mut Vec<PendingTrade>,
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
    ensure!(b.expiry_blocks > 0, "transaction lifetime must be positive");
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
            decision,
            outcome,
        } => {
            c.check_amount(amount)?;
            ensure!(!amount.is_zero(), "zero deposit");
            let o = context(s, *decision, *outcome)?;
            let epoch = s.epoch();
            let w = world_mut(s, o);
            let pending = accounts.world(o);
            let mut a = pending_account(w, pending, &b.sender, epoch).unwrap();
            ensure!(a.ordinary >= *amount, "insufficient deposit balance");
            a.ordinary -= amount;
            stage_account(pending, b.sender, a, c)?;
            trades.push(PendingTrade {
                id: codec::transaction_id(t),
                sender: b.sender,
                outcome: o,
                amount: amount.clone(),
                is_buy: true,
            });
        }
        Operation::Redeem {
            shares,
            decision,
            outcome,
        } => {
            c.check_shares(shares)?;
            ensure!(!shares.is_zero(), "zero redemption");
            let o = context(s, *decision, *outcome)?;
            let epoch = s.epoch();
            let w = world_mut(s, o);
            let pending = accounts.world(o);
            let mut a = pending_account(w, pending, &b.sender, epoch).unwrap();
            ensure!(a.shares >= *shares, "insufficient shares");
            a.shares -= shares;
            stage_account(pending, b.sender, a, c)?;
            trades.push(PendingTrade {
                id: codec::transaction_id(t),
                sender: b.sender,
                outcome: o,
                amount: shares.clone(),
                is_buy: false,
            });
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
                } => c.parameter_change_at(&s.frozen, *parameter, *old, *new, s.clock)?,
            }
            let id = proposal_id(&s.chain_id, *round, &b.sender, description, proposal);
            ensure!(
                s.proposals.get(&id).is_none(),
                "proposal already registered"
            );
            s.proposals.insert(
                id.to_vec(),
                ProposalRecord {
                    round: *round,
                    proposer: b.sender,
                    description: *description,
                    action: proposal.clone().into(),
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
    // Fees are prepaid in both worlds; unsettled trade proceeds cannot pay them.
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

/// Cash available for a grant. Outstanding Stash needs nonzero backing for
/// its redemption and price arithmetic, so one raw unit remains while shares exist.
pub fn grant_capacity(w: &World) -> Amount {
    &w.revenue
        + if w.shares.is_zero() {
            w.reserve.clone()
        } else if w.reserve > Amount::from(1u32) {
            &w.reserve - 1u32
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
    ensure!(*amount <= grant_capacity(w), "insufficient grant backing");
    let cash = w.revenue.clone().min(amount.clone());
    let shortfall = amount - &cash;
    w.revenue -= cash;
    w.reserve -= shortfall;
    w.grant_escrow = amount.clone();
    Ok(())
}
fn eligible(c: &Config, s: &State, p: &Proposal) -> Result<()> {
    match p {
        Proposal::Grant { payments } => {
            let amount = c.validate_grant(payments)?;
            ensure!(!amount.is_zero(), "empty grant");
            ensure!(
                amount <= grant_capacity(&s.world),
                "insufficient grant backing"
            );
        }
        Proposal::Parameter {
            parameter,
            old,
            new,
        } => {
            let resolution = rounded_deadline(
                s.clock,
                s.frozen
                    .decision_blocks
                    .checked_mul(s.frozen.interval)
                    .context("decision schedule overflow")?,
                s.frozen.interval,
            )?;
            let activation = rounded_deadline(resolution, s.frozen.rest, s.frozen.interval)?;
            c.parameter_change_at(&s.frozen, *parameter, *old, *new, activation)?;
        }
    }
    Ok(())
}
pub(crate) fn rounded_deadline(clock: u64, duration: u64, interval: u64) -> Result<u64> {
    ensure!(interval > 0, "zero schedule interval");
    let elapsed = duration
        .div_ceil(interval)
        .checked_mul(interval)
        .context("rounded schedule overflow")?;
    clock
        .checked_add(elapsed)
        .context("schedule deadline overflow")
}
fn rest(s: &mut State, pending: Option<(Parameter, u64)>) -> Result<()> {
    s.phase = Phase::Rest(Rest {
        until: s
            .clock
            .checked_add(s.frozen.rest)
            .context("rest deadline overflow")?,
        pending,
    });
    Ok(())
}
fn timeout(s: &mut State, round: u64) -> Result<()> {
    s.rounds.insert(
        round.to_be_bytes().to_vec(),
        RoundRecord {
            status: RoundStatus::Timeout,
            refund_height: s.height + 1,
        },
    );
    s.ranking = crate::tree::Map::new();
    rest(s, None)
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
        let schedule_valid = rounded_deadline(
            s.clock,
            s.frozen
                .decision_blocks
                .checked_mul(s.frozen.interval)
                .context("decision schedule overflow")?,
            s.frozen.interval,
        )
        .and_then(|resolution| rounded_deadline(resolution, s.frozen.rest, s.frozen.interval));
        if schedule_valid.is_ok()
            && s.height.checked_add(s.frozen.decision_blocks).is_some()
            && eligible(c, s, &p.action).is_ok()
        {
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
                "Hashstash/decision",
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
                started_height: s.height,
                blocks: s.frozen.decision_blocks,
                leading_blocks: 0,
            };
            let mut pass = s.world.clone();
            if let Proposal::Grant { payments } = &*d.proposal {
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
        timeout(s, a.round)?;
    }
    Ok(())
}
/// Compare actual marginal prices M/S, independently of display precision.
/// An empty world's price is zero; equality never awards a leading block.
pub fn pass_beats_fail(pass: &World, fail: &World, margin_bps: u64) -> bool {
    if pass.shares.is_zero() {
        return false;
    }
    if fail.shares.is_zero() {
        return !pass.curve_mass.is_zero();
    }
    &pass.curve_mass * &fail.shares * 10_000u32
        > &fail.curve_mass * &pass.shares * (Amount::from(10_000u32) + Amount::from(margin_bps))
}

#[cfg(test)]
mod margin_tests {
    use super::*;

    fn world(mass: Amount, shares: Amount) -> World {
        World {
            reserve: mass.clone(),
            curve_mass: mass,
            shares,
            ..World::default()
        }
    }

    #[test]
    fn pass_margin_uses_exact_strict_comparison_and_all_u64_values() {
        let fail = world(100u32.into(), 1u32.into());
        assert!(!pass_beats_fail(&fail, &fail, 0));
        assert!(pass_beats_fail(
            &world(101u32.into(), 1u32.into()),
            &fail,
            0
        ));
        assert!(!pass_beats_fail(
            &world(105u32.into(), 1u32.into()),
            &fail,
            500
        ));
        assert!(pass_beats_fail(
            &world(106u32.into(), 1u32.into()),
            &fail,
            500
        ));
        assert!(!pass_beats_fail(
            &World::default(),
            &World::default(),
            u64::MAX
        ));
        assert!(pass_beats_fail(&fail, &World::default(), u64::MAX));
        assert!(!pass_beats_fail(&World::default(), &fail, 0));
        let fail = world(
            Amount::from(10_000u32) << 400usize,
            Amount::from(1u32) << 511usize,
        );
        let threshold = (Amount::from(u64::MAX) + 10_000u32) << 400usize;
        let at_threshold = world(threshold.clone(), fail.shares.clone());
        assert!(!pass_beats_fail(&at_threshold, &fail, u64::MAX));
        assert!(pass_beats_fail(
            &world(threshold + 1u32, fail.shares.clone()),
            &fail,
            u64::MAX
        ));
    }

    #[test]
    fn displayed_zero_prices_do_not_hide_strict_leads_or_margin_ties() {
        let c = Config::devnet();
        let supply = Amount::from(1u32) << 500usize;
        let fail = world(100u32.into(), supply.clone());
        let equal = world(200u32.into(), &supply * 2u32);
        let threshold = world(210u32.into(), &supply * 2u32);
        let lead = world(211u32.into(), &supply * 2u32);
        for w in [&fail, &equal, &threshold, &lead] {
            assert!(w.quote(&c).is_zero());
        }
        assert!(!pass_beats_fail(&equal, &fail, 0));
        assert!(pass_beats_fail(&threshold, &fail, 0));
        assert!(!pass_beats_fail(&threshold, &fail, 500));
        assert!(pass_beats_fail(&lead, &fail, 500));
    }
}

fn resolve(c: &Config, s: &mut State) -> Result<bool> {
    let Phase::Governance(d) = s.phase.clone() else {
        bail!("resolution outside governance");
    };
    let pass = s.alternative.as_ref().unwrap();
    ensure!(
        s.height.checked_sub(d.started_height) == Some(d.blocks),
        "decision has not ended"
    );
    let funded = match &*d.proposal {
        Proposal::Grant { payments } => pass.grant_escrow == c.validate_grant(payments)?,
        Proposal::Parameter { .. } => true,
    };
    let won = funded && d.leading_blocks > d.blocks / 2;
    let alternative = s.alternative.take().unwrap();
    if won {
        s.world = alternative;
    }
    let mut pending = None;
    // Clear the conditional context before interpreting a paid recipient's settled balance.
    rest(s, None)?;
    if won {
        match &*d.proposal {
            Proposal::Grant { payments } => {
                ensure!(
                    s.world.grant_escrow == c.validate_grant(payments)?,
                    "grant escrow mismatch"
                );
                s.world.grant_escrow = Amount::zero();
                for payment in payments {
                    credit(s, &payment.recipient, &payment.amount, c)?;
                }
            }
            Proposal::Parameter { parameter, new, .. } => pending = Some((*parameter, *new)),
        }
    }
    rest(s, pending)?;
    Ok(won)
}

/// Execute economic state transitions without a header-history context.
/// Chain admission, templates and replay additionally validate every signed
/// anchor's ancestry and lifetime; this helper alone is not block validation.
/// block_work is raw expected hashes, rounded down to whole monetary atoms.
pub fn execute(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    block_work: &Amount,
    transactions: &[Transaction],
) -> Result<State> {
    Ok(execute_with_fills(c, parent, parent_hash, miner, block_work, transactions)?.0)
}

/// Replay economic transitions once and return actual batch fills.
/// Like execute, this has no header-history context; Chain validates signed
/// anchor ancestry and lifetime before block admission or historical replay.
pub fn execute_with_fills(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    block_work: &Amount,
    transactions: &[Transaction],
) -> Result<(State, Vec<TradeFill>)> {
    ensure!(crypto::valid_key(miner), "invalid miner key");
    ensure!(
        transactions.len() <= c.max_signatures,
        "signature limit exceeded"
    );
    let mut execution = prepare_block(c, parent, miner, block_work)?;
    for t in transactions {
        let prepared =
            fees::PreparedTransaction::with_limit(t, c.transaction_bytes(&parent.settings))?;
        crypto::verify(t)?;
        execution.apply_prepared_transaction(c, &prepared)?;
    }
    finish_block_with_fills(c, parent, parent_hash, miner, block_work, execution)
}

/// Completed time/phase transitions before the first user transaction.
/// A single prepared state can admit independent atomic transaction attempts.
pub(crate) struct BlockExecution {
    pub state: State,
    opening: State,
    spent: Spending,
    trades: Vec<PendingTrade>,
    miner_fees: Amount,
    used_weight: u64,
    weight_limit: u64,
    miner: PublicKey,
    subsidy_expected: bool,
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
        let reward_expected =
            self.subsidy_expected || !self.miner_fees.is_zero() || !quote.miner_fee.is_zero();
        let reserved_accounts = u64::from(
            reward_expected
                && self.state.account(&self.miner, None).is_none()
                && creates != Some(self.miner),
        );
        let used = self
            .used_weight
            .checked_add(quote.weight)
            .and_then(|n| n.checked_add(reserved_accounts * fees::ACCOUNT_WEIGHT))
            .ok_or_else(|| anyhow::anyhow!("block weight overflow"))?;
        ensure!(used <= self.weight_limit, "block exceeds weighted capacity");
        let spent = reserve_inputs(&self.opening, &self.spent, prepared.transaction())?;
        apply_prepared_transaction(c, &mut self.state, prepared, Some(&quote), &mut self.trades)?;
        self.spent.extend(spent);
        self.used_weight += quote.weight;
        self.miner_fees += quote.miner_fee;
        Ok(())
    }
}
pub(crate) fn prepare_block(
    c: &Config,
    parent: &State,
    miner: &PublicKey,
    block_work: &Amount,
) -> Result<BlockExecution> {
    c.validate_fee_percent(&parent.settings)?;
    c.validate_governance_settings(&parent.settings)?;
    ensure!(crypto::valid_key(miner), "invalid miner key");
    let subsidy = math::issuance(block_work, &c.work_per_atom()?)?;
    c.check_amount(&subsidy)?;
    let subsidy_expected = !subsidy.is_zero();
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
    if let Phase::Governance(d) = &mut s.phase {
        let pass = parent.alternative.as_ref().context("missing PASS world")?;
        if pass_beats_fail(
            pass,
            &parent.world,
            parent.frozen.pass_margin_bps.unwrap_or(0),
        ) {
            d.leading_blocks = d
                .leading_blocks
                .checked_add(1)
                .context("leading block overflow")?;
        }
        if s.height.checked_sub(d.started_height) == Some(d.blocks) {
            resolve(c, &mut s)?;
        }
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
            + u64::from(subsidy_expected && s.account(miner, None).is_none())
                * fees::ACCOUNT_WEIGHT
            <= weight_limit,
        "protocol account creation exceeds weighted capacity"
    );
    Ok(BlockExecution {
        opening: s.clone(),
        state: s,
        spent: BTreeMap::new(),
        trades: Vec::new(),
        miner_fees,
        used_weight,
        weight_limit,
        miner: *miner,
        subsidy_expected,
    })
}

pub(crate) fn finish_block(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    block_work: &Amount,
    execution: BlockExecution,
) -> Result<State> {
    Ok(finish_block_with_fills(c, parent, parent_hash, miner, block_work, execution)?.0)
}

fn finish_block_with_fills(
    c: &Config,
    parent: &State,
    parent_hash: &Hash,
    miner: &PublicKey,
    block_work: &Amount,
    execution: BlockExecution,
) -> Result<(State, Vec<TradeFill>)> {
    ensure!(crypto::valid_key(miner), "invalid miner key");
    let BlockExecution {
        state: mut s,
        opening,
        spent: _,
        trades,
        miner_fees,
        mut used_weight,
        weight_limit,
        miner: prepared_miner,
        subsidy_expected: _,
    } = execution;
    ensure!(
        *miner == prepared_miner,
        "block payout changed during execution"
    );
    let fills = settle_trades(c, &opening, &mut s, &trades)?;
    let subsidy = math::issuance(block_work, &c.work_per_atom()?)?;
    c.check_amount(&subsidy)?;
    s.issued += &subsidy;
    if !miner_fees.is_zero() {
        each_world(&mut s, |w, _| {
            ensure!(
                w.revenue >= miner_fees,
                "miner fee entitlement exceeds staged Revenue"
            );
            w.revenue -= &miner_fees;
            Ok(())
        })?;
    }
    let reward = subsidy + miner_fees;
    if !reward.is_zero() {
        let accounts_before = s.world.accounts.len();
        credit(&mut s, miner, &reward, c)?;
        used_weight += (s.world.accounts.len() - accounts_before) as u64 * fees::ACCOUNT_WEIGHT;
    }
    ensure!(
        used_weight <= weight_limit,
        "block exceeds weighted capacity"
    );
    each_world(&mut s, |w, _| replenish_reserve(c, w))?;
    auction(c, &mut s, parent_hash)?;
    if let Phase::Rest(r) = &s.phase
        && s.clock >= r.until
    {
        if let Some((p, v)) = r.pending {
            c.parameter_change_at(&parent.frozen, p, parent.frozen.get(p), v, s.clock)?;
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
    Ok((s, fills))
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
                sender: sender(),
                nonce: s.account(&sender(), None).unwrap().nonce,
                fee: 20u32.into(),
                anchor: [0; 32],
                expiry_blocks: 100,
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
                        assert_eq!(s.root(), expected.root());
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
                sender: owner(),
                nonce: s.account(&owner(), None).unwrap().nonce + offset,
                fee: fee.into(),
                anchor: [0; 32],
                expiry_blocks: s.height + 100,
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
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
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
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn genesis_stash_redeems_completely_and_reopens_without_balance_conversion() {
        let mut c = config();
        c.initial.max_price_change_bps = 10_000;
        let genesis = State::genesis(&c);
        genesis.audit(&c).unwrap();
        assert!(matches!(&genesis.phase, Phase::Rest(r) if r.until == c.initial.rest));
        assert!(genesis.rounds.is_empty());
        let mut s = advance(&c, &genesis, 1_000, &[]);
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 300u32.into(),

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
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn initial_rest_defers_governance_but_not_trading_and_opens_round_zero() {
        let mut c = config();
        c.initial.rest = 2 * c.initial.interval + 1;
        c.validate().unwrap();
        let mut s = advance(&c, &State::genesis(&c), 1000, &[]);
        let deposit = signed(
            &s,
            Operation::Deposit {
                amount: 300u32.into(),

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
        s = advance(&c, &s, 0, &[proposal]);
        for _ in 0..10 {
            if s.decision_id().is_some() {
                break;
            }
            s = advance(&c, &s, 0, &[]);
        }
        assert!(s.decision_id().is_some());
        assert_eq!(s.alternative.as_ref().unwrap().grant_escrow, 10u32.into());
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
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
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
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
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn grant_can_never_exhaust_reserve_and_rejection_is_nonmutating() {
        let c = config();
        let s = funded_curve(&c);
        let mut w = s.world.clone();
        let before = w.root();
        let capacity = grant_capacity(&w);
        assert!(grant_reserve(&c, &mut w, &(&capacity + 1u32)).is_err());
        assert_eq!(w.root(), before);
        grant_reserve(&c, &mut w, &capacity).unwrap();
        assert_eq!(w.reserve, 1u32.into());
        assert_eq!(w.curve_mass, s.world.curve_mass);
        w.validate(&c, &s.issued, &s.auction_escrow).unwrap();
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn pass_and_fail_discard_only_the_other_world_and_settle_reserved_grant_once() {
        let c = config();
        let start = decision(&c);
        let mut fail = start.clone();
        while matches!(fail.phase, Phase::Governance(_)) {
            fail = advance(&c, &fail, 0, &[]);
        }
        assert!(fail.world.grant_escrow.is_zero());
        assert_eq!(fail.world.reserve, start.world.reserve);
        assert_eq!(fail.world.accounts.root(), start.world.accounts.root());
        let mut pass = start;
        let tx = signed(
            &pass,
            Operation::Deposit {
                amount: 100_000u32.into(),

                decision: pass.decision_id(),
                outcome: Some(Outcome::Pass),
            },
            0,
        );
        pass = advance(&c, &pass, 0, &[tx]);
        while matches!(pass.phase, Phase::Governance(_)) {
            pass = advance(&c, &pass, 0, &[]);
        }
        assert!(pass.world.grant_escrow.is_zero());
        assert_ne!(pass.root(), fail.root());
    }

    fn short_grant_rounds() -> Config {
        let mut c = config();
        // This fixture isolates repeated reserve funding from trade throttling.
        c.initial.max_price_change_bps = u64::MAX;
        c.initial.lead = c.initial.interval;
        c.initial.decision_blocks = 3;
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
        // Both execution and full audit must agree after checkpoint replay.
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

                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
            0,
        );
        s = replayed_step(c, &s, &[tx]);
        while matches!(s.phase, Phase::Governance(_)) {
            let pass = s.alternative.as_ref().unwrap();
            let expected =
                &pass.account(&owner(), s.epoch()).unwrap().ordinary + &pass.grant_escrow;
            s = replayed_step(c, &s, &[]);
            if s.decision_id().is_none() {
                assert_eq!(s.account(&owner(), None).unwrap().ordinary, expected);
                let after = replayed_step(c, &s, &[]);
                assert_eq!(after.account(&owner(), None).unwrap().ordinary, expected);
            }
        }
        s
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn repeated_funded_grants_reuse_returned_funds_and_replay() {
        let c = short_grant_rounds();
        let mut settled = funded_curve(&c);
        let issued = settled.issued.clone();
        // Each award exceeds the former per-grant fraction. The following
        // deposits return part of earlier awards to Stash for later grants.
        assert!(Amount::from(150_000u32) > &settled.world.reserve / 10u32);
        for _ in 0..8 {
            let opened = open_large_grant(&c, settled, 150_000);
            settled = pass_large_grant(&c, opened);
            assert!(settled.world.grant_escrow.is_zero());
            assert_eq!(settled.issued, issued);
        }
        assert!(Amount::from(8 * 150_000u32) > issued);
        replayed_step(&c, &settled, &[]).audit(&c).unwrap();
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn grants_keep_real_backing_and_escrow_invariants() {
        let c = short_grant_rounds();
        let s = funded_curve(&c);
        let capacity = grant_capacity(&s.world);
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
        assert_eq!(world.reserve, 1u32.into());
        let reserved = world.root();
        assert!(grant_reserve(&c, &mut world, &1u32.into()).is_err());
        assert_eq!(reserved, world.root());

        let opened = open_large_grant(&c, s, 200_000);
        let mut corrupt = opened.clone();
        let pass = corrupt.alternative.as_mut().unwrap();
        pass.grant_escrow -= 1u32;
        pass.revenue += 1u32;
        // Conservation still holds, but the award must be fully funded.
        assert!(
            corrupt
                .audit(&c)
                .unwrap_err()
                .to_string()
                .contains("escrow")
        );
        let mut corrupt = opened;
        corrupt.alternative.as_mut().unwrap().grant_escrow += 1u32;
        assert!(corrupt.validate(&c).is_err());
    }
    #[test]
    fn grant_capacity_retains_only_nonzero_stash_backing() {
        let c = config();
        for (reserve, revenue, shares, expected) in [
            (0u32, 0u32, 0u32, 0u32),
            (0, 5, 0, 5),
            (1, 0, 1, 0),
            (1, 5, 1, 5),
            (2, 0, 1, 1),
            (19, 0, 1, 18),
        ] {
            let mut w = World {
                reserve: reserve.into(),
                revenue: revenue.into(),
                shares: shares.into(),
                ..World::default()
            };
            assert_eq!(grant_capacity(&w), expected.into());
            if expected > 0 {
                grant_reserve(&c, &mut w, &expected.into()).unwrap();
                assert_eq!(w.reserve, u32::from(shares > 0).into());
                assert!(w.revenue.is_zero());
            }
        }
        let empty = State::genesis(&c);
        assert!(
            eligible(
                &c,
                &empty,
                &Proposal::Parameter {
                    parameter: Parameter::DecisionBlocks,
                    old: c.initial.decision_blocks,
                    new: c.initial.decision_blocks + 1,
                }
            )
            .is_ok()
        );
    }
}
