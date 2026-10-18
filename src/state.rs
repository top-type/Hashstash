use crate::{
    codec,
    config::{Config, Settings},
    crypto,
    tree::Map,
    types::*,
};
use anyhow::{Context, Result, ensure};
use num_traits::{CheckedSub, Zero};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// One world's account records. No code outside this module can insert or
/// remove a record: [`World::put`] is the only per-key writer, and it updates
/// `account_cash` and `account_shares` with each record. The one exception,
/// [`State::with_pass_records`], restores a saved world whose aggregates were
/// saved with it. The `World` fields themselves stay public, because tests
/// build worlds field by field, so code that assigns a whole map or an
/// aggregate must keep the others consistent.
/// `World::validate` checks conservation against the aggregates only;
/// `State::audit` recounts them from the records.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Accounts(Map<Account>);
impl std::ops::Deref for Accounts {
    type Target = Map<Account>;
    fn deref(&self) -> &Map<Account> {
        &self.0
    }
}

/// The PASS world's account records that differ from the FAIL world's, in
/// key order, as [State::split_pass_records] lists them: a changed or added
/// record, or None for a removed one.
pub type PassChanges<'a> = Vec<(&'a [u8], Option<&'a Account>)>;
/// [PassChanges] as a saved state decodes them.
pub type SavedPassChanges = Vec<(Vec<u8>, Option<Account>)>;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct World {
    pub accounts: Accounts,
    #[serde(with = "amount")]
    pub reserve: Amount,
    #[serde(with = "amount")]
    pub shares: Amount,
    #[serde(with = "amount")]
    pub revenue: Amount,
    #[serde(with = "amount")]
    pub grant_escrow: Amount,
    #[serde(with = "amount")]
    pub curve_mass: Amount,
    #[serde(with = "amount")]
    pub account_cash: Amount,
    #[serde(with = "amount")]
    pub account_shares: Amount,
}
impl World {
    pub fn account(&self, key: &PublicKey, epoch: Option<u64>) -> Option<Account> {
        self.accounts.get(key).map(|a| {
            let mut a = a.clone();
            let wanted = epoch.unwrap_or(0);
            if a.epoch != wanted {
                a.epoch = wanted;
            }
            a
        })
    }
    pub(crate) fn validate_account_update(a: &Account, c: &Config) -> Result<()> {
        c.check_amount(&a.ordinary)?;
        c.check_shares(&a.shares)?;
        Ok(())
    }
    pub fn put(&mut self, key: PublicKey, a: Account, c: &Config) -> Result<()> {
        Self::validate_account_update(&a, c)?;
        if let Some(old) = self.account(&key, None) {
            // A broken aggregate rejects the block instead of aborting.
            let cash = self
                .account_cash
                .checked_sub(&old.ordinary)
                .context("account cash aggregate underflow")?;
            let shares = self
                .account_shares
                .checked_sub(&old.shares)
                .context("account share aggregate underflow")?;
            self.account_cash = cash;
            self.account_shares = shares;
        }
        self.account_cash += &a.ordinary;
        self.account_shares += &a.shares;
        self.accounts.0.insert(key.to_vec(), a);
        Ok(())
    }
    pub fn quote(&self, c: &Config) -> Amount {
        if self.shares.is_zero() {
            0u32.into()
        } else {
            &c.quote_scale * &self.curve_mass / &self.shares
        }
    }
    pub fn root(&self) -> Hash {
        crypto::tagged_hash(
            "Hashstash/world",
            &codec::encode(&(
                self.accounts.root(),
                &self.reserve,
                &self.shares,
                &self.revenue,
                &self.grant_escrow,
                &self.curve_mass,
                &self.account_cash,
                &self.account_shares,
            )),
        )
    }
    pub fn validate(&self, c: &Config, issued: &Amount, auction_escrow: &Amount) -> Result<()> {
        ensure!(
            self.reserve.is_zero() == self.shares.is_zero(),
            "empty Stash invariant"
        );
        ensure!(self.shares == self.account_shares, "share conservation");
        ensure!(
            self.curve_mass >= self.reserve,
            "reserve exceeds curve mass"
        );
        ensure!(
            self.curve_mass.is_zero() == self.reserve.is_zero(),
            "empty curve mass invariant"
        );
        ensure!(
            &self.account_cash
                + &self.reserve
                + &self.revenue
                + &self.grant_escrow
                + auction_escrow
                == *issued,
            "HASH conservation"
        );
        for x in [
            &self.reserve,
            &self.revenue,
            &self.account_cash,
            &self.grant_escrow,
            &self.curve_mass,
        ] {
            c.check_amount(x)?;
        }
        c.check_shares(&self.shares)?;
        Ok(())
    }
    pub fn audit_accounts(&self, c: &Config, last_epoch: u64) -> Result<()> {
        let (mut cash, mut shares) = (Amount::zero(), Amount::zero());
        for (key, _) in self.accounts.iter() {
            let key: PublicKey = key.try_into()?;
            ensure!(crypto::valid_key(&key), "invalid account key");
            let raw = self.accounts.get(&key).unwrap();
            ensure!(raw.epoch <= last_epoch, "account epoch is in the future");
            let a = self.account(&key, None).unwrap();
            c.check_amount(&a.ordinary)?;
            c.check_shares(&a.shares)?;
            cash += &a.ordinary;
            shares += &a.shares;
        }
        ensure!(
            cash == self.account_cash && shares == self.account_shares,
            "account aggregate mismatch"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Auction {
    pub round: u64,
    pub opened: u64,
    pub leader: Option<Hash>,
    pub lead_since: u64,
    pub replacement_height: u64,
    /// Leaders that lost the lead to a strictly higher bid, oldest first,
    /// with the lead start each held. One of them resumes that lead start
    /// when it leads again because every later leader was cancelled.
    pub displaced: Displaced,
}
/// An auction's displaced leaders. A round can displace one leader per block,
/// so the list can hold thousands of entries. State versions share it: a clone
/// is constant time, and only a version that changes it copies it. It encodes
/// and commits exactly as the plain list.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Displaced(Arc<Vec<(Hash, u64)>>);
impl std::fmt::Debug for Displaced {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}
impl Displaced {
    /// Keeps the entries `keep` accepts; an unchanged list stays shared.
    pub fn retain(&mut self, mut keep: impl FnMut(&(Hash, u64)) -> bool) {
        let Some(first) = self.0.iter().position(|entry| !keep(entry)) else {
            return;
        };
        let mut kept = self.0[..first].to_vec();
        kept.extend(self.0[first + 1..].iter().filter(|&entry| keep(entry)));
        self.0 = Arc::new(kept);
    }
    pub fn push(&mut self, entry: (Hash, u64)) {
        Arc::make_mut(&mut self.0).push(entry);
    }
    pub fn pop(&mut self) -> Option<(Hash, u64)> {
        if self.0.is_empty() {
            return None;
        }
        Arc::make_mut(&mut self.0).pop()
    }
    #[cfg(test)]
    fn shares(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl std::ops::Deref for Displaced {
    type Target = [(Hash, u64)];
    fn deref(&self) -> &[(Hash, u64)] {
        &self.0
    }
}
impl<'a> IntoIterator for &'a Displaced {
    type Item = &'a (Hash, u64);
    type IntoIter = std::slice::Iter<'a, (Hash, u64)>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
impl From<Vec<(Hash, u64)>> for Displaced {
    fn from(entries: Vec<(Hash, u64)>) -> Self {
        Self(Arc::new(entries))
    }
}
impl PartialEq<Vec<(Hash, u64)>> for Displaced {
    fn eq(&self, other: &Vec<(Hash, u64)>) -> bool {
        *self.0 == *other
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub id: Hash,
    pub epoch: u64,
    pub round: u64,
    pub proposal_id: Hash,
    /// The winning action, shared with its `actions` entry. A grant can list
    /// as many payments as governed capacity admits; state clones must not
    /// copy them. The encoding is that of the plain proposal, but the state
    /// root commits the action only through `actions` (see `PhaseCommitment`).
    pub proposal: Arc<Proposal>,
    pub started: u64,
    pub started_height: u64,
    pub blocks: u64,
    pub leading_blocks: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rest {
    pub until: u64,
    pub pending: Option<(Parameter, u64)>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Phase {
    Auction(Auction),
    Governance(Decision),
    Rest(Rest),
}
/// The phase as the state root commits it: the same tags and fields, except
/// that a decision omits its copy of the proposal. That action is committed
/// once, as the `actions` entry under `proposal_id`, so computing a root never
/// re-encodes a grant.
#[derive(Serialize)]
enum PhaseCommitment<'a> {
    Auction(&'a Auction),
    Governance {
        id: Hash,
        epoch: u64,
        round: u64,
        proposal_id: Hash,
        started: u64,
        started_height: u64,
        blocks: u64,
        leading_blocks: u64,
    },
    Rest(&'a Rest),
}
impl<'a> From<&'a Phase> for PhaseCommitment<'a> {
    fn from(phase: &'a Phase) -> Self {
        match phase {
            Phase::Auction(a) => Self::Auction(a),
            Phase::Governance(d) => Self::Governance {
                id: d.id,
                epoch: d.epoch,
                round: d.round,
                proposal_id: d.proposal_id,
                started: d.started,
                started_height: d.started_height,
                blocks: d.blocks,
                leading_blocks: d.leading_blocks,
            },
            Phase::Rest(r) => Self::Rest(r),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoundStatus {
    Open,
    Won(Hash),
    Timeout,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundRecord {
    pub status: RoundStatus,
    pub refund_height: u64,
}
/// A registered proposal's auction standing. Its action is the `actions`
/// entry under the same ID, so updating support or cancelling re-encodes only
/// this small record, however many payments the grant lists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub round: u64,
    /// The registering sender, bound into the proposal ID.
    pub proposer: PublicKey,
    pub description: Hash,
    #[serde(with = "amount")]
    pub support: Amount,
    pub refund_height: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupportRecord {
    pub round: u64,
    pub proposal: Hash,
    pub sender: PublicKey,
    #[serde(with = "amount")]
    pub amount: Amount,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub chain_id: Hash,
    pub height: u64,
    pub clock: u64,
    #[serde(with = "amount")]
    pub issued: Amount,
    pub settings: Settings,
    pub frozen: Settings,
    pub world: World,
    pub alternative: Option<World>,
    pub phase: Phase,
    pub proposals: Map<ProposalRecord>,
    /// Each registered proposal's action, keyed like `proposals`. Written once,
    /// at registration, and never updated.
    pub actions: Map<Proposal>,
    pub supports: Map<SupportRecord>,
    pub rounds: Map<RoundRecord>,
    pub ranking: Map<Hash>,
    #[serde(with = "amount")]
    pub auction_escrow: Amount,
    pub last_round: u64,
    pub last_epoch: u64,
}
impl State {
    pub fn genesis(c: &Config) -> Self {
        let mut rounds = Map::new();
        let phase = if c.initial.rest == 0 {
            rounds.insert(
                0u64.to_be_bytes().to_vec(),
                RoundRecord {
                    status: RoundStatus::Open,
                    refund_height: 0,
                },
            );
            Phase::Auction(Auction {
                round: 0,
                opened: 0,
                leader: None,
                lead_since: 0,
                replacement_height: 0,
                displaced: Displaced::default(),
            })
        } else {
            Phase::Rest(Rest {
                until: c.initial.rest,
                pending: None,
            })
        };
        Self {
            chain_id: c.chain_id(),
            height: 0,
            clock: 0,
            issued: 0u32.into(),
            settings: c.initial.clone(),
            frozen: c.initial.clone(),
            world: World::default(),
            alternative: None,
            phase,
            proposals: Map::new(),
            actions: Map::new(),
            supports: Map::new(),
            rounds,
            ranking: Map::new(),
            auction_escrow: 0u32.into(),
            last_round: 0,
            last_epoch: 0,
        }
    }
    pub fn epoch(&self) -> Option<u64> {
        if let Phase::Governance(d) = &self.phase {
            Some(d.epoch)
        } else {
            None
        }
    }
    pub fn decision_id(&self) -> Option<Hash> {
        if let Phase::Governance(d) = &self.phase {
            Some(d.id)
        } else {
            None
        }
    }
    pub fn auction_round(&self) -> Option<u64> {
        if let Phase::Auction(a) = &self.phase {
            Some(a.round)
        } else {
            None
        }
    }
    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            Phase::Auction(_) => "auction",
            Phase::Governance(_) => "governance",
            Phase::Rest(_) => "rest",
        }
    }
    pub fn account(&self, key: &PublicKey, outcome: Option<Outcome>) -> Option<Account> {
        let w = if outcome == Some(Outcome::Pass) {
            self.alternative.as_ref().unwrap_or(&self.world)
        } else {
            &self.world
        };
        w.account(key, self.epoch())
    }
    /// Cash that can fund an ordinary payment or common fee in every possible
    /// outcome. Outcome-specific trades instead use that world's account cash.
    /// `account(key, None)` remains a view of the canonical/FAIL world.
    pub fn common_spendable(&self, key: &PublicKey) -> Option<Amount> {
        let cash = self.account(key, None)?.ordinary;
        if self.alternative.is_some() {
            Some(cash.min(self.account(key, Some(Outcome::Pass))?.ordinary))
        } else {
            Some(cash)
        }
    }
    /// This state as a saved checkpoint stores it: during a decision the PASS
    /// world's account records are left out, and listed instead as their
    /// differences from the FAIL world's records, in key order (a changed or
    /// added record, or None for a removed one). Execution opens the PASS
    /// world as a copy of the FAIL world, so the records both worlds still
    /// share are stored once, and [State::with_pass_records] restores them
    /// shared again rather than as a second copy of every account.
    pub fn split_pass_records(&self) -> (State, PassChanges<'_>) {
        let mut state = self.clone();
        let (Some(saved), Some(pass)) = (&mut state.alternative, &self.alternative) else {
            return (state, Vec::new());
        };
        saved.accounts = Accounts::default();
        let mut changes = Vec::new();
        let mut fail = self.world.accounts.iter().peekable();
        for (key, record) in pass.accounts.iter() {
            while let Some((removed, _)) = fail.next_if(|&(other, _)| other < key) {
                changes.push((removed, None));
            }
            match fail.next_if(|&(other, _)| other == key) {
                Some((_, shared)) if std::ptr::eq(shared, record) || shared == record => {}
                _ => changes.push((key, Some(record))),
            }
        }
        changes.extend(fail.map(|(removed, _)| (removed, None)));
        (state, changes)
    }
    /// The state [State::split_pass_records] split, with the PASS world's
    /// account records rebuilt from the FAIL world's and the listed changes,
    /// so the records they share are shared. The caller still checks the
    /// result against its committed root.
    pub fn with_pass_records(mut self, changes: SavedPassChanges) -> Result<Self> {
        let Some(pass) = &mut self.alternative else {
            ensure!(changes.is_empty(), "PASS records without a PASS world");
            return Ok(self);
        };
        ensure!(pass.accounts.is_empty(), "PASS records saved twice");
        let mut accounts = self.world.accounts.0.clone();
        let mut previous: Option<Vec<u8>> = None;
        for (key, record) in changes {
            ensure!(
                previous.as_ref().is_none_or(|previous| *previous < key),
                "PASS record changes are not in key order"
            );
            match record {
                Some(record) => accounts.insert(key.clone(), record),
                None => ensure!(
                    accounts.remove(&key).is_some(),
                    "removed PASS record absent"
                ),
            }
            previous = Some(key);
        }
        pass.accounts = Accounts(accounts);
        Ok(self)
    }
    pub fn root(&self) -> Hash {
        crypto::tagged_hash(
            "Hashstash/state",
            &codec::encode(&(
                (
                    self.chain_id,
                    self.height,
                    self.clock,
                    &self.issued,
                    &self.settings,
                    &self.frozen,
                    self.world.root(),
                    self.alternative.as_ref().map(World::root),
                    PhaseCommitment::from(&self.phase),
                ),
                (
                    self.proposals.root(),
                    self.actions.root(),
                    self.supports.root(),
                    self.rounds.root(),
                    self.ranking.root(),
                    &self.auction_escrow,
                    self.last_round,
                    self.last_epoch,
                ),
            )),
        )
    }
    pub fn validate(&self, c: &Config) -> Result<()> {
        ensure!(self.chain_id == c.chain_id(), "state chain mismatch");
        c.validate_fee_percent(&self.settings)?;
        c.validate_fee_percent(&self.frozen)?;
        c.validate_governance_settings(&self.settings)?;
        c.validate_governance_settings(&self.frozen)?;
        ensure!(
            self.height <= c.max_height
                && self.clock >= self.height
                && (self.height != 0 || self.clock == 0),
            "nominal clock is outside the representable block history"
        );
        if let Phase::Rest(r) = &self.phase
            && let Some((parameter, new)) = r.pending
        {
            let remaining = r
                .until
                .checked_sub(self.clock)
                .ok_or_else(|| anyhow::anyhow!("expired pending rest"))?;
            let activation =
                crate::consensus::rounded_deadline(self.clock, remaining, self.frozen.interval)?;
            let height =
                crate::consensus::activation_height(self.height, 0, remaining, self.frozen.interval);
            c.parameter_change_at(
                &self.frozen,
                parameter,
                self.frozen.get(parameter),
                new,
                activation,
                height,
            )?;
        }
        match &self.phase {
            Phase::Auction(a) => {
                a.opened
                    .checked_add(c.auction_timeout_for(&self.frozen)?)
                    .ok_or_else(|| anyhow::anyhow!("auction deadline overflow"))?;
            }
            Phase::Governance(d) => {
                ensure!(
                    d.started_height.checked_add(d.blocks).is_some(),
                    "decision height overflow"
                );
                let resolution = crate::consensus::rounded_deadline(
                    d.started,
                    d.blocks
                        .checked_mul(self.frozen.interval)
                        .ok_or_else(|| anyhow::anyhow!("decision schedule overflow"))?,
                    self.frozen.interval,
                )?;
                let activation = crate::consensus::rounded_deadline(
                    resolution,
                    self.frozen.rest,
                    self.frozen.interval,
                )?;
                if let Proposal::Parameter {
                    parameter,
                    old,
                    new,
                } = *d.proposal
                {
                    let height = crate::consensus::activation_height(
                        d.started_height,
                        d.blocks,
                        self.frozen.rest,
                        self.frozen.interval,
                    );
                    c.parameter_change_at(&self.frozen, parameter, old, new, activation, height)?;
                }
            }
            Phase::Rest(_) => {}
        }
        c.check_amount(&self.issued)?;
        c.check_amount(&self.auction_escrow)?;
        ensure!(
            matches!(self.phase, Phase::Governance(_)) == self.alternative.is_some(),
            "conditional state invariant"
        );
        self.world.validate(c, &self.issued, &self.auction_escrow)?;
        if self.rounds.is_empty() {
            ensure!(
                matches!(&self.phase, Phase::Rest(r) if r.pending.is_none() && r.until == c.initial.rest && self.clock < r.until)
                    && self.last_round == 0
                    && self.last_epoch == 0
                    && self.proposals.is_empty()
                    && self.actions.is_empty()
                    && self.supports.is_empty()
                    && self.ranking.is_empty()
                    && self.auction_escrow.is_zero(),
                "initial rest invariant"
            );
        }
        if let Some(w) = &self.alternative {
            w.validate(c, &self.issued, &self.auction_escrow)?;
        }
        Ok(())
    }
    pub fn audit(&self, c: &Config) -> Result<()> {
        self.validate(c)?;
        self.world.audit_accounts(c, self.last_epoch)?;
        if let Some(w) = &self.alternative {
            w.audit_accounts(c, self.last_epoch)?;
            let epoch = self.epoch();
            for (key, _) in self.world.accounts.iter() {
                let k: PublicKey = key.try_into()?;
                let a = self.world.account(&k, epoch).unwrap();
                let b = w
                    .account(&k, epoch)
                    .ok_or_else(|| anyhow::anyhow!("conditional account existence differs"))?;
                ensure!(a.nonce == b.nonce, "conditional nonce mismatch");
            }
            ensure!(
                self.world.accounts.len() == w.accounts.len(),
                "conditional account count differs"
            );
        }
        ensure!(self.height <= c.max_height, "state height exceeds range");
        ensure!(
            self.last_round <= self.height && self.last_epoch <= self.height,
            "cycle counter exceeds height"
        );
        ensure!(self.settings == self.frozen, "cycle settings mismatch");
        ensure!(
            self.world.grant_escrow.is_zero(),
            "FAIL world has grant escrow"
        );
        let mut expected_ranking = Map::new();
        let mut outstanding = std::collections::BTreeMap::<Hash, Amount>::new();
        let mut escrow = Amount::zero();
        for (key, support) in self.supports.iter() {
            ensure!(
                key == support_key(support.round, &support.proposal, &support.sender),
                "support key mismatch"
            );
            ensure!(crypto::valid_key(&support.sender), "invalid support sender");
            ensure!(
                self.world.accounts.get(&support.sender).is_some(),
                "missing supporter account"
            );
            ensure!(!support.amount.is_zero(), "empty support record");
            c.check_amount(&support.amount)?;
            let proposal = self
                .proposals
                .get(&support.proposal)
                .ok_or_else(|| anyhow::anyhow!("missing supported proposal"))?;
            ensure!(proposal.round == support.round, "support round mismatch");
            *outstanding.entry(support.proposal).or_default() += &support.amount;
            let round = self
                .rounds
                .get(&support.round.to_be_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing support round"))?;
            if !matches!(round.status, RoundStatus::Won(id) if id == support.proposal) {
                escrow += &support.amount;
            }
        }
        ensure!(
            escrow == self.auction_escrow,
            "auction support escrow mismatch"
        );
        ensure!(
            self.actions.len() == self.proposals.len(),
            "proposal action count mismatch"
        );
        for (key, proposal) in self.proposals.iter() {
            let action = self
                .actions
                .get(key)
                .ok_or_else(|| anyhow::anyhow!("missing proposal action"))?;
            if let Proposal::Grant { payments } = action {
                c.validate_grant(payments)?;
            }
            let id: Hash = key.try_into()?;
            ensure!(
                id == proposal_id(
                    &self.chain_id,
                    proposal.round,
                    &proposal.proposer,
                    &proposal.description,
                    action
                ),
                "proposal key mismatch"
            );
            ensure!(
                self.world.accounts.get(&proposal.proposer).is_some(),
                "missing proposer account"
            );
            ensure!(!proposal.support.is_zero(), "empty proposal support");
            c.check_amount(&proposal.support)?;
            let round = self
                .rounds
                .get(&proposal.round.to_be_bytes())
                .ok_or_else(|| anyhow::anyhow!("missing proposal round"))?;
            let unpaid = outstanding.get(&id).cloned().unwrap_or_default();
            ensure!(
                unpaid <= proposal.support,
                "proposal support aggregate exceeded"
            );
            if matches!(round.status, RoundStatus::Won(winner) if winner == id)
                || matches!(round.status, RoundStatus::Open) && proposal.refund_height.is_none()
            {
                ensure!(
                    unpaid == proposal.support,
                    "active or winning support aggregate mismatch"
                );
            }
            if let Some(height) = proposal.refund_height {
                ensure!(
                    height <= self.height.saturating_add(1),
                    "proposal refund height is in the future"
                );
            }
            if self.auction_round() == Some(proposal.round) && proposal.refund_height.is_none() {
                expected_ranking.insert(rank_key(&proposal.support, &id), id);
            }
        }
        ensure!(
            self.ranking.root() == expected_ranking.root(),
            "auction ranking mismatch"
        );
        ensure!(
            u64::try_from(self.rounds.len())?
                == if self.rounds.is_empty() {
                    0
                } else {
                    self.last_round + 1
                },
            "round history length mismatch"
        );
        for (key, round) in self.rounds.iter() {
            let index = u64::from_be_bytes(key.try_into()?);
            ensure!(index <= self.last_round, "round index is in the future");
            match round.status {
                RoundStatus::Open => ensure!(
                    self.auction_round() == Some(index) && round.refund_height == 0,
                    "open round mismatch"
                ),
                RoundStatus::Won(id) => {
                    let proposal = self
                        .proposals
                        .get(&id)
                        .ok_or_else(|| anyhow::anyhow!("missing winning proposal"))?;
                    ensure!(
                        proposal.round == index && proposal.refund_height.is_none(),
                        "winning proposal mismatch"
                    );
                    ensure!(
                        round.refund_height > 0
                            && round.refund_height <= self.height.saturating_add(1),
                        "invalid round refund height"
                    );
                }
                RoundStatus::Timeout => ensure!(
                    round.refund_height > 0 && round.refund_height <= self.height.saturating_add(1),
                    "invalid timeout refund height"
                ),
            }
        }
        match &self.phase {
            Phase::Auction(a) => {
                ensure!(
                    a.round == self.last_round
                        && a.opened <= a.lead_since
                        && a.lead_since <= self.clock,
                    "auction phase clock mismatch"
                );
                ensure!(
                    self.clock - a.opened < c.auction_timeout_for(&self.frozen)?,
                    "expired auction"
                );
                ensure!(
                    a.replacement_height <= self.height.saturating_add(1),
                    "invalid auction replacement height"
                );
                // Recorded lead starts are distinct proposals of this round
                // in the order they were displaced.
                let mut since = a.opened;
                let mut seen = std::collections::BTreeSet::new();
                for (id, start) in &a.displaced {
                    let p = self
                        .proposals
                        .get(id)
                        .ok_or_else(|| anyhow::anyhow!("missing displaced auction leader"))?;
                    ensure!(
                        p.round == a.round
                            && since <= *start
                            && *start <= a.lead_since
                            && seen.insert(*id),
                        "displaced auction leader mismatch"
                    );
                    since = *start;
                }
                if let Some(id) = a.leader {
                    let p = self
                        .proposals
                        .get(&id)
                        .ok_or_else(|| anyhow::anyhow!("missing auction leader"))?;
                    ensure!(
                        p.round == a.round && p.refund_height.is_none(),
                        "inactive auction leader"
                    );
                    if let Some((_, best_id)) = self.ranking.last() {
                        ensure!(
                            p.support == self.proposals.get(best_id).unwrap().support,
                            "auction leader is not highest supported"
                        );
                    }
                    ensure!(
                        self.clock - a.lead_since < self.frozen.lead,
                        "expired auction leader"
                    );
                }
            }
            Phase::Governance(d) => {
                ensure!(
                    d.epoch == self.last_epoch && d.epoch > 0 && d.round == self.last_round,
                    "decision epoch mismatch"
                );
                ensure!(
                    d.started_height <= self.height
                        && self.height - d.started_height < d.blocks
                        && d.leading_blocks <= self.height - d.started_height
                        && d.started.checked_add(
                            (self.height - d.started_height)
                                .checked_mul(self.frozen.interval)
                                .ok_or_else(|| anyhow::anyhow!("decision schedule overflow"))?
                        ) == Some(self.clock),
                    "decision clock mismatch"
                );
                ensure!(
                    d.blocks == self.frozen.decision_blocks,
                    "decision block count mismatch"
                );
                let p = self
                    .proposals
                    .get(&d.proposal_id)
                    .ok_or_else(|| anyhow::anyhow!("missing decision proposal"))?;
                ensure!(
                    p.round == d.round && self.actions.get(&d.proposal_id) == Some(&*d.proposal),
                    "decision proposal mismatch"
                );
                ensure!(
                    matches!(self.rounds.get(&d.round.to_be_bytes()).map(|r| &r.status), Some(RoundStatus::Won(id)) if *id == d.proposal_id),
                    "decision round winner mismatch"
                );
                let pass = self.alternative.as_ref().unwrap();
                match &*d.proposal {
                    Proposal::Grant { payments } => {
                        ensure!(
                            pass.grant_escrow == c.validate_grant(payments)?,
                            "grant escrow mismatch"
                        );
                    }
                    Proposal::Parameter {
                        parameter,
                        old,
                        new,
                    } => {
                        ensure!(
                            pass.grant_escrow.is_zero(),
                            "parameter decision contains grant state"
                        );
                        c.parameter_change(&self.frozen, *parameter, *old, *new)?;
                    }
                }
            }
            Phase::Rest(r) => {
                ensure!(
                    r.until > self.clock && r.until - self.clock <= self.frozen.rest,
                    "rest clock mismatch"
                );
                if let Some((p, new)) = r.pending {
                    c.parameter_change(&self.frozen, p, self.frozen.get(p), new)?;
                }
            }
        }
        Ok(())
    }
}
/// The registering sender is bound into the ID, so copying a pending Propose
/// creates a separate proposal instead of displacing the original.
pub fn proposal_id(
    chain: &Hash,
    round: u64,
    proposer: &PublicKey,
    description: &Hash,
    proposal: &Proposal,
) -> Hash {
    crypto::tagged_hash(
        "Hashstash/proposal",
        &codec::encode(&(chain, round, proposer, description, proposal)),
    )
}
pub fn support_key(round: u64, id: &Hash, sender: &PublicKey) -> Vec<u8> {
    crypto::tagged_hash("Hashstash/support", &codec::encode(&(round, id, sender))).to_vec()
}
pub fn rank_key(amount: &Amount, id: &Hash) -> Vec<u8> {
    let mut key = vec![0u8; 64];
    let bytes = amount.to_bytes_be();
    assert!(bytes.len() <= 64);
    key[64 - bytes.len()..].copy_from_slice(&bytes);
    key.extend(id.iter().map(|x| !x));
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(payments: u8) -> Proposal {
        Proposal::Grant {
            payments: (1..=payments)
                .map(|i| GrantPayment {
                    recipient: [i; 32],
                    amount: 1u32.into(),
                })
                .collect(),
        }
    }

    fn record(proposer: PublicKey) -> ProposalRecord {
        ProposalRecord {
            round: 0,
            proposer,
            description: [4; 32],
            support: 1u32.into(),
            refund_height: None,
        }
    }

    /// A decision on a registered 40-payment grant, sharing its action.
    fn governed() -> (State, Hash) {
        let mut s = State::genesis(&Config::devnet());
        let action = grant(40);
        let id = proposal_id(&s.chain_id, 0, &[3; 32], &[4; 32], &action);
        s.proposals.insert(id.to_vec(), record([3; 32]));
        s.actions.insert(id.to_vec(), action);
        s.phase = Phase::Governance(Decision {
            id: [5; 32],
            epoch: 1,
            round: 0,
            proposal_id: id,
            proposal: s.actions.get_shared(&id).unwrap().clone(),
            started: 0,
            started_height: 0,
            blocks: 1,
            leading_blocks: 0,
        });
        (s, id)
    }

    #[test]
    fn state_clones_share_governed_proposals_without_changing_encodings() {
        let (s, id) = governed();
        let mut copy = s.clone();
        // A path-copying insert leaves the registered action shared.
        copy.actions.insert([9; 32].to_vec(), grant(1));
        let (Phase::Governance(a), Phase::Governance(b)) = (&s.phase, &copy.phase) else {
            unreachable!()
        };
        assert!(Arc::ptr_eq(&a.proposal, &b.proposal));
        assert!(Arc::ptr_eq(&a.proposal, copy.actions.get_shared(&id).unwrap()));
        let plain = (
            a.id,
            a.epoch,
            a.round,
            a.proposal_id,
            &grant(40),
            a.started,
            a.started_height,
            a.blocks,
            a.leading_blocks,
        );
        assert_eq!(codec::encode(a), codec::encode(&plain));
    }

    #[test]
    fn state_clones_share_displaced_leaders_without_changing_encodings() {
        // Audit R26: the list was an inline Vec copied by every state clone.
        let entries: Vec<(Hash, u64)> = (0..3600u32)
            .map(|i| {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                (id, u64::from(i))
            })
            .collect();
        let mut s = State::genesis(&Config::devnet());
        s.phase = Phase::Auction(Auction {
            round: 0,
            opened: 0,
            leader: None,
            lead_since: 0,
            replacement_height: 0,
            displaced: entries.clone().into(),
        });
        let copy = s.clone();
        let (Phase::Auction(a), Phase::Auction(b)) = (&s.phase, &copy.phase) else {
            unreachable!()
        };
        assert!(a.displaced.shares(&b.displaced));
        // The encoding, and so the phase commitment, is the plain list's.
        assert_eq!(codec::encode(&a.displaced), codec::encode(&entries));
        assert_eq!(
            serde_json::to_string(&a.displaced).unwrap(),
            serde_json::to_string(&entries).unwrap()
        );
        let decoded: Displaced = codec::decode(&codec::encode(&entries), usize::MAX).unwrap();
        assert_eq!(decoded, entries);
        assert_eq!(format!("{decoded:?}"), format!("{entries:?}"));
        // Only a change copies the list, and only for the changed version.
        let mut changed = b.displaced.clone();
        changed.retain(|_| true);
        assert!(changed.shares(&a.displaced));
        changed.retain(|(id, _)| id[3] != 7);
        assert!(!changed.shares(&a.displaced));
        let mut expected = entries.clone();
        expected.retain(|(id, _)| id[3] != 7);
        assert_eq!((changed.len(), a.displaced.len()), (3585, 3600));
        assert_eq!(changed, expected);
        changed.push(([9; 32], 9));
        assert_eq!(changed.last(), Some(&([9; 32], 9)));
        assert_eq!(changed.pop(), Some(([9; 32], 9)));
        assert_eq!(changed, expected);
        let mut empty = Displaced::default();
        assert_eq!(empty.pop(), None);
        assert!(empty.shares(&empty.clone()));
    }

    #[test]
    fn the_state_root_commits_actions_once_and_never_in_the_phase() {
        // Auction and rest commitments are the phase encoding itself.
        for phase in [
            Phase::Auction(Auction {
                round: 2,
                opened: 30,
                leader: Some([7; 32]),
                lead_since: 45,
                replacement_height: 4,
                displaced: vec![([8; 32], 35)].into(),
            }),
            Phase::Rest(Rest {
                until: 90,
                pending: Some((Parameter::Lead, 30)),
            }),
        ] {
            assert_eq!(
                codec::encode(&PhaseCommitment::from(&phase)),
                codec::encode(&phase)
            );
        }
        // A decision commits its tag and every field but its proposal copy.
        let (s, id) = governed();
        let Phase::Governance(d) = &s.phase else {
            unreachable!()
        };
        let committed = (
            1u32,
            d.id,
            d.epoch,
            d.round,
            d.proposal_id,
            d.started,
            d.started_height,
            d.blocks,
            d.leading_blocks,
        );
        assert_eq!(
            codec::encode(&PhaseCommitment::from(&s.phase)),
            codec::encode(&committed)
        );
        // The action is committed through the actions map instead.
        let mut other = s.clone();
        other.actions.insert(id.to_vec(), grant(39));
        assert_ne!(other.root(), s.root());
    }

    #[test]
    fn saved_pass_records_list_only_differences_and_restore_shared() {
        let c = Config::devnet();
        let (mut s, _) = governed();
        let account = |ordinary: u32| Account {
            ordinary: ordinary.into(),
            ..Account::default()
        };
        for key in 1..=5u8 {
            s.world.put([key; 32], account(u32::from(key)), &c).unwrap();
        }
        let mut pass = s.world.clone();
        // Changed, removed and added records; one rewritten with its value.
        pass.put([2; 32], account(20), &c).unwrap();
        pass.accounts.0.remove(&[3; 32]);
        pass.put([6; 32], account(6), &c).unwrap();
        pass.put([5; 32], account(5), &c).unwrap();
        s.alternative = Some(pass);
        let (saved, changes) = s.split_pass_records();
        assert!(saved.alternative.as_ref().unwrap().accounts.is_empty());
        let listed: Vec<(u8, Option<Amount>)> = changes
            .iter()
            .map(|(key, record)| (key[0], record.map(|a| a.ordinary.clone())))
            .collect();
        let expected: Vec<(u8, Option<Amount>)> =
            vec![(2, Some(20u32.into())), (3, None), (6, Some(6u32.into()))];
        assert_eq!(listed, expected);
        // The saved encoding restores the same state, with unchanged records
        // shared by both worlds.
        let decoded: (State, SavedPassChanges) =
            codec::decode(&codec::encode(&(&saved, &changes)), usize::MAX).unwrap();
        let restored = decoded.0.with_pass_records(decoded.1).unwrap();
        assert_eq!(restored.root(), s.root());
        let pass = restored.alternative.as_ref().unwrap();
        for key in [1, 4, 5] {
            let fail = restored.world.accounts.get_shared(&[key; 32]).unwrap();
            assert!(Arc::ptr_eq(
                fail,
                pass.accounts.get_shared(&[key; 32]).unwrap()
            ));
        }
        // Changes out of key order, a removal of an absent record, and
        // records without a PASS world are refused.
        fn owned(changes: &[(&[u8], Option<&Account>)]) -> SavedPassChanges {
            changes
                .iter()
                .map(|(key, record)| (key.to_vec(), record.cloned()))
                .collect()
        }
        let mut reversed = owned(&changes);
        reversed.reverse();
        assert!(saved.clone().with_pass_records(reversed).is_err());
        let absent = vec![([9; 32].to_vec(), None)];
        assert!(saved.clone().with_pass_records(absent.clone()).is_err());
        let mut rest = saved.clone();
        rest.alternative = None;
        assert!(rest.with_pass_records(owned(&changes)).is_err());
        assert!(saved.with_pass_records(owned(&changes)).is_ok());
    }

    #[test]
    fn broken_account_aggregates_are_errors_without_mutation() {
        // Audit F160: these subtractions used to panic and abort the node.
        let c = Config::devnet();
        let key = [7; 32];
        let mut w = World::default();
        let account = Account {
            ordinary: 5u32.into(),
            shares: 3u32.into(),
            ..Account::default()
        };
        w.put(key, account, &c).unwrap();
        for (cash, shares, error) in [(4u32, 3u32, "cash"), (5, 2, "share")] {
            let mut broken = w.clone();
            broken.account_cash = cash.into();
            broken.account_shares = shares.into();
            let before = broken.root();
            let result = broken.put(key, Account::default(), &c);
            assert!(result.unwrap_err().to_string().contains(error));
            assert_eq!(broken.root(), before);
        }
    }

    #[test]
    fn proposal_ids_bind_the_registering_sender() {
        let chain = Config::devnet().chain_id();
        let action = grant(2);
        let first = proposal_id(&chain, 7, &[1; 32], &[4; 32], &action);
        assert_ne!(first, proposal_id(&chain, 7, &[2; 32], &[4; 32], &action));
        assert_eq!(first, proposal_id(&chain, 7, &[1; 32], &[4; 32], &action));
    }
}
