use crate::{
    codec,
    config::{Config, Settings},
    crypto,
    tree::Map,
    types::*,
};
use anyhow::{Result, ensure};
use num_traits::Zero;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct World {
    pub accounts: Map<Account>,
    #[serde(with = "amount")]
    pub reserve: Amount,
    #[serde(with = "amount")]
    pub shares: Amount,
    #[serde(with = "amount")]
    pub revenue: Amount,
    #[serde(with = "amount")]
    pub grant_escrow: Amount,
    #[serde(with = "amount")]
    pub price_integral: Amount,
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
            self.account_cash -= &old.ordinary;
            self.account_shares -= &old.shares;
        }
        self.account_cash += &a.ordinary;
        self.account_shares += &a.shares;
        self.accounts.insert(key.to_vec(), a);
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
                &self.price_integral,
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
        ensure!(
            self.price_integral.bits() <= c.max_integer_bits,
            "price integral overflow"
        );
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
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub id: Hash,
    pub epoch: u64,
    pub round: u64,
    pub proposal_id: Hash,
    pub proposal: Proposal,
    pub started: u64,
    pub duration: u64,
    #[serde(with = "amount")]
    pub start_integral: Amount,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub round: u64,
    pub description: Hash,
    pub action: Proposal,
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
                    &self.phase,
                ),
                (
                    self.proposals.root(),
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
            c.parameter_change_at(
                &self.frozen,
                parameter,
                self.frozen.get(parameter),
                new,
                activation,
            )?;
        }
        match &self.phase {
            Phase::Auction(a) => {
                a.opened
                    .checked_add(c.auction_timeout_for(&self.frozen)?)
                    .ok_or_else(|| anyhow::anyhow!("auction deadline overflow"))?;
            }
            Phase::Governance(d) => {
                let resolution = crate::consensus::rounded_deadline(
                    d.started,
                    d.duration,
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
                } = d.proposal
                {
                    c.parameter_change_at(&self.frozen, parameter, old, new, activation)?;
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
        for (key, proposal) in self.proposals.iter() {
            if let Proposal::Grant { payments } = &proposal.action {
                c.validate_grant(payments)?;
            }
            let id: Hash = key.try_into()?;
            ensure!(
                id == proposal_id(
                    &self.chain_id,
                    proposal.round,
                    &proposal.description,
                    &proposal.action
                ),
                "proposal key mismatch"
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
                    d.started <= self.clock && self.clock - d.started < d.duration,
                    "decision clock mismatch"
                );
                ensure!(
                    d.duration == self.frozen.duration,
                    "decision duration mismatch"
                );
                let p = self
                    .proposals
                    .get(&d.proposal_id)
                    .ok_or_else(|| anyhow::anyhow!("missing decision proposal"))?;
                ensure!(
                    p.round == d.round && p.action == d.proposal,
                    "decision proposal mismatch"
                );
                ensure!(
                    matches!(self.rounds.get(&d.round.to_be_bytes()).map(|r| &r.status), Some(RoundStatus::Won(id)) if *id == d.proposal_id),
                    "decision round winner mismatch"
                );
                let pass = self.alternative.as_ref().unwrap();
                ensure!(
                    d.start_integral <= self.world.price_integral
                        && d.start_integral <= pass.price_integral,
                    "decision integral baseline mismatch"
                );
                match &d.proposal {
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
pub fn proposal_id(chain: &Hash, round: u64, description: &Hash, proposal: &Proposal) -> Hash {
    crypto::tagged_hash(
        "Hashstash/proposal",
        &codec::encode(&(chain, round, description, proposal)),
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
