//! The proposal index is derived from tip to tip: a new block re-ranks only
//! the open round, and the result always equals a full build.
use super::*;
use crate::state::{Auction, Decision, Phase, ProposalRecord, Rest, RoundRecord, RoundStatus};

fn builds() -> usize {
    PROPOSAL_INDEX_BUILDS.with(|builds| builds.get())
}

fn action() -> Proposal {
    Proposal::Parameter {
        parameter: Parameter::BlockBytes,
        old: 16_384,
        new: 32_768,
    }
}

fn register(s: &mut State, id: Hash, round: u64, support: u64) {
    s.actions.insert(id.to_vec(), action());
    s.proposals.insert(
        id.to_vec(),
        ProposalRecord {
            round,
            proposer: [0; 32],
            description: [0; 32],
            support: support.into(),
            refund_height: None,
        },
    );
}

fn auction(round: u64, leader: Option<Hash>) -> Phase {
    Phase::Auction(Auction {
        round,
        opened: 0,
        leader,
        lead_since: 0,
        replacement_height: 0,
        displaced: Default::default(),
    })
}

fn view(s: State, cache: TipCache) -> ReadView {
    ReadView {
        chain: PublishedChain {
            config: Arc::new(Config::devnet()),
            tip: [9; 32],
            state: Arc::new(s),
        },
        mempool: Arc::from(Vec::new()),
        pool_revision: 0,
        cache: Arc::new(cache),
    }
}

/// A deterministic governance history: auctions that register and support
/// proposals and change leaders, then win into a decision or time out.
struct History {
    s: State,
    seed: u64,
    minted: u64,
}
impl History {
    fn random(&mut self, below: u64) -> u64 {
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed % below
    }
    fn round_ids(&self, round: u64) -> Vec<Hash> {
        self.s
            .proposals
            .iter()
            .filter(|(_, p)| p.round == round)
            .map(|(key, _)| key.try_into().unwrap())
            .collect()
    }
    /// One block's changes, returning the proposals it registered.
    fn step(&mut self) -> Vec<Hash> {
        let mut registered = Vec::new();
        match self.s.phase.clone() {
            Phase::Rest(_) => {
                if self.random(3) == 0 {
                    let round = if self.s.rounds.is_empty() {
                        0
                    } else {
                        self.s.last_round + 1
                    };
                    self.s.last_round = round;
                    self.s.rounds.insert(
                        round.to_be_bytes().to_vec(),
                        RoundRecord {
                            status: RoundStatus::Open,
                            refund_height: 0,
                        },
                    );
                    self.s.phase = auction(round, None);
                }
            }
            Phase::Governance(_) => {
                if self.random(2) == 0 {
                    self.s.phase = Phase::Rest(Rest {
                        until: 0,
                        pending: None,
                    });
                }
            }
            Phase::Auction(a) => {
                for _ in 0..self.random(4) {
                    self.minted += 1;
                    let id = crypto::tagged_hash("index-test", &self.minted.to_le_bytes());
                    let support = 1 + self.random(40);
                    register(&mut self.s, id, a.round, support);
                    registered.push(id);
                }
                let ids = self.round_ids(a.round);
                for _ in 0..self.random(3) {
                    if ids.is_empty() {
                        break;
                    }
                    let id = ids[self.random(ids.len() as u64) as usize];
                    let mut record = self.s.proposals.get(&id).unwrap().clone();
                    record.support += 1 + self.random(30);
                    self.s.proposals.insert(id.to_vec(), record);
                }
                let leader = (!ids.is_empty() && self.random(2) == 0)
                    .then(|| ids[self.random(ids.len() as u64) as usize]);
                self.s.phase = auction(a.round, leader);
                match self.random(6) {
                    0 if !ids.is_empty() => {
                        let winner = ids[self.random(ids.len() as u64) as usize];
                        self.s.rounds.insert(
                            a.round.to_be_bytes().to_vec(),
                            RoundRecord {
                                status: RoundStatus::Won(winner),
                                refund_height: self.s.height + 1,
                            },
                        );
                        self.s.phase = Phase::Governance(Decision {
                            id: [1; 32],
                            epoch: 1,
                            round: a.round,
                            proposal_id: winner,
                            proposal: Arc::new(action()),
                            started: 0,
                            started_height: self.s.height,
                            blocks: 4,
                            leading_blocks: 0,
                        });
                    }
                    1 => {
                        self.s.rounds.insert(
                            a.round.to_be_bytes().to_vec(),
                            RoundRecord {
                                status: RoundStatus::Timeout,
                                refund_height: self.s.height + 1,
                            },
                        );
                        self.s.phase = Phase::Rest(Rest {
                            until: 0,
                            pending: None,
                        });
                    }
                    _ => {}
                }
            }
        }
        self.s.height += 1;
        registered
    }
}

#[test]
fn derived_indexes_equal_full_builds_over_a_governance_history() {
    let mut history = History {
        s: State::genesis(&Config::devnet()),
        seed: 0x9e37_79b9_7f4a_7c15,
        minted: 0,
    };
    assert!(matches!(history.s.phase, Phase::Rest(_)));
    let mut previous = Arc::new(ProposalIndex::build(&history.s));
    // An index several unread tips back, with every registration since.
    let mut older = (previous.clone(), Vec::new());
    let mut rounds = BTreeSet::new();
    for step in 0..600 {
        let registered = history.step();
        let s = &history.s;
        let full = ProposalIndex::build(s);
        let derived = ProposalIndex::derive(&previous, &registered, s);
        assert_eq!(derived.as_ref(), Some(&full), "step {step}");
        older.1.extend_from_slice(&registered);
        assert_eq!(
            ProposalIndex::derive(&older.0, &older.1, s).as_ref(),
            Some(&full),
            "chained step {step}"
        );
        if !registered.is_empty() {
            // A missed registration is detected and falls back to a build.
            assert!(ProposalIndex::derive(&previous, &registered[1..], s).is_none());
        }
        // Only the auction round, if any, is ranked again for each tip.
        assert!(full.open.len() <= 1);
        rounds.extend(full.closed.keys().copied());
        previous = Arc::new(full);
        if step % 7 == 0 {
            older = (previous.clone(), Vec::new());
        }
    }
    assert!(
        rounds.len() >= 10,
        "history closed only {} rounds",
        rounds.len()
    );
    assert!(history.s.proposals.len() >= 200);
}

#[test]
fn a_new_tip_reads_its_snapshot_and_round_pages_without_walking_history() {
    let mut s = State::genesis(&Config::devnet());
    let mut minted = 0u64;
    let mut mint = |s: &mut State, round: u64, support: u64| {
        minted += 1;
        let id = crypto::tagged_hash("index-test", &minted.to_le_bytes());
        register(s, id, round, support);
        id
    };
    for round in 0..4u64 {
        for support in 0..60 {
            mint(&mut s, round, 1 + support % 13);
        }
        s.rounds.insert(
            round.to_be_bytes().to_vec(),
            RoundRecord {
                status: RoundStatus::Timeout,
                refund_height: 1,
            },
        );
    }
    s.last_round = 4;
    s.rounds.insert(
        4u64.to_be_bytes().to_vec(),
        RoundRecord {
            status: RoundStatus::Open,
            refund_height: 0,
        },
    );
    let open: Vec<Hash> = (0..5)
        .map(|support| mint(&mut s, 4, 10 + support))
        .collect();
    s.phase = auction(4, Some(open[0]));
    let parent = view(s.clone(), TipCache::default());
    let before = builds();
    let polled = Node::read_rpc(&parent, "snapshot", json!({})).unwrap();
    assert_eq!(builds(), before + 1);
    assert_eq!(polled["proposals_total"], 5);

    // The next block registers one proposal, adds support and changes leader.
    let added = mint(&mut s, 4, 3);
    let mut record = s.proposals.get(&open[1]).unwrap().clone();
    record.support += 100u32;
    s.proposals.insert(open[1].to_vec(), record);
    s.phase = auction(4, Some(added));
    s.height += 1;
    let child = view(s.clone(), TipCache::extending(&parent.cache, vec![added]));
    // Another block nobody read in between: its base is the parent's index.
    let late = mint(&mut s, 4, 1);
    s.height += 1;
    let grandchild = view(s.clone(), TipCache::extending(&child.cache, vec![late]));
    let reads = |v: &ReadView| -> Vec<Value> {
        let mut values = vec![Node::read_rpc(v, "snapshot", json!({})).unwrap()];
        for round in 0..5u64 {
            values.push(Node::read_rpc(v, "proposals", json!({"round":round})).unwrap());
        }
        values
    };
    let before = builds();
    let derived = reads(&grandchild);
    let first = reads(&child);
    assert_eq!(builds(), before, "a new tip walked every proposal");
    assert_eq!(derived[0]["proposals_total"], 7);
    assert_eq!(derived[0]["proposals"][0]["id"], hex::encode(added));
    // Each equals a cold read of the same state, which builds the index.
    assert_eq!(
        first,
        reads(&view(
            child.chain.state.as_ref().clone(),
            TipCache::default()
        ))
    );
    assert_eq!(derived, reads(&view(s, TipCache::default())));
    assert_eq!(builds(), before + 2);
    // Closed rounds are shared between tips rather than copied.
    assert!(Arc::ptr_eq(
        &parent.proposal_index().closed,
        &grandchild.proposal_index().closed
    ));
}

#[test]
fn published_blocks_derive_the_index_from_the_previous_tip() {
    let directory = tempfile::tempdir().unwrap();
    let miner = crypto::public_key(&[72; 32]).unwrap();
    // Without a rest the genesis opens round 0, which every snapshot lists.
    let mut config = Config::devnet();
    config.initial.rest = 0;
    let node = Node::open(&directory.path().join("chain.sqlite"), config, miner).unwrap();
    let before = builds();
    let poll = || Node::read_rpc(&node.read_view().unwrap(), "snapshot", json!({})).unwrap();
    poll();
    assert_eq!(builds(), before + 1);
    for height in 1..=3 {
        node.mine(1_000_000).unwrap();
        // A second block before any read chains onto the same base.
        if height == 2 {
            node.mine(1_000_000).unwrap();
        }
        assert_eq!(
            poll()["status"]["height"],
            if height == 1 { 1 } else { height + 1 }
        );
    }
    assert_eq!(builds(), before + 1, "a published block rebuilt the index");
}

#[test]
fn unfiltered_pages_list_every_proposal_in_key_order() {
    let mut s = State::genesis(&Config::devnet());
    for (id, round) in [(3u8, 0u64), (1, 2), (2, 1)] {
        register(&mut s, [id; 32], round, 5);
    }
    let v = view(s, TipCache::default());
    let page = Node::read_rpc(&v, "proposals", json!({})).unwrap();
    let ids: Vec<_> = page
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, [1u8, 2, 3].map(|id| hex::encode([id; 32])).to_vec());
}

#[test]
fn unfiltered_pages_cost_their_rows_not_the_history_before_them() {
    let mut s = State::genesis(&Config::devnet());
    for n in 0..64 * 600u32 {
        let id = crypto::tagged_hash("unfiltered-page", &n.to_le_bytes());
        register(&mut s, id, u64::from(n % 7), 1);
    }
    let all: Vec<String> = s
        .proposals
        .iter()
        .map(|(key, _)| hex::encode(key))
        .collect();
    let v = view(s, TipCache::default());
    // A session with 50 work units left. Charging the history before a page
    // (600 units here) could never fit; once proposals outgrow a whole burst
    // the first unfiltered page of every tip was refused. Stratum's bucket
    // refills one unit per millisecond, so the test cannot outwait it.
    let session = Arc::new(NetworkGuard::default())
        .admit("127.0.0.1".parse().unwrap(), Surface::Stratum)
        .unwrap();
    session.work(8192 - 50).unwrap();
    for offset in [0, 1, 20_000, all.len() - 3, all.len(), all.len() + 9] {
        let page = Node::read_rpc_metered(
            &v,
            "proposals",
            json!({"offset":offset,"limit":5}),
            Some(&session),
        )
        .unwrap();
        let ids: Vec<_> = page
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect();
        let end = all.len().min(offset + 5);
        assert_eq!(ids, all[offset.min(end)..end], "offset {offset}");
    }
}
