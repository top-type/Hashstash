//! Decision-rule regressions: symmetric outcome curves, empty worlds, auction
//! leadership, branch-stable decision IDs and non-panicking invariant checks.
use hashstash::{
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, RoundStatus, State, proposal_id},
    types::*,
};
use num_traits::Zero;

const ATTACKER: [u8; 32] = [61; 32];
const DEFENDER: [u8; 32] = [62; 32];

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn config(decision_blocks: u64, lead: u64) -> Config {
    let mut c = Config::testnet();
    c.initial.rest = 0;
    c.initial.lead = lead;
    c.initial.decision_blocks = decision_blocks;
    c.validate().unwrap();
    c
}
fn sign(s: &State, secret: &[u8; 32], fee: u32, operation: Operation) -> Transaction {
    crypto::sign(
        &TransactionBody {
            sender: key(secret),
            nonce: s.account(&key(secret), None).unwrap().nonce,
            fee: fee.into(),
            anchor: [0; 32],
            expiry_blocks: s.height + 100,
            operation,
            data: vec![],
        },
        secret,
    )
    .unwrap()
}
fn step_by(c: &Config, s: &State, miner: &PublicKey, subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), miner, &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn step(c: &Config, s: &State, txs: &[Transaction]) -> State {
    step_by(c, s, &key(&ATTACKER), 0, txs)
}
/// Round-zero auction with two funded accounts and an empty reserve.
fn funded(c: &Config) -> State {
    let s = step_by(c, &State::genesis(c), &key(&ATTACKER), 3_000_000, &[]);
    let pay = sign(
        &s,
        &ATTACKER,
        4,
        Operation::TransferExact {
            recipient: key(&DEFENDER),
            amount: 500_000u32.into(),
        },
    );
    let s = step(c, &s, &[pay]);
    assert_eq!(s.auction_round(), Some(0));
    s
}
fn propose(
    s: &State,
    secret: &[u8; 32],
    description: u8,
    proposal: Proposal,
    support: u32,
) -> (Transaction, Hash) {
    let round = s.auction_round().unwrap();
    let id = proposal_id(
        &s.chain_id,
        round,
        &key(secret),
        &[description; 32],
        &proposal,
    );
    let tx = sign(
        s,
        secret,
        4,
        Operation::Propose {
            round,
            description: [description; 32],
            proposal,
            support: support.into(),
        },
    );
    (tx, id)
}
fn miner_fee(new: u64) -> Proposal {
    Proposal::Parameter {
        parameter: Parameter::MinerFeePercent,
        old: 50,
        new,
    }
}
fn trade(s: &State, secret: &[u8; 32], amount: u32, outcome: Outcome) -> Transaction {
    sign(
        s,
        secret,
        4,
        Operation::Deposit {
            amount: amount.into(),
            decision: s.decision_id(),
            outcome: Some(outcome),
        },
    )
}
fn leader(s: &State) -> (Option<Hash>, u64) {
    let Phase::Auction(a) = &s.phase else {
        panic!("auction expected")
    };
    (a.leader, a.lead_since)
}
fn stash(s: &State, secret: &[u8; 32], operation: Operation) -> Transaction {
    sign(s, secret, 4, operation)
}
fn grant(amount: Amount) -> Proposal {
    Proposal::Grant {
        payments: vec![GrantPayment {
            recipient: key(&ATTACKER),
            amount,
        }],
    }
}
/// Round zero with the attacker holding Stash on a flat reserve.
fn staked(c: &Config) -> State {
    let s = funded(c);
    let deposit = stash(
        &s,
        &ATTACKER,
        Operation::Deposit {
            amount: 1_000_000u32.into(),
            decision: None,
            outcome: None,
        },
    );
    step(c, &s, &[deposit])
}

/// Audit F010. A flat FAIL world could not move while a grant's one-atom
/// overdraft bent PASS, and block revenue then flattened PASS right after a
/// tiny buy, so one small PASS trade won every observation. Both outcomes now
/// open on the same curve, revenue waits until resolution and the bid cannot
/// fund its own grant, so an equal FAIL trade is a sufficient defence.
#[test]
fn reserve_overdraft_grant_opens_symmetric_curves_and_equal_defence_ties() {
    let c = config(8, 0);
    let mut s = funded(&c);
    let deposit = sign(
        &s,
        &ATTACKER,
        4,
        Operation::Deposit {
            amount: 1_000_000u32.into(),
            decision: None,
            outcome: None,
        },
    );
    s = step(&c, &s, &[deposit]);
    // Waiting revenue beside a flat reserve.
    let tip = sign(
        &s,
        &ATTACKER,
        100_000,
        Operation::TransferExact {
            recipient: key(&ATTACKER),
            amount: 1u32.into(),
        },
    );
    s = step(&c, &s, &[tip]);
    assert_eq!(s.world.reserve, s.world.curve_mass);
    let reserve = s.world.reserve.clone();
    let support = 1u32;
    // The proposal's own revenue share is waiting revenue when it opens.
    let (probe, _) = propose(&s, &ATTACKER, 7, miner_fee(40), support);
    let revenue_fee = hashstash::fees::quote(&c, &s, &probe).unwrap().revenue_fee;
    let waiting = &s.world.revenue + &revenue_fee;
    // All waiting revenue, the bid and one reserve atom.
    let grant = &waiting + support + 1u32;
    let (tx, id) = propose(
        &s,
        &ATTACKER,
        7,
        Proposal::Grant {
            payments: vec![GrantPayment {
                recipient: key(&ATTACKER),
                amount: grant.clone(),
            }],
        },
        support,
    );
    let paid_before = s.account(&key(&ATTACKER), None).unwrap().ordinary;
    s = step(&c, &s, &[tx]);
    let Phase::Governance(d) = s.phase.clone() else {
        panic!("decision expected")
    };
    assert_eq!(d.proposal_id, id);
    let pass = s.alternative.as_ref().unwrap();
    // The bid is not available to the grant: the reserve covers bid + 1.
    let shortfall = Amount::from(support + 1);
    assert_eq!(pass.reserve, &reserve - &shortfall);
    assert_eq!(s.world.reserve, pass.reserve);
    assert_eq!(s.world.curve_mass, pass.curve_mass);
    assert_eq!(s.world.shares, pass.shares);
    assert_eq!(pass.revenue, Amount::from(support));
    assert_eq!(s.world.revenue, &waiting + &shortfall + support);

    // The attacker buys PASS; the defender spends the same amount on FAIL.
    let attack = trade(&s, &ATTACKER, 10, Outcome::Pass);
    let defence = trade(&s, &DEFENDER, 10, Outcome::Fail);
    s = step(&c, &s, &[attack, defence]);
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.curve_mass, s.world.curve_mass);
    assert_eq!(pass.shares, s.world.shares);
    // Fee revenue did not refill either curve during the decision.
    assert_eq!(pass.reserve, &reserve - &shortfall + 10u32);
    assert!(pass.reserve < pass.curve_mass);
    assert!(!consensus::pass_beats_fail(pass, &s.world, 0));
    while s.decision_id().is_some() {
        if let Phase::Governance(d) = &s.phase {
            assert_eq!(d.leading_blocks, 0);
        }
        // Each block's fees would have refilled a bent curve before the fix.
        let fee = sign(
            &s,
            &DEFENDER,
            4,
            Operation::TransferExact {
                recipient: key(&DEFENDER),
                amount: 1u32.into(),
            },
        );
        s = step(&c, &s, &[fee]);
    }
    // FAIL won: the grant was not paid and FAIL's shortfall is back in its
    // reserve together with the defender's trade.
    assert!(s.account(&key(&DEFENDER), None).unwrap().shares > Amount::zero());
    assert!(s.account(&key(&ATTACKER), None).unwrap().ordinary < &paid_before + &grant);
    assert!(s.world.grant_escrow.is_zero());
    assert_eq!(s.world.reserve, s.world.curve_mass);
}

/// Audit F010 follow-up. Both outcomes open on the drawn curve, and the
/// largest grant once left one reserve atom in each: every buy was throttled
/// to nothing and sales paid nothing until resolution. A grant now draws at
/// most half of the reserve, so both outcomes stay tradeable.
#[test]
fn the_largest_grant_leaves_both_outcomes_tradeable() {
    let c = config(4, 0);
    let mut s = staked(&c);
    let reserve = s.world.reserve.clone();
    let capacity = consensus::grant_capacity(&s.world);
    let (tx, id) = propose(&s, &ATTACKER, 81, grant(capacity), 1);
    s = step(&c, &s, &[tx]);
    assert!(matches!(&s.phase, Phase::Governance(d) if d.proposal_id == id));
    let pass = s.alternative.as_ref().unwrap();
    assert_eq!(pass.reserve, s.world.reserve);
    assert!(&pass.reserve * 2u32 >= reserve);
    for outcome in [Outcome::Fail, Outcome::Pass] {
        let buyer = s.account(&key(&DEFENDER), Some(outcome)).unwrap();
        let seller = s.account(&key(&ATTACKER), Some(outcome)).unwrap();
        let buy = trade(&s, &DEFENDER, 10_000, outcome);
        let sale = stash(
            &s,
            &ATTACKER,
            Operation::Redeem {
                shares: 1_000u32.into(),
                decision: s.decision_id(),
                outcome: Some(outcome),
            },
        );
        // The seller does not mine, so its cash rises only from the sale.
        s = step_by(&c, &s, &key(&DEFENDER), 0, &[buy, sale]);
        let bought = s.account(&key(&DEFENDER), Some(outcome)).unwrap();
        let sold = s.account(&key(&ATTACKER), Some(outcome)).unwrap();
        assert!(bought.shares > buyer.shares, "{outcome:?} buy filled");
        assert!(sold.ordinary + 4u32 > seller.ordinary, "{outcome:?} sale paid");
    }
}

/// Audit F014. With no Stash outstanding when a decision opened, a one-atom
/// PASS bootstrap deposit beat the empty FAIL world in every observation.
#[test]
fn empty_fail_world_gives_a_one_atom_pass_deposit_no_lead() {
    let c = config(4, 0);
    let mut s = funded(&c);
    assert!(s.world.shares.is_zero());
    let (tx, _) = propose(
        &s,
        &ATTACKER,
        9,
        Proposal::Parameter {
            parameter: Parameter::Lead,
            old: 0,
            new: 15,
        },
        1,
    );
    s = step(&c, &s, &[tx]);
    assert!(s.decision_id().is_some());
    let buy = trade(&s, &ATTACKER, 1, Outcome::Pass);
    s = step(&c, &s, &[buy]);
    assert!(!s.alternative.as_ref().unwrap().shares.is_zero());
    assert!(s.world.shares.is_zero());
    while s.decision_id().is_some() {
        if let Phase::Governance(d) = &s.phase {
            assert_eq!(d.leading_blocks, 0);
        }
        s = step(&c, &s, &[]);
    }
    assert_eq!(s.settings.lead, 0);
    assert!(s.world.shares.is_zero());
}

/// Audit F016 and F160. An unfundable grant with a larger bid used to take the
/// lead, restart the eligible leader's lead period and then be refunded in
/// full. It is now cancelled when it reaches the top and never leads.
#[test]
fn ineligible_top_proposal_is_cancelled_without_resetting_the_leader() {
    let lead = 4 * Config::testnet().initial.interval;
    let c = config(4, lead);
    let mut s = funded(&c);
    let (honest, honest_id) = propose(&s, &ATTACKER, 11, miner_fee(40), 1);
    s = step(&c, &s, &[honest]);
    let (first, since) = leader(&s);
    assert_eq!(first, Some(honest_id));
    s = step(&c, &s, &[]);
    let (griefer, griefer_id) = propose(
        &s,
        &DEFENDER,
        12,
        Proposal::Grant {
            payments: vec![GrantPayment {
                recipient: key(&DEFENDER),
                amount: Amount::from(1u32) << 200usize,
            }],
        },
        2,
    );
    s = step(&c, &s, &[griefer]);
    assert_eq!(leader(&s), (Some(honest_id), since));
    let cancelled = s.proposals.get(&griefer_id).unwrap();
    assert_eq!(cancelled.refund_height, Some(s.height + 1));
    assert!(s.ranking.iter().all(|(_, id)| *id != griefer_id));

    // A broken escrow invariant rejects the refund instead of panicking.
    let refund = sign(
        &s,
        &DEFENDER,
        4,
        Operation::Refund {
            round: 0,
            proposal: griefer_id,
        },
    );
    let mut broken = s.clone();
    broken.auction_escrow = Amount::zero();
    let error = consensus::execute(
        &c,
        &broken,
        &broken.root(),
        &key(&ATTACKER),
        &0u32.into(),
        std::slice::from_ref(&refund),
    )
    .unwrap_err();
    assert!(error.to_string().contains("escrow"), "{error}");
    let cash = s.account(&key(&DEFENDER), None).unwrap().ordinary;
    s = step(&c, &s, &[refund]);
    assert_eq!(
        s.account(&key(&DEFENDER), None).unwrap().ordinary,
        cash + 2u32 - 4u32
    );

    // The eligible leader matures on its original schedule.
    while s.decision_id().is_none() {
        s = step(&c, &s, &[]);
    }
    let Phase::Governance(d) = &s.phase else {
        unreachable!()
    };
    assert_eq!(d.proposal_id, honest_id);
    assert_eq!(d.started, since + lead);
}

/// Audit F016 follow-up. Grants sized at the current capacity outbid the
/// honest leader while eligible. A Redeem then lowers capacity, so both are
/// cancelled in one block and fully refunded. Their interruption used to
/// restart the honest lead period; the honest leader now resumes its own.
#[test]
fn leaders_cancelled_after_a_capacity_drop_do_not_restart_the_lead_they_took() {
    let lead = 4 * Config::testnet().initial.interval;
    let c = config(4, lead);
    let mut s = staked(&c);
    let (honest, honest_id) = propose(&s, &DEFENDER, 51, miner_fee(40), 1);
    s = step(&c, &s, &[honest]);
    let (_, since) = leader(&s);
    let capacity = consensus::grant_capacity(&s.world);
    let (first, first_id) = propose(&s, &ATTACKER, 52, grant(&capacity - 1u32), 2);
    s = step(&c, &s, &[first]);
    assert_eq!(leader(&s), (Some(first_id), s.clock));
    let (second, second_id) = propose(&s, &ATTACKER, 53, grant(capacity), 3);
    s = step(&c, &s, &[second]);
    assert_eq!(leader(&s), (Some(second_id), s.clock));
    let Phase::Auction(a) = &s.phase else {
        unreachable!()
    };
    assert_eq!(a.displaced.len(), 2);

    // A small sale lowers the capacity below both grants.
    let sale = stash(
        &s,
        &ATTACKER,
        Operation::Redeem {
            shares: 1_000u32.into(),
            decision: None,
            outcome: None,
        },
    );
    s = step(&c, &s, &[sale]);
    for id in [first_id, second_id] {
        assert_eq!(s.proposals.get(&id).unwrap().refund_height, Some(s.height + 1));
    }
    assert_eq!(leader(&s), (Some(honest_id), since));
    while s.decision_id().is_none() {
        s = step(&c, &s, &[]);
    }
    let Phase::Governance(d) = &s.phase else {
        unreachable!()
    };
    assert_eq!(d.proposal_id, honest_id);
    assert_eq!(d.started, since + lead);
}

/// A strictly higher bid that is not cancelled still restarts the lead, and
/// the proposal it displaced keeps only its own earlier start on record.
#[test]
fn a_cancelled_leader_hands_the_lead_back_but_a_live_outbid_does_not() {
    let lead = 4 * Config::testnet().initial.interval;
    let c = config(4, lead);
    let mut s = staked(&c);
    let (honest, honest_id) = propose(&s, &DEFENDER, 61, miner_fee(40), 1);
    s = step(&c, &s, &[honest]);
    let (_, since) = leader(&s);
    let (rival, rival_id) = propose(&s, &DEFENDER, 62, miner_fee(30), 2);
    s = step(&c, &s, &[rival]);
    let rival_since = s.clock;
    let capacity = consensus::grant_capacity(&s.world);
    let (griefer, griefer_id) = propose(&s, &ATTACKER, 63, grant(capacity), 3);
    s = step(&c, &s, &[griefer]);
    assert_eq!(leader(&s).0, Some(griefer_id));
    let sale = stash(
        &s,
        &ATTACKER,
        Operation::Redeem {
            shares: 1_000u32.into(),
            decision: None,
            outcome: None,
        },
    );
    s = step(&c, &s, &[sale]);
    // The rival's live outbid of the honest proposal still counts.
    assert_eq!(leader(&s), (Some(rival_id), rival_since));
    let Phase::Auction(a) = &s.phase else {
        unreachable!()
    };
    assert_eq!(a.displaced, vec![(honest_id, since)]);
}

/// A bid that leads at the timeout opens its decision even before its own
/// lead matures. Outbidding every leader just before it matures, from fresh
/// proposals, used to end the round in a timeout with every bid refunded.
#[test]
fn the_leader_at_the_auction_timeout_wins_instead_of_a_refunded_timeout() {
    let interval = Config::testnet().initial.interval;
    let lead = 4 * interval;
    let c = config(4, lead);
    let mut s = funded(&c);
    let (honest, honest_id) = propose(&s, &DEFENDER, 71, miner_fee(40), 1);
    s = step(&c, &s, &[honest]);
    let (mut support, mut last, mut last_since) = (1, honest_id, leader(&s).1);
    while s.decision_id().is_none() {
        assert!(matches!(s.phase, Phase::Auction(_)), "the round timed out");
        if s.clock + interval - last_since < lead {
            s = step(&c, &s, &[]);
            continue;
        }
        // Outbid the leader in the block where it would have matured.
        support += 1;
        let (tx, id) = propose(&s, &ATTACKER, 71 + support as u8, miner_fee(30), support);
        s = step(&c, &s, &[tx]);
        if s.decision_id().is_none() {
            assert_eq!(leader(&s), (Some(id), s.clock));
        }
        (last, last_since) = (id, s.clock);
    }
    let Phase::Governance(d) = &s.phase else {
        unreachable!()
    };
    assert_eq!(d.proposal_id, last);
    assert_ne!(last, honest_id);
    assert_eq!(d.started, c.auction_timeout);
    assert!(d.started - last_since < lead);
    assert!(matches!(
        s.rounds.get(&0u64.to_be_bytes()).unwrap().status,
        RoundStatus::Won(id) if id == last
    ));
}

/// Audit F046. Proposal and support records are never pruned, yet a
/// Parameter proposal and a new support record paid only their byte weight,
/// less per permanent record than creating an account.
#[test]
fn new_governance_records_pay_record_weight() {
    let c = config(4, 4 * Config::testnet().initial.interval);
    let s = funded(&c);
    let rate = Amount::from(c.initial.minimum_fee_rate);
    let (tx, id) = propose(&s, &ATTACKER, 91, miner_fee(40), 1);
    let quote = fees::quote(&c, &s, &tx).unwrap();
    let bytes = codec::encode(&tx).len() as u64;
    assert_eq!(quote.weight, bytes + fees::RECORD_WEIGHT);
    assert_eq!(quote.record_fee, rate);
    // A fee that covers only the bytes no longer suffices.
    let mut cheap = tx.clone();
    cheap.body.fee = (Amount::from(bytes) * &rate + Amount::from(fees::FEE_SCALE - 1))
        / Amount::from(fees::FEE_SCALE);
    let cheap = crypto::sign(&cheap.body, &ATTACKER).unwrap();
    assert!(consensus::execute(&c, &s, &s.root(), &key(&ATTACKER), &0u32.into(), &[cheap]).is_err());
    let s = step(&c, &s, &[tx]);
    // A new supporter creates a record; the proposer adds to its own.
    for (secret, record) in [(&DEFENDER, true), (&ATTACKER, false)] {
        let tx = sign(
            &s,
            secret,
            4,
            Operation::Support {
                round: 0,
                proposal: id,
                amount: 1u32.into(),
            },
        );
        let quote = fees::quote(&c, &s, &tx).unwrap();
        let bytes = codec::encode(&tx).len() as u64;
        let weight = if record { fees::RECORD_WEIGHT } else { 0 };
        assert_eq!(quote.weight, bytes + weight);
        assert_eq!(quote.record_fee.is_zero(), !record);
    }
}

/// Audit F109: ties keep the incumbent, otherwise the smallest proposal ID
/// leads; a strictly higher bid restarts the lead period.
#[test]
fn equal_bids_keep_the_incumbent_or_choose_the_smallest_id() {
    let c = config(4, 4 * Config::testnet().initial.interval);
    let mut s = funded(&c);
    let (a, a_id) = propose(&s, &ATTACKER, 21, miner_fee(40), 5);
    let (b, b_id) = propose(&s, &DEFENDER, 22, miner_fee(30), 5);
    s = step(&c, &s, &[a, b]);
    let (first, since) = leader(&s);
    let (small, large) = if a_id < b_id {
        (a_id, b_id)
    } else {
        (b_id, a_id)
    };
    assert_eq!(first, Some(small));
    s = step(&c, &s, &[]);
    // A later equal bid does not displace the incumbent, whatever its ID.
    let (c_tx, _) = propose(&s, &ATTACKER, 23, miner_fee(20), 5);
    s = step(&c, &s, &[c_tx]);
    assert_eq!(leader(&s), (Some(small), since));
    let raise = sign(
        &s,
        if large == a_id { &ATTACKER } else { &DEFENDER },
        4,
        Operation::Support {
            round: 0,
            proposal: large,
            amount: 1u32.into(),
        },
    );
    s = step(&c, &s, &[raise]);
    assert_eq!(leader(&s), (Some(large), s.clock));
}

/// Audit F179/F108: the decision ID uses only branch-stable inputs, so a
/// same-parent sibling with another miner and transaction set opens the same
/// decision, and the ID is computable before the opening block exists.
#[test]
fn same_parent_siblings_open_the_same_decision_id() {
    let c = config(4, 0);
    let s = funded(&c);
    let (tx, id) = propose(&s, &ATTACKER, 31, miner_fee(40), 1);
    let extra = sign(
        &s,
        &DEFENDER,
        4,
        Operation::TransferExact {
            recipient: key(&DEFENDER),
            amount: 1u32.into(),
        },
    );
    let a = step_by(&c, &s, &key(&ATTACKER), 0, std::slice::from_ref(&tx));
    let b = step_by(&c, &s, &key(&DEFENDER), 7, &[extra, tx]);
    assert_ne!(a.root(), b.root());
    assert_eq!(a.decision_id(), b.decision_id());
    let parent = s.root();
    let expected = crypto::tagged_hash(
        "Hashstash/decision",
        &codec::encode(&(s.chain_id, 0u64, id, s.height + 1, parent)),
    );
    assert_eq!(a.decision_id(), Some(expected));
}

/// Audit F158: common credits require the same account existence and nonce
/// in both outcomes instead of creating a fresh nonce-zero copy.
#[test]
fn common_credit_rejects_account_existence_divergence() {
    let c = config(4, 0);
    let s = funded(&c);
    let (tx, _) = propose(&s, &ATTACKER, 41, miner_fee(40), 1);
    let mut s = step(&c, &s, &[tx]);
    assert!(s.decision_id().is_some());
    let stray = key(&[63; 32]);
    s.world.put(stray, Account::default(), &c).unwrap();
    s.validate(&c).unwrap();
    let error = consensus::execute(&c, &s, &s.root(), &stray, &1u32.into(), &[]).unwrap_err();
    assert!(error.to_string().contains("differs"), "{error}");
}

/// Audit F012 defence in depth: an unrepresentable rest deadline postpones
/// the next auction instead of invalidating every block at that height.
#[test]
fn unrepresentable_rest_after_timeout_keeps_blocks_valid() {
    let c = config(4, 0);
    let mut s = funded(&c);
    s.settings.rest = u64::MAX - 100;
    s.frozen.rest = s.settings.rest;
    s.audit(&c).unwrap();
    for _ in 0..64 {
        if matches!(s.phase, Phase::Rest(_)) {
            break;
        }
        s = step(&c, &s, &[]);
    }
    assert!(matches!(&s.phase, Phase::Rest(r) if r.until == u64::MAX));
    for _ in 0..3 {
        s = step(&c, &s, &[]);
    }
    assert!(matches!(s.phase, Phase::Rest(_)));
}
