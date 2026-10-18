//! Genesis has arithmetic/construction bounds, not policy grids. Governed
//! changes add only the bounds that keep a passed change reversible.
use hashstash::{
    codec,
    config::{
        Config, MAX_GOVERNED_BLOCK_BYTES, MAX_GOVERNED_DURATION, MAX_GOVERNED_PRICE_CHANGE_BPS,
        MAX_MINIMAL_PROPOSE_BYTES, MIN_GOVERNED_BLOCK_BYTES, MIN_GOVERNED_DECISION_BLOCKS,
    },
    consensus, crypto, fees, math,
    state::{Phase, State, proposal_id},
    types::{Amount, Operation, Parameter, Proposal, PublicKey, Transaction, TransactionBody},
};

#[test]
fn block_capacity_stays_within_the_proposal_floor_and_storage_ceiling() {
    // Audit R01/R05: the old 1,024 floor admitted capacities that no Propose
    // could fit, and the old ceiling (isize::MAX) admitted blocks no peer
    // frame or SQLite row could carry.
    let c = Config::testnet();
    for (old, new) in [
        (MIN_GOVERNED_BLOCK_BYTES * 2, MIN_GOVERNED_BLOCK_BYTES),
        (MIN_GOVERNED_BLOCK_BYTES + 1, MIN_GOVERNED_BLOCK_BYTES),
        (MIN_GOVERNED_BLOCK_BYTES, MIN_GOVERNED_BLOCK_BYTES * 2),
        (16_384, 12_345),
        (MAX_GOVERNED_BLOCK_BYTES / 2, MAX_GOVERNED_BLOCK_BYTES),
        (MAX_GOVERNED_BLOCK_BYTES, MAX_GOVERNED_BLOCK_BYTES / 2),
    ] {
        let mut settings = c.initial.clone();
        settings.block_bytes = old;
        c.parameter_change(&settings, Parameter::BlockBytes, old, new)
            .unwrap();
        settings.block_bytes = new;
        assert_eq!(c.transaction_bytes(&settings), new as usize);
    }
    for (old, new) in [
        // Below the floor, even within one halving.
        (MIN_GOVERNED_BLOCK_BYTES, MIN_GOVERNED_BLOCK_BYTES / 2),
        (MIN_GOVERNED_BLOCK_BYTES + 1, MIN_GOVERNED_BLOCK_BYTES - 1),
        (MIN_GOVERNED_BLOCK_BYTES, 2_300),
        (MIN_GOVERNED_BLOCK_BYTES, 1_100),
        (MIN_GOVERNED_BLOCK_BYTES, 0),
        // Above the ceiling, even within one doubling.
        (MAX_GOVERNED_BLOCK_BYTES, MAX_GOVERNED_BLOCK_BYTES + 1),
        (MAX_GOVERNED_BLOCK_BYTES, isize::MAX as u64),
        (MAX_GOVERNED_BLOCK_BYTES, u64::MAX),
        // More than one doubling or halving.
        (16_384, 32_769),
        (16_384, 8_191),
        (16_384, MAX_GOVERNED_BLOCK_BYTES),
    ] {
        let mut settings = c.initial.clone();
        settings.block_bytes = old;
        assert!(
            c.parameter_change(&settings, Parameter::BlockBytes, old, new)
                .is_err(),
            "{old} -> {new} must be rejected"
        );
    }
    let settings = &c.initial;
    assert!(
        c.parameter_change(settings, Parameter::BlockBytes, 8_192, 16_384)
            .is_err()
    );
    assert!(
        c.parameter_change(
            settings,
            Parameter::BlockBytes,
            settings.block_bytes,
            settings.block_bytes
        )
        .is_err()
    );
    // Genesis has the same floor and ceiling.
    for (bytes, valid) in [
        (MIN_GOVERNED_BLOCK_BYTES - 1, false),
        (MIN_GOVERNED_BLOCK_BYTES, true),
        (MAX_GOVERNED_BLOCK_BYTES, true),
        (MAX_GOVERNED_BLOCK_BYTES + 1, false),
    ] {
        let mut config = c.clone();
        config.initial.block_bytes = bytes;
        assert_eq!(config.validate().is_ok(), valid, "{bytes}");
    }
    let mut config = c;
    config.max_signatures = usize::MAX;
    config.validate().unwrap();
    config.max_signatures = 0;
    config.validate().unwrap();
}

/// The largest data-free Support: compact u64 nonce, expiry and round at 9
/// bytes, fee and support amounts at 64 bytes plus their lengths, the
/// proposal hash and the fixed signature.
const MAX_MINIMAL_SUPPORT_BYTES: u64 = 32 + 9 + 65 + 32 + 9 + (1 + 9 + 32 + 65) + 1 + 64;

/// Sign an executable transaction padded with data to a worst-case size.
fn padded(s: &State, secret: &[u8; 32], operation: Operation, encoded_bytes: u64) -> Transaction {
    let sender = crypto::public_key(secret).unwrap();
    let mut body = TransactionBody {
        sender,
        nonce: s.account(&sender, None).unwrap().nonce,
        fee: 100u32.into(),
        anchor: [0; 32],
        expiry_blocks: 100,
        operation,
        data: Vec::new(),
    };
    let size = |body: &TransactionBody| {
        codec::encode(&Transaction {
            body: body.clone(),
            signature: [0; 64],
        })
        .len() as u64
    };
    body.data = vec![0; usize::try_from(encoded_bytes - size(&body)).unwrap()];
    // Data beyond 250 bytes takes a wider length prefix.
    let excess = size(&body) - encoded_bytes;
    body.data
        .truncate(body.data.len() - usize::try_from(excess).unwrap());
    let tx = crypto::sign(&s.chain_id, &body, secret).unwrap();
    assert_eq!(codec::encode(&tx).len() as u64, encoded_bytes);
    tx
}

#[test]
fn a_floor_capacity_block_holds_the_heaviest_minimal_proposal_and_support_with_a_new_miner() {
    // Audit R01: below about 2,400 weight a block that reserved its new
    // miner's account had no room left for any Propose, so one passed
    // decision lowering capacity there (the old floor was 1,024) could never
    // be undone. The floor now covers the heaviest data-free Propose.
    let mut c = Config::testnet();
    c.initial.block_bytes = MIN_GOVERNED_BLOCK_BYTES;
    c.initial.rest = 0;
    c.validate().unwrap();
    let key = |secret: &[u8; 32]| -> PublicKey { crypto::public_key(secret).unwrap() };
    let (proposer, supporter, miner) = ([41; 32], [42; 32], key(&[43; 32]));
    let subsidy = Amount::from(1_000_000u32);
    let mut s = State::genesis(&c);
    for funded in [&proposer, &supporter] {
        s = consensus::execute(&c, &s, &s.root(), &key(funded), &subsidy, &[]).unwrap();
    }
    let round = s.auction_round().unwrap();
    let proposal = Proposal::Parameter {
        parameter: Parameter::BlockBytes,
        old: MIN_GOVERNED_BLOCK_BYTES,
        new: MIN_GOVERNED_BLOCK_BYTES * 2,
    };
    let operation = Operation::Propose {
        round,
        description: [44; 32],
        proposal: proposal.clone(),
        support: 10u32.into(),
    };
    let propose = padded(&s, &proposer, operation.clone(), MAX_MINIMAL_PROPOSE_BYTES);
    let id = proposal_id(&s.chain_id, round, &key(&proposer), &[44; 32], &proposal);
    let support = padded(
        &s,
        &supporter,
        Operation::Support {
            round,
            proposal: id,
            amount: 10u32.into(),
        },
        MAX_MINIMAL_SUPPORT_BYTES,
    );
    let mut proposed = s.clone();
    consensus::apply_transaction(&c, &mut proposed, &propose).unwrap();
    let propose_weight = fees::quote(&c, &s, &propose).unwrap().weight;
    assert_eq!(
        propose_weight,
        MAX_MINIMAL_PROPOSE_BYTES + fees::RECORD_WEIGHT
    );
    assert_eq!(
        fees::quote(&c, &proposed, &support).unwrap().weight,
        MAX_MINIMAL_SUPPORT_BYTES + fees::RECORD_WEIGHT
    );
    assert!(s.account(&miner, None).is_none());
    // Each alone, and both together, beside the new miner's account.
    for (parent, transactions) in [
        (&s, vec![propose.clone()]),
        (&proposed, vec![support.clone()]),
        (&s, vec![propose.clone(), support]),
    ] {
        let next = consensus::execute(&c, parent, &parent.root(), &miner, &subsidy, &transactions)
            .unwrap();
        next.audit(&c).unwrap();
        assert!(next.account(&miner, None).is_some());
        assert!(next.proposals.get(&id).is_some());
    }
    // The remaining room is exact: a Propose filling it with data still fits
    // beside the new miner account, and one byte more does not.
    let room = MIN_GOVERNED_BLOCK_BYTES.saturating_sub(fees::RECORD_WEIGHT + fees::ACCOUNT_WEIGHT);
    assert!(room > MAX_MINIMAL_PROPOSE_BYTES);
    for (bytes, fits) in [(room, true), (room + 1, false)] {
        let tx = padded(&s, &proposer, operation.clone(), bytes);
        let result = consensus::execute(&c, &s, &s.root(), &miner, &subsidy, &[tx]);
        if fits {
            result.unwrap();
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("weighted capacity")
            );
        }
    }
}

#[test]
fn sqlite_rows_hold_the_largest_valid_block_record() {
    // Audit R05: a block above SQLite's row length limit would fail to store
    // even on the node that mined it. Chain::open runs this probe, which
    // checks the limit without allocating the blob.
    let db = rusqlite::Connection::open_in_memory().unwrap();
    let probe = |bytes: u64| {
        db.query_row("SELECT length(zeroblob(?1))", [bytes], |row| {
            row.get::<_, i64>(0)
        })
    };
    let largest = hashstash::chain::MAX_BLOCK_ROW_BYTES;
    assert_eq!(probe(largest).unwrap(), largest as i64);
    assert!(probe(1_000_000_001).is_err());
}

#[test]
fn parameters_accept_direct_values_and_zero_where_defined() {
    let c = Config::testnet();
    // A leader from the first half of a round must still be able to mature.
    let longest_lead = (c.auction_timeout - c.initial.interval) / 2;
    for (parameter, next) in [
        (Parameter::Lead, 3),
        (Parameter::Lead, 0),
        (Parameter::Lead, longest_lead),
        (Parameter::Rest, 7),
        (Parameter::Rest, 0),
        (Parameter::Rest, MAX_GOVERNED_DURATION),
        (Parameter::DecisionBlocks, 17),
        (Parameter::DecisionBlocks, MIN_GOVERNED_DECISION_BLOCKS),
        (
            Parameter::DecisionBlocks,
            MAX_GOVERNED_DURATION / c.initial.interval,
        ),
        (Parameter::Interval, 30),
        (Parameter::Interval, 7),
        (Parameter::BlockBytes, 32_768),
        (Parameter::BlockBytes, 8_192),
        (Parameter::MinimumFeeRate, 2),
        (Parameter::MaxPriceChangeBps, 1),
        (Parameter::MaxPriceChangeBps, MAX_GOVERNED_PRICE_CHANGE_BPS),
    ] {
        c.parameter_change(&c.initial, parameter, c.initial.get(parameter), next)
            .unwrap();
        let mut changed = c.clone();
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
    }
    for parameter in [Parameter::Interval, Parameter::DecisionBlocks] {
        assert!(
            c.parameter_change(&c.initial, parameter, c.initial.get(parameter), 0)
                .is_err()
        );
    }
    // Governance cannot select a value that no later decision could undo,
    // although genesis may still start with any representable value.
    for (parameter, next) in [
        // The first observation ties, so PASS could never reach a majority.
        (Parameter::DecisionBlocks, 1),
        (Parameter::DecisionBlocks, 2),
        // Phases that outlast any practical revision.
        (
            Parameter::DecisionBlocks,
            MAX_GOVERNED_DURATION / c.initial.interval + 1,
        ),
        (Parameter::Lead, longest_lead + 1),
        (Parameter::Lead, c.auction_timeout * 8),
        (Parameter::Rest, MAX_GOVERNED_DURATION + 1),
        (Parameter::Rest, u64::MAX - 1),
        // A step beyond the ASERT half life starves the next target.
        (Parameter::Interval, c.daa_half_life + 1),
        (Parameter::Interval, c.daa_half_life),
        (Parameter::Interval, c.auction_timeout - 2 * c.initial.lead + 1),
        (Parameter::Interval, 86_400),
        (Parameter::Interval, 1 << 40),
        // One decision at most doubles or halves capacity and block rate.
        (Parameter::Interval, 31),
        (Parameter::Interval, 6),
        (Parameter::Interval, 1),
        (Parameter::BlockBytes, 32_769),
        (Parameter::BlockBytes, 8_191),
        // Pinned prices can never produce a PASS lead, and an unbounded fall
        // lets one holder empty a world and suppress PASS leads.
        (Parameter::MaxPriceChangeBps, 0),
        (
            Parameter::MaxPriceChangeBps,
            MAX_GOVERNED_PRICE_CHANGE_BPS + 1,
        ),
        (Parameter::MaxPriceChangeBps, u64::MAX),
        // One decision cannot price every account out of transacting, and a
        // zero rate makes permanent account and record state free.
        (Parameter::MinimumFeeRate, 3),
        (Parameter::MinimumFeeRate, u64::MAX),
        (Parameter::MinimumFeeRate, 0),
    ] {
        assert!(
            c.parameter_change(&c.initial, parameter, c.initial.get(parameter), next)
                .is_err(),
            "{parameter:?} = {next} must be rejected"
        );
        let mut changed = c.clone();
        changed.initial.set(parameter, next);
        changed.validate().unwrap();
    }
    let mut free = c.initial.clone();
    free.minimum_fee_rate = 0;
    c.parameter_change(&free, Parameter::MinimumFeeRate, 0, 1)
        .unwrap();
    assert!(
        c.parameter_change(&free, Parameter::MinimumFeeRate, 0, 2)
            .is_err()
    );
    let mut lead = c.initial.clone();
    lead.lead = c.auction_timeout * 8;
    assert_eq!(
        c.auction_timeout_for(&lead).unwrap(),
        lead.lead + lead.interval
    );
    lead.lead = u64::MAX;
    assert!(c.validate_governance_settings(&lead).is_err());
}

#[test]
fn fee_rate_increases_stop_at_a_bounded_multiple_of_genesis_and_revert_in_one_decision() {
    // Audit R05: doublings compounded without limit, until the Propose that
    // would revert them was unaffordable.
    for genesis in [0, 1, 7] {
        let mut c = Config::testnet();
        c.initial.minimum_fee_rate = genesis;
        c.validate().unwrap();
        let ceiling = c.max_governed_fee_rate();
        assert_eq!(ceiling, genesis.max(1) << 16);
        let mut settings = c.initial.clone();
        let mut decisions = 0;
        while settings.minimum_fee_rate < ceiling {
            let old = settings.minimum_fee_rate;
            let next = old.saturating_mul(2).clamp(1, ceiling);
            c.parameter_change(&settings, Parameter::MinimumFeeRate, old, next)
                .unwrap();
            settings.minimum_fee_rate = next;
            decisions += 1;
        }
        assert!(decisions >= 16);
        assert!(
            c.parameter_change(&settings, Parameter::MinimumFeeRate, ceiling, ceiling + 1)
                .is_err()
        );
        // One decision returns all the way down, but never to a free rate.
        for back in [genesis.max(1), 1] {
            c.parameter_change(&settings, Parameter::MinimumFeeRate, ceiling, back)
                .unwrap();
        }
        assert!(
            c.parameter_change(&settings, Parameter::MinimumFeeRate, ceiling, 0)
                .is_err()
        );
    }
}

#[test]
fn governed_intervals_move_by_one_doubling_or_halving_above_a_quarter_of_genesis() {
    // Audit R05: one decision could select one-second blocks, multiplying
    // chain growth, orphan risk and per-block state churn fifteen times.
    let c = Config::testnet();
    assert_eq!(c.min_governed_interval(), c.initial.interval / 4);
    let mut settings = c.initial.clone();
    settings.interval = 5;
    c.parameter_change(&settings, Parameter::Interval, 5, 3)
        .unwrap();
    for below in [2, 1] {
        assert!(
            c.parameter_change(&settings, Parameter::Interval, 5, below)
                .is_err()
        );
    }
    // A one-second genesis interval keeps a one-second floor.
    let mut fast = Config::testnet();
    fast.initial.interval = 1;
    fast.validate().unwrap();
    assert_eq!(fast.min_governed_interval(), 1);
    fast.parameter_change(&fast.initial, Parameter::Interval, 1, 2)
        .unwrap();
    // The lead room still bounds an increase within one doubling.
    settings.interval = 181;
    c.parameter_change(&settings, Parameter::Interval, 181, 360)
        .unwrap();
    assert!(
        c.parameter_change(&settings, Parameter::Interval, 181, 361)
            .is_err()
    );
}

#[test]
fn interval_increases_recheck_the_lead_and_decision_bounds() {
    // Audit F028: two separately valid decisions must not combine into a lead
    // that a late leader cannot reach or a decision far beyond 2^22 seconds.
    let c = Config::devnet();
    let interval = c.initial.interval;
    let mut lead = c.initial.clone();
    lead.lead = (c.auction_timeout - interval) / 2;
    c.parameter_change(&c.initial, Parameter::Lead, c.initial.lead, lead.lead)
        .unwrap();
    let mut decision = c.initial.clone();
    decision.decision_blocks = MAX_GOVERNED_DURATION / interval;
    c.parameter_change(
        &c.initial,
        Parameter::DecisionBlocks,
        c.initial.decision_blocks,
        decision.decision_blocks,
    )
    .unwrap();
    for settings in [&lead, &decision] {
        for longer in [interval + 2, 900] {
            assert!(
                c.parameter_change(settings, Parameter::Interval, interval, longer)
                    .is_err(),
                "{longer}"
            );
        }
        // A shorter interval only helps, so settings outside the bounds can
        // still move back toward them.
        c.parameter_change(settings, Parameter::Interval, interval, interval / 2)
            .unwrap();
    }
    // The same longer interval is fine with the default lead and decision.
    c.parameter_change(&c.initial, Parameter::Interval, interval, interval + 2)
        .unwrap();
}

#[test]
fn deadlines_are_checked_through_the_whole_height_range() {
    let c = Config::testnet();
    let settings = &c.initial;
    let decision = 100;
    let mut changed = settings.clone();
    changed.decision_blocks = decision;
    // Every later block can add one interval before a deadline is computed,
    // so the activation clock must leave room for the whole height range.
    let span = settings.interval * c.max_height
        + c.auction_timeout_for(&changed).unwrap()
        + decision * settings.interval
        + settings.rest
        + 2 * settings.interval;
    let latest = u64::MAX - span;
    let change = |clock, height| {
        c.parameter_change_at(
            settings,
            Parameter::DecisionBlocks,
            settings.decision_blocks,
            decision,
            clock,
            height,
        )
    };
    change(latest, 0).unwrap();
    assert!(change(latest + 1, 0).is_err());
    // The same value is valid without a clock, then stale late in the range.
    c.parameter_change(
        settings,
        Parameter::DecisionBlocks,
        settings.decision_blocks,
        decision,
    )
    .unwrap();
    assert!(change(latest + settings.interval, 0).is_err());
    // Audit F012: only the remaining heights add clock. Each block advances
    // both, so the same change stays valid on its schedule.
    for height in [1, 1_000, c.max_height] {
        let clock = latest + settings.interval * height;
        change(clock, height).unwrap();
        assert!(change(clock + 1, height).is_err());
    }
}

#[test]
fn a_clock_range_shorter_than_the_height_range_still_allows_governance() {
    // Audit F012: interval * max_height overflowed for every interval above
    // one, so this valid genesis rejected every parameter proposal.
    let mut c = Config::testnet();
    c.max_height = i64::MAX as u64;
    c.validate().unwrap();
    let s = &c.initial;
    for (parameter, new) in [
        (Parameter::MinerFeePercent, 40),
        (Parameter::PassMarginBps, 100),
        (Parameter::Rest, s.rest - 1),
        (Parameter::Interval, s.interval - 1),
        (Parameter::DecisionBlocks, s.decision_blocks - 1),
    ] {
        c.parameter_change_at(s, parameter, s.get(parameter), new, 15, 1)
            .unwrap();
    }
    // A change may not reach further past the clock range than now.
    for (parameter, new) in [
        (Parameter::Rest, s.rest + 1),
        (Parameter::Interval, s.interval + 1),
        (Parameter::DecisionBlocks, s.decision_blocks + 1),
    ] {
        let error = c
            .parameter_change_at(s, parameter, s.get(parameter), new, 15, 1)
            .unwrap_err();
        assert!(
            error.to_string().contains("overflow before the height limit"),
            "{parameter:?}: {error}"
        );
    }
}

#[test]
fn rest_cannot_reach_the_deadline_overflow_window_after_activation() {
    // Audit F012: a Rest checked only at its activation clock A could lie in
    // (u64::MAX - A - timeout, u64::MAX - A]. The next auction then timed out
    // into an unrepresentable rest and every candidate block was invalid.
    let c = Config::testnet();
    let settings = &c.initial;
    let activation = 1_000_000;
    let timeout = c.auction_timeout_for(settings).unwrap();
    for rest in [
        u64::MAX - activation,
        u64::MAX - activation - timeout,
        MAX_GOVERNED_DURATION + 1,
    ] {
        let mut changed = settings.clone();
        changed.rest = rest;
        // The former single-clock check accepted every one of these.
        c.validate_governance_settings_at(&changed, activation)
            .unwrap();
        assert!(
            c.parameter_change_at(settings, Parameter::Rest, settings.rest, rest, activation, 0)
                .is_err()
        );
    }
    c.parameter_change_at(
        settings,
        Parameter::Rest,
        settings.rest,
        MAX_GOVERNED_DURATION,
        activation,
        0,
    )
    .unwrap();
}

#[test]
fn decision_block_count_can_be_one() {
    let c = Config::testnet();
    for duration in [1, c.initial.interval - 1, c.initial.interval] {
        let mut changed = c.clone();
        changed.initial.decision_blocks = duration;
        changed.validate().unwrap();
    }
    c.parameter_change(
        &c.initial,
        Parameter::Interval,
        c.initial.interval,
        c.initial.decision_blocks + 1,
    )
    .unwrap();
}

#[test]
fn pass_margin_genesis_supports_every_u64_value_and_governed_margins_stay_reachable() {
    let c = Config::testnet();
    // PASS must lead from observation ceil(N/2), after ceil(N/2)-1 traded
    // blocks that can each move the price by at most MaxPriceChangeBps.
    let reachable = (c.initial.decision_blocks.div_ceil(2) - 1) * c.initial.max_price_change_bps;
    for margin in [1, 123, reachable - 1] {
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, margin)
            .unwrap();
    }
    for margin in [reachable, 10_000, 100_000, u64::MAX] {
        assert!(
            c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, margin)
                .is_err()
        );
    }
    // Shortening the decision or tightening the bound cannot strand a margin.
    let mut wide = c.initial.clone();
    wide.pass_margin_bps = Some(reachable - 1);
    for (parameter, next) in [
        (Parameter::DecisionBlocks, c.initial.decision_blocks - 2),
        (
            Parameter::MaxPriceChangeBps,
            c.initial.max_price_change_bps - 1,
        ),
    ] {
        assert!(
            c.parameter_change(&wide, parameter, wide.get(parameter), next)
                .is_err()
        );
    }
    for margin in [1, 123, 10_000, 100_000, u64::MAX] {
        let mut changed = c.clone();
        changed.initial.pass_margin_bps = Some(margin);
        changed.validate().unwrap();
        assert_ne!(changed.chain_id(), c.chain_id());
        let mut state = State::genesis(&c);
        let root = state.root();
        state.settings.pass_margin_bps = Some(margin);
        assert_ne!(state.root(), root);
        state.settings = c.initial.clone();
        state.frozen.pass_margin_bps = Some(margin);
        assert_ne!(state.root(), root);
    }
    assert!(
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 1, 2)
            .is_err()
    );
    assert!(
        c.parameter_change(&c.initial, Parameter::PassMarginBps, 0, 0)
            .is_err()
    );
    let mut missing = c.clone();
    missing.initial.pass_margin_bps = None;
    assert!(missing.validate().is_err());
}

#[test]
fn state_validation_and_audit_accept_governed_settings_outside_all_old_grids() {
    let c = Config::testnet();
    let mut state = State::genesis(&c);
    state.settings.block_bytes = 8 * 1024 * 1024;
    state.settings.lead = 1 << 20;
    state.settings.rest = 1 << 21;
    state.settings.decision_blocks = 4096;
    state.settings.pass_margin_bps = Some(u64::MAX);
    state.frozen = state.settings.clone();

    state.audit(&c).unwrap();
    state.settings.block_bytes = 1;
    assert!(state.validate(&c).is_err());
}

#[test]
fn auction_audit_uses_the_same_extended_timeout_as_consensus() {
    for mut c in [Config::testnet()] {
        c.initial.lead = c.auction_timeout * 2;
        c.validate().unwrap();
        let miner = crypto::public_key(&[7; 32]).unwrap();
        let subsidy = math::work(&math::target_from_bits(c.initial_bits).unwrap());
        let mut state = State::genesis(&c);
        for _ in 0..256 {
            if matches!(state.phase, Phase::Auction(_)) {
                break;
            }
            state = consensus::execute(&c, &state, &[0; 32], &miner, &subsidy, &[]).unwrap();
            state.audit(&c).unwrap();
        }
        let Phase::Auction(auction) = &state.phase else {
            panic!("initial rest did not finish")
        };
        let opened = auction.opened;
        let timeout = c.auction_timeout_for(&state.frozen).unwrap();
        assert!(timeout > c.auction_timeout);
        for elapsed in (c.initial.interval..=timeout).step_by(c.initial.interval as usize) {
            state = consensus::execute(&c, &state, &[0; 32], &miner, &subsidy, &[]).unwrap();
            assert_eq!(state.clock - opened, elapsed);
            state.audit(&c).unwrap();
            if elapsed < timeout {
                assert!(matches!(state.phase, Phase::Auction(_)));
            } else {
                assert!(matches!(state.phase, Phase::Rest(_)));
            }
        }
    }
}
