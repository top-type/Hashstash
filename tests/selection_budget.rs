#[path = "support/curved.rs"]
mod curved;
mod support;
use hashstash::{
    chain::{
        Chain, MAX_CACHED_INVALID_BLOCKS, MAX_SELECTION_CANDIDATES,
        SELECTION_ATTEMPTS_PER_CANDIDATE,
    },
    codec,
    config::Config,
    crypto,
    types::*,
};

const SECRET: [u8; 32] = [61; 32];
fn key() -> PublicKey {
    crypto::public_key(&SECRET).unwrap()
}
fn configuration() -> Config {
    let mut c = Config::devnet();
    c.initial_bits = 0x1f1fffff;
    c.limit_bits = c.initial_bits;
    c.initial.block_bytes = 262144;
    c
}
fn append(chain: &mut Chain, transactions: Vec<Transaction>) -> Block {
    let time = chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
    let block = Chain::mine(chain.template(key(), transactions, time).unwrap(), 100_000).unwrap();
    chain.submit(block.clone(), time as u64).unwrap();
    chain.tip_state().audit(&chain.config).unwrap();
    block
}
fn signed(
    chain: &Chain,
    secret: &[u8; 32],
    nonce: u64,
    operation: Operation,
    expiry_offset: u64,
) -> Transaction {
    support::sign_minimum(
        chain.tip_state(),
        TransactionBody {
            data: Vec::new(),
            sender: crypto::public_key(secret).unwrap(),
            nonce,
            fee: 100u32.into(),
            anchor: hashstash::codec::block_hash(
                &hashstash::codec::genesis_block(&chain.config).unwrap(),
            ),
            expiry_blocks: chain.tip_height() + 10_000 + expiry_offset,
            operation,
        },
        secret,
        0,
    )
}
fn self_payment(chain: &Chain, secret: &[u8; 32], nonce: u64) -> Transaction {
    signed(
        chain,
        secret,
        nonce,
        Operation::TransferExact {
            recipient: crypto::public_key(secret).unwrap(),
            amount: 1u32.into(),
        },
        0,
    )
}

#[test]
fn reversed_nonce_chain_uses_one_signature_and_operation_per_transaction() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("chain.db"), configuration()).unwrap();
    append(&mut chain, vec![]);
    let ordered: Vec<_> = (0..256)
        .map(|nonce| self_payment(&chain, &SECRET, nonce))
        .collect();
    let reverse: Vec<_> = ordered.iter().rev().cloned().collect();
    let time = chain.tip_block().header.timestamp + 2;
    let (chosen, selected_block) = chain.select_template(key(), &reverse, 256, time).unwrap();
    assert_eq!(chosen.transactions, ordered);
    assert_eq!(chosen.signatures_checked, 256);
    assert_eq!(chosen.execution_attempts, 256);
    assert!(!chosen.budget_exhausted);
    let expected_block = chain.template(key(), ordered, time).unwrap();
    assert_eq!(selected_block, expected_block);
    assert!(
        codec::body_size(&selected_block).unwrap()
            < chain.tip_state().settings.block_bytes as usize
    );
    let mined = Chain::mine(selected_block, 100_000).unwrap();
    chain.submit(mined, time as u64).unwrap();
    chain.tip_state().audit(&chain.config).unwrap();
}

#[test]
fn newly_ready_priority_candidate_precedes_unrelated_entries_at_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("priority.db"), configuration()).unwrap();
    for _ in 0..3 {
        append(&mut chain, vec![]);
    }
    let other_secret = [63; 32];
    let create = signed(
        &chain,
        &SECRET,
        0,
        Operation::TransferExact {
            recipient: crypto::public_key(&other_secret).unwrap(),
            // Cover principal and fees for every opening-balance commitment.
            amount: 600u32.into(),
        },
        0,
    );
    append(&mut chain, vec![create]);
    // The pending transaction needs a detached predecessor. There is enough
    // unrelated recovered traffic to fill the pool before a second full pass.
    // Give both dependency transactions actual miner-fee priority: minimum
    // one-atom fees all round to zero miner revenue and then sort by txid.
    let mut pending_body = self_payment(&chain, &SECRET, 2).body;
    pending_body.fee = 5u32.into();
    let pending = crypto::sign(&chain.chain_id(), &pending_body, &SECRET).unwrap();
    let mut predecessor_body = self_payment(&chain, &SECRET, 1).body;
    predecessor_body.fee = 3u32.into();
    let predecessor = crypto::sign(&chain.chain_id(), &predecessor_body, &SECRET).unwrap();
    let unrelated: Vec<_> = (0..255)
        .map(|nonce| self_payment(&chain, &other_secret, nonce))
        .collect();
    let quote = |tx| hashstash::fees::quote(&chain.config, chain.tip_state(), tx).unwrap();
    let pending_quote = quote(&pending);
    let predecessor_quote = quote(&predecessor);
    assert!(
        &pending_quote.miner_fee * Amount::from(predecessor_quote.weight)
            > &predecessor_quote.miner_fee * Amount::from(pending_quote.weight)
    );
    for tx in &unrelated {
        let other_quote = quote(tx);
        assert!(
            &predecessor_quote.miner_fee * Amount::from(other_quote.weight)
                > &other_quote.miner_fee * Amount::from(predecessor_quote.weight)
        );
    }
    let mut candidates = vec![pending.clone(), predecessor.clone()];
    candidates.extend(unrelated.iter().cloned());
    let result = chain.select_transactions(key(), &candidates, 256).unwrap();
    let mut expected = vec![predecessor, pending];
    expected.extend(unrelated[..254].iter().cloned());
    assert_eq!(result.transactions, expected);
    assert_eq!(result.signatures_checked, candidates.len());
    assert_eq!(result.execution_attempts, 256);
    assert!(!result.budget_exhausted);
    append(&mut chain, result.transactions);
}

#[test]
fn rejected_candidate_and_duplicate_cannot_corrupt_selection_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("chain.db"), configuration()).unwrap();
    append(&mut chain, vec![]);
    let recipient = crypto::public_key(&[62; 32]).unwrap();
    let bad = signed(
        &chain,
        &SECRET,
        0,
        Operation::TransferExact {
            recipient,
            amount: 999999u32.into(),
        },
        0,
    );
    let good = self_payment(&chain, &SECRET, 0);
    let mut bad_signature = good.clone();
    bad_signature.signature[0] ^= 1;
    let result = chain
        .select_transactions(
            key(),
            &[bad.clone(), good.clone(), bad, bad_signature, good.clone()],
            256,
        )
        .unwrap();
    assert_eq!(result.transactions, vec![good]);
    assert_eq!(result.signatures_checked, 3);
    assert!((1..=2).contains(&result.execution_attempts));
    append(&mut chain, result.transactions);
    assert!(chain.tip_state().account(&recipient, None).is_none());
}

#[test]
fn repeated_state_failures_have_a_linear_per_sender_operation_budget() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("chain.db"), configuration()).unwrap();
    for _ in 0..3 {
        append(&mut chain, vec![]);
    }
    let other_secret = [63; 32];
    let other = crypto::public_key(&other_secret).unwrap();
    let create = signed(
        &chain,
        &SECRET,
        0,
        Operation::TransferExact {
            recipient: other,
            amount: 400u32.into(),
        },
        0,
    );
    append(&mut chain, vec![create]);
    let missing = crypto::public_key(&[64; 32]).unwrap();
    let valid: Vec<_> = (0..128)
        .map(|nonce| self_payment(&chain, &other_secret, nonce))
        .collect();
    // The opening balance cannot cover these payments. They can never apply,
    // so they are dropped before ranking and never charged an attempt.
    let mut candidates: Vec<_> = (0..128)
        .map(|index| {
            signed(
                &chain,
                &SECRET,
                1,
                Operation::TransferExact {
                    recipient: missing,
                    amount: 999999u32.into(),
                },
                index,
            )
        })
        .collect();
    candidates.extend(valid.iter().rev().cloned());
    let result = chain.select_transactions(key(), &candidates, 256).unwrap();
    assert!(!result.budget_exhausted);
    assert_eq!(result.execution_attempts, valid.len());
    assert_eq!(result.signatures_checked, candidates.len());
    assert_eq!(result.transactions, valid);
    // Affordable, higher-priority candidates that always fail are retried
    // after each acceptance, but only within their own sender's budget. They
    // previously consumed the shared budget and truncated the valid selection.
    let mut candidates: Vec<_> = (0..128)
        .map(|index| {
            let mut body = signed(
                &chain,
                &SECRET,
                1,
                Operation::TransferExact {
                    recipient: missing,
                    amount: 0u32.into(),
                },
                index,
            )
            .body;
            body.fee = 100u32.into();
            crypto::sign(&chain.chain_id(), &body, &SECRET).unwrap()
        })
        .collect();
    let failing = candidates.len();
    candidates.extend(valid.iter().rev().cloned());
    let result = chain.select_transactions(key(), &candidates, 256).unwrap();
    assert!(result.budget_exhausted);
    assert_eq!(
        result.execution_attempts,
        valid.len() + failing * SELECTION_ATTEMPTS_PER_CANDIDATE
    );
    assert_eq!(result.signatures_checked, candidates.len());
    assert_eq!(result.transactions, valid);
    // Each failing candidate was tried, so its sender is not left undecided.
    assert!(result.exhausted_senders.is_empty());
    append(&mut chain, result.transactions);
    assert!(chain.tip_state().account(&missing, None).is_none());
}

#[test]
fn only_candidates_their_budget_never_reached_leave_a_sender_undecided() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("chain.db"), configuration()).unwrap();
    for _ in 0..5 {
        append(&mut chain, vec![]);
    }
    let other_secret = [63; 32];
    let other = crypto::public_key(&other_secret).unwrap();
    let fund = Operation::TransferExact {
        recipient: other,
        amount: 5000u32.into(),
    };
    let fund = signed(&chain, &SECRET, 0, fund, 0);
    append(&mut chain, vec![fund]);
    let with_fee = |secret: &[u8; 32], nonce: u64, amount: u32, fee: u32| {
        let recipient = crypto::public_key(secret).unwrap();
        let operation = Operation::TransferExact {
            recipient,
            amount: amount.into(),
        };
        let mut body = signed(&chain, secret, nonce, operation, 0).body;
        body.fee = fee.into();
        crypto::sign(&chain.chain_id(), &body, secret).unwrap()
    };
    // A high-fee zero transfer that always fails is retried after every
    // acceptance of the other sender until its own sender's budget is spent;
    // that sender's valid, lowest-fee alternative at the same nonce is then
    // never attempted.
    let failing = with_fee(&SECRET, 1, 0, 1000);
    let alternative = self_payment(&chain, &SECRET, 1);
    let others: Vec<_> = (0..16)
        .map(|nonce| with_fee(&other_secret, nonce, 1, 100))
        .collect();
    let mut candidates = vec![failing, alternative];
    candidates.extend(others.iter().cloned());
    let result = chain.select_transactions(key(), &candidates, 256).unwrap();
    assert_eq!(result.transactions, others);
    assert!(result.budget_exhausted);
    assert_eq!(
        result.exhausted_senders,
        std::collections::BTreeSet::from([key()])
    );
    assert!(!result.truncated);
}

#[test]
fn selection_obeys_exact_body_size_and_signature_limits() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = configuration();
    config.initial.block_bytes = 5120;
    let mut chain = Chain::open(&directory.path().join("chain.db"), config).unwrap();
    append(&mut chain, vec![]);
    let candidates: Vec<_> = (0..256)
        .map(|nonce| self_payment(&chain, &SECRET, nonce))
        .collect();
    let result = chain.select_transactions(key(), &candidates, 256).unwrap();
    let block = chain
        .template(
            key(),
            result.transactions.clone(),
            chain.tip_block().header.timestamp + 2,
        )
        .unwrap();
    assert!(codec::body_size(&block).unwrap() <= 5120);
    let mut over = result.transactions;
    over.push(candidates[over.len()].clone());
    assert!(
        chain
            .template(key(), over, chain.tip_block().header.timestamp + 2)
            .is_err()
    );
    let limited = chain.select_transactions(key(), &candidates, 3).unwrap();
    assert_eq!(limited.transactions.len(), 3);
    let oversized = vec![candidates[0].clone(); MAX_SELECTION_CANDIDATES + 1];
    assert!(chain.select_transactions(key(), &oversized, 256).is_err());
}

#[test]
fn governed_capacity_shrink_evicts_large_pending_transactions_and_refreshes_templates() {
    use hashstash::{node::Node, state::Phase};
    use serde_json::json;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("changing-capacity.db");
    let mut config = configuration();
    config.initial.block_bytes = 32 * 1024;
    let mut chain = Chain::open(&path, config.clone()).unwrap();
    for _ in 0..100 {
        append(&mut chain, vec![]);
    }
    let deposit = signed(
        &chain,
        &SECRET,
        0,
        Operation::Deposit {
            amount: 18_000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
    );
    append(&mut chain, vec![deposit]);
    curved::chain(&mut chain, &SECRET);
    let nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
    let proposal = signed(
        &chain,
        &SECRET,
        nonce,
        Operation::Propose {
            round: chain.tip_state().auction_round().unwrap(),
            description: [74; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: 32 * 1024,
                new: 16 * 1024,
            },
            support: 1u32.into(),
        },
        0,
    );
    append(&mut chain, vec![proposal]);
    for _ in 0..200 {
        if let Phase::Rest(rest) = &chain.tip_state().phase
            && rest.pending == Some((Parameter::BlockBytes, 16 * 1024))
            && chain.tip_state().clock + chain.tip_state().settings.interval >= rest.until
        {
            break;
        }
        let txs = if let Phase::Governance(decision) = &chain.tip_state().phase
            && chain.tip_state().clock == decision.started
        {
            vec![signed(
                &chain,
                &SECRET,
                chain.tip_state().account(&key(), None).unwrap().nonce,
                Operation::Deposit {
                    amount: 10_000u32.into(),

                    decision: Some(decision.id),
                    outcome: Some(Outcome::Pass),
                },
                0,
            )]
        } else {
            vec![]
        };
        append(&mut chain, txs);
    }
    assert!(matches!(&chain.tip_state().phase, Phase::Rest(rest)
        if rest.pending == Some((Parameter::BlockBytes, 16 * 1024))
        && chain.tip_state().clock + chain.tip_state().settings.interval >= rest.until));
    let mut pending = self_payment(
        &chain,
        &SECRET,
        chain.tip_state().account(&key(), None).unwrap().nonce,
    );
    pending.body.data = vec![7; 20 * 1024];
    pending.body.fee = 1000u32.into();
    let chain_id = chain.chain_id();
    pending = crypto::sign(&chain_id, &pending.body, &SECRET).unwrap();
    let timestamp = chain.tip_block().header.timestamp + config.initial.interval as u32;
    let activation =
        Chain::mine(chain.template(key(), vec![], timestamp).unwrap(), 100_000).unwrap();
    drop(chain);
    let node = Node::open(&path, config, key()).unwrap();
    node.submit_transaction(pending.clone()).unwrap();
    assert_eq!(node.template().unwrap().transactions, vec![pending.clone()]);
    assert_eq!(node.status().unwrap()["mempool"], 1);
    assert!(node.submit_block(activation).unwrap());
    assert_eq!(node.status().unwrap()["settings"]["block_bytes"], 16 * 1024);
    assert_eq!(node.status().unwrap()["mempool"], 0);
    assert!(node.template().unwrap().transactions.is_empty());
    assert!(node.submit_transaction(pending.clone()).is_err());
    pending.body.data.truncate(8 * 1024);
    pending = crypto::sign(&chain_id, &pending.body, &SECRET).unwrap();
    assert!(codec::encode(&pending).len() > 4096);
    node.submit_transaction(pending.clone()).unwrap();
    assert_eq!(node.template().unwrap().transactions, vec![pending]);
    node.mine(100_000).unwrap();
    assert_eq!(node.rpc("mempool", json!({})).unwrap(), json!([]));
}

#[test]
fn invalid_body_cache_uses_full_message_and_is_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("chain.db"), configuration()).unwrap();
    let time = chain.tip_block().header.timestamp + 2;
    let valid = Chain::mine(chain.template(key(), vec![], time).unwrap(), 100_000).unwrap();
    let mut invalid = valid.clone();
    invalid.state_root[0] ^= 1;
    let first = chain
        .submit(invalid.clone(), time as u64)
        .unwrap_err()
        .to_string();
    assert!(!first.contains("cached"));
    assert!(
        chain
            .submit(invalid, time as u64)
            .unwrap_err()
            .to_string()
            .contains("cached invalid")
    );
    for value in 1..=MAX_CACHED_INVALID_BLOCKS + 1 {
        let mut bad = valid.clone();
        bad.height += value as u64;
        assert!(chain.submit(bad, time as u64).is_err());
    }
    assert_eq!(chain.cached_invalid_count(), MAX_CACHED_INVALID_BLOCKS);
    // These payloads all have the same header digest. The valid payload still wins.
    assert!(chain.submit(valid, time as u64).unwrap());
    chain.tip_state().audit(&chain.config).unwrap();
}

#[test]
fn unknown_parent_and_future_time_failures_are_retryable() {
    let directory = tempfile::tempdir().unwrap();
    let config = configuration();
    let mut source = Chain::open(&directory.path().join("source.db"), config.clone()).unwrap();
    let first = append(&mut source, vec![]);
    let second = append(&mut source, vec![]);
    let mut target = Chain::open(&directory.path().join("target.db"), config).unwrap();
    assert!(
        target
            .submit(second.clone(), second.header.timestamp as u64)
            .is_err()
    );
    assert_eq!(target.cached_invalid_count(), 0);
    let early = first.header.timestamp as u64 - source.config.future_seconds as u64 - 1;
    assert!(target.submit(first.clone(), early).is_err());
    assert_eq!(target.cached_invalid_count(), 0);
    target
        .submit(first, second.header.timestamp as u64)
        .unwrap();
    target
        .submit(second, source.tip_block().header.timestamp as u64)
        .unwrap();
    assert_eq!(target.tip_hash(), source.tip_hash());
}

#[test]
fn deferred_historical_replay_resumes_and_never_caches_valid_block_as_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("main.db"), configuration()).unwrap();
    let mut fork = Chain::open(&directory.path().join("fork.db"), configuration()).unwrap();
    for height in 1..=900 {
        let block = append(&mut chain, vec![]);
        if height <= 500 {
            fork.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
    }
    let time = fork.tip_block().header.timestamp + 3;
    let block = Chain::mine(fork.template(key(), vec![], time).unwrap(), 100_000).unwrap();
    let hash = codec::block_hash(&block);
    let mut deferrals = 0;
    loop {
        match chain.submit_with_replay_budget(
            block.clone(),
            chain.tip_block().header.timestamp as u64,
            8,
        ) {
            Ok(_) => break,
            Err(error) => {
                assert!(
                    error.is::<hashstash::chain::ValidationDeferred>(),
                    "{error}"
                );
                assert_eq!(chain.cached_invalid_count(), 0);
                deferrals += 1;
                assert!(deferrals < 100);
            }
        }
    }
    // Resumption must work even when the replayed prefix itself exceeds the
    // entire historical-state cache; the last checkpoint keeps moving forward.
    assert!(deferrals > hashstash::chain::MAX_CACHED_STATES / 8);
    assert!(chain.block(&hash).is_some());
    assert_eq!(chain.tip_height(), 900);
    chain.state_at(&hash).unwrap().audit(&chain.config).unwrap();
    fork.submit(block, time as u64).unwrap();
    while fork.tip_height() <= chain.tip_height() {
        let block = append(&mut fork, vec![]);
        chain
            .submit_with_replay_budget(block.clone(), block.header.timestamp as u64, 8)
            .unwrap();
        if chain.tip_hash() == fork.tip_hash() {
            break;
        }
    }
    assert_eq!(chain.tip_hash(), fork.tip_hash());
    assert_eq!(
        codec::encode(chain.tip_state()),
        codec::encode(fork.tip_state())
    );
    assert_eq!(chain.cached_invalid_count(), 0);
    let expected_tip = chain.tip_hash();
    let expected_state = codec::encode(chain.tip_state());
    drop(chain);
    let restarted = Chain::open(&directory.path().join("main.db"), configuration()).unwrap();
    assert_eq!(restarted.tip_hash(), expected_tip);
    assert_eq!(codec::encode(restarted.tip_state()), expected_state);
}

#[test]
fn prepared_selection_matches_execution_through_governance_and_activation() {
    use hashstash::state::Phase;
    let directory = tempfile::tempdir().unwrap();
    let mut chain = Chain::open(&directory.path().join("governance.db"), configuration()).unwrap();
    for _ in 0..100 {
        append(&mut chain, vec![]);
    }
    let deposit = signed(
        &chain,
        &SECRET,
        0,
        Operation::Deposit {
            amount: 18_000u32.into(),

            decision: None,
            outcome: None,
        },
        0,
    );
    append(&mut chain, vec![deposit]);
    curved::chain(&mut chain, &SECRET);
    let nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
    let round = chain.tip_state().auction_round().unwrap();
    let proposal = signed(
        &chain,
        &SECRET,
        nonce,
        Operation::Propose {
            round,
            description: [70; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::Lead,
                old: chain.tip_state().settings.lead,
                new: chain.tip_state().settings.lead * 2,
            },
            support: 1u32.into(),
        },
        0,
    );
    append(&mut chain, vec![proposal]);
    let mut observations = 0;
    let mut saw_auction_activation = false;
    let mut saw_resolution = false;
    let mut saw_setting_activation = false;
    for _ in 0..150 {
        let phase_before = chain.tip_state().phase_name();
        let old_lead = chain.tip_state().settings.lead;
        let nonce = chain.tip_state().account(&key(), None).unwrap().nonce;
        let mut valid = vec![self_payment(&chain, &SECRET, nonce)];
        let mut candidates = Vec::new();
        if let Phase::Governance(decision) = &chain.tip_state().phase {
            if chain.tip_state().clock == decision.started {
                valid.push(signed(
                    &chain,
                    &SECRET,
                    nonce + 1,
                    Operation::Deposit {
                        amount: 10_000u32.into(),

                        decision: Some(decision.id),
                        outcome: Some(Outcome::Pass),
                    },
                    0,
                ));
            }
            if chain.tip_state().height + 1 >= decision.started_height + decision.blocks {
                // Selection must resolve first and reject the stale outcome context.
                candidates.push(signed(
                    &chain,
                    &SECRET,
                    nonce,
                    Operation::Deposit {
                        amount: 1u32.into(),

                        decision: Some(decision.id),
                        outcome: Some(Outcome::Pass),
                    },
                    0,
                ));
            }
        }
        candidates.extend(valid.iter().rev().cloned());
        let timestamp =
            chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
        let (selected, selected_block) = chain
            .select_template(key(), &candidates, 256, timestamp)
            .unwrap();
        assert_eq!(selected.transactions, valid);
        let expected = chain.template(key(), valid, timestamp).unwrap();
        assert_eq!(selected_block, expected);
        let mined = Chain::mine(selected_block, 100_000).unwrap();
        chain.submit(mined, timestamp as u64).unwrap();
        chain.tip_state().audit(&chain.config).unwrap();
        let phase_after = chain.tip_state().phase_name();
        saw_auction_activation |= phase_before == "auction" && phase_after == "governance";
        saw_resolution |= phase_before == "governance" && phase_after == "rest";
        saw_setting_activation |= old_lead == configuration().initial.lead
            && chain.tip_state().settings.lead == old_lead * 2;
        observations += 1;
        if saw_setting_activation {
            break;
        }
    }
    assert!(saw_auction_activation && saw_resolution && saw_setting_activation);
    assert!(observations > 10);
}
