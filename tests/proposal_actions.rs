//! Regression for audit finding F027. A grant's payments are committed once,
//! in the write-once `actions` map, when its Propose registers it. A Support
//! aimed at a large grant then rewrites and rehashes only the small proposal
//! record, so its tree work does not depend on how many payments the grant
//! lists, and it never copies or re-encodes the stored grant.
use hashstash::{
    codec,
    config::Config,
    consensus, crypto,
    state::{self, State},
    types::*,
};
use std::sync::Arc;

const PROPOSER: [u8; 32] = [131; 32];
const SUPPORTER: [u8; 32] = [132; 32];

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn step(c: &Config, s: &State, subsidy: u64, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &key(&PROPOSER), &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn sign(s: &State, secret: &[u8; 32], operation: Operation) -> Transaction {
    let sender = key(secret);
    crypto::sign(
        &TransactionBody {
            sender,
            nonce: s.account(&sender, None).unwrap().nonce,
            fee: 100u64.into(),
            anchor: [0; 32],
            expiry_blocks: s.height + 100,
            operation,
            data: Vec::new(),
        },
        secret,
    )
    .unwrap()
}

/// Registers a grant with `payments` recipients, then supports it once.
/// Returns the registering state, the supported state and the proposal ID.
fn register_and_support(payments: u8) -> (State, State, Hash) {
    let c = Config::testnet();
    let mut s = step(&c, &State::genesis(&c), 2_000_000, &[]);
    let transfer = Operation::TransferExact {
        recipient: key(&SUPPORTER),
        amount: 10_000u32.into(),
    };
    let pay = sign(&s, &PROPOSER, transfer);
    s = step(&c, &s, 0, &[pay]);
    while s.auction_round().is_none() {
        s = step(&c, &s, 1, &[]);
    }
    let round = s.auction_round().unwrap();
    let mut recipients: Vec<_> = (1..=payments).map(|i| key(&[i; 32])).collect();
    recipients.sort();
    let proposal = Proposal::Grant {
        payments: recipients
            .into_iter()
            .map(|recipient| GrantPayment {
                recipient,
                amount: 1u32.into(),
            })
            .collect(),
    };
    let propose = Operation::Propose {
        round,
        description: [7; 32],
        proposal: proposal.clone(),
        support: 1u32.into(),
    };
    let propose = sign(&s, &PROPOSER, propose);
    let registered = step(&c, &s, 1, &[propose]);
    let id = state::proposal_id(&s.chain_id, round, &key(&PROPOSER), &[7; 32], &proposal);
    assert_eq!(registered.actions.get(&id), Some(&proposal));
    let support = Operation::Support {
        round,
        proposal: id,
        amount: 1u32.into(),
    };
    let support = sign(&registered, &SUPPORTER, support);
    let supported = step(&c, &registered, 1, &[support]);
    (registered, supported, id)
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn supports_never_rewrite_or_reencode_the_supported_grant() {
    let mut records = Vec::new();
    for payments in [1, 12] {
        let (registered, supported, id) = register_and_support(payments);
        let record = supported.proposals.get(&id).unwrap();
        assert_eq!(record.support, 2u32.into());
        assert_eq!(supported.auction_round(), registered.auction_round());
        // The action map and the stored grant itself are untouched.
        assert_eq!(supported.actions.root(), registered.actions.root());
        assert!(Arc::ptr_eq(
            registered.actions.get_shared(&id).unwrap(),
            supported.actions.get_shared(&id).unwrap()
        ));
        records.push(codec::encode(record));
    }
    // The record a Support rewrites and rehashes has the same size however
    // many payments the supported grant lists.
    assert_eq!(records[0].len(), records[1].len());
}
