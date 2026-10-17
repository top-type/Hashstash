//! Regression for audit finding F075. A proposal ID binds the sender that
//! registers it, so a lighter copy of a pending Propose, ordered first by a
//! miner or fee ranking, registers its own proposal. The original still lands
//! with its own ID, data and attribution instead of failing as a duplicate.
use hashstash::{
    config::Config,
    consensus, crypto,
    state::{self, State},
    types::*,
};

const HONEST: [u8; 32] = [121; 32];
const COPIER: [u8; 32] = [122; 32];

fn key(secret: &[u8; 32]) -> PublicKey {
    crypto::public_key(secret).unwrap()
}
fn step(c: &Config, s: &State, subsidy: u64, txs: &[Transaction]) -> anyhow::Result<State> {
    let next = consensus::execute(c, s, &s.root(), &key(&HONEST), &subsidy.into(), txs)?;
    next.audit(c)?;
    Ok(next)
}
fn sign(s: &State, secret: &[u8; 32], operation: Operation, data: Vec<u8>) -> Transaction {
    let sender = key(secret);
    crypto::sign(
        &TransactionBody {
            sender,
            nonce: s.account(&sender, None).unwrap().nonce,
            fee: 100u64.into(),
            anchor: [0; 32],
            expiry_blocks: s.height + 100,
            operation,
            data,
        },
        secret,
    )
    .unwrap()
}

#[test]
#[cfg_attr(
    not(feature = "test-fixtures"),
    ignore = "requires explicit test-fixtures funding"
)]
fn copied_propose_registers_separately_from_the_original() {
    let c = Config::testnet();
    let mut s = step(&c, &State::genesis(&c), 2_000_000, &[]).unwrap();
    let transfer = Operation::TransferExact {
        recipient: key(&COPIER),
        amount: 10_000u32.into(),
    };
    let pay = sign(&s, &HONEST, transfer, Vec::new());
    s = step(&c, &s, 0, &[pay]).unwrap();
    for _ in 0..100 {
        if s.auction_round().is_some() {
            break;
        }
        s = step(&c, &s, 1, &[]).unwrap();
    }
    let round = s.auction_round().expect("auction did not open");
    let proposal = Proposal::Grant {
        payments: vec![GrantPayment {
            recipient: key(&[123; 32]),
            amount: 5u32.into(),
        }],
    };
    let description = [13; 32];
    let propose = || Operation::Propose {
        round,
        description,
        proposal: proposal.clone(),
        support: 1u32.into(),
    };
    // The lighter copy is ordered first, as fee ranking or its miner would.
    let copy = sign(&s, &COPIER, propose(), Vec::new());
    let honest = sign(&s, &HONEST, propose(), b"rationale".to_vec());
    let next = step(&c, &s, 1, &[copy, honest]).unwrap();
    assert_eq!(next.proposals.len(), 2);
    for secret in [COPIER, HONEST] {
        let sender = key(&secret);
        let id = state::proposal_id(&s.chain_id, round, &sender, &description, &proposal);
        let record = next.proposals.get(&id).unwrap();
        assert_eq!(record.proposer, sender);
        assert_eq!(*record.action, proposal);
    }
    // One sender still registers a given proposal once; more bids use Support.
    let again = sign(&next, &HONEST, propose(), Vec::new());
    assert!(step(&c, &next, 1, &[again]).is_err());
}
