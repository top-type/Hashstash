//! Independent exact-fee signing oracle for state-transition fixtures.
use hashstash::{
    codec, crypto,
    state::{State, support_key},
    types::*,
};
pub fn sign_minimum(
    s: &State,
    mut body: TransactionBody,
    secret: &[u8; 32],
    extra: u64,
) -> Transaction {
    body.fee = 0u32.into();
    loop {
        let creation = matches!(&body.operation,Operation::TransferExact { recipient,.. } if s.account(recipient,None).is_none());
        // A proposal, and a support without an existing record, add a record.
        let record = match &body.operation {
            Operation::Propose { .. } => true,
            Operation::Support {
                round, proposal, ..
            } => s
                .supports
                .get(&support_key(*round, proposal, &body.sender))
                .is_none(),
            _ => false,
        };
        let bytes = codec::encode(&Transaction {
            body: body.clone(),
            signature: [0; 64],
        })
        .len() as u64;
        let grant_recipients = match &body.operation {
            Operation::Propose {
                proposal: Proposal::Grant { payments },
                ..
            } => payments.len() as u64,
            _ => 0,
        };
        let weight = bytes
            + if creation { 1024 } else { 0 }
            + if record { 1024 } else { 0 }
            + grant_recipients * 1024;
        let fee = (Amount::from(weight) * s.settings.minimum_fee_rate + 1023u32) / 1024u32 + extra;
        if body.fee == fee {
            return crypto::sign(&s.chain_id, &body, secret).unwrap();
        }
        body.fee = fee;
    }
}
