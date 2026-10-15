//! Multi-recipient grants use one bounded decision and prepaid settlement work.
use hashstash::{
    codec,
    config::Config,
    consensus, crypto, fees,
    state::{Phase, State},
    types::*,
};
use num_traits::Zero;

const OWNER: [u8; 32] = [181; 32];
fn key(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.initial.rest = 60;
    c.initial.lead = 30;
    c.initial.decision_blocks = 12;
    c.initial.block_bytes = 4096;
    c.validate().unwrap();
    c
}
fn sign(s: &State, operation: Operation, offset: u64, data: Vec<u8>) -> Transaction {
    crypto::sign(
        &TransactionBody {
            chain_id: s.chain_id,
            sender: key(181),
            nonce: s.account(&key(181), None).unwrap().nonce + offset,
            fee: 100u32.into(),
            expiry_height: s.height + 1000,
            operation,
            data,
        },
        &OWNER,
    )
    .unwrap()
}
fn step(c: &Config, s: &State, miner: PublicKey, subsidy: u32, txs: &[Transaction]) -> State {
    let next = consensus::execute(c, s, &s.root(), &miner, &subsidy.into(), txs).unwrap();
    next.audit(c).unwrap();
    next
}
fn funded(c: &Config) -> State {
    funded_amount(c, 1_000_000)
}
fn funded_amount(c: &Config, amount: u32) -> State {
    let mut s = step(c, &State::genesis(c), key(181), amount * 2, &[]);
    let deposit = sign(
        &s,
        Operation::Deposit {
            amount: amount.into(),

            decision: None,
            outcome: None,
        },
        0,
        vec![],
    );
    s = step(c, &s, key(181), 0, &[deposit]);
    while s.auction_round().is_none() {
        s = step(c, &s, key(181), 0, &[]);
    }
    s
}
fn payments(amounts: &[u32]) -> Vec<GrantPayment> {
    let mut payments: Vec<_> = amounts
        .iter()
        .enumerate()
        .map(|(i, amount)| GrantPayment {
            recipient: key(182 + i as u8),
            amount: (*amount).into(),
        })
        .collect();
    payments.sort_by_key(|p| p.recipient);
    payments
}
fn propose(s: &State, payments: Vec<GrantPayment>) -> Transaction {
    sign(
        s,
        Operation::Propose {
            round: s.auction_round().unwrap(),
            description: [171; 32],
            proposal: Proposal::Grant { payments },
            support: 10u32.into(),
        },
        0,
        vec![],
    )
}
fn active(c: &Config, payments: Vec<GrantPayment>) -> State {
    activate(c, funded(c), payments)
}
fn activate(c: &Config, mut s: State, payments: Vec<GrantPayment>) -> State {
    let proposal = propose(&s, payments);
    let proposal = cover_fee(c, &s, proposal);
    s = step(c, &s, key(181), 0, &[proposal]);
    for _ in 0..20 {
        if s.decision_id().is_some() {
            return s;
        }
        s = step(c, &s, key(181), 0, &[]);
    }
    panic!("grant did not activate");
}
fn cover_fee(c: &Config, s: &State, mut tx: Transaction) -> Transaction {
    loop {
        let required = fees::quote(c, s, &tx).unwrap().minimum_fee;
        if tx.body.fee >= required {
            return tx;
        }
        tx.body.fee = required;
        tx = crypto::sign(&tx.body, &OWNER).unwrap();
    }
}
fn indexed_key(prefix: u8, index: usize) -> PublicKey {
    let mut secret = [prefix; 32];
    secret[..8].copy_from_slice(&(index as u64).to_le_bytes());
    crypto::public_key(&secret).unwrap()
}
/// Return the last admissible list and the first list exceeding an existing
/// transaction-byte or block-weight limit. No recipient-count ceiling is used.
fn capacity_grants(c: &Config, s: &State) -> (Vec<GrantPayment>, Transaction, Transaction) {
    let mut high = (s.settings.block_bytes / fees::ACCOUNT_WEIGHT) as usize + 1;
    let mut entries: Vec<_> = (0..high)
        .map(|index| GrantPayment {
            recipient: indexed_key(0xa7, index),
            amount: 100u32.into(),
        })
        .collect();
    entries.sort_by_key(|p| p.recipient);
    let make = |count| {
        let tx = propose(s, entries[..count].to_vec());
        cover_fee(c, s, tx)
    };
    let mut low = 0;
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        let tx = make(middle);
        if codec::encode(&tx).len() <= c.transaction_bytes(&s.settings)
            && fees::quote(c, s, &tx).unwrap().weight <= s.settings.block_bytes
        {
            low = middle;
        } else {
            high = middle;
        }
    }
    (entries[..low].to_vec(), make(low), make(high))
}
fn before_resolution(c: &Config, mut s: State, pass: bool) -> State {
    if pass {
        let buy = sign(
            &s,
            Operation::Deposit {
                amount: 100_000u32.into(),

                decision: s.decision_id(),
                outcome: Some(Outcome::Pass),
            },
            0,
            vec![],
        );
        s = step(c, &s, key(181), 0, &[buy]);
        assert!(s.alternative.as_ref().unwrap().quote(c) > s.world.quote(c));
    }
    loop {
        let Phase::Governance(d) = &s.phase else {
            panic!("grant resolved too soon");
        };
        if s.height + 1 >= d.started_height + d.blocks {
            return s;
        }
        s = step(c, &s, key(181), 0, &[]);
    }
}

#[test]
fn grant_execution_weight_is_fixed_even_for_existing_recipients() {
    let c = config();
    let s = funded(&c);
    let entries = payments(&[2000, 3000, 4000]);
    let tx = propose(&s, entries.clone());
    let quote = fees::quote(&c, &s, &tx).unwrap();
    assert_eq!(
        quote.weight,
        codec::encode(&tx).len() as u64 + 3 * fees::ACCOUNT_WEIGHT
    );
    assert_eq!(quote.grant_recipient_fee, 3u32.into());
    assert!(quote.account_creation_fee.is_zero());
    let seed = sign(
        &s,
        Operation::TransferExact {
            recipient: entries[0].recipient,
            amount: 1u32.into(),
        },
        0,
        vec![],
    );
    let seeded = step(&c, &s, key(181), 0, &[seed]);
    let seeded_quote = fees::quote(&c, &seeded, &tx).unwrap();
    assert_eq!(seeded_quote.weight, quote.weight);
    assert_eq!(seeded_quote.minimum_fee, quote.minimum_fee);
    assert_eq!(&quote.miner_fee + &quote.revenue_fee, tx.body.fee);
}

#[test]
fn aggregate_grant_cannot_exceed_funds_by_splitting_payments() {
    let c = config();
    let mut s = funded(&c);
    // Each payment fits independently; their total exceeds the available funds.
    let entries = payments(&[600_000, 600_000]);
    let tx = propose(&s, entries);
    s = step(&c, &s, key(181), 0, &[tx]);
    let backing = &s.world.reserve + &s.world.revenue;
    for _ in 0..20 {
        s = step(&c, &s, key(181), 0, &[]);
        assert!(s.decision_id().is_none());
        assert!(s.world.grant_escrow.is_zero());
        assert!(&s.world.reserve + &s.world.revenue >= backing);
    }
    assert!(s.account(&key(182), None).is_none());
    assert!(s.account(&key(183), None).is_none());
}

#[test]
fn multi_recipient_grant_can_spend_more_than_half_the_reserve() {
    let c = config();
    let entries = payments(&[300_000, 300_000]);
    let opening = active(&c, entries.clone());
    let escrow = &opening.alternative.as_ref().unwrap().grant_escrow;
    assert_eq!(escrow, &Amount::from(600_000u32));
    assert!(escrow * 2u32 > opening.world.reserve);
    let closing = before_resolution(&c, opening, true);
    let settled = step(&c, &closing, key(181), 0, &[]);
    for payment in entries {
        assert_eq!(
            settled.account(&payment.recipient, None).unwrap().ordinary,
            payment.amount
        );
    }
    assert!(settled.world.grant_escrow.is_zero());
}

#[test]
fn pass_pays_every_exact_amount_once_and_fail_pays_none() {
    let c = config();
    let entries = payments(&[2000, 3000, 4000]);
    let opening = active(&c, entries.clone());
    assert_eq!(
        opening.alternative.as_ref().unwrap().grant_escrow,
        9000u32.into()
    );
    for won in [false, true] {
        let closing = before_resolution(&c, opening.clone(), won);
        let mut settled = step(&c, &closing, key(181), 0, &[]);
        assert!(settled.alternative.is_none());
        assert!(settled.world.grant_escrow.is_zero());
        assert_eq!(settled.issued, opening.issued);
        for payment in &entries {
            if won {
                assert_eq!(
                    settled.account(&payment.recipient, None).unwrap().ordinary,
                    payment.amount
                );
            } else {
                assert!(settled.account(&payment.recipient, None).is_none());
            }
        }
        let cash = settled.world.account_cash.clone();
        settled = step(&c, &settled, key(181), 0, &[]);
        assert_eq!(settled.world.account_cash, cash);
    }
}

#[test]
fn settlement_leaves_transaction_capacity_and_failed_closing_block_is_atomic() {
    let c = config();
    let entries = payments(&[2000, 3000, 4000]);
    let closing = before_resolution(&c, active(&c, entries.clone()), true);
    let original = codec::encode(&closing);
    let tx = sign(
        &closing,
        Operation::TransferExact {
            recipient: key(190),
            amount: 7u32.into(),
        },
        0,
        vec![],
    );
    let paid = step(&c, &closing, key(191), 1, std::slice::from_ref(&tx));
    for payment in &entries {
        assert_eq!(
            paid.account(&payment.recipient, None).unwrap().ordinary,
            payment.amount
        );
    }
    assert_eq!(paid.account(&key(190), None).unwrap().ordinary, 7u32.into());
    assert_eq!(
        paid.account(&key(191), None).unwrap().ordinary,
        51u32.into()
    );
    let mut invalid = tx.clone();
    invalid.body.nonce += 1;
    invalid = crypto::sign(&invalid.body, &OWNER).unwrap();
    assert!(
        consensus::execute(
            &c,
            &closing,
            &closing.root(),
            &key(191),
            &1u32.into(),
            &[invalid]
        )
        .is_err()
    );
    assert_eq!(codec::encode(&closing), original);
    for payment in &entries {
        assert!(closing.account(&payment.recipient, None).is_none());
    }
}

#[test]
fn grant_recipient_miner_still_consumes_one_account_creation_weight() {
    let c = config();
    let entries = payments(&[2000, 3000, 4000]);
    let closing = before_resolution(&c, active(&c, entries.clone()), true);
    let tx = sign(
        &closing,
        Operation::TransferExact {
            recipient: key(181),
            amount: 1u32.into(),
        },
        0,
        vec![0; 3300],
    );
    let quote = fees::quote(&c, &closing, &tx).unwrap();
    assert!(quote.weight <= c.initial.block_bytes);
    assert!(quote.weight + fees::ACCOUNT_WEIGHT > c.initial.block_bytes);
    assert!(
        consensus::execute(
            &c,
            &closing,
            &closing.root(),
            &entries[0].recipient,
            &1u32.into(),
            std::slice::from_ref(&tx)
        )
        .is_err()
    );
    assert!(
        consensus::execute(
            &c,
            &closing,
            &closing.root(),
            &key(191),
            &1u32.into(),
            std::slice::from_ref(&tx)
        )
        .is_err()
    );
    step(&c, &closing, key(181), 1, &[tx]);
    let paid = step(&c, &closing, entries[0].recipient, 1, &[]);
    assert_eq!(
        paid.account(&entries[0].recipient, None).unwrap().ordinary,
        &entries[0].amount + 1u32
    );
}

#[test]
fn grant_lists_use_existing_transaction_bytes_and_prepaid_block_weight() {
    let mut c = config();
    c.initial.block_bytes = 16_384;
    let s = funded(&c);
    let (entries, fits, exceeds_weight) = capacity_grants(&c, &s);
    assert_eq!(entries.len(), 15);
    assert!(codec::encode(&exceeds_weight).len() < c.transaction_bytes(&s.settings));
    assert!(fees::quote(&c, &s, &exceeds_weight).unwrap().weight > c.initial.block_bytes);
    step(&c, &s, key(181), 0, &[fits]);
    assert!(
        consensus::execute(
            &c,
            &s,
            &s.root(),
            &key(181),
            &0u32.into(),
            &[exceeds_weight]
        )
        .unwrap_err()
        .to_string()
        .contains("weighted capacity")
    );

    c.initial.block_bytes = 128 * 1024;
    c.validate().unwrap();
    let s = funded(&c);
    let (entries, fits, exceeds_weight) = capacity_grants(&c, &s);
    assert!(entries.len() > 16);
    assert!(codec::encode(&fits).len() > 4096);
    assert!(codec::encode(&fits).len() <= c.transaction_bytes(&s.settings));
    assert!(fees::quote(&c, &s, &exceeds_weight).unwrap().weight > c.initial.block_bytes);
    step(&c, &s, key(181), 0, &[fits]);
    assert!(
        consensus::execute(
            &c,
            &s,
            &s.root(),
            &key(181),
            &0u32.into(),
            &[exceeds_weight]
        )
        .unwrap_err()
        .to_string()
        .contains("weighted capacity")
    );
}

#[test]
fn maximum_grant_settles_once_with_full_small_block_and_large_account_tree() {
    let mut c = config();
    c.initial.block_bytes = 40 * 1024 * 1024 + 37;
    c.validate().unwrap();
    let mut s = funded_amount(&c, 100_000_000);
    // Populate a realistic existing tree before the fork. Settlement must only
    // write the payout leaves, with the old state retaining its original root.
    for index in 0..10_000 {
        s.world
            .put(indexed_key(0xa6, index), Account::default(), &c)
            .unwrap();
    }
    s.audit(&c).unwrap();
    let (entries, _, oversized) = capacity_grants(&c, &s);
    assert!(entries.len() > 32 * 1024 * 1024 / (fees::ACCOUNT_WEIGHT as usize + 34));
    assert!(
        consensus::execute(&c, &s, &s.root(), &key(181), &0u32.into(), &[oversized])
            .unwrap_err()
            .to_string()
            .contains("weighted capacity")
    );
    let opening = activate(&c, s, entries.clone());
    for won in [false, true] {
        let mut closing = before_resolution(&c, opening.clone(), won);
        // Model a later smaller ordinary-capacity limit: an already admitted
        // grant's prepaid settlement must remain executable at the minimum.
        closing.settings.block_bytes = hashstash::config::MIN_GOVERNED_BLOCK_BYTES;
        closing.frozen.block_bytes = closing.settings.block_bytes;
        closing.audit(&c).unwrap();
        let root_before = closing.root();
        let mut tx = sign(
            &closing,
            Operation::TransferExact {
                recipient: key(181),
                amount: 1u32.into(),
            },
            0,
            vec![],
        );
        let body_bytes = |tx: &Transaction| {
            codec::body_size(&Block {
                header: Header {
                    version: codec::HEADER_VERSION,
                    previous: root_before,
                    merkle_root: [0; 32],
                    timestamp: c.genesis_time + closing.clock as u32,
                    bits: c.initial_bits,
                    nonce: 0,
                },
                height: closing.height + 1,
                miner: key(181),
                state_root: [0; 32],
                extranonce: [0; 8],
                transactions: vec![tx.clone()],
            })
            .unwrap() as u64
        };
        tx.body
            .data
            .resize((closing.settings.block_bytes - body_bytes(&tx)) as usize, 0);
        while body_bytes(&tx) > closing.settings.block_bytes {
            tx.body.data.pop();
        }
        tx = crypto::sign(&tx.body, &OWNER).unwrap();
        assert_eq!(body_bytes(&tx), closing.settings.block_bytes);
        assert!(fees::quote(&c, &closing, &tx).unwrap().weight <= closing.settings.block_bytes);
        let started = std::time::Instant::now();
        let settled = consensus::execute(
            &c,
            &closing,
            &root_before,
            &key(181),
            &0u32.into(),
            std::slice::from_ref(&tx),
        )
        .unwrap();
        eprintln!(
            "grant settlement: {} recipients, 10000 prior accounts, won={won}, elapsed_us={}",
            entries.len(),
            started.elapsed().as_micros()
        );
        settled.audit(&c).unwrap();
        assert_eq!(closing.root(), root_before);
        assert!(settled.alternative.is_none());
        assert!(settled.world.grant_escrow.is_zero());
        for payment in &entries {
            assert!(closing.account(&payment.recipient, None).is_none());
            if won {
                assert_eq!(
                    settled.account(&payment.recipient, None).unwrap().ordinary,
                    payment.amount
                );
            } else {
                assert!(settled.account(&payment.recipient, None).is_none());
            }
        }
        // Replaying the identical closing block must give the same state;
        // replacing it with an invalid block cannot partially credit the list.
        assert_eq!(
            consensus::execute(
                &c,
                &closing,
                &root_before,
                &key(181),
                &0u32.into(),
                std::slice::from_ref(&tx),
            )
            .unwrap()
            .root(),
            settled.root()
        );
        tx.body.nonce += 1;
        tx = crypto::sign(&tx.body, &OWNER).unwrap();
        assert!(
            consensus::execute(&c, &closing, &root_before, &key(181), &0u32.into(), &[tx]).is_err()
        );
        assert_eq!(closing.root(), root_before);
        let next = step(&c, &settled, key(181), 0, &[]);
        assert_eq!(next.world.account_cash, settled.world.account_cash);
        assert_eq!(next.world.accounts.len(), settled.world.accounts.len());
    }
}
