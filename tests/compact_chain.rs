//! Current compact commitment and actual block-capacity coverage.
use hashstash::{chain::Chain, codec, config::Config, crypto, types::*};
fn miner(n: u8) -> PublicKey {
    crypto::public_key(&[n; 32]).unwrap()
}
fn config() -> Config {
    let mut c = Config::testnet();
    c.genesis_time = 1_700_000_000;
    c.initial_bits = 0x1f7fffff;
    c.limit_bits = c.initial_bits;
    c
}
#[test]
fn rolled_version_preserves_current_commitment_and_standard_mining() {
    let dir = tempfile::tempdir().unwrap();
    let c = config();
    let mut chain = Chain::open(&dir.path().join("rolling.sqlite"), c.clone()).unwrap();
    let mut block = chain
        .template(miner(1), vec![], c.genesis_time + 15)
        .unwrap();
    let root = block.header.merkle_root;
    block.header.version |= 0x1fffe000;
    assert!(codec::is_current_header(&block.header));
    assert_eq!(codec::merkle_root(&block).unwrap(), root);
    let block = Chain::mine(block, 1_000_000).unwrap();
    assert!(chain.submit(block, u64::from(c.genesis_time + 15)).unwrap());
    chain.tip_state().audit(&c).unwrap();
}
#[test]
fn selection_accounts_for_real_body_bytes_and_new_account_weight() {
    let dir = tempfile::tempdir().unwrap();
    for limit in [8192, 16384] {
        for new_accounts in [false, true] {
            let mut c = config();
            c.initial.block_bytes = limit;
            c.validate().unwrap();
            let mut chain = Chain::open(
                &dir.path()
                    .join(format!("capacity-{limit}-{new_accounts}.sqlite")),
                c.clone(),
            )
            .unwrap();
            let first = Chain::mine(
                chain
                    .template(miner(1), vec![], c.genesis_time + 15)
                    .unwrap(),
                1_000_000,
            )
            .unwrap();
            chain.submit(first, u64::from(c.genesis_time + 15)).unwrap();
            let candidates: Vec<_> = (0..100)
                .map(|nonce| {
                    crypto::sign(
                        &TransactionBody {
                            chain_id: c.chain_id(),
                            sender: miner(1),
                            nonce,
                            fee: 100u32.into(),
                            expiry_height: 100,
                            operation: Operation::TransferExact {
                                recipient: if new_accounts {
                                    miner(nonce as u8 + 10)
                                } else {
                                    miner(1)
                                },
                                amount: 1u32.into(),
                            },
                            data: vec![],
                        },
                        &[1; 32],
                    )
                    .unwrap()
                })
                .collect();
            let (selected, block) = chain
                .select_template(miner(3), &candidates, 100, c.genesis_time + 30)
                .unwrap();
            assert!(!selected.transactions.is_empty());
            assert!(selected.transactions.len() < candidates.len());
            assert_eq!(
                block,
                chain
                    .template(miner(3), selected.transactions.clone(), c.genesis_time + 30)
                    .unwrap()
            );
            assert!(codec::body_size(&block).unwrap() <= limit as usize);
            let mut extra = selected.transactions.clone();
            extra.push(candidates[selected.transactions.len()].clone());
            assert!(
                chain
                    .template(miner(3), extra, c.genesis_time + 30)
                    .is_err()
            );
            let block = Chain::mine(block, 1_000_000).unwrap();
            chain.submit(block, u64::from(c.genesis_time + 30)).unwrap();
            assert_eq!(
                chain.tip_state().settings.minimum_fee_rate,
                c.initial.minimum_fee_rate
            );
            chain.tip_state().audit(&c).unwrap();
        }
    }
}
