//! Canonical serialization and Bitcoin-compatible mining commitments.
use crate::{
    crypto::sha256d,
    types::{Block, Hash, Header, PublicKey, Transaction},
};
use anyhow::{Result, ensure};
use bincode::Options;
use serde::{Serialize, de::DeserializeOwned};

pub const HEADER_VERSION: u32 = 0x2000_0005;
pub const VERSION_ROLLING_MASK: u32 = 0x1fff_e000;
pub fn is_current_header(header: &Header) -> bool {
    header.version & !VERSION_ROLLING_MASK == HEADER_VERSION
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

/// Primitive consensus encoding: bincode 1 canonical variable-width little-endian integers.
/// The current protocol defines one schema; old chain records are not accepted.
/// Only infallible consensus record types are passed to this interface.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    options()
        .serialize(value)
        .expect("consensus serialization is infallible")
}

pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8], max: usize) -> Result<T> {
    ensure!(bytes.len() <= max, "encoded record exceeds limit");
    let value: T = options().with_limit(max as u64).deserialize(bytes)?;
    ensure!(encode(&value) == bytes, "noncanonical encoding");
    Ok(value)
}

pub fn decode_block(bytes: &[u8], max: usize) -> Result<Block> {
    decode(bytes, max)
}

/// Hash fields are already raw SHA256d bytes; never reverse them here.
pub fn header_bytes(header: &Header) -> [u8; 80] {
    let mut bytes = [0u8; 80];
    bytes[0..4].copy_from_slice(&header.version.to_le_bytes());
    bytes[4..36].copy_from_slice(&header.previous);
    bytes[36..68].copy_from_slice(&header.merkle_root);
    bytes[68..72].copy_from_slice(&header.timestamp.to_le_bytes());
    bytes[72..76].copy_from_slice(&header.bits.to_le_bytes());
    bytes[76..80].copy_from_slice(&header.nonce.to_le_bytes());
    bytes
}

pub fn block_hash(block: &Block) -> Hash {
    sha256d(&header_bytes(&block.header))
}
pub fn transaction_id(tx: &Transaction) -> Hash {
    sha256d(&encode(tx))
}

fn compact_size(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=252 => out.push(value as u8),
        253..=0xffff => {
            out.push(253);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x10000..=0xffffffff => {
            out.push(254);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(255);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn height_script(height: u64) -> Vec<u8> {
    if height == 0 {
        return vec![0];
    }
    if height <= 16 {
        return vec![0x50 + height as u8];
    }
    let mut n = height;
    let mut data = Vec::new();
    while n > 0 {
        data.push(n as u8);
        n >>= 8;
    }
    if data.last().unwrap() & 0x80 != 0 {
        data.push(0);
    }
    let mut script = vec![data.len() as u8];
    script.extend(data);
    script
}

/// One Bitcoin-format coinbase input and zero-valued OP_RETURN output.
/// The only Merkle leaf commits to the payout key and the entire block body.
pub fn coinbase_parts(height: u64, miner: &PublicKey, commitment: &Hash) -> (Vec<u8>, Vec<u8>) {
    let height_push = height_script(height);
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&1u32.to_le_bytes());
    prefix.push(1);
    prefix.extend_from_slice(&[0; 32]);
    prefix.extend_from_slice(&u32::MAX.to_le_bytes());
    compact_size((height_push.len() + 1 + 8) as u64, &mut prefix);
    prefix.extend_from_slice(&height_push);
    prefix.push(8);
    let mut suffix = Vec::new();
    suffix.extend_from_slice(&u32::MAX.to_le_bytes());
    suffix.push(1);
    suffix.extend_from_slice(&0u64.to_le_bytes());
    suffix.push(70);
    suffix.extend_from_slice(&[0x6a, 68]);
    suffix.extend_from_slice(b"HST6");
    suffix.extend_from_slice(miner);
    suffix.extend_from_slice(commitment);
    suffix.extend_from_slice(&0u32.to_le_bytes());
    (prefix, suffix)
}

/// Count, order and complete canonical transaction bytes are authenticated.
/// Mining fields are excluded so extranonce rolling never reexecutes state.
pub fn combined_commitment(block: &Block) -> Hash {
    crate::crypto::tagged_hash(
        "Hashstash/block-commitment/v26",
        &encode(&(&block.transactions, &block.state_root)),
    )
}
pub fn coinbase_parts_for_block(block: &Block) -> (Vec<u8>, Vec<u8>) {
    coinbase_parts(block.height, &block.miner, &combined_commitment(block))
}
pub fn coinbase(block: &Block) -> Result<Vec<u8>> {
    let (mut prefix, suffix) = coinbase_parts_for_block(block);
    prefix.extend_from_slice(&block.extranonce);
    prefix.extend(suffix);
    Ok(prefix)
}

pub fn merkle_root(block: &Block) -> Result<Hash> {
    Ok(sha256d(&coinbase(block)?))
}
/// The coinbase is the sole Merkle leaf, including when transactions are present.
pub fn mining_merkle_branch(_block: &Block) -> Vec<Hash> {
    Vec::new()
}

/// Fixed state root plus record count and length-prefixed coinbase/transactions.
pub fn body_size(block: &Block) -> Result<usize> {
    let mut prefix = Vec::new();
    compact_size(
        (block.transactions.len() as u64)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("record count overflow"))?,
        &mut prefix,
    );
    let mut size = prefix.len() + 32;
    for record in std::iter::once(coinbase(block)?).chain(block.transactions.iter().map(encode)) {
        prefix.clear();
        compact_size(record.len() as u64, &mut prefix);
        size = size
            .checked_add(prefix.len())
            .and_then(|n| n.checked_add(record.len()))
            .ok_or_else(|| anyhow::anyhow!("block size overflow"))?;
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Operation, TransactionBody};
    #[test]
    fn bitcoin_genesis_header() {
        // Bitcoin Core src/kernel/chainparams.cpp, original mainnet genesis header.
        let header = Header {
            version: 1,
            previous: [0; 32],
            merkle_root: hex::decode(
                "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            timestamp: 1231006505,
            bits: 0x1d00ffff,
            nonce: 2083236893,
        };
        assert_eq!(
            hex::encode(sha256d(&header_bytes(&header))),
            "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
        );
        crate::math::check_pow(
            &header,
            &crate::math::target_from_bits(header.bits).unwrap(),
        )
        .unwrap();
    }

    fn tx(nonce: u64) -> Transaction {
        Transaction {
            body: TransactionBody {
                data: Vec::new(),
                chain_id: [1; 32],
                sender: [2; 32],
                nonce,
                fee: 0u32.into(),
                expiry_height: 100,
                operation: Operation::TransferExact {
                    recipient: [9; 32],
                    amount: 3u32.into(),
                },
            },
            signature: [4; 64],
        }
    }
    fn block(txs: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: HEADER_VERSION,
                previous: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1,
                bits: 0x207fffff,
                nonce: 0,
            },
            height: 1000,
            miner: [1; 32],
            state_root: [2; 32],
            extranonce: [3; 8],
            transactions: txs,
        }
    }
    #[test]
    fn canonical_bounded_codec_and_coinbase() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct AmountRecord(#[serde(with = "crate::types::amount")] crate::types::Amount);
        let mut nonminimal = vec![2];
        nonminimal.extend_from_slice(&[1, 0]);
        assert!(decode::<AmountRecord>(&nonminimal, 64).is_err());
        let minimal = encode(&AmountRecord(1u32.into()));
        assert_eq!(decode::<AmountRecord>(&minimal, 64).unwrap().0, 1u32.into());
        let t = tx(42);
        let bytes = encode(&t);
        assert_eq!(decode::<Transaction>(&bytes, bytes.len()).unwrap(), t);
        assert!(decode::<Transaction>(&bytes, bytes.len() - 1).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode::<Transaction>(&extra, extra.len()).is_err());
        assert!(decode::<Vec<u8>>(&u64::MAX.to_le_bytes(), 1024).is_err());
        let b = block(vec![]);
        let c = coinbase(&b).unwrap();
        assert_eq!(&c[..4], &1u32.to_le_bytes());
        assert_eq!(c[4], 1);
        assert!(c.windows(4).any(|x| x == b"HST6"));
        assert_eq!(body_size(&b).unwrap(), 32 + 1 + 1 + c.len());
        let (prefix, suffix) = coinbase_parts_for_block(&b);
        assert_eq!(c, [prefix, b.extranonce.to_vec(), suffix].concat());
        let mut malformed = serde_json::to_value(&b).unwrap();
        malformed["extranonce"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<Block>(malformed).is_err());
        let mut changed = b.clone();
        changed.extranonce[0] ^= 1;
        assert_ne!(merkle_root(&changed).unwrap(), merkle_root(&b).unwrap());
        assert_eq!(changed.state_root, b.state_root);
    }

    #[test]
    fn compact_integers_reject_wider_encodings_and_hostile_lengths() {
        for (value, length) in [
            (0, 1),
            (250, 1),
            (251, 3),
            (65_535, 3),
            (65_536, 5),
            (u32::MAX as u64, 5),
            (u32::MAX as u64 + 1, 9),
            (u64::MAX, 9),
        ] {
            let bytes = encode(&value);
            assert_eq!(bytes.len(), length);
            assert_eq!(decode::<u64>(&bytes, length).unwrap(), value);
        }
        for bytes in [
            vec![251, 1, 0],
            vec![252, 1, 0, 0, 0],
            vec![253, 1, 0, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(decode::<u64>(&bytes, bytes.len()).is_err());
        }
        assert!(decode::<u64>(&[251, 1], 2).is_err());
        assert!(decode::<u64>(&[254], 1).is_err());
        assert!(decode::<Operation>(&[6], 1).is_err());
        let mut hostile = vec![253];
        hostile.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode::<Vec<Transaction>>(&hostile, 1024).is_err());
        #[derive(serde::Serialize, serde::Deserialize)]
        struct AmountRecord(#[serde(with = "crate::types::amount")] crate::types::Amount);
        assert!(decode::<AmountRecord>(&hostile, 1024).is_err());
        assert_eq!(encode(&AmountRecord(0u32.into())), [0]);
        for bad in [vec![1, 0], vec![2, 1, 0], vec![251, 0, 0]] {
            assert!(decode::<AmountRecord>(&bad, bad.len()).is_err());
        }
    }

    #[test]
    fn compact_records_have_no_empty_fields_or_signature_framing() {
        use crate::types::Account;
        let mut transaction = tx(42);
        transaction.body.fee = 258u32.into();
        transaction.body.operation = Operation::TransferExact {
            recipient: [5; 32],
            amount: 65_537u32.into(),
        };
        let bytes = encode(&transaction);
        assert_eq!(bytes.len(), 171);
        assert_eq!(bytes.len(), encode(&transaction.body).len() + 64);
        assert_eq!(&bytes[bytes.len() - 64..], &[4; 64]);
        assert_eq!(encode(&Account::default()), [0, 0, 0, 0]);
        let account = Account {
            ordinary: crate::types::Amount::from(10u32).pow(18),
            shares: crate::types::Amount::from(10u32).pow(36),
            ..Account::default()
        };
        assert_eq!(encode(&account).len(), 27);
        for n in [0, 63, 65] {
            let mut malformed = serde_json::to_value(&transaction).unwrap();
            malformed["signature"] = serde_json::json!(vec![4u8; n]);
            assert!(serde_json::from_value::<Transaction>(malformed).is_err());
        }
        let mut obsolete = serde_json::to_value(&account).unwrap();
        obsolete["conditional"] = serde_json::json!("0");
        assert!(serde_json::from_value::<Account>(obsolete).is_err());
        let obsolete = serde_json::json!({"TransferExact":{
            "recipient":([5u8; 32]),"amount":"1","max_account_charge":"0"
        }});
        assert!(serde_json::from_value::<Operation>(obsolete).is_err());
        for obsolete in ["Transfer", "Donate", "Commit", "Merge"] {
            let mut object = serde_json::Map::new();
            object.insert(obsolete.into(), serde_json::json!({}));
            assert!(
                serde_json::from_value::<Operation>(serde_json::Value::Object(object)).is_err()
            );
        }
    }

    #[test]
    fn compact_commitment_binds_complete_ordered_contents() {
        let original = block(vec![tx(1), tx(2), tx(3)]);
        let commitment = combined_commitment(&original);
        let root = merkle_root(&original).unwrap();
        let assert_changed = |changed: &Block| {
            assert_ne!(combined_commitment(changed), commitment);
            assert_ne!(merkle_root(changed).unwrap(), root);
        };
        let mut changed = original.clone();
        changed.transactions.swap(0, 1);
        assert_changed(&changed);
        changed = original.clone();
        changed.transactions.push(tx(3));
        assert_changed(&changed);
        changed = original.clone();
        changed.transactions.pop();
        assert_changed(&changed);
        changed = original.clone();
        changed.transactions[0].signature[0] ^= 1;
        assert_changed(&changed);
        changed = original.clone();
        changed.transactions[0].body.nonce += 1;
        assert_changed(&changed);
        changed = original.clone();
        changed.state_root[0] ^= 1;
        assert_changed(&changed);

        // Bitcoin's duplicate-last tree can equate [a,b,c] and [a,b,c,c].
        // Here the vector length is inside the signed block-content opening.
        let mut duplicate_last = original.clone();
        duplicate_last.transactions.push(tx(3));
        assert_ne!(combined_commitment(&duplicate_last), commitment);

        // Mining can roll these without reexecuting or recommitting the body.
        changed = original.clone();
        changed.header.nonce += 1;
        changed.header.timestamp += 1;
        changed.header.version ^= VERSION_ROLLING_MASK;
        changed.header.merkle_root[0] ^= 1;
        changed.extranonce[0] ^= 1;
        assert_eq!(combined_commitment(&changed), commitment);
        assert_ne!(merkle_root(&changed).unwrap(), root);
        changed = original.clone();
        changed.miner[0] ^= 1;
        assert_eq!(combined_commitment(&changed), commitment);
        assert_ne!(merkle_root(&changed).unwrap(), root);
    }

    #[test]
    fn current_block_roundtrip_and_unknown_field_rejection() {
        let original = block(vec![tx(1)]);
        let bytes = encode(&original);
        assert_eq!(decode_block(&bytes, bytes.len()).unwrap(), original);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_block(&trailing, trailing.len()).is_err());
        let mut json = serde_json::to_value(&original).unwrap();
        json["unexpected"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<Block>(json).is_err());
        let mut header = original.header;
        header.version |= VERSION_ROLLING_MASK;
        assert!(is_current_header(&header));
        header.version ^= 4;
        assert!(!is_current_header(&header));
    }
    #[test]
    fn coinbase_only_tree_and_body_count_boundary() {
        for count in [0, 1, 2, 3, 251, 252, 1024] {
            let b = block((0..count).map(tx).collect());
            assert!(mining_merkle_branch(&b).is_empty());
            let cb = coinbase(&b).unwrap();
            assert_eq!(merkle_root(&b).unwrap(), sha256d(&cb));
            let mut expected = 32 + if count + 1 < 253 { 1 } else { 3 };
            for record in std::iter::once(cb).chain(b.transactions.iter().map(encode)) {
                expected += record.len() + if record.len() < 253 { 1 } else { 3 };
            }
            assert_eq!(body_size(&b).unwrap(), expected);
        }
    }
}
