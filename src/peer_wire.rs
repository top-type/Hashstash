//! Peer envelopes around canonical block and transaction records.
//! Lengths and nested collection counts are checked before record allocation.
use crate::{
    codec,
    config::Config,
    types::{Block, Hash, Transaction},
};
use anyhow::{Context, Result, ensure};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub const MAGIC: &[u8; 8] = b"HSP2PBIN";
pub const MAX_LOCATORS: usize = 128;
pub const MAX_BLOCKS: usize = 32;
pub const MAX_TRANSACTIONS: usize = 256;
pub const TRANSACTION_BATCH_BYTES: usize = 512 * 1024;
pub const ACK_BYTES: usize = 9;
pub const DISCOVERY_BYTES: usize = 8 + 1 + 32 + 32 + 1 + 32 * 18;
/// Initial local admission allowance. Governance may increase it; this is not
/// a block-validity limit. The four-byte peer envelope has its own wire bound.
pub const DEFAULT_RECORD_ADMISSION_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_WIRE_PAYLOAD_BYTES: usize = u32::MAX as usize;
pub const SYNC_OVERHEAD_BYTES: usize = MAGIC.len() + 1 + 32 + 9 + MAX_LOCATORS * 32 + 9 + 9;
const RECORD_OVERHEAD: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sync {
    pub chain: Hash,
    pub locator: Vec<Hash>,
    pub blocks: Vec<Block>,
    pub transactions: Vec<Transaction>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Sync(Sync),
    Ack,
    GetAddresses {
        chain: Hash,
        node: Hash,
        advertise: Option<SocketAddr>,
    },
    Addresses {
        chain: Hash,
        node: Hash,
        addresses: Vec<SocketAddr>,
    },
}

fn push_address(out: &mut Vec<u8>, address: SocketAddr) -> Result<()> {
    ensure!(address.port() != 0, "zero peer port");
    let ip = match address.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => {
            ensure!(address.scope_id() == 0, "scoped peer address");
            ip
        }
    };
    out.extend_from_slice(&ip.octets());
    out.extend_from_slice(&address.port().to_be_bytes());
    Ok(())
}
trait ScopeId {
    fn scope_id(&self) -> u32;
}
impl ScopeId for SocketAddr {
    fn scope_id(&self) -> u32 {
        match self {
            SocketAddr::V6(a) => a.scope_id(),
            _ => 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub block_bytes: usize,
    pub transaction_bytes: usize,
    pub block_transactions: usize,
}
impl Limits {
    pub fn from_config(config: &Config) -> Self {
        Self::for_capacity(config, config.initial.block_bytes)
    }
    pub fn for_capacity(config: &Config, capacity: u64) -> Self {
        // Saturation is intentional at the wire representation boundary;
        // oversized payloads receive a transport error, never a consensus one.
        let record_bytes = usize::try_from(capacity)
            .unwrap_or(usize::MAX)
            .saturating_add(RECORD_OVERHEAD)
            .clamp(DEFAULT_RECORD_ADMISSION_BYTES, MAX_WIRE_PAYLOAD_BYTES);
        Self {
            block_bytes: record_bytes,
            transaction_bytes: record_bytes,
            block_transactions: config.max_signatures,
        }
    }
    pub fn frame_bytes(self) -> usize {
        self.block_bytes
            .saturating_add((1024 * 1024).max(self.transaction_bytes.saturating_add(32 * 1024)))
            .min(MAX_WIRE_PAYLOAD_BYTES)
    }
    pub fn transaction_batch_bytes(self) -> usize {
        TRANSACTION_BATCH_BYTES.max(self.transaction_bytes.saturating_add(9))
    }
}

pub fn record_size(bytes: usize) -> Result<usize> {
    let length = u64::try_from(bytes)?;
    codec::encode(&length)
        .len()
        .checked_add(bytes)
        .ok_or_else(|| anyhow::anyhow!("peer record framing length overflow"))
}
fn push_record(out: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<()> {
    let next = out
        .len()
        .checked_add(record_size(bytes.len())?)
        .context("peer frame length overflow")?;
    ensure!(next <= maximum, "peer frame too large");
    out.extend(codec::encode(&(bytes.len() as u64)));
    out.extend_from_slice(bytes);
    Ok(())
}
pub fn encode(message: &Message, limits: Limits) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    match message {
        Message::Ack => out.push(1),
        Message::GetAddresses {
            chain,
            node,
            advertise,
        } => {
            out.push(2);
            out.extend_from_slice(chain);
            out.extend_from_slice(node);
            out.push(u8::from(advertise.is_some()));
            if let Some(address) = advertise {
                push_address(&mut out, *address)?;
            }
        }
        Message::Addresses {
            chain,
            node,
            addresses,
        } => {
            ensure!(
                addresses.len() <= crate::peer_discovery::MAX_ADDRESSES,
                "peer address count limit"
            );
            out.push(3);
            out.extend_from_slice(chain);
            out.extend_from_slice(node);
            out.push(addresses.len() as u8);
            for address in addresses {
                push_address(&mut out, *address)?;
            }
        }
        Message::Sync(sync) => {
            ensure!(
                sync.locator.len() <= MAX_LOCATORS
                    && sync.blocks.len() <= MAX_BLOCKS
                    && sync.transactions.len() <= MAX_TRANSACTIONS,
                "peer batch limit exceeded"
            );
            out.push(0);
            out.extend_from_slice(&sync.chain);
            out.extend(codec::encode(&(sync.locator.len() as u64)));
            for hash in &sync.locator {
                out.extend_from_slice(hash);
            }
            out.extend(codec::encode(&(sync.blocks.len() as u64)));
            for block in &sync.blocks {
                ensure!(
                    block.transactions.len() <= limits.block_transactions,
                    "peer block transaction limit exceeded"
                );
                let bytes = codec::encode(block);
                ensure!(
                    bytes.len() <= limits.block_bytes,
                    "peer block record too large"
                );
                push_record(&mut out, &bytes, limits.frame_bytes())?;
                ensure!(out.len() <= limits.frame_bytes(), "peer frame too large");
            }
            out.extend(codec::encode(&(sync.transactions.len() as u64)));
            for tx in &sync.transactions {
                let bytes = codec::encode(tx);
                ensure!(
                    bytes.len() <= limits.transaction_bytes,
                    "peer transaction too large"
                );
                push_record(&mut out, &bytes, limits.frame_bytes())?;
                ensure!(out.len() <= limits.frame_bytes(), "peer frame too large");
            }
        }
    }
    ensure!(out.len() <= limits.frame_bytes(), "peer frame too large");
    Ok(out)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        ensure!(count <= self.bytes.len() - self.at, "truncated peer record");
        let start = self.at;
        self.at += count;
        Ok(&self.bytes[start..self.at])
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn address(&mut self) -> Result<SocketAddr> {
        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(self.take(16)?)?);
        let port = u16::from_be_bytes(self.take(2)?.try_into()?);
        ensure!(port != 0, "zero peer port");
        Ok(SocketAddr::new(
            ip.to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            port,
        ))
    }
    fn integer(&mut self) -> Result<u64> {
        let (value, minimum) = match self.byte()? {
            n @ 0..=250 => (u64::from(n), 0),
            251 => (
                u64::from(u16::from_le_bytes(self.take(2)?.try_into()?)),
                251,
            ),
            252 => (
                u64::from(u32::from_le_bytes(self.take(4)?.try_into()?)),
                65_536,
            ),
            253 => (u64::from_le_bytes(self.take(8)?.try_into()?), 4_294_967_296),
            _ => anyhow::bail!("invalid compact u64 marker"),
        };
        ensure!(value >= minimum, "noncanonical compact integer");
        Ok(value)
    }
    fn count(&mut self, maximum: usize) -> Result<usize> {
        let value = self.integer()?;
        ensure!(
            value <= maximum as u64,
            "peer collection or record length exceeds limit"
        );
        Ok(value as usize)
    }
    fn record(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = self.count(maximum)?;
        ensure!(length > 0, "empty peer record");
        self.take(length)
    }
    fn amount(&mut self) -> Result<()> {
        let length = self.count(self.bytes.len() - self.at)?;
        let bytes = self.take(length)?;
        ensure!(bytes.last() != Some(&0), "noncanonical amount");
        Ok(())
    }
    fn option(&mut self, value: impl FnOnce(&mut Self) -> Result<()>) -> Result<()> {
        match self.byte()? {
            0 => Ok(()),
            1 => value(self),
            _ => anyhow::bail!("invalid option tag"),
        }
    }
    fn transaction(&mut self, maximum: usize) -> Result<()> {
        let start = self.at;
        self.take(64)?; // chain ID and sender
        self.integer()?;
        self.amount()?;
        self.integer()?;
        match self.integer()? {
            0 => {
                self.take(32)?;
                self.amount()?;
            }
            1 | 2 => {
                self.amount()?;
                self.option(|r| {
                    r.take(32)?;
                    Ok(())
                })?;
                self.option(|r| {
                    ensure!(r.integer()? <= 1, "invalid outcome tag");
                    Ok(())
                })?;
            }
            3 => {
                self.integer()?;
                self.take(32)?;
                match self.integer()? {
                    0 => {
                        let payments = self.integer()?;
                        // Every payment needs a 32-byte key and at least an
                        // amount-length byte. Bound the declared count by the
                        // actual record and remaining transaction byte budget
                        // before walking fields or allocating decoded values.
                        let available = (self.bytes.len() - self.at)
                            .min(maximum.saturating_sub(self.at - start));
                        ensure!(
                            payments <= (available / 33) as u64,
                            "peer grant count exceeds remaining transaction bytes"
                        );
                        ensure!(payments > 0, "empty grant payment list");
                        for _ in 0..payments {
                            self.take(32)?;
                            self.amount()?;
                        }
                    }
                    1 => {
                        ensure!(self.integer()? <= 8, "invalid parameter tag");
                        self.integer()?;
                        self.integer()?;
                    }
                    _ => anyhow::bail!("invalid proposal tag"),
                }
                self.amount()?;
            }
            4 => {
                self.integer()?;
                self.take(32)?;
                self.amount()?;
            }
            5 => {
                self.integer()?;
                self.take(32)?;
            }
            _ => anyhow::bail!("invalid operation tag"),
        }
        let data = self.count(maximum)?;
        self.take(data)?;
        self.take(64)?;
        ensure!(self.at - start <= maximum, "peer transaction too large");
        Ok(())
    }
    fn finish(self) -> Result<()> {
        ensure!(self.at == self.bytes.len(), "trailing peer bytes");
        Ok(())
    }
}

// This nonallocating walk checks only canonical framing and bounded collections.
// Actual decoding remains the consensus codec; all semantic/signature checks remain in the node.
fn preflight_block(bytes: &[u8], limits: Limits) -> Result<()> {
    let mut r = Cursor::new(bytes);
    ensure!(r.integer()? <= u32::MAX.into(), "invalid header version");
    r.take(64)?; // previous and Merkle root
    for _ in 0..3 {
        ensure!(r.integer()? <= u32::MAX.into(), "invalid header integer");
    }
    r.integer()?; // height
    r.take(32 + 32 + 8)?; // miner, state root, fixed extranonce
    let transactions = r.count(limits.block_transactions)?;
    // Even the shortest signed transaction requires its 64-byte signature.
    // A forged count cannot cause a long walk through nonexistent records.
    ensure!(
        transactions <= (bytes.len() - r.at) / 64,
        "peer transaction count exceeds remaining block bytes"
    );
    for _ in 0..transactions {
        r.transaction(limits.transaction_bytes)?;
    }
    r.finish()
}

pub fn decode(bytes: &[u8], limits: Limits) -> Result<Message> {
    ensure!(bytes.len() <= limits.frame_bytes(), "peer frame too large");
    let mut r = Cursor::new(bytes);
    ensure!(r.take(MAGIC.len())? == MAGIC, "invalid peer message format");
    let message = match r.byte()? {
        1 => Message::Ack,
        2 => {
            ensure!(bytes.len() <= DISCOVERY_BYTES, "discovery frame too large");
            let chain = r.take(32)?.try_into()?;
            let node = r.take(32)?.try_into()?;
            let advertise = match r.byte()? {
                0 => None,
                1 => Some(r.address()?),
                _ => anyhow::bail!("invalid advertisement flag"),
            };
            Message::GetAddresses {
                chain,
                node,
                advertise,
            }
        }
        3 => {
            ensure!(bytes.len() <= DISCOVERY_BYTES, "discovery frame too large");
            let chain = r.take(32)?.try_into()?;
            let node = r.take(32)?.try_into()?;
            let count = r.byte()? as usize;
            ensure!(
                count <= crate::peer_discovery::MAX_ADDRESSES,
                "peer address count limit"
            );
            // Exact fixed-width count is checked before allocating addresses.
            ensure!(
                r.bytes.len() - r.at == count * 18,
                "truncated or trailing peer addresses"
            );
            let mut addresses = Vec::with_capacity(count);
            for _ in 0..count {
                addresses.push(r.address()?);
            }
            Message::Addresses {
                chain,
                node,
                addresses,
            }
        }
        0 => {
            let chain = r.take(32)?.try_into()?;
            let count = r.count(MAX_LOCATORS)?;
            // Check all fixed-width locator bytes before allocating the vector.
            let locator_bytes = r.take(count * 32)?;
            let locator = locator_bytes
                .chunks_exact(32)
                .map(|h| h.try_into().expect("fixed hash size"))
                .collect();
            let count = r.count(MAX_BLOCKS)?;
            let mut blocks = Vec::new();
            for _ in 0..count {
                let bytes = r.record(limits.block_bytes)?;
                preflight_block(bytes, limits)?;
                blocks.push(codec::decode_block(bytes, limits.block_bytes)?);
            }
            let count = r.count(MAX_TRANSACTIONS)?;
            let mut transactions = Vec::new();
            for _ in 0..count {
                let bytes = r.record(limits.transaction_bytes)?;
                let mut record = Cursor::new(bytes);
                record.transaction(limits.transaction_bytes)?;
                record.finish()?;
                transactions.push(codec::decode(bytes, limits.transaction_bytes)?);
            }
            Message::Sync(Sync {
                chain,
                locator,
                blocks,
                transactions,
            })
        }
        _ => anyhow::bail!("unknown peer message type"),
    };
    r.finish()?;
    Ok(message)
}

pub fn frame(payload: &[u8], maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        !payload.is_empty() && payload.len() <= maximum,
        "peer frame too large or empty"
    );
    let length = u32::try_from(payload.len())?;
    let capacity = payload
        .len()
        .checked_add(4)
        .context("peer frame length overflow")?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, types::*};

    #[test]
    fn governed_capacity_expands_admission_without_framing_overflow() {
        let config = Config::devnet();
        let old = Limits::from_config(&config);
        let larger = Limits::for_capacity(&config, 40 * 1024 * 1024 + 173);
        assert!(larger.block_bytes > DEFAULT_RECORD_ADMISSION_BYTES);
        assert!(larger.frame_bytes() > old.frame_bytes());
        let boundary = Limits::for_capacity(&config, u64::MAX);
        assert_eq!(boundary.frame_bytes(), MAX_WIRE_PAYLOAD_BYTES);
        assert!(record_size(usize::MAX).is_err());
        let bytes = [1u8; 16];
        assert!(frame(&bytes, bytes.len() - 1).is_err());
        assert_eq!(frame(&bytes, bytes.len()).unwrap().len(), bytes.len() + 4);
    }

    #[test]
    fn discovery_addresses_are_fixed_width_bounded_and_strict() {
        let limits = Limits::from_config(&Config::devnet());
        for packet in [
            Message::GetAddresses {
                chain: [1; 32],
                node: [2; 32],
                advertise: Some("8.8.8.8:18481".parse().unwrap()),
            },
            Message::Addresses {
                chain: [1; 32],
                node: [2; 32],
                addresses: vec![
                    "8.8.8.8:18481".parse().unwrap(),
                    "[2606:4700::1]:18481".parse().unwrap(),
                ],
            },
        ] {
            let wire = encode(&packet, limits).unwrap();
            assert_eq!(decode(&wire, limits).unwrap(), packet);
            let mut trailing = wire.clone();
            trailing.push(0);
            assert!(decode(&trailing, limits).is_err());
            assert!(decode(&wire[..wire.len() - 1], limits).is_err());
        }
        let mut header = MAGIC.to_vec();
        header.push(3);
        header.extend_from_slice(&[1; 64]);
        header.push(255);
        assert!(
            decode(&header, limits)
                .unwrap_err()
                .to_string()
                .contains("count")
        );
        let too_many = Message::Addresses {
            chain: [1; 32],
            node: [2; 32],
            addresses: vec!["8.8.8.8:1".parse().unwrap(); 33],
        };
        assert!(encode(&too_many, limits).is_err());
    }

    fn transaction(operation: Operation, nonce: u64) -> Transaction {
        crypto::sign(
            &TransactionBody {
                chain_id: Config::devnet().chain_id(),
                sender: crypto::public_key(&[1; 32]).unwrap(),
                nonce,
                fee: 300u32.into(),
                expiry_height: 1000,
                operation,
                data: vec![0, 255, 10, 0],
            },
            &[1; 32],
        )
        .unwrap()
    }
    fn fixture() -> (Limits, Sync) {
        let config = Config::devnet();
        let recipient = crypto::public_key(&[2; 32]).unwrap();
        let operations = vec![
            Operation::TransferExact {
                recipient,
                amount: Amount::from(10u32).pow(18),
            },
            Operation::Deposit {
                amount: 1u32.into(),
                decision: None,
                outcome: None,
            },
            Operation::Redeem {
                shares: Amount::from(10u32).pow(36),
                decision: Some([5; 32]),
                outcome: Some(Outcome::Pass),
            },
            Operation::Deposit {
                amount: 251u32.into(),
                decision: Some([5; 32]),
                outcome: Some(Outcome::Fail),
            },
            Operation::Propose {
                round: 65_536,
                description: [3; 32],
                proposal: Proposal::Grant {
                    payments: vec![crate::types::GrantPayment {
                        recipient,
                        amount: 1u32.into(),
                    }],
                },
                support: 2u32.into(),
            },
            Operation::Propose {
                round: 1,
                description: [4; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::MinimumFeeRate,
                    old: 1,
                    new: 2,
                },
                support: 3u32.into(),
            },
            Operation::Support {
                round: 1,
                proposal: [4; 32],
                amount: 5u32.into(),
            },
            Operation::Refund {
                round: 1,
                proposal: [4; 32],
            },
        ];
        let transactions = operations
            .into_iter()
            .enumerate()
            .map(|(n, op)| transaction(op, n as u64))
            .collect::<Vec<_>>();
        let block = Block {
            header: Header {
                version: codec::HEADER_VERSION,
                previous: [2; 32],
                merkle_root: [3; 32],
                timestamp: 1_777_777_777,
                bits: 0x207fffff,
                nonce: 65_536,
            },
            height: 251,
            miner: recipient,
            state_root: [9; 32],
            extranonce: [10; 8],
            transactions: transactions.clone(),
        };
        (
            Limits::from_config(&config),
            Sync {
                chain: config.chain_id(),
                locator: vec![[7; 32]],
                blocks: vec![block],
                transactions,
            },
        )
    }
    #[test]
    fn roundtrip_preserves_canonical_records_ids_signatures_and_commitments() {
        let (limits, sync) = fixture();
        let wire = encode(&Message::Sync(sync.clone()), limits).unwrap();
        let Message::Sync(decoded) = decode(&wire, limits).unwrap() else {
            panic!()
        };
        assert_eq!(decoded, sync);
        for (before, after) in sync.transactions.iter().zip(&decoded.transactions) {
            assert_eq!(codec::encode(before), codec::encode(after));
            assert_eq!(codec::transaction_id(before), codec::transaction_id(after));
            assert_eq!(before.signature, after.signature);
        }
        assert_eq!(
            codec::block_hash(&sync.blocks[0]),
            codec::block_hash(&decoded.blocks[0])
        );
        assert_eq!(
            codec::combined_commitment(&sync.blocks[0]),
            codec::combined_commitment(&decoded.blocks[0])
        );
        assert_eq!(sync.blocks[0].state_root, decoded.blocks[0].state_root);
        let json = serde_json::to_vec(&serde_json::json!({"chain":sync.chain,"locator":sync.locator,"blocks":sync.blocks,"transactions":sync.transactions})).unwrap();
        assert!(wire.len() < json.len());
        eprintln!(
            "mixed-operation relay: binary={} bytes, JSON={} bytes",
            wire.len(),
            json.len()
        );
    }
    #[test]
    fn rejects_every_truncation_trailing_data_wrong_magic_and_message_type() {
        let (limits, sync) = fixture();
        let wire = encode(&Message::Sync(sync), limits).unwrap();
        for end in 0..wire.len() {
            assert!(
                decode(&wire[..end], limits).is_err(),
                "accepted truncation {end}"
            );
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(decode(&trailing, limits).is_err());
        let mut bad_magic = wire.clone();
        bad_magic[0] ^= 1;
        assert!(decode(&bad_magic, limits).is_err());
        let mut unknown = wire;
        unknown[8] = u8::MAX;
        assert!(decode(&unknown, limits).is_err());
        let ack = encode(&Message::Ack, limits).unwrap();
        assert_eq!(ack.len(), ACK_BYTES);
        assert_eq!(decode(&ack, limits).unwrap(), Message::Ack);
        let mut ack_extra = ack;
        ack_extra.push(0);
        assert!(decode(&ack_extra, limits).is_err());
    }
    #[test]
    fn rejects_declared_collection_and_record_lengths_before_contents() {
        let (limits, _) = fixture();
        let prefix = [MAGIC.as_slice(), &[0], &[0; 32]].concat();
        for count in [129u64, u64::MAX] {
            let mut wire = prefix.clone();
            wire.extend(codec::encode(&count));
            assert!(decode(&wire, limits).is_err());
        }
        for (prefix_tail, count) in [(vec![0], 33u64), (vec![0, 0], 257u64)] {
            let mut wire = prefix.clone();
            wire.extend(prefix_tail);
            wire.extend(codec::encode(&count));
            assert!(decode(&wire, limits).is_err());
        }
        for (tail, maximum) in [
            (vec![0, 1], limits.block_bytes),
            (vec![0, 0, 1], limits.transaction_bytes),
        ] {
            let mut wire = prefix.clone();
            wire.extend(tail);
            wire.extend(codec::encode(&(maximum as u64 + 1)));
            assert!(decode(&wire, limits).is_err());
        }
        for bad in [
            vec![251, 0, 0],
            vec![252, 251, 0, 0, 0],
            vec![254],
            vec![255],
        ] {
            let mut wire = prefix.clone();
            wire.extend(bad);
            assert!(decode(&wire, limits).is_err());
        }
        let mut missing = prefix;
        missing.push(1);
        assert!(decode(&missing, limits).is_err());
    }
    #[test]
    fn nested_record_limits_apply_before_allocating_transactions_or_data() {
        let (limits, sync) = fixture();
        let mut block = sync.blocks[0].clone();
        block.transactions.clear();
        let mut bytes = codec::encode(&block);
        assert_eq!(bytes.pop(), Some(0));
        bytes.extend(codec::encode(&u64::MAX));
        assert!(preflight_block(&bytes, limits).is_err());
        let mut tx = sync.transactions[0].clone();
        tx.body.data.clear();
        let mut bytes = codec::encode(&tx);
        let data_at = bytes.len() - 65;
        bytes.splice(data_at..data_at + 1, codec::encode(&u64::MAX));
        let mut r = Cursor::new(&bytes);
        assert!(r.transaction(limits.transaction_bytes).is_err());
        let smaller = Limits {
            transaction_bytes: 64,
            ..limits
        };
        let wire = encode(&Message::Sync(sync.clone()), limits).unwrap();
        assert!(decode(&wire, smaller).is_err());
        let fewer = Limits {
            block_transactions: 1,
            ..limits
        };
        assert!(decode(&wire, fewer).is_err());
        let tiny = Limits {
            block_bytes: 1,
            ..limits
        };
        assert!(decode(&wire, tiny).is_err());
        tx.body.fee = 0u32.into();
        let bytes = codec::encode(&tx);
        let amount_at = 64 + codec::encode(&tx.body.nonce).len();
        let mut bad = bytes.clone();
        bad.splice(amount_at..amount_at + 1, [1, 0]);
        let mut r = Cursor::new(&bad);
        assert!(r.transaction(limits.transaction_bytes).is_err());
    }
    #[test]
    fn grant_payment_counts_are_bounded_before_nested_peer_record_work() {
        let (limits, sync) = fixture();
        let mut template = sync.transactions[4].clone();
        for count in [1usize, 17, 100] {
            let mut payments: Vec<_> = (1..=count)
                .map(|n| GrantPayment {
                    recipient: crypto::public_key(&[n as u8; 32]).unwrap(),
                    amount: Amount::from(n),
                })
                .collect();
            payments.sort_by_key(|p| p.recipient);
            let Operation::Propose { proposal, .. } = &mut template.body.operation else {
                panic!()
            };
            *proposal = Proposal::Grant { payments };
            template = crypto::sign(&template.body, &[1; 32]).unwrap();
            let mut current = sync.clone();
            current.transactions = vec![template.clone()];
            current.blocks[0].transactions = vec![template.clone()];
            let expected = Message::Sync(current);
            assert_eq!(
                decode(&encode(&expected, limits).unwrap(), limits).unwrap(),
                expected
            );
        }
        let raw = codec::encode(&template);
        let mut cursor = Cursor::new(&raw);
        cursor.take(64).unwrap();
        cursor.integer().unwrap();
        cursor.amount().unwrap();
        cursor.integer().unwrap();
        assert_eq!(cursor.integer().unwrap(), 3);
        cursor.integer().unwrap();
        cursor.take(32).unwrap();
        assert_eq!(cursor.integer().unwrap(), 0);
        let count_at = cursor.at;
        for count in [1, 17, u64::MAX] {
            // No payment payload follows: the declared count must be rejected
            // before either the first payment or bincode allocation is attempted.
            let bad = [&raw[..count_at], codec::encode(&count).as_slice()].concat();
            let error = Cursor::new(&bad)
                .transaction(limits.transaction_bytes)
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("grant count exceeds remaining transaction bytes")
            );
            let mut wire = [MAGIC.as_slice(), &[0], &sync.chain, &[0, 0, 1]].concat();
            push_record(&mut wire, &bad, limits.frame_bytes()).unwrap();
            assert!(decode(&wire, limits).is_err());
            let mut block = sync.blocks[0].clone();
            block.transactions.clear();
            let mut block_bytes = codec::encode(&block);
            assert_eq!(block_bytes.pop(), Some(0));
            block_bytes.push(1);
            block_bytes.extend(&bad);
            assert!(preflight_block(&block_bytes, limits).is_err());
        }
        for bad_count in [vec![0], vec![251, 16, 0]] {
            let bad = [&raw[..count_at], &bad_count].concat();
            assert!(
                Cursor::new(&bad)
                    .transaction(limits.transaction_bytes)
                    .is_err()
            );
        }
    }
    #[test]
    fn binary_frames_are_length_delimited_and_bounded() {
        let (limits, sync) = fixture();
        let payload = encode(&Message::Sync(sync), limits).unwrap();
        let framed = frame(&payload, limits.frame_bytes()).unwrap();
        assert_eq!(
            u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
            payload.len()
        );
        assert_eq!(&framed[4..], payload);
        assert!(frame(&[], limits.frame_bytes()).is_err());
        assert!(frame(&payload, payload.len() - 1).is_err());
    }
    #[test]
    fn preflight_accepts_block_count_and_price_movement_parameters_but_rejects_unknown_tags() {
        let (limits, sync) = fixture();
        for parameter in [
            Parameter::DecisionBlocks,
            Parameter::MinimumFeeRate,
            Parameter::MaxPriceChangeBps,
        ] {
            let tx = transaction(
                Operation::Propose {
                    round: 1,
                    description: [4; 32],
                    support: 3u32.into(),
                    proposal: Proposal::Parameter {
                        parameter,
                        old: 1,
                        new: 2,
                    },
                },
                0,
            );
            let mut current = sync.clone();
            current.transactions = vec![tx.clone()];
            current.blocks[0].transactions = vec![tx.clone()];
            let wire = encode(&Message::Sync(current.clone()), limits).unwrap();
            assert_eq!(decode(&wire, limits).unwrap(), Message::Sync(current));
            let raw = codec::encode(&tx);
            let mut cursor = Cursor::new(&raw);
            cursor.take(64).unwrap();
            cursor.integer().unwrap();
            cursor.amount().unwrap();
            cursor.integer().unwrap();
            assert_eq!(cursor.integer().unwrap(), 3);
            cursor.integer().unwrap();
            cursor.take(32).unwrap();
            assert_eq!(cursor.integer().unwrap(), 1);
            let mut unknown = raw.clone();
            unknown[cursor.at] = 9;
            assert!(
                Cursor::new(&unknown)
                    .transaction(limits.transaction_bytes)
                    .unwrap_err()
                    .to_string()
                    .contains("invalid parameter tag")
            );
        }
    }
    #[test]
    fn nested_preflight_matches_integer_option_and_amount_boundaries() {
        let (limits, mut sync) = fixture();
        sync.transactions[0].body.nonce = u64::MAX;
        sync.transactions[0].body.expiry_height = u64::MAX;
        sync.transactions[0] = crypto::sign(&sync.transactions[0].body, &[1; 32]).unwrap();
        sync.blocks[0].height = u64::MAX;
        let wire = encode(&Message::Sync(sync.clone()), limits).unwrap();
        assert_eq!(decode(&wire, limits).unwrap(), Message::Sync(sync.clone()));
        let raw = codec::encode(&sync.transactions[1]);
        let mut cursor = Cursor::new(&raw);
        cursor.take(64).unwrap();
        cursor.integer().unwrap();
        let amount_at = cursor.at;
        for length in [8193u64, u64::MAX] {
            let mut bad = raw.clone();
            bad.splice(amount_at..amount_at + 1, codec::encode(&length));
            assert!(
                Cursor::new(&bad)
                    .transaction(limits.transaction_bytes)
                    .is_err()
            );
        }
        cursor.amount().unwrap();
        cursor.integer().unwrap();
        assert_eq!(cursor.integer().unwrap(), 1);
        cursor.amount().unwrap();
        let mut bad = raw.clone();
        bad[cursor.at] = 2;
        assert!(
            Cursor::new(&bad)
                .transaction(limits.transaction_bytes)
                .is_err()
        );
        let mut bad = codec::encode(&sync.blocks[0]);
        let width = codec::encode(&sync.blocks[0].header.version).len();
        bad.splice(..width, codec::encode(&(u32::MAX as u64 + 1)));
        assert!(preflight_block(&bad, limits).is_err());
    }
}
