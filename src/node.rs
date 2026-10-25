//! Bounded local RPC, fork-aware peer synchronization and solo Stratum V1.
/// The `run --wallet-passphrase-file` passphrase that seals node hot keys.
pub use crate::wallet_store::WalletPassphrase;
use crate::{
    address,
    chain::{
        Chain, HeaderDeferred, HeaderHold, HeaderParent, MAX_SELECTION_CANDIDATES, SelectionResult,
        StorageHealth,
    },
    codec,
    config::Config,
    crypto,
    explorer::Explorer,
    fees, math,
    network_guard::{
        self, NetworkGuard, PeerClass, PeerSlots, Session, StratumPending, Surface, TrustedPrefix,
    },
    peer_auth::{Channel as PeerChannel, Policy as PeerPolicy},
    peer_discovery::{self, AddressBook, Options as DiscoveryOptions},
    peer_wire::{self, Message as PeerPacket, Sync as PeerMessage},
    state::State,
    types::*,
    wallet,
    wallet_store::{ManageRequest, WalletStore},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use num_traits::{ToPrimitive, Zero};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinHandle,
    time::timeout,
};
use zeroize::Zeroizing;

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_MEMPOOL: usize = 256;
pub const MAX_ADAPTIVE_MEMPOOL: usize = 4096;

fn mempool_limit(_config: &Config) -> usize {
    MAX_ADAPTIVE_MEMPOOL
}
/// Previously pooled transactions that lost only to block capacity. They wait
/// beside the next-block selection, bounded by this count and one block's bytes.
pub const MAX_BACKLOG: usize = MAX_MEMPOOL;
/// Detached blocks plus their transactions examined by one reorg recovery.
const MAX_RECOVERY_EXAMINED: usize = 2 * MAX_SELECTION_CANDIDATES;
const MAX_REJECTED_TRANSACTIONS: usize = 4096;
pub const MAX_FRAME: usize = 32 * 1024 * 1024;
// Service pagination target only. It never bounds a canonical record.
const JSON_PAGE_BYTES: usize = 32 * 1024 * 1024;
fn transaction_request_bytes(transaction_bytes: usize) -> Result<usize> {
    // A representable small request remains usable even when governance chose
    // a capacity whose largest possible hexadecimal envelope cannot fit a Vec.
    Ok(transaction_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(128 * 1024))
        .unwrap_or(isize::MAX as usize)
        .min(isize::MAX as usize))
}
fn admission_frame_bytes(config: &Config, capacity: u64) -> Result<usize> {
    let peer = peer_wire::Limits::for_capacity(config, capacity).frame_bytes();
    let bytes = usize::try_from(capacity).unwrap_or(isize::MAX as usize);
    let http = transaction_request_bytes(bytes)?
        .saturating_add(16 * 1024)
        .min(isize::MAX as usize);
    Ok(peer.max(http))
}
// Local response service limit; independent of canonical record validity.
pub(crate) const MAX_RESPONSE_FRAME: usize = 193 * 1024 * 1024;
/// Transaction IDs one `blockreceipt` lookup may name.
pub(crate) const MAX_RECEIPT_TXIDS: usize = 64;
/// A governed capacity can make one valid record's hexadecimal response exceed
/// the fixed service limit; the HTTP frame then grows with that capacity.
fn response_frame_bytes(transaction_bytes: usize) -> Result<usize> {
    Ok(MAX_RESPONSE_FRAME.max(
        transaction_request_bytes(transaction_bytes)?
            .saturating_add(64 * 1024)
            .min(isize::MAX as usize),
    ))
}
/// A confirmed record stays servable after governance lowers capacity, so the
/// HTTP frame follows the greatest validated block capacity (the active
/// history's or a competitive branch's), as request admission does.
fn http_response_frame(transaction_bytes: usize, known_block_bytes: u64) -> Result<usize> {
    response_frame_bytes(
        transaction_bytes.max(usize::try_from(known_block_bytes).unwrap_or(isize::MAX as usize)),
    )
}
/// Read responses charge one admission work unit per this many projected JSON
/// values: about one grant payment, matching the per-recipient request charge.
const RESPONSE_VALUES_PER_WORK: usize = 32;
/// Admission work for one exact curved-price evaluation: a few milliseconds of
/// 2048-bit series arithmetic, about 1/256 s of the RPC work refill rate.
const CURVE_EVALUATION_WORK: usize = 512;
/// Grant payments kept by a display summary of a record too large for a page.
const SUMMARY_GRANT_PAYMENTS: usize = 256;

/// Admission work for a request that reselects the pending pool with one
/// newcomer, or scans it: one unit per pending entry (the published
/// selection and its backlog) plus the newcomer, and at least MAX_MEMPOOL,
/// as each mined block is charged and as peers pay for the pool their loose
/// transactions are selected against. A small pool's change is not charged as
/// a full 4,096-entry selection, so a sustained local workload is not refused
/// for work that did not run; a full pool still pays for all of it.
fn pool_change_work(pending: usize) -> usize {
    pending.saturating_add(1).max(MAX_MEMPOOL)
}
/// Charge read work once its actual size is known. In-process calls are unmetered.
fn charge(meter: Option<&Session>, work: usize) -> Result<()> {
    match meter {
        Some(session) if work > 0 => session.work(work),
        _ => Ok(()),
    }
}

/// Bound collection responses before constructing their generic JSON trees.
/// The cursor/offset always advances by returned rows, including when either
/// the serialized-byte or JSON-value budget ends a page early.
struct JsonPage {
    items: Vec<Value>,
    bytes_left: usize,
    values_left: usize,
}
impl JsonPage {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            bytes_left: JSON_PAGE_BYTES,
            values_left: network_guard::MAX_JSON_VALUES,
        }
    }
    fn encode<T: Serialize>(&self, row: &T) -> Result<(Vec<u8>, usize)> {
        struct BoundedJson {
            bytes: Vec<u8>,
            maximum: usize,
        }
        impl std::io::Write for BoundedJson {
            fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
                if input.len() > self.maximum.saturating_sub(self.bytes.len()) {
                    return Err(std::io::Error::other("JSON page byte budget exhausted"));
                }
                self.bytes.extend_from_slice(input);
                Ok(input.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = BoundedJson {
            bytes: Vec::new(),
            maximum: self.bytes_left,
        };
        serde_json::to_writer(&mut output, row)?;
        let values = network_guard::preflight_json_value_count(&output.bytes, self.values_left)?;
        Ok((output.bytes, values))
    }
    fn accept(&mut self, (bytes, values): (Vec<u8>, usize)) -> Result<bool> {
        self.items.push(serde_json::from_slice(&bytes)?);
        self.bytes_left -= bytes.len();
        self.values_left -= values;
        Ok(true)
    }
    fn push<T: Serialize>(&mut self, row: &T) -> Result<bool> {
        match self.encode(row) {
            Ok(record) => self.accept(record),
            Err(_) if !self.items.is_empty() => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// A first row too large for an empty page is replaced by its bounded
    /// summary, so one large record never makes a page, or a snapshot that
    /// embeds it, unavailable. Later oversized rows still start the next page.
    fn push_summarized<T: Serialize>(
        &mut self,
        row: &T,
        summary: impl FnOnce() -> Result<Value>,
    ) -> Result<bool> {
        match self.encode(row) {
            Ok(record) => self.accept(record),
            Err(_) if !self.items.is_empty() => Ok(false),
            Err(_) => self.push(&summary()?),
        }
    }
}

#[derive(Serialize)]
struct ProposalPageRow<'a> {
    id: String,
    proposal: ProposalView<'a>,
}

/// One `proposal` object for clients: the record and its action, which
/// consensus keeps in a separate write-once map.
#[derive(Serialize)]
struct ProposalView<'a> {
    #[serde(flatten)]
    record: &'a crate::state::ProposalRecord,
    action: &'a Proposal,
}

/// A display row whose grant payments were cut to SUMMARY_GRANT_PAYMENTS.
#[derive(Serialize)]
struct Truncated<T> {
    #[serde(flatten)]
    row: T,
    truncated: bool,
    payment_count: usize,
}

fn grant_payments(proposal: &Proposal) -> usize {
    match proposal {
        Proposal::Grant { payments } => payments.len(),
        Proposal::Parameter { .. } => 0,
    }
}
fn truncated_proposal(proposal: &Proposal) -> Proposal {
    match proposal {
        Proposal::Grant { payments } => Proposal::Grant {
            payments: payments
                .iter()
                .take(SUMMARY_GRANT_PAYMENTS)
                .cloned()
                .collect(),
        },
        other => other.clone(),
    }
}
fn truncated_operation(operation: &Operation) -> (Operation, usize) {
    match operation {
        Operation::Propose {
            round,
            description,
            proposal,
            support,
        } => (
            Operation::Propose {
                round: *round,
                description: *description,
                proposal: truncated_proposal(proposal),
                support: support.clone(),
            },
            grant_payments(proposal),
        ),
        other => (other.clone(), 0),
    }
}

#[derive(Serialize)]
struct RawMempoolRow<'a> {
    #[serde(flatten)]
    transaction: &'a Transaction,
    display_operation: &'a Operation,
}

#[derive(Serialize)]
struct PendingBody<'a> {
    sender: PublicKey,
    nonce: u64,
    fee: String,
    anchor: Hash,
    expiry_blocks: u64,
    operation: &'a Operation,
}

#[derive(Serialize)]
struct PendingRow<'a> {
    body: PendingBody<'a>,
}

fn pending_row<'a>(body: &TransactionBody, operation: &'a Operation) -> PendingRow<'a> {
    PendingRow {
        body: PendingBody {
            sender: body.sender,
            nonce: body.nonce,
            fee: body.fee.to_str_radix(10),
            anchor: body.anchor,
            expiry_blocks: body.expiry_blocks,
            operation,
        },
    }
}

/// Pre-charged projection work for mempool rows: one unit per row and grant
/// payment (at most SUMMARY_GRANT_PAYMENTS for snapshot summaries), plus one
/// per 32 data bytes (JSON numbers) for full JSON rows; hex rows cost one unit
/// per KiB of hexadecimal output.
fn mempool_work(pool: &[Transaction], offset: usize, limit: usize, format: &str) -> usize {
    pool.iter()
        .skip(offset)
        .take(limit)
        .map(|transaction| {
            let payments = pending_payments(&transaction.body.operation);
            let data = transaction.body.data.len();
            1 + match format {
                "summary" => payments.min(SUMMARY_GRANT_PAYMENTS),
                "hex" => (payments * 34 + data) / 512,
                _ => payments + data / RESPONSE_VALUES_PER_WORK,
            }
        })
        .fold(0, usize::saturating_add)
}

fn pending_payments(operation: &Operation) -> usize {
    match operation {
        Operation::Propose { proposal, .. } => grant_payments(proposal),
        _ => 0,
    }
}

fn mempool_page(pool: &[Transaction], offset: usize, limit: usize, summary: bool) -> Result<Value> {
    let mut page = JsonPage::new();
    for transaction in pool.iter().skip(offset).take(limit) {
        let accepted = if summary {
            let body = &transaction.body;
            // Summaries never fail on one huge pending grant, and stay bounded
            // like the snapshot's proposal rows; full rows are in `mempool`.
            let summarize = || -> Result<Value> {
                let (operation, payment_count) = truncated_operation(&body.operation);
                Ok(serde_json::to_value(Truncated {
                    row: pending_row(body, &operation),
                    truncated: true,
                    payment_count,
                })?)
            };
            if pending_payments(&body.operation) > SUMMARY_GRANT_PAYMENTS {
                page.push(&summarize()?)?
            } else {
                page.push_summarized(&pending_row(body, &body.operation), summarize)?
            }
        } else {
            page.push(&RawMempoolRow {
                transaction,
                display_operation: &transaction.body.operation,
            })?
        };
        if !accepted {
            break;
        }
    }
    Ok(Value::Array(page.items))
}

fn mempool_hex_page(pool: &[Transaction], offset: usize, limit: usize) -> Result<Value> {
    let mut items = Vec::new();
    let mut size = 0usize;
    for transaction in pool.iter().skip(offset).take(limit) {
        let bytes = codec::encode(transaction);
        let row_bytes = bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(128))
            .context("hex record length overflow")?;
        if !items.is_empty() && size.saturating_add(row_bytes) > JSON_PAGE_BYTES {
            break;
        }
        // Return one large record alone, without turning a page target into a
        // transaction-size limit or silently skipping an accepted record.
        items.push(json!({"txid":hex::encode(crypto::sha256d(&bytes)),"raw":hex::encode(bytes)}));
        size = size.saturating_add(row_bytes);
    }
    Ok(Value::Array(items))
}

const MAX_BATCH: usize = peer_wire::MAX_BLOCKS;
// One reply's block work plus the recipient's loose-transaction and pool
// (selection plus backlog) reselection terms stays within one second of peer
// work refill.
const PEER_BATCH_WORK: usize = network_guard::PEER_WORK_PER_SECOND as usize
    - peer_wire::MAX_TRANSACTIONS
    - MAX_ADAPTIVE_MEMPOOL
    - MAX_BACKLOG;
const MAX_SNAPSHOT_KEYS: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Deadline for the request line and headers on the public-web listener.
const PUBLIC_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const VERSION_MASK: u32 = 0x1fffe000;
const HASHRATE_WINDOW_SECONDS: u64 = 300;
const MAX_SUBMITTED_HEADERS: usize = 4096;
pub const DEFAULT_STRATUM_SHARE_DIFFICULTY: f64 = 65_536.0;
/// Of the MAX_CONNECTIONS authorized worker slots, sources outside the
/// operator's `--stratum-trusted` prefixes may hold all but this many when
/// the operator named any, and at most STRATUM_GROUP_WORKERS from one group
/// (IPv4 /24, IPv6 /48, or one address on a local network). Trusted prefixes
/// may use every slot.
pub const STRATUM_TRUSTED_WORKERS: usize = 16;
pub const STRATUM_GROUP_WORKERS: usize = 16;
/// When the slots a newly authorized worker may use are full, it replaces
/// the worker it competes with that has gone longest without a valid share,
/// counted from its authorization, once that is at least this long. Miners
/// that keep reporting shares are never replaced, and idle sockets cannot
/// keep every slot from new miners.
pub const STRATUM_IDLE_WORKER: Duration = Duration::from_secs(300);

struct MiningWorker {
    worker: String,
    accepted: u64,
    rejected: u64,
    blocks: u64,
    difficulty: f64,
    last_share: Option<Instant>,
    /// When it authorized or last sent a valid share or block. A share
    /// refused for a rate or a budget that others share still proves work.
    active: Instant,
    /// The source's group (see `network_guard::stratum_group`), and whether
    /// a prefix the operator trusts holds it.
    group: IpAddr,
    trusted: bool,
    /// Told when a newcomer replaces this worker, which then disconnects.
    evict: Arc<tokio::sync::Notify>,
}
struct WorkBucket {
    second: u64,
    samples: u64,
    work: Amount,
}
struct MiningRuntime {
    enabled: bool,
    bind_address: Option<SocketAddr>,
    connect_url: Option<String>,
    /// Whether `connect_url` came from `--stratum-advertise`. A URL derived
    /// from the bind address names an operator interface and stays private.
    advertised: bool,
    password_required: bool,
    difficulty: f64,
    /// Worker slots that only trusted prefixes may use: STRATUM_TRUSTED_WORKERS,
    /// or none while the operator trusts no prefix.
    trusted_reserve: usize,
    started: Instant,
    accepted: u64,
    rejected: u64,
    blocks: u64,
    workers: HashMap<u32, MiningWorker>,
    buckets: VecDeque<WorkBucket>,
}
impl Default for MiningRuntime {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: None,
            connect_url: None,
            advertised: false,
            password_required: false,
            difficulty: DEFAULT_STRATUM_SHARE_DIFFICULTY,
            trusted_reserve: STRATUM_TRUSTED_WORKERS,
            started: Instant::now(),
            accepted: 0,
            rejected: 0,
            blocks: 0,
            workers: HashMap::new(),
            buckets: VecDeque::new(),
        }
    }
}
impl MiningRuntime {
    /// Register a newly authorized worker as `id`, replacing an idle worker
    /// when the slots it may use are full: one of its own group when that
    /// group is at its cap, otherwise one outside trusted prefixes, or for a
    /// trusted newcomer, failing that, a trusted one. The replaced session is
    /// told to close. Without such a worker the newcomer is refused.
    fn register(
        &mut self,
        id: u32,
        worker: MiningWorker,
        now: Instant,
    ) -> Result<(), &'static str> {
        let (group, trusted) = (worker.group, worker.trusted);
        let general = self.workers.values().filter(|w| !w.trusted).count();
        let grouped = self
            .workers
            .values()
            .filter(|w| !w.trusted && w.group == group)
            .count();
        let victim = if !trusted && grouped >= STRATUM_GROUP_WORKERS {
            let victim = self.idlest(now, |w| !w.trusted && w.group == group);
            Some(victim.ok_or("per-network mining worker limit reached")?)
        } else if self.workers.len() >= MAX_CONNECTIONS
            || (!trusted && general >= MAX_CONNECTIONS - self.trusted_reserve)
        {
            let victim = self
                .idlest(now, |w| !w.trusted)
                .or_else(|| trusted.then(|| self.idlest(now, |w| w.trusted)).flatten());
            Some(victim.ok_or("mining worker capacity reached")?)
        } else {
            None
        };
        if let Some(old) = victim.and_then(|victim| self.workers.remove(&victim)) {
            old.evict.notify_one();
        }
        self.workers.insert(id, worker);
        Ok(())
    }
    /// The worker matching `candidate` that has gone longest without a valid
    /// share since it authorized, if that is STRATUM_IDLE_WORKER or more.
    fn idlest(&self, now: Instant, candidate: impl Fn(&MiningWorker) -> bool) -> Option<u32> {
        self.workers
            .iter()
            .filter(|(_, w)| candidate(w))
            .map(|(id, w)| (w.active, *id))
            .filter(|(active, _)| now.saturating_duration_since(*active) >= STRATUM_IDLE_WORKER)
            .min()
            .map(|(_, id)| id)
    }
    /// Worker `id` sent a valid share or block, whether or not it was accepted.
    fn proved(&mut self, id: u32, now: Instant) {
        if let Some(worker) = self.workers.get_mut(&id) {
            worker.active = worker.active.max(now);
        }
    }
    fn prune(&mut self, second: u64) {
        while self
            .buckets
            .front()
            .is_some_and(|b| b.second + HASHRATE_WINDOW_SECONDS <= second)
        {
            self.buckets.pop_front();
        }
    }
    fn submission(&mut self, worker: Option<u32>, accepted: Option<(Option<&Amount>, bool)>) {
        let instant = Instant::now();
        match accepted {
            Some((work, block)) => {
                self.accepted = self.accepted.saturating_add(1);
                self.blocks = self.blocks.saturating_add(u64::from(block));
                if let Some(work) = work {
                    let second = self.started.elapsed().as_secs();
                    self.prune(second);
                    if !self.buckets.back().is_some_and(|b| b.second == second) {
                        self.buckets.push_back(WorkBucket {
                            second,
                            samples: 0,
                            work: Amount::zero(),
                        });
                    }
                    let bucket = self.buckets.back_mut().unwrap();
                    bucket.work += work;
                    bucket.samples += 1;
                }
                if let Some(w) = worker.and_then(|id| self.workers.get_mut(&id)) {
                    w.accepted = w.accepted.saturating_add(1);
                    w.blocks = w.blocks.saturating_add(u64::from(block));
                    w.last_share = Some(instant);
                }
            }
            None => {
                self.rejected = self.rejected.saturating_add(1);
                if let Some(w) = worker.and_then(|id| self.workers.get_mut(&id)) {
                    w.rejected = w.rejected.saturating_add(1);
                }
            }
        }
    }
    fn value(&mut self, miner: &PublicKey, chain_id: &Hash) -> Result<Value> {
        let second = self.started.elapsed().as_secs();
        self.prune(second);
        let elapsed = second.min(HASHRATE_WINDOW_SECONDS);
        let samples: u64 = self.buckets.iter().map(|b| b.samples).sum();
        let work: Amount = self.buckets.iter().map(|b| &b.work).sum();
        let hashrate = if elapsed >= 30 && samples >= 3 {
            Some((work / elapsed).to_str_radix(10))
        } else {
            None
        };
        let mut workers: Vec<_> = self.workers.iter().collect();
        workers.sort_by_key(|(id, _)| **id);
        Ok(json!({
            "payout_public_key":hex::encode(miner),
            "payout_address":address::encode(miner, chain_id)?,
            "stratum":{
                "enabled":self.enabled,
                "bind_address":self.bind_address.map(|address| address.to_string()),
                "connect_url":self.connect_url,
                "loopback_only":self.bind_address.is_some_and(|address| address.ip().is_loopback()),
                "password_required":self.password_required,
                "share_difficulty":self.difficulty
            },
            "workers_connected":workers.len(),
            "accepted_shares":self.accepted.to_string(),
            "rejected_shares":self.rejected.to_string(),
            "blocks_found":self.blocks.to_string(),
            "hashrate_hps":hashrate,
            "hashrate_window_seconds":elapsed,
            "workers":workers.into_iter().map(|(_,w)| json!({
                "worker":w.worker,"accepted_shares":w.accepted.to_string(),
                "rejected_shares":w.rejected.to_string(),"blocks_found":w.blocks.to_string(),
                "share_difficulty":w.difficulty,
                "last_share_age_seconds":w.last_share.map(|t|t.elapsed().as_secs())
            })).collect::<Vec<_>>()
        }))
    }
}
struct MiningConnection {
    runtime: Arc<Mutex<MiningRuntime>>,
    id: u32,
}
impl Drop for MiningConnection {
    fn drop(&mut self) {
        self.runtime.unpoisoned().workers.remove(&self.id);
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn parse_hash(s: &str) -> Result<Hash> {
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte hexadecimal value"))
}
pub fn parse_key(s: &str) -> Result<PublicKey> {
    let key = parse_hash(s)?;
    ensure!(crypto::valid_key(&key), "invalid BIP340 public key");
    Ok(key)
}
/// Technical interfaces also accept legacy raw keys; encoded addresses are
/// always checksum-validated against this chain before becoming account keys.
pub fn parse_account(s: &str, chain_id: &Hash) -> Result<PublicKey> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        parse_key(s)
    } else {
        address::decode(s, chain_id)
    }
}

/// Expected hashes per block below which proof of work gates nothing: about
/// a second of one GPU, and far less of any ASIC.
pub const EASY_LIMIT_WORK: u64 = 1 << 32;
/// Expected hashes of one block at the network's easiest permitted target.
pub fn limit_work(config: &Config) -> Result<Amount> {
    Ok(math::work(&math::target_from_bits(config.limit_bits)?))
}
/// Whether the easiest permitted target makes blocks practically free, as the
/// presets' development limit (0x207fffff, about two hashes per block) does
/// until `init --hashrate` calibrates it. Side-branch admission, header
/// presync and the other proof-of-work-gated defences then cost an attacker
/// nothing whenever difficulty eases to that limit.
pub fn easy_proof_of_work(config: &Config) -> bool {
    limit_work(config).is_ok_and(|work| work < Amount::from(EASY_LIMIT_WORK))
}
/// A disposable development network: fixture issuance, or proof of work
/// that a CPU mines at once on a node that no untrusted peer reaches (see
/// `serve`). Only there may local processes mine through RPC. Untrusted
/// peers' hashrate can lift an easy network's difficulty far above its limit.
pub fn development_network(config: &Config, untrusted_peers: bool) -> bool {
    config.test_work || (!untrusted_peers && easy_proof_of_work(config))
}
/// Mining attempts charged as one work unit by the `mine` RPC.
const MINE_ATTEMPTS_PER_WORK: u64 = 4096;

/// Block commits that may fail in a row, over at least STORAGE_EXIT_SECONDS,
/// before the node exits with STORAGE_EXIT_STATUS: storage that cannot take
/// blocks, such as a full disk, would otherwise leave a running node on a
/// frozen tip whose miners' blocks are lost.
const STORAGE_EXIT_FAILURES: u32 = 8;
const STORAGE_EXIT_SECONDS: u64 = 60;
/// EX_IOERR from sysexits.h, distinct from the 70 of a poisoned lock.
const STORAGE_EXIT_STATUS: i32 = 74;
/// Whether storage has failed long enough for the node to stop.
fn storage_exit_due(health: &StorageHealth, now: u64) -> bool {
    health.failed_commits >= STORAGE_EXIT_FAILURES
        && health
            .failing_since
            .is_some_and(|since| now.saturating_sub(since) >= STORAGE_EXIT_SECONDS)
}
/// A panic while shared node state was held may have left it half updated.
/// Exit so a supervisor restarts from durable storage instead of keeping a live
/// process that can no longer validate, mine or accept mutations.
fn poisoned(lock: &str) -> ! {
    eprintln!("fatal: {lock} lock poisoned by an earlier panic; exiting for a supervised restart");
    std::process::exit(70)
}
/// Locks holding only counters, diagnostics, caches or the peer address book,
/// never chain, snapshot or wallet state. A panic while one was held leaves at
/// most a stale entry, so later work keeps using it: one failed connection
/// never disables admission, discovery or mining for the life of the process.
trait Unpoisoned<T> {
    fn unpoisoned(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> Unpoisoned<T> for Mutex<T> {
    fn unpoisoned(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// How long a relay refusal holds. Shape and signature failures are permanent
/// for the exact signed bytes. Checks against chain state alone hold for one
/// tip. A newcomer that lost its selection, or that the replacement or
/// full-pool rule refused, holds only while both the tip and the pool it was
/// judged against are unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Permanent,
    Tip(Hash),
    Pool(Hash, u64),
}
/// Recently rejected relay and submission identities, with the reason given.
#[derive(Default)]
struct RejectedTransactions {
    entries: HashMap<Hash, (Refusal, String)>,
    order: VecDeque<Hash>,
}
impl RejectedTransactions {
    fn contains(&self, id: &Hash, tip: &Hash, pool_revision: u64) -> bool {
        self.refusal(id, tip, pool_revision).is_some()
    }
    /// Why `id` was refused, while that refusal still holds.
    fn refusal(&self, id: &Hash, tip: &Hash, pool_revision: u64) -> Option<&str> {
        let (refusal, reason) = self.entries.get(id)?;
        match refusal {
            Refusal::Permanent => true,
            Refusal::Tip(at) => at == tip,
            Refusal::Pool(at, revision) => at == tip && *revision == pool_revision,
        }
        .then_some(reason.as_str())
    }
    #[cfg(test)]
    fn insert(&mut self, id: Hash, scope: Refusal) {
        self.refuse(id, scope, "transaction recently refused");
    }
    fn refuse(&mut self, id: Hash, scope: Refusal, reason: &str) {
        let reason = reason.chars().take(256).collect();
        if self.entries.insert(id, (scope, reason)).is_none() {
            self.order.push_back(id);
        }
        while self.order.len() > MAX_REJECTED_TRANSACTIONS {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            }
        }
    }
}

/// Admissible newcomers screened before a selection.
#[derive(Default)]
struct Newcomers<'a> {
    /// Worth a selection, in arrival order.
    candidates: Vec<(Hash, &'a Transaction)>,
    /// Candidates that rebid or extend their own sender's backlog chain.
    waiting: HashSet<Hash>,
    /// Refused by the next block's opening (fee or funds); final for this tip.
    unpayable: Vec<(Hash, anyhow::Error)>,
    /// After a missing earlier nonce, which may still arrive on this tip.
    gapped: Vec<Hash>,
    /// Refused by the replacement or full-pool rule; final for this pool.
    outbid: Vec<(Hash, anyhow::Error)>,
}

/// Node-wide wall time that admission work may hold the node lock for, per
/// second and in a burst: every selection a newcomer causes, from a relay, a
/// submission or a hot-wallet send, is charged what it took. Relayed
/// newcomers wait in a queue while it is spent. Public broadcasts have a
/// reserved budget of their own, which relays cannot spend and which is
/// answered 429 while it is spent; however many sources send, their
/// admission keeps the lock at most the sum of the two fractions of the
/// time, plus one selection. The operator's own private submissions are
/// charged to the first but never refused.
const SELECTION_TIME_PER_SECOND: Duration = Duration::from_millis(200);
const SELECTION_TIME_BURST: Duration = Duration::from_secs(1);
const PUBLIC_SELECTION_TIME_PER_SECOND: Duration = Duration::from_millis(50);
const PUBLIC_SELECTION_TIME_BURST: Duration = Duration::from_millis(250);
/// Relayed newcomers queued for that budget, admitted together by one
/// selection: in entries, and in block bytes in all and per source.
const MAX_QUEUED_ADMISSIONS: usize = 1024;
const QUEUED_ADMISSION_BLOCKS: usize = 4;
/// Queued newcomers one drain admits with its selection, at most, and at
/// most one block's bytes of them; the rest wait for the next drain, so one
/// lock hold stays about one selection.
const MAX_DRAINED_ADMISSIONS: usize = MAX_MEMPOOL;
/// Sender nonces remembered as refused for validity by recent selections,
/// for the tip and pool they were judged against.
const MAX_INVALID_NONCES: usize = MAX_REJECTED_TRANSACTIONS;
/// A transaction replacing a pending one at the same sender nonce must raise
/// the signed fee per weight unit by at least 1/REPLACEMENT_RAISE, and by at
/// least the minimum fee rate.
const REPLACEMENT_RAISE: u32 = 8;
/// One sender's backlog chain, past its first entry, holds at most
/// 1/BACKLOG_SENDER_SHARE of the backlog's entries and bytes: each entry's
/// funds are checked on its own, so a chain may hold more than its sender
/// can pay for, and it must not crowd out every other sender's entries.
const BACKLOG_SENDER_SHARE: usize = 2;
/// Executing blocks that would not become the tip: node-wide wall time, and
/// each relaying source's own share of it, per second and in a burst that
/// admits one block at the largest benchmarked clearing cost.
const SIDE_VALIDATION_TIME_PER_SECOND: Duration = Duration::from_millis(250);
const SIDE_SOURCE_TIME_PER_SECOND: Duration = Duration::from_millis(50);
const SIDE_VALIDATION_TIME_BURST: Duration = Duration::from_secs(4);
/// Side-branch blocks one relaying source may have stored, refilled by
/// SIDE_SOURCE_BLOCKS_PER_TIP per new active-chain height, beside the
/// node-wide `chain::SIDE_BRANCH_BURST`: one source alone can spend only a
/// sixteenth of that.
const SIDE_SOURCE_BLOCKS: u64 = crate::chain::SIDE_BRANCH_BURST / 16;
const SIDE_SOURCE_BLOCKS_PER_TIP: u64 = 1;
/// Sources tracked for side-branch shares; fully refilled ones are forgotten.
const MAX_SIDE_SOURCES: usize = 1024;
/// Historical state replay one block submission may run, in steps between
/// which the node lock is released: in all, and per lock hold for a block
/// that would become the tip and for a side block. Every hold of a side
/// block is charged to the side-validation budgets, which are checked again
/// before the next. A block that would become the tip is never refused, so
/// its holds are sized by time instead: its first hold replays one step, and
/// each later one as many as fit REPLAY_HOLD_TIME at the pace the previous
/// hold measured, at least one and at most REPLAY_STEPS_PER_HOLD (see
/// [replay_steps_after]).
const REPLAY_STEPS: usize = 64;
const REPLAY_STEPS_PER_HOLD: usize = 8;
const SIDE_REPLAY_STEPS_PER_HOLD: usize = 1;
const REPLAY_HOLD_TIME: Duration = Duration::from_millis(50);
/// Spends from accounts that a pending transfer creates, held until that
/// funding confirms: in all, per sender and per source, and the new tips
/// one may wait for. They also stay within one block's bytes, of which each
/// source holds at most 1/AWAITING_SOURCES. Relaying sources together leave
/// one source's share of entries and bytes to local submissions and reorg
/// recovery.
const MAX_AWAITING: usize = MAX_MEMPOOL;
const AWAITING_PER_SENDER: usize = 16;
const AWAITING_SOURCES: usize = 4;
const AWAITING_PER_SOURCE: usize = MAX_AWAITING / AWAITING_SOURCES;
const AWAITING_TIPS: u32 = 6;

/// A wall-time token bucket. Work is charged after it ran, so the bucket may
/// fall into debt, at most one burst deep; new work starts only with credit.
struct TimeBudget {
    credit: i128,
    at: Instant,
    rate: Duration,
    burst: Duration,
}
impl TimeBudget {
    fn new(rate: Duration, burst: Duration) -> Self {
        Self {
            credit: burst.as_nanos() as i128,
            at: Instant::now(),
            rate,
            burst,
        }
    }
    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.at).as_nanos() as i128;
        let gained = elapsed.saturating_mul(self.rate.as_nanos() as i128) / 1_000_000_000;
        self.credit = self
            .credit
            .saturating_add(gained)
            .min(self.burst.as_nanos() as i128);
        self.at = self.at.max(now);
    }
    /// How long until new work may start; zero while credit remains.
    fn wait(&mut self, now: Instant) -> Duration {
        self.refill(now);
        if self.credit > 0 {
            return Duration::ZERO;
        }
        let missing = (1 - self.credit) as u128;
        let rate = self.rate.as_nanos().max(1);
        let nanos = (missing * 1_000_000_000).div_ceil(rate);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
    fn spend(&mut self, spent: Duration, now: Instant) {
        self.refill(now);
        self.credit = self
            .credit
            .saturating_sub(spent.as_nanos() as i128)
            .max(-(self.burst.as_nanos() as i128));
    }
    fn full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.credit >= self.burst.as_nanos() as i128
    }
}

/// A newcomer for admission, and the peer source that relayed it.
struct Newcomer {
    id: Hash,
    transaction: Transaction,
    /// Its encoded length.
    bytes: usize,
    source: Option<IpAddr>,
    /// The relaying peer's own address, credited when the newcomer enters
    /// the pool (see `PeerSlots::delivered`).
    peer: Option<IpAddr>,
    /// Its signature was already checked.
    authenticated: bool,
    /// The operator's own private submission, exempt from [InvalidNonces].
    operator: bool,
}
impl Newcomer {
    fn new(transaction: Transaction, source: Option<IpAddr>, authenticated: bool) -> Self {
        let encoded = codec::encode(&transaction);
        Self {
            id: crypto::sha256d(&encoded),
            bytes: encoded.len(),
            transaction,
            source,
            peer: None,
            authenticated,
            operator: false,
        }
    }
}
/// Where admission put a newcomer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admitted {
    /// In the selection or its backlog.
    Pending,
    /// Held until the transfer that creates its sender's account confirms.
    Awaiting,
}
/// Relayed newcomers waiting for the selection budget or for a block
/// submission (see `Node::drain_admissions`), at most MAX_QUEUED_ADMISSIONS
/// entries and QUEUED_ADMISSION_BLOCKS blocks' bytes. Each source keeps a
/// fair share: it may hold at most one block's bytes, and a newcomer for a
/// full queue displaces the oldest entries of the source holding the most
/// (entries, or bytes for a queue full of bytes), unless its own source
/// holds as many.
#[derive(Default)]
struct AdmissionQueue {
    entries: VecDeque<Newcomer>,
    ids: HashSet<Hash>,
    /// Entries and bytes held, in all and by source.
    bytes: usize,
    held: BTreeMap<Option<IpAddr>, (usize, usize)>,
}
impl AdmissionQueue {
    /// Queue `newcomer` within the bounds for blocks of `block_bytes`.
    fn push(&mut self, newcomer: Newcomer, block_bytes: usize) {
        if self.ids.contains(&newcomer.id) {
            return;
        }
        let own = self.held.get(&newcomer.source).copied().unwrap_or_default();
        if own.1.saturating_add(newcomer.bytes) > block_bytes {
            return;
        }
        let byte_limit = block_bytes.saturating_mul(QUEUED_ADMISSION_BLOCKS);
        loop {
            let by_bytes = self.bytes.saturating_add(newcomer.bytes) > byte_limit;
            if !by_bytes && self.entries.len() < MAX_QUEUED_ADMISSIONS {
                break;
            }
            let share = |held: &(usize, usize)| if by_bytes { held.1 } else { held.0 };
            let Some((&largest, most)) = self.held.iter().max_by_key(|(_, held)| share(held))
            else {
                return;
            };
            if share(&own) >= share(most) {
                return;
            }
            let Some(evicted) = self
                .entries
                .iter()
                .position(|queued| queued.source == largest)
                .and_then(|oldest| self.entries.remove(oldest))
            else {
                return;
            };
            self.forget(&evicted);
        }
        let held = self.held.entry(newcomer.source).or_default();
        held.0 += 1;
        held.1 += newcomer.bytes;
        self.bytes += newcomer.bytes;
        self.ids.insert(newcomer.id);
        self.entries.push_back(newcomer);
    }
    fn forget(&mut self, newcomer: &Newcomer) {
        self.ids.remove(&newcomer.id);
        self.bytes -= newcomer.bytes;
        if let Some(held) = self.held.get_mut(&newcomer.source) {
            held.0 -= 1;
            held.1 -= newcomer.bytes;
            if held.0 == 0 {
                self.held.remove(&newcomer.source);
            }
        }
    }
    /// The oldest entries, at least one while any is queued, up to
    /// MAX_DRAINED_ADMISSIONS of them and `block_bytes` bytes in all.
    fn take(&mut self, block_bytes: usize) -> Vec<Newcomer> {
        let mut taken = Vec::new();
        let mut bytes = 0usize;
        while let Some(next) = self.entries.front() {
            if taken.len() >= MAX_DRAINED_ADMISSIONS
                || (!taken.is_empty() && bytes.saturating_add(next.bytes) > block_bytes)
            {
                break;
            }
            bytes = bytes.saturating_add(next.bytes);
            let Some(newcomer) = self.entries.pop_front() else {
                break;
            };
            self.forget(&newcomer);
            taken.push(newcomer);
        }
        taken
    }
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
/// The node-wide selection budget, the relayed newcomers queued for it, and
/// the budget reserved for public broadcasts.
struct Admission {
    budget: TimeBudget,
    queue: AdmissionQueue,
    public: TimeBudget,
}

/// A spend whose sender has no account yet, though a pending transfer creates
/// one. Consensus reserves inputs from the block opening, so it can confirm
/// only in a block after that transfer; it waits here meanwhile.
struct Awaiting {
    id: Hash,
    transaction: Transaction,
    /// Its encoded length.
    bytes: usize,
    source: Option<IpAddr>,
    /// New tips seen while its sender still had no account.
    tips: u32,
}

/// Whether `new` may replace `old`, a pending transaction at the same sender
/// nonce: it raises the signed fee per weight unit by at least an eighth and
/// by at least the minimum fee rate, so a sender cannot churn the pool with
/// free replacements, and it earns the miner at least as much per weight
/// unit, so the selection ranks it ahead of `old` by fee rather than by
/// transaction ID (see [crate::chain::Priority]). Weights are quoted against
/// the tip state; one that cannot be quoted is left to the opening screen.
fn replaces(config: &Config, state: &State, new: &Transaction, old: &Transaction) -> bool {
    let (Ok(quoted), Ok(pending)) = (
        fees::quote(config, state, new),
        fees::quote(config, state, old),
    ) else {
        return true;
    };
    let rank = |quote: &fees::FeeQuote| crate::chain::Priority::new(quote, ZERO_HASH);
    raises(
        state,
        (&new.body.fee, quoted.weight),
        (&old.body.fee, pending.weight),
    ) && rank(&quoted).outbids(&rank(&pending))
}
/// Whether a signed fee and weight raise the fee per weight unit of another
/// by the replacement rule's margins (see [replaces]).
fn raises(state: &State, new: (&Amount, u64), old: (&Amount, u64)) -> bool {
    let (new_weight, old_weight) = (Amount::from(new.1), Amount::from(old.1));
    let offered = new.0 * &old_weight;
    let held = old.0 * &new_weight;
    let scale = Amount::from(fees::FEE_SCALE);
    let increment = Amount::from(state.settings.minimum_fee_rate) * &new_weight * &old_weight;
    offered > held
        && &offered * REPLACEMENT_RAISE >= &held * (REPLACEMENT_RAISE + 1)
        && &offered * &scale >= &held * &scale + increment
}
/// Sender nonces at which a selection refused a newcomer for validity, not
/// for capacity, with that newcomer's signed fee and weight, for the tip
/// and pool revision it was judged against. Another relayed or publicly
/// broadcast newcomer at such a nonce, such as a copy changed in one data
/// byte, is refused without a selection unless it raises that fee rate by
/// the replacement rule. The operator's private submissions are exempt.
/// Anyone holding a refused transaction's bytes can resend it once the pool
/// changes, so a transaction refused again, after it already set an entry,
/// sets one that holds back only other resent transactions: a transaction
/// its sender signed since, at an equal fee rate, still gets its selection.
#[derive(Default)]
struct InvalidNonces {
    at: (Hash, u64),
    /// The refused fee and weight, and whether a resent transaction set it.
    entries: BTreeMap<(PublicKey, u64), (Amount, u64, bool)>,
    /// Transactions that set an entry, at most MAX_INVALID_NONCES of the
    /// latest, whatever tip and pool they were judged against.
    set: HashSet<Hash>,
    order: VecDeque<Hash>,
}
impl InvalidNonces {
    /// The refused fee and weight at `transaction`'s sender nonce, while
    /// that refusal holds and holds back `id`.
    fn refused(
        &self,
        at: (Hash, u64),
        id: &Hash,
        transaction: &Transaction,
    ) -> Option<(&Amount, u64)> {
        let body = &transaction.body;
        let (fee, weight, resent) = self.entries.get(&(body.sender, body.nonce))?;
        (self.at == at && (!resent || self.set.contains(id))).then_some((fee, *weight))
    }
    fn refuse(&mut self, at: (Hash, u64), id: Hash, transaction: &Transaction, weight: u64) {
        if self.at != at {
            self.at = at;
            self.entries.clear();
        }
        let resent = self.set.contains(&id);
        if !resent {
            self.set.insert(id);
            self.order.push_back(id);
            while self.order.len() > MAX_INVALID_NONCES {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
        let body = &transaction.body;
        let key = (body.sender, body.nonce);
        // A resent transaction never weakens an entry a new one set.
        let weakens = self
            .entries
            .get(&key)
            .is_some_and(|entry| resent && !entry.2);
        if !weakens && (self.entries.len() < MAX_INVALID_NONCES || self.entries.contains_key(&key))
        {
            self.entries.insert(key, (body.fee.clone(), weight, resent));
        }
    }
}
/// A next-block selection and its capacity-displaced backlog.
type Pool = (Vec<Transaction>, Vec<Transaction>);
/// What a selection left of the next block, by the selection's own body
/// accounting with one further record, and which senders it left undecided.
struct Room {
    used_bytes: usize,
    used_weight: u64,
    byte_limit: usize,
    weight_limit: u64,
    /// Each selected sender's next nonce.
    next: BTreeMap<PublicKey, u64>,
    /// Truncated (which an admission selection never is) or count-full:
    /// every entry it left out is undecided.
    saturated: bool,
    /// Senders whose attempt budget ran out before one of their candidates
    /// was tried. Another sender's spent budget says nothing about an entry.
    exhausted: BTreeSet<PublicKey>,
}
impl Room {
    fn after(chain: &Chain, miner: PublicKey, selection: &SelectionResult) -> Result<Self> {
        let limit = mempool_limit(&chain.config).min(chain.config.max_signatures);
        let mut room = Self::of(chain, miner, &selection.transactions)?;
        room.saturated = selection.truncated || selection.transactions.len() >= limit;
        room.exhausted = selection.exhausted_senders.clone();
        Ok(room)
    }
    /// What `transactions`, a selection on the tip, leave of the next block,
    /// leaving no sender undecided.
    fn of(chain: &Chain, miner: PublicKey, transactions: &[Transaction]) -> Result<Self> {
        let state = chain.tip_state();
        let height = state
            .height
            .checked_add(1)
            .context("candidate height overflow")?;
        let (prefix, suffix) = codec::coinbase_parts(height, &miner, &ZERO_HASH);
        let system = prefix.len() + 8 + suffix.len();
        let mut room = Self {
            used_bytes: compact_size_len(transactions.len() + 2)
                + compact_size_len(system)
                + system
                + 32,
            // Weighted capacity equals block bytes; a missing miner account
            // may reserve one account weight.
            used_weight: if state.account(&miner, None).is_none() {
                fees::ACCOUNT_WEIGHT
            } else {
                0
            },
            byte_limit: usize::try_from(state.settings.block_bytes).unwrap_or(usize::MAX),
            weight_limit: state.settings.block_bytes,
            next: BTreeMap::new(),
            saturated: false,
            exhausted: BTreeSet::new(),
        };
        for tx in transactions {
            let bytes = codec::encode(tx).len();
            room.used_bytes = room
                .used_bytes
                .saturating_add(compact_size_len(bytes) + bytes);
            let weight =
                fees::quote(&chain.config, state, tx).map_or(u64::MAX, |quote| quote.weight);
            room.used_weight = room.used_weight.saturating_add(weight);
            let nonce = room.next.entry(tx.body.sender).or_insert(0);
            *nonce = tx.body.nonce.saturating_add(1).max(*nonce);
        }
        Ok(room)
    }
    fn fits(&self, bytes: usize, weight: u64) -> bool {
        self.used_bytes
            .saturating_add(compact_size_len(bytes) + bytes)
            <= self.byte_limit
            && self.used_weight.saturating_add(weight) <= self.weight_limit
    }
    /// The nonce after `sender`'s selected entries, or its account nonce.
    fn start(&self, state: &State, sender: &PublicKey) -> u64 {
        self.next.get(sender).copied().unwrap_or_else(|| {
            state
                .account(sender, None)
                .map_or(0, |account| account.nonce)
        })
    }
    fn undecided(&self, sender: &PublicKey) -> bool {
        self.saturated || self.exhausted.contains(sender)
    }
}
/// The weakest entry of a full selection, by the selection's own order:
/// miner fee per weight unit, then signed fee per weight unit, then
/// transaction ID (see [crate::chain::Priority]).
#[derive(Clone)]
struct Weakest(crate::chain::Priority);
impl Weakest {
    fn of(config: &Config, state: &State, transaction: &Transaction) -> Option<Self> {
        let quote = fees::quote(config, state, transaction).ok()?;
        Some(Self(crate::chain::Priority::new(
            &quote,
            codec::transaction_id(transaction),
        )))
    }
    /// Whether `other` ranks before this entry.
    fn outranked_by(&self, other: &Self) -> bool {
        other.0 < self.0
    }
}
/// A full installed selection's weakest entry, which a newcomer must outrank
/// to enter it by displacing an entry, and what makes it full: its count,
/// for every newcomer, or its bytes, for a newcomer they leave no room for.
#[derive(Clone)]
struct Floor {
    weakest: Weakest,
    count_full: bool,
    /// The selection's block bytes, counted as [Room] counts them, and their limit.
    used_bytes: usize,
    byte_limit: usize,
}
impl Floor {
    /// Whether a newcomer of `bytes` encoded bytes can enter only by displacing an entry.
    fn binds(&self, bytes: usize) -> bool {
        self.count_full
            || self
                .used_bytes
                .saturating_add(compact_size_len(bytes) + bytes)
                > self.byte_limit
    }
}

/// Bounds on executing blocks that would not become the tip (see
/// `Node::side_permit`).
struct SideValidation {
    budget: TimeBudget,
    sources: BTreeMap<IpAddr, SideSource>,
}
/// A locally submitted side block found the execution slot busy. It waits
/// for the slot without the node lock, then checks again.
#[derive(Debug)]
struct SideSlotBusy;
impl std::fmt::Display for SideSlotBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "another side-branch block is being validated")
    }
}
impl std::error::Error for SideSlotBusy {}
/// One relaying source's side-branch share.
struct SideSource {
    blocks: u64,
    /// The active height that last refilled `blocks`.
    height: u64,
    time: TimeBudget,
}
impl SideSource {
    fn new(height: u64) -> Self {
        Self {
            blocks: SIDE_SOURCE_BLOCKS,
            height,
            time: TimeBudget::new(SIDE_SOURCE_TIME_PER_SECOND, SIDE_VALIDATION_TIME_BURST),
        }
    }
    fn refill(&mut self, height: u64) {
        if height > self.height {
            self.blocks = (height - self.height)
                .saturating_mul(SIDE_SOURCE_BLOCKS_PER_TIP)
                .saturating_add(self.blocks)
                .min(SIDE_SOURCE_BLOCKS);
            self.height = height;
        }
    }
}

/// Blocks being validated. A block delivered again meanwhile waits for that
/// validation rather than repeating it.
#[derive(Default)]
struct Validating {
    blocks: Mutex<HashSet<Hash>>,
    done: std::sync::Condvar,
}
/// A block's validation in progress. A submission drops it as soon as the
/// block is stored, before the admission that storing starts, so a copy or
/// a child waiting for it goes on at once, and ahead of that admission.
struct ValidatingClaim<'a> {
    validating: &'a Validating,
    hash: Hash,
}
impl Validating {
    /// Wait while `hash` is being validated. A block waits only for its own
    /// earlier copy or for its parent, so waits never form a cycle.
    fn settle(&self, hash: &Hash) -> std::sync::MutexGuard<'_, HashSet<Hash>> {
        let mut blocks = self.blocks.unpoisoned();
        while blocks.contains(hash) {
            blocks = self
                .done
                .wait(blocks)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        blocks
    }
    fn claim(&self, hash: Hash) -> ValidatingClaim<'_> {
        self.settle(&hash).insert(hash);
        ValidatingClaim {
            validating: self,
            hash,
        }
    }
}
impl Drop for ValidatingClaim<'_> {
    fn drop(&mut self) {
        self.validating.blocks.unpoisoned().remove(&self.hash);
        self.validating.done.notify_all();
    }
}

/// Template builds at once. Each is claimed for the parent it extends. A
/// build for the tip waits only for another build of that same parent, whose
/// result it then reuses; a build that a new tip overtook stops at its next
/// step, so it delays the new tip's by at most the step it is in.
const MAX_TEMPLATE_BUILDS: usize = 2;
/// Template builds in progress, by the parent each extends.
#[derive(Default)]
struct TemplateBuilds {
    running: Mutex<Vec<Hash>>,
    done: std::sync::Condvar,
}
struct BuildClaim<'a> {
    builds: &'a TemplateBuilds,
    parent: Hash,
}
impl TemplateBuilds {
    /// Taken before the node lock, never while holding it.
    fn claim(&self, parent: Hash) -> BuildClaim<'_> {
        let mut running = self.running.unpoisoned();
        while running.contains(&parent) || running.len() >= MAX_TEMPLATE_BUILDS {
            running = self
                .done
                .wait(running)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        running.push(parent);
        BuildClaim {
            builds: self,
            parent,
        }
    }
}
impl Drop for BuildClaim<'_> {
    fn drop(&mut self) {
        let mut running = self.builds.running.unpoisoned();
        if let Some(position) = running.iter().position(|parent| *parent == self.parent) {
            running.swap_remove(position);
        }
        drop(running);
        self.builds.done.notify_all();
    }
}

/// Replay steps for the next node-lock hold of a block that would become
/// the tip, after a hold that ran `granted` steps in `spent`: as many as fit
/// REPLAY_HOLD_TIME at that pace, at least one and at most
/// REPLAY_STEPS_PER_HOLD. After a slow step the next hold runs one.
fn replay_steps_after(granted: usize, spent: Duration) -> usize {
    let fit = REPLAY_HOLD_TIME.as_nanos().saturating_mul(granted as u128) / spent.as_nanos().max(1);
    usize::try_from(fit)
        .unwrap_or(usize::MAX)
        .clamp(1, REPLAY_STEPS_PER_HOLD)
}

#[cfg(test)]
thread_local! {
    /// Run on this thread once a submitted block that became the tip is
    /// stored, before the admission that storing starts.
    static BLOCK_STORED_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
    /// Run on this thread after each node-lock hold of a block that would
    /// become the tip; it returns how long to count that hold as.
    static REPLAY_HOLD_HOOK: std::cell::RefCell<Option<Box<dyn FnMut() -> Duration>>> =
        const { std::cell::RefCell::new(None) };
}

fn compact_size_len(n: usize) -> usize {
    match n {
        0..=252 => 1,
        253..=65535 => 3,
        65536..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod explorer_worker_tests;
#[doc(hidden)]
pub mod fuzz;
#[cfg(test)]
mod local_rpc_tests;
#[cfg(test)]
mod pool_tests;
#[cfg(test)]
mod proposal_index_tests;
#[cfg(test)]
thread_local! {
    /// Pool selections run on this thread, and the signatures they checked.
    static POOL_SELECTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static POOL_SIGNATURES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Fail the next pool recovery on this thread.
    static FAIL_RECOVERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Curve evaluations this thread ran while it held the node lock, and
    /// how long it held that lock in all.
    static CLEARING_UNDER_INNER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static INNER_HELD: std::cell::Cell<Duration> = const { std::cell::Cell::new(Duration::ZERO) };
    /// Charge admission work on this thread this long, whatever it took.
    static SELECTION_CHARGE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
    /// Charge each side block's replay hold or execution on this thread
    /// this long, whatever it took.
    static SIDE_CHARGE: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
    /// Full proposal index builds, each a walk of every proposal, on this thread.
    static PROPOSAL_INDEX_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The node lock. Test builds meter it: a std mutex is held by one thread and
/// clearing runs synchronously on that thread, so the change in the thread's
/// curve evaluations between acquiring and releasing it is exactly the
/// clearing run while the lock was held.
#[cfg(not(test))]
type InnerGuard<'a> = std::sync::MutexGuard<'a, Inner>;
#[cfg(test)]
struct InnerGuard<'a> {
    guard: std::sync::MutexGuard<'a, Inner>,
    evaluations: u64,
    acquired: Instant,
}
#[cfg(test)]
impl std::ops::Deref for InnerGuard<'_> {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.guard
    }
}
#[cfg(test)]
impl std::ops::DerefMut for InnerGuard<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.guard
    }
}
#[cfg(test)]
impl Drop for InnerGuard<'_> {
    fn drop(&mut self) {
        let spent = crate::batch::thread_curve_evaluations() - self.evaluations;
        CLEARING_UNDER_INNER.with(|total| total.set(total.get() + spent));
        INNER_HELD.with(|total| total.set(total.get() + self.acquired.elapsed()));
    }
}
fn lock_inner(inner: &Mutex<Inner>) -> InnerGuard<'_> {
    let guard = inner.lock().unwrap_or_else(|_| poisoned("node state"));
    #[cfg(test)]
    let guard = InnerGuard {
        guard,
        evaluations: crate::batch::thread_curve_evaluations(),
        acquired: Instant::now(),
    };
    guard
}

struct Inner {
    chain: Chain,
    /// The next-block selection; templates commit to these entries, or to
    /// their longest prefix that finishes as a block.
    mempool: PoolPart,
    /// Pending entries displaced by capacity, retried against later blocks.
    backlog: PoolPart,
    /// Tip the pool was last selected against; differs only after a failed recovery.
    pool_tip: Hash,
    /// Advances with every installed change to the selection or backlog.
    pool_revision: u64,
    /// Advances with every change to the selection itself, and with the tip.
    selection_revision: u64,
    /// The configured miner's last template. A selection change leaves it in
    /// place as a valid same-parent fallback; a tip change removes it.
    template: Option<TemplateEntry>,
    // Download progress is independent of which branch currently has greatest work.
    downloads: VecDeque<Download>,
    /// Header downloads by outbound peer, at most MAX_CONNECTIONS.
    header_syncs: BTreeMap<SocketAddr, HeaderSync>,
    relay_cursor: usize,
    /// Spends waiting for a pending transfer to create their sender's account.
    awaiting: Vec<Awaiting>,
    /// The floor of the installed selection (see `Node::pool_floor`), and
    /// the selection revision it was found at.
    floor: Option<(u64, Option<Floor>)>,
    /// Sender nonces recent selections refused for validity.
    invalid_nonces: InvalidNonces,
}
impl Inner {
    fn pending(&self) -> impl Iterator<Item = &Transaction> {
        self.mempool.iter().chain(self.backlog.iter())
    }
    /// Install a selection and its backlog in one buffer, which published
    /// read views share instead of copying.
    fn set_pool(&mut self, mempool: Vec<Transaction>, backlog: Vec<Transaction>) {
        let selected = mempool.len();
        let entries: Arc<[Transaction]> = mempool.into_iter().chain(backlog).collect();
        self.backlog = PoolPart {
            entries: entries.clone(),
            range: selected..entries.len(),
        };
        self.mempool = PoolPart {
            entries,
            range: 0..selected,
        };
    }
    /// Every pending entry, the selection and then its backlog, shared.
    fn shared_pending(&self) -> Arc<[Transaction]> {
        self.mempool.entries.clone()
    }
}
/// The next-block selection or its backlog: a part of one buffer holding
/// both (see [Inner::set_pool]).
struct PoolPart {
    entries: Arc<[Transaction]>,
    range: std::ops::Range<usize>,
}
impl PoolPart {
    fn empty() -> Self {
        Self {
            entries: Arc::from(Vec::new()),
            range: 0..0,
        }
    }
}
impl std::ops::Deref for PoolPart {
    type Target = [Transaction];
    fn deref(&self) -> &[Transaction] {
        &self.entries[self.range.clone()]
    }
}
struct TemplateEntry {
    block: Arc<Block>,
    /// The tip it extends.
    tip: Hash,
    /// The selection revision its transactions were captured at.
    selection: u64,
    /// When its build finished, and how long the build took.
    finished: Instant,
    cost: Duration,
    /// Transactions that builds for this tip could not finish a block with.
    /// Later builds for the tip leave them out, with their senders' later
    /// nonces; they stay pooled and are tried again on the next tip.
    parked: HashSet<Hash>,
}
/// How current a template its caller needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Freshness {
    /// Built for the selection installed when it was asked for: local
    /// mining and RPC, which are trusted.
    Current,
    /// Stratum work. After a selection change, the last same-parent
    /// template, still a valid block, is served until as long as its build
    /// took has passed since that build finished, so repeated rebuilds use
    /// at most half of one core however fast the selection changes. A new
    /// tip is always built at once.
    Throttled,
}
/// Template builds one request runs while new tips keep overtaking them.
/// After these it is served an empty template for the tip then current,
/// which clears no trades (see [Node::template_shared]).
const TEMPLATE_BUILD_ATTEMPTS: u32 = 3;
/// A stored side-branch block whose descendants a peer may still provide,
/// and the source that delivered it (see `network_guard::peer_source`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Download {
    hash: Hash,
    source: IpAddr,
}
/// A header download from one outbound peer (transport version 2). Presync
/// counts the work the peer's branch claims without holding its headers;
/// once that exceeds the tip, the branch is fetched again from where it
/// leaves validated history and held. An unproven branch therefore costs no
/// storage however long it is, and a proven one holds at most
/// `chain::MAX_SYNC_HEADERS` headers with every other download.
struct HeaderSync {
    /// Stored block where the branch leaves validated history: its hash,
    /// height and branch work.
    root: (Hash, u64, Amount),
    /// Last header counted, its height and the work its chain claims.
    last: (Hash, u64, Amount),
    /// Last header fetched again and held; holding resumes after it.
    held: Option<(Hash, u64, Amount)>,
    /// Counting first passed the tip's work at this header and height; the
    /// headers up to it are fetched again and held.
    proof: Option<(Hash, u64)>,
    /// Keeps this download's held headers from eviction until it ends.
    pin: u64,
    /// The peer's last answer while counting; the last answer that held a
    /// new header while holding.
    touched: Instant,
    /// Headers this download counted that passed their proof-of-work and
    /// target checks. Stored headers, which a peer can resend without any
    /// work, never count: downloads that counted least give way first.
    counted: u64,
}
impl HeaderSync {
    /// Where holding resumes: the last held header, or the stored root.
    fn resume(&self) -> (Hash, u64, Amount) {
        self.held.clone().unwrap_or_else(|| self.root.clone())
    }
    /// The header the next request continues after.
    fn cursor(&self) -> Hash {
        match self.proof {
            Some(_) => self.resume().0,
            None => self.last.0,
        }
    }
    /// The last header counted and the last held: a reply that changes
    /// neither made no progress.
    fn position(&self) -> (Hash, Option<Hash>) {
        (self.last.0, self.held.as_ref().map(|held| held.0))
    }
}
/// A header download holding a branch that holds no new header for this
/// long releases its pinned headers and holds that branch again from its
/// stored root at the peer's next answer. Counting holds nothing and never
/// expires; at most MAX_CONNECTIONS downloads run, and at most
/// HEADER_SYNCS_PER_SOURCE from one network group. A new download beyond
/// either bound displaces the one that counted fewest checked headers, the
/// least recently answered among equals (see `make_room_for_header_sync`).
const HEADER_SYNC_IDLE: Duration = Duration::from_secs(600);
/// Header downloads from peers in one network group (`network_guard::peer_source`).
const HEADER_SYNCS_PER_SOURCE: usize = 4;
/// Headers a reply reads under one hold of the node lock.
const HEADER_READ_CHUNK: usize = 250;
/// Before a new header download from `peer` is kept, displace one when the
/// downloads are full, or when `peer`'s network group already runs its
/// share: the download that counted fewest checked headers, the least
/// recently answered among equals, from that group or else from all. A
/// download that only resent stored headers has counted none, so downloads
/// created for free, however many addresses create them, displace only each
/// other, never one that counted work.
fn make_room_for_header_sync(
    chain: &mut Chain,
    syncs: &mut BTreeMap<SocketAddr, HeaderSync>,
    peer: SocketAddr,
) {
    let source = network_guard::peer_source(peer.ip());
    let same = |other: &SocketAddr| network_guard::peer_source(other.ip()) == source;
    let pool: Vec<_> =
        if syncs.keys().filter(|other| same(other)).count() >= HEADER_SYNCS_PER_SOURCE {
            syncs.iter().filter(|(other, _)| same(other)).collect()
        } else if syncs.len() >= MAX_CONNECTIONS {
            syncs.iter().collect()
        } else {
            return;
        };
    let weakest = pool
        .into_iter()
        .min_by_key(|(other, sync)| (sync.counted, sync.touched, **other))
        .map(|(other, _)| *other);
    if let Some(weakest) = weakest
        && let Some(old) = syncs.remove(&weakest)
    {
        chain.release_header_pin(old.pin);
    }
}
/// A peer that closed this many consecutive sessions on their first header
/// request, before any reply byte, is taken for a version 1 peer.
const LEGACY_PEER_CLOSES: u32 = 2;
/// Such a peer is synchronized by blocks only for this long before a header
/// request is tried again; a close older than this no longer counts.
const LEGACY_PEER_RETRY: Duration = Duration::from_secs(600);
const MAX_LEGACY_PEERS: usize = 256;
/// Consecutive sessions a peer closed on their first header request.
#[derive(Clone, Copy, Debug)]
struct HeaderCloses {
    count: u32,
    /// The last such close; from LEGACY_PEER_CLOSES on, when the peer was
    /// taken for a version 1 peer.
    at: Instant,
}
impl HeaderCloses {
    fn legacy(&self) -> bool {
        self.count >= LEGACY_PEER_CLOSES
    }
}
/// Record that `source` delivered `hash`, a child of `previous`. Each source
/// advances only its own cursor for a branch and never moves or removes one
/// another source contributed, even for the same block. When the list is
/// full, a source displaces another source's oldest cursor only while that
/// source holds more cursors than it does; otherwise it drops its own oldest.
/// One source resending stored blocks, which needs no proof of work, can
/// therefore never displace a source that holds fewer cursors.
fn note_download(downloads: &mut VecDeque<Download>, hash: Hash, previous: Hash, source: IpAddr) {
    downloads.retain(|d| d.source != source || (d.hash != hash && d.hash != previous));
    downloads.push_front(Download { hash, source });
    if downloads.len() > MAX_CONNECTIONS {
        let mut held: HashMap<IpAddr, usize> = HashMap::new();
        for download in downloads.iter() {
            *held.entry(download.source).or_default() += 1;
        }
        let most = held.values().copied().max().unwrap_or(0);
        let oldest = if held[&source] >= most {
            downloads.iter().rposition(|d| d.source == source)
        } else {
            downloads.iter().rposition(|d| held[&d.source] == most)
        };
        if let Some(oldest) = oldest {
            downloads.remove(oldest);
        }
    }
}
/// Follow one header reply from `peer` (see `HeaderSync`). The reply must
/// continue the request: after the download's cursor, an admitted held
/// chain's best header or a block of this node's active chain. Returns
/// whether another request can continue the download.
///
/// A reply that no longer continues the request is ignored without blame:
/// between a request and its reply another download or a relayed block may
/// have extended the admitted header the request listed, or the download it
/// continued may have given way to another. The header requests then end,
/// and the session's block exchange still runs.
fn follow_headers(
    chain: &mut Chain,
    syncs: &mut BTreeMap<SocketAddr, HeaderSync>,
    downloads: &mut VecDeque<Download>,
    peer: SocketAddr,
    headers: &[Header],
    now: u64,
) -> Result<bool> {
    let start = headers[0].previous;
    let mut sync = match syncs.remove(&peer) {
        // Headers that extend the active tip are not held: ordinary
        // synchronization fetches their blocks.
        previous if start == chain.tip_hash() => {
            if let Some(previous) = previous {
                chain.release_header_pin(previous.pin);
            }
            return Ok(false);
        }
        Some(mut sync) if sync.cursor() == start => {
            // Holding resumes after a header dropped meanwhile, as with a
            // branch whose block failed validation: hold again from the
            // stored root. That is no fault of the peer.
            if sync.proof.is_some() {
                // The download has left the map: release its pins itself
                // if the lookup fails, or they would stay fixed.
                let parent = match chain.header_parent(&start) {
                    Ok(parent) => parent,
                    Err(error) => {
                        chain.release_header_pin(sync.pin);
                        return Err(error);
                    }
                };
                if parent == HeaderParent::Unknown {
                    sync.held = None;
                    syncs.insert(peer, sync);
                    return Ok(true);
                }
            }
            sync
        }
        previous => {
            if let Some(previous) = previous {
                chain.release_header_pin(previous.pin);
            }
            match chain.header_parent(&start)? {
                HeaderParent::Stored { height, work } => HeaderSync {
                    root: (start, height, work.clone()),
                    last: (start, height, work),
                    held: None,
                    proof: None,
                    pin: chain.new_header_pin(),
                    touched: Instant::now(),
                    counted: 0,
                },
                // The peer continues an admitted chain from its best header.
                // It is extended while it leads the tip by less than
                // HELD_LEAD_BLOCKS next-block works and by fewer than
                // HELD_LEAD_HEADERS headers, one linked header after
                // another: a header that does not follow the one before it
                // would fork inside the admitted chain, so it ends the reply.
                HeaderParent::Held { admitted: true, .. } if chain.admitted_header_tip(&start) => {
                    let mut previous = start;
                    for header in headers {
                        if header.previous != previous {
                            return Ok(false);
                        }
                        previous = crypto::sha256d(&codec::header_bytes(header));
                        match chain.hold_header(header.clone(), now, 0) {
                            Ok(HeaderHold::Ahead | HeaderHold::Full) => return Ok(false),
                            Ok(_) => {}
                            Err(error) if error.is::<HeaderDeferred>() => return Ok(false),
                            Err(error) => return Err(error),
                        }
                    }
                    return Ok(headers.len() == peer_wire::MAX_HEADERS);
                }
                // No longer what the request listed (see above), or never
                // was: nothing is followed.
                _ => return Ok(false),
            }
        }
    };
    let position = sync.position();
    let step = advance_headers(chain, &mut sync, headers, now);
    // Counting pins nothing, so any answer keeps it current; holding stays
    // current only while it holds new headers.
    if sync.proof.is_none() || sync.position() != position {
        sync.touched = Instant::now();
    }
    if !matches!(step, Ok(HeaderStep::Continue(_))) {
        // Every other ending releases the download's pinned headers.
        chain.release_header_pin(sync.pin);
    }
    match step? {
        HeaderStep::Continue(more) => {
            // One download per outbound peer. The peer's own download left
            // the map above, so only a new one can displace another.
            make_room_for_header_sync(chain, syncs, peer);
            syncs.insert(peer, sync);
            Ok(more)
        }
        HeaderStep::Admitted => {
            // The branch's blocks are requested from its stored root on, and
            // validated without the side-branch admission policy.
            note_download(
                downloads,
                sync.root.0,
                sync.root.0,
                network_guard::peer_source(peer.ip()),
            );
            Ok(false)
        }
        HeaderStep::Ended => Ok(false),
    }
}
/// How one header reply left a header download.
enum HeaderStep {
    /// Still counting or holding; whether another request can continue it.
    Continue(bool),
    /// Its held chain claims more work than the tip.
    Admitted,
    /// It reached the active tip, or the peer now serves another branch.
    Ended,
}
fn advance_headers(
    chain: &mut Chain,
    sync: &mut HeaderSync,
    headers: &[Header],
    now: u64,
) -> Result<HeaderStep> {
    let tip_work = chain.chain_work().clone();
    // The reply's headers from where holding resumes, when all are in hand.
    let mut since = (sync.proof.is_none() && sync.last.0 == sync.resume().0).then_some(0);
    for (index, header) in headers.iter().enumerate() {
        let hash = crypto::sha256d(&codec::header_bytes(header));
        let (cursor, height, claimed) = match sync.proof {
            Some(_) => sync.resume(),
            None => sync.last.clone(),
        };
        ensure!(header.previous == cursor, "peer headers are not linked");
        // Validated history: the branch leaves it at this block instead.
        if let HeaderParent::Stored { height, work } = chain.header_parent(&hash)? {
            if hash == chain.tip_hash() {
                // The rest extends the active tip.
                return Ok(HeaderStep::Ended);
            }
            sync.root = (hash, height, work.clone());
            sync.held = None;
            if sync.proof.is_none_or(|(proof, _)| proof == hash) {
                sync.proof = None;
                sync.last = (hash, height, work);
                since = Some(index + 1);
            }
            continue;
        }
        let work = match chain.check_header(header, height + 1, now) {
            Ok(work) => work,
            // It may become eligible later; the peer is not at fault.
            Err(error) if error.is::<HeaderDeferred>() => return Ok(HeaderStep::Continue(false)),
            Err(error) => return Err(error),
        };
        let (height, claimed) = (height + 1, claimed + work);
        match sync.proof {
            None => {
                sync.counted = sync.counted.saturating_add(1);
                sync.last = (hash, height, claimed.clone());
                if claimed <= tip_work {
                    continue;
                }
                if let Some(from) = since {
                    // The whole branch since its resume point is in hand.
                    let mut hold = HeaderHold::Held;
                    for header in &headers[from..=index] {
                        hold = chain.hold_header(header.clone(), now, sync.pin)?;
                        match hold {
                            // Already held well past the tip by another download.
                            HeaderHold::Ahead => break,
                            // No room to pin it, now or later.
                            HeaderHold::Full => return Ok(HeaderStep::Ended),
                            _ => {}
                        }
                    }
                    if matches!(hold, HeaderHold::Admitted | HeaderHold::Ahead) {
                        return Ok(HeaderStep::Admitted);
                    }
                }
                // Fetch the counted branch again from its resume point.
                sync.proof = Some((hash, height));
                return Ok(HeaderStep::Continue(true));
            }
            Some((proof, proof_height)) => {
                let hold = chain.hold_header(header.clone(), now, sync.pin)?;
                match hold {
                    HeaderHold::Full => return Ok(HeaderStep::Ended),
                    // Not held: another download's admitted chain already
                    // leads here.
                    HeaderHold::Ahead if claimed > tip_work => return Ok(HeaderStep::Admitted),
                    HeaderHold::Ahead => return Ok(HeaderStep::Ended),
                    _ => {}
                }
                sync.held = Some((hash, height, claimed.clone()));
                // Done once this header itself claims more work than the
                // tip; a shared prefix another download admitted may not.
                if hold == HeaderHold::Admitted && claimed > tip_work {
                    return Ok(HeaderStep::Admitted);
                }
                if height == proof_height {
                    if hash != proof {
                        // The peer now serves another branch than it counted.
                        return Ok(HeaderStep::Ended);
                    }
                    // The tip grew past the counted work: count on from here.
                    sync.proof = None;
                    sync.last = (hash, height, claimed);
                    since = Some(index + 1);
                }
            }
        }
    }
    let full = headers.len() == peer_wire::MAX_HEADERS;
    if sync.proof.is_some() && !full {
        // The peer's chain now ends short of the header it counted.
        return Ok(HeaderStep::Ended);
    }
    Ok(HeaderStep::Continue(full))
}
struct PublishedChain {
    config: Arc<Config>,
    tip: Hash,
    state: Arc<State>,
}
impl PublishedChain {
    fn chain_id(&self) -> Hash {
        self.state.chain_id
    }
    fn tip_hash(&self) -> Hash {
        self.tip
    }
    fn tip_height(&self) -> u64 {
        self.state.height
    }
    fn tip_state(&self) -> &State {
        &self.state
    }
}
struct ReadView {
    chain: PublishedChain,
    /// The selection and then its backlog, shared with the node's own pool.
    mempool: Arc<[Transaction]>,
    pool_revision: u64,
    cache: Arc<TipCache>,
    /// The chain's live storage faults, shared by every view.
    storage: Arc<Mutex<StorageHealth>>,
}
/// Read-only results derived from one published tip state. Views of the same
/// tip share it across mempool changes, so repeated reads never rebuild them.
#[derive(Default)]
struct TipCache {
    root: std::sync::OnceLock<Hash>,
    /// The bounded governance summary; a complete large grant is never kept.
    governance: std::sync::OnceLock<Value>,
    proposals: std::sync::OnceLock<Arc<ProposalIndex>>,
    /// An ancestor's index and the proposals registered since, when this tip
    /// extends the previously published one; its index derives from them.
    proposal_base: Option<ProposalBase>,
}
impl TipCache {
    /// The cache of a tip whose block extends the tip `parent` was published
    /// for, registering `registered` proposals. Its index derives from the
    /// parent's or, if no read built that one, from the parent's own base.
    fn extending(parent: &TipCache, registered: Vec<Hash>) -> Self {
        let proposal_base = match parent.proposals.get() {
            Some(index) => Some(ProposalBase {
                index: index.clone(),
                registered,
            }),
            None => parent.proposal_base.as_ref().and_then(|base| {
                let total = base.registered.len().checked_add(registered.len())?;
                (total <= MAX_DERIVED_REGISTRATIONS).then(|| ProposalBase {
                    index: base.index.clone(),
                    registered: [&base.registered[..], &registered].concat(),
                })
            }),
        };
        Self {
            proposal_base,
            ..Self::default()
        }
    }
}
/// Registrations a chain of unread tips may carry before the next read
/// builds its index in full instead of deriving it.
const MAX_DERIVED_REGISTRATIONS: usize = 16_384;
struct ProposalBase {
    index: Arc<ProposalIndex>,
    registered: Vec<Hash>,
}
/// Proposals a block registers, in the order its transactions run.
fn registered_proposals(chain_id: &Hash, block: &Block) -> Vec<Hash> {
    block
        .transactions
        .iter()
        .filter_map(|tx| match &tx.body.operation {
            Operation::Propose {
                round,
                description,
                proposal,
                ..
            } => Some(crate::state::proposal_id(
                chain_id,
                *round,
                &tx.body.sender,
                description,
                proposal,
            )),
            _ => None,
        })
        .collect()
}
/// Consensus keys proposals by ID only and never removes them. This local
/// index of each round's proposals is maintained from tip to tip: a round no
/// descendant can change is shared, so a new block re-ranks only the open
/// round, and neither a snapshot nor a round page walks all history.
#[derive(Debug, PartialEq, Eq)]
struct ProposalIndex {
    /// Rounds before `open_from`. Their proposals, support and winner are
    /// final on every descendant of this tip.
    closed: Arc<BTreeMap<u64, Arc<[Hash]>>>,
    /// Rounds from `open_from` on (the auction round, if any).
    open: BTreeMap<u64, Arc<[Hash]>>,
    open_from: u64,
    /// Proposals indexed; equal to the state's count.
    count: usize,
}
impl ProposalIndex {
    /// The first round a descendant can still change: only the auction round
    /// accepts proposals and support, and only it can change its leader. A
    /// decision's round already records its winner.
    fn open_from(s: &State) -> u64 {
        match &s.phase {
            crate::state::Phase::Auction(a) => a.round,
            _ if s.rounds.is_empty() => 0,
            _ => s.last_round.saturating_add(1),
        }
    }
    /// Each round's IDs: its leader, decision or winner first, then by
    /// support (highest first) and ID. Cheap spam cannot hide better-backed
    /// proposals behind ground IDs that sort first.
    fn rank(s: &State, round: u64, mut ids: Vec<(&Amount, Hash)>) -> Arc<[Hash]> {
        let first = match &s.phase {
            crate::state::Phase::Auction(a) if a.round == round && a.leader.is_some() => a.leader,
            crate::state::Phase::Governance(d) if d.round == round => Some(d.proposal_id),
            _ => match s.rounds.get(&round.to_be_bytes()).map(|r| &r.status) {
                Some(crate::state::RoundStatus::Won(id)) => Some(*id),
                _ => None,
            },
        };
        ids.sort_by(|(a_support, a), (b_support, b)| {
            (Some(*b) == first)
                .cmp(&(Some(*a) == first))
                .then_with(|| b_support.cmp(a_support))
                .then_with(|| a.cmp(b))
        });
        ids.into_iter().map(|(_, id)| id).collect()
    }
    fn assemble(
        s: &State,
        mut closed: Arc<BTreeMap<u64, Arc<[Hash]>>>,
        rounds: BTreeMap<u64, Vec<(&Amount, Hash)>>,
    ) -> Self {
        let open_from = Self::open_from(s);
        let mut open = BTreeMap::new();
        for (round, ids) in rounds {
            let ranked = Self::rank(s, round, ids);
            if round < open_from {
                Arc::make_mut(&mut closed).insert(round, ranked);
            } else {
                open.insert(round, ranked);
            }
        }
        Self {
            closed,
            open,
            open_from,
            count: s.proposals.len(),
        }
    }
    /// Walks every proposal ever recorded: once at startup or after a
    /// reorganization, not once per tip.
    fn build(s: &State) -> Self {
        #[cfg(test)]
        PROPOSAL_INDEX_BUILDS.with(|builds| builds.set(builds.get() + 1));
        let mut rounds = BTreeMap::<u64, Vec<(&Amount, Hash)>>::new();
        for (key, proposal) in s.proposals.iter() {
            let Ok(id) = Hash::try_from(key) else {
                continue;
            };
            rounds
                .entry(proposal.round)
                .or_default()
                .push((&proposal.support, id));
        }
        Self::assemble(s, Arc::default(), rounds)
    }
    /// The index of a descendant of `base`'s tip that registered `registered`
    /// since. Rounds closed at the base are kept; the base's open rounds and
    /// the new proposals are ranked again. Returns None, for a full build,
    /// if the counts disagree, which a missed registration would cause.
    fn derive(base: &Self, registered: &[Hash], s: &State) -> Option<Self> {
        if Self::open_from(s) < base.open_from
            || base.count.checked_add(registered.len())? != s.proposals.len()
        {
            return None;
        }
        let mut rounds = BTreeMap::<u64, Vec<(&Amount, Hash)>>::new();
        for id in base
            .open
            .values()
            .flat_map(|ids| ids.iter())
            .chain(registered)
        {
            let proposal = s.proposals.get(id)?;
            if proposal.round < base.open_from {
                return None;
            }
            rounds
                .entry(proposal.round)
                .or_default()
                .push((&proposal.support, *id));
        }
        Some(Self::assemble(s, base.closed.clone(), rounds))
    }
    fn round(&self, round: u64) -> &[Hash] {
        let rounds = if round < self.open_from {
            &*self.closed
        } else {
            &self.open
        };
        rounds.get(&round).map_or(&[][..], |ids| &ids[..])
    }
    fn round_len(&self, round: u64) -> usize {
        self.round(round).len()
    }
}
/// The worker owns only a weak node reference. Dropping the last node closes its
/// coalesced wake queue and joins the worker before its derived DB is reopened.
struct ExplorerWorker {
    sender: Option<mpsc::SyncSender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Set when a notification first finds the worker gone, so that is logged once.
    gone: AtomicBool,
}
impl ExplorerWorker {
    fn start(explorer: Explorer, inner: Weak<Mutex<Inner>>, config: Config) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("hashstash-explorer".into())
            .spawn(move || {
                // An update's own panic only fails that update. Any other
                // panic unwound through the node lock or this loop; exit like
                // a service task rather than leave the index frozen unlogged.
                let worker = std::panic::AssertUnwindSafe(|| {
                    explorer_worker(explorer, &inner, &config, &receiver)
                });
                if std::panic::catch_unwind(worker).is_err() {
                    eprintln!("fatal: explorer worker panicked; exiting for a supervised restart");
                    std::process::exit(70);
                }
            });
        match thread {
            Ok(thread) => Self {
                sender: Some(sender),
                thread: Some(thread),
                gone: AtomicBool::new(false),
            },
            Err(error) => {
                eprintln!("Explorer worker unavailable: {error}");
                Self {
                    sender: None,
                    thread: None,
                    gone: AtomicBool::new(true),
                }
            }
        }
    }
    fn notify(&self) {
        if let Some(sender) = &self.sender
            && let Err(mpsc::TrySendError::Disconnected(())) = sender.try_send(())
            && !self.gone.swap(true, Ordering::Relaxed)
        {
            eprintln!("Explorer worker stopped; the explorer index no longer follows the chain");
        }
    }
}
/// Index each canonical change as it is notified. After a failed capture or
/// update the worker also wakes at the retry time, so an idle chain does not
/// leave the index behind until the next block.
fn explorer_worker(
    mut explorer: Explorer,
    inner: &Weak<Mutex<Inner>>,
    config: &Config,
    receiver: &mpsc::Receiver<()>,
) {
    loop {
        let woke = match explorer.retry_at() {
            Some(at) => !matches!(
                receiver.recv_timeout(at.saturating_duration_since(Instant::now())),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            None => receiver.recv().is_ok(),
        };
        if !woke {
            return;
        }
        loop {
            if matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                return;
            }
            let Some(inner) = inner.upgrade() else {
                return;
            };
            let update = explorer.capture(&lock_inner(&inner).chain);
            drop(inner);
            match update {
                Ok(Some(update)) => {
                    if let Err(error) = explorer.apply_update(config, update) {
                        eprintln!("Explorer index update unavailable: {error}");
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    eprintln!("Explorer capture unavailable: {error}");
                    break;
                }
            }
        }
    }
}
impl Drop for ExplorerWorker {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl ReadView {
    fn capture(inner: &Inner) -> Self {
        Self {
            chain: PublishedChain {
                config: Arc::new(inner.chain.config.clone()),
                tip: inner.chain.tip_hash(),
                state: Arc::new(inner.chain.tip_state().clone()),
            },
            mempool: inner.shared_pending(),
            pool_revision: inner.pool_revision,
            cache: Arc::default(),
            storage: inner.chain.storage_health(),
        }
    }
    /// The storage faults to report: degraded while blocks cannot be stored.
    fn storage_value(&self) -> Value {
        let health = self.storage.unpoisoned().clone();
        json!({"degraded":health.degraded(), "failed_commits":health.failed_commits,
            "failing_since":health.failing_since, "last_error":health.last_error,
            "checkpoint_error":health.checkpoint_error})
    }
    fn state_root(&self) -> Hash {
        *self
            .cache
            .root
            .get_or_init(|| self.chain.tip_state().root())
    }
    fn proposal_index(&self) -> &ProposalIndex {
        self.cache.proposals.get_or_init(|| {
            let s = self.chain.tip_state();
            Arc::new(
                self.cache
                    .proposal_base
                    .as_ref()
                    .and_then(|base| ProposalIndex::derive(&base.index, &base.registered, s))
                    .unwrap_or_else(|| ProposalIndex::build(s)),
            )
        })
    }
    /// The governance projection with a large decision grant summarized, so
    /// the retained copy stays bounded however many payments the grant has.
    fn governance_summary(&self) -> Value {
        self.cache
            .governance
            .get_or_init(|| governance_value(self, true))
            .clone()
    }
}

/// Payments of the decision grant projected into governance responses.
fn decision_payments(s: &State) -> usize {
    match &s.phase {
        crate::state::Phase::Governance(d) => grant_payments(&d.proposal),
        _ => 0,
    }
}

/// The governance projection. `decision_grant` reports a decision grant's
/// payment count and total; a summary keeps only the first
/// SUMMARY_GRANT_PAYMENTS of a larger grant in `phase` and sets `truncated`.
fn governance_value(i: &ReadView, summary: bool) -> Value {
    let s = i.chain.tip_state();
    let world = |w: &crate::state::World| json!({"reserve":w.reserve.to_str_radix(10),"shares":w.shares.to_str_radix(10),"curve_mass":w.curve_mass.to_str_radix(10),"grant_capacity":crate::consensus::grant_capacity(w).to_str_radix(10),"account_shares":w.account_shares.to_str_radix(10),"revenue":w.revenue.to_str_radix(10),"grant_escrow":w.grant_escrow.to_str_radix(10)});
    let progress = if let crate::state::Phase::Governance(d) = &s.phase {
        let observed = s.height.saturating_sub(d.started_height).min(d.blocks);
        json!({"time_unit":"blocks","leading_blocks":d.leading_blocks,"observed_blocks":observed,"blocks":d.blocks,"blocks_remaining":d.blocks.saturating_sub(observed),"trading_closed":trading_closed(s)})
    } else {
        Value::Null
    };
    let summarized;
    let (phase, decision_grant) = match &s.phase {
        crate::state::Phase::Governance(d) => match &*d.proposal {
            Proposal::Grant { payments } => {
                let truncated = summary && payments.len() > SUMMARY_GRANT_PAYMENTS;
                // Consensus validated the grant; only its amounts are summed.
                let total: Amount = payments.iter().map(|payment| &payment.amount).sum();
                let grant = json!({"payment_count":payments.len(),"payment_total":total.to_str_radix(10),"truncated":truncated});
                if truncated {
                    summarized = crate::state::Phase::Governance(crate::state::Decision {
                        proposal: Arc::new(truncated_proposal(&d.proposal)),
                        ..d.clone()
                    });
                    (&summarized, grant)
                } else {
                    (&s.phase, grant)
                }
            }
            Proposal::Parameter { .. } => (&s.phase, Value::Null),
        },
        _ => (&s.phase, Value::Null),
    };
    json!({"phase":phase,"decision_grant":decision_grant,"height":s.height,"state_root":hex::encode(i.state_root()),"clock":s.clock,"time_unit":"seconds","clock_basis":"target_interval","settings":s.settings,"frozen":s.frozen,"pass_margin_bps":s.frozen.pass_margin_bps.unwrap_or(0).to_string(),"world":world(&s.world),"pass":s.alternative.as_ref().map(world),"auction_escrow":s.auction_escrow.to_str_radix(10),"progress":progress})
}

/// One page of proposal rows, charged per row and projected payment before
/// it is built. A summary page (the wallet snapshot) keeps the first
/// SUMMARY_GRANT_PAYMENTS of any larger grant; a full page summarizes a row
/// only when it alone cannot fit the page budget.
fn proposal_page(
    i: &ReadView,
    ids: &[Hash],
    summary: bool,
    meter: Option<&Session>,
) -> Result<Value> {
    let s = i.chain.tip_state();
    let rows = ids
        .iter()
        .map(|id| {
            let record = s.proposals.get(id).context("indexed proposal missing")?;
            let action = s.actions.get(id).context("indexed proposal missing")?;
            Ok((id, record, action))
        })
        .collect::<Result<Vec<_>>>()?;
    let projected = |action: &Proposal| {
        let payments = grant_payments(action);
        if summary {
            payments.min(SUMMARY_GRANT_PAYMENTS)
        } else {
            payments
        }
    };
    charge(
        meter,
        rows.iter()
            .map(|(_, _, action)| 1 + projected(action))
            .fold(0, usize::saturating_add),
    )?;
    let mut page = JsonPage::new();
    for (id, record, action) in rows {
        let summarize = || -> Result<Value> {
            let summary = truncated_proposal(action);
            Ok(serde_json::to_value(Truncated {
                row: ProposalPageRow {
                    id: hex::encode(id),
                    proposal: ProposalView {
                        record,
                        action: &summary,
                    },
                },
                truncated: true,
                payment_count: grant_payments(action),
            })?)
        };
        let accepted = if summary && grant_payments(action) > SUMMARY_GRANT_PAYMENTS {
            page.push(&summarize()?)?
        } else {
            page.push_summarized(
                &ProposalPageRow {
                    id: hex::encode(id),
                    proposal: ProposalView { record, action },
                },
                summarize,
            )?
        };
        if !accepted {
            break;
        }
    }
    Ok(Value::Array(page.items))
}
#[derive(Clone)]
pub struct Node {
    inner: Arc<Mutex<Inner>>,
    /// Template builds, which run outside `inner`, by the parent each extends.
    template_builds: Arc<TemplateBuilds>,
    /// Advances with every new tip, so a build for an older tip stops.
    tip_generation: Arc<AtomicU64>,
    /// The node-wide selection budget and relayed newcomers queued for it.
    admission: Arc<Mutex<Admission>>,
    /// Held while newcomer admission runs, so one selection for newcomers
    /// runs at a time. Taken before `inner`, never while holding it.
    admission_run: Arc<Mutex<()>>,
    /// Block submissions waiting for `inner`; admission lets them go first.
    blocks_waiting: Arc<AtomicUsize>,
    /// Blocks being validated, so a block delivered twice executes once.
    validating: Arc<Validating>,
    /// Held while a block that would not become the tip executes.
    side_running: Arc<Mutex<()>>,
    side_validation: Arc<Mutex<SideValidation>>,
    explorer: Arc<ExplorerWorker>,
    explorer_path: Arc<PathBuf>,
    session_token_path: Arc<PathBuf>,
    /// Owner-only sidecar with the Stratum addresses that recently authorized.
    stratum_trusted_path: Arc<PathBuf>,
    miner: PublicKey,
    wallets: Arc<Mutex<WalletStore>>,
    startup_wallet_mode: Option<&'static str>,
    rpc_sessions: Arc<Semaphore>,
    peer_sessions: Arc<PeerSlots>,
    rpc_parsers: Arc<Semaphore>,
    peer_parsers: Arc<Semaphore>,
    stratum_parsers: Arc<Semaphore>,
    rpc_workers: Arc<Semaphore>,
    rpc_mutations: Arc<Semaphore>,
    /// Held only by server-wallet sends and management, which also take a
    /// free `rpc_mutations` worker if one frees first.
    wallet_mutations: Arc<Semaphore>,
    /// The one development `mine` call that may run, apart from mutations.
    dev_mining: Arc<Semaphore>,
    /// `run --dev-rpc`: allow `mine` on a network that is not a development one.
    dev_rpc: bool,
    /// Set by `serve` when peers beyond loopback or discovery can reach this
    /// node, which then is no development network (see `development_network`).
    untrusted_peers: bool,
    peer_workers: Arc<Semaphore>,
    stratum_workers: Arc<Semaphore>,
    /// Solved Stratum blocks validate on their own permits, never behind
    /// mining workers or template builds.
    block_submissions: Arc<Semaphore>,
    guard: Arc<NetworkGuard>,
    published: Arc<RwLock<Arc<ReadView>>>,
    peer_events: Arc<Mutex<VecDeque<Value>>>,
    outbound_sessions: Arc<Semaphore>,
    mining: Arc<Mutex<MiningRuntime>>,
    work_updates: watch::Sender<u64>,
    mining_session_ids: Arc<Mutex<SessionIds>>,
    stratum_pending: Arc<StratumPending>,
    listener_health: Arc<Mutex<HashMap<&'static str, ListenerHealth>>>,
    peer_auth: Option<Arc<PeerPolicy>>,
    peer_health: Arc<Mutex<HashMap<SocketAddr, PeerHealth>>>,
    /// Outbound peers that closed sessions on their first header request,
    /// as a transport version 1 peer does.
    legacy_peers: Arc<Mutex<HashMap<SocketAddr, HeaderCloses>>>,
    discovery_options: DiscoveryOptions,
    discovery: Arc<Mutex<Option<AddressBook>>>,
    discovery_path: PathBuf,
    discovery_id: Hash,
    last_tip_change: Arc<AtomicU64>,
    server_active: Arc<AtomicBool>,
    // Read by transport tasks on runtime workers, which never take the node lock.
    known_block_bytes: Arc<AtomicU64>,
    rejected: Arc<Mutex<RejectedTransactions>>,
}
#[derive(Default)]
struct PeerHealth {
    configured_at: u64,
    last_attempt: u64,
    last_success: u64,
    failures: u32,
}
/// Accept failures never stop a listener; they are counted for `peerstatus`.
#[derive(Default, Serialize)]
struct ListenerHealth {
    accept_errors: u64,
    last_error: Option<String>,
    last_error_at: u64,
}
/// Live Stratum extranonces. A wrapped counter skips every value still held
/// by a connected session, so admission never depends on a lifetime count.
struct SessionIds {
    next: u32,
    live: HashSet<u32>,
}
struct SessionId(Arc<Mutex<SessionIds>>, u32);
impl SessionIds {
    /// The counter starts at a random value, so nodes that pay one key and
    /// serve the same template, or one node before and after a restart, do
    /// not hand the same extranonces to their first miners.
    fn random() -> Self {
        let mut seed = [0u8; 4];
        let _ = getrandom::fill(&mut seed);
        Self {
            next: u32::from_le_bytes(seed),
            live: HashSet::new(),
        }
    }
    fn allocate(ids: &Arc<Mutex<Self>>) -> Option<SessionId> {
        let mut state = ids.unpoisoned();
        // Live IDs are bounded by the pre-authorization slots plus the
        // worker registry, since a session leaves the first only to enter it.
        loop {
            let id = state.next;
            state.next = state.next.wrapping_add(1);
            if state.live.insert(id) {
                return Some(SessionId(ids.clone(), id));
            }
        }
    }
}
impl Drop for SessionId {
    fn drop(&mut self) {
        self.0.unpoisoned().live.remove(&self.1);
    }
}
impl Node {
    pub fn open(path: &Path, config: Config, miner: PublicKey) -> Result<Self> {
        Self::open_with_wallet_passphrase(path, config, miner, None)
    }
    /// Opens with the passphrase that locks this node's wallet storage: its
    /// hot keys are then saved only encrypted (see `WalletStore`).
    pub fn open_with_wallet_passphrase(
        path: &Path,
        config: Config,
        miner: PublicKey,
        wallet_passphrase: Option<&WalletPassphrase>,
    ) -> Result<Self> {
        ensure!(crypto::valid_key(&miner), "invalid miner public key");
        // The wallet sidecar cannot be rebuilt and fails closed. Check it before
        // the full history replay, so a damaged file stops startup immediately.
        config.validate()?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let wallets = WalletStore::open_unrecorded(path, config.chain_id(), wallet_passphrase)?;
        let chain = Chain::open(path, config)?;
        // Only a launch whose chain database accepted this network records it,
        // so a mistaken network choice leaves the wallet store unchanged.
        wallets.record_network()?;
        let inner = Inner {
            pool_tip: chain.tip_hash(),
            pool_revision: 0,
            selection_revision: 0,
            chain,
            mempool: PoolPart::empty(),
            backlog: PoolPart::empty(),
            template: None,
            downloads: VecDeque::new(),
            header_syncs: BTreeMap::new(),
            relay_cursor: 0,
            awaiting: Vec::new(),
            floor: None,
            invalid_nonces: InvalidNonces::default(),
        };
        // A derived index failure never makes chain validation unavailable.
        let explorer = Explorer::open(path, &inner.chain).unwrap_or_else(|error| {
            eprintln!("Explorer index unavailable: {error}");
            Explorer::unavailable()
        });
        let published = Arc::new(RwLock::new(Arc::new(ReadView::capture(&inner))));
        let known_block_bytes = inner.chain.max_known_block_bytes();
        let guard = Arc::new(NetworkGuard::with_frame_limit(admission_frame_bytes(
            &inner.chain.config,
            inner.chain.max_known_block_bytes(),
        )?));
        // One block at the genesis signature limit, with a full loose batch and
        // pool (selection plus backlog) reselection, must always fit a single
        // peer work burst.
        guard.allow_work(inner.chain.config.max_signatures.saturating_add(
            1 + peer_wire::MAX_TRANSACTIONS + MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG,
        ))?;
        let explorer_config = inner.chain.config.clone();
        let discovery_path = peer_discovery::path_for(path, inner.chain.chain_id());
        let mut discovery_id = [0; 32];
        getrandom::fill(&mut discovery_id)
            .map_err(|e| anyhow!("peer discovery randomness unavailable: {e}"))?;
        let inner = Arc::new(Mutex::new(inner));
        let explorer = Arc::new(ExplorerWorker::start(
            explorer,
            Arc::downgrade(&inner),
            explorer_config,
        ));
        // A long startup catch-up continues on the worker, not before listeners.
        explorer.notify();
        Ok(Self {
            inner,
            template_builds: Arc::default(),
            tip_generation: Arc::new(AtomicU64::new(0)),
            admission: Arc::new(Mutex::new(Admission {
                budget: TimeBudget::new(SELECTION_TIME_PER_SECOND, SELECTION_TIME_BURST),
                queue: AdmissionQueue::default(),
                public: TimeBudget::new(
                    PUBLIC_SELECTION_TIME_PER_SECOND,
                    PUBLIC_SELECTION_TIME_BURST,
                ),
            })),
            admission_run: Arc::new(Mutex::new(())),
            blocks_waiting: Arc::new(AtomicUsize::new(0)),
            validating: Arc::default(),
            side_running: Arc::new(Mutex::new(())),
            side_validation: Arc::new(Mutex::new(SideValidation {
                budget: TimeBudget::new(
                    SIDE_VALIDATION_TIME_PER_SECOND,
                    SIDE_VALIDATION_TIME_BURST,
                ),
                sources: BTreeMap::new(),
            })),
            explorer,
            explorer_path: Arc::new(crate::local_files::sidecar(path, "explorer.sqlite")),
            session_token_path: Arc::new(session_token_path(path)),
            stratum_trusted_path: Arc::new(crate::local_files::sidecar(
                path,
                "stratum-trusted.json",
            )),
            miner,
            wallets: Arc::new(Mutex::new(wallets)),
            startup_wallet_mode: None,
            rpc_sessions: Arc::new(Semaphore::new(8)),
            peer_sessions: Arc::new(PeerSlots::default()),
            rpc_parsers: Arc::new(Semaphore::new(2)),
            peer_parsers: Arc::new(Semaphore::new(network_guard::PEER_DECODERS)),
            stratum_parsers: Arc::new(Semaphore::new(2)),
            rpc_workers: Arc::new(Semaphore::new(4)),
            rpc_mutations: Arc::new(Semaphore::new(2)),
            wallet_mutations: Arc::new(Semaphore::new(1)),
            dev_mining: Arc::new(Semaphore::new(1)),
            dev_rpc: false,
            untrusted_peers: false,
            peer_workers: Arc::new(Semaphore::new(2)),
            stratum_workers: Arc::new(Semaphore::new(2)),
            block_submissions: Arc::new(Semaphore::new(2)),
            guard,
            published,
            peer_events: Arc::new(Mutex::new(VecDeque::new())),
            outbound_sessions: Arc::new(Semaphore::new(2)),
            mining: Arc::new(Mutex::new(MiningRuntime::default())),
            work_updates: watch::channel(0).0,
            mining_session_ids: Arc::new(Mutex::new(SessionIds::random())),
            stratum_pending: Arc::new(StratumPending::default()),
            listener_health: Arc::new(Mutex::new(HashMap::new())),
            peer_auth: None,
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            legacy_peers: Arc::new(Mutex::new(HashMap::new())),
            discovery_options: DiscoveryOptions::default(),
            discovery: Arc::new(Mutex::new(None)),
            discovery_path,
            discovery_id,
            last_tip_change: Arc::new(AtomicU64::new(now())),
            server_active: Arc::new(AtomicBool::new(false)),
            known_block_bytes: Arc::new(AtomicU64::new(known_block_bytes)),
            rejected: Arc::new(Mutex::new(RejectedTransactions::default())),
        })
    }
    /// Require pinned transport for every peer connection; never falls back to plaintext.
    pub fn with_peer_auth(mut self, policy: Arc<PeerPolicy>) -> Result<Self> {
        ensure!(
            policy.public_key() != self.miner,
            "peer identity must be separate from the mining/spending account"
        );
        // Saved, seeded and later imported wallet accounts must differ as well.
        self.wallets_locked()?
            .reserve_peer_identity(policy.public_key())?;
        self.peer_auth = Some(policy);
        Ok(self)
    }
    pub fn with_discovery(mut self, options: DiscoveryOptions) -> Result<Self> {
        options.validate()?;
        self.discovery_options = options;
        Ok(self)
    }
    /// Allow the development `mine` RPC on a network that is not a
    /// development one (see `development_network`).
    pub fn with_dev_rpc(mut self) -> Self {
        self.dev_rpc = true;
        self
    }
    /// A worker for a server-wallet send or management call: the reserved
    /// one, or a shared mutation worker if that frees first, so RPC reads and
    /// submissions holding every shared worker cannot hold off the operator's
    /// wallet. None when neither frees within the I/O deadline.
    async fn wallet_worker(&self) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
        let (reserved, shared) = (self.wallet_mutations.clone(), self.rpc_mutations.clone());
        let permit = timeout(IO_TIMEOUT, async move {
            tokio::select! {
                biased;
                permit = reserved.acquire_owned() => permit,
                permit = shared.acquire_owned() => permit,
            }
        })
        .await;
        Ok(match permit {
            Ok(permit) => Some(permit?),
            Err(_) => None,
        })
    }
    pub fn peer_status(&self) -> Result<Value> {
        let at = now();
        let health = self.peer_health.unpoisoned();
        let mut peers = health
            .iter()
            .map(|(address, h)| {
                json!({
                    "address":address.to_string(), "last_attempt":h.last_attempt,
                    "last_success":h.last_success, "consecutive_failures":h.failures,
                    "reachable":h.last_success > 0 && at.saturating_sub(h.last_success) < 90,
                    "stalled":at.saturating_sub(h.last_success.max(h.configured_at)) >= 90
                })
            })
            .collect::<Vec<_>>();
        peers.sort_by_key(|p| p["address"].as_str().unwrap_or("").to_owned());
        let discovery = self.discovery.unpoisoned();
        let discovery_status = match discovery.as_ref() {
            Some(book) => {
                json!({"enabled":true,"known":book.entries().count(),"verified":book.entries().filter(|e|e.last_success>0).count(),"advertise":book.options.advertise,"seeds":book.options.seeds,"last_error":book.last_error,"load_error":book.load_error,"peers":book.entries().collect::<Vec<_>>()})
            }
            None => json!({"enabled":false}),
        };
        drop(discovery);
        let listeners = json!(*self.listener_health.unpoisoned());
        // Peers taken for version 1 peers are synchronized by blocks only.
        let mut legacy: Vec<String> = self
            .header_closes()
            .iter()
            .filter(|(_, closes)| closes.legacy())
            .map(|(peer, _)| peer.to_string())
            .collect();
        legacy.sort();
        let view = self.read_view()?;
        // The tip heuristic follows the governed block interval, never below 180 s.
        let stall_after = view
            .chain
            .tip_state()
            .settings
            .interval
            .saturating_mul(12)
            .max(180);
        Ok(
            json!({"transport":if self.peer_auth.as_ref().is_some_and(|p|p.is_discovery()){"authenticated-discovery"}else if self.peer_auth.is_some(){"pinned-signed"}else{"compact-binary"}, "wire_format":"compact-binary",
            "public_key":self.peer_auth.as_ref().map(|p|hex::encode(p.public_key())), "peers":peers,
            "discovery":discovery_status, "listeners":listeners,
            "observed_at":at, "encrypted":false,
            "transport_version":peer_wire::TRANSPORT_VERSION, "version1_peers":legacy,
            "capacity_allowance":self.known_block_bytes.load(Ordering::Acquire),
            "chain_height":view.chain.tip_height(),
            "seconds_without_new_tip":at.saturating_sub(self.last_tip_change.load(Ordering::Relaxed)),
            "chain_stalled":at.saturating_sub(self.last_tip_change.load(Ordering::Relaxed)) >= stall_after,
            "storage":view.storage_value()}),
        )
    }
    /// Blocks cannot currently be stored, as on a full disk: the tip stays
    /// where it is, so work handed out on it is wasted until they can.
    pub fn storage_degraded(&self) -> Result<bool> {
        Ok(self.read_view()?.storage.unpoisoned().degraded())
    }
    /// Exit, for a supervised restart, once block commits have failed for
    /// long enough (see [storage_exit_due]); `chain` just failed to store one.
    fn exit_if_storage_failing(chain: &Chain) {
        let health = chain.storage_health().unpoisoned().clone();
        if storage_exit_due(&health, now()) {
            eprintln!(
                "fatal: {} block commits failed in a row since {}, the last with: {}; exiting for a supervised restart",
                health.failed_commits,
                health.failing_since.unwrap_or_default(),
                health.last_error.as_deref().unwrap_or("unknown error")
            );
            std::process::exit(STORAGE_EXIT_STATUS);
        }
    }
    /// Validation may change the greatest competitive capacity on any branch,
    /// including without a tip change. Record it for transport tasks and
    /// admission. It falls again when a competing branch is left behind or
    /// governance lowers it, and admission's byte bursts and frame memory
    /// follow it down; callers hold the node lock, so the latest chain value
    /// wins. Nothing else sets the private guard's frame allowance.
    fn note_capacity(&self, chain: &Chain) -> Result<()> {
        let capacity = chain.max_known_block_bytes();
        self.known_block_bytes.store(capacity, Ordering::Release);
        self.guard
            .set_frame(admission_frame_bytes(&chain.config, capacity)?)
    }
    fn publish(&self, inner: &Inner) -> Result<()> {
        self.note_capacity(&inner.chain)?;
        let mut next = ReadView::capture(inner);
        // One block extending the published tip derives its proposal index
        // from that tip's; a reorganization builds it in full. The caller's
        // node lock serializes publication, so the tip read here stays current.
        let block = inner.chain.tip_block();
        let registered = (block.header.previous == self.read_view()?.chain.tip_hash())
            .then(|| registered_proposals(&inner.chain.chain_id(), block));
        let mut published = self
            .published
            .write()
            .unwrap_or_else(|_| poisoned("snapshot"));
        if published.chain.tip_hash() != next.chain.tip_hash() {
            self.last_tip_change.store(now(), Ordering::Relaxed);
            if let Some(registered) = registered {
                next.cache = Arc::new(TipCache::extending(&published.cache, registered));
            }
        } else {
            // A mempool-only change keeps the tip's derived read results.
            next.cache = published.cache.clone();
        }
        *published = Arc::new(next);
        self.work_updates
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        self.explorer.notify();
        Ok(())
    }
    fn read_view(&self) -> Result<Arc<ReadView>> {
        Ok(self
            .published
            .read()
            .unwrap_or_else(|_| poisoned("snapshot"))
            .clone())
    }
    // Transport limits are read on runtime workers. They use the published
    // configuration and recorded capacity, never the node lock, which block
    // validation and pool selection may hold for a long time.
    fn peer_limits(&self) -> Result<peer_wire::Limits> {
        self.peer_limits_at_least(None)
    }
    /// Transport limits for at least the capacity allowance `declared`, which
    /// this node sent with a request: a reply sized for that allowance is
    /// still received if the allowance has fallen since.
    fn peer_limits_at_least(&self, declared: Option<u64>) -> Result<peer_wire::Limits> {
        let view = self.read_view()?;
        let capacity = self.known_block_bytes.load(Ordering::Acquire);
        Ok(peer_wire::Limits::for_capacity(
            &view.chain.config,
            capacity.max(declared.unwrap_or(0)),
        ))
    }
    fn peer_exchange_timeout(&self) -> Result<Duration> {
        // A peer may be validating the block we just sent before it answers.
        // Keep the ordinary deadline, adding one second per MiB of the
        // largest frame, which carries a capacity's worth of blocks and as
        // much again of loose transactions: as long as its sender allows
        // itself to write it (`peer_write_timeout`).
        Ok(peer_write_timeout(self.peer_limits()?.frame_bytes()))
    }
    /// The allowance for an inbound connection's handshake and first
    /// message: a locator, address or header request, which carries no
    /// blocks and waits for no validation, so it is read for as long as its
    /// sender may take to write the largest such request.
    fn peer_request_timeout(&self) -> Result<Duration> {
        Ok(peer_write_timeout(
            self.peer_limits()?.locator_request_bytes(),
        ))
    }

    /// Seed a wallet store that holds no wallets. A store holding wallets keeps
    /// its saved selection over startup flags.
    pub fn with_wallet(mut self, secret: [u8; 32]) -> Result<Self> {
        ensure!(
            self.startup_wallet_mode.is_none(),
            "startup wallet mode is already configured"
        );
        self.wallets_locked()?.seed_hot(secret)?;
        self.startup_wallet_mode = Some("hot");
        Ok(self)
    }
    /// Seed a store holding no wallets with a watched account; a store holding
    /// wallets keeps its saved selection.
    pub fn with_watch_key(mut self, public: PublicKey) -> Result<Self> {
        ensure!(
            self.startup_wallet_mode.is_none(),
            "startup wallet mode is already configured"
        );
        self.wallets_locked()?.seed_watch(public)?;
        self.startup_wallet_mode = Some("watch");
        Ok(self)
    }
    fn wallets_locked(&self) -> Result<std::sync::MutexGuard<'_, WalletStore>> {
        Ok(self.wallets.lock().unwrap_or_else(|_| poisoned("wallet")))
    }
    /// Wallet-store reads for async handlers run on the blocking pool, so a
    /// store write in progress never parks a runtime worker.
    async fn wallet_read<T: Send + 'static>(
        &self,
        read: impl FnOnce(&WalletStore) -> T + Send + 'static,
    ) -> Result<T> {
        let node = self.clone();
        tokio::task::spawn_blocking(move || Ok(read(&*node.wallets_locked()?)))
            .await
            .context("wallet reader failed")?
    }
    fn locked(&self) -> Result<InnerGuard<'_>> {
        Ok(lock_inner(&self.inner))
    }
    fn rejected_locked(&self) -> std::sync::MutexGuard<'_, RejectedTransactions> {
        // Only a cache: a panic elsewhere cannot leave it inconsistent.
        self.rejected.unpoisoned()
    }
    fn listener_error(&self, kind: i32, error: &std::io::Error, delay: Duration) {
        let name = match kind {
            0 => "rpc",
            1 => "p2p",
            2 => "stratum",
            _ => "public_web",
        };
        {
            let mut health = self.listener_health.unpoisoned();
            let entry = health.entry(name).or_default();
            entry.accept_errors = entry.accept_errors.saturating_add(1);
            entry.last_error = Some(error.to_string().chars().take(256).collect());
            entry.last_error_at = now();
        }
        // Per-connection resets are only counted; resource errors are logged
        // at most once per backoff interval.
        if !delay.is_zero() {
            eprintln!("{name} listener accept failed: {error}; retrying in {delay:?}");
        }
    }
    /// Configured or pinned peers have their own reserved inbound capacity.
    /// Discovery peers this node verified in the last hour have separate
    /// reserved slots, but stay subject to network group caps. Operator
    /// privileges go to the exact configured or pinned address
    /// (`protected_peers`), never to its neighbours in an IPv6 /64, which a
    /// pin's key check, also by exact address, does not cover.
    fn peer_class(&self, configured: &HashSet<IpAddr>, ip: IpAddr) -> PeerClass {
        if configured.contains(&ip.to_canonical()) {
            PeerClass::Operator
        } else if self
            .discovery
            .unpoisoned()
            .as_ref()
            .is_some_and(|book| book.verified_ip(ip, now()))
        {
            PeerClass::Verified
        } else {
            PeerClass::General
        }
    }
    fn peer_event(&self, peer: String, result: &Result<()>) {
        let error = result
            .as_ref()
            .err()
            .map(|e| e.to_string().chars().take(256).collect::<String>());
        let mut events = self.peer_events.unpoisoned();
        events.push_back(json!({"peer":peer,"time":now(),"ok":result.is_ok(),"error":error}));
        while events.len() > 64 {
            events.pop_front();
        }
    }
    fn timestamp(chain: &Chain) -> u32 {
        let local = now().min(u32::MAX as u64) as u32;
        local.max(chain.tip_block().header.timestamp)
    }
    /// Shape and authentication of the exact signed bytes for this node's
    /// chain ID; failures are permanent.
    fn screen_signed(chain_id: &Hash, tx: &Transaction) -> Result<()> {
        ensure!(
            tx.body.expiry_blocks > 0,
            "transaction lifetime must be positive"
        );
        ensure!(tx.body.nonce < u64::MAX, "invalid or exhausted nonce");
        crypto::verify(chain_id, tx).context("invalid transaction signature")
    }
    /// Cheap checks against the current tip, before any signature check or
    /// selection: size, signed anchor and lifetime, a funded sender and an
    /// unused nonce. Selection never includes a sender without an account at
    /// the block opening, so recovered entries need a funded sender as well.
    fn admissible(chain: &Chain, tx: &Transaction) -> Result<()> {
        ensure!(
            Self::admissible_or_unfunded(chain, tx)?,
            "sender account does not exist"
        );
        Ok(())
    }
    /// [Node::admissible], except that a sender without an account yields
    /// false instead of a refusal: a pending transfer may still create it.
    fn admissible_or_unfunded(chain: &Chain, tx: &Transaction) -> Result<bool> {
        Self::admissible_sized(chain, tx, codec::encode(tx).len())
    }
    /// [Node::admissible_or_unfunded] for a transaction of `bytes` encoded bytes.
    fn admissible_sized(chain: &Chain, tx: &Transaction, bytes: usize) -> Result<bool> {
        let state = chain.tip_state();
        ensure!(
            bytes <= chain.config.transaction_bytes(&state.settings),
            "transaction too large"
        );
        ensure!(
            tx.body.expiry_blocks > 0 && tx.body.nonce < u64::MAX,
            "invalid lifetime or nonce"
        );
        chain.validate_transaction_anchor(tx)?;
        let Some(account) = state.account(&tx.body.sender, None) else {
            return Ok(false);
        };
        ensure!(tx.body.nonce >= account.nonce, "nonce already used");
        Ok(true)
    }
    fn pool_ids(i: &Inner) -> HashSet<Hash> {
        i.pending().map(codec::transaction_id).collect()
    }
    /// The installed selection's weakest entry and what fills it (see
    /// [Floor]). While it holds as many entries as a selection may, or its
    /// bytes leave no room for a newcomer, that newcomer can enter only by
    /// displacing an entry. Every selected entry outranks it and is tried
    /// before it, so one that does not outrank the weakest entry is refused
    /// without a selection. Kept for one selection revision.
    fn pool_floor(i: &mut Inner, miner: PublicKey) -> Option<Floor> {
        if i.mempool.is_empty() || i.pool_tip != i.chain.tip_hash() {
            return None;
        }
        if let Some((revision, floor)) = &i.floor
            && *revision == i.selection_revision
        {
            return floor.clone();
        }
        let config = &i.chain.config;
        let state = i.chain.tip_state();
        let mut weakest: Option<Weakest> = None;
        for tx in i.mempool.iter() {
            let Some(entry) = Weakest::of(config, state, tx) else {
                // An entry its own quote no longer prices sets no floor.
                weakest = None;
                break;
            };
            if weakest.as_ref().is_none_or(|w| entry.outranked_by(w)) {
                weakest = Some(entry);
            }
        }
        let limit = mempool_limit(config).min(config.max_signatures);
        let floor = weakest.and_then(|weakest| {
            let room = Room::of(&i.chain, miner, &i.mempool).ok()?;
            Some(Floor {
                weakest,
                count_full: i.mempool.len() >= limit,
                used_bytes: room.used_bytes,
                byte_limit: room.byte_limit,
            })
        });
        i.floor = Some((i.selection_revision, floor.clone()));
        floor
    }
    /// Admissible newcomers sorted by what a selection could do with them,
    /// without running one: a replacement that does not raise its pending
    /// predecessor's fee rate enough, one at a sender nonce where a selection
    /// on this tip and pool refused another for validity (see
    /// [InvalidNonces]; `operator` submissions are exempt) that does not
    /// raise that one's fee rate enough, an entry the next block's opening
    /// refuses for its fee or funds, one after a missing earlier nonce of its
    /// sender, and, while the selection is full by its count or by bytes for
    /// that entry (see [Floor]), one that does not outrank its weakest entry,
    /// are never selected on this tip and pool. A candidate that rebids or
    /// extends its own sender's backlog chain cannot be selected before that
    /// chain, so it may wait in the backlog within the same bounds.
    fn screen_newcomers<'a>(
        &self,
        i: &Inner,
        newcomers: Vec<(Hash, &'a Transaction)>,
        floor: Option<&Floor>,
        operator: &HashSet<Hash>,
    ) -> Result<Newcomers<'a>> {
        let state = i.chain.tip_state();
        let mut screened = Newcomers::default();
        let mut nonces = BTreeMap::<PublicKey, BTreeSet<u64>>::new();
        let mut pending = BTreeMap::new();
        for tx in i.pending() {
            nonces
                .entry(tx.body.sender)
                .or_default()
                .insert(tx.body.nonce);
            pending.insert((tx.body.sender, tx.body.nonce), tx);
        }
        let judged = (i.chain.tip_hash(), i.pool_revision);
        let mut replacing = Vec::new();
        for (id, tx) in newcomers {
            if let Some(old) = pending.get(&(tx.body.sender, tx.body.nonce))
                && !replaces(&i.chain.config, state, tx, old)
            {
                screened.outbid.push((
                    id,
                    anyhow!(
                        "a pending transaction at this nonce is replaced only by one raising its fee rate by at least an eighth and by the minimum fee rate, and earning the miner at least as much per weight unit"
                    ),
                ));
            } else if !operator.contains(&id)
                && let Some((fee, weight)) = i.invalid_nonces.refused(judged, &id, tx)
                && fees::quote(&i.chain.config, state, tx)
                    .is_ok_and(|quote| !raises(state, (&tx.body.fee, quote.weight), (fee, weight)))
            {
                screened.outbid.push((
                    id,
                    anyhow!(
                        "the last selection refused a transaction at this sender nonce as invalid; until the pool changes, another is considered only if it raises that fee rate by at least an eighth and by the minimum fee rate"
                    ),
                ));
            } else {
                replacing.push((id, tx));
            }
        }
        if replacing.is_empty() {
            return Ok(screened);
        }
        let transactions: Vec<&Transaction> = replacing.iter().map(|(_, tx)| *tx).collect();
        let opening = i.chain.opening_screen(self.miner, &transactions)?;
        let mut payable = Vec::new();
        for ((id, tx), opening) in replacing.into_iter().zip(opening) {
            match opening {
                Ok(()) => {
                    nonces
                        .entry(tx.body.sender)
                        .or_default()
                        .insert(tx.body.nonce);
                    payable.push((id, tx));
                }
                Err(error) => screened.unpayable.push((id, error)),
            }
        }
        // The first nonce from the account nonce up that nothing pending holds.
        let mut reachable = BTreeMap::new();
        let mut candidates = Vec::new();
        for (id, tx) in payable {
            let sender = tx.body.sender;
            let next = *reachable.entry(sender).or_insert_with(|| {
                let mut next = state
                    .account(&sender, None)
                    .map_or(0, |account| account.nonce);
                while nonces[&sender].contains(&next) {
                    next = next.saturating_add(1);
                }
                next
            });
            if tx.body.nonce > next {
                screened.gapped.push(id);
            } else {
                candidates.push((id, tx));
            }
        }
        let mut backlog = BTreeMap::<PublicKey, (u64, u64)>::new();
        for tx in i.backlog.iter() {
            let (low, high) = backlog
                .entry(tx.body.sender)
                .or_insert((tx.body.nonce, tx.body.nonce));
            *low = (*low).min(tx.body.nonce);
            *high = (*high).max(tx.body.nonce);
        }
        let mut chained: Vec<_> = candidates.iter().collect();
        chained.sort_by_key(|(_, tx)| (tx.body.sender, tx.body.nonce));
        // Past its first entry, a sender's chain keeps at most its share.
        let share = (MAX_BACKLOG / BACKLOG_SENDER_SHARE) as u64;
        for (id, tx) in chained {
            if let Some((low, high)) = backlog.get_mut(&tx.body.sender)
                && (*low..=high.saturating_add(1)).contains(&tx.body.nonce)
                && tx.body.nonce - *low <= share
            {
                *high = (*high).max(tx.body.nonce);
                screened.waiting.insert(*id);
            }
        }
        for (id, tx) in candidates {
            let floor = floor.filter(|floor| {
                !screened.waiting.contains(&id) && floor.binds(codec::encode(tx).len())
            });
            let outranks = |floor: &Floor| {
                Weakest::of(&i.chain.config, state, tx)
                    .is_some_and(|entry| floor.weakest.outranked_by(&entry))
            };
            if floor.is_some_and(|floor| !outranks(floor)) {
                screened.outbid.push((
                    id,
                    anyhow!(
                        "the pool is full and this transaction does not outbid its weakest entry"
                    ),
                ));
            } else {
                screened.candidates.push((id, tx));
            }
        }
        Ok(screened)
    }
    /// Admit authenticated or locally signed newcomers against the current
    /// tip, with at most one selection for all of them, and say where each
    /// went. Every refusal is remembered for as long as it holds, so a
    /// resent identity, relayed or submitted, never reaches a selection. A
    /// relaying peer whose newcomer enters the pool delivered something new.
    fn admit_locked(
        &self,
        i: &mut Inner,
        newcomers: Vec<Newcomer>,
    ) -> Result<Vec<Result<Admitted>>> {
        let tip = i.chain.tip_hash();
        let mut retained = Self::pool_ids(i);
        let mut outcomes: Vec<Option<Result<Admitted>>> = newcomers.iter().map(|_| None).collect();
        let mut index = HashMap::new();
        let mut checked = Vec::new();
        // Spends whose sender has no account yet are held only after this
        // admission's selection, so funding admitted with them counts.
        let mut unfunded = Vec::new();
        for (position, newcomer) in newcomers.iter().enumerate() {
            let id = newcomer.id;
            if retained.contains(&id) {
                outcomes[position] = Some(Ok(Admitted::Pending));
                continue;
            }
            if i.awaiting.iter().any(|entry| entry.id == id) {
                outcomes[position] = Some(Ok(Admitted::Awaiting));
                continue;
            }
            if let Some(reason) = self.rejected_locked().refusal(&id, &tip, i.pool_revision) {
                outcomes[position] = Some(Err(anyhow!("{reason}")));
                continue;
            }
            // Outcomes are written through `index`, so it keeps the first
            // occurrence's position.
            if let std::collections::hash_map::Entry::Vacant(vacant) = index.entry(id) {
                vacant.insert(position);
            } else {
                outcomes[position] = Some(Err(anyhow!("transaction repeated in one admission")));
                continue;
            }
            // There is no separate count gate: selection ranks a newcomer
            // against the whole pool by fee, so a better bid displaces the
            // weakest entry.
            let settings = &i.chain.tip_state().settings;
            let message = if newcomer.bytes > i.chain.config.transaction_bytes(settings) {
                "transaction too large".to_owned()
            } else {
                match Self::admissible_sized(&i.chain, &newcomer.transaction, newcomer.bytes) {
                    Ok(true) => {
                        checked.push((id, &newcomer.transaction));
                        continue;
                    }
                    Ok(false) => {
                        unfunded.push(position);
                        continue;
                    }
                    Err(error) => format!("transaction not valid in next block: {error}"),
                }
            };
            self.rejected_locked()
                .refuse(id, Refusal::Tip(tip), &message);
            outcomes[position] = Some(Err(anyhow!(message)));
        }
        if !checked.is_empty() {
            let floor = Self::pool_floor(i, self.miner);
            let operator: HashSet<Hash> = newcomers
                .iter()
                .filter(|newcomer| newcomer.operator)
                .map(|newcomer| newcomer.id)
                .collect();
            let screened = self.screen_newcomers(i, checked, floor.as_ref(), &operator)?;
            {
                let mut rejected = self.rejected_locked();
                for (id, error) in &screened.unpayable {
                    let message = format!("transaction not valid in next block: {error:#}");
                    rejected.refuse(*id, Refusal::Tip(tip), &message);
                    outcomes[index[id]] = Some(Err(anyhow!(message)));
                }
                for (id, error) in &screened.outbid {
                    let message = format!("{error:#}");
                    rejected.refuse(*id, Refusal::Pool(tip, i.pool_revision), &message);
                    outcomes[index[id]] = Some(Err(anyhow!(message)));
                }
            }
            // One after a missing earlier nonce is skipped but not
            // remembered: its predecessor may still arrive on this tip.
            for id in &screened.gapped {
                outcomes[index[id]] = Some(Err(anyhow!(
                    "transaction not valid in next block: an earlier nonce from this sender is not pending"
                )));
            }
            // Reselect only for a new candidate that a selection could include.
            if !screened.candidates.is_empty() {
                let mut authenticated = retained.clone();
                let mut candidates: Vec<Transaction> = i.pending().cloned().collect();
                for (id, tx) in &screened.candidates {
                    if newcomers[index[id]].authenticated {
                        authenticated.insert(*id);
                    }
                    candidates.push((*tx).clone());
                }
                retained.extend(&screened.waiting);
                let (pool, room) = Self::select_pool_room(
                    &i.chain,
                    self.miner,
                    &candidates,
                    &retained,
                    &authenticated,
                )?;
                let accepted: HashSet<_> = pool
                    .0
                    .iter()
                    .chain(&pool.1)
                    .map(codec::transaction_id)
                    .collect();
                self.install_pool(i, pool)?;
                // A newcomer that lost this selection is reconsidered once the
                // tip or the pool changes, for example after a competing chain
                // is replaced.
                let refusal = Refusal::Pool(tip, i.pool_revision);
                let state = i.chain.tip_state();
                let mut invalid = Vec::new();
                let mut rejected = self.rejected_locked();
                for (id, tx) in &screened.candidates {
                    let newcomer = &newcomers[index[id]];
                    if accepted.contains(id) {
                        if let Some(peer) = newcomer.peer {
                            self.peer_sessions.delivered(peer);
                        }
                        outcomes[index[id]] = Some(Ok(Admitted::Pending));
                        continue;
                    }
                    let message = if screened.waiting.contains(id) {
                        "block capacity exhausted: an earlier transaction from this sender is still waiting for capacity, and this one does not outbid the waiting backlog"
                    } else {
                        // Left out at its sender's next nonce by a selection
                        // that decided that sender, with room to spare: it
                        // was refused for validity, not for capacity.
                        let sender = &tx.body.sender;
                        if !room.undecided(sender)
                            && tx.body.nonce == room.start(state, sender)
                            && let Ok(quote) = fees::quote(&i.chain.config, state, tx)
                            && room.fits(newcomer.bytes, quote.weight)
                        {
                            invalid.push((*id, *tx, quote.weight));
                        }
                        "transaction not valid in next block or block capacity exhausted"
                    };
                    rejected.refuse(*id, refusal, message);
                    outcomes[index[id]] = Some(Err(anyhow!(message)));
                }
                drop(rejected);
                let judged = (tip, i.pool_revision);
                for (id, tx, weight) in invalid {
                    i.invalid_nonces.refuse(judged, id, tx, weight);
                }
            }
        }
        if !unfunded.is_empty() {
            let funding = self.funded_accounts(i);
            for position in unfunded {
                let newcomer = &newcomers[position];
                outcomes[position] = Some(match Self::hold_unfunded(i, newcomer, &funding) {
                    Ok(()) => Ok(Admitted::Awaiting),
                    Err((pooled, reason)) => {
                        let message = format!("transaction not valid in next block: {reason}");
                        // Funding may still enter the pool on this tip.
                        let scope = if pooled {
                            Refusal::Pool(tip, i.pool_revision)
                        } else {
                            Refusal::Tip(tip)
                        };
                        self.rejected_locked().refuse(newcomer.id, scope, &message);
                        Err(anyhow!(message))
                    }
                });
            }
        }
        Ok(outcomes
            .into_iter()
            .map(|outcome| outcome.unwrap_or_else(|| Err(anyhow!("transaction not admitted"))))
            .collect())
    }
    /// Accounts that a pending transfer, or one still queued for admission,
    /// creates by paying them. A queued transfer has passed only its
    /// signature check, so it counts only if the next block's opening could
    /// take it: its sender's account and unused nonce, its anchor, and an
    /// opening balance covering its amount and fee.
    fn funded_accounts(&self, i: &Inner) -> HashSet<PublicKey> {
        let recipient = |tx: &Transaction| match &tx.body.operation {
            Operation::TransferExact { recipient, .. } => Some(*recipient),
            _ => None,
        };
        let mut funded: HashSet<PublicKey> = i.pending().filter_map(recipient).collect();
        let queued: Vec<Transaction> = self
            .admission
            .unpoisoned()
            .queue
            .entries
            .iter()
            .filter(|queued| recipient(&queued.transaction).is_some_and(|to| !funded.contains(&to)))
            .map(|queued| queued.transaction.clone())
            .collect();
        let queued: Vec<&Transaction> = queued
            .iter()
            .filter(|tx| Self::admissible(&i.chain, tx).is_ok())
            .collect();
        if !queued.is_empty()
            && let Ok(opening) = i.chain.opening_screen(self.miner, &queued)
        {
            funded.extend(
                queued
                    .into_iter()
                    .zip(opening)
                    .filter(|(_, opening)| opening.is_ok())
                    .filter_map(|(tx, _)| recipient(tx)),
            );
        }
        funded
    }
    /// Hold a newcomer whose sender has no account, if a transfer in
    /// `funding` (see [Node::funded_accounts]) creates that account, within
    /// the holding bounds. Its signature was checked before it got here, or
    /// its detached block checked it. A refusal says whether it depends on
    /// the pool, because no transfer creates the account yet; the others
    /// hold for the tip, during which held spends are only added.
    fn hold_unfunded(
        i: &mut Inner,
        newcomer: &Newcomer,
        funding: &HashSet<PublicKey>,
    ) -> std::result::Result<(), (bool, &'static str)> {
        let body = &newcomer.transaction.body;
        if !funding.contains(&body.sender) {
            return Err((true, "sender account does not exist"));
        }
        if body.nonce >= AWAITING_PER_SENDER as u64 {
            return Err((
                false,
                "sender account does not exist, and its pending funding leaves this nonce too far ahead",
            ));
        }
        let (mut sender, mut source, mut bytes) = (0usize, (0usize, 0usize), 0usize);
        let mut relayed = (0usize, 0usize);
        for entry in &i.awaiting {
            let held = &entry.transaction.body;
            if held.sender == body.sender {
                if held.nonce == body.nonce {
                    return Err((
                        false,
                        "sender account does not exist, and another transaction at this nonce waits for its funding",
                    ));
                }
                sender += 1;
            }
            let count = |held: &mut (usize, usize)| {
                held.0 += 1;
                held.1 = held.1.saturating_add(entry.bytes);
            };
            if entry.source == newcomer.source {
                count(&mut source);
            }
            if entry.source.is_some() {
                count(&mut relayed);
            }
            bytes = bytes.saturating_add(entry.bytes);
        }
        let limit = usize::try_from(i.chain.tip_state().settings.block_bytes).unwrap_or(usize::MAX);
        // Each source holds at most its share of the entries and bytes, and
        // relaying sources together leave local submissions and recovery
        // (the source None) one share of their own.
        let share = limit / AWAITING_SOURCES;
        let relays_full = newcomer.source.is_some()
            && (relayed.0 >= MAX_AWAITING - AWAITING_PER_SOURCE
                || relayed.1.saturating_add(newcomer.bytes) > limit - share);
        if i.awaiting.len() >= MAX_AWAITING
            || sender >= AWAITING_PER_SENDER
            || source.0 >= AWAITING_PER_SOURCE
            || source.1.saturating_add(newcomer.bytes) > share
            || bytes.saturating_add(newcomer.bytes) > limit
            || relays_full
        {
            return Err((
                false,
                "sender account does not exist, and no more spends can wait for their funding",
            ));
        }
        i.awaiting.push(Awaiting {
            id: newcomer.id,
            transaction: newcomer.transaction.clone(),
            bytes: newcomer.bytes,
            source: newcomer.source,
            tips: 0,
        });
        Ok(())
    }
    /// After a new tip: held spends whose sender now has an account go back
    /// through admission; the rest wait while a transfer in `funding` still
    /// creates the account, their anchors allow them, and for at most
    /// AWAITING_TIPS tips.
    fn reconsider_awaiting(i: &mut Inner, funding: &HashSet<PublicKey>) -> Vec<Newcomer> {
        let mut ready = Vec::new();
        for mut entry in std::mem::take(&mut i.awaiting) {
            let sender = entry.transaction.body.sender;
            if i.chain.tip_state().account(&sender, None).is_some() {
                ready.push(Newcomer {
                    id: entry.id,
                    transaction: entry.transaction,
                    bytes: entry.bytes,
                    source: entry.source,
                    peer: None,
                    authenticated: true,
                    operator: false,
                });
                continue;
            }
            entry.tips += 1;
            if entry.tips <= AWAITING_TIPS
                && funding.contains(&sender)
                && i.chain
                    .validate_transaction_anchor(&entry.transaction)
                    .is_ok()
            {
                i.awaiting.push(entry);
            }
        }
        ready
    }
    /// The node lock for block work, announced so that admission yields to it.
    fn locked_for_block(&self) -> Result<InnerGuard<'_>> {
        self.blocks_waiting.fetch_add(1, Ordering::AcqRel);
        let guard = self.locked();
        self.blocks_waiting.fetch_sub(1, Ordering::AcqRel);
        guard
    }
    /// A direct submission lets block submissions waiting for the node lock
    /// go first, for up to a second.
    fn yield_to_blocks(&self) {
        let until = Instant::now() + Duration::from_secs(1);
        while self.blocks_waiting.load(Ordering::Acquire) > 0 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    /// Charge admission work to the node-wide selection budget, or to the
    /// budget reserved for public broadcasts.
    fn charge_selection(&self, spent: Duration, public: bool) {
        #[cfg(test)]
        let spent = SELECTION_CHARGE
            .with(|charge| charge.get())
            .unwrap_or(spent);
        let mut admission = self.admission.unpoisoned();
        let budget = if public {
            &mut admission.public
        } else {
            &mut admission.budget
        };
        budget.spend(spent, Instant::now());
    }
    /// How long until the node-wide selection budget has credit, if it has none.
    #[cfg(test)]
    fn selection_wait(&self) -> Option<Duration> {
        let wait = self.admission.unpoisoned().budget.wait(Instant::now());
        (!wait.is_zero()).then_some(wait)
    }
    /// How long until the budget reserved for public broadcasts has credit,
    /// if it has none. Relays never spend it.
    fn public_selection_wait(&self) -> Option<Duration> {
        let wait = self.admission.unpoisoned().public.wait(Instant::now());
        (!wait.is_zero()).then_some(wait)
    }
    /// Admit one newcomer at once, as a direct submission does: after any
    /// newcomer admission in progress and after waiting block submissions.
    /// Its lock time is charged to the node-wide selection budget, or for a
    /// public broadcast to the budget reserved for those. A public broadcast
    /// starts only while that budget has credit, checked once it is its turn,
    /// so broadcasts that waited together cannot all run on one credit; when
    /// it is spent, nothing runs and the refusal is a [network_guard::Limited].
    fn admit_now(
        &self,
        public: bool,
        prepare: impl FnOnce(&mut Inner) -> Result<Newcomer>,
    ) -> Result<(Hash, Admitted)> {
        let outcome = {
            let _run = self.admission_run.unpoisoned();
            if public && let Some(wait) = self.public_selection_wait() {
                return Err(network_guard::Limited {
                    reason: "transaction admission is busy",
                    retry_after: Some(wait),
                }
                .into());
            }
            self.yield_to_blocks();
            let mut i = self.locked()?;
            let started = Instant::now();
            let outcome = prepare(&mut i).and_then(|mut newcomer| {
                newcomer.operator = !public;
                let id = newcomer.id;
                let outcome = self.admit_locked(&mut i, vec![newcomer])?.pop();
                Ok((id, outcome.context("admission outcome missing")??))
            });
            drop(i);
            self.charge_selection(started.elapsed(), public);
            outcome
        };
        if let Err(error) = self.drain_admissions() {
            eprintln!("Queued transaction admission deferred: {error:#}");
        }
        outcome
    }
    /// Queue relayed newcomers for admission (see [AdmissionQueue]) within
    /// the bounds for blocks of `block_bytes`.
    fn queue_admissions(&self, newcomers: impl IntoIterator<Item = Newcomer>, block_bytes: u64) {
        let block_bytes = usize::try_from(block_bytes).unwrap_or(usize::MAX);
        let mut admission = self.admission.unpoisoned();
        for newcomer in newcomers {
            admission.queue.push(newcomer, block_bytes);
        }
    }
    /// Admit queued newcomers, at most a block's bytes and
    /// MAX_DRAINED_ADMISSIONS of them per selection, while the node-wide
    /// selection budget has credit and no block submission waits for the
    /// node lock. Admission already running in another thread takes what is
    /// queued meanwhile, so this returns at once; anything left waits for
    /// the next drain, which every relay, submission and new tip starts.
    fn drain_admissions(&self) -> Result<()> {
        let ready = |admission: &mut Admission| {
            !admission.queue.is_empty()
                && self.blocks_waiting.load(Ordering::Acquire) == 0
                && admission.budget.wait(Instant::now()).is_zero()
        };
        loop {
            {
                let _run = match self.admission_run.try_lock() {
                    Ok(run) => run,
                    Err(std::sync::TryLockError::Poisoned(run)) => run.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
                };
                loop {
                    let block_bytes = self.read_view()?.chain.tip_state().settings.block_bytes;
                    let batch = {
                        let mut admission = self.admission.unpoisoned();
                        if !ready(&mut admission) {
                            break;
                        }
                        admission
                            .queue
                            .take(usize::try_from(block_bytes).unwrap_or(usize::MAX))
                    };
                    let mut i = self.locked()?;
                    let started = Instant::now();
                    let outcome = self.admit_locked(&mut i, batch);
                    drop(i);
                    self.charge_selection(started.elapsed(), false);
                    outcome?;
                }
            }
            // A newcomer queued just before the admission lock was released
            // found it busy; take it now.
            if !ready(&mut self.admission.unpoisoned()) {
                return Ok(());
            }
        }
    }
    /// One next-block selection plus its capacity-displaced backlog. Only
    /// `retained` identities, entries already pooled or recovered from detached
    /// blocks and newcomers waiting behind their sender's backlog chain, may
    /// wait in the backlog; any other newcomer that does not fit is refused.
    /// Every pool entry was authenticated when it entered the pool, and every
    /// detached block transaction when its block executed, so only candidates
    /// outside `authenticated` have their signatures checked. The selection
    /// does not finish the block, so it never clears batch trades: a trade's
    /// fill decides no transaction's validity, and clearing runs only when a
    /// template is built, outside the node lock.
    fn select_pool(
        chain: &Chain,
        miner: PublicKey,
        candidates: &[Transaction],
        retained: &HashSet<Hash>,
        authenticated: &HashSet<Hash>,
    ) -> Result<Pool> {
        Self::select_pool_room(chain, miner, candidates, retained, authenticated)
            .map(|(pool, _)| pool)
    }
    /// [Node::select_pool], with the room its selection left (see [Room]).
    fn select_pool_room(
        chain: &Chain,
        miner: PublicKey,
        candidates: &[Transaction],
        retained: &HashSet<Hash>,
        authenticated: &HashSet<Hash>,
    ) -> Result<(Pool, Room)> {
        let selection = chain.select_admission(
            miner,
            candidates,
            mempool_limit(&chain.config),
            authenticated,
        )?;
        #[cfg(test)]
        {
            POOL_SELECTIONS.with(|count| count.set(count.get() + 1));
            POOL_SIGNATURES.with(|count| count.set(count.get() + selection.signatures_checked));
        }
        let room = Room::after(chain, miner, &selection)?;
        let backlog = Self::displaced(chain, &selection, &room, candidates, retained)?;
        Ok(((selection.transactions, backlog), room))
    }
    /// Retained entries the selection left out only for block capacity. Unless
    /// the selection was saturated (or truncated, which an admission selection
    /// never is) or left the sender's own candidates unattempted, an entry
    /// that still fits the selected block's
    /// bytes and weight was refused for validity: it is dropped with its sender's
    /// later nonces. Weights quoted against the parent state can only overstate
    /// in-block weights, so a fitting estimate is conservative. The best bids
    /// are kept within MAX_BACKLOG entries and one block's bytes, independent
    /// of the selection's size: a count-saturated selection keeps its backlog.
    /// An entry cannot be selected before its sender's earlier nonces, so it
    /// ranks no higher than the lowest bid among them, and it is kept only
    /// after all of them: a high bid behind a low one never displaces another
    /// sender's entry, and the room of an entry left out goes to the next
    /// bid. Past its first entry, one sender's chain keeps at most its share
    /// (see BACKLOG_SENDER_SHARE).
    fn displaced(
        chain: &Chain,
        selection: &SelectionResult,
        room: &Room,
        candidates: &[Transaction],
        retained: &HashSet<Hash>,
    ) -> Result<Vec<Transaction>> {
        struct Waiting<'a> {
            transaction: &'a Transaction,
            bytes: usize,
            weight: u64,
            /// Its own bid.
            bid: crate::chain::Priority,
            /// The lowest bid along its sender's chain up to it.
            rank: crate::chain::Priority,
        }
        let state = chain.tip_state();
        let mut seen: HashSet<Hash> = selection
            .transactions
            .iter()
            .map(codec::transaction_id)
            .collect();
        let mut senders = BTreeMap::<PublicKey, Vec<Waiting<'_>>>::new();
        for transaction in candidates {
            let id = codec::transaction_id(transaction);
            if !retained.contains(&id)
                || !seen.insert(id)
                || Self::admissible(chain, transaction).is_err()
            {
                continue;
            }
            let Ok(quote) = fees::quote(&chain.config, state, transaction) else {
                continue;
            };
            let bid = crate::chain::Priority::new(&quote, id);
            senders
                .entry(transaction.body.sender)
                .or_default()
                .push(Waiting {
                    transaction,
                    bytes: codec::encode(transaction).len(),
                    weight: quote.weight,
                    rank: bid.clone(),
                    bid,
                });
        }
        let mut first = BTreeMap::new();
        let mut waiting = Vec::new();
        for (sender, mut entries) in senders {
            entries.sort_by(|a, b| {
                let nonce = a.transaction.body.nonce.cmp(&b.transaction.body.nonce);
                nonce.then_with(|| a.bid.cmp(&b.bid))
            });
            let start = room.start(state, &sender);
            first.insert(sender, start);
            let undecided = room.undecided(&sender);
            let mut expected = start;
            let mut lowest: Option<crate::chain::Priority> = None;
            for mut entry in entries {
                let nonce = entry.transaction.body.nonce;
                // Used, replaced or outbid at an equal nonce; then a nonce gap.
                if nonce < expected {
                    continue;
                }
                if nonce > expected {
                    break;
                }
                if room.fits(entry.bytes, entry.weight) && !undecided && expected == start {
                    break;
                }
                // Ranks never improve along a chain, so each entry sorts
                // after its predecessors (by nonce where they tie).
                if let Some(lowest) = &lowest
                    && *lowest > entry.bid
                {
                    entry.rank = lowest.clone();
                }
                lowest = Some(entry.rank.clone());
                waiting.push(entry);
                expected += 1;
            }
        }
        waiting.sort_by(|a, b| {
            let nonce = a.transaction.body.nonce.cmp(&b.transaction.body.nonce);
            a.rank.cmp(&b.rank).then(nonce)
        });
        let byte_limit = room.byte_limit;
        let (share_entries, share_bytes) = (
            MAX_BACKLOG / BACKLOG_SENDER_SHARE,
            byte_limit / BACKLOG_SENDER_SHARE,
        );
        let mut bytes = 0usize;
        // Each sender's next nonce to keep, and the entries and bytes its
        // chain holds past its first entry.
        let mut kept = BTreeMap::<PublicKey, (u64, usize, usize)>::new();
        let mut backlog = Vec::new();
        for entry in waiting {
            if backlog.len() == MAX_BACKLOG {
                break;
            }
            let sender = entry.transaction.body.sender;
            let (next, chained, chained_bytes) =
                kept.entry(sender).or_insert((first[&sender], 0, 0));
            // A predecessor left out strands every later nonce of its sender.
            if entry.transaction.body.nonce != *next {
                continue;
            }
            let following = *next != first[&sender];
            if following
                && (*chained >= share_entries
                    || chained_bytes.saturating_add(entry.bytes) > share_bytes)
            {
                continue;
            }
            let Some(total) = bytes
                .checked_add(entry.bytes)
                .filter(|total| *total <= byte_limit)
            else {
                continue;
            };
            bytes = total;
            *next += 1;
            if following {
                *chained += 1;
                *chained_bytes += entry.bytes;
            }
            backlog.push(entry);
        }
        Ok(backlog
            .into_iter()
            .map(|entry| entry.transaction.clone())
            .collect())
    }
    /// Install a selected pool, publishing only an actual change. A changed
    /// next-block selection also makes the cached template outdated.
    fn install_pool(
        &self,
        i: &mut Inner,
        (mempool, backlog): (Vec<Transaction>, Vec<Transaction>),
    ) -> Result<bool> {
        i.pool_tip = i.chain.tip_hash();
        let selection_changed = mempool[..] != i.mempool[..];
        let changed = selection_changed || backlog[..] != i.backlog[..];
        // An unchanged pool keeps the buffer its published view shares.
        if changed {
            i.set_pool(mempool, backlog);
        }
        if selection_changed {
            i.selection_revision = i.selection_revision.wrapping_add(1);
        }
        if changed {
            i.pool_revision = i.pool_revision.wrapping_add(1);
            self.publish(i)?;
        }
        Ok(changed)
    }
    /// The pool is selected for the current tip after every change; only an
    /// incomplete reorg recovery can leave entries from an earlier tip.
    fn refresh_stale_pool(&self, i: &mut Inner) -> Result<()> {
        if i.pool_tip == i.chain.tip_hash() {
            return Ok(());
        }
        let candidates: Vec<Transaction> = i
            .pending()
            .filter(|tx| Self::admissible(&i.chain, tx).is_ok())
            .cloned()
            .collect();
        let retained = candidates.iter().map(codec::transaction_id).collect();
        let pool = Self::select_pool(&i.chain, self.miner, &candidates, &retained, &retained)?;
        self.install_pool(i, pool)?;
        Ok(())
    }
    pub fn status(&self) -> Result<Value> {
        let view = self.read_view()?;
        Ok(Self::status_locked(&view))
    }
    fn status_locked(inner: &ReadView) -> Value {
        let s = inner.chain.tip_state();
        json!({"chain_id":hex::encode(inner.chain.chain_id()), "height":inner.chain.tip_height(), "storage":inner.storage_value(), "tip":hex::encode(inner.chain.tip_hash()), "state_root":hex::encode(inner.state_root()), "clock":s.clock, "time_unit":"seconds", "clock_basis":"target_interval", "issued":s.issued.to_str_radix(10), "test_work":inner.chain.config.test_work, "phase":s.phase_name(), "decision":s.decision_id().map(hex::encode), "auction_round":s.auction_round(), "settings":s.settings, "mempool":inner.mempool.len(), "reserve":s.world.reserve.to_str_radix(10), "shares":s.world.shares.to_str_radix(10), "curve_mass":s.world.curve_mass.to_str_radix(10),"grant_capacity":crate::consensus::grant_capacity(&s.world).to_str_radix(10), "revenue":s.world.revenue.to_str_radix(10), "fee_policy":json!({"minimum_fee_rate":s.settings.minimum_fee_rate.to_string(),"fee_scale":crate::fees::FEE_SCALE,"account_weight":crate::fees::ACCOUNT_WEIGHT})})
    }
    pub fn template(&self) -> Result<Block> {
        let mut block = self.template_shared(Freshness::Current)?.0.as_ref().clone();
        block.header.timestamp = block
            .header
            .timestamp
            .max(now().min(u32::MAX as u64) as u32);
        Ok(block)
    }
    /// The configured miner's template for the current tip, committing to the
    /// installed selection. Finishing a block clears its batch trades, so the
    /// build runs outside the node lock; the lock is held only to capture the
    /// selection and to store the result. Each build is claimed for the tip
    /// it extends: a request waits only for a build of the same parent, whose
    /// result it then reuses (see [TemplateBuilds]), and a new tip abandons a
    /// build for the old one at its next step, so new-tip work waits for an
    /// outdated build only until that step ends. The instant returned with a
    /// template that lags the selection or the tip is when to ask again; only
    /// Throttled templates lag the selection.
    fn template_shared(&self, freshness: Freshness) -> Result<(Arc<Block>, Option<Instant>)> {
        let served = |i: &Inner| -> Option<(Arc<Block>, Option<Instant>)> {
            let entry = i.template.as_ref()?;
            let tip = i.chain.tip_hash();
            if entry.tip != tip {
                return None;
            }
            if entry.selection == i.selection_revision && i.pool_tip == tip {
                return Some((entry.block.clone(), None));
            }
            let retry = entry.finished + entry.cost;
            (freshness == Freshness::Throttled && Instant::now() < retry)
                .then(|| (entry.block.clone(), Some(retry)))
        };
        let mut attempt = 0;
        loop {
            let parent = {
                let i = self.locked()?;
                if let Some(served) = served(&i) {
                    return Ok(served);
                }
                i.chain.tip_hash()
            };
            let _build = self.template_builds.claim(parent);
            // A new tip needs proof of work, so a repeat is rare. While the
            // tip keeps moving, as during catch-up, a request stops after
            // TEMPLATE_BUILD_ATTEMPTS builds rather than holding a build
            // slot, and a Stratum worker, until it rests. Each of those stops
            // at the next step once a new tip arrives and starts again on it.
            // The request is then served an empty template for the tip then
            // current: it clears no trades, so it runs to its end, holding its
            // slot only briefly, and is served unstored and due again at
            // once, so Stratum connections ask for the full template as soon
            // as their refresh interval allows.
            let (job, selection, generation, mut parked, empty) = {
                let mut i = self.locked()?;
                // Another build may have finished while this one waited.
                if let Some(served) = served(&i) {
                    return Ok(served);
                }
                // A new tip arrived while this one waited: claim that tip
                // instead, so a build is always claimed for the parent it
                // extends and a build of it never runs twice at once.
                if i.chain.tip_hash() != parent {
                    continue;
                }
                attempt += 1;
                let empty = attempt > TEMPLATE_BUILD_ATTEMPTS;
                self.refresh_stale_pool(&mut i)?;
                let parked = i
                    .template
                    .as_ref()
                    .filter(|entry| entry.tip == parent)
                    .map(|entry| entry.parked.clone())
                    .unwrap_or_default();
                let transactions = if empty {
                    Vec::new()
                } else {
                    Self::unparked(&i.mempool, &parked)
                };
                let job =
                    i.chain
                        .template_job(self.miner, transactions, Self::timestamp(&i.chain))?;
                (
                    job,
                    i.selection_revision,
                    self.tip_generation.load(Ordering::Acquire),
                    parked,
                    empty,
                )
            };
            let stale = || !empty && self.tip_generation.load(Ordering::Acquire) != generation;
            let started = Instant::now();
            let built = match job.build_unless(&stale) {
                Ok(built) => built,
                Err(error) if error.is::<crate::chain::TemplateStale>() => continue,
                Err(error) => return Err(error),
            };
            let finished = Instant::now();
            // The block was cut short before this transaction: it could not
            // be finished with it, or it no longer applied (logged by the
            // build). Later builds for this tip leave it out.
            if let Some(cut) = job.transactions().get(built.kept) {
                parked.insert(codec::transaction_id(cut));
            }
            let block = Arc::new(built.block);
            if empty {
                return Ok((block, Some(Instant::now())));
            }
            let mut i = self.locked()?;
            if i.chain.tip_hash() != job.previous() {
                continue;
            }
            // Current only if the selection did not change meanwhile.
            i.template = Some(TemplateEntry {
                block: block.clone(),
                tip: job.previous(),
                selection,
                finished,
                cost: finished - started,
                parked,
            });
            return Ok((block, None));
        }
    }
    /// `selection` without the `parked` transactions and their senders'
    /// later nonces, which could not apply without them.
    fn unparked(selection: &[Transaction], parked: &HashSet<Hash>) -> Vec<Transaction> {
        if parked.is_empty() {
            return selection.to_vec();
        }
        let mut stopped = HashSet::new();
        selection
            .iter()
            .filter(|tx| {
                if stopped.contains(&tx.body.sender) {
                    return false;
                }
                if parked.contains(&codec::transaction_id(tx)) {
                    stopped.insert(tx.body.sender);
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    }
    pub fn submit_transaction(&self, tx: Transaction) -> Result<Hash> {
        self.submit_transaction_from(tx, false)
    }
    /// [Node::submit_transaction], charged to the budget reserved for public
    /// broadcasts when `public`.
    fn submit_transaction_from(&self, tx: Transaction, public: bool) -> Result<Hash> {
        let view = self.read_view()?;
        let newcomer = Newcomer::new(tx, None, true);
        let id = newcomer.id;
        // A refused identity is answered from the refusal cache, without the
        // node lock or a selection, as a relayed copy is.
        if let Some(reason) =
            self.rejected_locked()
                .refusal(&id, &view.chain.tip_hash(), view.pool_revision)
        {
            bail!("{reason}");
        }
        // Authenticate before waiting for chain state.
        if let Err(error) = Self::screen_signed(&view.chain.chain_id(), &newcomer.transaction) {
            let message = format!("transaction not valid in next block: {error:#}");
            self.rejected_locked()
                .refuse(id, Refusal::Permanent, &message);
            bail!(message);
        }
        drop(view);
        self.admit_now(public, |_| Ok(newcomer)).map(|(id, _)| id)
    }
    fn wallet_submit(&self, request: HotWalletRequest) -> Result<Hash> {
        let sender = parse_account(
            &request.expected_sender,
            &self.read_view()?.chain.chain_id(),
        )?;
        // Copy the key checked against the selection revision and release the
        // wallet lock before waiting for chain state: wallet status readers must
        // never queue behind block validation or pool selection.
        let secret = Zeroizing::new(
            *self
                .wallets_locked()?
                .selected_secret(&sender, request.wallet_revision)?,
        );
        self.admit_now(false, |i| {
            let body = self.prepare_locked(
                i,
                sender,
                WalletRequest {
                    operation: request.operation,
                    fee: request.fee,
                    extra_fee: request.extra_fee,
                    data_hex: request.data_hex,
                    expiry_blocks: request.expiry_blocks,
                    anchor: request.anchor,
                    nonce: request.nonce,
                },
            )?;
            let transaction = crypto::sign(&i.chain.tip_state().chain_id, &body, &secret)?;
            Ok(Newcomer::new(transaction, None, false))
        })
        .map(|(id, _)| id)
    }
    fn prepare_locked(
        &self,
        i: &mut Inner,
        sender: PublicKey,
        request: WalletRequest,
    ) -> Result<TransactionBody> {
        // Every pool change already reselects for the current tip.
        self.refresh_stale_pool(i)?;
        Self::prepare_body(
            &i.chain.config,
            i.chain.tip_state(),
            i.chain.tip_hash(),
            i.pending(),
            sender,
            request,
        )
    }
    /// Prepare from one published view without the node lock.
    fn prepare_view(
        view: &ReadView,
        sender: PublicKey,
        request: WalletRequest,
    ) -> Result<TransactionBody> {
        Self::prepare_body(
            &view.chain.config,
            view.chain.tip_state(),
            view.chain.tip_hash(),
            view.mempool.iter(),
            sender,
            request,
        )
    }
    fn prepare_body<'a>(
        config: &Config,
        state: &State,
        tip: Hash,
        pending: impl Iterator<Item = &'a Transaction>,
        sender: PublicKey,
        request: WalletRequest,
    ) -> Result<TransactionBody> {
        check_operation_bounds(config, &request.operation)?;
        ensure!(
            request.expiry_blocks.is_none_or(|blocks| blocks > 0),
            "expiry_blocks must be positive"
        );
        let account = state
            .account(&sender, None)
            .context("sender account has not been funded")?;
        let mut nonce = account.nonce;
        for tx in pending {
            if tx.body.sender == sender {
                nonce = nonce.max(tx.body.nonce.checked_add(1).context("nonce exhausted")?);
            }
        }
        ensure!(nonce < u64::MAX, "nonce exhausted");
        ensure!(
            request.nonce.is_none_or(|requested| requested == nonce),
            "requested nonce differs from pending nonce"
        );
        let body = wallet_body(config, state, tip, sender, nonce, request)?;
        let unsigned_size = codec::encode(&body).len();
        // A signed transaction adds exactly 64 signature bytes.
        ensure!(
            unsigned_size.saturating_add(64) <= config.transaction_bytes(&state.settings),
            "transaction too large"
        );
        Ok(body)
    }
    /// Returns whether the block became the tip. A committed block is reported
    /// as accepted even when the following pool recovery fails.
    pub fn submit_block(&self, block: Block) -> Result<bool> {
        self.submit_block_from(block, None)
    }
    /// [Node::submit_block] for a block that `source` relayed, or that was
    /// submitted locally. The node lock is held only to check the block
    /// against the chain, in bounded replay steps between which it is
    /// released, and to store it: execution, which may clear batch trades
    /// for seconds, runs without it, so admission, templates and reads go
    /// on meanwhile. A block that would not become the tip replays its
    /// parent state and executes only within the side-branch bounds (see
    /// [Node::side_permit]), checked before any of that work and between
    /// its replay steps; otherwise its header is held, as the side-branch
    /// admission policy holds it.
    fn submit_block_from(&self, block: Block, source: Option<IpAddr>) -> Result<bool> {
        // A parent another worker is still validating is stored first.
        drop(self.validating.settle(&block.header.previous));
        let validating = self.validating.claim(codec::block_hash(&block));
        // The execution slot of a block that would not become the tip.
        let mut slot = None;
        let mut replay = REPLAY_STEPS;
        // Replay steps for the next hold of a block that would become the
        // tip, sized by time (see [replay_steps_after]).
        let mut per_hold = 1;
        let validation = loop {
            let mut i = self.locked_for_block()?;
            let height = i.chain.tip_height();
            let started = Instant::now();
            let mut granted = 0;
            let begun = i.chain.begin_submission(&block, now(), &mut |side| {
                let steps = if side {
                    self.side_permit(&mut slot, source, height)?;
                    SIDE_REPLAY_STEPS_PER_HOLD
                } else {
                    per_hold
                };
                granted = steps.min(replay);
                Ok(Some(granted))
            });
            let spent = started.elapsed();
            // A side block's checks and replay under the lock are charged
            // as its execution is; a block that would become the tip sizes
            // its next hold by this one's pace.
            if slot.is_some() {
                self.charge_side(source, spent);
            } else if granted > 0 {
                #[cfg(test)]
                let spent = REPLAY_HOLD_HOOK
                    .with(|hook| hook.borrow_mut().as_mut().map_or(spent, |hook| hook()));
                per_hold = replay_steps_after(granted, spent);
            }
            match begun {
                Ok(Some(validation)) => break validation,
                Ok(None) => return Ok(false),
                // A local block waits for the slot without the node lock.
                Err(error) if error.is::<SideSlotBusy>() => {
                    drop(i);
                    slot = Some(self.side_running.unpoisoned());
                }
                // The replay resumes from its retained progress.
                Err(error)
                    if error.is::<crate::chain::ValidationDeferred>() && replay > granted =>
                {
                    replay -= granted;
                }
                Err(error) => {
                    // A held header may raise the peer capacity allowance.
                    if let Err(error) = self.note_capacity(&i.chain) {
                        eprintln!("Peer capacity allowance unchanged: {error:#}");
                    }
                    return Err(error);
                }
            }
        };
        let started = Instant::now();
        let executed = validation.execute(&block);
        if slot.is_some() {
            self.charge_side(source, started.elapsed());
        }
        drop(slot);
        let mut i = self.locked_for_block()?;
        let old_tip = i.chain.tip_hash();
        let submitted = i
            .chain
            .finish_submission(validation, block, executed, now());
        // Validation can change the competitive capacity on any branch.
        if let Err(error) = self.note_capacity(&i.chain) {
            eprintln!("Peer capacity allowance unchanged: {error:#}");
        }
        if submitted.is_err() {
            Self::exit_if_storage_failing(&i.chain);
        }
        let changed = submitted?;
        if !changed {
            return Ok(false);
        }
        // A template build for the old tip stops at its next step.
        self.tip_generation.fetch_add(1, Ordering::AcqRel);
        i.template = None;
        i.selection_revision = i.selection_revision.wrapping_add(1);
        let pending: Vec<Transaction> = i.pending().cloned().collect();
        // Recovery may need disk access and cannot roll back a committed
        // block. The new tip is published once, together with its recovered
        // pool, so no reader sees it without the entries still pending.
        match self.recover_pool(&mut i, old_tip, &pending) {
            Ok(true) => {}
            // An unchanged pool still has a new tip to publish.
            Ok(false) => {
                if let Err(error) = self.publish(&i) {
                    eprintln!("New tip publication deferred: {error:#}");
                }
            }
            Err(error) => {
                // Keep every earlier entry; the next selection revalidates them.
                eprintln!("Pending transaction recovery deferred: {error:#}");
                i.set_pool(pending, Vec::new());
                i.pool_tip = old_tip;
                i.pool_revision = i.pool_revision.wrapping_add(1);
                i.selection_revision = i.selection_revision.wrapping_add(1);
                if let Err(error) = self.publish(&i) {
                    eprintln!("Pending transaction publication deferred: {error:#}");
                }
            }
        }
        let funding = self.funded_accounts(&i);
        let funded = Self::reconsider_awaiting(&mut i, &funding);
        let block_bytes = i.chain.tip_state().settings.block_bytes;
        drop(i);
        // The block is stored. A copy or child waiting for its validation
        // goes on now and asks for the node lock as a block submission, so
        // the admission below yields to it.
        drop(validating);
        #[cfg(test)]
        BLOCK_STORED_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        // Spends whose funding just confirmed, and relayed newcomers that
        // waited for the block, go through admission now.
        self.queue_admissions(funded, block_bytes);
        if let Err(error) = self.drain_admissions() {
            eprintln!("Queued transaction admission deferred: {error:#}");
        }
        Ok(true)
    }
    /// Admit a block that would not become the tip to replay its parent
    /// state and execute, into `slot`: one at a time node-wide, while
    /// node-wide side-validation time remains, and, for a relayed block,
    /// within its source's own share of stored side blocks and of that time.
    /// Replay holds and execution are charged after they ran
    /// ([Node::charge_side]); a block holding the slot continues its replay
    /// only while that time remains. Local submissions are trusted: they
    /// wait for the slot ([SideSlotBusy]). A refused block is not invalid;
    /// its header is held, so its branch is still followed once it claims
    /// more work than the tip.
    fn side_permit<'a>(
        &'a self,
        slot: &mut Option<std::sync::MutexGuard<'a, ()>>,
        source: Option<IpAddr>,
        height: u64,
    ) -> Result<()> {
        let refused = |reason| Err(crate::chain::SideBranchRefused(reason).into());
        let Some(source) = source else {
            if slot.is_none() {
                *slot = Some(match self.side_running.try_lock() {
                    Ok(running) => running,
                    Err(std::sync::TryLockError::Poisoned(running)) => running.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => return Err(SideSlotBusy.into()),
                });
            }
            return Ok(());
        };
        let now = Instant::now();
        if slot.is_some() {
            let mut side = self.side_validation.unpoisoned();
            if !side.budget.wait(now).is_zero() {
                return refused("side-branch validation time is spent");
            }
            if let Some(share) = side.sources.get_mut(&source)
                && !share.time.wait(now).is_zero()
            {
                return refused("this source's side-branch validation time is spent");
            }
            return Ok(());
        }
        let running = match self.side_running.try_lock() {
            Ok(running) => running,
            Err(std::sync::TryLockError::Poisoned(running)) => running.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return refused("another side-branch block is being validated");
            }
        };
        let mut side = self.side_validation.unpoisoned();
        if !side.budget.wait(now).is_zero() {
            return refused("side-branch validation time is spent");
        }
        if side.sources.len() >= MAX_SIDE_SOURCES && !side.sources.contains_key(&source) {
            side.sources.retain(|_, share| {
                share.refill(height);
                share.blocks < SIDE_SOURCE_BLOCKS || !share.time.full(now)
            });
            if side.sources.len() >= MAX_SIDE_SOURCES {
                return refused("too many sources hold side-branch shares");
            }
        }
        let share = side
            .sources
            .entry(source)
            .or_insert_with(|| SideSource::new(height));
        share.refill(height);
        if share.blocks == 0 {
            return refused("this source's side-branch blocks are spent");
        }
        if !share.time.wait(now).is_zero() {
            return refused("this source's side-branch validation time is spent");
        }
        share.blocks -= 1;
        *slot = Some(running);
        Ok(())
    }
    /// Charge a side block's replay or execution time node-wide and to its
    /// source.
    fn charge_side(&self, source: Option<IpAddr>, spent: Duration) {
        #[cfg(test)]
        let spent = SIDE_CHARGE.with(|charge| charge.get()).unwrap_or(spent);
        let mut side = self.side_validation.unpoisoned();
        let now = Instant::now();
        side.budget.spend(spent, now);
        if let Some(share) = source.and_then(|source| side.sources.get_mut(&source)) {
            share.time.spend(spent, now);
        }
    }
    /// Rebuild the pool for a new tip with one bounded selection, including
    /// transactions from an abandoned branch or same-height fork. Only header
    /// metadata is walked to the fork point, and each detached body is loaded
    /// once, oldest first, so nonce predecessors precede their successors.
    /// Anchor, nonce and funded-sender checks drop stale entries before the
    /// selection, which checks no signatures: pending entries were authenticated
    /// when pooled and detached ones when their blocks executed. An entry
    /// whose sender only a recovered transfer creates waits for that transfer
    /// to confirm (see [Awaiting]). Examination stops after
    /// MAX_RECOVERY_EXAMINED blocks and transactions. Returns whether the
    /// installed pool changed and was therefore published.
    fn recover_pool(&self, i: &mut Inner, old_tip: Hash, pending: &[Transaction]) -> Result<bool> {
        #[cfg(test)]
        ensure!(
            !FAIL_RECOVERY.with(|fail| fail.replace(false)),
            "injected recovery failure"
        );
        // The new branch is canonical: its fork point is the first old-branch
        // ancestor that is the canonical block at its own height.
        let mut detached = Vec::new();
        let mut cursor = old_tip;
        loop {
            let height = i
                .chain
                .block_height(&cursor)?
                .context("old branch block missing")?;
            if i.chain.hash_at_height(height) == Some(cursor) {
                break;
            }
            detached.push(cursor);
            cursor = i
                .chain
                .block_parent(&cursor)?
                .context("old branch parent missing")?;
        }
        let mut ids = HashSet::new();
        let mut candidates = Vec::new();
        let mut unfunded = Vec::new();
        let mut consider = |chain: &Chain, tx: &Transaction, candidates: &mut Vec<Transaction>| {
            if ids.insert(codec::transaction_id(tx)) {
                match Self::admissible_or_unfunded(chain, tx) {
                    Ok(true) => candidates.push(tx.clone()),
                    Ok(false) => unfunded.push(tx.clone()),
                    Err(_) => {}
                }
            }
        };
        for tx in pending {
            consider(&i.chain, tx, &mut candidates);
        }
        let mut examined = 0usize;
        'blocks: for hash in detached.iter().rev() {
            examined += 1;
            if examined > MAX_RECOVERY_EXAMINED {
                break;
            }
            let block = i.chain.block(hash).context("detached block missing")?;
            for tx in &block.transactions {
                examined += 1;
                if examined > MAX_RECOVERY_EXAMINED || candidates.len() >= MAX_SELECTION_CANDIDATES
                {
                    break 'blocks;
                }
                consider(&i.chain, tx, &mut candidates);
            }
        }
        candidates.truncate(MAX_SELECTION_CANDIDATES);
        // Each candidate was pooled or included before, so each may wait.
        let retained = candidates.iter().map(codec::transaction_id).collect();
        let pool = Self::select_pool(&i.chain, self.miner, &candidates, &retained, &retained)?;
        let changed = self.install_pool(i, pool)?;
        if !unfunded.is_empty() {
            let funding = self.funded_accounts(i);
            let (mut dropped, mut reason) = (0usize, "");
            for transaction in unfunded {
                // Beyond the holding bounds, or without a transfer that
                // creates its sender, it can be submitted again once funded.
                if let Err((_, why)) =
                    Self::hold_unfunded(i, &Newcomer::new(transaction, None, true), &funding)
                {
                    dropped += 1;
                    reason = why;
                }
            }
            if dropped > 0 {
                eprintln!(
                    "Reorganization recovery dropped {dropped} spends from accounts not yet created ({reason}); they can be submitted again once funded"
                );
            }
        }
        Ok(changed)
    }
    /// Also used on runtime workers, so it compares with the published tip.
    /// Submitting a solved block still validates it against the chain itself.
    fn mining_job_eligible(&self, block: &Block) -> Result<bool> {
        Ok(self.read_view()?.chain.tip_hash() == block.header.previous)
    }
    pub fn mine(&self, max_attempts: u64) -> Result<Block> {
        ensure!(
            (1..=100_000_000).contains(&max_attempts),
            "attempts must be 1..100000000"
        );
        let block = Chain::mine(self.template()?, max_attempts)?;
        self.submit_block(block.clone())?;
        Ok(block)
    }
    fn mine_to(&self, max_attempts: u64, recipient: PublicKey) -> Result<Block> {
        ensure!(
            crypto::valid_key(&recipient),
            "invalid mining recipient public key"
        );
        if recipient == self.miner {
            return self.mine(max_attempts);
        }
        ensure!(
            (1..=100_000_000).contains(&max_attempts),
            "attempts must be 1..100000000"
        );
        // Mining rewards affect the complete post-state commitment. Build a new
        // candidate without changing the configured miner or its Stratum
        // cache, finished outside the node lock like every template.
        let candidate = loop {
            let parent = self.locked()?.chain.tip_hash();
            let _build = self.template_builds.claim(parent);
            let job = {
                let i = self.locked()?;
                // A new tip arrived while this waited: claim that tip
                // instead, so the build is claimed for the parent it extends.
                if i.chain.tip_hash() != parent {
                    continue;
                }
                let candidates: Vec<Transaction> = i.pending().cloned().collect();
                let selection = i.chain.select_admission(
                    recipient,
                    &candidates,
                    mempool_limit(&i.chain.config),
                    &Self::pool_ids(&i),
                )?;
                i.chain.template_job(
                    recipient,
                    selection.transactions,
                    Self::timestamp(&i.chain),
                )?
            };
            break job.build()?.block;
        };
        let block = Chain::mine(candidate, max_attempts)?;
        self.submit_block(block.clone())?;
        Ok(block)
    }
    fn locator(chain: &Chain) -> Vec<Hash> {
        let mut out = Vec::new();
        let mut height = chain.tip_height();
        let mut step = 1u64;
        loop {
            if let Some(hash) = chain.hash_at_height(height) {
                out.push(hash);
            }
            if height == 0 {
                break;
            }
            height = height.saturating_sub(step);
            if out.len() >= 10 {
                step = step.saturating_mul(2);
            }
        }
        out
    }
    /// A locator lists download cursors first and its sender's complete
    /// active chain locator last. The run of hashes this node has active that
    /// ends it, with heights rising towards its front, therefore lies on the
    /// sender's active chain; return the highest. `canonical` gives each
    /// locator entry's active height here, if any.
    fn shared_active_tip(locator: &[Hash], canonical: &[Option<u64>]) -> Option<Hash> {
        let mut shared: Option<(Hash, u64)> = None;
        for (hash, height) in locator.iter().zip(canonical).rev() {
            match *height {
                Some(h) if shared.is_none_or(|(_, last)| h > last) => shared = Some((*hash, h)),
                _ => break,
            }
        }
        shared.map(|(hash, _)| hash)
    }
    /// Blocks after the best canonical locator match, the recipient's minimum
    /// admission limits, and the framed block bytes.
    #[cfg(test)]
    fn blocks_after(
        chain: &Chain,
        locator: &[Hash],
    ) -> Result<(Vec<Block>, peer_wire::Limits, usize)> {
        Self::blocks_within(chain, locator, None, &|_| true)
    }
    /// Each locator entry's height on this node's active chain, if any, and
    /// the highest of them.
    fn locator_heights(chain: &Chain, locator: &[Hash]) -> Result<(Vec<Option<u64>>, u64)> {
        ensure!(
            !locator.is_empty() && locator.len() <= 128,
            "invalid locator length"
        );
        // An untrusted locator is matched through the header index only: no
        // block body is decoded and no historical state is rebuilt for it.
        // A repeated hash is ignored.
        let mut seen = HashSet::new();
        let mut canonical = Vec::with_capacity(locator.len());
        for hash in locator {
            let mut height = None;
            if seen.insert(*hash)
                && let Some(h) = chain.block_height(hash)?
                && chain.hash_at_height(h) == Some(*hash)
            {
                height = Some(h);
            }
            canonical.push(height);
        }
        let height = canonical
            .iter()
            .flatten()
            .max()
            .copied()
            .context("no common ancestor")?;
        Ok((canonical, height))
    }
    /// As `blocks_after`, for a recipient that declared its block capacity
    /// allowance (transport version 2): every block, the first included, fits
    /// that allowance, so the reply never exceeds what it can receive.
    /// `charge` pays each block's work once the block is read; the reply
    /// ends before the first block it refuses.
    fn blocks_within(
        chain: &Chain,
        locator: &[Hash],
        declared: Option<u64>,
        charge: &dyn Fn(usize) -> bool,
    ) -> Result<(Vec<Block>, peer_wire::Limits, usize)> {
        let (canonical, height) = Self::locator_heights(chain, locator)?;
        // The recipient's admission allowance covers the genesis capacity and
        // the branch capacity of every block on its own active chain, which
        // the index records for the highest one this node shares. The next
        // active body also fits the common ancestor's capacity. Later blocks
        // stop before one requiring a larger capacity, so the recipient can
        // first validate a governed increase and raise its allowance on the
        // next synchronization. A declared allowance replaces this estimate,
        // within this node's own.
        let tip = chain.tip_height();
        let shared = Self::shared_active_tip(locator, &canonical);
        let mut capacity = chain.config.initial.block_bytes;
        if let Some(declared) = declared {
            capacity = declared.min(chain.max_known_block_bytes());
        } else if let Some(hash) = shared {
            capacity = capacity.max(
                chain
                    .block_capacity(&hash)?
                    .context("shared active block missing")?,
            );
        }
        // Only a match on the recipient's own active chain is a common
        // ancestor whose capacity the recipient has validated. A higher match
        // is one of its download cursors, possibly on a branch it stored but
        // whose larger capacity it no longer counts: a block after it is sent
        // only within the shared estimate, as one beyond would be refused whole.
        let ancestor =
            declared.is_none() && shared.is_some() && chain.hash_at_height(height) == shared;
        let mut limits = peer_wire::Limits::for_capacity(&chain.config, capacity);
        let mut out = Vec::new();
        let mut size = 0usize;
        let mut work = 0usize;
        for h in height + 1..=tip {
            if out.len() >= MAX_BATCH {
                break;
            }
            let b = chain
                .block(&chain.hash_at_height(h).context("active height missing")?)
                .context("active block missing")?;
            if out.is_empty() && ancestor {
                capacity = capacity.max(u64::try_from(codec::body_size(&b)?)?);
                limits = peer_wire::Limits::for_capacity(&chain.config, capacity);
            }
            let block_budget = limits.block_batch_bytes().min(
                limits
                    .frame_bytes()
                    .saturating_sub(peer_wire::SYNC_OVERHEAD_BYTES),
            );
            let record = codec::encode(&b).len();
            let bytes = peer_wire::record_size(record)?;
            let next_size = size
                .checked_add(bytes)
                .context("peer block batch length overflow")?;
            // Work is bounded per reply as well as bytes; the first block is
            // always sent, and its work fits the scaled peer burst.
            let next_work = work.saturating_add(b.transactions.len() + 1);
            if out.is_empty() {
                if record > limits.block_bytes || bytes > block_budget {
                    // A version 2 recipient learns this branch from its
                    // headers, and raises its declared allowance once the
                    // branch claims more work than its tip; a cursor's
                    // branch is sent once the recipient counts its capacity.
                    if !ancestor {
                        break;
                    }
                    bail!(
                        "valid block exceeds local peer wire capacity; import requires a larger transport representation"
                    );
                }
            } else if record > limits.block_bytes
                || next_size > block_budget
                || next_work > PEER_BATCH_WORK
            {
                break;
            }
            if !charge(b.transactions.len() + 1) {
                break;
            }
            size = next_size;
            work = next_work;
            out.push(b);
        }
        Ok((out, limits, size))
    }
    /// What a header reply to `locator` sends: the best canonical match's
    /// height and hash, and how many active headers follow it, at most
    /// MAX_HEADERS. Only the locator is looked up; no header is read yet.
    ///
    /// A requester whose locator opens with that match and its parent, and
    /// lies wholly on this node's active chain, is catching up on this chain:
    /// headers after its own tip extend that tip, which it never holds, so
    /// one header tells it so instead of a full reply it would discard.
    fn header_reply_plan(chain: &Chain, locator: &[Hash]) -> Result<(u64, Hash, usize)> {
        let (canonical, height) = Self::locator_heights(chain, locator)?;
        let hash = chain
            .hash_at_height(height)
            .context("active height missing")?;
        let available = usize::try_from(chain.tip_height().saturating_sub(height))
            .unwrap_or(usize::MAX)
            .min(peer_wire::MAX_HEADERS);
        let catching_up = locator[0] == hash
            && height > 0
            && canonical.get(1) == Some(&Some(height - 1))
            && Self::shared_active_tip(locator, &canonical) == Some(hash);
        Ok((
            height,
            hash,
            if catching_up {
                available.min(1)
            } else {
                available
            },
        ))
    }
    /// Active headers after `height`, whose block is `hash`, from the header
    /// index without any block body: at most `count`, read HEADER_READ_CHUNK
    /// at a time with the node lock released in between and block work let
    /// first, so a reply never holds the lock for long. A reorganization
    /// meanwhile ends the reply where the active chain still continued it.
    fn headers_from(&self, mut height: u64, mut hash: Hash, count: usize) -> Result<Vec<Header>> {
        let mut headers = Vec::with_capacity(count);
        while headers.len() < count {
            if !headers.is_empty() {
                self.yield_to_blocks();
            }
            let i = self.locked()?;
            if i.chain.hash_at_height(height) != Some(hash) {
                break;
            }
            let end = count.min(headers.len() + HEADER_READ_CHUNK);
            while headers.len() < end {
                let Some(next) = i.chain.hash_at_height(height + 1) else {
                    return Ok(headers);
                };
                headers.push(
                    i.chain
                        .block_header(&next)?
                        .context("active header missing")?,
                );
                (height, hash) = (height + 1, next);
            }
        }
        Ok(headers)
    }
    #[cfg(test)]
    fn peer_snapshot(&self, locator: Option<&[Hash]>) -> Result<PeerMessage> {
        self.peer_snapshot_within(locator, None)
    }
    /// `peer_snapshot_charged` with nothing to pay.
    #[cfg(test)]
    fn peer_snapshot_within(
        &self,
        locator: Option<&[Hash]>,
        declared: Option<u64>,
    ) -> Result<PeerMessage> {
        self.peer_snapshot_charged(locator, declared, &|_| true)
    }
    /// A synchronization message whose blocks fit `declared`, the capacity
    /// allowance a version 2 recipient declared, when there is one. Each
    /// block and loose transaction is paid for with `charge` as it is added,
    /// before the message is encoded: the message ends at the first entry the
    /// budget refuses, so a session whose budget is spent receives a shorter
    /// message, and none is built beyond what that budget pays for.
    fn peer_snapshot_charged(
        &self,
        locator: Option<&[Hash]>,
        declared: Option<u64>,
        charge: &dyn Fn(usize) -> bool,
    ) -> Result<PeerMessage> {
        let mut i = self.locked()?;
        let (blocks, peer_limits, blocks_bytes) = match locator {
            Some(l) => Self::blocks_within(&i.chain, l, declared, charge)?,
            None => (
                Vec::new(),
                peer_wire::Limits::from_config(&i.chain.config),
                0,
            ),
        };
        let transaction_budget = peer_limits.transaction_batch_bytes().min(
            peer_limits
                .frame_bytes()
                .saturating_sub(blocks_bytes)
                .saturating_sub(peer_wire::SYNC_OVERHEAD_BYTES),
        );
        let mut transaction_bytes = 0usize;
        let start = i.relay_cursor.min(i.mempool.len().saturating_sub(1));
        let mut visited = 0;
        let mut transactions = Vec::new();
        // Preserve normal simultaneous block/mempool relay, while postponing
        // records larger than the recipient's validated admission allowance.
        for tx in i
            .mempool
            .iter()
            .cycle()
            .skip(start)
            .take(i.mempool.len().min(MAX_MEMPOOL))
        {
            let raw_bytes = codec::encode(tx).len();
            if raw_bytes > peer_limits.transaction_bytes {
                visited += 1;
                continue;
            }
            let bytes = peer_wire::record_size(raw_bytes)?;
            let next = transaction_bytes
                .checked_add(bytes)
                .context("peer transaction batch length overflow")?;
            if next > transaction_budget {
                if transactions.is_empty() {
                    visited += 1;
                    continue;
                }
                break;
            }
            // Unpaid entries stay for a later message.
            if !charge(1) {
                break;
            }
            visited += 1;
            transaction_bytes = next;
            transactions.push(tx.clone());
        }
        i.relay_cursor = if i.mempool.is_empty() {
            0
        } else {
            (start + visited) % i.mempool.len()
        };
        // Download cursors come first and the active chain locator last. The
        // active part is never shortened by deduplication, so a responder can
        // tell which of its hashes this node has on its active chain.
        let active = Self::locator(&i.chain);
        // A cursor into a presynced branch whose held headers now claim more
        // work than the tip resumes at its stored root, so the peer resends
        // the bodies; cursors the chain no longer knows are dropped.
        let mut seen: HashSet<Hash> = active.iter().copied().collect();
        let mut request_locator = Vec::new();
        let mut cursors = std::mem::take(&mut i.downloads);
        cursors.retain(|cursor| {
            let entry = match i.chain.download_cursor(&cursor.hash) {
                Ok(Some(entry)) => entry,
                Ok(None) => return false,
                Err(_) => cursor.hash,
            };
            if seen.insert(entry) {
                request_locator.push(entry);
            }
            true
        });
        i.downloads = cursors;
        request_locator.extend(active);
        // Keep genesis as the final fallback even for the largest supported height.
        if request_locator.len() > 128 {
            let genesis = i.chain.hash_at_height(0).expect("genesis exists");
            request_locator.truncate(127);
            request_locator.push(genesis);
        }
        Ok(PeerMessage {
            chain: i.chain.chain_id(),
            locator: request_locator,
            blocks,
            transactions,
        })
    }
    /// A header request to `peer`: the cursor of its header download, the
    /// best admitted held chains, then this node's active chain locator,
    /// with this node's block capacity allowance.
    fn header_request(&self, peer: SocketAddr) -> Result<PeerPacket> {
        let mut guard = self.locked()?;
        let Inner {
            chain,
            header_syncs,
            ..
        } = &mut *guard;
        // A download that holds no new header for a while releases its
        // pinned headers, which become evictable, and holds its branch
        // again from the stored root when its peer next answers.
        for sync in header_syncs.values_mut() {
            if sync.proof.is_some() && sync.touched.elapsed() >= HEADER_SYNC_IDLE {
                chain.release_header_pin(sync.pin);
                sync.held = None;
            }
        }
        let mut locator: Vec<Hash> = header_syncs
            .get(&peer)
            .map(HeaderSync::cursor)
            .into_iter()
            .collect();
        locator.extend(chain.admitted_header_tips(8));
        locator.extend(Self::locator(chain));
        // Keep genesis as the final fallback even for the largest supported height.
        if locator.len() > peer_wire::MAX_LOCATORS {
            let genesis = chain.hash_at_height(0).expect("genesis exists");
            locator.truncate(peer_wire::MAX_LOCATORS - 1);
            locator.push(genesis);
        }
        Ok(PeerPacket::GetHeaders {
            chain: chain.chain_id(),
            version: peer_wire::TRANSPORT_VERSION,
            capacity: chain.max_known_block_bytes(),
            locator,
        })
    }
    /// Answer a header request from this node's active chain.
    #[cfg(test)]
    fn headers_reply(&self, locator: &[Hash], version: u8) -> Result<PeerPacket> {
        self.headers_reply_within(locator, version, |_| Ok(()))
    }
    /// Answer a header request from this node's active chain. `charge` pays
    /// for the number of headers the reply will carry before any is read; a
    /// refusal ends the reply unbuilt.
    fn headers_reply_within(
        &self,
        locator: &[Hash],
        version: u8,
        charge: impl FnOnce(usize) -> Result<()>,
    ) -> Result<PeerPacket> {
        let (chain, (height, hash, planned)) = {
            let i = self.locked()?;
            (
                i.chain.chain_id(),
                Self::header_reply_plan(&i.chain, locator)?,
            )
        };
        charge(planned)?;
        Ok(PeerPacket::Headers {
            chain,
            version: version.min(peer_wire::TRANSPORT_VERSION),
            headers: self.headers_from(height, hash, planned)?,
        })
    }
    /// Follow a header reply from `peer`, an outbound peer this node asked.
    /// Returns whether another request can continue the download.
    fn receive_headers(&self, peer: SocketAddr, headers: &[Header]) -> Result<bool> {
        ensure!(
            headers.len() <= peer_wire::MAX_HEADERS,
            "peer header limit exceeded"
        );
        let mut guard = self.locked()?;
        let Inner {
            chain,
            header_syncs,
            downloads,
            ..
        } = &mut *guard;
        if headers.is_empty() {
            match header_syncs.get_mut(&peer) {
                // Holding stopped short of the header the peer counted: it
                // no longer serves that branch, and its pins are released.
                Some(sync) if sync.proof.is_some() => {
                    chain.release_header_pin(sync.pin);
                    header_syncs.remove(&peer);
                }
                // The peer's branch ends at the counted cursor; counting
                // resumes there when it grows.
                Some(sync) => sync.touched = Instant::now(),
                None => {}
            }
            return Ok(false);
        }
        // Headers that one reply admits are written in one commit.
        let result = chain
            .hold_batch(|chain| {
                follow_headers(chain, header_syncs, downloads, peer, headers, now())
            })
            .and_then(std::convert::identity);
        // An admitted chain can raise the capacity allowance without a new block.
        if let Err(error) = self.note_capacity(chain) {
            eprintln!("Peer capacity allowance unchanged: {error:#}");
        }
        result
    }
    /// Header request closes within LEGACY_PEER_RETRY of their last one.
    fn header_closes(&self) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, HeaderCloses>> {
        let mut closes = self.legacy_peers.unpoisoned();
        closes.retain(|_, closes| closes.at.elapsed() < LEGACY_PEER_RETRY);
        closes
    }
    /// Whether to open a session with `peer` by header requests: unless it
    /// is taken for a version 1 peer.
    fn speaks_headers(&self, peer: SocketAddr) -> bool {
        !self
            .header_closes()
            .get(&peer)
            .is_some_and(HeaderCloses::legacy)
    }
    /// Count a session `peer` closed on its first header request before any
    /// reply byte; whether it is now taken for a version 1 peer. A version 2
    /// peer can do this too, when it refuses or evicts the session, so one
    /// such session is not enough.
    fn note_header_close(&self, peer: SocketAddr) -> bool {
        let mut closes = self.header_closes();
        if closes.len() >= MAX_LEGACY_PEERS
            && !closes.contains_key(&peer)
            && let Some(oldest) = closes.iter().min_by_key(|(_, c)| c.at).map(|(p, _)| *p)
        {
            closes.remove(&oldest);
        }
        let entry = closes.entry(peer).or_insert(HeaderCloses {
            count: 0,
            at: Instant::now(),
        });
        entry.count = entry.count.saturating_add(1);
        entry.at = Instant::now();
        entry.legacy()
    }
    /// `peer` answered a header request: its earlier closes no longer count.
    fn note_header_reply(&self, peer: SocketAddr) {
        self.legacy_peers.unpoisoned().remove(&peer);
    }
    /// Accept a peer message from `source`, the address that sent it. A block
    /// of it that this call makes the tip, and a transaction of it that a
    /// selection admits as new, credit that address with a delivery, which
    /// keeps its inbound sessions from eviction (`PeerSlots::delivered`); the
    /// block also tells discovery that the address advanced this node
    /// (`PeerSlots::advanced`).
    fn receive_peer(&self, msg: &PeerMessage, source: IpAddr) -> Result<()> {
        ensure!(
            msg.chain == self.read_view()?.chain.chain_id(),
            "different genesis configuration"
        );
        let peer = source;
        let source = network_guard::peer_source(source);
        ensure!(
            msg.blocks.len() <= MAX_BATCH
                && msg.transactions.len() <= MAX_MEMPOOL
                && msg.locator.len() <= 128,
            "peer batch limit exceeded"
        );
        let config = self.read_view()?.chain.config.clone();
        // The last block of a reply made only of linked known active blocks.
        let mut shared = None;
        for (index, b) in msg.blocks.iter().enumerate() {
            let hash = codec::block_hash(b);
            let known = {
                let i = self.locked_for_block()?;
                match i.chain.block_height(&hash)? {
                    // A stored active block is never download progress by
                    // itself; only a linked all-active reply is (below).
                    Some(height) if i.chain.hash_at_height(height) == Some(hash) => {
                        let linked = index == 0 || shared == Some(b.header.previous);
                        shared = linked.then_some(hash);
                        continue;
                    }
                    known => known.is_some(),
                }
            };
            shared = None;
            if !known {
                // Every valid block meets its own compact target within the
                // genesis limit. Check that before copying or hashing a large
                // record under the node lock.
                let target = math::target_from_bits(b.header.bits)?;
                ensure!(
                    target <= math::target_from_bits(config.limit_bits)?,
                    "block target exceeds the network limit"
                );
                math::check_pow(&b.header, &target)?;
                match self.submit_block_from(b.clone(), Some(source)) {
                    Ok(true) => self.peer_sessions.advanced(peer),
                    Ok(false) => {}
                    // A declined side block's header is held for presync, so
                    // the rest of its branch is still downloaded after it. A
                    // full presync bound may evict that header at once; the
                    // reply's later blocks then have no known parent, which
                    // is not the sender's fault, so its blocks end here.
                    Err(error) if error.is::<crate::chain::SideBranchRefused>() => {
                        let held = self.locked_for_block()?.chain.header_parent(&hash)?;
                        if held == HeaderParent::Unknown {
                            break;
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            // A stored side block still refreshes its sender's cursor, so a
            // download resumes after a restart or eviction. Replacing the
            // sender's preceding cursor for this branch makes normal downloads
            // consume one entry each rather than one per batch.
            // Retain accepted progress even if a later message entry is invalid.
            let mut i = self.locked_for_block()?;
            note_download(&mut i.downloads, hash, b.header.previous, source);
        }
        if let Some(hash) = shared {
            // A reply wholly inside the active chain still shows where the
            // sender's chain continues; without it a fork deeper than one
            // batch beyond a sparse locator entry never reaches its blocks.
            // Such a cursor belongs to its source and replaces that source's
            // cursor at the reply's start. In a full list it displaces only
            // the oldest active-chain cursor, never a competing-branch cursor,
            // and only its own source's or one whose source holds more.
            let mut i = self.locked()?;
            let start = msg.blocks[0].header.previous;
            let Inner {
                chain, downloads, ..
            } = &mut *i;
            downloads.retain(|d| d.source != source || (d.hash != hash && d.hash != start));
            if downloads.len() >= MAX_CONNECTIONS {
                let mut held: HashMap<IpAddr, usize> = HashMap::new();
                for download in downloads.iter() {
                    *held.entry(download.source).or_default() += 1;
                }
                let own = held.get(&source).copied().unwrap_or(0) + 1;
                let oldest = downloads.iter().rposition(|d| {
                    (d.source == source || held[&d.source] > own)
                        && chain
                            .block_height(&d.hash)
                            .ok()
                            .flatten()
                            .is_some_and(|height| chain.hash_at_height(height) == Some(d.hash))
                });
                if let Some(oldest) = oldest {
                    downloads.remove(oldest);
                }
            }
            if downloads.len() < MAX_CONNECTIONS {
                downloads.push_back(Download { hash, source });
            }
        }
        // Admit the batch together. Revalidating every growing prefix here made
        // one ordinary full-pool relay need tens of thousands of signature checks.
        // Outdated/duplicate entries remain expected during synchronization.
        // Each message also drains newcomers that earlier ones queued.
        if msg.transactions.is_empty() {
            return self.drain_admissions();
        }
        // Authenticate unseen entries before taking the node lock. Rejected
        // identities are remembered, so replayed junk never reaches selection.
        let view = self.read_view()?;
        let mut seen: HashSet<_> = view.mempool.iter().map(codec::transaction_id).collect();
        let mut fresh = Vec::new();
        {
            let rejected = self.rejected_locked();
            for tx in &msg.transactions {
                let encoded = codec::encode(tx);
                let id = crypto::sha256d(&encoded);
                if !rejected.contains(&id, &view.chain.tip_hash(), view.pool_revision)
                    && seen.insert(id)
                {
                    fresh.push(Newcomer {
                        id,
                        transaction: tx.clone(),
                        bytes: encoded.len(),
                        source: Some(source),
                        peer: Some(peer),
                        authenticated: true,
                        operator: false,
                    });
                }
            }
        }
        let chain_id = view.chain.chain_id();
        fresh.retain(
            |newcomer| match Self::screen_signed(&chain_id, &newcomer.transaction) {
                Ok(()) => true,
                Err(error) => {
                    self.rejected_locked().refuse(
                        newcomer.id,
                        Refusal::Permanent,
                        &format!("transaction not valid in next block: {error:#}"),
                    );
                    false
                }
            },
        );
        // Newcomers wait for the node-wide selection budget and for block
        // submissions in a queue, which one selection drains.
        self.queue_admissions(fresh, view.chain.tip_state().settings.block_bytes);
        drop(view);
        self.drain_admissions()
    }
    #[cfg(test)]
    fn read_rpc(i: &ReadView, method: &str, params: Value) -> Result<Value> {
        Self::read_rpc_metered(i, method, params, None)
    }
    /// The admission session, when present, is charged for work that depends
    /// on request operands or on state size, before that work is performed.
    fn read_rpc_metered(
        i: &ReadView,
        method: &str,
        params: Value,
        meter: Option<&Session>,
    ) -> Result<Value> {
        let chain_id = i.chain.chain_id();
        match method {
            "address" | "validateaddress" => {
                let public = if method == "validateaddress" {
                    address::decode(required_str(&params, "address")?, &chain_id)?
                } else {
                    parse_key(required_str(&params, "public_key")?)?
                };
                Ok(
                    json!({"address":address::encode(&public,&chain_id)?,"public_key":hex::encode(public),"address_hrp":address::hrp(&chain_id)}),
                )
            }
            "status" => Ok(Self::status_locked(i)),
            "config" => Ok(serde_json::to_value(&i.chain.config)?),
            "fee_quote" => {
                let c = &i.chain.config;
                let sender = parse_account(required_str(&params, "sender")?, &chain_id)?;
                let mut fields = params;
                fields
                    .as_object_mut()
                    .context("expected quote fields")?
                    .remove("sender");
                let request: WalletRequest = serde_json::from_value(fields)?;
                let s = i.chain.tip_state();
                let nonce = request
                    .nonce
                    .unwrap_or_else(|| s.account(&sender, None).map_or(0, |a| a.nonce));
                let body = wallet_body(c, s, i.chain.tip_hash(), sender, nonce, request)?;
                fee_quote_json(c, s, i.chain.tip_hash(), i.state_root(), &body)
            }
            "transfer_quote" => {
                let c = &i.chain.config;
                if let Some(data) = params.get("data_hex") {
                    transaction_data(
                        c.transaction_bytes(&i.chain.tip_state().settings),
                        Some(
                            data.as_str()
                                .context("transaction data must be hexadecimal bytes")?,
                        ),
                    )?;
                }
                let recipient = parse_account(required_str(&params, "recipient")?, &chain_id)?;
                let sender = params
                    .get("sender")
                    .map(|sender| {
                        parse_account(
                            sender
                                .as_str()
                                .context("sender must be an address or public key")?,
                            &chain_id,
                        )
                    })
                    .transpose()?;
                let amount = parse_amount(required_str(&params, "amount")?)?;

                c.check_amount(&amount)?;
                ensure!(!amount.is_zero(), "zero transfer");
                let sender = sender.context("sender is required for automatic fee quote")?;
                let mut fields = params;
                let values = fields.as_object_mut().context("expected quote fields")?;
                for key in ["sender", "recipient", "amount"] {
                    values.remove(key);
                }
                values.insert(
                    "operation".into(),
                    serde_json::to_value(Operation::TransferExact {
                        recipient,
                        amount: amount.clone(),
                    })?,
                );
                let request: WalletRequest = serde_json::from_value(fields)?;
                let s = i.chain.tip_state();
                let nonce = request
                    .nonce
                    .unwrap_or_else(|| s.account(&sender, None).map_or(0, |a| a.nonce));
                let body = wallet_body(c, s, i.chain.tip_hash(), sender, nonce, request)?;
                let mut quote = fee_quote_json(c, s, i.chain.tip_hash(), i.state_root(), &body)?;
                let fee = parse_amount(required_str(&quote, "fee")?)?;
                let total = &amount + &fee;
                c.check_amount(&total)?;
                quote["recipient"] = json!(address::encode(&recipient, &chain_id)?);
                quote["public_key"] = json!(hex::encode(recipient));
                quote["amount"] = json!(amount.to_str_radix(10));
                quote["recipient_receives"] = json!(amount.to_str_radix(10));
                quote["account_creation_charge"] = quote["account_creation_fee"].clone();
                quote["total_debit"] = json!(total.to_str_radix(10));
                Ok(quote)
            }
            "governance" => {
                // The inline decision grant is projected into every response.
                let payments = decision_payments(i.chain.tip_state());
                charge(meter, payments)?;
                Ok(if payments > SUMMARY_GRANT_PAYMENTS {
                    // A complete grant can be as large as governed capacity
                    // admits, so it is built per paid call and never retained.
                    governance_value(i, false)
                } else {
                    i.governance_summary()
                })
            }
            "proposals" => {
                let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(128)
                    .min(128) as usize;
                let round = params.get("round").and_then(Value::as_u64);
                // Round pages follow support, which changes between tips. A
                // client paging one listing names the tip of its first page.
                if let Some(tip) = params.get("tip") {
                    let tip = parse_hash(tip.as_str().context("tip must be a block hash")?)?;
                    ensure!(
                        tip == i.chain.tip_hash(),
                        "proposal pages changed with a new tip; restart from offset 0"
                    );
                }
                let ids: Vec<Hash> = match round {
                    Some(round) => {
                        let ids = i.proposal_index().round(round);
                        let ids = ids.get(offset..).unwrap_or_default();
                        ids[..ids.len().min(limit)].to_vec()
                    }
                    // Key order is the map's own: the offset is found by
                    // subtree size, so a page reads only its rows however
                    // many proposals history holds.
                    None => i
                        .chain
                        .tip_state()
                        .proposals
                        .iter_from(offset)
                        .take(limit)
                        .filter_map(|(key, _)| Hash::try_from(key).ok())
                        .collect(),
                };
                proposal_page(i, &ids, false, meter)
            }
            "support" => {
                let key = parse_account(required_str(&params, "key")?, &chain_id)?;
                let proposal = parse_hash(required_str(&params, "proposal")?)?;
                let round = params
                    .get("round")
                    .and_then(Value::as_u64)
                    .context("round required")?;
                let s = i.chain.tip_state();
                let p = s.proposals.get(&proposal).context("unknown proposal")?;
                ensure!(p.round == round, "wrong proposal round");
                let r = s
                    .rounds
                    .get(&round.to_be_bytes())
                    .context("unknown round")?;
                let record = s
                    .supports
                    .get(&crate::state::support_key(round, &proposal, &key));
                let next_height = s.height.checked_add(1).context("height exhausted")?;
                let won = matches!(&r.status, crate::state::RoundStatus::Won(winner) if *winner == proposal);
                let eligible = match &r.status {
                    crate::state::RoundStatus::Won(winner) => {
                        *winner != proposal && next_height >= r.refund_height
                    }
                    crate::state::RoundStatus::Timeout => next_height >= r.refund_height,
                    crate::state::RoundStatus::Open => {
                        p.refund_height.is_some_and(|h| next_height >= h)
                    }
                };
                // A winning round's support became revenue when its decision
                // opened; the retained record is never refundable. A refund
                // removes the record, so "none" also covers claimed support.
                let status = match record {
                    None => "none",
                    Some(_) if won => "converted_to_revenue",
                    Some(_) if eligible => "refundable",
                    Some(_) => "locked",
                };
                Ok(
                    json!({"amount":record.map_or_else(||"0".to_owned(),|r|r.amount.to_str_radix(10)),"refundable":record.is_some() && eligible,"status":status}),
                )
            }
            "mempool" => {
                let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(128)
                    .min(128) as usize;
                let format = params
                    .get("format")
                    .and_then(Value::as_str)
                    .unwrap_or("json");
                ensure!(
                    matches!(format, "json" | "hex"),
                    "mempool format must be json or hex"
                );
                charge(meter, mempool_work(&i.mempool, offset, limit, format))?;
                if format == "hex" {
                    mempool_hex_page(&i.mempool, offset, limit)
                } else {
                    mempool_page(&i.mempool, offset, limit, false)
                        .context("mempool JSON page is too large; request format: hex")
                }
            }
            "account" => {
                let key = parse_account(required_str(&params, "key")?, &chain_id)?;
                let outcome = parse_outcome(&params)?;
                let s = i.chain.tip_state();
                let a = s.account(&key, outcome).context("account does not exist")?;
                let world = match outcome {
                    Some(Outcome::Pass) => {
                        s.alternative.as_ref().context("no active PASS state")?
                    }
                    _ => &s.world,
                };
                charge(meter, curve_evaluation_work(world))?;
                let (numerator, den) = if world.shares.is_zero() {
                    (Amount::from(1u32), i.chain.config.share_scale.clone())
                } else {
                    (world.curve_mass.clone(), world.shares.clone())
                };
                let value = &a.shares * &numerator;
                let withdrawal = stash_withdrawal(world, &a.shares)?;
                let payment_available = s.common_spendable(&key).unwrap_or_default();
                // Nonces are common to both outcomes. Clients obtain the next
                // pending nonce without downloading every raw pending record.
                // A decimal string, as in snapshot, so no client rounds it.
                let pending_nonce = i
                    .mempool
                    .iter()
                    .filter(|tx| tx.body.sender == key)
                    .fold(a.nonce, |nonce, tx| {
                        nonce.max(tx.body.nonce.saturating_add(1))
                    })
                    .to_string();
                Ok(
                    json!({"key":hex::encode(key), "account":a, "pending_nonce":pending_nonce, "payment_available_hash":payment_available.to_str_radix(10), "price_hash_per_share":{"numerator":numerator.to_str_radix(10),"denominator":den.to_str_radix(10)}, "stash_value_hash":{"numerator":value.to_str_radix(10),"denominator":den.to_str_radix(10)}, "stash_withdrawal_hash":withdrawal.to_str_radix(10)}),
                )
            }
            "stash_quote" => {
                let s = i.chain.tip_state();
                let c = &i.chain.config;
                let key = parse_account(required_str(&params, "key")?, &chain_id)?;
                ensure!(
                    params
                        .get("outcome")
                        .is_none_or(|value| value.is_null() || value.is_string()),
                    "outcome must be pass or fail"
                );
                let outcome = parse_outcome(&params)?;
                ensure!(
                    s.decision_id().is_some() == outcome.is_some(),
                    "select PASS or FAIL during governance; omit outcome otherwise"
                );
                ensure!(outcome.is_none() || !trading_closed(s), TRADING_CLOSED);
                let w = match outcome {
                    Some(Outcome::Pass) => {
                        s.alternative.as_ref().context("no active PASS state")?
                    }
                    _ => &s.world,
                };
                let a = s.account(&key, outcome).context("account does not exist")?;
                let kind = required_str(&params, "kind")?;
                ensure!(
                    matches!(kind, "deposit" | "withdraw" | "redeem"),
                    "kind must be deposit, withdraw or redeem"
                );
                let all = match params.get("all") {
                    None => false,
                    Some(value) => value.as_bool().context("all must be boolean")?,
                };
                ensure!(
                    !all || matches!(kind, "withdraw" | "redeem"),
                    "all is only valid for withdrawal"
                );
                let amount_text = match params.get("amount") {
                    None if all => "0",
                    Some(value) => value.as_str().context("amount must be a decimal string")?,
                    None => bail!("missing string field amount"),
                };
                ensure!(amount_text.len() <= 155, "amount out of range");
                let amount = parse_amount(amount_text)?;
                if kind == "redeem" {
                    c.check_shares(&amount)?;
                } else {
                    c.check_amount(&amount)?;
                }
                ensure!(all || !amount.is_zero(), "amount must be positive");
                // Valuations before and after, plus a withdrawal share search.
                charge(meter, 3 * curve_evaluation_work(w))?;
                let before = stash_withdrawal(w, &a.shares)?;
                let is_buy = kind == "deposit";
                let (amount, input) = if is_buy {
                    ensure!(amount <= a.ordinary, "insufficient deposit balance");
                    (amount.clone(), amount)
                } else {
                    ensure!(!a.shares.is_zero(), "Stash has no shares");
                    let target = if all {
                        if kind == "redeem" {
                            a.shares.clone()
                        } else {
                            before.clone()
                        }
                    } else {
                        amount
                    };
                    let burn = if kind == "redeem" {
                        ensure!(target <= a.shares, "amount exceeds Stash share balance");
                        target.clone()
                    } else {
                        ensure!(target <= before, "amount exceeds Stash withdrawal balance");
                        if all {
                            a.shares.clone()
                        } else {
                            math::dynamic_withdrawal_shares(
                                &w.reserve,
                                &w.shares,
                                &target,
                                &w.curve_mass,
                            )?
                        }
                    };
                    ensure!(burn <= a.shares, "insufficient shares");
                    (target, burn)
                };
                charge(
                    meter,
                    trade_work(w, is_buy, &input, s.settings.max_price_change_bps),
                )?;
                let (filled, output, after_world) =
                    preview_trade(c, w, is_buy, &input, s.settings.max_price_change_bps)?;
                let share_after = if is_buy {
                    &a.shares + &output
                } else {
                    &a.shares - &filled
                };
                let after = stash_withdrawal(&after_world, &share_after)?;
                let shares = if is_buy {
                    output.clone()
                } else {
                    input.clone()
                };
                let output_hash = if is_buy {
                    ensure!(after >= before, "deposit reduces withdrawal value");
                    &after - &before
                } else {
                    output.clone()
                };
                Ok(json!({
                    "kind":kind, "amount":amount.to_str_radix(10), "all":all,
                    "shares":shares.to_str_radix(10), "shares_filled":if is_buy {output.to_str_radix(10)} else {filled.to_str_radix(10)},
                    "input_requested":input.to_str_radix(10), "input_filled":filled.to_str_radix(10),
                    "input_unfilled":(&input-&filled).to_str_radix(10), "output":output.to_str_radix(10),
                    "output_hash":output_hash.to_str_radix(10),
                    "share_before":a.shares.to_str_radix(10), "share_after":share_after.to_str_radix(10),
                    "stash_before_hash":before.to_str_radix(10), "stash_after_hash":after.to_str_radix(10),
                    "outcome":outcome, "decision":s.decision_id().map(hex::encode),
                    "height":s.height, "tip":hex::encode(i.chain.tip_hash()), "state_root":hex::encode(i.state_root()),
                    "transaction_fee_included":false, "indicative":true, "partial_fill_possible":true,
                    "execution":"block_batch", "max_price_change_bps":s.settings.max_price_change_bps
                }))
            }
            "quote" => {
                let amount = parse_amount(required_str(&params, "amount")?)?;
                ensure!(
                    params
                        .get("outcome")
                        .is_none_or(|value| value.is_null() || value.is_string()),
                    "outcome must be pass or fail"
                );
                let outcome = parse_outcome(&params)?;
                let s = i.chain.tip_state();
                ensure!(
                    s.decision_id().is_some() == outcome.is_some(),
                    "select PASS or FAIL during governance; omit outcome otherwise"
                );
                ensure!(outcome.is_none() || !trading_closed(s), TRADING_CLOSED);
                let w = match outcome {
                    Some(Outcome::Pass) => {
                        s.alternative.as_ref().context("no active PASS state")?
                    }
                    _ => &s.world,
                };
                let c = &i.chain.config;
                ensure!(
                    amount.bits() <= c.money_bits.max(c.share_bits),
                    "amount out of range"
                );
                let is_buy = match required_str(&params, "kind")? {
                    "deposit" => {
                        c.check_amount(&amount)?;
                        // Every deposit is debited from account cash, so a
                        // larger hypothetical order can never execute. Only a
                        // curved price search depends on the order's size.
                        ensure!(
                            curve_evaluation_work(w) == 0 || amount <= w.account_cash,
                            "deposit exceeds circulating account cash"
                        );
                        true
                    }
                    "redeem" => {
                        c.check_shares(&amount)?;
                        ensure!(
                            amount <= w.account_shares,
                            "shares exceed redeemable supply"
                        );
                        false
                    }
                    _ => bail!("kind must be deposit or redeem"),
                };
                ensure!(!amount.is_zero(), "amount must be positive");
                charge(
                    meter,
                    trade_work(w, is_buy, &amount, s.settings.max_price_change_bps),
                )?;
                let (filled, output, _) =
                    preview_trade(c, w, is_buy, &amount, s.settings.max_price_change_bps)?;
                Ok(json!({
                    "output":output.to_str_radix(10), "tip":hex::encode(i.chain.tip_hash()),
                    "amount":amount.to_str_radix(10), "input_requested":amount.to_str_radix(10),
                    "input_filled":filled.to_str_radix(10), "input_unfilled":(&amount-&filled).to_str_radix(10),
                    "kind":params.get("kind"), "outcome":params.get("outcome"),
                    "decision":s.decision_id().map(hex::encode), "transaction_fee_included":false,
                    "height":s.height, "state_root":hex::encode(i.state_root()),
                    "reserve":w.reserve.to_str_radix(10), "shares":w.shares.to_str_radix(10),
                    "indicative":true, "partial_fill_possible":true, "execution":"block_batch",
                    "max_price_change_bps":s.settings.max_price_change_bps
                }))
            }
            "snapshot" => {
                let keys = params
                    .get("keys")
                    .map(|keys| -> Result<HashSet<PublicKey>> {
                        let keys = keys.as_array().context("keys must be an array")?;
                        ensure!(keys.len() <= MAX_SNAPSHOT_KEYS, "too many snapshot keys");
                        keys.iter()
                            .map(|key| {
                                parse_account(
                                    key.as_str().context("snapshot keys must be strings")?,
                                    &chain_id,
                                )
                            })
                            .collect()
                    })
                    .transpose()?;
                let key = params.get("key").and_then(Value::as_str);
                if let Some(key) = key {
                    parse_account(key, &chain_id)?;
                }
                let account = |outcome: Option<&str>| -> Result<Value> {
                    let Some(key) = key else {
                        return Ok(Value::Null);
                    };
                    let public = parse_account(key, &chain_id)?;
                    let mut request = json!({"key":key});
                    if let Some(outcome) = outcome {
                        request["outcome"] = json!(outcome);
                    }
                    if i.chain
                        .tip_state()
                        .account(&public, parse_outcome(&request)?)
                        .is_none()
                    {
                        return Ok(Value::Null);
                    }
                    Self::read_rpc_metered(i, "account", request, meter)
                };
                let conditional = i.chain.tip_state().alternative.is_some();
                // Rest lists the round that just ended, never all history.
                let round = match &i.chain.tip_state().phase {
                    crate::state::Phase::Auction(auction) => Some(auction.round),
                    crate::state::Phase::Governance(decision) => Some(decision.round),
                    crate::state::Phase::Rest(_) => (!i.chain.tip_state().rounds.is_empty())
                        .then_some(i.chain.tip_state().last_round),
                };
                let ordinary = account(None)?;
                let fail = if conditional {
                    ordinary.clone()
                } else {
                    Value::Null
                };
                // A wallet summary: grants above SUMMARY_GRANT_PAYMENTS keep
                // their first payments with a count, so polling stays bounded
                // however large a grant is; `proposals` and `governance`
                // return complete records.
                let proposals = match round {
                    Some(round) => {
                        let ids = i.proposal_index().round(round);
                        proposal_page(i, &ids[..ids.len().min(128)], true, meter)?
                    }
                    None => json!([]),
                };
                charge(
                    meter,
                    decision_payments(i.chain.tip_state()).min(SUMMARY_GRANT_PAYMENTS),
                )?;
                let governance = i.governance_summary();
                charge(meter, mempool_work(&i.mempool, 0, 128, "summary"))?;
                let mut snapshot = json!({
                    "status":Self::status_locked(i),
                    "config":i.chain.config,
                    "governance":governance,
                    "proposals":proposals,
                    // The page holds the round's leader first, then the best
                    // supported; the total says whether more pages exist.
                    "proposals_total":round.map_or(0, |round| i.proposal_index().round_len(round)),
                    "mempool":mempool_page(&i.mempool,0,128,true)?,
                    "account":ordinary,
                    "pass":if conditional { account(Some("pass"))? } else { Value::Null },
                    "fail":fail
                });
                // This is a spending ceiling before fees, never a sum of the
                // two alternative futures. All fields share this published tip.
                snapshot["payment_available_hash"] =
                    snapshot["account"]["payment_available_hash"].clone();
                // The mempool page above is capped. Give the selected sender
                // its own pending rows, so a wallet still sees its transactions
                // when they sit past that page. Its next nonce over the whole
                // pool, as prepare_locked computes it, is `account.pending_nonce`.
                if let Some(key) = key {
                    let sender = parse_account(key, &chain_id)?;
                    let own: Vec<Transaction> = i
                        .mempool
                        .iter()
                        .filter(|tx| tx.body.sender == sender)
                        .cloned()
                        .collect();
                    // Charged like the global page above, before it is built.
                    charge(meter, mempool_work(&own, 0, 128, "summary"))?;
                    snapshot["sender_mempool"] = mempool_page(&own, 0, 128, true)?;
                }
                if let Some(keys) = keys {
                    let s = i.chain.tip_state();
                    // Only read holdings from the same immutable view. Unlike
                    // account RPC, this never values each wallet on the curve.
                    let balance = |key: &PublicKey, outcome| {
                        s.account(key, outcome).map_or(Value::Null, |account| {
                            json!({
                                "ordinary":account.ordinary.to_str_radix(10),
                                "shares":account.shares.to_str_radix(10)
                            })
                        })
                    };
                    snapshot["balances"] = Value::Object(
                        keys.into_iter()
                            .map(|key| {
                                let ordinary = balance(&key, None);
                                let fail = if conditional { ordinary.clone() } else { Value::Null };
                                (
                                    hex::encode(key),
                                    json!({
                                        "account":ordinary,
                                        "pass":if conditional { balance(&key, Some(Outcome::Pass)) } else { Value::Null },
                                        "fail":fail
                                    }),
                                )
                            })
                            .collect(),
                    );
                }
                Ok(snapshot)
            }
            "grant_quote" => {
                let amount = parse_amount(required_str(&params, "amount")?)?;
                i.chain.config.check_amount(&amount)?;
                let s = i.chain.tip_state();
                let capacity = crate::consensus::grant_capacity(&s.world);
                let funded = amount.clone().min(capacity.clone());
                Ok(
                    json!({"funded":funded.to_str_radix(10),"capacity":capacity.to_str_radix(10),"feasible":funded==amount,"tip":hex::encode(i.chain.tip_hash())}),
                )
            }
            _ => bail!("unknown read method"),
        }
    }
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        self.rpc_with_admission(method, params, None)
    }
    /// `broadcasttransaction`: admit one signed transaction. A public one is
    /// charged to the admission budget reserved for public broadcasts.
    fn broadcast(&self, params: Value, public: bool) -> Result<Value> {
        let request: BroadcastRequest = serde_json::from_value(params)?;
        let tx = wallet::decode_signed(&request.raw, &self.read_view()?.chain.chain_id())?;
        let id = self.submit_transaction_from(tx, public)?;
        Ok(json!({"transaction_id":hex::encode(id)}))
    }
    fn public_rpc(&self, method: &str, params: Value, admission: &Session) -> Result<Value> {
        ensure!(
            public_rpc_allowed(method),
            "method is unavailable on public web"
        );
        let mut result = if method == "broadcasttransaction" {
            self.broadcast(params, true)
        } else {
            self.rpc_with_admission(method, params, Some(admission))
        }
        .map_err(public_error)?;
        // The public mining panel shows workers and the advertised endpoint;
        // the Stratum bind interface stays private to the operator, including
        // inside a connect URL derived from it without --stratum-advertise.
        let mining = match method {
            "mining" => Some(&mut result),
            "snapshot" => result.get_mut("mining"),
            _ => None,
        };
        if let Some(stratum) = mining
            .and_then(|mining| mining.get_mut("stratum"))
            .and_then(Value::as_object_mut)
        {
            stratum.remove("bind_address");
            stratum.remove("loopback_only");
            let advertised = self.mining.unpoisoned().advertised;
            if !advertised {
                stratum.insert("connect_url".into(), Value::Null);
            }
        }
        Ok(result)
    }
    fn rpc_with_admission(
        &self,
        method: &str,
        params: Value,
        admission: Option<&Session>,
    ) -> Result<Value> {
        if crate::explorer::METHODS.contains(&method) {
            let view = self.read_view()?;
            charge(
                admission,
                explorer_state_work(method, view.chain.tip_state()),
            )?;
            return Explorer::read(
                &self.explorer_path,
                method,
                params,
                &view.chain.config,
                view.chain.tip_state(),
                view.chain.tip_hash(),
                view.state_root(),
                &view.mempool,
            );
        }
        match method {
            "mining" => self.mining_status(),
            "preparetransaction" => {
                let request: PrepareRequest = serde_json::from_value(params)?;
                // Public preparation reads one published view, never the node lock.
                let i = self.read_view()?;
                let sender = parse_account(&request.sender, &i.chain.chain_id())?;
                let body = Self::prepare_view(
                    &i,
                    sender,
                    WalletRequest {
                        operation: request.operation,
                        fee: request.fee,
                        extra_fee: request.extra_fee,
                        data_hex: request.data_hex,
                        expiry_blocks: request.expiry_blocks,
                        anchor: request.anchor,
                        nonce: request.nonce,
                    },
                )?;
                let mut result =
                    serde_json::to_value(wallet::unsigned(&body, &i.chain.chain_id()))?;

                result["fee_quote"] = fee_quote_json(
                    &i.chain.config,
                    i.chain.tip_state(),
                    i.chain.tip_hash(),
                    i.state_root(),
                    &body,
                )?;

                Ok(result)
            }
            "fee_quote" | "transfer_quote" => {
                // Omitted parameters are no fields. Any other non-object is
                // refused: indexing a JSON array or scalar by name panics.
                let params = if params.is_null() { json!({}) } else { params };
                ensure!(params.is_object(), "expected quote fields");
                // Every quote names its sender, on either listener. The
                // private one needs no session token, so a default read from
                // the selected server wallet would tell any local process the
                // operator's account and balance, which `/api/session` keeps
                // behind the token.
                required_str(&params, "sender")?;
                let i = self.read_view()?;
                Self::read_rpc_metered(&i, method, params, admission)
            }
            "broadcasttransaction" => self.broadcast(params, false),
            "getblock" => {
                let format = params.get("format").map_or(Some("json"), Value::as_str);
                ensure!(
                    matches!(format, Some("json" | "hex")),
                    "format must be \"json\" or \"hex\""
                );
                let block = {
                    let i = self.locked()?;
                    let h = if let Some(h) = params.get("hash").and_then(Value::as_str) {
                        parse_hash(h)?
                    } else if let Some(height) = params.get("height").and_then(Value::as_u64) {
                        i.chain
                            .hash_at_height(height)
                            .context("unknown active height")?
                    } else {
                        i.chain.tip_hash()
                    };
                    i.chain.block(&h).context("unknown block")?
                };
                // Replies are built after the node lock is released.
                let (hash, height) = (codec::block_hash(&block), block.height);
                if format == Some("hex") {
                    // The canonical record: two characters per byte, which
                    // the response frame admits for every valid block. One
                    // work unit per KiB of hexadecimal output.
                    let raw = codec::encode(&block);
                    drop(block);
                    charge(admission, raw.len() / 512)?;
                    return Ok(
                        json!({"hash":hex::encode(hash),"height":height,"raw":hex::encode(raw)}),
                    );
                }
                // The JSON form holds one generic value per byte, tens of
                // bytes of memory each, so it is built only within the JSON
                // page budgets and paid for per value before the tree exists.
                let (text, values) = JsonPage::new().encode(&block).map_err(|_| {
                    anyhow!("block is too large for a JSON reply; request format \"hex\"")
                })?;
                drop(block);
                charge(admission, values / RESPONSE_VALUES_PER_WORK)?;
                Ok(serde_json::from_slice(&text)?)
            }
            "blockreceipt" => {
                // A bounded receipt lookup: one canonical hash and the presence of
                // a few transaction IDs, never a JSON copy of an arbitrarily large block.
                let height = params
                    .get("height")
                    .and_then(Value::as_u64)
                    .context("height required")?;
                let ids = match params.get("txids") {
                    Some(ids) => {
                        let ids = ids.as_array().context("txids must be an array")?;
                        ensure!(ids.len() <= MAX_RECEIPT_TXIDS, "too many transaction IDs");
                        ids.iter()
                            .map(|id| parse_hash(id.as_str().context("txids must be strings")?))
                            .collect::<Result<Vec<_>>>()?
                    }
                    None => Vec::new(),
                };
                // An optional earlier lookup to confirm in the same read, so a
                // caller's inspected blocks are known to share one canonical chain.
                let checked = match params.get("checked") {
                    Some(checked) => {
                        let at = checked
                            .get("height")
                            .and_then(Value::as_u64)
                            .context("checked height required")?;
                        let hash = checked
                            .get("hash")
                            .and_then(Value::as_str)
                            .context("checked hash required")?;
                        Some((at, parse_hash(hash)?))
                    }
                    None => None,
                };
                let (hash, block, checked_canonical) = {
                    let i = self.locked()?;
                    let h = i
                        .chain
                        .hash_at_height(height)
                        .context("unknown active height")?;
                    let checked_canonical =
                        checked.map(|(at, hash)| i.chain.hash_at_height(at) == Some(hash));
                    // Without IDs the canonical index answers; no body is loaded.
                    let block = if ids.is_empty() {
                        None
                    } else {
                        Some(i.chain.block(&h).context("unknown block")?)
                    };
                    (h, block, checked_canonical)
                };
                let mut included = vec![false; ids.len()];
                for transaction in block.iter().flat_map(|block| &block.transactions) {
                    if included.iter().all(|found| *found) {
                        break;
                    }
                    let id = codec::transaction_id(transaction);
                    for (found, wanted) in included.iter_mut().zip(&ids) {
                        *found |= *wanted == id;
                    }
                }
                let mut result =
                    json!({"height":height,"hash":hex::encode(hash),"included":included});
                if let Some(canonical) = checked_canonical {
                    result["checked_canonical"] = json!(canonical);
                }
                Ok(result)
            }
            "peers" => Ok(json!(*self.peer_events.unpoisoned())),
            "peerstatus" => self.peer_status(),

            "submittransaction" => {
                let tx: Transaction =
                    serde_json::from_value(params.get("transaction").cloned().unwrap_or(params))?;
                Ok(json!({"txid":hex::encode(self.submit_transaction(tx)?)}))
            }
            "submitblock" => {
                // Also the canonical record, as `getblock` returns it in hex.
                let b: Block = match params.get("raw") {
                    Some(raw) => {
                        let raw = hex::decode(raw.as_str().context("raw must be a string")?)
                            .context("raw must be hexadecimal")?;
                        let block = codec::decode_block(&raw, raw.len())?;
                        // The JSON form's method price counts its transactions.
                        charge(admission, block.transactions.len())?;
                        block
                    }
                    None => serde_json::from_value(params.get("block").cloned().unwrap_or(params))?,
                };
                let hash = codec::block_hash(&b);
                Ok(json!({"hash":hex::encode(hash),"selected":self.submit_block(b)?}))
            }
            "mine" => {
                // Any local process can reach the private listener. On a real
                // network, or one untrusted peers reach, this would let it
                // burn the node's CPU and pick the payout; only an explicit
                // operator flag allows that.
                let config = self.read_view()?.chain.config.clone();
                ensure!(
                    self.dev_rpc || development_network(&config, self.untrusted_peers),
                    "mine is a development method, and {}; start the node with --dev-rpc to allow it",
                    if easy_proof_of_work(&config) {
                        "untrusted peers can reach this node"
                    } else {
                        "this network's proof of work is not a development target"
                    }
                );
                let recipient = params
                    .get("recipient")
                    .map(|v| {
                        parse_account(
                            v.as_str().context(
                                "recipient must be an address or hexadecimal public key",
                            )?,
                            &self.read_view()?.chain.chain_id(),
                        )
                    })
                    .transpose()?
                    .unwrap_or(self.miner);
                let count = params.get("count").and_then(Value::as_u64).unwrap_or(1);
                ensure!((1..=1000).contains(&count), "count must be 1..1000");
                let attempts = params
                    .get("attempts")
                    .and_then(Value::as_u64)
                    .unwrap_or(1_000_000);
                ensure!(
                    (1..=100_000_000).contains(&attempts),
                    "attempts must be 1..100000000"
                );
                let mut hashes = Vec::new();
                for _ in 0..count {
                    if let Some(admission) = admission {
                        // Recheck each block's current queue. Charging an entire
                        // batch as 4096-transaction blocks rejects even empty
                        // batches beyond the admission bucket's capacity. The
                        // attempts are charged too: one unit per 4,096 hashes.
                        let work = pool_change_work(self.read_view()?.mempool.len())
                            .saturating_add(attempts.div_ceil(MINE_ATTEMPTS_PER_WORK) as usize);
                        if let Err(error) = admission.work(work) {
                            // Only a batch refused before its first block is a
                            // refusal a client may simply resend.
                            if hashes.is_empty() {
                                return Err(error);
                            }
                            bail!("mined {} of {count} blocks, then {error}", hashes.len());
                        }
                    }
                    hashes.push(hex::encode(codec::block_hash(
                        &self.mine_to(attempts, recipient)?,
                    )));
                }
                Ok(json!({"blocks":hashes}))
            }
            _ => {
                let i = self.read_view()?;
                let mut result = Self::read_rpc_metered(&i, method, params, admission)?;
                if method == "snapshot" {
                    result["mining"] = self.mining_status()?;
                }
                Ok(result)
            }
        }
    }
    fn mining_status(&self) -> Result<Value> {
        let view = self.read_view()?;
        let chain_id = view.chain.chain_id();
        let mut result = self.mining.unpoisoned().value(&self.miner, &chain_id)?;
        result["target_block_seconds"] = json!(view.chain.tip_state().settings.interval);
        result["daa_half_life_seconds"] = json!(view.chain.config.daa_half_life);
        result["minimum_work"] = json!(
            math::work(&math::target_from_bits(view.chain.config.limit_bits)?).to_str_radix(10)
        );
        Ok(result)
    }
}
/// Public callers get no local storage detail such as a database path; the
/// operator's log keeps the full error. Request validation errors pass through.
fn public_error(error: anyhow::Error) -> anyhow::Error {
    if error
        .chain()
        .any(|cause| cause.is::<rusqlite::Error>() || cause.is::<std::io::Error>())
    {
        eprintln!("Public RPC storage error: {error:#}");
        anyhow!("node storage is temporarily unavailable")
    } else {
        error
    }
}
/// Explorer work that grows with the live state, beyond the flat method price.
/// Every governance page projects the live phase, including the decision's
/// inline grant, so it is charged per payment as the governance RPC is.
fn explorer_state_work(method: &str, s: &State) -> usize {
    match &s.phase {
        crate::state::Phase::Governance(d) if method == "explorer_governance" => {
            grant_payments(&d.proposal)
        }
        _ => 0,
    }
}
/// Admission work for one curve valuation. A flat curve has exact closed forms.
fn curve_evaluation_work(w: &crate::state::World) -> usize {
    if w.shares.is_zero() || w.reserve == w.curve_mass {
        0
    } else {
        CURVE_EVALUATION_WORK
    }
}

/// Pre-charged admission work for one single-order clearing estimate. An order
/// that cannot move the curve price by half the per-block limit clears with a
/// price evaluation or two; a larger one may search its executable budget with
/// about one evaluation per input bit. Purchases move the price by at most the
/// reserve growth; sales by at most the sold supply scaled by mass/reserve.
fn trade_work(w: &crate::state::World, is_buy: bool, input: &Amount, bps: u64) -> usize {
    let evaluation = curve_evaluation_work(w);
    if evaluation == 0 {
        return 0;
    }
    let small = if is_buy {
        input * 20_000u32 <= &w.reserve * bps
    } else {
        input * &w.curve_mass * 20_000u32 <= &w.shares * &w.reserve * bps
    };
    let evaluations = if small {
        2
    } else {
        2 + usize::try_from(input.bits()).unwrap_or(usize::MAX)
    };
    evaluations.saturating_mul(evaluation)
}

/// A one-order estimate. Actual fills depend on the full set of included orders.
fn preview_trade(
    c: &Config,
    w: &crate::state::World,
    is_buy: bool,
    input: &Amount,
    cap: u64,
) -> Result<(Amount, Amount, crate::state::World)> {
    let orders = [crate::batch::Order {
        id: [0; 32],
        amount: input.clone(),
    }];
    let result = if is_buy {
        crate::batch::clear(c, w, &orders, &[], cap)?
    } else {
        crate::batch::clear(c, w, &[], &orders, cap)?
    };
    let fill = if is_buy {
        result.buys.first()
    } else {
        result.sells.first()
    }
    .context("missing trade estimate")?;
    let filled = fill.input.clone();
    let output = fill.output.clone();
    let mut after = w.clone();
    after.reserve = result.reserve;
    after.shares = result.shares;
    after.curve_mass = result.curve_mass;
    Ok((filled, output, after))
}

/// Full-holding curve valuation before fees, without the per-block price limit.
/// This is not an executable single-block withdrawal estimate; use preview_trade.
fn stash_withdrawal(w: &crate::state::World, shares: &Amount) -> Result<Amount> {
    Ok(if shares.is_zero() || w.shares.is_zero() {
        Amount::zero()
    } else {
        &w.reserve - math::dynamic_remaining_reserve(&w.reserve, &w.shares, shares, &w.curve_mass)?
    })
}
fn required_str<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v.get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {name}"))
}
fn parse_amount(s: &str) -> Result<Amount> {
    ensure!(
        !s.is_empty()
            && s.len() <= 20_000
            && (s.len() == 1 || !s.starts_with('0'))
            && s.bytes().all(|c| c.is_ascii_digit()),
        "invalid decimal amount"
    );
    Amount::parse_bytes(s.as_bytes(), 10).context("invalid amount")
}
fn parse_outcome(v: &Value) -> Result<Option<Outcome>> {
    match v.get("outcome").and_then(Value::as_str) {
        None => Ok(None),
        Some("Pass" | "pass") => Ok(Some(Outcome::Pass)),
        Some("Fail" | "fail") => Ok(Some(Outcome::Fail)),
        _ => bail!("outcome must be pass or fail"),
    }
}
const TRADING_CLOSED: &str = "conditional trading is closed: the decision resolves at the start of the next block, before its transactions";
/// The child of this tip resolves its decision in prepare_block before any of
/// its transactions (the same `height - started_height == blocks` test), so no
/// conditional Deposit or Redeem prepared at this tip can ever be included.
fn trading_closed(s: &State) -> bool {
    let crate::state::Phase::Governance(d) = &s.phase else {
        return false;
    };
    s.height
        .checked_add(1)
        .and_then(|next| next.checked_sub(d.started_height))
        == Some(d.blocks)
}
fn conditional(operation: &Operation) -> bool {
    matches!(
        operation,
        Operation::Deposit {
            decision: Some(_),
            ..
        } | Operation::Redeem {
            decision: Some(_),
            ..
        }
    )
}

fn check_operation_bounds(config: &Config, operation: &Operation) -> Result<()> {
    if let Operation::Deposit {
        decision, outcome, ..
    }
    | Operation::Redeem {
        decision, outcome, ..
    } = operation
    {
        ensure!(
            decision.is_some() == outcome.is_some(),
            "decision and outcome must appear together"
        );
    }
    match operation {
        Operation::TransferExact { recipient, amount } => {
            ensure!(crypto::valid_key(recipient), "invalid recipient key");
            ensure!(!amount.is_zero(), "zero transfer");
            config.check_amount(amount)?;
        }
        Operation::Deposit { amount, .. } => {
            config.check_amount(amount)?;
            ensure!(!amount.is_zero(), "zero deposit");
        }
        Operation::Redeem { shares, .. } => {
            config.check_shares(shares)?;
            ensure!(!shares.is_zero(), "zero redemption");
        }

        Operation::Support { amount, .. } => config.check_amount(amount)?,
        Operation::Propose {
            proposal, support, ..
        } => {
            config.check_amount(support)?;
            if let Proposal::Grant { payments } = proposal {
                config.validate_grant(payments)?;
            }
        }
        Operation::Refund { .. } => {}
    }
    Ok(())
}

/// Reads a line without ever allocating beyond the configured bound.
async fn bounded_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    bounded_line_buf(r, max, &mut out).await
}
async fn bounded_line_buf<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
    out: &mut Vec<u8>,
) -> Result<Vec<u8>> {
    loop {
        let buf = r.fill_buf().await?;
        if buf.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            )
            .into());
        }
        let end = buf.iter().position(|c| *c == b'\n').map(|p| p + 1);
        let take = end.unwrap_or(buf.len());
        ensure!(take <= max.saturating_sub(out.len()), "frame too large");
        out.extend_from_slice(&buf[..take]);
        r.consume(take);
        if end.is_some() {
            return Ok(std::mem::take(out));
        }
    }
}
async fn write_json<W: AsyncWrite + Unpin>(w: &mut W, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() < MAX_FRAME, "outgoing frame too large");
    bytes.push(b'\n');
    timeout(IO_TIMEOUT, w.write_all(&bytes)).await??;
    Ok(())
}
/// One per peer connection. A signed session can never revert to unsigned
/// frames: if its channel is lost, every later read or write fails closed.
enum PeerTransport {
    Plain,
    Signed(PeerChannel),
    Failed,
}
/// The expected message and read allowance for one peer frame.
#[derive(Clone, Copy, PartialEq)]
enum PeerRead {
    /// A connection's first message: a locator, address or header request.
    /// After a header reply, the next header request or locator request.
    Request,
    Sync,
    Ack,
    Addresses,
    Headers,
}
/// A write allows the ordinary deadline plus one second per whole MiB sent.
fn peer_write_timeout(bytes: usize) -> Duration {
    IO_TIMEOUT + Duration::from_secs(bytes as u64 / (1024 * 1024))
}
async fn write_peer<W: AsyncWrite + Unpin>(
    node: &Node,
    write: &mut W,
    message: PeerPacket,
    admission: &Session,
    transport: &mut PeerTransport,
) -> Result<()> {
    let work = match &message {
        // A synchronization message paid for each block and loose
        // transaction as it was built (`peer_snapshot_charged`), and a header
        // reply for each header, one work unit as a block without a body,
        // before any was read (`headers_reply_async`). Here each pays one unit.
        PeerPacket::Sync(_) | PeerPacket::Headers { .. } => 1,
        PeerPacket::Ack => 1,
        PeerPacket::GetAddresses { .. } | PeerPacket::GetHeaders { .. } => 1,
        PeerPacket::Addresses { addresses, .. } => addresses.len().max(1),
    };
    // This node chose the reply. Its budget bounds amplification, but an
    // exhausted budget never penalizes the recipient's address.
    admission.outgoing(0, work.max(1))?;
    let limits = node.peer_limits()?;
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let mut mode = std::mem::replace(transport, PeerTransport::Failed);
    let (bytes, mode) = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let bytes = peer_wire::encode(&message, limits).and_then(|payload| match &mut mode {
            PeerTransport::Signed(channel) => channel.seal(payload),
            PeerTransport::Plain => peer_wire::frame(&payload, limits.frame_bytes()),
            PeerTransport::Failed => Err(anyhow!("peer transport failed closed")),
        });
        // The channel returns on every path, including encoding errors.
        (bytes, mode)
    })
    .await
    .context("peer serialization worker failed")?;
    *transport = mode;
    let bytes = bytes?;
    admission.outgoing(bytes.len(), 0)?;
    timeout(peer_write_timeout(bytes.len()), write.write_all(&bytes)).await??;
    Ok(())
}
enum JsonBody {
    Ordinary,
    Rpc,
    HotWallet,
}

async fn parse_value_async(
    node: &Node,
    bytes: Vec<u8>,
    surface: Surface,
    body_kind: JsonBody,
) -> Result<Value> {
    let slots = match surface {
        Surface::Rpc => node.rpc_parsers.clone(),
        Surface::Peer => node.peer_parsers.clone(),
        Surface::Stratum => node.stratum_parsers.clone(),
    };
    parse_value_with_slots(bytes, body_kind, slots).await
}
async fn parse_value_with_slots(
    bytes: Vec<u8>,
    body_kind: JsonBody,
    slots: Arc<Semaphore>,
) -> Result<Value> {
    // Waiting for a local parser is never the client's fault.
    let permit = timeout(IO_TIMEOUT, slots.acquire_owned())
        .await
        .map_err(|_| network_guard::Busy("JSON parser workers busy"))??;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match body_kind {
            JsonBody::HotWallet => network_guard::parse_wallet_json(&bytes, bytes.len()),
            JsonBody::Rpc => network_guard::parse_rpc_json(&bytes, bytes.len()),
            JsonBody::Ordinary => network_guard::parse_json(&bytes),
        }
    })
    .await
    .context("JSON worker failed")?
}
/// Read and decode one peer frame. The read allowance, or an earlier
/// `deadline`, applies only while waiting for the peer's bytes; exceeding it
/// is the peer's fault. Waits for local workers afterwards never penalize it.
async fn read_peer_packet<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    transport: &mut PeerTransport,
    kind: PeerRead,
    deadline: Option<tokio::time::Instant>,
) -> Result<PeerPacket> {
    read_peer_packet_within(r, node, admission, transport, kind, deadline, None).await
}
/// The peer closed the connection between two messages, with no frame
/// begun: the exchange ends, but nothing it sent was malformed, so this
/// starts no cooldown. A peer whose own processing failed, or that gave up
/// waiting, closes this way.
#[derive(Debug)]
pub struct PeerClosed;
impl std::fmt::Display for PeerClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("peer closed the connection between messages")
    }
}
impl std::error::Error for PeerClosed {}
/// As `read_peer_packet`, reading a reply to a request that declared the
/// block capacity allowance `declared`: the reply is decoded within that
/// allowance even if this node's own has fallen since.
async fn read_peer_packet_within<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    transport: &mut PeerTransport,
    kind: PeerRead,
    deadline: Option<tokio::time::Instant>,
    declared: Option<u64>,
) -> Result<PeerPacket> {
    admission.request()?;
    let limits = node.peer_limits_at_least(declared)?;
    // A first message carries no blocks, so it never needs a block allowance.
    let maximum = match kind {
        PeerRead::Request => limits.locator_request_bytes(),
        PeerRead::Sync => limits.frame_bytes(),
        PeerRead::Ack => peer_wire::ACK_BYTES,
        PeerRead::Addresses => peer_wire::DISCOVERY_BYTES,
        PeerRead::Headers => peer_wire::HEADERS_BYTES,
    };
    let exchange_timeout = if kind == PeerRead::Addresses {
        IO_TIMEOUT
    } else {
        node.peer_exchange_timeout()?
    };
    let mut read_by = tokio::time::Instant::now() + exchange_timeout;
    if let Some(deadline) = deadline {
        read_by = read_by.min(deadline);
    }
    match closed_before_reply(r, read_by).await {
        Ok(false) => {}
        Ok(true) => return Err(PeerClosed.into()),
        Err(error) => {
            admission.malformed();
            return Err(error);
        }
    }
    let result = match transport {
        PeerTransport::Signed(channel) => {
            let receive = tokio::time::timeout_at(read_by, channel.receive(r, maximum, admission));
            match keep_frame_progress(admission, receive).await {
                Ok(frame) => {
                    channel
                        .open(frame, admission, node.peer_parsers.clone())
                        .await
                }
                Err(error) => Err(error),
            }
        }
        PeerTransport::Plain => {
            let read = tokio::time::timeout_at(read_by, read_peer_frame(r, maximum, admission));
            keep_frame_progress(admission, read).await
        }
        PeerTransport::Failed => Err(anyhow!("peer transport failed closed")),
    };
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(error) => {
            // Local memory pressure from other sessions is not this peer's
            // fault, and a budget refusal already penalized it once.
            if !error.is::<network_guard::Busy>() && !error.is::<network_guard::Limited>() {
                admission.malformed();
            }
            return Err(error);
        }
    };
    let permit = timeout(IO_TIMEOUT, node.peer_parsers.clone().acquire_owned()).await??;
    // The decoded message is built beside the frame's bytes, which stay
    // reserved until it has been processed.
    let decoding = admission.decoding(bytes.len());
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _decoding = decoding;
        let packet = peer_wire::decode(&bytes, limits);
        drop(bytes);
        packet
    })
    .await
    .context("peer decoding worker failed")?;
    match result {
        Ok(packet) => {
            let expected = matches!(
                (kind, &packet),
                (
                    PeerRead::Request,
                    PeerPacket::Sync(_)
                        | PeerPacket::GetAddresses { .. }
                        | PeerPacket::GetHeaders { .. }
                ) | (PeerRead::Sync, PeerPacket::Sync(_))
                    | (PeerRead::Ack, PeerPacket::Ack)
                    | (PeerRead::Addresses, PeerPacket::Addresses { .. })
                    | (PeerRead::Headers, PeerPacket::Headers { .. })
            );
            ensure!(expected, "unexpected peer message type");
            if kind == PeerRead::Request
                && matches!(&packet, PeerPacket::Sync(hello) if !hello.blocks.is_empty())
            {
                admission.malformed();
                bail!("first peer message must be a locator request");
            }
            let work = match &packet {
                PeerPacket::Sync(message) => {
                    let incoming = message.transactions.len()
                        + message
                            .blocks
                            .iter()
                            .map(|b| b.transactions.len() + 1)
                            .sum::<usize>();
                    let existing = if message.transactions.is_empty() {
                        0
                    } else {
                        node.read_view()?.mempool.len()
                    };
                    incoming.saturating_add(existing)
                }
                PeerPacket::Ack => 1,
                PeerPacket::GetAddresses { .. } | PeerPacket::GetHeaders { .. } => 1,
                PeerPacket::Addresses { addresses, .. } => addresses.len().max(1),
                PeerPacket::Headers { headers, .. } => headers.len().max(1),
            };
            admission.work(work.max(1))?;
            Ok(packet)
        }
        Err(error) => {
            admission.malformed();
            Err(error)
        }
    }
}
/// Await one frame's bytes from the peer. A frame that started in this read
/// and holds more than `FRAME_PROGRESS_HOLD` of shared frame memory must
/// receive `FRAME_PROGRESS_BYTES` more in every `FRAME_PROGRESS_WINDOW`;
/// otherwise the read ends as `Busy`, which releases the memory with the
/// session and starts no cooldown. Configured and pinned peers, and
/// connections this node opened, are exempt. A complete frame holds its
/// memory only until its message has been processed (`frame_processed`).
async fn keep_frame_progress<T>(
    admission: &Session,
    read: impl std::future::Future<Output = Result<Result<T>, tokio::time::error::Elapsed>>,
) -> Result<T> {
    let Some((started, _)) = admission.frame_progress() else {
        return read.await.map_err(anyhow::Error::from).and_then(|v| v);
    };
    let stalled = async {
        let mut previous = None;
        loop {
            tokio::time::sleep(network_guard::FRAME_PROGRESS_WINDOW).await;
            let Some((frame, held)) = admission.frame_progress() else {
                continue;
            };
            if frame == started {
                continue;
            }
            if let Some((seen, before)) = previous
                && seen == frame
                && held > network_guard::FRAME_PROGRESS_HOLD
                && held < before + network_guard::FRAME_PROGRESS_BYTES
            {
                return network_guard::Busy("peer frame stalled while holding shared frame memory");
            }
            previous = Some((frame, held));
        }
    };
    tokio::select! {
        result = read => result.map_err(anyhow::Error::from).and_then(|v| v),
        stalled = stalled => Err(stalled.into()),
    }
}
async fn read_peer<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    transport: &mut PeerTransport,
) -> Result<PeerMessage> {
    match read_peer_packet(r, node, admission, transport, PeerRead::Sync, None).await? {
        PeerPacket::Sync(message) => Ok(message),
        _ => bail!("unexpected message during synchronization"),
    }
}
async fn read_peer_frame<R: AsyncBufRead + Unpin>(
    r: &mut R,
    maximum: usize,
    admission: &Session,
) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    admission.bytes(header.len())?;
    admission.begin_frame()?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length >= peer_wire::ACK_BYTES && length <= maximum,
        "peer frame too large or truncated"
    );
    // Frame memory is reserved as bytes arrive, never for a declared length.
    let mut out = Vec::with_capacity(length.min(8192));
    let mut chunk = [0u8; 8192];
    while out.len() < length {
        let take = chunk.len().min(length - out.len());
        admission.reserve_frame(take)?;
        r.read_exact(&mut chunk[..take]).await?;
        admission.bytes(take)?;
        out.extend_from_slice(&chunk[..take]);
    }
    Ok(out)
}

/// The private listener's session token lives in this file next to the node
/// database, rewritten at every server start. Loopback TCP is shared by every
/// local account and service, so only clients able to read the node's own
/// files can use server-wallet endpoints.
pub fn session_token_path(database: &Path) -> PathBuf {
    crate::local_files::sidecar(database, "session-token")
}
fn write_session_token(path: &Path, token: &str) -> Result<()> {
    // Never write through an existing file or link; create a fresh one that
    // only the node's account can read.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("session token file cannot be replaced"),
    }
    crate::local_files::write_private(path, token.as_bytes())
        .context("session token file cannot be created")
}

#[derive(Clone)]
pub struct ServerOptions {
    pub rpc: SocketAddr,
    /// Separate restricted website/RPC listener; never exposes server wallets.
    pub public_web: Option<SocketAddr>,
    pub p2p: SocketAddr,
    pub stratum: SocketAddr,
    /// Bind the solo-mining listener. Disabling it does not disable block validation or relay.
    pub stratum_enabled: bool,
    pub peers: Vec<SocketAddr>,
    pub stratum_password: Option<String>,
    pub stratum_share_difficulty: f64,
    pub stratum_advertise: Option<String>,
    /// Prefixes whose Stratum sources always count as recently authorized,
    /// so the operator's miners keep reserved pre-authorization slots.
    pub stratum_trusted: Vec<TrustedPrefix>,
}
impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            rpc: "127.0.0.1:18480".parse().unwrap(),
            public_web: None,
            p2p: "127.0.0.1:18481".parse().unwrap(),
            stratum: "127.0.0.1:18482".parse().unwrap(),
            stratum_enabled: true,
            peers: Vec::new(),
            stratum_password: None,
            stratum_share_difficulty: DEFAULT_STRATUM_SHARE_DIFFICULTY,
            stratum_advertise: None,
            stratum_trusted: Vec::new(),
        }
    }
}
pub struct Server {
    pub rpc: SocketAddr,
    pub public_web: Option<SocketAddr>,
    pub p2p: SocketAddr,
    pub stratum: SocketAddr,
    pub stratum_enabled: bool,
    /// Owner-only file with this run's private session token.
    pub session_token_file: PathBuf,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    mining: Arc<Mutex<MiningRuntime>>,
    _lease: ServerLease,
}
struct ServerLease(Arc<AtomicBool>);
impl Drop for ServerLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
impl Server {
    pub async fn stop(mut self) {
        let _ = self.stop.send(true);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        for task in &self.tasks {
            task.abort();
        }
        let mut mining = self.mining.unpoisoned();
        mining.enabled = false;
        mining.workers.clear();
    }
}

pub async fn serve(mut node: Node, options: ServerOptions) -> Result<Server> {
    ensure!(
        node.server_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok(),
        "this node already has a server"
    );
    let lease = ServerLease(node.server_active.clone());
    validate_stratum_difficulty(options.stratum_share_difficulty)?;
    // Without a password anyone reaching the listener could authorize and hold
    // every worker slot indefinitely; only a loopback listener may run open.
    ensure!(
        !options.stratum_enabled
            || options.stratum.ip().is_loopback()
            || options
                .stratum_password
                .as_deref()
                .is_some_and(|p| !p.is_empty()),
        "a non-loopback Stratum listener requires a password"
    );
    let advertised = options
        .stratum_advertise
        .as_deref()
        .map(stratum_connect_url)
        .transpose()?;
    ensure!(
        options.rpc.ip().is_loopback(),
        "RPC requires a loopback address"
    );
    ensure!(
        options.peers.len() <= MAX_CONNECTIONS,
        "too many configured peers"
    );
    if let Some(policy) = &node.peer_auth {
        policy.validate_peers(&options.peers)?;
    }
    node.discovery_options.validate()?;
    ensure!(
        !node.discovery_options.enabled
            || node.peer_auth.as_ref().is_some_and(|p| p.is_discovery()),
        "peer discovery requires explicit open authenticated transport"
    );
    // Set before this server's clones of the node: RPC mining treats a node
    // that untrusted peers can reach as a real network.
    node.untrusted_peers = node.discovery_options.enabled || !options.p2p.ip().is_loopback();
    {
        let mut health = node.peer_health.unpoisoned();
        for peer in &options.peers {
            health.entry(*peer).or_insert_with(|| PeerHealth {
                configured_at: now(),
                ..Default::default()
            });
        }
    }
    // Configured and pinned peer addresses keep reserved inbound capacity.
    let protected = Arc::new(protected_peers(
        &options.peers,
        node.peer_auth.iter().flat_map(|p| p.pinned_ips()),
    ));
    // Addresses whose miners authorized before a restart, and prefixes the
    // operator trusts, keep reserved Stratum slots from the first connection.
    node.stratum_pending.allow(&options.stratum_trusted);
    if options.stratum_enabled {
        let (pending, path) = (
            node.stratum_pending.clone(),
            node.stratum_trusted_path.clone(),
        );
        let loaded = tokio::task::spawn_blocking(move || pending.load_trusted(&path))
            .await
            .context("Stratum trusted address reader failed")?;
        if let Err(error) = loaded {
            eprintln!("Saved Stratum trusted addresses ignored: {error:#}");
        }
    }
    let rpc = TcpListener::bind(options.rpc).await?;
    let p2p = TcpListener::bind(options.p2p).await?;
    let stratum = if options.stratum_enabled {
        Some(TcpListener::bind(options.stratum).await?)
    } else {
        None
    };
    let addresses = (
        rpc.local_addr()?,
        p2p.local_addr()?,
        stratum
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()?
            .unwrap_or(options.stratum),
    );
    if node.discovery_options.enabled {
        let book = AddressBook::open(
            node.discovery_path.clone(),
            node.read_view()?.chain.chain_id(),
            node.discovery_options.clone(),
            addresses.1,
            &options.peers,
            now(),
        )?;
        *node.discovery.unpoisoned() = Some(book);
    }
    let public_web = match options.public_web {
        Some(address) => Some(TcpListener::bind(address).await?),
        None => None,
    };
    let public_web_address = public_web
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()?;
    let mut random_token = [0u8; 32];
    getrandom::fill(&mut random_token)
        .map_err(|e| anyhow!("session randomness unavailable: {e}"))?;
    let session_token = hex::encode(random_token);
    write_session_token(&node.session_token_path, &session_token)?;
    {
        let mut mining = node.mining.unpoisoned();
        ensure!(!mining.enabled, "this node already has a mining listener");
        *mining = MiningRuntime {
            enabled: options.stratum_enabled,
            bind_address: options.stratum_enabled.then_some(addresses.2),
            advertised: options.stratum_enabled && advertised.is_some(),
            connect_url: if options.stratum_enabled {
                advertised.or_else(|| {
                    (!addresses.2.ip().is_unspecified())
                        .then(|| format!("stratum+tcp://{}", addresses.2))
                })
            } else {
                None
            },
            password_required: options.stratum_password.is_some(),
            difficulty: options.stratum_share_difficulty,
            // Slots kept for trusted prefixes would stay empty without any.
            trusted_reserve: if options.stratum_trusted.is_empty() {
                0
            } else {
                STRATUM_TRUSTED_WORKERS
            },
            ..MiningRuntime::default()
        };
    }
    let private_http = Arc::new(HttpContext {
        public: false,
        session_token: Some(session_token),
        sessions: HttpSessions::Fixed(node.rpc_sessions.clone()),
        parsers: node.rpc_parsers.clone(),
        workers: node.rpc_workers.clone(),
        mutations: node.rpc_mutations.clone(),
        replies: None,
        guard: node.guard.clone(),
    });
    // The proxy may originate every public connection from loopback. Separate
    // admission records and worker slots prevent it exhausting private RPC.
    // Each visitor it names, like each direct client, holds only a share.
    // A full session pool makes room for networks holding fewer sessions.
    let public_http = Arc::new(HttpContext {
        public: true,
        session_token: None,
        sessions: HttpSessions::Public(PublicSessions::new(network_guard::PUBLIC_WEB_SESSIONS)),
        parsers: Arc::new(Semaphore::new(2)),
        workers: Arc::new(Semaphore::new(4)),
        mutations: Arc::new(Semaphore::new(2)),
        replies: Some(Arc::new(Semaphore::new(PUBLIC_REPLY_MEMORY_KIB))),
        guard: Arc::new(NetworkGuard::for_public_web()),
    });
    let (stop, rx) = watch::channel(false);
    let mut tasks = Vec::new();
    // Independent listener budgets keep peer saturation away from local RPC.
    // Worker permits remain owned by blocking jobs even if the socket closes.

    let mut listeners = vec![(rpc, 0), (p2p, 1)];
    if let Some(listener) = stratum {
        listeners.push((listener, 2));
    }
    if let Some(listener) = public_web {
        listeners.push((listener, 3));
    }
    for (listener, kind) in listeners {
        let n = node.clone();
        let password = options.stratum_password.clone();
        let share_difficulty = options.stratum_share_difficulty;
        let mut shutdown = rx.clone();
        let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let refusals = Arc::new(Semaphore::new(HTTP_REFUSAL_REPLIES));
        let web = kind == 0 || kind == 3;
        let http = if kind == 3 {
            public_http.clone()
        } else {
            private_http.clone()
        };
        let protected = protected.clone();
        tasks.push(service_task("listener", async move {
            let mut clients = tokio::task::JoinSet::new();
            let mut accept_failures = 0u32;
            loop { tokio::select! {
                _ = shutdown.changed() => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                accepted = listener.accept() => {
                    let (stream, address) = match accepted {
                        Ok(accepted) => { accept_failures = 0; accepted }
                        Err(error) => {
                            // An accept failure never stops the listener or its live sessions.
                            let delay = accept_retry_delay(&error, &mut accept_failures);
                            n.listener_error(kind, &error, delay);
                            tokio::select! { _ = shutdown.changed() => break, _ = tokio::time::sleep(delay) => {} }
                            continue;
                        }
                    };
                    if kind == 1 && n.peer_auth.as_ref().is_some_and(|p| !p.allows_ip(address.ip())) { drop(stream); continue; }
                    let surface=match kind {0|3=>Surface::Rpc,1=>Surface::Peer,_=>Surface::Stratum};
                    let guard = if web { &http.guard } else { &n.guard };
                    // As for peers and Stratum, an HTTP connection is admitted before it
                    // takes listener or session capacity, so an attempt refused for want of
                    // capacity still spends its address's request unit and respects its
                    // cooldown. A refused HTTP connection is answered rather than dropped:
                    // a cooldown or connection quota with 429, busy capacity with 503.
                    let web_admission = if web {
                        match guard.admit(address.ip(), surface) {
                            Ok(admission) => Some(admission),
                            Err(error) => {
                                let refusal = HttpRefusal::of(&error)
                                    .unwrap_or_else(|| HttpRefusal::busy("connection refused"));
                                refuse_connection(&mut clients, &refusals, guard, address, stream, refusal);
                                continue
                            }
                        }
                    } else { None };
                    // A Stratum connection's capacity is its pre-authorization slot, which it
                    // holds only until authorization; authorized workers are bounded by the
                    // worker registry, so unauthenticated sockets cannot occupy their capacity.
                    let permit = if kind == 2 { None } else {
                        let Ok(permit) = limit.clone().try_acquire_owned() else {
                            if let Some(admission) = web_admission {
                                drop(admission);
                                let refusal = HttpRefusal::busy("connection limit reached");
                                refuse_connection(&mut clients, &refusals, guard, address, stream, refusal);
                            }
                            continue
                        };
                        Some(permit)
                    };
                    let (admission, capacity, pending) = if kind == 1 {
                        // Rate limits and cooldowns apply before slot selection, so a
                        // connection flood spends its own request budget. A configured or
                        // pinned address, recognized exactly, is charged to its own record
                        // only, so its prefix neighbours' cooldowns cannot refuse it, and
                        // keeps a share of frame memory too.
                        let operator = protected.contains(&address.ip().to_canonical());
                        let admitted = if operator { guard.admit_operator(address.ip(),surface) } else { guard.admit(address.ip(),surface) };
                        let Ok(admission)=admitted else {drop(stream);continue};
                        let class = n.peer_class(&protected, address.ip());
                        let Some(slot) = n.peer_sessions.try_acquire(address.ip(), class) else { drop(stream); continue };
                        (admission, SessionCapacity::Peer(slot), None)
                    } else if kind == 2 {
                        // As for peers, an attempt refused for want of a slot still
                        // spends its address's request budget and respects its cooldown.
                        let Ok(admission)=guard.admit(address.ip(),surface) else {drop(stream);continue};
                        let Some(slot) = n.stratum_pending.try_acquire(address.ip()) else { drop(stream); continue };
                        // Only mining sessions use an extranonce.
                        let Some(id) = SessionIds::allocate(&n.mining_session_ids) else { drop(stream); continue };
                        (admission, SessionCapacity::Mining(id), Some(slot))
                    } else {
                        let admission = web_admission.expect("HTTP connections are admitted first");
                        let Some(slot) = http.session_slot(&admission) else {
                            drop(admission);
                            let refusal = HttpRefusal::busy("HTTP sessions busy");
                            refuse_connection(&mut clients, &refusals, guard, address, stream, refusal);
                            continue
                        };
                        (admission, SessionCapacity::Http(slot), None)
                    };
                    let extranonce = match &capacity { SessionCapacity::Mining(id) => id.1, _ => 0 };
                    // A newcomer may take over a general peer slot; this session then closes.
                    let evicted = match &capacity { SessionCapacity::Peer(slot) => Some(slot.eviction()), _ => None };
                    // A public newcomer may likewise close this HTTP session to take its place.
                    let takeover = match &capacity { SessionCapacity::Http(slot) => slot.takeover(), _ => None };
                    let node = n.clone(); let password = password.clone(); let http=http.clone();
                    let task = clients.spawn(async move { let _permit = permit; let _capacity = capacity; let _ = stream.set_nodelay(true);
                        let reporter = node.clone();
                        let result = match kind { 0|3 => http_session(node, stream, http, admission).await, 1 => peer_session(node, stream, admission, evicted).await, _ => stratum_session(node, stream, password, share_difficulty, extranonce.to_le_bytes(), admission, pending).await };
                        // Peer data is untrusted; individual failures close only that connection.
                        // Only P2P failures enter the peer diagnostics ring, so web and
                        // mining clients cannot push synchronization errors out of it.
                        if kind == 1 && result.is_err() { reporter.peer_event(format!("inbound/{kind}/{address}"), &result); }
                    });
                    if let Some((pool, id)) = takeover { pool.attach(id, task); }
                }
            }}
            clients.abort_all(); while clients.join_next().await.is_some() {}
        }));
    }
    if node.discovery_options.enabled {
        tasks.push(service_task(
            "peer discovery",
            discovery_loop(node.clone(), rx.clone()),
        ));
        tasks.push(service_task(
            "discovery seed",
            discovery_seed_loop(node.clone(), rx.clone()),
        ));
    }
    if options.stratum_enabled {
        tasks.push(service_task(
            "Stratum trusted addresses",
            stratum_trusted_loop(node.clone(), rx.clone()),
        ));
    }
    for peer in options
        .peers
        .into_iter()
        .filter(|_| !node.discovery_options.enabled)
    {
        let n = node.clone();
        let mut shutdown = rx.clone();
        tasks.push(service_task("peer synchronization", async move {
            let mut failures=0u32;
            loop {
                let result=tokio::select! { _ = shutdown.changed() => break, result=sync_peer(&n, peer) => result };
                failures=if sync_completed(&result){0}else{failures.saturating_add(1)};
                let mut random=[0u8;8];let _=getrandom::fill(&mut random);
                let delay=network_guard::retry_delay(failures,u64::from_le_bytes(random));
                tokio::select! { _ = shutdown.changed() => break, _ = tokio::time::sleep(delay) => {} }
            }
        }));
    }
    Ok(Server {
        rpc: addresses.0,
        public_web: public_web_address,
        p2p: addresses.1,
        stratum: addresses.2,
        stratum_enabled: options.stratum_enabled,
        session_token_file: node.session_token_path.as_ref().clone(),
        mining: node.mining.clone(),
        stop,
        tasks,
        _lease: lease,
    })
}
/// Long-lived service loops (listeners, configured-peer synchronization and
/// discovery) have no supervisor inside the process: a panic in one would
/// leave a running node that silently stopped that service. Exit instead,
/// like a poisoned node lock, for a supervised restart. Sessions spawned by a
/// listener stay isolated; a panic there closes only that connection.
fn service_task(
    name: &'static str,
    task: impl std::future::Future<Output = ()> + Send + 'static,
) -> JoinHandle<()> {
    // Stopping or dropping the server aborts the supervisor; abort the service with it.
    struct AbortOnDrop(tokio::task::AbortHandle);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let service = tokio::spawn(task);
    let abort = AbortOnDrop(service.abort_handle());
    tokio::spawn(async move {
        let _abort = abort;
        if service.await.is_err_and(|error| error.is_panic()) {
            eprintln!("fatal: {name} task panicked; exiting for a supervised restart");
            std::process::exit(70);
        }
    })
}
fn random_u64() -> u64 {
    let mut bytes = [0; 8];
    let _ = getrandom::fill(&mut bytes);
    u64::from_le_bytes(bytes)
}
/// Capacity held for the whole life of one accepted connection; each value
/// is released by its drop.
#[allow(dead_code)]
enum SessionCapacity {
    Http(HttpSlot),
    Peer(network_guard::PeerSlot),
    Mining(SessionId),
}
/// Accept errors never end a listener. A reset, aborted or refused connection
/// is that client's failure: it consumed one queued connection, so it is
/// skipped at once however often it repeats, and only listener health counts
/// it. An interrupted call retries at once until it repeats 64 times. Other
/// errors, such as descriptor or memory exhaustion, back off from 10 ms to
/// one second while existing sessions continue. `consecutive` counts the
/// listener's errors since its last accepted connection, except
/// per-connection ones.
fn accept_retry_delay(error: &std::io::Error, consecutive: &mut u32) -> Duration {
    use std::io::ErrorKind::*;
    if matches!(
        error.kind(),
        ConnectionAborted | ConnectionReset | ConnectionRefused
    ) {
        return Duration::ZERO;
    }
    let delay = if matches!(error.kind(), Interrupted | WouldBlock) && *consecutive < 64 {
        Duration::ZERO
    } else {
        Duration::from_millis((10u64 << (*consecutive).min(7)).min(1000))
    };
    *consecutive = consecutive.saturating_add(1);
    delay
}
/// The addresses that keep operator privileges on inbound peer sessions:
/// configured and pinned peers' exact addresses, an IPv4-mapped one as IPv4.
/// Never a wider prefix: a pin's key is checked for its exact address only,
/// so in discovery mode a neighbour in a pinned peer's IPv6 /64 joins with
/// any key and must not inherit its reserved slots, eviction immunity,
/// group-cap exemption or frame memory share.
fn protected_peers(
    peers: &[SocketAddr],
    pinned: impl IntoIterator<Item = IpAddr>,
) -> HashSet<IpAddr> {
    peers
        .iter()
        .map(SocketAddr::ip)
        .chain(pinned)
        .map(|ip| ip.to_canonical())
        .collect()
}
/// One discovery turn with `peer`, judged as a whole for scheduling
/// (`discovery_contact`): a synchronization and, when that succeeded, at
/// most once a minute per peer, an address exchange, which holds the
/// outbound slot as well. One overall deadline of five read allowances
/// still bounds the synchronization, but one that has delivered nothing new
/// after two is cut off, so a slow-walking endpoint holds a slot for at most
/// that long plus one allowance for the address exchange.
async fn discovery_turn(node: &Node, peer: SocketAddr) -> peer_discovery::Contact {
    let Ok(allowance) = node.peer_exchange_timeout() else {
        return peer_discovery::Contact::Failed;
    };
    let started = Instant::now();
    let session = timeout(allowance.saturating_mul(5), sync_peer(node, peer));
    tokio::pin!(session);
    let cutoff = tokio::time::sleep(allowance.saturating_mul(2));
    tokio::pin!(cutoff);
    let mut watching = true;
    let result = loop {
        tokio::select! {
            // Only whether the exchange completed counts here; what this
            // node made of the blocks is judged from the tip below.
            result = &mut session => break Some(discovery_result(result)),
            () = &mut cutoff, if watching => {
                if !node.peer_sessions.delivered_since(peer.ip(), started) {
                    break None;
                }
                watching = false;
            }
        }
    };
    if result.is_none() {
        let stalled = Err(anyhow!(
            "peer synchronization delivered nothing new within two read allowances"
        ));
        node.peer_event(peer.to_string(), &stalled);
    }
    let advanced = node.peer_sessions.advanced_since(peer.ip(), started);
    let contact = discovery_contact(result.as_ref(), advanced, started.elapsed(), allowance);
    let query = contact.success()
        && matches!(result, Some(Ok(())))
        && node
            .discovery
            .unpoisoned()
            .as_mut()
            .is_some_and(|b| b.needs_discovery(peer, now()));
    if !query {
        return contact;
    }
    // A separate exchange cannot change Sync/Ack semantics or cause an
    // authenticated connection to retry unsigned.
    let exchanged = discover_peer(node, peer).await;
    if exchanged.is_err() {
        node.peer_event(format!("discovery/{peer}"), &exchanged);
    }
    discovery_contact(result.as_ref(), advanced, started.elapsed(), allowance)
}
/// A discovery turn's synchronization result as `discovery_contact` judges
/// it. A session whose replay this node deferred completes (`SyncOutcome`),
/// and is judged as the deferral it reports: this node's own limit, never
/// the peer's, however long the exchange took.
fn discovery_result(
    result: Result<Result<SyncOutcome>, tokio::time::error::Elapsed>,
) -> Result<()> {
    match result {
        Ok(Ok(outcome)) if outcome.deferred => Err(crate::chain::ValidationDeferred.into()),
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(anyhow!(
            "peer synchronization exceeded its overall deadline"
        )),
    }
}
/// What a discovery turn achieved, for scheduling: `result` is the
/// synchronization's, `None` for one cut off because it had delivered
/// nothing new, and `elapsed` the whole turn's time. A block of the peer's
/// that became the tip makes it `Advanced`, whatever else happened; only
/// proof of work earns that. A turn whose exchange otherwise completed is
/// `Current` within one read allowance and `Stalled` after it: a slow turn
/// that delivered nothing held an outbound slot without advancing this
/// node. As for configured peers (`sync_completed`), a deferred replay or a
/// held side-branch header completes an exchange; a deferred replay is this
/// node's own limit, never the peer's.
fn discovery_contact(
    result: Option<&Result<()>>,
    advanced: bool,
    elapsed: Duration,
    allowance: Duration,
) -> peer_discovery::Contact {
    use crate::chain::{SideBranchRefused, ValidationDeferred};
    use peer_discovery::Contact;
    if advanced {
        return Contact::Advanced;
    }
    match result {
        None => Contact::Stalled,
        Some(Err(error)) if error.is::<ValidationDeferred>() => Contact::Current,
        Some(Err(error)) if !error.is::<SideBranchRefused>() => Contact::Failed,
        Some(_) if elapsed <= allowance => Contact::Current,
        Some(_) => Contact::Stalled,
    }
}
/// A deferred replay or a held side-branch header is local validation
/// progress, not a peer failure. A session reports both in its outcome
/// (`SyncOutcome::deferred`) and completes; the errors are still accepted
/// here from any path that ends with them.
fn sync_completed(result: &Result<SyncOutcome>) -> bool {
    match result {
        Ok(_) => true,
        Err(error) => {
            error.is::<crate::chain::ValidationDeferred>()
                || error.is::<crate::chain::SideBranchRefused>()
        }
    }
}
async fn discovery_seed_loop(node: Node, mut shutdown: watch::Receiver<bool>) {
    loop {
        for seed in &node.discovery_options.seeds {
            let resolved = tokio::select! {
                _=shutdown.changed()=>return,
                result=timeout(Duration::from_secs(5),tokio::net::lookup_host(seed.as_str()))=>result,
            };
            match resolved {
                Ok(Ok(addresses)) => {
                    if let Some(book) = node.discovery.unpoisoned().as_mut() {
                        for address in addresses.take(peer_discovery::MAX_SEED_RESULTS) {
                            book.add_seed(address, seed, now());
                        }
                    }
                }
                Ok(Err(error)) => node.peer_event(
                    format!("seed/{seed}"),
                    &Err(anyhow!("seed resolution failed: {error}")),
                ),
                Err(error) => node.peer_event(
                    format!("seed/{seed}"),
                    &Err(anyhow!("seed resolution timed out: {error}")),
                ),
            }
        }
        tokio::select! { _=shutdown.changed()=>return, _=tokio::time::sleep(Duration::from_secs(600))=>{} }
    }
}
async fn discovery_loop(node: Node, mut shutdown: watch::Receiver<bool>) {
    let mut workers = tokio::task::JoinSet::new();
    let mut saved_at = 0;
    loop {
        let candidates = {
            let mut guard = node.discovery.unpoisoned();
            let Some(book) = guard.as_mut() else { break };
            book.next(now(), 2usize.saturating_sub(workers.len()))
        };
        for peer in candidates {
            let n = node.clone();
            workers.spawn(async move { (peer, discovery_turn(&n, peer).await) });
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            Some(result)=workers.join_next(),if !workers.is_empty()=>{
                if let Ok((peer,contact))=result
                    && let Some(book)=node.discovery.unpoisoned().as_mut() {
                    book.finished(peer,contact,now(),random_u64());
                }
            }
            _=tokio::time::sleep(Duration::from_millis(200))=>{},
        }
        if now().saturating_sub(saved_at) >= 5 {
            persist_address_book(&node).await;
            saved_at = now();
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    persist_address_book(&node).await;
}
/// Stratum addresses that authorized are saved at most once per this interval,
/// and when the server stops, so they keep reserved slots after a restart.
const STRATUM_TRUSTED_SAVE: Duration = Duration::from_secs(10);
async fn stratum_trusted_loop(node: Node, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(STRATUM_TRUSTED_SAVE) => {}
        }
        persist_stratum_trusted(&node).await;
    }
    persist_stratum_trusted(&node).await;
}
/// The file write and its fsync run on a blocking worker; a failed save is
/// retried at the next interval.
async fn persist_stratum_trusted(node: &Node) {
    let Some(bytes) = node.stratum_pending.unsaved_trusted() else {
        return;
    };
    let path = node.stratum_trusted_path.clone();
    let saved = tokio::task::spawn_blocking(move || StratumPending::persist_trusted(&path, &bytes))
        .await
        .map_err(|error| anyhow!("Stratum trusted address writer failed: {error}"))
        .and_then(|result| result);
    if let Err(error) = saved {
        eprintln!("Stratum trusted addresses not saved: {error:#}");
        node.stratum_pending.save_failed();
    }
}
/// Serialize under the discovery lock only when the persisted form changed;
/// the file write and its fsync run on a blocking worker without the lock.
async fn persist_address_book(node: &Node) {
    let pending = node
        .discovery
        .unpoisoned()
        .as_mut()
        .and_then(|book| match book.pending_save() {
            Ok(pending) => pending.map(|bytes| (book.path().to_path_buf(), bytes)),
            Err(error) => {
                book.last_error = Some(format!("address book save failed: {error}"));
                None
            }
        });
    let Some((path, bytes)) = pending else {
        return;
    };
    let result =
        tokio::task::spawn_blocking(move || AddressBook::persist(&path, &bytes).map(|()| bytes))
            .await
            .map_err(|error| anyhow!("address book worker failed: {error}"))
            .and_then(|result| result);
    if let Some(book) = node.discovery.unpoisoned().as_mut() {
        match result {
            Ok(bytes) => {
                book.mark_saved(bytes);
                book.last_error = None;
            }
            Err(error) => book.last_error = Some(format!("address book save failed: {error}")),
        }
    }
}
async fn discover_peer(node: &Node, peer: SocketAddr) -> Result<()> {
    // As for synchronization, one deadline covers the wait for an outbound
    // slot and the whole exchange, so a slow-walking endpoint holds a slot,
    // and a discovery worker, for at most one exchange allowance. Expiry
    // drops the exchange without a cooldown and is reported by the caller.
    let deadline = tokio::time::Instant::now() + node.peer_exchange_timeout()?;
    let _permit = tokio::time::timeout_at(deadline, node.outbound_sessions.clone().acquire_owned())
        .await
        .map_err(|_| anyhow!("outbound peer slots remained busy"))??;
    tokio::time::timeout_at(deadline, discover_peer_steps(node, peer))
        .await
        .map_err(|_| anyhow!("peer discovery exceeded its overall deadline"))?
}
async fn discover_peer_steps(node: &Node, peer: SocketAddr) -> Result<()> {
    let policy = node
        .peer_auth
        .as_ref()
        .context("discovery requires authenticated transport")?;
    ensure!(
        policy.is_discovery(),
        "discovery disabled in pinned transport"
    );
    let admission = node.guard.admit_outbound(peer.ip(), Surface::Peer)?;
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(peer)).await??;
    let chain = node.read_view()?.chain.chain_id();
    let mut transport = PeerTransport::Signed(
        timeout(
            IO_TIMEOUT,
            PeerChannel::connect(&mut stream, policy, peer, chain, &admission),
        )
        .await??,
    );
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write_peer(
        node,
        &mut write,
        PeerPacket::GetAddresses {
            chain,
            node: node.discovery_id,
            advertise: node.discovery_options.advertise,
        },
        &admission,
        &mut transport,
    )
    .await?;
    match read_peer_packet(
        &mut read,
        node,
        &admission,
        &mut transport,
        PeerRead::Addresses,
        None,
    )
    .await?
    {
        PeerPacket::Addresses {
            chain: remote_chain,
            node: identity,
            addresses,
        } => {
            ensure!(remote_chain == chain, "discovery chain mismatch");
            ensure!(identity != node.discovery_id, "self discovery connection");
            let mut guard = node.discovery.unpoisoned();
            guard
                .as_mut()
                .context("discovery stopped")?
                .learn(peer, &addresses, now());
            Ok(())
        }
        _ => bail!("unexpected peer discovery response"),
    }
}
async fn peer_session(
    node: Node,
    stream: TcpStream,
    admission: Session,
    evicted: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
    // An absolute deadline bounds how long one connection holds an inbound
    // slot, however each individual step is paced. It also covers waits for
    // local workers and validation, so expiry closes without a cooldown;
    // each peer read has its own allowance, and a peer that misses it is
    // penalized there.
    let deadline = node.peer_exchange_timeout()?.saturating_mul(2);
    // Replies are paid for while they are built on peer workers.
    let admission = Arc::new(admission);
    let steps = timeout(deadline, peer_session_steps(&node, stream, &admission));
    // A newcomer that took over this general slot ends the session at once,
    // also without a cooldown: it did nothing wrong.
    let evicted = async {
        match evicted {
            Some(evicted) => evicted.notified().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result = steps => result.map_err(|_| anyhow!("peer session exceeded its overall deadline"))?,
        () = evicted => Err(anyhow!("peer session evicted for a newcomer")),
    }
}
async fn peer_session_steps(
    node: &Node,
    mut stream: TcpStream,
    admission: &Arc<Session>,
) -> Result<()> {
    let remote = stream.peer_addr()?;
    // The handshake and first message share one deadline.
    let first = tokio::time::Instant::now() + node.peer_request_timeout()?;
    let mut transport = if let Some(policy) = &node.peer_auth {
        // Nothing has been proved before the handshake completes. A failure
        // here closes the connection without a cooldown that would also hit
        // honest hosts sharing this source address; rate limits still apply.
        PeerTransport::Signed(
            tokio::time::timeout_at(
                first,
                PeerChannel::accept(
                    &mut stream,
                    policy,
                    remote.ip(),
                    node.read_view()?.chain.chain_id(),
                    admission,
                ),
            )
            .await??,
        )
    } else {
        PeerTransport::Plain
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut request = read_peer_packet(
        &mut read,
        node,
        admission,
        &mut transport,
        PeerRead::Request,
        Some(first),
    )
    .await?;
    // A version 2 client opens with header requests. The block capacity
    // allowance it declares bounds the blocks this session replies with.
    let mut declared = None;
    let mut rounds = 0;
    while let PeerPacket::GetHeaders {
        chain,
        version,
        capacity,
        locator,
    } = request
    {
        ensure!(
            chain == node.read_view()?.chain.chain_id(),
            "different genesis configuration"
        );
        rounds += 1;
        if rounds > peer_wire::MAX_HEADER_ROUNDS {
            admission.malformed();
            bail!("too many header requests in one peer session");
        }
        declared = Some(capacity);
        let reply = headers_reply_async(node, locator, version, admission.clone()).await?;
        // A processed message holds no frame memory while its reply is
        // written and the next frame awaited (see `Session::frame_processed`).
        admission.frame_processed();
        write_peer(node, &mut write, reply, admission, &mut transport).await?;
        request = read_peer_packet(
            &mut read,
            node,
            admission,
            &mut transport,
            PeerRead::Request,
            None,
        )
        .await?;
    }
    let hello = match request {
        PeerPacket::Sync(hello) => hello,
        PeerPacket::GetAddresses {
            chain,
            node: identity,
            advertise,
        } if declared.is_none() => {
            ensure!(
                chain == node.read_view()?.chain.chain_id(),
                "discovery chain mismatch"
            );
            ensure!(identity != node.discovery_id, "self discovery connection");
            let reply = {
                let mut guard = node.discovery.unpoisoned();
                let book = guard.as_mut().context("peer discovery disabled")?;
                if let Some(address) = advertise {
                    book.advertisement(remote, address, now());
                }
                PeerPacket::Addresses {
                    chain,
                    node: node.discovery_id,
                    addresses: book.advertised(now(), random_u64()),
                }
            };
            admission.frame_processed();
            write_peer(node, &mut write, reply, admission, &mut transport).await?;
            return Ok(());
        }
        _ => bail!("unexpected first peer message"),
    };
    // Only the locator outlives the hello's processing.
    let (PeerMessage { locator, .. }, _) = receive_peer_async(node, hello, remote.ip()).await?;
    admission.frame_processed();
    let reply = peer_snapshot_async(node, Some(locator), declared, admission.clone()).await?;
    write_peer(
        node,
        &mut write,
        PeerPacket::Sync(reply),
        admission,
        &mut transport,
    )
    .await?;
    let push = read_peer(&mut read, node, admission, &mut transport).await?;
    // A push whose replay this node deferred is still acknowledged: the
    // exchange completed, and the next one continues the replay.
    receive_peer_async(node, push, remote.ip()).await?;
    admission.frame_processed();
    write_peer(node, &mut write, PeerPacket::Ack, admission, &mut transport).await?;
    Ok(())
}
/// What one outbound synchronization session achieved. `sync_peer` returns
/// it once the whole exchange completed (header requests, if the peer
/// answers them, then the locator request, the peer's reply, this node's
/// push and the peer's acknowledgement), whatever local validation made of
/// the blocks; it fails only when the exchange itself did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Header requests the peer answered.
    pub header_rounds: usize,
    /// Why processing a header reply ended the header requests early, if it
    /// did: the reply failed its checks or local storage failed. (A reply
    /// that raced another download is ignored without an error.) The block
    /// exchange ran regardless.
    pub header_error: Option<String>,
    /// Blocks the peer's reply carried.
    pub blocks: usize,
    /// Local validation deferred one of the reply's blocks: rebuilding its
    /// parent's state needs more history replay than one submission may
    /// run. The replay keeps its progress, and the next session with a peer
    /// serving that branch continues it.
    pub deferred: bool,
}
pub async fn sync_peer(node: &Node, peer: SocketAddr) -> Result<SyncOutcome> {
    // Only configured peers enter this bounded map; manual diagnostics cannot grow it.
    if let Some(h) = node.peer_health.unpoisoned().get_mut(&peer) {
        h.last_attempt = now();
    }
    let result = sync_peer_inner(node, peer).await;
    if let Some(h) = node.peer_health.unpoisoned().get_mut(&peer) {
        if sync_completed(&result) {
            h.last_success = now();
            h.failures = 0;
        } else {
            h.failures = h.failures.saturating_add(1);
        }
    }
    if let Ok(SyncOutcome {
        header_error: Some(error),
        ..
    }) = &result
    {
        node.peer_event(
            format!("{peer}/headers"),
            &Err(anyhow!("header requests ended early: {error}")),
        );
    }
    node.peer_event(
        peer.to_string(),
        &result.as_ref().map(|_| ()).map_err(|e| anyhow!("{e}")),
    );
    result
}
/// Process a peer message on a peer worker; the message, and whether local
/// validation deferred one of its blocks. A deferral is local progress, not
/// a fault of the peer's: the message's later blocks and its transactions
/// wait for another message, and the exchange carrying it goes on.
async fn receive_peer_async(
    node: &Node,
    message: PeerMessage,
    source: IpAddr,
) -> Result<(PeerMessage, bool)> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let worker = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        match worker.receive_peer(&message, source) {
            Ok(()) => Ok((message, false)),
            Err(error) if error.is::<crate::chain::ValidationDeferred>() => Ok((message, true)),
            Err(error) => Err(error),
        }
    })
    .await
    .context("peer validation worker failed")?
}
/// A synchronization message built on a peer worker, its blocks and loose
/// transactions paid for from `admission`'s budget as they are added.
async fn peer_snapshot_async(
    node: &Node,
    locator: Option<Vec<Hash>>,
    declared: Option<u64>,
    admission: Arc<Session>,
) -> Result<PeerMessage> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        // This node chose the message's contents, so an exhausted budget
        // shortens it and never penalizes the peer.
        let charge = |work: usize| admission.outgoing(0, work).is_ok();
        node.peer_snapshot_charged(locator.as_deref(), declared, &charge)
    })
    .await
    .context("peer snapshot worker failed")?
}
async fn header_request_async(node: &Node, peer: SocketAddr) -> Result<PeerPacket> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.header_request(peer)
    })
    .await
    .context("peer header worker failed")?
}
/// A header reply built on a peer worker. Its headers are paid for from
/// `admission`'s budget before any is read, one work unit each, so a reply
/// is never built and then refused. A budget that cannot pay for the whole
/// reply ends the session unbuilt, never penalizing the requester. The
/// reply is not shortened instead: a requester that is holding a counted
/// branch takes a short reply for a chain that now ends short of what it
/// counted, and would end its download.
async fn headers_reply_async(
    node: &Node,
    locator: Vec<Hash>,
    version: u8,
    admission: Arc<Session>,
) -> Result<PeerPacket> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.headers_reply_within(&locator, version, |planned| {
            admission.outgoing(0, planned.max(1))
        })
    })
    .await
    .context("peer header worker failed")?
}
async fn receive_headers_async(
    node: &Node,
    peer: SocketAddr,
    headers: Vec<Header>,
) -> Result<bool> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.receive_headers(peer, &headers)
    })
    .await
    .context("peer header worker failed")?
}
/// Whether the peer closed the connection after reading a request whole,
/// before any reply byte: an end of stream, reset or abort while waiting
/// for the reply's first byte, which stays unread.
async fn closed_before_reply<R: AsyncBufRead + Unpin>(
    read: &mut R,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    match tokio::time::timeout_at(deadline, read.fill_buf()).await {
        Err(_) => bail!("peer message timed out"),
        Ok(Ok(bytes)) => Ok(bytes.is_empty()),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            ) =>
        {
            Ok(true)
        }
        Ok(Err(error)) => Err(error.into()),
    }
}
/// Whether a failed peer read ended because the peer closed or reset the
/// connection, rather than with a malformed frame or a timeout.
fn peer_closed(error: &anyhow::Error) -> bool {
    error.is::<PeerClosed>()
        || error.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                )
            })
        })
}
/// How the header requests of one session went.
#[derive(Default)]
struct HeaderPhase {
    /// Requests the peer answered.
    rounds: usize,
    /// Why processing an answer ended the requests early, if it did.
    error: Option<String>,
    /// The block capacity allowance the last request declared, which the
    /// peer's block reply then fits.
    declared: Option<u64>,
}
/// Header requests that open a version 2 session, until a reply leaves
/// nothing more to fetch. A version 1 peer rejects the first request as an
/// unknown message type and closes the connection without replying. So can
/// a version 2 peer that refuses or evicts the session; a peer that does
/// this on LEGACY_PEER_CLOSES consecutive sessions, without answering a
/// header request in between, is synchronized by blocks only for
/// LEGACY_PEER_RETRY.
///
/// A reply received whole whose processing fails, because it fails its
/// checks or local storage does, ends the requests without failing the
/// session, as a reply that raced another download does without an error:
/// the connection is intact, and the block exchange that follows still
/// runs. Only a failed exchange ends the session.
async fn header_rounds<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    node: &Node,
    peer: SocketAddr,
    read: &mut R,
    write: &mut W,
    admission: &Session,
    transport: &mut PeerTransport,
) -> Result<HeaderPhase> {
    let mut phase = HeaderPhase::default();
    for round in 0..peer_wire::MAX_HEADER_ROUNDS {
        let request = header_request_async(node, peer).await?;
        if let PeerPacket::GetHeaders { capacity, .. } = &request {
            phase.declared = Some(*capacity);
        }
        write_peer(node, write, request, admission, transport).await?;
        let deadline = tokio::time::Instant::now() + node.peer_exchange_timeout()?;
        if round == 0 && closed_before_reply(read, deadline).await? {
            let blocks_only = if node.note_header_close(peer) {
                format!(
                    "synchronizing it by blocks only for {} seconds",
                    LEGACY_PEER_RETRY.as_secs()
                )
            } else {
                format!(
                    "after {LEGACY_PEER_CLOSES} consecutive sessions closed this way it is synchronized by blocks only"
                )
            };
            bail!(
                "peer closed the connection on a header request: it may run peer transport version 1 or Hashstash 0.42.0 or earlier, follow another genesis, or be at its connection limits; {blocks_only}"
            );
        }
        let reply = read_peer_packet(
            read,
            node,
            admission,
            transport,
            PeerRead::Headers,
            Some(deadline),
        )
        .await?;
        let PeerPacket::Headers {
            chain,
            version,
            headers,
        } = reply
        else {
            bail!("unexpected peer header reply");
        };
        ensure!(
            chain == node.read_view()?.chain.chain_id(),
            "different genesis configuration"
        );
        ensure!(
            version == peer_wire::TRANSPORT_VERSION,
            "unsupported peer transport version {version}"
        );
        if round == 0 {
            node.note_header_reply(peer);
        }
        phase.rounds += 1;
        match receive_headers_async(node, peer, headers).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                phase.error = Some(format!("{error:#}"));
                break;
            }
        }
    }
    Ok(phase)
}
async fn sync_peer_inner(node: &Node, peer: SocketAddr) -> Result<SyncOutcome> {
    // Keep the former five-stage overall budget, growing with the same
    // validated capacity as individual exchanges. One deadline covers the
    // wait for an outbound slot and the exchange, so a slow peer can hold one
    // of the two outbound slots only for this long, and waiting for a slot
    // fails instead of hanging behind such peers.
    let deadline = tokio::time::Instant::now() + node.peer_exchange_timeout()?.saturating_mul(5);
    // Reserve separate inbound capacity so simultaneous outgoing synchronizations
    // cannot consume every receiving slot on all peers.
    let _frame_permit =
        tokio::time::timeout_at(deadline, node.outbound_sessions.clone().acquire_owned())
            .await
            .map_err(|_| anyhow!("outbound peer slots remained busy"))??;
    tokio::time::timeout_at(deadline, sync_peer_steps(node, peer))
        .await
        .map_err(|_| anyhow!("peer synchronization exceeded its overall deadline"))?
}
async fn sync_peer_steps(node: &Node, peer: SocketAddr) -> Result<SyncOutcome> {
    // Messages are paid for while they are built on peer workers.
    let admission = Arc::new(node.guard.admit_outbound(peer.ip(), Surface::Peer)?);
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(peer)).await??;
    let mut transport = if let Some(policy) = &node.peer_auth {
        PeerTransport::Signed(
            timeout(
                IO_TIMEOUT,
                PeerChannel::connect(
                    &mut stream,
                    policy,
                    peer,
                    node.read_view()?.chain.chain_id(),
                    &admission,
                ),
            )
            .await??,
        )
    } else {
        PeerTransport::Plain
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    // Transport version 2: headers come first, so a branch is learned from
    // its headers whatever its blocks' size or its distance from the tip.
    let mut outcome = SyncOutcome::default();
    let mut declared = None;
    let headers = node.speaks_headers(peer);
    if headers {
        let phase = header_rounds(
            node,
            peer,
            &mut read,
            &mut write,
            &admission,
            &mut transport,
        )
        .await?;
        outcome.header_rounds = phase.rounds;
        outcome.header_error = phase.error;
        declared = phase.declared;
    }
    write_peer(
        node,
        &mut write,
        PeerPacket::Sync(peer_snapshot_async(node, None, None, admission.clone()).await?),
        &admission,
        &mut transport,
    )
    .await?;
    // The reply fits the allowance the header requests declared.
    let reply = match read_peer_packet_within(
        &mut read,
        node,
        &admission,
        &mut transport,
        PeerRead::Sync,
        None,
        declared,
    )
    .await
    {
        Ok(PeerPacket::Sync(reply)) => reply,
        Ok(_) => bail!("unexpected message during synchronization"),
        // A peer synchronized by blocks only after closing on header
        // requests usually closes this request for the same reason.
        Err(error) if !headers && peer_closed(&error) => bail!(
            "peer closed the connection on a locator request while synchronized by blocks only: it may run Hashstash 0.42.0 or earlier, follow another genesis, or be at its connection limits"
        ),
        Err(error) => return Err(error),
    };
    outcome.blocks = reply.blocks.len();
    // A reply whose replay this node deferred still gets this node's push,
    // and the peer's acknowledgement completes the session.
    let (reply, deferred) = receive_peer_async(node, reply, peer.ip()).await?;
    outcome.deferred = deferred;
    write_peer(
        node,
        &mut write,
        PeerPacket::Sync(
            peer_snapshot_async(node, Some(reply.locator), None, admission.clone()).await?,
        ),
        &admission,
        &mut transport,
    )
    .await?;
    read_peer_packet(
        &mut read,
        node,
        &admission,
        &mut transport,
        PeerRead::Ack,
        None,
    )
    .await?;
    Ok(outcome)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletRequest {
    operation: Operation,
    fee: Option<String>,
    extra_fee: Option<String>,
    data_hex: Option<String>,
    expiry_blocks: Option<u64>,
    anchor: Option<String>,
    nonce: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HotWalletRequest {
    operation: Operation,
    fee: Option<String>,
    extra_fee: Option<String>,
    data_hex: Option<String>,
    expiry_blocks: Option<u64>,
    anchor: Option<String>,
    nonce: Option<u64>,
    expected_sender: String,
    wallet_revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareRequest {
    sender: String,
    operation: Operation,
    fee: Option<String>,
    extra_fee: Option<String>,
    data_hex: Option<String>,
    expiry_blocks: Option<u64>,
    anchor: Option<String>,
    nonce: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BroadcastRequest {
    raw: String,
}

/// Construct one exact-fee body. Quotes never reserve a nonce or funds.
fn wallet_body(
    c: &Config,
    s: &State,
    tip: Hash,
    sender: PublicKey,
    nonce: u64,
    request: WalletRequest,
) -> Result<TransactionBody> {
    ensure!(nonce < u64::MAX, "nonce exhausted");
    ensure!(
        request.expiry_blocks.is_none_or(|blocks| blocks > 0),
        "expiry_blocks must be positive"
    );
    let anchor = request
        .anchor
        .as_deref()
        .map(parse_hash)
        .transpose()?
        .unwrap_or(tip);
    ensure!(
        anchor == tip,
        "anchor differs from the quoted tip; refresh before preparing"
    );
    let expiry_blocks = request
        .expiry_blocks
        .unwrap_or_else(|| wallet::default_expiry_blocks(&request.operation));
    let expiry_height = s
        .height
        .checked_add(expiry_blocks)
        .context("expiry height overflow")?;
    ensure!(
        expiry_height > s.height,
        "expiry height must allow inclusion"
    );
    check_operation_bounds(c, &request.operation)?;
    // Quotes, preparation and hot-wallet sends refuse what admission would.
    ensure!(
        !(conditional(&request.operation) && trading_closed(s)),
        TRADING_CLOSED
    );
    let data = transaction_data(
        c.transaction_bytes(&s.settings),
        request.data_hex.as_deref(),
    )?;
    let mut body = TransactionBody {
        sender,
        nonce,
        fee: Amount::zero(),
        anchor,
        expiry_blocks,
        operation: request.operation,
        data,
    };

    ensure!(
        request.fee.is_none() || request.extra_fee.is_none(),
        "specify either an exact fee or an optional extra, not both"
    );
    let extra = parse_amount(request.extra_fee.as_deref().unwrap_or("0"))?;
    c.check_amount(&extra)?;
    let explicit = request.fee.as_deref().map(parse_amount).transpose()?;
    if let Some(fee) = &explicit {
        c.check_amount(fee)?;
        body.fee = fee.clone();
    }
    // The fee integer's encoded length contributes to its own minimum charge.
    let mut stable = false;
    let mut weight = 0;
    for _ in 0..32 {
        let quote = fees::quote(
            c,
            s,
            &Transaction {
                body: body.clone(),
                signature: [0; 64],
            },
        )?;
        weight = quote.weight;
        if explicit.is_some() {
            ensure!(
                body.fee >= quote.minimum_fee,
                "signed fee is below the mandatory minimum"
            );
            stable = true;
            break;
        }
        let fee = &quote.minimum_fee + &extra;
        c.check_amount(&fee)?;
        if fee == body.fee {
            stable = true;
            break;
        }
        body.fee = fee;
    }
    ensure!(stable, "automatic fee quote did not converge");

    ensure!(
        codec::encode(&body).len().saturating_add(64) <= c.transaction_bytes(&s.settings),
        "transaction too large"
    );
    // A block admits the weight its capacity names, and the bytes are only
    // part of it. A transaction whose weight alone exceeds that can never be
    // included, so it is neither quoted nor prepared for signing.
    ensure!(
        weight <= s.settings.block_bytes,
        "transaction weight {weight} exceeds the block capacity of {} weight units: \
         each new account, proposal or support record and grant recipient adds {} to its bytes",
        s.settings.block_bytes,
        fees::ACCOUNT_WEIGHT
    );
    Ok(body)
}

fn fee_quote_json(
    c: &Config,
    s: &State,
    tip: Hash,
    state_root: Hash,
    body: &TransactionBody,
) -> Result<Value> {
    ensure!(
        body.anchor == tip,
        "fee quote anchor differs from its snapshot"
    );
    let expiry_height = s
        .height
        .checked_add(body.expiry_blocks)
        .context("expiry height overflow")?;
    let quote = crate::fees::quote(
        c,
        s,
        &Transaction {
            body: body.clone(),
            signature: [0; 64],
        },
    )?;
    let mut value = json!({
       "fee":quote.fee.to_str_radix(10), "minimum_fee":quote.minimum_fee.to_str_radix(10),
       "account_creation_fee":quote.account_creation_fee.to_str_radix(10),
       "grant_recipient_fee":quote.grant_recipient_fee.to_str_radix(10),
       "record_fee":quote.record_fee.to_str_radix(10),
       "extra_fee":quote.extra_fee.to_str_radix(10),
       "miner_fee":quote.miner_fee.to_str_radix(10), "revenue_fee":quote.revenue_fee.to_str_radix(10),
       "miner_fee_percent":quote.miner_fee_percent,
       "weight":quote.weight.to_string(), "minimum_fee_rate":s.settings.minimum_fee_rate.to_string(),
       "chain_id":hex::encode(s.chain_id), "height":s.height, "tip":hex::encode(tip), "state_root":hex::encode(state_root),
       "sender":address::encode(&body.sender,&s.chain_id)?, "sender_public_key":hex::encode(body.sender),
       "payment_available_hash":s.common_spendable(&body.sender).unwrap_or_default().to_str_radix(10),
       "nonce":body.nonce, "anchor":hex::encode(body.anchor), "anchor_height":s.height,
       "expiry_blocks":body.expiry_blocks, "expiry_height":expiry_height, "pending":false,
       "operation":body.operation,
       "data_hex":hex::encode(&body.data), "data_bytes":body.data.len()
    });
    if let Some(change) = scheduled_change(s, body, &quote) {
        value["scheduled_change"] = change;
    }
    if matches!(
        body.operation,
        Operation::Deposit { .. } | Operation::Redeem { .. }
    ) {
        value["execution"] = json!("block_batch");
        value["partial_fill_possible"] = json!(true);
        value["unfilled_input_returned"] = json!(true);
    }
    Ok(value)
}

/// A passed MinimumFeeRate or BlockBytes change that takes effect within the
/// quoted lifetime: one pending in rest, or one the next block passes when it
/// resolves the current decision. That block's final observation depends only
/// on this tip, so the outcome is already certain; with a zero rest it also
/// activates the change, and no tip is ever in rest. Earlier in a decision the
/// outcome is unknown and nothing is reported. The activating block still uses
/// the tip's settings and the blocks after it use the new value, under which
/// this fee or size may no longer be valid. The quote stays exact; clients
/// warn or defer instead.
fn scheduled_change(
    s: &State,
    body: &TransactionBody,
    quote: &crate::fees::FeeQuote,
) -> Option<Value> {
    let interval = s.settings.interval.max(1);
    let (parameter, new, activation) = match &s.phase {
        crate::state::Phase::Rest(rest) => {
            let (parameter, new) = rest.pending?;
            // The first block whose scheduled clock reaches the deadline activates it.
            let remaining = rest.until.saturating_sub(s.clock);
            let blocks = remaining.div_ceil(interval).max(1);
            (parameter, new, s.height.saturating_add(blocks))
        }
        crate::state::Phase::Governance(decision) => {
            let resolution = s.height.checked_add(1)?;
            if decision.started_height.checked_add(decision.blocks)? != resolution {
                return None;
            }
            let Proposal::Parameter { parameter, new, .. } = &*decision.proposal else {
                return None;
            };
            // As consensus resolves it: the tip's own observation counts.
            let leads = crate::consensus::pass_beats_fail(
                s.alternative.as_ref()?,
                &s.world,
                s.frozen.pass_margin_bps.unwrap_or(0),
            );
            if decision.leading_blocks.saturating_add(u64::from(leads)) <= decision.blocks / 2 {
                return None;
            }
            // The resolving block starts the rest; the first block whose
            // clock reaches its end, possibly that same block, activates it.
            let blocks = s.frozen.rest.div_ceil(interval);
            (*parameter, *new, resolution.saturating_add(blocks))
        }
        crate::state::Phase::Auction(_) => return None,
    };
    if !matches!(parameter, Parameter::MinimumFeeRate | Parameter::BlockBytes) {
        return None;
    }
    let effective = activation.saturating_add(1);
    if effective > s.height.saturating_add(body.expiry_blocks) {
        return None;
    }
    let mut settings = s.settings.clone();
    settings.set(parameter, new);
    let minimum = (Amount::from(quote.weight) * settings.minimum_fee_rate
        + Amount::from(crate::fees::FEE_SCALE - 1))
        / crate::fees::FEE_SCALE;
    let bytes = codec::encode(&Transaction {
        body: body.clone(),
        signature: [0; 64],
    })
    .len() as u64;
    let valid = body.fee >= minimum
        && quote.weight <= settings.block_bytes
        && bytes <= settings.block_bytes;
    Some(json!({
        "parameter": parameter, "value": new.to_string(),
        "activation_height": activation, "effective_height": effective,
        "minimum_fee": minimum.to_str_radix(10), "valid_after": valid
    }))
}

fn transaction_data(max_bytes: usize, input: Option<&str>) -> Result<Vec<u8>> {
    let input = input.unwrap_or("");
    ensure!(
        input.len() <= max_bytes.saturating_mul(2),
        "transaction data is too large"
    );
    ensure!(
        input.len().is_multiple_of(2),
        "transaction data must contain complete hex bytes"
    );
    let data = hex::decode(input).context("transaction data must be hexadecimal bytes")?;
    Ok(data)
}

struct HttpContext {
    public: bool,
    session_token: Option<String>,
    sessions: HttpSessions,
    parsers: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    mutations: Arc<Semaphore>,
    /// The public website's built reply bodies held until written, in KiB
    /// (`PUBLIC_REPLY_MEMORY_KIB`); `None` on the private listener.
    replies: Option<Arc<Semaphore>>,
    guard: Arc<NetworkGuard>,
}
impl HttpContext {
    /// A session place for an admitted connection, if one is free or, on
    /// the public website, can be made (`PublicSessions`).
    fn session_slot(&self, admission: &Session) -> Option<HttpSlot> {
        match &self.sessions {
            HttpSessions::Fixed(pool) => pool.clone().try_acquire_owned().ok().map(HttpSlot::Fixed),
            HttpSessions::Public(pool) => pool.acquire(admission.network()).map(HttpSlot::Public),
        }
    }
}
/// Session capacity of one HTTP listener.
enum HttpSessions {
    /// The private RPC listener's fixed pool.
    Fixed(Arc<Semaphore>),
    /// The public website's pool, which can make room for a newcomer.
    Public(Arc<PublicSessions>),
}
/// One HTTP session's place in its listener's pool, released by its drop.
#[allow(dead_code)]
enum HttpSlot {
    Fixed(tokio::sync::OwnedSemaphorePermit),
    Public(PublicSlot),
}
impl HttpSlot {
    /// The public pool and place to record the task serving this session
    /// in, so a newcomer can close it to take its place.
    fn takeover(&self) -> Option<(Arc<PublicSessions>, u64)> {
        match self {
            Self::Public(slot) => Some((slot.pool.clone(), slot.id)),
            Self::Fixed(_) => None,
        }
    }
}
/// Built public reply bodies, in KiB, that may wait for their clients to
/// read them at once. A body larger than the whole allowance takes all of
/// it, so one largest valid reply is always served; past the allowance a
/// reply is replaced by a short error, so slow readers cannot make the node
/// hold a reply per session.
const PUBLIC_REPLY_MEMORY_KIB: usize = 64 * 1024;
/// Public reply bodies up to this size need no allowance: all sessions
/// together hold at most 2 MiB of them, and a wallet's short replies, such
/// as a broadcast's, are never replaced for want of it.
const PUBLIC_REPLY_UNHELD: usize = 64 * 1024;
/// The public website's sessions. When all are in use, a newcomer from a
/// network (an IPv4 /24 or IPv6 /48, or one address on a local network)
/// holding at least two fewer sessions than the network holding the most
/// closes that network's oldest session and takes its place. A few networks
/// therefore cannot keep everyone else out by holding sessions open, as a
/// reply that is never read would: shutting newcomers out takes about as
/// many networks as there are sessions. The loopback proxy's sessions carry
/// many visitors behind the proxy's own limits and are never closed this
/// way; its newcomers count as a network holding none.
struct PublicSessions {
    capacity: usize,
    live: Mutex<PublicSessionTable>,
}
#[derive(Default)]
struct PublicSessionTable {
    next: u64,
    /// Oldest first: each session's network and the task serving it.
    sessions: BTreeMap<u64, (Option<IpAddr>, Option<tokio::task::AbortHandle>)>,
}
struct PublicSlot {
    pool: Arc<PublicSessions>,
    id: u64,
}
impl PublicSessions {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            live: Mutex::default(),
        })
    }
    fn acquire(self: &Arc<Self>, network: Option<IpAddr>) -> Option<PublicSlot> {
        let mut live = self.live.unpoisoned();
        if live.sessions.len() >= self.capacity {
            let mut held: HashMap<IpAddr, usize> = HashMap::new();
            for net in live.sessions.values().filter_map(|(net, _)| *net) {
                *held.entry(net).or_default() += 1;
            }
            let own = network.and_then(|net| held.get(&net).copied()).unwrap_or(0);
            let most = held.values().copied().max().unwrap_or(0);
            if most < own.saturating_add(2) {
                return None;
            }
            let victim = live
                .sessions
                .iter()
                .find(|(_, (net, task))| task.is_some() && net.is_some_and(|n| held[&n] == most))
                .map(|(id, _)| *id)?;
            if let Some((_, Some(task))) = live.sessions.remove(&victim) {
                task.abort();
            }
        }
        let id = live.next;
        live.next += 1;
        live.sessions.insert(id, (network, None));
        Some(PublicSlot {
            pool: self.clone(),
            id,
        })
    }
    /// Record the task serving session `id`, unless it already ended.
    fn attach(&self, id: u64, task: tokio::task::AbortHandle) {
        if let Some(entry) = self.live.unpoisoned().sessions.get_mut(&id) {
            entry.1 = Some(task);
        }
    }
}
impl Drop for PublicSlot {
    fn drop(&mut self) {
        self.pool.live.unpoisoned().sessions.remove(&self.id);
    }
}

fn public_rpc_allowed(method: &str) -> bool {
    crate::explorer::METHODS.contains(&method)
        || matches!(
            method,
            "status"
                | "config"
                | "snapshot"
                | "account"
                | "address"
                | "validateaddress"
                | "quote"
                | "stash_quote"
                | "fee_quote"
                | "transfer_quote"
                | "grant_quote"
                | "governance"
                | "proposals"
                | "support"
                | "mempool"
                | "mining"
                | "preparetransaction"
                | "broadcasttransaction"
        )
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
    token: Option<String>,
}

fn validate_http_origin(host: &str, origin: Option<&str>, local: SocketAddr) -> Result<()> {
    let host = host.to_ascii_lowercase();
    let exact = local.to_string();
    let localhost = format!("localhost:{}", local.port());
    let default_host = if local.ip().is_ipv6() {
        format!("[{}]", local.ip())
    } else {
        local.ip().to_string()
    };
    let allowed = host == exact
        || (local.ip().is_loopback() && host == localhost)
        || (local.port() == 80
            && (host == default_host || (local.ip().is_loopback() && host == "localhost")));
    ensure!(allowed, "forbidden: unexpected Host header");
    if let Some(origin) = origin {
        ensure!(
            origin == format!("http://{host}"),
            "forbidden: Origin must match this node's exact HTTP origin"
        );
    }
    Ok(())
}
fn validate_public_http_origin(host: &str, origin: Option<&str>) -> Result<()> {
    // Public content carries no server-wallet authority. Allow a reverse proxy
    // to preserve its external Host, including HTTPS, without trusting any
    // Forwarded/X-Forwarded-* header or weakening the private listener's rules.
    let host = host.to_ascii_lowercase();
    ensure!(
        !host.is_empty()
            && host.len() <= 320
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)),
        "forbidden: invalid public Host header"
    );
    let url = reqwest::Url::parse(&format!("http://{host}"))
        .map_err(|_| anyhow!("forbidden: invalid public Host header"))?;
    ensure!(url.host_str().is_some(), "forbidden: public Host required");
    if let Some(origin) = origin {
        ensure!(
            origin == format!("http://{host}") || origin == format!("https://{host}"),
            "forbidden: Origin must match public Host"
        );
    }
    Ok(())
}
fn token_matches(candidate: Option<&str>, expected: &str) -> bool {
    let Some(candidate) = candidate else {
        return false;
    };
    if candidate.len() != expected.len() {
        return false;
    }
    candidate
        .as_bytes()
        .iter()
        .zip(expected.as_bytes())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// An HTTP/1.x request line's method and target: exactly one space separates
/// its three non-empty printable ASCII tokens, and it ends in CRLF.
fn http_request_line(line: &[u8]) -> Result<(&str, &str)> {
    ensure!(line.ends_with(b"\r\n"), "invalid HTTP request line");
    let line = std::str::from_utf8(line)?;
    let parts: Vec<_> = line[..line.len() - 2].split(' ').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_graphic()))
            && (parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0"),
        "invalid HTTP request line"
    );
    Ok((parts[0], parts[1]))
}

async fn read_http<R: AsyncBufRead + Unpin>(
    read: &mut R,
    local: SocketAddr,
    admission: &Session,
    public: bool,
    transaction_bytes: usize,
    session_token: Option<&str>,
) -> Result<HttpRequest> {
    // A proxy sends the whole head at once; an idle remote socket must not
    // hold a public session for the full request deadline.
    let head_timeout = if public {
        PUBLIC_HEADER_TIMEOUT
    } else {
        IO_TIMEOUT
    };
    let head = tokio::time::Instant::now() + head_timeout;
    let first = tokio::time::timeout_at(head, bounded_line(read, 4096)).await??;
    let (method, path) = http_request_line(&first)?;
    let (method, path) = (method.to_owned(), path.to_owned());
    ensure!(
        path.starts_with('/'),
        "absolute request targets are unsupported"
    );
    let mut headers = HashMap::new();
    let mut size = first.len();
    loop {
        let line = tokio::time::timeout_at(head, bounded_line(read, 4096)).await??;
        size += line.len();
        ensure!(size <= 16384, "HTTP headers too large");
        if line == b"\r\n" {
            break;
        }
        ensure!(line.ends_with(b"\r\n"), "invalid HTTP header line");
        let text = std::str::from_utf8(&line)?;
        let (name, value) = text.split_once(':').context("invalid HTTP header")?;
        ensure!(
            !name.is_empty() && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid HTTP header name"
        );
        let name = name.to_ascii_lowercase();
        ensure!(
            headers.insert(name, value.trim().to_owned()).is_none(),
            "duplicate HTTP header"
        );
    }
    // The shipped proxy overwrites X-Real-IP with the connecting address. Only
    // its loopback sessions are attributed; its own record still caps them all.
    if admission.proxied()
        && let Some(client) = headers.get("x-real-ip")
    {
        let client = client
            .parse::<IpAddr>()
            .map_err(|_| anyhow!("invalid X-Real-IP header"))?;
        if let Err(error) = admission.forwarded_for(client) {
            // A visitor its own quota refuses spends none of the proxy's.
            admission.refund_refused_visitor();
            return Err(error);
        }
    }
    ensure!(
        !headers.contains_key("transfer-encoding"),
        "chunked requests are unsupported"
    );
    let host = headers
        .get("host")
        .context("forbidden: Host header required")?;
    let origin = headers.get("origin").map(String::as_str);
    if public {
        validate_public_http_origin(host, origin)?;
    } else {
        validate_http_origin(host, origin, local)?;
    }
    if (path.starts_with("/api/") || path == "/rpc")
        && let Some(site) = headers.get("sec-fetch-site")
    {
        ensure!(
            site == "same-origin" || site == "none",
            "forbidden: cross-origin API request"
        );
    }
    let length = headers
        .get("content-length")
        .map(|s| -> Result<usize> {
            // 1*DIGIT only: no sign, whitespace or list syntax.
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "invalid HTTP content length"
            );
            Ok(s.parse::<usize>()?)
        })
        .transpose()?;
    let wallet = path == "/api/wallet" || path == "/api/wallet/manage";
    let length = if method == "POST" {
        // Route and authorize before any body byte is read or allocated.
        ensure!(path == "/rpc" || wallet, "resource not found");
        ensure!(
            !(public && wallet),
            "forbidden: server wallet endpoints are unavailable on public web"
        );
        ensure!(
            !wallet
                || token_matches(
                    headers.get("x-hashstash-token").map(String::as_str),
                    session_token.unwrap_or(""),
                ),
            "forbidden: invalid session token"
        );
        ensure!(
            headers
                .get("content-type")
                .and_then(|v| v.split(';').next())
                .map(str::trim)
                == Some("application/json"),
            "application/json content type required"
        );
        length.context("content length required")?
    } else {
        let length = length.unwrap_or(0);
        ensure!(length == 0, "body is unsupported for this HTTP method");
        length
    };
    ensure!(
        length
            <= if path == "/rpc" || path == "/api/wallet" {
                transaction_request_bytes(transaction_bytes)?
            } else {
                128 * 1024
            },
        "HTTP body too large"
    );
    if public && method == "GET" {
        // Pages and scripts are not wallet-critical calls: their request,
        // bytes and reply leave the proxy's essential reserve in place.
        admission.nonessential();
    }
    admission.request()?;
    admission.bytes(length.saturating_add(size))?;
    // Grow only with received bytes: a claimed length alone never allocates.
    let mut body = Vec::with_capacity(length.min(64 * 1024));
    (&mut *read)
        .take(length as u64)
        .read_to_end(&mut body)
        .await?;
    ensure!(body.len() == length, "HTTP body ended early");
    Ok(HttpRequest {
        method,
        path,
        body,
        token: headers.remove("x-hashstash-token"),
    })
}

/// After an early error the client may still be sending its body. Closing
/// with unread input usually resets the connection and discards the response,
/// so end the write side and discard a bounded amount of input first.
async fn finish_http<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(read: &mut R, write: &mut W) {
    finish_http_within(read, write, 256 * 1024).await;
}
async fn finish_http_within<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    read: &mut R,
    write: &mut W,
    limit: u64,
) {
    let _ = write.shutdown().await;
    let _ = timeout(
        Duration::from_secs(1),
        tokio::io::copy(&mut (&mut *read).take(limit), &mut tokio::io::sink()),
    )
    .await;
}

async fn http_response<W: AsyncWrite + Unpin>(
    write: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    http_response_limited(write, status, content_type, body, MAX_RESPONSE_FRAME).await
}
async fn http_response_limited<W: AsyncWrite + Unpin>(
    write: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
    limit: usize,
) -> Result<()> {
    write_http_response(write, status, content_type, body, limit, None).await
}
async fn write_http_response<W: AsyncWrite + Unpin>(
    write: &mut W,
    status: u16,
    content_type: &str,
    body: &[u8],
    limit: usize,
    retry_after: Option<u64>,
) -> Result<()> {
    ensure!(body.len() <= limit, "HTTP response too large");
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let retry_after = retry_after.map_or_else(String::new, |s| format!("Retry-After: {s}\r\n"));
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{retry_after}Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n\r\n",
        body.len()
    );
    timeout(reply_write_deadline(body.len()), async {
        write.write_all(header.as_bytes()).await?;
        write.write_all(body).await
    })
    .await??;
    Ok(())
}
/// A reply must be written within this base time plus its body's time at
/// `REPLY_WRITE_RATE` bytes per second, and never longer than `IO_TIMEOUT`.
/// A client that stops reading a short reply, such as a script, then holds
/// its session for seconds rather than the whole I/O deadline.
const REPLY_WRITE_BASE: Duration = Duration::from_secs(5);
const REPLY_WRITE_RATE: u64 = 64 * 1024;
fn reply_write_deadline(bytes: usize) -> Duration {
    let transfer = (bytes as u64).saturating_mul(1000) / REPLY_WRITE_RATE;
    REPLY_WRITE_BASE
        .saturating_add(Duration::from_millis(transfer))
        .min(IO_TIMEOUT)
}
fn http_error(message: &str) -> Value {
    json!({"error":{"message":message}})
}
/// A request refused on admission grounds rather than for its content. Its
/// work never ran, so it is answered, never dropped, and the answer says
/// when to resend it: 429 for the client's own quota (a cooldown or an
/// exhausted request, byte or work budget), 503 for local capacity that all
/// clients share. A charge beyond the quota's whole burst can never be
/// admitted and is answered 400. Each answer is a short fixed-shape error.
/// A public reply refused by its byte budget after the request ran is not
/// one of these: it is answered 200 with a JSON-RPC error.
struct HttpRefusal {
    status: u16,
    retry_after: Option<u64>,
    message: String,
}
impl HttpRefusal {
    fn busy(message: &str) -> Self {
        Self {
            status: 503,
            retry_after: Some(1),
            message: message.into(),
        }
    }
    fn of(error: &anyhow::Error) -> Option<Self> {
        if let Some(limited) = error.downcast_ref::<network_guard::Limited>() {
            Some(match limited.retry_after {
                Some(wait) => Self {
                    status: 429,
                    // Whole seconds, rounded up, so a client that waits them
                    // finds both the cooldown over and the charge refilled.
                    retry_after: Some((wait.as_secs() + u64::from(wait.subsec_nanos() > 0)).max(1)),
                    message: limited.reason.into(),
                },
                None => Self {
                    status: 400,
                    retry_after: None,
                    message: format!("{}: the request exceeds the whole budget", limited.reason),
                },
            })
        } else {
            error
                .downcast_ref::<network_guard::Busy>()
                .map(|busy| Self::busy(busy.0))
        }
    }
    async fn send<W: AsyncWrite + Unpin>(&self, write: &mut W, body: &Value) -> Result<()> {
        write_http_response(
            write,
            self.status,
            "application/json",
            &serde_json::to_vec(body)?,
            MAX_RESPONSE_FRAME,
            self.retry_after,
        )
        .await
    }
    async fn send_error<W: AsyncWrite + Unpin>(&self, write: &mut W) -> Result<()> {
        self.send(write, &http_error(&self.message)).await
    }
}
/// Answer an admission refusal with the endpoint's error body; any other
/// error still ends the session.
async fn refuse_request<W: AsyncWrite + Unpin>(
    write: &mut W,
    error: anyhow::Error,
    body: impl FnOnce(&str) -> Value,
) -> Result<()> {
    match HttpRefusal::of(&error) {
        Some(refusal) => refusal.send(write, &body(&refusal.message)).await,
        None => Err(error),
    }
}
/// Answers to HTTP connections refused before their session starts, in
/// flight at once per listener. Past this a refused connection is closed
/// unanswered, so refusals cannot hold more than this bounded capacity.
const HTTP_REFUSAL_REPLIES: usize = 16;
/// A refused connection's request head is awaited for at most this long,
/// within the usual 16 KiB head limit, because HTTP clients expect the answer
/// after their request; one that sends no well-formed head closes unanswered.
const HTTP_REFUSAL_HEAD: Duration = Duration::from_secs(2);
/// One refusal answer's write deadline. Discarding the client's unread body
/// afterwards, so the answer is not lost to a reset, has its own bounded
/// time in `finish_http_within`.
const HTTP_REFUSAL_WRITE: Duration = Duration::from_secs(1);
/// Unread body bytes discarded after an answer to a connection refused before
/// its session started: enough for an ordinary RPC or wallet request, and no
/// more than the head limit, since such a connection's data is not charged.
const HTTP_REFUSAL_DRAIN: u64 = 16 * 1024;
/// Answer a refused HTTP connection while a refusal reply slot is free and
/// its address was not already answered within the Retry-After it was given
/// (`NetworkGuard::answer_refusal`); otherwise close it unanswered, as
/// before. Admitted sessions never wait for these.
fn refuse_connection(
    clients: &mut tokio::task::JoinSet<()>,
    replies: &Arc<Semaphore>,
    guard: &NetworkGuard,
    address: SocketAddr,
    stream: TcpStream,
    refusal: HttpRefusal,
) {
    let Ok(permit) = replies.clone().try_acquire_owned() else {
        return;
    };
    let window = Duration::from_secs(refusal.retry_after.unwrap_or(1));
    if !guard.answer_refusal(address.ip(), Surface::Rpc, window) {
        return;
    }
    clients.spawn(async move {
        let _permit = permit;
        refuse_http(stream, refusal).await;
    });
}
/// Answer a connection refused before its session started, such as one
/// arriving during its address's cooldown or while every session is busy.
/// It is answered only after a request line that passes `read_http`'s check
/// and a bounded head; nothing else in the head is interpreted or charged.
async fn refuse_http(stream: TcpStream, refusal: HttpRefusal) {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let head = async {
        let first = bounded_line(&mut read, 4096).await?;
        http_request_line(&first)?;
        let mut size = first.len();
        loop {
            let line = bounded_line(&mut read, 4096).await?;
            size += line.len();
            ensure!(size <= 16384, "HTTP headers too large");
            if line == b"\r\n" {
                return anyhow::Ok(());
            }
            ensure!(line.ends_with(b"\r\n"), "invalid HTTP header line");
        }
    };
    if !matches!(timeout(HTTP_REFUSAL_HEAD, head).await, Ok(Ok(()))) {
        return;
    }
    if matches!(
        timeout(HTTP_REFUSAL_WRITE, refusal.send_error(&mut write)).await,
        Ok(Ok(()))
    ) {
        finish_http_within(&mut read, &mut write, HTTP_REFUSAL_DRAIN).await;
    }
}
/// Like peer replies, public-web replies spend the byte budget without
/// penalty: the node chose their size, so an exhausted budget only asks the
/// client to retry. The public byte burst covers the whole response frame, so
/// one maximal valid reply waits for refill instead of never fitting. An
/// explorer reply, whose method price is flat, also pays `work` for the bytes
/// it built.
fn charge_public_reply(admission: &Session, bytes: usize, work: usize) -> Result<()> {
    admission.outgoing(bytes, work)
}
/// Settle a built public reply before it is written. The part of its
/// `reserved` work that its `reply_work` did not use returns; its bytes are
/// held against the public reply allowance until written; and its bytes and
/// any work beyond the reservation are charged. A reply that does not fit
/// the allowance or the byte budget is replaced by a short JSON-RPC error
/// that keeps its status, because the request has already run; its reserved
/// work stays paid either way. Returns the held allowance.
fn settle_public_reply(
    admission: &Session,
    replies: &Arc<Semaphore>,
    body: &mut Vec<u8>,
    reply_work: usize,
    reserved: usize,
    rpc_error: impl Fn(&str) -> Value,
) -> Result<Option<tokio::sync::OwnedSemaphorePermit>> {
    admission.refund_work(reserved.saturating_sub(reply_work));
    let unreserved = reply_work.saturating_sub(reserved);
    // A reply is held in memory until its client has read it. A large one is
    // held against the allowance and, past it, replaced at once rather than
    // held, however many sessions read slowly.
    let mut held = None;
    if body.len() > PUBLIC_REPLY_UNHELD {
        let kib = body.len().div_ceil(1024).min(PUBLIC_REPLY_MEMORY_KIB);
        held = replies.clone().try_acquire_many_owned(kib as u32).ok();
        if held.is_none() {
            *body = serde_json::to_vec(&rpc_error("public replies are busy; try again"))?;
        }
    }
    if charge_public_reply(admission, body.len(), unreserved).is_err() {
        // Never a cooldown: the node chose the reply's size. The request has
        // already run, so this is no admission refusal and keeps the status
        // its result had: 429 and 503 promise that nothing ran, and a
        // broadcast whose reply is replaced here may already be relayed.
        *body = serde_json::to_vec(&rpc_error(
            "public response byte budget exhausted; try again",
        ))?;
        held = None;
    }
    Ok(held)
}
/// Explorer replies pay one work unit per this many bytes they return, once
/// they are built, in addition to their method price. Public work bursts
/// admit the work of one largest reply.
const EXPLORER_REPLY_BYTES_PER_WORK: usize = network_guard::REPLY_BYTES_PER_WORK as usize;
/// One explorer record's bytes per byte of a largest transaction: its raw
/// and data hexadecimal and its decoded operation, with room to spare.
const EXPLORER_RECORD_EXPANSION: usize = 8;
/// The reply work reserved for a public explorer page before it is built:
/// that of `MAX_PAGE` records, each as large as a largest transaction's
/// record at `capacity`, within the page budget. A larger page, such as one
/// whose first record alone exceeds the budget, pays the rest with its bytes.
fn explorer_reply_reserve(capacity: usize) -> usize {
    let rows = crate::explorer::MAX_PAGE as usize;
    rows.saturating_mul(capacity.saturating_mul(EXPLORER_RECORD_EXPANSION))
        .min(JSON_PAGE_BYTES)
        / EXPLORER_REPLY_BYTES_PER_WORK
}
/// Public calls a wallet needs to show its balance, to price, prepare and
/// broadcast a transfer, a Stash deposit or redemption, and to check its
/// support for a refund. Only these may spend the reserve that the public
/// website's shared budget keeps; explorer and other reads must leave it.
fn public_rpc_essential(method: &str) -> bool {
    matches!(
        method,
        "status"
            | "snapshot"
            | "account"
            | "fee_quote"
            | "transfer_quote"
            | "stash_quote"
            | "support"
            | "preparetransaction"
            | "broadcasttransaction"
    )
}

/// One JSON-RPC answer's bytes, built where the result was computed. A
/// metered read, or a mined batch before its first block, refused by the
/// client's budget did not run: its error carries the refusal status. A body
/// beyond `limit` is replaced by a short error.
fn rpc_reply(
    id: &Value,
    result: Result<Value>,
    limit: usize,
) -> Result<(Vec<u8>, Option<HttpRefusal>)> {
    let rpc_error =
        |message: &str| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message}});
    let mut refusal = None;
    let response = match result {
        Ok(v) => json!({"jsonrpc":"2.0","id":id,"result":v}),
        Err(e) => {
            refusal = HttpRefusal::of(&e);
            let message = refusal
                .as_ref()
                .map_or_else(|| e.to_string(), |r| r.message.clone());
            rpc_error(&message)
        }
    };
    let mut body = serde_json::to_vec(&response)?;
    drop(response);
    if body.len() > limit {
        body = serde_json::to_vec(&rpc_error("RPC response exceeds the local response limit"))?;
    }
    Ok((body, refusal))
}

async fn http_session(
    node: Node,
    stream: TcpStream,
    http: Arc<HttpContext>,
    admission: Session,
) -> Result<()> {
    let local = stream.local_addr()?;
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let transaction_bytes = {
        let view = node.read_view()?;
        view.chain
            .config
            .transaction_bytes(&view.chain.tip_state().settings)
    };
    let known_block_bytes = node.known_block_bytes.load(Ordering::Acquire);
    let response_frame = http_response_frame(transaction_bytes, known_block_bytes)?;
    // Explorer records follow the greatest validated capacity, as the frame.
    let page_capacity =
        transaction_bytes.max(usize::try_from(known_block_bytes).unwrap_or(usize::MAX));
    if http.public {
        // The public guard never sees the private capacity updates. Its byte
        // burst admits one response frame, so a large valid reply waits for
        // refill instead of never fitting, and it follows a lower capacity.
        http.guard.set_frame(response_frame)?;
    }
    // Every RPC work burst admits one largest valid request at this
    // capacity, such as a broadcast of a largest transaction.
    http.guard
        .allow_rpc_work(largest_request_work(transaction_bytes)?)?;
    let request = match timeout(
        IO_TIMEOUT,
        read_http(
            &mut read,
            local,
            &admission,
            http.public,
            transaction_bytes,
            http.session_token.as_deref(),
        ),
    )
    .await
    {
        Ok(Ok(request)) => request,
        failed => {
            // A quota refused the head or body before it was read: answer it
            // and discard the unread body, without a further framing penalty.
            if let Ok(Err(e)) = &failed
                && let Some(refusal) = HttpRefusal::of(e)
            {
                let sent = refusal.send_error(&mut write).await;
                if sent.is_ok() {
                    finish_http(&mut read, &mut write).await;
                }
                return sent;
            }
            let (message, drain) = match failed {
                Ok(Err(e)) if !e.is::<tokio::time::error::Elapsed>() => (e.to_string(), true),
                _ => ("HTTP request timed out".into(), false),
            };
            let status = if message.starts_with("forbidden:") {
                403
            } else if message == "resource not found" {
                404
            } else {
                // Framing errors and expired deadlines. Refused origins and
                // unknown paths stay unpenalized: ordinary browsers cause them.
                admission.framing_error();
                400
            };
            let sent = http_response(
                &mut write,
                status,
                "application/json",
                &serde_json::to_vec(&http_error(&message))?,
            )
            .await;
            if drain && sent.is_ok() {
                finish_http(&mut read, &mut write).await;
            }
            return sent;
        }
    };
    if request.method == "GET" {
        let asset = match request.path.as_str() {
            "/" | "/index.html" => Some((
                "text/html; charset=utf-8",
                include_bytes!("../ui/index.html").as_slice(),
            )),
            "/app.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/app.js").as_slice(),
            )),
            "/chat.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/chat.js").as_slice(),
            )),
            "/mail-crypto.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/mail-crypto.js").as_slice(),
            )),
            "/transaction-mail.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/transaction-mail.js").as_slice(),
            )),
            "/mail.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/mail.js").as_slice(),
            )),
            "/proposal-data.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/proposal-data.js").as_slice(),
            )),
            "/explorer.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/explorer.js").as_slice(),
            )),
            "/vendor/noble.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/vendor/noble.js").as_slice(),
            )),
            "/browser-wallet.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/browser-wallet.js").as_slice(),
            )),
            "/amounts.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/amounts.js").as_slice(),
            )),
            "/shares.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/shares.js").as_slice(),
            )),
            "/address.js" => Some((
                "application/javascript; charset=utf-8",
                include_bytes!("../ui/address.js").as_slice(),
            )),
            "/style.css" => Some((
                "text/css; charset=utf-8",
                include_bytes!("../ui/style.css").as_slice(),
            )),
            _ => None,
        };
        if let Some((mime, body)) = asset {
            // A public page or script spends the byte budget like any reply.
            // Nothing ran, so a refusal asks the client to wait (429).
            if http.public
                && let Err(e) = charge_public_reply(&admission, body.len(), 0)
            {
                return refuse_request(&mut write, e, http_error).await;
            }
            return http_response(&mut write, 200, mime, body).await;
        }
        if request.path == "/api/session" {
            let chain_id = node.read_view()?.chain.chain_id();
            // Loopback is shared by every local account and service, so the
            // session token is never served here. Clients that may use server
            // wallets read it from the owner-only session token file and
            // present it to see them: their names and addresses would link
            // the operator's accounts for any other local process.
            let wallets = !http.public
                && token_matches(
                    request.token.as_deref(),
                    http.session_token.as_deref().unwrap_or(""),
                );
            let mut data = if wallets {
                node.wallet_read(WalletStore::status).await?
            } else {
                json!({"address_hrp":address::hrp(&chain_id)})
            };
            data["browser_wallet"] = json!(true);
            data["public_web"] = json!(http.public);
            data["chain_id"] = json!(hex::encode(chain_id));
            data["miner"] = json!(hex::encode(node.miner));
            return http_response(
                &mut write,
                200,
                "application/json",
                &serde_json::to_vec(&data)?,
            )
            .await;
        }
        return http_response(
            &mut write,
            404,
            "application/json",
            &serde_json::to_vec(&http_error("resource not found"))?,
        )
        .await;
    }
    if request.method != "POST" {
        return http_response(
            &mut write,
            405,
            "application/json",
            &serde_json::to_vec(&http_error("method not allowed"))?,
        )
        .await;
    }
    if request.path != "/rpc"
        && request.path != "/api/wallet"
        && request.path != "/api/wallet/manage"
    {
        return http_response(
            &mut write,
            404,
            "application/json",
            &serde_json::to_vec(&http_error("resource not found"))?,
        )
        .await;
    }
    let wallet_endpoint = request.path == "/api/wallet" || request.path == "/api/wallet/manage";
    // Reject before looking at the server wallet store or any supplied token.
    if http.public && wallet_endpoint {
        return http_response(
            &mut write,
            403,
            "application/json",
            &serde_json::to_vec(&http_error(
                "server wallet endpoints are unavailable on public web",
            ))?,
        )
        .await;
    }
    let disabled_signer =
        request.path == "/api/wallet" && !node.wallet_read(WalletStore::hot_enabled).await?;
    if wallet_endpoint
        && (!token_matches(
            request.token.as_deref(),
            http.session_token.as_deref().unwrap_or(""),
        ) || disabled_signer)
    {
        return http_response(
            &mut write,
            403,
            "application/json",
            &serde_json::to_vec(&http_error(if disabled_signer {
                "no hot wallet is selected"
            } else {
                "invalid session token"
            }))?,
        )
        .await;
    }
    let value = parse_value_with_slots(
        request.body,
        match request.path.as_str() {
            "/api/wallet" => JsonBody::HotWallet,
            "/rpc" => JsonBody::Rpc,
            _ => JsonBody::Ordinary,
        },
        http.parsers.clone(),
    )
    .await;
    let value = match value {
        Ok(value) => value,
        Err(e) => {
            if let Some(refusal) = HttpRefusal::of(&e) {
                return refusal.send_error(&mut write).await;
            }
            admission.malformed();
            return http_response(
                &mut write,
                400,
                "application/json",
                &serde_json::to_vec(&http_error(&e.to_string()))?,
            )
            .await;
        }
    };
    if request.path == "/api/wallet/manage" {
        if let Err(e) = admission.work(1) {
            return refuse_request(&mut write, e, http_error).await;
        }
        let Some(permit) = node.wallet_worker().await? else {
            return HttpRefusal::busy("wallet workers busy")
                .send_error(&mut write)
                .await;
        };
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let request: ManageRequest = serde_json::from_value(value)?;
            node.wallets_locked()?.manage(request)
        })
        .await
        .context("wallet manager worker failed")?;
        // A backup body holds a key; it is wiped once written.
        let (status, body) = match result {
            Ok(body) => (200, body),
            Err(e) => (
                400,
                Zeroizing::new(serde_json::to_vec(&http_error(&e.to_string()))?),
            ),
        };
        return http_response(&mut write, status, "application/json", &body).await;
    }
    if request.path == "/api/wallet" {
        // Signing and submitting reselects the pending pool with the newcomer.
        if let Err(e) = admission.work(pool_change_work(node.read_view()?.mempool.len())) {
            return refuse_request(&mut write, e, http_error).await;
        }
        let Some(permit) = node.wallet_worker().await? else {
            return HttpRefusal::busy("wallet workers busy")
                .send_error(&mut write)
                .await;
        };
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            node.wallet_submit(serde_json::from_value::<HotWalletRequest>(value)?)
        })
        .await
        .context("wallet worker failed")?;
        let (status, value) = match result {
            Ok(id) => (200, json!({"transaction_id":hex::encode(id)})),
            Err(e) => (400, http_error(&e.to_string())),
        };
        return http_response(
            &mut write,
            status,
            "application/json",
            &serde_json::to_vec(&value)?,
        )
        .await;
    }
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let params = value.get("params").cloned().unwrap_or(json!({}));
    if http.public {
        let error = if !value.is_object()
            || value.get("jsonrpc") != Some(&json!("2.0"))
            || !value.get("method").is_some_and(Value::is_string)
            || !params.is_object()
        {
            Some((
                400,
                -32600,
                "one JSON-RPC 2.0 request with object params is required",
            ))
        } else if !public_rpc_allowed(&method) {
            Some((403, -32601, "method is unavailable on public web"))
        } else {
            None
        };
        if let Some((status, code, message)) = error {
            return http_response(
                &mut write,
                status,
                "application/json",
                &serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
                )?,
            )
            .await;
        }
    }
    // Development mining has its own single worker, so looping `mine` calls
    // never hold the mutation workers that sends and the faucet need.
    let mutation = matches!(
        method.as_str(),
        "template"
            | "submitblock"
            | "submittransaction"
            | "getblock"
            | "blockreceipt"
            | "preparetransaction"
            | "broadcasttransaction"
    );
    let mut cost = rpc_cost(&method, &params);

    if matches!(
        method.as_str(),
        "submittransaction" | "template" | "preparetransaction" | "broadcasttransaction"
    ) {
        cost = cost.saturating_add(pool_change_work(node.read_view()?.mempool.len()));
    } else if method == "mine" {
        // Reserve individual blocks when their actual queue is known.
        cost = 1;
    }

    let rpc_error =
        |message: &str| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message}});
    let public = http.public;
    // A public broadcast waits while the admission budget reserved for
    // public broadcasts, which relays never spend, is spent, rather than
    // queueing for the node lock. Nothing ran, so it is answered 429 before
    // its work is charged.
    if public
        && method == "broadcasttransaction"
        && let Some(wait) = node.public_selection_wait()
    {
        let busy = network_guard::Limited {
            reason: "transaction admission is busy",
            retry_after: Some(wait),
        };
        return refuse_request(&mut write, busy.into(), rpc_error).await;
    }
    if public && !public_rpc_essential(&method) {
        admission.nonessential();
    }
    if let Err(e) = admission.work(cost) {
        return refuse_request(&mut write, e, rpc_error).await;
    }
    let explorer = crate::explorer::METHODS.contains(&method.as_str());
    // A valid record may need more than the fixed service frame once
    // governance raises capacity; the frame then follows that capacity.
    let limit = response_frame;
    // Work reserved for a public explorer reply before it is built.
    let mut reserved = 0;
    let (mut body, refusal, admission) =
        if value.get("jsonrpc") != Some(&Value::String("2.0".into())) {
            let (body, refusal) = rpc_reply(&id, Err(anyhow!("jsonrpc must be 2.0")), limit)?;
            (body, refusal, admission)
        } else {
            let slots = if method == "mine" {
                node.dev_mining.clone()
            } else if mutation {
                http.mutations.clone()
            } else {
                http.workers.clone()
            };
            let Ok(permit) = timeout(IO_TIMEOUT, slots.acquire_owned()).await else {
                let busy = HttpRefusal::busy("RPC workers busy");
                return busy.send(&mut write, &rpc_error(&busy.message)).await;
            };
            let permit = permit?;
            // A public explorer reply pays one work unit per KiB it returns.
            // That work is reserved for a largest page at this capacity
            // before the page is built, while a worker is held, so a client
            // cannot skip it by leaving too little budget for the reply's
            // bytes; what the page did not use returns once its size is
            // known. Nothing ran yet, so a refusal returns the method price
            // and asks the client to wait.
            if public && explorer {
                let reserve = explorer_reply_reserve(page_capacity);
                if let Err(e) = admission.outgoing(0, reserve) {
                    drop(permit);
                    admission.refund_work(cost);
                    return refuse_request(&mut write, e, rpc_error).await;
                }
                reserved = reserve;
            }
            let id = id.clone();
            // The reply is serialized, and its JSON tree freed, on this worker:
            // a page may hold millions of values, too many for a runtime thread.
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let result = if public {
                    node.public_rpc(&method, params, &admission)
                } else {
                    node.rpc_with_admission(&method, params, Some(&admission))
                };
                rpc_reply(&id, result, limit).map(|(body, refusal)| (body, refusal, admission))
            })
            .await
            .context("RPC worker failed")??
        };
    let explorer_work = if explorer {
        body.len() / EXPLORER_REPLY_BYTES_PER_WORK
    } else {
        0
    };
    // Held until the reply is written.
    let _held = match (&http.replies, public) {
        (Some(replies), true) => settle_public_reply(
            &admission,
            replies,
            &mut body,
            explorer_work,
            reserved,
            rpc_error,
        )?,
        _ => None,
    };
    let (status, retry_after) = refusal.map_or((200, None), |r| (r.status, r.retry_after));
    write_http_response(
        &mut write,
        status,
        "application/json",
        &body,
        limit,
        retry_after,
    )
    .await
}

fn rpc_cost(method: &str, params: &Value) -> usize {
    let base: usize = match method {
        "explorer_account" | "explorer_transaction" | "explorer_chat" | "explorer_mail" => {
            MAX_ADAPTIVE_MEMPOOL + 64
        }
        "explorer_blocks" | "explorer_transactions" | "explorer_block" | "explorer_governance" => {
            128
        }
        "mine" => {
            params
                .get("count")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .min(1000) as usize
                * MAX_MEMPOOL
        }
        "submittransaction" | "template" | "preparetransaction" | "broadcasttransaction" => {
            MAX_MEMPOOL + 1
        }
        "submitblock" => params
            .get("block")
            .unwrap_or(params)
            .get("transactions")
            .and_then(Value::as_array)
            .map_or(1, |v| v.len() + 1),
        "grant_quote" => 4096,
        "account" | "quote" | "stash_quote" | "transfer_quote" | "fee_quote" | "status" => 8,
        "governance" => 16,
        // One key validation plus up to three holdings reads, with no curve
        // valuation. Oversized requests are rejected before reading accounts.
        "snapshot" => {
            48 + params
                .get("keys")
                .and_then(Value::as_array)
                .map_or(0, |keys| keys.len().min(MAX_SNAPSHOT_KEYS))
                * 4
        }
        _ => 1,
    };
    // Only a method that decodes an operation or a signed transaction from
    // its parameters pays for the grant recipients or raw bytes it may
    // validate. Other methods never read such fields, so a list there costs
    // only the request bytes it took to send.
    let paths: &[&str] = match method {
        "preparetransaction" | "fee_quote" | "transfer_quote" => {
            &["/operation/Propose/proposal/Grant/payments"]
        }
        "submittransaction" => &[
            "/body/operation/Propose/proposal/Grant/payments",
            "/transaction/body/operation/Propose/proposal/Grant/payments",
        ],
        _ => &[],
    };
    let recipients = paths
        .iter()
        .filter_map(|path| params.pointer(path).and_then(Value::as_array))
        .map(Vec::len)
        .max()
        .unwrap_or(0);
    let raw_work = match method {
        // A raw grant may carry one key validation per 34 encoded bytes.
        // Ordinary large data pays the same bounded parsing-work allowance.
        "broadcasttransaction" => params
            .get("raw")
            .and_then(Value::as_str)
            .map_or(0, |raw| raw.len() / (2 * 34)),
        _ => 0,
    };
    base.saturating_add(recipients).saturating_add(raw_work)
}
/// The work of one largest valid request at a capacity of
/// `transaction_bytes`: a broadcast whose hexadecimal transaction fills the
/// HTTP body limit pays its raw parsing work, its method base and a full
/// pool's reselection. RPC work bursts admit it (`allow_rpc_work`), so a
/// valid transaction is never refused, with a penalty, as larger than a
/// whole budget.
fn largest_request_work(transaction_bytes: usize) -> Result<usize> {
    Ok((transaction_request_bytes(transaction_bytes)? / (2 * 34))
        .saturating_add(MAX_MEMPOOL + 1)
        .saturating_add(pool_change_work(MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG)))
}

#[cfg(test)]
mod capacity_work_tests {
    use super::*;

    #[test]
    fn transaction_http_allowance_tracks_capacity_and_never_wraps() {
        let capacity = 40 * 1024 * 1024 + 173;
        assert_eq!(
            transaction_request_bytes(capacity).unwrap(),
            capacity * 2 + 128 * 1024
        );
        assert_eq!(
            transaction_request_bytes(usize::MAX).unwrap(),
            isize::MAX as usize
        );
        assert!(
            admission_frame_bytes(&Config::devnet(), capacity as u64).unwrap()
                >= transaction_request_bytes(capacity).unwrap() + 16 * 1024
        );
    }

    #[test]
    fn pool_changes_pay_for_the_pool_they_reselect() {
        // The load check's 64-entry pool pays the per-block floor, not a
        // full 4,096-entry selection: a 1,048,576-unit burst admits 4,096
        // such submissions instead of 255.
        assert_eq!(pool_change_work(0), MAX_MEMPOOL);
        assert_eq!(pool_change_work(64), MAX_MEMPOOL);
        assert_eq!(
            pool_change_work(MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG),
            MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG + 1
        );
        assert_eq!(pool_change_work(usize::MAX), usize::MAX);
    }

    #[test]
    fn admission_refusals_map_to_retryable_http_answers() {
        let limited = |retry_after| {
            anyhow::Error::from(network_guard::Limited {
                reason: "network rate budget exhausted",
                retry_after,
            })
        };
        let quota = HttpRefusal::of(&limited(Some(Duration::from_millis(1)))).unwrap();
        assert_eq!((quota.status, quota.retry_after), (429, Some(1)));
        assert_eq!(quota.message, "network rate budget exhausted");
        let quota = HttpRefusal::of(&limited(Some(Duration::from_millis(16_001)))).unwrap();
        assert_eq!(quota.retry_after, Some(17));
        // Context added on the way out keeps the refusal recognizable.
        let wrapped = limited(Some(Duration::ZERO)).context("while charging");
        assert_eq!(HttpRefusal::of(&wrapped).unwrap().retry_after, Some(1));
        let never = HttpRefusal::of(&limited(None)).unwrap();
        assert_eq!((never.status, never.retry_after), (400, None));
        let busy = network_guard::Busy("JSON parser workers busy").into();
        let busy = HttpRefusal::of(&busy).unwrap();
        assert_eq!((busy.status, busy.retry_after), (503, Some(1)));
        assert!(HttpRefusal::of(&anyhow!("transaction not valid in next block")).is_none());
    }

    #[tokio::test]
    async fn refusal_answers_are_short_and_carry_retry_after() {
        let refusal = HttpRefusal::of(&anyhow::Error::from(network_guard::Limited {
            reason: "temporary network cooldown",
            retry_after: Some(Duration::from_millis(250)),
        }))
        .unwrap();
        let mut wire = Vec::new();
        refusal.send_error(&mut wire).await.unwrap();
        let text = String::from_utf8(wire).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{text}"
        );
        assert!(text.contains("\r\nRetry-After: 1\r\n"), "{text}");
        assert!(text.contains("\r\nConnection: close\r\n"), "{text}");
        let (_, body) = text.split_once("\r\n\r\n").unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"error":{"message":"temporary network cooldown"}})
        );
        // Bounded, fixed-shape answer: no amplification of a tiny request.
        assert!(text.len() < 1024, "{}", text.len());
    }

    #[test]
    fn rpc_replies_are_serialized_by_their_worker_within_the_response_limit() {
        let id = json!(7);
        let decode = |body: &[u8]| serde_json::from_slice::<Value>(body).unwrap();
        let (body, refusal) = rpc_reply(&id, Ok(json!({"page":"x".repeat(100)})), 1024).unwrap();
        assert_eq!(decode(&body)["result"]["page"].as_str().unwrap().len(), 100);
        assert!(refusal.is_none());
        // An oversized result becomes the short limit error, keeping its ID.
        let (body, refusal) = rpc_reply(&id, Ok(json!("x".repeat(2048))), 1024).unwrap();
        let reply = decode(&body);
        assert_eq!(reply["id"], 7);
        assert_eq!(
            reply["error"]["message"],
            "RPC response exceeds the local response limit"
        );
        assert!(refusal.is_none() && body.len() < 1024);
        // A refused request keeps its refusal status for the async writer.
        let limited = anyhow::Error::from(network_guard::Limited {
            reason: "transaction admission is busy",
            retry_after: Some(Duration::from_millis(1500)),
        });
        let (body, refusal) = rpc_reply(&id, Err(limited), 1024).unwrap();
        let refusal = refusal.unwrap();
        assert_eq!((refusal.status, refusal.retry_after), (429, Some(2)));
        assert_eq!(
            decode(&body)["error"]["message"],
            "transaction admission is busy"
        );
    }

    #[test]
    fn a_largest_valid_broadcast_fits_every_rpc_work_burst() {
        // At the governed maximum and at 8 MiB, a broadcast filling the HTTP
        // body limit with its hexadecimal transaction, against a full pool,
        // was charged more than the private burst (1,048,576) and a public
        // visitor's (197,632): refused for good with a penalty.
        for capacity in [crate::config::MAX_GOVERNED_BLOCK_BYTES as usize, 8 << 20] {
            let raw = "00".repeat(transaction_request_bytes(capacity).unwrap() / 2 - 64);
            let cost = rpc_cost("broadcasttransaction", &json!({ "raw": raw }))
                + pool_change_work(MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG);
            let largest = largest_request_work(capacity).unwrap();
            assert!(cost <= largest, "{cost} > {largest}");
            assert!(largest > 197_632);
            for guard in [NetworkGuard::default(), NetworkGuard::for_public_web()] {
                let guard = Arc::new(guard);
                guard.set_frame(MAX_RESPONSE_FRAME).unwrap();
                guard.allow_rpc_work(largest).unwrap();
                let session = guard
                    .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
                    .unwrap();
                if session.proxied() {
                    session
                        .forwarded_for("198.51.100.5".parse().unwrap())
                        .unwrap();
                }
                session.work(cost).unwrap();
            }
        }
        // At launch capacity the allowance changes no burst.
        assert!(largest_request_work(16 * 1024).unwrap() < 131_072);
    }

    #[test]
    fn short_replies_must_be_written_within_seconds_and_long_ones_within_the_deadline() {
        assert_eq!(reply_write_deadline(0), REPLY_WRITE_BASE);
        // A script of about 200 KiB that a client never reads holds its
        // session about 8 seconds, not the whole 15-second I/O deadline.
        let script = include_bytes!("../ui/app.js").len();
        let deadline = reply_write_deadline(script);
        assert!(
            deadline > REPLY_WRITE_BASE + Duration::from_secs(2) && deadline < IO_TIMEOUT,
            "{deadline:?}"
        );
        assert_eq!(reply_write_deadline(MAX_RESPONSE_FRAME), IO_TIMEOUT);
        assert_eq!(reply_write_deadline(usize::MAX), IO_TIMEOUT);
    }

    #[tokio::test]
    async fn a_full_public_pool_closes_the_oldest_session_of_the_network_holding_most() {
        let pool = PublicSessions::new(4);
        let net = |n: u8| Some(IpAddr::from([198, 51, n, 0]));
        // Each session's task never ends by itself, like one whose client
        // never reads its reply.
        let open = |network| {
            let slot = pool.acquire(network)?;
            let task = tokio::spawn(std::future::pending::<()>());
            pool.attach(slot.id, task.abort_handle());
            Some((slot, task))
        };
        // One network holds three of four sessions, as a few addresses
        // holding unread replies would; another holds the fourth. Before,
        // every newcomer was refused until their deadlines ran out.
        let (first, oldest) = open(net(1)).unwrap();
        let (second, next) = open(net(1)).unwrap();
        let rest = [open(net(1)).unwrap(), open(net(2)).unwrap()];
        // A newcomer from a third network closes the first one's oldest.
        let third = open(net(3)).unwrap();
        assert!(oldest.await.unwrap_err().is_cancelled());
        // The first network, now at two, cannot take another place, and
        // neither can the second, holding one.
        assert!(open(net(1)).is_none() && open(net(2)).is_none());
        // The loopback proxy's newcomers count as a network holding none.
        let proxied = open(None).unwrap();
        assert!(next.await.unwrap_err().is_cancelled());
        // Each network now holds one place: nobody can take another's.
        assert!(open(net(4)).is_none() && open(None).is_none());
        // The proxy's own sessions are never closed this way.
        drop((first, second, rest, third));
        let proxy: Vec<_> = (0..3).map(|_| open(None).unwrap()).collect();
        assert!(open(net(5)).is_none());
        drop((proxy, proxied));
        assert!(open(net(5)).is_some());
    }

    #[test]
    fn explorer_reply_work_is_paid_even_when_its_bytes_are_refused() {
        const MIB: usize = 1024 * 1024;
        let guard = Arc::new(NetworkGuard::for_public_web());
        let visitor = guard
            .admit("198.51.100.30".parse().unwrap(), Surface::Rpc)
            .unwrap();
        let replies = Arc::new(Semaphore::new(PUBLIC_REPLY_MEMORY_KIB));
        let error = |message: &str| json!({"error": message});
        // The reservation at the governed maximum: a whole page budget.
        let reserve = explorer_reply_reserve(crate::config::MAX_GOVERNED_BLOCK_BYTES as usize);
        assert_eq!(reserve, 32 * 1024);
        // The visitor spends its byte burst, so its next reply's bytes are
        // refused. Its explorer page's work was reserved before the page was
        // built, so the 16,384 units the 16 MiB page pays stay paid.
        visitor.outgoing(66 * MIB / 8, 0).unwrap();
        visitor.outgoing(0, reserve).unwrap();
        let mut body = vec![b'x'; 16 * MIB];
        let held =
            settle_public_reply(&visitor, &replies, &mut body, 16 * 1024, reserve, error).unwrap();
        assert!(held.is_none());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            "public response byte budget exhausted; try again"
        );
        assert_eq!(replies.available_permits(), PUBLIC_REPLY_MEMORY_KIB);
        // Without that payment the whole 131,072-unit burst would remain.
        assert!(visitor.outgoing(0, 131_072 - 8 * 1024).is_err());
        // A page smaller than the reservation pays only its own work, and
        // its bytes are held against the reply allowance until written.
        let reader = guard
            .admit("198.51.101.30".parse().unwrap(), Surface::Rpc)
            .unwrap();
        reader.outgoing(0, reserve).unwrap();
        let mut body = vec![b'x'; MIB];
        let held = settle_public_reply(&reader, &replies, &mut body, 1024, reserve, error).unwrap();
        assert_eq!(body.len(), MIB);
        assert_eq!(replies.available_permits(), PUBLIC_REPLY_MEMORY_KIB - 1024);
        reader.outgoing(0, 131_072 - 2 * 1024).unwrap();
        // Past the allowance a reply is replaced at once rather than held.
        let crowded = Arc::new(Semaphore::new(512));
        let mut body = vec![b'x'; MIB];
        let other = guard
            .admit("198.51.102.30".parse().unwrap(), Surface::Rpc)
            .unwrap();
        let _held_elsewhere = crowded.clone().try_acquire_many_owned(256).unwrap();
        assert!(
            settle_public_reply(&other, &crowded, &mut body, 0, 0, error)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap()["error"],
            "public replies are busy; try again"
        );
        drop(held);
        assert_eq!(replies.available_permits(), PUBLIC_REPLY_MEMORY_KIB);
        // A short reply, such as a broadcast's, needs no allowance: it is
        // never replaced, however many large replies wait.
        let _rest = crowded.clone().try_acquire_many_owned(256).unwrap();
        assert_eq!(crowded.available_permits(), 0);
        let mut body = vec![b'x'; PUBLIC_REPLY_UNHELD];
        assert!(
            settle_public_reply(&other, &crowded, &mut body, 0, 0, error)
                .unwrap()
                .is_none()
        );
        assert_eq!(body.len(), PUBLIC_REPLY_UNHELD);
    }

    #[test]
    fn explorer_reservations_follow_capacity_and_leave_room_for_parallel_pages() {
        // At launch capacity a page reserves the work of 50 records of a
        // 16 KiB transaction (128 KiB each), not that of a whole 32 MiB page
        // budget, so a browser's parallel explorer calls, each with its
        // method price, fit one visitor's work burst together.
        let launch = explorer_reply_reserve(16 * 1024);
        assert_eq!(launch, 6_400);
        let price = rpc_cost("explorer_mail", &json!({}));
        let guard = Arc::new(NetworkGuard::for_public_web());
        let visitor = guard
            .admit("198.51.100.40".parse().unwrap(), Surface::Rpc)
            .unwrap();
        for _ in 0..network_guard::PUBLIC_WEB_VISITOR_SESSIONS {
            visitor.work(price).unwrap();
            visitor.outgoing(0, launch).unwrap();
        }
        // Larger capacities reserve more, up to the page budget.
        assert_eq!(explorer_reply_reserve(1 << 20), JSON_PAGE_BYTES / 1024);
        assert_eq!(explorer_reply_reserve(usize::MAX), JSON_PAGE_BYTES / 1024);
    }

    #[test]
    fn large_grant_preparation_reserves_work_for_every_recipient() {
        let params = json!({"operation":{"Propose":{"proposal":{"Grant":{"payments":vec![Value::Null; 1000]}}}}});
        assert_eq!(rpc_cost("fee_quote", &params), 1008);
        assert_eq!(
            rpc_cost("broadcasttransaction", &json!({"raw":"00".repeat(34_000)})),
            MAX_MEMPOOL + 1 + 1000
        );
        let signed = json!({"transaction":{"body":params}});
        assert_eq!(
            rpc_cost("submittransaction", &signed),
            MAX_MEMPOOL + 1 + 1000
        );
        // Methods that never decode an operation or a raw transaction ignore
        // such fields, so a visitor's garbage list there costs the base price.
        assert_eq!(rpc_cost("status", &params), 8);
        assert_eq!(rpc_cost("snapshot", &params), 48);
        assert_eq!(
            rpc_cost("explorer_block", &json!({"raw":"00".repeat(34_000)})),
            128
        );
        assert_eq!(rpc_cost("grant_quote", &params), 4096);
    }

    #[test]
    fn proposal_response_pages_preserve_every_row_at_byte_and_value_boundaries() {
        let recipient = crypto::public_key(&[43; 32]).unwrap();
        let action = Proposal::Grant {
            payments: vec![GrantPayment {
                recipient,
                amount: 1u32.into(),
            }],
        };
        let records: Vec<_> = (0..3)
            .map(|round| crate::state::ProposalRecord {
                round,
                proposer: recipient,
                description: [44; 32],
                support: 1u32.into(),
                refund_height: None,
            })
            .collect();
        let first = ProposalPageRow {
            id: hex::encode([0; 32]),
            proposal: ProposalView {
                record: &records[0],
                action: &action,
            },
        };
        let encoded = serde_json::to_vec(&first).unwrap();
        let values =
            network_guard::preflight_json_value_count(&encoded, network_guard::MAX_JSON_VALUES)
                .unwrap();
        for by_bytes in [true, false] {
            let mut offset = 0;
            let mut rounds = Vec::new();
            while offset < records.len() {
                let mut page = JsonPage::new();
                if by_bytes {
                    page.bytes_left = encoded.len() + encoded.len() / 2;
                } else {
                    page.values_left = values + values / 2;
                }
                for (index, record) in records.iter().enumerate().skip(offset) {
                    if !page
                        .push(&ProposalPageRow {
                            id: hex::encode([index as u8; 32]),
                            proposal: ProposalView {
                                record,
                                action: &action,
                            },
                        })
                        .unwrap()
                    {
                        break;
                    }
                }
                assert_eq!(page.items.len(), 1);
                offset += page.items.len();
                rounds.extend(
                    page.items
                        .iter()
                        .map(|row| row["proposal"]["round"].as_u64().unwrap()),
                );
            }
            assert_eq!(rounds, [0, 1, 2]);
        }
    }

    #[test]
    fn snapshot_omits_large_pending_data_and_hex_mempool_preserves_every_signed_byte() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let secret = [46; 32];
        let sender = crypto::public_key(&secret).unwrap();
        let node = Node::open(
            &directory.path().join("response.db"),
            config.clone(),
            sender,
        )
        .unwrap();
        let transaction = crypto::sign(
            &config.chain_id(),
            &TransactionBody {
                sender,
                nonce: 17,
                fee: 123u32.into(),
                anchor: [38; 32],
                expiry_blocks: 100,
                operation: Operation::TransferExact {
                    recipient: sender,
                    amount: 1u32.into(),
                },
                data: vec![255; 2 * 1024 * 1024],
            },
            &secret,
        )
        .unwrap();
        // Isolate response projection from transaction execution and funding.
        // No block, transaction, faucet claim or external connection is made.
        {
            let mut inner = node.locked().unwrap();
            let backlog = inner.backlog.to_vec();
            inner.set_pool(vec![transaction.clone()], backlog);
            node.publish(&inner).unwrap();
        }
        let snapshot = node.rpc("snapshot", json!({})).unwrap();
        let pending = &snapshot["mempool"][0];
        assert_eq!(pending["body"]["sender"], json!(sender));
        assert_eq!(pending["body"]["nonce"], 17);
        assert_eq!(pending["body"]["fee"], "123");
        assert_eq!(
            pending["body"]["operation"],
            serde_json::to_value(&transaction.body.operation).unwrap()
        );
        assert!(pending["body"].get("data").is_none());
        assert!(pending.get("signature").is_none());
        assert!(serde_json::to_vec(pending).unwrap().len() < 2048);
        assert!(
            node.rpc("mempool", json!({}))
                .unwrap_err()
                .to_string()
                .contains("format: hex")
        );
        let full = node.rpc("mempool", json!({"format":"hex"})).unwrap();
        assert_eq!(
            full[0]["txid"],
            hex::encode(codec::transaction_id(&transaction))
        );
        assert_eq!(
            wallet::decode_signed(full[0]["raw"].as_str().unwrap(), &config.chain_id()).unwrap(),
            transaction
        );
        assert!(
            node.rpc("mempool", json!({"format":"hex", "offset":1}))
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );

        let mut modest = transaction.clone();
        modest.body.data = vec![1, 2, 3];
        let expected = serde_json::to_value(&modest).unwrap();
        let raw = mempool_page(&[modest], 0, 1, false).unwrap();
        assert_eq!(raw[0]["body"], expected["body"]);
        assert_eq!(raw[0]["signature"], expected["signature"]);
        assert_eq!(raw[0]["display_operation"], expected["body"]["operation"]);
    }
}

#[cfg(test)]
mod read_admission_tests {
    use super::*;
    use crate::state::{
        Auction, Decision, Phase, ProposalRecord, RoundRecord, RoundStatus, SupportRecord,
    };

    fn key() -> PublicKey {
        crypto::public_key(&[1; 32]).unwrap()
    }
    /// A curved world (reserve below curve mass) with one funded account.
    fn curved() -> State {
        let c = Config::devnet();
        let mut s = State::genesis(&c);
        let scale = Amount::from(10u32).pow(18);
        s.world
            .put(
                key(),
                Account {
                    ordinary: 1000u32.into(),
                    shares: &scale * 1000u32,
                    ..Account::default()
                },
                &c,
            )
            .unwrap();
        s.world.reserve = 1000u32.into();
        s.world.curve_mass = 5000u32.into();
        s.world.shares = &scale * 1000u32;
        s.issued = 2000u32.into();
        s.height = 7;
        s.phase = Phase::Auction(Auction {
            round: 0,
            opened: 0,
            leader: None,
            lead_since: 0,
            replacement_height: 0,
            displaced: Default::default(),
        });
        s
    }
    fn view(s: State, mempool: Vec<Transaction>) -> ReadView {
        ReadView {
            chain: PublishedChain {
                config: Arc::new(Config::devnet()),
                tip: [9; 32],
                state: Arc::new(s),
            },
            mempool: mempool.into(),
            pool_revision: 0,
            cache: Arc::default(),
            storage: Arc::default(),
        }
    }
    /// A loopback proxy session (no cooldown) with its work burst spent.
    fn drained() -> Session {
        let session = Arc::new(NetworkGuard::for_public_web())
            .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
            .unwrap();
        session.work(1_048_576).unwrap();
        session
    }
    fn register(s: &mut State, id: u8, round: u64, support: u32, action: Proposal) {
        s.actions.insert(vec![id; 32], action);
        s.proposals.insert(
            vec![id; 32],
            ProposalRecord {
                round,
                proposer: [0; 32],
                description: [0; 32],
                support: support.into(),
                refund_height: None,
            },
        );
    }
    fn parameter() -> Proposal {
        Proposal::Parameter {
            parameter: Parameter::BlockBytes,
            old: 16_384,
            new: 32_768,
        }
    }
    fn grant(count: usize) -> Proposal {
        Proposal::Grant {
            payments: vec![
                GrantPayment {
                    recipient: key(),
                    amount: 1u32.into(),
                };
                count
            ],
        }
    }
    fn hex_ids(ids: &[u8]) -> Vec<String> {
        ids.iter().map(|id| hex::encode([*id; 32])).collect()
    }
    fn ids(page: &Value) -> Vec<String> {
        page.as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn curve_quotes_are_clamped_and_charged_before_their_search() {
        let s = curved();
        let bps = s.settings.max_price_change_bps;
        let w = &s.world;
        let mut flat = w.clone();
        flat.curve_mass = flat.reserve.clone();
        assert_eq!(trade_work(&flat, true, &Amount::from(1000u32), bps), 0);
        assert_eq!(curve_evaluation_work(&flat), 0);
        assert_eq!(
            trade_work(w, true, &Amount::from(10u32), bps),
            2 * CURVE_EVALUATION_WORK
        );
        // An order able to cross the price cap pays for its budget search.
        assert_eq!(
            trade_work(w, true, &Amount::from(1000u32), bps),
            12 * CURVE_EVALUATION_WORK
        );
        // Sales scale by mass/reserve (5 here): 1% of supply is within half
        // of a 10% cap, 2% may not be.
        assert_eq!(bps, 1000);
        let small = &w.shares / 100u32;
        assert_eq!(trade_work(w, false, &small, bps), 2 * CURVE_EVALUATION_WORK);
        assert!(trade_work(w, false, &(&small * 2u32), bps) > 2 * CURVE_EVALUATION_WORK);
        let curved_view = view(s.clone(), vec![]);
        for amount in [
            "1001".to_owned(),
            ((Amount::from(1u32) << 512usize) - 1u32).to_str_radix(10),
        ] {
            let error = Node::read_rpc(
                &curved_view,
                "quote",
                json!({"kind":"deposit","amount":amount}),
            )
            .unwrap_err();
            assert!(error.to_string().contains("account cash"), "{error}");
        }
        let deposit = json!({"kind":"deposit","amount":"10"});
        assert!(Node::read_rpc(&curved_view, "quote", deposit.clone()).is_ok());
        let error =
            Node::read_rpc_metered(&curved_view, "quote", deposit.clone(), Some(&drained()))
                .unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
        let stash = json!({"key":hex::encode(key()),"kind":"redeem","amount":"1"});
        let account = json!({"key":hex::encode(key())});
        for (method, params) in [("stash_quote", stash), ("account", account)] {
            assert!(Node::read_rpc(&curved_view, method, params.clone()).is_ok());
            let error =
                Node::read_rpc_metered(&curved_view, method, params, Some(&drained())).unwrap_err();
            assert!(error.to_string().contains("budget"), "{method}: {error}");
        }
        // A flat curve has no size-dependent search and remains cheap.
        let mut s = s;
        s.world.curve_mass = s.world.reserve.clone();
        let flat_view = view(s, vec![]);
        assert!(Node::read_rpc_metered(&flat_view, "quote", deposit, Some(&drained())).is_ok());
    }

    #[test]
    fn governance_grant_projection_is_charged_and_summarized_for_wallets() {
        let mut s = curved();
        s.phase = Phase::Governance(Decision {
            id: [5; 32],
            epoch: 1,
            round: 0,
            proposal_id: [6; 32],
            proposal: grant(4096).into(),
            started: 0,
            started_height: 0,
            blocks: 10,
            leading_blocks: 0,
        });
        // The decision proposal is also the first row of its round.
        register(&mut s, 6, 0, 5, grant(4096));
        // Every explorer governance page projects the live phase too.
        assert_eq!(explorer_state_work("explorer_governance", &s), 4096);
        assert_eq!(explorer_state_work("explorer_blocks", &s), 0);
        assert_eq!(explorer_state_work("explorer_governance", &curved()), 0);
        let pending = Transaction {
            body: TransactionBody {
                sender: key(),
                nonce: 0,
                fee: 1u32.into(),
                anchor: [9; 32],
                expiry_blocks: 10,
                operation: Operation::Propose {
                    round: 0,
                    description: [0; 32],
                    proposal: grant(300),
                    support: 1u32.into(),
                },
                data: Vec::new(),
            },
            signature: [0; 64],
        };
        let view = view(s, vec![pending]);
        let error =
            Node::read_rpc_metered(&view, "governance", json!({}), Some(&drained())).unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
        let payments = |value: &Value| {
            value["phase"]["Governance"]["proposal"]["Grant"]["payments"]
                .as_array()
                .unwrap()
                .len()
        };
        let full = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(payments(&full), 4096);
        assert_eq!(
            full["decision_grant"],
            json!({"payment_count":4096,"payment_total":"4096","truncated":false})
        );
        assert_eq!(
            full["state_root"],
            hex::encode(view.chain.tip_state().root())
        );
        // A complete projection is built per paid call and never retained.
        assert!(view.cache.governance.get().is_none());
        assert_eq!(
            Node::read_rpc(&view, "governance", json!({})).unwrap(),
            full
        );
        // Wallet polling carries one bounded summary per tip, of the decision
        // and of its proposal row alike.
        let snapshot = Node::read_rpc(&view, "snapshot", json!({})).unwrap();
        let governance = &snapshot["governance"];
        assert_eq!(payments(governance), SUMMARY_GRANT_PAYMENTS);
        assert_eq!(
            governance["decision_grant"],
            json!({"payment_count":4096,"payment_total":"4096","truncated":true})
        );
        assert_eq!(view.cache.governance.get(), Some(governance));
        let row = &snapshot["proposals"][0];
        assert_eq!(row["truncated"], true);
        assert_eq!(row["payment_count"], 4096);
        assert_eq!(
            row["proposal"]["action"]["Grant"]["payments"]
                .as_array()
                .unwrap()
                .len(),
            SUMMARY_GRANT_PAYMENTS
        );
        // So is a pending grant above the summary size, however small.
        let pending = &snapshot["mempool"][0];
        assert_eq!(pending["truncated"], true);
        assert_eq!(pending["payment_count"], 300);
        // A direct proposals or mempool page keeps the complete grant.
        let page = Node::read_rpc(&view, "proposals", json!({"round":0})).unwrap();
        assert!(page[0].get("truncated").is_none());
        let pool = Node::read_rpc(&view, "mempool", json!({})).unwrap();
        assert_eq!(
            pool[0]["body"]["operation"]["Propose"]["proposal"]["Grant"]["payments"]
                .as_array()
                .unwrap()
                .len(),
            300
        );
        // Each is charged for what it projects: a budget below one complete
        // grant still serves the bounded snapshot.
        let budget = || {
            let session = Arc::new(NetworkGuard::for_public_web())
                .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
                .unwrap();
            session.work(1_048_576 - 2048).unwrap();
            session
        };
        for method in ["governance", "proposals"] {
            let error = Node::read_rpc_metered(&view, method, json!({"round":0}), Some(&budget()))
                .unwrap_err();
            assert!(error.to_string().contains("budget"), "{method}: {error}");
        }
        let polled = Node::read_rpc_metered(&view, "snapshot", json!({}), Some(&budget()));
        assert!(polled.is_ok(), "{:?}", polled.err());
    }

    #[test]
    fn oversized_grant_rows_are_summarized_instead_of_failing_pages() {
        let mut s = curved();
        // About 35 JSON values per payment: one record exceeds the page budget.
        let large = grant(64_000);
        register(&mut s, 1, 0, 5, large.clone());
        register(&mut s, 2, 0, 4, parameter());
        let pending = Transaction {
            body: TransactionBody {
                sender: key(),
                nonce: 0,
                fee: 1u32.into(),
                anchor: [9; 32],
                expiry_blocks: 10,
                operation: Operation::Propose {
                    round: 0,
                    description: [0; 32],
                    proposal: large,
                    support: 1u32.into(),
                },
                data: Vec::new(),
            },
            signature: [0; 64],
        };
        let view = view(s, vec![pending]);
        let page = Node::read_rpc(&view, "proposals", json!({"round":0})).unwrap();
        assert_eq!(ids(&page), [hex::encode([1; 32]), hex::encode([2; 32])]);
        assert_eq!(page[0]["truncated"], true);
        assert_eq!(page[0]["payment_count"], 64_000);
        assert_eq!(
            page[0]["proposal"]["action"]["Grant"]["payments"]
                .as_array()
                .unwrap()
                .len(),
            SUMMARY_GRANT_PAYMENTS
        );
        assert!(page[1].get("truncated").is_none());
        let snapshot = Node::read_rpc(&view, "snapshot", json!({})).unwrap();
        assert_eq!(snapshot["proposals"][0]["truncated"], true);
        assert_eq!(snapshot["proposals_total"], 2);
        let summary = &snapshot["mempool"][0];
        assert_eq!(summary["truncated"], true);
        assert_eq!(summary["payment_count"], 64_000);
        assert_eq!(summary["body"]["nonce"], 0);
        // Full JSON mempool rows keep their explicit hexadecimal fallback.
        assert!(
            Node::read_rpc(&view, "mempool", json!({}))
                .unwrap_err()
                .to_string()
                .contains("format: hex")
        );
        // The projected grant is charged before any page is built.
        let error =
            Node::read_rpc_metered(&view, "proposals", json!({"round":0}), Some(&drained()))
                .unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
    }

    #[test]
    fn round_pages_are_indexed_ranked_by_support_and_lead_with_the_leader() {
        let mut s = curved();
        for (id, round, support) in [(0u8, 1, 50), (1, 0, 5), (2, 0, 9), (3, 0, 9), (4, 0, 1)] {
            register(&mut s, id, round, support, parameter());
        }
        s.phase = Phase::Auction(Auction {
            round: 0,
            opened: 0,
            leader: Some([4; 32]),
            lead_since: 0,
            replacement_height: 0,
            displaced: Default::default(),
        });
        let auction = view(s.clone(), vec![]);
        let round = Node::read_rpc(&auction, "proposals", json!({"round":0})).unwrap();
        assert_eq!(ids(&round), hex_ids(&[4, 2, 3, 1]));
        let page = Node::read_rpc(
            &auction,
            "proposals",
            json!({"round":0,"offset":1,"limit":2}),
        )
        .unwrap();
        assert_eq!(ids(&page), hex_ids(&[2, 3]));
        // Support order changes between tips, so a listing paged across
        // blocks could skip a row; naming the first page's tip refuses that.
        let tip = hex::encode(auction.chain.tip_hash());
        let bound = json!({"round":0,"offset":1,"limit":2,"tip":tip});
        assert_eq!(
            ids(&Node::read_rpc(&auction, "proposals", bound).unwrap()),
            hex_ids(&[2, 3])
        );
        let stale = json!({"round":0,"offset":1,"tip":hex::encode([8; 32])});
        let error = Node::read_rpc(&auction, "proposals", stale).unwrap_err();
        assert!(
            error.to_string().contains("restart from offset 0"),
            "{error}"
        );
        assert!(
            Node::read_rpc(&auction, "proposals", json!({"round":0,"offset":9}))
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        let all = Node::read_rpc(&auction, "proposals", json!({})).unwrap();
        assert_eq!(ids(&all), hex_ids(&[0, 1, 2, 3, 4]));
        let snapshot = Node::read_rpc(&auction, "snapshot", json!({})).unwrap();
        assert_eq!(ids(&snapshot["proposals"]), hex_ids(&[4, 2, 3, 1]));
        assert_eq!(snapshot["proposals_total"], 4);
        // Rest lists the round that just ended, with its winner first.
        s.phase = Phase::Rest(crate::state::Rest {
            until: 100,
            pending: None,
        });
        s.rounds.insert(
            0u64.to_be_bytes().to_vec(),
            RoundRecord {
                status: RoundStatus::Won([3; 32]),
                refund_height: 7,
            },
        );
        s.last_round = 0;
        let rest = Node::read_rpc(&view(s.clone(), vec![]), "snapshot", json!({})).unwrap();
        assert_eq!(ids(&rest["proposals"]), hex_ids(&[3, 2, 1, 4]));
        s.rounds = crate::tree::Map::new();
        let genesis = Node::read_rpc(&view(s, vec![]), "snapshot", json!({})).unwrap();
        assert!(genesis["proposals"].as_array().unwrap().is_empty());
        assert_eq!(genesis["proposals_total"], 0);
    }

    #[test]
    fn support_status_tells_converted_locked_refundable_and_none_apart() {
        let mut s = curved();
        for (id, round) in [(1u8, 0u64), (2, 0), (3, 0), (4, 1)] {
            register(&mut s, id, round, 5, parameter());
        }
        for (round, status) in [(0u64, RoundStatus::Won([1; 32])), (1, RoundStatus::Open)] {
            s.rounds.insert(
                round.to_be_bytes().to_vec(),
                RoundRecord {
                    status,
                    refund_height: 7,
                },
            );
        }
        for (round, id) in [(0u64, 1u8), (0, 2), (1, 4)] {
            s.supports.insert(
                crate::state::support_key(round, &[id; 32], &key()),
                SupportRecord {
                    round,
                    proposal: [id; 32],
                    sender: key(),
                    amount: 5u32.into(),
                },
            );
        }
        let view = view(s, vec![]);
        for (id, round, status, refundable) in [
            (1u8, 0u64, "converted_to_revenue", false),
            (2, 0, "refundable", true),
            (3, 0, "none", false),
            (4, 1, "locked", false),
        ] {
            let support = Node::read_rpc(
                &view,
                "support",
                json!({"key":hex::encode(key()),"proposal":hex::encode([id; 32]),"round":round}),
            )
            .unwrap();
            assert_eq!(support["status"], status, "{id}");
            assert_eq!(support["refundable"], refundable, "{id}");
        }
    }

    #[test]
    fn account_reports_the_pending_nonce_and_responses_follow_capacity() {
        let pending = |nonce| Transaction {
            body: TransactionBody {
                sender: key(),
                nonce,
                fee: 1u32.into(),
                anchor: [9; 32],
                expiry_blocks: 10,
                operation: Operation::Refund {
                    round: 0,
                    proposal: [0; 32],
                },
                data: Vec::new(),
            },
            signature: [0; 64],
        };
        let view = view(curved(), vec![pending(0), pending(1)]);
        let account = Node::read_rpc(&view, "account", json!({"key":hex::encode(key())})).unwrap();
        assert_eq!(account["account"]["nonce"], 0);
        // A decimal string, which a keyed snapshot's account read repeats.
        assert_eq!(account["pending_nonce"], "2");
        let snapshot =
            Node::read_rpc(&view, "snapshot", json!({"key":hex::encode(key())})).unwrap();
        assert_eq!(
            snapshot["account"]["pending_nonce"],
            account["pending_nonce"]
        );
        assert_eq!(response_frame_bytes(16 * 1024).unwrap(), MAX_RESPONSE_FRAME);
        let governed = 200 * 1024 * 1024;
        assert!(response_frame_bytes(governed).unwrap() > 2 * governed);
        assert_eq!(
            response_frame_bytes(usize::MAX).unwrap(),
            isize::MAX as usize
        );
        // After governance lowers capacity, a confirmed record from the larger
        // history still fits: the frame follows the greatest validated capacity.
        assert_eq!(
            http_response_frame(16 * 1024, governed as u64).unwrap(),
            response_frame_bytes(governed).unwrap()
        );
        assert_eq!(
            http_response_frame(governed, 16 * 1024).unwrap(),
            response_frame_bytes(governed).unwrap()
        );
    }

    #[test]
    fn public_replies_spend_bytes_without_penalty_and_one_frame_always_fits() {
        // A directly connected visitor, for whom a penalty starts a cooldown.
        let remote: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        let guard = Arc::new(NetworkGuard::for_public_web());
        let session = guard.admit(remote, Surface::Rpc).unwrap();
        // One valid reply above the 66 MiB baseline burst, as a governed
        // capacity allows; the frame for that capacity covers it.
        let reply = 100 * 1024 * 1024;
        let frame = http_response_frame(16 * 1024, 48 * 1024 * 1024).unwrap();
        assert!(reply <= frame);
        guard.set_frame(frame).unwrap();
        charge_public_reply(&session, reply, 0).unwrap();
        // The next one exceeds the remaining budget: a refusal that says when
        // the budget has refilled, never a cooldown for a size the node chose.
        // The 7 MiB it lacks refill at a visitor's eighth of 32 MiB/s.
        let refused = charge_public_reply(&session, reply, 0).unwrap_err();
        let limited = refused
            .downcast_ref::<network_guard::Limited>()
            .expect("a quota refusal");
        assert_eq!(limited.reason, "outgoing network budget exhausted");
        assert!(
            limited
                .retry_after
                .is_some_and(|wait| wait > Duration::from_millis(1500)
                    && wait <= Duration::from_millis(1750)),
            "{:?}",
            limited.retry_after
        );
        session.request().unwrap();
        drop(guard.admit(remote, Surface::Rpc).unwrap());
    }

    #[test]
    fn sender_pending_rows_are_charged_before_the_snapshot_builds_them() {
        let other = crypto::public_key(&[2; 32]).unwrap();
        let pending = |sender, nonce, proposal: Option<Proposal>| Transaction {
            body: TransactionBody {
                sender,
                nonce,
                fee: 1u32.into(),
                anchor: [9; 32],
                expiry_blocks: 10,
                operation: match proposal {
                    Some(proposal) => Operation::Propose {
                        round: 0,
                        description: [0; 32],
                        proposal,
                        support: 1u32.into(),
                    },
                    None => Operation::Refund {
                        round: 0,
                        proposal: [0; 32],
                    },
                },
                data: Vec::new(),
            },
            signature: [0; 64],
        };
        // The global page holds only the other sender's rows; the selected
        // sender's grant rows appear only in its own page.
        let mut pool: Vec<_> = (0..128).map(|n| pending(other, n, None)).collect();
        pool.extend((0..128).map(|n| pending(key(), n, Some(grant(512)))));
        let view = view(curved(), pool);
        let budget = || {
            let session = Arc::new(NetworkGuard::for_public_web())
                .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
                .unwrap();
            session.work(1_048_576 - 8192).unwrap();
            session
        };
        let anonymous = Node::read_rpc_metered(&view, "snapshot", json!({}), Some(&budget()));
        assert!(anonymous.is_ok(), "{:?}", anonymous.err());
        let keyed = json!({"key":hex::encode(key())});
        let error = Node::read_rpc_metered(&view, "snapshot", keyed, Some(&budget())).unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
    }

    async fn parse(raw: &[u8], token: Option<&str>) -> Result<HttpRequest> {
        let session = Arc::new(NetworkGuard::default())
            .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
            .unwrap();
        let mut read = tokio::io::BufReader::new(raw);
        read_http(
            &mut read,
            "127.0.0.1:18480".parse().unwrap(),
            &session,
            false,
            16 * 1024,
            token,
        )
        .await
    }
    fn post(path: &str, headers: &str, body: &str) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:18480\r\nContent-Type: application/json\r\n{headers}\r\n{body}"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn http_requests_are_canonical_and_routed_before_any_body_is_read() {
        let valid = parse(&post("/rpc", "Content-Length: 2\r\n", "{}"), None)
            .await
            .unwrap();
        assert_eq!(
            (valid.method.as_str(), valid.body.as_slice()),
            ("POST", &b"{}"[..])
        );
        for length in ["+2", " 2,2", "0x2", "-0", ""] {
            let raw = post("/rpc", &format!("Content-Length: {length}\r\n"), "{}");
            assert!(parse(&raw, None).await.is_err(), "{length:?}");
        }
        for line in [
            "POST  /rpc HTTP/1.1",
            "POST\t/rpc HTTP/1.1",
            "POST /rpc HTTP/1.1 ",
        ] {
            let raw = format!("{line}\r\nHost: 127.0.0.1:18480\r\nContent-Length: 0\r\n\r\n");
            let error = parse(raw.as_bytes(), None).await.err().unwrap();
            assert_eq!(error.to_string(), "invalid HTTP request line", "{line:?}");
        }
        // Each claims a large body that never arrives. Routing and wallet
        // authorization fail before any body byte is awaited or allocated.
        let claimed = "Content-Length: 131072\r\n";
        let unrouted = parse(&post("/unknown", claimed, ""), None).await;
        assert_eq!(unrouted.err().unwrap().to_string(), "resource not found");
        let unauthorized = parse(&post("/api/wallet/manage", claimed, ""), Some("secret")).await;
        assert_eq!(
            unauthorized.err().unwrap().to_string(),
            "forbidden: invalid session token"
        );
        let authorized = parse(
            &post(
                "/api/wallet/manage",
                &format!("X-Hashstash-Token: secret\r\n{claimed}"),
                "{}",
            ),
            Some("secret"),
        )
        .await;
        assert_eq!(
            authorized.err().unwrap().to_string(),
            "HTTP body ended early"
        );
    }
}

/// Reply bounds for one client RPC call. Bytes bound the transfer; the JSON
/// value budget bounds the in-memory tree a compact hostile reply could expand to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcLimits {
    pub bytes: usize,
    pub values: usize,
}
impl RpcLimits {
    /// Fixed-shape replies such as status, account, mining and submission results.
    pub const SMALL: Self = Self {
        bytes: 1024 * 1024,
        values: 65_536,
    };
    /// Caller-selected methods whose reply shape is unknown; frame bound only.
    pub const FRAME: Self = Self {
        bytes: MAX_RESPONSE_FRAME,
        values: usize::MAX,
    };
    /// Replies that echo their request, such as `preparetransaction`, stay
    /// proportional to it: hex bodies double bytes and the quote repeats the operation.
    pub fn echoing(params: &Value) -> Result<Self> {
        let request = serde_json::to_vec(params)?;
        Ok(Self {
            bytes: request
                .len()
                .saturating_mul(4)
                .saturating_add(Self::SMALL.bytes)
                .min(MAX_RESPONSE_FRAME),
            values: rpc_json_values(&request)
                .saturating_mul(2)
                .saturating_add(Self::SMALL.values),
        })
    }
}

/// Count JSON strings, scalars and containers without building a tree.
/// Malformed input is counted conservatively and later rejected by serde.
pub fn rpc_json_values(bytes: &[u8]) -> usize {
    let (mut values, mut quoted, mut escaped, mut scalar) = (0usize, false, false, false);
    for &b in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                quoted = false;
            }
            continue;
        }
        match b {
            b'"' | b'[' | b'{' => {
                values += 1;
                quoted = b == b'"';
                scalar = false;
            }
            b',' | b':' | b']' | b'}' => scalar = false,
            _ if b.is_ascii_whitespace() => scalar = false,
            _ => {
                values += usize::from(!scalar);
                scalar = true;
            }
        }
    }
    values
}

/// The most of an HTTP error reply's body read for its JSON error message.
const RPC_ERROR_BYTES: usize = 64 * 1024;
/// Client transport for command-line RPC. Plain HTTP is limited to loopback
/// IP literals unless explicitly allowed; environment proxies and redirects are
/// never followed, so replies come only from the endpoint the user named.
pub struct RpcClient {
    url: reqwest::Url,
    loopback: bool,
    client: reqwest::Client,
}
impl RpcClient {
    pub fn new(url: &str, insecure_http: bool) -> Result<Self> {
        let parsed = reqwest::Url::parse(url).context("invalid RPC URL")?;
        ensure!(
            parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.query().is_none()
                && parsed.fragment().is_none(),
            "RPC URL must not contain credentials, a query or a fragment"
        );
        let loopback = parsed
            .host_str()
            .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        match parsed.scheme() {
            "https" => {}
            "http" => ensure!(
                loopback || insecure_http,
                "plain HTTP RPC is limited to loopback IP addresses; use https:// or pass --insecure-http"
            ),
            _ => bail!("RPC URL must use http or https"),
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(parsed.scheme() == "https")
            .build()?;
        Ok(Self {
            url: parsed,
            loopback,
            client,
        })
    }
    /// True only for a loopback IP literal, never for a resolvable host name.
    pub fn is_loopback(&self) -> bool {
        self.loopback
    }
    pub async fn call(&self, method: &str, params: Value, limits: RpcLimits) -> Result<Value> {
        Ok(self.call_measured(method, params, limits).await?.0)
    }
    /// Also return the reply's byte length so callers can budget a whole scan.
    pub async fn call_measured(
        &self,
        method: &str,
        params: Value,
        limits: RpcLimits,
    ) -> Result<(Value, usize)> {
        let maximum = limits.bytes.min(MAX_RESPONSE_FRAME);
        let response = self
            .client
            .post(self.url.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await?;
        ensure!(
            !response.status().is_redirection(),
            "RPC endpoint answered with a redirect; use its final URL"
        );
        let mut response = response;
        if let Some(failed) = response.error_for_status_ref().err() {
            // A refusal (429, 503) or other HTTP error still carries the
            // node's short JSON error; show it, and when to resend, instead
            // of the bare status.
            let retry = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .map(|value| format!(", retry after {value} s"))
                .unwrap_or_default();
            let status = response.status().as_u16();
            let mut bytes = Vec::new();
            while let Ok(Some(chunk)) = response.chunk().await {
                if bytes.len() + chunk.len() > RPC_ERROR_BYTES {
                    return Err(failed.into());
                }
                bytes.extend_from_slice(&chunk);
            }
            let error = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|mut body| body.get_mut("error").map(Value::take));
            return Err(match error {
                Some(error) => anyhow!("RPC error (HTTP {status}{retry}): {error}"),
                None => failed.into(),
            });
        }
        ensure!(
            response.content_length().unwrap_or(0) <= maximum as u64,
            "RPC response too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= maximum,
                "RPC response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        ensure!(
            rpc_json_values(&bytes) <= limits.values,
            "RPC response exceeds its JSON value budget"
        );
        let mut v: Value = serde_json::from_slice(&bytes)?;
        if let Some(error) = v.get("error") {
            bail!("RPC error: {error}");
        }
        let result = v
            .get_mut("result")
            .map(Value::take)
            .context("missing RPC result")?;
        Ok((result, bytes.len()))
    }
    /// Discover the next nonce. A loopback endpoint's reported `pending_nonce`,
    /// its account nonce raised past its pending transactions, is taken at its
    /// word, so no raw pending record of any governed size is downloaded, as is
    /// a remote one equal to the account nonce. Otherwise a remote endpoint
    /// could plant a future nonce, so the client scans its mempool: the account
    /// nonce rises past this sender's pending transactions, signature-checked
    /// for `chain_id`, while they use consecutive nonces, as an honest pool
    /// holds them, and must reach any reported pending nonce. An endpoint can
    /// still misreport the account nonce or hide pending rows, so the review
    /// shows the chosen nonce and `--nonce` overrides it.
    pub async fn pending_nonce(
        &self,
        chain_id: &Hash,
        sender: &PublicKey,
        budget: ScanBudget,
    ) -> Result<PendingNonce> {
        let scan = async {
            let account = self
                .call(
                    "account",
                    json!({"key":hex::encode(sender)}),
                    RpcLimits::SMALL,
                )
                .await?;
            let account_nonce = account["account"]["nonce"]
                .as_u64()
                .context("invalid nonce")?;
            let reported = match account.get("pending_nonce").filter(|v| !v.is_null()) {
                Some(reported) => {
                    // A decimal string; earlier endpoints sent a JSON number.
                    let nonce = match reported {
                        // Canonical digits only; parsing then rejects values above u64.
                        Value::String(text) => {
                            parse_amount(text).ok().and_then(|_| text.parse().ok())
                        }
                        other => other.as_u64(),
                    }
                    .context("invalid pending nonce")?;
                    ensure!(
                        nonce >= account_nonce,
                        "pending nonce precedes account nonce"
                    );
                    if self.loopback || nonce == account_nonce {
                        return Ok(PendingNonce {
                            nonce,
                            account_nonce,
                            pending: None,
                        });
                    }
                    Some(nonce)
                }
                None => None,
            };
            let mut own = std::collections::BTreeSet::new();
            let (mut offset, mut bytes_left) = (0, budget.bytes);
            while offset < MAX_ADAPTIVE_MEMPOOL {
                // Each row holds two strings, so the value budget stays small
                // however large the raw transactions are.
                let (page, bytes) = self
                    .call_measured(
                        "mempool",
                        json!({"offset":offset,"format":"hex"}),
                        RpcLimits {
                            bytes: bytes_left,
                            values: 4096,
                        },
                    )
                    .await
                    .context(
                        "pending transaction scan failed or exceeded its byte budget; pass --nonce",
                    )?;
                bytes_left -= bytes;
                let page = page.as_array().context("invalid mempool response")?;
                ensure!(page.len() <= 128, "mempool page exceeds requested limit");
                if page.is_empty() {
                    break;
                }
                for row in page {
                    let tx = wallet::decode_signed(
                        row.get("raw")
                            .and_then(Value::as_str)
                            .context("mempool signed transaction missing")?,
                        chain_id,
                    )?;
                    if tx.body.sender == *sender {
                        own.insert(tx.body.nonce);
                    }
                }
                offset += page.len();
            }
            // Honest pools reject nonce gaps, so a row past one justifies nothing.
            let (mut nonce, mut pending) = (account_nonce, 0);
            for used in own.range(account_nonce..) {
                if *used != nonce {
                    break;
                }
                nonce = nonce.checked_add(1).context("nonce exhausted")?;
                pending += 1;
            }
            if let Some(reported) = reported {
                ensure!(
                    nonce >= reported,
                    "RPC endpoint reports pending nonce {reported}, but its signed pending transactions from this sender reach only nonce {nonce}; check the account's next nonce on a node you trust and pass --nonce"
                );
            }
            Ok(PendingNonce {
                nonce,
                account_nonce,
                pending: Some(pending),
            })
        };
        timeout(budget.time, scan).await.map_err(|_| {
            anyhow!(
                "pending transaction scan exceeded {} seconds; pass --nonce",
                budget.time.as_secs()
            )
        })?
    }
}

/// A client-discovered nonce and what it was derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingNonce {
    pub nonce: u64,
    pub account_nonce: u64,
    /// Consecutive signature-checked pending nonces from this sender, when the
    /// client scanned the mempool instead of taking the reported pending nonce.
    pub pending: Option<usize>,
}

/// Total reply bytes and time one pending-nonce scan may use, however an
/// endpoint paginates. An honest mempool holds at most one next block.
#[derive(Clone, Copy, Debug)]
pub struct ScanBudget {
    pub bytes: usize,
    pub time: Duration,
}
impl ScanBudget {
    pub const DEFAULT: Self = Self {
        bytes: 2 * MAX_RESPONSE_FRAME,
        time: Duration::from_secs(300),
    };
}

pub async fn call_rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    RpcClient::new(url, false)?
        .call(method, params, RpcLimits::FRAME)
        .await
}

pub fn validate_stratum_difficulty(difficulty: f64) -> Result<()> {
    ensure!(
        difficulty.is_finite() && (1e-12..=1e18).contains(&difficulty),
        "Stratum share difficulty must be finite and between 1e-12 and 1e18"
    );
    Ok(())
}
fn suggested_stratum_difficulty(floor: f64, minimum: f64, suggested: f64) -> Result<f64> {
    validate_stratum_difficulty(suggested)?;
    Ok(floor.max(minimum).max(suggested))
}
pub fn stratum_connect_url(endpoint: &str) -> Result<String> {
    ensure!(
        !endpoint.is_empty()
            && endpoint.len() <= 320
            && endpoint.is_ascii()
            && !endpoint
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            && !endpoint.contains(['/', '\\', '?', '#', '@', '%']),
        "advertised Stratum endpoint must be HOST:PORT"
    );
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .context("IPv6 endpoint requires [ADDRESS]:PORT")?;
        let ip: std::net::Ipv6Addr = host.parse().context("invalid advertised IPv6 address")?;
        ensure!(
            !ip.is_unspecified(),
            "advertised address cannot be a wildcard"
        );
        (host, port)
    } else {
        let (host, port) = endpoint
            .rsplit_once(':')
            .context("advertised endpoint needs a port")?;
        ensure!(
            !host.is_empty()
                && !host.contains(':')
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "invalid advertised hostname"
        );
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            ensure!(
                !ip.is_unspecified(),
                "advertised address cannot be a wildcard"
            );
        }
        (host, port)
    };
    ensure!(
        !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        "invalid advertised endpoint"
    );
    ensure!(
        port.parse::<u16>().is_ok_and(|port| port != 0),
        "advertised port must be 1..65535"
    );
    let url = format!("stratum+tcp://{endpoint}");
    let parsed = reqwest::Url::parse(&url).context("invalid advertised endpoint")?;
    ensure!(
        parsed.host_str().is_some() && parsed.port().is_some(),
        "invalid advertised endpoint"
    );
    Ok(url)
}
fn stratum_share_target(difficulty: f64) -> Result<Amount> {
    validate_stratum_difficulty(difficulty)?;
    // Divide by the exact binary rational encoded by f64, without rounding a
    // 256-bit target through floating point. nBits remains the block target.
    let bits = difficulty.to_bits();
    let significand = (bits & ((1u64 << 52) - 1)) | (1u64 << 52);
    let exponent = ((bits >> 52) & 0x7ff) as i32 - 1023 - 52;
    let mut numerator = math::target_from_bits(0x1d00ffff)?;
    let mut denominator = Amount::from(significand);
    if exponent >= 0 {
        denominator <<= exponent as usize;
    } else {
        numerator <<= (-exponent) as usize;
    }
    let maximum = (Amount::from(1u32) << 256usize) - 1u32;
    Ok((numerator / denominator).min(maximum))
}

fn stratum_minimum_compatible(config: &Config, minimum: f64) -> Result<bool> {
    if minimum == 0.0 {
        return Ok(true);
    }
    // BIP310 promises a minimum for the whole connection. Every target is
    // bounded by the immutable chain limit, including after governance changes.
    Ok(stratum_share_target(minimum)? >= math::target_from_bits(config.limit_bits)?)
}
struct StratumJob {
    block: Arc<Block>,
    difficulty: f64,
    share_target: Amount,
    block_target: Amount,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    branch: Vec<Hash>,
}
impl StratumJob {
    fn new(block: Arc<Block>, difficulty: f64) -> Result<Self> {
        let (prefix, suffix) = codec::coinbase_parts_for_block(&block);
        let block_target = math::target_from_bits(block.header.bits)?;
        let mut difficulty = difficulty;
        if stratum_share_target(difficulty)? < block_target {
            // Round toward easier work. Never ask an unmodified worker to
            // discard a solution that would satisfy the chain's block target.
            let one = math::target_from_bits(0x1d00ffff)?
                .to_f64()
                .context("difficulty conversion")?;
            difficulty =
                (one / block_target.to_f64().context("target conversion")?).min(difficulty);
            while stratum_share_target(difficulty)? < block_target {
                difficulty = difficulty.next_down();
            }
        }
        Ok(Self {
            share_target: stratum_share_target(difficulty)?,
            block_target,
            branch: codec::mining_merkle_branch(&block),
            block,
            difficulty,
            prefix,
            suffix,
        })
    }
    fn notify(&self, id: &str, clean: bool) -> Value {
        let mut previous = self.block.header.previous;
        for word in previous.chunks_exact_mut(4) {
            word.reverse();
        }
        let timestamp = self
            .block
            .header
            .timestamp
            .max(now().min(u32::MAX as u64) as u32);
        json!({"id":null,"method":"mining.notify","params":[id,hex::encode(previous),hex::encode(&self.prefix),hex::encode(&self.suffix),self.branch.iter().map(hex::encode).collect::<Vec<_>>(),format!("{:08x}",self.block.header.version),format!("{:08x}",self.block.header.bits),format!("{timestamp:08x}"),clean]})
    }
    fn candidate(
        &self,
        extra1: [u8; 4],
        extra2: [u8; 4],
        timestamp: u32,
        nonce: u32,
        version: u32,
    ) -> Header {
        let mut coinbase = Vec::with_capacity(self.prefix.len() + 8 + self.suffix.len());
        coinbase.extend_from_slice(&self.prefix);
        coinbase.extend_from_slice(&extra1);
        coinbase.extend_from_slice(&extra2);
        coinbase.extend_from_slice(&self.suffix);
        let mut root = crypto::sha256d(&coinbase);
        for sibling in &self.branch {
            let mut pair = [0; 64];
            pair[..32].copy_from_slice(&root);
            pair[32..].copy_from_slice(sibling);
            root = crypto::sha256d(&pair);
        }
        Header {
            version,
            previous: self.block.header.previous,
            merkle_root: root,
            timestamp,
            bits: self.block.header.bits,
            nonce,
        }
    }
}
#[derive(Debug)]
struct StratumError(i32, &'static str);
impl std::fmt::Display for StratumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for StratumError {}
fn mining_error(code: i32, message: &'static str) -> anyhow::Error {
    StratumError(code, message).into()
}
fn hex_u32(v: &Value) -> Result<u32> {
    let s = v.as_str().context("hexadecimal string required")?;
    ensure!(s.len() == 8, "expected eight hex digits");
    Ok(u32::from_str_radix(s, 16)?)
}
fn stratum_submit_version(
    job_version: u32,
    params: &[Value],
    rolling_requested: bool,
    rolling_mask: Option<u32>,
) -> Result<u32> {
    if params.len() == 5 && rolling_mask.is_none() {
        return Ok(job_version);
    }
    ensure!(params.len() == 6, "invalid submit arguments");
    // Some proxies forward ASIC version bits without forwarding configure.
    // Only an untouched session gets this fixed consensus-safe fallback;
    // an explicit failed request must never silently broaden its mask.
    let mask = match rolling_mask {
        Some(mask) => mask,
        None if !rolling_requested => VERSION_MASK,
        None => bail!("version rolling was not enabled"),
    };
    let bits = hex_u32(&params[5])?;
    ensure!(bits & !mask == 0, "version bits outside negotiated mask");
    Ok((job_version & !mask) | bits)
}
/// Jobs retained per Stratum connection while its parent remains the tip.
const MAX_STRATUM_JOBS: usize = 8;
/// Same-parent template changes reach a connection at most once per interval,
/// so a retained job survives at least MAX_STRATUM_JOBS intervals of churn.
const STRATUM_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
/// Connections awaiting authorization hold network_guard pre-authorization
/// slots. Authorized workers leave them for the MAX_CONNECTIONS worker registry.
const STRATUM_AUTHORIZATION_WINDOW: Duration = network_guard::STRATUM_AUTHORIZATION_WINDOW;
/// Reporting difficulty follows each connection's share rate at its current
/// difficulty. A sample of at least STRATUM_RATE_SAMPLE share intervals is
/// judged once it spans STRATUM_SHARE_WINDOW: above STRATUM_MAX_SHARE_RATE per
/// second, difficulty is multiplied by the largest power of two that keeps
/// the rate at or above STRATUM_TARGET_SHARE_RATE. A stream above
/// STRATUM_BURST_SHARE_RATE, the session request rate past which its shares
/// are refused, is raised as soon as its sample is complete.
const STRATUM_MAX_SHARE_RATE: u64 = 2;
const STRATUM_TARGET_SHARE_RATE: u64 = 1;
const STRATUM_BURST_SHARE_RATE: u64 = 8;
const STRATUM_RATE_SAMPLE: u64 = 16;
/// The shortest span a rate is measured over, so shares buffered together
/// cannot imply an unbounded rate, and the span after which a sample is
/// judged and restarts.
const STRATUM_RATE_FLOOR: Duration = Duration::from_millis(250);
const STRATUM_SHARE_WINDOW: Duration = Duration::from_secs(30);
/// Difficulty above the floor or what the miner negotiated halves once its
/// valid shares since the last change average fewer than one per
/// STRATUM_SLOW_SHARE over at least STRATUM_DECAY_SPAN.
const STRATUM_SLOW_SHARE: Duration = Duration::from_secs(4);
const STRATUM_DECAY_SPAN: Duration = Duration::from_secs(120);
/// Worker names one connection may authorize, as a proxy does for each of
/// the miners behind it.
const MAX_STRATUM_WORKER_NAMES: usize = 64;
const STRATUM_RATE_LIMITED: &str = "mining session request rate limit";
/// When a deferred same-parent refresh runs: one interval after the last job,
/// and not before the node's throttled template may be rebuilt.
fn stratum_refresh_at(
    last_job: tokio::time::Instant,
    retry: Option<tokio::time::Instant>,
) -> tokio::time::Instant {
    let interval = last_job + STRATUM_REFRESH_INTERVAL;
    retry.map_or(interval, |retry| interval.max(retry))
}
/// Whether a published change leaves the connection's work on `fingerprint`
/// (parent, Merkle root) to its next scheduled refresh: a same-parent change
/// within STRATUM_REFRESH_INTERVAL of the last job, or while a refresh is
/// already scheduled (`deferred`), which then fetches the latest template.
/// A new tip is served at once.
fn stratum_defers(
    fingerprint: Option<(Hash, Hash)>,
    tip: Hash,
    deferred: bool,
    since_job: Duration,
) -> bool {
    fingerprint.is_some_and(|(parent, _)| parent == tip)
        && (deferred || since_job < STRATUM_REFRESH_INTERVAL)
}
#[allow(clippy::too_many_arguments)]
async fn new_job<W: AsyncWrite + Unpin>(
    node: &Node,
    write: &mut W,
    jobs: &mut HashMap<String, Arc<StratumJob>>,
    counter: &mut u64,
    difficulty: f64,
    seen: &mut HashMap<Hash, Hash>,
    worker_id: u32,
    block: Arc<Block>,
) -> Result<(Hash, Hash)> {
    let parent_changed = jobs
        .iter()
        .max_by_key(|(id, _)| *id)
        .is_some_and(|(_, old)| old.block.header.previous != block.header.previous);
    let clean = parent_changed || jobs.is_empty();
    if parent_changed {
        seen.clear();
    }
    if clean {
        jobs.clear();
    } else if jobs.len() >= MAX_STRATUM_JOBS {
        // Same-parent work remains valid. Retire only the oldest job (IDs are
        // fixed-width counters) instead of flushing work still in flight.
        if let Some(oldest) = jobs.keys().min().cloned() {
            jobs.remove(&oldest);
        }
    }
    *counter = counter.checked_add(1).context("job counter exhausted")?;
    let id = format!("{counter:016x}");
    let permit = timeout(IO_TIMEOUT, node.stratum_workers.clone().acquire_owned()).await??;
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        StratumJob::new(block, difficulty)
    })
    .await
    .context("mining job worker failed")??;
    if let Some(worker) = node.mining.unpoisoned().workers.get_mut(&worker_id) {
        worker.difficulty = job.difficulty;
    }
    write_json(
        write,
        &json!({"id":null,"method":"mining.set_difficulty","params":[job.difficulty]}),
    )
    .await?;
    write_json(write, &job.notify(&id, clean)).await?;
    let fingerprint = (job.block.header.previous, job.block.header.merkle_root);
    jobs.insert(id, Arc::new(job));
    Ok(fingerprint)
}
/// A throttled template, and when to ask again if it lags the selection.
/// Waiting for a template holds no mining worker: the node bounds its own
/// builds (see [TemplateBuilds]), so jobs, shares and solved blocks never
/// queue behind a build.
async fn template_async(node: &Node) -> Result<(Arc<Block>, Option<tokio::time::Instant>)> {
    let node = node.clone();
    let (block, retry) =
        tokio::task::spawn_blocking(move || node.template_shared(Freshness::Throttled))
            .await
            .context("mining template worker failed")??;
    Ok((block, retry.map(tokio::time::Instant::from_std)))
}
fn stratum_session_expired(authorized: bool, connected: Duration) -> bool {
    !authorized && connected >= STRATUM_AUTHORIZATION_WINDOW
}
/// Power-of-two difficulty multiplier for `intervals` share intervals observed
/// over `elapsed`, or None while the rate is acceptable or not yet judged.
fn stratum_rate_factor(intervals: u64, elapsed: Duration) -> Option<f64> {
    let millis = elapsed
        .max(STRATUM_RATE_FLOOR)
        .as_millis()
        .min(u64::MAX as u128) as u64;
    let shares = intervals.saturating_mul(1000);
    let ceiling = if elapsed < STRATUM_SHARE_WINDOW {
        STRATUM_BURST_SHARE_RATE
    } else {
        STRATUM_MAX_SHARE_RATE
    };
    if intervals < STRATUM_RATE_SAMPLE || shares <= ceiling.saturating_mul(millis) {
        return None;
    }
    // Rounded down, so noise in a sample never pushes the rate below target.
    let factor = shares / STRATUM_TARGET_SHARE_RATE.saturating_mul(millis);
    Some((1u64 << factor.ilog2()) as f64)
}
/// Whether `shares` valid shares over `elapsed` since the difficulty last
/// changed are few enough to halve it.
fn stratum_decays(shares: u64, elapsed: Duration) -> bool {
    elapsed >= STRATUM_DECAY_SPAN
        && u128::from(shares).saturating_mul(STRATUM_SLOW_SHARE.as_millis()) < elapsed.as_millis()
}
/// One connection's share rate at its current difficulty.
struct ShareRate {
    /// The first share of the current sample, and the share intervals since.
    sample: Option<(tokio::time::Instant, u64)>,
    /// When the current difficulty took effect, and the valid shares since.
    since: tokio::time::Instant,
    shares: u64,
}
impl ShareRate {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            sample: None,
            since: now,
            shares: 0,
        }
    }
    /// A valid share at the current, uncapped difficulty: the factor to
    /// raise it by, if any. A judged sample restarts with this share.
    fn sample(&mut self, now: tokio::time::Instant) -> Option<f64> {
        let (start, intervals) = match self.sample {
            Some((start, intervals)) => (start, intervals + 1),
            None => (now, 0),
        };
        let elapsed = now.duration_since(start);
        self.sample = Some(if elapsed >= STRATUM_SHARE_WINDOW {
            (now, 0)
        } else {
            (start, intervals)
        });
        stratum_rate_factor(intervals, elapsed)
    }
    /// Whether the difficulty should halve now.
    fn slow(&self, now: tokio::time::Instant) -> bool {
        stratum_decays(self.shares, now.duration_since(self.since))
    }
}
/// An authorized worker's line may carry a solved block, so it waits for a
/// parser without a deadline. The parser semaphore is never closed.
async fn parse_worker_line(node: &Node, bytes: Vec<u8>) -> Result<Value> {
    let permit = node.stratum_parsers.clone().acquire_owned().await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        network_guard::parse_json(&bytes)
    })
    .await
    .context("JSON worker failed")?
}
/// The reply to a line an authorized worker sent past its rate or a budget.
fn stratum_restricted(reason: Option<&anyhow::Error>) -> anyhow::Error {
    reason.map_or_else(
        || mining_error(20, STRATUM_RATE_LIMITED),
        |error| anyhow!("{error}"),
    )
}
fn disconnected_between_frames(error: &anyhow::Error, partial: &[u8]) -> bool {
    partial.is_empty()
        && error.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::NotConnected
            )
        })
}
async fn stratum_session(
    node: Node,
    stream: TcpStream,
    password: Option<String>,
    floor: f64,
    extra: [u8; 4],
    admission: Session,
    pending: Option<network_guard::PendingSlot>,
) -> Result<()> {
    let (read, write) = stream.into_split();
    stratum_lines(
        node, read, write, password, floor, extra, admission, pending,
    )
    .await
}
/// A Stratum session over any byte stream: the listener's TCP halves, or the
/// fuzz harness's in-memory input and reply buffer (see [fuzz]).
#[allow(clippy::too_many_arguments)]
async fn stratum_lines<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    node: Node,
    read: R,
    mut write: W,
    password: Option<String>,
    floor: f64,
    extra: [u8; 4],
    admission: Session,
    mut pending: Option<network_guard::PendingSlot>,
) -> Result<()> {
    let admission = Arc::new(admission);
    let mut read = BufReader::new(read);
    let mut subscribed = false;
    let mut authorized = false;
    // Every worker name this connection authorized, first the one its
    // statistics are reported under.
    let mut names: Vec<String> = Vec::new();
    let mut registration: Option<MiningConnection> = None;
    let evicted = Arc::new(tokio::sync::Notify::new());
    let mut version_rolling = false;
    let mut rolling_requested = false;
    let mut mask = 0u32;
    let mut difficulty = floor;
    let mut minimum_difficulty = floor;
    // The difficulty a lowered rate may return to: the floor, or what the
    // miner negotiated or suggested last.
    let mut negotiated = floor;
    let mut jobs: HashMap<String, Arc<StratumJob>> = HashMap::new();
    let mut seen = HashMap::<Hash, Hash>::new();
    let mut counter = 0;
    let mut fingerprint: Option<(Hash, Hash)> = None;
    let mut deferred = false;
    // When the node's throttled template may next be rebuilt, if it lagged.
    let mut retry: Option<tokio::time::Instant> = None;
    let mut rate = ShareRate::new(tokio::time::Instant::now());
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut updates = node.work_updates.subscribe();
    let connected = tokio::time::Instant::now();
    let mut last_job = tokio::time::Instant::now();
    let mut partial_line = Vec::new();
    let mut partial_since = None;
    loop {
        tokio::select! {
            line = bounded_line_buf(&mut read, 16384, &mut partial_line) => {
                let line = match line {
                    Ok(v) => v,
                    Err(e) if disconnected_between_frames(&e, &partial_line) => return Ok(()),
                    Err(e) => { admission.malformed(); return Err(e); }
                };
                // An unauthenticated line is charged before it is parsed. An authorized
                // worker's line is handled first and its charge enforced after the reply,
                // so an address budget or rate overrun never discards a solved block.
                // Past its rate or a budget, a worker's line can only submit a block.
                // Only a spent overrun allowance (`limit`) closes the session: other
                // sources can exhaust the budgets a worker shares with them.
                let mut limit = None;
                let mut throttled = false;
                let mut refusal = None;
                if authorized {
                    match admission.worker_line(line.len()) {
                        Ok(network_guard::WorkerLine::Admitted) => {}
                        Ok(network_guard::WorkerLine::Throttled) => throttled = true,
                        Ok(network_guard::WorkerLine::Refused(e)) => refusal = Some(e),
                        Err(e) => limit = Some(e),
                    }
                } else {
                    admission.request()?;
                    admission.bytes(line.len())?;
                }
                let restricted = throttled || refusal.is_some() || limit.is_some();
                let reason = limit.as_ref().or(refusal.as_ref());
                let parsed = if authorized { parse_worker_line(&node,line).await } else { parse_value_async(&node,line,Surface::Stratum,JsonBody::Ordinary).await };
                let request = match parsed { Ok(v) => v, Err(e) => { admission.malformed(); return Err(e); } };
                // The time a never-authorized connection waited is charged to its
                // address when its pre-authorization slot is released, however it ends.
                if stratum_session_expired(authorized,connected.elapsed()) { bail!("mining authorization timed out"); }
                partial_since = None;
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let params = request.get("params").and_then(Value::as_array).cloned().unwrap_or_default();
                let mut submission = None;
                let mut refresh = false;
                let mut at_capacity = false;
                let mut retarget = false;
                let mut result: Result<Value> = (|| {
                    if restricted && method != "mining.submit" { return Err(stratum_restricted(reason)); }
                    match method {
                        "mining.configure" => {
                            let extensions = params.first().and_then(Value::as_array).context("extensions required")?;
                            rolling_requested |= extensions.iter().any(|ext|ext.as_str()==Some("version-rolling"));
                            let options = params.get(1).cloned().unwrap_or(json!({}));
                            ensure!(options.is_object(), "extension options must be an object");
                            let mut reply = serde_json::Map::new();
                            let mut next_mask = mask;
                            let mut next_rolling = version_rolling;
                            let mut next_difficulty = difficulty;
                            let mut next_minimum = minimum_difficulty;
                            let mut next_negotiated = negotiated;
                            for ext in extensions {
                                let ext = ext.as_str().context("extension must be a string")?;
                                if ext == "version-rolling" {
                                    let requested = options.get("version-rolling.mask").map(hex_u32).transpose()?.unwrap_or(u32::MAX);
                                    let candidate = requested & VERSION_MASK;
                                    let bits = options.get("version-rolling.min-bit-count").map(|v| v.as_u64().context("invalid minimum version bit count")).transpose()?.unwrap_or(0);
                                    if candidate.count_ones() as u64 >= bits {
                                        next_mask = candidate; next_rolling = true;
                                        reply.insert(ext.into(),json!(true));
                                        reply.insert("version-rolling.mask".into(),json!(format!("{candidate:08x}")));
                                    } else { reply.insert(ext.into(),json!(false)); }
                                } else if ext == "minimum-difficulty" {
                                    let minimum = options.get("minimum-difficulty.value").and_then(Value::as_f64).context("minimum difficulty value required")?;
                                    if minimum != 0.0 { validate_stratum_difficulty(minimum)?; }
                                    let view = node.read_view()?;
                                    let compatible = stratum_minimum_compatible(&view.chain.config, minimum)?;
                                    if compatible {
                                        next_minimum = floor.max(minimum);
                                        next_difficulty = next_minimum;
                                        next_negotiated = next_minimum;
                                    }
                                    reply.insert(ext.into(),json!(compatible));
                                } else { reply.insert(ext.into(),json!(ext == "subscribe-extranonce")); }
                            }
                            mask = next_mask; version_rolling = next_rolling;
                            refresh = next_difficulty != difficulty;
                            if refresh { rate = ShareRate::new(tokio::time::Instant::now()); }
                            difficulty = next_difficulty;
                            minimum_difficulty = next_minimum;
                            negotiated = next_negotiated;
                            Ok(Value::Object(reply))
                        }
                        "mining.subscribe" => {
                            subscribed = true;
                            Ok(json!([[["mining.set_difficulty",hex::encode(extra)],["mining.notify",hex::encode(extra)]],hex::encode(extra),4]))
                        }
                        "mining.authorize" => {
                            ensure!(subscribed, "subscribe first");
                            let name = params.first().and_then(Value::as_str).context("worker name required")?;
                            ensure!(!name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control), "invalid worker name");
                            // Same comparison as the HTTP session token: no early exit on content.
                            if !password.as_deref().is_none_or(|p|token_matches(params.get(1).and_then(Value::as_str),p)) {
                                return Ok(json!(false));
                            }
                            if authorized {
                                // A proxy authorizes each miner behind it on one connection,
                                // which keeps its one registry slot.
                                if !names.iter().any(|known| known == name) {
                                    ensure!(names.len() < MAX_STRATUM_WORKER_NAMES, "too many worker names on one connection");
                                    names.push(name.to_owned());
                                }
                                return Ok(json!(true));
                            }
                            let identity = u32::from_le_bytes(extra);
                            // Only a prefix the operator named lifts the limits that
                            // bind other sources' workers.
                            let trusted = pending.as_ref().is_some_and(network_guard::PendingSlot::operator_trusted);
                            let entry = MiningWorker {
                                worker:name.to_owned(),accepted:0,rejected:0,blocks:0,difficulty,last_share:None,
                                active:Instant::now(),group:network_guard::stratum_group(admission.address()),
                                trusted,evict:evicted.clone(),
                            };
                            if let Err(reason) = node.mining.unpoisoned().register(identity, entry, Instant::now()) {
                                at_capacity = true;
                                bail!(reason);
                            }
                            registration = Some(MiningConnection {runtime:node.mining.clone(),id:identity});
                            // Authorize only once registered. The worker registry now
                            // bounds this session; free its pre-authorization slot and
                            // let its address reconnect uncharged into reserved slots.
                            names.push(name.to_owned());
                            authorized = true;
                            admission.authorize_worker(trusted);
                            if let Some(slot) = pending.take() { slot.authorized(); }
                            refresh = true;
                            Ok(json!(true))
                        }
                        "mining.extranonce.subscribe" => Ok(json!(true)),
                        "mining.suggest_difficulty" => {
                            let suggested = params.first().and_then(Value::as_f64).context("difficulty required")?;
                            let next = suggested_stratum_difficulty(floor,minimum_difficulty,suggested)?;
                            refresh = next != difficulty;
                            if refresh { rate = ShareRate::new(tokio::time::Instant::now()); }
                            difficulty = next;
                            negotiated = next;
                            Ok(json!(true))
                        }
                        "mining.submit" => {
                            ensure!(authorized && subscribed,"unauthorized");
                            ensure!(matches!(params.len(),5|6),"invalid submit arguments");
                            // The worker name is checked after the proof of work, so a
                            // solved block is submitted whatever name it carries.
                            let named = params[0].as_str().is_some_and(|name| names.iter().any(|known| known == name));
                            let id = params[1].as_str().context("job id required")?;
                            let job = jobs.get(id).ok_or_else(||mining_error(21,"unknown or stale job"))?.clone();
                            if !node.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                            let version = stratum_submit_version(job.block.header.version,&params,rolling_requested,version_rolling.then_some(mask))?;
                            let extra2: [u8;4] = hex::decode(params[2].as_str().context("extranonce2 required")?)?.try_into().map_err(|_|anyhow!("extranonce2 must be four bytes"))?;
                            let timestamp = hex_u32(&params[3])?;
                            let nonce = hex_u32(&params[4])?;
                            submission = Some((job,extra2,timestamp,nonce,version,named));
                            Ok(json!(true))
                        }
                        _ => bail!("unsupported mining method"),
                    }
                })();
                if let Some((job,extra2,timestamp,nonce,version,named)) = submission {
                    // One fixed-size coinbase and header hash: computing it here
                    // avoids a worker queue that could time out on a found block.
                    let header = job.candidate(extra,extra2,timestamp,nonce,version);
                    let hash = crypto::sha256d(&codec::header_bytes(&header));
                    let candidate = (|| -> Result<(Option<Amount>,bool)> {
                        if seen.contains_key(&hash) { return Err(mining_error(22,"duplicate share")); }
                        let view = node.read_view()?;
                        if !node.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                        ensure!(timestamp >= job.block.header.timestamp,"timestamp predates job minimum");
                        ensure!(timestamp as u64 <= now().saturating_add(view.chain.config.future_seconds as u64),"timestamp too far in future");
                        let proof = Amount::from_bytes_le(&hash);
                        let is_block = proof <= job.block_target;
                        let is_share = proof <= job.share_target;
                        if !is_block && !named { bail!("worker mismatch"); }
                        if !is_block && !is_share { return Err(mining_error(23,"low difficulty share")); }
                        // Only one sampling threshold contributes to hashrate.
                        // Valid network-only blocks are counted but add no rate sample.
                        Ok((is_share.then(||math::work(&job.share_target)),is_block))
                    })();
                    result = match candidate {
                        Err(error) => Err(error),
                        Ok((work,is_block)) => {
                            let submitted_parent = job.block.header.previous;
                            // Proven work keeps the worker's slot, even when the share is
                            // refused for its rate or a budget that others share.
                            if let Some(registration) = &registration { node.mining.unpoisoned().proved(registration.id, Instant::now()); }
                            // Valid shares measure the connection's rate, including shares
                            // refused for that rate. Only those at its current, uncapped
                            // difficulty can raise it: a job capped at network difficulty
                            // cannot be raised further.
                            if work.is_some() {
                                let now = tokio::time::Instant::now();
                                rate.shares = rate.shares.saturating_add(1);
                                if job.difficulty == difficulty && let Some(factor) = rate.sample(now) {
                                    let next = (difficulty * factor).min(1e18);
                                    if next > difficulty { difficulty = next; retarget = true; rate = ShareRate::new(now); }
                                }
                            }
                            let accepted = if is_block {
                                // Budgets and worker queues may delay a solved block but
                                // never discard it, and a budget that other sources share
                                // never ends the worker's session: the work is charged after.
                                let _ = admission.worker_work(1 + job.block.transactions.len());
                                // Solved blocks have their own permits, never taken by
                                // template builds or jobs. The semaphore is never closed;
                                // wait without a deadline.
                                let permit = node.block_submissions.clone().acquire_owned().await.ok();
                                let validator = node.clone();
                                tokio::task::spawn_blocking(move || -> Result<()> {
                                    let _permit = permit;
                                    if !validator.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                                    let mut block = job.block.as_ref().clone();
                                    block.header = header;
                                    block.extranonce[..4].copy_from_slice(&extra);
                                    block.extranonce[4..].copy_from_slice(&extra2);
                                    // A valid block that did not become the tip lost a race
                                    // with a competing child of the same parent.
                                    if validator.submit_block(block)? { Ok(()) } else { Err(mining_error(21,"stale job")) }
                                }).await.unwrap_or_else(|_| Err(anyhow!("mining block worker failed")))
                            } else if restricted {
                                Err(stratum_restricted(reason))
                            } else { admission.worker_work(1) };
                            accepted.map(|()| {
                                seen.insert(hash, submitted_parent);
                                node.mining.unpoisoned().submission(registration.as_ref().map(|r|r.id),Some((work.as_ref(),is_block)));
                                refresh |= is_block;
                                json!(true)
                            })
                        }
                    };
                }
                let successful = result.is_ok();
                if method=="mining.submit" && !successful { node.mining.unpoisoned().submission(registration.as_ref().map(|r|r.id),None); }
                let denied = method=="mining.authorize" && !authorized;
                let response = match result {
                    Ok(v) => json!({"id":id,"result":v,"error":null}),
                    Err(e) => { let code=e.downcast_ref::<StratumError>().map_or(20,|error|error.0); json!({"id":id,"result":null,"error":[code,e.to_string(),null]}) }
                };
                write_json(&mut write,&response).await?;
                // A full worker registry is capacity, not misbehaviour.
                if denied && at_capacity { bail!("mining worker capacity reached"); }
                if denied { admission.malformed(); bail!("mining authorization denied"); }
                if let Some(error) = limit { return Err(error); }
                // Never evict duplicate evidence while the parent remains valid.
                // A fresh connection gets a different extranonce and new work.
                ensure!(seen.len()<MAX_SUBMITTED_HEADERS,"share history capacity reached; reconnect");
                // A raised difficulty takes effect with the next job, even when the
                // share that measured the rate was itself refused for it.
                if authorized && (retarget || (successful && refresh)) {
                    let (block, lagging) = template_async(&node).await?;
                    fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra),block).await?);
                    last_job=tokio::time::Instant::now();
                    // A template that lags the selection is refreshed once the node may rebuild it.
                    deferred = lagging.is_some();
                    retry = lagging;
                }
            }
            changed = updates.changed() => {
                changed.context("mining update channel closed")?;
                if authorized {
                    // A new tip replaces work at once. Same-parent template changes
                    // are coalesced so transaction churn cannot retire retained
                    // jobs faster than one per STRATUM_REFRESH_INTERVAL, nor ask
                    // for a template again while a refresh is already scheduled.
                    let tip = node.read_view()?.chain.tip_hash();
                    if stratum_defers(fingerprint, tip, deferred, last_job.elapsed()) {
                        deferred = true;
                    } else {
                        let (block, lagging) = template_async(&node).await?;
                        if fingerprint!=Some((block.header.previous,block.header.merkle_root)) {
                            fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra),block).await?);
                            last_job=tokio::time::Instant::now();
                        }
                        deferred = lagging.is_some();
                        retry = lagging;
                    }
                }
            }
            _ = tokio::time::sleep_until(stratum_refresh_at(last_job, retry)), if deferred => {
                let (block, lagging) = template_async(&node).await?;
                if fingerprint!=Some((block.header.previous,block.header.merkle_root)) {
                    fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra),block).await?);
                    last_job=tokio::time::Instant::now();
                }
                deferred = lagging.is_some();
                retry = lagging;
            }
            _ = evicted.notified() => bail!("an idle mining worker was replaced by a newcomer"),
            _ = tick.tick() => {
                if stratum_session_expired(authorized,connected.elapsed()) { bail!("mining authorization timed out"); }
                if !partial_line.is_empty() { let began=partial_since.get_or_insert_with(tokio::time::Instant::now); ensure!(began.elapsed()<IO_TIMEOUT,"mining partial frame timed out"); }
                // Difficulty raised beyond what the miner negotiated falls back while
                // its shares stay slow, one halving at a time.
                let now = tokio::time::Instant::now();
                let decayed = authorized && difficulty > negotiated && rate.slow(now);
                if decayed {
                    difficulty = (difficulty / 2.0).max(negotiated);
                    rate = ShareRate::new(now);
                }
                if authorized && (decayed || last_job.elapsed()>=Duration::from_secs(30)) {
                    let (block, lagging) = template_async(&node).await?;
                    fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra),block).await?);
                    last_job=tokio::time::Instant::now();
                    if lagging.is_some() {
                        deferred = true;
                        retry = lagging;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn exact_wallet_quote_preserves_fee_and_exact_payment() {
        let directory = tempfile::tempdir().unwrap();
        let secret = [71; 32];
        let sender = crypto::public_key(&secret).unwrap();
        let recipient = crypto::public_key(&[72; 32]).unwrap();
        let config = Config::testnet();
        let node = Node::open(
            &directory.path().join("node.sqlite"),
            config.clone(),
            sender,
        )
        .unwrap()
        .with_wallet(secret)
        .unwrap();
        for _ in 0..10 {
            node.mine(1_000_000).unwrap();
        }
        let operation = Operation::TransferExact {
            recipient,
            amount: 5u32.into(),
        };
        let quote = node
            .rpc(
                "transfer_quote",
                json!({"sender":hex::encode(sender),"recipient":hex::encode(recipient),"amount":"5","extra_fee":"3"}),
            )
            .unwrap();
        assert_eq!(quote["account_creation_fee"], "1");
        assert_eq!(quote["minimum_fee"], "2");
        assert_eq!(quote["fee"], "5");
        assert_eq!(quote["total_debit"], "10");
        assert!(quote.get("maximum_total_debit").is_none());
        assert_eq!(quote["sender_public_key"], hex::encode(sender));
        let before = node.read_view().unwrap().chain.tip_state().clone();
        let request = json!({"sender":hex::encode(sender),"operation":operation,"extra_fee":"3","anchor":quote["tip"],"expiry_blocks":2,"nonce":0});
        let prepared = node.rpc("preparetransaction", request.clone()).unwrap();
        assert_eq!(
            prepared["fee_quote"],
            quote_with_expiry(quote, before.height + 2)
        );
        assert_eq!(node.rpc("mempool", json!({})).unwrap(), json!([]));
        let mut envelope = prepared.clone();
        envelope.as_object_mut().unwrap().remove("fee_quote");
        let body = wallet::decode_unsigned(&serde_json::from_value(envelope).unwrap()).unwrap();
        let foreign = crypto::sign(&[0; 32], &body, &secret).unwrap();
        assert!(
            node.rpc(
                "broadcasttransaction",
                json!({"raw":wallet::signed_hex(&foreign)})
            )
            .unwrap_err()
            .to_string()
            .contains("signature for this network"),
            "a signature for another chain ID is rejected"
        );
        let tx = crypto::sign(&before.chain_id, &body, &secret).unwrap();
        let raw = wallet::signed_hex(&tx);
        node.rpc("broadcasttransaction", json!({"raw":raw}))
            .unwrap();
        let pending = node.rpc("mempool", json!({})).unwrap();
        assert_eq!(
            pending[0]["display_operation"],
            serde_json::to_value(&operation).unwrap()
        );
        assert_eq!(pending[0]["body"], serde_json::to_value(&body).unwrap());
        assert!(
            node.rpc("preparetransaction", request)
                .unwrap_err()
                .to_string()
                .contains("pending nonce")
        );
        node.mine(1_000_000).unwrap();
        let after = node.read_view().unwrap().chain.tip_state().clone();
        let subsidy = &after.issued - &before.issued;
        assert_eq!(
            after.account(&recipient, None).unwrap().ordinary,
            Amount::from(5u32)
        );
        // Sender is also the miner: the non-miner share of the whole fee leaves their account.
        assert_eq!(
            after.account(&sender, None).unwrap().ordinary,
            before.account(&sender, None).unwrap().ordinary + subsidy - 8u32
        );
        assert_eq!(after.world.revenue, &before.world.revenue + 3u32);
        after.audit(&config).unwrap();
        let quote = node
            .rpc(
                "transfer_quote",
                json!({"sender":hex::encode(sender),"recipient":hex::encode(recipient),"amount":"5"}),
            )
            .unwrap();
        assert_eq!(quote["account_creation_fee"], "0");
        assert_eq!(quote["fee"], "1");
        assert_eq!(quote["minimum_fee"], "1");
    }
    #[test]
    fn quotes_report_a_fee_or_capacity_change_due_within_their_lifetime() {
        // Audit F157: a two-block transaction prepared at the activation parent
        // has only the activation block left under the old settings.
        use crate::state::{Phase, Rest};
        let c = Config::devnet();
        let mut s = State::genesis(&c);
        let interval = s.settings.interval;
        s.height = 10;
        s.clock = 10 * interval;
        let body = |expiry_blocks, fee: u32| TransactionBody {
            sender: [1; 32],
            nonce: 0,
            fee: fee.into(),
            anchor: [2; 32],
            expiry_blocks,
            // A new recipient: 1,024 creation weight on top of the bytes.
            operation: Operation::TransferExact {
                recipient: [3; 32],
                amount: 1u32.into(),
            },
            data: vec![],
        };
        let check = |s: &State, body: TransactionBody| {
            let tx = Transaction {
                body,
                signature: [0; 64],
            };
            let quote = crate::fees::quote(&c, s, &tx).unwrap();
            assert_eq!(quote.minimum_fee, 2u32.into());
            scheduled_change(s, &tx.body, &quote)
        };
        let rest = |delay, pending| {
            Phase::Rest(Rest {
                until: 10 * interval + delay,
                pending: Some(pending),
            })
        };
        s.phase = rest(interval, (Parameter::MinimumFeeRate, 2));
        let change = check(&s, body(2, 2)).unwrap();
        assert_eq!(change["parameter"], "MinimumFeeRate");
        assert_eq!(change["activation_height"], 11);
        assert_eq!(change["effective_height"], 12);
        assert_eq!(change["minimum_fee"], "3");
        assert_eq!(change["valid_after"], false);
        assert_eq!(check(&s, body(2, 3)).unwrap()["valid_after"], true);
        // A one-block lifetime ends with the activation block itself.
        assert!(check(&s, body(1, 2)).is_none());
        // A partial interval still activates at the next block boundary.
        s.phase = rest(interval + 1, (Parameter::MinimumFeeRate, 2));
        assert!(check(&s, body(2, 2)).is_none());
        assert_eq!(check(&s, body(3, 2)).unwrap()["effective_height"], 13);
        // Other settings never invalidate a quoted fee or size.
        s.phase = rest(interval, (Parameter::MinerFeePercent, 10));
        assert!(check(&s, body(2, 2)).is_none());
        // The projection only compares sizes; this capacity is below the
        // transaction's weight (and the governed floor).
        let capacity = crate::fees::ACCOUNT_WEIGHT;
        s.phase = rest(interval, (Parameter::BlockBytes, capacity));
        let change = check(&s, body(2, 2)).unwrap();
        assert_eq!(change["value"], capacity.to_string());
        assert_eq!(change["valid_after"], false);
    }
    #[test]
    fn quotes_report_a_change_the_next_block_passes() {
        // A decision's last tip already decides its outcome. With a zero rest
        // the resolving block also activates the change, so no tip is ever in
        // rest; a two-block quote there had only that block left under the old
        // fee and reported nothing. The reported heights are checked against
        // consensus executing the following blocks.
        use crate::state::{Decision, Phase, RoundRecord, RoundStatus};
        let mut c = Config::devnet();
        c.test_work = false;
        let miner = crypto::public_key(&[9; 32]).unwrap();
        let interval = c.initial.interval;
        let tip = |rest, leading_blocks| {
            let mut c = c.clone();
            c.initial.rest = rest;
            let mut s = State::genesis(&c);
            s.height = 10;
            s.clock = 10 * interval;
            // An unchanged PASS world never leads, so the tip's own
            // observation adds no PASS block.
            s.alternative = Some(s.world.clone());
            // The auction round that this proposal won.
            s.rounds.insert(
                0u64.to_be_bytes().to_vec(),
                RoundRecord {
                    status: RoundStatus::Won([6; 32]),
                    refund_height: 6,
                },
            );
            s.phase = Phase::Governance(Decision {
                id: [5; 32],
                epoch: 0,
                round: 0,
                proposal_id: [6; 32],
                proposal: Arc::new(Proposal::Parameter {
                    parameter: Parameter::MinimumFeeRate,
                    old: 1,
                    new: 2,
                }),
                started: 6 * interval,
                started_height: 7,
                blocks: 4,
                leading_blocks,
            });
            (c, s)
        };
        let report = |s: &State, expiry_blocks| {
            let tx = Transaction {
                body: TransactionBody {
                    sender: miner,
                    nonce: 0,
                    fee: 2u32.into(),
                    anchor: [2; 32],
                    expiry_blocks,
                    operation: Operation::TransferExact {
                        recipient: crypto::public_key(&[3; 32]).unwrap(),
                        amount: 1u32.into(),
                    },
                    data: vec![],
                },
                signature: [0; 64],
            };
            let quote = crate::fees::quote(&c, s, &tx).unwrap();
            assert_eq!(quote.minimum_fee, 2u32.into());
            scheduled_change(s, &tx.body, &quote)
        };
        // The first height whose block runs under the new minimum fee rate.
        let consensus_effective = |c: &Config, s: &State| {
            let mut state = s.clone();
            while state.settings.minimum_fee_rate == 1 {
                state =
                    crate::consensus::execute(c, &state, &[0; 32], &miner, &Amount::zero(), &[])
                        .unwrap();
                assert!(state.height < 20, "the change never activated");
            }
            state.height + 1
        };
        for (rest, effective) in [(0, 12), (1, 13), (interval, 13), (interval + 1, 14)] {
            let (c, s) = tip(rest, 3);
            assert_eq!(consensus_effective(&c, &s), effective, "rest {rest}");
            let lifetime = effective - s.height;
            let change = report(&s, lifetime).unwrap();
            assert_eq!(change["parameter"], "MinimumFeeRate");
            assert_eq!(change["activation_height"], effective - 1, "rest {rest}");
            assert_eq!(change["effective_height"], effective, "rest {rest}");
            assert_eq!(change["valid_after"], false);
            // A lifetime that ends with the activation block is unaffected.
            assert!(report(&s, lifetime - 1).is_none(), "rest {rest}");
            // A losing decision changes nothing.
            let (c, lost) = tip(rest, 2);
            let after =
                crate::consensus::execute(&c, &lost, &[0; 32], &miner, &Amount::zero(), &[])
                    .unwrap();
            assert!(!matches!(after.phase, Phase::Rest(ref r) if r.pending.is_some()));
            assert_eq!(after.settings.minimum_fee_rate, 1);
            assert!(report(&lost, lifetime).is_none(), "rest {rest}");
        }
        // Before the last tip the outcome is still open.
        let (_, mut early) = tip(0, 3);
        early.height = 9;
        assert!(report(&early, 10).is_none());
    }
    #[test]
    fn quotes_refuse_a_transaction_heavier_than_block_capacity() {
        // Consensus limits a block's weight, not only its bytes: a payment
        // that creates an account adds 1,024 weight. One whose bytes fit but
        // whose weight cannot was quoted and prepared, and only refused at
        // admission with a generic error.
        let c = Config::devnet();
        let mut s = State::genesis(&c);
        let sender = crypto::public_key(&[11; 32]).unwrap();
        let recipient = crypto::public_key(&[12; 32]).unwrap();
        let capacity = usize::try_from(s.settings.block_bytes).unwrap();
        let request = || WalletRequest {
            operation: Operation::TransferExact {
                recipient,
                amount: 1u32.into(),
            },
            fee: None,
            extra_fee: None,
            data_hex: Some(hex::encode(vec![7; capacity - 512])),
            expiry_blocks: None,
            anchor: None,
            nonce: None,
        };
        let error = wallet_body(&c, &s, [4; 32], sender, 0, request()).unwrap_err();
        assert!(error.to_string().contains("weight"), "{error}");
        // The same bytes to an existing account fit.
        s.world.put(recipient, Account::default(), &c).unwrap();
        let body = wallet_body(&c, &s, [4; 32], sender, 0, request()).unwrap();
        let quote = fees::quote(
            &c,
            &s,
            &Transaction {
                body,
                signature: [0; 64],
            },
        )
        .unwrap();
        assert!(quote.weight <= s.settings.block_bytes);
        assert!(quote.weight + fees::ACCOUNT_WEIGHT > s.settings.block_bytes);
    }
    fn quote_with_expiry(mut quote: Value, expiry: u64) -> Value {
        for field in [
            "recipient",
            "public_key",
            "amount",
            "recipient_receives",
            "account_creation_charge",
            "total_debit",
            "maximum_total_debit",
        ] {
            quote.as_object_mut().unwrap().remove(field);
        }
        quote["expiry_height"] = json!(expiry);
        quote
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn wallet_preparation_binds_quoted_tip_and_two_block_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let key = crypto::public_key(&[73; 32]).unwrap();
        let node = Node::open(
            &directory.path().join("anchored.sqlite"),
            Config::devnet(),
            key,
        )
        .unwrap();
        let operation = Operation::TransferExact {
            recipient: key,
            amount: 1u32.into(),
        };
        let request = json!({"sender":hex::encode(key),"operation":operation});
        let genesis_quote = node.rpc("fee_quote", request.clone()).unwrap();
        assert_eq!(genesis_quote["anchor"], node.status().unwrap()["tip"]);
        assert_eq!(genesis_quote["anchor_height"], 0);
        assert_eq!(genesis_quote["expiry_blocks"], 2);
        assert_eq!(genesis_quote["expiry_height"], 2);
        let mut maximum_lifetime = request.clone();
        maximum_lifetime["expiry_blocks"] = json!(u64::MAX);
        assert_eq!(
            node.rpc("fee_quote", maximum_lifetime.clone()).unwrap()["expiry_height"],
            u64::MAX
        );
        node.mine(100_000).unwrap();
        assert!(
            node.rpc("fee_quote", maximum_lifetime)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
        let mut exact = request.clone();
        exact["anchor"] = node.status().unwrap()["tip"].clone();
        let prepared = node.rpc("preparetransaction", exact.clone()).unwrap();
        let mut envelope = prepared.clone();
        envelope.as_object_mut().unwrap().remove("fee_quote");
        let signed_body =
            wallet::decode_unsigned(&serde_json::from_value(envelope).unwrap()).unwrap();
        assert_eq!(hex::encode(signed_body.anchor), exact["anchor"]);
        assert_eq!(signed_body.expiry_blocks, 2);
        assert_eq!(prepared["fee_quote"]["anchor_height"], 1);
        assert_eq!(prepared["fee_quote"]["expiry_height"], 3);
        assert!(
            serde_json::to_value(&signed_body)
                .unwrap()
                .get("expiry_height")
                .is_none()
        );
        node.mine(100_000).unwrap();
        for method in ["preparetransaction", "fee_quote"] {
            assert!(
                node.rpc(method, exact.clone())
                    .unwrap_err()
                    .to_string()
                    .contains("quoted tip")
            );
        }
        let mut longer = request;
        longer["expiry_blocks"] = json!(10_000);
        let quote = node.rpc("fee_quote", longer).unwrap();
        assert_eq!(quote["expiry_blocks"], 10_000);
        assert_eq!(quote["expiry_height"], 10_002);
    }
    #[test]
    fn exact_quotes_reject_ambiguous_and_unbounded_authorizations() {
        let directory = tempfile::tempdir().unwrap();
        let key = crypto::public_key(&[73; 32]).unwrap();
        let node = Node::open(
            &directory.path().join("node.sqlite"),
            Config::testnet(),
            key,
        )
        .unwrap();
        let operation = Operation::TransferExact {
            recipient: key,
            amount: 1u32.into(),
        };
        let request = json!({"sender":hex::encode(key),"operation":operation});
        for (field, value) in [
            ("fee", json!("1")),
            ("max_fee", json!("0")),
            ("extra_fee", json!("-1")),
            ("max_fee", json!("1".repeat(20_001))),
            ("nonce", json!(u64::MAX)),
            ("expiry_height", json!(0)),
            ("expiry_blocks", json!(0)),
            ("anchor", json!("not-a-block-hash")),
            ("anchor", json!("00".repeat(32))),
            ("unknown", json!(true)),
        ] {
            let mut invalid = request.clone();
            invalid[field] = value;
            assert!(node.rpc("fee_quote", invalid).is_err(), "accepted {field}");
        }
        let mut ambiguous = request.clone();
        ambiguous["fee"] = json!("20");
        ambiguous["extra_fee"] = json!("0");
        assert!(
            node.rpc("fee_quote", ambiguous)
                .unwrap_err()
                .to_string()
                .contains("either")
        );
        let mut removed = request.clone();
        removed["operation"] = json!({"FeeMarket":{"priority_fee":"0","operation":[]}});
        assert!(node.rpc("fee_quote", removed).is_err());
        assert_eq!(node.status().unwrap()["height"], 0);
        assert_eq!(node.rpc("mempool", json!({})).unwrap(), json!([]));
    }
    #[test]
    fn stratum_version_compatibility_preserves_negotiation_and_fixed_bits() {
        let base = codec::HEADER_VERSION;
        let five = vec![Value::Null; 5];
        let mut six = five.clone();
        six.push(json!("046d4000"));
        assert_eq!(
            stratum_submit_version(base, &five, false, None).unwrap(),
            base
        );
        assert_eq!(
            stratum_submit_version(base, &five, true, None).unwrap(),
            base
        );
        assert_eq!(
            stratum_submit_version(base, &six, false, None).unwrap(),
            0x246d4005
        );
        assert!(stratum_submit_version(base, &six, true, None).is_err());
        assert!(stratum_submit_version(base, &five, true, Some(VERSION_MASK)).is_err());
        assert!(stratum_submit_version(base, &six, true, Some(0x2000)).is_err());
        for bits in [
            json!("80000000"),
            json!("00000001"),
            json!("20000000"),
            json!("100000000"),
            json!("0"),
            json!(0),
            Value::Null,
        ] {
            six[5] = bits;
            assert!(stratum_submit_version(base, &six, false, None).is_err());
        }
        six[5] = json!("00000000");
        assert_eq!(
            stratum_submit_version(base, &six, true, Some(0)).unwrap(),
            base
        );
        assert_eq!(
            stratum_submit_version(base, &six, false, None).unwrap(),
            base
        );
        six.push(Value::Null);
        assert!(stratum_submit_version(base, &six, false, None).is_err());
    }

    #[test]
    fn stratum_proxy_captured_nonzero_versions_reproduce_valid_reporting_proofs() {
        // Public wire proof vectors: no nonce search or network submission.
        let previous =
            hex::decode("4768ea0230d3b82b53ed2b3d411e4f07ccf3efcfd378d7322fafd31d8fcff1c6")
                .unwrap()
                .try_into()
                .unwrap();
        let job = StratumJob {
            block: Arc::new(Block {
                header: Header {version: codec::HEADER_VERSION, previous, merkle_root: [0;32], timestamp: 0, bits: 0x1a1804ea, nonce: 0},
                height: 1, miner: [0;32], state_root: [0;32], extranonce: [0;8], transactions: vec![],
            }),
            difficulty: 65_536.0,
            share_target: stratum_share_target(65_536.0).unwrap(),
            block_target: math::target_from_bits(0x1a1804ea).unwrap(),
            prefix: hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0a5108").unwrap(),
            suffix: hex::decode("ffffffff010000000000000000466a4448535436b06a9c0f38f08d2ba3d0ed7da5f8e0e21f038b688b369ba87a37dbc633e6d842ba348f90206b673e1b51d156dad95b4ddab92e43ca4e8d6b718c8fbfc96e0e0e00000000").unwrap(),
            branch: vec![],
        };
        for (extra2, time, nonce, bits, expected) in [
            (
                "0000f4b8",
                0x6ad003a6,
                0x088f84b6,
                "046d4000",
                "000000000000a00a0bbe287005e3b37887aa9fa767f5e607416aa784ff14acb8",
            ),
            (
                "0000f4f0",
                0x6ad003c4,
                0x34b402cc,
                "03880000",
                "000000000000a2a3b34056af14868f1021c366b4fe2ef4a5b9afcef6ada91a62",
            ),
        ] {
            let params = json!([
                "public-fixture",
                "job",
                extra2,
                format!("{time:08x}"),
                format!("{nonce:08x}"),
                bits
            ]);
            let version = stratum_submit_version(
                codec::HEADER_VERSION,
                params.as_array().unwrap(),
                false,
                None,
            )
            .unwrap();
            let extra2 = hex::decode(extra2).unwrap().try_into().unwrap();
            let header = job.candidate([5, 0, 0, 0], extra2, time, nonce, version);
            assert!(codec::is_current_header(&header));
            let hash = crypto::sha256d(&codec::header_bytes(&header));
            assert_eq!(
                hex::encode(hash.into_iter().rev().collect::<Vec<_>>()),
                expected
            );
            let proof = Amount::from_bytes_le(&hash);
            assert!(proof <= job.share_target);
            assert!(proof > job.block_target);
            let unrolled = job.candidate([5, 0, 0, 0], extra2, time, nonce, codec::HEADER_VERSION);
            assert!(
                Amount::from_bytes_le(&crypto::sha256d(&codec::header_bytes(&unrolled)))
                    > job.share_target
            );
        }
    }

    #[test]
    fn stratum_reporting_targets_are_exact_bounded_and_separate_from_block_targets() {
        let diff1 = math::target_from_bits(0x1d00ffff).unwrap();
        assert_eq!(stratum_share_target(1.0).unwrap(), diff1);
        assert_eq!(stratum_share_target(65_536.0).unwrap(), &diff1 >> 16usize);
        assert_eq!(stratum_share_target(0.5).unwrap(), &diff1 * 2u32);
        assert_eq!(
            stratum_share_target(1e-12).unwrap(),
            (Amount::from(1u32) << 256usize) - 1u32
        );
        for bad in [0.0, -1.0, f64::INFINITY, f64::NAN, 1e-13, 1e19] {
            assert!(stratum_share_target(bad).is_err());
        }
    }
    #[test]
    fn stratum_minimum_respects_the_fixed_network_limit() {
        let mut config = Config::testnet();
        config.limit_bits = 0x1d00ffff;
        config.initial_bits = config.limit_bits;
        assert!(stratum_minimum_compatible(&config, 0.5).unwrap());
        assert!(!stratum_minimum_compatible(&config, 2.0).unwrap());
        config.limit_bits = math::MAX_TARGET_BITS;
        assert!(!stratum_minimum_compatible(&config, 0.5).unwrap());
        assert!(stratum_minimum_compatible(&config, 0.0).unwrap());
        assert!(stratum_minimum_compatible(&config, 1e-12).unwrap());

        let directory = tempfile::tempdir().unwrap();
        let miner = crypto::public_key(&[71; 32]).unwrap();
        let node = Node::open(&directory.path().join("jobs.sqlite"), config, miner).unwrap();
        let mut block = node.template().unwrap();
        let mut previous_difficulty = f64::MAX;
        for bits in [
            0x1d00ffff,
            0x1e00ffff,
            0x1f00ffff,
            0x207fffff,
            math::MAX_TARGET_BITS,
        ] {
            // Isolate job construction from mining. These successive targets
            // model target changes; jobs keep their own immutable thresholds.
            block.header.bits = bits;
            let job = StratumJob::new(Arc::new(block.clone()), 1.0).unwrap();
            assert_eq!(job.block_target, math::target_from_bits(bits).unwrap());
            assert!(
                job.share_target >= job.block_target,
                "valid network block discarded at {bits:08x}"
            );
            assert_eq!(
                job.share_target,
                stratum_share_target(job.difficulty).unwrap()
            );
            assert!(job.difficulty <= previous_difficulty);
            assert!(
                job.difficulty >= 1e-12,
                "accepted minimum must remain satisfiable"
            );
            previous_difficulty = job.difficulty;
        }
    }
    #[test]
    fn suggested_difficulty_respects_admin_and_negotiated_minimums() {
        assert_eq!(
            suggested_stratum_difficulty(1e-8, 65_536.0, 2e-8).unwrap(),
            65_536.0
        );
        assert_eq!(
            suggested_stratum_difficulty(65_536.0, 65_536.0, 1.0).unwrap(),
            65_536.0
        );
        assert_eq!(
            suggested_stratum_difficulty(65_536.0, 131_072.0, 262_144.0).unwrap(),
            262_144.0
        );
        assert!(suggested_stratum_difficulty(1.0, 1.0, f64::NAN).is_err());
    }
    #[test]
    fn advertised_mining_addresses_require_clean_explicit_endpoints() {
        for valid in [
            "127.0.0.1:3333",
            "miner.example:3333",
            "[::1]:3333",
            "[2001:db8::1]:3333",
        ] {
            assert_eq!(
                stratum_connect_url(valid).unwrap(),
                format!("stratum+tcp://{valid}")
            );
        }
        for invalid in [
            "",
            "miner.example",
            "stratum+tcp://miner.example:3333",
            "a:0",
            "a:65536",
            "0.0.0.0:3333",
            "[::]:3333",
            "a:3333/path",
            "a:3333?secret",
            "user@a:3333",
            "a:3333\n",
            "a :3333",
            "::1:3333",
            "[not-an-ip]:3333",
        ] {
            assert!(
                stratum_connect_url(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }
    #[test]
    fn mining_statistics_warm_up_expire_samples_and_remove_disconnected_workers() {
        let mut stats = MiningRuntime {
            started: Instant::now() - Duration::from_secs(31),
            ..MiningRuntime::default()
        };
        let miner = crypto::public_key(&[1; 32]).unwrap();
        assert!(stats.value(&miner, &[2; 32]).unwrap()["hashrate_hps"].is_null());
        for _ in 0..3 {
            stats.submission(None, Some((None, true)));
        }
        assert_eq!(stats.value(&miner, &[2; 32]).unwrap()["blocks_found"], "3");
        assert!(
            stats.value(&miner, &[2; 32]).unwrap()["hashrate_hps"].is_null(),
            "network-only blocks cannot satisfy reporting-share warmup"
        );
        for _ in 0..3 {
            stats.submission(None, Some((Some(&Amount::from(310u32)), false)));
        }
        let value = stats.value(&miner, &[2; 32]).unwrap();
        assert_eq!(value["accepted_shares"], "6");
        assert_eq!(value["blocks_found"], "3");
        assert_eq!(value["hashrate_hps"], "30");
        stats.prune(331);
        assert!(stats.buckets.is_empty());
        stats
            .workers
            .insert(7, idle_worker(Instant::now(), "127.0.0.1", false));
        let runtime = Arc::new(Mutex::new(stats));
        let registration = MiningConnection {
            runtime: runtime.clone(),
            id: 7,
        };
        drop(registration);
        assert!(runtime.lock().unwrap().workers.is_empty());
    }
    fn stash_read_fixture() -> (ReadView, PublicKey) {
        let c = Config::devnet();
        let mut s = State::genesis(&c);
        let key = crypto::public_key(&[1; 32]).unwrap();
        let other = crypto::public_key(&[2; 32]).unwrap();
        let scale = Amount::from(10u32).pow(18);
        for (public, shares) in [(key, 100u32), (other, 900u32)] {
            s.world
                .put(
                    public,
                    Account {
                        ordinary: 1000u32.into(),
                        shares: &scale * shares,
                        ..Account::default()
                    },
                    &c,
                )
                .unwrap();
        }
        s.world.reserve = 1000u32.into();
        s.world.curve_mass = 5000u32.into();
        s.world.shares = &scale * 1000u32;
        s.issued = 3000u32.into();
        s.height = 7;
        s.phase = crate::state::Phase::Auction(crate::state::Auction {
            round: 0,
            opened: 0,
            leader: None,
            lead_since: 0,
            replacement_height: 0,
            displaced: Default::default(),
        });
        s.world.validate(&c, &s.issued, &s.auction_escrow).unwrap();
        (
            ReadView {
                chain: PublishedChain {
                    config: Arc::new(c),
                    tip: [7; 32],
                    state: Arc::new(s),
                },
                mempool: Arc::from(Vec::new()),
                pool_revision: 0,
                cache: Arc::default(),
                storage: Arc::default(),
            },
            key,
        )
    }
    fn stash_test_apply(view: &ReadView, operation: Operation) -> State {
        let mut s = view.chain.tip_state().clone();
        let sender = crypto::public_key(&[1; 32]).unwrap();
        let transaction = crypto::sign(
            &s.chain_id,
            &TransactionBody {
                data: Vec::new(),
                sender,
                nonce: s.account(&sender, None).unwrap().nonce,
                fee: 1u32.into(),
                anchor: [38; 32],
                expiry_blocks: s.height + 1,
                operation,
            },
            &[1; 32],
        )
        .unwrap();
        crate::consensus::apply_transaction(&view.chain.config, &mut s, &transaction).unwrap();
        s.world
            .validate(&view.chain.config, &s.issued, &s.auction_escrow)
            .unwrap();
        if let Some(pass) = &s.alternative {
            pass.validate(&view.chain.config, &s.issued, &s.auction_escrow)
                .unwrap();
        }
        s
    }
    #[test]
    fn snapshot_balances_are_optional_bounded_and_chain_checked() {
        let (view, key) = stash_read_fixture();
        let key_hex = hex::encode(key);
        let encoded = address::encode(&key, &view.chain.chain_id()).unwrap();
        let unknown = hex::encode(crypto::public_key(&[3; 32]).unwrap());
        let original = Node::read_rpc(&view, "snapshot", json!({"key":key_hex})).unwrap();
        // The selected key also gets its pending rows; its next nonce is
        // reported once, by the embedded account read.
        assert_eq!(original.as_object().unwrap().len(), 11);
        assert_eq!(original["proposals_total"], 0);
        assert!(original.get("pending_nonce").is_none());
        assert_eq!(original["account"]["pending_nonce"], "0");
        assert!(original["sender_mempool"].is_array());
        assert!(original.get("balances").is_none());
        let mut snapshot = Node::read_rpc(
            &view,
            "snapshot",
            json!({"key":key_hex,"keys":[key_hex.to_uppercase(),encoded.to_uppercase(),unknown]}),
        )
        .unwrap();
        assert_eq!(snapshot["balances"].as_object().unwrap().len(), 2);
        assert_eq!(
            snapshot["balances"][&key_hex],
            json!({
                "account":{"ordinary":"1000","shares":"100000000000000000000"},
                "pass":null,"fail":null
            })
        );
        assert_eq!(
            snapshot["balances"][&unknown],
            json!({"account":null,"pass":null,"fail":null})
        );
        snapshot.as_object_mut().unwrap().remove("balances");
        assert_eq!(snapshot, original);
        let empty = Node::read_rpc(&view, "snapshot", json!({"keys":[]})).unwrap();
        assert_eq!(empty["balances"], json!({}));
        let full = Node::read_rpc(
            &view,
            "snapshot",
            json!({"keys":vec![key_hex.clone();MAX_SNAPSHOT_KEYS]}),
        )
        .unwrap();
        assert_eq!(full["balances"].as_object().unwrap().len(), 1);

        let wrong_network = address::encode(&key, &[99; 32]).unwrap();
        for keys in [
            Value::Null,
            json!({}),
            json!(key_hex),
            json!([null]),
            json!([42]),
            json!([key_hex, "invalid"]),
            json!([hex::encode([0; 32])]),
            json!([wrong_network]),
            json!(vec![key_hex.clone(); MAX_SNAPSHOT_KEYS + 1]),
        ] {
            assert!(Node::read_rpc(&view, "snapshot", json!({"keys":keys})).is_err());
        }
        assert_eq!(rpc_cost("snapshot", &json!({})), 48);
        assert_eq!(rpc_cost("snapshot", &json!({"keys":[key_hex]})), 52);
        assert_eq!(
            rpc_cost(
                "snapshot",
                &json!({"keys":vec![key_hex;MAX_SNAPSHOT_KEYS + 1]})
            ),
            48 + 4 * MAX_SNAPSHOT_KEYS
        );
    }

    #[test]
    fn snapshot_balances_follow_both_governance_worlds() {
        let (mut view, key) = stash_read_fixture();
        let s = Arc::make_mut(&mut view.chain.state);
        s.phase = crate::state::Phase::Governance(crate::state::Decision {
            id: [3; 32],
            epoch: 1,
            round: 0,
            proposal_id: [4; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: 1_048_576,
                new: 2_097_152,
            }
            .into(),
            started: 0,
            started_height: 0,
            blocks: 64,
            leading_blocks: 0,
        });
        s.alternative = Some(s.world.clone());
        view.chain.state = Arc::new(stash_test_apply(
            &view,
            Operation::Deposit {
                amount: 40u32.into(),
                decision: Some([3; 32]),
                outcome: Some(Outcome::Pass),
            },
        ));
        let key_hex = hex::encode(key);
        let snapshot =
            Node::read_rpc(&view, "snapshot", json!({"key":key_hex,"keys":[key_hex]})).unwrap();
        assert_eq!(snapshot["account"], snapshot["fail"]);
        assert_eq!(
            snapshot["fail"],
            Node::read_rpc(&view, "account", json!({"key":key_hex,"outcome":"fail"})).unwrap()
        );
        for field in ["account", "pass", "fail"] {
            let bare = &snapshot["balances"][&key_hex][field];
            assert_eq!(bare.as_object().unwrap().len(), 2);
            for amount in ["ordinary", "shares"] {
                assert_eq!(bare[amount], snapshot[field]["account"][amount]);
            }
        }
        assert_eq!(snapshot["balances"][&key_hex]["pass"]["ordinary"], "959");
        assert!(snapshot["balances"][&key_hex]["pass"]["conditional"].is_null());
        assert!(snapshot["balances"][&key_hex]["fail"]["conditional"].is_null());
        assert_ne!(
            snapshot["balances"][&key_hex]["pass"]["shares"],
            snapshot["balances"][&key_hex]["fail"]["shares"]
        );
        assert_eq!(
            snapshot["status"]["state_root"],
            snapshot["governance"]["state_root"]
        );
    }

    #[test]
    fn automatic_outcome_rpc_quotes_and_common_payment_capacity_are_consistent() {
        let (mut view, key) = stash_read_fixture();
        let config = Config::devnet();
        let state = Arc::make_mut(&mut view.chain.state);
        state.chain_id = config.chain_id();
        state.settings.minimum_fee_rate = config.initial.minimum_fee_rate;
        state.phase = crate::state::Phase::Governance(crate::state::Decision {
            id: [3; 32],
            epoch: 1,
            round: 0,
            proposal_id: [4; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: 1_048_576,
                new: 2_097_152,
            }
            .into(),
            started: 0,
            started_height: 0,
            blocks: 64,
            leading_blocks: 0,
        });
        state.alternative = Some(state.world.clone());
        view.chain.config = Arc::new(config);
        let config = &view.chain.config;
        let mut state = view.chain.tip_state().clone();
        let operation = Operation::Deposit {
            amount: 40u32.into(),
            decision: Some([3; 32]),
            outcome: Some(Outcome::Pass),
        };
        let tx = crypto::sign(
            &state.chain_id,
            &TransactionBody {
                data: Vec::new(),
                sender: key,
                nonce: 0,
                fee: 100u32.into(),
                anchor: [38; 32],
                expiry_blocks: state.height + 1,
                operation,
            },
            &[1; 32],
        )
        .unwrap();
        let fee = crate::fees::quote(config, &state, &tx).unwrap().fee;
        crate::consensus::apply_transaction(config, &mut state, &tx).unwrap();
        let pass_cash = Amount::from(960u32) - &fee;
        let fail_cash = Amount::from(1000u32) - &fee;
        view.chain.state = Arc::new(state);
        let snapshot = Node::read_rpc(&view, "snapshot", json!({"key":hex::encode(key)})).unwrap();
        assert_eq!(
            snapshot["payment_available_hash"],
            pass_cash.to_str_radix(10)
        );
        assert_eq!(
            snapshot["account"]["account"]["ordinary"],
            fail_cash.to_str_radix(10)
        );
        for side in ["pass", "fail"] {
            assert_eq!(
                snapshot[side]["payment_available_hash"],
                pass_cash.to_str_radix(10)
            );
            assert!(snapshot[side]["account"]["conditional"].is_null());
        }
        // Raw FAIL cash is usable for a FAIL trade even though only the smaller
        // PASS amount can be sent as an ordinary payment. Quotes exclude fees.
        let amount = (&pass_cash + 1u32).to_str_radix(10);
        let params =
            |side| json!({"key":hex::encode(key),"outcome":side,"kind":"deposit","amount":amount});
        assert!(Node::read_rpc(&view, "stash_quote", params("pass")).is_err());
        assert!(Node::read_rpc(&view, "stash_quote", params("fail")).is_ok());
        for operation in [
            json!({"Commit":{"amount":"1","decision":([3u8; 32])}}),
            json!({"Merge":{"amount":"1","decision":([3u8; 32])}}),
        ] {
            assert!(serde_json::from_value::<Operation>(operation.clone()).is_err());
            let request = json!({"sender":hex::encode(key),"operation":operation});
            assert!(Node::read_rpc(&view, "fee_quote", request.clone()).is_err());
            assert!(Node::read_rpc(&view, "preparetransaction", request).is_err());
        }
    }

    #[test]
    fn snapshot_balances_use_the_published_view_after_chain_changes() {
        let dir = tempfile::tempdir().unwrap();
        let key = crypto::public_key(&[1; 32]).unwrap();
        let key_hex = hex::encode(key);
        let node = Node::open(&dir.path().join("chain.sqlite"), Config::devnet(), key).unwrap();
        let request = json!({"key":key_hex,"keys":[key_hex]});
        let old_view = node.read_view().unwrap();
        let before = Node::read_rpc(&old_view, "snapshot", request.clone()).unwrap();
        assert!(before["balances"][&key_hex]["account"].is_null());
        node.mine(100_000).unwrap();
        let after = node.rpc("snapshot", request.clone()).unwrap();
        assert_eq!(after["status"]["height"], 1);
        assert_eq!(
            after["balances"][&key_hex]["account"]["ordinary"],
            after["account"]["account"]["ordinary"]
        );
        assert_ne!(
            after["status"]["state_root"],
            before["status"]["state_root"]
        );
        assert_eq!(
            Node::read_rpc(&old_view, "snapshot", request).unwrap(),
            before
        );
    }
    #[test]
    fn storage_that_cannot_take_blocks_is_reported_until_it_can() {
        let dir = tempfile::tempdir().unwrap();
        let key = crypto::public_key(&[1; 32]).unwrap();
        let node = Node::open(&dir.path().join("chain.sqlite"), Config::devnet(), key).unwrap();
        node.mine(100_000).unwrap();
        let healthy = node.status().unwrap()["storage"].clone();
        assert_eq!(healthy["degraded"], false);
        assert_eq!(healthy["failed_commits"], 0);
        // Blocks commit until the database cannot grow, as on a full disk.
        node.locked().unwrap().chain.limit_database_pages(Some(0));
        let mut mined = 0;
        let error = loop {
            match node.mine(100_000) {
                Ok(_) => mined += 1,
                Err(error) => break error,
            }
            assert!(mined < 200, "the database never filled");
        };
        assert!(format!("{error:#}").contains("full"), "{error:#}");
        assert!(node.storage_degraded().unwrap());
        for report in [
            node.status().unwrap()["storage"].clone(),
            node.rpc("status", json!({})).unwrap()["storage"].clone(),
            node.peer_status().unwrap()["storage"].clone(),
        ] {
            assert_eq!(report["degraded"], true, "{report}");
            assert_eq!(report["failed_commits"], 1);
            assert!(report["last_error"].as_str().unwrap().contains("full"));
        }
        // A stored block ends the streak.
        node.locked().unwrap().chain.limit_database_pages(None);
        node.mine(100_000).unwrap();
        assert!(!node.storage_degraded().unwrap());
        assert_eq!(node.peer_status().unwrap()["storage"]["degraded"], false);
    }
    #[test]
    fn the_node_stops_only_after_storage_failed_repeatedly_for_a_minute() {
        let failing = |failed_commits, since| StorageHealth {
            failed_commits,
            failing_since: Some(since),
            last_error: Some("database or disk is full".into()),
            checkpoint_error: None,
        };
        let now = 10_000;
        assert!(storage_exit_due(
            &failing(STORAGE_EXIT_FAILURES, now - 60),
            now
        ));
        // Fewer failures, or a burst of deliveries within the minute, do not.
        assert!(!storage_exit_due(
            &failing(STORAGE_EXIT_FAILURES - 1, now - 600),
            now
        ));
        assert!(!storage_exit_due(&failing(100, now - 59), now));
        assert!(!storage_exit_due(&StorageHealth::default(), now));
    }
    #[test]
    fn stash_quotes_match_execution_and_account_withdrawal_value() {
        let (view, key) = stash_read_fixture();
        let account = Node::read_rpc(&view, "account", json!({"key":hex::encode(key)})).unwrap();
        assert_eq!(account["stash_withdrawal_hash"], "409");
        assert_eq!(
            account["stash_value_hash"]["numerator"],
            "500000000000000000000000"
        );
        let root = view.chain.tip_state().root();
        for kind in ["deposit", "withdraw"] {
            for amount in [1u32, 10, 100, 409] {
                let quote = Node::read_rpc(
                    &view,
                    "stash_quote",
                    json!({"key":hex::encode(key),"kind":kind,"amount":amount.to_string()}),
                )
                .unwrap();
                assert_eq!(quote["height"], 7);
                assert_eq!(quote["tip"], hex::encode([7; 32]));
                assert_eq!(quote["state_root"], hex::encode(root));
                assert_eq!(quote["transaction_fee_included"], false);
                assert!(quote["decision"].is_null());
                let shares = parse_amount(quote["shares"].as_str().unwrap()).unwrap();
                let output = parse_amount(quote["output_hash"].as_str().unwrap()).unwrap();
                let operation = if kind == "deposit" {
                    Operation::Deposit {
                        amount: amount.into(),
                        decision: None,
                        outcome: None,
                    }
                } else {
                    if quote["input_unfilled"] == "0" {
                        assert!(output >= Amount::from(amount));
                    }
                    let w = &view.chain.tip_state().world;
                    assert!(stash_withdrawal(w, &(&shares - 1u32)).unwrap() < Amount::from(amount));
                    Operation::Redeem {
                        shares,
                        decision: None,
                        outcome: None,
                    }
                };
                let next = stash_test_apply(&view, operation);
                let a = next.account(&key, None).unwrap();
                let after = stash_withdrawal(&next.world, &a.shares).unwrap();
                assert_eq!(quote["stash_after_hash"], after.to_str_radix(10));
                assert_eq!(quote["share_before"], account["account"]["shares"]);
                assert_eq!(quote["share_after"], a.shares.to_str_radix(10));
                if kind == "deposit" {
                    assert_eq!(after - 409u32, output);
                    let filled = parse_amount(quote["input_filled"].as_str().unwrap()).unwrap();
                    assert_eq!(a.ordinary, Amount::from(999u32) - filled);
                } else {
                    assert_eq!(a.ordinary, 999u32 + output);
                }
            }
        }
        let all = Node::read_rpc(
            &view,
            "stash_quote",
            json!({"key":hex::encode(key),"kind":"withdraw","all":true}),
        )
        .unwrap();
        assert_eq!(all["amount"], "409");
        assert!(parse_amount(all["output_hash"].as_str().unwrap()).unwrap() < 409u32.into());
        assert_ne!(all["input_unfilled"], "0");
        assert_eq!(all["indicative"], true);
        assert_eq!(all["partial_fill_possible"], true);
        assert_eq!(all["shares"], account["account"]["shares"]);
        assert_eq!(all["share_before"], account["account"]["shares"]);
        assert_ne!(all["share_after"], "0");
        let next = stash_test_apply(
            &view,
            Operation::Redeem {
                shares: parse_amount(all["shares"].as_str().unwrap()).unwrap(),
                decision: None,
                outcome: None,
            },
        );
        assert_eq!(
            next.account(&key, None).unwrap().shares.to_str_radix(10),
            all["share_after"]
        );
        assert_eq!(
            root,
            view.chain.tip_state().root(),
            "quotes must not mutate state"
        );
    }
    #[test]
    fn stash_quotes_reject_invalid_amounts_and_context() {
        let (view, key) = stash_read_fixture();
        for patch in [
            json!({"amount":"0"}),
            json!({"amount":"01"}),
            json!({"amount":"-1"}),
            json!({"amount":1}),
            json!({"amount":"9".repeat(156)}),
            json!({"kind":"unsupported"}),
            json!({"all":"true"}),
            json!({"kind":"deposit","all":true}),
            json!({"kind":"deposit","amount":"1001"}),
            json!({"amount":"410"}),
            json!({"outcome":"Pass"}),
            json!({"outcome":"Fail"}),
            json!({"outcome":1}),
            json!({"key":hex::encode(crypto::public_key(&[3;32]).unwrap())}),
        ] {
            let mut request = json!({"key":hex::encode(key),"kind":"withdraw","amount":"1"});
            request
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            assert!(
                Node::read_rpc(&view, "stash_quote", request.clone()).is_err(),
                "{request}"
            );
        }
        for outcome in [json!("Pass"), json!("Fail"), json!(1), json!({})] {
            assert!(
                Node::read_rpc(
                    &view,
                    "quote",
                    json!({"kind":"deposit","amount":"1","outcome":outcome})
                )
                .is_err()
            );
        }
        let governance = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(governance["time_unit"], "seconds");
        assert!(governance["progress"].is_null());
    }
    #[test]
    fn stash_quotes_redeem_exact_share_atoms_and_report_remaining_holdings() {
        let (view, key) = stash_read_fixture();
        let scale = Amount::from(10u32).pow(18);
        let before = view.chain.tip_state().account(&key, None).unwrap().shares;
        let root = view.chain.tip_state().root();
        for units in [1u32, 10, 99, 100] {
            let atoms = &scale * units;
            let quote = Node::read_rpc(
                &view,
                "stash_quote",
                json!({"key":hex::encode(key),"kind":"redeem","amount":atoms.to_str_radix(10)}),
            )
            .unwrap();
            assert_eq!(quote["kind"], "redeem");
            assert_eq!(quote["amount"], atoms.to_str_radix(10));
            assert_eq!(quote["shares"], atoms.to_str_radix(10));
            assert_eq!(quote["share_before"], before.to_str_radix(10));
            let filled = parse_amount(quote["input_filled"].as_str().unwrap()).unwrap();
            assert!(filled <= atoms);
            assert_eq!(quote["share_after"], (&before - &filled).to_str_radix(10));
            let payout = parse_amount(quote["output_hash"].as_str().unwrap()).unwrap();
            let next = stash_test_apply(
                &view,
                Operation::Redeem {
                    shares: atoms,
                    decision: None,
                    outcome: None,
                },
            );
            let account = next.account(&key, None).unwrap();
            assert_eq!(quote["share_after"], account.shares.to_str_radix(10));
            assert_eq!(
                quote["stash_after_hash"],
                stash_withdrawal(&next.world, &account.shares)
                    .unwrap()
                    .to_str_radix(10)
            );
            assert_eq!(account.ordinary, 999u32 + payout);
        }
        for amount in [None, Some("0"), Some("1")] {
            let mut request = json!({"key":hex::encode(key),"kind":"redeem","all":true});
            if let Some(amount) = amount {
                request["amount"] = json!(amount);
            }
            let quote = Node::read_rpc(&view, "stash_quote", request).unwrap();
            assert_eq!(quote["amount"], before.to_str_radix(10));
            assert_eq!(quote["shares"], before.to_str_radix(10));
            assert_ne!(quote["share_after"], "0");
            assert_ne!(quote["input_unfilled"], "0");
            assert!(parse_amount(quote["output_hash"].as_str().unwrap()).unwrap() < 409u32.into());
        }
        for amount in [
            "0".to_string(),
            "01".to_string(),
            (&before + 1u32).to_str_radix(10),
            (Amount::from(1u32) << 256usize).to_str_radix(10),
        ] {
            assert!(
                Node::read_rpc(
                    &view,
                    "stash_quote",
                    json!({"key":hex::encode(key),"kind":"redeem","amount":amount})
                )
                .is_err()
            );
        }
        for outcome in ["Pass", "Fail"] {
            assert!(Node::read_rpc(&view, "stash_quote", json!({"key":hex::encode(key),"kind":"redeem","amount":scale.to_str_radix(10),"outcome":outcome})).is_err());
        }
        assert_eq!(root, view.chain.tip_state().root());
    }
    #[test]
    fn stash_quotes_follow_both_governance_worlds() {
        let (mut view, key) = stash_read_fixture();
        let s = Arc::make_mut(&mut view.chain.state);
        s.phase = crate::state::Phase::Governance(crate::state::Decision {
            id: [3; 32],
            epoch: 1,
            round: 0,
            proposal_id: [4; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::BlockBytes,
                old: 1_048_576,
                new: 2_097_152,
            }
            .into(),
            started: 0,
            started_height: 0,
            blocks: 64,
            leading_blocks: 0,
        });
        s.alternative = Some(s.world.clone());
        view.chain.state = Arc::new(stash_test_apply(
            &view,
            Operation::Deposit {
                amount: 40u32.into(),
                decision: Some([3; 32]),
                outcome: Some(Outcome::Pass),
            },
        ));
        assert!(
            Node::read_rpc(
                &view,
                "stash_quote",
                json!({"key":hex::encode(key),"kind":"withdraw","amount":"1"})
            )
            .is_err()
        );
        for outcome in [Value::Null, json!(1), json!({})] {
            assert!(
                Node::read_rpc(
                    &view,
                    "quote",
                    json!({"kind":"deposit","amount":"10","outcome":outcome})
                )
                .is_err()
            );
        }
        assert!(Node::read_rpc(&view, "quote", json!({"kind":"deposit","amount":"10"})).is_err());
        let governance = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(governance["time_unit"], "seconds");
        assert_eq!(governance["clock"], view.chain.tip_state().clock);
        assert_eq!(governance["progress"]["time_unit"], "blocks");
        assert_eq!(governance["progress"]["observed_blocks"], 7);
        assert_eq!(governance["progress"]["blocks_remaining"], 57);
        let mut before_values = vec![];
        for outcome in [Outcome::Pass, Outcome::Fail] {
            for kind in ["withdraw", "deposit", "redeem"] {
                let amount = if kind == "redeem" {
                    "1000000000000000000"
                } else {
                    "10"
                };
                let quote = Node::read_rpc(
                    &view,
                    "stash_quote",
                    json!({"key":hex::encode(key),"kind":kind,"amount":amount,"outcome":outcome}),
                )
                .unwrap();
                if kind != "withdraw" {
                    let generic = Node::read_rpc(
                        &view,
                        "quote",
                        json!({"kind":kind,"amount":amount,"outcome":outcome}),
                    )
                    .unwrap();
                    for field in [
                        "input_requested",
                        "input_filled",
                        "input_unfilled",
                        "output",
                        "decision",
                    ] {
                        assert_eq!(generic[field], quote[field], "{kind} {field}");
                    }
                }
                assert_eq!(quote["decision"], hex::encode([3; 32]));
                assert_eq!(quote["outcome"], json!(outcome));
                if kind == "withdraw" {
                    before_values.push(quote["stash_before_hash"].clone());
                }
                let shares = parse_amount(quote["shares"].as_str().unwrap()).unwrap();
                let operation = if kind == "deposit" {
                    Operation::Deposit {
                        amount: 10u32.into(),
                        decision: Some([3; 32]),
                        outcome: Some(outcome),
                    }
                } else {
                    Operation::Redeem {
                        shares,
                        decision: Some([3; 32]),
                        outcome: Some(outcome),
                    }
                };
                let next = stash_test_apply(&view, operation);
                let w = if outcome == Outcome::Pass {
                    next.alternative.as_ref().unwrap()
                } else {
                    &next.world
                };
                let a = next.account(&key, Some(outcome)).unwrap();
                assert_eq!(
                    quote["share_before"],
                    view.chain
                        .tip_state()
                        .account(&key, Some(outcome))
                        .unwrap()
                        .shares
                        .to_str_radix(10)
                );
                assert_eq!(quote["share_after"], a.shares.to_str_radix(10));
                assert_eq!(
                    quote["stash_after_hash"],
                    stash_withdrawal(w, &a.shares).unwrap().to_str_radix(10)
                );
                let before_cash = view
                    .chain
                    .tip_state()
                    .account(&key, Some(outcome))
                    .unwrap()
                    .ordinary;
                let after_cash = if kind == "deposit" {
                    before_cash
                        - parse_amount(quote["input_filled"].as_str().unwrap()).unwrap()
                        - 1u32
                } else {
                    before_cash + parse_amount(quote["output_hash"].as_str().unwrap()).unwrap()
                        - 1u32
                };
                assert_eq!(a.ordinary, after_cash);
            }
        }
        assert_ne!(before_values[0], before_values[1]);
    }
    #[test]
    fn conditional_trading_closes_at_the_decisions_last_tip() {
        let (mut view, key) = stash_read_fixture();
        let decision = |blocks| {
            crate::state::Phase::Governance(crate::state::Decision {
                id: [3; 32],
                epoch: 1,
                round: 0,
                proposal_id: [4; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::BlockBytes,
                    old: 1_048_576,
                    new: 2_097_152,
                }
                .into(),
                started: 0,
                started_height: 0,
                blocks,
                leading_blocks: 0,
            })
        };
        let s = Arc::make_mut(&mut view.chain.state);
        // The fixture tip is height 7: its child, height 8, resolves an
        // eight-block decision before any of its transactions.
        s.phase = decision(8);
        s.alternative = Some(s.world.clone());
        let request = |operation| WalletRequest {
            operation,
            fee: None,
            extra_fee: None,
            data_hex: None,
            expiry_blocks: None,
            anchor: None,
            nonce: None,
        };
        let deposit = Operation::Deposit {
            amount: 10u32.into(),
            decision: Some([3; 32]),
            outcome: Some(Outcome::Pass),
        };
        let redeem = Operation::Redeem {
            shares: 1u32.into(),
            decision: Some([3; 32]),
            outcome: Some(Outcome::Fail),
        };
        let closed =
            |error: anyhow::Error| error.to_string().contains("conditional trading is closed");
        let governance = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(governance["progress"]["trading_closed"], true);
        assert_eq!(governance["progress"]["blocks_remaining"], 1);
        for (method, params) in [
            (
                "stash_quote",
                json!({"key":hex::encode(key),"kind":"deposit","amount":"10","outcome":"pass"}),
            ),
            (
                "stash_quote",
                json!({"key":hex::encode(key),"kind":"redeem","amount":"1","outcome":"fail"}),
            ),
            (
                "quote",
                json!({"kind":"deposit","amount":"10","outcome":"fail"}),
            ),
        ] {
            assert!(
                closed(Node::read_rpc(&view, method, params).unwrap_err()),
                "{method}"
            );
        }
        for operation in [deposit.clone(), redeem.clone()] {
            let fee = json!({"sender":hex::encode(key),"operation":operation});
            assert!(closed(Node::read_rpc(&view, "fee_quote", fee).unwrap_err()));
            assert!(closed(
                Node::prepare_view(&view, key, request(operation)).unwrap_err()
            ));
        }
        // Operations common to both outcomes still execute in that block.
        let recipient = crypto::public_key(&[2; 32]).unwrap();
        let transfer = Operation::TransferExact {
            recipient,
            amount: 1u32.into(),
        };
        assert!(Node::prepare_view(&view, key, request(transfer)).is_ok());
        // One block earlier the same decision still trades.
        Arc::make_mut(&mut view.chain.state).phase = decision(9);
        view.cache = Arc::default();
        let governance = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(governance["progress"]["trading_closed"], false);
        assert!(
            Node::read_rpc(
                &view,
                "stash_quote",
                json!({"key":hex::encode(key),"kind":"deposit","amount":"10","outcome":"pass"})
            )
            .is_ok()
        );
        assert!(
            Node::read_rpc(
                &view,
                "quote",
                json!({"kind":"deposit","amount":"10","outcome":"fail"})
            )
            .is_ok()
        );
        assert!(Node::prepare_view(&view, key, request(deposit)).is_ok());
        assert!(Node::prepare_view(&view, key, request(redeem)).is_ok());
    }
    #[test]
    fn stash_quotes_handle_empty_dust_and_exhausted_curves() {
        let (mut view, key) = stash_read_fixture();
        let s = Arc::make_mut(&mut view.chain.state);
        let mut a = s.account(&key, None).unwrap();
        a.shares = 0u32.into();
        s.world.put(key, a.clone(), &view.chain.config).unwrap();
        let request = json!({"key":hex::encode(key),"kind":"withdraw","all":true,"amount":"0"});
        assert!(Node::read_rpc(&view, "stash_quote", request.clone()).is_err());
        assert_eq!(
            Node::read_rpc(&view, "account", json!({"key":hex::encode(key)})).unwrap()["stash_withdrawal_hash"],
            "0"
        );
        // A nonzero position may still pay zero integer HASH.
        a.shares = 1u32.into();
        Arc::make_mut(&mut view.chain.state)
            .world
            .put(key, a.clone(), &view.chain.config)
            .unwrap();
        let dust = Node::read_rpc(&view, "stash_quote", request.clone()).unwrap();
        assert_eq!(dust["input_filled"], "0");
        assert_eq!(dust["output_hash"], "0");
        // A 100% downward movement allowance permits emptying a curve.
        let s = Arc::make_mut(&mut view.chain.state);
        s.settings.max_price_change_bps = 10_000;
        s.world.accounts = Default::default();
        s.world.account_cash = 0u32.into();
        s.world.account_shares = 0u32.into();
        a.shares = s.world.shares.clone();
        s.world.put(key, a.clone(), &view.chain.config).unwrap();
        s.issued = 2000u32.into();
        let quote = Node::read_rpc(&view, "stash_quote", request).unwrap();
        assert_eq!(quote["output_hash"], "1000");
        let next = stash_test_apply(
            &view,
            Operation::Redeem {
                shares: a.shares,
                decision: None,
                outcome: None,
            },
        );
        assert!(next.world.reserve.is_zero() && next.world.shares.is_zero());
        view.chain.state = Arc::new(next);
        // A fully redeemed curve can reopen at the starting rate.
        let quote = Node::read_rpc(
            &view,
            "stash_quote",
            json!({"key":hex::encode(key),"kind":"deposit","amount":"10"}),
        )
        .unwrap();
        assert_eq!(quote["stash_before_hash"], "0");
        assert_eq!(quote["stash_after_hash"], "10");
        let next = stash_test_apply(
            &view,
            Operation::Deposit {
                amount: 10u32.into(),
                decision: None,
                outcome: None,
            },
        );
        assert_eq!(next.world.reserve, 10u32.into());
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn genesis_rpc_quotes_stash_and_keeps_mining_rewards_spendable() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::testnet();
        let miner = crypto::public_key(&[1; 32]).unwrap();
        let node = Node::open(&dir.path().join("chain.sqlite"), config.clone(), miner).unwrap();
        let snapshot = node.rpc("snapshot", json!({})).unwrap();
        assert_eq!(snapshot["status"]["phase"], "rest");
        assert_eq!(
            snapshot["governance"]["phase"]["Rest"]["until"],
            config.initial.rest
        );
        assert!(snapshot["proposals"].as_array().unwrap().is_empty());
        assert_eq!(
            node.rpc("quote", json!({"kind":"deposit","amount":"1"}))
                .unwrap()["output"],
            config.share_scale.to_str_radix(10)
        );
        assert_eq!(
            node.rpc("grant_quote", json!({"amount":"1"})).unwrap()["feasible"],
            false
        );
        node.mine(100_000).unwrap();
        let account = node
            .rpc("account", json!({"key":hex::encode(miner)}))
            .unwrap();
        assert_ne!(account["account"]["ordinary"], "0");
        assert_eq!(account["account"]["shares"], "0");
        assert_eq!(account["price_hash_per_share"]["numerator"], "1");
        assert_eq!(
            account["price_hash_per_share"]["denominator"],
            config.share_scale.to_str_radix(10)
        );
        let quote = node
            .rpc(
                "stash_quote",
                json!({"key":hex::encode(miner),"kind":"deposit","amount":"1"}),
            )
            .unwrap();
        assert_eq!(quote["shares"], config.share_scale.to_str_radix(10));
        let request = json!({"sender":hex::encode(miner),"operation":Operation::Deposit {
            amount: 1u32.into(), decision: None, outcome: None,
        },"extra_fee":"0"});
        let prepared = node.rpc("preparetransaction", request).unwrap();
        assert_eq!(prepared["fee_quote"]["expiry_height"], 3);
    }
    #[tokio::test]
    async fn bounded_line_rejects_before_unbounded_allocation() {
        let bytes = b"123456789\n";
        let mut reader = BufReader::new(&bytes[..]);
        assert!(bounded_line(&mut reader, 5).await.is_err());
        let mut reader = BufReader::new(&bytes[..]);
        assert_eq!(bounded_line(&mut reader, 10).await.unwrap(), bytes);
    }
    #[tokio::test]
    async fn mining_disconnects_are_distinct_from_incomplete_or_oversized_frames() {
        for (bytes, clean) in [(&b""[..], true), (&b"partial"[..], false)] {
            let mut reader = BufReader::new(bytes);
            let mut partial = Vec::new();
            let error = bounded_line_buf(&mut reader, 16, &mut partial)
                .await
                .unwrap_err();
            assert_eq!(disconnected_between_frames(&error, &partial), clean);
        }
        let mut reader = BufReader::new(&b"oversized first frame\n"[..]);
        let mut partial = Vec::new();
        let error = bounded_line_buf(&mut reader, 4, &mut partial)
            .await
            .unwrap_err();
        assert!(partial.is_empty());
        assert!(!disconnected_between_frames(&error, &partial));
        let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset).into();
        assert!(disconnected_between_frames(&reset, &[]));
        assert!(!disconnected_between_frames(&reset, b"partial"));
    }
    #[tokio::test]
    async fn authorized_miners_can_disconnect_and_immediately_reconnect() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[44; 32]).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for id in 1u32..=3 {
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (server, peer) = listener.accept().await.unwrap();
            let admission = node.guard.admit(peer.ip(), Surface::Stratum).unwrap();
            let session = tokio::spawn(stratum_session(
                node.clone(),
                server,
                None,
                DEFAULT_STRATUM_SHARE_DIFFICULTY,
                id.to_le_bytes(),
                admission,
                None,
            ));
            let (read, mut write) = client.into_split();
            let mut read = BufReader::new(read);
            write_json(
                &mut write,
                &json!({"id":1,"method":"mining.subscribe","params":[]}),
            )
            .await
            .unwrap();
            let response: Value = serde_json::from_slice(
                &timeout(Duration::from_secs(2), bounded_line(&mut read, 16384))
                    .await
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert!(response["error"].is_null());
            write_json(
                &mut write,
                &json!({"id":2,"method":"mining.authorize","params":["reconnecting.worker","x"]}),
            )
            .await
            .unwrap();
            loop {
                let response: Value = serde_json::from_slice(
                    &timeout(Duration::from_secs(2), bounded_line(&mut read, 16384))
                        .await
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert!(response["error"].is_null());
                if response["method"] == "mining.notify" {
                    break;
                }
            }
            write.shutdown().await.unwrap();
            timeout(Duration::from_secs(2), session)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(node.mining_status().unwrap()["workers_connected"], 0);
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_block_waits_for_busy_mining_workers_instead_of_being_dropped() {
        async fn message<R: AsyncBufRead + Unpin>(read: &mut R) -> Value {
            let line = timeout(Duration::from_secs(10), bounded_line(read, 16384))
                .await
                .expect("mining session stopped responding")
                .expect("mining session closed");
            serde_json::from_slice(&line).unwrap()
        }
        async fn job<R: AsyncBufRead + Unpin>(read: &mut R) -> Value {
            loop {
                let value = message(read).await;
                assert!(value["error"].is_null(), "{value}");
                if value["method"] == "mining.notify" {
                    return value;
                }
            }
        }
        async fn reply<R: AsyncBufRead + Unpin>(read: &mut R, id: u64) -> Value {
            loop {
                let value = message(read).await;
                if value["id"] == id {
                    return value;
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[45; 32]).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let admission = node.guard.admit(peer.ip(), Surface::Stratum).unwrap();
        let extra1 = 9u32.to_le_bytes();
        let session = tokio::spawn(stratum_session(
            node.clone(),
            server,
            None,
            DEFAULT_STRATUM_SHARE_DIFFICULTY,
            extra1,
            admission,
            None,
        ));
        let (read, mut write) = client.into_split();
        let mut read = BufReader::new(read);
        for (id, method, params) in [
            (1, "mining.subscribe", json!([])),
            (2, "mining.authorize", json!(["patient.worker", "x"])),
        ] {
            write_json(
                &mut write,
                &json!({"id":id,"method":method,"params":params}),
            )
            .await
            .unwrap();
        }
        let solve = |job: &Value, extra2: [u8; 4]| {
            let p = &job["params"];
            let word = |value: &Value| u32::from_str_radix(value.as_str().unwrap(), 16).unwrap();
            let mut coinbase = hex::decode(p[2].as_str().unwrap()).unwrap();
            coinbase.extend(extra1);
            coinbase.extend(extra2);
            coinbase.extend(hex::decode(p[3].as_str().unwrap()).unwrap());
            let mut previous: Hash = hex::decode(p[1].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            for chunk in previous.chunks_exact_mut(4) {
                chunk.reverse();
            }
            let mut header = Header {
                version: word(&p[5]),
                previous,
                merkle_root: crypto::sha256d(&coinbase),
                timestamp: word(&p[7]),
                bits: word(&p[6]),
                nonce: 0,
            };
            let target = math::target_from_bits(header.bits).unwrap();
            while math::check_pow(&header, &target).is_err() {
                header.nonce += 1;
            }
            json!([
                "patient.worker",
                p[0],
                hex::encode(extra2),
                format!("{:08x}", header.timestamp),
                format!("{:08x}", header.nonce)
            ])
        };
        // Both mining workers are busy, as with two sessions waiting for
        // template builds: a solved block never waits for them.
        let found = solve(&job(&mut read).await, [7; 4]);
        let busy = node
            .stratum_workers
            .clone()
            .acquire_many_owned(2)
            .await
            .unwrap();
        write_json(
            &mut write,
            &json!({"id":3,"method":"mining.submit","params":found}),
        )
        .await
        .unwrap();
        assert_eq!(reply(&mut read, 3).await["result"], true);
        assert_eq!(node.status().unwrap()["height"], 1);
        drop(busy);
        // Its own permits busy for longer than the I/O timeout, a solution
        // waits for capacity rather than ending the session.
        let found = solve(&job(&mut read).await, [8; 4]);
        let held = node
            .block_submissions
            .clone()
            .acquire_many_owned(2)
            .await
            .unwrap();
        write_json(
            &mut write,
            &json!({"id":4,"method":"mining.submit","params":found}),
        )
        .await
        .unwrap();
        tokio::time::sleep(IO_TIMEOUT + Duration::from_secs(1)).await;
        assert!(!session.is_finished(), "busy workers ended the session");
        assert_eq!(node.status().unwrap()["height"], 1);
        drop(held);
        let reply = reply(&mut read, 4).await;
        assert_eq!(reply["result"], true, "{reply}");
        assert_eq!(node.status().unwrap()["height"], 2);
        assert_eq!(node.mining_status().unwrap()["blocks_found"], "2");
        write.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[test]
    fn canonical_rpc_amounts() {
        assert!(parse_amount("01").is_err());
        assert!(parse_amount("-1").is_err());
        assert_eq!(parse_amount("123").unwrap(), 123u32.into());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn solved_block_survives_an_address_cooldown_from_another_session() {
        async fn reply<R: AsyncBufRead + Unpin>(read: &mut R, id: u64) -> Value {
            loop {
                let line = timeout(Duration::from_secs(5), bounded_line(read, 16384))
                    .await
                    .expect("mining session stopped responding")
                    .expect("mining session closed");
                let value: Value = serde_json::from_slice(&line).unwrap();
                if value["id"] == id {
                    return value;
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[46; 32]).unwrap(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let admission = node.guard.admit(peer.ip(), Surface::Stratum).unwrap();
        let extra1 = 11u32.to_le_bytes();
        let session = tokio::spawn(stratum_session(
            node.clone(),
            server,
            None,
            DEFAULT_STRATUM_SHARE_DIFFICULTY,
            extra1,
            admission,
            None,
        ));
        let (read, mut write) = client.into_split();
        let mut read = BufReader::new(read);
        write_json(
            &mut write,
            &json!({"id":1,"method":"mining.subscribe","params":[]}),
        )
        .await
        .unwrap();
        reply(&mut read, 1).await;
        write_json(
            &mut write,
            &json!({"id":2,"method":"mining.authorize","params":["shared.worker","x"]}),
        )
        .await
        .unwrap();
        assert_eq!(reply(&mut read, 2).await["result"], true);
        let job = loop {
            let line = timeout(Duration::from_secs(5), bounded_line(&mut read, 16384))
                .await
                .unwrap()
                .unwrap();
            let value: Value = serde_json::from_slice(&line).unwrap();
            if value["method"] == "mining.notify" {
                break value;
            }
        };
        // Another device behind the same address misbehaves repeatedly. The
        // longest cooldown refuses new connections from the address.
        let other = node.guard.admit(peer.ip(), Surface::Stratum).unwrap();
        for _ in 0..7 {
            other.malformed();
        }
        assert!(node.guard.admit(peer.ip(), Surface::Stratum).is_err());
        let p = &job["params"];
        let word = |value: &Value| u32::from_str_radix(value.as_str().unwrap(), 16).unwrap();
        let extra2 = [8u8; 4];
        let mut coinbase = hex::decode(p[2].as_str().unwrap()).unwrap();
        coinbase.extend(extra1);
        coinbase.extend(extra2);
        coinbase.extend(hex::decode(p[3].as_str().unwrap()).unwrap());
        let mut previous: Hash = hex::decode(p[1].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        for chunk in previous.chunks_exact_mut(4) {
            chunk.reverse();
        }
        let mut header = Header {
            version: word(&p[5]),
            previous,
            merkle_root: crypto::sha256d(&coinbase),
            timestamp: word(&p[7]),
            bits: word(&p[6]),
            nonce: 0,
        };
        let target = math::target_from_bits(header.bits).unwrap();
        while math::check_pow(&header, &target).is_err() {
            header.nonce += 1;
        }
        // The authorized worker's solved block is still submitted, and the
        // worker stays connected.
        write_json(
            &mut write,
            &json!({"id":3,"method":"mining.submit","params":["shared.worker",p[0],hex::encode(extra2),format!("{:08x}",header.timestamp),format!("{:08x}",header.nonce)]}),
        )
        .await
        .unwrap();
        assert_eq!(reply(&mut read, 3).await["result"], true);
        assert_eq!(node.status().unwrap()["height"], 1);
        write_json(
            &mut write,
            &json!({"id":4,"method":"mining.extranonce.subscribe","params":[]}),
        )
        .await
        .unwrap();
        assert_eq!(reply(&mut read, 4).await["result"], true);
        write.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[test]
    fn reporting_rate_raises_difficulty_by_a_power_of_two_toward_the_target() {
        let seconds = Duration::from_secs;
        // Too few intervals keep difficulty, however fast they came.
        assert_eq!(stratum_rate_factor(15, Duration::ZERO), None);
        // Before a whole window, only a stream past the session request
        // rate, whose shares are being refused, is raised.
        assert_eq!(stratum_rate_factor(16, seconds(2)), None);
        assert_eq!(stratum_rate_factor(17, seconds(2)), Some(8.0));
        assert_eq!(stratum_rate_factor(16, seconds(1)), Some(16.0));
        // A whole window is judged against two shares per second, and the
        // factor rounds down, so the raised rate stays at or above the target.
        assert_eq!(stratum_rate_factor(60, seconds(30)), None);
        assert_eq!(stratum_rate_factor(61, seconds(30)), Some(2.0));
        assert_eq!(stratum_rate_factor(119, seconds(30)), Some(2.0));
        assert_eq!(stratum_rate_factor(120, seconds(30)), Some(4.0));
        // Shares buffered together are measured over at least 250 ms.
        assert_eq!(stratum_rate_factor(16, Duration::ZERO), Some(64.0));
        assert_eq!(
            stratum_rate_factor(40, Duration::from_millis(100)),
            Some(128.0)
        );
        assert_eq!(stratum_rate_factor(355 * 30, seconds(30)), Some(256.0));
        // Extreme counts and spans saturate instead of overflowing.
        assert_eq!(
            stratum_rate_factor(u64::MAX, Duration::ZERO),
            Some((1u64 << 56) as f64)
        );
        assert_eq!(stratum_rate_factor(u64::MAX, Duration::MAX), None);
    }
    #[test]
    fn share_rate_noise_near_the_target_never_raises_difficulty() {
        // A miner at the target rate, with exponentially distributed gaps
        // between shares, for ten hours. Four-interval samples raised such a
        // miner within about a minute.
        let start = tokio::time::Instant::now();
        let mut rate = ShareRate::new(start);
        let mut random = 0x9e37_79b9_7f4a_7c15u64;
        let mut at = start;
        for _ in 0..36_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let uniform = ((random >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
            at += Duration::from_secs_f64(-uniform.ln());
            assert_eq!(rate.sample(at), None, "raised after {:?}", at - start);
        }
        // Four shares per second are halved to target after one window.
        let mut rate = ShareRate::new(start);
        let quarter = Duration::from_millis(250);
        let raised = (0..=120u32).find_map(|n| rate.sample(start + quarter * n).map(|f| (n, f)));
        assert_eq!(raised, Some((120, 4.0)));
        // Ten per second exceed the session rate and are raised as soon as
        // the sample is complete.
        let mut rate = ShareRate::new(start);
        let tenth = Duration::from_millis(100);
        let raised = (0..=16u32).find_map(|n| rate.sample(start + tenth * n).map(|f| (n, f)));
        assert_eq!(raised, Some((16, 8.0)));
    }
    #[test]
    fn slow_shares_halve_raised_difficulty() {
        let seconds = Duration::from_secs;
        // Fewer than one share per four seconds over two minutes.
        assert!(stratum_decays(0, seconds(120)));
        assert!(stratum_decays(29, seconds(120)));
        assert!(!stratum_decays(30, seconds(120)));
        assert!(!stratum_decays(0, seconds(119)));
        assert!(stratum_decays(249, seconds(1000)));
        assert!(!stratum_decays(250, seconds(1000)));
        let start = tokio::time::Instant::now();
        let mut rate = ShareRate::new(start);
        assert!(!rate.slow(start + seconds(119)));
        assert!(rate.slow(start + seconds(120)));
        rate.shares = 30;
        assert!(!rate.slow(start + seconds(120)));
    }
    fn idle_worker(authorized: Instant, source: &str, trusted: bool) -> MiningWorker {
        MiningWorker {
            worker: "fixture".into(),
            accepted: 0,
            rejected: 0,
            blocks: 0,
            difficulty: DEFAULT_STRATUM_SHARE_DIFFICULTY,
            last_share: None,
            active: authorized,
            group: network_guard::stratum_group(source.parse().unwrap()),
            trusted,
            evict: Arc::new(tokio::sync::Notify::new()),
        }
    }
    #[tokio::test]
    async fn worker_registry_caps_sources_reserves_trusted_slots_and_replaces_only_idle_workers() {
        let start = Instant::now();
        let idle = start + STRATUM_IDLE_WORKER;
        let later = idle + STRATUM_IDLE_WORKER;
        let mut registry = MiningRuntime::default();
        let source = |group: usize, host: usize| format!("198.51.{group}.{host}");
        let mut id = 0u32;
        let mut next = || {
            id += 1;
            id
        };
        // One /24 holds at most its share of the slots, however many
        // addresses it uses, until one of its own workers is idle.
        for host in 0..STRATUM_GROUP_WORKERS {
            let worker = idle_worker(start, &source(1, host), false);
            registry.register(next(), worker, start).unwrap();
        }
        let newcomer = idle_worker(start, &source(1, 200), false);
        let refused = registry.register(next(), newcomer, start);
        assert_eq!(refused, Err("per-network mining worker limit reached"));
        let victim = registry.workers[&1].evict.clone();
        let newcomer = idle_worker(idle, &source(1, 200), false);
        registry.register(next(), newcomer, idle).unwrap();
        assert!(!registry.workers.contains_key(&1));
        timeout(Duration::from_secs(1), victim.notified())
            .await
            .expect("the replaced worker was not told to close");
        // Miners reporting shares are never replaced. Sources outside trusted
        // prefixes hold at most all but the reserved slots.
        let reporting: Vec<u32> = registry.workers.keys().copied().collect();
        for id in reporting {
            registry.proved(id, idle);
        }
        for group in 2..4 {
            for host in 0..STRATUM_GROUP_WORKERS {
                let worker = idle_worker(idle, &source(group, host), false);
                registry.register(next(), worker, idle).unwrap();
            }
        }
        assert_eq!(
            registry.workers.len(),
            MAX_CONNECTIONS - STRATUM_TRUSTED_WORKERS
        );
        let newcomer = idle_worker(idle, &source(4, 1), false);
        let refused = registry.register(next(), newcomer, idle);
        assert_eq!(refused, Err("mining worker capacity reached"));
        // The operator's trusted prefixes keep the rest, from one network.
        for host in 0..STRATUM_TRUSTED_WORKERS {
            let worker = idle_worker(idle, &format!("203.0.113.{host}"), true);
            registry.register(next(), worker, idle).unwrap();
        }
        assert_eq!(registry.workers.len(), MAX_CONNECTIONS);
        let newcomer = idle_worker(idle, "203.0.113.200", true);
        assert!(registry.register(next(), newcomer, idle).is_err());
        // Once idle, others' workers make way first, for either kind of newcomer.
        let newcomer = idle_worker(later, &source(4, 1), false);
        registry.register(next(), newcomer, later).unwrap();
        let newcomer = idle_worker(later, "203.0.113.201", true);
        registry.register(next(), newcomer, later).unwrap();
        let trusted = registry.workers.values().filter(|w| w.trusted).count();
        assert_eq!(trusted, STRATUM_TRUSTED_WORKERS + 1);
        // A trusted newcomer replaces an idle trusted worker only when every
        // other worker is active; another source's newcomer never does.
        let reporting: Vec<u32> = registry
            .workers
            .iter()
            .filter(|(_, w)| !w.trusted)
            .map(|(id, _)| *id)
            .collect();
        for id in reporting {
            registry.proved(id, later);
        }
        let newcomer = idle_worker(later, &source(5, 1), false);
        let refused = registry.register(next(), newcomer, later);
        assert_eq!(refused, Err("mining worker capacity reached"));
        let newcomer = idle_worker(later, "203.0.113.202", true);
        registry.register(next(), newcomer, later).unwrap();
        assert_eq!(
            registry.workers.values().filter(|w| w.trusted).count(),
            trusted
        );
        assert_eq!(registry.workers.len(), MAX_CONNECTIONS);
        // Trusted prefixes have no group cap.
        let mut farm = MiningRuntime::default();
        for host in 0..MAX_CONNECTIONS {
            let worker = idle_worker(start, &format!("203.0.113.{host}"), true);
            farm.register(next(), worker, start).unwrap();
        }
        // Without trusted prefixes no slot is held back for them.
        let mut open = MiningRuntime {
            trusted_reserve: 0,
            ..MiningRuntime::default()
        };
        for group in 0..MAX_CONNECTIONS / STRATUM_GROUP_WORKERS {
            for host in 0..STRATUM_GROUP_WORKERS {
                let worker = idle_worker(start, &source(10 + group, host), false);
                open.register(next(), worker, start).unwrap();
            }
        }
        assert_eq!(open.workers.len(), MAX_CONNECTIONS);
        let newcomer = idle_worker(start, &source(20, 1), false);
        let refused = open.register(next(), newcomer, start);
        assert_eq!(refused, Err("mining worker capacity reached"));
    }
    /// A Stratum session served over loopback TCP as the listener serves one
    /// without a pre-authorization slot, with the miner's ends of it.
    async fn loopback_session(
        node: &Node,
        floor: f64,
        extra: u32,
    ) -> (
        JoinHandle<Result<()>>,
        BufReader<tokio::net::tcp::OwnedReadHalf>,
        tokio::net::tcp::OwnedWriteHalf,
        IpAddr,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let admission = node.guard.admit(peer.ip(), Surface::Stratum).unwrap();
        let session = tokio::spawn(stratum_session(
            node.clone(),
            server,
            None,
            floor,
            extra.to_le_bytes(),
            admission,
            None,
        ));
        let (read, write) = client.into_split();
        (session, BufReader::new(read), write, peer.ip())
    }
    async fn miner_message<R: AsyncBufRead + Unpin>(read: &mut R) -> Value {
        let line = timeout(Duration::from_secs(10), bounded_line(read, 16384))
            .await
            .expect("mining session stopped responding")
            .expect("mining session closed");
        serde_json::from_slice(&line).unwrap()
    }
    async fn miner_call<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        read: &mut R,
        write: &mut W,
        id: u64,
        method: &str,
        params: Value,
    ) -> Value {
        write_json(write, &json!({"id":id,"method":method,"params":params}))
            .await
            .unwrap();
        loop {
            let value = miner_message(read).await;
            if value["id"] == id {
                return value;
            }
        }
    }
    /// A submission for `job` under `name` whose header hash satisfies `accept`.
    fn miner_submission(
        job: &Value,
        name: &str,
        extra1: u32,
        extra2: [u8; 4],
        accept: impl Fn(&Amount) -> bool,
    ) -> Value {
        let p = &job["params"];
        let word = |value: &Value| u32::from_str_radix(value.as_str().unwrap(), 16).unwrap();
        let mut coinbase = hex::decode(p[2].as_str().unwrap()).unwrap();
        coinbase.extend(extra1.to_le_bytes());
        coinbase.extend(extra2);
        coinbase.extend(hex::decode(p[3].as_str().unwrap()).unwrap());
        let mut previous: Hash = hex::decode(p[1].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        for chunk in previous.chunks_exact_mut(4) {
            chunk.reverse();
        }
        let mut header = Header {
            version: word(&p[5]),
            previous,
            merkle_root: crypto::sha256d(&coinbase),
            timestamp: word(&p[7]),
            bits: word(&p[6]),
            nonce: 0,
        };
        while !accept(&Amount::from_bytes_le(&crypto::sha256d(
            &codec::header_bytes(&header),
        ))) {
            header.nonce += 1;
        }
        json!([
            name,
            p[0],
            hex::encode(extra2),
            format!("{:08x}", header.timestamp),
            format!("{:08x}", header.nonce)
        ])
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_budget_refusals_restrict_a_worker_without_closing_it() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[47; 32]).unwrap(),
        )
        .unwrap();
        let (session, mut read, mut write, ip) = loopback_session(&node, 1e-12, 12).await;
        miner_call(&mut read, &mut write, 1, "mining.subscribe", json!([])).await;
        let reply = miner_call(
            &mut read,
            &mut write,
            2,
            "mining.authorize",
            json!(["budget.worker", "x"]),
        )
        .await;
        assert_eq!(reply["result"], true, "{reply}");
        let job = loop {
            let value = miner_message(&mut read).await;
            if value["method"] == "mining.notify" {
                break value;
            }
        };
        let block = math::target_from_bits(
            u32::from_str_radix(job["params"][6].as_str().unwrap(), 16).unwrap(),
        )
        .unwrap();
        let share =
            |extra2| miner_submission(&job, "budget.worker", 12, extra2, |hash| hash > &block);
        let mut refused = None;
        for attempt in 0..8u8 {
            let params = share([attempt, 1, 0, 0]);
            // Once any cooldown an earlier attempt caused is over, other
            // sessions at the worker's address spend its whole request budget.
            let mut other = loop {
                if let Ok(other) = node.guard.admit(ip, Surface::Stratum) {
                    break other;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            loop {
                while other.request().is_ok() {}
                match node.guard.admit(ip, Surface::Stratum) {
                    Ok(next) => other = next,
                    Err(_) => break,
                }
            }
            drop(other);
            let active = node.mining.unpoisoned().workers[&12].active;
            let reply = miner_call(
                &mut read,
                &mut write,
                10 + u64::from(attempt),
                "mining.submit",
                params,
            )
            .await;
            if reply["result"] == true {
                continue;
            }
            assert_eq!(
                reply["error"][1], "network rate budget exhausted",
                "{reply}"
            );
            // The refused share still proved work, so the worker is not idle.
            assert!(node.mining.unpoisoned().workers[&12].active > active);
            refused = Some(attempt);
            break;
        }
        assert!(
            refused.is_some(),
            "a drained address budget never restricted a share"
        );
        // The worker stays connected and mines once the budget refills.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let reply = miner_call(
            &mut read,
            &mut write,
            99,
            "mining.submit",
            share([99, 0, 0, 0]),
        )
        .await;
        assert_eq!(reply["result"], true, "{reply}");
        assert!(!session.is_finished());
        write.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_idle_worker_replaced_by_a_newcomer_disconnects() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[49; 32]).unwrap(),
        )
        .unwrap();
        let (session, mut read, mut write, _) = loopback_session(&node, 1e-12, 13).await;
        miner_call(&mut read, &mut write, 1, "mining.subscribe", json!([])).await;
        let reply = miner_call(
            &mut read,
            &mut write,
            2,
            "mining.authorize",
            json!(["idle.worker", "x"]),
        )
        .await;
        assert_eq!(reply["result"], true, "{reply}");
        {
            // Other sources' workers fill the slots outside trusted prefixes.
            let mut runtime = node.mining.unpoisoned();
            for index in 1..(MAX_CONNECTIONS - STRATUM_TRUSTED_WORKERS) {
                let worker = idle_worker(Instant::now(), &format!("198.51.{index}.1"), false);
                runtime
                    .register(1000 + index as u32, worker, Instant::now())
                    .unwrap();
            }
            let newcomer = || idle_worker(Instant::now(), "203.0.113.1", false);
            assert!(runtime.register(5000, newcomer(), Instant::now()).is_err());
            // Once every worker has gone without a share for the idle period,
            // the one idle longest, which authorized first, makes way.
            let later = Instant::now() + STRATUM_IDLE_WORKER;
            runtime.register(5000, newcomer(), later).unwrap();
            assert!(!runtime.workers.contains_key(&13));
        }
        let ended = timeout(Duration::from_secs(5), session)
            .await
            .unwrap()
            .unwrap();
        assert!(ended.unwrap_err().to_string().contains("replaced"));
    }
    #[test]
    fn extranonces_start_at_a_random_value_on_each_node() {
        let first = || {
            let dir = tempfile::tempdir().unwrap();
            let node = Node::open(
                &dir.path().join("node.db"),
                Config::devnet(),
                crypto::public_key(&[48; 32]).unwrap(),
            )
            .unwrap();
            SessionIds::allocate(&node.mining_session_ids).unwrap().1
        };
        // Nodes paying one key with the same template, or one node across a
        // restart, would otherwise give their first miners the same work.
        let first: HashSet<u32> = (0..4).map(|_| first()).collect();
        assert_eq!(first.len(), 4, "{first:?}");
    }
    #[test]
    fn authorized_solo_workers_need_not_find_a_block_to_stay_connected() {
        assert!(!stratum_session_expired(
            true,
            Duration::from_secs(24 * 60 * 60)
        ));
        assert!(stratum_session_expired(false, Duration::from_secs(10)));
        assert!(!stratum_session_expired(false, Duration::from_secs(9)));
    }
    #[test]
    fn peer_parser_accepts_large_binary_body_with_configured_record_limits() {
        let transaction = Transaction {
            body: TransactionBody {
                data: Vec::new(),
                sender: crypto::public_key(&[1; 32]).unwrap(),
                nonce: 0,
                fee: 0u32.into(),
                anchor: [38; 32],
                expiry_blocks: 1000,
                operation: Operation::TransferExact {
                    recipient: [2; 32],
                    amount: 1u32.into(),
                },
            },
            signature: [1; 64],
        };
        let mut block = Block {
            header: Header {
                version: 0x20000000,
                previous: [0; 32],
                merkle_root: [0; 32],
                timestamp: 1,
                bits: 0x207fffff,
                nonce: 0,
            },
            height: 1,
            miner: transaction.body.sender,
            state_root: [0; 32],
            extranonce: [0; 8],
            transactions: vec![],
        };
        let base = codec::body_size(&block).unwrap();
        block.transactions.push(transaction.clone());
        let record = codec::body_size(&block).unwrap() - base;
        let count = (4 * 1024 * 1024 - base) / record;
        block.transactions = vec![transaction; count];
        assert!(codec::body_size(&block).unwrap() <= 4 * 1024 * 1024);
        assert!(codec::body_size(&block).unwrap() + record > 4 * 1024 * 1024);
        let message = PeerMessage {
            chain: [1; 32],
            locator: vec![[0; 32]],
            blocks: vec![block],
            transactions: vec![],
        };
        let mut config = Config::devnet();
        config.max_signatures = count;
        // Record admission follows the validated capacity, here 4 MiB.
        let limits = peer_wire::Limits::for_capacity(&config, 4 * 1024 * 1024);
        let preset = peer_wire::Limits::from_config(&config);
        assert!(peer_wire::encode(&PeerPacket::Sync(message.clone()), preset).is_err());
        let wire = peer_wire::encode(&PeerPacket::Sync(message.clone()), limits).unwrap();
        assert_eq!(
            peer_wire::decode(&wire, limits).unwrap(),
            PeerPacket::Sync(message)
        );
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use crate::peer_auth::Policy;

    fn advance(chain: &mut Chain, miner: PublicKey) -> Block {
        let timestamp =
            chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
        let block =
            Chain::mine(chain.template(miner, vec![], timestamp).unwrap(), 100_000).unwrap();
        chain.submit(block.clone(), timestamp as u64).unwrap();
        block
    }
    /// One-second blocks: ASERT raises each block's work above the last.
    fn rush(chain: &mut Chain, miner: PublicKey) {
        let timestamp = chain.tip_block().header.timestamp + 1;
        let block =
            Chain::mine(chain.template(miner, vec![], timestamp).unwrap(), 1_000_000).unwrap();
        chain.submit(block, timestamp as u64).unwrap();
    }
    /// A node opened on a chain database populated first by `build`.
    fn node_on(path: &Path, config: &Config, build: impl FnOnce(&mut Chain)) -> Node {
        let mut chain = Chain::open(path, config.clone()).unwrap();
        build(&mut chain);
        drop(chain);
        Node::open(path, config.clone(), crypto::public_key(&[66; 32]).unwrap()).unwrap()
    }
    /// Synchronize `target` from `source` until their tips agree; the number
    /// of exchanges, each one request locator and one reply. As in the sync
    /// loop, a deferred replay resumes at the next exchange: a node restarted
    /// from a saved checkpoint rebuilds a fork point below it in steps.
    fn converge(source: &Node, target: &Node, limit: usize) -> Option<usize> {
        for round in 1..=limit {
            let request = target.peer_snapshot(None).unwrap();
            let reply = source.peer_snapshot(Some(&request.locator)).unwrap();
            let received = target.receive_peer(&reply, "8.1.1.1".parse().unwrap());
            if let Err(error) = &received
                && !error.is::<crate::chain::ValidationDeferred>()
            {
                panic!("{error:#}");
            }
            if target.read_view().unwrap().chain.tip_hash()
                == source.read_view().unwrap().chain.tip_hash()
            {
                return Some(round);
            }
        }
        None
    }

    #[test]
    fn deep_forks_synchronize_past_a_shared_prefix_longer_than_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut shared = Chain::open(&dir.path().join("shared.db"), config.clone()).unwrap();
        let prefix: Vec<Block> = (0..300)
            .map(|_| advance(&mut shared, crypto::public_key(&[61; 32]).unwrap()))
            .collect();
        let branch = |name: &str, seed: u8, length: usize| {
            node_on(&dir.path().join(name), &config, |chain| {
                for block in &prefix {
                    chain
                        .submit(block.clone(), block.header.timestamp as u64)
                        .unwrap();
                }
                for _ in 0..length {
                    advance(chain, crypto::public_key(&[seed; 32]).unwrap());
                }
            })
        };
        // The receiver's sparse locator matches the heavier sender's chain
        // more than one batch below the fork, so a whole reply consists of
        // blocks it already has. Those once ended every exchange unchanged.
        let receiver = branch("receiver.db", 62, 80);
        let sender = branch("sender.db", 63, 100);
        assert!(converge(&sender, &receiver, 20).is_some());
    }

    #[test]
    fn a_heavier_branch_is_presynced_past_a_tip_that_declines_its_first_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        // The receiver's light chain has pushed its next block's work to more
        // than 64 times a block at the initial target.
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let light = receiver.read_view().unwrap().chain.tip_height() as usize;
        let work = receiver.locked().unwrap().chain.chain_work().clone();
        let sender = node_on(&dir.path().join("sender.db"), &config, |chain| {
            while *chain.chain_work() <= work {
                rush(chain, crypto::public_key(&[63; 32]).unwrap());
            }
        });
        // The heavier branch's first block is declined, and with it every
        // later block used to be an unknown parent. Its headers are held
        // instead, then its bodies are fetched again and it is adopted.
        let first = {
            let i = sender.locked().unwrap();
            i.chain
                .hash_at_height(1)
                .and_then(|hash| i.chain.block(&hash))
        }
        .unwrap();
        let error = receiver.submit_block(first).unwrap_err();
        assert!(error.is::<crate::chain::SideBranchRefused>(), "{error:#}");
        assert!(converge(&sender, &receiver, 4 * light / MAX_BATCH + 8).is_some());
        let i = receiver.locked().unwrap();
        let held = i.chain.held_header_count();
        let invalid = i.chain.cached_invalid_count();
        drop(i);
        assert_eq!((held, invalid), (0, 0));
    }

    const HEADER_PEER: &str = "8.1.1.1:18481";
    /// One header request from `target` answered by `source`, its reply cut
    /// to `keep` headers; whether `target` would ask again, and the request.
    fn header_round(source: &Node, target: &Node, keep: usize) -> (bool, Vec<Hash>, u64) {
        let peer = HEADER_PEER.parse().unwrap();
        let PeerPacket::GetHeaders {
            locator,
            version,
            capacity,
            ..
        } = target.header_request(peer).unwrap()
        else {
            panic!("not a header request")
        };
        assert_eq!(version, peer_wire::TRANSPORT_VERSION);
        let PeerPacket::Headers { headers, .. } = source.headers_reply(&locator, version).unwrap()
        else {
            panic!("not a header reply")
        };
        let headers = &headers[..keep.min(headers.len())];
        (
            target.receive_headers(peer, headers).unwrap(),
            locator,
            capacity,
        )
    }
    /// Version 2 synchronization in process: header rounds, then one block
    /// reply within the declared capacity, until the tips agree.
    fn converge_headers(source: &Node, target: &Node, limit: usize) -> Option<usize> {
        for round in 1..=limit {
            let mut capacity = 0;
            for _ in 0..peer_wire::MAX_HEADER_ROUNDS {
                let (more, _, declared) = header_round(source, target, usize::MAX);
                capacity = declared;
                if !more {
                    break;
                }
            }
            let request = target.peer_snapshot(None).unwrap();
            let reply = source
                .peer_snapshot_within(Some(&request.locator), Some(capacity))
                .unwrap();
            target
                .receive_peer(&reply, HEADER_PEER.parse::<SocketAddr>().unwrap().ip())
                .unwrap();
            if target.read_view().unwrap().chain.tip_hash()
                == source.read_view().unwrap().chain.tip_hash()
            {
                return Some(round);
            }
        }
        None
    }
    fn held_counts(node: &Node) -> (usize, usize) {
        let i = node.locked().unwrap();
        (i.chain.held_header_count(), i.chain.admitted_header_count())
    }

    #[test]
    fn header_presync_counts_a_branch_before_holding_it_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let path = dir.path().join("receiver.db");
        let receiver = node_on(&path, &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let work = receiver.locked().unwrap().chain.chain_work().clone();
        let sender = node_on(&dir.path().join("sender.db"), &config, |chain| {
            while *chain.chain_work() <= work {
                rush(chain, crypto::public_key(&[63; 32]).unwrap());
            }
        });
        let branch = sender.read_view().unwrap().chain.tip_height() as usize;
        // Half of the branch, delivered alone, is only counted: nothing is held.
        let (more, locator, _) = header_round(&sender, &receiver, branch / 2);
        assert!(!more);
        assert_eq!(
            locator.len(),
            Node::locator(&receiver.locked().unwrap().chain).len()
        );
        assert_eq!(held_counts(&receiver), (0, 0));
        // The next request continues after the last counted header, and the
        // count passes the tip's work: still nothing is held.
        let (more, locator, _) = header_round(&sender, &receiver, usize::MAX);
        assert!(more);
        let counted = sender
            .locked()
            .unwrap()
            .chain
            .hash_at_height(branch as u64 / 2);
        assert_eq!(Some(locator[0]), counted);
        assert_eq!(held_counts(&receiver), (0, 0));
        // The branch is fetched again from genesis and held: admitted once it
        // claims more work than the tip, which the last header does.
        let (more, locator, _) = header_round(&sender, &receiver, usize::MAX);
        assert!(!more);
        assert_eq!(
            Some(locator[0]),
            receiver.locked().unwrap().chain.hash_at_height(0)
        );
        assert_eq!(held_counts(&receiver), (branch, branch));
        let tip = receiver.read_view().unwrap().chain.tip_hash();
        // Admitted headers are persisted and restored on restart.
        drop(receiver);
        let receiver = Node::open(
            &path,
            config.clone(),
            crypto::public_key(&[66; 32]).unwrap(),
        )
        .unwrap();
        assert_eq!(held_counts(&receiver), (branch, branch));
        assert_eq!(receiver.read_view().unwrap().chain.tip_hash(), tip);
        // Its blocks, first of all the one the tip's work declines, now bypass
        // the admission policy: block synchronization alone adopts the branch.
        assert!(converge(&sender, &receiver, branch / MAX_BATCH + 4).is_some());
        assert_eq!(held_counts(&receiver), (0, 0));
        drop(receiver);
        let receiver = Node::open(&path, config, crypto::public_key(&[66; 32]).unwrap()).unwrap();
        assert_eq!(held_counts(&receiver), (0, 0));
        assert_eq!(
            receiver.read_view().unwrap().chain.tip_hash(),
            sender.read_view().unwrap().chain.tip_hash()
        );
    }

    #[test]
    fn header_downloads_follow_branches_too_long_for_held_presync() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let block_work = math::work(&math::target_from_bits(config.initial_bits).unwrap());
        // On-schedule blocks keep the initial target. A light chain of
        // one-second blocks raises its work per block, so a branch of
        // on-schedule blocks needs more headers than presync by held headers
        // ever holds before it claims more work.
        let needed = Amount::from(crate::chain::MAX_HELD_HEADERS + 256) * &block_work;
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while *chain.chain_work() <= needed {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let work = receiver.locked().unwrap().chain.chain_work().clone();
        let sender = node_on(&dir.path().join("sender.db"), &config, |chain| {
            while *chain.chain_work() <= work {
                advance(chain, crypto::public_key(&[63; 32]).unwrap());
            }
        });
        let branch = sender.read_view().unwrap().chain.tip_height() as usize;
        assert!(branch > crate::chain::MAX_HELD_HEADERS);
        // Block synchronization alone presyncs by held headers; it stalls at
        // the bound, and its branch never claims more work than the tip.
        // Replies past the bound end without failing the exchange.
        let mut rounds = 0;
        while held_counts(&receiver).0 < crate::chain::MAX_HELD_HEADERS && rounds < 2 * branch {
            let request = receiver.peer_snapshot(None).unwrap();
            let reply = sender.peer_snapshot(Some(&request.locator)).unwrap();
            receiver
                .receive_peer(&reply, "8.1.1.2".parse().unwrap())
                .unwrap();
            rounds += 1;
        }
        assert_eq!(held_counts(&receiver), (crate::chain::MAX_HELD_HEADERS, 0));
        for _ in 0..4 {
            let request = receiver.peer_snapshot(None).unwrap();
            let reply = sender.peer_snapshot(Some(&request.locator)).unwrap();
            receiver
                .receive_peer(&reply, "8.1.1.2".parse().unwrap())
                .unwrap();
        }
        assert_eq!(held_counts(&receiver), (crate::chain::MAX_HELD_HEADERS, 0));
        // Header downloads count the whole branch, then hold all of it.
        let mut admitted = 0;
        let limit = 2 * (branch / MAX_BATCH + branch / peer_wire::MAX_HEADERS) + 16;
        for _ in 0..limit {
            if converge_headers(&sender, &receiver, 1).is_some() {
                break;
            }
            admitted = admitted.max(held_counts(&receiver).1);
        }
        assert!(admitted > crate::chain::MAX_HELD_HEADERS, "{admitted}");
        assert_eq!(
            receiver.read_view().unwrap().chain.tip_hash(),
            sender.read_view().unwrap().chain.tip_hash()
        );
        assert_eq!(held_counts(&receiver).1, 0);
    }

    /// `count` linked headers without blocks after `previous`, `step` seconds
    /// apart from `timestamp`, each meeting its own proof of work at `bits`.
    fn mined_headers(
        mut previous: Hash,
        timestamp: u32,
        step: u32,
        bits: u32,
        count: usize,
        salt: u8,
    ) -> Vec<Header> {
        let target = math::target_from_bits(bits).unwrap();
        (0..count as u32)
            .map(|n| {
                let mut header = Header {
                    version: codec::HEADER_VERSION,
                    previous,
                    merkle_root: [salt; 32],
                    timestamp: timestamp + n * step,
                    bits,
                    nonce: 0,
                };
                while math::check_pow(&header, &target).is_err() {
                    header.nonce += 1;
                }
                previous = crypto::sha256d(&codec::header_bytes(&header));
                header
            })
            .collect()
    }
    fn header_hash(header: &Header) -> Hash {
        crypto::sha256d(&codec::header_bytes(header))
    }

    #[test]
    fn cheap_headers_after_a_tied_sibling_stay_within_the_held_bounds() {
        use crate::chain::{HELD_COMMITS, HELD_LEAD_HEADERS, MAX_SYNC_HEADERS};
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        // The tip's next block needs more than 1,024 times the work of a
        // header at the network limit, so a lead of 16 next-block works
        // alone would let one admitted chain grow by 8,192 such headers.
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(1024u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let tip = receiver.locked().unwrap().chain.tip_block().header.clone();
        let peer: SocketAddr = HEADER_PEER.parse().unwrap();
        // A sibling of the tip, as a stale block would be, ties its work; the
        // first cheap header after it then claims more work than the tip.
        let branch = |salt: u8, cheap: usize| {
            let sibling = mined_headers(tip.previous, tip.timestamp, 0, tip.bits, 1, salt);
            let mut headers = sibling.clone();
            headers.extend(mined_headers(
                header_hash(&sibling[0]),
                tip.timestamp + 1,
                1,
                config.limit_bits,
                cheap,
                salt,
            ));
            headers
        };
        let commits = || HELD_COMMITS.with(std::cell::Cell::get);
        let first = branch(1, 2 * peer_wire::MAX_HEADERS + 1);
        assert!(
            !receiver
                .receive_headers(peer, &first[..peer_wire::MAX_HEADERS])
                .unwrap()
        );
        assert_eq!(held_counts(&receiver), (2, 2));
        // Its best header is extended, and one reply commits once, not once
        // per admitted header.
        let before = commits();
        let reply = &first[2..2 + peer_wire::MAX_HEADERS];
        assert!(receiver.receive_headers(peer, reply).unwrap());
        assert_eq!(commits() - before, 1);
        let extended = 2 + peer_wire::MAX_HEADERS;
        assert_eq!(held_counts(&receiver), (extended, extended));
        // A fork from inside the admitted chain is not followed. Its reply no
        // longer continues anything the request listed, which a race can
        // cause too, so it ends the header requests without blame.
        let inside = header_hash(&first[100]);
        let fork = mined_headers(inside, tip.timestamp, 1, config.limit_bits, 4, 9);
        assert!(!receiver.receive_headers(peer, &fork).unwrap());
        assert_eq!(held_counts(&receiver), (extended, extended));
        // The chain grows by HELD_LEAD_HEADERS headers after its admission at
        // most, though its lead in work would allow more.
        let reply = &first[extended..extended + peer_wire::MAX_HEADERS];
        assert!(!receiver.receive_headers(peer, reply).unwrap());
        let lead = 2 + HELD_LEAD_HEADERS as usize;
        assert_eq!(held_counts(&receiver), (lead, lead));
        // Every tied sibling's chain grows as far, and all of them together
        // stop at MAX_SYNC_HEADERS.
        for salt in 2.. {
            let headers = branch(salt, 1 + HELD_LEAD_HEADERS as usize);
            receiver.receive_headers(peer, &headers[..2]).unwrap();
            for reply in headers[2..].chunks(peer_wire::MAX_HEADERS) {
                if !receiver.receive_headers(peer, reply).unwrap() {
                    break;
                }
            }
            let (held, admitted) = held_counts(&receiver);
            assert_eq!(held, admitted);
            assert!(admitted <= MAX_SYNC_HEADERS);
            if admitted == MAX_SYNC_HEADERS {
                break;
            }
            assert!(salt < 70, "{admitted}");
        }
        // Then no further header is held.
        assert!(!receiver.receive_headers(peer, &branch(99, 4)).unwrap());
        assert_eq!(held_counts(&receiver), (MAX_SYNC_HEADERS, MAX_SYNC_HEADERS));
    }

    #[test]
    fn header_downloads_release_their_pins_when_holding_stalls_and_keep_their_count() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let (genesis, deficit) = {
            let i = receiver.locked().unwrap();
            let genesis = i.chain.hash_at_height(0).unwrap();
            let HeaderParent::Stored { work, .. } = i.chain.header_parent(&genesis).unwrap() else {
                panic!("genesis is stored")
            };
            (genesis, i.chain.chain_work() - work)
        };
        // On-schedule headers from genesis whose last one alone claims more
        // work than the tip, after more than two replies.
        let block_work = math::work(&math::target_from_bits(config.initial_bits).unwrap());
        let count = (deficit / &block_work).to_usize().unwrap() + 1;
        assert!(count > 2 * peer_wire::MAX_HEADERS, "{count}");
        let start = config.genesis_time + 15;
        let branch = mined_headers(genesis, start, 15, config.initial_bits, count, 7);
        let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
            HEADER_PEER.parse().unwrap(),
            "8.1.1.3:18481".parse().unwrap(),
            "8.1.1.4:18481".parse().unwrap(),
        );
        let cursor = |peer| match receiver.header_request(peer).unwrap() {
            PeerPacket::GetHeaders { locator, .. } => locator[0],
            _ => panic!("not a header request"),
        };
        let pause = |peer| {
            let mut i = receiver.locked().unwrap();
            i.header_syncs.get_mut(&peer).unwrap().touched = Instant::now()
                .checked_sub(HEADER_SYNC_IDLE + Duration::from_secs(60))
                .expect("the monotonic clock is older than the pause");
        };
        let replies = || branch.chunks(peer_wire::MAX_HEADERS);
        let pinned = || receiver.locked().unwrap().chain.pinned_header_count();
        let count_branch = |peer| {
            let held = held_counts(&receiver);
            for reply in replies() {
                assert!(receiver.receive_headers(peer, reply).unwrap());
                assert_eq!(held_counts(&receiver), held);
            }
            assert_eq!(cursor(peer), genesis);
        };
        // Counting survives a pause longer than the holding idle limit.
        assert!(
            receiver
                .receive_headers(a, replies().next().unwrap())
                .unwrap()
        );
        pause(a);
        let counted = header_hash(&branch[peer_wire::MAX_HEADERS - 1]);
        assert_eq!(cursor(a), counted);
        for reply in replies().skip(1) {
            assert!(receiver.receive_headers(a, reply).unwrap());
        }
        assert_eq!((held_counts(&receiver), cursor(a)), ((0, 0), genesis));
        // Holding pins the branch's headers; another download of the same
        // branch pins the same ones.
        let first = &branch[..peer_wire::MAX_HEADERS];
        assert!(receiver.receive_headers(a, first).unwrap());
        assert_eq!(pinned(), peer_wire::MAX_HEADERS);
        count_branch(b);
        assert!(receiver.receive_headers(b, first).unwrap());
        let full = peer_wire::MAX_HEADERS;
        assert_eq!((held_counts(&receiver).0, pinned()), (full, full));
        // A peer that answers holding with nothing ends its download, and
        // releases its pins only: the other download still holds them.
        assert!(!receiver.receive_headers(a, &[]).unwrap());
        assert!(!receiver.locked().unwrap().header_syncs.contains_key(&a));
        assert_eq!(pinned(), peer_wire::MAX_HEADERS);
        // A resume point dropped meanwhile restarts holding at the stored
        // root rather than failing the session.
        let dropped = header_hash(&branch[1500]);
        receiver
            .locked()
            .unwrap()
            .chain
            .forget_held_header(&dropped);
        assert_eq!(cursor(b), header_hash(&branch[peer_wire::MAX_HEADERS - 1]));
        let second = &branch[peer_wire::MAX_HEADERS..2 * peer_wire::MAX_HEADERS];
        assert!(receiver.receive_headers(b, second).unwrap());
        assert_eq!(cursor(b), genesis);
        // A reply that stops short of the counted header ends the download.
        assert!(!receiver.receive_headers(b, &branch[..10]).unwrap());
        assert!(!receiver.locked().unwrap().header_syncs.contains_key(&b));
        assert_eq!((held_counts(&receiver).0, pinned()), (1500, 0));
        // Holding that pauses past the idle limit releases its pins and
        // holds again from the stored root when the peer answers.
        count_branch(c);
        assert!(receiver.receive_headers(c, first).unwrap());
        assert_eq!(pinned(), peer_wire::MAX_HEADERS);
        pause(c);
        assert_eq!((cursor(c), pinned()), (genesis, 0));
        let mut more = true;
        for reply in replies() {
            assert!(more);
            more = receiver.receive_headers(c, reply).unwrap();
        }
        assert_eq!(held_counts(&receiver), (count, count));
        assert_eq!(pinned(), 0);
    }

    #[test]
    fn a_header_lookup_that_fails_releases_its_downloads_pins() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let (genesis, deficit) = {
            let i = receiver.locked().unwrap();
            let genesis = i.chain.hash_at_height(0).unwrap();
            let HeaderParent::Stored { work, .. } = i.chain.header_parent(&genesis).unwrap() else {
                panic!("genesis is stored")
            };
            (genesis, i.chain.chain_work() - work)
        };
        let block_work = math::work(&math::target_from_bits(config.initial_bits).unwrap());
        let count = (deficit / &block_work).to_usize().unwrap() + 1;
        assert!(count > 2 * peer_wire::MAX_HEADERS, "{count}");
        let start = config.genesis_time + 15;
        let branch = mined_headers(genesis, start, 15, config.initial_bits, count, 7);
        let peer: SocketAddr = HEADER_PEER.parse().unwrap();
        let pinned = || receiver.locked().unwrap().chain.pinned_header_count();
        // The branch is counted past the tip's work, then held from its root.
        for reply in branch.chunks(peer_wire::MAX_HEADERS) {
            assert!(receiver.receive_headers(peer, reply).unwrap());
        }
        let first = &branch[..peer_wire::MAX_HEADERS];
        assert!(receiver.receive_headers(peer, first).unwrap());
        assert_eq!(pinned(), peer_wire::MAX_HEADERS);
        // The next reply's resume header cannot be looked up, as with a
        // damaged database. The download has already left its map by then;
        // its pins went with it and stayed fixed until a restart.
        receiver.locked().unwrap().chain.break_header_index(true);
        let second = &branch[peer_wire::MAX_HEADERS..2 * peer_wire::MAX_HEADERS];
        assert!(receiver.receive_headers(peer, second).is_err());
        receiver.locked().unwrap().chain.break_header_index(false);
        assert_eq!(pinned(), 0);
        assert!(!receiver.locked().unwrap().header_syncs.contains_key(&peer));
        // Released, the branch's headers are ordinary presync headers again.
        assert_eq!(held_counts(&receiver), (peer_wire::MAX_HEADERS, 0));
    }

    #[test]
    fn downloads_that_counted_no_work_never_displace_one_that_did() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let (genesis, stored) = {
            let i = receiver.locked().unwrap();
            let stored = i.chain.hash_at_height(2).unwrap();
            (
                i.chain.hash_at_height(0).unwrap(),
                i.chain.block_header(&stored).unwrap().unwrap(),
            )
        };
        let cursor = |peer| match receiver.header_request(peer).unwrap() {
            PeerPacket::GetHeaders { locator, .. } => locator[0],
            _ => panic!("not a header request"),
        };
        // An honest peer's branch, counted in part: it claims less work than
        // the tip so far, and the download waits for more.
        let branch = mined_headers(
            genesis,
            config.genesis_time + 15,
            15,
            config.initial_bits,
            100,
            7,
        );
        let honest: SocketAddr = HEADER_PEER.parse().unwrap();
        assert!(!receiver.receive_headers(honest, &branch).unwrap());
        assert_eq!(cursor(honest), header_hash(&branch[99]));
        // Many more addresses than downloads are kept, in as many network
        // groups, each answer with a header this node already stores. Such a
        // reply takes no proof of work to make, and each one used to start a
        // download that displaced the least recently answered: the honest
        // count, which then restarted from its fork point every session.
        for n in 0..2 * MAX_CONNECTIONS {
            let peer = SocketAddr::from(([9, n as u8, 1, 1], 18481));
            assert!(
                !receiver
                    .receive_headers(peer, std::slice::from_ref(&stored))
                    .unwrap()
            );
        }
        assert_eq!(cursor(honest), header_hash(&branch[99]));
        // One network group runs at most its share of the downloads.
        for n in 0..2 * HEADER_SYNCS_PER_SOURCE {
            let peer = SocketAddr::from(([9, 200, 1, n as u8], 18481));
            receiver
                .receive_headers(peer, std::slice::from_ref(&stored))
                .unwrap();
        }
        let i = receiver.locked().unwrap();
        assert_eq!(i.header_syncs.len(), MAX_CONNECTIONS);
        let group = network_guard::peer_source(IpAddr::from([9, 200, 1, 1]));
        let same = i
            .header_syncs
            .keys()
            .filter(|peer| network_guard::peer_source(peer.ip()) == group)
            .count();
        assert_eq!(same, HEADER_SYNCS_PER_SOURCE);
        assert!(i.header_syncs.contains_key(&honest));
    }

    #[test]
    fn admitted_chains_grow_only_from_their_best_header() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let receiver = node_on(&dir.path().join("receiver.db"), &config, |chain| {
            for _ in 0..4 {
                rush(chain, crypto::public_key(&[62; 32]).unwrap());
            }
        });
        let tip = receiver.locked().unwrap().chain.tip_block().header.clone();
        let peer: SocketAddr = HEADER_PEER.parse().unwrap();
        // A tied sibling of the tip and headers at the network limit after it.
        let sibling = mined_headers(tip.previous, tip.timestamp, 0, tip.bits, 1, 1);
        let mut best = sibling.clone();
        best.extend(mined_headers(
            header_hash(&sibling[0]),
            tip.timestamp + 1,
            1,
            config.limit_bits,
            8,
            1,
        ));
        // `best[k]` is the k-th cheap header after the sibling.
        let fork = |at: usize, count: usize, salt: u8| {
            mined_headers(
                header_hash(&best[at]),
                tip.timestamp + 50,
                1,
                config.limit_bits,
                count,
                salt,
            )
        };
        assert!(!receiver.receive_headers(peer, &best[..2]).unwrap());
        assert!(!receiver.receive_headers(peer, &best[2..5]).unwrap());
        assert_eq!(held_counts(&receiver), (5, 5));
        // Two downloads list the same best header; once one extends it, the
        // other's reply, which starts there, no longer continues anything
        // admitted. Its peer did nothing wrong: the reply is ignored.
        let (first, second): (SocketAddr, SocketAddr) = (
            "8.1.1.5:18481".parse().unwrap(),
            "8.2.1.5:18481".parse().unwrap(),
        );
        for peer in [first, second] {
            let PeerPacket::GetHeaders { locator, .. } = receiver.header_request(peer).unwrap()
            else {
                panic!("not a header request")
            };
            assert_eq!(locator[0], header_hash(&best[4]));
        }
        assert!(!receiver.receive_headers(first, &best[5..6]).unwrap());
        assert_eq!(held_counts(&receiver), (6, 6));
        assert!(!receiver.receive_headers(second, &best[5..6]).unwrap());
        assert_eq!(held_counts(&receiver), (6, 6));
        // A reply that leaves the best header's chain part-way, by a header
        // that does not follow the one before it, stops there.
        let inside = fork(3, 1, 9);
        let reply = [best[6].clone(), inside[0].clone()];
        assert!(!receiver.receive_headers(peer, &reply).unwrap());
        assert_eq!(held_counts(&receiver), (7, 7));
        // A download from the stored root that offers another child of the
        // admitted sibling holds it, but does not admit it.
        let counted = [best[0].clone(), fork(0, 1, 10)[0].clone()];
        assert!(receiver.receive_headers(first, &counted).unwrap());
        assert_eq!(held_counts(&receiver), (8, 7));
        receiver.receive_headers(first, &[]).unwrap();
        // Nor does a block pushed after a header inside the chain: its header
        // is held as presync only.
        let pushed = fork(2, 1, 11);
        let hold = |header: &Header| {
            receiver
                .locked()
                .unwrap()
                .chain
                .hold_header(header.clone(), now(), 0)
                .unwrap()
        };
        assert_eq!(hold(&pushed[0]), HeaderHold::Held);
        assert_eq!(held_counts(&receiver), (9, 7));
        // A branch from inside that claims more work than every admitted
        // chain is admitted, as a heavier branch from anywhere is.
        let heavier = fork(2, 5, 12);
        for header in &heavier[..4] {
            assert_eq!(hold(header), HeaderHold::Held);
        }
        assert_eq!(hold(&heavier[4]), HeaderHold::Admitted);
        assert_eq!(held_counts(&receiver), (14, 12));
        assert!(
            receiver
                .locked()
                .unwrap()
                .chain
                .admitted_header_tip(&header_hash(&heavier[4]))
        );
    }

    #[test]
    fn locator_matching_uses_the_index_and_answers_without_historical_state() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let miner = crypto::public_key(&[61; 32]).unwrap();
        let mut chain = Chain::open(&dir.path().join("chain.db"), config.clone()).unwrap();
        for _ in 0..300 {
            advance(&mut chain, miner);
        }
        let mut side = Chain::open(&dir.path().join("side.db"), config.clone()).unwrap();
        let fork = advance(&mut side, crypto::public_key(&[62; 32]).unwrap());
        chain
            .submit(fork.clone(), fork.header.timestamp as u64)
            .unwrap();
        let old = chain.hash_at_height(10).unwrap();
        // Unknown, repeated and losing-branch hashes are ignored; the best
        // canonical match wins even far below every cached historical state.
        let mut locator = vec![[9; 32], codec::block_hash(&fork)];
        locator.extend(std::iter::repeat_n(old, 120));
        locator.push(chain.hash_at_height(3).unwrap());
        let (blocks, limits, size) = Node::blocks_after(&chain, &locator).unwrap();
        assert_eq!(blocks.len(), MAX_BATCH);
        assert_eq!(blocks[0].height, 11);
        assert_eq!(blocks.last().unwrap().height, 10 + MAX_BATCH as u64);
        assert_eq!(
            limits.block_bytes,
            peer_wire::Limits::from_config(&config).block_bytes
        );
        let framed = blocks
            .iter()
            .map(|b| peer_wire::record_size(codec::encode(b).len()).unwrap())
            .sum::<usize>();
        assert_eq!(size, framed);
        // At the tip the current state supplies the recipient's capacity.
        let (blocks, limits, size) = Node::blocks_after(&chain, &[chain.tip_hash()]).unwrap();
        assert!(blocks.is_empty() && size == 0);
        assert_eq!(
            limits.block_bytes,
            peer_wire::Limits::for_capacity(&config, chain.tip_state().settings.block_bytes)
                .block_bytes
        );
        assert!(Node::blocks_after(&chain, &[[9; 32], codec::block_hash(&fork)]).is_err());
        assert!(Node::blocks_after(&chain, &[]).is_err());
        // Only the shared run ending the locator is the recipient's active
        // chain: a cursor that this node has active, listed before the
        // recipient's own diverging tip, is not.
        let at = |height| chain.hash_at_height(height).unwrap();
        let cursor_first = [at(200), codec::block_hash(&fork), at(10), at(3)];
        assert_eq!(
            Node::shared_active_tip(&cursor_first, &[Some(200), None, Some(10), Some(3)]),
            Some(at(10))
        );
        assert_eq!(
            Node::shared_active_tip(&[at(5), at(10), at(3)], &[Some(5), Some(10), Some(3)]),
            Some(at(10))
        );
        assert_eq!(Node::shared_active_tip(&[[9; 32]], &[None]), None);
    }

    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn catch_up_replies_are_bounded_by_recipient_work_as_well_as_bytes() {
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::devnet();
        // Two of these blocks fit one reply's byte allowance, but not its work.
        config.max_signatures = PEER_BATCH_WORK / 2;
        config.initial.block_bytes = 4 * 1024 * 1024;
        config.initial_bits = 0x1f1fffff;
        config.limit_bits = config.initial_bits;
        config.validate().unwrap();
        let secret = [68; 32];
        let miner = crypto::public_key(&secret).unwrap();
        let mut chain = Chain::open(&dir.path().join("work.db"), config.clone()).unwrap();
        let append = |chain: &mut Chain, transactions: Vec<Transaction>| {
            let timestamp =
                chain.tip_block().header.timestamp + chain.tip_state().settings.interval as u32;
            let block = Chain::mine(
                chain.template(miner, transactions, timestamp).unwrap(),
                1_000_000,
            )
            .unwrap();
            chain.submit(block, timestamp as u64).unwrap();
        };
        for _ in 0..8 {
            append(&mut chain, vec![]);
        }
        let funded = chain.tip_hash();
        // One signing context keeps fixture construction fast.
        let secp = Secp256k1::new();
        let pair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(secret).unwrap());
        let anchor = codec::block_hash(&codec::genesis_block(&config).unwrap());
        let chain_id = config.chain_id();
        let mut nonce = 0;
        for _ in 0..2 {
            let transactions = (0..config.max_signatures)
                .map(|_| {
                    let body = TransactionBody {
                        sender: miner,
                        nonce,
                        fee: 1u32.into(),
                        anchor,
                        expiry_blocks: 1000,
                        operation: Operation::TransferExact {
                            recipient: miner,
                            amount: 1u32.into(),
                        },
                        data: vec![],
                    };
                    nonce += 1;
                    let message = crypto::signing_message(&chain_id, &body);
                    Transaction {
                        signature: *secp.sign_schnorr_no_aux_rand(&message, &pair).as_ref(),
                        body,
                    }
                })
                .collect();
            append(&mut chain, transactions);
        }
        let (blocks, limits, size) = Node::blocks_after(&chain, &[funded]).unwrap();
        assert!(2 * size < limits.block_batch_bytes());
        assert_eq!(blocks.len(), 1, "work, not bytes, ends this reply");
        // A block's work is its transaction count plus one.
        assert!(blocks[0].transactions.len() < PEER_BATCH_WORK);
        let (blocks, _, _) = Node::blocks_after(&chain, &[codec::block_hash(&blocks[0])]).unwrap();
        assert_eq!(blocks.len(), 1);
        // A genesis signature limit above the baseline burst still admits
        // one complete block message.
        let mut large = Config::devnet();
        large.max_signatures = 100_000;
        let node = Node::open(&dir.path().join("large.db"), large, miner).unwrap();
        let session = node
            .guard
            .admit("127.0.0.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        assert!(
            session
                .work(100_001 + peer_wire::MAX_TRANSACTIONS + MAX_ADAPTIVE_MEMPOOL + MAX_BACKLOG)
                .is_ok()
        );
    }

    #[test]
    fn resent_stored_blocks_cannot_displace_another_sources_download_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = Node::open(
            &dir.path().join("node.db"),
            config.clone(),
            crypto::public_key(&[63; 32]).unwrap(),
        )
        .unwrap();
        let other = crypto::public_key(&[64; 32]).unwrap();
        let sibling = |node: &Node| {
            let i = node.locked().unwrap();
            let template = i
                .chain
                .template(other, vec![], Node::timestamp(&i.chain))
                .unwrap();
            Chain::mine(template, 100_000).unwrap()
        };
        // Each stale block is a stored sibling of an active block, so none is
        // another's parent.
        let (mut known, mut stale) = (Vec::new(), Vec::new());
        for _ in 0..2 * MAX_BATCH + 1 {
            let block = sibling(&node);
            known.push(node.mine(100_000).unwrap());
            assert!(!node.submit_block(block.clone()).unwrap());
            stale.push(block);
        }
        let honest: IpAddr = "8.1.1.1".parse().unwrap();
        let attacker: IpAddr = "9.1.1.1".parse().unwrap();
        // The honest cursor is a stored side block the attacker never sends;
        // a request drops cursors the chain does not know.
        let cursor = Download {
            hash: codec::block_hash(&stale.pop().unwrap()),
            source: network_guard::peer_source(honest),
        };
        node.locked().unwrap().downloads.push_back(cursor);
        let message = |blocks: &[Block]| PeerMessage {
            chain: config.chain_id(),
            locator: vec![],
            blocks: blocks.to_vec(),
            transactions: vec![],
        };
        let downloads = || {
            node.locked()
                .unwrap()
                .downloads
                .iter()
                .copied()
                .collect::<Vec<_>>()
        };
        // Stored blocks need no proof of work to resend. Active ones never
        // become cursors.
        let resent: Vec<_> = known.iter().step_by(2).take(MAX_BATCH).cloned().collect();
        for _ in 0..2 {
            node.receive_peer(&message(&resent), attacker).unwrap();
        }
        assert_eq!(downloads(), [cursor]);
        // 64 non-adjacent stored side blocks, sent repeatedly by one source,
        // displace only that source's own cursors.
        for _ in 0..2 {
            for batch in stale.chunks(MAX_BATCH) {
                node.receive_peer(&message(batch), attacker).unwrap();
            }
        }
        let held = downloads();
        assert_eq!(held.len(), MAX_CONNECTIONS);
        assert!(held.contains(&cursor));
        assert!(
            held.iter()
                .all(|d| *d == cursor || d.source == network_guard::peer_source(attacker))
        );
        // A linked reply of known active blocks marks where its sender's
        // chain continues, but never displaces a competing-branch cursor.
        node.receive_peer(&message(&known[..MAX_BATCH]), attacker)
            .unwrap();
        assert_eq!(downloads(), held);
        // The honest source resending a stored side block, as after a
        // restart, still records its own cursor for it.
        node.receive_peer(&message(&stale[..1]), honest).unwrap();
        let held = downloads();
        assert_eq!(
            held[0],
            Download {
                hash: codec::block_hash(&stale[0]),
                source: network_guard::peer_source(honest),
            }
        );
        assert!(held.contains(&cursor));
        // A request lists each cursor once, before the complete active locator.
        let locator = node.peer_snapshot(None).unwrap().locator;
        assert!(locator.ends_with(&Node::locator(&node.locked().unwrap().chain)));
        assert_eq!(locator.iter().filter(|h| **h == held[0].hash).count(), 1);
        assert!(locator.contains(&cursor.hash));
        // A block missing its own proof of work is rejected before validation.
        let mut invalid = sibling(&node);
        let target = math::target_from_bits(invalid.header.bits).unwrap();
        while math::check_pow(&invalid.header, &target).is_ok() {
            invalid.header.nonce = invalid.header.nonce.wrapping_add(1);
        }
        let error = node.receive_peer(&message(&[invalid]), honest).unwrap_err();
        assert!(error.to_string().contains("proof of work"), "{error}");
    }

    #[tokio::test]
    async fn a_stalled_frame_holds_only_the_memory_its_bytes_used() {
        let guard = Arc::new(NetworkGuard::default());
        let session = guard
            .admit("127.0.0.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        let (mut writer, reader) = tokio::io::duplex(64 * 1024);
        let mut reader = BufReader::new(reader);
        // Declare a 3 MiB frame, send 10,000 of its bytes, then stall.
        writer
            .write_all(&(3u32 * 1024 * 1024).to_be_bytes())
            .await
            .unwrap();
        writer.write_all(&[0; 10_000]).await.unwrap();
        let read = read_peer_frame(&mut reader, 4 * 1024 * 1024, &session);
        assert!(timeout(Duration::from_millis(200), read).await.is_err());
        // Only received bytes, in whole read chunks, hold the shared budget.
        let held = guard.frame_memory_in_use();
        assert!((10_000..=16 * 1024).contains(&held), "{held}");
        drop(session);
        assert_eq!(guard.frame_memory_in_use(), 0);
        drop(writer);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_frame_that_stops_arriving_while_holding_shared_memory_ends_without_a_cooldown() {
        const KIB: usize = 1024;
        let guard = Arc::new(NetworkGuard::default());
        let read = |session: Session, declared: usize, sent: usize, then: Vec<usize>| async move {
            let (mut writer, reader) = tokio::io::duplex(4 * 1024 * KIB);
            let mut reader = BufReader::new(reader);
            writer
                .write_all(&(declared as u32).to_be_bytes())
                .await
                .unwrap();
            writer.write_all(&vec![0; sent]).await.unwrap();
            let feeder = tokio::spawn(async move {
                for chunk in then {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    writer.write_all(&vec![0; chunk]).await.unwrap();
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(writer);
            });
            let started = Instant::now();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(7);
            let frame = tokio::time::timeout_at(
                deadline,
                read_peer_frame(&mut reader, 16 * 1024 * KIB, &session),
            );
            let result = keep_frame_progress(&session, frame).await.map(|f| f.len());
            feeder.abort();
            (result, started.elapsed(), session)
        };
        let admit = |a: u8| {
            guard
                .admit(IpAddr::from([8, a, 1, 1]), Surface::Peer)
                .unwrap()
        };
        let (stalled, small, steady) = tokio::join!(
            // 2 MiB of a declared 8 MiB frame, then nothing.
            read(admit(1), 8 * 1024 * KIB, 2 * 1024 * KIB, vec![]),
            // A frame holding less than 1 MiB may stall until its allowance.
            read(admit(2), 1024 * KIB, 512 * KIB, vec![]),
            // A large frame that keeps arriving at 128 KiB/s completes.
            read(
                admit(3),
                1100 * KIB + 640 * KIB,
                1100 * KIB,
                vec![128 * KIB; 5]
            ),
        );
        let (result, elapsed, session) = stalled;
        let error = result.unwrap_err();
        assert!(error.is::<network_guard::Busy>(), "{error}");
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        drop(session);
        let (result, elapsed, small) = small;
        assert!(result.unwrap_err().is::<tokio::time::error::Elapsed>());
        assert!(elapsed >= Duration::from_secs(6), "{elapsed:?}");
        drop(small);
        let (result, _, steady) = steady;
        assert_eq!(result.unwrap(), 1740 * KIB);
        drop(steady);
        // The stalled frame's memory returned with its session; the others'
        // with theirs.
        assert_eq!(guard.frame_memory_in_use(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_processed_hello_holds_no_frame_memory_while_its_sender_stalls() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let miner = crypto::public_key(&[71; 32]).unwrap();
        let node = Node::open(&dir.path().join("node.db"), config, miner).unwrap();
        let guard = Arc::new(NetworkGuard::default());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let admission = guard.admit(remote.ip(), Surface::Peer).unwrap();
        let session = tokio::spawn(peer_session(node.clone(), stream, admission, None));
        // A hello padded with loose transactions that fail validation: it is
        // processed without error, and its sender then never reads the reply
        // nor sends its push.
        let junk = |n: u8| Transaction {
            body: TransactionBody {
                sender: crypto::public_key(&[n; 32]).unwrap(),
                nonce: 0,
                fee: 1u32.into(),
                anchor: [0; 32],
                expiry_blocks: 10,
                operation: Operation::TransferExact {
                    recipient: miner,
                    amount: 1u32.into(),
                },
                data: vec![0; 8 * 1024],
            },
            signature: [0; 64],
        };
        let mut hello = node.peer_snapshot(None).unwrap();
        hello.transactions = (1..=32).map(junk).collect();
        let limits = node.peer_limits().unwrap();
        let payload = peer_wire::encode(&PeerPacket::Sync(hello), limits).unwrap();
        assert!(payload.len() > 256 * 1024);
        let frame = peer_wire::frame(&payload, limits.frame_bytes()).unwrap();
        client.write_all(&frame).await.unwrap();
        // The reply starts arriving once the hello was processed. From then
        // on the session holds none of the shared frame memory, although it
        // waits a whole read allowance for the push.
        timeout(Duration::from_secs(10), client.readable())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(guard.frame_memory_in_use(), 0);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!session.is_finished());
        assert_eq!(guard.frame_memory_in_use(), 0);
        drop(client);
        assert!(session.await.unwrap().is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_discovery_exchange_that_stalls_after_its_handshake_ends_within_one_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = Node::open(
            &dir.path().join("node.db"),
            config.clone(),
            crypto::public_key(&[68; 32]).unwrap(),
        )
        .unwrap()
        .with_peer_auth(Policy::discovery([69; 32], vec![]).unwrap())
        .unwrap();
        let server = Policy::discovery([70; 32], vec![]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let chain = config.chain_id();
        // The endpoint takes most of an allowance to answer the handshake,
        // completes it, and then never answers the address request.
        let stall = tokio::spawn(async move {
            let (mut stream, remote) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
            let guard = Arc::new(NetworkGuard::default());
            let admission = guard.admit(remote.ip(), Surface::Peer).unwrap();
            let channel = PeerChannel::accept(&mut stream, &server, remote.ip(), chain, &admission)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop((channel, stream));
        });
        let started = Instant::now();
        let error = discover_peer(&node, endpoint).await.unwrap_err();
        let elapsed = started.elapsed();
        // Each step used to have its own 15-second allowance, so this took 25
        // seconds and could take far longer; one allowance now bounds the
        // whole exchange, including the wait for an outbound slot.
        let allowance = node.peer_exchange_timeout().unwrap();
        assert!(error.to_string().contains("overall deadline"), "{error}");
        assert!(
            elapsed + Duration::from_millis(100) >= allowance
                && elapsed < allowance + Duration::from_secs(2),
            "{elapsed:?}"
        );
        assert_eq!(node.outbound_sessions.available_permits(), 2);
        stall.abort();
    }

    #[test]
    fn download_cursors_are_kept_per_source() {
        let hash = |n: u32| {
            let mut hash = [0; 32];
            hash[..4].copy_from_slice(&n.to_be_bytes());
            hash
        };
        let (a, b) = (IpAddr::from([8, 1, 0, 0]), IpAddr::from([9, 1, 0, 0]));
        let first = Download {
            hash: hash(2),
            source: a,
        };
        let mut downloads = VecDeque::new();
        // A source advances its own cursor along a branch.
        note_download(&mut downloads, hash(1), hash(0), a);
        note_download(&mut downloads, hash(2), hash(1), a);
        assert_eq!(downloads, [first]);
        // Another source extending that block, or sending it again, adds its
        // own cursor and leaves the first source's in place.
        note_download(&mut downloads, hash(3), hash(2), b);
        note_download(&mut downloads, hash(2), hash(1), b);
        assert_eq!(downloads.len(), 3);
        assert!(downloads.contains(&first));
        // A flooding source displaces others only down to its own count.
        downloads.clear();
        for n in 0..MAX_CONNECTIONS as u32 {
            note_download(&mut downloads, hash(n), hash(n + 10_000), a);
        }
        for n in 0..1_000 {
            note_download(&mut downloads, hash(n + 20_000), hash(n + 30_000), b);
        }
        assert_eq!(downloads.len(), MAX_CONNECTIONS);
        let from_a = downloads.iter().filter(|d| d.source == a).count();
        assert_eq!(from_a, MAX_CONNECTIONS / 2);
        // The newest cursors survive.
        assert!(downloads.contains(&Download {
            hash: hash(MAX_CONNECTIONS as u32 - 1),
            source: a,
        }));
    }

    #[test]
    fn listener_ids_and_retry_policy_never_end_admission() {
        let ids = Arc::new(Mutex::new(SessionIds {
            next: u32::MAX,
            live: HashSet::from([0]),
        }));
        let last = SessionIds::allocate(&ids).unwrap();
        assert_eq!(last.1, u32::MAX);
        // The wrapped counter skips an extranonce still held by a session.
        let wrapped = SessionIds::allocate(&ids).unwrap();
        assert_eq!(wrapped.1, 1);
        drop(last);
        assert!(!ids.lock().unwrap().live.contains(&u32::MAX));
        use std::io::{Error, ErrorKind};
        // A sustained flood of reset or aborted connections never slows the
        // listener: each such error is one client's queued connection.
        let mut failures = 0;
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::ConnectionRefused,
        ] {
            for _ in 0..10_000 {
                assert_eq!(
                    accept_retry_delay(&Error::from(kind), &mut failures),
                    Duration::ZERO
                );
            }
        }
        assert_eq!(failures, 0);
        let exhausted = Error::other("too many open files");
        let delays: Vec<_> = (0..9)
            .map(|_| accept_retry_delay(&exhausted, &mut failures).as_millis())
            .collect();
        assert_eq!(delays, [10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
        // Interrupted calls retry at once, but cannot spin without bound.
        let mut interrupted = 0;
        let interrupt = Error::from(ErrorKind::Interrupted);
        for _ in 0..64 {
            assert_eq!(
                accept_retry_delay(&interrupt, &mut interrupted),
                Duration::ZERO
            );
        }
        assert_eq!(
            accept_retry_delay(&interrupt, &mut interrupted),
            Duration::from_millis(1000)
        );
        assert!(sync_completed(&Ok(SyncOutcome::default())));
        assert!(sync_completed(
            &Err(crate::chain::ValidationDeferred.into())
        ));
        assert!(!sync_completed(&Err(anyhow!("peer closed"))));
    }

    #[tokio::test]
    async fn a_failed_signed_write_keeps_its_channel_and_never_downgrades() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = Node::open(
            &dir.path().join("node.db"),
            config.clone(),
            crypto::public_key(&[65; 32]).unwrap(),
        )
        .unwrap();
        let client = Policy::discovery([66; 32], vec![]).unwrap();
        let server = Policy::discovery([67; 32], vec![]).unwrap();
        let guard = Arc::new(NetworkGuard::default());
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        let (a, b) = (
            guard.admit_outbound(local, Surface::Peer).unwrap(),
            guard.admit(local, Surface::Peer).unwrap(),
        );
        let (mut left, mut right) = tokio::io::duplex(4096);
        let chain = config.chain_id();
        let (channel, _) = tokio::join!(
            PeerChannel::connect(
                &mut left,
                &client,
                "127.0.0.1:1".parse().unwrap(),
                chain,
                &a
            ),
            PeerChannel::accept(&mut right, &server, local, chain, &b)
        );
        let mut transport = PeerTransport::Signed(channel.unwrap());
        let genesis = codec::genesis_block(&config).unwrap();
        // Encoding fails: more blocks than one message may carry.
        let oversized = PeerPacket::Sync(PeerMessage {
            chain,
            locator: vec![],
            blocks: vec![genesis; MAX_BATCH + 1],
            transactions: vec![],
        });
        let mut sink = Vec::new();
        assert!(
            write_peer(&node, &mut sink, oversized, &a, &mut transport)
                .await
                .is_err()
        );
        assert!(matches!(transport, PeerTransport::Signed(_)));
        write_peer(&node, &mut sink, PeerPacket::Ack, &a, &mut transport)
            .await
            .unwrap();
        // A signed frame header precedes the payload, never a bare length.
        assert_eq!(sink.len(), 4 + 8 + 64 + peer_wire::ACK_BYTES);
        let mut failed = PeerTransport::Failed;
        assert!(
            write_peer(&node, &mut sink, PeerPacket::Ack, &a, &mut failed)
                .await
                .is_err()
        );
        let mut empty: &[u8] = &[];
        assert!(
            read_peer_packet(&mut empty, &node, &b, &mut failed, PeerRead::Ack, None)
                .await
                .is_err()
        );
    }

    #[test]
    fn discovery_contacts_are_judged_by_what_they_delivered_and_how_long_they_held_a_slot() {
        use peer_discovery::Contact;
        let allowance = Duration::from_secs(15);
        let (quick, slow) = (Duration::from_secs(2), Duration::from_secs(16));
        let ok: Result<()> = Ok(());
        let deferred: Result<()> = Err(crate::chain::ValidationDeferred.into());
        let refused: Result<()> = Err(crate::chain::SideBranchRefused("test").into());
        let failed: Result<()> = Err(anyhow!("peer closed"));
        let judge =
            |result, advanced, elapsed| discovery_contact(result, advanced, elapsed, allowance);
        // Completing promptly with nothing new: the peer is not ahead.
        assert_eq!(judge(Some(&ok), false, quick), Contact::Current);
        assert_eq!(judge(Some(&refused), false, quick), Contact::Current);
        // Completing slowly with nothing new, or being cut off for that,
        // held an outbound slot without advancing this node.
        assert_eq!(judge(Some(&ok), false, slow), Contact::Stalled);
        assert_eq!(judge(Some(&refused), false, slow), Contact::Stalled);
        assert_eq!(judge(None, false, slow * 2), Contact::Stalled);
        // This node's own replay limit is never the peer's fault.
        assert_eq!(judge(Some(&deferred), false, slow), Contact::Current);
        assert_eq!(judge(Some(&failed), false, quick), Contact::Failed);
        // A block of the peer's that became the tip outweighs the rest.
        for result in [Some(&ok), Some(&failed), None] {
            assert_eq!(judge(result, true, slow * 4), Contact::Advanced);
        }
        // A session that completes after this node deferred its replay
        // reports that in its outcome, and is judged as the deferral.
        let outcome = |deferred| SyncOutcome {
            header_rounds: 1,
            header_error: None,
            blocks: MAX_BATCH,
            deferred,
        };
        let deferred = discovery_result(Ok(Ok(outcome(true))));
        assert_eq!(judge(Some(&deferred), false, slow), Contact::Current);
        let completed = discovery_result(Ok(Ok(outcome(false))));
        assert_eq!(judge(Some(&completed), false, slow), Contact::Stalled);
    }

    #[test]
    fn operator_privileges_need_the_exact_configured_or_pinned_address() {
        let dir = tempfile::tempdir().unwrap();
        let node = Node::open(
            &dir.path().join("node.db"),
            Config::devnet(),
            crypto::public_key(&[65; 32]).unwrap(),
        )
        .unwrap();
        let configured: SocketAddr = "[2600:1f18:1:2::10]:18481".parse().unwrap();
        let pinned: IpAddr = "8.8.4.4".parse().unwrap();
        let protected = protected_peers(&[configured], [pinned]);
        let class = |ip: &str| node.peer_class(&protected, ip.parse().unwrap());
        assert_eq!(class("2600:1f18:1:2::10"), PeerClass::Operator);
        assert_eq!(class("8.8.4.4"), PeerClass::Operator);
        assert_eq!(class("::ffff:8.8.4.4"), PeerClass::Operator);
        // A neighbour in the same IPv6 /64, which in discovery mode joins
        // with any key, is an ordinary source.
        assert_eq!(class("2600:1f18:1:2::11"), PeerClass::General);
        assert_eq!(class("8.8.4.5"), PeerClass::General);
    }

    /// Write one unsigned peer frame, as a peer would.
    async fn send_packet<W: AsyncWrite + Unpin>(
        write: &mut W,
        packet: &PeerPacket,
        limits: peer_wire::Limits,
    ) {
        let payload = peer_wire::encode(packet, limits).unwrap();
        let frame = peer_wire::frame(&payload, limits.frame_bytes()).unwrap();
        write.write_all(&frame).await.unwrap();
    }
    /// Read one unsigned peer frame; None once the connection has closed.
    async fn receive_packet<R: tokio::io::AsyncRead + Unpin>(
        read: &mut R,
        limits: peer_wire::Limits,
    ) -> Option<PeerPacket> {
        let mut length = [0u8; 4];
        read.read_exact(&mut length).await.ok()?;
        let mut payload = vec![0; u32::from_be_bytes(length) as usize];
        read.read_exact(&mut payload).await.ok()?;
        Some(peer_wire::decode(&payload, limits).unwrap())
    }
    /// Serve `node`'s peer sessions on a loopback port, admitting each as
    /// the node's listener does: an address its guard refuses, for example
    /// one cooling down, is closed at once.
    async fn listen(node: Node) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            while let Ok((stream, remote)) = listener.accept().await {
                if let Ok(admission) = node.guard.admit(remote.ip(), Surface::Peer) {
                    tokio::spawn(peer_session(node.clone(), stream, admission, None));
                }
            }
        });
        (address, task)
    }

    #[test]
    fn header_replies_are_paid_for_before_any_header_is_read() {
        const LENGTH: usize = 300;
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = node_on(&dir.path().join("node.db"), &config, |chain| {
            for _ in 0..LENGTH {
                advance(chain, crypto::public_key(&[61; 32]).unwrap());
            }
        });
        let genesis = node.locked().unwrap().chain.hash_at_height(0).unwrap();
        let version = peer_wire::TRANSPORT_VERSION;
        let reads = || crate::chain::HEADER_READS.with(std::cell::Cell::get);
        // A reply is planned from its locator alone and paid for before any
        // header is read, so a refused payment reads none. Replies used to be
        // read in full under the node lock and refused only when written.
        let before = reads();
        let mut planned = None;
        let refused = node.headers_reply_within(&[genesis], version, |count| {
            planned = Some(count);
            Err(anyhow!("outgoing network budget exhausted"))
        });
        assert!(refused.is_err());
        assert_eq!((planned, reads()), (Some(LENGTH), before));
        let PeerPacket::Headers { headers, .. } = node
            .headers_reply_within(&[genesis], version, |_| Ok(()))
            .unwrap()
        else {
            panic!("not a header reply")
        };
        assert_eq!((headers.len(), reads() - before), (LENGTH, LENGTH));
        assert_eq!(headers[0].previous, genesis);
        for pair in headers.windows(2) {
            assert_eq!(pair[1].previous, header_hash(&pair[0]));
        }
        // A requester catching up on this chain, whose locator opens with
        // its tip and that tip's parent, learns that this chain extends its
        // tip from one header rather than from a full reply it would discard.
        let i = node.locked().unwrap();
        let at = |height| i.chain.hash_at_height(height).unwrap();
        let plan = |locator: &[Hash]| Node::header_reply_plan(&i.chain, locator).unwrap();
        assert_eq!(plan(&[at(10), at(9), at(0)]), (10, at(10), 1));
        // Otherwise the reply holds every header after the match, up to
        // MAX_HEADERS: after a sparse locator, or after a cursor listed first.
        let after = LENGTH - 10;
        assert_eq!(plan(&[at(10), at(0)]), (10, at(10), after));
        assert_eq!(plan(&[at(10), [9; 32], at(9)]), (10, at(10), after));
        assert_eq!(plan(&[at(0)]), (0, genesis, LENGTH));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_that_leaves_between_messages_is_not_cooled_down() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = Node::open(
            &dir.path().join("node.db"),
            config.clone(),
            crypto::public_key(&[73; 32]).unwrap(),
        )
        .unwrap();
        for _ in 0..20 {
            node.mine(100_000).unwrap();
        }
        let genesis = node.locked().unwrap().chain.hash_at_height(0).unwrap();
        let limits = node.peer_limits().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, remote) = listener.accept().await.unwrap();
        let admission = node.guard.admit(remote.ip(), Surface::Peer).unwrap();
        let session = tokio::spawn(peer_session(node.clone(), stream, admission, None));
        let request = PeerPacket::GetHeaders {
            chain: config.chain_id(),
            version: peer_wire::TRANSPORT_VERSION,
            capacity: config.initial.block_bytes,
            locator: vec![genesis],
        };
        send_packet(&mut client, &request, limits).await;
        let Some(PeerPacket::Headers { headers, .. }) = receive_packet(&mut client, limits).await
        else {
            panic!("no header reply")
        };
        assert_eq!(headers.len(), 20);
        // The client leaves after a whole reply instead of sending its next
        // request, as a peer does whose own processing failed. That ends the
        // session, but it sent nothing malformed: no cooldown, where the end
        // of stream used to count as a malformed frame.
        drop(client);
        let error = session.await.unwrap().unwrap_err();
        assert!(error.is::<PeerClosed>(), "{error:#}");
        assert!(node.guard.admit(remote.ip(), Surface::Peer).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_header_reply_that_fails_processing_still_leaves_the_block_exchange() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let node = Node::open(
            &dir.path().join("node.db"),
            config.clone(),
            crypto::public_key(&[72; 32]).unwrap(),
        )
        .unwrap();
        node.mine(100_000).unwrap();
        let genesis = node.locked().unwrap().chain.hash_at_height(0).unwrap();
        let limits = node.peer_limits().unwrap();
        let chain = config.chain_id();
        // A header after genesis, which is no longer the tip, that misses
        // its proof of work.
        let mut invalid = Header {
            version: codec::HEADER_VERSION,
            previous: genesis,
            merkle_root: [5; 32],
            timestamp: config.genesis_time + 15,
            bits: config.initial_bits,
            nonce: 0,
        };
        let target = math::target_from_bits(invalid.bits).unwrap();
        while math::check_pow(&invalid, &target).is_ok() {
            invalid.nonce += 1;
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let Some(PeerPacket::GetHeaders { version, .. }) =
                receive_packet(&mut stream, limits).await
            else {
                panic!("no header request")
            };
            let reply = PeerPacket::Headers {
                chain,
                version,
                headers: vec![invalid],
            };
            send_packet(&mut stream, &reply, limits).await;
            // The requester ends its header requests and still asks for
            // blocks, takes this reply, pushes and waits for the Ack.
            while let Some(packet) = receive_packet(&mut stream, limits).await {
                let PeerPacket::Sync(message) = packet else {
                    panic!("unexpected {packet:?}")
                };
                received.push(message);
                let answer = if received.len() == 1 {
                    PeerPacket::Sync(PeerMessage {
                        chain,
                        locator: vec![genesis],
                        blocks: vec![],
                        transactions: vec![],
                    })
                } else {
                    PeerPacket::Ack
                };
                send_packet(&mut stream, &answer, limits).await;
            }
            received.len()
        });
        // The header requests end, and the session completes its block
        // exchange instead of failing with them.
        let outcome = sync_peer(&node, address).await.unwrap();
        assert_eq!(outcome.header_rounds, 1);
        let error = outcome.header_error.unwrap();
        assert!(error.contains("proof of work"), "{error}");
        assert!(!outcome.deferred);
        assert_eq!(peer.await.unwrap(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_deferred_replay_completes_its_exchange_without_blaming_either_side() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let key = |seed: u8| crypto::public_key(&[seed; 32]).unwrap();
        // Both sides share 100 blocks; the minority then has 300 of its own
        // and the heavier side 301. Each side's fork point lies 300 blocks
        // below its tip, where only genesis is still retained beneath it:
        // rebuilding that state replays 100 blocks, more than the 64 one
        // submission may replay, so the first block of the other branch
        // defers until a later session continues its replay.
        let mut minority = Chain::open(&dir.path().join("minority.db"), config.clone()).unwrap();
        let prefix: Vec<Block> = (0..100).map(|_| advance(&mut minority, key(61))).collect();
        let own: Vec<Block> = (0..300).map(|_| advance(&mut minority, key(62))).collect();
        drop(minority);
        let minority = |name: &str| {
            node_on(&dir.path().join(name), &config, |chain| {
                for block in prefix.iter().chain(&own) {
                    chain
                        .submit(block.clone(), block.header.timestamp as u64)
                        .unwrap();
                }
            })
        };
        let heavy = node_on(&dir.path().join("heavy.db"), &config, |chain| {
            for block in &prefix {
                chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
            for _ in 0..301 {
                advance(chain, key(63));
            }
        });
        let first = heavy.locked().unwrap().chain.hash_at_height(101).unwrap();
        let local: IpAddr = "127.0.0.1".parse().unwrap();
        // A minority node that admitted the heavier branch's headers lists
        // its download cursor, and the heavier node pushes that branch's
        // blocks. The minority node defers while processing the push, and
        // acknowledges it all the same.
        let responder = minority("responder.db");
        assert!(!header_round(&heavy, &responder, usize::MAX).0);
        assert_eq!(held_counts(&responder).1, 301);
        let (address, listener) = listen(responder.clone()).await;
        let outcome = sync_peer(&heavy, address).await.unwrap();
        assert!(!outcome.deferred);
        listener.abort();
        assert!(responder.locked().unwrap().chain.block(&first).is_none());
        // Neither side counts the other's close as a malformed frame.
        assert!(heavy.guard.admit_outbound(local, Surface::Peer).is_ok());
        assert!(responder.guard.admit(local, Surface::Peer).is_ok());
        // A minority node that requests the heavier branch defers while
        // processing the reply, and still pushes and waits for the Ack.
        let initiator = minority("initiator.db");
        let (address, listener) = listen(heavy.clone()).await;
        let outcome = sync_peer(&initiator, address).await.unwrap();
        assert!(outcome.deferred, "{outcome:?}");
        assert_eq!((outcome.header_rounds, outcome.blocks), (1, MAX_BATCH));
        assert!(initiator.locked().unwrap().chain.block(&first).is_none());
        assert!(heavy.guard.admit(local, Surface::Peer).is_ok());
        // Later sessions continue the replay, and the heavier branch is
        // adopted. Pausing as the session loops do keeps the address within
        // its request rate.
        let mut sessions = 1;
        while initiator.read_view().unwrap().chain.tip_hash()
            != heavy.read_view().unwrap().chain.tip_hash()
        {
            tokio::time::sleep(Duration::from_millis(250)).await;
            sync_peer(&initiator, address).await.unwrap();
            sessions += 1;
            assert!(sessions < 40, "{sessions}");
        }
        listener.abort();
    }
}
