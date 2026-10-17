//! Bounded local RPC, fork-aware peer synchronization and solo Stratum V1.
use crate::{
    address,
    chain::Chain,
    codec,
    config::Config,
    crypto,
    explorer::Explorer,
    fees, math,
    network_guard::{self, NetworkGuard, Session, Surface},
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
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
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

pub const MAX_CONNECTIONS: usize = 64;
pub const MAX_MEMPOOL: usize = 256;
pub const MAX_ADAPTIVE_MEMPOOL: usize = 4096;

fn mempool_limit(_config: &Config) -> usize {
    MAX_ADAPTIVE_MEMPOOL
}
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
/// A governed capacity can make one valid record's hexadecimal response exceed
/// the fixed service limit; the HTTP frame then grows with that capacity.
fn response_frame_bytes(transaction_bytes: usize) -> Result<usize> {
    Ok(MAX_RESPONSE_FRAME.max(
        transaction_request_bytes(transaction_bytes)?
            .saturating_add(64 * 1024)
            .min(isize::MAX as usize),
    ))
}
/// Read responses charge one admission work unit per this many projected JSON
/// values: about one grant payment, matching the per-recipient request charge.
const RESPONSE_VALUES_PER_WORK: usize = 32;
/// Admission work for one exact curved-price evaluation: a few milliseconds of
/// 2048-bit series arithmetic, about 1/256 s of the RPC work refill rate.
const CURVE_EVALUATION_WORK: usize = 512;
/// Grant payments kept by a display summary of a record too large for a page.
const SUMMARY_GRANT_PAYMENTS: usize = 256;

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
    proposal: &'a crate::state::ProposalRecord,
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
/// payment, plus one per 32 data bytes (JSON numbers) for full JSON rows; hex
/// rows cost one unit per KiB of hexadecimal output.
fn mempool_work(pool: &[Transaction], offset: usize, limit: usize, format: &str) -> usize {
    pool.iter()
        .skip(offset)
        .take(limit)
        .map(|transaction| {
            let payments = match &transaction.body.operation {
                Operation::Propose { proposal, .. } => grant_payments(proposal),
                _ => 0,
            };
            let data = transaction.body.data.len();
            1 + match format {
                "summary" => payments,
                "hex" => (payments * 34 + data) / 512,
                _ => payments + data / RESPONSE_VALUES_PER_WORK,
            }
        })
        .fold(0, usize::saturating_add)
}

fn mempool_page(pool: &[Transaction], offset: usize, limit: usize, summary: bool) -> Result<Value> {
    let mut page = JsonPage::new();
    for transaction in pool.iter().skip(offset).take(limit) {
        let accepted = if summary {
            let body = &transaction.body;
            // Summaries never fail on one huge pending grant; a bounded
            // display copy keeps snapshots and wallets available.
            page.push_summarized(&pending_row(body, &body.operation), || {
                let (operation, payment_count) = truncated_operation(&body.operation);
                Ok(serde_json::to_value(Truncated {
                    row: pending_row(body, &operation),
                    truncated: true,
                    payment_count,
                })?)
            })?
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
const MAX_SNAPSHOT_KEYS: usize = 256;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
const VERSION_MASK: u32 = 0x1fffe000;
const HASHRATE_WINDOW_SECONDS: u64 = 300;
const MAX_SUBMITTED_HEADERS: usize = 4096;
pub const DEFAULT_STRATUM_SHARE_DIFFICULTY: f64 = 65_536.0;

struct MiningWorker {
    worker: String,
    accepted: u64,
    rejected: u64,
    blocks: u64,
    difficulty: f64,
    last_share: Option<Instant>,
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
    password_required: bool,
    difficulty: f64,
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
            password_required: false,
            difficulty: DEFAULT_STRATUM_SHARE_DIFFICULTY,
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
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.workers.remove(&self.id);
        }
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

struct Inner {
    chain: Chain,
    mempool: Vec<Transaction>,
    template: Option<Arc<Block>>,
    // Download progress is independent of which branch currently has greatest work.
    downloads: VecDeque<Hash>,
    relay_cursor: usize,
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
    mempool: Vec<Transaction>,
    cache: Arc<TipCache>,
}
/// Read-only results derived from one published tip state. Views of the same
/// tip share it across mempool changes, so repeated reads never rebuild them.
#[derive(Default)]
struct TipCache {
    root: std::sync::OnceLock<Hash>,
    governance: std::sync::OnceLock<Value>,
    proposals: std::sync::OnceLock<ProposalIndex>,
}
/// Consensus keys proposals by ID only and never removes them. This local
/// index is built once per tip, so a round page never walks all history.
struct ProposalIndex {
    /// Every proposal ID in consensus key order, for unfiltered pages.
    all: Vec<Hash>,
    /// Each round's IDs: its leader, decision or winner first, then by
    /// support (highest first) and ID. Cheap spam cannot hide better-backed
    /// proposals behind ground IDs that sort first.
    rounds: std::collections::BTreeMap<u64, Vec<Hash>>,
}
impl ProposalIndex {
    fn build(s: &State) -> Self {
        let mut all = Vec::with_capacity(s.proposals.len());
        let mut rounds = std::collections::BTreeMap::<u64, Vec<(&Amount, Hash)>>::new();
        for (key, proposal) in s.proposals.iter() {
            let Ok(id) = Hash::try_from(key) else {
                continue;
            };
            all.push(id);
            rounds
                .entry(proposal.round)
                .or_default()
                .push((&proposal.support, id));
        }
        let first = |round: u64| match &s.phase {
            crate::state::Phase::Auction(a) if a.round == round && a.leader.is_some() => a.leader,
            crate::state::Phase::Governance(d) if d.round == round => Some(d.proposal_id),
            _ => match s.rounds.get(&round.to_be_bytes()).map(|r| &r.status) {
                Some(crate::state::RoundStatus::Won(id)) => Some(*id),
                _ => None,
            },
        };
        let rounds = rounds
            .into_iter()
            .map(|(round, mut ids)| {
                let first = first(round);
                ids.sort_by(|(a_support, a), (b_support, b)| {
                    (Some(*b) == first)
                        .cmp(&(Some(*a) == first))
                        .then_with(|| b_support.cmp(a_support))
                        .then_with(|| a.cmp(b))
                });
                (round, ids.into_iter().map(|(_, id)| id).collect())
            })
            .collect();
        Self { all, rounds }
    }
    fn round_len(&self, round: u64) -> usize {
        self.rounds.get(&round).map_or(0, Vec::len)
    }
}
/// The worker owns only a weak node reference. Dropping the last node closes its
/// coalesced wake queue and joins the worker before its derived DB is reopened.
struct ExplorerWorker {
    sender: Option<mpsc::SyncSender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl ExplorerWorker {
    fn start(mut explorer: Explorer, inner: Weak<Mutex<Inner>>, config: Config) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("hashstash-explorer".into())
            .spawn(move || {
                'worker: while receiver.recv().is_ok() {
                    loop {
                        if matches!(receiver.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                            break 'worker;
                        }
                        let update = (|| -> Result<_> {
                            let Some(inner) = inner.upgrade() else {
                                return Ok(None);
                            };
                            let guard = inner.lock().map_err(|_| anyhow!("node lock poisoned"))?;
                            explorer.capture(&guard.chain)
                        })();
                        match update {
                            Ok(Some(update)) => {
                                if let Err(error) = explorer.apply_update(&config, update) {
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
            });
        match thread {
            Ok(thread) => Self {
                sender: Some(sender),
                thread: Some(thread),
            },
            Err(error) => {
                eprintln!("Explorer worker unavailable: {error}");
                Self {
                    sender: None,
                    thread: None,
                }
            }
        }
    }
    fn notify(&self) {
        if let Some(sender) = &self.sender {
            let _ = sender.try_send(());
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
            mempool: inner.mempool.clone(),
            cache: Arc::default(),
        }
    }
    fn state_root(&self) -> Hash {
        *self
            .cache
            .root
            .get_or_init(|| self.chain.tip_state().root())
    }
    fn proposal_index(&self) -> &ProposalIndex {
        self.cache
            .proposals
            .get_or_init(|| ProposalIndex::build(self.chain.tip_state()))
    }
}
#[derive(Clone)]
pub struct Node {
    inner: Arc<Mutex<Inner>>,
    explorer: Arc<ExplorerWorker>,
    explorer_path: Arc<PathBuf>,
    session_token_path: Arc<PathBuf>,
    miner: PublicKey,
    wallets: Arc<Mutex<WalletStore>>,
    startup_wallet_mode: Option<&'static str>,
    rpc_sessions: Arc<Semaphore>,
    peer_sessions: Arc<Semaphore>,
    rpc_parsers: Arc<Semaphore>,
    peer_parsers: Arc<Semaphore>,
    stratum_parsers: Arc<Semaphore>,
    rpc_workers: Arc<Semaphore>,
    rpc_mutations: Arc<Semaphore>,
    peer_workers: Arc<Semaphore>,
    stratum_workers: Arc<Semaphore>,
    guard: Arc<NetworkGuard>,
    published: Arc<RwLock<Arc<ReadView>>>,
    peer_events: Arc<Mutex<VecDeque<Value>>>,
    outbound_sessions: Arc<Semaphore>,
    mining: Arc<Mutex<MiningRuntime>>,
    work_updates: watch::Sender<u64>,
    mining_session_ids: Arc<AtomicU64>,
    peer_auth: Option<Arc<PeerPolicy>>,
    peer_health: Arc<Mutex<HashMap<SocketAddr, PeerHealth>>>,
    discovery_options: DiscoveryOptions,
    discovery: Arc<Mutex<Option<AddressBook>>>,
    discovery_path: PathBuf,
    discovery_id: Hash,
    last_tip_change: Arc<AtomicU64>,
    server_active: Arc<AtomicBool>,
}
#[derive(Default)]
struct PeerHealth {
    configured_at: u64,
    last_attempt: u64,
    last_success: u64,
    failures: u32,
}
impl Node {
    pub fn open(path: &Path, config: Config, miner: PublicKey) -> Result<Self> {
        ensure!(crypto::valid_key(&miner), "invalid miner public key");
        let inner = Inner {
            chain: Chain::open(path, config)?,
            mempool: Vec::new(),
            template: None,
            downloads: VecDeque::new(),
            relay_cursor: 0,
        };
        // A derived index failure never makes chain validation unavailable.
        let explorer = Explorer::open(path, &inner.chain).unwrap_or_else(|error| {
            eprintln!("Explorer index unavailable: {error}");
            Explorer::unavailable()
        });
        let published = Arc::new(RwLock::new(Arc::new(ReadView::capture(&inner))));
        let wallets = WalletStore::open(path, inner.chain.chain_id())?;
        let guard = Arc::new(NetworkGuard::with_frame_limit(admission_frame_bytes(
            &inner.chain.config,
            inner.chain.max_known_block_bytes(),
        )?));
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
        Ok(Self {
            inner,
            explorer,
            explorer_path: Arc::new(path.with_extension("explorer.sqlite")),
            session_token_path: Arc::new(session_token_path(path)),
            miner,
            wallets: Arc::new(Mutex::new(wallets)),
            startup_wallet_mode: None,
            rpc_sessions: Arc::new(Semaphore::new(8)),
            peer_sessions: Arc::new(Semaphore::new(8)),
            rpc_parsers: Arc::new(Semaphore::new(2)),
            peer_parsers: Arc::new(Semaphore::new(2)),
            stratum_parsers: Arc::new(Semaphore::new(2)),
            rpc_workers: Arc::new(Semaphore::new(4)),
            rpc_mutations: Arc::new(Semaphore::new(2)),
            peer_workers: Arc::new(Semaphore::new(2)),
            stratum_workers: Arc::new(Semaphore::new(2)),
            guard,
            published,
            peer_events: Arc::new(Mutex::new(VecDeque::new())),
            outbound_sessions: Arc::new(Semaphore::new(2)),
            mining: Arc::new(Mutex::new(MiningRuntime::default())),
            work_updates: watch::channel(0).0,
            mining_session_ids: Arc::new(AtomicU64::new(0)),
            peer_auth: None,
            peer_health: Arc::new(Mutex::new(HashMap::new())),
            discovery_options: DiscoveryOptions::default(),
            discovery: Arc::new(Mutex::new(None)),
            discovery_path,
            discovery_id,
            last_tip_change: Arc::new(AtomicU64::new(now())),
            server_active: Arc::new(AtomicBool::new(false)),
        })
    }
    /// Require pinned transport for every peer connection; never falls back to plaintext.
    pub fn with_peer_auth(mut self, policy: Arc<PeerPolicy>) -> Result<Self> {
        ensure!(
            policy.public_key() != self.miner,
            "peer identity must be separate from the mining/spending account"
        );
        self.peer_auth = Some(policy);
        Ok(self)
    }
    pub fn with_discovery(mut self, options: DiscoveryOptions) -> Result<Self> {
        options.validate()?;
        self.discovery_options = options;
        Ok(self)
    }
    pub fn peer_status(&self) -> Result<Value> {
        let at = now();
        let health = self
            .peer_health
            .lock()
            .map_err(|_| anyhow!("peer health lock poisoned"))?;
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
        let discovery = self
            .discovery
            .lock()
            .map_err(|_| anyhow!("peer discovery lock poisoned"))?;
        let discovery_status = match discovery.as_ref() {
            Some(book) => {
                json!({"enabled":true,"known":book.entries().count(),"verified":book.entries().filter(|e|e.last_success>0).count(),"advertise":book.options.advertise,"seeds":book.options.seeds,"last_error":book.last_error,"peers":book.entries().collect::<Vec<_>>()})
            }
            None => json!({"enabled":false}),
        };
        Ok(
            json!({"transport":if self.peer_auth.as_ref().is_some_and(|p|p.is_discovery()){"authenticated-discovery"}else if self.peer_auth.is_some(){"pinned-signed"}else{"compact-binary"}, "wire_format":"compact-binary",
            "public_key":self.peer_auth.as_ref().map(|p|hex::encode(p.public_key())), "peers":peers,
            "discovery":discovery_status,
            "observed_at":at, "encrypted":false,
            "chain_height":self.read_view()?.chain.tip_height(),
            "seconds_without_new_tip":at.saturating_sub(self.last_tip_change.load(Ordering::Relaxed)),
            "chain_stalled":at.saturating_sub(self.last_tip_change.load(Ordering::Relaxed)) >= 180}),
        )
    }
    fn publish(&self, inner: &Inner) -> Result<()> {
        self.guard.allow_frame(admission_frame_bytes(
            &inner.chain.config,
            inner.chain.max_known_block_bytes(),
        )?)?;
        let mut next = ReadView::capture(inner);
        let mut published = self
            .published
            .write()
            .map_err(|_| anyhow!("snapshot lock poisoned"))?;
        if published.chain.tip_hash() != next.chain.tip_hash() {
            self.last_tip_change.store(now(), Ordering::Relaxed);
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
            .map_err(|_| anyhow!("snapshot lock poisoned"))?
            .clone())
    }
    fn peer_limits(&self) -> Result<peer_wire::Limits> {
        let inner = self.locked()?;
        let limits = peer_wire::Limits::for_capacity(
            &inner.chain.config,
            inner.chain.max_known_block_bytes(),
        );
        self.guard.allow_frame(admission_frame_bytes(
            &inner.chain.config,
            inner.chain.max_known_block_bytes(),
        )?)?;
        Ok(limits)
    }
    fn peer_exchange_timeout(&self) -> Result<Duration> {
        let inner = self.locked()?;
        // A peer may be validating the block we just sent before it answers.
        // Keep the ordinary deadline, adding one second per governed MiB;
        // the actual wire representation bounds this allowance as well.
        let bytes = inner
            .chain
            .max_known_block_bytes()
            .min(peer_wire::MAX_WIRE_PAYLOAD_BYTES as u64);
        Ok(IO_TIMEOUT + Duration::from_secs(bytes / (1024 * 1024)))
    }

    /// Seed a fresh wallet store. A saved runtime selection survives startup flags.
    pub fn with_wallet(mut self, secret: [u8; 32]) -> Result<Self> {
        ensure!(
            self.startup_wallet_mode.is_none(),
            "startup wallet mode is already configured"
        );
        self.wallets_locked()?.seed_hot(secret)?;
        self.startup_wallet_mode = Some("hot");
        Ok(self)
    }
    /// Seed a fresh store with a watched account; preserve a saved selection.
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
        self.wallets
            .lock()
            .map_err(|_| anyhow!("wallet lock poisoned"))
    }
    fn wallet_status(&self) -> Result<Value> {
        Ok(self.wallets_locked()?.status())
    }
    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| anyhow!("node state lock poisoned"))
    }
    fn peer_event(&self, peer: String, result: &Result<()>) {
        if let Ok(mut events) = self.peer_events.lock() {
            let error = result
                .as_ref()
                .err()
                .map(|e| e.to_string().chars().take(256).collect::<String>());
            events.push_back(json!({"peer":peer,"time":now(),"ok":result.is_ok(),"error":error}));
            while events.len() > 64 {
                events.pop_front();
            }
        }
    }
    fn timestamp(chain: &Chain) -> u32 {
        let local = now().min(u32::MAX as u64) as u32;
        local.max(chain.tip_block().header.timestamp)
    }
    fn selected(
        chain: &Chain,
        miner: PublicKey,
        candidates: &[Transaction],
    ) -> Result<Vec<Transaction>> {
        Ok(chain
            .select_transactions(miner, candidates, mempool_limit(&chain.config))?
            .transactions)
    }
    fn combine_candidates(first: &[Transaction], second: &[Transaction]) -> Vec<Transaction> {
        let mut seen = HashSet::new();
        first
            .iter()
            .chain(second)
            .filter(|tx| seen.insert(codec::transaction_id(tx)))
            .cloned()
            .collect()
    }
    pub fn status(&self) -> Result<Value> {
        let view = self.read_view()?;
        Ok(Self::status_locked(&view))
    }
    fn status_locked(inner: &ReadView) -> Value {
        let s = inner.chain.tip_state();
        json!({"chain_id":hex::encode(inner.chain.chain_id()), "height":inner.chain.tip_height(), "tip":hex::encode(inner.chain.tip_hash()), "state_root":hex::encode(inner.state_root()), "clock":s.clock, "time_unit":"seconds", "clock_basis":"target_interval", "issued":s.issued.to_str_radix(10), "test_work":inner.chain.config.test_work, "phase":s.phase_name(), "decision":s.decision_id().map(hex::encode), "auction_round":s.auction_round(), "settings":s.settings, "mempool":inner.mempool.len(), "reserve":s.world.reserve.to_str_radix(10), "shares":s.world.shares.to_str_radix(10), "curve_mass":s.world.curve_mass.to_str_radix(10),"grant_capacity":crate::consensus::grant_capacity(&s.world).to_str_radix(10), "revenue":s.world.revenue.to_str_radix(10), "fee_policy":json!({"minimum_fee_rate":s.settings.minimum_fee_rate.to_string(),"fee_scale":crate::fees::FEE_SCALE,"account_weight":crate::fees::ACCOUNT_WEIGHT})})
    }
    pub fn template(&self) -> Result<Block> {
        let mut block = self.template_shared()?.as_ref().clone();
        block.header.timestamp = block
            .header
            .timestamp
            .max(now().min(u32::MAX as u64) as u32);
        Ok(block)
    }
    fn template_shared(&self) -> Result<Arc<Block>> {
        let mut i = self.locked()?;
        if let Some(template) = &i.template {
            return Ok(template.clone());
        }
        let (selected, block) = i.chain.select_template(
            self.miner,
            &i.mempool,
            mempool_limit(&i.chain.config),
            Self::timestamp(&i.chain),
        )?;
        i.mempool = selected.transactions;
        self.publish(&i)?;
        let block = Arc::new(block);
        i.template = Some(block.clone());
        Ok(block)
    }
    pub fn submit_transaction(&self, tx: Transaction) -> Result<Hash> {
        let mut i = self.locked()?;
        self.submit_locked(&mut i, tx)
    }
    fn submit_locked(&self, i: &mut Inner, tx: Transaction) -> Result<Hash> {
        let id = codec::transaction_id(&tx);
        if i.mempool.iter().any(|t| codec::transaction_id(t) == id) {
            return Ok(id);
        }
        ensure!(
            i.mempool.len() < mempool_limit(&i.chain.config),
            "mempool full"
        );
        ensure!(
            codec::encode(&tx).len()
                <= i.chain
                    .config
                    .transaction_bytes(&i.chain.tip_state().settings),
            "transaction too large"
        );
        let mut candidates = i.mempool.clone();
        candidates.push(tx);
        let selected = Self::selected(&i.chain, self.miner, &candidates)?;
        ensure!(
            selected.iter().any(|t| codec::transaction_id(t) == id),
            "transaction not valid in next block or block capacity exhausted"
        );
        i.mempool = selected;
        i.template = None;
        self.publish(i)?;
        Ok(id)
    }
    fn wallet_submit(&self, request: HotWalletRequest) -> Result<Hash> {
        let sender = parse_account(
            &request.expected_sender,
            &self.read_view()?.chain.chain_id(),
        )?;
        // Keep selection fixed until the signed transaction has been accepted.
        let wallets = self.wallets_locked()?;
        let secret = wallets.selected_secret(&sender, request.wallet_revision)?;
        let mut i = self.locked()?;
        let body = self.prepare_locked(
            &mut i,
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
        self.submit_locked(&mut i, crypto::sign(&body, secret)?)
    }
    fn prepare_locked(
        &self,
        i: &mut Inner,
        sender: PublicKey,
        request: WalletRequest,
    ) -> Result<TransactionBody> {
        check_operation_bounds(&i.chain.config, &request.operation)?;
        ensure!(
            request.expiry_blocks.is_none_or(|blocks| blocks > 0),
            "expiry_blocks must be positive"
        );
        let selected = Self::selected(&i.chain, self.miner, &i.mempool)?;
        if selected != i.mempool {
            i.mempool = selected;
            i.template = None;
            self.publish(i)?;
        }
        let state = i.chain.tip_state();
        let account = state
            .account(&sender, None)
            .context("sender account has not been funded")?;
        let mut nonce = account.nonce;
        for tx in &i.mempool {
            if tx.body.sender == sender {
                nonce = nonce.max(tx.body.nonce.checked_add(1).context("nonce exhausted")?);
            }
        }
        ensure!(nonce < u64::MAX, "nonce exhausted");
        ensure!(
            request.nonce.is_none_or(|requested| requested == nonce),
            "requested nonce differs from pending nonce"
        );
        let body = wallet_body(
            &i.chain.config,
            state,
            i.chain.tip_hash(),
            sender,
            nonce,
            request,
        )?;
        let unsigned_size = codec::encode(&body).len();
        // A signed transaction adds exactly 64 signature bytes.
        ensure!(
            unsigned_size.saturating_add(64) <= i.chain.config.transaction_bytes(&state.settings),
            "transaction too large"
        );
        Ok(body)
    }
    pub fn submit_block(&self, block: Block) -> Result<bool> {
        let mut i = self.locked()?;
        let old_tip = i.chain.tip_hash();
        let changed = i.chain.submit_with_replay_budget(block, now(), 64)?;
        if changed {
            i.template = None;
            let pending = std::mem::take(&mut i.mempool);
            // Publish the newly committed tip immediately, with an empty valid pool.
            // Recovery may need disk access and cannot roll back a committed block.
            self.publish(&i)?;
            // Recover transactions from the abandoned branch, including same-height forks.
            let mut left = i.chain.block(&old_tip).context("old tip missing")?;
            let mut right = i.chain.tip_block().clone();
            let mut detached = Vec::new();
            while codec::block_hash(&left) != codec::block_hash(&right) {
                if left.height >= right.height && left.height > 0 {
                    detached.push(codec::block_hash(&left));
                    left = i
                        .chain
                        .block(&left.header.previous)
                        .context("old branch parent missing")?;
                } else {
                    right = i
                        .chain
                        .block(&right.header.previous)
                        .context("new branch parent missing")?;
                }
            }
            // Preserve valid pending entries, then recover detached transactions.
            // Capacity is charged only to accepted, unique candidates.
            let mut recovered = Self::selected(&i.chain, self.miner, &pending)?;
            for hash in detached.into_iter().rev() {
                let block = i.chain.block(&hash).context("detached block missing")?;
                for chunk in block.transactions.chunks(MAX_MEMPOOL) {
                    let priority = Self::combine_candidates(&pending, &recovered);
                    let selected = Self::selected(&i.chain, self.miner, &priority)?;
                    let candidates = Self::combine_candidates(&selected, chunk);
                    recovered = Self::selected(&i.chain, self.miner, &candidates)?;
                }
            }
            let priority = Self::combine_candidates(&pending, &recovered);
            let recovered = Self::selected(&i.chain, self.miner, &priority)?;
            i.mempool = recovered;
            self.publish(&i)?;
        }
        Ok(changed)
    }
    fn mining_job_eligible(&self, block: &Block) -> Result<bool> {
        let i = self.locked()?;
        Ok(i.chain.tip_hash() == block.header.previous)
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
        // candidate without changing the configured miner or its Stratum cache.
        let candidate = {
            let i = self.locked()?;
            i.chain
                .select_template(
                    recipient,
                    &i.mempool,
                    mempool_limit(&i.chain.config),
                    Self::timestamp(&i.chain),
                )?
                .1
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
    fn blocks_after(chain: &Chain, locator: &[Hash]) -> Result<(Vec<Block>, peer_wire::Limits)> {
        ensure!(
            !locator.is_empty() && locator.len() <= 128,
            "invalid locator length"
        );
        let height = locator
            .iter()
            .filter_map(|h| chain.block(h).map(|b| (*h, b.height)))
            .filter(|(h, height)| chain.hash_at_height(*height) == Some(*h))
            .max_by_key(|(_, height)| *height)
            .map(|(_, h)| h)
            .context("no common ancestor")?;
        let mut out = Vec::new();
        let mut size = 0usize;
        // The recipient has validated this common ancestor. Stop before a
        // larger newly governed block so it can first validate the transition
        // and increase its admission allowance on the next synchronization.
        let ancestor = chain
            .hash_at_height(height)
            .context("common ancestor missing")?;
        let parent = chain
            .state_at(&ancestor)
            .context("common ancestor state missing")?;
        let limits = peer_wire::Limits::for_capacity(&chain.config, parent.settings.block_bytes);
        let block_budget = limits
            .block_bytes
            .checked_add(MAX_BATCH * 9)
            .context("peer block batch budget overflow")?
            .min(
                limits
                    .frame_bytes()
                    .saturating_sub(peer_wire::SYNC_OVERHEAD_BYTES),
            );
        for h in height + 1..=chain.tip_height() {
            if out.len() >= MAX_BATCH {
                break;
            }
            let b = chain
                .block(&chain.hash_at_height(h).context("active height missing")?)
                .context("active block missing")?;
            let bytes = peer_wire::record_size(codec::encode(&b).len())?;
            if bytes > block_budget && out.is_empty() {
                bail!(
                    "valid block exceeds local peer wire capacity; import requires a larger transport representation"
                );
            }
            let next_size = size
                .checked_add(bytes)
                .context("peer block batch length overflow")?;
            if next_size > block_budget {
                break;
            }
            size = next_size;
            out.push(b);
        }
        Ok((out, limits))
    }
    fn peer_snapshot(&self, locator: Option<&[Hash]>) -> Result<PeerMessage> {
        let mut i = self.locked()?;
        let (blocks, peer_limits) = match locator {
            Some(l) => Self::blocks_after(&i.chain, l)?,
            None => (Vec::new(), peer_wire::Limits::from_config(&i.chain.config)),
        };
        let blocks_bytes = blocks
            .iter()
            .try_fold(0usize, |total, block| -> Result<usize> {
                total
                    .checked_add(peer_wire::record_size(codec::encode(block).len())?)
                    .context("peer block framing length overflow")
            })?;
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
            visited += 1;
            transaction_bytes = next;
            transactions.push(tx.clone());
        }
        i.relay_cursor = if i.mempool.is_empty() {
            0
        } else {
            (start + visited) % i.mempool.len()
        };
        let active = Self::locator(&i.chain);
        let mut request_locator: Vec<Hash> = i.downloads.iter().copied().collect();
        request_locator.extend(active);
        let mut seen = HashSet::new();
        request_locator.retain(|h| seen.insert(*h));
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
    fn receive_peer(&self, msg: &PeerMessage) -> Result<()> {
        ensure!(
            msg.chain == self.read_view()?.chain.chain_id(),
            "different genesis configuration"
        );
        ensure!(
            msg.blocks.len() <= MAX_BATCH
                && msg.transactions.len() <= MAX_MEMPOOL
                && msg.locator.len() <= 128,
            "peer batch limit exceeded"
        );
        for b in &msg.blocks {
            self.submit_block(b.clone())?;
            let mut i = self.locked()?;
            let hash = codec::block_hash(b);
            // Replace the preceding cursor for this branch, so normal downloads
            // consume one entry each rather than one per batch.
            // Retain accepted progress even if a later message entry is invalid.
            i.downloads
                .retain(|h| *h != hash && *h != b.header.previous);
            i.downloads.push_front(hash);
            i.downloads.truncate(MAX_CONNECTIONS);
        }
        // Admit the batch together. Revalidating every growing prefix here made
        // one ordinary full-pool relay need tens of thousands of signature checks.
        // Outdated/duplicate entries remain expected during synchronization.
        let mut i = self.locked()?;
        let mut ids: HashSet<_> = i.mempool.iter().map(codec::transaction_id).collect();
        let mut candidates = i.mempool.clone();
        for tx in &msg.transactions {
            if codec::encode(tx).len()
                <= i.chain
                    .config
                    .transaction_bytes(&i.chain.tip_state().settings)
                && ids.insert(codec::transaction_id(tx))
            {
                candidates.push(tx.clone());
            }
        }
        if candidates.len() != i.mempool.len() {
            i.mempool = Self::selected(&i.chain, self.miner, &candidates)?;
            i.template = None;
            self.publish(&i)?;
        }
        Ok(())
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
                let s = i.chain.tip_state();
                // The inline decision grant is projected into every response.
                if let crate::state::Phase::Governance(d) = &s.phase {
                    charge(meter, grant_payments(&d.proposal))?;
                }
                Ok(i.cache
                    .governance
                    .get_or_init(|| {
                        let world = |w: &crate::state::World| json!({"reserve":w.reserve.to_str_radix(10),"shares":w.shares.to_str_radix(10),"curve_mass":w.curve_mass.to_str_radix(10),"grant_capacity":crate::consensus::grant_capacity(w).to_str_radix(10),"account_shares":w.account_shares.to_str_radix(10),"revenue":w.revenue.to_str_radix(10),"grant_escrow":w.grant_escrow.to_str_radix(10)});
                        let progress = if let crate::state::Phase::Governance(d) = &s.phase {
                            let observed = s.height.saturating_sub(d.started_height).min(d.blocks);
                            json!({"time_unit":"blocks","leading_blocks":d.leading_blocks,"observed_blocks":observed,"blocks":d.blocks,"blocks_remaining":d.blocks.saturating_sub(observed)})
                        } else {
                            Value::Null
                        };
                        json!({"phase":s.phase,"height":s.height,"state_root":hex::encode(i.state_root()),"clock":s.clock,"time_unit":"seconds","clock_basis":"target_interval","settings":s.settings,"frozen":s.frozen,"pass_margin_bps":s.frozen.pass_margin_bps.unwrap_or(0).to_string(),"world":world(&s.world),"pass":s.alternative.as_ref().map(world),"auction_escrow":s.auction_escrow.to_str_radix(10),"progress":progress})
                    })
                    .clone())
            }
            "proposals" => {
                let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = params
                    .get("limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(128)
                    .min(128) as usize;
                let round = params.get("round").and_then(Value::as_u64);
                let s = i.chain.tip_state();
                let index = i.proposal_index();
                let ids = match round {
                    Some(round) => index.rounds.get(&round).map_or(&[][..], Vec::as_slice),
                    None => &index.all,
                };
                let ids = ids.get(offset..).unwrap_or_default();
                let ids = &ids[..ids.len().min(limit)];
                let mut work = 0usize;
                for id in ids {
                    let proposal = s.proposals.get(id).context("indexed proposal missing")?;
                    work = work.saturating_add(1 + grant_payments(&proposal.action));
                }
                charge(meter, work)?;
                let mut page = JsonPage::new();
                for id in ids {
                    let proposal = s.proposals.get(id).context("indexed proposal missing")?;
                    let accepted = page.push_summarized(
                        &ProposalPageRow {
                            id: hex::encode(id),
                            proposal,
                        },
                        || {
                            let summary = crate::state::ProposalRecord {
                                round: proposal.round,
                                description: proposal.description,
                                action: truncated_proposal(&proposal.action),
                                support: proposal.support.clone(),
                                refund_height: proposal.refund_height,
                            };
                            Ok(serde_json::to_value(Truncated {
                                row: ProposalPageRow {
                                    id: hex::encode(id),
                                    proposal: &summary,
                                },
                                truncated: true,
                                payment_count: grant_payments(&proposal.action),
                            })?)
                        },
                    )?;
                    if !accepted {
                        break;
                    }
                }
                Ok(Value::Array(page.items))
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
                let pending_nonce = i
                    .mempool
                    .iter()
                    .filter(|tx| tx.body.sender == key)
                    .fold(a.nonce, |nonce, tx| {
                        nonce.max(tx.body.nonce.saturating_add(1))
                    });
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
                let proposals = match round {
                    Some(round) => {
                        Self::read_rpc_metered(i, "proposals", json!({"round":round}), meter)?
                    }
                    None => json!([]),
                };
                charge(meter, mempool_work(&i.mempool, 0, 128, "summary"))?;
                let mut snapshot = json!({
                    "status":Self::status_locked(i),
                    "config":i.chain.config,
                    "governance":Self::read_rpc_metered(i,"governance",json!({}),meter)?,
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
    fn public_rpc(&self, method: &str, params: Value, admission: &Session) -> Result<Value> {
        ensure!(
            public_rpc_allowed(method),
            "method is unavailable on public web"
        );
        let mut result = if matches!(method, "fee_quote" | "transfer_quote") {
            // The private RPC convenience fallback reads the selected server
            // wallet. Public requests must always identify their own sender.
            required_str(&params, "sender")?;
            let view = self.read_view()?;
            Self::read_rpc_metered(&view, method, params, Some(admission))
        } else {
            self.rpc_with_admission(method, params, Some(admission))
        }
        .map_err(public_error)?;
        // The public mining panel shows workers and the advertised endpoint;
        // the Stratum bind interface stays private to the operator.
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
            return Explorer::read(
                &self.explorer_path,
                method,
                params,
                &view.chain.config,
                view.chain.tip_state(),
                view.chain.tip_hash(),
                &view.mempool,
            );
        }
        match method {
            "mining" => self.mining_status(),
            "preparetransaction" => {
                let request: PrepareRequest = serde_json::from_value(params)?;
                let sender = parse_account(&request.sender, &self.read_view()?.chain.chain_id())?;
                let mut i = self.locked()?;
                let body = self.prepare_locked(
                    &mut i,
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
                    i.chain.tip_state().root(),
                    &body,
                )?;

                Ok(result)
            }
            "fee_quote" | "transfer_quote" => {
                let i = self.read_view()?;
                let mut params = params;
                if params.get("sender").is_none() {
                    let session = self.wallets_locked()?.status();
                    params["sender"] = session
                        .get("public_key")
                        .filter(|key| key.is_string())
                        .cloned()
                        .unwrap_or_else(|| json!(hex::encode(self.miner)));
                }
                Self::read_rpc_metered(&i, method, params, admission)
            }
            "broadcasttransaction" => {
                let request: BroadcastRequest = serde_json::from_value(params)?;
                let tx = wallet::decode_signed(&request.raw)?;
                Ok(json!({"transaction_id":hex::encode(self.submit_transaction(tx)?)}))
            }
            "getblock" => {
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
                Ok(serde_json::to_value(
                    i.chain.block(&h).context("unknown block")?,
                )?)
            }
            "peers" => Ok(json!(
                *self
                    .peer_events
                    .lock()
                    .map_err(|_| anyhow!("diagnostic lock poisoned"))?
            )),
            "peerstatus" => self.peer_status(),

            "submittransaction" => {
                let tx: Transaction =
                    serde_json::from_value(params.get("transaction").cloned().unwrap_or(params))?;
                Ok(json!({"txid":hex::encode(self.submit_transaction(tx)?)}))
            }
            "submitblock" => {
                let b: Block =
                    serde_json::from_value(params.get("block").cloned().unwrap_or(params))?;
                let hash = codec::block_hash(&b);
                Ok(json!({"hash":hex::encode(hash),"selected":self.submit_block(b)?}))
            }
            "mine" => {
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
                let mut hashes = Vec::new();
                for _ in 0..count {
                    if let Some(admission) = admission {
                        let view = self.read_view()?;

                        // Recheck each block's current queue. Charging an entire
                        // batch as 4096-transaction blocks rejects even empty
                        // batches beyond the admission bucket's capacity.
                        admission.work((view.mempool.len() + 1).max(MAX_MEMPOOL))?;
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
        let mut result = self
            .mining
            .lock()
            .map_err(|_| anyhow!("mining statistics lock poisoned"))?
            .value(&self.miner, &chain_id)?;
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
async fn write_peer<W: AsyncWrite + Unpin>(
    node: &Node,
    write: &mut W,
    message: PeerPacket,
    admission: &Session,
    auth: &mut Option<PeerChannel>,
) -> Result<()> {
    let work = match &message {
        PeerPacket::Sync(message) => {
            message.transactions.len()
                + message
                    .blocks
                    .iter()
                    .map(|b| b.transactions.len() + 1)
                    .sum::<usize>()
        }
        PeerPacket::Ack => 1,
        PeerPacket::GetAddresses { .. } => 1,
        PeerPacket::Addresses { addresses, .. } => addresses.len().max(1),
    };
    admission.work(work.max(1))?;
    let limits = node.peer_limits()?;
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let mut channel = auth.take();
    let (bytes, channel) = tokio::task::spawn_blocking(move || -> Result<_> {
        let _permit = permit;
        let payload = peer_wire::encode(&message, limits)?;
        let bytes = if let Some(auth) = &mut channel {
            auth.seal(payload)?
        } else {
            peer_wire::frame(&payload, limits.frame_bytes())?
        };
        Ok((bytes, channel))
    })
    .await
    .context("peer serialization worker failed")??;
    *auth = channel;
    admission.bytes(bytes.len())?;
    timeout(IO_TIMEOUT, write.write_all(&bytes)).await??;
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
    let permit = timeout(IO_TIMEOUT, slots.acquire_owned()).await??;
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
async fn read_peer_packet<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    auth: &mut Option<PeerChannel>,
    acknowledgment: bool,
) -> Result<PeerPacket> {
    read_peer_packet_bounded(r, node, admission, auth, acknowledgment, None).await
}
async fn read_peer_packet_bounded<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    auth: &mut Option<PeerChannel>,
    acknowledgment: bool,
    bound: Option<usize>,
) -> Result<PeerPacket> {
    admission.request()?;
    let limits = node.peer_limits()?;
    let maximum = if acknowledgment {
        peer_wire::ACK_BYTES
    } else {
        bound.unwrap_or_else(|| limits.frame_bytes())
    };
    let exchange_timeout = if bound.is_some() {
        IO_TIMEOUT
    } else {
        node.peer_exchange_timeout()?
    };
    let result = if let Some(auth) = auth {
        timeout(
            exchange_timeout,
            auth.read(r, maximum, admission, node.peer_parsers.clone()),
        )
        .await
        .map_err(anyhow::Error::from)
        .and_then(|v| v)
    } else {
        timeout(exchange_timeout, read_peer_frame(r, maximum, admission))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|v| v)
    };
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(error) => {
            admission.malformed();
            return Err(error);
        }
    };
    let permit = timeout(IO_TIMEOUT, node.peer_parsers.clone().acquire_owned()).await??;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        peer_wire::decode(&bytes, limits)
    })
    .await
    .context("peer decoding worker failed")?;
    match result {
        Ok(packet) => {
            ensure!(
                matches!(&packet, PeerPacket::Ack) == acknowledgment,
                "unexpected peer message type"
            );
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
                PeerPacket::GetAddresses { .. } => 1,
                PeerPacket::Addresses { addresses, .. } => addresses.len().max(1),
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
async fn read_peer<R: AsyncBufRead + Unpin>(
    r: &mut R,
    node: &Node,
    admission: &Session,
    auth: &mut Option<PeerChannel>,
) -> Result<PeerMessage> {
    match read_peer_packet(r, node, admission, auth, false).await? {
        PeerPacket::Sync(message) => Ok(message),
        PeerPacket::Ack => bail!("unexpected peer acknowledgment"),
        _ => bail!("unexpected discovery message during synchronization"),
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
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length >= peer_wire::ACK_BYTES && length <= maximum,
        "peer frame too large or truncated"
    );
    let mut out = Vec::with_capacity(length.min(8192));
    let mut chunk = [0u8; 8192];
    while out.len() < length {
        let take = chunk.len().min(length - out.len());
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
    database.with_extension("session-token")
}
fn write_session_token(path: &Path, token: &str) -> Result<()> {
    // Never write through an existing file or link; create a fresh one that
    // only the node's account can read (Windows inherits the directory ACL).
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("session token file cannot be replaced"),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .context("session token file cannot be created")?;
    std::io::Write::write_all(&mut file, token.as_bytes())?;
    file.sync_all()?;
    Ok(())
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
        if let Ok(mut mining) = self.mining.lock() {
            mining.enabled = false;
            mining.workers.clear();
        }
    }
}

pub async fn serve(node: Node, options: ServerOptions) -> Result<Server> {
    ensure!(
        node.server_active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok(),
        "this node already has a server"
    );
    let lease = ServerLease(node.server_active.clone());
    validate_stratum_difficulty(options.stratum_share_difficulty)?;
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
    {
        let mut health = node
            .peer_health
            .lock()
            .map_err(|_| anyhow!("peer health lock poisoned"))?;
        for peer in &options.peers {
            health.entry(*peer).or_insert_with(|| PeerHealth {
                configured_at: now(),
                ..Default::default()
            });
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
        *node
            .discovery
            .lock()
            .map_err(|_| anyhow!("peer discovery lock poisoned"))? = Some(book);
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
        let mut mining = node
            .mining
            .lock()
            .map_err(|_| anyhow!("mining statistics lock poisoned"))?;
        ensure!(!mining.enabled, "this node already has a mining listener");
        *mining = MiningRuntime {
            enabled: options.stratum_enabled,
            bind_address: options.stratum_enabled.then_some(addresses.2),
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
            ..MiningRuntime::default()
        };
    }
    let private_http = Arc::new(HttpContext {
        public: false,
        session_token: Some(session_token),
        sessions: node.rpc_sessions.clone(),
        parsers: node.rpc_parsers.clone(),
        workers: node.rpc_workers.clone(),
        mutations: node.rpc_mutations.clone(),
        guard: node.guard.clone(),
    });
    // The proxy may originate every public connection from loopback. Separate
    // admission records and worker slots prevent it exhausting private RPC.
    let public_http = Arc::new(HttpContext {
        public: true,
        session_token: None,
        sessions: Arc::new(Semaphore::new(8)),
        parsers: Arc::new(Semaphore::new(2)),
        workers: Arc::new(Semaphore::new(4)),
        mutations: Arc::new(Semaphore::new(2)),
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
        let extranonces = if kind == 2 {
            node.mining_session_ids.clone()
        } else {
            Arc::new(AtomicU64::new(0))
        };
        let http = if kind == 3 {
            public_http.clone()
        } else {
            private_http.clone()
        };
        let sessions = if kind == 0 || kind == 3 {
            http.sessions.clone()
        } else {
            node.peer_sessions.clone()
        };
        tasks.push(tokio::spawn(async move {
            let mut clients = tokio::task::JoinSet::new();
            loop { tokio::select! {
                _ = shutdown.changed() => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                accepted = listener.accept() => {
                    let Ok((stream, address)) = accepted else { break };
                    if kind == 1 && n.peer_auth.as_ref().is_some_and(|p| !p.allows_ip(address.ip())) { drop(stream); continue; }
                    let Ok(permit) = limit.clone().try_acquire_owned() else { drop(stream); continue };
                    let large = if kind != 2 {
                        let Ok(permit) = sessions.clone().try_acquire_owned() else { drop(stream); continue };
                        Some(permit)
                    } else { None };
                    let surface=match kind {0|3=>Surface::Rpc,1=>Surface::Peer,_=>Surface::Stratum};
                    let guard = if kind == 0 || kind == 3 { &http.guard } else { &n.guard };
                    let Ok(admission)=guard.admit(address.ip(),surface) else {drop(stream);continue};
                    let node = n.clone(); let password = password.clone(); let http=http.clone();
                    let next = extranonces.fetch_add(1, Ordering::Relaxed);
                    let Ok(extranonce) = u32::try_from(next) else { drop(stream); continue };
                    clients.spawn(async move { let _permit = permit; let _large = large; let _ = stream.set_nodelay(true);
                        let reporter = node.clone();
                        let result = match kind { 0|3 => http_session(node, stream, http, admission).await, 1 => peer_session(node, stream, admission).await, _ => stratum_session(node, stream, password, share_difficulty, extranonce.to_le_bytes(), admission).await };
                        // Peer data is untrusted; individual failures close only that connection.
                        if result.is_err() { reporter.peer_event(format!("inbound/{kind}/{address}"), &result); }
                    });
                }
            }}
            clients.abort_all(); while clients.join_next().await.is_some() {}
        }));
    }
    if node.discovery_options.enabled {
        tasks.push(tokio::spawn(discovery_loop(node.clone(), rx.clone())));
        tasks.push(tokio::spawn(discovery_seed_loop(node.clone(), rx.clone())));
    }
    for peer in options
        .peers
        .into_iter()
        .filter(|_| !node.discovery_options.enabled)
    {
        let n = node.clone();
        let mut shutdown = rx.clone();
        tasks.push(tokio::spawn(async move {
            let mut failures=0u32;
            loop {
                let result=tokio::select! { _ = shutdown.changed() => break, result=sync_peer(&n, peer) => result };
                failures=if result.is_ok()||result.as_ref().is_err_and(|e|e.is::<crate::chain::ValidationDeferred>()){0}else{failures.saturating_add(1)};
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
fn random_u64() -> u64 {
    let mut bytes = [0; 8];
    let _ = getrandom::fill(&mut bytes);
    u64::from_le_bytes(bytes)
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
                    if let Ok(mut guard) = node.discovery.lock()
                        && let Some(book) = guard.as_mut()
                    {
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
            let Ok(mut guard) = node.discovery.lock() else {
                break;
            };
            let Some(book) = guard.as_mut() else { break };
            book.next(now(), 2usize.saturating_sub(workers.len()))
        };
        for peer in candidates {
            let n = node.clone();
            workers.spawn(async move {
                // Keep the former five-stage overall budget, but grow it with
                // the same validated capacity as individual exchanges.
                let Ok(exchange_timeout) = n.peer_exchange_timeout() else {
                    return (peer, false);
                };
                let result = timeout(exchange_timeout.saturating_mul(5), sync_peer(&n, peer)).await;
                let success = matches!(result, Ok(Ok(())));
                if success {
                    let query = n
                        .discovery
                        .lock()
                        .ok()
                        .and_then(|mut g| g.as_mut().map(|b| b.needs_discovery(peer, now())))
                        .unwrap_or(false);
                    if query {
                        // A separate exchange cannot change Sync/Ack semantics or
                        // cause an authenticated connection to retry unsigned.
                        let result = discover_peer(&n, peer).await;
                        if result.is_err() {
                            n.peer_event(format!("discovery/{peer}"), &result);
                        }
                    }
                }
                (peer, success)
            });
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            Some(result)=workers.join_next(),if !workers.is_empty()=>{
                if let Ok((peer,success))=result
                    && let Ok(mut guard)=node.discovery.lock()
                    && let Some(book)=guard.as_mut() {
                    book.finished(peer,success,now(),random_u64());
                }
            }
            _=tokio::time::sleep(Duration::from_millis(200))=>{},
        }
        if now().saturating_sub(saved_at) >= 5 {
            if let Ok(mut guard) = node.discovery.lock()
                && let Some(book) = guard.as_mut()
            {
                book.last_error = book
                    .save()
                    .err()
                    .map(|e| format!("address book save failed: {e}"));
            }
            saved_at = now();
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
    if let Ok(mut guard) = node.discovery.lock()
        && let Some(book) = guard.as_mut()
    {
        book.last_error = book
            .save()
            .err()
            .map(|e| format!("address book save failed: {e}"));
    }
}
async fn discover_peer(node: &Node, peer: SocketAddr) -> Result<()> {
    let _permit = timeout(IO_TIMEOUT, node.outbound_sessions.clone().acquire_owned()).await??;
    let policy = node
        .peer_auth
        .as_ref()
        .context("discovery requires authenticated transport")?;
    ensure!(
        policy.is_discovery(),
        "discovery disabled in pinned transport"
    );
    let admission = node.guard.admit(peer.ip(), Surface::Peer)?;
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(peer)).await??;
    let chain = node.read_view()?.chain.chain_id();
    let mut auth = Some(
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
        &mut auth,
    )
    .await?;
    match read_peer_packet_bounded(
        &mut read,
        node,
        &admission,
        &mut auth,
        false,
        Some(peer_wire::DISCOVERY_BYTES),
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
            let mut guard = node
                .discovery
                .lock()
                .map_err(|_| anyhow!("peer discovery lock poisoned"))?;
            guard
                .as_mut()
                .context("discovery stopped")?
                .learn(peer, &addresses, now());
            Ok(())
        }
        _ => bail!("unexpected peer discovery response"),
    }
}
async fn peer_session(node: Node, mut stream: TcpStream, admission: Session) -> Result<()> {
    let remote = stream.peer_addr()?;
    let mut auth = if let Some(policy) = &node.peer_auth {
        let ip = stream.peer_addr()?.ip();
        match timeout(
            IO_TIMEOUT,
            PeerChannel::accept(
                &mut stream,
                policy,
                ip,
                node.read_view()?.chain.chain_id(),
                &admission,
            ),
        )
        .await
        {
            Ok(Ok(channel)) => Some(channel),
            result => {
                admission.malformed();
                return Err(match result {
                    Ok(Err(e)) => e,
                    Err(e) => e.into(),
                    _ => unreachable!(),
                });
            }
        }
    } else {
        None
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let hello = match read_peer_packet(&mut read, &node, &admission, &mut auth, false).await? {
        PeerPacket::Sync(hello) => hello,
        PeerPacket::GetAddresses {
            chain,
            node: identity,
            advertise,
        } => {
            ensure!(
                chain == node.read_view()?.chain.chain_id(),
                "discovery chain mismatch"
            );
            ensure!(identity != node.discovery_id, "self discovery connection");
            let reply = {
                let mut guard = node
                    .discovery
                    .lock()
                    .map_err(|_| anyhow!("peer discovery lock poisoned"))?;
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
            write_peer(&node, &mut write, reply, &admission, &mut auth).await?;
            return Ok(());
        }
        _ => bail!("unexpected first peer message"),
    };
    ensure!(
        hello.blocks.is_empty(),
        "first peer message must be a locator request"
    );
    let hello = receive_peer_async(&node, hello).await?;
    let reply = peer_snapshot_async(&node, Some(hello.locator)).await?;
    write_peer(
        &node,
        &mut write,
        PeerPacket::Sync(reply),
        &admission,
        &mut auth,
    )
    .await?;
    let push = read_peer(&mut read, &node, &admission, &mut auth).await?;
    receive_peer_async(&node, push).await?;
    write_peer(&node, &mut write, PeerPacket::Ack, &admission, &mut auth).await?;
    Ok(())
}
pub async fn sync_peer(node: &Node, peer: SocketAddr) -> Result<()> {
    if let Ok(mut health) = node.peer_health.lock() {
        // Only configured peers enter this bounded map; manual diagnostics cannot grow it.
        if let Some(h) = health.get_mut(&peer) {
            h.last_attempt = now();
        }
    }
    let result = sync_peer_inner(node, peer).await;
    if let Ok(mut health) = node.peer_health.lock()
        && let Some(h) = health.get_mut(&peer)
    {
        if result.is_ok()
            || result
                .as_ref()
                .is_err_and(|e| e.is::<crate::chain::ValidationDeferred>())
        {
            h.last_success = now();
            h.failures = 0;
        } else {
            h.failures = h.failures.saturating_add(1);
        }
    }
    node.peer_event(peer.to_string(), &result);
    result
}
async fn receive_peer_async(node: &Node, message: PeerMessage) -> Result<PeerMessage> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.receive_peer(&message)?;
        Ok(message)
    })
    .await
    .context("peer validation worker failed")?
}
async fn peer_snapshot_async(node: &Node, locator: Option<Vec<Hash>>) -> Result<PeerMessage> {
    let permit = timeout(IO_TIMEOUT, node.peer_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.peer_snapshot(locator.as_deref())
    })
    .await
    .context("peer snapshot worker failed")?
}
async fn sync_peer_inner(node: &Node, peer: SocketAddr) -> Result<()> {
    // Reserve separate inbound capacity so simultaneous outgoing synchronizations
    // cannot consume every receiving slot on all peers.
    let _frame_permit = node.outbound_sessions.clone().acquire_owned().await?;
    let admission = node.guard.admit(peer.ip(), Surface::Peer)?;
    let mut stream = timeout(IO_TIMEOUT, TcpStream::connect(peer)).await??;
    let mut auth = if let Some(policy) = &node.peer_auth {
        Some(
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
        None
    };
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    write_peer(
        node,
        &mut write,
        PeerPacket::Sync(peer_snapshot_async(node, None).await?),
        &admission,
        &mut auth,
    )
    .await?;
    let reply = read_peer(&mut read, node, &admission, &mut auth).await?;
    let reply = receive_peer_async(node, reply).await?;
    write_peer(
        node,
        &mut write,
        PeerPacket::Sync(peer_snapshot_async(node, Some(reply.locator)).await?),
        &admission,
        &mut auth,
    )
    .await?;
    read_peer_packet(&mut read, node, &admission, &mut auth, true).await?;
    Ok(())
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
    for _ in 0..32 {
        let quote = fees::quote(
            c,
            s,
            &Transaction {
                body: body.clone(),
                signature: [0; 64],
            },
        )?;
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
    sessions: Arc<Semaphore>,
    parsers: Arc<Semaphore>,
    workers: Arc<Semaphore>,
    mutations: Arc<Semaphore>,
    guard: Arc<NetworkGuard>,
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

async fn read_http<R: AsyncBufRead + Unpin>(
    read: &mut R,
    local: SocketAddr,
    admission: &Session,
    public: bool,
    transaction_bytes: usize,
    session_token: Option<&str>,
) -> Result<HttpRequest> {
    let first = bounded_line(read, 4096).await?;
    ensure!(first.ends_with(b"\r\n"), "invalid HTTP request line");
    let first = std::str::from_utf8(&first)?;
    // Exactly one space separates the three request-line tokens.
    let parts: Vec<_> = first[..first.len() - 2].split(' ').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_graphic()))
            && (parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0"),
        "invalid HTTP request line"
    );
    let method = parts[0].to_owned();
    let path = parts[1].to_owned();
    ensure!(
        path.starts_with('/'),
        "absolute request targets are unsupported"
    );
    let mut headers = HashMap::new();
    let mut size = first.len();
    loop {
        let line = bounded_line(read, 4096).await?;
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
    let _ = write.shutdown().await;
    let _ = timeout(
        Duration::from_secs(1),
        tokio::io::copy(&mut (&mut *read).take(256 * 1024), &mut tokio::io::sink()),
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
    ensure!(body.len() <= limit, "HTTP response too large");
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Opener-Policy: same-origin\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'\r\n\r\n",
        body.len()
    );
    timeout(IO_TIMEOUT, async {
        write.write_all(header.as_bytes()).await?;
        write.write_all(body).await
    })
    .await??;
    Ok(())
}
fn http_error(message: &str) -> Value {
    json!({"error":{"message":message}})
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
            let (message, drain) = match failed {
                Ok(Err(e)) => (e.to_string(), true),
                _ => ("HTTP request timed out".into(), false),
            };
            let status = if message.starts_with("forbidden:") {
                403
            } else if message == "resource not found" {
                404
            } else {
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
            return http_response(&mut write, 200, mime, body).await;
        }
        if request.path == "/api/session" {
            let chain_id = node.read_view()?.chain.chain_id();
            // Loopback is shared by every local account and service, so the
            // session token is never served here. Clients that may use server
            // wallets read it from the owner-only session token file.
            let mut data = if http.public {
                json!({"address_hrp":address::hrp(&chain_id)})
            } else {
                node.wallet_status()?
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
    let disabled_signer = request.path == "/api/wallet" && !node.wallets_locked()?.hot_enabled();
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
        admission.work(1)?;
        let permit = timeout(IO_TIMEOUT, node.rpc_mutations.clone().acquire_owned()).await??;
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let request: ManageRequest = serde_json::from_value(value)?;
            node.wallets_locked()?.manage(request)
        })
        .await
        .context("wallet manager worker failed")?;
        let (status, data) = match result {
            Ok(data) => (200, data),
            Err(e) => (400, http_error(&e.to_string())),
        };
        return http_response(
            &mut write,
            status,
            "application/json",
            &serde_json::to_vec(&data)?,
        )
        .await;
    }
    if request.path == "/api/wallet" {
        admission.work(mempool_limit(&node.read_view()?.chain.config) + 1)?;
        let permit = timeout(IO_TIMEOUT, node.rpc_mutations.clone().acquire_owned()).await??;
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
    let mutation = matches!(
        method.as_str(),
        "mine"
            | "template"
            | "submitblock"
            | "submittransaction"
            | "getblock"
            | "preparetransaction"
            | "broadcasttransaction"
    );
    let mut cost = rpc_cost(&method, &params);

    if matches!(
        method.as_str(),
        "submittransaction" | "template" | "preparetransaction" | "broadcasttransaction"
    ) {
        cost = cost.saturating_add(MAX_ADAPTIVE_MEMPOOL + 1);
    } else if method == "mine" {
        // Reserve individual blocks when their actual queue is known.
        cost = 1;
    }

    admission.work(cost)?;
    let public = http.public;
    let (result, admission) = if value.get("jsonrpc") != Some(&Value::String("2.0".into())) {
        (Err(anyhow!("jsonrpc must be 2.0")), admission)
    } else {
        let slots = if mutation {
            http.mutations.clone()
        } else {
            http.workers.clone()
        };
        let permit = timeout(IO_TIMEOUT, slots.acquire_owned()).await??;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = if public {
                node.public_rpc(&method, params, &admission)
            } else {
                node.rpc_with_admission(&method, params, Some(&admission))
            };
            (result, admission)
        })
        .await
        .context("RPC worker failed")?
    };
    let response = match result {
        Ok(v) => json!({"jsonrpc":"2.0","id":id.clone(),"result":v}),
        Err(e) => {
            json!({"jsonrpc":"2.0","id":id.clone(),"error":{"code":-32000,"message":e.to_string()}})
        }
    };
    let mut body = serde_json::to_vec(&response)?;
    drop(response);
    // A valid record may need more than the fixed service frame once
    // governance raises capacity; the frame then follows that capacity.
    let limit = response_frame_bytes(transaction_bytes)?;
    let refused = if body.len() > limit {
        Some("RPC response exceeds the local response limit")
    } else if public && admission.bytes(body.len()).is_err() {
        // Like peer replies, public responses spend the byte budget.
        Some("network rate budget exhausted")
    } else {
        None
    };
    if let Some(message) = refused {
        body = serde_json::to_vec(
            &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message}}),
        )?;
    }
    http_response_limited(&mut write, 200, "application/json", &body, limit).await
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
    let recipients = [
        "/operation/Propose/proposal/Grant/payments",
        "/body/operation/Propose/proposal/Grant/payments",
        "/transaction/body/operation/Propose/proposal/Grant/payments",
    ]
    .iter()
    .filter_map(|path| params.pointer(path).and_then(Value::as_array))
    .map(Vec::len)
    .max()
    .unwrap_or(0);
    let raw_work = params.get("raw").and_then(Value::as_str).map_or(0, |raw| {
        // A raw grant may carry one key validation per 34 encoded bytes.
        // Ordinary large data pays the same bounded parsing-work allowance.
        raw.len() / (2 * 34)
    });
    base.saturating_add(recipients).saturating_add(raw_work)
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
    fn large_grant_preparation_reserves_work_for_every_recipient() {
        let params = json!({"operation":{"Propose":{"proposal":{"Grant":{"payments":vec![Value::Null; 1000]}}}}});
        assert_eq!(rpc_cost("fee_quote", &params), 1008);
        assert_eq!(
            rpc_cost("broadcasttransaction", &json!({"raw":"00".repeat(34_000)})),
            MAX_MEMPOOL + 1 + 1000
        );
    }

    #[test]
    fn proposal_response_pages_preserve_every_row_at_byte_and_value_boundaries() {
        let recipient = crypto::public_key(&[43; 32]).unwrap();
        let records: Vec<_> = (0..3)
            .map(|round| crate::state::ProposalRecord {
                round,
                description: [44; 32],
                action: Proposal::Grant {
                    payments: vec![GrantPayment {
                        recipient,
                        amount: 1u32.into(),
                    }],
                },
                support: 1u32.into(),
                refund_height: None,
            })
            .collect();
        let first = ProposalPageRow {
            id: hex::encode([0; 32]),
            proposal: &records[0],
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
                for (index, proposal) in records.iter().enumerate().skip(offset) {
                    if !page
                        .push(&ProposalPageRow {
                            id: hex::encode([index as u8; 32]),
                            proposal,
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
            inner.mempool = vec![transaction.clone()];
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
            wallet::decode_signed(full[0]["raw"].as_str().unwrap()).unwrap(),
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
            mempool,
            cache: Arc::default(),
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
    fn record(round: u64, support: u32, action: Proposal) -> ProposalRecord {
        ProposalRecord {
            round,
            description: [0; 32],
            action,
            support: support.into(),
            refund_height: None,
        }
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
            let error =
                Node::read_rpc(&curved_view, "quote", json!({"kind":"deposit","amount":amount}))
                    .unwrap_err();
            assert!(error.to_string().contains("account cash"), "{error}");
        }
        let deposit = json!({"kind":"deposit","amount":"10"});
        assert!(Node::read_rpc(&curved_view, "quote", deposit.clone()).is_ok());
        let error = Node::read_rpc_metered(&curved_view, "quote", deposit.clone(), Some(&drained()))
            .unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
        let stash = json!({"key":hex::encode(key()),"kind":"redeem","amount":"1"});
        let account = json!({"key":hex::encode(key())});
        for (method, params) in [("stash_quote", stash), ("account", account)] {
            assert!(Node::read_rpc(&curved_view, method, params.clone()).is_ok());
            let error = Node::read_rpc_metered(&curved_view, method, params, Some(&drained()))
                .unwrap_err();
            assert!(error.to_string().contains("budget"), "{method}: {error}");
        }
        // A flat curve has no size-dependent search and remains cheap.
        let mut s = s;
        s.world.curve_mass = s.world.reserve.clone();
        let flat_view = view(s, vec![]);
        assert!(Node::read_rpc_metered(&flat_view, "quote", deposit, Some(&drained())).is_ok());
    }

    #[test]
    fn governance_grant_projection_is_charged_and_cached_per_tip() {
        let mut s = curved();
        s.phase = Phase::Governance(Decision {
            id: [5; 32],
            epoch: 1,
            round: 0,
            proposal_id: [6; 32],
            proposal: grant(4096),
            started: 0,
            started_height: 0,
            blocks: 10,
            leading_blocks: 0,
        });
        let view = view(s, vec![]);
        let error = Node::read_rpc_metered(&view, "governance", json!({}), Some(&drained()))
            .unwrap_err();
        assert!(error.to_string().contains("budget"), "{error}");
        let first = Node::read_rpc(&view, "governance", json!({})).unwrap();
        assert_eq!(
            first["phase"]["Governance"]["proposal"]["Grant"]["payments"]
                .as_array()
                .unwrap()
                .len(),
            4096
        );
        assert!(view.cache.governance.get().is_some());
        assert_eq!(Node::read_rpc(&view, "governance", json!({})).unwrap(), first);
        assert_eq!(first["state_root"], hex::encode(view.chain.tip_state().root()));
    }

    #[test]
    fn oversized_grant_rows_are_summarized_instead_of_failing_pages() {
        let mut s = curved();
        // About 35 JSON values per payment: one record exceeds the page budget.
        let large = grant(64_000);
        s.proposals.insert(vec![1; 32], record(0, 5, large.clone()));
        s.proposals.insert(vec![2; 32], record(0, 4, parameter()));
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
            s.proposals
                .insert(vec![id; 32], record(round, support, parameter()));
        }
        s.phase = Phase::Auction(Auction {
            round: 0,
            opened: 0,
            leader: Some([4; 32]),
            lead_since: 0,
            replacement_height: 0,
        });
        let auction = view(s.clone(), vec![]);
        let round = Node::read_rpc(&auction, "proposals", json!({"round":0})).unwrap();
        assert_eq!(ids(&round), hex_ids(&[4, 2, 3, 1]));
        let page = Node::read_rpc(&auction, "proposals", json!({"round":0,"offset":1,"limit":2}))
            .unwrap();
        assert_eq!(ids(&page), hex_ids(&[2, 3]));
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
            s.proposals.insert(vec![id; 32], record(round, 5, parameter()));
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
        assert_eq!(account["pending_nonce"], 2);
        assert_eq!(response_frame_bytes(16 * 1024).unwrap(), MAX_RESPONSE_FRAME);
        let governed = 200 * 1024 * 1024;
        assert!(response_frame_bytes(governed).unwrap() > 2 * governed);
        assert_eq!(
            response_frame_bytes(usize::MAX).unwrap(),
            isize::MAX as usize
        );
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
        assert_eq!((valid.method.as_str(), valid.body.as_slice()), ("POST", &b"{}"[..]));
        for length in ["+2", " 2,2", "0x2", "-0", ""] {
            let raw = post("/rpc", &format!("Content-Length: {length}\r\n"), "{}");
            assert!(parse(&raw, None).await.is_err(), "{length:?}");
        }
        for line in ["POST  /rpc HTTP/1.1", "POST\t/rpc HTTP/1.1", "POST /rpc HTTP/1.1 "] {
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

pub async fn call_rpc(url: &str, method: &str, params: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    let mut response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response.content_length().unwrap_or(0) <= MAX_RESPONSE_FRAME as u64,
        "RPC response too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE_FRAME,
            "RPC response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let v: Value = serde_json::from_slice(&bytes)?;
    if let Some(error) = v.get("error") {
        bail!("RPC error: {error}");
    }
    v.get("result").cloned().context("missing RPC result")
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
async fn new_job<W: AsyncWrite + Unpin>(
    node: &Node,
    write: &mut W,
    jobs: &mut HashMap<String, Arc<StratumJob>>,
    counter: &mut u64,
    difficulty: f64,
    seen: &mut HashMap<Hash, Hash>,
    worker_id: u32,
) -> Result<(Hash, Hash)> {
    let block = template_async(node).await?;
    let parent_changed = jobs
        .iter()
        .max_by_key(|(id, _)| *id)
        .is_some_and(|(_, old)| old.block.header.previous != block.header.previous);
    let clean = parent_changed || jobs.is_empty() || jobs.len() >= 8;
    if parent_changed {
        seen.clear();
    }
    if clean {
        jobs.clear();
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
    if let Ok(mut stats) = node.mining.lock()
        && let Some(worker) = stats.workers.get_mut(&worker_id)
    {
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
async fn template_async(node: &Node) -> Result<Arc<Block>> {
    let permit = timeout(IO_TIMEOUT, node.stratum_workers.clone().acquire_owned()).await??;
    let node = node.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        node.template_shared()
    })
    .await
    .context("mining template worker failed")?
}
fn stratum_session_expired(authorized: bool, connected: Duration) -> bool {
    !authorized && connected >= Duration::from_secs(30)
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
) -> Result<()> {
    let admission = Arc::new(admission);
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut subscribed = false;
    let mut authorized = false;
    let mut worker = String::new();
    let mut registration: Option<MiningConnection> = None;
    let mut version_rolling = false;
    let mut rolling_requested = false;
    let mut mask = 0u32;
    let mut difficulty = floor;
    let mut minimum_difficulty = floor;
    let mut jobs: HashMap<String, Arc<StratumJob>> = HashMap::new();
    let mut seen = HashMap::<Hash, Hash>::new();
    let mut counter = 0;
    let mut fingerprint = None;
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
                admission.request()?;
                admission.bytes(line.len())?;
                let request = match parse_value_async(&node,line,Surface::Stratum,JsonBody::Ordinary).await { Ok(v) => v, Err(e) => { admission.malformed(); return Err(e); } };
                ensure!(!stratum_session_expired(authorized,connected.elapsed()), "mining authorization timed out");
                partial_since = None;
                let id = request.get("id").cloned().unwrap_or(Value::Null);
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let params = request.get("params").and_then(Value::as_array).cloned().unwrap_or_default();
                let mut submission = None;
                let mut refresh = false;
                let mut result: Result<Value> = (|| {
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
                                    }
                                    reply.insert(ext.into(),json!(compatible));
                                } else { reply.insert(ext.into(),json!(ext == "subscribe-extranonce")); }
                            }
                            mask = next_mask; version_rolling = next_rolling;
                            refresh = next_difficulty != difficulty;
                            difficulty = next_difficulty;
                            minimum_difficulty = next_minimum;
                            Ok(Value::Object(reply))
                        }
                        "mining.subscribe" => {
                            subscribed = true;
                            Ok(json!([[["mining.set_difficulty",hex::encode(extra)],["mining.notify",hex::encode(extra)]],hex::encode(extra),4]))
                        }
                        "mining.authorize" => {
                            ensure!(subscribed, "subscribe first");
                            ensure!(!authorized,"worker already authorized");
                            let name = params.first().and_then(Value::as_str).context("worker name required")?;
                            ensure!(!name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control), "invalid worker name");
                            authorized = password.as_ref().is_none_or(|p|params.get(1).and_then(Value::as_str)==Some(p.as_str()));
                            if authorized {
                                worker = name.to_owned();
                                let identity = u32::from_le_bytes(extra);
                                let mut runtime = node.mining.lock().map_err(|_|anyhow!("mining statistics lock poisoned"))?;
                                ensure!(runtime.workers.len() < MAX_CONNECTIONS, "mining worker capacity reached");
                                runtime.workers.insert(identity,MiningWorker {worker:worker.clone(),accepted:0,rejected:0,blocks:0,difficulty,last_share:None});
                                registration = Some(MiningConnection {runtime:node.mining.clone(),id:identity});
                                refresh = true;
                            }
                            Ok(json!(authorized))
                        }
                        "mining.extranonce.subscribe" => Ok(json!(true)),
                        "mining.suggest_difficulty" => {
                            let suggested = params.first().and_then(Value::as_f64).context("difficulty required")?;
                            let next = suggested_stratum_difficulty(floor,minimum_difficulty,suggested)?;
                            refresh = next != difficulty;
                            difficulty = next;
                            Ok(json!(true))
                        }
                        "mining.submit" => {
                            ensure!(authorized && subscribed,"unauthorized");
                            ensure!(matches!(params.len(),5|6),"invalid submit arguments");
                            ensure!(params[0].as_str()==Some(worker.as_str()),"worker mismatch");
                            let id = params[1].as_str().context("job id required")?;
                            let job = jobs.get(id).ok_or_else(||mining_error(21,"unknown or stale job"))?.clone();
                            if !node.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                            let version = stratum_submit_version(job.block.header.version,&params,rolling_requested,version_rolling.then_some(mask))?;
                            let extra2: [u8;4] = hex::decode(params[2].as_str().context("extranonce2 required")?)?.try_into().map_err(|_|anyhow!("extranonce2 must be four bytes"))?;
                            let timestamp = hex_u32(&params[3])?;
                            let nonce = hex_u32(&params[4])?;
                            admission.work(1)?;
                            submission = Some((job,extra2,timestamp,nonce,version));
                            Ok(json!(true))
                        }
                        _ => bail!("unsupported mining method"),
                    }
                })();
                if let Some((job,extra2,timestamp,nonce,version)) = submission {
                    let permit = timeout(IO_TIMEOUT,node.stratum_workers.clone().acquire_owned()).await??;
                    let source = job.clone();
                    let (header,hash) = tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let header = source.candidate(extra,extra2,timestamp,nonce,version);
                        let hash = crypto::sha256d(&codec::header_bytes(&header));
                        (header,hash)
                    }).await.context("mining proof worker failed")?;
                    let candidate = (|| -> Result<(Option<Amount>,bool)> {
                        if seen.contains_key(&hash) { return Err(mining_error(22,"duplicate share")); }
                        let view = node.read_view()?;
                        if !node.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                        ensure!(timestamp >= job.block.header.timestamp,"timestamp predates job minimum");
                        ensure!(timestamp as u64 <= now().saturating_add(view.chain.config.future_seconds as u64),"timestamp too far in future");
                        let proof = Amount::from_bytes_le(&hash);
                        let is_block = proof <= job.block_target;
                        let is_share = proof <= job.share_target;
                        if !is_block && !is_share { return Err(mining_error(23,"low difficulty share")); }
                        // Only one sampling threshold contributes to hashrate.
                        // Valid network-only blocks are counted but add no rate sample.
                        Ok((is_share.then(||math::work(&job.share_target)),is_block))
                    })();
                    result = match candidate {
                        Err(error) => Err(error),
                        Ok((work,is_block)) => {
                            let submitted_parent = job.block.header.previous;
                            let accepted = if is_block {
                                admission.work(job.block.transactions.len())?;
                                let permit = timeout(IO_TIMEOUT,node.stratum_workers.clone().acquire_owned()).await??;
                                let validator = node.clone();
                                tokio::task::spawn_blocking(move || -> Result<()> {
                                    let _permit = permit;
                                    if !validator.mining_job_eligible(&job.block)? { return Err(mining_error(21,"stale job")); }
                                    let mut block = job.block.as_ref().clone();
                                    block.header = header;
                                    block.extranonce[..4].copy_from_slice(&extra);
                                    block.extranonce[4..].copy_from_slice(&extra2);
                                    validator.submit_block(block)?;
                                    Ok(())
                                }).await.context("mining block worker failed")?
                            } else { Ok(()) };
                            accepted.map(|()| {
                                seen.insert(hash, submitted_parent);
                                if let Ok(mut stats) = node.mining.lock() { stats.submission(registration.as_ref().map(|r|r.id),Some((work.as_ref(),is_block))); }
                                refresh |= is_block;
                                json!(true)
                            })
                        }
                    };
                }
                let successful = result.is_ok();
                if method=="mining.submit" && !successful && let Ok(mut stats)=node.mining.lock() { stats.submission(registration.as_ref().map(|r|r.id),None); }
                let denied = method=="mining.authorize" && !authorized;
                let response = match result {
                    Ok(v) => json!({"id":id,"result":v,"error":null}),
                    Err(e) => { let code=e.downcast_ref::<StratumError>().map_or(20,|error|error.0); json!({"id":id,"result":null,"error":[code,e.to_string(),null]}) }
                };
                write_json(&mut write,&response).await?;
                if denied { admission.malformed(); bail!("mining authorization denied"); }
                // Never evict duplicate evidence while the parent remains valid.
                // A fresh connection gets a different extranonce and new work.
                ensure!(seen.len()<MAX_SUBMITTED_HEADERS,"share history capacity reached; reconnect");
                if successful && authorized && refresh {
                    fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra)).await?);
                    last_job=tokio::time::Instant::now();
                }
            }
            changed = updates.changed() => {
                changed.context("mining update channel closed")?;
                if authorized {
                    let block=template_async(&node).await?;
                    if fingerprint!=Some((block.header.previous,block.header.merkle_root)) {
                        fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra)).await?);
                        last_job=tokio::time::Instant::now();
                    }
                }
            }
            _ = tick.tick() => {
                ensure!(!stratum_session_expired(authorized,connected.elapsed()),"mining authorization timed out");
                if !partial_line.is_empty() { let began=partial_since.get_or_insert_with(tokio::time::Instant::now); ensure!(began.elapsed()<IO_TIMEOUT,"mining partial frame timed out"); }
                if authorized && last_job.elapsed()>=Duration::from_secs(30) {
                    fingerprint=Some(new_job(&node,&mut write,&mut jobs,&mut counter,difficulty,&mut seen,u32::from_le_bytes(extra)).await?);
                    last_job=tokio::time::Instant::now();
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
                json!({"recipient":hex::encode(recipient),"amount":"5","extra_fee":"3"}),
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
        let tx = crypto::sign(&body, &secret).unwrap();
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
                json!({"recipient":hex::encode(recipient),"amount":"5"}),
            )
            .unwrap();
        assert_eq!(quote["account_creation_fee"], "0");
        assert_eq!(quote["fee"], "1");
        assert_eq!(quote["minimum_fee"], "1");
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
        stats.workers.insert(
            7,
            MiningWorker {
                worker: "fixture".into(),
                accepted: 0,
                rejected: 0,
                blocks: 0,
                difficulty: 65536.0,
                last_share: None,
            },
        );
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
        });
        s.world.validate(&c, &s.issued, &s.auction_escrow).unwrap();
        (
            ReadView {
                chain: PublishedChain {
                    config: Arc::new(c),
                    tip: [7; 32],
                    state: Arc::new(s),
                },
                mempool: vec![],
                cache: Arc::default(),
            },
            key,
        )
    }
    fn stash_test_apply(view: &ReadView, operation: Operation) -> State {
        let mut s = view.chain.tip_state().clone();
        let sender = crypto::public_key(&[1; 32]).unwrap();
        let transaction = crypto::sign(
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
        assert_eq!(original.as_object().unwrap().len(), 10);
        assert_eq!(original["proposals_total"], 0);
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
            },
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
            },
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
            },
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
        s.world.accounts = crate::tree::Map::new();
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
    #[test]
    fn canonical_rpc_amounts() {
        assert!(parse_amount("01").is_err());
        assert!(parse_amount("-1").is_err());
        assert_eq!(parse_amount("123").unwrap(), 123u32.into());
    }
    #[test]
    fn authorized_solo_workers_need_not_find_a_block_to_stay_connected() {
        assert!(!stratum_session_expired(
            true,
            Duration::from_secs(24 * 60 * 60)
        ));
        assert!(stratum_session_expired(false, Duration::from_secs(30)));
        assert!(!stratum_session_expired(false, Duration::from_secs(29)));
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
        let limits = peer_wire::Limits::from_config(&config);
        let wire = peer_wire::encode(&PeerPacket::Sync(message.clone()), limits).unwrap();
        assert_eq!(
            peer_wire::decode(&wire, limits).unwrap(),
            PeerPacket::Sync(message)
        );
    }
}
