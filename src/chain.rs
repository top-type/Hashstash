use crate::{codec, config::Config, consensus, crypto, fees, math, state::State, types::*};
use anyhow::{Context, Result, ensure};
use num_traits::Zero;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub const MAX_CACHED_STATES: usize = 128;
pub const MAX_CACHED_INVALID_BLOCKS: usize = 128;
/// Local metadata cache only. Eviction never discards accepted history or limits reorg depth.
pub const MAX_CACHED_ENTRIES: usize = 256;
const INVALID_BLOCK_TTL: Duration = Duration::from_secs(60);
#[derive(Debug)]
struct PermanentBlockError(String);
impl std::fmt::Display for PermanentBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for PermanentBlockError {}
#[derive(Debug)]
struct LocalIndexError(anyhow::Error);
impl std::fmt::Display for LocalIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "local history index: {}", self.0)
    }
}
impl std::error::Error for LocalIndexError {}
/// Local validation paused after a bounded amount of cached-state replay.
/// Retrying the same block resumes from retained progress; it is not invalid.
#[derive(Debug)]
pub struct ValidationDeferred;
impl std::fmt::Display for ValidationDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "state replay deferred; retry validation")
    }
}
impl std::error::Error for ValidationDeferred {}

fn permanent(error: anyhow::Error) -> anyhow::Error {
    // Metadata now comes from SQLite too; a local I/O/index problem must never
    // poison the cache of invalid remote blocks.
    if error.is::<LocalIndexError>() || error.is::<rusqlite::Error>() {
        error
    } else {
        PermanentBlockError(error.to_string()).into()
    }
}

/// Local transaction-selection policy; these are not consensus block limits.
pub const MAX_SELECTION_CANDIDATES: usize = 8192;
pub const SELECTION_ATTEMPTS_PER_CANDIDATE: usize = 4;
#[derive(Debug)]
pub struct SelectionResult {
    pub transactions: Vec<Transaction>,
    pub signatures_checked: usize,
    pub execution_attempts: usize,
    pub budget_exhausted: bool,
}
fn compact_size_len(n: usize) -> usize {
    match n {
        0..=252 => 1,
        253..=65535 => 3,
        65536..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Entry {
    header: Header,
    height: u64,
    // Expected elapsed seconds for timestamp ASERT, independent of economic progress.
    clock: u64,
    // The first mined block anchors its own branch. These derived fields are
    // rebuilt from validated headers, so pre-mining idle time is not DAA debt.
    anchor_timestamp: u32,
    anchor_clock: u64,
    work: Amount,
}
#[derive(Default)]
struct StateCache {
    states: BTreeMap<Hash, Arc<State>>,
    order: VecDeque<Hash>,
}
#[derive(Default)]
struct EntryCache {
    entries: BTreeMap<Hash, Arc<Entry>>,
    order: VecDeque<Hash>,
}
pub struct Chain {
    pub config: Config,
    db: Connection,
    entries: RefCell<EntryCache>,
    tip_entry: Arc<Entry>,
    tip: Hash,
    genesis: Block,
    tip_block: Block,
    tip_state: Arc<State>,
    cache: RefCell<StateCache>,
    invalid_blocks: BTreeMap<Hash, String>,
    invalid_order: VecDeque<(Hash, Instant)>,
    replay_budget: Cell<Option<usize>>,
    known_block_bytes: Cell<u64>,
}
impl Chain {
    pub fn open(path: &Path, config: Config) -> Result<Self> {
        config.validate()?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(2))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS blocks(seq INTEGER PRIMARY KEY AUTOINCREMENT, hash BLOB NOT NULL UNIQUE, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL);")?;
        // Derived indexes are rebuilt from independently validated block bodies on every open.
        // SQLite bounds its page cache; canonical and losing-branch metadata stay on disk.
        db.execute_batch("PRAGMA cache_size=-8192; PRAGMA temp_store=FILE; CREATE TABLE IF NOT EXISTS entry_index(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS canonical_index(height INTEGER PRIMARY KEY, hash BLOB NOT NULL); CREATE TEMP TABLE IF NOT EXISTS state_replay_path(position INTEGER PRIMARY KEY, hash BLOB NOT NULL);")?;
        let saved: Option<Vec<u8>> = db
            .query_row("SELECT value FROM metadata WHERE key='config'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let encoded = config.consensus_bytes();
        if let Some(saved) = saved {
            ensure!(
                saved == encoded,
                "database belongs to a different network configuration"
            );
        } else {
            db.execute(
                "INSERT INTO metadata(key,value) VALUES('config',?1)",
                [&encoded],
            )?;
        }
        let state = State::genesis(&config);
        state.validate(&config)?;
        let genesis = codec::genesis_block(&config)?;
        let genesis_hash = codec::block_hash(&genesis);
        let genesis_entry = Arc::new(Entry {
            header: genesis.header.clone(),
            height: 0,
            clock: 0,
            anchor_timestamp: config.genesis_time,
            anchor_clock: 0,
            work: Amount::zero(),
        });
        db.execute_batch("BEGIN IMMEDIATE; DELETE FROM entry_index; DELETE FROM canonical_index;")?;
        db.execute(
            "INSERT INTO entry_index(hash,bytes) VALUES(?1,?2)",
            params![
                genesis_hash.as_slice(),
                codec::encode(genesis_entry.as_ref())
            ],
        )?;
        db.execute(
            "INSERT INTO canonical_index(height,hash) VALUES(0,?1)",
            [genesis_hash.as_slice()],
        )?;
        let state = Arc::new(state);
        let mut chain = Self {
            config,
            db,
            entries: RefCell::new(EntryCache::default()),
            tip_entry: genesis_entry.clone(),
            tip: genesis_hash,
            genesis: genesis.clone(),
            tip_block: genesis,
            tip_state: state.clone(),
            cache: RefCell::new(StateCache::default()),
            invalid_blocks: BTreeMap::new(),
            invalid_order: VecDeque::new(),
            replay_budget: Cell::new(None),
            known_block_bytes: Cell::new(state.settings.block_bytes),
        };
        chain.cache_entry(genesis_hash, genesis_entry);
        chain.cache_state(genesis_hash, state);
        // Replay one bounded record at a time instead of buffering the entire database.
        let mut sequence = 0i64;
        loop {
            let row: Option<(i64, Vec<u8>, Vec<u8>, u64)> = chain.db.query_row(
                "SELECT seq,hash,bytes,accepted_at FROM blocks WHERE seq>?1 ORDER BY seq LIMIT 1",
                [sequence], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional()?;
            let Some((seq, raw_hash, bytes, accepted_at)) = row else {
                break;
            };
            sequence = seq;
            let block: Block = codec::decode_block(&bytes, bytes.len())?;
            let hash = codec::block_hash(&block);
            ensure!(raw_hash == hash, "stored block hash mismatch");
            let (entry, state) = chain
                .validate_block(&block, accepted_at)
                .context("invalid stored history")?;
            let best = entry.work > chain.tip_entry.work;
            chain.db.execute(
                "INSERT INTO entry_index(hash,bytes) VALUES(?1,?2)",
                params![hash.as_slice(), codec::encode(&entry)],
            )?;
            let entry = Arc::new(entry);
            chain.cache_entry(hash, entry.clone());
            chain.cache_state(hash, state.clone());
            if best {
                Self::write_canonical(&chain.db, hash, entry.height)?;
                chain.select_tip(hash, block, state, entry);
            }
        }
        let saved_tip: Option<Vec<u8>> = chain
            .db
            .query_row("SELECT value FROM metadata WHERE key='tip'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(raw) = saved_tip {
            let hash: Hash = raw.as_slice().try_into().context("invalid persisted tip")?;
            let entry = chain.load_entry(&hash)?.context("persisted tip absent")?;
            ensure!(
                entry.work == chain.tip_entry.work,
                "persisted tip has less work"
            );
            let block = chain
                .load_block(&hash)?
                .context("persisted tip block absent")?;
            let state = chain.load_state(&hash)?;
            Self::write_canonical(&chain.db, hash, entry.height)?;
            chain.select_tip(hash, block, state, entry);
        }
        chain.db.execute_batch("COMMIT")?;
        Ok(chain)
    }
    pub fn chain_id(&self) -> Hash {
        self.config.chain_id()
    }
    pub fn tip_hash(&self) -> Hash {
        self.tip
    }
    pub fn tip_height(&self) -> u64 {
        self.tip_block.height
    }
    pub fn tip_state(&self) -> &State {
        &self.tip_state
    }
    pub fn tip_block(&self) -> &Block {
        &self.tip_block
    }
    pub fn block(&self, hash: &Hash) -> Option<Block> {
        self.load_block(hash).ok().flatten()
    }
    /// Height of a locally validated block, including genesis and side branches.
    pub fn block_height(&self, hash: &Hash) -> Result<Option<u64>> {
        Ok(self.load_entry(hash)?.map(|entry| entry.height))
    }

    /// Check the signed preparation reference against the next block on this
    /// tip, returning its fixed, derived expiry height. Membership in this
    /// genesis-descended branch also establishes the transaction's network.
    pub fn validate_transaction_anchor(&self, transaction: &Transaction) -> Result<u64> {
        self.transaction_anchor_results(&self.tip, &[transaction])?
            .pop()
            .unwrap()
            .map_err(anyhow::Error::msg)
    }

    fn transaction_anchor_results(
        &self,
        parent: &Hash,
        transactions: &[&Transaction],
    ) -> Result<Vec<std::result::Result<u64, String>>> {
        let parent_entry = self
            .load_entry(parent)?
            .ok_or_else(|| LocalIndexError(anyhow::anyhow!("candidate parent absent")))?;
        let height = parent_entry
            .height
            .checked_add(1)
            .context("candidate height overflow")?;
        let genesis = codec::block_hash(&self.genesis);
        let mut required = BTreeMap::<u64, BTreeSet<Hash>>::new();
        let mut ancestors = BTreeSet::new();
        let mut results = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let body = &tx.body;
            let result = if body.expiry_blocks == 0 {
                Err("transaction lifetime must be positive".into())
            } else if let Some(anchor) = self.load_entry(&body.anchor)? {
                if anchor.height >= height {
                    Err("transaction anchor must precede its including block".into())
                } else if let Some(expiry) = anchor.height.checked_add(body.expiry_blocks) {
                    if height > expiry {
                        Err("transaction expired relative to its signed anchor".into())
                    } else {
                        if body.anchor == genesis {
                            ancestors.insert(genesis);
                        } else {
                            required
                                .entry(anchor.height)
                                .or_default()
                                .insert(body.anchor);
                        }
                        Ok(expiry)
                    }
                } else {
                    Err("transaction lifetime overflows its anchor height".into())
                }
            } else {
                Err("unknown transaction anchor".into())
            };
            results.push(result);
        }
        // Canonical references use indexed height lookups. A side branch is
        // walked only to its common canonical ancestor, once for all references.
        // Memory depends on this block's references, never on chain age.
        let mut cursor = *parent;
        let mut entry = parent_entry;
        while !required.is_empty() {
            if self.canonical_hash(entry.height)? == Some(cursor) {
                for (height, requested) in &required {
                    if let Some(hash) = self.canonical_hash(*height)?
                        && requested.contains(&hash)
                    {
                        ancestors.insert(hash);
                    }
                }
                break;
            }
            if let Some(requested) = required.remove(&entry.height)
                && requested.contains(&cursor)
            {
                ancestors.insert(cursor);
            }
            if required.is_empty() || entry.height == 0 {
                break;
            }
            cursor = entry.header.previous;
            entry = self
                .load_entry(&cursor)?
                .ok_or_else(|| LocalIndexError(anyhow::anyhow!("candidate ancestor absent")))?;
        }
        for (tx, result) in transactions.iter().zip(&mut results) {
            if result.is_ok() && !ancestors.contains(&tx.body.anchor) {
                *result = Err("transaction anchor is not on the candidate parent branch".into());
            }
        }
        Ok(results)
    }

    fn validate_transaction_anchors(
        &self,
        parent: &Hash,
        transactions: &[Transaction],
    ) -> Result<()> {
        let refs: Vec<_> = transactions.iter().collect();
        for result in self.transaction_anchor_results(parent, &refs)? {
            result.map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }
    pub fn state_at(&self, hash: &Hash) -> Option<Arc<State>> {
        self.load_state(hash).ok()
    }
    /// A state this chain already retains; unlike state_at, never replays history.
    pub fn cached_state(&self, hash: &Hash) -> Option<Arc<State>> {
        if *hash == self.tip {
            return Some(self.tip_state.clone());
        }
        self.cache.borrow().states.get(hash).cloned()
    }
    pub fn cached_state_count(&self) -> usize {
        self.cache.borrow().states.len()
    }
    pub fn cached_entry_count(&self) -> usize {
        self.entries.borrow().entries.len()
    }
    fn cache_entry(&self, hash: Hash, entry: Arc<Entry>) {
        let mut cache = self.entries.borrow_mut();
        if cache.entries.contains_key(&hash) {
            return;
        }
        while cache.entries.len() >= MAX_CACHED_ENTRIES {
            if let Some(old) = cache.order.pop_front() {
                cache.entries.remove(&old);
            }
        }
        cache.entries.insert(hash, entry);
        cache.order.push_back(hash);
    }
    fn read_entry(db: &Connection, hash: &Hash) -> Result<Option<Arc<Entry>>> {
        (|| -> Result<_> {
            let bytes: Option<Vec<u8>> = db
                .query_row(
                    "SELECT bytes FROM entry_index WHERE hash=?1",
                    [hash.as_slice()],
                    |r| r.get(0),
                )
                .optional()?;
            bytes
                .map(|bytes| codec::decode::<Entry>(&bytes, 4096).map(Arc::new))
                .transpose()
        })()
        .map_err(|e| LocalIndexError(e).into())
    }
    fn load_entry(&self, hash: &Hash) -> Result<Option<Arc<Entry>>> {
        if *hash == self.tip {
            return Ok(Some(self.tip_entry.clone()));
        }
        if let Some(entry) = self.entries.borrow().entries.get(hash) {
            return Ok(Some(entry.clone()));
        }
        let entry = Self::read_entry(&self.db, hash)?;
        if let Some(entry) = &entry {
            self.cache_entry(*hash, entry.clone());
        }
        Ok(entry)
    }
    /// Walk a branch using disk metadata. No in-memory vector grows with reorg depth.
    fn write_canonical(db: &Connection, hash: Hash, height: u64) -> Result<()> {
        db.execute("DELETE FROM canonical_index WHERE height>?1", [height])?;
        let mut cursor = hash;
        loop {
            let entry = Self::read_entry(db, &cursor)?.context("canonical entry absent")?;
            let active: Option<Vec<u8>> = db
                .query_row(
                    "SELECT hash FROM canonical_index WHERE height=?1",
                    [entry.height],
                    |r| r.get(0),
                )
                .optional()?;
            if active.as_deref() == Some(cursor.as_slice()) {
                break;
            }
            db.execute("INSERT INTO canonical_index(height,hash) VALUES(?1,?2) ON CONFLICT(height) DO UPDATE SET hash=excluded.hash", params![entry.height, cursor.as_slice()])?;
            ensure!(entry.height > 0, "canonical genesis mismatch");
            cursor = entry.header.previous;
        }
        Ok(())
    }
    pub fn cached_invalid_count(&self) -> usize {
        self.invalid_blocks.len()
    }
    fn expire_invalid(&mut self) {
        while self
            .invalid_order
            .front()
            .is_some_and(|(_, time)| time.elapsed() >= INVALID_BLOCK_TTL)
        {
            let (hash, _) = self.invalid_order.pop_front().unwrap();
            self.invalid_blocks.remove(&hash);
        }
    }
    fn remember_invalid(&mut self, identity: Hash, error: &anyhow::Error) {
        while self.invalid_blocks.len() >= MAX_CACHED_INVALID_BLOCKS {
            if let Some((hash, _)) = self.invalid_order.pop_front() {
                self.invalid_blocks.remove(&hash);
            }
        }
        self.invalid_blocks
            .insert(identity, error.to_string().chars().take(256).collect());
        self.invalid_order.push_back((identity, Instant::now()));
    }
    fn load_block(&self, hash: &Hash) -> Result<Option<Block>> {
        if *hash == codec::block_hash(&self.genesis) {
            return Ok(Some(self.genesis.clone()));
        }
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT bytes FROM blocks WHERE hash=?1",
                [hash.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        bytes.map(|b| codec::decode_block(&b, b.len())).transpose()
    }
    pub fn max_known_block_bytes(&self) -> u64 {
        self.known_block_bytes.get()
    }
    fn cache_state(&self, hash: Hash, state: Arc<State>) {
        self.known_block_bytes
            .set(self.known_block_bytes.get().max(state.settings.block_bytes));
        let mut cache = self.cache.borrow_mut();
        if cache.states.contains_key(&hash) {
            return;
        }
        while cache.states.len() >= MAX_CACHED_STATES {
            if let Some(old) = cache.order.pop_front() {
                cache.states.remove(&old);
            }
        }
        cache.states.insert(hash, state);
        cache.order.push_back(hash);
    }
    fn load_state(&self, hash: &Hash) -> Result<Arc<State>> {
        if *hash == self.tip {
            return Ok(self.tip_state.clone());
        }
        let mut cursor = *hash;
        self.db.execute("DELETE FROM state_replay_path", [])?;
        let mut path_length = 0u64;
        let mut state = loop {
            if cursor == self.tip {
                break self.tip_state.clone();
            }
            if let Some(state) = self.cache.borrow().states.get(&cursor) {
                break state.clone();
            }
            let entry = self.load_entry(&cursor)?.context("unknown state")?;
            if entry.height == 0 {
                break Arc::new(State::genesis(&self.config));
            }
            self.db.execute(
                "INSERT INTO state_replay_path(position,hash) VALUES(?1,?2)",
                params![path_length, cursor.as_slice()],
            )?;
            path_length += 1;
            cursor = entry.header.previous;
        };
        while path_length > 0 {
            if let Some(remaining) = self.replay_budget.get() {
                if remaining == 0 {
                    return Err(ValidationDeferred.into());
                }
                self.replay_budget.set(Some(remaining - 1));
            }
            path_length -= 1;
            let next: Vec<u8> = self.db.query_row(
                "SELECT hash FROM state_replay_path WHERE position=?1",
                [path_length],
                |r| r.get(0),
            )?;
            let next: Hash = next.as_slice().try_into().context("invalid replay index")?;
            let block = self
                .load_block(&next)?
                .context("stored ancestor block absent")?;
            let subsidy = math::work(&math::target_from_bits(block.header.bits)?);
            self.validate_transaction_anchors(&block.header.previous, &block.transactions)?;
            let replayed = consensus::execute(
                &self.config,
                &state,
                &block.header.previous,
                &block.miner,
                &subsidy,
                &block.transactions,
            )?;
            ensure!(
                replayed.root() == block.state_root,
                "replayed state commitment mismatch"
            );
            state = Arc::new(replayed);
            self.cache_state(next, state.clone());
        }
        Ok(state)
    }
    fn select_tip(&mut self, hash: Hash, block: Block, state: Arc<State>, entry: Arc<Entry>) {
        self.tip = hash;
        self.tip_block = block;
        self.tip_state = state;
        self.tip_entry = entry;
    }
    pub fn chain_work(&self) -> &Amount {
        &self.tip_entry.work
    }
    /// Required target for a child without executing a block template.
    pub fn next_target(&self) -> Result<Amount> {
        self.target(&self.tip_entry)
    }
    pub fn expected_elapsed_seconds(&self) -> u64 {
        self.tip_entry.clock
    }
    fn canonical_hash(&self, height: u64) -> Result<Option<Hash>> {
        (|| -> Result<_> {
            let raw: Option<Vec<u8>> = self
                .db
                .query_row(
                    "SELECT hash FROM canonical_index WHERE height=?1",
                    [height],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(raw) = raw {
                Ok(Some(
                    raw.as_slice()
                        .try_into()
                        .context("malformed canonical hash")?,
                ))
            } else {
                ensure!(height > self.tip_height(), "canonical height absent");
                Ok(None)
            }
        })()
        .map_err(|error| LocalIndexError(error).into())
    }
    pub fn hash_at_height(&self, height: u64) -> Option<Hash> {
        self.canonical_hash(height).ok().flatten()
    }
    fn median(&self, parent: Hash) -> Result<u32> {
        let mut times = Vec::new();
        let mut hash = parent;
        for _ in 0..self.config.timestamp_window {
            let e = self.load_entry(&hash)?.context("median ancestor absent")?;
            times.push(e.header.timestamp);
            if e.height == 0 {
                break;
            }
            hash = e.header.previous;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }
    fn target(&self, parent: &Entry) -> Result<Amount> {
        let initial = math::target_from_bits(self.config.initial_bits)?;
        if parent.height == 0 {
            return Ok(initial);
        }
        let error = parent.header.timestamp as i128
            - parent.anchor_timestamp as i128
            - (parent.clock as i128 - parent.anchor_clock as i128);
        Ok(math::asert(
            &initial,
            error,
            self.config.daa_half_life,
            &math::target_from_bits(self.config.limit_bits)?,
        ))
    }
    fn validate_block(&self, block: &Block, now: u64) -> Result<(Entry, Arc<State>)> {
        let parent = self
            .load_entry(&block.header.previous)?
            .context("unknown parent")?;
        ensure!(
            block.header.timestamp as u64 <= now.saturating_add(self.config.future_seconds as u64),
            "block timestamp too far in future; defer until eligible"
        );
        let target = (|| -> Result<Amount> {
            ensure!(
                block.height == parent.height + 1 && block.height <= self.config.max_height,
                "invalid block height"
            );
            ensure!(
                codec::is_current_header(&block.header),
                "unsupported header version bits"
            );
            ensure!(
                block.transactions.len() <= self.config.max_signatures,
                "signature limit exceeded"
            );
            ensure!(
                block.header.timestamp > self.median(block.header.previous)?,
                "timestamp must exceed median past time"
            );
            let target = self.target(&parent)?;
            ensure!(
                block.header.bits == math::bits_from_target(&target),
                "incorrect difficulty target"
            );
            math::check_pow(&block.header, &target)?;
            ensure!(
                block.header.merkle_root == codec::merkle_root(block)?,
                "incorrect transaction Merkle root"
            );
            self.validate_transaction_anchors(&block.header.previous, &block.transactions)?;
            Ok(target)
        })()
        .map_err(permanent)?;
        let parent_state = self.load_state(&block.header.previous)?;
        // Disk/reconstruction failures above are transient local failures and are
        // never entered into the cache of permanently invalid block messages.
        (|| -> Result<(Entry, Arc<State>)> {
            ensure!(
                codec::body_size(block)? as u64 <= parent_state.settings.block_bytes,
                "block body exceeds byte limit"
            );
            let work = math::work(&target);
            let state = consensus::execute(
                &self.config,
                &parent_state,
                &block.header.previous,
                &block.miner,
                &work,
                &block.transactions,
            )?;
            ensure!(
                state.root() == block.state_root,
                "incorrect post-state commitment"
            );
            let clock = parent
                .clock
                .checked_add(parent_state.settings.interval)
                .context("expected timestamp schedule overflow")?;
            let (anchor_timestamp, anchor_clock) = if parent.height == 0 {
                (block.header.timestamp, clock)
            } else {
                (parent.anchor_timestamp, parent.anchor_clock)
            };
            Ok((
                Entry {
                    header: block.header.clone(),
                    height: block.height,
                    clock,
                    anchor_timestamp,
                    anchor_clock,
                    work: &parent.work + work,
                },
                Arc::new(state),
            ))
        })()
        .map_err(permanent)
    }

    /// Budget only reconstruction of already validated historical states.
    /// No bound is added to consensus reorg depth. A caller retries deferred work.
    pub fn submit_with_replay_budget(
        &mut self,
        block: Block,
        now: u64,
        steps: usize,
    ) -> Result<bool> {
        ensure!(steps > 0, "replay budget must be positive");
        self.replay_budget.set(Some(steps));
        let result = self.submit(block, now);
        self.replay_budget.set(None);
        result
    }
    pub fn submit(&mut self, block: Block, now: u64) -> Result<bool> {
        let hash = codec::block_hash(&block);
        if self.load_entry(&hash)?.is_some() {
            return Ok(false);
        }
        let bytes = codec::encode(&block);
        // A header digest alone cannot identify an invalid body: a peer may send
        // another payload carrying the same valid header. Hash the whole record.
        let identity = crypto::sha256d(&bytes);
        self.expire_invalid();
        if let Some(error) = self.invalid_blocks.get(&identity) {
            anyhow::bail!("cached invalid block: {error}");
        }
        let (entry, state) = match self.validate_block(&block, now) {
            Ok(valid) => valid,
            Err(error) => {
                if error.downcast_ref::<PermanentBlockError>().is_some() {
                    self.remember_invalid(identity, &error);
                }
                return Err(error);
            }
        };
        let best = entry.work > self.tip_entry.work;
        let transaction = self.db.transaction()?;
        transaction.execute(
            "INSERT INTO blocks(hash,bytes,accepted_at) VALUES(?1,?2,?3)",
            params![hash.as_slice(), bytes, now],
        )?;
        transaction.execute(
            "INSERT INTO entry_index(hash,bytes) VALUES(?1,?2)",
            params![hash.as_slice(), codec::encode(&entry)],
        )?;
        if best {
            Self::write_canonical(&transaction, hash, entry.height)?;
            transaction.execute("INSERT INTO metadata(key,value) VALUES('tip',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[hash.as_slice()])?;
        }
        transaction.commit()?;
        let entry = Arc::new(entry);
        self.cache_entry(hash, entry.clone());
        self.cache_state(hash, state.clone());
        if best {
            self.select_tip(hash, block, state, entry);
        }
        Ok(best)
    }
    pub fn template(
        &self,
        miner: PublicKey,
        transactions: Vec<Transaction>,
        timestamp: u32,
    ) -> Result<Block> {
        let parent = &self.tip_entry;
        self.validate_transaction_anchors(&self.tip, &transactions)?;
        let target = self.target(parent)?;
        let state = consensus::execute(
            &self.config,
            &self.tip_state,
            &self.tip,
            &miner,
            &math::work(&target),
            &transactions,
        )?;
        self.template_from_execution(miner, transactions, timestamp, state.root())
    }
    fn template_from_execution(
        &self,
        miner: PublicKey,
        transactions: Vec<Transaction>,
        timestamp: u32,
        state_root: Hash,
    ) -> Result<Block> {
        let target = self.target(&self.tip_entry)?;
        let timestamp = timestamp.max(
            self.median(self.tip)?
                .checked_add(1)
                .context("timestamp exhausted")?,
        );
        let mut block = Block {
            header: Header {
                version: codec::HEADER_VERSION,
                previous: self.tip,
                merkle_root: ZERO_HASH,
                timestamp,
                bits: math::bits_from_target(&target),
                nonce: 0,
            },
            height: self.tip_entry.height + 1,
            miner,
            state_root,
            extranonce: [0; 8],
            transactions,
        };
        block.header.merkle_root = codec::merkle_root(&block)?;
        ensure!(
            codec::body_size(&block)? as u64 <= self.tip_state.settings.block_bytes,
            "block body exceeds byte limit"
        );
        Ok(block)
    }
    /// Build one intermediate state and try bounded atomic operations against it.
    /// Signature checks are cached for this invocation only. A rejected candidate
    /// cannot mutate the state accepted for previous candidates. Budget exhaustion
    /// is a local selection policy outcome, never a consensus validity judgment.
    pub fn select_transactions(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
    ) -> Result<SelectionResult> {
        self.select_executed(miner, candidates, limit)
            .map(|(selected, _)| selected)
    }
    /// Selection and construction share the same parent, miner and
    /// configuration. The completed state never escapes as a reusable unchecked
    /// input; received blocks still pass the normal independent validation path.
    pub fn select_template(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        timestamp: u32,
    ) -> Result<(SelectionResult, Block)> {
        let (selected, state) = self.select_executed(miner, candidates, limit)?;
        let block = self.template_from_execution(
            miner,
            selected.transactions.clone(),
            timestamp,
            state.root(),
        )?;
        Ok((selected, block))
    }
    fn select_executed(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
    ) -> Result<(SelectionResult, State)> {
        ensure!(
            candidates.len() <= MAX_SELECTION_CANDIDATES,
            "selection candidate limit exceeded"
        );
        ensure!(crypto::valid_key(&miner), "invalid miner key");
        let target = self.target(&self.tip_entry)?;
        let block_work = math::work(&target);
        let mut execution =
            consensus::prepare_block(&self.config, &self.tip_state, &miner, &block_work)?;
        let mut result = SelectionResult {
            transactions: Vec::new(),
            signatures_checked: 0,
            execution_attempts: 0,
            budget_exhausted: false,
        };
        let limit = limit.min(self.config.max_signatures);
        let budget = candidates.len() * SELECTION_ATTEMPTS_PER_CANDIDATE;
        let (prefix, suffix) = codec::coinbase_parts(execution.state.height, &miner, &ZERO_HASH);
        let system_bytes = prefix.len() + 8 + suffix.len();
        // The combined coinbase commitment has a separately transmitted state-root opening.
        let mut records_bytes = compact_size_len(system_bytes) + system_bytes + 32;
        let byte_limit = self.tip_state.settings.block_bytes as usize;
        let mut ids = BTreeSet::new();
        let mut pending = Vec::new();
        for transaction in candidates {
            let bytes = codec::encode(transaction);
            let id = crypto::sha256d(&bytes);
            if bytes.len() > self.config.transaction_bytes(&self.tip_state.settings)
                || !ids.insert(id)
            {
                continue;
            }
            if transaction.body.expiry_blocks == 0 || transaction.body.nonce == u64::MAX {
                continue;
            }
            result.signatures_checked += 1;
            if crypto::verify(transaction).is_err() {
                continue;
            }
            let Ok(quote) = fees::quote(&self.config, &execution.state, transaction) else {
                continue;
            };
            let (priority, weight) = (quote.miner_fee, quote.weight);
            let recipient = match transaction.body.operation.clone() {
                Operation::TransferExact { recipient, .. } => Some(recipient),
                _ => None,
            };
            pending.push((
                transaction,
                compact_size_len(bytes.len()) + bytes.len(),
                priority,
                weight,
                id,
                recipient,
            ));
        }
        type RankedCandidate<'a> = (&'a Transaction, usize, Amount, u64, Hash, Option<PublicKey>);
        let refs: Vec<_> = pending.iter().map(|candidate| candidate.0).collect();
        let anchor_validity = self.transaction_anchor_results(&self.tip, &refs)?;
        pending = pending
            .into_iter()
            .zip(anchor_validity)
            .filter_map(|(candidate, validity)| validity.is_ok().then_some(candidate))
            .collect();
        let rank = |pending: &mut Vec<RankedCandidate<'_>>| {
            pending.sort_by(|a, b| {
                let earnings = (&b.2 * Amount::from(a.3)).cmp(&(&a.2 * Amount::from(b.3)));
                earnings.then_with(|| a.4.cmp(&b.4))
            });
        };
        // Rank actual miner earnings per weight; txid breaks equal bids.
        rank(&mut pending);
        while !pending.is_empty() && result.transactions.len() < limit {
            let previous_count = result.transactions.len();
            let mut index = 0;
            while index < pending.len() {
                let (transaction, bytes) = (pending[index].0, pending[index].1);
                let nonce = execution
                    .state
                    .account(&transaction.body.sender, None)
                    .map(|a| a.nonce);
                if nonce.is_some_and(|n| transaction.body.nonce < n) {
                    pending.remove(index);
                    continue;
                }
                if nonce != Some(transaction.body.nonce) {
                    index += 1;
                    continue;
                }
                // Include the mandatory system record and CompactSize count growth.
                let record_count = result.transactions.len() + 2;
                let body_size = compact_size_len(record_count) + records_bytes + bytes;
                if body_size > byte_limit {
                    pending.remove(index);
                    continue;
                }
                if result.execution_attempts == budget {
                    result.budget_exhausted = true;
                    break;
                }
                result.execution_attempts += 1;
                let created_recipient = pending[index]
                    .5
                    .filter(|recipient| execution.state.account(recipient, None).is_none());
                if execution
                    .apply_verified_transaction(&self.config, transaction)
                    .is_ok()
                {
                    records_bytes += bytes;
                    result.transactions.push(transaction.clone());
                    pending.remove(index);
                    if let Some(recipient) = created_recipient {
                        // Creating an account lowers the weight of later payments
                        // to that account while their exact fees stay fixed. Reprice affected
                        // candidates, then rank again before filling more slots.
                        let mut repriced = false;
                        pending.retain_mut(|candidate| {
                            if candidate.5 != Some(recipient) {
                                return true;
                            }
                            let Ok(quote) =
                                fees::quote(&self.config, &execution.state, candidate.0)
                            else {
                                return false;
                            };
                            candidate.2 = quote.miner_fee;
                            candidate.3 = quote.weight;
                            repriced = true;
                            true
                        });
                        if repriced {
                            rank(&mut pending);
                        }
                    }
                    // An accepted prerequisite may make an earlier, higher-priority
                    // candidate executable. Revisit it before filling the last slots
                    // with lower-priority transactions. Authentication stays cached
                    // and the same linear budget bounds actual operation attempts.
                    break;
                } else {
                    index += 1;
                }
            }
            if result.budget_exhausted || result.transactions.len() == previous_count {
                break;
            }
        }
        let state = consensus::finish_block(
            &self.config,
            &self.tip_state,
            &self.tip,
            &miner,
            &block_work,
            execution,
        )?;
        Ok((result, state))
    }

    pub fn validate_transaction(&self, transaction: &Transaction) -> Result<()> {
        self.template(
            transaction.body.sender,
            vec![transaction.clone()],
            self.tip_block().header.timestamp,
        )?;
        Ok(())
    }
    pub fn mine(mut block: Block, max_attempts: u64) -> Result<Block> {
        let target = math::target_from_bits(block.header.bits)?;
        for _ in 0..max_attempts {
            if math::check_pow(&block.header, &target).is_ok() {
                return Ok(block);
            }
            let (next, overflow) = block.header.nonce.overflowing_add(1);
            block.header.nonce = next;
            if overflow {
                let n = u64::from_le_bytes(block.extranonce).wrapping_add(1);
                block.extranonce = n.to_le_bytes();
                block.header.merkle_root = codec::merkle_root(&block)?;
            }
        }
        anyhow::bail!("no valid nonce in mining attempt limit")
    }
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    fn candidate(chain: &Chain, salt: u64) -> Block {
        let miner = crypto::public_key(&[91; 32]).unwrap();
        let mut block = chain
            .template(miner, vec![], chain.tip_block().header.timestamp + 15)
            .unwrap();
        block.extranonce = salt.to_le_bytes();
        block.header.merkle_root = codec::merkle_root(&block).unwrap();
        Chain::mine(block, 100_000).unwrap()
    }
    #[test]
    fn losing_history_evicts_hot_metadata_without_losing_blocks_or_future_forks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bounded.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let first = candidate(&chain, 0);
        let mut older = None;
        for salt in 0..(MAX_CACHED_ENTRIES + 64) {
            let mut block = first.clone();
            block.extranonce = (salt as u64).to_le_bytes();
            block.header.merkle_root = codec::merkle_root(&block).unwrap();
            block = Chain::mine(block, 100_000).unwrap();
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            if salt == 2 {
                older = Some(block);
            }
            assert!(chain.cached_entry_count() <= MAX_CACHED_ENTRIES);
        }
        let older = older.unwrap();
        let hash = codec::block_hash(&older);
        assert!(!chain.entries.borrow().entries.contains_key(&hash));
        assert_eq!(
            codec::encode(&chain.block(&hash).unwrap()),
            codec::encode(&older)
        );
        let mut branch = Chain::open(&directory.path().join("branch.db"), config.clone()).unwrap();
        branch
            .submit(older.clone(), older.header.timestamp as u64)
            .unwrap();
        let next = candidate(&branch, 999);
        assert!(
            chain
                .submit(next.clone(), next.header.timestamp as u64)
                .unwrap()
        );
        assert_eq!(chain.hash_at_height(1), Some(hash));
        let tip = chain.tip_hash();
        let root = chain.tip_state().root();
        drop(chain);
        // Derived indexes must never become an authority over stored block validation.
        let db = Connection::open(&path).unwrap();
        db.execute("UPDATE entry_index SET bytes=x'00'", [])
            .unwrap();
        db.execute("DELETE FROM canonical_index", []).unwrap();
        drop(db);
        let reopened = Chain::open(&path, config).unwrap();
        assert_eq!(reopened.tip_hash(), tip);
        assert_eq!(reopened.tip_state().root(), root);
        assert!(reopened.cached_entry_count() <= MAX_CACHED_ENTRIES);
        assert_eq!(reopened.hash_at_height(1), Some(hash));
    }
    #[test]
    fn deep_higher_work_fork_survives_index_eviction_and_budgeted_state_replay() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut main = Chain::open(&directory.path().join("main.db"), config.clone()).unwrap();
        let mut fork = Chain::open(&directory.path().join("fork.db"), config.clone()).unwrap();
        for n in 0..(MAX_CACHED_ENTRIES + 20) {
            let block = candidate(&main, n as u64);
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let length = main.tip_height();
        for n in 0..length {
            let block = candidate(&fork, 10_000 + n);
            fork.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_ne!(main.tip_hash(), fork.tip_hash());
        // Evict reconstructed states and metadata, including the losing branch tip.
        main.cache.borrow_mut().states.clear();
        main.cache.borrow_mut().order.clear();
        main.entries.borrow_mut().entries.clear();
        main.entries.borrow_mut().order.clear();
        let next = candidate(&fork, 20_000);
        fork.submit(next.clone(), next.header.timestamp as u64)
            .unwrap();
        let mut deferred = 0;
        loop {
            match main.submit_with_replay_budget(next.clone(), next.header.timestamp as u64, 17) {
                Ok(selected) => {
                    assert!(selected);
                    break;
                }
                Err(error) if error.is::<ValidationDeferred>() => {
                    deferred += 1;
                    assert!(deferred < 100);
                }
                Err(error) => panic!("{error:#}"),
            }
        }
        assert!(deferred > 0);
        assert_eq!(main.tip_hash(), fork.tip_hash());
        assert_eq!(main.tip_state().root(), fork.tip_state().root());
        for height in 0..=fork.tip_height() {
            assert_eq!(main.hash_at_height(height), fork.hash_at_height(height));
        }
        assert!(main.cached_entry_count() <= MAX_CACHED_ENTRIES);
        assert!(main.cached_state_count() <= MAX_CACHED_STATES);
    }
    #[test]
    fn invalid_cache_entries_expire_without_affecting_consensus() {
        let directory = tempfile::tempdir().unwrap();
        let mut chain = Chain::open(&directory.path().join("cache.db"), Config::devnet()).unwrap();
        chain.remember_invalid([7; 32], &anyhow::anyhow!("invalid message"));
        chain.invalid_order.front_mut().unwrap().1 =
            Instant::now() - INVALID_BLOCK_TTL - Duration::from_secs(1);
        chain.expire_invalid();
        assert_eq!(chain.cached_invalid_count(), 0);
        assert!(chain.invalid_order.is_empty());
        chain.tip_state().audit(&chain.config).unwrap();
    }
    #[test]
    fn interrupted_block_persistence_is_atomic_and_the_same_block_can_be_retried() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("atomic.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let first = candidate(&chain, 1);
        chain
            .submit(first.clone(), u64::from(first.header.timestamp))
            .unwrap();
        let before = (
            chain.tip_hash(),
            chain.tip_height(),
            chain.tip_state().root(),
        );
        let next = candidate(&chain, 2);
        let hash = codec::block_hash(&next);
        // Fail at three different persistence stages, including after the block
        // body and canonical index have already been written in the transaction.
        for trigger in [
            "CREATE TEMP TRIGGER stop_write BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT,'test write failure'); END;",
            "CREATE TEMP TRIGGER stop_write BEFORE INSERT ON canonical_index BEGIN SELECT RAISE(ABORT,'test write failure'); END;",
            "CREATE TEMP TRIGGER stop_write BEFORE UPDATE ON metadata WHEN NEW.key='tip' BEGIN SELECT RAISE(ABORT,'test write failure'); END;",
        ] {
            chain.db.execute_batch(trigger).unwrap();
            let error = chain
                .submit(next.clone(), u64::from(next.header.timestamp))
                .unwrap_err();
            assert!(
                error.to_string().contains("test write failure"),
                "{error:#}"
            );
            assert_eq!(
                (
                    chain.tip_hash(),
                    chain.tip_height(),
                    chain.tip_state().root()
                ),
                before
            );
            assert!(chain.block(&hash).is_none());
            assert!(chain.hash_at_height(next.height).is_none());
            assert_eq!(chain.cached_invalid_count(), 0);
            chain.db.execute_batch("DROP TRIGGER stop_write").unwrap();
            drop(chain);
            chain = Chain::open(&path, config.clone()).unwrap();
            assert_eq!(
                (
                    chain.tip_hash(),
                    chain.tip_height(),
                    chain.tip_state().root()
                ),
                before
            );
            assert!(chain.block(&hash).is_none());
        }
        assert!(
            chain
                .submit(next.clone(), u64::from(next.header.timestamp))
                .unwrap()
        );
        assert_eq!(chain.tip_hash(), hash);
        let root = chain.tip_state().root();
        drop(chain);
        let chain = Chain::open(&path, config).unwrap();
        assert_eq!(chain.tip_hash(), hash);
        assert_eq!(chain.tip_state().root(), root);
        chain.tip_state().audit(&chain.config).unwrap();
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn anchor_index_failure_does_not_poison_invalid_block_cache() {
        let directory = tempfile::tempdir().unwrap();
        let mut chain =
            Chain::open(&directory.path().join("anchor-index.db"), Config::devnet()).unwrap();
        let first = candidate(&chain, 1);
        chain
            .submit(first.clone(), u64::from(first.header.timestamp))
            .unwrap();
        let owner = crypto::public_key(&[91; 32]).unwrap();
        let tx = crypto::sign(
            &TransactionBody {
                sender: owner,
                nonce: 0,
                fee: 1u32.into(),
                anchor: chain.tip_hash(),
                expiry_blocks: 2,
                operation: Operation::TransferExact {
                    recipient: owner,
                    amount: 1u32.into(),
                },
                data: vec![],
            },
            &[91; 32],
        )
        .unwrap();
        let block = Chain::mine(chain.template(owner, vec![tx], 0).unwrap(), 100_000).unwrap();
        chain
            .db
            .execute("DELETE FROM canonical_index WHERE height=1", [])
            .unwrap();
        let error = chain
            .submit(block.clone(), u64::from(block.header.timestamp))
            .unwrap_err();
        assert!(error.is::<LocalIndexError>(), "{error:#}");
        assert_eq!(chain.cached_invalid_count(), 0);
        chain
            .db
            .execute(
                "INSERT INTO canonical_index(height,hash) VALUES(1,?1)",
                [codec::block_hash(&first).as_slice()],
            )
            .unwrap();
        assert!(
            chain
                .submit(block.clone(), u64::from(block.header.timestamp))
                .unwrap()
        );
    }
}
