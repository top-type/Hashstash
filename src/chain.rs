use crate::{codec, config::Config, consensus, crypto, fees, math, state::State, types::*};
use anyhow::{Context, Result, ensure};
use num_traits::Zero;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

/// Recently validated or reconstructed states outside the active-chain checkpoints.
pub const MAX_CACHED_STATES: usize = 128;
pub const MAX_CACHED_INVALID_BLOCKS: usize = 128;
/// Local metadata cache only. Eviction never discards accepted history or limits reorg depth.
pub const MAX_CACHED_ENTRIES: usize = 256;
/// Active-chain states this close to the tip are all retained. Deeper ones are
/// thinned to two per doubling of depth, so reconstructing an ancestor replays
/// about its depth below the tip at most, never the whole chain height.
pub const DENSE_STATE_CHECKPOINTS: u64 = 32;
/// Ancestor-walk steps charged as one replayed block against a replay budget.
const WALK_STEPS_PER_REPLAY_STEP: u64 = 16;
/// Local side-branch admission policy, not a consensus rule. A block that would
/// not become the tip must carry at least 1/SIDE_BRANCH_WORK_RATIO of the next
/// active-chain block's work, and its branch must be able to overtake the tip
/// within SIDE_BRANCH_CATCH_UP_BLOCKS further blocks of the same work.
pub const SIDE_BRANCH_WORK_RATIO: u32 = 64;
pub const SIDE_BRANCH_CATCH_UP_BLOCKS: u32 = 4096;
/// A losing branch raises the peer capacity allowance only while it stays within
/// this many next-block works of the tip, with at least 1/CAPACITY_BRANCH_WORK_RATIO
/// of that work in its leaf block.
pub const CAPACITY_BRANCH_MARGIN_BLOCKS: u32 = 6;
pub const CAPACITY_BRANCH_WORK_RATIO: u32 = 4;
const MAX_CAPACITY_BRANCHES: usize = 256;
/// Blocks replayed per committed batch of the startup index rebuild. Unit tests
/// use small batches so reopening their short chains crosses batch boundaries.
const INDEX_REBUILD_BATCH: u64 = if cfg!(test) { 7 } else { 4096 };
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
/// Local admission policy declined a block that would not become the tip.
/// The block is not invalid and is never cached as such; it can be offered
/// again once its branch is competitive.
#[derive(Debug)]
pub struct SideBranchRefused(&'static str);
impl std::fmt::Display for SideBranchRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "side branch not retained: {}", self.0)
    }
}
impl std::error::Error for SideBranchRefused {}
/// Retained reconstruction progress no longer links to the active chain.
#[derive(Debug)]
struct StaleReplay;
impl std::fmt::Display for StaleReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "retained state replay no longer matches the active chain")
    }
}
impl std::error::Error for StaleReplay {}

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
/// Operation attempts granted to each sender per candidate it submits.
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
/// Height of the skip-link target, as in Bitcoin's block index.
fn skip_height(height: u64) -> u64 {
    fn invert_lowest_one(n: u64) -> u64 {
        n & n.wrapping_sub(1)
    }
    if height < 2 {
        0
    } else if height & 1 == 1 {
        invert_lowest_one(invert_lowest_one(height - 1)) + 1
    } else {
        invert_lowest_one(height)
    }
}
/// Whether an active-chain state at `height` stays retained below a tip at `tip`.
/// Retention only shrinks as the tip advances, so dropped states are not needed again.
fn checkpoint_retained(height: u64, tip: u64) -> bool {
    if height == 0 {
        return true;
    }
    if height >= tip {
        return false;
    }
    let depth = tip - height;
    if depth < DENSE_STATE_CHECKPOINTS {
        return true;
    }
    let step = 1u64 << (62 - depth.leading_zeros());
    height % step == 0
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct Entry {
    header: Header,
    height: u64,
    // Expected elapsed seconds for timestamp ASERT, independent of economic progress.
    clock: u64,
    // The first mined blocks anchor their own branch. These derived fields are
    // rebuilt from validated headers, so pre-mining idle time is not DAA debt.
    anchor_timestamp: u32,
    anchor_clock: u64,
    work: Amount,
    // Ancestor at skip_height(height), giving logarithmic ancestry lookups.
    skip: Hash,
    // Greatest governed block capacity on this branch through this post-state.
    capacity: u64,
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
/// Resumable reconstruction of one historical state. Progress is kept outside
/// the recent-state cache, so unrelated insertions cannot discard it.
struct Replay {
    target: Hash,
    /// Next entry to inspect while the base state is still unknown.
    walk: Option<Hash>,
    /// Side-branch blocks recorded for this target in the temporary path
    /// table; position zero is the target itself.
    side: u64,
    /// Active-chain heights still to apply before the side-branch path.
    canonical: (u64, u64),
    /// Latest reconstructed ancestor.
    base: Option<(Hash, Arc<State>)>,
}
/// A stored losing-branch leaf that may still raise the peer capacity allowance.
struct BranchLeaf {
    work: Amount,
    block_work: Amount,
    capacity: u64,
}
impl BranchLeaf {
    fn of(entry: &Entry) -> Self {
        Self {
            work: entry.work.clone(),
            block_work: math::target_from_bits(entry.header.bits)
                .map(|target| math::work(&target))
                .unwrap_or_default(),
            capacity: entry.capacity,
        }
    }
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
    // Active-chain states by height. Side-branch traffic never evicts them.
    checkpoints: RefCell<BTreeMap<u64, (Hash, Arc<State>)>>,
    cache: RefCell<StateCache>,
    replay: RefCell<Option<Replay>>,
    invalid_blocks: BTreeMap<Hash, String>,
    invalid_order: VecDeque<(Hash, Instant)>,
    replay_budget: Cell<Option<usize>>,
    branches: BTreeMap<Hash, BranchLeaf>,
    known_block_bytes: u64,
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
        // The journal limit returns WAL space after checkpoints of the batched
        // startup index rebuild instead of keeping the log at its peak size.
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_size_limit=67108864; CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS blocks(seq INTEGER PRIMARY KEY AUTOINCREMENT, hash BLOB NOT NULL UNIQUE, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS rejected_blocks(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL, reason TEXT NOT NULL);")?;
        // Derived indexes are rebuilt from independently validated block bodies on every open.
        // SQLite bounds its page cache; canonical and losing-branch metadata stay on disk.
        db.execute_batch("PRAGMA cache_size=-8192; PRAGMA temp_store=FILE; CREATE TABLE IF NOT EXISTS entry_index(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS canonical_index(height INTEGER PRIMARY KEY, hash BLOB NOT NULL); CREATE TEMP TABLE IF NOT EXISTS state_replay_path(target BLOB NOT NULL, position INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY(target,position));")?;
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
            skip: ZERO_HASH,
            capacity: state.settings.block_bytes,
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
            checkpoints: RefCell::new(BTreeMap::from([(0, (genesis_hash, state))])),
            cache: RefCell::new(StateCache::default()),
            replay: RefCell::new(None),
            invalid_blocks: BTreeMap::new(),
            invalid_order: VecDeque::new(),
            replay_budget: Cell::new(None),
            branches: BTreeMap::new(),
            known_block_bytes: genesis_entry.capacity,
        };
        chain.cache_entry(genesis_hash, genesis_entry);
        // Stored blocks that fail current validation are set aside when they
        // belong to losing branches. Storage and index errors still stop startup.
        let mut rejected = BTreeMap::<Hash, (Option<Amount>, String)>::new();
        let claimed_work = |parent: Option<&Amount>, block: &Block| {
            let target = math::target_from_bits(block.header.bits).ok()?;
            Some(parent? + math::work(&target))
        };
        // Replay one bounded record at a time instead of buffering the entire database.
        let mut sequence = 0i64;
        let mut replayed = 0u64;
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
            if let Some((parent, _)) = rejected.get(&block.header.previous) {
                let claimed = claimed_work(parent.as_ref(), &block);
                rejected.insert(hash, (claimed, "parent block fails validation".into()));
                continue;
            }
            let (entry, state) = match chain.validate_block(&block, accepted_at, false) {
                Ok(valid) => valid,
                Err(error) if error.is::<PermanentBlockError>() => {
                    let parent = chain.load_entry(&block.header.previous)?;
                    let claimed = claimed_work(parent.as_ref().map(|entry| &entry.work), &block);
                    rejected.insert(hash, (claimed, error.to_string()));
                    continue;
                }
                Err(error) => return Err(error.context("invalid stored history")),
            };
            let best = entry.work > chain.tip_entry.work;
            chain.db.execute(
                "INSERT INTO entry_index(hash,bytes) VALUES(?1,?2)",
                params![hash.as_slice(), codec::encode(&entry)],
            )?;
            if best {
                Self::write_canonical(&chain.db, hash, entry.height)?;
            }
            chain.record(hash, block, Arc::new(entry), state, best);
            replayed += 1;
            // Derived indexes are rebuilt from scratch on every open, so an
            // interrupted rebuild loses nothing; committing in batches keeps the
            // write-ahead log, and the free space it needs, bounded.
            if replayed % INDEX_REBUILD_BATCH == 0 {
                chain.db.execute_batch("COMMIT; BEGIN IMMEDIATE;")?;
            }
        }
        let saved_tip: Option<Vec<u8>> = chain
            .db
            .query_row("SELECT value FROM metadata WHERE key='tip'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let persisted = saved_tip
            .as_deref()
            .and_then(|raw| Hash::try_from(raw).ok());
        // Tips only gain work and every accepted block is committed with the tip
        // it produces, so a stored losing branch never claims more work than the
        // persisted tip. Anything else means the persisted tip itself, or the
        // database, disagrees with current validation: fail closed.
        let persisted_work = match persisted {
            Some(hash) => chain.load_entry(&hash)?.map(|entry| entry.work.clone()),
            None => None,
        };
        for (hash, (claimed, reason)) in &rejected {
            if claimed
                .as_ref()
                .zip(persisted_work.as_ref())
                .is_none_or(|(claimed, persisted)| claimed > persisted)
            {
                anyhow::bail!(
                    "invalid stored history: block {} fails validation: {reason}",
                    hex::encode(hash)
                );
            }
        }
        let hinted = match persisted {
            Some(hash) if hash != chain.tip => chain
                .load_entry(&hash)?
                .filter(|entry| entry.work == chain.tip_entry.work)
                .map(|entry| (hash, entry)),
            _ => None,
        };
        if let Some((hash, entry)) = hinted {
            // An equal-work hint only breaks the first-seen tie between
            // already revalidated branches.
            let block = chain
                .load_block(&hash)?
                .context("persisted tip block absent")?;
            let state = chain.load_state(&hash)?;
            Self::write_canonical(&chain.db, hash, entry.height)?;
            let previous = (chain.tip, chain.tip_entry.clone());
            chain.select_tip(hash, block, state, entry.clone());
            chain.note_branch(hash, &entry, true, previous);
            chain.refresh_capacity();
        } else if persisted != Some(chain.tip) && (saved_tip.is_some() || chain.tip != genesis_hash)
        {
            // A missing, malformed or lower-work hint cannot override validated
            // history; record the replayed best tip instead.
            eprintln!("Ignoring a stale persisted chain tip; using the replayed best tip");
            chain.db.execute("INSERT INTO metadata(key,value) VALUES('tip',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [chain.tip.as_slice()])?;
        }
        for (hash, (_, reason)) in &rejected {
            chain.db.execute(
                "INSERT OR IGNORE INTO rejected_blocks(hash,bytes,accepted_at,reason) SELECT hash,bytes,accepted_at,?2 FROM blocks WHERE hash=?1",
                params![hash.as_slice(), reason],
            )?;
            chain
                .db
                .execute("DELETE FROM blocks WHERE hash=?1", [hash.as_slice()])?;
        }
        if !rejected.is_empty() {
            eprintln!(
                "Moved {} stored side-branch block(s) that fail validation into rejected_blocks",
                rejected.len()
            );
        }
        chain.db.execute_batch("COMMIT")?;
        // Housekeeping only: a failed checkpoint leaves committed history intact.
        let _ = chain.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
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
    /// Parent of a locally validated block, from header metadata without its body.
    pub fn block_parent(&self, hash: &Hash) -> Result<Option<Hash>> {
        Ok(self.load_entry(hash)?.map(|entry| entry.header.previous))
    }
    /// Greatest governed block capacity on a locally validated block's branch
    /// through its post-state, from header metadata.
    pub fn block_capacity(&self, hash: &Hash) -> Result<Option<u64>> {
        Ok(self.load_entry(hash)?.map(|entry| entry.capacity))
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

    /// Hash of the ancestor at `height` of the branch at `cursor`. Skip links keep
    /// the walk logarithmic in distance, and once it meets the active chain the
    /// canonical height index answers directly (the cursor becomes `None`).
    fn branch_ancestor(
        &self,
        cursor: &mut Option<(Hash, Arc<Entry>)>,
        height: u64,
    ) -> Result<Hash> {
        loop {
            let Some((hash, entry)) = cursor.as_ref() else {
                return self.canonical_hash(height)?.ok_or_else(|| {
                    LocalIndexError(anyhow::anyhow!("canonical ancestor absent")).into()
                });
            };
            if entry.height <= height {
                ensure!(entry.height == height, "ancestor above its descendant");
                return Ok(*hash);
            }
            if self.canonical_hash(entry.height)? == Some(*hash) {
                *cursor = None;
                continue;
            }
            let skip = skip_height(entry.height);
            let skip_previous = skip_height(entry.height - 1);
            let next = if skip == height
                || (skip > height && !(skip_previous + 2 < skip && skip_previous >= height))
            {
                entry.skip
            } else {
                entry.header.previous
            };
            let next_entry = self
                .load_entry(&next)?
                .ok_or_else(|| LocalIndexError(anyhow::anyhow!("candidate ancestor absent")))?;
            *cursor = Some((next, next_entry));
        }
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
        // Canonical references use indexed height lookups. On a side branch,
        // skip links reach each referenced height without walking every block.
        // Memory depends on this block's references, never on chain age.
        let mut cursor = Some((*parent, parent_entry));
        for (height, requested) in required.iter().rev() {
            let hash = self.branch_ancestor(&mut cursor, *height)?;
            if requested.contains(&hash) {
                ancestors.insert(hash);
            }
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
    /// A state this chain already retains: the tip, an active-chain checkpoint
    /// or a recent state. Unlike state_at, it never replays history.
    pub fn cached_state(&self, hash: &Hash) -> Option<Arc<State>> {
        if *hash == self.tip {
            return Some(self.tip_state.clone());
        }
        let checkpoint = self
            .checkpoints
            .borrow()
            .values()
            .find(|(retained, _)| retained == hash)
            .map(|(_, state)| state.clone());
        checkpoint.or_else(|| self.cache.borrow().states.get(hash).cloned())
    }
    /// Recently validated or reconstructed states outside the active-chain checkpoints.
    pub fn cached_state_count(&self) -> usize {
        self.cache.borrow().states.len()
    }
    /// Retained active-chain states; logarithmic in the chain height.
    pub fn checkpoint_state_count(&self) -> usize {
        self.checkpoints.borrow().len()
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
                .prepare_cached("SELECT bytes FROM entry_index WHERE hash=?1")?
                .query_row([hash.as_slice()], |r| r.get(0))
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
    /// Cached statements avoid re-preparing SQL for each block of a deep switch.
    fn write_canonical(db: &Connection, hash: Hash, height: u64) -> Result<()> {
        db.prepare_cached("DELETE FROM canonical_index WHERE height>?1")?
            .execute([height])?;
        let mut cursor = hash;
        loop {
            let entry = Self::read_entry(db, &cursor)?.context("canonical entry absent")?;
            let active: Option<Vec<u8>> = db
                .prepare_cached("SELECT hash FROM canonical_index WHERE height=?1")?
                .query_row([entry.height], |r| r.get(0))
                .optional()?;
            if active.as_deref() == Some(cursor.as_slice()) {
                break;
            }
            db.prepare_cached("INSERT INTO canonical_index(height,hash) VALUES(?1,?2) ON CONFLICT(height) DO UPDATE SET hash=excluded.hash")?
                .execute(params![entry.height, cursor.as_slice()])?;
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
    /// Greatest block capacity on the active chain's history or on a losing
    /// branch that is still competitive with the tip. Recomputed after every
    /// accepted block, so it falls again when such a branch is left behind.
    pub fn max_known_block_bytes(&self) -> u64 {
        self.known_block_bytes
    }
    /// Least recently used states are evicted first; a hit refreshes the state.
    fn cache_state(&self, hash: Hash, state: Arc<State>) {
        let mut cache = self.cache.borrow_mut();
        if cache.states.insert(hash, state).is_some()
            && let Some(position) = cache.order.iter().position(|cached| *cached == hash)
        {
            cache.order.remove(position);
        }
        cache.order.push_back(hash);
        while cache.states.len() > MAX_CACHED_STATES {
            let Some(old) = cache.order.pop_front() else {
                break;
            };
            cache.states.remove(&old);
        }
    }
    /// A recent state, marked most recently used.
    fn recent_state(&self, hash: &Hash) -> Option<Arc<State>> {
        let mut cache = self.cache.borrow_mut();
        let state = cache.states.get(hash)?.clone();
        if let Some(position) = cache.order.iter().position(|cached| cached == hash) {
            cache.order.remove(position);
            cache.order.push_back(*hash);
        }
        Some(state)
    }
    fn uncache_state(&self, hash: &Hash) -> Option<Arc<State>> {
        let mut cache = self.cache.borrow_mut();
        let state = cache.states.remove(hash)?;
        cache.order.retain(|cached| cached != hash);
        Some(state)
    }
    fn checkpoint_state(&self, height: u64, hash: &Hash) -> Option<Arc<State>> {
        self.checkpoints
            .borrow()
            .get(&height)
            .filter(|(retained, _)| retained == hash)
            .map(|(_, state)| state.clone())
    }
    fn charge_replay(&self) -> Result<()> {
        if let Some(remaining) = self.replay_budget.get() {
            if remaining == 0 {
                return Err(ValidationDeferred.into());
            }
            self.replay_budget.set(Some(remaining - 1));
        }
        Ok(())
    }
    fn clear_replay_path(&self, target: &Hash) -> Result<()> {
        self.db
            .prepare_cached("DELETE FROM state_replay_path WHERE target=?1")?
            .execute([target.as_slice()])?;
        Ok(())
    }
    /// Reconstruct a validated state from the nearest retained ancestor: the tip,
    /// a recent state, or an active-chain checkpoint. A replay budget also
    /// covers the ancestor walk; deferred work resumes from retained progress.
    fn load_state(&self, hash: &Hash) -> Result<Arc<State>> {
        if *hash == self.tip {
            return Ok(self.tip_state.clone());
        }
        if let Some(state) = self.recent_state(hash) {
            return Ok(state);
        }
        if let Some(entry) = self.load_entry(hash)?
            && let Some(state) = self.checkpoint_state(entry.height, hash)
        {
            return Ok(state);
        }
        let resumed = self
            .replay
            .borrow_mut()
            .take_if(|replay| replay.target == *hash);
        let mut replay = match resumed {
            Some(replay) => replay,
            None => self.start_replay(hash)?,
        };
        let result = match self.run_replay(&mut replay) {
            Err(error) if error.is::<StaleReplay>() => {
                // The active chain changed below retained progress; start over.
                replay = self.start_replay(hash)?;
                self.run_replay(&mut replay)
            }
            result => result,
        };
        match result {
            Err(error) if error.is::<ValidationDeferred>() => {
                // The latest progress also enters the recent cache, so another
                // deferred target taking the record does not discard it.
                if let Some((base, state)) = &replay.base {
                    self.cache_state(*base, state.clone());
                }
                let previous = self.replay.borrow_mut().replace(replay);
                if let Some(previous) = previous {
                    self.clear_replay_path(&previous.target)?;
                }
                Err(error)
            }
            result => {
                self.clear_replay_path(hash)?;
                result
            }
        }
    }
    fn start_replay(&self, hash: &Hash) -> Result<Replay> {
        self.clear_replay_path(hash)?;
        Ok(Replay {
            target: *hash,
            walk: Some(*hash),
            side: 0,
            canonical: (1, 0),
            base: None,
        })
    }
    fn run_replay(&self, replay: &mut Replay) -> Result<Arc<State>> {
        let mut steps = 0u64;
        while let Some(cursor) = replay.walk {
            let retained = if cursor == self.tip {
                Some(self.tip_state.clone())
            } else {
                self.recent_state(&cursor)
            };
            if let Some(state) = retained {
                replay.base = Some((cursor, state));
                replay.walk = None;
                break;
            }
            let entry = self.load_entry(&cursor)?.context("unknown state")?;
            if let Some(state) = self.checkpoint_state(entry.height, &cursor) {
                replay.base = Some((cursor, state));
                replay.walk = None;
                break;
            }
            if self.canonical_hash(entry.height)? == Some(cursor) {
                // The branch meets the active chain: continue by height from the
                // nearest checkpoint, at most about this depth below the tip, or
                // from progress an earlier deferred replay left in the cache.
                let (mut height, mut base) = self
                    .checkpoints
                    .borrow()
                    .range(..=entry.height)
                    .next_back()
                    .map(|(height, (hash, state))| (*height, (*hash, state.clone())))
                    .context("genesis checkpoint absent")?;
                for retained in (height + 1..entry.height).rev() {
                    if let Some(hash) = self.canonical_hash(retained)?
                        && let Some(state) = self.recent_state(&hash)
                    {
                        (height, base) = (retained, (hash, state));
                        break;
                    }
                }
                replay.base = Some(base);
                replay.canonical = (height + 1, entry.height);
                replay.walk = None;
                break;
            }
            if steps % WALK_STEPS_PER_REPLAY_STEP == 0 {
                self.charge_replay()?;
            }
            steps += 1;
            self.db
                .prepare_cached(
                    "INSERT INTO state_replay_path(target,position,hash) VALUES(?1,?2,?3)",
                )?
                .execute(params![
                    replay.target.as_slice(),
                    replay.side,
                    cursor.as_slice()
                ])?;
            replay.side += 1;
            replay.walk = Some(entry.header.previous);
        }
        let (mut hash, mut state) = replay.base.clone().context("replay base absent")?;
        while replay.canonical.0 <= replay.canonical.1 {
            let height = replay.canonical.0;
            let Some(next) = self.canonical_hash(height)? else {
                return Err(StaleReplay.into());
            };
            self.charge_replay()?;
            let block = self
                .load_block(&next)?
                .context("stored ancestor block absent")?;
            if block.header.previous != hash {
                return Err(StaleReplay.into());
            }
            state = self.replay_block(&block, &state)?;
            hash = next;
            replay.base = Some((hash, state.clone()));
            replay.canonical.0 = height + 1;
            if checkpoint_retained(height, self.tip_height()) {
                self.checkpoints
                    .borrow_mut()
                    .insert(height, (hash, state.clone()));
            }
        }
        while replay.side > 0 {
            let position = replay.side - 1;
            let next: Vec<u8> = self
                .db
                .prepare_cached(
                    "SELECT hash FROM state_replay_path WHERE target=?1 AND position=?2",
                )?
                .query_row(params![replay.target.as_slice(), position], |r| r.get(0))?;
            let next: Hash = next.as_slice().try_into().context("invalid replay index")?;
            self.charge_replay()?;
            let block = self
                .load_block(&next)?
                .context("stored ancestor block absent")?;
            if block.header.previous != hash {
                return Err(StaleReplay.into());
            }
            state = self.replay_block(&block, &state)?;
            hash = next;
            replay.base = Some((hash, state.clone()));
            replay.side = position;
        }
        ensure!(hash == replay.target, "state replay ended at another block");
        let height = self.load_entry(&hash)?.map(|entry| entry.height);
        if height.is_none_or(|height| self.checkpoint_state(height, &hash).is_none()) {
            self.cache_state(hash, state.clone());
        }
        Ok(state)
    }
    fn replay_block(&self, block: &Block, parent: &State) -> Result<Arc<State>> {
        let subsidy = math::work(&math::target_from_bits(block.header.bits)?);
        self.validate_transaction_anchors(&block.header.previous, &block.transactions)?;
        let replayed = consensus::execute(
            &self.config,
            parent,
            &block.header.previous,
            &block.miner,
            &subsidy,
            &block.transactions,
        )?;
        ensure!(
            replayed.root() == block.state_root,
            "replayed state commitment mismatch"
        );
        Ok(Arc::new(replayed))
    }
    /// Install a validated block's in-memory metadata after its rows are written.
    fn record(
        &mut self,
        hash: Hash,
        block: Block,
        entry: Arc<Entry>,
        state: Arc<State>,
        best: bool,
    ) {
        self.cache_entry(hash, entry.clone());
        let previous = (self.tip, self.tip_entry.clone());
        if best {
            self.select_tip(hash, block, state, entry.clone());
        } else {
            self.cache_state(hash, state);
        }
        self.note_branch(hash, &entry, best, previous);
        self.refresh_capacity();
    }
    /// Callers have already written the canonical index for the new tip.
    fn select_tip(&mut self, hash: Hash, block: Block, state: Arc<State>, entry: Arc<Entry>) {
        let extends = block.header.previous == self.tip;
        let previous = (
            self.tip,
            self.tip_entry.height,
            std::mem::replace(&mut self.tip_state, state),
        );
        self.tip = hash;
        self.tip_block = block;
        self.tip_entry = entry;
        let height = self.tip_entry.height;
        if extends {
            self.checkpoints
                .get_mut()
                .insert(previous.1, (previous.0, previous.2));
        } else {
            // The previous tip leaves the active chain; keep it as a recent state.
            self.cache_state(previous.0, previous.2);
            let stale: Vec<u64> = self
                .checkpoints
                .borrow()
                .iter()
                .filter(|(height, (hash, _))| {
                    self.canonical_hash(**height).ok().flatten() != Some(*hash)
                })
                .map(|(height, _)| *height)
                .collect();
            for height in stale {
                self.checkpoints.get_mut().remove(&height);
            }
            // Recently validated states of the new active chain become checkpoints.
            for height in height.saturating_sub(DENSE_STATE_CHECKPOINTS)..height {
                if self.checkpoints.get_mut().contains_key(&height) {
                    continue;
                }
                if let Some(hash) = self.canonical_hash(height).ok().flatten()
                    && let Some(state) = self.uncache_state(&hash)
                {
                    self.checkpoints.get_mut().insert(height, (hash, state));
                }
            }
        }
        self.checkpoints
            .get_mut()
            .retain(|retained, _| checkpoint_retained(*retained, height));
    }
    /// Track stored losing-branch leaves that could still raise peer capacity.
    fn note_branch(&mut self, hash: Hash, entry: &Entry, best: bool, previous: (Hash, Arc<Entry>)) {
        self.branches.remove(&entry.header.previous);
        self.branches.remove(&hash);
        if !best {
            self.branches.insert(hash, BranchLeaf::of(entry));
        } else if entry.header.previous != previous.0 && previous.0 != hash {
            // A tip has no stored children, so the previous tip is now a leaf.
            self.branches.insert(previous.0, BranchLeaf::of(&previous.1));
        }
    }
    fn refresh_capacity(&mut self) {
        let next = self
            .target(&self.tip_entry)
            .map(|target| math::work(&target))
            .unwrap_or_default();
        let margin = &next * CAPACITY_BRANCH_MARGIN_BLOCKS;
        let tip_work = &self.tip_entry.work;
        // Tip work only grows, so a leaf left behind does not return.
        self.branches
            .retain(|_, leaf| &leaf.work + &margin >= *tip_work);
        while self.branches.len() > MAX_CAPACITY_BRANCHES {
            let lowest = self
                .branches
                .iter()
                .min_by(|a, b| a.1.work.cmp(&b.1.work).then_with(|| a.0.cmp(b.0)))
                .map(|(hash, _)| *hash);
            if let Some(hash) = lowest {
                self.branches.remove(&hash);
            }
        }
        self.known_block_bytes = self
            .branches
            .values()
            .filter(|leaf| &leaf.block_work * CAPACITY_BRANCH_WORK_RATIO >= next)
            .map(|leaf| leaf.capacity)
            .fold(self.tip_entry.capacity, u64::max);
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
                .prepare_cached("SELECT hash FROM canonical_index WHERE height=?1")?
                .query_row([height], |row| row.get(0))
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
    /// Local anti-DoS admission for a block that would not become the tip. Its
    /// claimed work is backed by the proof of work checked before this runs.
    fn admit_branch(&self, parent: &Entry, work: &Amount) -> Result<()> {
        let branch = &parent.work + work;
        if branch > self.tip_entry.work {
            return Ok(());
        }
        let next = math::work(&self.target(&self.tip_entry)?);
        if work * SIDE_BRANCH_WORK_RATIO < next {
            return Err(SideBranchRefused("block work is far below the active chain's").into());
        }
        if branch + work * SIDE_BRANCH_CATCH_UP_BLOCKS < self.tip_entry.work {
            return Err(
                SideBranchRefused("branch cannot plausibly overtake the active chain").into(),
            );
        }
        Ok(())
    }
    fn validate_block(
        &self,
        block: &Block,
        now: u64,
        admission: bool,
    ) -> Result<(Entry, Arc<State>)> {
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
            Ok(target)
        })()
        .map_err(permanent)?;
        let work = math::work(&target);
        // Admission policy runs after the cheap header checks and before any
        // ancestry walk or state reconstruction for the block.
        if admission {
            self.admit_branch(&parent, &work)?;
        }
        self.validate_transaction_anchors(&block.header.previous, &block.transactions)
            .map_err(permanent)?;
        let parent_state = self.load_state(&block.header.previous)?;
        // Disk/reconstruction failures above are transient local failures and are
        // never entered into the cache of permanently invalid block messages.
        (|| -> Result<(Entry, Arc<State>)> {
            ensure!(
                codec::body_size(block)? as u64 <= parent_state.settings.block_bytes,
                "block body exceeds byte limit"
            );
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
            let (anchor_timestamp, anchor_clock) = match parent.height {
                0 => (block.header.timestamp, clock),
                // The first block cannot backdate its branch's schedule: the
                // anchor is at least the second timestamp less one interval.
                1 => {
                    let floor = u64::from(block.header.timestamp)
                        .saturating_sub(parent_state.settings.interval);
                    (
                        parent.anchor_timestamp.max(u32::try_from(floor)?),
                        parent.anchor_clock,
                    )
                }
                _ => (parent.anchor_timestamp, parent.anchor_clock),
            };
            let mut ancestry = Some((block.header.previous, parent.clone()));
            let skip = self.branch_ancestor(&mut ancestry, skip_height(block.height))?;
            Ok((
                Entry {
                    header: block.header.clone(),
                    height: block.height,
                    clock,
                    anchor_timestamp,
                    anchor_clock,
                    work: &parent.work + work,
                    skip,
                    capacity: parent.capacity.max(state.settings.block_bytes),
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
        let (entry, state) = match self.validate_block(&block, now, true) {
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
        self.record(hash, block, Arc::new(entry), state, best);
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
        // Header timestamps are u32: the chain cannot extend once median
        // past time reaches u32::MAX (2106-02-07 UTC), a protocol lifetime limit.
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
            // Only opening funds can be committed and commitments only grow, so
            // a candidate the opening balance cannot cover never executes. It
            // is dropped before ranking, whatever fee it declares.
            if !execution.opening_funds_cover(transaction) {
                continue;
            }
            let recipient = match &transaction.body.operation {
                Operation::TransferExact { recipient, .. } => Some(*recipient),
                _ => None,
            };
            pending.push(Candidate {
                transaction,
                bytes: compact_size_len(bytes.len()) + bytes.len(),
                priority: Priority {
                    fee: quote.miner_fee,
                    weight: quote.weight,
                    id,
                },
                recipient,
                slot: Slot::Waiting,
            });
        }
        let refs: Vec<_> = pending.iter().map(|candidate| candidate.transaction).collect();
        let anchor_validity = self.transaction_anchor_results(&self.tip, &refs)?;
        let mut pending: Vec<_> = pending
            .into_iter()
            .zip(anchor_validity)
            .filter_map(|(candidate, validity)| validity.is_ok().then_some(candidate))
            .collect();
        // Index candidates by sender nonce and payment recipient. Each sender
        // has its own operation budget, so one sender's failing candidates
        // cannot use up the attempts available to others.
        let mut senders = BTreeMap::<PublicKey, SenderQueue>::new();
        let mut payments = BTreeMap::<PublicKey, Vec<usize>>::new();
        for (index, candidate) in pending.iter().enumerate() {
            let body = &candidate.transaction.body;
            let queue = senders.entry(body.sender).or_insert_with(|| SenderQueue {
                nonce: execution
                    .state
                    .account(&body.sender, None)
                    .map_or(u64::MAX, |account| account.nonce),
                budget: 0,
                waiting: BTreeMap::new(),
            });
            queue.budget += SELECTION_ATTEMPTS_PER_CANDIDATE;
            queue.waiting.entry(body.nonce).or_default().push(index);
            if let Some(recipient) = candidate.recipient {
                payments.entry(recipient).or_default().push(index);
            }
        }
        // Rank actual miner earnings per weight; txid breaks equal bids. Only
        // candidates at their sender's current nonce are ready to execute.
        let mut ready = BTreeSet::new();
        for queue in senders.values_mut() {
            // Lower nonces are already used and never become executable.
            queue.waiting = queue.waiting.split_off(&queue.nonce);
            for index in queue.waiting.remove(&queue.nonce).unwrap_or_default() {
                pending[index].slot = Slot::Ready;
                ready.insert((pending[index].priority.clone(), index));
            }
        }
        let mut parked = Vec::new();
        while result.transactions.len() < limit {
            let Some((_, index)) = ready.pop_first() else {
                break;
            };
            let (transaction, bytes, recipient) = {
                let candidate = &mut pending[index];
                candidate.slot = Slot::Done;
                (candidate.transaction, candidate.bytes, candidate.recipient)
            };
            let queue = senders
                .get_mut(&transaction.body.sender)
                .context("selection sender absent")?;
            // Another candidate already used this nonce.
            if transaction.body.nonce != queue.nonce {
                continue;
            }
            // Include the mandatory system record and CompactSize count growth.
            // Used bytes only grow, so a candidate that does not fit never will.
            let record_count = result.transactions.len() + 2;
            let body_size = compact_size_len(record_count) + records_bytes + bytes;
            if body_size > byte_limit || !execution.opening_funds_cover(transaction) {
                continue;
            }
            if queue.budget == 0 {
                result.budget_exhausted = true;
                continue;
            }
            queue.budget -= 1;
            result.execution_attempts += 1;
            let created_recipient =
                recipient.filter(|recipient| execution.state.account(recipient, None).is_none());
            if execution
                .apply_verified_transaction(&self.config, transaction)
                .is_err()
            {
                pending[index].slot = Slot::Parked;
                parked.push(index);
                continue;
            }
            records_bytes += bytes;
            result.transactions.push(transaction.clone());
            queue.nonce = transaction.body.nonce + 1;
            let mut revisit = queue.waiting.remove(&queue.nonce).unwrap_or_default();
            // An accepted prerequisite may make an earlier, higher-priority
            // failure executable. Revisit failures before lower-priority
            // entries; each sender's budget bounds the repeated attempts.
            revisit.append(&mut parked);
            for next in revisit {
                if matches!(pending[next].slot, Slot::Waiting | Slot::Parked) {
                    pending[next].slot = Slot::Ready;
                    ready.insert((pending[next].priority.clone(), next));
                }
            }
            if let Some(recipient) = created_recipient {
                // Creating an account lowers the weight of later payments to that
                // account while their exact fees stay fixed. Reprice only those.
                for payment in payments.remove(&recipient).unwrap_or_default() {
                    let slot = pending[payment].slot;
                    if slot == Slot::Done {
                        continue;
                    }
                    if slot == Slot::Ready {
                        ready.remove(&(pending[payment].priority.clone(), payment));
                    }
                    let Ok(quote) =
                        fees::quote(&self.config, &execution.state, pending[payment].transaction)
                    else {
                        pending[payment].slot = Slot::Done;
                        continue;
                    };
                    pending[payment].priority.fee = quote.miner_fee;
                    pending[payment].priority.weight = quote.weight;
                    if slot == Slot::Ready {
                        ready.insert((pending[payment].priority.clone(), payment));
                    }
                }
            }
        }
        let state = match consensus::finish_block(
            &self.config,
            &self.tip_state,
            &self.tip,
            &miner,
            &block_work,
            execution,
        ) {
            Ok(state) => state,
            Err(error) => {
                let (length, state) = self
                    .finish_prefix(&miner, &block_work, &result.transactions)
                    .ok_or(error)?;
                result.transactions.truncate(length);
                state
            }
        };
        Ok((result, state))
    }
    /// Selection is local policy: if the accepted set cannot finish as a block,
    /// keep the longest prefix found by bisection, down to an empty block.
    /// A chain-level failure that also rejects the empty block is returned.
    fn finish_prefix(
        &self,
        miner: &PublicKey,
        block_work: &Amount,
        accepted: &[Transaction],
    ) -> Option<(usize, State)> {
        let finish = |length: usize| -> Result<State> {
            let mut execution =
                consensus::prepare_block(&self.config, &self.tip_state, miner, block_work)?;
            for transaction in &accepted[..length] {
                execution.apply_verified_transaction(&self.config, transaction)?;
            }
            consensus::finish_block(
                &self.config,
                &self.tip_state,
                &self.tip,
                miner,
                block_work,
                execution,
            )
        };
        let mut best = (0, finish(0).ok()?);
        let mut failed = accepted.len();
        while failed - best.0 > 1 {
            let middle = best.0 + (failed - best.0) / 2;
            match finish(middle) {
                Ok(state) => best = (middle, state),
                Err(_) => failed = middle,
            }
        }
        Some(best)
    }

    /// Test and diagnostic helper: a one-transaction template paid to the
    /// transaction's own sender. That sender already has an account, so unlike
    /// mempool admission (`select_transactions` with the node's payout key) this
    /// never reserves miner account-creation weight. Do not use it for admission.
    #[doc(hidden)]
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

/// Selection order: higher actual miner earnings per weight, then txid.
#[derive(Clone)]
struct Priority {
    fee: Amount,
    weight: u64,
    id: Hash,
}
impl Ord for Priority {
    fn cmp(&self, other: &Self) -> Ordering {
        (&other.fee * Amount::from(self.weight))
            .cmp(&(&self.fee * Amount::from(other.weight)))
            .then_with(|| self.id.cmp(&other.id))
    }
}
impl PartialOrd for Priority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for Priority {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Priority {}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Waiting,
    Ready,
    Parked,
    Done,
}
struct Candidate<'a> {
    transaction: &'a Transaction,
    bytes: usize,
    priority: Priority,
    recipient: Option<PublicKey>,
    slot: Slot,
}
struct SenderQueue {
    nonce: u64,
    budget: usize,
    waiting: BTreeMap<u64, Vec<usize>>,
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
    #[test]
    fn skip_links_find_every_ancestor_of_a_side_branch() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut main = Chain::open(&directory.path().join("main.db"), config.clone()).unwrap();
        let mut side = Chain::open(&directory.path().join("side.db"), config).unwrap();
        for n in 0..160 {
            let block = candidate(&main, n);
            if n < 5 {
                side.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        // A side branch that stays behind the main chain's work.
        let mut tip = side.tip_hash();
        for n in 0..150 {
            let block = candidate(&side, 1_000 + n);
            side.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            assert!(
                !main
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
            tip = codec::block_hash(&block);
        }
        let mut expected = BTreeMap::new();
        let mut cursor = tip;
        loop {
            let entry = main.load_entry(&cursor).unwrap().unwrap();
            expected.insert(entry.height, cursor);
            if entry.height == 0 {
                break;
            }
            cursor = entry.header.previous;
        }
        assert_eq!(expected.len(), 156);
        for (height, hash) in expected {
            let mut ancestry = Some((tip, main.load_entry(&tip).unwrap().unwrap()));
            assert_eq!(main.branch_ancestor(&mut ancestry, height).unwrap(), hash);
        }
        for height in 1..4096u64 {
            assert!(skip_height(height) < height);
        }
    }
    #[test]
    fn active_chain_checkpoints_stay_logarithmic_and_monotone() {
        for tip in [1u64, 31, 32, 33, 1_000, 1 << 20, (1 << 40) + 7] {
            let low = tip.saturating_sub(4096);
            let retained = (low..tip)
                .chain((0..64).map(|shift| tip >> shift))
                .filter(|height| checkpoint_retained(*height, tip))
                .collect::<BTreeSet<_>>();
            assert!(retained.contains(&0));
            for height in tip.saturating_sub(DENSE_STATE_CHECKPOINTS - 1)..tip {
                assert!(retained.contains(&height));
            }
            // A state dropped once is never retained by a later tip.
            for height in &retained {
                for later in [tip + 1, tip + 31, tip * 2 + 3] {
                    if checkpoint_retained(*height, later) {
                        assert!(checkpoint_retained(*height, tip));
                    }
                }
            }
        }
        let tip = 1u64 << 20;
        let count = (0..tip)
            .filter(|height| checkpoint_retained(*height, tip))
            .count();
        assert!(count <= DENSE_STATE_CHECKPOINTS as usize + 2 * 20 + 1, "{count}");
    }
    #[test]
    fn stale_tip_hints_are_replaced_by_the_replayed_best_tip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hint.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut first = None;
        for n in 0..3 {
            let block = candidate(&chain, n);
            first.get_or_insert(codec::block_hash(&block));
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let tip = chain.tip_hash();
        drop(chain);
        // An absent block, a lower-work ancestor and a malformed value.
        for hint in [vec![7; 32], first.unwrap().to_vec(), vec![1, 2, 3]] {
            let db = Connection::open(&path).unwrap();
            db.execute("UPDATE metadata SET value=?1 WHERE key='tip'", [&hint])
                .unwrap();
            drop(db);
            let chain = Chain::open(&path, config.clone()).unwrap();
            assert_eq!(chain.tip_hash(), tip);
            let saved: Vec<u8> = chain
                .db
                .query_row("SELECT value FROM metadata WHERE key='tip'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(saved, tip.to_vec());
        }
    }
    #[test]
    fn losing_blocks_failing_replay_move_aside_and_startup_truncates_the_wal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rejected.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut branch = Chain::open(&directory.path().join("branch.db"), config.clone()).unwrap();
        for n in 0..3 {
            let block = candidate(&chain, n);
            if n == 0 {
                branch
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let tip = chain.tip_hash();
        let root = chain.tip_state().root();
        drop(chain);
        // A losing sibling that does not validate, and its child.
        let mut invalid = candidate(&branch, 77);
        invalid.state_root = [9; 32];
        invalid.header.merkle_root = codec::merkle_root(&invalid).unwrap();
        let invalid = Chain::mine(invalid, 100_000).unwrap();
        let mut child = invalid.clone();
        child.header.previous = codec::block_hash(&invalid);
        child.height += 1;
        child.header.timestamp += 15;
        let child = Chain::mine(child, 100_000).unwrap();
        let db = Connection::open(&path).unwrap();
        for block in [&invalid, &child] {
            db.execute(
                "INSERT INTO blocks(hash,bytes,accepted_at) VALUES(?1,?2,?3)",
                params![
                    codec::block_hash(block).as_slice(),
                    codec::encode(block),
                    u64::from(block.header.timestamp)
                ],
            )
            .unwrap();
        }
        drop(db);
        let chain = Chain::open(&path, config.clone()).unwrap();
        assert_eq!(chain.tip_hash(), tip);
        assert_eq!(chain.tip_state().root(), root);
        for block in [&invalid, &child] {
            assert!(chain.block(&codec::block_hash(block)).is_none());
        }
        let moved: i64 = chain
            .db
            .query_row("SELECT COUNT(*) FROM rejected_blocks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(moved, 2);
        // The rebuilt indexes were checkpointed and the log truncated.
        let wal = std::fs::metadata(format!("{}-wal", path.display()))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert_eq!(wal, 0);
        drop(chain);
        let chain = Chain::open(&path, config).unwrap();
        assert_eq!(chain.tip_hash(), tip);
    }
}
