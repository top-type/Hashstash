use crate::{codec, config::Config, consensus, crypto, fees, math, state::State, types::*};
use anyhow::{Context, Result, ensure};
use num_traits::Zero;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
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
/// Side blocks stored without becoming the tip draw on a local budget of this
/// many blocks, refilled by SIDE_BRANCH_BLOCKS_PER_TIP for each new active-chain
/// height, so work-free sibling floods on an easy target stay proportional to
/// chain growth.
pub const SIDE_BRANCH_BURST: u64 = 4096;
pub const SIDE_BRANCH_BLOCKS_PER_TIP: u64 = 4;
/// Proof-of-work checked headers of declined branches held in memory for
/// presync. Eviction drops the leaf whose held chain claims the least work.
/// Headers of a chain that claimed more work than the tip, and headers a
/// header download fetches again after counting that much work, are not
/// counted or evicted: their storage is bounded by that work instead.
pub const MAX_HELD_HEADERS: usize = 32_768;
/// A held chain that already claims more work than the tip by this many
/// next-block works needs no further headers until its blocks arrive.
pub const HELD_LEAD_BLOCKS: u32 = 16;
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
/// A header's timestamp is beyond the future allowance. It may become
/// eligible later, so it is not invalid and its sender is not at fault.
#[derive(Debug)]
pub struct HeaderDeferred;
impl std::fmt::Display for HeaderDeferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block timestamp too far in future; defer until eligible")
    }
}
impl std::error::Error for HeaderDeferred {}
/// Where a header's parent is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderParent {
    /// A validated block: its height and branch work.
    Stored { height: u64, work: Amount },
    /// A held header: its height, the work its held chain claims, and
    /// whether that chain claimed more work than the tip.
    Held {
        height: u64,
        claimed: Amount,
        admitted: bool,
    },
    Unknown,
}
/// The result of holding one header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderHold {
    /// Its block is already validated and stored.
    Stored,
    /// Held; its chain does not claim more work than the tip.
    Held,
    /// Held, and its chain claimed more work than the tip: its blocks are
    /// validated without the side-branch admission policy.
    Admitted,
    /// Not held: its chain already leads the tip by HELD_LEAD_BLOCKS.
    Ahead,
}
/// Local admission policy declined to validate or store a block that would
/// not become the tip. The block is not invalid and is never cached as such.
/// Its proof-of-work checked header is held, so later blocks of its branch
/// can still be received; once held headers claim more work than the tip,
/// the branch's blocks are admitted when delivered again.
#[derive(Debug)]
pub struct SideBranchRefused(&'static str);
impl std::fmt::Display for SideBranchRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "side branch header held, block not stored: {}", self.0)
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

#[cfg(test)]
thread_local! {
    /// Fail block finishing on this thread for accepted sets longer than this.
    pub(crate) static FAIL_FINISH_ABOVE: Cell<Option<usize>> = const { Cell::new(None) };
    /// Run on this thread when a template build starts, before any clearing.
    pub(crate) static TEMPLATE_BUILD_HOOK: RefCell<Option<Box<dyn FnMut()>>> =
        const { RefCell::new(None) };
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
    /// Some sender ran out of operation attempts. A candidate that failed
    /// every attempt it was given counts as refused, not undecided.
    pub budget_exhausted: bool,
    /// Senders with a candidate their budget left entirely unattempted; the
    /// selection did not decide those senders' left-out candidates.
    pub exhausted_senders: BTreeSet<PublicKey>,
    /// The accepted set could not be finished as a block, so only a prefix
    /// was kept and no left-out candidate was decided. Admission selections
    /// never finish the block and are never truncated.
    pub truncated: bool,
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
/// Retained non-genesis heights at least DENSE_STATE_CHECKPOINTS below `tip`:
/// two per doubling of depth, so a caller can visit them without a scan.
fn sparse_checkpoint_heights(tip: u64) -> Vec<u64> {
    let mut heights = Vec::new();
    let mut depth = DENSE_STATE_CHECKPOINTS;
    while depth < tip {
        // Every depth in [depth, 2*depth) shares checkpoint_retained's step.
        let step = 1u64 << (62 - depth.leading_zeros());
        let low = tip - (2 * depth - 1).min(tip - 1);
        let mut height = low.div_ceil(step) * step;
        while height <= tip - depth {
            heights.push(height);
            height += step;
        }
        depth *= 2;
    }
    heights
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
    /// Active-chain block at the last of those heights, where the walk met
    /// the active chain; a reorganization below it makes the progress stale.
    meeting: Hash,
    /// Latest reconstructed ancestor.
    base: Option<(Hash, Arc<State>)>,
}
/// A header held without its block: checked against its parent's required
/// target when that parent is stored, and otherwise for its own proof of work.
struct HeldHeader {
    header: Header,
    height: u64,
    /// Stored block where this held chain begins; body downloads resume there.
    root: Hash,
    /// Work claimed by this header and its held ancestors.
    contributed: Amount,
    /// The root's validated work plus `contributed`.
    claimed: Amount,
    /// The held chain once claimed more work than the tip: its blocks are
    /// validated without the side-branch admission policy, and the header
    /// is persisted.
    admitted: bool,
    /// The header download holding this header after counting that its
    /// branch claims more work than the tip, or zero.
    pin: u64,
}
impl HeldHeader {
    fn evictable(&self) -> bool {
        !self.admitted && self.pin == 0
    }
}
/// Header presync for branches the admission policy declined or that a
/// header download proved heavier than the tip. Evictable headers are
/// bounded by count; admitted and pinned ones by the work they claim.
#[derive(Default)]
struct HeldHeaders {
    headers: BTreeMap<Hash, HeldHeader>,
    children: BTreeMap<Hash, BTreeSet<Hash>>,
    /// Evictable held headers without held children, by contributed work.
    leaves: BTreeSet<(Amount, Hash)>,
    /// Number of evictable held headers.
    evictable: usize,
    /// Admitted headers without admitted children, by claimed work.
    tips: BTreeSet<(Amount, Hash)>,
    /// Blocks outside the held set with admitted held children, and how
    /// many: where admitted chains' body downloads resume.
    roots: BTreeMap<Hash, usize>,
}
impl HeldHeaders {
    fn previous(&self, hash: &Hash) -> Option<Hash> {
        self.headers.get(hash).map(|held| held.header.previous)
    }
    fn has_admitted_child(&self, hash: &Hash) -> bool {
        self.children
            .get(hash)
            .is_some_and(|children| children.iter().any(|child| self.admitted(child)))
    }
    fn add_root(&mut self, root: Hash, count: usize) {
        if count > 0 {
            *self.roots.entry(root).or_default() += count;
        }
    }
    fn drop_root(&mut self, root: &Hash) {
        if let Some(count) = self.roots.get_mut(root) {
            *count -= 1;
            if *count == 0 {
                self.roots.remove(root);
            }
        }
    }
    /// Make a held header evictable or not, keeping the leaf index exact.
    fn reclassify(&mut self, hash: &Hash, update: impl FnOnce(&mut HeldHeader)) {
        let Some(held) = self.headers.get_mut(hash) else {
            return;
        };
        let before = held.evictable();
        update(held);
        let (after, contributed) = (held.evictable(), held.contributed.clone());
        let childless = !self.children.contains_key(hash);
        match (before, after) {
            (true, false) => {
                self.evictable -= 1;
                self.leaves.remove(&(contributed, *hash));
            }
            (false, true) => {
                self.evictable += 1;
                if childless {
                    self.leaves.insert((contributed, *hash));
                }
            }
            _ => {}
        }
    }
    /// Insert a new non-admitted header whose parent is stored or held.
    /// Eviction is left to `evict`, so a header about to be admitted is never
    /// evicted first.
    fn insert(&mut self, hash: Hash, held: HeldHeader) -> bool {
        if self.headers.contains_key(&hash) {
            return false;
        }
        debug_assert!(!held.admitted);
        let previous = held.header.previous;
        if let Some(parent) = self.headers.get(&previous)
            && parent.evictable()
        {
            self.leaves.remove(&(parent.contributed.clone(), previous));
        }
        self.children.entry(previous).or_default().insert(hash);
        if held.evictable() {
            self.evictable += 1;
            self.leaves.insert((held.contributed.clone(), hash));
        }
        self.headers.insert(hash, held);
        true
    }
    /// Only evictable leaves are evicted, so every held chain stays linked
    /// to its root.
    fn evict(&mut self) {
        while self.evictable > MAX_HELD_HEADERS {
            let Some((_, weakest)) = self.leaves.pop_first() else {
                break;
            };
            self.remove(&weakest);
        }
    }
    fn remove(&mut self, hash: &Hash) -> Option<HeldHeader> {
        let held = self.headers.remove(hash)?;
        let previous = held.header.previous;
        if held.evictable() {
            self.evictable -= 1;
            self.leaves.remove(&(held.contributed.clone(), *hash));
        }
        if held.admitted {
            self.tips.remove(&(held.claimed.clone(), *hash));
            if !self.headers.contains_key(&previous) {
                self.drop_root(&previous);
            }
        }
        if let Some(siblings) = self.children.get_mut(&previous) {
            siblings.remove(hash);
            if siblings.is_empty() {
                self.children.remove(&previous);
                if let Some(parent) = self.headers.get(&previous)
                    && parent.evictable()
                {
                    self.leaves.insert((parent.contributed.clone(), previous));
                }
            }
        }
        if let Some(parent) = self.headers.get(&previous)
            && parent.admitted
            && !self.has_admitted_child(&previous)
        {
            self.tips.insert((parent.claimed.clone(), previous));
        }
        // Remaining children now begin where this header's block is stored.
        let admitted = self.children.get(hash).map_or(0, |children| {
            children.iter().filter(|child| self.admitted(child)).count()
        });
        self.add_root(*hash, admitted);
        Some(held)
    }
    /// Drop a held header that failed validation and every held descendant.
    fn remove_branch(&mut self, hash: &Hash) -> Vec<(Hash, HeldHeader)> {
        let mut removed = Vec::new();
        let mut pending = vec![*hash];
        while let Some(next) = pending.pop() {
            pending.extend(self.children.get(&next).into_iter().flatten().copied());
            if let Some(held) = self.remove(&next) {
                removed.push((next, held));
            }
        }
        self.roots.remove(hash);
        removed
    }
    /// Mark a header and its held ancestors admitted; return those newly marked.
    fn admit(&mut self, hash: &Hash) -> Vec<Hash> {
        let mut marked = Vec::new();
        let mut cursor = *hash;
        while self
            .headers
            .get(&cursor)
            .is_some_and(|held| !held.admitted)
        {
            self.reclassify(&cursor, |held| held.admitted = true);
            marked.push(cursor);
            cursor = self.previous(&cursor).expect("held header");
        }
        if let Some(&top) = marked.first() {
            let claimed = self.headers[&top].claimed.clone();
            self.tips.insert((claimed, top));
            match self.headers.get(&cursor) {
                Some(stop) => {
                    let claimed = stop.claimed.clone();
                    self.tips.remove(&(claimed, cursor));
                }
                None => self.add_root(cursor, 1),
            }
        }
        marked
    }
    fn admitted(&self, hash: &Hash) -> bool {
        self.headers.get(hash).is_some_and(|header| header.admitted)
    }
    /// Release a header download's pin: its headers become evictable.
    fn unpin(&mut self, pin: u64) {
        let pinned: Vec<Hash> = self
            .headers
            .iter()
            .filter(|(_, held)| held.pin == pin)
            .map(|(hash, _)| *hash)
            .collect();
        for hash in pinned {
            self.reclassify(&hash, |held| held.pin = 0);
        }
        self.evict();
    }
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
    held: HeldHeaders,
    // Last identifier handed to a header download for its pinned headers.
    next_pin: u64,
    // Remaining side-branch admissions and the active height that last refilled them.
    side_budget: u64,
    side_budget_height: u64,
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
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_size_limit=67108864; CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS blocks(seq INTEGER PRIMARY KEY AUTOINCREMENT, hash BLOB NOT NULL UNIQUE, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS rejected_blocks(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL, reason TEXT NOT NULL); CREATE TABLE IF NOT EXISTS held_headers(hash BLOB PRIMARY KEY, header BLOB NOT NULL, height INTEGER NOT NULL);")?;
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
            held: HeldHeaders::default(),
            next_pin: 0,
            side_budget: SIDE_BRANCH_BURST,
            side_budget_height: 0,
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
        // Admitted held headers of chains still competing with the tip are
        // restored before stale branches are pruned, so their roots stay.
        chain.load_held()?;
        chain.prune_held()?;
        let pruned = chain.prune_stale_branches()?;
        chain.refresh_capacity();
        if pruned > 0 {
            eprintln!("Pruned {pruned} stored losing-branch block(s) that fell out of competition");
        }
        chain.side_budget_height = chain.tip_height();
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
    /// The newest retained active-chain checkpoint at or below `height`, at most
    /// about half that height's depth below it. Like cached_state, it never replays.
    pub fn checkpoint_at_or_below(&self, height: u64) -> Option<(Hash, Arc<State>)> {
        self.checkpoints
            .borrow()
            .range(..=height)
            .next_back()
            .filter(|(height, (hash, _))| self.hash_at_height(**height) == Some(*hash))
            .map(|(_, (hash, state))| (*hash, state.clone()))
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
            meeting: ZERO_HASH,
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
                replay.meeting = cursor;
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
        // Resumed progress must still lead to the block where the walk met the
        // active chain; a reorganization above the cursor would otherwise
        // replay the new branch instead.
        if replay.canonical.0 <= replay.canonical.1
            && self.canonical_hash(replay.canonical.1)? != Some(replay.meeting)
        {
            return Err(StaleReplay.into());
        }
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
        if hash != replay.target {
            return Err(StaleReplay.into());
        }
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
            // Only new active-chain heights refill side-branch admissions.
            if entry.height > self.side_budget_height {
                let gained = entry.height - self.side_budget_height;
                self.side_budget = gained
                    .saturating_mul(SIDE_BRANCH_BLOCKS_PER_TIP)
                    .saturating_add(self.side_budget)
                    .min(SIDE_BRANCH_BURST);
                self.side_budget_height = entry.height;
            }
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
            // Recently validated states of the new active chain become
            // checkpoints, at the dense heights and at every deeper retained one.
            let dense = height.saturating_sub(DENSE_STATE_CHECKPOINTS)..height;
            for height in sparse_checkpoint_heights(height).into_iter().chain(dense) {
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
        // A chain whose held headers claimed more work than the tip resumes
        // its body downloads at a stored root: the next body fits that root's
        // capacity, whatever the branch's distance from the tip was before.
        let held = self
            .held
            .roots
            .keys()
            .filter_map(|root| self.load_entry(root).ok().flatten())
            .map(|entry| entry.capacity)
            .max()
            .unwrap_or(0);
        self.known_block_bytes = self
            .branches
            .values()
            .filter(|leaf| &leaf.block_work * CAPACITY_BRANCH_WORK_RATIO >= next)
            .map(|leaf| leaf.capacity)
            .fold(self.tip_entry.capacity.max(held), u64::max);
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
        self.competitive(&branch, work, &next).map_err(SideBranchRefused)?;
        if self.side_budget == 0 {
            return Err(SideBranchRefused("side-branch admission budget is spent").into());
        }
        Ok(())
    }
    /// Whether a losing branch ending in a block of `work` stays worth keeping.
    fn competitive(
        &self,
        branch: &Amount,
        work: &Amount,
        next: &Amount,
    ) -> std::result::Result<(), &'static str> {
        if work * SIDE_BRANCH_WORK_RATIO < *next {
            return Err("block work is far below the active chain's");
        }
        if branch + work * SIDE_BRANCH_CATCH_UP_BLOCKS < self.tip_entry.work {
            return Err("branch cannot plausibly overtake the active chain");
        }
        Ok(())
    }
    /// Hold a header without its block, so its branch can still be presynced
    /// from peers. Held headers are never executed. A chain that claims more
    /// work than the tip is admitted, proven by proof of work alone; its
    /// headers are persisted and its bodies validated when they arrive.
    fn hold(&mut self, hash: Hash, held: HeldHeader) -> Result<HeaderHold> {
        let overtakes = held.claimed > self.tip_entry.work;
        self.held.insert(hash, held);
        let hold = if overtakes {
            let marked = self.held.admit(&hash);
            self.persist_held(&marked)?;
            // Its stored root may raise the capacity allowance.
            self.refresh_capacity();
            HeaderHold::Admitted
        } else {
            HeaderHold::Held
        };
        self.held.evict();
        Ok(hold)
    }
    /// Write newly admitted held headers, so a restart keeps them.
    fn persist_held(&mut self, hashes: &[Hash]) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        // A savepoint also nests inside the startup transaction.
        let transaction = self.db.savepoint()?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT OR REPLACE INTO held_headers(hash,header,height) VALUES(?1,?2,?3)",
            )?;
            for hash in hashes {
                let held = &self.held.headers[hash];
                insert.execute(params![
                    hash.as_slice(),
                    codec::header_bytes(&held.header).as_slice(),
                    held.height
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }
    /// Delete removed held headers that were persisted: the admitted ones.
    fn unpersist_held(&mut self, removed: &[(Hash, HeldHeader)]) -> Result<()> {
        if !removed.iter().any(|(_, held)| held.admitted) {
            return Ok(());
        }
        let transaction = self.db.savepoint()?;
        {
            let mut delete =
                transaction.prepare_cached("DELETE FROM held_headers WHERE hash=?1")?;
            for (hash, held) in removed {
                if held.admitted {
                    delete.execute([hash.as_slice()])?;
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }
    /// Extend a held chain with a child whose parent is itself only held. Only
    /// the header's structure and its own proof of work can be checked here.
    fn hold_child(&mut self, block: &Block, now: u64) -> Result<()> {
        let parent = &self.held.headers[&block.header.previous];
        ensure!(block.height == parent.height + 1, "invalid block height");
        self.hold_header(block.header.clone(), now, 0)?;
        Ok(())
    }
    /// Where a header's parent is known: stored, held, or neither.
    pub fn header_parent(&self, hash: &Hash) -> Result<HeaderParent> {
        if let Some(entry) = self.load_entry(hash)? {
            return Ok(HeaderParent::Stored {
                height: entry.height,
                work: entry.work.clone(),
            });
        }
        Ok(match self.held.headers.get(hash) {
            Some(held) => HeaderParent::Held {
                height: held.height,
                claimed: held.claimed.clone(),
                admitted: held.admitted,
            },
            None => HeaderParent::Unknown,
        })
    }
    /// Check a header without its block and return its work. After a stored
    /// parent it must meet that parent's required target and median time;
    /// after a parent known only as a header, which cannot be executed, its
    /// own proof of work within the network limit. `height` is its parent's
    /// height plus one. A timestamp beyond the future allowance is deferred.
    pub fn check_header(&self, header: &Header, height: u64, now: u64) -> Result<Amount> {
        ensure!(height <= self.config.max_height, "invalid block height");
        ensure!(
            codec::is_current_header(header),
            "unsupported header version bits"
        );
        if header.timestamp as u64 > now.saturating_add(self.config.future_seconds as u64) {
            return Err(HeaderDeferred.into());
        }
        let target = match self.load_entry(&header.previous)? {
            Some(parent) => {
                ensure!(height == parent.height + 1, "invalid block height");
                ensure!(
                    header.timestamp > self.median(header.previous)?,
                    "timestamp must exceed median past time"
                );
                let target = self.target(&parent)?;
                ensure!(
                    header.bits == math::bits_from_target(&target),
                    "incorrect difficulty target"
                );
                target
            }
            None => {
                let target = math::target_from_bits(header.bits)?;
                ensure!(
                    target <= math::target_from_bits(self.config.limit_bits)?,
                    "block target exceeds the network limit"
                );
                target
            }
        };
        math::check_pow(header, &target)?;
        Ok(math::work(&target))
    }
    /// Hold a header whose parent is stored or held, after `check_header`.
    /// A nonzero `pin` keeps it from eviction until released: a header
    /// download fetches a branch again only after counting that it claims
    /// more work than the tip. A chain already leading the tip by
    /// HELD_LEAD_BLOCKS next-block works is not extended.
    pub fn hold_header(&mut self, header: Header, now: u64, pin: u64) -> Result<HeaderHold> {
        let hash = crypto::sha256d(&codec::header_bytes(&header));
        if self.load_entry(&hash)?.is_some() {
            return Ok(HeaderHold::Stored);
        }
        if let Some(held) = self.held.headers.get(&hash) {
            if held.admitted {
                return Ok(HeaderHold::Admitted);
            }
            if pin != 0 {
                self.held.reclassify(&hash, |held| held.pin = pin);
            }
            return Ok(HeaderHold::Held);
        }
        let (height, root, contributed, claimed) = match self.held.headers.get(&header.previous) {
            Some(parent) => {
                if parent.admitted {
                    let next = math::work(&self.target(&self.tip_entry)?);
                    if parent.claimed > &self.tip_entry.work + next * HELD_LEAD_BLOCKS {
                        return Ok(HeaderHold::Ahead);
                    }
                }
                (
                    parent.height + 1,
                    parent.root,
                    parent.contributed.clone(),
                    parent.claimed.clone(),
                )
            }
            None => {
                let parent = self
                    .load_entry(&header.previous)?
                    .context("held header parent unknown")?;
                (
                    parent.height + 1,
                    header.previous,
                    Amount::zero(),
                    parent.work.clone(),
                )
            }
        };
        let work = self.check_header(&header, height, now)?;
        self.hold(
            hash,
            HeldHeader {
                header,
                height,
                root,
                contributed: contributed + &work,
                claimed: claimed + work,
                admitted: false,
                pin,
            },
        )
    }
    /// A new identifier for a header download's pinned headers.
    pub fn new_header_pin(&mut self) -> u64 {
        self.next_pin += 1;
        self.next_pin
    }
    /// A header download ended: its pinned headers that were not admitted
    /// become evictable presync headers.
    pub fn release_header_pin(&mut self, pin: u64) {
        if pin != 0 {
            self.held.unpin(pin);
        }
    }
    /// The admitted held chains' best headers, most claimed work first: a
    /// header request continues after them.
    pub fn admitted_header_tips(&self, limit: usize) -> Vec<Hash> {
        self.held
            .tips
            .iter()
            .rev()
            .take(limit)
            .map(|(_, hash)| *hash)
            .collect()
    }
    /// A stored block's header, from the header index without its body. A
    /// header reply reads thousands, so they bypass the metadata cache.
    pub fn block_header(&self, hash: &Hash) -> Result<Option<Header>> {
        Ok(Self::read_entry(&self.db, hash)?.map(|entry| entry.header.clone()))
    }
    /// The locator entry for a peer download cursor: a stored block, a held
    /// header whose branch is still being presynced, or, once held headers
    /// claim more work than the tip, the stored block where that branch's body
    /// downloads resume. None for a cursor this chain no longer knows.
    pub fn download_cursor(&self, hash: &Hash) -> Result<Option<Hash>> {
        if self.load_entry(hash)?.is_some() {
            return Ok(Some(*hash));
        }
        Ok(self.held.headers.get(hash).map(|header| {
            if header.admitted {
                header.root
            } else {
                *hash
            }
        }))
    }
    /// Headers held for presync, admitted or pinned ones included.
    pub fn held_header_count(&self) -> usize {
        self.held.headers.len()
    }
    /// Held headers of chains that claimed more work than the tip; these are
    /// persisted and survive a restart.
    pub fn admitted_header_count(&self) -> usize {
        self.held
            .headers
            .values()
            .filter(|held| held.admitted)
            .count()
    }
    /// Drop admitted held chains whose best header now claims less work than
    /// the tip by more than CAPACITY_BRANCH_MARGIN_BLOCKS next-block works:
    /// they no longer compete, so they neither raise the capacity allowance
    /// nor stay on disk.
    fn prune_held(&mut self) -> Result<()> {
        let next = math::work(&self.target(&self.tip_entry)?);
        let floor = &next * CAPACITY_BRANCH_MARGIN_BLOCKS;
        let mut removed = Vec::new();
        while let Some((claimed, tip)) = self.held.tips.first().cloned()
            && claimed + &floor < self.tip_entry.work
        {
            // The header and any presync headers after it go, then its
            // ancestors down to another held branch or the stored root.
            let mut parent = self.held.previous(&tip);
            removed.extend(self.held.remove_branch(&tip));
            while let Some(hash) = parent
                && !self.held.children.contains_key(&hash)
                && let Some(held) = self.held.remove(&hash)
            {
                parent = Some(held.header.previous);
                removed.push((hash, held));
            }
        }
        self.unpersist_held(&removed)?;
        if !removed.is_empty() {
            self.refresh_capacity();
        }
        Ok(())
    }
    /// Restore the admitted held headers a previous run persisted. Each must
    /// still follow a stored block or a restored header and meet its own
    /// proof of work; others are deleted.
    fn load_held(&mut self) -> Result<()> {
        let rows: Vec<(Vec<u8>, Vec<u8>, u64)> = self
            .db
            .prepare("SELECT hash,header,height FROM held_headers ORDER BY height,hash")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let limit = math::target_from_bits(self.config.limit_bits)?;
        let mut dropped = Vec::new();
        for (raw, bytes, height) in rows {
            let restored = (|| -> Result<Option<(Hash, HeldHeader)>> {
                let header = crate::peer_wire::header_from_bytes(&bytes)?;
                let hash = crypto::sha256d(&codec::header_bytes(&header));
                ensure!(raw == hash, "held header hash mismatch");
                if self.load_entry(&hash)?.is_some() {
                    return Ok(None);
                }
                let (root, contributed, claimed) = match self.held.headers.get(&header.previous) {
                    Some(parent) => {
                        ensure!(parent.height + 1 == height, "held header height mismatch");
                        (parent.root, parent.contributed.clone(), parent.claimed.clone())
                    }
                    None => {
                        let parent = self
                            .load_entry(&header.previous)?
                            .context("held header parent unknown")?;
                        ensure!(parent.height + 1 == height, "held header height mismatch");
                        (header.previous, Amount::zero(), parent.work.clone())
                    }
                };
                let target = math::target_from_bits(header.bits)?;
                ensure!(target <= limit, "block target exceeds the network limit");
                math::check_pow(&header, &target)?;
                let work = math::work(&target);
                Ok(Some((
                    hash,
                    HeldHeader {
                        header,
                        height,
                        root,
                        contributed: contributed + &work,
                        claimed: claimed + work,
                        admitted: false,
                        pin: 0,
                    },
                )))
            })();
            match restored {
                Ok(Some((hash, held))) => {
                    self.held.insert(hash, held);
                    self.held.admit(&hash);
                }
                // A row whose parent is gone, whose block is now stored, or
                // that fails its checks is not restored.
                _ => dropped.push(raw),
            }
        }
        for raw in dropped {
            self.db
                .execute("DELETE FROM held_headers WHERE hash=?1", [raw.as_slice()])?;
        }
        Ok(())
    }
    /// Delete stored losing-branch blocks that a child at their required target
    /// could no longer extend competitively, unless a kept descendant needs them.
    /// Children follow their parents in storage order, so one reverse pass
    /// suffices. Peers can deliver a pruned branch again through header presync.
    fn prune_stale_branches(&mut self) -> Result<u64> {
        let next = math::work(&self.target(&self.tip_entry)?);
        let mut needed = BTreeSet::new();
        let mut sequence = i64::MAX;
        let mut pruned = 0u64;
        loop {
            let row: Option<(i64, Vec<u8>)> = self
                .db
                .query_row(
                    "SELECT seq,hash FROM blocks WHERE seq<?1 ORDER BY seq DESC LIMIT 1",
                    [sequence],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((seq, raw)) = row else {
                break;
            };
            sequence = seq;
            let hash: Hash = raw.as_slice().try_into().context("malformed block hash")?;
            let entry = Self::read_entry(&self.db, &hash)?.context("stored block entry absent")?;
            if self.canonical_hash(entry.height)? == Some(hash) {
                needed.remove(&hash);
                continue;
            }
            let child = math::work(&self.target(&entry)?);
            let branch = &entry.work + &child;
            // A stored root of an admitted held chain is where its body
            // downloads resume.
            if needed.remove(&hash)
                || self.held.roots.contains_key(&hash)
                || self.competitive(&branch, &child, &next).is_ok()
            {
                needed.insert(entry.header.previous);
                continue;
            }
            self.db
                .prepare_cached("DELETE FROM blocks WHERE hash=?1")?
                .execute([hash.as_slice()])?;
            self.db
                .prepare_cached("DELETE FROM entry_index WHERE hash=?1")?
                .execute([hash.as_slice()])?;
            pruned += 1;
            if pruned % INDEX_REBUILD_BATCH == 0 {
                self.db.execute_batch("COMMIT; BEGIN IMMEDIATE;")?;
            }
        }
        if pruned > 0 {
            // Pruned hashes may sit in the hot caches; they are only caches.
            *self.entries.get_mut() = EntryCache::default();
            *self.cache.get_mut() = StateCache::default();
            let kept: Vec<Hash> = self.branches.keys().copied().collect();
            for hash in kept {
                if Self::read_entry(&self.db, &hash)?.is_none() {
                    self.branches.remove(&hash);
                }
            }
            self.refresh_capacity();
        }
        Ok(pruned)
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
        if self.held.headers.contains_key(&block.header.previous) {
            self.hold_child(&block, now)?;
            return Err(SideBranchRefused("parent is a held side-branch header").into());
        }
        // A held chain that claimed more work than the tip is not declined again.
        let admitted = self.held.admitted(&hash);
        let (entry, state) = match self.validate_block(&block, now, !admitted) {
            Ok(valid) => valid,
            Err(error) => {
                if error.is::<SideBranchRefused>() {
                    // The header checks passed against the stored parent, so
                    // the block's compact target is exactly its required one.
                    let parent = self
                        .load_entry(&block.header.previous)?
                        .context("unknown parent")?;
                    let work = math::work(&math::target_from_bits(block.header.bits)?);
                    let claimed = &parent.work + &work;
                    self.hold(
                        hash,
                        HeldHeader {
                            header: block.header.clone(),
                            height: block.height,
                            root: block.header.previous,
                            contributed: work,
                            claimed,
                            admitted: false,
                            pin: 0,
                        },
                    )?;
                } else if error.downcast_ref::<PermanentBlockError>().is_some() {
                    self.remember_invalid(identity, &error);
                    // Only a body its header commits to proves the header
                    // invalid; any other body disqualifies just itself.
                    if codec::merkle_root(&block).ok() == Some(block.header.merkle_root) {
                        let removed = self.held.remove_branch(&hash);
                        self.unpersist_held(&removed)?;
                        self.refresh_capacity();
                    }
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
        // A stored block no longer needs its held header.
        transaction.execute("DELETE FROM held_headers WHERE hash=?1", [hash.as_slice()])?;
        transaction.commit()?;
        if !best && !admitted {
            self.side_budget = self.side_budget.saturating_sub(1);
        }
        self.held.remove(&hash);
        self.record(hash, block, Arc::new(entry), state, best);
        if best && let Err(error) = self.prune_held() {
            // Housekeeping only: the accepted block is already committed.
            eprintln!("Held header pruning deferred: {error:#}");
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
    /// Capture a template for the tip's next block that is finished without
    /// the chain (see [TemplateJob]).
    pub fn template_job(
        &self,
        miner: PublicKey,
        transactions: Vec<Transaction>,
        timestamp: u32,
    ) -> Result<TemplateJob> {
        ensure!(crypto::valid_key(&miner), "invalid miner key");
        ensure!(
            transactions.len() <= self.config.max_signatures,
            "signature limit exceeded"
        );
        let target = self.target(&self.tip_entry)?;
        Ok(TemplateJob {
            config: self.config.clone(),
            parent: self.tip_state.clone(),
            header: self.child_header(&target)?,
            block_work: math::work(&target),
            miner,
            timestamp,
            transactions,
        })
    }
    /// The header fields of the tip's next block, which the tip alone decides.
    fn child_header(&self, target: &Amount) -> Result<ChildHeader> {
        Ok(ChildHeader {
            previous: self.tip,
            height: self.tip_entry.height + 1,
            bits: math::bits_from_target(target),
            // Header timestamps are u32: the chain cannot extend once median
            // past time reaches u32::MAX (2106-02-07 UTC), a protocol lifetime limit.
            earliest: self
                .median(self.tip)?
                .checked_add(1)
                .context("timestamp exhausted")?,
            block_bytes: self.tip_state.settings.block_bytes,
        })
    }
    fn template_from_execution(
        &self,
        miner: PublicKey,
        transactions: Vec<Transaction>,
        timestamp: u32,
        state_root: Hash,
    ) -> Result<Block> {
        let target = self.target(&self.tip_entry)?;
        self.child_header(&target)?
            .assemble(miner, transactions, timestamp, state_root)
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
        self.select_authenticated(miner, candidates, limit, &HashSet::new())
    }
    /// Selection that skips only the signature check of candidates whose
    /// transaction id is in `authenticated`. The id hashes the exact signed
    /// bytes, signature included, so an earlier successful check by the caller
    /// still holds; every other selection and validity rule applies unchanged.
    pub fn select_authenticated(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        authenticated: &HashSet<Hash>,
    ) -> Result<SelectionResult> {
        self.select_executed(miner, candidates, limit, authenticated)
            .map(|(selected, _)| selected)
    }
    /// Mempool admission: the selection [Chain::select_authenticated] makes,
    /// without finishing the block. Every rule that decides which candidates
    /// a block includes runs while they are applied: signatures, size, anchor
    /// and lifetime, fee quotes, opening-funds reservation, nonce order,
    /// weight (with the miner-account reserve), operation validity and each
    /// sender's attempt budget. Finishing only settles the included trades
    /// and pays the miner. A trade's inputs and fee are reserved from
    /// block-opening balances, so its fill never decides whether any
    /// transaction is valid, and admission needs no batch clearing. Whenever
    /// the block finishes, which nothing is known to prevent, the result is
    /// exactly that selection. It is never truncated: a block that cannot be
    /// finished is cut short when its template is built ([TemplateJob]).
    pub fn select_admission(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        authenticated: &HashSet<Hash>,
    ) -> Result<SelectionResult> {
        self.select_open(miner, candidates, limit, authenticated)
            .map(|(selected, _, _)| selected)
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
        self.select_template_authenticated(miner, candidates, limit, timestamp, &HashSet::new())
    }
    /// `select_template` with the signature-check skip of `select_authenticated`.
    pub fn select_template_authenticated(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        timestamp: u32,
        authenticated: &HashSet<Hash>,
    ) -> Result<(SelectionResult, Block)> {
        let (selected, state) = self.select_executed(miner, candidates, limit, authenticated)?;
        let block = self.template_from_execution(
            miner,
            selected.transactions.clone(),
            timestamp,
            state.root(),
        )?;
        Ok((selected, block))
    }
    /// The checks that the next block's opening alone decides, for each
    /// transaction on its own: a fee quote, the least minimum fee it could
    /// need in that block (an earlier transaction may still create its payment
    /// recipient), and opening funds for its declared inputs and fee. Settings
    /// are fixed within a block, accounts are never removed and commitments
    /// only grow, so a transaction failing any of these is never selected on
    /// the current tip, whatever else is pending. This costs one block
    /// opening, without signatures or execution.
    pub fn opening_screen(
        &self,
        miner: PublicKey,
        transactions: &[&Transaction],
    ) -> Result<Vec<Result<()>>> {
        let target = self.target(&self.tip_entry)?;
        let execution = consensus::prepare_block(
            &self.config,
            &self.tip_state,
            &miner,
            &math::work(&target),
        )?;
        Ok(transactions
            .iter()
            .map(|transaction| {
                let quote = fees::quote(&self.config, &execution.state, transaction)?;
                // Account creation adds exactly its rate to the rounded minimum.
                ensure!(
                    transaction.body.fee >= &quote.minimum_fee - &quote.account_creation_fee,
                    "signed fee is below the mandatory minimum"
                );
                ensure!(
                    execution.opening_funds_cover(transaction),
                    "opening balance does not cover its inputs and fee"
                );
                Ok(())
            })
            .collect())
    }
    fn select_executed(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        authenticated: &HashSet<Hash>,
    ) -> Result<(SelectionResult, State)> {
        let (mut result, execution, block_work) =
            self.select_open(miner, candidates, limit, authenticated)?;
        let finisher = Finisher {
            config: &self.config,
            parent: &self.tip_state,
            previous: &self.tip,
            miner: &miner,
            block_work: &block_work,
        };
        let accepted = result.transactions.len();
        let state = match finisher.finish(execution, accepted) {
            Ok(state) => state,
            Err(error) => {
                let Some((length, state)) = finisher.prefix(&result.transactions) else {
                    return Err(error);
                };
                eprintln!("Selection kept {length} of {accepted} transactions: {error:#}");
                result.transactions.truncate(length);
                // The dropped tail was never judged invalid; it stays pending.
                result.truncated = true;
                state
            }
        };
        Ok((result, state))
    }
    /// The selection loop, leaving the block unfinished: the returned
    /// execution has applied exactly the selected transactions, in order.
    fn select_open(
        &self,
        miner: PublicKey,
        candidates: &[Transaction],
        limit: usize,
        authenticated: &HashSet<Hash>,
    ) -> Result<(SelectionResult, consensus::BlockExecution, Amount)> {
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
            exhausted_senders: BTreeSet::new(),
            truncated: false,
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
            if !authenticated.contains(&id) {
                result.signatures_checked += 1;
                if crypto::verify(&self.tip_state.chain_id, transaction).is_err() {
                    continue;
                }
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
                attempted: false,
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
                // A candidate that already failed its attempts stays refused;
                // only one never tried leaves its sender undecided.
                if !pending[index].attempted {
                    result.exhausted_senders.insert(transaction.body.sender);
                }
                continue;
            }
            queue.budget -= 1;
            result.execution_attempts += 1;
            pending[index].attempted = true;
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
        Ok((result, execution, block_work))
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

/// Finishing a child of one parent state. This is the only step of selection
/// or template construction that clears batch trades.
struct Finisher<'a> {
    config: &'a Config,
    parent: &'a State,
    previous: &'a Hash,
    miner: &'a PublicKey,
    block_work: &'a Amount,
}
impl Finisher<'_> {
    fn finish(&self, execution: consensus::BlockExecution, accepted: usize) -> Result<State> {
        #[cfg(test)]
        ensure!(
            FAIL_FINISH_ABOVE.with(|limit| limit.get().is_none_or(|limit| accepted <= limit)),
            "injected block finishing failure"
        );
        #[cfg(not(test))]
        let _ = accepted;
        consensus::finish_block(
            self.config,
            self.parent,
            self.previous,
            self.miner,
            self.block_work,
            execution,
        )
    }
    /// Selection is local policy: if the accepted set cannot finish as a block,
    /// keep the longest prefix found by bisection, down to an empty block.
    /// A chain-level failure that also rejects the empty block is returned.
    fn prefix(&self, accepted: &[Transaction]) -> Option<(usize, State)> {
        let finish = |length: usize| -> Result<State> {
            let mut execution =
                consensus::prepare_block(self.config, self.parent, self.miner, self.block_work)?;
            for transaction in &accepted[..length] {
                execution.apply_verified_transaction(self.config, transaction)?;
            }
            self.finish(execution, length)
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
}

/// The header fields of the tip's next block, which the tip alone decides.
#[derive(Clone)]
struct ChildHeader {
    previous: Hash,
    height: u64,
    bits: u32,
    /// The least timestamp the median-past-time rule allows.
    earliest: u32,
    block_bytes: u64,
}
impl ChildHeader {
    fn assemble(
        &self,
        miner: PublicKey,
        transactions: Vec<Transaction>,
        timestamp: u32,
        state_root: Hash,
    ) -> Result<Block> {
        let mut block = Block {
            header: Header {
                version: codec::HEADER_VERSION,
                previous: self.previous,
                merkle_root: ZERO_HASH,
                timestamp: timestamp.max(self.earliest),
                bits: self.bits,
                nonce: 0,
            },
            height: self.height,
            miner,
            state_root,
            extranonce: [0; 8],
            transactions,
        };
        block.header.merkle_root = codec::merkle_root(&block)?;
        ensure!(
            codec::body_size(&block)? as u64 <= self.block_bytes,
            "block body exceeds byte limit"
        );
        Ok(block)
    }
}

/// A template for the tip's next block, captured by [Chain::template_job]
/// so that it can be finished without the chain. Finishing clears the
/// included batch trades, which can take long at large magnitudes, so a node
/// builds templates outside its chain lock. The transactions must be a
/// selection made against this tip, such as [Chain::select_admission]
/// returns: they are replayed in order without signature or anchor checks,
/// as the selection's own execution applied them, and the block finishes
/// exactly as that selection's would. Received blocks still pass the
/// normal independent validation path.
pub struct TemplateJob {
    config: Config,
    parent: Arc<State>,
    header: ChildHeader,
    block_work: Amount,
    miner: PublicKey,
    timestamp: u32,
    transactions: Vec<Transaction>,
}
/// A built template, and how many of its job's transactions it kept: all of
/// them unless the block could not be finished with them.
#[derive(Debug)]
pub struct TemplateBuild {
    pub block: Block,
    pub kept: usize,
}
impl TemplateJob {
    /// The parent block the template extends.
    pub fn previous(&self) -> Hash {
        self.header.previous
    }
    pub fn build(&self) -> Result<TemplateBuild> {
        #[cfg(test)]
        TEMPLATE_BUILD_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        let finisher = Finisher {
            config: &self.config,
            parent: &self.parent,
            previous: &self.header.previous,
            miner: &self.miner,
            block_work: &self.block_work,
        };
        let mut execution =
            consensus::prepare_block(&self.config, &self.parent, &self.miner, &self.block_work)?;
        // A failed application changes nothing, so replaying a selection made
        // against this parent reproduces its execution. Should one no longer
        // apply, the block keeps the prefix before it.
        let mut applied = 0;
        for transaction in &self.transactions {
            if execution
                .apply_verified_transaction(&self.config, transaction)
                .is_err()
            {
                break;
            }
            applied += 1;
        }
        let (kept, state) = match finisher.finish(execution, applied) {
            Ok(state) => (applied, state),
            Err(error) => {
                let Some(kept) = finisher.prefix(&self.transactions[..applied]) else {
                    return Err(error);
                };
                eprintln!(
                    "Template kept {} of {} transactions: {error:#}",
                    kept.0,
                    self.transactions.len()
                );
                kept
            }
        };
        if applied < self.transactions.len() && kept == applied {
            eprintln!(
                "Template kept {kept} of {} transactions: a selected transaction no longer applies",
                self.transactions.len()
            );
        }
        let block = self.header.assemble(
            self.miner,
            self.transactions[..kept].to_vec(),
            self.timestamp,
            state.root(),
        )?;
        Ok(TemplateBuild { block, kept })
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
    attempted: bool,
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
            &chain.chain_id(),
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
        // The sparse enumeration is exactly the deeper retained heights.
        for tip in [1u64, 2, 31, 32, 33, 63, 64, 65, 100, 1_000, 4_097, 70_000] {
            let expected: Vec<u64> = (1..tip.saturating_sub(DENSE_STATE_CHECKPOINTS - 1))
                .filter(|height| checkpoint_retained(*height, tip))
                .collect();
            let mut sparse = sparse_checkpoint_heights(tip);
            sparse.sort_unstable();
            assert_eq!(sparse, expected, "tip {tip}");
        }
        let deep = sparse_checkpoint_heights((1 << 40) + 7);
        assert!(deep.len() <= 2 * 40, "{}", deep.len());
        assert!(deep.iter().all(|height| checkpoint_retained(*height, (1 << 40) + 7)));
    }
    #[test]
    fn deep_reorganizations_promote_every_retained_state_of_the_new_chain() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut main = Chain::open(&directory.path().join("main.db"), config.clone()).unwrap();
        let mut fork = Chain::open(&directory.path().join("fork.db"), config).unwrap();
        for n in 0..200 {
            let block = candidate(&main, n);
            if n < 100 {
                fork.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        // A branch forked at height 100 overtakes; its states were all
        // validated as recent side states before the switch.
        while main.tip_hash() != fork.tip_hash() {
            let block = candidate(&fork, 10_000 + fork.tip_height());
            fork.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_eq!(main.tip_hash(), fork.tip_hash());
        let tip = main.tip_height();
        let deeper = sparse_checkpoint_heights(tip);
        assert!(deeper.iter().filter(|height| **height > 100).count() >= 3);
        let checkpoints = main.checkpoints.borrow();
        for height in deeper.into_iter().chain(tip - DENSE_STATE_CHECKPOINTS + 1..tip) {
            let (hash, state) = checkpoints.get(&height).expect("retained state");
            assert_eq!(Some(*hash), main.hash_at_height(height), "height {height}");
            assert_eq!(state.height, height);
        }
    }
    #[test]
    fn held_headers_evict_the_weakest_leaf_and_keep_chains_linked() {
        let header = |previous: Hash, height: u64, contributed: u32, pin: u64| HeldHeader {
            header: Header {
                version: codec::HEADER_VERSION,
                previous,
                merkle_root: ZERO_HASH,
                timestamp: 0,
                bits: 0,
                nonce: 0,
            },
            height,
            root: ZERO_HASH,
            contributed: contributed.into(),
            claimed: contributed.into(),
            admitted: false,
            pin,
        };
        let id = |prefix: u8, n: u32| {
            let mut hash = [prefix; 32];
            hash[..4].copy_from_slice(&n.to_le_bytes());
            hash
        };
        let mut held = HeldHeaders::default();
        // One long presync chain, each header adding work to its branch.
        let mut previous = ZERO_HASH;
        for n in 0..100 {
            held.insert(id(1, n), header(previous, n as u64 + 1, 10 * (n + 1), 0));
            held.evict();
            previous = id(1, n);
        }
        assert_eq!(held.leaves.len(), 1);
        // A flood of cheap single headers fills the store and evicts itself.
        for n in 0..MAX_HELD_HEADERS as u32 {
            held.insert(id(2, n), header(ZERO_HASH, 1, 5, 0));
            held.evict();
        }
        assert_eq!(held.headers.len(), MAX_HELD_HEADERS);
        assert!((0..100).all(|n| held.headers.contains_key(&id(1, n))));
        assert_eq!(held.admit(&id(1, 99)).len(), 100);
        assert!((0..100).all(|n| held.admitted(&id(1, n))));
        // Admitted headers no longer count against the presync bound.
        assert_eq!(held.evictable, MAX_HELD_HEADERS - 100);
        assert_eq!(held.tips.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(), [id(1, 99)]);
        assert_eq!(held.roots.get(&ZERO_HASH), Some(&1));
        // A stored header leaves its descendants linked; an invalid one drops them.
        held.remove(&id(1, 0));
        assert!(held.headers.contains_key(&id(1, 1)));
        assert_eq!(held.roots.get(&id(1, 0)), Some(&1));
        assert!(!held.roots.contains_key(&ZERO_HASH));
        held.remove_branch(&id(1, 50));
        assert!((50..100).all(|n| !held.headers.contains_key(&id(1, n))));
        assert!((1..50).all(|n| held.headers.contains_key(&id(1, n))));
        assert_eq!(held.tips.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(), [id(1, 49)]);
        // A pinned download is not evicted however long, until it is released.
        let mut previous = id(1, 49);
        for n in 0..2 * MAX_HELD_HEADERS as u32 {
            held.insert(id(3, n), header(previous, 51 + n as u64, 1_000_000 + n, 7));
            held.evict();
            previous = id(3, n);
        }
        assert!((0..2 * MAX_HELD_HEADERS as u32).all(|n| held.headers.contains_key(&id(3, n))));
        assert_eq!(held.evictable, MAX_HELD_HEADERS - 100);
        held.unpin(7);
        assert_eq!(held.evictable, MAX_HELD_HEADERS);
        // Released, the download's weakest leaves go first: its own newest
        // headers rank above every cheap header, which are evicted first.
        assert!((0..MAX_HELD_HEADERS as u32).all(|n| !held.headers.contains_key(&id(2, n))));
        assert!((0..MAX_HELD_HEADERS as u32).all(|n| held.headers.contains_key(&id(3, n))));
        assert!(!held.headers.contains_key(&id(3, MAX_HELD_HEADERS as u32)));
        assert!(held.leaves.iter().all(|(_, hash)| held.headers[hash].evictable()));
    }
    #[test]
    fn side_branch_admissions_are_budgeted_by_active_chain_growth() {
        let directory = tempfile::tempdir().unwrap();
        let mut chain = Chain::open(&directory.path().join("budget.db"), Config::devnet()).unwrap();
        for n in 0..3 {
            let block = candidate(&chain, n);
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let parent = chain.tip_block().header.previous;
        let mut sibling =
            Chain::open(&directory.path().join("sibling.db"), Config::devnet()).unwrap();
        for height in 1..chain.tip_height() {
            let block = chain.block(&chain.hash_at_height(height).unwrap()).unwrap();
            sibling
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_eq!(sibling.tip_hash(), parent);
        chain.side_budget = 2;
        let siblings: Vec<_> = (0..3).map(|n| candidate(&sibling, 100 + n)).collect();
        for block in &siblings[..2] {
            assert!(!chain.submit(block.clone(), block.header.timestamp as u64).unwrap());
        }
        let refused = chain
            .submit(siblings[2].clone(), siblings[2].header.timestamp as u64)
            .unwrap_err();
        assert!(refused.is::<SideBranchRefused>(), "{refused:#}");
        assert!(chain.block(&codec::block_hash(&siblings[2])).is_none());
        assert_eq!(chain.held_header_count(), 1);
        // A new active-chain block refills the budget.
        let next = candidate(&chain, 9);
        assert!(chain.submit(next.clone(), next.header.timestamp as u64).unwrap());
        assert_eq!(chain.side_budget, SIDE_BRANCH_BLOCKS_PER_TIP);
        assert!(!chain.submit(siblings[2].clone(), siblings[2].header.timestamp as u64).unwrap());
        assert_eq!(chain.held_header_count(), 0);
    }
    #[test]
    fn stale_losing_branches_are_pruned_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prune.db");
        let config = Config::devnet();
        let miner = crypto::public_key(&[91; 32]).unwrap();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut early = Chain::open(&directory.path().join("early.db"), config.clone()).unwrap();
        let first = candidate(&chain, 0);
        for target in [&mut chain, &mut early] {
            target.submit(first.clone(), first.header.timestamp as u64).unwrap();
        }
        // An early losing branch of three on-schedule blocks.
        let mut stale = Vec::new();
        for n in 0..3 {
            let block = candidate(&early, 50 + n);
            early.submit(block.clone(), block.header.timestamp as u64).unwrap();
            stale.push(block);
        }
        let block = candidate(&chain, 1);
        chain.submit(block.clone(), block.header.timestamp as u64).unwrap();
        for _ in 0..2 {
            let block = candidate(&chain, 2 + chain.tip_height());
            chain.submit(block.clone(), block.header.timestamp as u64).unwrap();
        }
        for block in &stale {
            assert!(!chain.submit(block.clone(), block.header.timestamp as u64).unwrap());
        }
        // One-second blocks make the active chain's next block more than 64
        // times the work a child of the stale branch would carry.
        while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
            let time = chain.tip_block().header.timestamp + 1;
            let block = Chain::mine(chain.template(miner, vec![], time).unwrap(), 100_000).unwrap();
            chain.submit(block, time as u64).unwrap();
        }
        // A sibling of the tip stays competitive.
        let mut near = Chain::open(&directory.path().join("near.db"), config.clone()).unwrap();
        for height in 1..chain.tip_height() {
            let block = chain.block(&chain.hash_at_height(height).unwrap()).unwrap();
            near.submit(block.clone(), block.header.timestamp as u64).unwrap();
        }
        let time = chain.tip_block().header.timestamp;
        let mut sibling = near.template(miner, vec![], time).unwrap();
        sibling.extranonce = [7; 8];
        sibling.header.merkle_root = codec::merkle_root(&sibling).unwrap();
        let sibling = Chain::mine(sibling, 1_000_000).unwrap();
        assert!(!chain.submit(sibling.clone(), time as u64).unwrap());
        let tip = chain.tip_hash();
        drop(chain);
        let chain = Chain::open(&path, config.clone()).unwrap();
        assert_eq!(chain.tip_hash(), tip);
        for block in &stale {
            assert!(chain.block(&codec::block_hash(block)).is_none());
            assert!(chain.block_height(&codec::block_hash(block)).unwrap().is_none());
        }
        assert!(chain.block(&codec::block_hash(&sibling)).is_some());
        drop(chain);
        // Pruning is complete: the next startup has nothing left to remove.
        let mut chain = Chain::open(&path, config).unwrap();
        assert_eq!(chain.prune_stale_branches().unwrap(), 0);
        assert_eq!(chain.tip_hash(), tip);
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
