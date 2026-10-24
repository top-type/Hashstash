use crate::{
    codec,
    config::Config,
    consensus, crypto, fees, math,
    state::{Phase, SavedPassChanges, State},
    types::*,
};
use anyhow::{Context, Result, ensure};
use bincode::Options;
use num_traits::Zero;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    io::{Read, Write},
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

/// Recently validated or reconstructed states outside the active-chain checkpoints.
pub const MAX_CACHED_STATES: usize = 128;
/// Deferred reconstructions kept for blocks that would become the tip or
/// belong to an admitted held chain, apart from the one kept for side blocks.
/// Side-branch traffic can neither take these over nor evict them.
const MAX_PRIORITY_REPLAYS: usize = 4;
/// Post-states of stored blocks where admitted held chains continue, kept
/// outside the recent-state cache until the chain is adopted or dropped.
const MAX_PINNED_STATES: usize = 8;
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
/// The same budget in stored bytes: at most this many, refilled by
/// SIDE_BRANCH_BLOCKS_PER_TIP block capacities per new active-chain height,
/// so side storage tracks the chain's own growth rather than the block count
/// times a governed capacity. Both budgets persist across restarts.
pub const SIDE_BRANCH_BURST_BYTES: u64 = 64 << 20;
/// Free disk space below which side blocks are declined (their headers are
/// held as for any declined block) and state checkpoints are not saved, so
/// what remains serves the active chain.
pub const STORAGE_RESERVE_BYTES: u64 = 512 << 20;
/// Proof-of-work checked headers of declined branches held in memory for
/// presync. Eviction drops the leaf whose held chain claims the least work.
/// Headers of a chain that claimed more work than the tip, and headers a
/// header download fetches again after counting that much work, are not
/// counted or evicted: MAX_SYNC_HEADERS bounds them instead.
pub const MAX_HELD_HEADERS: usize = 32_768;
/// Held headers that are admitted or pinned by a header download, together,
/// at about 1 KiB of memory each. A header after a held parent needs only its
/// own proof of work within the network limit, which is the initial target
/// on every preset, so the work such headers claim does not bound their
/// number. A hold that would exceed this is refused instead, and ends the
/// download that asked for it: a branch that needs more headers than this
/// before it claims more work than the tip is not followed.
pub const MAX_SYNC_HEADERS: usize = 2 * MAX_HELD_HEADERS;
/// A held chain that already claims more work than the tip by this many
/// next-block works needs no further headers until its blocks arrive.
pub const HELD_LEAD_BLOCKS: u32 = 16;
/// Nor does an admitted chain extended by this many headers since it was
/// admitted or restored: cheap headers can claim little work each.
pub const HELD_LEAD_HEADERS: u32 = 2_048;
/// A losing branch raises the peer capacity allowance only while it stays within
/// this many next-block works of the tip, with at least 1/CAPACITY_BRANCH_WORK_RATIO
/// of that work in its leaf block.
pub const CAPACITY_BRANCH_MARGIN_BLOCKS: u32 = 6;
pub const CAPACITY_BRANCH_WORK_RATIO: u32 = 4;
const MAX_CAPACITY_BRANCHES: usize = 256;
/// One stored block row: the greatest valid body plus generous room for its
/// header and record framing.
pub const MAX_BLOCK_ROW_BYTES: u64 = crate::config::MAX_GOVERNED_BLOCK_BYTES + (1 << 20);
/// Marker of the stored history's rules, kept in the database metadata. Like
/// the peer marker, its suffix names the generation that introduced them;
/// a release whose stored blocks or states another cannot read changes it.
pub const STORAGE_FORMAT: &[u8] = b"hashstash-storage-043";
/// Blocks replayed per committed batch of the startup index rebuild. Unit tests
/// use small batches so reopening their short chains crosses batch boundaries.
const INDEX_REBUILD_BATCH: u64 = if cfg!(test) { 7 } else { 4096 };
/// Active-chain heights between persisted state checkpoints. A chain shorter
/// than this plus CHECKPOINT_DEPTH saves none and replays all history on start.
const CHECKPOINT_INTERVAL: u64 = 1024;
/// A checkpoint saves the state this far below the tip, within the dense
/// retained window, so a restart validates the blocks above it again and
/// branches forking within that depth stay cheap to reconstruct.
const CHECKPOINT_DEPTH: u64 = DENSE_STATE_CHECKPOINTS - 1;
/// Saved checkpoints kept: the newest two, the older serving when the newer
/// fails its checks, and up to two older ones about one per doubling of depth
/// (see [saved_checkpoints_kept]), from which a reorganization below a
/// restored state rebuilds its fork point instead of from genesis.
const MAX_SAVED_CHECKPOINTS: usize = 4;
/// After a failed save, periodic saves wait one checkpoint interval of
/// active-chain heights before trying again, doubling with each further
/// failure up to this many intervals, instead of retrying on every block.
const CHECKPOINT_RETRY_INTERVALS: u64 = 16;
/// A periodic save audits its state off the node lock; the save waits at
/// most this many blocks for the audit before waiting for it under the lock.
const CHECKPOINT_AUDIT_BLOCKS: u64 = if cfg!(test) { 1 } else { 16 };
/// A saved state is split into rows of at most this size, far below SQLite's value limit.
const CHECKPOINT_PART_BYTES: usize = 4 << 20;
/// Canonical-index row naming the build that derived the persisted indexes.
/// A binary that predates saved checkpoints clears that index on every start,
/// this row with it, so indexes it rebuilt never meet a checkpoint.
const INDEX_BUILD_HEIGHT: i64 = -1;
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
    Stored {
        height: u64,
        work: Amount,
    },
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
    /// Not held: its chain already leads the tip by HELD_LEAD_BLOCKS, or
    /// by HELD_LEAD_HEADERS headers since it was admitted.
    Ahead,
    /// Not held: admitted and pinned headers already number MAX_SYNC_HEADERS.
    Full,
}
/// Local admission policy declined to validate or store a block that would
/// not become the tip. The block is not invalid and is never cached as such.
/// Its proof-of-work checked header is held, so later blocks of its branch
/// can still be received; once held headers claim more work than the tip,
/// the branch's blocks are admitted when delivered again.
#[derive(Debug)]
pub struct SideBranchRefused(pub &'static str);
impl std::fmt::Display for SideBranchRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "side branch header held, block not stored: {}", self.0)
    }
}
impl std::error::Error for SideBranchRefused {}
/// A submitter's own bounds on a received block, consulted by
/// [Chain::begin_submission] with whether the block would be stored on a
/// side branch: the replayed blocks this call may run, or a refusal.
pub type SubmissionBudget<'a> = &'a mut dyn FnMut(bool) -> Result<Option<usize>>;
/// Retained reconstruction progress no longer links to the active chain.
#[derive(Debug)]
struct StaleReplay;
impl std::fmt::Display for StaleReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "retained state replay no longer matches the active chain"
        )
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

/// A template build stopped at a step boundary because the caller no longer
/// wants it, as when its parent stopped being the tip. Nothing was built.
#[derive(Debug)]
pub struct TemplateStale;
impl std::fmt::Display for TemplateStale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "template build abandoned: its parent is no longer the tip"
        )
    }
}
impl std::error::Error for TemplateStale {}
fn unless_stale(stale: &dyn Fn() -> bool) -> Result<()> {
    if stale() {
        return Err(TemplateStale.into());
    }
    Ok(())
}

/// Local storage faults that leave the node running, for its status reports.
/// The node shares it with its readers, which never take the chain lock.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct StorageHealth {
    /// Block commits that failed in a row; any stored block resets it.
    pub failed_commits: u32,
    /// Unix time of the first of those failures.
    pub failing_since: Option<u64>,
    /// The last of those failures, such as a full disk.
    pub last_error: Option<String>,
    /// Why the last state checkpoint save, or one found at startup, failed;
    /// cleared once a checkpoint is saved.
    pub checkpoint_error: Option<String>,
}
impl StorageHealth {
    /// Blocks cannot be stored: the tip stays where it is until they can.
    pub fn degraded(&self) -> bool {
        self.failed_commits > 0
    }
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
fn error_text(error: &anyhow::Error) -> String {
    format!("{error:#}").chars().take(256).collect()
}
/// Free space available to this process on the filesystem holding `path`;
/// None where it is unknown, which never declines anything.
fn free_bytes(path: &Path) -> Option<u64> {
    #[cfg(test)]
    if let Some(free) = FREE_BYTES.with(Cell::get) {
        return Some(free);
    }
    filesystem_free_bytes(path)
}
#[cfg(unix)]
fn filesystem_free_bytes(path: &Path) -> Option<u64> {
    let stat = rustix::fs::statvfs(path).ok()?;
    Some(stat.f_bavail.saturating_mul(stat.f_frsize))
}
#[cfg(not(unix))]
fn filesystem_free_bytes(_: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
thread_local! {
    /// Free disk space reported on this thread instead of the filesystem's.
    pub(crate) static FREE_BYTES: Cell<Option<u64>> = const { Cell::new(None) };
    /// Fail the deletion of stale branches in a full replay on this thread
    /// right after its first batch commit, as an interrupted start would.
    pub(crate) static FAIL_STALE_DELETION: Cell<bool> = const { Cell::new(false) };
    /// Canonical-index lookups on this thread.
    pub(crate) static CANONICAL_LOOKUPS: Cell<usize> = const { Cell::new(0) };
    /// Fail block finishing on this thread for accepted sets longer than this.
    pub(crate) static FAIL_FINISH_ABOVE: Cell<Option<usize>> = const { Cell::new(None) };
    /// Run on this thread when a template build starts, before any clearing.
    pub(crate) static TEMPLATE_BUILD_HOOK: RefCell<Option<Box<dyn FnMut()>>> =
        const { RefCell::new(None) };
    /// Blocks executed by validation on this thread.
    pub(crate) static VALIDATED_BLOCKS: Cell<usize> = const { Cell::new(0) };
    /// Historical blocks replayed to rebuild a parent state on this thread.
    pub(crate) static REPLAYED_BLOCKS: Cell<usize> = const { Cell::new(0) };
    /// Run on this thread when a received block's execution starts.
    pub(crate) static BLOCK_EXECUTION_HOOK: RefCell<Option<Box<dyn FnMut()>>> =
        const { RefCell::new(None) };
    /// Commits of admitted held headers on this thread.
    pub(crate) static HELD_COMMITS: Cell<usize> = const { Cell::new(0) };
}

/// Digest of the running executable. A saved checkpoint is used only by the
/// build that wrote it: any other build, whose validation rules may differ,
/// revalidates all stored history once instead. An unreadable image (None)
/// disables checkpoints, which leaves every start a full replay.
fn build_identity() -> Option<Hash> {
    static IDENTITY: OnceLock<Option<Hash>> = OnceLock::new();
    *IDENTITY.get_or_init(|| {
        // On Linux this is the running image even if its path was replaced since.
        let path = if cfg!(target_os = "linux") {
            "/proc/self/exe".into()
        } else {
            std::env::current_exe().ok()?
        };
        let mut digest = Sha256::new();
        std::io::copy(&mut std::fs::File::open(path).ok()?, &mut digest).ok()?;
        Some(digest.finalize().into())
    })
}
/// The consensus record options (see codec), streamed: a saved state is
/// written and read in parts, never as one buffer.
fn checkpoint_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_little_endian()
}
/// Writes a saved state as consecutive part rows of one checkpoint height.
struct PartWriter<'a> {
    db: &'a Connection,
    height: u64,
    parts: u64,
    length: u64,
    buffer: Vec<u8>,
}
impl PartWriter<'_> {
    fn flush_part(&mut self) -> rusqlite::Result<()> {
        if !self.buffer.is_empty() {
            self.db
                .prepare_cached(
                    "INSERT INTO state_checkpoint_parts(height,part,bytes) VALUES(?1,?2,?3)",
                )?
                .execute(params![self.height, self.parts, self.buffer])?;
            self.parts += 1;
            self.buffer.clear();
        }
        Ok(())
    }
}
impl Write for PartWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let taken = bytes.len().min(CHECKPOINT_PART_BYTES - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..taken]);
        self.length += taken as u64;
        if self.buffer.len() == CHECKPOINT_PART_BYTES {
            self.flush_part().map_err(std::io::Error::other)?;
        }
        Ok(taken)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Reads the part rows of one checkpoint height back as one stream.
struct PartReader<'a> {
    db: &'a Connection,
    height: u64,
    part: u64,
    buffer: Vec<u8>,
    offset: usize,
}
impl Read for PartReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.offset == self.buffer.len() {
            let next: Option<Vec<u8>> = self
                .db
                .prepare_cached(
                    "SELECT bytes FROM state_checkpoint_parts WHERE height=?1 AND part=?2",
                )
                .and_then(|mut statement| {
                    statement
                        .query_row(params![self.height, self.part], |r| r.get(0))
                        .optional()
                })
                .map_err(std::io::Error::other)?;
            let Some(next) = next else {
                return Ok(0);
            };
            (self.buffer, self.offset) = (next, 0);
            self.part += 1;
        }
        let count = out.len().min(self.buffer.len() - self.offset);
        out[..count].copy_from_slice(&self.buffer[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
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
    height.is_multiple_of(step)
}
/// The saved checkpoints that stay once the newest of `saved` (heights,
/// newest first) is written: it and the next newest, then, by buckets of
/// `interval` heights, the newest one of each bucket that is a multiple of
/// the greatest power of two not above its depth in buckets, about one per
/// doubling of depth; at most MAX_SAVED_CHECKPOINTS in all.
fn saved_checkpoints_kept(saved: &[u64], interval: u64) -> BTreeSet<u64> {
    let interval = interval.max(1);
    let mut kept = BTreeSet::new();
    let Some(top) = saved.first().map(|newest| newest / interval) else {
        return kept;
    };
    let mut buckets = BTreeSet::new();
    for (index, height) in saved.iter().enumerate() {
        if kept.len() == MAX_SAVED_CHECKPOINTS {
            break;
        }
        let bucket = height / interval;
        let depth = top.saturating_sub(bucket).max(1);
        let step = 1u64 << (63 - depth.leading_zeros());
        if index < 2 || (!buckets.contains(&bucket) && bucket.is_multiple_of(step)) {
            kept.insert(*height);
            buckets.insert(bucket);
        }
    }
    kept
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
    /// Header downloads holding this header after counting that its branch
    /// claims more work than the tip (see `HeldHeaders::pinned`).
    pins: u32,
    /// Headers held after an admitted parent since its chain was admitted
    /// or restored, this one included; zero for others.
    lead: u32,
}
impl HeldHeader {
    fn evictable(&self) -> bool {
        !self.admitted && self.pins == 0
    }
}
/// Header presync for branches the admission policy declined or that a
/// header download proved heavier than the tip. Evictable headers are
/// bounded by MAX_HELD_HEADERS, admitted and pinned ones by MAX_SYNC_HEADERS.
#[derive(Default)]
struct HeldHeaders {
    headers: BTreeMap<Hash, HeldHeader>,
    children: BTreeMap<Hash, BTreeSet<Hash>>,
    /// The held headers of each header download, by its pin. Several
    /// downloads of one branch share its headers; each keeps them until it
    /// ends, whichever ends first.
    pinned: BTreeMap<u64, BTreeSet<Hash>>,
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
    /// Insert a new non-admitted, unpinned header whose parent is stored or
    /// held. Eviction is left to `evict`, so a header about to be admitted
    /// or pinned is never evicted first.
    fn insert(&mut self, hash: Hash, held: HeldHeader) -> bool {
        if self.headers.contains_key(&hash) {
            return false;
        }
        debug_assert!(!held.admitted && held.pins == 0);
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
        if held.pins > 0 {
            for pinned in self.pinned.values_mut() {
                pinned.remove(hash);
            }
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
        while self.headers.get(&cursor).is_some_and(|held| !held.admitted) {
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
    /// An admitted header without admitted children: where its chain is extended.
    fn admitted_tip(&self, hash: &Hash) -> bool {
        self.headers
            .get(hash)
            .is_some_and(|held| held.admitted && !self.has_admitted_child(hash))
    }
    /// Held headers that are admitted or pinned, which are never evicted.
    fn fixed(&self) -> usize {
        self.headers.len() - self.evictable
    }
    /// Held headers that admitting `hash`'s chain would make fixed: it and
    /// its held ancestors down to an admitted one, those not yet pinned.
    fn admission_cost(&self, hash: &Hash) -> usize {
        let mut cost = 0;
        let mut cursor = *hash;
        while let Some(held) = self.headers.get(&cursor)
            && !held.admitted
        {
            cost += usize::from(held.evictable());
            cursor = held.header.previous;
        }
        cost
    }
    /// Pin a held header to a header download, once per download.
    fn pin(&mut self, hash: Hash, pin: u64) {
        if pin != 0
            && self.headers.contains_key(&hash)
            && self.pinned.entry(pin).or_default().insert(hash)
        {
            self.reclassify(&hash, |held| held.pins += 1);
        }
    }
    /// Release a header download's pin. Its headers that no other download
    /// pins and that were not admitted become evictable.
    fn unpin(&mut self, pin: u64) {
        for hash in self.pinned.remove(&pin).unwrap_or_default() {
            self.reclassify(&hash, |held| held.pins -= 1);
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
    // Deferred reconstruction for a side block the admission policy let in;
    // another side block's deferral takes it over.
    replay: RefCell<Option<Replay>>,
    // Deferred reconstructions for blocks that would become the tip or belong
    // to an admitted held chain, oldest first. Side blocks never take them over.
    priority_replays: RefCell<VecDeque<Replay>>,
    // The block being checked would become the tip or belongs to an admitted
    // held chain; its deferred reconstruction is a priority one.
    replay_priority: Cell<bool>,
    // Post-states of the stored blocks where admitted held chains continue
    // (see [Chain::repin]), outside the recent cache.
    pinned: BTreeMap<Hash, Arc<State>>,
    invalid_blocks: BTreeMap<Hash, String>,
    invalid_order: VecDeque<(Hash, Instant)>,
    replay_budget: Cell<Option<usize>>,
    branches: BTreeMap<Hash, BranchLeaf>,
    known_block_bytes: u64,
    held: HeldHeaders,
    // Last identifier handed to a header download for its pinned headers.
    next_pin: u64,
    // Headers admitted inside `hold_batch`, persisted when it ends.
    held_batch: Option<Vec<Hash>>,
    // Remaining side-branch admissions and stored bytes, and the active height
    // that last refilled them.
    side_budget: u64,
    side_budget_bytes: u64,
    side_budget_height: u64,
    // The saved checkpoint this process started from, while it stays on the
    // active chain. Below it only genesis is retained, so it stays retained too.
    restored: Option<(u64, Hash)>,
    // An older saved checkpoint loaded to rebuild a fork point below the
    // restored one, retained while it stays on the active chain.
    loaded: Cell<Option<(u64, Hash)>>,
    // Active-chain heights between saved checkpoints (CHECKPOINT_INTERVAL).
    checkpoint_every: u64,
    // Saves that failed in a row, and the tip height before which periodic
    // saves are not tried again.
    checkpoint_failures: u32,
    checkpoint_retry: u64,
    // A periodic checkpoint whose state is audited off the node lock.
    checkpoint_audit: Option<CheckpointAudit>,
    // The database file, whose filesystem's free space is checked.
    path: std::path::PathBuf,
    health: Arc<std::sync::Mutex<StorageHealth>>,
    // Startup finished; only an opened chain saves a checkpoint when dropped.
    opened: bool,
}
/// A state checkpoint audited on its own thread before it is saved.
struct CheckpointAudit {
    height: u64,
    hash: Hash,
    state: Arc<State>,
    // The tip height when the audit started.
    started: u64,
    audit: std::thread::JoinHandle<Result<()>>,
}
impl Drop for Chain {
    /// A clean stop saves a checkpoint near the tip, so the next start
    /// replays only the blocks above it.
    fn drop(&mut self) {
        if self.opened && !std::thread::panicking() {
            self.save_checkpoint(1);
        }
    }
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
        // zeroblob is refused above SQLite's row length limit without being
        // allocated. A build that could not store every valid block would
        // reject one that its peers accept, so it fails here instead.
        db.query_row(
            "SELECT length(zeroblob(?1))",
            [MAX_BLOCK_ROW_BYTES],
            |row| row.get::<_, i64>(0),
        )
        .context("this SQLite build cannot store the largest valid block")?;
        // The journal limit returns WAL space after checkpoints of the batched
        // startup index rebuild instead of keeping the log at its peak size.
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_size_limit=67108864; CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value BLOB NOT NULL); CREATE TABLE IF NOT EXISTS blocks(seq INTEGER PRIMARY KEY AUTOINCREMENT, hash BLOB NOT NULL UNIQUE, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS rejected_blocks(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL, accepted_at INTEGER NOT NULL, reason TEXT NOT NULL); CREATE TABLE IF NOT EXISTS held_headers(hash BLOB PRIMARY KEY, header BLOB NOT NULL, height INTEGER NOT NULL);")?;
        // Derived indexes are rebuilt from independently validated block bodies,
        // except below a saved state checkpoint that passes its checks.
        // SQLite bounds its page cache; canonical and losing-branch metadata stay on disk.
        db.execute_batch("PRAGMA cache_size=-8192; PRAGMA temp_store=FILE; CREATE TABLE IF NOT EXISTS entry_index(hash BLOB PRIMARY KEY, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS canonical_index(height INTEGER PRIMARY KEY, hash BLOB NOT NULL); CREATE TABLE IF NOT EXISTS state_checkpoints(height INTEGER PRIMARY KEY, hash BLOB NOT NULL, build BLOB NOT NULL, length INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS state_checkpoint_parts(height INTEGER NOT NULL, part INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(height,part)); CREATE TEMP TABLE IF NOT EXISTS state_replay_path(target BLOB NOT NULL, position INTEGER NOT NULL, hash BLOB NOT NULL, PRIMARY KEY(target,position));")?;
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
        // The same genesis file has the same chain ID under Hashstash 0.42.0,
        // but its blocks commit to another state encoding. It wrote no
        // format marker, so its stored history is refused by name here
        // instead of failing replay at its first block.
        let format: Option<Vec<u8>> = db
            .query_row("SELECT value FROM metadata WHERE key='format'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(format) = format {
            ensure!(
                format == STORAGE_FORMAT,
                "database was written in storage format {}, not this release's {}",
                format.escape_ascii(),
                STORAGE_FORMAT.escape_ascii()
            );
        } else {
            let stored: bool =
                db.query_row("SELECT EXISTS(SELECT 1 FROM blocks)", [], |r| r.get(0))?;
            ensure!(
                !stored,
                "database holds blocks written by Hashstash 0.42.0 or earlier, which this release cannot validate; keep it for that release and give this one a new --data path"
            );
            db.execute(
                "INSERT INTO metadata(key,value) VALUES('format',?1)",
                [STORAGE_FORMAT],
            )?;
        }
        let mut chain = Self::at_genesis(config, db, path)?;
        chain.db.execute_batch("BEGIN IMMEDIATE;")?;
        // A saved checkpoint spares replaying the history below it. Any doubt
        // about it, or about the indexes it relies on, means a full replay.
        let restored = chain.restore().unwrap_or_else(|error| {
            eprintln!(
                "Not using the saved state checkpoint: {error:#}; replaying all stored history"
            );
            false
        });
        let mut pruned = 0;
        if !restored {
            // A failed restore may have committed index batches; they are rebuilt below.
            let _ = chain.db.execute_batch("ROLLBACK;");
            let db = std::mem::replace(&mut chain.db, Connection::open_in_memory()?);
            let health = chain.health.clone();
            chain = Self::at_genesis(chain.config.clone(), db, path)?;
            chain.health = health;
            pruned = chain.replay_all()?;
        }
        // Admitted held headers of chains still competing with the tip are
        // restored before stale branches are pruned, so their roots stay.
        chain.load_held()?;
        chain.prune_held()?;
        chain.repin();
        let pruned = pruned + chain.prune_stale_branches()?;
        chain.refresh_capacity();
        if pruned > 0 {
            eprintln!("Pruned {pruned} stored losing-branch block(s) that fell out of competition");
        }
        chain.resume_side_budget()?;
        chain.db.execute_batch("COMMIT")?;
        // Housekeeping only: a failed WAL checkpoint leaves committed history intact.
        let _ = chain.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        chain.opened = true;
        chain.save_checkpoint(chain.checkpoint_every);
        Ok(chain)
    }
    /// A chain holding only genesis in memory; its database rows are untouched.
    fn at_genesis(config: Config, db: Connection, path: &Path) -> Result<Self> {
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
        let state = Arc::new(state);
        let chain = Self {
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
            priority_replays: RefCell::new(VecDeque::new()),
            replay_priority: Cell::new(false),
            pinned: BTreeMap::new(),
            invalid_blocks: BTreeMap::new(),
            invalid_order: VecDeque::new(),
            replay_budget: Cell::new(None),
            branches: BTreeMap::new(),
            known_block_bytes: genesis_entry.capacity,
            held: HeldHeaders::default(),
            next_pin: 0,
            held_batch: None,
            side_budget: SIDE_BRANCH_BURST,
            side_budget_bytes: SIDE_BRANCH_BURST_BYTES,
            side_budget_height: 0,
            restored: None,
            loaded: Cell::new(None),
            checkpoint_every: CHECKPOINT_INTERVAL,
            checkpoint_failures: 0,
            checkpoint_retry: 0,
            checkpoint_audit: None,
            path: path.to_path_buf(),
            health: Arc::default(),
            opened: false,
        };
        chain.cache_entry(genesis_hash, genesis_entry);
        Ok(chain)
    }
    /// Write the genesis index rows, which every derived index starts from,
    /// and mark the indexes as derived by this build.
    fn index_genesis(&self) -> Result<()> {
        let genesis = codec::block_hash(&self.genesis);
        self.db.execute(
            "INSERT OR REPLACE INTO entry_index(hash,bytes) VALUES(?1,?2)",
            params![genesis.as_slice(), codec::encode(self.tip_entry.as_ref())],
        )?;
        self.db.execute(
            "INSERT OR REPLACE INTO canonical_index(height,hash) VALUES(0,?1)",
            [genesis.as_slice()],
        )?;
        let build = build_identity().unwrap_or(ZERO_HASH);
        self.db.execute(
            "INSERT OR REPLACE INTO canonical_index(height,hash) VALUES(?1,?2)",
            params![INDEX_BUILD_HEIGHT, build.as_slice()],
        )?;
        Ok(())
    }
    fn persisted_tip(&self) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .query_row("SELECT value FROM metadata WHERE key='tip'", [], |r| {
                r.get(0)
            })
            .optional()?)
    }
    /// Rebuild every derived index from all stored block bodies, inside the
    /// open transaction. Saved checkpoints are dropped first, in the same
    /// transaction: none outlives the entries it was saved with, so another
    /// build's checkpoint never meets entries this build derived. Returns
    /// how many stored losing-branch blocks it pruned without executing them.
    fn replay_all(&mut self) -> Result<u64> {
        let genesis_hash = codec::block_hash(&self.genesis);
        // Judged before the persisted index is wiped; any doubt about it
        // leaves nothing to skip.
        let judged = self.judge_stale_branches().ok();
        let mut skipped: BTreeSet<Hash> = judged
            .as_ref()
            .map(|(_, _, stale)| stale.iter().copied().collect())
            .unwrap_or_default();
        self.db.execute_batch("BEGIN IMMEDIATE; DELETE FROM entry_index; DELETE FROM canonical_index; DELETE FROM state_checkpoint_parts; DELETE FROM state_checkpoints;")?;
        self.index_genesis()?;
        // Stored blocks that fail current validation are set aside when they
        // belong to losing branches. Storage and index errors still stop startup.
        let mut rejected = BTreeMap::<Hash, (Option<Amount>, String)>::new();
        self.replay_stored(Some(&mut rejected), Some(&mut skipped))?;
        let mut pruned = 0u64;
        if !skipped.is_empty() {
            // The judgement stands only if the replay reproduced the persisted
            // tip's index entry exactly, as the rules that wrote the persisted
            // index would, and skipped no block judged worth keeping, below a
            // stale parent; otherwise the skipped blocks are executed after all.
            let reproduced = judged.as_ref().is_some_and(|(tip, bytes, stale)| {
                skipped.len() == stale.len()
                    && self.load_entry(tip).ok().flatten().is_some_and(|entry| {
                        entry.work == self.tip_entry.work && codec::encode(entry.as_ref()) == *bytes
                    })
            });
            if reproduced && let Some((_, _, stale)) = &judged {
                // Children before their parents, in descending storage
                // order as judged: a batch commit, after which this start
                // may be interrupted, never leaves a stored block whose
                // parent is gone.
                for hash in stale {
                    self.db
                        .prepare_cached("DELETE FROM blocks WHERE hash=?1")?
                        .execute([hash.as_slice()])?;
                    pruned += 1;
                    if pruned.is_multiple_of(INDEX_REBUILD_BATCH) {
                        self.db.execute_batch("COMMIT; BEGIN IMMEDIATE;")?;
                        #[cfg(test)]
                        if FAIL_STALE_DELETION.with(Cell::get) {
                            anyhow::bail!("stale branch deletion interrupted");
                        }
                    }
                }
            } else {
                eprintln!(
                    "The rebuilt index does not confirm the persisted one; replaying the stored losing branches judged stale from it too"
                );
                self.replay_stored(Some(&mut rejected), None)?;
            }
        }
        let saved_tip = self.persisted_tip()?;
        let persisted = saved_tip
            .as_deref()
            .and_then(|raw| Hash::try_from(raw).ok());
        // Tips only gain work and every accepted block is committed with the tip
        // it produces, so a stored losing branch never claims more work than the
        // persisted tip. Anything else means the persisted tip itself, or the
        // database, disagrees with current validation: fail closed.
        let persisted_work = match persisted {
            Some(hash) => self.load_entry(&hash)?.map(|entry| entry.work.clone()),
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
        if !self.follow_tip_hint(persisted)?
            && persisted != Some(self.tip)
            && (saved_tip.is_some() || self.tip != genesis_hash)
        {
            // A missing, malformed or lower-work hint cannot override validated
            // history; record the replayed best tip instead.
            eprintln!("Ignoring a stale persisted chain tip; using the replayed best tip");
            self.db.execute("INSERT INTO metadata(key,value) VALUES('tip',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [self.tip.as_slice()])?;
        }
        for (hash, (_, reason)) in &rejected {
            self.db.execute(
                "INSERT OR IGNORE INTO rejected_blocks(hash,bytes,accepted_at,reason) SELECT hash,bytes,accepted_at,?2 FROM blocks WHERE hash=?1",
                params![hash.as_slice(), reason],
            )?;
            self.db
                .execute("DELETE FROM blocks WHERE hash=?1", [hash.as_slice()])?;
        }
        if !rejected.is_empty() {
            eprintln!(
                "Moved {} stored side-branch block(s) that fail validation into rejected_blocks",
                rejected.len()
            );
        }
        Ok(pruned)
    }
    /// Before a full replay: the persisted tip, its persisted index entry, and
    /// the stored losing-branch blocks that [Chain::prune_stale_branches]
    /// would delete once the replay had executed them, judged from the
    /// persisted index by the same rule against the persisted tip. The tip's
    /// ancestry, and a stored block that a persisted held header follows,
    /// are always kept, whatever the persisted canonical index says. Each
    /// block judged stale must have an entry that agrees with its parent's
    /// (see [Chain::check_entry]); a missing or disagreeing entry, or one
    /// claiming more work than the persisted tip, is an error. The stale
    /// blocks come in descending storage order, children before parents.
    fn judge_stale_branches(&self) -> Result<(Hash, Vec<u8>, Vec<Hash>)> {
        let tip = self
            .persisted_tip()?
            .and_then(|raw| Hash::try_from(raw.as_slice()).ok())
            .context("persisted tip absent")?;
        let bytes: Vec<u8> = self.db.query_row(
            "SELECT bytes FROM entry_index WHERE hash=?1",
            [tip.as_slice()],
            |r| r.get(0),
        )?;
        let tip_entry = codec::decode::<Entry>(&bytes, 4096)?;
        let next = math::work(&self.target(&tip_entry)?);
        let mut needed = BTreeSet::from([tip]);
        let held: Vec<Vec<u8>> = self
            .db
            .prepare("SELECT header FROM held_headers")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for header in held {
            needed.insert(crate::peer_wire::header_from_bytes(&header)?.previous);
        }
        let mut stale = Vec::new();
        let mut sequence = i64::MAX;
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
            // A stale tip hint is no reference: the replay replaces it.
            ensure!(
                entry.work <= tip_entry.work,
                "a stored block claims more work than the persisted tip"
            );
            let child = math::work(&self.target(&entry)?);
            let branch = &entry.work + &child;
            if needed.remove(&hash)
                || Self::competitive(&tip_entry.work, &branch, &child, &next).is_ok()
            {
                needed.insert(entry.header.previous);
                continue;
            }
            let parent = Self::read_entry(&self.db, &entry.header.previous)?
                .context("stored block parent entry absent")?;
            self.check_entry(&hash, &entry, &parent, None)?;
            stale.push(hash);
        }
        Ok((tip, bytes, stale))
    }
    /// An equal-work persisted tip only breaks the first-seen tie between
    /// already revalidated branches. True when it became the tip.
    fn follow_tip_hint(&mut self, persisted: Option<Hash>) -> Result<bool> {
        let hinted = match persisted {
            Some(hash) if hash != self.tip => self
                .load_entry(&hash)?
                .filter(|entry| entry.work == self.tip_entry.work)
                .map(|entry| (hash, entry)),
            _ => None,
        };
        let Some((hash, entry)) = hinted else {
            return Ok(false);
        };
        let block = self
            .load_block(&hash)?
            .context("persisted tip block absent")?;
        let state = self.load_state(&hash)?;
        Self::write_canonical(&self.db, hash, entry.height)?;
        let previous = (self.tip, self.tip_entry.clone());
        self.select_tip(hash, block, state, entry.clone());
        self.note_branch(hash, &entry, true, previous);
        self.refresh_capacity();
        Ok(true)
    }
    /// Validate, in storage order, every stored block without an index entry,
    /// adding its entry and canonical heights. With `rejected`, a block that
    /// fails validation and its descendants are set aside there; without it,
    /// the failure is returned. A block in `skipped`, and every descendant,
    /// which joins it, is neither executed nor indexed.
    fn replay_stored(
        &mut self,
        mut rejected: Option<&mut BTreeMap<Hash, (Option<Amount>, String)>>,
        mut skipped: Option<&mut BTreeSet<Hash>>,
    ) -> Result<()> {
        let claimed_work = |parent: Option<&Amount>, block: &Block| {
            let target = math::target_from_bits(block.header.bits).ok()?;
            Some(parent? + math::work(&target))
        };
        // Replay one bounded record at a time instead of buffering the entire database.
        let mut sequence = 0i64;
        let mut replayed = 0u64;
        loop {
            let row: Option<(i64, Vec<u8>, Vec<u8>, u64)> = self.db.query_row(
                "SELECT seq,hash,bytes,accepted_at FROM blocks WHERE seq>?1 AND NOT EXISTS(SELECT 1 FROM entry_index e WHERE e.hash=blocks.hash) ORDER BY seq LIMIT 1",
                [sequence], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional()?;
            let Some((seq, raw_hash, bytes, accepted_at)) = row else {
                break;
            };
            sequence = seq;
            let block: Block = codec::decode_block(&bytes, bytes.len())?;
            let hash = codec::block_hash(&block);
            ensure!(raw_hash == hash, "stored block hash mismatch");
            if let Some(rejected) = rejected.as_deref_mut() {
                // Set aside by an earlier pass of the same replay.
                if rejected.contains_key(&hash) {
                    continue;
                }
                if let Some((parent, _)) = rejected.get(&block.header.previous) {
                    let claimed = claimed_work(parent.as_ref(), &block);
                    rejected.insert(hash, (claimed, "parent block fails validation".into()));
                    continue;
                }
            }
            if let Some(skipped) = skipped.as_deref_mut()
                && (skipped.contains(&hash) || skipped.contains(&block.header.previous))
            {
                skipped.insert(hash);
                continue;
            }
            // A stored block whose parent is no longer stored, as a deletion
            // that an older build interrupted may leave, is set aside with
            // its descendants like one that fails validation. It claims no
            // work: if the persisted tip were among them, the tip would have
            // no index entry and startup still stops.
            if let Some(rejected) = rejected.as_deref_mut()
                && self.load_entry(&block.header.previous)?.is_none()
            {
                rejected.insert(hash, (Some(Amount::zero()), "parent block absent".into()));
                continue;
            }
            let (entry, state) = match self.validate_block(&block, accepted_at, false) {
                Ok(valid) => valid,
                Err(error) if error.is::<PermanentBlockError>() && rejected.is_some() => {
                    let parent = self.load_entry(&block.header.previous)?;
                    let claimed = claimed_work(parent.as_ref().map(|entry| &entry.work), &block);
                    if let Some(rejected) = rejected.as_deref_mut() {
                        rejected.insert(hash, (claimed, error.to_string()));
                    }
                    continue;
                }
                Err(error) => return Err(error.context("invalid stored history")),
            };
            let best = entry.work > self.tip_entry.work;
            self.db.execute(
                "INSERT INTO entry_index(hash,bytes) VALUES(?1,?2)",
                params![hash.as_slice(), codec::encode(&entry)],
            )?;
            if best {
                Self::write_canonical(&self.db, hash, entry.height)?;
            }
            self.record(hash, block, Arc::new(entry), state, best);
            replayed += 1;
            // Derived indexes are rebuilt from scratch whenever they are in
            // doubt, so an interrupted rebuild loses nothing; committing in
            // batches keeps the write-ahead log, and the free space it needs,
            // bounded.
            if replayed.is_multiple_of(INDEX_REBUILD_BATCH) {
                self.db.execute_batch("COMMIT; BEGIN IMMEDIATE;")?;
            }
        }
        Ok(())
    }
    /// Start from the newest saved checkpoint that passes its checks, see
    /// [Chain::resume]. False when none qualifies. An error leaves only
    /// derived rows changed, which a full replay rebuilds.
    fn restore(&mut self) -> Result<bool> {
        let Some(build) = build_identity() else {
            return Ok(false);
        };
        let saved: Vec<(u64, Vec<u8>, Vec<u8>, u64)> = self
            .db
            .prepare("SELECT height,hash,build,length FROM state_checkpoints ORDER BY height DESC")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        if saved.is_empty() {
            return Ok(false);
        }
        let indexed_by: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT hash FROM canonical_index WHERE height=?1",
                [INDEX_BUILD_HEIGHT],
                |r| r.get(0),
            )
            .optional()?;
        if indexed_by.as_deref() != Some(build.as_slice()) {
            // After an upgrade, the previous binary derived the indexes and
            // saved the checkpoints alike.
            eprintln!(
                "Ignoring state checkpoints saved by another build; replaying all stored history"
            );
            return Ok(false);
        }
        let mut foreign = false;
        for (height, hash, saved_build, length) in saved {
            // Only this build's checkpoint on the saved active chain qualifies.
            let Ok(hash) = Hash::try_from(hash.as_slice()) else {
                continue;
            };
            if saved_build != build {
                if !foreign {
                    eprintln!("Ignoring state checkpoints saved by another build");
                }
                foreign = true;
                continue;
            }
            if height == 0 || self.canonical_hash(height)? != Some(hash) {
                continue;
            }
            match self.load_checkpoint(height, &hash, length) {
                Ok(state) => {
                    self.resume(height, hash, state)?;
                    eprintln!(
                        "Started from the state checkpoint at height {height}; revalidated the stored blocks above it"
                    );
                    return Ok(true);
                }
                Err(error) => {
                    eprintln!(
                        "Discarding the saved state checkpoint at height {height}: {error:#}"
                    );
                    self.note_checkpoint_error(Some(format!(
                        "height {height}: {}",
                        error_text(&error)
                    )));
                    Self::delete_saved_state(&self.db, height)?;
                }
            }
        }
        Ok(false)
    }
    /// Report why the last checkpoint save, or one found when needed, failed;
    /// None once a checkpoint is saved.
    fn note_checkpoint_error(&self, error: Option<String>) {
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .checkpoint_error = error;
    }
    /// Decode a saved state and check it against the block it belongs to: its
    /// root must equal the committed state root, and since that root omits a
    /// decision's copy of its winning action, the full state audit must pass.
    /// A decision's PASS world is rebuilt on its FAIL world (see
    /// [State::split_pass_records]), so decoding it never holds a second copy
    /// of the account records the two worlds share, and the root check covers
    /// the rebuilt world too.
    fn load_checkpoint(&self, height: u64, hash: &Hash, length: u64) -> Result<Arc<State>> {
        let mut parts = PartReader {
            db: &self.db,
            height,
            part: 0,
            buffer: Vec::new(),
            offset: 0,
        };
        let (state, pass): (State, SavedPassChanges) = checkpoint_options()
            .with_limit(length)
            .deserialize_from(&mut parts)?;
        ensure!(parts.read(&mut [0])? == 0, "saved state has trailing bytes");
        let mut state = state.with_pass_records(pass)?;
        let block = self.load_block(hash)?.context("checkpoint block absent")?;
        ensure!(
            codec::block_hash(&block) == *hash
                && block.height == height
                && state.height == height
                && codec::merkle_root(&block)? == block.header.merkle_root,
            "saved state does not belong to its block"
        );
        ensure!(
            state.root() == block.state_root,
            "saved state differs from its block's state commitment"
        );
        state.audit(&self.config)?;
        // Share the decision's action with its committed entry, as execution does.
        if let Phase::Governance(decision) = &mut state.phase
            && let Some(action) = state.actions.get_shared(&decision.proposal_id)
        {
            decision.proposal = action.clone();
        }
        Ok(Arc::new(state))
    }
    /// Make a checked saved state the tip and rebuild only what lies above it.
    /// Its active-chain ancestors and the stored losing branches forking below
    /// it keep their persisted index entries, each checked against its
    /// parent's (see [Chain::check_entry]); none of them is executed. Its
    /// stored descendants are validated again in storage order, and the saved
    /// tip must come out on top, so the result is the one a full replay gives.
    fn resume(&mut self, height: u64, hash: Hash, state: Arc<State>) -> Result<()> {
        self.index_genesis()?;
        let mut ancestry = (codec::block_hash(&self.genesis), self.tip_entry.clone());
        let mut descendants = BTreeSet::from([hash]);
        let mut losing = Vec::new();
        let mut indexed = 1u64;
        {
            // Parents precede children in storage order, so the ancestry
            // arrives one height at a time and descendants after their parents.
            let mut statement = self.db.prepare(
                "SELECT b.hash,e.bytes FROM blocks b LEFT JOIN entry_index e ON e.hash=b.hash ORDER BY b.seq",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let raw: Vec<u8> = row.get(0)?;
                let block_hash = Hash::try_from(raw.as_slice()).context("malformed block hash")?;
                let entry = row
                    .get::<_, Option<Vec<u8>>>(1)?
                    .map(|bytes| codec::decode::<Entry>(&bytes, 4096))
                    .transpose()?;
                indexed += u64::from(entry.is_some());
                if let Some(entry) = &entry
                    && entry.height <= height
                    && self.canonical_hash(entry.height)? == Some(block_hash)
                {
                    ensure!(
                        entry.height == ancestry.1.height + 1
                            && entry.header.previous == ancestry.0,
                        "saved active chain is not linked"
                    );
                    let skip = self
                        .canonical_hash(skip_height(entry.height))?
                        .context("saved skip target absent")?;
                    self.check_entry(&block_hash, entry, &ancestry.1, Some(skip))?;
                    ancestry = (block_hash, Arc::new(entry.clone()));
                    continue;
                }
                // A descendant without an entry is one an interrupted start
                // had not rebuilt yet; it is validated below either way.
                let previous = match &entry {
                    Some(entry) => entry.header.previous,
                    None => {
                        self.load_block(&block_hash)?
                            .context("stored block absent")?
                            .header
                            .previous
                    }
                };
                if descendants.contains(&previous) {
                    descendants.insert(block_hash);
                } else {
                    ensure!(entry.is_some(), "stored losing block has no index entry");
                    losing.push(block_hash);
                }
            }
        }
        ensure!(
            ancestry.0 == hash && ancestry.1.height == height,
            "checkpoint is not on the saved active chain"
        );
        let entry = ancestry.1;
        ensure!(
            entry.clock == state.clock && entry.capacity >= state.settings.block_bytes,
            "saved state disagrees with its block's index entry"
        );
        let total: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM entry_index", [], |r| r.get(0))?;
        ensure!(total == indexed, "index entries without stored blocks");
        let saved_tip = self
            .persisted_tip()?
            .and_then(|raw| Hash::try_from(raw.as_slice()).ok())
            .context("saved tip absent")?;
        ensure!(
            descendants.contains(&saved_tip),
            "saved tip does not descend from the checkpoint"
        );
        descendants.remove(&hash);
        for descendant in &descendants {
            self.db
                .prepare_cached("DELETE FROM entry_index WHERE hash=?1")?
                .execute([descendant.as_slice()])?;
        }
        self.db
            .execute("DELETE FROM canonical_index WHERE height>?1", [height])?;
        self.tip_block = self.load_block(&hash)?.context("checkpoint block absent")?;
        self.tip = hash;
        self.tip_entry = entry;
        self.tip_state = state;
        self.restored = Some((height, hash));
        // Losing blocks follow their parents too: each is checked against an
        // ancestor or a losing block already checked.
        let mut checked = BTreeSet::new();
        let mut heaviest = Amount::zero();
        for hash in losing {
            let entry = Self::read_entry(&self.db, &hash)?.context("losing entry absent")?;
            let previous = entry.header.previous;
            let parent = self
                .load_entry(&previous)?
                .context("losing block parent absent")?;
            ensure!(
                checked.contains(&previous)
                    || self.canonical_hash(parent.height)? == Some(previous),
                "losing block parent is not checked"
            );
            let mut cursor = Some((previous, parent.clone()));
            let skip = self.branch_ancestor(&mut cursor, skip_height(entry.height))?;
            self.check_entry(&hash, &entry, &parent, Some(skip))?;
            heaviest = heaviest.max(entry.work.clone());
            checked.insert(hash);
            let tip = (self.tip, self.tip_entry.clone());
            self.note_branch(hash, &entry, false, tip);
        }
        self.replay_stored(None, None)?;
        self.follow_tip_hint(Some(saved_tip))?;
        ensure!(
            self.tip == saved_tip && heaviest <= self.tip_entry.work,
            "blocks above the checkpoint do not lead to the saved tip"
        );
        self.refresh_capacity();
        Ok(())
    }
    /// A persisted index entry agrees with its checked parent's: its header
    /// hashes to the block, its height, target, work and schedule anchors
    /// follow from the parent, its clock advances and its capacity never
    /// falls. `skip`, when given, is the checked ancestor at its skip height.
    fn check_entry(
        &self,
        hash: &Hash,
        entry: &Entry,
        parent: &Entry,
        skip: Option<Hash>,
    ) -> Result<()> {
        let target = self.target(parent)?;
        let interval = entry
            .clock
            .checked_sub(parent.clock)
            .filter(|interval| *interval > 0)
            .context("index entry clock does not advance")?;
        let anchors = match parent.height {
            0 => (entry.header.timestamp, entry.clock),
            1 => (
                parent.anchor_timestamp.max(u32::try_from(
                    u64::from(entry.header.timestamp).saturating_sub(interval),
                )?),
                parent.anchor_clock,
            ),
            _ => (parent.anchor_timestamp, parent.anchor_clock),
        };
        ensure!(
            crypto::sha256d(&codec::header_bytes(&entry.header)) == *hash
                && entry.height == parent.height + 1
                && entry.header.bits == math::bits_from_target(&target)
                && entry.work == &parent.work + math::work(&target)
                && (entry.anchor_timestamp, entry.anchor_clock) == anchors
                && entry.capacity >= parent.capacity
                && skip.is_none_or(|skip| entry.skip == skip),
            "index entry disagrees with its parent's"
        );
        Ok(())
    }
    /// Saved checkpoints on the active chain, newest first.
    fn saved_checkpoints(&self) -> Result<Vec<(u64, Hash)>> {
        let rows: Vec<(u64, Vec<u8>)> = self
            .db
            .prepare_cached("SELECT height,hash FROM state_checkpoints ORDER BY height DESC")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let mut saved = Vec::new();
        for (height, hash) in rows {
            if let Ok(hash) = Hash::try_from(hash.as_slice())
                && self.canonical_hash(height)? == Some(hash)
            {
                saved.push((height, hash));
            }
        }
        Ok(saved)
    }
    /// Save the active-chain state CHECKPOINT_DEPTH below the tip once it is
    /// at least `gap` heights above the newest checkpoint saved on the active
    /// chain, and, for a periodic save, at least one checkpoint interval
    /// above genesis. Saving is an optimisation only: a failure is logged,
    /// reported (see [StorageHealth]) and costs the next start replay, and
    /// the older checkpoints are kept.
    /// A periodic save (`gap` above 1) audits the state on its own thread,
    /// off the node lock, and writes it at a later block once the audit has
    /// passed; after a failure, periodic saves wait (see
    /// CHECKPOINT_RETRY_INTERVALS). A clean stop (`gap` 1) finishes a pending
    /// save and audits and saves its own at once.
    fn save_checkpoint(&mut self, gap: u64) {
        match self.try_save_checkpoint(gap) {
            Ok(false) => {}
            Ok(true) => {
                self.checkpoint_failures = 0;
                self.checkpoint_retry = 0;
                self.note_checkpoint_error(None);
            }
            Err(error) => {
                eprintln!("Could not save a state checkpoint, keeping the older ones: {error:#}");
                // A failed write leaves the write-ahead log at its peak size,
                // up to the space that was free; return that space now.
                let _ = self.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
                self.checkpoint_failures = self.checkpoint_failures.saturating_add(1);
                let intervals = 1u64
                    .checked_shl(self.checkpoint_failures - 1)
                    .unwrap_or(u64::MAX)
                    .min(CHECKPOINT_RETRY_INTERVALS);
                self.checkpoint_retry = self
                    .tip_height()
                    .saturating_add(intervals.saturating_mul(self.checkpoint_every));
                self.note_checkpoint_error(Some(error_text(&error)));
            }
        }
    }
    /// True when a checkpoint was written.
    fn try_save_checkpoint(&mut self, gap: u64) -> Result<bool> {
        let Some(build) = build_identity() else {
            return Ok(false);
        };
        let (stop, tip) = (gap <= 1, self.tip_height());
        let mut written = false;
        if let Some(audit) = self.checkpoint_audit.take_if(|audit| {
            stop || audit.audit.is_finished() || tip >= audit.started + CHECKPOINT_AUDIT_BLOCKS
        }) {
            written = self.write_audited(audit, &build)?;
            if !stop {
                return Ok(written);
            }
        }
        if self.checkpoint_audit.is_some() || (!stop && tip < self.checkpoint_retry) {
            return Ok(written);
        }
        // Periodic saves begin one interval above genesis; a clean stop saves
        // at any height, so the next start validates only the blocks above
        // it, however short the chain.
        let floor = if stop {
            1
        } else {
            self.checkpoint_every.max(1)
        };
        let Some(height) = tip
            .checked_sub(CHECKPOINT_DEPTH)
            .filter(|height| *height >= floor)
        else {
            return Ok(written);
        };
        let saved = self.saved_checkpoints()?;
        if saved
            .first()
            .is_some_and(|(newest, _)| newest.saturating_add(gap) > height)
        {
            return Ok(written);
        }
        let Some(hash) = self.canonical_hash(height)? else {
            return Ok(written);
        };
        // The dense window retains it unless a reorganization just evicted it.
        let Some(state) = self.checkpoint_state(height, &hash) else {
            return Ok(written);
        };
        if stop {
            state
                .audit(&self.config)
                .with_context(|| format!("the state at height {height} fails its audit"))?;
            self.write_checkpoint(height, &hash, &build, &state, &saved)?;
            return Ok(true);
        }
        let (config, audited) = (self.config.clone(), state.clone());
        let audit = std::thread::Builder::new()
            .name("checkpoint-audit".into())
            .spawn(move || audited.audit(&config))
            .context("cannot start the state audit")?;
        self.checkpoint_audit = Some(CheckpointAudit {
            height,
            hash,
            state,
            started: tip,
            audit,
        });
        Ok(false)
    }
    /// Write a periodic checkpoint whose audit ended, if it passed and its
    /// block is still on the active chain above the newest saved one. True
    /// when it was written.
    fn write_audited(&mut self, audit: CheckpointAudit, build: &Hash) -> Result<bool> {
        let height = audit.height;
        audit
            .audit
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the audit panicked")))
            .with_context(|| format!("the state at height {height} fails its audit"))?;
        if self.canonical_hash(height)? != Some(audit.hash) {
            return Ok(false);
        }
        let saved = self.saved_checkpoints()?;
        if saved.first().is_some_and(|(newest, _)| *newest >= height) {
            return Ok(false);
        }
        self.write_checkpoint(height, &audit.hash, build, &audit.state, &saved)?;
        Ok(true)
    }
    /// Save `state` at `height`, above every one of `saved` (the active
    /// chain's, newest first), keeping those [saved_checkpoints_kept] names
    /// and deleting every other. Refused while free disk space is below twice
    /// the largest saved state plus STORAGE_RESERVE_BYTES: the new state is
    /// written before the old ones go, and the write-ahead log holds it too.
    fn write_checkpoint(
        &mut self,
        height: u64,
        hash: &Hash,
        build: &Hash,
        state: &State,
        saved: &[(u64, Hash)],
    ) -> Result<()> {
        if let Some(free) = free_bytes(&self.path) {
            let largest: Option<u64> =
                self.db
                    .query_row("SELECT MAX(length) FROM state_checkpoints", [], |r| {
                        r.get(0)
                    })?;
            let needed = largest
                .unwrap_or(0)
                .saturating_mul(2)
                .saturating_add(STORAGE_RESERVE_BYTES);
            ensure!(
                free >= needed,
                "{free} bytes of disk space are free, below the {needed} a save needs"
            );
        }
        let heights: Vec<u64> = std::iter::once(height)
            .chain(saved.iter().map(|(height, _)| *height))
            .collect();
        let keep = saved_checkpoints_kept(&heights, self.checkpoint_every);
        let transaction = self.db.transaction()?;
        Self::write_saved_state(&transaction, height, hash, build, state)?;
        let all: Vec<u64> = transaction
            .prepare("SELECT height FROM state_checkpoints")?
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for old in all.into_iter().filter(|height| !keep.contains(height)) {
            Self::delete_saved_state(&transaction, old)?;
        }
        transaction.commit()?;
        Ok(())
    }
    /// Store `state` as the saved checkpoint of the block `hash` at `height`:
    /// its serde encoding, except that a decision's PASS world lists only its
    /// account records that differ from the FAIL world's.
    fn write_saved_state(
        db: &Connection,
        height: u64,
        hash: &Hash,
        build: &Hash,
        state: &State,
    ) -> Result<()> {
        db.execute(
            "DELETE FROM state_checkpoint_parts WHERE height=?1",
            [height],
        )?;
        let mut parts = PartWriter {
            db,
            height,
            parts: 0,
            length: 0,
            buffer: Vec::with_capacity(CHECKPOINT_PART_BYTES),
        };
        checkpoint_options().serialize_into(&mut parts, &state.split_pass_records())?;
        parts.flush_part()?;
        db.execute(
            "INSERT OR REPLACE INTO state_checkpoints(height,hash,build,length) VALUES(?1,?2,?3,?4)",
            params![height, hash.as_slice(), build.as_slice(), parts.length],
        )?;
        Ok(())
    }
    fn delete_saved_state(db: &Connection, height: u64) -> Result<()> {
        db.execute(
            "DELETE FROM state_checkpoint_parts WHERE height=?1",
            [height],
        )?;
        db.execute("DELETE FROM state_checkpoints WHERE height=?1", [height])?;
        Ok(())
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
        checkpoint
            .or_else(|| self.pinned.get(hash).cloned())
            .or_else(|| self.cache.borrow().states.get(hash).cloned())
    }
    /// The newest retained active-chain checkpoint at or below `height`, at most
    /// about half that height's depth below it, except below the state a start
    /// restored, where only genesis is retained until a replay through that
    /// height retains checkpoints again. Like cached_state, it never replays.
    pub fn checkpoint_at_or_below(&self, height: u64) -> Option<(Hash, Arc<State>)> {
        self.checkpoints
            .borrow()
            .range(..=height)
            .next_back()
            .filter(|(height, (hash, _))| self.hash_at_height(**height) == Some(*hash))
            .map(|(_, (hash, state))| (*hash, state.clone()))
    }
    /// The storage faults this chain reports, shared, so a reader can follow
    /// them without the chain.
    pub fn storage_health(&self) -> Arc<std::sync::Mutex<StorageHealth>> {
        self.health.clone()
    }
    /// Let the database grow by at most `pages` more pages (None: no limit),
    /// so writes fail as on a full disk.
    #[cfg(test)]
    pub(crate) fn limit_database_pages(&self, pages: Option<u64>) {
        let count: u64 = self
            .db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        let limit = pages.map_or(1 << 30, |pages| count + pages);
        self.db
            .execute_batch(&format!("PRAGMA max_page_count={limit}"))
            .unwrap();
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
    /// A recent state, marked most recently used, or a pinned one.
    fn recent_state(&self, hash: &Hash) -> Option<Arc<State>> {
        if let Some(state) = self.pinned.get(hash) {
            return Some(state.clone());
        }
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
        // A priority record stays one, whichever block resumes it next.
        let mut priority = self.replay_priority.get();
        let resumed = self
            .replay
            .borrow_mut()
            .take_if(|replay| replay.target == *hash)
            .or_else(|| {
                let mut kept = self.priority_replays.borrow_mut();
                let position = kept.iter().position(|replay| replay.target == *hash)?;
                priority = true;
                kept.remove(position)
            });
        let mut replay = match resumed {
            Some(replay) => replay,
            None => self.start_replay(hash)?,
        };
        let result = match self.run_replay(&mut replay, priority) {
            Err(error) if error.is::<StaleReplay>() => {
                // The active chain changed below retained progress; start over.
                replay = self.start_replay(hash)?;
                self.run_replay(&mut replay, priority)
            }
            result => result,
        };
        match result {
            Err(error) if error.is::<ValidationDeferred>() => {
                self.keep_replay(replay, priority)?;
                Err(error)
            }
            result => {
                self.clear_replay_path(hash)?;
                result
            }
        }
    }
    /// Keep deferred progress for a retry: a block that would become the tip
    /// or belongs to an admitted held chain in its own record (`priority`),
    /// which side blocks never take over, even one resuming it, others in
    /// the one record side blocks share. Only a record taken over enters the
    /// recent cache, with its latest progress, so a side block deferred hold
    /// after hold adds nothing there.
    fn keep_replay(&self, replay: Replay, priority: bool) -> Result<()> {
        let displaced = if priority {
            let mut priority = self.priority_replays.borrow_mut();
            priority.push_back(replay);
            if priority.len() > MAX_PRIORITY_REPLAYS {
                priority.pop_front()
            } else {
                None
            }
        } else {
            self.replay.borrow_mut().replace(replay)
        };
        if let Some(displaced) = displaced {
            if let Some((base, state)) = &displaced.base {
                self.cache_state(*base, state.clone());
            }
            self.clear_replay_path(&displaced.target)?;
        }
        Ok(())
    }
    /// After a start from a saved checkpoint, only genesis is retained below
    /// it. For a priority replay (see [Chain::keep_replay]), one that would
    /// otherwise run from a retained state at `below` up to `meeting` on the
    /// active chain, more than a checkpoint interval: the newest saved
    /// checkpoint between them on the active chain that passes its checks
    /// (see [Chain::load_checkpoint]), retained from then on. Loading it
    /// costs one replay step and one state's decoding and audit. Side blocks
    /// never load one.
    fn load_saved_between(
        &self,
        below: u64,
        meeting: u64,
        priority: bool,
    ) -> Result<Option<(u64, Hash, Arc<State>)>> {
        if !priority
            || self.restored.is_none()
            || meeting.saturating_sub(below) <= self.checkpoint_every
        {
            return Ok(None);
        }
        let Some(build) = build_identity() else {
            return Ok(None);
        };
        let saved: Vec<(u64, Vec<u8>, Vec<u8>, u64)> = self
            .db
            .prepare_cached("SELECT height,hash,build,length FROM state_checkpoints WHERE height>?1 AND height<=?2 ORDER BY height DESC")?
            .query_map([below, meeting], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (height, hash, saved_build, length) in saved {
            let Ok(hash) = Hash::try_from(hash.as_slice()) else {
                continue;
            };
            if saved_build != build || self.canonical_hash(height)? != Some(hash) {
                continue;
            }
            self.charge_replay()?;
            match self.load_checkpoint(height, &hash, length) {
                Ok(state) => {
                    eprintln!(
                        "Loaded the saved state checkpoint at height {height} to rebuild a fork point below the restored one"
                    );
                    self.checkpoints
                        .borrow_mut()
                        .insert(height, (hash, state.clone()));
                    self.loaded.set(Some((height, hash)));
                    return Ok(Some((height, hash, state)));
                }
                Err(error) => {
                    eprintln!(
                        "Discarding the saved state checkpoint at height {height}: {error:#}"
                    );
                    self.note_checkpoint_error(Some(format!(
                        "height {height}: {}",
                        error_text(&error)
                    )));
                    Self::delete_saved_state(&self.db, height)?;
                }
            }
        }
        Ok(None)
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
    fn run_replay(&self, replay: &mut Replay, priority: bool) -> Result<Arc<State>> {
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
                // Only the recent states are candidates, so finding the
                // nearest takes at most MAX_CACHED_STATES index reads however
                // far the checkpoint lies below the meeting height.
                let mut recent: Vec<(u64, Hash)> = self
                    .cache
                    .borrow()
                    .states
                    .iter()
                    .filter(|(_, state)| state.height > height && state.height < entry.height)
                    .map(|(hash, state)| (state.height, *hash))
                    .collect();
                recent.sort_unstable_by(|a, b| b.cmp(a));
                for (retained, hash) in recent {
                    if self.canonical_hash(retained)? == Some(hash)
                        && let Some(state) = self.recent_state(&hash)
                    {
                        (height, base) = (retained, (hash, state));
                        break;
                    }
                }
                if let Some((saved, hash, state)) =
                    self.load_saved_between(height, entry.height, priority)?
                {
                    (height, base) = (saved, (hash, state));
                }
                replay.base = Some(base);
                replay.canonical = (height + 1, entry.height);
                replay.meeting = cursor;
                replay.walk = None;
                break;
            }
            if steps.is_multiple_of(WALK_STEPS_PER_REPLAY_STEP) {
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
        #[cfg(test)]
        REPLAYED_BLOCKS.with(|count| count.set(count.get() + 1));
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
            self.refill_side_budget(entry.height);
        } else {
            self.cache_state(hash, state);
        }
        self.note_branch(hash, &entry, best, previous);
        self.refresh_capacity();
    }
    /// The most side-branch bytes the budget holds: SIDE_BRANCH_BURST_BYTES,
    /// or a refill's worth of block capacities if that is more.
    fn side_bytes_cap(&self) -> u64 {
        let refill = SIDE_BRANCH_BLOCKS_PER_TIP.saturating_mul(self.tip_state.settings.block_bytes);
        SIDE_BRANCH_BURST_BYTES.max(refill)
    }
    /// Only new active-chain heights refill side-branch admissions, by
    /// SIDE_BRANCH_BLOCKS_PER_TIP blocks and as many block capacities each.
    fn refill_side_budget(&mut self, height: u64) {
        if height <= self.side_budget_height {
            return;
        }
        let gained = height - self.side_budget_height;
        self.side_budget = gained
            .saturating_mul(SIDE_BRANCH_BLOCKS_PER_TIP)
            .saturating_add(self.side_budget)
            .min(SIDE_BRANCH_BURST);
        let refill = SIDE_BRANCH_BLOCKS_PER_TIP.saturating_mul(self.tip_state.settings.block_bytes);
        self.side_budget_bytes = gained
            .saturating_mul(refill)
            .saturating_add(self.side_budget_bytes)
            .min(self.side_bytes_cap());
        self.side_budget_height = height;
    }
    /// The side-branch budgets as the previous run left them (see
    /// [Chain::finish_submission]), refilled for the heights the active chain
    /// gained since; full budgets for a database without them. A restart
    /// therefore grants no new burst of side blocks.
    fn resume_side_budget(&mut self) -> Result<()> {
        let tip = self.tip_height();
        let saved: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='side_budget'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let saved = saved.filter(|raw| raw.len() == 24).map(|raw| {
            let word = |at: usize| u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
            (word(0), word(8), word(16))
        });
        let (blocks, bytes, height) =
            saved.unwrap_or((SIDE_BRANCH_BURST, SIDE_BRANCH_BURST_BYTES, tip));
        self.side_budget = blocks.min(SIDE_BRANCH_BURST);
        self.side_budget_bytes = bytes.min(self.side_bytes_cap());
        self.side_budget_height = height.min(tip);
        self.refill_side_budget(tip);
        Ok(())
    }
    fn side_budget_record(blocks: u64, bytes: u64, height: u64) -> Vec<u8> {
        [blocks, bytes, height]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect()
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
            // A reorganization below the restored state rebuilt its fork point
            // from genesis, retaining checkpoints on the way like any replay,
            // so branches off the new active chain are cheap to rebuild again.
            if let Some((height, hash)) = self.restored
                && self.canonical_hash(height).ok().flatten() != Some(hash)
            {
                self.restored = None;
            }
            if let Some((height, hash)) = self.loaded.get()
                && self.canonical_hash(height).ok().flatten() != Some(hash)
            {
                self.loaded.set(None);
            }
            // States pinned for admitted held chains whose blocks are now on
            // the active chain return to the recent cache, which feeds the
            // retained heights below.
            let adopted: Vec<Hash> = self
                .pinned
                .iter()
                .filter(|(hash, state)| {
                    self.canonical_hash(state.height).ok().flatten() == Some(**hash)
                })
                .map(|(hash, _)| *hash)
                .collect();
            for hash in adopted {
                if let Some(state) = self.pinned.remove(&hash) {
                    self.cache_state(hash, state);
                }
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
        let restored = self.restored.map(|(height, _)| height);
        let loaded = self.loaded.get().map(|(height, _)| height);
        self.checkpoints.get_mut().retain(|retained, _| {
            checkpoint_retained(*retained, height)
                || Some(*retained) == restored
                || Some(*retained) == loaded
        });
    }
    /// Track stored losing-branch leaves that could still raise peer capacity.
    fn note_branch(&mut self, hash: Hash, entry: &Entry, best: bool, previous: (Hash, Arc<Entry>)) {
        self.branches.remove(&entry.header.previous);
        self.branches.remove(&hash);
        if !best {
            self.branches.insert(hash, BranchLeaf::of(entry));
        } else if entry.header.previous != previous.0 && previous.0 != hash {
            // A tip has no stored children, so the previous tip is now a leaf.
            self.branches
                .insert(previous.0, BranchLeaf::of(&previous.1));
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
        #[cfg(test)]
        CANONICAL_LOOKUPS.with(|count| count.set(count.get() + 1));
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
    /// `size` is the block's encoded length.
    fn admit_branch(
        &self,
        previous: &Hash,
        parent: &Arc<Entry>,
        work: &Amount,
        size: u64,
    ) -> Result<()> {
        let branch = &parent.work + work;
        if branch > self.tip_entry.work {
            return Ok(());
        }
        let next = math::work(&self.target(&self.tip_entry)?);
        Self::competitive(&self.tip_entry.work, &branch, work, &next).map_err(SideBranchRefused)?;
        if self.side_budget == 0 {
            return Err(SideBranchRefused("side-branch admission budget is spent").into());
        }
        if self.side_budget_bytes < size {
            return Err(SideBranchRefused("side-branch storage budget is spent").into());
        }
        if free_bytes(&self.path).is_some_and(|free| free < STORAGE_RESERVE_BYTES) {
            return Err(SideBranchRefused("free disk space is below the reserve").into());
        }
        if self.forks_below_restored(previous, parent)? {
            return Err(
                SideBranchRefused("branch forks below the state restored at startup").into(),
            );
        }
        Ok(())
    }
    /// After a start from a saved checkpoint, only genesis is retained below
    /// it: rebuilding a parent state on a branch that forks there would replay
    /// from genesis rather than about its depth. Such a losing branch is held
    /// as headers until it claims more work than the tip, like any declined one.
    fn forks_below_restored(&self, previous: &Hash, parent: &Arc<Entry>) -> Result<bool> {
        let Some((height, hash)) = self.restored else {
            return Ok(false);
        };
        if self.cached_state(previous).is_some() {
            return Ok(false);
        }
        if parent.height < height {
            return Ok(true);
        }
        let mut cursor = Some((*previous, parent.clone()));
        Ok(self.branch_ancestor(&mut cursor, height)? != hash)
    }
    /// Whether a losing branch ending in a block of `work` stays worth keeping
    /// against a tip of work `tip` whose next block carries `next`.
    fn competitive(
        tip: &Amount,
        branch: &Amount,
        work: &Amount,
        next: &Amount,
    ) -> std::result::Result<(), &'static str> {
        if work * SIDE_BRANCH_WORK_RATIO < *next {
            return Err("block work is far below the active chain's");
        }
        if branch + work * SIDE_BRANCH_CATCH_UP_BLOCKS < *tip {
            return Err("branch cannot plausibly overtake the active chain");
        }
        Ok(())
    }
    /// Hold a header without its block, so its branch can still be presynced
    /// from peers. Held headers are never executed. A chain that claims more
    /// work than the tip is admitted, proven by proof of work alone; its
    /// headers are persisted and its bodies validated when they arrive. A
    /// nonzero `pin` keeps the header for that header download. A header
    /// that would make more than MAX_SYNC_HEADERS pinned or admitted is not
    /// held.
    fn hold(&mut self, hash: Hash, held: HeldHeader, pin: u64) -> Result<HeaderHold> {
        let overtakes = held.claimed > self.tip_entry.work;
        let cost = usize::from(pin != 0 || overtakes)
            + if overtakes {
                self.held.admission_cost(&held.header.previous)
            } else {
                0
            };
        if cost > 0 && self.held.fixed() + cost > MAX_SYNC_HEADERS {
            return Ok(HeaderHold::Full);
        }
        self.held.insert(hash, held);
        self.held.pin(hash, pin);
        let hold = if overtakes {
            let marked = self.held.admit(&hash);
            match &mut self.held_batch {
                Some(batch) => batch.extend(marked),
                None => {
                    self.persist_held(&marked)?;
                    // Its stored root may raise the capacity allowance.
                    self.refresh_capacity();
                    self.repin();
                }
            }
            HeaderHold::Admitted
        } else {
            HeaderHold::Held
        };
        self.held.evict();
        Ok(hold)
    }
    /// Run `hold`, holding headers, with the headers it admits persisted in
    /// one savepoint at its end and the capacity allowance refreshed once:
    /// a header reply then commits once, not once per admitted header.
    pub fn hold_batch<T>(&mut self, hold: impl FnOnce(&mut Self) -> T) -> Result<T> {
        if self.held_batch.is_some() {
            // An enclosing batch persists these too.
            return Ok(hold(self));
        }
        self.held_batch = Some(Vec::new());
        let result = hold(self);
        let marked: Vec<Hash> = self
            .held_batch
            .take()
            .unwrap_or_default()
            .into_iter()
            .filter(|hash| self.held.admitted(hash))
            .collect();
        if !marked.is_empty() {
            self.persist_held(&marked)?;
            self.refresh_capacity();
            self.repin();
        }
        Ok(result)
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
        #[cfg(test)]
        HELD_COMMITS.with(|count| count.set(count.get() + 1));
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
    /// A nonzero `pin` keeps it from eviction until that pin is released: a
    /// header download fetches a branch again only after counting that it
    /// claims more work than the tip. An admitted chain already leading the
    /// tip by HELD_LEAD_BLOCKS next-block works, or extended by
    /// HELD_LEAD_HEADERS headers, is not extended. Nothing is pinned or
    /// admitted beyond MAX_SYNC_HEADERS.
    pub fn hold_header(&mut self, header: Header, now: u64, pin: u64) -> Result<HeaderHold> {
        let hash = crypto::sha256d(&codec::header_bytes(&header));
        if self.load_entry(&hash)?.is_some() {
            return Ok(HeaderHold::Stored);
        }
        if let Some(held) = self.held.headers.get(&hash) {
            if held.admitted {
                return Ok(HeaderHold::Admitted);
            }
            if pin != 0 && held.evictable() && self.held.fixed() >= MAX_SYNC_HEADERS {
                return Ok(HeaderHold::Full);
            }
            self.held.pin(hash, pin);
            return Ok(HeaderHold::Held);
        }
        let (height, root, contributed, claimed, lead) =
            match self.held.headers.get(&header.previous) {
                Some(parent) => {
                    if parent.admitted {
                        let next = math::work(&self.target(&self.tip_entry)?);
                        if parent.claimed > &self.tip_entry.work + next * HELD_LEAD_BLOCKS
                            || parent.lead >= HELD_LEAD_HEADERS
                        {
                            return Ok(HeaderHold::Ahead);
                        }
                    }
                    (
                        parent.height + 1,
                        parent.root,
                        parent.contributed.clone(),
                        parent.claimed.clone(),
                        if parent.admitted { parent.lead + 1 } else { 0 },
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
                        0,
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
                pins: 0,
                lead,
            },
            pin,
        )
    }
    /// Whether `hash` is an admitted held header without admitted children,
    /// the only place a peer may extend an admitted chain.
    pub fn admitted_header_tip(&self, hash: &Hash) -> bool {
        self.held.admitted_tip(hash)
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
        Ok(self.held.headers.get(hash).map(
            |header| {
                if header.admitted { header.root } else { *hash }
            },
        ))
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
    /// Held headers that at least one header download pins.
    pub fn pinned_header_count(&self) -> usize {
        self.held
            .headers
            .values()
            .filter(|held| held.pins > 0)
            .count()
    }
    /// Drop a held header and its held descendants, as a failed body does.
    #[cfg(test)]
    pub(crate) fn forget_held_header(&mut self, hash: &Hash) {
        self.held.remove_branch(hash);
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
            self.repin();
        }
        Ok(())
    }
    /// Pin the post-states of the stored blocks where admitted held chains
    /// continue, the parents of their next bodies, while the recent cache
    /// still has them: side-branch traffic can flush that cache, which would
    /// make each body replay its whole branch from the fork point. A state
    /// pinned for a block that no longer roots an admitted chain, because
    /// its child was stored or the chain was dropped, returns to the cache,
    /// as do those beyond MAX_PINNED_STATES whose blocks carry the least work.
    fn repin(&mut self) {
        let released: Vec<Hash> = self
            .pinned
            .keys()
            .filter(|hash| !self.held.roots.contains_key(*hash))
            .copied()
            .collect();
        for hash in released {
            if let Some(state) = self.pinned.remove(&hash) {
                self.cache_state(hash, state);
            }
        }
        let roots: Vec<Hash> = self
            .held
            .roots
            .keys()
            .filter(|root| !self.pinned.contains_key(*root))
            .copied()
            .collect();
        for root in roots {
            if let Some(state) = self.uncache_state(&root) {
                self.pinned.insert(root, state);
            }
        }
        while self.pinned.len() > MAX_PINNED_STATES {
            let weakest = self
                .pinned
                .keys()
                .map(|hash| {
                    let work = self
                        .load_entry(hash)
                        .ok()
                        .flatten()
                        .map(|entry| entry.work.clone());
                    (work.unwrap_or_default(), *hash)
                })
                .min();
            let Some((_, hash)) = weakest else {
                break;
            };
            if let Some(state) = self.pinned.remove(&hash) {
                self.cache_state(hash, state);
            }
        }
    }
    /// Restore the admitted held headers a previous run persisted, at most
    /// MAX_SYNC_HEADERS. Each must still follow a stored block or a restored
    /// header and meet its own proof of work; others are deleted.
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
                        (
                            parent.root,
                            parent.contributed.clone(),
                            parent.claimed.clone(),
                        )
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
                        pins: 0,
                        lead: 0,
                    },
                )))
            })();
            match restored {
                // Rows past the bound on admitted headers are not restored.
                Ok(Some((hash, held))) if self.held.fixed() < MAX_SYNC_HEADERS => {
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
                || Self::competitive(&self.tip_entry.work, &branch, &child, &next).is_ok()
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
            if pruned.is_multiple_of(INDEX_REBUILD_BATCH) {
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
        let validation = self.check_block(block, now, admission, None, &mut |_| Ok(None))?;
        let executed = validation.execute(block)?;
        Ok((executed.entry, executed.state))
    }
    /// Every check of a block that needs this chain: its header against the
    /// stored parent and that parent's required target, proof of work and
    /// Merkle root, the side-branch admission policy, transaction anchors and
    /// the parent state. Executing the block needs only the returned capture.
    /// `budget` is consulted between the admission policy and the anchors
    /// (see [Chain::begin_submission]).
    fn check_block(
        &self,
        block: &Block,
        now: u64,
        admission: bool,
        bytes: Option<Vec<u8>>,
        budget: SubmissionBudget<'_>,
    ) -> Result<BlockValidation> {
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
        // ancestry walk or state reconstruction for the block, beyond the
        // logarithmic skip-link lookup of a start from a saved checkpoint.
        if admission {
            let size = match &bytes {
                Some(bytes) => bytes.len() as u64,
                None => codec::encode(block).len() as u64,
            };
            self.admit_branch(&block.header.previous, &parent, &work, size)?;
        }
        // So are the caller's own bounds on a block that would be stored on a
        // side branch, and the replay its parent state may need.
        let extends = &parent.work + &work > self.tip_entry.work;
        self.replay_budget.set(budget(admission && !extends)?);
        self.replay_priority.set(!admission || extends);
        self.validate_transaction_anchors(&block.header.previous, &block.transactions)
            .map_err(permanent)?;
        // The skip link depends only on the block's own branch, whichever
        // branch is active when the block is stored.
        let mut ancestry = Some((block.header.previous, parent.clone()));
        let skip = self
            .branch_ancestor(&mut ancestry, skip_height(block.height))
            .map_err(permanent)?;
        // Disk/reconstruction failures here are transient local failures and are
        // never entered into the cache of permanently invalid block messages.
        let parent_state = self.load_state(&block.header.previous)?;
        Ok(BlockValidation {
            config: self.config.clone(),
            hash: codec::block_hash(block),
            bytes,
            parent,
            parent_state,
            work,
            skip,
            admitted: !admission,
            extends,
        })
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
        let Some(validation) = self.begin_submission(&block, now, &mut |_| Ok(Some(steps)))? else {
            return Ok(false);
        };
        let executed = validation.execute(&block);
        self.finish_submission(validation, block, executed, now)
    }
    pub fn submit(&mut self, block: Block, now: u64) -> Result<bool> {
        let Some(validation) = self.begin_submission(&block, now, &mut |_| Ok(None))? else {
            return Ok(false);
        };
        let executed = validation.execute(&block);
        self.finish_submission(validation, block, executed, now)
    }
    /// The checks of [Chain::submit] that need this chain. None for a block
    /// that is already stored. Once the block has passed its header checks
    /// and the side-branch admission policy, and before its transaction
    /// anchors, skip-link walk or parent state, `budget` is told whether the
    /// block would be stored on a side branch (it would not become the tip
    /// and is not part of an admitted held chain). It returns the replayed
    /// blocks that rebuilding a historical parent state may run in this call
    /// (None for no limit; see [Chain::submit_with_replay_budget]), or refuses
    /// with [SideBranchRefused], which holds the block's header as the
    /// admission policy does. The returned capture executes the block without
    /// the chain, so a node runs execution, which may clear batch trades for
    /// seconds, outside its chain lock; [Chain::finish_submission] then
    /// stores the result, which is exactly what [Chain::submit] would give
    /// at the time it finishes.
    pub fn begin_submission(
        &mut self,
        block: &Block,
        now: u64,
        budget: SubmissionBudget<'_>,
    ) -> Result<Option<BlockValidation>> {
        let hash = codec::block_hash(block);
        if self.load_entry(&hash)?.is_some() {
            return Ok(None);
        }
        let bytes = codec::encode(block);
        // A header digest alone cannot identify an invalid body: a peer may send
        // another payload carrying the same valid header. Hash the whole record.
        let identity = crypto::sha256d(&bytes);
        self.expire_invalid();
        if let Some(error) = self.invalid_blocks.get(&identity) {
            anyhow::bail!("cached invalid block: {error}");
        }
        if self.held.headers.contains_key(&block.header.previous) {
            self.hold_child(block, now)?;
            return Err(SideBranchRefused("parent is a held side-branch header").into());
        }
        // A held chain that claimed more work than the tip is not declined again.
        let admitted = self.held.admitted(&hash);
        let checked = self.check_block(block, now, !admitted, Some(bytes), budget);
        self.replay_budget.set(None);
        self.replay_priority.set(false);
        match checked {
            Ok(validation) => Ok(Some(validation)),
            Err(error) => {
                if error.is::<SideBranchRefused>() {
                    self.decline(block)?;
                } else if error.downcast_ref::<PermanentBlockError>().is_some() {
                    self.reject(block, identity, &error)?;
                }
                Err(error)
            }
        }
    }
    /// Store a block that [Chain::begin_submission] checked and that was then
    /// executed, returning whether it became the tip. Other blocks may have
    /// been stored meanwhile: one this block's submission raced and lost is
    /// reported as not selected, and a block that no longer extends the tip
    /// passes the side-branch admission policy against the current tip, as
    /// if it had only now arrived. None of its checks depended on the tip.
    pub fn finish_submission(
        &mut self,
        validation: BlockValidation,
        block: Block,
        executed: Result<ExecutedBlock>,
        now: u64,
    ) -> Result<bool> {
        let hash = validation.hash;
        if self.load_entry(&hash)?.is_some() {
            return Ok(false);
        }
        let bytes = validation.bytes.unwrap_or_else(|| codec::encode(&block));
        let ExecutedBlock { entry, state } = match executed {
            Ok(executed) => executed,
            Err(error) => {
                if error.downcast_ref::<PermanentBlockError>().is_some() {
                    self.reject(&block, crypto::sha256d(&bytes), &error)?;
                }
                return Err(error);
            }
        };
        let best = entry.work > self.tip_entry.work;
        let admitted = validation.admitted;
        let size = bytes.len() as u64;
        if !best
            && !admitted
            && let Err(error) = self.admit_branch(
                &block.header.previous,
                &validation.parent,
                &validation.work,
                size,
            )
        {
            if error.is::<SideBranchRefused>() {
                self.decline(&block)?;
            }
            return Err(error);
        }
        // A side block draws on the budgets, which are stored with it.
        let side = (!best && !admitted).then(|| {
            (
                self.side_budget.saturating_sub(1),
                self.side_budget_bytes.saturating_sub(size),
            )
        });
        let budget = side.map(|(blocks, bytes)| {
            Self::side_budget_record(blocks, bytes, self.side_budget_height)
        });
        let stored = (|| -> Result<()> {
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
            if let Some(budget) = &budget {
                transaction.execute("INSERT INTO metadata(key,value) VALUES('side_budget',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [budget])?;
            }
            // A stored block no longer needs its held header.
            transaction.execute("DELETE FROM held_headers WHERE hash=?1", [hash.as_slice()])?;
            transaction.commit()?;
            Ok(())
        })();
        // A failed commit, such as on a full disk, rolls back and changes
        // nothing else; the node reports the streak and may stop over it.
        {
            let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
            match &stored {
                Ok(()) => {
                    health.failed_commits = 0;
                    health.failing_since = None;
                    health.last_error = None;
                }
                Err(error) => {
                    health.failed_commits = health.failed_commits.saturating_add(1);
                    health.failing_since.get_or_insert_with(unix_now);
                    health.last_error = Some(error_text(error));
                }
            }
        }
        stored?;
        if let Some((blocks, bytes)) = side {
            (self.side_budget, self.side_budget_bytes) = (blocks, bytes);
        }
        self.held.remove(&hash);
        self.record(hash, block, Arc::new(entry), state, best);
        self.repin();
        if best {
            if let Err(error) = self.prune_held() {
                // Housekeeping only: the accepted block is already committed.
                eprintln!("Held header pruning deferred: {error:#}");
            }
            self.save_checkpoint(self.checkpoint_every);
        }
        Ok(best)
    }
    /// Hold the header of a block the side-branch admission policy declined.
    /// Its header checks passed against the stored parent, so the block's
    /// compact target is exactly its required one. Fails only when an
    /// admitted held chain cannot be persisted.
    fn decline(&mut self, block: &Block) -> Result<()> {
        let parent = self
            .load_entry(&block.header.previous)?
            .context("unknown parent")?;
        let work = math::work(&math::target_from_bits(block.header.bits)?);
        let claimed = &parent.work + &work;
        self.hold(
            codec::block_hash(block),
            HeldHeader {
                header: block.header.clone(),
                height: block.height,
                root: block.header.previous,
                contributed: work,
                claimed,
                admitted: false,
                pins: 0,
                lead: 0,
            },
            0,
        )?;
        Ok(())
    }
    /// Remember a permanently invalid block message. Only a body its header
    /// commits to proves the header invalid, with every held header after
    /// it; any other body disqualifies just itself.
    fn reject(&mut self, block: &Block, identity: Hash, error: &anyhow::Error) -> Result<()> {
        self.remember_invalid(identity, error);
        if codec::merkle_root(block).ok() == Some(block.header.merkle_root) {
            let removed = self.held.remove_branch(&codec::block_hash(block));
            self.unpersist_held(&removed)?;
            self.refresh_capacity();
            self.repin();
        }
        Ok(())
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
    /// recipient, or for a Support the sender's support record), and opening
    /// funds for its declared inputs and fee. Settings
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
        let execution =
            consensus::prepare_block(&self.config, &self.tip_state, &miner, &math::work(&target))?;
        Ok(transactions
            .iter()
            .map(|transaction| {
                let quote = fees::quote(&self.config, &execution.state, transaction)?;
                // Account and record creation each add exactly their rate to
                // the rounded minimum. A proposal's own record is always new.
                let creation = match &transaction.body.operation {
                    Operation::Support { .. } => &quote.account_creation_fee + &quote.record_fee,
                    _ => quote.account_creation_fee.clone(),
                };
                ensure!(
                    transaction.body.fee >= &quote.minimum_fee - &creation,
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
                let Some((length, state)) = finisher.prefix(&result.transactions, &|| false)?
                else {
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
        let refs: Vec<_> = pending
            .iter()
            .map(|candidate| candidate.transaction)
            .collect();
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
    /// None for a chain-level failure that also rejects the empty block. The
    /// search stops with [TemplateStale] between attempts once `stale` holds.
    fn prefix(
        &self,
        accepted: &[Transaction],
        stale: &dyn Fn() -> bool,
    ) -> Result<Option<(usize, State)>> {
        let finish = |length: usize| -> Result<State> {
            let mut execution =
                consensus::prepare_block(self.config, self.parent, self.miner, self.block_work)?;
            for transaction in &accepted[..length] {
                execution.apply_verified_transaction(self.config, transaction)?;
            }
            self.finish(execution, length)
        };
        let Ok(empty) = finish(0) else {
            return Ok(None);
        };
        let mut best = (0, empty);
        let mut failed = accepted.len();
        while failed - best.0 > 1 {
            unless_stale(stale)?;
            let middle = best.0 + (failed - best.0) / 2;
            match finish(middle) {
                Ok(state) => best = (middle, state),
                Err(_) => failed = middle,
            }
        }
        Ok(Some(best))
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
        self.build_unless(&|| false)
    }
    /// [TemplateJob::build], abandoned with [TemplateStale] once `stale`
    /// holds at a step boundary: between applied transactions, before the
    /// block is finished, and between the finishing attempts of a prefix
    /// search. One finishing attempt, which clears the included trades,
    /// always runs to its end.
    pub fn build_unless(&self, stale: &dyn Fn() -> bool) -> Result<TemplateBuild> {
        #[cfg(test)]
        TEMPLATE_BUILD_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        unless_stale(stale)?;
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
            unless_stale(stale)?;
            if execution
                .apply_verified_transaction(&self.config, transaction)
                .is_err()
            {
                break;
            }
            applied += 1;
        }
        unless_stale(stale)?;
        let (kept, state) = match finisher.finish(execution, applied) {
            Ok(state) => (applied, state),
            Err(error) => {
                let Some(kept) = finisher.prefix(&self.transactions[..applied], stale)? else {
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

/// A received block that passed every check needing the chain, captured by
/// [Chain::begin_submission]. Executing it is a pure function of this capture
/// and the block, the same execution [Chain::submit] runs, so a node runs it
/// on its own worker without holding its chain lock.
pub struct BlockValidation {
    config: Config,
    hash: Hash,
    /// The canonical block message, once a submission encoded it.
    bytes: Option<Vec<u8>>,
    parent: Arc<Entry>,
    parent_state: Arc<State>,
    work: Amount,
    skip: Hash,
    /// Part of a held chain that claimed more work than the tip, so exempt
    /// from the side-branch admission policy.
    admitted: bool,
    /// The block's branch claimed more work than the tip when it was checked.
    extends: bool,
}
/// The execution of a [BlockValidation], for [Chain::finish_submission].
pub struct ExecutedBlock {
    entry: Entry,
    state: Arc<State>,
}
impl BlockValidation {
    /// Whether the block would have become the tip when it was checked;
    /// otherwise it is stored, if at all, on a side branch.
    pub fn extends_tip(&self) -> bool {
        self.extends
    }
    /// Whether the side-branch admission policy did not apply to it.
    pub fn admitted(&self) -> bool {
        self.admitted
    }
    /// Apply the block's transactions to its parent state and check the
    /// committed result. Failures are permanent for this block message.
    pub fn execute(&self, block: &Block) -> Result<ExecutedBlock> {
        #[cfg(test)]
        BLOCK_EXECUTION_HOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        let (parent, parent_state, work) = (&self.parent, &self.parent_state, &self.work);
        (|| -> Result<ExecutedBlock> {
            ensure!(
                codec::body_size(block)? as u64 <= parent_state.settings.block_bytes,
                "block body exceeds byte limit"
            );
            #[cfg(test)]
            VALIDATED_BLOCKS.with(|count| count.set(count.get() + 1));
            let state = consensus::execute(
                &self.config,
                parent_state,
                &block.header.previous,
                &block.miner,
                work,
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
            Ok(ExecutedBlock {
                entry: Entry {
                    header: block.header.clone(),
                    height: block.height,
                    clock,
                    anchor_timestamp,
                    anchor_clock,
                    work: &parent.work + work,
                    skip: self.skip,
                    capacity: parent.capacity.max(state.settings.block_bytes),
                },
                state: Arc::new(state),
            })
        })()
        .map_err(permanent)
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
    fn stored_history_of_another_generation_is_refused_by_name() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("format.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let block = candidate(&chain, 0);
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        let tip = chain.tip_hash();
        drop(chain);
        assert_eq!(Chain::open(&path, config.clone()).unwrap().tip_hash(), tip);
        let edit = |path: &Path, statement: &str| {
            Connection::open(path)
                .unwrap()
                .execute_batch(statement)
                .unwrap();
        };
        let refusal = |path: &Path| {
            Chain::open(path, Config::devnet())
                .err()
                .unwrap()
                .to_string()
        };
        // A 0.42.0 database has the same configuration row and its blocks,
        // but no format marker.
        edit(&path, "DELETE FROM metadata WHERE key='format'");
        let error = refusal(&path);
        assert!(
            error.contains("Hashstash 0.42.0 or earlier") && error.contains("new --data path"),
            "{error}"
        );
        edit(
            &path,
            "INSERT INTO metadata(key,value) VALUES('format',CAST('hashstash-storage-099' AS BLOB))",
        );
        let error = refusal(&path);
        assert!(
            error.contains("hashstash-storage-099") && error.contains("hashstash-storage-043"),
            "{error}"
        );
        // A database without blocks holds nothing to misread; it takes the marker.
        let empty = directory.path().join("empty.db");
        drop(Chain::open(&empty, config.clone()).unwrap());
        edit(&empty, "DELETE FROM metadata WHERE key='format'");
        let chain = Chain::open(&empty, config).unwrap();
        let format: Vec<u8> = chain
            .db
            .query_row("SELECT value FROM metadata WHERE key='format'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(format, STORAGE_FORMAT);
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
        assert!(
            count <= DENSE_STATE_CHECKPOINTS as usize + 2 * 20 + 1,
            "{count}"
        );
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
        assert!(
            deep.iter()
                .all(|height| checkpoint_retained(*height, (1 << 40) + 7))
        );
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
        for height in deeper
            .into_iter()
            .chain(tip - DENSE_STATE_CHECKPOINTS + 1..tip)
        {
            let (hash, state) = checkpoints.get(&height).expect("retained state");
            assert_eq!(Some(*hash), main.hash_at_height(height), "height {height}");
            assert_eq!(state.height, height);
        }
    }
    fn held_header(previous: Hash, height: u64, contributed: u32) -> HeldHeader {
        HeldHeader {
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
            pins: 0,
            lead: 0,
        }
    }
    fn held_id(prefix: u8, n: u32) -> Hash {
        let mut hash = [prefix; 32];
        hash[..4].copy_from_slice(&n.to_le_bytes());
        hash
    }
    #[test]
    fn held_headers_evict_the_weakest_leaf_and_keep_chains_linked() {
        let header = held_header;
        let id = held_id;
        let mut held = HeldHeaders::default();
        // One long presync chain, each header adding work to its branch.
        let mut previous = ZERO_HASH;
        for n in 0..100 {
            held.insert(id(1, n), header(previous, n as u64 + 1, 10 * (n + 1)));
            held.evict();
            previous = id(1, n);
        }
        assert_eq!(held.leaves.len(), 1);
        // A flood of cheap single headers fills the store and evicts itself.
        for n in 0..MAX_HELD_HEADERS as u32 {
            held.insert(id(2, n), header(ZERO_HASH, 1, 5));
            held.evict();
        }
        assert_eq!(held.headers.len(), MAX_HELD_HEADERS);
        assert!((0..100).all(|n| held.headers.contains_key(&id(1, n))));
        assert_eq!(held.admit(&id(1, 99)).len(), 100);
        assert!((0..100).all(|n| held.admitted(&id(1, n))));
        // Admitted headers no longer count against the presync bound.
        assert_eq!(held.evictable, MAX_HELD_HEADERS - 100);
        assert_eq!(
            held.tips.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(),
            [id(1, 99)]
        );
        assert_eq!(held.roots.get(&ZERO_HASH), Some(&1));
        // A stored header leaves its descendants linked; an invalid one drops them.
        held.remove(&id(1, 0));
        assert!(held.headers.contains_key(&id(1, 1)));
        assert_eq!(held.roots.get(&id(1, 0)), Some(&1));
        assert!(!held.roots.contains_key(&ZERO_HASH));
        held.remove_branch(&id(1, 50));
        assert!((50..100).all(|n| !held.headers.contains_key(&id(1, n))));
        assert!((1..50).all(|n| held.headers.contains_key(&id(1, n))));
        assert_eq!(
            held.tips.iter().map(|(_, hash)| *hash).collect::<Vec<_>>(),
            [id(1, 49)]
        );
        // A pinned download is not evicted however long, until it is released.
        let mut previous = id(1, 49);
        for n in 0..2 * MAX_HELD_HEADERS as u32 {
            held.insert(id(3, n), header(previous, 51 + n as u64, 1_000_000 + n));
            held.pin(id(3, n), 7);
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
        assert!(
            held.leaves
                .iter()
                .all(|(_, hash)| held.headers[hash].evictable())
        );
    }
    #[test]
    fn held_headers_stay_pinned_until_every_download_holding_them_ends() {
        let mut held = HeldHeaders::default();
        let mut previous = ZERO_HASH;
        for n in 0..10 {
            held.insert(held_id(1, n), held_header(previous, n as u64 + 1, 1));
            held.pin(held_id(1, n), 1);
            previous = held_id(1, n);
        }
        // A second download of the same branch holds the same headers; a
        // repeated pin of one download counts once.
        for n in 0..10 {
            held.pin(held_id(1, n), 2);
            held.pin(held_id(1, n), 2);
        }
        assert!(held.headers.values().all(|header| header.pins == 2));
        assert_eq!((held.fixed(), held.evictable), (10, 0));
        // The second download ends first: the first still holds every header,
        // so none of them, its resume point included, can be evicted.
        held.unpin(2);
        assert_eq!((held.fixed(), held.evictable), (10, 0));
        assert!(held.leaves.is_empty());
        // A header dropped while pinned leaves no pin behind.
        held.remove_branch(&held_id(1, 5));
        assert_eq!(held.pinned[&1].len(), 5);
        held.unpin(1);
        assert_eq!((held.fixed(), held.evictable), (0, 5));
        assert!(held.pinned.is_empty());
        assert_eq!(held.leaves.len(), 1);
        // Admitting a chain fixes its evictable headers, not its pinned ones,
        // down to its first admitted ancestor.
        held.pin(held_id(1, 2), 3);
        assert_eq!(held.admission_cost(&held_id(1, 4)), 4);
        held.admit(&held_id(1, 1));
        assert_eq!(held.admission_cost(&held_id(1, 4)), 2);
        assert_eq!(held.admission_cost(&held_id(1, 1)), 0);
        assert!(held.admitted_tip(&held_id(1, 1)));
        held.admit(&held_id(1, 4));
        assert!(!held.admitted_tip(&held_id(1, 1)) && held.admitted_tip(&held_id(1, 4)));
        assert_eq!((held.fixed(), held.evictable), (5, 0));
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
            assert!(
                !chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
        }
        let refused = chain
            .submit(siblings[2].clone(), siblings[2].header.timestamp as u64)
            .unwrap_err();
        assert!(refused.is::<SideBranchRefused>(), "{refused:#}");
        assert!(chain.block(&codec::block_hash(&siblings[2])).is_none());
        assert_eq!(chain.held_header_count(), 1);
        // A new active-chain block refills the budget.
        let next = candidate(&chain, 9);
        assert!(
            chain
                .submit(next.clone(), next.header.timestamp as u64)
                .unwrap()
        );
        assert_eq!(chain.side_budget, SIDE_BRANCH_BLOCKS_PER_TIP);
        assert!(
            !chain
                .submit(siblings[2].clone(), siblings[2].header.timestamp as u64)
                .unwrap()
        );
        assert_eq!(chain.held_header_count(), 0);
    }
    /// How [prune_at_startup] starts the chain again.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Restart {
        /// A full replay, which judges the stale branch from the persisted
        /// index and never executes it.
        Full,
        /// A full replay that does not reproduce the persisted tip's entry,
        /// so it executes the branch judged stale after all.
        TipDiffers,
        /// A full replay that finds a stale block's entry disagreeing with
        /// its parent's, so it judges nothing stale.
        EntryDiffers,
        /// A start from a saved checkpoint, which executes neither the stale
        /// branch nor anything else below it.
        Restored,
    }
    #[test]
    fn stale_losing_branches_are_pruned_at_startup() {
        for restart in [
            Restart::Full,
            Restart::TipDiffers,
            Restart::EntryDiffers,
            Restart::Restored,
        ] {
            prune_at_startup(restart);
        }
    }
    /// Delete the saved checkpoints of the closed database, so its next
    /// start is a full one, as after a binary change.
    fn forget_checkpoints(path: &Path) {
        Connection::open(path)
            .unwrap()
            .execute_batch("DELETE FROM state_checkpoint_parts; DELETE FROM state_checkpoints;")
            .unwrap();
    }
    /// Edit the persisted index entry of `hash` in the closed database.
    fn edit_entry(path: &Path, hash: &Hash, edit: impl FnOnce(&mut Entry)) {
        let db = Connection::open(path).unwrap();
        let mut entry = Chain::read_entry(&db, hash)
            .unwrap()
            .unwrap()
            .as_ref()
            .clone();
        edit(&mut entry);
        db.execute(
            "UPDATE entry_index SET bytes=?2 WHERE hash=?1",
            params![hash.as_slice(), codec::encode(&entry)],
        )
        .unwrap();
    }
    fn prune_at_startup(restart: Restart) {
        let restored = restart == Restart::Restored;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("prune.db");
        let config = Config::devnet();
        let miner = crypto::public_key(&[91; 32]).unwrap();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut early = Chain::open(&directory.path().join("early.db"), config.clone()).unwrap();
        let first = candidate(&chain, 0);
        for target in [&mut chain, &mut early] {
            target
                .submit(first.clone(), first.header.timestamp as u64)
                .unwrap();
        }
        // An early losing branch of three on-schedule blocks.
        let mut stale = Vec::new();
        for n in 0..3 {
            let block = candidate(&early, 50 + n);
            early
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            stale.push(block);
        }
        let block = candidate(&chain, 1);
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        for _ in 0..2 {
            let block = candidate(&chain, 2 + chain.tip_height());
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        for block in &stale {
            assert!(
                !chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
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
            near.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let time = chain.tip_block().header.timestamp;
        let mut sibling = near.template(miner, vec![], time).unwrap();
        sibling.extranonce = [7; 8];
        sibling.header.merkle_root = codec::merkle_root(&sibling).unwrap();
        let sibling = Chain::mine(sibling, 1_000_000).unwrap();
        assert!(!chain.submit(sibling.clone(), time as u64).unwrap());
        let tip = chain.tip_hash();
        // The active chain's blocks and the sibling; the stale branch aside.
        let kept = chain.tip_height() + 1;
        // A clean stop saves the state CHECKPOINT_DEPTH below the tip.
        drop(chain);
        if !restored {
            forget_checkpoints(&path);
        }
        match restart {
            Restart::TipDiffers => edit_entry(&path, &tip, |entry| entry.capacity += 1),
            Restart::EntryDiffers => edit_entry(&path, &codec::block_hash(&stale[1]), |entry| {
                entry.work += 1u32
            }),
            Restart::Full | Restart::Restored => {}
        }
        let (chain, validated) = reopen(&path, &config);
        assert_eq!(chain.tip_hash(), tip);
        assert_eq!(chain.restored.is_some(), restored);
        let expected = match restart {
            Restart::Full => kept,
            Restart::TipDiffers | Restart::EntryDiffers => kept + stale.len() as u64,
            // Only the blocks above the checkpoint, the sibling among them.
            Restart::Restored => CHECKPOINT_DEPTH + 1,
        };
        assert_eq!(validated as u64, expected, "{restart:?}");
        for block in &stale {
            assert!(chain.block(&codec::block_hash(block)).is_none());
            assert!(
                chain
                    .block_height(&codec::block_hash(block))
                    .unwrap()
                    .is_none()
            );
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
    fn extend(chain: &mut Chain, count: u64, salt: u64) {
        for n in 0..count {
            let block = candidate(chain, salt + n);
            assert!(
                chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
        }
    }
    /// The reopened chain and the blocks its startup executed.
    fn reopen(path: &Path, config: &Config) -> (Chain, usize) {
        VALIDATED_BLOCKS.with(|count| count.set(0));
        let chain = Chain::open(path, config.clone()).unwrap();
        (chain, VALIDATED_BLOCKS.with(Cell::get))
    }
    fn saved_heights(chain: &Chain) -> Vec<u64> {
        chain
            .db
            .prepare("SELECT height FROM state_checkpoints ORDER BY height")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }
    fn active_chain(chain: &Chain) -> Vec<Hash> {
        (0..=chain.tip_height())
            .map(|height| chain.hash_at_height(height).unwrap())
            .collect()
    }
    /// Decode the state saved at `height` of the closed database, edit it and store it again.
    fn rewrite_saved_state(path: &Path, height: u64, edit: impl FnOnce(&mut State)) {
        let db = Connection::open(path).unwrap();
        let (hash, build, length): (Vec<u8>, Vec<u8>, u64) = db
            .query_row(
                "SELECT hash,build,length FROM state_checkpoints WHERE height=?1",
                [height],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let mut parts = PartReader {
            db: &db,
            height,
            part: 0,
            buffer: Vec::new(),
            offset: 0,
        };
        let (state, pass): (State, SavedPassChanges) = checkpoint_options()
            .with_limit(length)
            .deserialize_from(&mut parts)
            .unwrap();
        let mut state = state.with_pass_records(pass).unwrap();
        edit(&mut state);
        let (hash, build) = (hash.try_into().unwrap(), build.try_into().unwrap());
        Chain::write_saved_state(&db, height, &hash, &build, &state).unwrap();
    }
    #[test]
    fn saved_checkpoints_restart_without_executing_the_history_below_them() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("saved.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        chain.checkpoint_every = 8;
        let mut early = Chain::open(&directory.path().join("early.db"), config.clone()).unwrap();
        for n in 0..10 {
            let block = candidate(&chain, n);
            for target in [&mut chain, &mut early] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        // A losing block at height 11, stored while it is competitive.
        let losing = candidate(&early, 500);
        extend(&mut chain, 50, 100);
        assert!(
            !chain
                .submit(losing.clone(), losing.header.timestamp as u64)
                .unwrap()
        );
        // Every 8 heights once the state 31 below the tip passes the first
        // interval; the newest two stay, and older ones about one per
        // doubling of depth, which 8 is not once 24 is saved.
        assert_eq!(saved_heights(&chain), [16, 24]);
        let (tip, root, active) = (
            chain.tip_hash(),
            chain.tip_state().root(),
            active_chain(&chain),
        );
        // A clean stop saves the state 31 below the tip at height 60.
        drop(chain);
        let (chain, validated) = reopen(&path, &config);
        assert_eq!(validated as u64, CHECKPOINT_DEPTH);
        assert_eq!((chain.tip_hash(), chain.tip_state().root()), (tip, root));
        assert_eq!(active_chain(&chain), active);
        // The newest two, and 16 as the older one about one doubling deeper.
        assert_eq!(saved_heights(&chain), [16, 24, 29]);
        assert_eq!(chain.restored, Some((29, active[29])));
        chain.tip_state().audit(&chain.config).unwrap();
        // The losing block kept its checked index entry; it was not executed.
        assert_eq!(
            chain.block_height(&codec::block_hash(&losing)).unwrap(),
            Some(11)
        );
        // Below the restored state only genesis is retained, and the restored
        // state itself stays retained.
        assert!(chain.cached_state(&active[29]).is_some());
        assert!((1..29).all(|height| chain.cached_state(&active[height]).is_none()));
        drop(chain);
        // A start interrupted while it rebuilt the blocks above the checkpoint
        // starts from it again.
        let db = Connection::open(&path).unwrap();
        db.execute_batch("DELETE FROM entry_index WHERE hash IN (SELECT hash FROM canonical_index WHERE height>40); DELETE FROM canonical_index WHERE height>40;").unwrap();
        drop(db);
        let (mut chain, validated) = reopen(&path, &config);
        assert_eq!(validated as u64, CHECKPOINT_DEPTH);
        assert_eq!((chain.tip_hash(), chain.tip_state().root()), (tip, root));
        assert_eq!(active_chain(&chain), active);
        // A losing branch forking above the restored state is admitted as before.
        let mut near = Chain::open(&directory.path().join("near.db"), config.clone()).unwrap();
        for hash in &active[1..60] {
            let block = chain.block(hash).unwrap();
            near.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let sibling = candidate(&near, 900);
        assert!(
            !chain
                .submit(sibling.clone(), sibling.header.timestamp as u64)
                .unwrap()
        );
        assert!(chain.block(&codec::block_hash(&sibling)).is_some());
    }
    #[test]
    fn restarts_validate_a_bounded_tail_however_tall_the_chain() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tall.db");
        let config = Config::devnet();
        // The default interval: no periodic save happens below its first
        // interval, yet each clean stop leaves only 31 blocks to validate.
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        assert_eq!(chain.checkpoint_every, CHECKPOINT_INTERVAL);
        for (round, height) in [40u64, 90, 160].into_iter().enumerate() {
            let count = height - chain.tip_height();
            extend(&mut chain, count, 1_000 * round as u64);
            let (tip, root) = (chain.tip_hash(), chain.tip_state().root());
            drop(chain);
            let (reopened, validated) = reopen(&path, &config);
            assert_eq!(validated as u64, CHECKPOINT_DEPTH, "at height {height}");
            assert_eq!(
                (reopened.tip_hash(), reopened.tip_state().root()),
                (tip, root)
            );
            assert_eq!(
                reopened.restored.map(|(saved, _)| saved),
                Some(height - CHECKPOINT_DEPTH)
            );
            chain = reopened;
        }
        // Without that save, as after a crash, the periodic saves bound it to
        // an interval more, and the blocks a pending audit spans.
        let path = directory.path().join("crashed.db");
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        for (round, height) in [60u64, 120, 200].into_iter().enumerate() {
            chain.checkpoint_every = 8;
            let count = height - chain.tip_height();
            extend(&mut chain, count, 10_000 * (round as u64 + 1));
            chain.opened = false;
            drop(chain);
            let (reopened, validated) = reopen(&path, &config);
            let bound = CHECKPOINT_DEPTH + 8 + CHECKPOINT_AUDIT_BLOCKS;
            assert!(validated as u64 <= bound, "{validated} at height {height}");
            assert_eq!(reopened.tip_height(), height);
            chain = reopened;
        }
    }
    #[test]
    fn checkpoints_failing_any_check_fall_back_to_a_full_replay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fallback.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        chain.checkpoint_every = 8;
        extend(&mut chain, 45, 0);
        let (tip, root) = (chain.tip_hash(), chain.tip_state().root());
        drop(chain);
        let sql = |sql: &str| Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        let start = |restored: Option<u64>| {
            let (mut chain, validated) = reopen(&path, &config);
            assert_eq!((chain.tip_hash(), chain.tip_state().root()), (tip, root));
            assert_eq!(chain.restored.map(|(height, _)| height), restored);
            let expected = restored.map_or(45, |height| 45 - height);
            assert_eq!(validated as u64, expected);
            chain.tip_state().audit(&chain.config).unwrap();
            // The next clean stop saves the state at height 14 again.
            chain.checkpoint_every = 8;
            saved_heights(&chain)
        };
        // A damaged newest checkpoint is discarded and the older one serves.
        sql("UPDATE state_checkpoint_parts SET bytes=zeroblob(length(bytes)) WHERE height=14");
        assert_eq!(start(Some(8)), [8]);
        assert_eq!(start(Some(14)), [8, 14]);
        // Another build's checkpoints are never used; the full replay drops
        // them. Each later fallback starts from the one its stop saved.
        sql("UPDATE state_checkpoints SET build=x'00'");
        assert!(start(None).is_empty());
        // A saved state that differs from the committed state root.
        rewrite_saved_state(&path, 14, |state| state.world.revenue += 1u32);
        assert!(start(None).is_empty());
        // An ancestor entry whose clock is off by a second: the parent's
        // schedule no longer yields its child's required target.
        {
            let db = Connection::open(&path).unwrap();
            let hash: Vec<u8> = db
                .query_row("SELECT hash FROM canonical_index WHERE height=5", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let mut entry = Chain::read_entry(&db, &hash.as_slice().try_into().unwrap())
                .unwrap()
                .unwrap()
                .as_ref()
                .clone();
            entry.clock += 1;
            db.execute(
                "UPDATE entry_index SET bytes=?2 WHERE hash=?1",
                params![hash, codec::encode(&entry)],
            )
            .unwrap();
        }
        assert!(start(None).is_empty());
        // Indexes rebuilt by a binary that predates checkpoints (it clears the
        // whole canonical index, the build marker with it), a missing
        // active-chain index, and an index entry without a block.
        sql("DELETE FROM canonical_index WHERE height<0");
        assert!(start(None).is_empty());
        sql("DELETE FROM canonical_index WHERE height>0");
        assert!(start(None).is_empty());
        sql("INSERT INTO entry_index(hash,bytes) VALUES(zeroblob(32),x'00')");
        assert!(start(None).is_empty());
        // A saved tip that the checkpoint's descendants cannot reach.
        sql(
            "UPDATE metadata SET value=(SELECT hash FROM canonical_index WHERE height=10) WHERE key='tip'",
        );
        assert!(start(None).is_empty());
        // The last fallback's stop saved a checkpoint that serves again.
        assert_eq!(start(Some(14)), [14]);
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn a_saved_decision_whose_action_is_not_the_committed_one_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("decision.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let secret = [91; 32];
        let owner = crypto::public_key(&secret).unwrap();
        // An account that nothing touches once the decision opens.
        let bystander = crypto::public_key(&[92; 32]).unwrap();
        let time = chain.tip_block().header.timestamp + 15;
        let block = Chain::mine(chain.template(bystander, vec![], time).unwrap(), 100_000).unwrap();
        assert!(chain.submit(block, time as u64).unwrap());
        let mut salt = 0;
        while chain.tip_state().auction_round().is_none() {
            extend(&mut chain, 1, salt);
            salt += 1;
        }
        let blocks = chain.tip_state().settings.decision_blocks;
        let action = |new| Proposal::Parameter {
            parameter: Parameter::DecisionBlocks,
            old: blocks,
            new,
        };
        let mut body = TransactionBody {
            sender: owner,
            nonce: chain.tip_state().account(&owner, None).unwrap().nonce,
            fee: 0u32.into(),
            anchor: chain.tip_hash(),
            expiry_blocks: 10,
            operation: Operation::Propose {
                round: chain.tip_state().auction_round().unwrap(),
                description: [14; 32],
                proposal: action(blocks * 2),
                support: 10u32.into(),
            },
            data: vec![],
        };
        let proposal = loop {
            let tx = crypto::sign(&chain.chain_id(), &body, &secret).unwrap();
            let minimum = fees::quote(&config, chain.tip_state(), &tx)
                .unwrap()
                .minimum_fee;
            if minimum <= body.fee {
                break tx;
            }
            body.fee = minimum;
        };
        let time = chain.tip_block().header.timestamp + 15;
        let block = Chain::mine(
            chain.template(owner, vec![proposal], time).unwrap(),
            100_000,
        )
        .unwrap();
        assert!(chain.submit(block, time as u64).unwrap());
        while chain.tip_state().decision_id().is_none() {
            extend(&mut chain, 1, salt);
            salt += 1;
        }
        // Save the decision state at the tip itself.
        let (height, hash, root) = (
            chain.tip_height(),
            chain.tip_hash(),
            chain.tip_state().root(),
        );
        let build = build_identity().unwrap();
        Chain::write_saved_state(&chain.db, height, &hash, &build, chain.tip_state()).unwrap();
        // The records both worlds share are saved once, not once per world.
        let plain = checkpoint_options()
            .serialized_size(chain.tip_state())
            .unwrap();
        let saved: u64 = chain
            .db
            .query_row(
                "SELECT length FROM state_checkpoints WHERE height=?1",
                [height],
                |r| r.get(0),
            )
            .unwrap();
        assert!(saved < plain, "{saved} >= {plain}");
        drop(chain);
        let (chain, validated) = reopen(&path, &config);
        assert_eq!((validated, chain.restored), (0, Some((height, hash))));
        let state = chain.tip_state();
        let Phase::Governance(decision) = &state.phase else {
            panic!("decision not restored");
        };
        // The restored decision shares the committed action, as execution does.
        let committed = state.actions.get_shared(&decision.proposal_id).unwrap();
        assert!(Arc::ptr_eq(&decision.proposal, committed));
        // The PASS world is rebuilt on the FAIL world: an account untouched
        // since the decision opened is one shared record, not two copies.
        let pass = state.alternative.as_ref().unwrap();
        let shared = state.world.accounts.get_shared(&bystander).unwrap();
        assert!(Arc::ptr_eq(
            shared,
            pass.accounts.get_shared(&bystander).unwrap()
        ));
        drop(chain);
        // The root omits the decision's copy of its action, so another copy
        // still matches the committed root; the audit refuses it.
        rewrite_saved_state(&path, height, |state| {
            let Phase::Governance(decision) = &mut state.phase else {
                unreachable!()
            };
            decision.proposal = Arc::new(action(blocks * 3));
            assert_eq!(state.root(), root);
        });
        let (chain, validated) = reopen(&path, &config);
        assert_eq!((validated as u64, chain.restored), (height, None));
        assert_eq!(chain.tip_state().root(), root);
        chain.tip_state().audit(&chain.config).unwrap();
        let state = chain.tip_state();
        let Phase::Governance(decision) = &state.phase else {
            panic!("decision not replayed");
        };
        assert_eq!(*decision.proposal, action(blocks * 2));
    }
    #[test]
    fn a_branch_forking_below_the_restored_state_is_held_until_it_leads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("restored.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        chain.checkpoint_every = 8;
        let mut fork = Chain::open(&directory.path().join("fork.db"), config.clone()).unwrap();
        for n in 0..10 {
            let block = candidate(&chain, n);
            for target in [&mut chain, &mut fork] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        extend(&mut chain, 50, 100);
        extend(&mut fork, 55, 1_000);
        drop(chain);
        let (mut chain, _) = reopen(&path, &config);
        assert_eq!(chain.restored.map(|(height, _)| height), Some(29));
        let branch: Vec<Block> = active_chain(&fork)[11..]
            .iter()
            .map(|hash| fork.block(hash).unwrap())
            .collect();
        // Its fork point could only be rebuilt from genesis, so the branch is
        // held as headers while it trails.
        let refused = chain
            .submit(branch[0].clone(), branch[0].header.timestamp as u64)
            .unwrap_err();
        assert!(refused.is::<SideBranchRefused>(), "{refused:#}");
        assert!(
            refused.to_string().contains("restored at startup"),
            "{refused:#}"
        );
        for block in &branch[1..] {
            let held = chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap_err();
            assert!(held.is::<SideBranchRefused>(), "{held:#}");
        }
        assert!(chain.block(&codec::block_hash(&branch[0])).is_none());
        // Once its headers claim more work than the tip, it is validated and adopted.
        for block in &branch {
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_eq!(chain.tip_hash(), fork.tip_hash());
        assert_eq!(chain.tip_state().root(), fork.tip_state().root());
        assert_eq!(active_chain(&chain), active_chain(&fork));
        assert_eq!(chain.restored, None);
        drop(chain);
        // The clean stop saved a checkpoint on the new active chain and
        // dropped those that are not on it.
        let (chain, validated) = reopen(&path, &config);
        assert_eq!(chain.tip_hash(), fork.tip_hash());
        let saved = fork.tip_height() - CHECKPOINT_DEPTH;
        assert_eq!(saved_heights(&chain), [saved]);
        assert_eq!(
            (chain.restored, validated as u64),
            (
                Some((saved, active_chain(&fork)[saved as usize])),
                CHECKPOINT_DEPTH
            )
        );
    }
    #[test]
    fn a_reorganization_below_the_restored_state_rebuilds_its_fork_point_from_genesis() {
        // Below a restored state only genesis is retained, so the fork point
        // of a heavier branch forking there is rebuilt from genesis, in
        // budgeted steps: about its height, where a process that never
        // restarted rebuilds it from a retained state about its depth below.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("deep.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        chain.checkpoint_every = 8;
        let mut live = Chain::open(&directory.path().join("live.db"), config.clone()).unwrap();
        let mut fork = Chain::open(&directory.path().join("fork.db"), config.clone()).unwrap();
        for n in 0..20 {
            let block = candidate(&chain, n);
            for target in [&mut chain, &mut live, &mut fork] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        for n in 0..40 {
            let block = candidate(&chain, 100 + n);
            for target in [&mut chain, &mut live] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        extend(&mut fork, 46, 1_000);
        drop(chain);
        // A copy of the stopped database, whose replays may load an older
        // saved checkpoint: its checkpoint interval is 8 heights, not 1,024.
        let copy = directory.path().join("deep-copy.db");
        for suffix in ["", "-wal"] {
            let source = format!("{}{suffix}", path.display());
            if Path::new(&source).exists() {
                std::fs::copy(&source, format!("{}{suffix}", copy.display())).unwrap();
            }
        }
        let (mut chain, _) = reopen(&path, &config);
        let (mut saved, _) = reopen(&copy, &config);
        saved.checkpoint_every = 8;
        assert_eq!(saved_heights(&saved), [16, 24, 29]);
        let branch: Vec<Block> = active_chain(&fork)[21..]
            .iter()
            .map(|hash| fork.block(hash).unwrap())
            .collect();
        for target in [&mut chain, &mut saved] {
            assert_eq!(target.restored.map(|(height, _)| height), Some(29));
            for block in &branch {
                let held = target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap_err();
                assert!(held.is::<SideBranchRefused>(), "{held:#}");
            }
        }
        // Each attempt may replay four blocks; returns how often the first
        // block, whose parent is the fork point, was deferred.
        let adopt = |target: &mut Chain| {
            let mut deferred = 0;
            for (index, block) in branch.iter().enumerate() {
                loop {
                    let time = block.header.timestamp as u64;
                    match target.submit_with_replay_budget(block.clone(), time, 4) {
                        Ok(_) => break,
                        Err(error) if error.is::<ValidationDeferred>() && index == 0 => {
                            deferred += 1
                        }
                        Err(error) => panic!("{error:#}"),
                    }
                }
            }
            assert_eq!(target.tip_hash(), fork.tip_hash());
            assert_eq!(target.tip_state().root(), fork.tip_state().root());
            deferred
        };
        // Twenty blocks from genesis, where the saved state at 16 is less
        // than an interval below the fork point; four from it, loaded at the
        // cost of one step, where it is more; and four from the state the
        // live process retains at height 16.
        assert_eq!(adopt(&mut chain), 4);
        assert_eq!(adopt(&mut saved), 1);
        assert_eq!(adopt(&mut live), 0);
        assert_eq!(chain.restored, None);
        let active = active_chain(&fork);
        assert_eq!(saved.loaded.get(), Some((16, active[16])));
        assert!(saved.cached_state(&active[16]).is_some());
        assert_eq!((chain.loaded.get(), saved.restored), (None, None));
    }
    #[test]
    fn saved_checkpoints_thin_out_to_about_one_per_doubling_of_depth() {
        let mut saved: Vec<u64> = Vec::new();
        let mut deepest = Vec::new();
        for newest in 1..=64u64 {
            let mut heights = vec![newest * 8 + 3];
            heights.extend(&saved);
            let kept = saved_checkpoints_kept(&heights, 8);
            assert!(kept.len() <= MAX_SAVED_CHECKPOINTS);
            // The newest two always stay, and only saved ones do.
            assert!(heights.iter().take(2).all(|height| kept.contains(height)));
            assert!(kept.iter().all(|height| heights.contains(height)));
            saved = kept.into_iter().rev().collect();
            deepest.push(newest - saved.last().unwrap() / 8);
        }
        // Once there are enough, an older one lies two to seven intervals below.
        assert!(
            deepest[8..].iter().all(|depth| (2..8).contains(depth)),
            "{deepest:?}"
        );
        // Several in one interval keep only its newest beyond the newest two.
        assert_eq!(
            saved_checkpoints_kept(&[100, 98, 97, 96, 88, 64], 8),
            BTreeSet::from([100, 98, 88, 64])
        );
    }
    /// Blocks replayed to rebuild parent states on this thread since the last call.
    fn replayed() -> usize {
        REPLAYED_BLOCKS.with(|count| count.replace(0))
    }
    /// Submit with a replay budget of `steps` until the block is stored,
    /// returning whether it became the tip and how often it was deferred.
    fn submit_deferred(chain: &mut Chain, block: &Block, steps: usize) -> (bool, usize) {
        let mut deferred = 0;
        loop {
            match chain.submit_with_replay_budget(
                block.clone(),
                block.header.timestamp as u64,
                steps,
            ) {
                Ok(selected) => return (selected, deferred),
                Err(error) if error.is::<ValidationDeferred>() => deferred += 1,
                Err(error) => panic!("{error:#}"),
            }
        }
    }
    #[test]
    fn side_block_replays_neither_take_over_nor_flush_a_priority_replay() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut chain = Chain::open(&directory.path().join("minority.db"), config.clone()).unwrap();
        let mut fork = Chain::open(&directory.path().join("majority.db"), config.clone()).unwrap();
        let mut near = Chain::open(&directory.path().join("near.db"), config.clone()).unwrap();
        for n in 0..140 {
            let block = candidate(&chain, n);
            for target in [&mut chain, &mut fork] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
            if n < 130 {
                near.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        extend(&mut chain, 10, 1_000);
        // The heavier branch's first ten blocks are stored while they trail.
        let branch: Vec<Block> = (0..11)
            .map(|n| {
                let block = candidate(&fork, 2_000 + n);
                fork.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
                block
            })
            .collect();
        for block in &branch[..10] {
            assert!(
                !chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
        }
        // A side block whose parent at height 130 must be rebuilt from
        // genesis once the checkpoints below 140 are gone, and the stored
        // branch's states evicted.
        let side = candidate(&near, 3_000);
        chain
            .checkpoints
            .borrow_mut()
            .retain(|height, _| *height == 0 || *height >= 140);
        *chain.cache.get_mut() = StateCache::default();
        let tip = &branch[10];
        replayed();
        let first = chain
            .submit_with_replay_budget(tip.clone(), tip.header.timestamp as u64, 4)
            .unwrap_err();
        assert!(first.is::<ValidationDeferred>(), "{first:#}");
        let mut rebuilt = replayed();
        // The side block's replay defers hold after hold before it is
        // stored, entering nothing into the recent cache meanwhile.
        let cached = chain.cached_state_count();
        let (selected, holds) = submit_deferred(&mut chain, &side, 1);
        assert!(!selected);
        assert!(holds >= MAX_CACHED_STATES, "{holds}");
        assert!(chain.cached_state_count() <= cached + 2);
        replayed();
        // The block that becomes the tip resumes where it stopped: it
        // replays its ten branch ancestors once in all.
        assert!(submit_deferred(&mut chain, tip, 4).0);
        rebuilt += replayed();
        assert_eq!(rebuilt, 10);
        assert_eq!(chain.tip_hash(), fork.tip_hash());
        assert_eq!(chain.tip_state().root(), fork.tip_state().root());
    }
    #[test]
    fn a_side_block_resuming_a_priority_replay_leaves_it_a_priority_one() {
        let directory = tempfile::tempdir().unwrap();
        let mut chain = Chain::open(&directory.path().join("resume.db"), Config::devnet()).unwrap();
        extend(&mut chain, 60, 0);
        let (first, second) = (
            chain.hash_at_height(40).unwrap(),
            chain.hash_at_height(30).unwrap(),
        );
        // Both states must be rebuilt from genesis.
        chain
            .checkpoints
            .borrow_mut()
            .retain(|height, _| *height == 0 || *height > 50);
        *chain.cache.get_mut() = StateCache::default();
        // One replayed block per attempt, as for a side block per hold.
        let defer = |chain: &Chain, target: &Hash, priority: bool| {
            chain.replay_priority.set(priority);
            chain.replay_budget.set(Some(1));
            let error = chain.load_state(target).unwrap_err();
            chain.replay_budget.set(None);
            chain.replay_priority.set(false);
            assert!(error.is::<ValidationDeferred>(), "{error:#}");
        };
        // A block that would become the tip defers its parent's rebuild; a
        // side block with the same parent resumes it and defers in turn.
        defer(&chain, &first, true);
        defer(&chain, &first, false);
        // Another side block's rebuild takes the side record, not that one,
        // which keeps its progress.
        defer(&chain, &second, false);
        let kept: Vec<(Hash, Option<Hash>)> = chain
            .priority_replays
            .borrow()
            .iter()
            .map(|replay| (replay.target, replay.base.as_ref().map(|(hash, _)| *hash)))
            .collect();
        assert_eq!(kept, [(first, chain.hash_at_height(2))]);
        let side = chain.replay.borrow().as_ref().map(|replay| replay.target);
        assert_eq!(side, Some(second));
        assert_eq!(chain.cached_state_count(), 0);
    }
    #[test]
    fn admitted_chains_keep_their_stored_states_out_of_the_recent_cache() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut chain = Chain::open(&directory.path().join("minority.db"), config.clone()).unwrap();
        let mut fork = Chain::open(&directory.path().join("majority.db"), config.clone()).unwrap();
        for n in 0..5 {
            let block = candidate(&chain, n);
            for target in [&mut chain, &mut fork] {
                target
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        extend(&mut chain, 3, 100);
        let branch: Vec<Block> = (0..6)
            .map(|n| {
                let block = candidate(&fork, 1_000 + n);
                fork.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
                block
            })
            .collect();
        // Declined while the side budget is spent, the branch is held as
        // headers until they claim more work than the tip.
        chain.side_budget = 0;
        for block in &branch {
            let held = chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap_err();
            assert!(held.is::<SideBranchRefused>(), "{held:#}");
        }
        let first = codec::block_hash(&branch[0]);
        assert!(
            !chain
                .submit(branch[0].clone(), branch[0].header.timestamp as u64)
                .unwrap()
        );
        assert!(chain.pinned.contains_key(&first));
        // Side-branch traffic flushing the recent cache costs the next body
        // no replay: its parent's state stays pinned.
        *chain.cache.get_mut() = StateCache::default();
        replayed();
        assert_eq!(submit_deferred(&mut chain, &branch[1], 1), (false, 0));
        assert_eq!(replayed(), 0);
        assert!(!chain.pinned.contains_key(&first));
        for block in &branch[2..] {
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_eq!(chain.tip_hash(), fork.tip_hash());
        assert_eq!(chain.tip_state().root(), fork.tip_state().root());
        // Adopted, the chain needs nothing pinned any more.
        assert!(chain.pinned.is_empty());
    }
    #[test]
    fn replays_find_recent_progress_without_an_index_read_per_height() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config::devnet();
        let mut chain = Chain::open(&directory.path().join("long.db"), config.clone()).unwrap();
        let mut near = Chain::open(&directory.path().join("near.db"), config.clone()).unwrap();
        for n in 0..130 {
            let block = candidate(&chain, n);
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
            if n < 120 {
                near.submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
            }
        }
        // Below the dense window only genesis stays retained; the state at
        // height 64 is a recent one.
        let (hash, state) = chain.checkpoints.borrow()[&64].clone();
        chain
            .checkpoints
            .borrow_mut()
            .retain(|height, _| *height == 0 || *height > 125);
        chain.cache_state(hash, state);
        let side = candidate(&near, 500);
        replayed();
        CANONICAL_LOOKUPS.with(|count| count.set(0));
        let deferred = chain
            .submit_with_replay_budget(side.clone(), side.header.timestamp as u64, 1)
            .unwrap_err();
        assert!(deferred.is::<ValidationDeferred>(), "{deferred:#}");
        let lookups = CANONICAL_LOOKUPS.with(Cell::get);
        assert!(lookups < 16, "{lookups} canonical index reads");
        // The replay still starts from that recent state.
        assert!(!submit_deferred(&mut chain, &side, 8).0);
        assert_eq!(replayed(), 120 - 64);
    }
    #[test]
    fn an_interrupted_stale_branch_deletion_never_orphans_a_stored_block() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("interrupted.db");
        let config = Config::devnet();
        let miner = crypto::public_key(&[91; 32]).unwrap();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut early = Chain::open(&directory.path().join("early.db"), config.clone()).unwrap();
        let first = candidate(&chain, 0);
        for target in [&mut chain, &mut early] {
            target
                .submit(first.clone(), first.header.timestamp as u64)
                .unwrap();
        }
        extend(&mut chain, 14, 1);
        // A losing branch of twelve blocks, stored while it competes.
        let stale: Vec<Block> = (0..12)
            .map(|n| {
                let block = candidate(&early, 50 + n);
                early
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
                block
            })
            .collect();
        for block in &stale {
            assert!(
                !chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
        }
        // One-second blocks leave it far behind (see prune_at_startup).
        while math::work(&chain.next_target().unwrap()) <= Amount::from(128u32) {
            let time = chain.tip_block().header.timestamp + 1;
            let block = Chain::mine(chain.template(miner, vec![], time).unwrap(), 100_000).unwrap();
            chain.submit(block, time as u64).unwrap();
        }
        let tip = chain.tip_hash();
        drop(chain);
        forget_checkpoints(&path);
        // A full start judges the branch stale and deletes it; it stops
        // right after its first batch of deletions is committed.
        FAIL_STALE_DELETION.with(|fail| fail.set(true));
        let interrupted = Chain::open(&path, config.clone());
        FAIL_STALE_DELETION.with(|fail| fail.set(false));
        assert!(interrupted.is_err());
        drop(interrupted);
        let db = Connection::open(&path).unwrap();
        let stored: Vec<Block> = db
            .prepare("SELECT bytes FROM blocks")
            .unwrap()
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .unwrap()
            .map(|bytes| {
                let bytes = bytes.unwrap();
                codec::decode_block(&bytes, bytes.len()).unwrap()
            })
            .collect();
        drop(db);
        let mut known: BTreeSet<Hash> = stored.iter().map(codec::block_hash).collect();
        known.insert(codec::block_hash(&codec::genesis_block(&config).unwrap()));
        let left = stale
            .iter()
            .filter(|block| known.contains(&codec::block_hash(block)))
            .count();
        assert!((1..stale.len()).contains(&left), "{left}");
        // Children went first: every stored block still has its parent.
        assert!(
            stored
                .iter()
                .all(|block| known.contains(&block.header.previous))
        );
        let chain = Chain::open(&path, config).unwrap();
        assert_eq!(chain.tip_hash(), tip);
        for block in &stale {
            assert!(chain.block(&codec::block_hash(block)).is_none());
        }
        let moved: i64 = chain
            .db
            .query_row("SELECT COUNT(*) FROM rejected_blocks", [], |r| r.get(0))
            .unwrap();
        assert_eq!(moved, 0);
    }
    #[test]
    fn a_stored_block_whose_parent_is_gone_is_set_aside_at_startup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("orphan.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        let mut branch = Chain::open(&directory.path().join("branch.db"), config.clone()).unwrap();
        let first = candidate(&chain, 0);
        for target in [&mut chain, &mut branch] {
            target
                .submit(first.clone(), first.header.timestamp as u64)
                .unwrap();
        }
        extend(&mut chain, 3, 1);
        let losing: Vec<Block> = (0..2)
            .map(|n| {
                let block = candidate(&branch, 50 + n);
                branch
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap();
                block
            })
            .collect();
        for block in &losing {
            assert!(
                !chain
                    .submit(block.clone(), block.header.timestamp as u64)
                    .unwrap()
            );
        }
        let (tip, root) = (chain.tip_hash(), chain.tip_state().root());
        drop(chain);
        Connection::open(&path)
            .unwrap()
            .execute(
                "DELETE FROM blocks WHERE hash=?1",
                [codec::block_hash(&losing[0]).as_slice()],
            )
            .unwrap();
        let chain = Chain::open(&path, config).unwrap();
        assert_eq!((chain.tip_hash(), chain.tip_state().root()), (tip, root));
        assert!(chain.block(&codec::block_hash(&losing[1])).is_none());
        let reason: String = chain
            .db
            .query_row(
                "SELECT reason FROM rejected_blocks WHERE hash=?1",
                [codec::block_hash(&losing[1]).as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason, "parent block absent");
    }
    /// Extend `chain` until a periodic checkpoint is due at its next block,
    /// returning the height that save takes.
    fn extend_until_due(chain: &mut Chain, salt: &mut u64) -> u64 {
        loop {
            let newest = saved_heights(chain).last().copied().unwrap_or(0);
            let height = (chain.tip_height() + 1).saturating_sub(CHECKPOINT_DEPTH);
            if height >= chain.checkpoint_every
                && newest + chain.checkpoint_every <= height
                && chain.tip_height() + 1 >= chain.checkpoint_retry
            {
                return height;
            }
            extend(chain, 1, *salt);
            *salt += 1;
        }
    }
    #[test]
    fn failed_checkpoint_saves_back_off_and_keep_the_older_checkpoints() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("backoff.db");
        let mut chain = Chain::open(&path, Config::devnet()).unwrap();
        chain.checkpoint_every = 8;
        let mut salt = 0;
        // Audited during one block, saved at the next.
        let height = extend_until_due(&mut chain, &mut salt);
        extend(&mut chain, 2, salt);
        salt += 2;
        assert_eq!(saved_heights(&chain), [height]);
        assert_eq!(chain_error(&chain), None);
        // Without room for another state, the next save fails once, and
        // returns the write-ahead log's space.
        FREE_BYTES.with(|free| free.set(Some(STORAGE_RESERVE_BYTES - 1)));
        extend_until_due(&mut chain, &mut salt);
        extend(&mut chain, 2, salt);
        salt += 2;
        let failed = chain.tip_height();
        assert_eq!(saved_heights(&chain), [height]);
        assert_eq!(chain.checkpoint_failures, 1);
        let error = chain_error(&chain).unwrap();
        assert!(error.contains("disk space"), "{error}");
        let wal = std::fs::metadata(format!("{}-wal", path.display()))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        assert_eq!(wal, 0);
        // Periodic saves wait an interval, then two, instead of retrying
        // on every block.
        assert_eq!(chain.checkpoint_retry, failed + 8);
        while chain.tip_height() + 1 < chain.checkpoint_retry {
            extend(&mut chain, 1, salt);
            salt += 1;
            assert!(chain.checkpoint_audit.is_none());
        }
        extend(&mut chain, 2, salt);
        salt += 2;
        assert_eq!(chain.checkpoint_failures, 2);
        let retry = chain.checkpoint_retry;
        assert_eq!(retry, chain.tip_height() + 16);
        // Once there is room again, the next save succeeds.
        FREE_BYTES.with(|free| free.set(None));
        let next = extend_until_due(&mut chain, &mut salt);
        assert!(chain.tip_height() + 1 >= retry);
        extend(&mut chain, 2, salt);
        assert_eq!(saved_heights(&chain), [height, next]);
        assert_eq!((chain.checkpoint_failures, chain_error(&chain)), (0, None));
    }
    fn chain_error(chain: &Chain) -> Option<String> {
        chain
            .storage_health()
            .lock()
            .unwrap()
            .checkpoint_error
            .clone()
    }
    #[test]
    fn a_state_failing_its_audit_is_not_saved_and_the_older_checkpoints_stay() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        chain.checkpoint_every = 8;
        let mut salt = 0;
        let height = extend_until_due(&mut chain, &mut salt);
        extend(&mut chain, 2, salt);
        salt += 2;
        assert_eq!(saved_heights(&chain), [height]);
        // A state whose amounts no longer balance, as a consensus change
        // that drifts from the audit could leave, at the next save's height.
        let due = extend_until_due(&mut chain, &mut salt);
        let (hash, state) = chain.checkpoints.borrow()[&due].clone();
        let mut drifted = state.as_ref().clone();
        drifted.world.revenue += 1u32;
        chain
            .checkpoints
            .borrow_mut()
            .insert(due, (hash, Arc::new(drifted)));
        extend(&mut chain, 2, salt);
        assert_eq!(saved_heights(&chain), [height]);
        let error = chain_error(&chain).unwrap();
        assert!(error.contains("fails its audit"), "{error}");
        // The older checkpoint still serves a restart.
        chain.checkpoints.borrow_mut().insert(due, (hash, state));
        let tip = chain.tip_hash();
        drop(chain);
        let mut db = Connection::open(&path).unwrap();
        // Keep only the checkpoint that passed, as if the stop had not saved.
        let transaction = db.transaction().unwrap();
        let all: Vec<u64> = transaction
            .prepare("SELECT height FROM state_checkpoints")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for saved in all.into_iter().filter(|saved| *saved != height) {
            Chain::delete_saved_state(&transaction, saved).unwrap();
        }
        transaction.commit().unwrap();
        drop(db);
        let (chain, _) = reopen(&path, &config);
        assert_eq!(chain.tip_hash(), tip);
        assert_eq!(chain.restored.map(|(saved, _)| saved), Some(height));
    }
    #[test]
    fn failed_block_commits_are_reported_until_a_block_is_stored() {
        let directory = tempfile::tempdir().unwrap();
        let mut chain = Chain::open(&directory.path().join("full.db"), Config::devnet()).unwrap();
        extend(&mut chain, 2, 0);
        let health = chain.storage_health();
        chain.limit_database_pages(Some(0));
        // Blocks are stored until the database cannot grow, as on a full disk.
        let mut salt = 10;
        let (block, error) = loop {
            let block = candidate(&chain, salt);
            salt += 1;
            match chain.submit(block.clone(), block.header.timestamp as u64) {
                Ok(selected) => assert!(selected),
                Err(error) => break (block, error),
            }
            assert!(salt < 200, "the database never filled");
        };
        assert!(format!("{error:#}").contains("full"), "{error:#}");
        let tip = chain.tip_hash();
        let failed = health.lock().unwrap().clone();
        assert!(failed.degraded());
        assert_eq!(failed.failed_commits, 1);
        assert!(failed.failing_since.is_some());
        assert!(failed.last_error.unwrap().contains("full"));
        // Each failure in a row counts; nothing else changed.
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap_err();
        assert_eq!(health.lock().unwrap().failed_commits, 2);
        assert_eq!(chain.tip_hash(), tip);
        // A stored block ends the streak.
        chain.limit_database_pages(None);
        assert!(
            chain
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap()
        );
        assert_eq!(*health.lock().unwrap(), StorageHealth::default());
    }
    #[test]
    fn side_branch_budgets_count_bytes_keep_a_disk_reserve_and_survive_restarts() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("budget.db");
        let config = Config::devnet();
        let mut chain = Chain::open(&path, config.clone()).unwrap();
        extend(&mut chain, 3, 0);
        let mut sibling =
            Chain::open(&directory.path().join("sibling.db"), config.clone()).unwrap();
        for height in 1..chain.tip_height() {
            let block = chain.block(&chain.hash_at_height(height).unwrap()).unwrap();
            sibling
                .submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        let siblings: Vec<_> = (0..3).map(|n| candidate(&sibling, 100 + n)).collect();
        let submit = |chain: &mut Chain, block: &Block| {
            chain.submit(block.clone(), block.header.timestamp as u64)
        };
        // Below the free disk reserve side blocks are declined; extending
        // the tip is not.
        FREE_BYTES.with(|free| free.set(Some(STORAGE_RESERVE_BYTES - 1)));
        let refused = submit(&mut chain, &siblings[0]).unwrap_err();
        FREE_BYTES.with(|free| free.set(None));
        assert!(
            refused.to_string().contains("free disk space"),
            "{refused:#}"
        );
        // A side block draws its encoded size from the byte budget.
        let size = codec::encode(&siblings[0]).len() as u64;
        chain.side_budget_bytes = size - 1;
        let refused = submit(&mut chain, &siblings[0]).unwrap_err();
        assert!(
            refused.to_string().contains("storage budget"),
            "{refused:#}"
        );
        chain.side_budget_bytes = size + 1;
        assert!(!submit(&mut chain, &siblings[0]).unwrap());
        assert_eq!(chain.side_budget_bytes, 1);
        assert_eq!(chain.side_budget, SIDE_BRANCH_BURST - 1);
        // A restart grants no new burst.
        drop(chain);
        let mut chain = Chain::open(&path, config).unwrap();
        assert_eq!(
            (chain.side_budget, chain.side_budget_bytes),
            (SIDE_BRANCH_BURST - 1, 1)
        );
        assert!(submit(&mut chain, &siblings[1]).is_err());
        // New active-chain heights refill both, by block capacities.
        FREE_BYTES.with(|free| free.set(Some(STORAGE_RESERVE_BYTES - 1)));
        extend(&mut chain, 1, 50);
        FREE_BYTES.with(|free| free.set(None));
        let capacity = chain.tip_state().settings.block_bytes;
        assert_eq!(
            chain.side_budget_bytes,
            1 + SIDE_BRANCH_BLOCKS_PER_TIP * capacity
        );
        assert!(!submit(&mut chain, &siblings[2]).unwrap());
    }
}
