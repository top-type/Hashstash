//! Rebuildable, read-only explorer projection. This database is not consensus.
//! Queries use SQL indexes and bounded pages; block execution only feeds the
//! projection when the canonical tip changes. Orphan records remain identifiable.
use crate::{
    address,
    chain::Chain,
    codec,
    config::Config,
    consensus, fees, math,
    state::{Phase, State},
    types::*,
};
use anyhow::{Context, Result, bail, ensure};
use num_traits::{ToPrimitive, Zero};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

// A pagination target, never a record or consensus validity limit. All sections
// of one response, pending records included, share this record-text allowance
// and the JSON-value limit. A section's first record is returned even when
// larger, so cursors cannot hide valid history.
const PAGE_BYTES: usize = 32 * 1024 * 1024;
/// Immutable execution checkpoints kept for shallow reorganizations; also the
/// longest catch-up that startup finishes before returning.
const CHECKPOINTS: usize = 128;
/// Detached blocks walked to relate an orphaned mail anchor to the canonical chain.
const ANCHOR_DEPTH: usize = 128;
/// Every governed capacity allows responses of at least MAX_RESPONSE_FRAME, so
/// a stored record kept below it, with room for the response envelope, stays
/// deliverable alone even after capacity is lowered; it is also far below
/// SQLite's 1e9-byte row limit. A larger projection omits its bulky signed
/// detail instead of stalling the index on a consensus-valid block.
const RECORD_BYTES: usize = crate::node::MAX_RESPONSE_FRAME - 64 * 1024;
/// A failed update that may be deterministic is retried this long after it
/// failed, or as soon as the canonical tip changes. The worker wakes for the
/// retry itself, so an idle chain does not leave the index behind for good.
const RETRY_FAILED: Duration = Duration::from_secs(60);
/// Lock contention is transient: the next notification retries it, and the
/// worker wakes after this delay when none arrives.
const RETRY_CONTENDED: Duration = Duration::from_secs(1);
const TABLES: [&str; 8] = [
    "explorer_blocks",
    "explorer_transactions",
    "explorer_events",
    "explorer_proposals",
    "explorer_contributions",
    "explorer_decisions",
    "explorer_chat",
    "explorer_mail",
];

pub const METHODS: &[&str] = &[
    "explorer_blocks",
    "explorer_transactions",
    "explorer_block",
    "explorer_transaction",
    "explorer_account",
    "explorer_governance",
    "explorer_chat",
    "explorer_mail",
];
const SCHEMA: &str = "petahash-atoms-separate-data-ordered-events";
pub const MAX_PAGE: u64 = 50;

pub struct Explorer {
    db: Option<Connection>,
    tip: Option<Hash>,
    /// Height of `tip`, the newest block whose rows are indexed as canonical.
    height: u64,
    ready: bool,
    /// Contiguous canonical checkpoints ending at or below `tip`. Blocks above
    /// the newest one are already indexed and replay without rewriting rows.
    states: VecDeque<(Hash, Arc<State>)>,
    /// The last captured update and chain tip. A failed update is retried
    /// after the canonical tip changes or its retry time passes, not on every
    /// worker notification.
    attempt: Option<(Hash, Hash)>,
    failed: Option<((Hash, Hash), Instant)>,
    /// When the worker retries the last failed capture or update without
    /// waiting for a notification.
    retry: Option<Instant>,
    /// RETRY_FAILED, shortened by worker tests.
    pub(crate) retry_delay: Duration,
    #[cfg(test)]
    pub(crate) hooks: TestHooks,
}
/// Fault injection for the worker tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct TestHooks {
    pub(crate) before_apply: Option<Box<dyn FnMut() -> Result<()> + Send>>,
}
/// One already validated canonical block, or retained rollback checkpoints.
/// Capturing this performs no state replay and no derived-index writes under
/// the node lock.
pub(crate) enum Update {
    /// Detach every row and index genesis: no indexed block is canonical.
    Genesis(Box<Block>),
    Advance(Box<Block>),
    /// An already indexed canonical block, executed only to rebuild checkpoints.
    Replay(Box<Block>),
    /// Detach rows above this retained checkpoint.
    Rollback(Hash, Arc<State>),
    /// Detach rows above the common ancestor (height, hash) and resume from
    /// the retained canonical checkpoints at or below it.
    Rebuild(u64, Hash, VecDeque<(Hash, Arc<State>)>),
}
impl Update {
    fn target(&self) -> Hash {
        match self {
            Self::Genesis(block) | Self::Advance(block) | Self::Replay(block) => {
                codec::block_hash(block)
            }
            Self::Rollback(hash, _) | Self::Rebuild(_, hash, _) => *hash,
        }
    }
}
impl Explorer {
    pub fn unavailable() -> Self {
        Self {
            db: None,
            tip: None,
            height: 0,
            ready: false,
            states: VecDeque::new(),
            attempt: None,
            failed: None,
            retry: None,
            retry_delay: RETRY_FAILED,
            #[cfg(test)]
            hooks: TestHooks::default(),
        }
    }
    /// `root` is the state root of `s`, which callers cache per published tip.
    #[allow(clippy::too_many_arguments)]
    pub fn read(
        path: &Path,
        method: &str,
        p: Value,
        c: &Config,
        s: &State,
        tip: Hash,
        root: Hash,
        mempool: &[Transaction],
    ) -> Result<Value> {
        // A separate WAL read transaction never takes the index writer mutex or
        // the chain lock. Its checkpoint must match the captured immutable state.
        let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(std::time::Duration::from_millis(100))?;
        db.execute_batch("BEGIN")?;
        let identity: String = db.query_row(
            "SELECT value FROM explorer_meta WHERE key='chain'",
            [],
            |r| r.get(0),
        )?;
        let version: String = db.query_row(
            "SELECT value FROM explorer_meta WHERE key='schema'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            identity == hex::encode(s.chain_id) && version == SCHEMA,
            "explorer index is unavailable"
        );
        let indexed: String =
            db.query_row("SELECT value FROM explorer_meta WHERE key='tip'", [], |r| {
                r.get(0)
            })?;
        let reader = Self {
            db: Some(db),
            tip: Some(parse_hash(&indexed)?),
            height: 0,
            ready: true,
            states: VecDeque::new(),
            attempt: None,
            failed: None,
            retry: None,
            retry_delay: RETRY_FAILED,
            #[cfg(test)]
            hooks: TestHooks::default(),
        };
        reader.rpc_rooted(method, p, c, s, tip, root, mempool)
    }
    /// Opens the index and sets it up for `chain`. Only a database that
    /// cannot be opened or initialised is an error: a failed setup or
    /// catch-up keeps the index, and its worker retries like any update.
    pub fn open(path: &Path, chain: &Chain) -> Result<Self> {
        let mut index = Self::connect(path, chain)?;
        index.sync(chain);
        Ok(index)
    }

    /// The opened and initialised database, not yet set up for `chain`.
    pub(crate) fn connect(path: &Path, chain: &Chain) -> Result<Self> {
        let db = Connection::open(crate::local_files::sidecar(path, "explorer.sqlite"))?;
        db.busy_timeout(std::time::Duration::from_millis(500))?;
        // As for the chain database, the journal limit returns WAL space after
        // a checkpoint of a large catch-up or rebuild commit instead of
        // keeping the log at its peak size.
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=67108864;
            CREATE TABLE IF NOT EXISTS explorer_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);",
        )?;
        let identity = hex::encode(chain.chain_id());
        let saved: Option<String> = db
            .query_row(
                "SELECT value FROM explorer_meta WHERE key='chain'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let version: Option<String> = db
            .query_row(
                "SELECT value FROM explorer_meta WHERE key='schema'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if saved.as_deref() != Some(identity.as_str()) || version.as_deref() != Some(SCHEMA) {
            db.execute_batch("DROP TABLE IF EXISTS explorer_mail; DROP TABLE IF EXISTS explorer_names; DROP TABLE IF EXISTS explorer_name_attempts;")?;
            db.execute_batch("DROP TABLE IF EXISTS explorer_chat;DROP TABLE IF EXISTS explorer_blocks;DROP TABLE IF EXISTS explorer_transactions;DROP TABLE IF EXISTS explorer_transaction_data;DROP TABLE IF EXISTS explorer_events;DROP TABLE IF EXISTS explorer_proposals;DROP TABLE IF EXISTS explorer_contributions;DROP TABLE IF EXISTS explorer_decisions;DELETE FROM explorer_meta;")?;
            db.execute("INSERT INTO explorer_meta VALUES('chain',?1)", [identity])?;
            db.execute("INSERT INTO explorer_meta VALUES('schema',?1)", [SCHEMA])?;
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS explorer_mail(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));CREATE INDEX IF NOT EXISTS explorer_mail_page ON explorer_mail(height,position) WHERE canonical=1;
            CREATE TABLE IF NOT EXISTS explorer_chat(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));CREATE INDEX IF NOT EXISTS explorer_chat_page ON explorer_chat(height DESC,position DESC) WHERE canonical=1;CREATE TABLE IF NOT EXISTS explorer_blocks(hash TEXT PRIMARY KEY,height INTEGER NOT NULL,canonical INTEGER NOT NULL,record TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS explorer_height ON explorer_blocks(height) WHERE canonical=1;
            CREATE TABLE IF NOT EXISTS explorer_transactions(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));
            CREATE TABLE IF NOT EXISTS explorer_transaction_data(txid TEXT NOT NULL,block_hash TEXT NOT NULL,data BLOB NOT NULL,PRIMARY KEY(txid,block_hash));
            CREATE INDEX IF NOT EXISTS explorer_tx_page ON explorer_transactions(height DESC,position DESC);
            CREATE INDEX IF NOT EXISTS explorer_tx_block ON explorer_transactions(block_hash,position);
            CREATE TABLE IF NOT EXISTS explorer_events(address TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(address,block_hash,position));
            CREATE INDEX IF NOT EXISTS explorer_account_page ON explorer_events(address,height DESC,position DESC);
            CREATE TABLE IF NOT EXISTS explorer_proposals(id TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(id,block_hash));
            CREATE INDEX IF NOT EXISTS explorer_proposal_page ON explorer_proposals(height DESC,position DESC);
            CREATE TABLE IF NOT EXISTS explorer_contributions(proposal TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(proposal,block_hash,position));
            CREATE INDEX IF NOT EXISTS explorer_contribution_page ON explorer_contributions(proposal,height DESC,position DESC);
            CREATE TABLE IF NOT EXISTS explorer_decisions(id TEXT NOT NULL,proposal TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(id,block_hash));
            CREATE INDEX IF NOT EXISTS explorer_decision_page ON explorer_decisions(height DESC);
            CREATE INDEX IF NOT EXISTS explorer_decision_proposal ON explorer_decisions(proposal,height DESC);
            CREATE INDEX IF NOT EXISTS explorer_current_tx ON explorer_transactions(height DESC,position DESC) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_event ON explorer_events(address,height DESC,position DESC) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_event_height ON explorer_events(height) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_proposal ON explorer_proposals(height DESC,position DESC) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_contribution ON explorer_contributions(proposal,height DESC,position DESC) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_contribution_page ON explorer_contributions(height DESC,position DESC) WHERE canonical=1;
            CREATE INDEX IF NOT EXISTS explorer_current_decision ON explorer_decisions(height DESC) WHERE canonical=1;
")?;
        let tip: Option<String> = db
            .query_row("SELECT value FROM explorer_meta WHERE key='tip'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(Self {
            db: Some(db),
            tip: tip.and_then(|v| parse_hash(&v).ok()),
            height: 0,
            ready: false,
            states: VecDeque::new(),
            attempt: None,
            failed: None,
            retry: None,
            retry_delay: RETRY_FAILED,
            #[cfg(test)]
            hooks: TestHooks::default(),
        })
    }

    pub(crate) fn capture(&mut self, chain: &Chain) -> Result<Option<Update>> {
        if self.db.is_none() || self.tip == Some(chain.tip_hash()) {
            self.retry = None;
            return Ok(None);
        }
        let update = self.next_update(chain).inspect_err(|_| {
            self.retry = Some(Instant::now() + self.retry_failed());
        })?;
        if let Some(update) = &update {
            self.attempt = Some((update.target(), chain.tip_hash()));
        }
        Ok(update)
    }

    /// When the worker should capture again without a notification: after
    /// a failed capture or update, at its retry time.
    pub(crate) fn retry_at(&self) -> Option<Instant> {
        self.retry
    }

    fn retry_failed(&self) -> Duration {
        self.retry_delay
    }

    /// A failed update's target is skipped, before any block is loaded under
    /// the node lock, until the canonical tip changes or RETRY_FAILED passes.
    fn backed_off(&self, target: Hash, chain: &Chain) -> bool {
        self.failed.is_some_and(|(attempt, retry)| {
            attempt == (target, chain.tip_hash()) && Instant::now() < retry
        })
    }

    /// The update that sets the index up for `chain`: detach rows above the
    /// common ancestor and resume from the checkpoints the chain retains, or
    /// first index genesis when no indexed block is canonical.
    fn setup(&self, chain: &Chain) -> Result<Option<Update>> {
        let db = self.db.as_ref().context("explorer index unavailable")?;
        let Some(height) = common_ancestor(db, chain)? else {
            let hash = chain.hash_at_height(0).context("missing genesis")?;
            if self.backed_off(hash, chain) {
                return Ok(None);
            }
            let genesis = chain.block(&hash).context("missing genesis block")?;
            return Ok(Some(Update::Genesis(Box::new(genesis))));
        };
        let hash = chain
            .hash_at_height(height)
            .context("missing common ancestor")?;
        if self.backed_off(hash, chain) {
            return Ok(None);
        }
        Ok(Some(Update::Rebuild(
            height,
            hash,
            checkpoints(chain, height)?,
        )))
    }

    fn next_update(&self, chain: &Chain) -> Result<Option<Update>> {
        let Some((tip, state)) = self.states.back() else {
            // Startup could not set the index up; set it up here instead.
            return self.setup(chain);
        };
        if chain.hash_at_height(state.height) != Some(*tip) {
            if let Some((hash, state)) = self
                .states
                .iter()
                .rev()
                .find(|(hash, state)| chain.hash_at_height(state.height) == Some(*hash))
            {
                if self.backed_off(*hash, chain) {
                    return Ok(None);
                }
                return Ok(Some(Update::Rollback(*hash, state.clone())));
            }
            // A reorg deeper than every checkpoint keeps the rows below the
            // common ancestor and replays from the nearest state the chain
            // already retains (or genesis) on the worker, never through the
            // node's cache/state_at path while holding its mutation lock.
            let db = self.db.as_ref().context("explorer index unavailable")?;
            let height = common_ancestor(db, chain)?.context("missing common genesis")?;
            let hash = chain
                .hash_at_height(height)
                .context("missing common ancestor")?;
            if self.backed_off(hash, chain) {
                return Ok(None);
            }
            return Ok(Some(Update::Rebuild(
                height,
                hash,
                checkpoints(chain, height)?,
            )));
        }
        let replay = state.height < self.height;
        if replay && chain.hash_at_height(self.height) != self.tip {
            // The indexed tip was detached above the newest checkpoint.
            if self.backed_off(*tip, chain) {
                return Ok(None);
            }
            return Ok(Some(Update::Rollback(*tip, state.clone())));
        }
        let hash = chain
            .hash_at_height(state.height + 1)
            .context("missing canonical successor")?;
        if self.backed_off(hash, chain) {
            return Ok(None);
        }
        let block = Box::new(if hash == chain.tip_hash() {
            chain.tip_block().clone()
        } else {
            chain
                .block(&hash)
                .context("missing stored canonical block")?
        });
        Ok(Some(if replay {
            Update::Replay(block)
        } else {
            Update::Advance(block)
        }))
    }

    pub(crate) fn apply_update(&mut self, c: &Config, update: Update) -> Result<()> {
        let attempt = self.attempt.take();
        // A panic is a bug, possibly one block's. Unwinding rolls back the
        // open SQLite transaction, and the checkpoints and tip change only
        // after a commit, so it fails like an error instead of silently
        // ending the worker and freezing the index.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            if let Some(hook) = self.hooks.before_apply.as_mut() {
                hook()?;
            }
            self.apply(c, update)
        }))
        .unwrap_or_else(|panic| {
            let message = panic
                .downcast_ref::<&str>()
                .map(|text| text.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(anyhow::anyhow!("explorer update panicked: {message}"))
        });
        // Lock contention is retried on the next notification; any other
        // failure may be deterministic and waits for a new tip or the delay.
        let now = Instant::now();
        (self.failed, self.retry) = match (&result, attempt) {
            (Err(error), Some(attempt)) if !contended(error) => {
                let retry = now + self.retry_failed();
                (Some((attempt, retry)), Some(retry))
            }
            (Err(_), _) => (None, Some(now + RETRY_CONTENDED)),
            _ => (None, None),
        };
        result
    }

    fn apply(&mut self, c: &Config, update: Update) -> Result<()> {
        let db = self.db.as_mut().context("explorer index unavailable")?;
        match update {
            Update::Genesis(block) => {
                ensure!(block.height == 0, "explorer genesis mismatch");
                let transaction = db.transaction()?;
                detach(&transaction, None)?;
                index_block(&transaction, c, &block, None)?;
                let hash = codec::block_hash(&block);
                set_tip(&transaction, &hash)?;
                transaction.commit()?;
                self.tip = Some(hash);
                self.height = 0;
                // Its checkpoint is the next setup step, a rebuild at genesis.
                self.states.clear();
            }
            Update::Rollback(hash, state) => {
                let transaction = db.transaction()?;
                detach(&transaction, Some(state.height))?;
                set_tip(&transaction, &hash)?;
                transaction.commit()?;
                self.tip = Some(hash);
                self.height = state.height;
                while self
                    .states
                    .back()
                    .is_some_and(|(_, saved)| saved.height >= state.height)
                {
                    self.states.pop_back();
                }
                self.states.push_back((hash, state));
            }
            Update::Rebuild(height, hash, states) => {
                ensure!(
                    states
                        .back()
                        .is_some_and(|(_, state)| state.height <= height),
                    "explorer checkpoint above common ancestor"
                );
                let transaction = db.transaction()?;
                detach(&transaction, Some(height))?;
                set_tip(&transaction, &hash)?;
                transaction.commit()?;
                self.tip = Some(hash);
                self.height = height;
                self.states = states;
                self.ready = true;
            }
            Update::Replay(block) => {
                let (tip, parent) = self
                    .states
                    .back()
                    .context("missing explorer checkpoint state")?;
                ensure!(
                    block.header.previous == *tip
                        && block.height == parent.height + 1
                        && block.height <= self.height,
                    "explorer replay successor mismatch"
                );
                let work = math::work(&math::target_from_bits(block.header.bits)?);
                let post = consensus::execute(
                    c,
                    parent,
                    &block.header.previous,
                    &block.miner,
                    &work,
                    &block.transactions,
                )?;
                ensure!(
                    post.root() == block.state_root,
                    "explorer replay commitment mismatch"
                );
                self.checkpoint(codec::block_hash(&block), Arc::new(post));
            }
            Update::Advance(block) => {
                let (tip, parent) = self
                    .states
                    .back()
                    .context("missing explorer checkpoint state")?;
                ensure!(
                    block.header.previous == *tip
                        && block.height == parent.height + 1
                        && self.tip == Some(*tip),
                    "explorer successor mismatch"
                );
                let transaction = db.transaction()?;
                let post = Arc::new(index_block(&transaction, c, &block, Some(parent))?);
                let hash = codec::block_hash(&block);
                set_tip(&transaction, &hash)?;
                transaction.commit()?;
                self.tip = Some(hash);
                self.height = block.height;
                self.checkpoint(hash, post);
            }
        }
        Ok(())
    }

    fn checkpoint(&mut self, hash: Hash, state: Arc<State>) {
        self.states.push_back((hash, state));
        while self.states.len() > CHECKPOINTS {
            self.states.pop_front();
        }
    }

    /// Detach rows above the common ancestor and resume from retained states.
    /// A short catch-up finishes here; a longer one (first start, rebuild or a
    /// lagging index) continues on the background worker, committing each
    /// block, so startup never waits on a full replay for a derived index.
    /// A failure here, transient or not, is logged and left to the worker,
    /// which retries it as it would its own failed update; the index is never
    /// disabled until the next restart.
    pub fn sync(&mut self, chain: &Chain) {
        if self.ready && self.tip == Some(chain.tip_hash()) {
            return;
        }
        self.ready = false;
        self.states.clear();
        self.attempt = None;
        if let Err(error) = self.catch_up(chain) {
            eprintln!("Explorer index catch-up continues in the background: {error:#}");
        }
    }

    fn catch_up(&mut self, chain: &Chain) -> Result<()> {
        // Genesis when nothing indexed is canonical, then the checkpoints.
        for _ in 0..2 {
            if !self.states.is_empty() {
                break;
            }
            let update = self.setup(chain).inspect_err(|_| {
                self.retry = Some(Instant::now() + self.retry_failed());
            })?;
            let Some(update) = update else {
                return Ok(());
            };
            self.attempt = Some((update.target(), chain.tip_hash()));
            self.apply_update(&chain.config, update)?;
        }
        let start = self
            .states
            .back()
            .context("missing explorer checkpoint state")?
            .1
            .height;
        if chain.tip_height().saturating_sub(start) <= CHECKPOINTS as u64 {
            while let Some(update) = self.capture(chain)? {
                self.apply_update(&chain.config, update)?;
            }
        }
        Ok(())
    }

    pub fn rpc(
        &self,
        method: &str,
        p: Value,
        c: &Config,
        s: &State,
        tip: Hash,
        mempool: &[Transaction],
    ) -> Result<Value> {
        self.rpc_rooted(method, p, c, s, tip, s.root(), mempool)
    }
    /// The state root costs a walk of the whole state, so a node passes the
    /// one it caches per published tip instead of recomputing it per call.
    #[allow(clippy::too_many_arguments)]
    fn rpc_rooted(
        &self,
        method: &str,
        p: Value,
        c: &Config,
        s: &State,
        tip: Hash,
        root: Hash,
        mempool: &[Transaction],
    ) -> Result<Value> {
        ensure!(
            self.ready && self.tip == Some(tip),
            "explorer index is updating; try again"
        );
        ensure!(p.is_object(), "explorer parameters must be an object");
        let db = self.db.as_ref().context("explorer unavailable")?;
        let limit = if p.get("limit").is_none() && method == "explorer_mail" {
            MAX_PAGE
        } else {
            limit(&p)?
        };
        let mut result = json!({"chain_id":hex::encode(s.chain_id),"tip":hex::encode(tip),"height":s.height,"state_root":hex::encode(root)});
        let mut budget = Budget::new();
        match method {
            "explorer_mail" => {
                fields(&p, &["limit", "after", "anchor"])?;
                let anchor = scan_anchor(db, &p, "after", "Mail")?;
                let (h, n) = scan_after(&p, anchor, "Mail", c)?;
                let mut statement=db.prepare("SELECT t.record,t.height,t.position FROM explorer_mail t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height>?1 OR(t.height=?1 AND t.position>?2)) ORDER BY t.height,t.position LIMIT ?3")?;
                let (items, next) = paged_more(
                    &mut statement,
                    params![h, n, limit + 1],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                result["messages"] = Value::from(items);
                result["has_more"] = json!(!next.is_null());
                result["scan_cursor"] = if next.is_null() {
                    json!(format!("{}:{}", s.height, i64::MAX))
                } else {
                    next.clone()
                };
                result["next_cursor"] = next;
                result["anchor"] = json!(hex::encode(tip));
                result["available"] = json!(true);
                result["ready"] = json!(true);
                result["indexed_height"] = json!(s.height);
            }
            "explorer_chat" => {
                fields(&p, &["limit", "cursor"])?;
                let (h, n) = cursor_named(&p, "cursor", s.height, c)?;
                // Message text is read from the stored transaction data rather
                // than from a second, JSON-escaped copy in the chat projection.
                let mut statement = db.prepare("SELECT t.record,t.height,t.position,x.data FROM explorer_chat t JOIN explorer_blocks b ON b.hash=t.block_hash JOIN explorer_transaction_data x ON x.txid=t.txid AND x.block_hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height<?1 OR (t.height=?1 AND t.position<?2)) ORDER BY t.height DESC,t.position DESC LIMIT ?3")?;
                let (items, next) = paged(
                    &mut statement,
                    params![h, n, limit],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                result["items"] = Value::from(items);
                result["next_cursor"] = next;
                result["pending"] = pending(
                    mempool
                        .iter()
                        .rev()
                        .filter_map(|t| chat_value(s, t, None, None, None).map(Ok))
                        .take(limit as usize),
                    &mut budget,
                )?;
                result["available"] = json!(true);
                result["ready"] = json!(true);
                result["indexed_height"] = json!(s.height);
                result["message_bytes"] = json!(c.transaction_bytes(&s.settings));
            }
            "explorer_blocks" => {
                fields(&p, &["limit", "before_height"])?;
                let before =
                    height_parameter(&p, "before_height")?.unwrap_or(s.height.saturating_add(1));
                let mut statement=db.prepare("SELECT record FROM explorer_blocks WHERE canonical=1 AND height<?1 ORDER BY height DESC LIMIT ?2")?;
                let (blocks, truncated) =
                    records(&mut statement, params![before, limit], &mut budget)?;
                result["next_before_height"] = blocks
                    .last()
                    .filter(|_| truncated || blocks.len() == limit as usize)
                    .map(|b| b["height"].clone())
                    .unwrap_or(Value::Null);
                result["blocks"] = Value::from(blocks);
            }
            "explorer_transactions" => {
                fields(&p, &["limit", "before"])?;
                let (h, n) = cursor(&p, s.height, c)?;
                let mut statement=db.prepare("SELECT t.record,t.height,t.position FROM explorer_transactions t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height<?1 OR (t.height=?1 AND t.position<?2)) ORDER BY t.height DESC,t.position DESC LIMIT ?3")?;
                let (items, next) = paged(
                    &mut statement,
                    params![h, n, limit],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                let mut items = items;
                for value in &mut items {
                    settlement(db, value)?;
                }
                result["transactions"] = Value::from(items);
                result["next_cursor"] = next;
                result["pending"] = pending(
                    mempool
                        .iter()
                        .take(limit as usize)
                        .map(|t| tx_value(c, s, t, None, None, None)),
                    &mut budget,
                )?;
            }
            "explorer_block" => {
                fields(&p, &["height", "hash", "limit", "tx_offset"])?;
                ensure!(
                    p.get("height").is_some() != p.get("hash").is_some(),
                    "provide one block height or hash"
                );
                let hash = if let Some(value) = p.get("hash") {
                    hex::encode(parse_hash(value.as_str().context("hash must be text")?)?)
                } else {
                    let h = height_parameter(&p, "height")?.context("height required")?;
                    db.query_row(
                        "SELECT hash FROM explorer_blocks WHERE canonical=1 AND height=?1",
                        [h],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
                    .context("unknown block")?
                };
                let record: Option<(String, bool)> = db
                    .query_row(
                        "SELECT record,canonical FROM explorer_blocks WHERE hash=?1",
                        [&hash],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((record, canonical)) = record {
                    let mut block: Value = serde_json::from_str(&record)?;
                    budget.admit(record.len(), &block, true);
                    block["status"] = json!(if canonical { "confirmed" } else { "orphaned" });
                    block["confirmations"] = json!(if canonical {
                        s.height
                            .saturating_sub(block["height"].as_u64().unwrap_or(s.height))
                            + 1
                    } else {
                        0
                    });
                    let offset = height_parameter(&p, "tx_offset")?.unwrap_or(0);
                    let transaction_count = block["transaction_count"]
                        .as_u64()
                        .context("invalid indexed transaction count")?;
                    ensure!(
                        offset <= transaction_count,
                        "transaction offset is too large"
                    );
                    let mut statement=db.prepare("SELECT record,height,position FROM explorer_transactions WHERE block_hash=?1 AND position>=?2 ORDER BY position LIMIT ?3")?;
                    let (mut transactions, _) = paged(
                        &mut statement,
                        params![hash, offset, limit],
                        limit,
                        s.height,
                        &mut budget,
                    )?;
                    if !canonical {
                        for t in &mut transactions {
                            t["status"] = json!("orphaned");
                            t["confirmations"] = json!(0);
                        }
                    }
                    for value in &mut transactions {
                        settlement(db, value)?;
                    }
                    result["next_tx_offset"] =
                        if offset + (transactions.len() as u64) < transaction_count {
                            json!(offset + transactions.len() as u64)
                        } else {
                            Value::Null
                        };
                    result["block"] = block;
                    result["transactions"] = Value::from(transactions);
                } else {
                    bail!("unknown block");
                }
            }
            "explorer_transaction" => {
                fields(&p, &["txid", "limit"])?;
                let id = hex::encode(parse_hash(string(&p, "txid")?)?);
                let row:Option<(String,Vec<u8>,bool)>=db.query_row("SELECT t.record,d.data,b.canonical FROM explorer_transactions t JOIN explorer_blocks b ON b.hash=t.block_hash JOIN explorer_transaction_data d ON d.txid=t.txid AND d.block_hash=t.block_hash WHERE t.txid=?1 ORDER BY b.canonical DESC,t.height DESC LIMIT 1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;

                let value = if let Some((record, data, true)) = row.as_ref() {
                    let mut value: Value = serde_json::from_str(record)?;
                    value["data_hex"] = json!(hex::encode(data));
                    value["data_truncated"] = json!(false);
                    confirmations(&mut value, s.height);
                    value
                } else if let Some(t) = mempool
                    .iter()
                    .find(|t| hex::encode(codec::transaction_id(t)) == id)
                {
                    let mut value = tx_value(c, s, t, None, None, None)?;
                    value["data_hex"] = json!(hex::encode(&t.body.data));
                    value["data_truncated"] = json!(false);
                    value
                } else if let Some((record, data, _)) = row {
                    let mut value: Value = serde_json::from_str(&record)?;
                    value["data_hex"] = json!(hex::encode(data));
                    value["data_truncated"] = json!(false);
                    value["status"] = json!("orphaned");
                    value["confirmations"] = json!(0);
                    value
                } else {
                    bail!("unknown transaction")
                };
                let mut value = value;
                settlement(db, &mut value)?;
                result["transaction"] = value;
            }
            "explorer_account" => {
                fields(&p, &["address", "limit", "before"])?;
                let key = address::decode(string(&p, "address")?, &s.chain_id)?;
                let encoded = address::encode(&key, &s.chain_id)?;
                result["address"] = json!(encoded);
                result["public_key"] = json!(hex::encode(key));
                let account = s.account(&key, None);
                let payment_available = s.common_spendable(&key).unwrap_or_default();
                result["payment_available_hash"] = json!(payment_available.to_str_radix(10));
                result["account"] = serde_json::to_value(&account)?;
                let den = s.world.shares.clone();
                let numerator = account
                    .as_ref()
                    .map_or_else(Amount::zero, |a| &a.shares * &s.world.curve_mass);
                result["stash_value_hash"] = json!({"numerator":numerator.to_str_radix(10),"denominator":if den.is_zero(){"1".into()}else{den.to_str_radix(10)}});
                let withdrawn = account.as_ref().map_or_else(
                    || Ok(Amount::zero()),
                    |a| -> Result<Amount> {
                        Ok(if a.shares.is_zero() {
                            Amount::zero()
                        } else {
                            &s.world.reserve
                                - math::dynamic_remaining_reserve(
                                    &s.world.reserve,
                                    &s.world.shares,
                                    &a.shares,
                                    &s.world.curve_mass,
                                )?
                        })
                    },
                )?;
                result["stash_withdrawal_hash"] = json!(withdrawn.to_str_radix(10));
                result["pass_account"] = serde_json::to_value(if s.alternative.is_some() {
                    s.account(&key, Some(Outcome::Pass))
                } else {
                    None
                })?;
                if let Some(world) = &s.alternative {
                    let a = s.account(&key, Some(Outcome::Pass));
                    let den = world.shares.clone();
                    let num = a
                        .as_ref()
                        .map_or_else(Amount::zero, |a| &a.shares * &world.curve_mass);
                    result["pass_stash_value_hash"] = json!({"numerator":num.to_str_radix(10),"denominator":if den.is_zero(){"1".into()}else{den.to_str_radix(10)}});
                    let withdrawn = a.as_ref().map_or_else(
                        || Ok(Amount::zero()),
                        |a| -> Result<Amount> {
                            Ok(if a.shares.is_zero() {
                                Amount::zero()
                            } else {
                                &world.reserve
                                    - math::dynamic_remaining_reserve(
                                        &world.reserve,
                                        &world.shares,
                                        &a.shares,
                                        &world.curve_mass,
                                    )?
                            })
                        },
                    )?;
                    result["pass_stash_withdrawal_hash"] = json!(withdrawn.to_str_radix(10));
                }
                // Event ordinals include settlement and mining entries, so
                // they are not bounded by the ordinary transaction count.
                let (h, n) = cursor_with_position_limit(&p, "before", s.height, i64::MAX as u64)?;
                let mut statement=db.prepare("SELECT e.record,e.height,e.position FROM explorer_events e JOIN explorer_blocks b ON b.hash=e.block_hash WHERE e.address=?1 AND e.canonical=1 AND b.canonical=1 AND (e.height<?2 OR (e.height=?2 AND e.position<?3)) ORDER BY e.height DESC,e.position DESC LIMIT ?4")?;
                let (items, next) = paged(
                    &mut statement,
                    params![encoded, h, n, limit],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                let mut items = items;
                for value in &mut items {
                    settlement(db, value)?;
                }
                result["history"] = Value::from(items);
                result["next_cursor"] = next;
                result["pending"] = pending(
                    mempool
                        .iter()
                        .filter(|t| {
                            t.body.sender == key || recipient(&t.body.operation) == Some(key)
                        })
                        .take(limit as usize)
                        .map(|t| tx_value(c, s, t, None, None, None)),
                    &mut budget,
                )?;
            }
            "explorer_governance" => {
                fields(
                    &p,
                    &[
                        "limit",
                        "before",
                        "before_height",
                        "proposal",
                        "proposal_before",
                    ],
                )?;
                let proposal = p
                    .get("proposal")
                    .map(|v| parse_hash(v.as_str().context("proposal ID must be text")?))
                    .transpose()?;
                let proposal_text = proposal.map(hex::encode).unwrap_or_default();
                let (h, n) = cursor(&p, s.height, c)?;
                let before =
                    height_parameter(&p, "before_height")?.unwrap_or(s.height.saturating_add(1));
                result["phase"] = json!(s.phase_name());
                result["current"] = serde_json::to_value(&s.phase)?;
                let (ph, pn) = cursor_named(&p, "proposal_before", s.height, c)?;
                let proposal_filter = if proposal.is_some() {
                    "p.id=?1"
                } else {
                    "?1=''"
                };
                let mut statement=db.prepare(&format!("SELECT p.record,p.height,p.position FROM explorer_proposals p JOIN explorer_blocks b ON b.hash=p.block_hash WHERE p.canonical=1 AND b.canonical=1 AND {proposal_filter} AND (p.height<?2 OR(p.height=?2 AND p.position<?3)) ORDER BY p.height DESC,p.position DESC LIMIT ?4"))?;
                let (mut proposals, proposal_next) = paged(
                    &mut statement,
                    params![proposal_text, ph, pn, limit],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                for p in &mut proposals {
                    let id = parse_hash(p["id"].as_str().context("indexed proposal ID")?)?;
                    if let Some(record) = s.proposals.get(&id) {
                        p["support"] = json!(record.support.to_str_radix(10));
                        p["refund_height"] = json!(record.refund_height);
                    }
                }
                result["proposal_next_cursor"] = proposal_next;
                result["proposals"] = Value::from(proposals);
                let decision_filter = if proposal.is_some() {
                    "(d.proposal=?1 OR d.id=?1)"
                } else {
                    "?1=''"
                };
                // The live decision appears only on the first page. With a
                // one-row page its cursor still permits reaching older results.
                let mut decisions = Vec::new();
                if !p.as_object().unwrap().contains_key("before_height")
                    && let Phase::Governance(d) = &s.phase
                    && proposal.is_none_or(|p| p == d.proposal_id || p == d.id)
                {
                    let live = decision_record(c, s, None)?;
                    budget.admit(json_bytes(&live), &live, true);
                    decisions.push(live);
                }
                let mut statement=db.prepare(&format!("SELECT d.record FROM explorer_decisions d JOIN explorer_blocks b ON b.hash=d.block_hash WHERE d.canonical=1 AND b.canonical=1 AND {decision_filter} AND d.height<?2 ORDER BY d.height DESC LIMIT ?3"))?;
                let (older, truncated) = records(
                    &mut statement,
                    params![proposal_text, before, limit - decisions.len() as u64],
                    &mut budget,
                )?;
                decisions.extend(older);
                result["next_before_height"] = decisions
                    .last()
                    .filter(|_| truncated || decisions.len() == limit as usize)
                    .map(|d| {
                        d["ended_height"]
                            .as_u64()
                            .map_or(json!(s.height.saturating_add(1)), |height| json!(height))
                    })
                    .unwrap_or(Value::Null);
                result["decisions"] = Value::from(decisions);
                let contribution_filter = if proposal.is_some() {
                    "e.proposal=?1"
                } else {
                    "?1=''"
                };
                let mut statement=db.prepare(&format!("SELECT e.record,e.height,e.position FROM explorer_contributions e JOIN explorer_blocks b ON b.hash=e.block_hash WHERE e.canonical=1 AND b.canonical=1 AND {contribution_filter} AND (e.height<?2 OR(e.height=?2 AND e.position<?3)) ORDER BY e.height DESC,e.position DESC LIMIT ?4"))?;
                let (items, next) = paged(
                    &mut statement,
                    params![proposal_text, h, n, limit],
                    limit,
                    s.height,
                    &mut budget,
                )?;
                result["contributions"] = Value::from(items);
                result["next_cursor"] = next;
            }
            _ => bail!("unknown explorer method"),
        }
        Ok(result)
    }
}

fn string<'a>(p: &'a Value, name: &str) -> Result<&'a str> {
    p.get(name)
        .and_then(Value::as_str)
        .with_context(|| format!("{name} must be text"))
}
fn parse_hash(value: &str) -> Result<Hash> {
    ensure!(value.len() == 64, "hash must be 64 hexadecimal characters");
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid hash"))
}
fn height_parameter(p: &Value, name: &str) -> Result<Option<u64>> {
    p.get(name)
        .map(|v| {
            let n = v
                .as_u64()
                .with_context(|| format!("{name} must be a nonnegative integer"))?;
            ensure!(n <= u32::MAX as u64 + 1, "height or offset too large");
            Ok(n)
        })
        .transpose()
}
fn limit(p: &Value) -> Result<u64> {
    let limit = p
        .get("limit")
        .map(|v| v.as_u64().context("limit must be an integer"))
        .transpose()?
        .unwrap_or(20);
    ensure!((1..=MAX_PAGE).contains(&limit), "limit must be 1..50");
    Ok(limit)
}
fn fields(p: &Value, allowed: &[&str]) -> Result<()> {
    ensure!(
        p.as_object()
            .context("parameters must be an object")?
            .keys()
            .all(|k| allowed.contains(&k.as_str())),
        "unknown explorer parameter"
    );
    Ok(())
}
fn cursor(p: &Value, height: u64, c: &Config) -> Result<(u64, u64)> {
    cursor_named(p, "before", height, c)
}
fn cursor_named(p: &Value, name: &str, height: u64, c: &Config) -> Result<(u64, u64)> {
    cursor_with_position_limit(p, name, height, position_limit(c))
}
/// A block holds at most max_signatures transactions; SQLite stores positions as i64.
fn position_limit(c: &Config) -> u64 {
    (c.max_signatures as u64).min(i64::MAX as u64)
}
fn cursor_with_position_limit(
    p: &Value,
    name: &str,
    height: u64,
    max_position: u64,
) -> Result<(u64, u64)> {
    match p.get(name) {
        None => Ok((height.saturating_add(1), 0)),
        Some(v) => {
            let text = v.as_str().context("cursor must be text")?;
            ensure!(text.len() <= 40, "cursor too long");
            let (h, n) = text.split_once(':').context("invalid cursor")?;
            let (h, n) = (h.parse::<u64>()?, n.parse::<u64>()?);
            ensure!(
                h <= u32::MAX as u64 + 1 && n <= max_position,
                "invalid cursor bounds"
            );
            Ok((h, n))
        }
    }
}
/// Continuations carry an anchor block from the previous page so a
/// reorganization cannot silently hide replacement messages below an already
/// consumed cursor. A cursor remains valid while every block at or below it is
/// unchanged: returns that unchanged height, and whether the anchor was replaced.
fn scan_anchor(
    db: &Connection,
    p: &Value,
    cursor: &str,
    label: &str,
) -> Result<Option<(u64, bool)>> {
    ensure!(
        p.get(cursor).is_some() == p.get("anchor").is_some(),
        "{cursor} and anchor must be supplied together"
    );
    let Some(_) = p.get("anchor") else {
        return Ok(None);
    };
    let mut hash = hex::encode(parse_hash(string(p, "anchor")?)?);
    // Detached records keep their parent, so a shallow replacement relates the
    // anchor to its newest canonical ancestor without restarting discovery.
    for depth in 0..=ANCHOR_DEPTH {
        let row: Option<(u64, bool, Option<String>)> = db
            .query_row(
                "SELECT height,canonical,json_extract(record,'$.previous') FROM explorer_blocks WHERE hash=?1",
                [&hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((height, canonical, previous)) = row else {
            break;
        };
        if canonical {
            return Ok(Some((height, depth > 0)));
        }
        let Some(previous) = previous else {
            break;
        };
        hash = previous;
    }
    bail!("{label} scan anchor is no longer canonical")
}
fn scan_after(
    p: &Value,
    anchor: Option<(u64, bool)>,
    label: &str,
    c: &Config,
) -> Result<(i64, i64)> {
    let Some(value) = p.get("after") else {
        return Ok((-1, -1));
    };
    let text = value.as_str().context("after must be text")?;
    ensure!(text.len() <= 40, "cursor too long");
    let (h, n) = text.split_once(':').context("invalid cursor")?;
    ensure!(
        !h.is_empty() && !n.is_empty() && h.bytes().chain(n.bytes()).all(|b| b.is_ascii_digit()),
        "invalid cursor"
    );
    let (h, n) = (h.parse::<u64>()?, n.parse::<u64>()?);
    let (unchanged, replaced) = anchor.context("missing scan anchor")?;
    // Report where the replaced history begins: a client may keep what it
    // found at or below that height and continue after it with this anchor.
    ensure!(
        !replaced || h <= unchanged,
        "{label} scan anchor is no longer canonical; blocks above height {unchanged} were replaced"
    );
    ensure!(
        h <= unchanged && h <= u32::MAX as u64 && (n <= position_limit(c) || n == i64::MAX as u64),
        "invalid cursor bounds"
    );
    Ok((h as i64, n as i64))
}
fn confirmations(v: &mut Value, tip: u64) {
    if let Some(h) = v["height"].as_u64() {
        v["confirmations"] = json!(tip.saturating_sub(h) + 1);
    }
}

/// One allowance shared by every section of a response, pending records
/// included: record text bytes and parsed JSON values, like node JSON pages.
struct Budget {
    bytes: usize,
    values: usize,
}
impl Budget {
    fn new() -> Self {
        Self::with_bytes(PAGE_BYTES)
    }
    fn with_bytes(bytes: usize) -> Self {
        Self {
            bytes,
            values: crate::network_guard::MAX_JSON_VALUES,
        }
    }
    fn fits(&self, bytes: usize) -> bool {
        bytes <= self.bytes
    }
    /// Charge one record. A section's first record is always admitted, so a
    /// large record is returned alone rather than hidden behind its cursor.
    fn admit(&mut self, bytes: usize, value: &Value, first: bool) -> bool {
        let values = json_values(value);
        if !first && (bytes > self.bytes || values > self.values) {
            return false;
        }
        self.bytes = self.bytes.saturating_sub(bytes);
        self.values = self.values.saturating_sub(values);
        true
    }
}
fn json_values(value: &Value) -> usize {
    1 + match value {
        Value::Array(items) => items.iter().map(json_values).sum(),
        Value::Object(fields) => fields.values().map(json_values).sum(),
        _ => 0,
    }
}
fn json_bytes(value: &Value) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            self.0 += input.len();
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}
/// Pending records have no cursor; the shared budget may shorten the list.
fn pending(values: impl Iterator<Item = Result<Value>>, budget: &mut Budget) -> Result<Value> {
    let mut items = Vec::new();
    for value in values {
        let value = value?;
        if !budget.admit(json_bytes(&value), &value, items.is_empty()) {
            break;
        }
        items.push(value);
    }
    Ok(Value::from(items))
}
/// Fixed-shape records paged by height; also reports whether the budget ended the page.
fn records<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    budget: &mut Budget,
) -> Result<(Vec<Value>, bool)> {
    let mut rows = statement.query(p)?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        let record: String = row.get(0)?;
        if !items.is_empty() && !budget.fits(record.len()) {
            return Ok((items, true));
        }
        let value: Value = serde_json::from_str(&record)?;
        if !budget.admit(record.len(), &value, items.is_empty()) {
            return Ok((items, true));
        }
        items.push(value);
    }
    Ok((items, false))
}
fn paged<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
    budget: &mut Budget,
) -> Result<(Vec<Value>, Value)> {
    paged_with_budget(statement, p, limit, tip, false, budget)
}
fn paged_more<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
    budget: &mut Budget,
) -> Result<(Vec<Value>, Value)> {
    paged_with_budget(statement, p, limit, tip, true, budget)
}

fn paged_with_budget<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
    has_lookahead: bool,
    budget: &mut Budget,
) -> Result<(Vec<Value>, Value)> {
    // Chat rows select their transaction data as a fourth column: the text.
    let text = statement.column_count() > 3;
    let mut rows = statement.query(p)?;
    let mut items = Vec::new();
    let mut last = None;
    while let Some(row) = rows.next()? {
        if items.len() == limit as usize {
            return Ok((items, json!(last)));
        }
        let record: String = row.get(0)?;
        let data: Option<Vec<u8>> = text.then(|| row.get(3)).transpose()?;
        let bytes = record.len() + data.as_ref().map_or(0, Vec::len);
        // A single record can expand in JSON. Return it alone rather than
        // silently skipping it; the HTTP response envelope stays bounded too.
        if !items.is_empty() && !budget.fits(bytes) {
            return Ok((items, json!(last)));
        }
        let (h, n): (u64, u64) = (row.get(1)?, row.get(2)?);
        let mut value: Value = serde_json::from_str(&record)?;
        if let Some(data) = data {
            value["text"] = json!(String::from_utf8(data).context("invalid indexed text")?);
        }
        confirmations(&mut value, tip);
        if !budget.admit(bytes, &value, items.is_empty()) {
            return Ok((items, json!(last)));
        }
        items.push(value);
        last = Some(format!("{h}:{n}"));
    }
    let next = if !has_lookahead && items.len() == limit as usize {
        json!(last)
    } else {
        Value::Null
    };
    Ok((items, next))
}

/// Mark indexed rows above `height`, or every row, as detached.
fn detach(db: &rusqlite::Transaction<'_>, height: Option<u64>) -> Result<()> {
    for table in TABLES {
        match height {
            Some(h) => db.execute(
                &format!("UPDATE {table} SET canonical=0 WHERE canonical=1 AND height>?1"),
                [h],
            )?,
            None => db.execute(
                &format!("UPDATE {table} SET canonical=0 WHERE canonical=1"),
                [],
            )?,
        };
    }
    Ok(())
}
fn set_tip(db: &rusqlite::Transaction<'_>, hash: &Hash) -> Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO explorer_meta VALUES('tip',?1)",
        [hex::encode(hash)],
    )?;
    Ok(())
}
/// Another connection held the index lock past the busy timeout: transient.
fn contended(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<rusqlite::Error>()
            .and_then(rusqlite::Error::sqlite_error_code)
            .is_some_and(|code| {
                matches!(
                    code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                )
            })
    })
}
/// The newest indexed canonical height whose block is still canonical.
fn common_ancestor(db: &Connection, chain: &Chain) -> Result<Option<u64>> {
    let last: Option<u64> = db
        .query_row(
            "SELECT height FROM explorer_blocks WHERE canonical=1 ORDER BY height DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let mut common = last.map(|h| h.min(chain.tip_height()));
    while let Some(h) = common {
        let stored: Option<String> = db
            .query_row(
                "SELECT hash FROM explorer_blocks WHERE canonical=1 AND height=?1",
                [h],
                |r| r.get(0),
            )
            .optional()?;
        if stored == chain.hash_at_height(h).map(hex::encode) {
            break;
        }
        common = h.checked_sub(1);
    }
    Ok(common)
}
/// Contiguous canonical states at or below `height` that the chain already
/// retains (oldest first). With none in that window, the chain's nearest
/// active-chain checkpoint below it (two per doubling of depth), else genesis.
/// This never replays history.
fn checkpoints(chain: &Chain, height: u64) -> Result<VecDeque<(Hash, Arc<State>)>> {
    let mut states = VecDeque::new();
    for h in (height.saturating_sub(CHECKPOINTS as u64 - 1)..=height).rev() {
        let hash = chain
            .hash_at_height(h)
            .context("missing canonical height")?;
        let state = if h == 0 {
            Some(Arc::new(State::genesis(&chain.config)))
        } else {
            chain.cached_state(&hash)
        };
        match state {
            Some(state) => states.push_front((hash, state)),
            None if states.is_empty() => {}
            None => break,
        }
    }
    if states.is_empty() {
        match chain.checkpoint_at_or_below(height) {
            Some(checkpoint) => states.push_back(checkpoint),
            None => {
                let hash = chain.hash_at_height(0).context("missing genesis")?;
                states.push_back((hash, Arc::new(State::genesis(&chain.config))));
            }
        }
    }
    Ok(states)
}

#[cfg(test)]
mod page_capacity_tests {
    use super::*;

    #[test]
    fn large_records_page_without_skipping_or_repeating_the_overflow_row() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE items(record TEXT,height INTEGER,position INTEGER)")
            .unwrap();
        for height in 1..=3 {
            let record = json!({"height":height,"text":"x".repeat(200)}).to_string();
            db.execute("INSERT INTO items VALUES(?1,?2,0)", params![record, height])
                .unwrap();
        }
        let mut query = db.prepare("SELECT record,height,position FROM items WHERE height<?1 ORDER BY height DESC LIMIT 50").unwrap();
        let (first, cursor) =
            paged_with_budget(&mut query, [4], 50, 3, false, &mut Budget::with_bytes(100)).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["height"], 3);
        assert_eq!(cursor, "3:0");
        let (second, cursor) =
            paged_with_budget(&mut query, [3], 50, 3, true, &mut Budget::with_bytes(100)).unwrap();
        assert_eq!(second[0]["height"], 2);
        assert_eq!(cursor, "2:0");
        let (last, cursor) =
            paged_with_budget(&mut query, [2], 50, 3, true, &mut Budget::with_bytes(100)).unwrap();
        assert_eq!(last[0]["height"], 1);
        assert!(cursor.is_null());
    }

    #[test]
    fn oversized_records_omit_bulky_detail_instead_of_failing_storage() {
        let value = json!({"txid":"01","fee":"3","operation":{"Grant":vec![[7u8; 32]; 64]}});
        let full = serde_json::to_string(&value).unwrap();
        assert_eq!(
            record_text(&value, "operation", full.len()),
            Some(full.clone())
        );
        assert!(bounded_json(&value, full.len() - 1).is_none());
        let reduced = record_text(&value, "operation", full.len() - 1).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reduced).unwrap(),
            json!({"txid":"01","fee":"3","operation_omitted":true})
        );
        assert!(record_text(&value, "operation", 8).is_none());
        // Mail keeps the signed transaction its clients verify and drops only
        // the decoded copy of its operation.
        let mail = json!({"txid":"01","raw":"ab".repeat(64),"operation":value["operation"]});
        let full = serde_json::to_string(&mail).unwrap();
        let reduced = record_text(&mail, "operation", full.len() - 1).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&reduced).unwrap(),
            json!({"txid":"01","raw":"ab".repeat(64),"operation_omitted":true})
        );
    }

    #[test]
    fn signed_mail_grant_carriers_remain_bounded_and_page_without_losing_raw_bytes() {
        let mut c = Config::testnet();
        c.initial.block_bytes = PAGE_BYTES as u64;
        let s = State::genesis(&c);
        let secret = [91; 32];
        let owner = crate::crypto::public_key(&secret).unwrap();
        let data = crate::mail::tests::fixture();
        // Exercise a near-capacity recipient list with this mail payload,
        // reserving space for transaction/block framing and the miner.
        let count = (PAGE_BYTES - data.len() - 2048) / (crate::fees::ACCOUNT_WEIGHT as usize + 34);
        let mut payments: Vec<_> = (0..count)
            .map(|i| {
                let mut recipient_secret = [83; 32];
                recipient_secret[..8].copy_from_slice(&(i as u64).to_le_bytes());
                GrantPayment {
                    recipient: crate::crypto::public_key(&recipient_secret).unwrap(),
                    amount: 1u32.into(),
                }
            })
            .collect();
        payments.sort_by_key(|p| p.recipient);
        let body = TransactionBody {
            sender: owner,
            nonce: 0,
            fee: 100_000u32.into(),
            anchor: [38; 32],
            expiry_blocks: 100,
            operation: Operation::Propose {
                round: 1,
                description: [43; 32],
                proposal: Proposal::Grant { payments },
                support: 1u32.into(),
            },
            data,
        };
        let first = crate::crypto::sign(&s.chain_id, &body, &secret).unwrap();
        assert!(count > 31_000);
        assert!(
            codec::encode(&first).len() + count * crate::fees::ACCOUNT_WEIGHT as usize + 1024
                <= PAGE_BYTES
        );
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE items(record TEXT,height INTEGER,position INTEGER)")
            .unwrap();
        let mut largest = 0;
        for nonce in 0..3 {
            let mut body = body.clone();
            body.nonce = nonce;
            let transaction = crate::crypto::sign(&s.chain_id, &body, &secret).unwrap();
            let record = mail_value(&s, &transaction, Some(nonce + 1), Some([7; 32]), Some(0))
                .unwrap()
                .to_string();
            largest = largest.max(record.len());
            assert!(record.len() < PAGE_BYTES);
            db.execute(
                "INSERT INTO items VALUES(?1,?2,0)",
                params![record, nonce + 1],
            )
            .unwrap();
        }
        let mut query = db
            .prepare(
                "SELECT record,height,position FROM items WHERE height>?1 ORDER BY height LIMIT 51",
            )
            .unwrap();
        // A shortened page budget exercises overflow with real, complete signed
        // grant carriers, without constructing multiple maximum-size pages.
        for previous in 0..3 {
            let (page, cursor) = paged_with_budget(
                &mut query,
                [previous],
                50,
                3,
                true,
                &mut Budget::with_bytes(largest),
            )
            .unwrap();
            assert_eq!(page.len(), 1);
            let transaction =
                crate::wallet::decode_signed(page[0]["raw"].as_str().unwrap(), &s.chain_id)
                    .unwrap();
            assert_eq!(transaction.body.nonce, previous as u64);
            assert_eq!(
                page[0]["txid"],
                hex::encode(codec::transaction_id(&transaction))
            );
            assert_eq!(page[0]["data_hex"], hex::encode(&transaction.body.data));
            if previous < 2 {
                assert_eq!(cursor, format!("{}:0", previous + 1));
            } else {
                assert!(cursor.is_null());
            }
        }
    }
}

fn recipient(operation: &Operation) -> Option<PublicKey> {
    match operation {
        Operation::TransferExact { recipient, .. } => Some(*recipient),
        _ => None,
    }
}
fn kind(operation: &Operation) -> &'static str {
    match operation {
        Operation::TransferExact { .. } => "transfer",
        Operation::Deposit { .. } => "deposit",
        Operation::Redeem { .. } => "redeem",

        Operation::Propose { .. } => "propose",
        Operation::Support { .. } => "support",
        Operation::Refund { .. } => "refund",
    }
}
fn operation_amount(operation: &Operation) -> Option<(&Amount, &'static str)> {
    match operation {
        Operation::TransferExact { amount, .. }
        | Operation::Deposit { amount, .. }
        | Operation::Support { amount, .. } => Some((amount, "hash")),
        Operation::Propose { support, .. } => Some((support, "hash")),
        Operation::Redeem { shares, .. } => Some((shares, "stash")),
        _ => None,
    }
}
fn chat_value(
    s: &State,
    t: &Transaction,
    height: Option<u64>,
    block: Option<Hash>,
    position: Option<u64>,
) -> Option<Value> {
    let message = crate::chat::from_transaction(t)?;
    let operation = t.body.operation.clone();
    let amount = operation_amount(&operation);
    Some(
        json!({"txid":hex::encode(codec::transaction_id(t)),"sender":address::encode(&t.body.sender, &s.chain_id).ok()?,"height":height,"block_hash":block.map(hex::encode),"position":position,"text":message,"kind":kind(&operation),"amount":amount.map(|(value,_)|value.to_str_radix(10)),"asset":amount.map(|(_,asset)|asset),"recipient":recipient(&operation).and_then(|key|address::encode(&key,&s.chain_id).ok()),"status":if height.is_some(){"confirmed"}else{"pending"},"confirmations":0}),
    )
}

fn mail_value(
    s: &State,
    t: &Transaction,
    height: Option<u64>,
    block: Option<Hash>,
    position: Option<u64>,
) -> Option<Value> {
    crate::mail::from_transaction(t)?;
    let operation = t.body.operation.clone();
    Some(
        json!({"txid":hex::encode(codec::transaction_id(t)),"raw":crate::wallet::signed_hex(t),"sender":address::encode(&t.body.sender,&s.chain_id).ok()?,"sender_public_key":hex::encode(t.body.sender),"nonce":t.body.nonce.to_string(),"kind":kind(&operation),"operation":operation,"data_hex":hex::encode(&t.body.data),"height":height,"block_hash":block.map(hex::encode),"position":position,"status":"confirmed","confirmations":0}),
    )
}

fn tx_value(
    c: &Config,
    s: &State,
    t: &Transaction,
    height: Option<u64>,
    block: Option<Hash>,
    paid: Option<Amount>,
) -> Result<Value> {
    let operation = t.body.operation.clone();
    let data = &t.body.data;
    if let Some(paid) = paid {
        ensure!(
            paid == t.body.fee,
            "recorded fee differs from signed charge"
        );
    }
    let quote = fees::quote(c, s, t).ok();
    let mut v = json!({"txid":hex::encode(codec::transaction_id(t)),"status":if height.is_some(){"confirmed"}else{"pending"},"height":height,"block_hash":block.map(hex::encode),"confirmations":0,"sender":address::encode(&t.body.sender,&s.chain_id)?,"sender_public_key":hex::encode(t.body.sender),"nonce":t.body.nonce,"fee":t.body.fee.to_str_radix(10),"minimum_fee":quote.as_ref().map(|q|q.minimum_fee.to_str_radix(10)),"extra_fee":quote.as_ref().map(|q|q.extra_fee.to_str_radix(10)),"anchor":hex::encode(t.body.anchor),"expiry_blocks":t.body.expiry_blocks,"kind":kind(&operation),"operation":operation,"data_hex":hex::encode(&data[..data.len().min(256)]),"data_bytes":data.len(),"data_truncated":data.len()>256,"size_bytes":codec::encode(t).len()});
    if let Some(recipient) = recipient(&operation) {
        v["recipient"] = json!(address::encode(&recipient, &s.chain_id)?);
    }
    if let Some((amount, asset)) = operation_amount(&operation) {
        v["amount"] = json!(amount.to_str_radix(10));
        v["asset"] = json!(asset);
    }
    conditional_fields(s, &operation, &mut v);
    // A pending minimum is a quote for the current tip, not a recorded charge.
    if height.is_none() {
        v["fee_estimated"] = json!(true);
    }
    Ok(v)
}

/// Trades name their own decision and outcome. Any other operation executed
/// while a decision is live applies to both outcomes; it names that decision
/// with no outcome, and its settlement effect is `common`.
fn conditional_fields(s: &State, operation: &Operation, value: &mut Value) {
    let (decision, outcome) = match operation {
        Operation::Deposit {
            decision, outcome, ..
        }
        | Operation::Redeem {
            decision, outcome, ..
        } => (*decision, *outcome),
        _ => match s.decision_id() {
            Some(decision) => (Some(decision), None),
            None => return,
        },
    };
    value["decision"] = json!(decision.map(hex::encode));
    value["outcome"] = json!(outcome.map(|o| match o {
        Outcome::Pass => "pass",
        Outcome::Fail => "fail",
    }));
}
fn settlement(db: &Connection, value: &mut Value) -> Result<()> {
    let Some(decision) = value.get("decision").and_then(Value::as_str) else {
        return Ok(());
    };
    let record:Option<String>=db.query_row("SELECT d.record FROM explorer_decisions d JOIN explorer_blocks b ON b.hash=d.block_hash WHERE d.id=?1 AND b.canonical=1 ORDER BY d.height DESC LIMIT 1",[decision],|r|r.get(0)).optional()?;
    let outcome = record
        .map(|r| serde_json::from_str::<Value>(&r))
        .transpose()?
        .and_then(|r| r["outcome"].as_str().map(str::to_owned));
    let effect = if value["status"] == "orphaned" {
        "orphaned"
    } else if value["status"] == "pending" {
        "pending"
    } else if let Some(selected) = value["outcome"].as_str() {
        match outcome.as_deref() {
            Some(winner) if winner == selected => "survived",
            Some(_) => "discarded",
            None => "conditional",
        }
    } else {
        "common"
    };
    value["settlement"] = json!({"resolved_outcome":outcome,"effect":effect});
    Ok(())
}

/// Execute an already validated block once while deriving its index records.
/// All rows remain uncommitted until the resulting consensus root agrees with
/// the block; the returned state is also the worker's next replay checkpoint.
fn index_block(
    db: &rusqlite::Transaction<'_>,
    c: &Config,
    b: &Block,
    parent: Option<&State>,
) -> Result<State> {
    ensure!(
        parent.is_some() == (b.height > 0),
        "explorer parent mismatch"
    );
    let chain_id = parent.map_or_else(|| c.chain_id(), |s| s.chain_id);
    let hash = codec::block_hash(b);
    let hash_text = hex::encode(hash);
    let expected = math::work(&math::target_from_bits(b.header.bits)?);
    let subsidy = if parent.is_some() {
        math::issuance(&expected, &c.work_per_atom()?)?
    } else {
        Amount::zero()
    };
    let difficulty = expected.to_f64().unwrap_or(f64::MAX) / 4_295_032_833f64;
    let miner = if b.height == 0 {
        None
    } else {
        Some(address::encode(&b.miner, &chain_id)?)
    };
    let mut summary = json!({"height":b.height,"hash":hash_text,"previous":hex::encode(b.header.previous),"state_root":hex::encode(b.state_root),"status":"confirmed","miner":miner,"miner_public_key":if b.height==0{None}else{Some(hex::encode(b.miner))},"expected_hashes":expected.to_str_radix(10),"difficulty":difficulty,"transaction_count":b.transactions.len(),"body_bytes":codec::body_size(b)?,"subsidy":subsidy.to_str_radix(10),"header":b.header});
    let mut transaction_fees = Amount::zero();
    let mut miner_fees = Amount::zero();
    let mut extra_fees = Amount::zero();
    let mut revenue_fees = Amount::zero();
    let mut mandatory = Amount::zero();
    let mut fee_state = parent
        .map(|p| {
            consensus::prepare_block(c, p, &b.miner, &expected).map(|execution| execution.state)
        })
        .transpose()?;
    let (post, fills) = if let Some(parent) = parent {
        consensus::execute_with_fills(
            c,
            parent,
            &b.header.previous,
            &b.miner,
            &expected,
            &b.transactions,
        )?
    } else {
        (State::genesis(c), Vec::new())
    };
    ensure!(
        post.root() == b.state_root,
        "explorer replay commitment mismatch"
    );
    let fills: BTreeMap<_, _> = fills
        .into_iter()
        .map(|fill| (fill.transaction_id, fill))
        .collect();
    // A decision resolves, paying any passed grant, before the block's
    // transactions run; the miner is credited after them. Event positions
    // follow that order, so payouts take the lowest ordinals of the block.
    let mut first = 0;
    if let Some(parent) = parent
        && let Phase::Governance(d) = &parent.phase
        && post.decision_id() != Some(d.id)
    {
        let record = decision_record(c, parent, Some(b.height))?;
        if record["outcome"] == "pass"
            && let Proposal::Grant { payments } = &*d.proposal
        {
            for (index, payment) in payments.iter().enumerate() {
                let event = json!({"height":b.height,"block_hash":hash_text,"kind":"governance_grant","amount":payment.amount.to_str_radix(10),"asset":"hash","decision":hex::encode(d.id),"proposal":hex::encode(d.proposal_id),"outcome":"pass","payout_index":index});
                event_row(
                    db,
                    &payment.recipient,
                    &post.chain_id,
                    &hash_text,
                    b.height,
                    index as u64,
                    &event,
                )?;
            }
            first = payments.len() as u64;
        }
        db.execute("INSERT OR REPLACE INTO explorer_decisions(id,proposal,block_hash,height,record) VALUES(?1,?2,?3,?4,?5)",params![hex::encode(d.id),hex::encode(d.proposal_id),hash_text,b.height,serde_json::to_string(&record)?])?;
    }
    for (position, t) in b.transactions.iter().enumerate() {
        let opening = fee_state.as_mut().context("genesis has transactions")?;
        let quote = fees::quote(c, opening, t)?;
        miner_fees += &quote.miner_fee;
        revenue_fees += &quote.revenue_fee;
        extra_fees += &quote.extra_fee;
        mandatory += &quote.minimum_fee;
        let paid = quote.fee;
        transaction_fees += &paid;
        let mut value = tx_value(c, opening, t, Some(b.height), Some(hash), Some(paid))?;
        let mut role = "sender";
        // A refund credits the whole unclaimed support, which its signed
        // operation does not state; no earlier transaction in a block can
        // change that record, so read it from the block's opening state. The
        // signer's event is then a credit, recorded with the recipient role.
        if let Operation::Refund { round, proposal } = &t.body.operation
            && let Some(support) =
                opening
                    .supports
                    .get(&crate::state::support_key(*round, proposal, &t.body.sender))
        {
            value["amount"] = json!(support.amount.to_str_radix(10));
            value["asset"] = json!("hash");
            role = "recipient";
        }
        let transaction_id = codec::transaction_id(t);
        let fill = if matches!(
            t.body.operation,
            Operation::Deposit { .. } | Operation::Redeem { .. }
        ) {
            Some(
                fills
                    .get(&transaction_id)
                    .context("missing confirmed trade fill")?,
            )
        } else {
            None
        };
        if let Some(fill) = fill {
            attach_fill(&mut value, fill);
        }
        let id = hex::encode(transaction_id);
        let operation = t.body.operation.clone();
        // Raw bytes, never a hex copy, in a row of their own: SQLite limits a
        // whole row, and this one stays smaller than the chain's row for the
        // stored block, while the bounded record never shares it.
        let record = record_text(&value, "operation", RECORD_BYTES)
            .context("oversized explorer transaction record")?;
        db.execute("INSERT OR REPLACE INTO explorer_transactions(txid,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![id,hash_text,b.height,position as u64,record])?;
        db.execute("INSERT OR REPLACE INTO explorer_transaction_data(txid,block_hash,data) VALUES(?1,?2,?3)",params![id,hash_text,t.body.data])?;
        if let Some(mut message) = chat_value(
            opening,
            t,
            Some(b.height),
            Some(hash),
            Some(position as u64),
        ) {
            // Reads restore the text from the transaction data above.
            if let Some(fields) = message.as_object_mut() {
                fields.remove("text");
            }
            db.execute("INSERT OR REPLACE INTO explorer_chat(txid,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)", params![id,hash_text,b.height,position as u64,serde_json::to_string(&message)?])?;
        }
        // Mail needs its complete signed `raw` transaction; clients verify the
        // decoded operation against it, so an oversized record drops that copy.
        // One whose signed transaction alone exceeds the bound is not listed:
        // a listed record must stay deliverable, or every scan would stop on it.
        if let Some(record) = mail_value(
            opening,
            t,
            Some(b.height),
            Some(hash),
            Some(position as u64),
        )
        .and_then(|message| record_text(&message, "operation", RECORD_BYTES))
        {
            db.execute("INSERT OR REPLACE INTO explorer_mail(txid,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![id,hash_text,b.height,position as u64,record])?;
        }
        let mut event = json!({"height":b.height,"block_hash":hash_text,"txid":id,"kind":kind(&operation),"role":role,"fee":value["fee"],"amount":value.get("amount"),"asset":value.get("asset"),"recipient":value.get("recipient")});
        conditional_fields(opening, &operation, &mut event);
        if let Some(fill) = fill {
            attach_fill(&mut event, fill);
        }
        event_row(
            db,
            &t.body.sender,
            &chain_id,
            &hash_text,
            b.height,
            first + position as u64 * 4,
            &event,
        )?;
        if let Some(recipient) = recipient(&operation) {
            event["role"] = json!("recipient");
            event["sender"] = value["sender"].clone();
            event_row(
                db,
                &recipient,
                &chain_id,
                &hash_text,
                b.height,
                first + position as u64 * 4 + 1,
                &event,
            )?;
        }
        // Fee allocation charges the first transfer that creates a recipient.
        // Track only existence here; execution and actual trade fills came from
        // the complete batch replay above.
        if let Operation::TransferExact { recipient, .. } = &operation
            && opening.account(recipient, None).is_none()
        {
            opening.world.put(*recipient, Account::default(), c)?;
            if let Some(pass) = &mut opening.alternative {
                pass.put(*recipient, Account::default(), c)?;
            }
        }
        // Record weight is charged only for a support record that does not
        // exist yet. A proposal writes its proposer's record and a support
        // writes its sender's, so a later support for the same record in this
        // block pays none, as consensus quotes it against the running state.
        let supported = match &operation {
            Operation::Propose {
                round,
                description,
                proposal,
                support,
            } => Some((
                *round,
                crate::state::proposal_id(&chain_id, *round, &t.body.sender, description, proposal),
                support,
            )),
            Operation::Support {
                round,
                proposal,
                amount,
            } => Some((*round, *proposal, amount)),
            _ => None,
        };
        if let Some((round, proposal, amount)) = supported {
            let key = crate::state::support_key(round, &proposal, &t.body.sender);
            let mut record = opening.supports.get(&key).cloned().unwrap_or(crate::state::SupportRecord {
                round,
                proposal,
                sender: t.body.sender,
                amount: Amount::zero(),
            });
            record.amount += amount;
            opening.supports.insert(key, record);
        }
        match &operation {
            Operation::Propose {
                round,
                description,
                proposal,
                support,
            } => {
                let id = hex::encode(crate::state::proposal_id(
                    &chain_id,
                    *round,
                    &t.body.sender,
                    description,
                    proposal,
                ));
                let record = json!({"id":id,"round":round,"description":hex::encode(description),"description_text":crate::proposal_data::from_transaction(t),"action":proposal,"support":support.to_str_radix(10),"created_height":b.height,"creator":value["sender"]});
                let record = record_text(&record, "action", RECORD_BYTES)
                    .context("oversized explorer proposal record")?;
                db.execute("INSERT OR REPLACE INTO explorer_proposals(id,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![id,hash_text,b.height,position as u64,record])?;
                contribution_row(
                    db,
                    &id,
                    &hash_text,
                    b.height,
                    position as u64,
                    &value,
                    support,
                )?;
            }
            Operation::Support {
                proposal, amount, ..
            } => contribution_row(
                db,
                &hex::encode(proposal),
                &hash_text,
                b.height,
                position as u64,
                &value,
                amount,
            )?,
            _ => {}
        }
    }
    summary["phase"] = json!(post.phase_name());
    summary["rewards"] = json!({"subsidy":subsidy.to_str_radix(10),"transaction_fees":transaction_fees.to_str_radix(10),"extra_fees":extra_fees.to_str_radix(10),"minimum_fees":mandatory.to_str_radix(10),"miner_fees":miner_fees.to_str_radix(10),"revenue_fees":revenue_fees.to_str_radix(10),"miner_total":(&subsidy+&miner_fees).to_str_radix(10),"complete":true});
    // Consensus credits the miner only a nonzero reward.
    if b.height > 0 && !(&subsidy + &miner_fees).is_zero() {
        let event = json!({"height":b.height,"block_hash":hash_text,"kind":"mining_reward","amount":summary["rewards"]["miner_total"],"complete":true,"asset":"hash"});
        event_row(
            db,
            &b.miner,
            &post.chain_id,
            &hash_text,
            b.height,
            first + b.transactions.len() as u64 * 4 + 10,
            &event,
        )?;
    }
    db.execute(
        "INSERT OR REPLACE INTO explorer_blocks VALUES(?1,?2,1,?3)",
        params![hash_text, b.height, serde_json::to_string(&summary)?],
    )?;
    Ok(post)
}
/// Serialized JSON no longer than `limit`, without building a larger string.
fn bounded_json(value: &impl serde::Serialize, limit: usize) -> Option<String> {
    struct Bounded {
        bytes: Vec<u8>,
        limit: usize,
    }
    impl std::io::Write for Bounded {
        fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
            if input.len() > self.limit - self.bytes.len() {
                return Err(std::io::Error::other("explorer record bound exceeded"));
            }
            self.bytes.extend_from_slice(input);
            Ok(input.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).ok()?;
    String::from_utf8(output.bytes).ok()
}
/// A stored record, replacing its `bulky` field with `<bulky>_omitted` when
/// the whole record would exceed `limit`.
fn record_text(value: &Value, bulky: &str, limit: usize) -> Option<String> {
    if let Some(text) = bounded_json(value, limit) {
        return Some(text);
    }
    let mut reduced: serde_json::Map<String, Value> = value
        .as_object()?
        .iter()
        .filter(|(name, _)| name.as_str() != bulky)
        .map(|(name, field)| (name.clone(), field.clone()))
        .collect();
    reduced.insert(format!("{bulky}_omitted"), json!(true));
    bounded_json(&reduced, limit)
}
fn event_row(
    db: &rusqlite::Transaction<'_>,
    key: &PublicKey,
    chain: &Hash,
    hash: &str,
    height: u64,
    position: u64,
    event: &Value,
) -> Result<()> {
    db.execute("INSERT OR REPLACE INTO explorer_events(address,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![address::encode(key,chain)?,hash,height,position,serde_json::to_string(event)?])?;
    Ok(())
}
fn contribution_row(
    db: &rusqlite::Transaction<'_>,
    proposal: &str,
    hash: &str,
    height: u64,
    position: u64,
    tx: &Value,
    amount: &Amount,
) -> Result<()> {
    let record = json!({"height":height,"block_hash":hash,"txid":tx["txid"],"proposal":proposal,"sender":tx["sender"],"amount":amount.to_str_radix(10)});
    db.execute("INSERT OR REPLACE INTO explorer_contributions(proposal,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![proposal,hash,height,position,serde_json::to_string(&record)?])?;
    Ok(())
}

fn decision_record(c: &Config, s: &State, ended_height: Option<u64>) -> Result<Value> {
    let Phase::Governance(d) = &s.phase else {
        bail!("no decision")
    };
    let pass = s
        .alternative
        .as_ref()
        .context("missing conditional state")?;
    let margin = s.frozen.pass_margin_bps.unwrap_or(0);
    let mut observed = s.height.saturating_sub(d.started_height).min(d.blocks);
    let mut leading = d.leading_blocks;
    // Resolution runs at the next block boundary using the parent's closing
    // quotes. Include that final observation in the historical result.
    if ended_height.is_some_and(|height| height > s.height) && observed < d.blocks {
        observed += 1;
        if consensus::pass_beats_fail(pass, &s.world, margin) {
            leading += 1;
        }
    }
    let funded = match &*d.proposal {
        Proposal::Grant { payments } => pass.grant_escrow == c.validate_grant(payments)?,
        _ => true,
    };
    let won = funded && observed == d.blocks && leading > d.blocks / 2;
    Ok(json!({
        "id":hex::encode(d.id), "proposal":hex::encode(d.proposal_id), "round":d.round,
        "started":d.started, "started_height":d.started_height, "ended_height":ended_height,
        "time_unit":"blocks", "blocks":d.blocks, "observed_blocks":observed,
        "leading_blocks":leading, "blocks_remaining":d.blocks.saturating_sub(observed),
        "outcome":ended_height.map(|_|if won {"pass"} else {"fail"}),
        "pass_margin_bps":margin, "funded":funded
    }))
}

fn attach_fill(value: &mut Value, fill: &consensus::TradeFill) {
    value["amount"] = json!(fill.input_filled.to_str_radix(10));
    value["input_requested"] = json!(fill.input_requested.to_str_radix(10));
    value["input_filled"] = json!(fill.input_filled.to_str_radix(10));
    value["input_unfilled"] = json!(fill.input_unfilled.to_str_radix(10));
    value["output"] = json!(fill.output.to_str_radix(10));
    value["output_asset"] = json!(if fill.is_buy { "shares" } else { "hash" });
    value["fill_status"] = json!(if fill.input_filled.is_zero() {
        "unfilled"
    } else if fill.input_unfilled.is_zero() {
        "full"
    } else {
        "partial"
    });
}

#[cfg(test)]
mod indexing_tests {
    use super::*;
    use crate::crypto;

    // Index an already validated economic transition without claiming that this
    // unit test found a high-difficulty proof. The real-PoW production tests
    // exercise zero-issuance blocks through Chain separately.
    #[test]
    fn production_index_separates_physical_work_and_whole_atom_rewards() {
        let mut c = Config::testnet();
        c.test_work = false;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("production-index.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        let parent = chain.tip_state();
        let miner = crypto::public_key(&[93; 32]).unwrap();
        let quantum = Amount::from(crate::config::WORK_PER_ATOM);
        let target = (Amount::from(1u32) << 256usize) / (&quantum * 3u32 + &quantum / 2u32);
        for bits in [c.initial_bits, math::bits_from_target(&target)] {
            let raw_work = math::work(&math::target_from_bits(bits).unwrap());
            let atoms = &raw_work / &quantum;
            let mut block = chain.tip_block().clone();
            block.height = 1;
            block.header.previous = chain.tip_hash();
            block.header.bits = bits;
            block.miner = miner;
            let post =
                consensus::execute(&c, parent, &block.header.previous, &miner, &raw_work, &[])
                    .unwrap();
            block.state_root = post.root();
            block.header.merkle_root = codec::merkle_root(&block).unwrap();
            let db = index.db.as_mut().unwrap();
            let transaction = db.transaction().unwrap();
            assert_eq!(
                index_block(&transaction, &c, &block, Some(parent))
                    .unwrap()
                    .root(),
                post.root()
            );
            let row: String = transaction
                .query_row(
                    "SELECT record FROM explorer_blocks WHERE hash=?1",
                    [hex::encode(codec::block_hash(&block))],
                    |row| row.get(0),
                )
                .unwrap();
            let record: Value = serde_json::from_str(&row).unwrap();
            assert_eq!(record["expected_hashes"], raw_work.to_str_radix(10));
            assert_eq!(record["subsidy"], atoms.to_str_radix(10));
            assert_eq!(record["rewards"]["miner_total"], atoms.to_str_radix(10));
            assert_eq!(post.issued, atoms);
            // Consensus credits no zero reward, so history records none.
            let rewards: u64 = transaction
                .query_row(
                    "SELECT COUNT(*) FROM explorer_events WHERE block_hash=?1",
                    [hex::encode(codec::block_hash(&block))],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(rewards, u64::from(!atoms.is_zero()));
            transaction.rollback().unwrap();
        }
    }

    #[test]
    fn index_records_actual_partial_fills_and_retains_signed_request() {
        let c = Config::testnet();
        let secret = [91; 32];
        let owner = crypto::public_key(&secret).unwrap();
        let other = crypto::public_key(&[92; 32]).unwrap();
        let mut parent = State::genesis(&c);
        for (key, shares) in [(owner, 100u32), (other, 900)] {
            parent
                .world
                .put(
                    key,
                    Account {
                        ordinary: 1000u32.into(),
                        shares: &c.share_scale * shares,
                        ..Account::default()
                    },
                    &c,
                )
                .unwrap();
        }
        parent.world.reserve = 1000u32.into();
        parent.world.curve_mass = 5000u32.into();
        parent.world.shares = &c.share_scale * 1000u32;
        parent.issued = 3000u32.into();
        parent.height = 1;
        let tx = crypto::sign(
            &parent.chain_id,
            &TransactionBody {
                sender: owner,
                nonce: 0,
                fee: 1u32.into(),
                anchor: [38; 32],
                expiry_blocks: 3,
                operation: Operation::Redeem {
                    shares: &c.share_scale * 100u32,
                    decision: None,
                    outcome: None,
                },
                data: Vec::new(),
            },
            &secret,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("partial-fill.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut block = chain.tip_block().clone();
        block.height = parent.height + 1;
        block.header.previous = [41; 32];
        block.miner = owner;
        block.transactions = vec![tx.clone()];
        let subsidy = math::work(&math::target_from_bits(block.header.bits).unwrap());
        let (post, fills) = consensus::execute_with_fills(
            &c,
            &parent,
            &block.header.previous,
            &owner,
            &subsidy,
            &block.transactions,
        )
        .unwrap();
        let fill = &fills[0];
        assert!(!fill.input_filled.is_zero());
        assert!(!fill.input_unfilled.is_zero());
        block.state_root = post.root();
        block.header.merkle_root = codec::merkle_root(&block).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        let db = index.db.as_mut().unwrap();
        let transaction = db.transaction().unwrap();
        assert_eq!(
            index_block(&transaction, &c, &block, Some(&parent))
                .unwrap()
                .root(),
            post.root()
        );
        transaction.commit().unwrap();
        let row: String = db
            .query_row(
                "SELECT record FROM explorer_transactions WHERE txid=?1",
                [hex::encode(codec::transaction_id(&tx))],
                |row| row.get(0),
            )
            .unwrap();
        let record: Value = serde_json::from_str(&row).unwrap();
        assert_eq!(record["fill_status"], "partial");
        assert_eq!(record["amount"], fill.input_filled.to_str_radix(10));
        assert_eq!(
            record["input_requested"],
            fill.input_requested.to_str_radix(10)
        );
        assert_eq!(
            record["operation"]["Redeem"]["shares"],
            fill.input_requested.to_str_radix(10)
        );
        assert_eq!(
            record["input_unfilled"],
            fill.input_unfilled.to_str_radix(10)
        );
        assert_eq!(record["output"], fill.output.to_str_radix(10));
        let row: String = db
            .query_row(
                "SELECT record FROM explorer_events WHERE position=0",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let event: Value = serde_json::from_str(&row).unwrap();
        assert_eq!(event["input_filled"], record["input_filled"]);
        assert_eq!(event["output"], record["output"]);
    }

    #[test]
    fn decision_history_counts_final_parent_quote_once_and_requires_majority() {
        let c = Config::testnet();
        let mut state = State::genesis(&c);
        state.height = 7;
        state.world.reserve = 100u32.into();
        state.world.curve_mass = 100u32.into();
        state.world.shares = 100u32.into();
        let mut pass = state.world.clone();
        pass.curve_mass = 110u32.into();
        state.alternative = Some(pass);
        state.phase = Phase::Governance(crate::state::Decision {
            id: [1; 32],
            epoch: 1,
            round: 1,
            proposal_id: [2; 32],
            proposal: Proposal::Parameter {
                parameter: Parameter::Lead,
                old: 1,
                new: 2,
            }
            .into(),
            started: 5,
            started_height: 5,
            blocks: 3,
            leading_blocks: 1,
        });
        let live = decision_record(&c, &state, None).unwrap();
        assert_eq!(live["observed_blocks"], 2);
        assert_eq!(live["leading_blocks"], 1);
        assert_eq!(live["blocks_remaining"], 1);
        assert!(live["outcome"].is_null());
        let ended = decision_record(&c, &state, Some(8)).unwrap();
        assert_eq!(ended["leading_blocks"], 2);
        assert_eq!(ended["observed_blocks"], 3);
        assert_eq!(ended["outcome"], "pass");
        // Presentation precision must not discard a real price lead when both
        // display quotes round to zero.
        let tiny_price_supply = &c.quote_scale * 1000u32;
        state.world.shares = tiny_price_supply.clone();
        state.alternative.as_mut().unwrap().shares = tiny_price_supply;
        assert!(state.world.quote(&c).is_zero());
        assert!(state.alternative.as_ref().unwrap().quote(&c).is_zero());
        let tiny = decision_record(&c, &state, Some(8)).unwrap();
        assert_eq!(tiny["leading_blocks"], 2);
        assert_eq!(tiny["outcome"], "pass");
        state.height = 8;
        if let Phase::Governance(decision) = &mut state.phase {
            decision.blocks = 4;
        }
        let tied = decision_record(&c, &state, Some(9)).unwrap();
        assert_eq!(tied["leading_blocks"], 2);
        assert_eq!(tied["outcome"], "fail");
    }

    #[test]
    fn account_history_continues_after_large_block_event_positions() {
        let mut c = Config::testnet();
        c.max_signatures = 100_000;
        c.validate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-event-positions.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let index = Explorer::open(&path, &chain).unwrap();
        let key = crypto::public_key(&[91; 32]).unwrap();
        let address = address::encode(&key, &c.chain_id()).unwrap();
        let hash = hex::encode(chain.tip_hash());
        // Three projection rows suffice to reproduce the public continuation
        // bug. These are valid event ordinals from the existing indexing rules;
        // producing thousands of signed transactions would test nothing extra.
        let positions = [
            c.max_signatures as u64 * 4 + 12 + 31_000,
            25_001 * 4 + 10,
            0,
        ];
        for position in positions {
            let record = json!({"height":0,"kind":"mining_reward","position":position});
            index.db.as_ref().unwrap().execute(
                "INSERT INTO explorer_events(address,block_hash,height,position,record) VALUES(?1,?2,0,?3,?4)",
                params![address, hash, position, record.to_string()],
            ).unwrap();
        }
        let query = |params| {
            index.rpc(
                "explorer_account",
                params,
                &c,
                chain.tip_state(),
                chain.tip_hash(),
                &[],
            )
        };
        let mut params = json!({"address":address,"limit":1});
        for position in positions {
            let page = query(params.clone()).unwrap();
            assert_eq!(page["history"].as_array().unwrap().len(), 1);
            assert_eq!(page["history"][0]["position"], position);
            params["before"] = page["next_cursor"].clone();
        }
        assert!(
            query(params).unwrap()["history"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        for cursor in ["0:9223372036854775808", "0:18446744073709551615", "0:-1"] {
            assert!(query(json!({"address":address,"before":cursor})).is_err());
        }
    }

    #[test]
    fn block_transaction_pages_continue_past_default_signature_count() {
        let mut c = Config::testnet();
        c.max_signatures = 8192;
        c.validate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large-block-offsets.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let index = Explorer::open(&path, &chain).unwrap();
        let db = index.db.as_ref().unwrap();
        let hash = hex::encode(chain.tip_hash());
        // Isolate historical block pagination from execution. The current
        // governed block capacity need not still fit this historical block.
        db.execute(
            "UPDATE explorer_blocks SET record=json_set(record,'$.transaction_count',4098) WHERE hash=?1",
            [&hash],
        ).unwrap();
        for position in [4096, 4097] {
            let record = json!({"height":0,"position":position,"status":"confirmed"});
            db.execute(
                "INSERT INTO explorer_transactions(txid,block_hash,height,position,record) VALUES(?1,?2,0,?3,?4)",
                params![format!("{position:064x}"),hash,position,record.to_string()],
            ).unwrap();
        }
        let query = |offset| {
            index.rpc(
                "explorer_block",
                json!({"hash":hash,"limit":1,"tx_offset":offset}),
                &c,
                chain.tip_state(),
                chain.tip_hash(),
                &[],
            )
        };
        let first = query(4096).unwrap();
        assert_eq!(first["transactions"][0]["position"], 4096);
        let second = query(first["next_tx_offset"].as_u64().unwrap()).unwrap();
        assert_eq!(second["transactions"][0]["position"], 4097);
        assert!(second["next_tx_offset"].is_null());
        assert!(
            query(4098).unwrap()["transactions"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(query(4099).is_err());
    }

    #[test]
    fn account_projection_preserves_each_outcome_and_common_payment_capacity() {
        for c in [Config::devnet(), Config::devnet()] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("account-view.sqlite");
            let chain = Chain::open(&path, c.clone()).unwrap();
            let index = Explorer::open(&path, &chain).unwrap();
            let key = crypto::public_key(&[91; 32]).unwrap();
            // Isolated account-view fixtures; no blocks or transactions are submitted.
            let mut state = State::genesis(&c);
            state
                .world
                .put(
                    key,
                    Account {
                        ordinary: 900u32.into(),
                        ..Account::default()
                    },
                    &c,
                )
                .unwrap();
            let query = |s: &State, key: &PublicKey| {
                index
                    .rpc(
                        "explorer_account",
                        json!({"address":address::encode(key,&c.chain_id()).unwrap()}),
                        &c,
                        s,
                        chain.tip_hash(),
                        &[],
                    )
                    .unwrap()
            };
            let single = query(&state, &key);
            assert_eq!(single["payment_available_hash"], "900");
            assert!(single["pass_account"].is_null());
            let mut pass = state.world.clone();
            pass.put(
                key,
                Account {
                    ordinary: 250u32.into(),
                    ..Account::default()
                },
                &c,
            )
            .unwrap();
            state.alternative = Some(pass);
            let split = query(&state, &key);
            assert_eq!(split["account"]["ordinary"], "900");
            assert_eq!(split["pass_account"]["ordinary"], "250");
            assert!(split["account"]["conditional"].is_null());
            assert!(split["pass_account"]["conditional"].is_null());
            assert_eq!(split["payment_available_hash"], "250");
            state
                .world
                .put(
                    key,
                    Account {
                        ordinary: 100u32.into(),
                        ..Account::default()
                    },
                    &c,
                )
                .unwrap();
            assert_eq!(query(&state, &key)["payment_available_hash"], "100");
            state.world.revenue = 37u32.into();
            assert_eq!(state.world.revenue, Amount::from(37u32));
            state.world = state.alternative.take().unwrap();
            let settled = query(&state, &key);
            assert_eq!(settled["account"]["ordinary"], "250");
            assert_eq!(settled["payment_available_hash"], "250");
            assert!(settled["pass_account"].is_null());
            let absent = query(&state, &crypto::public_key(&[92; 32]).unwrap());
            assert!(absent["account"].is_null());
            assert_eq!(absent["payment_available_hash"], "0");
        }
    }

    fn rows(index: &Explorer) -> Vec<(String, Vec<String>)> {
        let db = index.db.as_ref().unwrap();
        [
            "explorer_meta",
            "explorer_blocks",
            "explorer_transactions",
            "explorer_transaction_data",
            "explorer_events",
            "explorer_proposals",
            "explorer_contributions",
            "explorer_decisions",
            "explorer_chat",
            "explorer_mail",
        ]
        .into_iter()
        .map(|table| {
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let columns = statement.column_count();
            let mut values = statement
                .query_map([], |row| {
                    (0..columns)
                        .map(|column| row.get::<_, rusqlite::types::Value>(column))
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map(|values| format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            values.sort();
            (table.to_owned(), values)
        })
        .collect()
    }

    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn one_pass_index_preserves_fees_and_rolls_back_failed_commitments() {
        let c = Config::testnet();
        let secret = [91; 32];
        let owner = crypto::public_key(&secret).unwrap();
        let recipient = crypto::public_key(&[92; 32]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("single-pass.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        // A synthetic funded parent exercises indexing without mining a block.
        let parent = Arc::new(
            consensus::execute(
                &c,
                chain.tip_state(),
                &chain.tip_hash(),
                &owner,
                &Amount::from(10_000_000_000_000u64),
                &[],
            )
            .unwrap(),
        );
        let parent_hash = [41; 32];
        index.tip = Some(parent_hash);
        index.states = VecDeque::from([(parent_hash, parent.clone())]);
        let chain_id = parent.chain_id;
        let make = |nonce, extra: u32| {
            crypto::sign(
                &chain_id,
                &TransactionBody {
                    sender: owner,
                    nonce,
                    fee: Amount::from(1_000_000u32 + extra),
                    anchor: [38; 32],
                    expiry_blocks: 100,
                    operation: Operation::TransferExact {
                        recipient,
                        amount: 100u32.into(),
                    },
                    data: Vec::new(),
                },
                &secret,
            )
            .unwrap()
        };
        let transactions = vec![make(0, 7u32), make(1, 11u32)];
        let raw_work = math::work(&math::target_from_bits(chain.tip_block().header.bits).unwrap());
        let mut expected = consensus::prepare_block(&c, &parent, &owner, &raw_work).unwrap();
        let mut quotes = Vec::new();
        for tx in &transactions {
            quotes.push(fees::quote(&c, &expected.state, tx).unwrap());
            expected.apply_verified_transaction(&c, tx).unwrap();
        }
        assert_eq!(quotes[0].weight - quotes[1].weight, fees::ACCOUNT_WEIGHT);
        let mut block = chain.tip_block().clone();
        block.height = parent.height + 1;
        block.header.previous = parent_hash;
        block.miner = owner;
        block.transactions = transactions;
        let subsidy = math::work(&math::target_from_bits(block.header.bits).unwrap());
        let post = consensus::execute(
            &c,
            &parent,
            &parent_hash,
            &owner,
            &subsidy,
            &block.transactions,
        )
        .unwrap();
        block.state_root = post.root();
        block.header.merkle_root = codec::merkle_root(&block).unwrap();

        let before = rows(&index);
        let mut wrong_root = block.clone();
        wrong_root.state_root[0] ^= 1;
        wrong_root.header.merkle_root = codec::merkle_root(&wrong_root).unwrap();
        let error = index
            .apply_update(&c, Update::Advance(Box::new(wrong_root)))
            .unwrap_err();
        assert!(error.to_string().contains("commitment mismatch"));
        assert_eq!(rows(&index), before, "all partially derived rows roll back");
        assert_eq!(index.tip, Some(parent_hash));
        assert_eq!(index.states.len(), 1);
        assert_eq!(index.states.back().unwrap().1.root(), parent.root());

        index
            .apply_update(&c, Update::Advance(Box::new(block.clone())))
            .unwrap();
        assert_eq!(index.states.back().unwrap().1.root(), post.root());
        let hash = codec::block_hash(&block);
        let db = index.db.as_ref().unwrap();
        for (tx, quote) in block.transactions.iter().zip(&quotes) {
            let record: String = db
                .query_row(
                    "SELECT record FROM explorer_transactions WHERE txid=?1 AND block_hash=?2",
                    params![hex::encode(codec::transaction_id(tx)), hex::encode(hash)],
                    |row| row.get(0),
                )
                .unwrap();
            let value: Value = serde_json::from_str(&record).unwrap();
            assert_eq!(value["fee"], quote.fee.to_str_radix(10));
            assert!(value.get("max_fee").is_none());
            assert_eq!(value["minimum_fee"], quote.minimum_fee.to_str_radix(10));
        }
        let record: String = db
            .query_row(
                "SELECT record FROM explorer_blocks WHERE hash=?1",
                [hex::encode(hash)],
                |row| row.get(0),
            )
            .unwrap();
        let value: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(
            value["rewards"]["miner_fees"],
            (&quotes[0].miner_fee + &quotes[1].miner_fee).to_str_radix(10)
        );
        assert_eq!(
            value["rewards"]["revenue_fees"],
            (&quotes[0].revenue_fee + &quotes[1].revenue_fee).to_str_radix(10)
        );
        let applied = rows(&index);
        index
            .apply_update(&c, Update::Rollback(parent_hash, parent))
            .unwrap();
        index
            .apply_update(&c, Update::Advance(Box::new(block)))
            .unwrap();
        assert_eq!(
            rows(&index),
            applied,
            "reapplication restores every indexed row"
        );
    }

    #[test]
    fn supports_after_their_record_in_one_block_are_indexed_without_record_weight() {
        // Consensus quotes each transaction against the running block state:
        // a support for a record written earlier in the block (by its
        // proposal or another support) pays no record weight. The index used
        // to quote it against the block's opening state, overstating its
        // minimum fee and the block's mandatory fees.
        let mut c = Config::testnet();
        c.initial.rest = 0;
        c.test_work = false;
        let secret = [94; 32];
        let owner = crypto::public_key(&secret).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("support-weight.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        let mut parent = State::genesis(&c);
        parent
            .world
            .put(
                owner,
                Account {
                    ordinary: 1_000_000u32.into(),
                    ..Account::default()
                },
                &c,
            )
            .unwrap();
        parent.issued = 1_000_000u32.into();
        parent.height = 1;
        assert_eq!(parent.auction_round(), Some(0));
        let parent_hash = [42; 32];
        let mut block = chain.tip_block().clone();
        block.height = 2;
        block.header.previous = parent_hash;
        block.miner = owner;
        let work = math::work(&math::target_from_bits(block.header.bits).unwrap());
        let proposal = Proposal::Parameter {
            parameter: Parameter::MinimumFeeRate,
            old: 1,
            new: 2,
        };
        let description = [7; 32];
        let id = crate::state::proposal_id(&parent.chain_id, 0, &owner, &description, &proposal);
        let mut execution = consensus::prepare_block(&c, &parent, &owner, &work).unwrap();
        let mut quotes = Vec::new();
        for (nonce, operation) in [
            Operation::Propose {
                round: 0,
                description,
                proposal,
                support: 5u32.into(),
            },
            Operation::Support {
                round: 0,
                proposal: id,
                amount: 3u32.into(),
            },
            Operation::Support {
                round: 0,
                proposal: id,
                amount: 2u32.into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            // Each pays exactly the minimum consensus charges it.
            let mut body = TransactionBody {
                sender: owner,
                nonce: nonce as u64,
                fee: Amount::zero(),
                anchor: [38; 32],
                expiry_blocks: 100,
                operation,
                data: Vec::new(),
            };
            let quote = loop {
                let unsigned = Transaction {
                    body: body.clone(),
                    signature: [0; 64],
                };
                let quote = fees::quote(&c, &execution.state, &unsigned).unwrap();
                if quote.minimum_fee == body.fee {
                    break quote;
                }
                body.fee = quote.minimum_fee.clone();
            };
            let tx = crypto::sign(&parent.chain_id, &body, &secret).unwrap();
            execution.apply_verified_transaction(&c, &tx).unwrap();
            quotes.push(quote);
            block.transactions.push(tx);
        }
        // Only the proposal writes its proposer's support record.
        assert!(!quotes[0].record_fee.is_zero());
        assert!(quotes[1..].iter().all(|quote| quote.record_fee.is_zero()));
        let post = consensus::execute(
            &c,
            &parent,
            &parent_hash,
            &owner,
            &work,
            &block.transactions,
        )
        .unwrap();
        block.state_root = post.root();
        block.header.merkle_root = codec::merkle_root(&block).unwrap();
        let db = index.db.as_mut().unwrap();
        let transaction = db.transaction().unwrap();
        index_block(&transaction, &c, &block, Some(&parent)).unwrap();
        let record = |sql: &str, key: String| -> Value {
            let text: String = transaction.query_row(sql, [key], |row| row.get(0)).unwrap();
            serde_json::from_str(&text).unwrap()
        };
        for (tx, quote) in block.transactions.iter().zip(&quotes) {
            let value = record(
                "SELECT record FROM explorer_transactions WHERE txid=?1",
                hex::encode(codec::transaction_id(tx)),
            );
            assert_eq!(value["minimum_fee"], quote.minimum_fee.to_str_radix(10));
            assert_eq!(value["extra_fee"], "0");
        }
        let summary = record(
            "SELECT record FROM explorer_blocks WHERE hash=?1",
            hex::encode(codec::block_hash(&block)),
        );
        let mandatory = quotes
            .iter()
            .fold(Amount::zero(), |sum, quote| sum + &quote.minimum_fee);
        assert_eq!(
            summary["rewards"]["minimum_fees"],
            mandatory.to_str_radix(10)
        );
        assert_eq!(summary["rewards"]["extra_fees"], "0");
        drop(transaction);
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;
    use crate::crypto;

    fn extend(chain: &mut Chain, salt: u64) -> Block {
        let miner = crypto::public_key(&[91; 32]).unwrap();
        let mut block = chain
            .template(miner, vec![], chain.tip_block().header.timestamp + 15)
            .unwrap();
        block.extranonce = salt.to_le_bytes();
        block.header.merkle_root = codec::merkle_root(&block).unwrap();
        let block = Chain::mine(block, 100_000).unwrap();
        chain
            .submit(block.clone(), block.header.timestamp as u64)
            .unwrap();
        block
    }
    /// Run the background worker's capture/apply loop to completion.
    fn drain(index: &mut Explorer, chain: &Chain) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        while let Some(update) = index.capture(chain).unwrap() {
            kinds.push(match update {
                Update::Genesis(_) => "genesis",
                Update::Advance(_) => "advance",
                Update::Replay(_) => "replay",
                Update::Rollback(..) => "rollback",
                Update::Rebuild(..) => "rebuild",
            });
            index.apply_update(&chain.config, update).unwrap();
        }
        kinds
    }
    fn canonical_blocks(index: &Explorer) -> u64 {
        index
            .db
            .as_ref()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM explorer_blocks WHERE canonical=1",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn restarted_index_rolls_back_a_shallow_reorg_to_its_fork() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::devnet();
        let path = dir.path().join("restart.sqlite");
        let mut main = Chain::open(&path, c.clone()).unwrap();
        for salt in 0..5 {
            extend(&mut main, salt);
        }
        drop(Explorer::open(&path, &main).unwrap());
        let shared: Vec<_> = (1..=4)
            .map(|height| main.block(&main.hash_at_height(height).unwrap()).unwrap())
            .collect();
        drop(main);
        // A restarted node has no worker memory, but its chain retains the
        // recent states the explorer seeds as checkpoints without replay.
        let mut main = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &main).unwrap();
        assert_eq!(index.states.len(), 6);
        let mut fork = Chain::open(&dir.path().join("fork.sqlite"), c.clone()).unwrap();
        for block in shared {
            fork.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        for salt in 100..102 {
            let block = extend(&mut fork, salt);
            main.submit(block.clone(), block.header.timestamp as u64)
                .unwrap();
        }
        assert_eq!(main.tip_hash(), fork.tip_hash());
        let update = index.capture(&main).unwrap().unwrap();
        let Update::Rollback(hash, state) = &update else {
            panic!("a one-block reorg must not rebuild from genesis");
        };
        assert_eq!((*hash, state.height), (main.hash_at_height(4).unwrap(), 4));
        index.apply_update(&c, update).unwrap();
        assert_eq!(drain(&mut index, &main), ["advance", "advance"]);
        assert_eq!(index.tip, Some(main.tip_hash()));
        assert_eq!(canonical_blocks(&index), 7);
    }

    #[test]
    fn long_catch_up_commits_progress_and_replays_without_rewriting_rows() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::devnet();
        let path = dir.path().join("catch-up.sqlite");
        let mut chain = Chain::open(&path, c.clone()).unwrap();
        for salt in 0..(CHECKPOINTS as u64 + 12) {
            extend(&mut chain, salt);
        }
        // Enabling the explorer on a long chain indexes only genesis before
        // startup returns; the worker continues one committed block at a time.
        let mut index = Explorer::open(&path, &chain).unwrap();
        assert_eq!(index.tip, chain.hash_at_height(0));
        let error = index
            .rpc(
                "explorer_blocks",
                json!({}),
                &c,
                chain.tip_state(),
                chain.tip_hash(),
                &[],
            )
            .unwrap_err();
        assert!(error.to_string().contains("updating"));
        for _ in 0..5 {
            let update = index.capture(&chain).unwrap().unwrap();
            assert!(matches!(update, Update::Advance(_)));
            index.apply_update(&c, update).unwrap();
        }
        let db = index.db.as_ref().unwrap();
        db.execute(
            "UPDATE explorer_blocks SET record=json_set(record,'$.kept',1) WHERE height=3",
            [],
        )
        .unwrap();
        drop(index);
        drop(chain);
        // After a restart the chain no longer retains height 5's state: the
        // index keeps its committed rows and re-executes them only to rebuild
        // checkpoints, never through an unbudgeted chain state replay.
        let chain = Chain::open(&path, c.clone()).unwrap();
        assert!(
            chain
                .cached_state(&chain.hash_at_height(5).unwrap())
                .is_none()
        );
        let mut index = Explorer::open(&path, &chain).unwrap();
        assert_eq!(index.tip, chain.hash_at_height(5));
        assert_eq!(index.states.len(), 1);
        let kinds = drain(&mut index, &chain);
        assert_eq!(kinds[..5], ["replay"; 5]);
        assert!(kinds[5..].iter().all(|kind| *kind == "advance"));
        assert_eq!(kinds.len() as u64, chain.tip_height());
        assert_eq!(index.tip, Some(chain.tip_hash()));
        assert_eq!(canonical_blocks(&index), chain.tip_height() + 1);
        let kept: Option<u64> = index
            .db
            .as_ref()
            .unwrap()
            .query_row(
                "SELECT json_extract(record,'$.kept') FROM explorer_blocks WHERE height=3",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(kept, Some(1));
        assert_eq!(index.states.len(), CHECKPOINTS);
        drop(index);
        drop(chain);
        // A lag covered by retained states finishes before startup returns.
        let mut chain = Chain::open(&path, c.clone()).unwrap();
        extend(&mut chain, 999);
        let index = Explorer::open(&path, &chain).unwrap();
        assert_eq!(index.tip, Some(chain.tip_hash()));
        assert!(
            index
                .rpc(
                    "explorer_blocks",
                    json!({}),
                    &c,
                    chain.tip_state(),
                    chain.tip_hash(),
                    &[],
                )
                .is_ok()
        );
    }

    #[test]
    fn failed_update_waits_for_the_next_canonical_tip() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::devnet();
        let path = dir.path().join("backoff.sqlite");
        let mut chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        extend(&mut chain, 0);
        // A refused row stands in for a block this index cannot store.
        let refuse =
            |index: &Explorer, sql: &str| index.db.as_ref().unwrap().execute_batch(sql).unwrap();
        refuse(
            &index,
            "CREATE TEMP TRIGGER refuse BEFORE INSERT ON explorer_blocks BEGIN SELECT RAISE(ABORT,'refused'); END;",
        );
        let update = index.capture(&chain).unwrap().unwrap();
        assert!(index.apply_update(&c, update).is_err());
        // Mempool and template notifications for the same tip neither load
        // nor re-execute the failed block until its retry time.
        assert!(index.capture(&chain).unwrap().is_none());
        index.failed.as_mut().unwrap().1 = Instant::now();
        let update = index.capture(&chain).unwrap().unwrap();
        assert!(matches!(update, Update::Advance(_)));
        assert!(index.apply_update(&c, update).is_err());
        assert!(index.capture(&chain).unwrap().is_none());
        refuse(&index, "DROP TRIGGER refuse");
        extend(&mut chain, 1);
        assert_eq!(drain(&mut index, &chain), ["advance", "advance"]);
        assert_eq!(index.tip, Some(chain.tip_hash()));
        // Lock contention is transient: the next notification retries it.
        extend(&mut chain, 2);
        let writer = Connection::open(path.with_extension("explorer.sqlite")).unwrap();
        writer.execute_batch("BEGIN IMMEDIATE").unwrap();
        let update = index.capture(&chain).unwrap().unwrap();
        let error = index.apply_update(&c, update).unwrap_err();
        assert!(contended(&error), "{error:#}");
        writer.execute_batch("ROLLBACK").unwrap();
        assert!(index.failed.is_none());
        assert_eq!(drain(&mut index, &chain), ["advance"]);
        assert_eq!(index.tip, Some(chain.tip_hash()));
    }

    #[test]
    fn a_failed_startup_keeps_the_index_for_its_worker() {
        // Startup used to return the error of any failed setup or catch-up
        // step, and the node then replaced the index with an unavailable one
        // that nothing reopened: a transient failure, such as a full disk,
        // froze the explorer, mail and chat until a manual restart. The
        // failing step is now retried like any failed worker update.
        let dir = tempfile::tempdir().unwrap();
        let c = Config::devnet();
        // (index name, blocks indexed before the restart, failing apply call,
        // the updates that then finish the work)
        for (name, indexed, failing, expected) in [
            ("catch-up", 3, 2, vec!["advance"; 10]),
            ("rebuild", 3, 1, [vec!["rebuild"], vec!["advance"; 10]].concat()),
            (
                "genesis",
                0,
                1,
                [vec!["genesis", "rebuild"], vec!["advance"; 13]].concat(),
            ),
        ] {
            let path = dir.path().join(format!("{name}.sqlite"));
            let mut chain = Chain::open(&path, c.clone()).unwrap();
            for salt in 0..3 {
                extend(&mut chain, salt);
            }
            if indexed > 0 {
                drop(Explorer::open(&path, &chain).unwrap());
            }
            for salt in 3..13 {
                extend(&mut chain, salt);
            }
            let mut index = Explorer::connect(&path, &chain).unwrap();
            let mut calls = 0;
            index.hooks.before_apply = Some(Box::new(move || {
                calls += 1;
                ensure!(calls != failing, "injected explorer failure");
                Ok(())
            }));
            index.sync(&chain);
            let before = (indexed > 0).then(|| chain.hash_at_height(indexed).unwrap());
            assert_eq!(index.tip, before, "{name}");
            assert!(index.retry_at().is_some(), "{name}");
            // The worker waits for the retry time, then finishes the work.
            assert!(index.capture(&chain).unwrap().is_none(), "{name}");
            index.failed.as_mut().unwrap().1 = Instant::now();
            assert_eq!(drain(&mut index, &chain), expected, "{name}");
            assert_eq!(index.tip, Some(chain.tip_hash()), "{name}");
            assert_eq!(canonical_blocks(&index), chain.tip_height() + 1);
            assert!(
                index
                    .rpc(
                        "explorer_blocks",
                        json!({}),
                        &c,
                        chain.tip_state(),
                        chain.tip_hash(),
                        &[],
                    )
                    .is_ok(),
                "{name}"
            );
        }
    }

    #[test]
    fn far_behind_index_resumes_from_the_nearest_chain_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let c = Config::devnet();
        let path = dir.path().join("far-behind.sqlite");
        let mut chain = Chain::open(&path, c.clone()).unwrap();
        for salt in 0..700 {
            extend(&mut chain, salt);
        }
        let mut index = Explorer::open(&path, &chain).unwrap();
        drain(&mut index, &chain);
        assert_eq!(index.tip, chain.hash_at_height(700));
        drop(index);
        for salt in 700..1800 {
            extend(&mut chain, salt);
        }
        // 1,100 blocks behind, no state within 128 blocks of the indexed tip
        // is retained, but the chain keeps sparse checkpoints far below it.
        assert!((573..=700).all(|height| {
            chain
                .cached_state(&chain.hash_at_height(height).unwrap())
                .is_none()
        }));
        let mut index = Explorer::open(&path, &chain).unwrap();
        assert_eq!(index.tip, chain.hash_at_height(700));
        let (hash, state) = index.states.back().unwrap();
        assert_eq!(
            (Some(*hash), state.height),
            (chain.hash_at_height(512), 512)
        );
        let kinds = drain(&mut index, &chain);
        assert_eq!(kinds[..188], ["replay"; 188]);
        assert!(kinds[188..].iter().all(|kind| *kind == "advance"));
        assert_eq!(kinds.len(), 1288);
        assert_eq!(index.tip, Some(chain.tip_hash()));
        assert_eq!(canonical_blocks(&index), 1801);
    }

    #[test]
    fn detaching_rows_searches_height_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plans.sqlite");
        let chain = Chain::open(&path, Config::devnet()).unwrap();
        let index = Explorer::open(&path, &chain).unwrap();
        let db = index.db.as_ref().unwrap();
        for table in TABLES {
            let plan = db
                .prepare(&format!(
                    "EXPLAIN QUERY PLAN UPDATE {table} SET canonical=0 WHERE canonical=1 AND height>?1"
                ))
                .unwrap()
                .query_map([0], |row| row.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            assert!(
                plan.iter()
                    .any(|step| step.starts_with(&format!("SEARCH {table} USING"))),
                "{table}: {plan:?}"
            );
            if table == "explorer_events" {
                assert!(
                    plan.iter()
                        .any(|step| step.contains("explorer_current_event_height")),
                    "{plan:?}"
                );
            }
        }
    }

    #[test]
    fn one_budget_spans_every_section_of_a_response() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE items(record TEXT,height INTEGER,position INTEGER)")
            .unwrap();
        for height in 1..=3 {
            let record = json!({"height":height,"text":"x".repeat(200)}).to_string();
            db.execute("INSERT INTO items VALUES(?1,?2,0)", params![record, height])
                .unwrap();
        }
        let mut query = db.prepare("SELECT record,height,position FROM items WHERE height<?1 ORDER BY height DESC LIMIT 50").unwrap();
        let mut budget = Budget::with_bytes(300);
        let (first, cursor) = paged(&mut query, [4], 50, 3, &mut budget).unwrap();
        assert_eq!((first.len(), cursor), (1, json!("3:0")));
        // A later section of the same response always returns its first record.
        let (second, cursor) = paged(&mut query, [4], 50, 3, &mut budget).unwrap();
        assert_eq!((second.len(), cursor), (1, json!("3:0")));
        let rows = pending([json!("a"), json!("b")].into_iter().map(Ok), &mut budget).unwrap();
        assert_eq!(rows, json!(["a"]));
        // Parsed JSON values are bounded together with text bytes.
        let mut budget = Budget {
            bytes: PAGE_BYTES,
            values: 6,
        };
        let rows = pending(
            [json!([1, 2]), json!([3, 4]), json!([5, 6])]
                .into_iter()
                .map(Ok),
            &mut budget,
        )
        .unwrap();
        assert_eq!(rows, json!([[1, 2], [3, 4]]));
    }

    #[test]
    fn transaction_cursors_follow_the_configured_signature_limit() {
        let mut c = Config::testnet();
        c.max_signatures = 200_000;
        c.validate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("positions.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let index = Explorer::open(&path, &chain).unwrap();
        let query = |method, params| {
            index.rpc(method, params, &c, chain.tip_state(), chain.tip_hash(), &[])
        };
        for (method, field) in [
            ("explorer_transactions", "before"),
            ("explorer_chat", "cursor"),
            ("explorer_governance", "before"),
            ("explorer_governance", "proposal_before"),
        ] {
            for (cursor, valid) in [("1:150000", true), ("1:200000", true), ("1:200001", false)] {
                let mut params = serde_json::Map::new();
                params.insert(field.into(), json!(cursor));
                assert_eq!(
                    query(method, Value::Object(params)).is_ok(),
                    valid,
                    "{method} {field} {cursor}"
                );
            }
        }
        let anchor = hex::encode(chain.tip_hash());
        for (after, valid) in [
            ("0:150000", true),
            ("0:200001", false),
            ("0:9223372036854775807", true),
        ] {
            assert_eq!(
                query("explorer_mail", json!({"after":after,"anchor":anchor})).is_ok(),
                valid,
                "{after}"
            );
        }
    }
}

#[cfg(test)]
mod chat_tests {
    use super::*;
    use crate::crypto;
    #[test]
    fn non_payment_text_has_operation_metadata_without_a_required_amount() {
        let c = Config::testnet();
        let s = State::genesis(&c);
        let key = crypto::public_key(&[91; 32]).unwrap();
        for (operation, expected_kind, expected_amount, expected_asset) in [
            (
                Operation::Refund {
                    round: 0,
                    proposal: [1; 32],
                },
                "refund",
                Value::Null,
                Value::Null,
            ),
            (
                Operation::Deposit {
                    amount: 1u32.into(),
                    decision: None,
                    outcome: None,
                },
                "deposit",
                json!("1"),
                json!("hash"),
            ),
            (
                Operation::Redeem {
                    shares: 2u32.into(),
                    decision: None,
                    outcome: None,
                },
                "redeem",
                json!("2"),
                json!("stash"),
            ),
        ] {
            let tx = Transaction {
                body: TransactionBody {
                    sender: key,
                    nonce: 0,
                    fee: 10u32.into(),
                    anchor: [38; 32],
                    expiry_blocks: 100,
                    operation,
                    data: b"An ordinary signed note".to_vec(),
                },
                signature: [0; 64],
            };
            // Classification receives already validated transactions from its caller.
            let value = chat_value(&s, &tx, Some(1), Some([2; 32]), Some(3)).unwrap();
            assert_eq!(value["kind"], expected_kind);
            assert_eq!(value["amount"], expected_amount);
            assert_eq!(value["asset"], expected_asset);
            assert!(value["recipient"].is_null());
            assert_eq!(value["height"], 1);
            assert_eq!(value["position"], 3);
            assert_eq!(value["sender"], address::encode(&key, &s.chain_id).unwrap());
        }
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn encrypted_mail_includes_public_payments_and_is_reorg_safe() {
        let c = Config::testnet();
        let secret = [91; 32];
        let owner = crypto::public_key(&secret).unwrap();
        let other = crypto::public_key(&[92; 32]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mail.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        let funded = consensus::execute(
            &c,
            chain.tip_state(),
            &chain.tip_hash(),
            &owner,
            &Amount::from(10_000_000_000_000u64),
            &[],
        )
        .unwrap();
        let parent = Arc::new(
            consensus::execute(
                &c,
                &funded,
                &[41; 32],
                &other,
                &Amount::from(10_000_000_000_000u64),
                &[],
            )
            .unwrap(),
        );
        let parent_hash = [42; 32];
        index.tip = Some(parent_hash);
        index.states = VecDeque::from([(parent_hash, parent.clone())]);
        let chain_id = parent.chain_id;
        let make = |nonce, data| {
            crypto::sign(
                &chain_id,
                &TransactionBody {
                    sender: owner,
                    nonce,
                    fee: 1_000_000u64.into(),
                    anchor: [38; 32],
                    expiry_blocks: 100,
                    operation: Operation::TransferExact {
                        recipient: if nonce == 0 { other } else { owner },
                        amount: 100u32.into(),
                    },
                    data,
                },
                &secret,
            )
            .unwrap()
        };
        let payment = make(0, crate::mail::tests::fixture());
        let first = make(1, crate::mail::tests::fixture());
        let second = make(2, crate::mail::tests::fixture());
        let invalid = make(3, b"hashstash.mail/2\n{}".to_vec());
        let mut block = chain.tip_block().clone();
        block.height = parent.height + 1;
        block.header.previous = parent_hash;
        block.miner = owner;
        block.transactions = vec![payment.clone(), first.clone(), second.clone(), invalid];
        let post = consensus::execute(
            &c,
            &parent,
            &parent_hash,
            &owner,
            &math::work(&math::target_from_bits(block.header.bits).unwrap()),
            &block.transactions,
        )
        .unwrap();
        block.state_root = post.root();
        index
            .apply_update(&c, Update::Advance(Box::new(block.clone())))
            .unwrap();
        let tip = codec::block_hash(&block);
        let feed = index
            .rpc("explorer_mail", json!({"limit":1}), &c, &post, tip, &[])
            .unwrap();
        assert_eq!(
            feed["messages"][0]["txid"],
            hex::encode(codec::transaction_id(&payment))
        );
        assert_eq!(feed["messages"][0]["nonce"], "0");
        assert_eq!(feed["messages"][0]["confirmations"], 1);
        assert_eq!(feed["messages"][0]["sender_public_key"], hex::encode(owner));
        assert_eq!(feed["messages"][0]["kind"], "transfer");
        assert_eq!(
            feed["messages"][0]["operation"]["TransferExact"]["recipient"],
            json!(other)
        );
        assert_eq!(
            feed["messages"][0]["operation"]["TransferExact"]["amount"],
            "100"
        );
        for field in ["recipient", "recipient_public_key", "address", "pending"] {
            assert!(feed.get(field).is_none());
            assert!(feed["messages"][0].get(field).is_none());
        }
        let next = index
            .rpc(
                "explorer_mail",
                json!({"after":feed["next_cursor"],"anchor":feed["anchor"],"limit":2}),
                &c,
                &post,
                tip,
                &[],
            )
            .unwrap();
        assert_eq!(next["messages"][0]["nonce"], "1");
        assert_eq!(next["messages"][1]["nonce"], "2");
        assert_eq!(next["has_more"], false);
        assert!(next["next_cursor"].is_null());
        assert_eq!(next["scan_cursor"], format!("{}:{}", post.height, i64::MAX));
        let all = index
            .rpc(
                "explorer_mail",
                json!({}),
                &c,
                &post,
                tip,
                &[first.clone(), second],
            )
            .unwrap();
        assert_eq!(all["messages"].as_array().unwrap().len(), 3);
        let empty = index
            .rpc(
                "explorer_mail",
                json!({"after":next["scan_cursor"],"anchor":next["anchor"]}),
                &c,
                &post,
                tip,
                &[],
            )
            .unwrap();
        assert!(empty["messages"].as_array().unwrap().is_empty());
        index
            .apply_update(&c, Update::Rollback(parent_hash, parent.clone()))
            .unwrap();
        let error = index
            .rpc(
                "explorer_mail",
                json!({"after":next["scan_cursor"],"anchor":next["anchor"]}),
                &c,
                &parent,
                parent_hash,
                &[],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Mail scan anchor is no longer canonical")
        );
        let rolled = index
            .rpc(
                "explorer_mail",
                json!({}),
                &c,
                &parent,
                parent_hash,
                &[first],
            )
            .unwrap();
        assert!(rolled["messages"].as_array().unwrap().is_empty());
        assert!(rolled.get("pending").is_none());
        index
            .apply_update(&c, Update::Advance(Box::new(block)))
            .unwrap();
        assert_eq!(
            Explorer::read(
                &path.with_extension("explorer.sqlite"),
                "explorer_mail",
                json!({}),
                &c,
                &post,
                tip,
                post.root(),
                &[]
            )
            .unwrap()["messages"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        for bad in [
            json!({"address":address::encode(&owner,&c.chain_id()).unwrap()}),
            json!({"limit":51}),
            json!({"limit":0}),
            json!({"limit":"1"}),
            json!({"after":"0:0"}),
            json!({"anchor":hex::encode(tip)}),
            json!({"after":"invalid","anchor":hex::encode(tip)}),
            json!({"after":"0:0","anchor":"invalid"}),
            json!({"after":"0:0","anchor":"11".repeat(32)}),
            json!({"after":"999:0","anchor":hex::encode(tip)}),
            json!({"after":"0:100001","anchor":hex::encode(tip)}),
            json!({"after":"0:18446744073709551615","anchor":hex::encode(tip)}),
            json!({"after":"+0:0","anchor":hex::encode(tip)}),
            json!({"before":"1:0"}),
            json!({"unknown":true}),
        ] {
            assert!(
                index
                    .rpc("explorer_mail", bad.clone(), &c, &post, tip, &[])
                    .is_err(),
                "accepted {bad}"
            );
        }
    }
    #[test]
    #[cfg_attr(
        not(feature = "test-fixtures"),
        ignore = "requires explicit test-fixtures funding"
    )]
    fn transaction_text_indexes_pending_paginates_and_follows_reorgs() {
        // Synthetic funded state exercises derived indexing and transaction
        // execution; it never mines or contacts any running chain.
        let c = Config::testnet();
        let secret = [91; 32];
        let owner = crypto::public_key(&secret).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("isolated.sqlite");
        let chain = Chain::open(&path, c.clone()).unwrap();
        let mut index = Explorer::open(&path, &chain).unwrap();
        let parent = Arc::new(
            consensus::execute(
                &c,
                chain.tip_state(),
                &chain.tip_hash(),
                &owner,
                &Amount::from(10_000_000_000_000u64),
                &[],
            )
            .unwrap(),
        );
        parent.audit(&c).unwrap();
        let parent_hash = [41; 32];
        index.tip = Some(parent_hash);
        index.states = VecDeque::from([(parent_hash, parent.clone())]);
        let chain_id = parent.chain_id;
        let make = |nonce, text: &str, amount| {
            crypto::sign(
                &chain_id,
                &TransactionBody {
                    sender: owner,
                    nonce,
                    fee: 1_000_000u64.into(),
                    anchor: [38; 32],
                    expiry_blocks: 100,
                    operation: Operation::TransferExact {
                        recipient: crypto::public_key(&[6; 32]).unwrap(),
                        amount: Amount::from(amount),
                    },
                    data: text.as_bytes().to_vec(),
                },
                &secret,
            )
            .unwrap()
        };
        let first = make(0, "<script>plain text 🌱</script>", 1u32);
        let second = make(1, "second", 1u32);
        let blank = make(2, " \t\r\n", 1u32);
        let mut block = chain.tip_block().clone();
        block.height = parent.height + 1;
        block.header.previous = parent_hash;
        block.miner = owner;
        block.transactions = vec![first.clone(), second.clone(), blank];
        let subsidy = math::work(&math::target_from_bits(block.header.bits).unwrap());
        let post = consensus::execute(
            &c,
            &parent,
            &parent_hash,
            &owner,
            &subsidy,
            &block.transactions,
        )
        .unwrap();
        block.state_root = post.root();
        index
            .apply_update(&c, Update::Advance(Box::new(block.clone())))
            .unwrap();
        let tip = codec::block_hash(&block);
        // Text is stored once, as raw transaction bytes; the chat projection
        // keeps no second, JSON-escaped copy of it.
        let db = index.db.as_ref().unwrap();
        let (kind, length): (String, usize) = db
            .query_row(
                "SELECT typeof(data),length(data) FROM explorer_transaction_data WHERE txid=?1",
                [hex::encode(codec::transaction_id(&first))],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((kind.as_str(), length), ("blob", first.body.data.len()));
        // Data never shares a row with the bounded transaction record.
        let shared: u64 = db
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('explorer_transactions') WHERE name='data'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(shared, 0);
        let stored: String = db
            .query_row(
                "SELECT record FROM explorer_chat WHERE txid=?1",
                [hex::encode(codec::transaction_id(&first))],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            serde_json::from_str::<Value>(&stored)
                .unwrap()
                .get("text")
                .is_none()
        );
        let feed = index
            .rpc("explorer_chat", json!({"limit":1}), &c, &post, tip, &[])
            .unwrap();
        assert_eq!(
            feed["items"][0]["txid"],
            hex::encode(codec::transaction_id(&second))
        );
        assert_eq!(feed["items"][0]["position"], 1);
        assert_eq!(feed["items"][0]["confirmations"], 1);
        assert_eq!(feed["items"][0]["amount"], "1");
        assert_eq!(feed["items"][0]["kind"], "transfer");
        assert_eq!(feed["items"][0]["asset"], "hash");
        let page = index
            .rpc(
                "explorer_chat",
                json!({"cursor":feed["next_cursor"],"limit":1}),
                &c,
                &post,
                tip,
                &[],
            )
            .unwrap();
        assert_eq!(page["items"][0]["text"], "<script>plain text 🌱</script>");
        assert_eq!(
            index
                .rpc("explorer_chat", json!({}), &c, &post, tip, &[])
                .unwrap()["items"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        index
            .apply_update(&c, Update::Rollback(parent_hash, parent.clone()))
            .unwrap();
        let rolled = index
            .rpc(
                "explorer_chat",
                json!({}),
                &c,
                &parent,
                parent_hash,
                std::slice::from_ref(&first),
            )
            .unwrap();
        assert!(rolled["items"].as_array().unwrap().is_empty());
        assert_eq!(rolled["pending"][0]["status"], "pending");
        assert!(rolled["pending"][0]["height"].is_null());
        index
            .apply_update(&c, Update::Advance(Box::new(block)))
            .unwrap();
        let loaded = Explorer::read(
            &path.with_extension("explorer.sqlite"),
            "explorer_chat",
            json!({}),
            &c,
            &post,
            tip,
            post.root(),
            &[],
        )
        .unwrap();
        assert_eq!(loaded["items"].as_array().unwrap().len(), 2);
        for p in [
            json!({"limit":51}),
            json!({"cursor":"garbage"}),
            json!({"unknown":true}),
        ] {
            assert!(index.rpc("explorer_chat", p, &c, &post, tip, &[]).is_err());
        }
        assert!(post.world.revenue > Amount::zero());
    }
}
