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
use std::{collections::VecDeque, path::Path, sync::Arc};

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
const SCHEMA: &str = "24-address-only";
pub const MAX_PAGE: u64 = 50;

pub struct Explorer {
    db: Option<Connection>,
    tip: Option<Hash>,
    ready: bool,
    states: VecDeque<(Hash, Arc<State>)>,
}
/// One already validated canonical block, or a cached rollback anchor. Capturing
/// this performs no state replay and no derived-index writes under the node lock.
pub(crate) enum Update {
    Advance(Box<Block>),
    Rollback(Hash, Arc<State>),
}
impl Explorer {
    pub fn unavailable() -> Self {
        Self {
            db: None,
            tip: None,
            ready: false,
            states: VecDeque::new(),
        }
    }
    pub fn read(
        path: &Path,
        method: &str,
        p: Value,
        c: &Config,
        s: &State,
        tip: Hash,
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
            ready: true,
            states: VecDeque::new(),
        };
        reader.rpc(method, p, c, s, tip, mempool)
    }
    pub fn open(path: &Path, chain: &Chain) -> Result<Self> {
        let db = Connection::open(path.with_extension("explorer.sqlite"))?;
        db.busy_timeout(std::time::Duration::from_millis(500))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
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
            db.execute_batch("DROP TABLE IF EXISTS explorer_chat;DROP TABLE IF EXISTS explorer_blocks;DROP TABLE IF EXISTS explorer_transactions;DROP TABLE IF EXISTS explorer_events;DROP TABLE IF EXISTS explorer_proposals;DROP TABLE IF EXISTS explorer_contributions;DROP TABLE IF EXISTS explorer_decisions;DELETE FROM explorer_meta;")?;
            db.execute("INSERT INTO explorer_meta VALUES('chain',?1)", [identity])?;
            db.execute("INSERT INTO explorer_meta VALUES('schema',?1)", [SCHEMA])?;
        }
        db.execute_batch("CREATE TABLE IF NOT EXISTS explorer_mail(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));CREATE INDEX IF NOT EXISTS explorer_mail_page ON explorer_mail(height,position) WHERE canonical=1;
            CREATE TABLE IF NOT EXISTS explorer_chat(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));CREATE INDEX IF NOT EXISTS explorer_chat_page ON explorer_chat(height DESC,position DESC) WHERE canonical=1;CREATE TABLE IF NOT EXISTS explorer_blocks(hash TEXT PRIMARY KEY,height INTEGER NOT NULL,canonical INTEGER NOT NULL,record TEXT NOT NULL);
            CREATE UNIQUE INDEX IF NOT EXISTS explorer_height ON explorer_blocks(height) WHERE canonical=1;
            CREATE TABLE IF NOT EXISTS explorer_transactions(txid TEXT NOT NULL,block_hash TEXT NOT NULL,height INTEGER NOT NULL,position INTEGER NOT NULL,record TEXT NOT NULL,data TEXT NOT NULL,canonical INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(txid,block_hash));
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
        let mut index = Self {
            db: Some(db),
            tip: tip.and_then(|v| parse_hash(&v).ok()),
            ready: false,
            states: VecDeque::new(),
        };
        index.sync(chain)?;
        index
            .states
            .push_back((chain.tip_hash(), Arc::new(chain.tip_state().clone())));
        Ok(index)
    }

    pub(crate) fn capture(&self, chain: &Chain) -> Result<Option<Update>> {
        if self.db.is_none() || self.tip == Some(chain.tip_hash()) {
            return Ok(None);
        }
        let (tip, state) = self
            .states
            .back()
            .context("missing explorer checkpoint state")?;
        if chain.hash_at_height(state.height) != Some(*tip) {
            if let Some((hash, state)) = self
                .states
                .iter()
                .rev()
                .find(|(hash, state)| chain.hash_at_height(state.height) == Some(*hash))
            {
                return Ok(Some(Update::Rollback(*hash, state.clone())));
            }
            // A deep reorg replays from genesis on the worker, never through the
            // node's cache/state_at path while holding its mutation lock.
            return Ok(Some(Update::Rollback(
                chain.hash_at_height(0).context("missing genesis")?,
                Arc::new(State::genesis(&chain.config)),
            )));
        }
        let hash = chain
            .hash_at_height(state.height + 1)
            .context("missing canonical successor")?;
        let block = if hash == chain.tip_hash() {
            chain.tip_block().clone()
        } else {
            chain
                .block(&hash)
                .context("missing stored canonical block")?
        };
        Ok(Some(Update::Advance(Box::new(block))))
    }

    pub(crate) fn apply_update(&mut self, c: &Config, update: Update) -> Result<()> {
        let db = self.db.as_mut().context("explorer index unavailable")?;
        match update {
            Update::Rollback(hash, state) => {
                let transaction = db.transaction()?;
                for table in [
                    "explorer_blocks",
                    "explorer_transactions",
                    "explorer_events",
                    "explorer_proposals",
                    "explorer_contributions",
                    "explorer_decisions",
                    "explorer_chat",
                    "explorer_mail",
                ] {
                    transaction.execute(
                        &format!("UPDATE {table} SET canonical=0 WHERE canonical=1 AND height>?1"),
                        [state.height],
                    )?;
                }
                transaction.execute(
                    "INSERT OR REPLACE INTO explorer_meta VALUES('tip',?1)",
                    [hex::encode(hash)],
                )?;
                transaction.commit()?;
                self.tip = Some(hash);
                while self
                    .states
                    .back()
                    .is_some_and(|(_, saved)| saved.height >= state.height)
                {
                    self.states.pop_back();
                }
                self.states.push_back((hash, state));
            }
            Update::Advance(block) => {
                let (tip, parent) = self
                    .states
                    .back()
                    .context("missing explorer checkpoint state")?;
                ensure!(
                    block.header.previous == *tip && block.height == parent.height + 1,
                    "explorer successor mismatch"
                );
                let transaction = db.transaction()?;
                let post = Arc::new(index_block(&transaction, c, &block, Some(parent))?);
                let hash = codec::block_hash(&block);
                transaction.execute(
                    "INSERT OR REPLACE INTO explorer_meta VALUES('tip',?1)",
                    [hex::encode(hash)],
                )?;
                transaction.commit()?;
                self.tip = Some(hash);
                self.states.push_back((hash, post));
                while self.states.len() > 128 {
                    self.states.pop_front();
                }
            }
        }
        Ok(())
    }

    pub fn sync(&mut self, chain: &Chain) -> Result<()> {
        if self.ready && self.tip == Some(chain.tip_hash()) {
            return Ok(());
        }
        self.ready = false;
        let db = self.db.as_mut().context("explorer index unavailable")?;
        let last:Option<(u64,String)>=db.query_row("SELECT height,hash FROM explorer_blocks WHERE canonical=1 ORDER BY height DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let mut common = last.map(|(h, _)| h.min(chain.tip_height()));
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
        let mut parent = common
            .map(|height| {
                let hash = chain
                    .hash_at_height(height)
                    .context("missing common ancestor")?;
                chain
                    .state_at(&hash)
                    .context("missing common ancestor state")
            })
            .transpose()?;
        let transaction = db.transaction()?;
        match common {
            Some(h) => {
                transaction.execute(
                    "UPDATE explorer_blocks SET canonical=0 WHERE canonical=1 AND height>?1",
                    [h],
                )?;
            }
            None => {
                transaction.execute(
                    "UPDATE explorer_blocks SET canonical=0 WHERE canonical=1",
                    [],
                )?;
            }
        }
        for table in [
            "explorer_transactions",
            "explorer_events",
            "explorer_proposals",
            "explorer_contributions",
            "explorer_decisions",
            "explorer_chat",
            "explorer_mail",
        ] {
            match common {
                Some(h) => {
                    transaction.execute(
                        &format!("UPDATE {table} SET canonical=0 WHERE canonical=1 AND height>?1"),
                        [h],
                    )?;
                }
                None => {
                    transaction.execute(
                        &format!("UPDATE {table} SET canonical=0 WHERE canonical=1"),
                        [],
                    )?;
                }
            }
        }
        for height in common.map_or(0, |h| h + 1)..=chain.tip_height() {
            let hash = chain
                .hash_at_height(height)
                .context("missing canonical height")?;
            let block = chain.block(&hash).context("missing canonical block")?;
            parent = Some(Arc::new(index_block(
                &transaction,
                &chain.config,
                &block,
                parent.as_deref(),
            )?));
        }
        transaction.execute(
            "INSERT OR REPLACE INTO explorer_meta VALUES('tip',?1)",
            [hex::encode(chain.tip_hash())],
        )?;
        transaction.commit()?;
        self.tip = Some(chain.tip_hash());
        self.ready = true;
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
        let mut result = json!({"chain_id":hex::encode(s.chain_id),"tip":hex::encode(tip),"height":s.height,"state_root":hex::encode(s.root())});
        match method {
            "explorer_mail" => {
                fields(&p, &["limit", "after", "anchor"])?;
                let anchor = scan_anchor(db, &p, "after", "Mail")?;
                let (h, n) = scan_after(&p, anchor)?;
                let mut statement=db.prepare("SELECT t.record,t.height,t.position FROM explorer_mail t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height>?1 OR(t.height=?1 AND t.position>?2)) ORDER BY t.height,t.position LIMIT ?3")?;
                let (items, next) =
                    paged_more(&mut statement, params![h, n, limit + 1], limit, s.height)?;
                result["messages"] = json!(items);
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
                let (h, n) = cursor_named(&p, "cursor", s.height)?;
                let mut statement = db.prepare("SELECT t.record,t.height,t.position FROM explorer_chat t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height<?1 OR (t.height=?1 AND t.position<?2)) ORDER BY t.height DESC,t.position DESC LIMIT ?3")?;
                let (items, next) = paged(&mut statement, params![h, n, limit], limit, s.height)?;
                result["items"] = json!(items);
                result["next_cursor"] = next;
                result["pending"] = json!(
                    mempool
                        .iter()
                        .rev()
                        .filter_map(|t| chat_value(c, s, t, None, None, None))
                        .take(limit as usize)
                        .collect::<Vec<_>>()
                );
                result["available"] = json!(true);
                result["ready"] = json!(true);
                result["indexed_height"] = json!(s.height);
                result["message_bytes"] = json!(crate::config::MAX_BLOCK_RECORD_BYTES);
            }
            "explorer_blocks" => {
                fields(&p, &["limit", "before_height"])?;
                let before =
                    height_parameter(&p, "before_height")?.unwrap_or(s.height.saturating_add(1));
                let mut statement=db.prepare("SELECT record FROM explorer_blocks WHERE canonical=1 AND height<?1 ORDER BY height DESC LIMIT ?2")?;
                let blocks = statement
                    .query_map(params![before, limit], |r| r.get::<_, String>(0))?
                    .map(|r| Ok(serde_json::from_str::<Value>(&r?)?))
                    .collect::<Result<Vec<_>>>()?;
                result["next_before_height"] = blocks
                    .last()
                    .filter(|_| blocks.len() == limit as usize)
                    .map(|b| b["height"].clone())
                    .unwrap_or(Value::Null);
                result["blocks"] = json!(blocks);
            }
            "explorer_transactions" => {
                fields(&p, &["limit", "before"])?;
                let (h, n) = cursor(&p, s.height)?;
                let mut statement=db.prepare("SELECT t.record,t.height,t.position FROM explorer_transactions t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.canonical=1 AND b.canonical=1 AND (t.height<?1 OR (t.height=?1 AND t.position<?2)) ORDER BY t.height DESC,t.position DESC LIMIT ?3")?;
                let (items, next) = paged(&mut statement, params![h, n, limit], limit, s.height)?;
                let mut items = items;
                for value in &mut items {
                    settlement(db, value)?;
                }
                result["transactions"] = json!(items);
                result["next_cursor"] = next;
                result["pending"] = json!(
                    mempool
                        .iter()
                        .take(limit as usize)
                        .map(|t| tx_value(c, s, t, None, None, None))
                        .collect::<Result<Vec<_>>>()?
                );
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
                    result["transactions"] = json!(transactions);
                } else {
                    bail!("unknown block");
                }
            }
            "explorer_transaction" => {
                fields(&p, &["txid", "limit"])?;
                let id = hex::encode(parse_hash(string(&p, "txid")?)?);
                let row:Option<(String,String,bool)>=db.query_row("SELECT t.record,t.data,b.canonical FROM explorer_transactions t JOIN explorer_blocks b ON b.hash=t.block_hash WHERE t.txid=?1 ORDER BY b.canonical DESC,t.height DESC LIMIT 1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;

                let value = if let Some((record, data, true)) = row.as_ref() {
                    let mut value: Value = serde_json::from_str(record)?;
                    value["data_hex"] = json!(data);
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
                    value["data_hex"] = json!(data);
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
                result["protocol_version"] = json!(c.protocol_version);
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
                )?;
                let mut items = items;
                for value in &mut items {
                    settlement(db, value)?;
                }
                result["history"] = json!(items);
                result["next_cursor"] = next;
                result["pending"] = json!(
                    mempool
                        .iter()
                        .filter(
                            |t| t.body.sender == key || recipient(&t.body.operation) == Some(key)
                        )
                        .take(limit as usize)
                        .map(|t| tx_value(c, s, t, None, None, None))
                        .collect::<Result<Vec<_>>>()?
                );
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
                let (h, n) = cursor(&p, s.height)?;
                let before =
                    height_parameter(&p, "before_height")?.unwrap_or(s.height.saturating_add(1));
                result["phase"] = json!(s.phase_name());
                result["current"] = serde_json::to_value(&s.phase)?;
                let (ph, pn) = cursor_named(&p, "proposal_before", s.height)?;
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
                )?;
                for p in &mut proposals {
                    let id = parse_hash(p["id"].as_str().context("indexed proposal ID")?)?;
                    if let Some(record) = s.proposals.get(&id) {
                        p["support"] = json!(record.support.to_str_radix(10));
                        p["refund_height"] = json!(record.refund_height);
                    }
                }
                result["proposal_next_cursor"] = proposal_next;
                result["proposals"] = json!(proposals);
                let decision_filter = if proposal.is_some() {
                    "(d.proposal=?1 OR d.id=?1)"
                } else {
                    "?1=''"
                };
                let mut statement=db.prepare(&format!("SELECT d.record FROM explorer_decisions d JOIN explorer_blocks b ON b.hash=d.block_hash WHERE d.canonical=1 AND b.canonical=1 AND {decision_filter} AND d.height<?2 ORDER BY d.height DESC LIMIT ?3"))?;
                let mut decisions = statement
                    .query_map(params![proposal_text, before, limit], |r| {
                        r.get::<_, String>(0)
                    })?
                    .map(|r| Ok(serde_json::from_str::<Value>(&r?)?))
                    .collect::<Result<Vec<_>>>()?;
                // The live decision appears only on the first page. With a
                // one-row page its cursor still permits reaching older results.
                if !p.as_object().unwrap().contains_key("before_height")
                    && let Phase::Governance(d) = &s.phase
                    && proposal.is_none_or(|p| p == d.proposal_id || p == d.id)
                {
                    decisions.insert(0, decision_record(c, s, None)?);
                    decisions.truncate(limit as usize);
                }
                result["next_before_height"] = decisions
                    .last()
                    .filter(|_| decisions.len() == limit as usize)
                    .map(|d| {
                        d["ended_height"]
                            .as_u64()
                            .map_or(json!(s.height.saturating_add(1)), |height| json!(height))
                    })
                    .unwrap_or(Value::Null);
                result["decisions"] = json!(decisions);
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
                )?;
                result["contributions"] = json!(items);
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
fn cursor(p: &Value, height: u64) -> Result<(u64, u64)> {
    cursor_named(p, "before", height)
}
fn cursor_named(p: &Value, name: &str, height: u64) -> Result<(u64, u64)> {
    cursor_with_position_limit(p, name, height, 100_000)
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
/// Continuations carry the previous canonical tip so a reorganization cannot
/// silently hide replacement messages below an already consumed cursor.
fn scan_anchor(db: &Connection, p: &Value, cursor: &str, label: &str) -> Result<Option<u64>> {
    ensure!(
        p.get(cursor).is_some() == p.get("anchor").is_some(),
        "{cursor} and anchor must be supplied together"
    );
    let Some(_) = p.get("anchor") else {
        return Ok(None);
    };
    let hash = hex::encode(parse_hash(string(p, "anchor")?)?);
    let height: Option<u64> = db
        .query_row(
            "SELECT height FROM explorer_blocks WHERE hash=?1 AND canonical=1",
            [hash],
            |r| r.get(0),
        )
        .optional()?;
    ensure!(
        height.is_some(),
        "{label} scan anchor is no longer canonical"
    );
    Ok(height)
}
fn scan_after(p: &Value, anchor_height: Option<u64>) -> Result<(i64, i64)> {
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
    ensure!(
        h <= anchor_height.context("missing scan anchor")?
            && h <= u32::MAX as u64
            && (n <= 100_000 || n == i64::MAX as u64),
        "invalid cursor bounds"
    );
    Ok((h as i64, n as i64))
}
fn confirmations(v: &mut Value, tip: u64) {
    if let Some(h) = v["height"].as_u64() {
        v["confirmations"] = json!(tip.saturating_sub(h) + 1);
    }
}
fn paged<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
) -> Result<(Vec<Value>, Value)> {
    paged_with_budget(
        statement,
        p,
        limit,
        tip,
        false,
        crate::config::MAX_BLOCK_RECORD_BYTES,
    )
}
fn paged_more<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
) -> Result<(Vec<Value>, Value)> {
    paged_with_budget(
        statement,
        p,
        limit,
        tip,
        true,
        crate::config::MAX_BLOCK_RECORD_BYTES,
    )
}

fn paged_with_budget<P: rusqlite::Params>(
    statement: &mut rusqlite::Statement<'_>,
    p: P,
    limit: u64,
    tip: u64,
    has_lookahead: bool,
    byte_budget: usize,
) -> Result<(Vec<Value>, Value)> {
    let mut rows = statement.query(p)?;
    let mut items = Vec::new();
    let mut last = None;
    let mut bytes = 0usize;
    while let Some(row) = rows.next()? {
        if items.len() == limit as usize {
            return Ok((items, json!(last)));
        }
        let record: String = row.get(0)?;
        // A single record can expand in JSON. Return it alone rather than
        // silently skipping it; the HTTP response envelope stays bounded too.
        if !items.is_empty() && bytes.saturating_add(record.len()) > byte_budget {
            return Ok((items, json!(last)));
        }
        bytes = bytes.saturating_add(record.len());
        let (h, n): (u64, u64) = (row.get(1)?, row.get(2)?);
        let mut value: Value = serde_json::from_str(&record)?;
        confirmations(&mut value, tip);
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
        let (first, cursor) = paged_with_budget(&mut query, [4], 50, 3, false, 100).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0]["height"], 3);
        assert_eq!(cursor, "3:0");
        let (second, cursor) = paged_with_budget(&mut query, [3], 50, 3, true, 100).unwrap();
        assert_eq!(second[0]["height"], 2);
        assert_eq!(cursor, "2:0");
        let (last, cursor) = paged_with_budget(&mut query, [2], 50, 3, true, 100).unwrap();
        assert_eq!(last[0]["height"], 1);
        assert!(cursor.is_null());
    }

    #[test]
    fn signed_mail_grant_carriers_remain_bounded_and_page_without_losing_raw_bytes() {
        let mut c = Config::testnet();
        c.initial.block_bytes = crate::config::MAX_BLOCK_RECORD_BYTES as u64;
        let s = State::genesis(&c);
        let secret = [91; 32];
        let owner = crate::crypto::public_key(&secret).unwrap();
        let data = crate::mail::tests::fixture();
        // Exercise a near-capacity recipient list with this mail payload,
        // reserving space for transaction/block framing and the miner.
        let count = (crate::config::MAX_BLOCK_RECORD_BYTES - data.len() - 2048)
            / (crate::fees::ACCOUNT_WEIGHT as usize + 34);
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
            chain_id: s.chain_id,
            sender: owner,
            nonce: 0,
            fee: 100_000u32.into(),
            expiry_height: 100,
            operation: Operation::Propose {
                round: 1,
                description: [43; 32],
                proposal: Proposal::Grant { payments },
                support: 1u32.into(),
            },
            data,
        };
        let first = crate::crypto::sign(&body, &secret).unwrap();
        assert!(count > 31_000);
        assert!(
            codec::encode(&first).len() + count * crate::fees::ACCOUNT_WEIGHT as usize + 1024
                <= crate::config::MAX_BLOCK_RECORD_BYTES
        );
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE items(record TEXT,height INTEGER,position INTEGER)")
            .unwrap();
        let mut largest = 0;
        for nonce in 0..3 {
            let mut body = body.clone();
            body.nonce = nonce;
            let transaction = crate::crypto::sign(&body, &secret).unwrap();
            let record = mail_value(
                &c,
                &s,
                &transaction,
                Some(nonce + 1),
                Some([7; 32]),
                Some(0),
            )
            .unwrap()
            .to_string();
            largest = largest.max(record.len());
            assert!(record.len() < crate::config::MAX_BLOCK_RECORD_BYTES);
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
            let (page, cursor) =
                paged_with_budget(&mut query, [previous], 50, 3, true, largest).unwrap();
            assert_eq!(page.len(), 1);
            let transaction =
                crate::wallet::decode_signed(page[0]["raw"].as_str().unwrap()).unwrap();
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
    c: &Config,
    s: &State,
    t: &Transaction,
    height: Option<u64>,
    block: Option<Hash>,
    position: Option<u64>,
) -> Option<Value> {
    let message = crate::chat::from_transaction(c, t)?;
    let operation = t.body.operation.clone();
    let amount = operation_amount(&operation);
    Some(
        json!({"txid":hex::encode(codec::transaction_id(t)),"sender":address::encode(&t.body.sender, &s.chain_id).ok()?,"height":height,"block_hash":block.map(hex::encode),"position":position,"text":message,"kind":kind(&operation),"amount":amount.map(|(value,_)|value.to_str_radix(10)),"asset":amount.map(|(_,asset)|asset),"recipient":recipient(&operation).and_then(|key|address::encode(&key,&s.chain_id).ok()),"status":if height.is_some(){"confirmed"}else{"pending"},"confirmations":0}),
    )
}

fn mail_value(
    c: &Config,
    s: &State,
    t: &Transaction,
    height: Option<u64>,
    block: Option<Hash>,
    position: Option<u64>,
) -> Option<Value> {
    crate::mail::from_transaction(c, t)?;
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
    let mut v = json!({"txid":hex::encode(codec::transaction_id(t)),"status":if height.is_some(){"confirmed"}else{"pending"},"height":height,"block_hash":block.map(hex::encode),"confirmations":0,"sender":address::encode(&t.body.sender,&s.chain_id)?,"sender_public_key":hex::encode(t.body.sender),"nonce":t.body.nonce,"fee":t.body.fee.to_str_radix(10),"minimum_fee":quote.as_ref().map(|q|q.minimum_fee.to_str_radix(10)),"extra_fee":quote.as_ref().map(|q|q.extra_fee.to_str_radix(10)),"expiry_height":t.body.expiry_height,"kind":kind(&operation),"operation":operation,"data_hex":hex::encode(&data[..data.len().min(256)]),"data_bytes":data.len(),"data_truncated":data.len()>256,"size_bytes":codec::encode(t).len()});
    if let Some(recipient) = recipient(&operation) {
        v["recipient"] = json!(address::encode(&recipient, &s.chain_id)?);
    }
    if let Some((amount, asset)) = operation_amount(&operation) {
        v["amount"] = json!(amount.to_str_radix(10));
        v["asset"] = json!(asset);
    }
    conditional_fields(&operation, &mut v);
    Ok(v)
}

fn conditional_fields(operation: &Operation, value: &mut Value) {
    let (decision, outcome) = match operation {
        Operation::Deposit {
            decision, outcome, ..
        }
        | Operation::Redeem {
            decision, outcome, ..
        } => (*decision, *outcome),
        _ => return,
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
    let subsidy = if b.height == 0 {
        Amount::zero()
    } else {
        math::work(&math::target_from_bits(b.header.bits)?)
    };
    let expected = math::work(&math::target_from_bits(b.header.bits)?);
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
    let mut execution = parent
        .map(|p| consensus::prepare_block(c, p, &b.miner))
        .transpose()?;
    for (position, t) in b.transactions.iter().enumerate() {
        let execution = execution.as_mut().context("genesis has transactions")?;
        let quote = fees::quote(c, &execution.state, t)?;
        miner_fees += &quote.miner_fee;
        revenue_fees += &quote.revenue_fee;
        extra_fees += &quote.extra_fee;
        mandatory += &quote.minimum_fee;
        let paid = quote.fee;
        transaction_fees += &paid;
        let value = tx_value(
            c,
            &execution.state,
            t,
            Some(b.height),
            Some(hash),
            Some(paid),
        )?;
        let id = hex::encode(codec::transaction_id(t));
        let operation = t.body.operation.clone();
        db.execute("INSERT OR REPLACE INTO explorer_transactions(txid,block_hash,height,position,record,data) VALUES(?1,?2,?3,?4,?5,?6)",params![id,hash_text,b.height,position as u64,serde_json::to_string(&value)?,hex::encode(&t.body.data)])?;
        if let Some(message) = chat_value(
            c,
            &execution.state,
            t,
            Some(b.height),
            Some(hash),
            Some(position as u64),
        ) {
            db.execute("INSERT OR REPLACE INTO explorer_chat(txid,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)", params![id,hash_text,b.height,position as u64,serde_json::to_string(&message)?])?;
        }
        if let Some(message) = mail_value(
            c,
            &execution.state,
            t,
            Some(b.height),
            Some(hash),
            Some(position as u64),
        ) {
            let record = serde_json::to_string(&message)?;
            db.execute("INSERT OR REPLACE INTO explorer_mail(txid,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![id,hash_text,b.height,position as u64,record])?;
        }
        let mut event = json!({"height":b.height,"block_hash":hash_text,"txid":id,"kind":kind(&operation),"role":"sender","fee":value["fee"],"amount":value.get("amount"),"asset":value.get("asset"),"recipient":value.get("recipient")});
        conditional_fields(&operation, &mut event);
        event_row(
            db,
            &t.body.sender,
            &chain_id,
            &hash_text,
            b.height,
            position as u64 * 4,
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
                position as u64 * 4 + 1,
                &event,
            )?;
        }
        execution.apply_verified_transaction(c, t)?;
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
                    description,
                    proposal,
                ));
                let record = json!({"id":id,"round":round,"description":hex::encode(description),"description_text":crate::proposal_data::from_transaction(t),"action":proposal,"support":support.to_str_radix(10),"created_height":b.height,"creator":value["sender"]});
                db.execute("INSERT OR REPLACE INTO explorer_proposals(id,block_hash,height,position,record) VALUES(?1,?2,?3,?4,?5)",params![id,hash_text,b.height,position as u64,serde_json::to_string(&record)?])?;
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
    let post = if let (Some(parent), Some(execution)) = (parent, execution) {
        consensus::finish_block(c, parent, &b.header.previous, &b.miner, &subsidy, execution)?
    } else {
        State::genesis(c)
    };
    ensure!(
        post.root() == b.state_root,
        "explorer replay commitment mismatch"
    );
    summary["phase"] = json!(post.phase_name());
    summary["rewards"] = json!({"subsidy":subsidy.to_str_radix(10),"transaction_fees":transaction_fees.to_str_radix(10),"extra_fees":extra_fees.to_str_radix(10),"minimum_fees":mandatory.to_str_radix(10),"miner_fees":miner_fees.to_str_radix(10),"revenue_fees":revenue_fees.to_str_radix(10),"miner_total":(&subsidy+&miner_fees).to_str_radix(10),"complete":true});
    if b.height > 0 {
        let event = json!({"height":b.height,"block_hash":hash_text,"kind":"mining_reward","amount":summary["rewards"]["miner_total"],"complete":true,"asset":"hash"});
        event_row(
            db,
            &b.miner,
            &post.chain_id,
            &hash_text,
            b.height,
            b.transactions.len() as u64 * 4 + 10,
            &event,
        )?;
    }
    if let Some(parent) = parent
        && let Phase::Governance(d) = &parent.phase
        && post.decision_id() != Some(d.id)
    {
        let record = decision_record(c, parent, Some(b.height))?;
        if record["outcome"] == "pass"
            && let Proposal::Grant { payments } = &d.proposal
        {
            for (index, payment) in payments.iter().enumerate() {
                let event = json!({"height":b.height,"block_hash":hash_text,"kind":"governance_grant","amount":payment.amount.to_str_radix(10),"asset":"hash","decision":hex::encode(d.id),"proposal":hex::encode(d.proposal_id),"outcome":"pass","payout_index":index});
                event_row(
                    db,
                    &payment.recipient,
                    &post.chain_id,
                    &hash_text,
                    b.height,
                    b.transactions.len() as u64 * 4 + 12 + index as u64,
                    &event,
                )?;
            }
        }
        db.execute("INSERT OR REPLACE INTO explorer_decisions(id,proposal,block_hash,height,record) VALUES(?1,?2,?3,?4,?5)",params![hex::encode(d.id),hex::encode(d.proposal_id),hash_text,b.height,serde_json::to_string(&record)?])?;
    }
    db.execute(
        "INSERT OR REPLACE INTO explorer_blocks VALUES(?1,?2,1,?3)",
        params![hash_text, b.height, serde_json::to_string(&summary)?],
    )?;
    Ok(post)
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
    let end = d.started.saturating_add(d.duration);
    let clock = if ended_height.is_some() {
        s.clock
            .saturating_add(c.progress_increment(&s.settings))
            .min(end)
    } else {
        s.clock.min(end)
    };
    let extra = clock.saturating_sub(s.clock);
    let elapsed = clock.saturating_sub(d.started);
    let pass_integral =
        &pass.price_integral + pass.quote(c) * Amount::from(extra) - &d.start_integral;
    let fail_integral =
        &s.world.price_integral + s.world.quote(c) * Amount::from(extra) - &d.start_integral;
    let margin = s.frozen.pass_margin_bps.unwrap_or(0);
    let funded = match &d.proposal {
        Proposal::Grant { payments } => pass.grant_escrow == c.validate_grant(payments)?,
        _ => true,
    };
    let won = funded && consensus::pass_beats_fail(&pass_integral, &fail_integral, margin);
    let avg = |value: &Amount| {
        let den = &c.quote_scale * Amount::from(elapsed);
        if den.is_zero() {
            Value::Null
        } else {
            json!({"numerator":(value*Amount::from(1_000_000_000_000_000_000u64)).to_str_radix(10),"denominator":den.to_str_radix(10)})
        }
    };
    Ok(
        json!({"id":hex::encode(d.id),"proposal":hex::encode(d.proposal_id),"round":d.round,"started":d.started,"started_height":s.height.checked_sub(s.clock.saturating_sub(d.started) / s.frozen.interval),"time_unit":"seconds","clock_basis":"target_interval","ended_height":ended_height,"outcome":ended_height.map(|_|if won{"pass"}else{"fail"}),"duration":d.duration,"elapsed":elapsed,"pass_integral":pass_integral.to_str_radix(10),"fail_integral":fail_integral.to_str_radix(10),"quote_scale":c.quote_scale.to_str_radix(10),"pass_margin_bps":margin,"funded":funded,"pass_average":avg(&pass_integral),"fail_average":avg(&fail_integral)}),
    )
}

#[cfg(test)]
mod indexing_tests {
    use super::*;
    use crate::crypto;

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
            c.max_signatures as u64 * 4 + 12 + grant_payment_capacity() as u64 - 1,
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
                "INSERT INTO explorer_transactions(txid,block_hash,height,position,record,data) VALUES(?1,?2,0,?3,?4,'')",
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
            assert_eq!(single["protocol_version"], c.protocol_version);
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
        let make = |nonce, extra: u32| {
            crypto::sign(
                &TransactionBody {
                    chain_id: c.chain_id(),
                    sender: owner,
                    nonce,
                    fee: Amount::from(1_000_000u32 + extra),
                    expiry_height: 100,
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
        let mut expected = consensus::prepare_block(&c, &parent, &owner).unwrap();
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
                    min_shares: 0u32.into(),
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
                    min_received: 0u32.into(),
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
                    chain_id: c.chain_id(),
                    sender: key,
                    nonce: 0,
                    fee: 10u32.into(),
                    expiry_height: 100,
                    operation,
                    data: b"An ordinary signed note".to_vec(),
                },
                signature: [0; 64],
            };
            // Classification receives already validated transactions from its caller.
            let value = chat_value(&c, &s, &tx, Some(1), Some([2; 32]), Some(3)).unwrap();
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
        let make = |nonce, data| {
            crypto::sign(
                &TransactionBody {
                    chain_id: c.chain_id(),
                    sender: owner,
                    nonce,
                    fee: 1_000_000u64.into(),
                    expiry_height: 100,
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
        let make = |nonce, text: &str, amount| {
            crypto::sign(
                &TransactionBody {
                    chain_id: c.chain_id(),
                    sender: owner,
                    nonce,
                    fee: 1_000_000u64.into(),
                    expiry_height: 100,
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
