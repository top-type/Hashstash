//! An opt-in dispenser of already mined test funds. It has no consensus privileges.
//! The dedicated signer only authorizes fixed, exact transfers. Signed claims and
//! quotas are committed together before any network submission can take place.
use crate::{address, codec, crypto, fees, types::*, wallet};
use anyhow::{Context, Result, anyhow, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use num_traits::Zero;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, OwnedMutexGuard, Semaphore, oneshot},
    task::JoinHandle,
};
use zeroize::Zeroizing;

/// How far the wall clock may run behind the newest recorded claim before
/// payouts pause instead of stretching existing cooldowns and windows.
const CLOCK_TOLERANCE_SECONDS: i64 = 300;
/// Mining freshness always covers at least this many governed block intervals.
const FRESHNESS_INTERVALS: u64 = 12;
/// Replies other than snapshots are small fixed-shape records.
const RPC_REPLY_BYTES: usize = 4 * 1024 * 1024;
/// Block receipt lookups per refresh while locating a consumed nonce.
const SCAN_BLOCKS_PER_REFRESH: u64 = 64;
/// Reorganized receipts accounted again per refresh.
const RECEIPT_REPAIRS_PER_REFRESH: usize = 8;
/// Concurrent HTTP requests one client network may hold.
const CLIENT_SESSIONS: usize = 4;
/// HTTP connections served at once; further ones are closed unread.
const HTTP_CONNECTIONS: usize = 64;
/// The usual pause between refreshes.
const POLL_INTERVAL: Duration = Duration::from_secs(3);
/// The longest pause a busy node's `Retry-After` can impose between refreshes.
const MAX_POLL_WAIT: Duration = Duration::from_secs(60);
/// The longest `Retry-After` waited out before a refused request is resent
/// once. It fits a claim's 15-second answer deadline with both lookups.
const NODE_RETRY_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetConfig {
    pub bind: SocketAddr,
    pub rpc_url: String,
    pub chain_id: String,
    pub key_file: PathBuf,
    pub database: PathBuf,
    pub origins: Vec<String>,
    pub payout: String,
    pub max_fee: String,
    pub cooldown_seconds: u64,
    #[serde(default = "default_subnet_cooldown")]
    pub subnet_cooldown_seconds: u64,
    #[serde(default = "default_subnet_daily_claims")]
    pub subnet_daily_claims: u64,
    pub hourly_claims: u64,
    pub daily_claims: u64,
    pub lifetime_claims: u64,
    pub recent_block_seconds: u64,
    pub confirmations: u64,
    #[serde(default = "default_expiry_blocks")]
    pub expiry_blocks: u64,
}

fn default_expiry_blocks() -> u64 {
    2
}

fn default_subnet_cooldown() -> u64 {
    60
}

fn default_subnet_daily_claims() -> u64 {
    10
}

impl FaucetConfig {
    fn validate(&self) -> Result<()> {
        ensure!(self.bind.ip().is_loopback(), "faucet must bind to loopback");
        let rpc = reqwest::Url::parse(&self.rpc_url)?;
        ensure!(
            rpc.scheme() == "http"
                && rpc
                    .host_str()
                    .and_then(|v| v.parse::<IpAddr>().ok())
                    .is_some_and(|v| v.is_loopback())
                && rpc.username().is_empty()
                && rpc.password().is_none()
                && rpc.query().is_none()
                && rpc.fragment().is_none(),
            "RPC must be a loopback HTTP endpoint"
        );
        parse_hash(&self.chain_id)?;
        ensure!(
            !self.origins.is_empty() && self.origins.len() <= 16,
            "configure the public website origins"
        );
        for origin in &self.origins {
            let url = reqwest::Url::parse(origin)?;
            ensure!(
                origin.len() <= 256
                    && url.origin().ascii_serialization() == *origin
                    && (url.scheme() == "https"
                        || (url.scheme() == "http"
                            && url
                                .host_str()
                                .and_then(|v| v.parse::<IpAddr>().ok())
                                .is_some_and(|v| v.is_loopback()))),
                "invalid faucet origin"
            );
        }
        ensure!(
            !amount(&self.payout)?.is_zero() && !amount(&self.max_fee)?.is_zero(),
            "payout and fee cap must be positive"
        );
        ensure!(
            self.cooldown_seconds > 0 && self.cooldown_seconds <= 31_536_000,
            "invalid claim cooldown"
        );
        ensure!(
            self.subnet_cooldown_seconds > 0 && self.subnet_cooldown_seconds <= 31_536_000,
            "invalid subnet cooldown"
        );
        ensure!(
            self.subnet_daily_claims > 0 && self.subnet_daily_claims <= 1_000_000,
            "invalid subnet daily allowance"
        );
        ensure!(
            self.hourly_claims > 0
                && self.hourly_claims <= self.daily_claims
                && self.daily_claims <= self.lifetime_claims
                && self.lifetime_claims <= 1_000_000,
            "invalid faucet budgets"
        );
        ensure!(
            (10..=3600).contains(&self.recent_block_seconds),
            "invalid mining freshness window"
        );
        ensure!(
            (1..=100).contains(&self.confirmations) && self.expiry_blocks > 0,
            "invalid confirmation or expiry policy"
        );
        ensure!(
            self.database != self.key_file,
            "database and key paths must differ"
        );
        Ok(())
    }
}

fn amount(value: &str) -> Result<Amount> {
    ensure!(
        !value.is_empty() && value.len() <= 155 && value.bytes().all(|v| v.is_ascii_digit()),
        "invalid decimal amount"
    );
    let result = Amount::parse_bytes(value.as_bytes(), 10).context("invalid amount")?;
    ensure!(result.bits() <= 512, "amount is too large");
    Ok(result)
}

fn snapshot_payment_funds(value: &Value) -> Result<Amount> {
    // New outcome balances can differ. The default account is FAIL and must
    // never be mistaken for the amount an ordinary payment can spend in both.
    amount(value.as_str().context("missing payment balance")?)
}

fn parse_hash(value: &str) -> Result<Hash> {
    ensure!(value.len() == 64, "invalid hash length");
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow!("invalid hash"))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn subnet(value: &str) -> Result<String> {
    let ip: IpAddr = value.parse().context("valid client IP required")?;
    let ip = match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    Ok(match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v) => {
            // Customers commonly receive a /56. One holder must not obtain a
            // separate allowance for every /64 network it can address.
            let o = v.segments();
            format!(
                "{:x}:{:x}:{:x}:{:x}::/56",
                o[0],
                o[1],
                o[2],
                o[3] & 0xff00
            )
        }
    })
}

/// A condition that pauses new claims. Status and the journal report only its
/// fixed category; it clears on the first refresh where it no longer holds.
#[derive(Clone, Copy, Debug)]
struct Fault(&'static str);
impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "faucet paused: {}", self.0)
    }
}
impl std::error::Error for Fault {}

/// The node refused a request on admission grounds, answering HTTP 429 or
/// 503. The request did not run and may be resent after `retry_after`.
#[derive(Clone, Copy, Debug)]
struct NodeBusy {
    retry_after: Option<Duration>,
}
impl std::fmt::Display for NodeBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("node is busy")
    }
}
impl std::error::Error for NodeBusy {}

/// Loads the dedicated signer from a regular, owner-only file and wipes every
/// parsed copy of the secret.
fn read_signer(path: &Path) -> Result<(Zeroizing<[u8; 32]>, PublicKey)> {
    // Read through the one handle that was checked, so a path swapped for a
    // symbolic link or junction in between fails, on Windows too.
    let bytes = crate::local_files::read_private(path, 4096).context("faucet key")?;
    let mut key: Value = serde_json::from_slice(&bytes)?;
    let wiped = |value: Option<Value>| match value {
        Some(Value::String(text)) => Some(Zeroizing::new(text)),
        _ => None,
    };
    let named_secret = key.get("secret").is_some();
    let secret_text = wiped(key.get_mut("secret").map(Value::take));
    let private_text = wiped(key.get_mut("private_key").map(Value::take));
    let encoded = if named_secret {
        secret_text.as_ref()
    } else {
        private_text.as_ref()
    }
    .context("private key missing")?;
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(encoded.as_bytes(), secret.as_mut())
        .map_err(|_| anyhow!("invalid private key"))?;
    let sender = crypto::public_key(&secret)?;
    if let Some(public) = key.get("public").or_else(|| key.get("public_key")) {
        ensure!(
            public.as_str() == Some(hex::encode(sender).as_str()),
            "key file mismatch"
        );
    }
    Ok((secret, sender))
}

#[derive(Debug, Clone)]
struct Claim {
    address: String,
    amount_hashes: String,
    created: i64,
    nonce: u64,
    txid: String,
    raw: String,
    status: String,
    height: u64,
    expiry: u64,
}

fn row_claim(row: &rusqlite::Row<'_>) -> rusqlite::Result<Claim> {
    let amount_hashes: String = row.get(8)?;
    validate_claim_amount(&amount_hashes).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid stored faucet amount",
            )),
        )
    })?;
    Ok(Claim {
        address: row.get(0)?,
        amount_hashes,
        created: row.get(1)?,
        nonce: row.get::<_, String>(2)?.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?,
        txid: row.get(3)?,
        raw: row.get(4)?,
        status: row.get(5)?,
        height: row.get(6)?,
        expiry: row.get(7)?,
    })
}
const CLAIM_COLUMNS: &str = "address,created,nonce,txid,raw,status,height,expiry,amount_hashes";

fn validate_claim_amount(value: &str) -> Result<()> {
    let parsed = amount(value)?;
    ensure!(
        !parsed.is_zero() && parsed.to_str_radix(10) == value,
        "invalid stored faucet amount"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Cooldown {
    retry_after_seconds: u64,
    scope: &'static str,
}
impl std::fmt::Display for Cooldown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Please wait before claiming again")
    }
}
impl std::error::Error for Cooldown {}

fn cooldown(
    db: &Connection,
    c: &FaucetConfig,
    address: &str,
    subnet: &str,
    time: i64,
) -> Result<Option<Cooldown>> {
    let address_created: Option<i64> = db.query_row(
        "SELECT MAX(created) FROM claims WHERE address=?1",
        [address],
        |r| r.get(0),
    )?;
    let subnet_created: Option<i64> = db.query_row(
        "SELECT MAX(created) FROM claims WHERE subnet=?1",
        [subnet],
        |r| r.get(0),
    )?;
    let remaining = |created: Option<i64>, duration: u64| {
        created.map_or(0, |created| {
            created
                .saturating_add(duration as i64)
                .saturating_sub(time)
                .max(0) as u64
        })
    };
    let address_wait = remaining(address_created, c.cooldown_seconds);
    // Each client network also receives only a share of every day's allowance.
    // Its wait ends when enough of its claims have left the 24-hour window.
    let window = time.saturating_sub(86_400);
    let subnet_daily: u64 = db.query_row(
        "SELECT COUNT(*) FROM claims WHERE subnet=?1 AND created>?2",
        params![subnet, window],
        |r| r.get(0),
    )?;
    let daily_wait = if subnet_daily >= c.subnet_daily_claims {
        let leaving: i64 = db.query_row(
            "SELECT created FROM claims WHERE subnet=?1 AND created>?2 ORDER BY created LIMIT 1 OFFSET ?3",
            params![subnet, window, subnet_daily - c.subnet_daily_claims],
            |r| r.get(0),
        )?;
        remaining(Some(leaving), 86_400)
    } else {
        0
    };
    let subnet_wait = remaining(subnet_created, c.subnet_cooldown_seconds).max(daily_wait);
    let wait = address_wait.max(subnet_wait);
    Ok((wait > 0).then_some(Cooldown {
        retry_after_seconds: wait,
        scope: if address_wait >= subnet_wait {
            "address"
        } else {
            "network"
        },
    }))
}

/// The pending claim; at most one exists.
fn pending_claim(db: &Connection) -> Result<Option<Claim>> {
    Ok(db
        .query_row(
            &format!("SELECT {CLAIM_COLUMNS} FROM claims WHERE status='pending'"),
            [],
            row_claim,
        )
        .optional()?)
}

/// The newest claim for `address`.
fn last_claim(db: &Connection, address: &str) -> Result<Option<Claim>> {
    Ok(db.query_row(&format!("SELECT {CLAIM_COLUMNS} FROM claims WHERE address=?1 ORDER BY created DESC,rowid DESC LIMIT 1"), [address], row_claim).optional()?)
}

/// The quota clock. It never moves behind recorded claims; a wall clock far
/// behind them pauses payouts instead of stretching old windows.
fn quota_clock(db: &Connection, wall: i64) -> Result<i64> {
    let latest: Option<i64> = db.query_row("SELECT MAX(created) FROM claims", [], |r| r.get(0))?;
    match latest {
        Some(latest) if latest > wall.saturating_add(CLOCK_TOLERANCE_SECONDS) => {
            Err(Fault("clock_behind_ledger").into())
        }
        Some(latest) => Ok(wall.max(latest)),
        None => Ok(wall),
    }
}

/// Whether the hourly, daily and lifetime allowances admit another claim.
/// `lifetime` is the recorded claim count, kept so status never counts the
/// whole ledger.
fn within_budget(db: &Connection, c: &FaucetConfig, lifetime: u64, time: i64) -> Result<bool> {
    if lifetime >= c.lifetime_claims {
        return Ok(false);
    }
    for (period, cap) in [(3600, c.hourly_claims), (86400, c.daily_claims)] {
        let used: u64 = db.query_row(
            "SELECT COUNT(*) FROM claims WHERE created>=?1",
            [time.saturating_sub(period)],
            |r| r.get(0),
        )?;
        if used >= cap {
            return Ok(false);
        }
    }
    Ok(true)
}

struct Ledger {
    db: Connection,
    /// Every recorded claim, maintained by reservation so status never counts
    /// the whole ledger.
    lifetime: u64,
    /// Reservations since the ledger opened. Claims are the only ledger
    /// writers besides refreshes, and may reserve while a refresh waits for
    /// node lookups; the refresh applies what those found only while this is
    /// unchanged.
    generation: u64,
}
impl Ledger {
    fn open(
        path: &std::path::Path,
        chain: &Hash,
        sender: &PublicKey,
        payout: &str,
    ) -> Result<Self> {
        validate_claim_amount(payout)?;
        let mut db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS claims(address TEXT NOT NULL,subnet TEXT NOT NULL,created INTEGER NOT NULL,nonce TEXT NOT NULL,txid TEXT PRIMARY KEY,raw TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','confirmed','expired')),height INTEGER NOT NULL,expiry INTEGER NOT NULL,receipt_height INTEGER,receipt_hash TEXT);
            CREATE INDEX IF NOT EXISTS claim_address ON claims(address,created);
            CREATE INDEX IF NOT EXISTS claim_subnet ON claims(subnet,created);
            CREATE INDEX IF NOT EXISTS claim_created ON claims(created);
            CREATE INDEX IF NOT EXISTS claim_nonce ON claims(nonce);
            CREATE INDEX IF NOT EXISTS claim_receipt ON claims(receipt_height) WHERE status='confirmed';
            CREATE UNIQUE INDEX IF NOT EXISTS one_pending ON claims(status) WHERE status='pending';")?;
        for (name, value) in [
            ("chain", hex::encode(chain)),
            ("sender", hex::encode(sender)),
        ] {
            tx.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES(?1,?2)",
                params![name, value],
            )?;
            let saved: String =
                tx.query_row("SELECT value FROM meta WHERE key=?1", [name], |r| r.get(0))?;
            ensure!(saved == value, "faucet ledger identity changed");
        }
        let schema: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            schema.as_deref().is_none_or(|v| v == "2"),
            "unsupported faucet ledger schema"
        );
        let has_amount: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('claims') WHERE name='amount_hashes')",
            [],
            |r| r.get(0),
        )?;
        let baseline: Option<String> = tx
            .query_row("SELECT value FROM meta WHERE key='payout'", [], |r| {
                r.get(0)
            })
            .optional()?;
        let baseline = match baseline {
            Some(saved) => saved,
            None => {
                let count: u64 = tx.query_row("SELECT COUNT(*) FROM claims", [], |r| r.get(0))?;
                ensure!(
                    schema.is_none() && count == 0,
                    "missing historical faucet payout"
                );
                tx.execute("INSERT INTO meta(key,value) VALUES('payout',?1)", [payout])?;
                payout.to_owned()
            }
        };
        validate_claim_amount(&baseline)?;
        if schema.is_none() {
            ensure!(!has_amount, "unversioned faucet claim amounts");
            // The old signer only paid the pinned amount. Preserve its original
            // metadata and every claim byte while recording that amount per row.
            tx.execute_batch(
                "ALTER TABLE claims ADD COLUMN amount_hashes TEXT NOT NULL DEFAULT '0'",
            )?;
            tx.execute("UPDATE claims SET amount_hashes=?1", [&baseline])?;
            tx.execute(
                "INSERT INTO meta(key,value) VALUES('schema_version','2')",
                [],
            )?;
        } else {
            ensure!(has_amount, "missing faucet claim amounts");
        }
        {
            let mut query = tx.prepare("SELECT DISTINCT amount_hashes FROM claims")?;
            for saved in query.query_map([], |r| r.get::<_, String>(0))? {
                validate_claim_amount(&saved?)?;
            }
        }
        let lifetime: u64 = tx.query_row("SELECT COUNT(*) FROM claims", [], |r| r.get(0))?;
        tx.commit()?;
        Ok(Self {
            db,
            lifetime,
            generation: 0,
        })
    }
    fn pending(&self) -> Result<Option<Claim>> {
        pending_claim(&self.db)
    }
    fn last(&self, address: &str) -> Result<Option<Claim>> {
        last_claim(&self.db, address)
    }
    /// The newest confirmed claim with its recorded receipt height and hash.
    fn top_receipt(&self) -> Result<Option<(Claim, u64, String)>> {
        Ok(self.db.query_row(&format!("SELECT {CLAIM_COLUMNS},receipt_height,receipt_hash FROM claims WHERE status='confirmed' ORDER BY receipt_height DESC,rowid DESC LIMIT 1"), [], |r| Ok((row_claim(r)?, r.get(9)?, r.get(10)?))).optional()?)
    }
    /// The inclusion window of every claim signed with `nonce` that is not a
    /// confirmed payment.
    fn unsettled(&self, nonce: u64) -> Result<Vec<Window>> {
        let mut query = self.db.prepare(
            "SELECT txid,height,expiry FROM claims WHERE nonce=?1 AND status<>'confirmed' ORDER BY rowid",
        )?;
        let rows = query.query_map([nonce.to_string()], |r| {
            Ok(Window {
                txid: r.get(0)?,
                first: r.get::<_, u64>(1)?.saturating_add(1),
                last: r.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
    fn first_nonce(&self) -> Result<Option<u64>> {
        let nonce: Option<String> = self
            .db
            .query_row("SELECT nonce FROM claims ORDER BY rowid LIMIT 1", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(nonce.map(|v| v.parse()).transpose()?)
    }
    /// Nonces below this were accepted by the operator as spent elsewhere.
    fn nonce_floor(&self) -> Result<Option<u64>> {
        let floor: Option<String> = self
            .db
            .query_row("SELECT value FROM meta WHERE key='nonce_floor'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(floor.map(|v| v.parse()).transpose()?)
    }
    fn expire(&self, txid: &str) -> Result<()> {
        self.db.execute(
            "UPDATE claims SET status='expired' WHERE txid=?1 AND status='pending'",
            [txid],
        )?;
        Ok(())
    }
    fn clock(&self, wall: i64) -> Result<i64> {
        quota_clock(&self.db, wall)
    }
    fn budget(&self, c: &FaucetConfig, time: i64) -> Result<bool> {
        within_budget(&self.db, c, self.lifetime, time)
    }
    fn eligible(&self, c: &FaucetConfig, address: &str, subnet: &str, time: i64) -> Result<()> {
        if let Some(wait) = cooldown(&self.db, c, address, subnet, time)? {
            return Err(wait.into());
        }
        ensure!(self.budget(c, time)?, "Faucet allowance reached");
        Ok(())
    }
    fn reserve(&mut self, c: &FaucetConfig, claim: &Claim, subnet: &str) -> Result<()> {
        validate_claim_amount(&claim.amount_hashes)?;
        ensure!(
            amount(&claim.amount_hashes)? == amount(&c.payout)?,
            "faucet payout changed before reservation"
        );
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(wait) = cooldown(&tx, c, &claim.address, subnet, claim.created)? {
            return Err(wait.into());
        }
        let mut lifetime = 0;
        for (period, cap) in [
            (3600, c.hourly_claims),
            (86400, c.daily_claims),
            (i64::MAX, c.lifetime_claims),
        ] {
            let used: u64 = tx.query_row(
                "SELECT COUNT(*) FROM claims WHERE created>=?1",
                [claim.created.saturating_sub(period)],
                |r| r.get(0),
            )?;
            ensure!(used < cap, "Faucet allowance reached");
            lifetime = used;
        }
        tx.execute("INSERT INTO claims(address,subnet,created,nonce,txid,raw,status,height,expiry,amount_hashes) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9)", params![claim.address,subnet,claim.created,claim.nonce.to_string(),claim.txid,claim.raw,claim.height,claim.expiry,claim.amount_hashes])?;
        tx.commit()?;
        self.lifetime = lifetime + 1;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }
    fn summary(&self, time: i64) -> Result<Value> {
        let count = |status: &str| -> Result<u64> {
            Ok(self.db.query_row(
                "SELECT COUNT(*) FROM claims WHERE status=?1",
                [status],
                |r| r.get(0),
            )?)
        };
        let latest: Option<i64> =
            self.db
                .query_row("SELECT MAX(created) FROM claims", [], |r| r.get(0))?;
        Ok(json!({
            "claims":{"pending":count("pending")?,"confirmed":count("confirmed")?,"expired":count("expired")?},
            "pending":self.pending()?.map(|c| json!({"txid":c.txid,"nonce":c.nonce.to_string(),"anchor_height":c.height,"expiry_height":c.expiry,"created":c.created})),
            "latest_receipt":self.top_receipt()?.map(|(c, height, hash)| json!({"txid":c.txid,"nonce":c.nonce.to_string(),"height":height,"hash":hash})),
            "latest_created":latest,
            "clock":time,
            "nonce_floor":self.nonce_floor()?.map(|v| v.to_string()),
        }))
    }
}

/// Offline maintenance of a stopped faucet's ledger. Every action keeps all
/// claim rows, receipts, address cooldowns and budget usage.
#[derive(Clone, Copy, Debug)]
pub enum Maintenance {
    /// Summarize the ledger without changing it.
    Inspect,
    /// After operator review, record that the faucet key spent this nonce, and
    /// every lower one, outside the ledger. Unpaid claims at those nonces expire.
    AcceptSpentNonce(u64),
    /// After the host clock is verified, move claim times recorded in the future
    /// to the present so their cooldowns and windows restart from now.
    ClampFutureClaims,
}

pub fn maintain(config: &FaucetConfig, action: Maintenance) -> Result<Value> {
    config.validate()?;
    let (_, sender) = read_signer(&config.key_file)?;
    let chain = parse_hash(&config.chain_id)?;
    let payout = amount(&config.payout)?;
    let mut ledger = Ledger::open(&config.database, &chain, &sender, &payout.to_str_radix(10))?;
    let time = now();
    match action {
        Maintenance::Inspect => {}
        Maintenance::AcceptSpentNonce(nonce) => {
            let floor = nonce.checked_add(1).context("nonce exhausted")?;
            let tx = ledger
                .db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let saved: Option<String> = tx
                .query_row("SELECT value FROM meta WHERE key='nonce_floor'", [], |r| {
                    r.get(0)
                })
                .optional()?;
            let floor = floor.max(saved.map(|v| v.parse()).transpose()?.unwrap_or(0));
            let pending: Option<(String, String)> = tx
                .query_row(
                    "SELECT txid,nonce FROM claims WHERE status='pending'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((txid, pending_nonce)) = pending
                && pending_nonce.parse::<u64>()? < floor
            {
                tx.execute("UPDATE claims SET status='expired' WHERE txid=?1", [txid])?;
            }
            tx.execute(
                "INSERT INTO meta(key,value) VALUES('nonce_floor',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [floor.to_string()],
            )?;
            tx.commit()?;
        }
        Maintenance::ClampFutureClaims => {
            ledger
                .db
                .execute("UPDATE claims SET created=?1 WHERE created>?1", [time])?;
        }
    }
    ledger.summary(time)
}

#[derive(Clone, Debug, Serialize)]
struct RefreshErrorStatus {
    category: &'static str,
    consecutive_errors: u32,
    first_at: i64,
    last_at: i64,
}

#[derive(Default)]
struct RefreshDiagnostics {
    error: Option<RefreshErrorStatus>,
    last_log: Option<Instant>,
}

impl RefreshDiagnostics {
    fn record(&mut self, error: &anyhow::Error, timestamp: i64, instant: Instant) -> bool {
        // Fixed categories only. Exception displays can contain URLs, paths,
        // request data or secrets and must never reach status or the journal.
        let category = if let Some(fault) = error.downcast_ref::<Fault>() {
            fault.0
        } else if error.is::<NodeBusy>() {
            // The node is up and asked the faucet to wait, unlike a transport fault.
            "node_busy"
        } else if let Some(e) = error.downcast_ref::<reqwest::Error>() {
            if e.is_timeout() {
                "node_timeout"
            } else if e.is_decode() {
                "invalid_node_response"
            } else {
                "node_transport"
            }
        } else if error.is::<rusqlite::Error>() {
            "ledger"
        } else if error.is::<std::io::Error>() {
            "filesystem"
        } else if error.is::<serde_json::Error>() {
            "invalid_node_response"
        } else {
            "node_response_or_state"
        };
        let previous = self.error.as_ref();
        self.error = Some(RefreshErrorStatus {
            category,
            consecutive_errors: previous.map_or(1, |e| e.consecutive_errors.saturating_add(1)),
            first_at: previous.map_or(timestamp, |e| e.first_at),
            last_at: timestamp,
        });
        let log = self
            .last_log
            .is_none_or(|last| instant.duration_since(last) >= Duration::from_secs(60));
        if log {
            self.last_log = Some(instant);
        }
        log
    }
    fn recovered(&mut self) {
        self.error = None;
    }
}

#[derive(Deserialize)]
struct RpcReply<T> {
    result: Option<T>,
    error: Option<IgnoredAny>,
}

/// The faucet reads only these snapshot fields. Larger governance, proposal
/// and mempool sections are skipped while parsing, never built as JSON trees.
#[derive(Deserialize)]
struct NodeSnapshot {
    status: NodeStatus,
    account: Option<NodeAccount>,
    #[serde(default)]
    payment_available_hash: Value,
}
#[derive(Deserialize)]
struct NodeStatus {
    chain_id: String,
    height: u64,
    tip: String,
    state_root: String,
    settings: NodeSettings,
}
#[derive(Clone, Copy, Debug, Deserialize)]
struct NodeSettings {
    block_bytes: u64,
    minimum_fee_rate: u64,
    interval: u64,
}
#[derive(Deserialize)]
struct NodeAccount {
    account: NodeAccountState,
}
#[derive(Deserialize)]
struct NodeAccountState {
    nonce: u64,
}
#[derive(Deserialize)]
struct BlockReceipt {
    height: u64,
    hash: String,
    included: Vec<bool>,
    #[serde(default)]
    checked_canonical: Option<bool>,
}

/// Calls the loopback node. A request the node refuses on admission grounds
/// did not run, so after a `Retry-After` of at most `NODE_RETRY_WAIT` it is
/// resent once; otherwise the refusal is returned as `NodeBusy`.
async fn node_rpc<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<T> {
    let first = node_rpc_once(client, url, method, &params).await;
    let wait = first
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<NodeBusy>())
        .and_then(|busy| busy.retry_after);
    match wait {
        Some(wait) if wait <= NODE_RETRY_WAIT => {
            tokio::time::sleep(wait).await;
            node_rpc_once(client, url, method, &params).await
        }
        _ => first,
    }
}

/// One node call. Snapshot replies grow with governed content, so they follow
/// the node's own response frame; other replies keep a small fixed cap.
async fn node_rpc_once<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: &Value,
) -> Result<T> {
    let limit = if method == "snapshot" {
        crate::node::MAX_RESPONSE_FRAME
    } else {
        RPC_REPLY_BYTES
    };
    let response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?;
    let status = response.status();
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS
        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
    {
        // An admission refusal: 429 for this client's quota, 503 for capacity
        // shared by all. Only the wait matters; the error text is never
        // journaled, so its body is left unread.
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        return Err(NodeBusy { retry_after }.into());
    }
    let mut response = response.error_for_status()?;
    ensure!(
        response.content_length().unwrap_or(0) <= limit as u64,
        "RPC reply is too large"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "RPC reply is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let reply: RpcReply<T> = serde_json::from_slice(&bytes)?;
    ensure!(reply.error.is_none(), "node refused faucet request");
    reply.result.context("missing RPC result")
}

/// The pause before the next refresh: the usual interval, or the longer wait
/// a busy node asked for, within a minute.
fn poll_wait(refreshed: &Result<()>) -> Duration {
    refreshed
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<NodeBusy>())
        .and_then(|busy| busy.retry_after)
        .map_or(POLL_INTERVAL, |wait| wait.clamp(POLL_INTERVAL, MAX_POLL_WAIT))
}

/// The loopback node RPC endpoint, cloned out of the engine so node lookups
/// hold no lock.
#[derive(Clone)]
struct NodeClient {
    client: reqwest::Client,
    url: String,
}
impl NodeClient {
    async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        node_rpc(&self.client, &self.url, method, params).await
    }
    /// The canonical block at `height` and which of `txids` it holds. With
    /// `checked`, `None` means that earlier block is no longer canonical; the
    /// node reads both heights together, so a returned block shares its chain.
    async fn block_receipt(
        &self,
        height: u64,
        txids: &[String],
        checked: Option<(u64, Hash)>,
    ) -> Result<Option<(Hash, Vec<bool>)>> {
        ensure!(
            txids.len() <= crate::node::MAX_RECEIPT_TXIDS,
            "too many receipt transaction IDs"
        );
        let mut params = json!({"height":height,"txids":txids});
        if let Some((at, hash)) = checked {
            params["checked"] = json!({"height":at,"hash":hex::encode(hash)});
        }
        let receipt: BlockReceipt = self.call("blockreceipt", params).await?;
        ensure!(
            receipt.height == height
                && receipt.included.len() == txids.len()
                && receipt.checked_canonical.is_some() == checked.is_some(),
            "node returned another block receipt"
        );
        if receipt.checked_canonical == Some(false) {
            return Ok(None);
        }
        Ok(Some((parse_hash(&receipt.hash)?, receipt.included)))
    }
    /// The canonical block hash at `height`, read from the node's index alone.
    async fn canonical_hash(&self, height: u64) -> Result<Hash> {
        Ok(self
            .block_receipt(height, &[], None)
            .await?
            .context("missing block receipt")?
            .0)
    }
}

enum Located {
    Found(u64, Hash, String),
    Missing,
    Incomplete,
}

/// Heights `first..=last` at which one recorded claim could be included.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Window {
    txid: String,
    first: u64,
    last: u64,
}

/// Progress locating which recorded claim consumed one nonce. Only heights
/// inside some claim's window are inspected, each for just the claims it
/// covers. Every inspection confirms the previous one in the same node read,
/// so inspected blocks share one chain and are trusted while the highest of
/// them remains canonical.
struct Scan {
    nonce: u64,
    windows: Vec<Window>,
    next: u64,
    checked: Option<(u64, Hash)>,
    found: Option<(u64, Hash, String)>,
}
impl Scan {
    fn new(nonce: u64, windows: Vec<Window>) -> Self {
        Self {
            nonce,
            next: windows.iter().map(|w| w.first).min().unwrap_or(0),
            windows,
            checked: None,
            found: None,
        }
    }
    /// The lowest height from `next` through `high` that some window covers.
    fn upcoming(&self, high: u64) -> Option<u64> {
        self.windows
            .iter()
            .filter(|w| w.last >= self.next)
            .map(|w| w.first.max(self.next))
            .min()
            .filter(|at| *at <= high)
    }
}

/// Inspects a bounded number of blocks, asking each only for the claims whose
/// windows cover its height. Heights no window covers are skipped.
async fn advance(node: &NodeClient, scan: &mut Scan, high: u64) -> Result<Located> {
    if let Some((at, hash, txid)) = scan.found.clone() {
        // The recorded hash commits to the block that held the payment.
        if at <= high && node.canonical_hash(at).await? == hash {
            return Ok(Located::Found(at, hash, txid));
        }
        *scan = Scan::new(scan.nonce, std::mem::take(&mut scan.windows));
    }
    let mut budget = SCAN_BLOCKS_PER_REFRESH;
    loop {
        let Some(at) = scan.upcoming(high) else {
            // Every height that could hold a recorded claim was inspected.
            if let Some((at, hash)) = scan.checked
                && (at > high || node.canonical_hash(at).await? != hash)
            {
                *scan = Scan::new(scan.nonce, std::mem::take(&mut scan.windows));
                continue;
            }
            return Ok(Located::Missing);
        };
        if budget == 0 {
            return Ok(Located::Incomplete);
        }
        let txids: Vec<String> = scan
            .windows
            .iter()
            .filter(|w| w.first <= at && at <= w.last)
            .map(|w| w.txid.clone())
            .collect();
        let mut block = None;
        let mut found = None;
        let mut moved = false;
        // One height's IDs are inspected together, so every refresh makes
        // progress even when more claims than one lookup names share it.
        for chunk in txids.chunks(crate::node::MAX_RECEIPT_TXIDS) {
            budget = budget.saturating_sub(1);
            let Some((hash, included)) = node.block_receipt(at, chunk, scan.checked).await? else {
                moved = true;
                break;
            };
            if block.is_some_and(|seen| seen != hash) {
                moved = true;
                break;
            }
            block = Some(hash);
            if let Some(index) = included.iter().position(|found| *found) {
                found = Some(chunk[index].clone());
                break;
            }
        }
        if moved {
            // The canonical chain changed between inspections. Blocks from
            // different branches never prove absence, so start again.
            *scan = Scan::new(scan.nonce, std::mem::take(&mut scan.windows));
            continue;
        }
        match (block, found) {
            (Some(hash), Some(txid)) => {
                scan.found = Some((at, hash, txid.clone()));
                return Ok(Located::Found(at, hash, txid));
            }
            (Some(hash), None) => scan.checked = Some((at, hash)),
            (None, _) => {}
        }
        scan.next = at + 1;
    }
}

/// Whether the node still responds and its chain advanced recently. Freshness
/// follows the governed interval, so slower blocks never make the faucet
/// unavailable for most of every interval.
fn fresh(
    last_advance: Option<Instant>,
    last_success: Option<Instant>,
    interval: u64,
    recent_block_seconds: u64,
) -> bool {
    let window = recent_block_seconds.max(interval.saturating_mul(FRESHNESS_INTERVALS));
    last_advance.is_some_and(|v| v.elapsed() < Duration::from_secs(window))
        && last_success.is_some_and(|v| v.elapsed() < Duration::from_secs(20))
}

/// What status reports, and a claim checks, of the engine's latest accounted
/// snapshot. The engine publishes one after every refresh and reservation;
/// status answers from it with its own ledger connection, so it never waits
/// for the engine, its node lookups or its commits.
#[derive(Default)]
struct View {
    fault: Option<&'static str>,
    last_advance: Option<Instant>,
    last_success: Option<Instant>,
    /// The governed block interval, or zero before the first snapshot.
    interval: u64,
    /// The governed limit, if any, refusing a payment to an existing account
    /// and to a new one.
    limits: [Option<&'static str>; 2],
    funded: bool,
    lifetime: u64,
}
impl View {
    fn mining(&self, config: &FaucetConfig) -> bool {
        fresh(
            self.last_advance,
            self.last_success,
            self.interval,
            config.recent_block_seconds,
        )
    }
    /// Whether the last refresh succeeded recently enough to report a payment.
    fn recent(&self) -> bool {
        self.last_success
            .is_some_and(|v| v.elapsed() < Duration::from_secs(20))
    }
    /// Whether a claim may be prepared. Governed limits refuse every claim here
    /// only when even a payment to an existing account, the lightest kind,
    /// could not be included within the fee allowance. Otherwise each claim's
    /// exact quote decides, before anything is signed or reserved.
    fn availability(&self, db: &Connection, config: &FaucetConfig) -> Result<&'static str> {
        if self.fault.is_some() {
            return Ok("unavailable");
        }
        if !self.mining(config) {
            return Ok("waiting_for_mining");
        }
        if pending_claim(db)?.is_some() {
            return Ok("pending");
        }
        let time = match quota_clock(db, now()) {
            Ok(time) => time,
            Err(error) if error.is::<Fault>() => return Ok("unavailable"),
            Err(error) => return Err(error),
        };
        if !within_budget(db, config, self.lifetime, time)? {
            return Ok("quota_reached");
        }
        if let Some(limit) = self.limits[0] {
            return Ok(limit);
        }
        if !self.funded {
            return Ok("unfunded");
        }
        Ok("ready")
    }
    fn state(&self, db: &Connection, config: &FaucetConfig) -> Result<&'static str> {
        let state = self.availability(db, config)?;
        // A payment to a new account is the costliest claim. Governance can make
        // it unincludable or more expensive than the operator's fee allowance,
        // which status reports although existing accounts can still be paid.
        if state == "ready"
            && let Some(limit) = self.limits[1]
        {
            return Ok(limit);
        }
        Ok(state)
    }
}

fn claim_json(config: &FaucetConfig, claim: &Claim, time: i64) -> Value {
    json!({"status":claim.status,"txid":claim.txid,"chain_id":config.chain_id,"amount_hashes":claim.amount_hashes,"retry_after_seconds":(claim.created.saturating_add(config.cooldown_seconds as i64).saturating_sub(time)).max(0)})
}

/// Public status: the faucet's state and, for a named recipient, its claim and
/// the cooldown across that recipient and the client's network.
fn status_json(
    config: &FaucetConfig,
    chain: &Hash,
    sender: &PublicKey,
    view: &View,
    db: &Connection,
    recipient: Option<&str>,
    client_subnet: &str,
) -> Result<Value> {
    let state = view.state(db, config)?;
    // Refresh diagnostics stay in the operator journal, never in public status.
    let mut result = json!({"enabled":true,"chain_id":config.chain_id,"amount_hashes":config.payout,"available":state=="ready","mining_active":view.mining(config),"state":state,"cooldown_seconds":config.cooldown_seconds,"address":address::encode(sender,chain)?});
    if let Some(recipient) = recipient {
        let key = address::decode(recipient, chain)?;
        let canonical = address::encode(&key, chain)?;
        // Best-effort quota time for display; claims use the strict ledger clock.
        let time = quota_clock(db, now()).unwrap_or_else(|_| now());
        let waiting = cooldown(db, config, &canonical, client_subnet, time)?;
        result["retry_after_seconds"] = json!(waiting.map_or(0, |v| v.retry_after_seconds));
        if let Some(wait) = waiting {
            result["cooldown_scope"] = json!(wait.scope);
            if state == "ready" {
                result["state"] = json!("cooldown");
                result["available"] = json!(false);
            }
        }
        if let Some(claim) = last_claim(db, &canonical)?
            && view.fault.is_none()
            && (claim.status != "confirmed" || view.recent())
        {
            result["claim"] = claim_json(config, &claim, time);
        }
    }
    Ok(result)
}

/// Status answers from the latest published view and a read-only ledger
/// connection of their own, on a blocking thread. Write-ahead logging lets
/// that connection read while the engine commits.
struct StatusSource {
    config: FaucetConfig,
    chain: Hash,
    sender: PublicKey,
    view: std::sync::RwLock<Arc<View>>,
    reader: std::sync::Mutex<Connection>,
}
impl StatusSource {
    fn answer(&self, recipient: Option<&str>, client_subnet: &str) -> Result<Value> {
        let view = self
            .view
            .read()
            .map_err(|_| anyhow!("faucet status unavailable"))?
            .clone();
        let db = self
            .reader
            .lock()
            .map_err(|_| anyhow!("faucet status unavailable"))?;
        status_json(
            &self.config,
            &self.chain,
            &self.sender,
            &view,
            &db,
            recipient,
            client_subnet,
        )
    }
}

/// One node snapshot as a refresh reads it. The engine adopts it once its
/// accounting completes, so claims in the meantime keep using the last
/// snapshot whose payments were accounted for.
struct Snap {
    height: u64,
    tip: Hash,
    state_root: Hash,
    settings: NodeSettings,
    nonce: u64,
    funds: Amount,
}

/// The newest confirmed receipt, to be checked against the canonical chain.
struct ReceiptCheck {
    txid: String,
    nonce: u64,
    at: u64,
    hash: String,
    generation: u64,
}

/// A consumed nonce some recorded claim must account for, with its search.
struct Settle {
    scan: Scan,
    generation: u64,
}

/// A claim ready for the node to prepare, with everything its signed transfer
/// must match.
struct Preparation {
    canonical: String,
    client_subnet: String,
    operation: Operation,
    params: Value,
    nonce: u64,
    height: u64,
    anchor: Hash,
    state_root: Hash,
    settings: NodeSettings,
    expiry_blocks: u64,
    expiry: u64,
}

enum ClaimStart {
    /// A pending or cooling-down claim answers a repeated request.
    Answered(Value),
    Prepare(Box<Preparation>),
}

struct Engine {
    config: FaucetConfig,
    chain: Hash,
    secret: Zeroizing<[u8; 32]>,
    subnet_key: Arc<Zeroizing<[u8; 32]>>,
    sender: PublicKey,
    payout: Amount,
    maximum_fee: Amount,
    ledger: Ledger,
    node: NodeClient,
    published: Arc<StatusSource>,
    height: Option<u64>,
    tip: Option<Hash>,
    state_root: Option<Hash>,
    settings: Option<NodeSettings>,
    nonce: u64,
    funds: Amount,
    last_advance: Option<Instant>,
    last_success: Option<Instant>,
    refresh_diagnostics: RefreshDiagnostics,
    fault: Option<&'static str>,
    scan: Option<Scan>,
    reported_state: Option<&'static str>,
}

impl Engine {
    fn open(config: FaucetConfig) -> Result<Self> {
        config.validate()?;
        let (secret, sender) = read_signer(&config.key_file)?;
        // Subnet digests use a derived key, so requests never copy the signer.
        let subnet_key = Arc::new(Zeroizing::new(crypto::tagged_hash(
            "Hashstash/FaucetSubnetKey/v1",
            &secret[..],
        )));
        let chain = parse_hash(&config.chain_id)?;
        let payout = amount(&config.payout)?;
        let maximum_fee = amount(&config.max_fee)?;
        let ledger = Ledger::open(&config.database, &chain, &sender, &payout.to_str_radix(10))?;
        // Status reads through its own connection, opened once the ledger
        // exists in write-ahead mode.
        let reader = Connection::open_with_flags(
            &config.database,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        reader.busy_timeout(Duration::from_secs(2))?;
        let published = Arc::new(StatusSource {
            config: config.clone(),
            chain,
            sender,
            view: std::sync::RwLock::new(Arc::new(View::default())),
            reader: std::sync::Mutex::new(reader),
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            // The node RPC is loopback only; environment proxies never relay it.
            .no_proxy()
            .build()?;
        let node = NodeClient {
            client,
            url: config.rpc_url.clone(),
        };
        let engine = Self {
            config,
            chain,
            secret,
            subnet_key,
            sender,
            payout,
            maximum_fee,
            ledger,
            node,
            published,
            height: None,
            tip: None,
            state_root: None,
            settings: None,
            nonce: 0,
            funds: Amount::zero(),
            last_advance: None,
            last_success: None,
            refresh_diagnostics: RefreshDiagnostics::default(),
            fault: None,
            scan: None,
            reported_state: None,
        };
        engine.publish();
        Ok(engine)
    }
    #[cfg(test)]
    fn mining(&self) -> bool {
        fresh(
            self.last_advance,
            self.last_success,
            self.settings.map_or(0, |s| s.interval),
            self.config.recent_block_seconds,
        )
    }
    /// The state status reports and claims check, from this engine's fields.
    fn view(&self) -> View {
        // A fee estimate that cannot be made pays nothing.
        let limit = |new_account| {
            self.payout_limit(new_account)
                .unwrap_or(Some("unavailable"))
        };
        View {
            fault: self.fault,
            last_advance: self.last_advance,
            last_success: self.last_success,
            interval: self.settings.map_or(0, |s| s.interval),
            limits: [limit(false), limit(true)],
            funded: self.funds >= &self.payout + &self.maximum_fee,
            lifetime: self.ledger.lifetime,
        }
    }
    /// Makes the current state the one status answers from.
    fn publish(&self) {
        let view = Arc::new(self.view());
        if let Ok(mut published) = self.published.view.write() {
            *published = view;
        }
    }
    /// The exact weight and automatic fee of this faucet's payment under the
    /// latest governed settings, derived as node preparation derives them: the
    /// fee's own encoded length is part of its charge, and a payment to a new
    /// account adds the account-creation weight.
    fn payout_requirements(&self, new_account: bool) -> Result<Option<(u64, Amount)>> {
        let (Some(settings), Some(anchor)) = (self.settings, self.tip) else {
            return Ok(None);
        };
        let mut body = TransactionBody {
            sender: self.sender,
            nonce: self.nonce,
            fee: Amount::zero(),
            anchor,
            expiry_blocks: self.config.expiry_blocks,
            // Recipient keys have one fixed width, so any key gives the exact size.
            operation: Operation::TransferExact {
                recipient: self.sender,
                amount: self.payout.clone(),
            },
            data: Vec::new(),
        };
        let rate = Amount::from(settings.minimum_fee_rate);
        for _ in 0..32 {
            let encoded = codec::encode(&Transaction {
                body: body.clone(),
                signature: [0; 64],
            })
            .len();
            let weight = u64::try_from(encoded)?
                .checked_add(if new_account { fees::ACCOUNT_WEIGHT } else { 0 })
                .context("faucet payment weight overflow")?;
            let fee = (Amount::from(weight) * &rate + Amount::from(fees::FEE_SCALE - 1))
                / fees::FEE_SCALE;
            if fee == body.fee {
                return Ok(Some((weight, fee)));
            }
            body.fee = fee;
        }
        anyhow::bail!("faucet fee estimate did not converge")
    }
    /// The governed limit, if any, that refuses this kind of payment.
    fn payout_limit(&self, new_account: bool) -> Result<Option<&'static str>> {
        let (Some(settings), Some((weight, fee))) =
            (self.settings, self.payout_requirements(new_account)?)
        else {
            return Ok(None);
        };
        Ok(if weight > settings.block_bytes {
            Some("capacity_exceeded")
        } else if fee > self.maximum_fee {
            Some("fee_cap_exceeded")
        } else {
            None
        })
    }
    fn availability(&self) -> Result<&'static str> {
        self.view().availability(&self.ledger.db, &self.config)
    }
    fn state(&self) -> Result<&'static str> {
        self.view().state(&self.ledger.db, &self.config)
    }
    /// Journals operator-relevant state changes by fixed name only.
    fn report_state(&mut self) {
        let Ok(state) = self.state() else {
            return;
        };
        if self.reported_state != Some(state) {
            self.reported_state = Some(state);
            if !matches!(state, "ready" | "pending") {
                eprintln!(
                    "faucet state={state} reason={}",
                    self.fault.unwrap_or("none")
                );
            }
        }
    }
    /// Status from this engine's own fields and ledger connection.
    #[cfg(test)]
    fn status(&self, recipient: Option<&str>, client_subnet: &str) -> Result<Value> {
        status_json(
            &self.config,
            &self.chain,
            &self.sender,
            &self.view(),
            &self.ledger.db,
            recipient,
            client_subnet,
        )
    }
    /// Tests drive refreshes on an engine they own, through the same steps.
    #[cfg(test)]
    async fn refresh(&mut self) -> Result<()> {
        let (node, key) = (self.node.clone(), hex::encode(self.sender));
        poll_once(self, &node, &key).await
    }
    /// Checks a node snapshot and notes whether the chain advanced; the rest
    /// is adopted when its accounting finishes.
    fn observe(&mut self, snapshot: NodeSnapshot) -> Result<Snap> {
        let status = snapshot.status;
        ensure!(
            status.chain_id == self.config.chain_id,
            "node changed network"
        );
        let height = status.height;
        let tip = parse_hash(&status.tip)?;
        let state_root = parse_hash(&status.state_root)?;
        ensure!(height <= i64::MAX as u64, "unsupported chain height");
        // A missing account is expected until the dedicated mining payout is funded.
        let (funds, nonce) = match snapshot.account {
            None => (Amount::zero(), 0),
            Some(account) => (
                snapshot_payment_funds(&snapshot.payment_available_hash)?,
                account.account.nonce,
            ),
        };
        if self.height.is_some_and(|v| height > v) {
            self.last_advance = Some(Instant::now());
        }
        Ok(Snap {
            height,
            tip,
            state_root,
            settings: status.settings,
            nonce,
            funds,
        })
    }
    /// Ends a refresh in one step: adopts its snapshot with the outcome of its
    /// accounting, journals that outcome by fixed category and publishes the
    /// resulting state. A failed refresh clears the last success here, in the
    /// step that adopts its unaccounted snapshot, so the claim the engine goes
    /// to next can never prepare against that snapshot as if it were fresh.
    fn finish_refresh(&mut self, accounted: Result<(Snap, Result<Option<Fault>>)>) -> Result<()> {
        let refreshed = accounted.and_then(|(snap, outcome)| {
            self.height = Some(snap.height);
            self.tip = Some(snap.tip);
            self.state_root = Some(snap.state_root);
            self.settings = Some(snap.settings);
            self.funds = snap.funds;
            self.nonce = snap.nonce;
            match outcome {
                Ok(pause) => {
                    self.fault = pause.map(|pause| pause.0);
                    self.last_success = Some(Instant::now());
                    Ok(())
                }
                Err(error) => {
                    if let Some(fault) = error.downcast_ref::<Fault>() {
                        self.fault = Some(fault.0);
                    }
                    Err(error)
                }
            }
        });
        match &refreshed {
            Ok(()) => self.refresh_diagnostics.recovered(),
            Err(error) => {
                self.last_success = None;
                if self
                    .refresh_diagnostics
                    .record(error, now(), Instant::now())
                    && let Some(status) = self.refresh_diagnostics.error.as_ref()
                {
                    eprintln!(
                        "faucet refresh category={} consecutive_errors={} first_at={} last_at={}",
                        status.category,
                        status.consecutive_errors,
                        status.first_at,
                        status.last_at
                    );
                }
            }
        }
        self.report_state();
        self.publish();
        refreshed
    }
    /// The newest confirmed receipt, whose block commits to its own
    /// transactions, which included the payment, and to all older receipts.
    fn receipt_to_check(&self, height: u64) -> Result<Option<ReceiptCheck>> {
        self.ledger.clock(now())?;
        let Some((claim, at, hash)) = self.ledger.top_receipt()? else {
            return Ok(None);
        };
        if height < at {
            // A shorter chain cannot show yet whether this payment survived.
            return Err(Fault("node_behind_ledger").into());
        }
        Ok(Some(ReceiptCheck {
            txid: claim.txid,
            nonce: claim.nonce,
            at,
            hash,
            generation: self.ledger.generation,
        }))
    }
    /// Accounts a receipt that left the canonical chain again from its nonce,
    /// unless a claim was reserved since it was read; it is then read again.
    fn repair_receipt(&mut self, check: ReceiptCheck) -> Result<()> {
        if check.generation != self.ledger.generation {
            return Ok(());
        }
        let status = if self.ledger.pending()?.is_some() {
            "expired"
        } else {
            "pending"
        };
        self.ledger.db.execute(
            "UPDATE claims SET status=?1,receipt_height=NULL,receipt_hash=NULL WHERE txid=?2 AND status='confirmed'",
            params![status, check.txid],
        )?;
        self.scan = None;
        Ok(())
    }
    /// The nonce below `nonce`, the account's next one, that some recorded
    /// claim must account for, with the search for it resumed while it covers
    /// the same windows. A pending claim at an already settled nonce expires.
    fn settlement(&mut self, top: Option<u64>, nonce: u64) -> Result<Option<Settle>> {
        let floor = match top {
            Some(nonce) => Some(nonce.saturating_add(1)),
            None => self.ledger.first_nonce()?,
        }
        .max(self.ledger.nonce_floor()?);
        if let Some(claim) = self.ledger.pending()? {
            self.verify_stored(&claim)?;
            if floor.is_some_and(|floor| claim.nonce < floor) {
                // A recorded payment already settled this nonce on this chain.
                self.ledger.expire(&claim.txid)?;
            }
        }
        let Some(floor) = floor.filter(|floor| *floor < nonce) else {
            return Ok(None);
        };
        let windows = self.ledger.unsettled(floor)?;
        if windows.is_empty() {
            // A consumed nonce matching no recorded claim: the key signed elsewhere.
            return Err(Fault("nonce_conflict").into());
        }
        let scan = match self.scan.take() {
            Some(scan) if scan.nonce == floor && scan.windows == windows => scan,
            _ => Scan::new(floor, windows),
        };
        Ok(Some(Settle {
            scan,
            generation: self.ledger.generation,
        }))
    }
    /// Applies what a search found: the claim that consumed the nonce is
    /// confirmed at depth and other bytes signed with it expire. A claim
    /// reserved during the search defers this to the next refresh.
    fn settled(
        &mut self,
        job: Settle,
        located: Result<Located>,
        height: u64,
    ) -> Result<Option<Fault>> {
        let nonce = job.scan.nonce;
        // Progress survives a failed lookup and resumes on the next refresh.
        self.scan = Some(job.scan);
        let located = located?;
        if job.generation != self.ledger.generation {
            return Ok(Some(Fault("verifying_payments")));
        }
        match located {
            Located::Found(at, hash, txid) => {
                // Other bytes signed with this nonce can never apply on this chain.
                self.ledger.db.execute(
                    "UPDATE claims SET status='expired' WHERE nonce=?1 AND status='pending' AND txid<>?2",
                    params![nonce.to_string(), txid],
                )?;
                if height.saturating_sub(at).saturating_add(1) >= self.config.confirmations {
                    self.ledger.db.execute("UPDATE claims SET status='confirmed',receipt_height=?1,receipt_hash=?2 WHERE txid=?3 AND status<>'confirmed'",params![at,hex::encode(hash),txid])?;
                    self.scan = None;
                }
                Ok(None)
            }
            // A consumed nonce matching no recorded claim: the key signed elsewhere.
            Located::Missing => Err(Fault("nonce_conflict").into()),
            Located::Incomplete => Ok(Some(Fault("verifying_payments"))),
        }
    }
    /// The pending claim's bytes to broadcast again, if its nonce is still
    /// unused and it may still be included. Neither an orphaned anchor nor a
    /// shorter chain can include the bytes after their lifetime, so they
    /// expire with the nonce unused.
    fn pending_retry(&mut self, height: u64, nonce: u64, interval: u64) -> Result<Option<String>> {
        let Some(claim) = self.ledger.pending()? else {
            return Ok(None);
        };
        if claim.nonce < nonce {
            return Ok(None);
        }
        self.verify_stored(&claim)?;
        if height >= claim.expiry {
            self.ledger.expire(&claim.txid)?;
            return Ok(None);
        }
        let mining = fresh(
            self.last_advance,
            self.last_success,
            interval,
            self.config.recent_block_seconds,
        );
        Ok(mining.then_some(claim.raw))
    }
    /// A stored claim must still be exactly its signed fixed intent before it
    /// is retried.
    fn verify_stored(&self, claim: &Claim) -> Result<()> {
        let tx = wallet::decode_signed(&claim.raw, &self.chain)?;
        ensure!(
            claim.height.checked_add(tx.body.expiry_blocks) == Some(claim.expiry),
            "stored faucet lifetime differs from its signed transaction"
        );
        let operation = Operation::TransferExact {
            recipient: address::decode(&claim.address, &self.chain)?,
            amount: amount(&claim.amount_hashes)?,
        };
        verify_intent(
            &tx.body,
            self.sender,
            claim.nonce,
            tx.body.anchor,
            tx.body.expiry_blocks,
            &operation,
            &tx.body.fee,
        )?;
        ensure!(
            hex::encode(codec::transaction_id(&tx)) == claim.txid
                && tx.body.sender == self.sender
                && tx.body.nonce == claim.nonce,
            "invalid stored faucet transaction"
        );
        Ok(())
    }
    /// Tests drive claims on an engine they own, through the same steps.
    #[cfg(test)]
    async fn claim(&mut self, recipient: &str, client_subnet: &str) -> Result<Value> {
        let node = self.node.clone();
        claim_with(self, &node, recipient.to_owned(), client_subnet.to_owned()).await
    }
    /// Answers a repeated claim from the ledger, or checks eligibility and
    /// fixes everything the node is asked to prepare.
    fn claim_start(&self, recipient: &str, client_subnet: &str) -> Result<ClaimStart> {
        ensure!(self.fault.is_none(), "Faucet needs operator review");
        let time = self.ledger.clock(now())?;
        let key = address::decode(recipient, &self.chain)?;
        ensure!(key != self.sender, "choose a visitor wallet");
        let canonical = address::encode(&key, &self.chain)?;
        if let Some(existing) = self.ledger.last(&canonical)?
            && (existing.status == "pending"
                || existing
                    .created
                    .saturating_add(self.config.cooldown_seconds as i64)
                    > time)
        {
            ensure!(
                existing.status != "confirmed"
                    || self
                        .last_success
                        .is_some_and(|v| v.elapsed() < Duration::from_secs(20)),
                "Faucet is verifying its payment history"
            );
            let mut result = claim_json(&self.config, &existing, time);
            if let Some(wait) = cooldown(
                &self.ledger.db,
                &self.config,
                &canonical,
                client_subnet,
                time,
            )? {
                result["retry_after_seconds"] = json!(wait.retry_after_seconds);
                result["cooldown_scope"] = json!(wait.scope);
            }
            return Ok(ClaimStart::Answered(result));
        }
        ensure!(
            self.availability()? == "ready",
            "Faucet is waiting for mining, funds, or its next allowance"
        );
        self.ledger
            .eligible(&self.config, &canonical, client_subnet, time)?;
        let height = self.height.context("missing chain height")?;
        let anchor = self.tip.context("missing quoted tip")?;
        let state_root = self.state_root.context("missing quoted state root")?;
        let settings = self.settings.context("missing governed settings")?;
        let expiry_blocks = self.config.expiry_blocks;
        let expiry = height.checked_add(expiry_blocks).context("expiry overflow")?;
        // Durable claim heights use SQLite signed INTEGERs. Reject before signing
        // instead of truncating a valid u64 lifetime or corrupting the receipt.
        ensure!(
            expiry <= i64::MAX as u64,
            "expiry exceeds faucet ledger integer storage"
        );
        let operation = Operation::TransferExact {
            recipient: key,
            amount: self.payout.clone(),
        };
        let params = json!({"sender":hex::encode(self.sender),"operation":operation,"nonce":self.nonce,"anchor":hex::encode(anchor),"expiry_blocks":expiry_blocks,"extra_fee":"0"});
        Ok(ClaimStart::Prepare(Box::new(Preparation {
            canonical,
            client_subnet: client_subnet.to_owned(),
            operation,
            params,
            nonce: self.nonce,
            height,
            anchor,
            state_root,
            settings,
            expiry_blocks,
            expiry,
        })))
    }
    /// Verifies the node's preparation against the claim, signs it and
    /// reserves it durably. Returns the signed bytes and the claim's answer.
    fn claim_commit(&mut self, claim: Preparation, result: Value) -> Result<(String, Value)> {
        let Preparation {
            canonical,
            client_subnet,
            operation,
            nonce,
            height,
            anchor,
            state_root,
            settings,
            expiry_blocks,
            expiry,
            ..
        } = claim;
        let quote = &result["fee_quote"];
        ensure!(
            quote["chain_id"] == self.config.chain_id
                && quote["tip"] == hex::encode(anchor)
                && quote["state_root"] == hex::encode(state_root)
                && quote["height"] == height
                && quote["anchor"] == hex::encode(anchor)
                && quote["anchor_height"] == height
                && quote["expiry_blocks"] == expiry_blocks
                && quote["expiry_height"] == expiry,
            "prepared faucet snapshot changed"
        );
        // Preparation checks encoded size only. A payment heavier than the block
        // capacity could never be included and must not consume an allowance.
        let weight: u64 = quote["weight"]
            .as_str()
            .and_then(|v| v.parse().ok())
            .context("missing quoted weight")?;
        ensure!(
            weight <= settings.block_bytes,
            "prepared faucet payment exceeds block capacity"
        );
        // A fee-rate increase or capacity decrease due within this lifetime
        // would leave the payment only the activation block. Defer the claim
        // rather than spend the visitor's allowance on that one chance.
        ensure!(
            quote["scheduled_change"]["valid_after"] != false,
            "Faucet is waiting for a scheduled network change; try again in a few blocks"
        );
        let envelope = wallet::UnsignedEnvelope {
            chain_id: result["chain_id"]
                .as_str()
                .context("missing unsigned network context")?
                .into(),
            format: result["format"]
                .as_str()
                .context("missing unsigned format")?
                .into(),
            body: result["body"]
                .as_str()
                .context("missing unsigned body")?
                .into(),
        };
        let body = wallet::decode_unsigned(&envelope)?;
        ensure!(
            wallet::unsigned_chain(&envelope)? == self.chain,
            "prepared faucet network context changed"
        );
        verify_intent(
            &body,
            self.sender,
            nonce,
            anchor,
            expiry_blocks,
            &operation,
            &self.maximum_fee,
        )?;
        let tx = crypto::sign(&self.chain, &body, &self.secret)?;
        let claim = Claim {
            address: canonical,
            amount_hashes: self.payout.to_str_radix(10),
            created: self.ledger.clock(now())?,
            nonce: body.nonce,
            txid: hex::encode(codec::transaction_id(&tx)),
            raw: wallet::signed_hex(&tx),
            status: "pending".into(),
            height,
            expiry,
        };
        // No broadcast is allowed above this durable commit.
        self.ledger.reserve(&self.config, &claim, &client_subnet)?;
        self.publish();
        let answer = claim_json(&self.config, &claim, claim.created);
        Ok((claim.raw, answer))
    }
}

/// Exclusive use of the engine for one local step of a refresh or a claim.
/// The service runs each step on a blocking thread, so SQLite work, including
/// its synchronous commits, never occupies the async workers. Between steps a
/// refresh holds nothing while it waits for the node; a claim keeps the
/// engine (see `Held`).
trait Hold: Send {
    fn step<R, F>(&mut self, work: F) -> impl Future<Output = Result<R>> + Send
    where
        R: Send + 'static,
        F: FnOnce(&mut Engine) -> Result<R> + Send + 'static;
    /// Gives up a hold kept between steps.
    fn release(&mut self) {}
}

/// Tests own their engine and run each step in place.
#[cfg(test)]
impl Hold for Engine {
    fn step<R, F>(&mut self, work: F) -> impl Future<Output = Result<R>> + Send
    where
        R: Send + 'static,
        F: FnOnce(&mut Engine) -> Result<R> + Send + 'static,
    {
        std::future::ready(work(self))
    }
}

/// The service engine as a refresh uses it: taken for each step only.
struct Shared(Arc<Mutex<Engine>>);
impl Hold for Shared {
    fn step<R, F>(&mut self, work: F) -> impl Future<Output = Result<R>> + Send
    where
        R: Send + 'static,
        F: FnOnce(&mut Engine) -> Result<R> + Send + 'static,
    {
        let engine = self.0.clone();
        async move {
            let mut engine = engine.lock_owned().await;
            tokio::task::spawn_blocking(move || work(&mut engine))
                .await
                .context("faucet engine step failed")?
        }
    }
}

/// The service engine as a claim uses it: kept from the eligibility checks
/// through the reservation, so the nonce, the anchor and the one pending
/// payment cannot change while the node prepares the transfer.
struct Held(Option<OwnedMutexGuard<Engine>>);
impl Hold for Held {
    async fn step<R, F>(&mut self, work: F) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut Engine) -> Result<R> + Send + 'static,
    {
        let mut engine = self.0.take().context("faucet engine released")?;
        let (engine, result) = tokio::task::spawn_blocking(move || {
            let result = work(&mut engine);
            (engine, result)
        })
        .await
        .context("faucet engine step failed")?;
        self.0 = Some(engine);
        result
    }
    fn release(&mut self) {
        self.0 = None;
    }
}

/// One refresh: the node snapshot and its accounting, then one step that
/// adopts it and records the outcome, whether the refresh succeeded or not.
async fn poll_once(hold: &mut impl Hold, node: &NodeClient, key: &str) -> Result<()> {
    let accounted = account(hold, node, key).await;
    hold.step(move |engine| engine.finish_refresh(accounted))
        .await
}

/// A node snapshot with the outcome of its accounting, not yet adopted.
async fn account(
    hold: &mut impl Hold,
    node: &NodeClient,
    key: &str,
) -> Result<(Snap, Result<Option<Fault>>)> {
    // The snapshot is the largest reply; nothing is held while it arrives.
    let snapshot: NodeSnapshot = node.call("snapshot", json!({"key":key})).await?;
    let snap = hold.step(move |engine| engine.observe(snapshot)).await?;
    let outcome = reconcile(hold, node, &snap).await;
    Ok((snap, outcome))
}

/// Accounts for every faucet nonce the canonical chain consumed, and returns
/// a pause category while that accounting is incomplete. Reorganizations
/// relocate, retry or expire records automatically. Each nonce pays at most
/// one recorded claim, so no repair can create another payment. Node lookups
/// run between local steps, holding nothing, so a claim can be reserved
/// meanwhile; what those lookups found is then applied on a later refresh,
/// against the ledger as it is by then.
async fn reconcile(hold: &mut impl Hold, node: &NodeClient, snap: &Snap) -> Result<Option<Fault>> {
    let (height, nonce, interval) = (snap.height, snap.nonce, snap.settings.interval);
    // The newest confirmed receipt is checked by its block hash alone. One
    // that left the canonical chain is accounted again from its nonce.
    let mut verified = None;
    for _ in 0..RECEIPT_REPAIRS_PER_REFRESH {
        let Some(receipt) = hold
            .step(move |engine| engine.receipt_to_check(height))
            .await?
        else {
            verified = Some(None);
            break;
        };
        if hex::encode(node.canonical_hash(receipt.at).await?) == receipt.hash {
            verified = Some(Some(receipt.nonce));
            break;
        }
        hold.step(move |engine| engine.repair_receipt(receipt))
            .await?;
    }
    let Some(top) = verified else {
        // More reorganized receipts remain for the next refresh.
        return Ok(Some(Fault("verifying_payments")));
    };
    if let Some(mut job) = hold
        .step(move |engine| engine.settlement(top, nonce))
        .await?
    {
        let located = advance(node, &mut job.scan, height).await;
        if let Some(pause) = hold
            .step(move |engine| engine.settled(job, located, height))
            .await?
        {
            return Ok(Some(pause));
        }
    }
    // Only bytes whose nonce is still unused here may be retried or expired.
    if let Some(raw) = hold
        .step(move |engine| engine.pending_retry(height, nonce, interval))
        .await?
    {
        // Any RPC error is uncertain. Keep the durable pending record and its
        // quota reservation; a later poll retries exactly these signed bytes.
        let _ = node
            .call::<IgnoredAny>("broadcasttransaction", json!({"raw":raw}))
            .await;
    }
    Ok(None)
}

/// Pays one claim, or answers a repeated one. A refresh retries reserved
/// bytes anyway, so the broadcast needs no hold.
async fn claim_with(
    hold: &mut impl Hold,
    node: &NodeClient,
    recipient: String,
    client_subnet: String,
) -> Result<Value> {
    let preparation = match hold
        .step(move |engine| engine.claim_start(&recipient, &client_subnet))
        .await?
    {
        ClaimStart::Answered(answer) => return Ok(answer),
        ClaimStart::Prepare(preparation) => *preparation,
    };
    let prepared: Value = node
        .call("preparetransaction", preparation.params.clone())
        .await?;
    let (raw, answer) = hold
        .step(move |engine| engine.claim_commit(preparation, prepared))
        .await?;
    hold.release();
    let _ = node
        .call::<IgnoredAny>("broadcasttransaction", json!({"raw":raw}))
        .await;
    Ok(answer)
}

#[allow(clippy::too_many_arguments)]
fn verify_intent(
    body: &TransactionBody,
    sender: PublicKey,
    nonce: u64,
    anchor: Hash,
    expiry_blocks: u64,
    operation: &Operation,
    maximum: &Amount,
) -> Result<()> {
    ensure!(
        body.sender == sender
            && body.nonce == nonce
            && body.anchor == anchor
            && body.expiry_blocks == expiry_blocks
            && expiry_blocks > 0
            && body.fee <= *maximum,
        "prepared faucet envelope changed"
    );
    ensure!(
        body.data.is_empty() && body.operation == *operation,
        "prepared faucet transfer changed"
    );
    Ok(())
}

#[derive(Clone)]
struct App {
    engine: Arc<Mutex<Engine>>,
    status: Arc<StatusSource>,
    node: NodeClient,
    chain: Hash,
    subnet_key: Arc<Zeroizing<[u8; 32]>>,
    origins: Arc<Vec<String>>,
    hosts: Arc<Vec<String>>,
    sessions: Arc<Semaphore>,
    clients: Arc<ClientSessions>,
}
impl App {
    fn new(engine: Engine, origins: Vec<String>, hosts: Vec<String>) -> Self {
        engine.publish();
        Self {
            status: engine.published.clone(),
            node: engine.node.clone(),
            chain: engine.chain,
            subnet_key: engine.subnet_key.clone(),
            engine: Arc::new(Mutex::new(engine)),
            origins: Arc::new(origins),
            hosts: Arc::new(hosts),
            sessions: Arc::new(Semaphore::new(16)),
            clients: Arc::default(),
        }
    }
}

/// Requests in flight per client network, so one network cannot hold every
/// global session. Entries exist only while requests run and are never stored.
#[derive(Default)]
struct ClientSessions(std::sync::Mutex<HashMap<String, usize>>);
struct ClientSession {
    sessions: Arc<ClientSessions>,
    client: String,
}
impl ClientSessions {
    fn enter(self: &Arc<Self>, client: &str) -> Option<ClientSession> {
        let mut active = self.0.lock().ok()?;
        let count = active.entry(client.to_owned()).or_default();
        if *count >= CLIENT_SESSIONS {
            return None;
        }
        *count += 1;
        Some(ClientSession {
            sessions: self.clone(),
            client: client.to_owned(),
        })
    }
}
impl Drop for ClientSession {
    fn drop(&mut self) {
        if let Ok(mut active) = self.sessions.0.lock()
            && let Some(count) = active.get_mut(&self.client)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                active.remove(&self.client);
            }
        }
    }
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}
fn failure(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}

async fn protect(State(app): State<App>, request: Request, next: Next) -> Response {
    let Ok(_permit) = app.sessions.clone().try_acquire_owned() else {
        return failure(StatusCode::TOO_MANY_REQUESTS, "Faucet is busy");
    };
    let headers = request.headers();
    let origin = one_header(headers, "origin").map(str::to_owned);
    let allowed_origin = origin.as_ref().is_none_or(|v| app.origins.contains(v));
    let host = one_header(headers, "host");
    let valid_host = host.is_some_and(|h| app.hosts.iter().any(|v| v == h));
    let client = one_header(headers, "x-real-ip").and_then(|v| subnet(v).ok());
    let post = request.method() == Method::POST;
    let allowed = allowed_origin
        && valid_host
        && client.is_some()
        && (!post
            || (origin.is_some()
                && one_header(headers, "content-type").is_some_and(|v| {
                    v.split(';').next().map(str::trim) == Some("application/json")
                })));
    let client_session = client
        .as_deref()
        .filter(|_| allowed)
        .and_then(|client| app.clients.enter(client));
    let mut response = if !allowed {
        failure(StatusCode::FORBIDDEN, "Faucet website request required")
    } else if client_session.is_none() {
        failure(StatusCode::TOO_MANY_REQUESTS, "Faucet is busy")
    } else if request.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        match tokio::time::timeout(Duration::from_secs(15), next.run(request)).await {
            Ok(response) => response,
            Err(_) => failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Faucet request is still being checked",
            ),
        }
    };
    drop(client_session);
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("vary", "Origin"),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    if allowed_origin && let Some(origin) = origin {
        if let Ok(value) = HeaderValue::from_str(&origin) {
            response
                .headers_mut()
                .insert("access-control-allow-origin", value);
        }
        response.headers_mut().insert(
            "access-control-allow-methods",
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            HeaderValue::from_static("content-type"),
        );
    }
    response
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusQuery {
    address: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimRequest {
    address: String,
}

fn private_client_subnet(subnet_key: &[u8; 32], headers: &HeaderMap) -> Option<String> {
    let client = one_header(headers, "x-real-ip").and_then(|v| subnet(v).ok())?;
    let mut private_subnet = Zeroizing::new(Vec::with_capacity(32 + client.len()));
    private_subnet.extend_from_slice(&subnet_key[..]);
    private_subnet.extend_from_slice(client.as_bytes());
    Some(hex::encode(crypto::tagged_hash(
        "Hashstash/FaucetSubnet/v1",
        &private_subnet,
    )))
}

async fn status_handler(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<StatusQuery>,
) -> Response {
    let Some(client) = private_client_subnet(&app.subnet_key, &headers) else {
        return failure(StatusCode::FORBIDDEN, "Client address required");
    };
    // Status never waits for the engine: it reads the published view and its
    // own ledger connection, off the async workers.
    let status = app.status.clone();
    match tokio::task::spawn_blocking(move || status.answer(query.address.as_deref(), &client))
        .await
    {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(_)) => failure(StatusCode::BAD_REQUEST, "Invalid test-network address"),
        Err(_) => failure(StatusCode::SERVICE_UNAVAILABLE, "Faucet status is unavailable"),
    }
}
async fn claim_handler(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ClaimRequest>,
) -> Response {
    // Store only a keyed digest of the subnet, never the visitor's literal IP.
    let Some(client) = private_client_subnet(&app.subnet_key, &headers) else {
        return failure(StatusCode::FORBIDDEN, "Client address required");
    };
    if address::decode(&request.address, &app.chain).is_err() {
        return failure(StatusCode::BAD_REQUEST, "Invalid test-network address");
    }
    // Claims take turns with the engine; a refresh waiting for the node holds
    // it only between its lookups.
    let mut held = Held(Some(app.engine.clone().lock_owned().await));
    match claim_with(&mut held, &app.node, request.address, client).await {
        Ok(v) => Json(v).into_response(),
        Err(error) => {
            let message = error.to_string();
            if let Some(wait) = error.downcast_ref::<Cooldown>() {
                let mut response=(StatusCode::TOO_MANY_REQUESTS,Json(json!({"error":message,"state":"cooldown","retry_after_seconds":wait.retry_after_seconds,"cooldown_scope":wait.scope}))).into_response();
                if let Ok(value) = HeaderValue::from_str(&wait.retry_after_seconds.to_string()) {
                    response.headers_mut().insert("retry-after", value);
                }
                response
            } else if message == "Faucet allowance reached" {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({"error":message,"state":"quota_reached"})),
                )
                    .into_response()
            } else {
                failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Faucet is waiting for mining, funds, or another payment",
                )
            }
        }
    }
}

pub struct FaucetServer {
    pub address: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    poll: JoinHandle<()>,
}
impl FaucetServer {
    pub async fn stop(mut self) {
        self.poll.abort();
        let _ = (&mut self.poll).await;
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let _ = (&mut self.task).await;
    }
}
impl Drop for FaucetServer {
    fn drop(&mut self) {
        // Dropping a handle must not leave an unattended signer polling and
        // retrying pending payments. Durable intents remain available on restart.
        self.poll.abort();
        self.task.abort();
    }
}

pub async fn serve(config: FaucetConfig) -> Result<FaucetServer> {
    let opened = config.clone();
    let engine = tokio::task::spawn_blocking(move || Engine::open(opened)).await??;
    let listener = TcpListener::bind(config.bind).await?;
    let address = listener.local_addr()?;
    let hosts = config
        .origins
        .iter()
        .map(|s| s.split_once("://").expect("validated origin").1.to_owned())
        .collect();
    let key = hex::encode(engine.sender);
    let app = App::new(engine, config.origins.clone(), hosts);
    let (engine, node) = (app.engine.clone(), app.node.clone());
    let routes = router(app);
    let poll = tokio::spawn(async move {
        // The engine is taken only for each local step of a refresh, never
        // while it waits for the node, so status and claims never wait on a
        // slow or busy node's lookups.
        let mut shared = Shared(engine);
        loop {
            let refreshed = poll_once(&mut shared, &node, &key).await;
            tokio::time::sleep(poll_wait(&refreshed)).await;
        }
    });
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(async move {
        crate::local_http::serve(
            listener,
            routes,
            HTTP_CONNECTIONS,
            crate::local_http::HEAD_TIMEOUT,
            async {
                let _ = shutdown.await;
            },
        )
        .await;
    });
    Ok(FaucetServer {
        address,
        stop: Some(stop),
        task,
        poll,
    })
}

fn router(app: App) -> Router {
    Router::new()
        .route("/faucet/status", get(status_handler))
        .route("/faucet/claim", post(claim_handler))
        .layer(DefaultBodyLimit::max(1024))
        .layer(middleware::from_fn_with_state(app.clone(), protect))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn faucet_uses_common_payment_capacity_and_fails_closed_without_it() {
        let mut snapshot = json!({
            "account":{"account":{"ordinary":"1000"}},
            "pass":{"account":{"ordinary":"250"}},
            "payment_available_hash":"250"
        });
        let funds = |snapshot: &Value| snapshot_payment_funds(&snapshot["payment_available_hash"]);
        assert_eq!(funds(&snapshot).unwrap(), 250u32.into());
        snapshot["payment_available_hash"] = json!("0");
        assert_eq!(funds(&snapshot).unwrap(), Amount::zero());
        snapshot
            .as_object_mut()
            .unwrap()
            .remove("payment_available_hash");
        assert!(funds(&snapshot).is_err());
        for malformed in [json!(250), json!(null), json!("-1"), json!("1.5")] {
            snapshot["payment_available_hash"] = malformed;
            assert!(funds(&snapshot).is_err());
        }
    }

    #[test]
    fn refresh_diagnostics_are_sanitized_rate_limited_bounded_and_recoverable() {
        let mut diagnostics = RefreshDiagnostics::default();
        let instant = Instant::now();
        let secret = "secret=https://user:password@host/private/signed.json";
        let error = anyhow!(secret);
        assert!(diagnostics.record(&error, 100, instant));
        assert!(!diagnostics.record(&error, 101, instant + Duration::from_secs(1)));
        let status = diagnostics.error.as_ref().unwrap();
        assert_eq!(status.consecutive_errors, 2);
        assert_eq!(status.first_at, 100);
        assert_eq!(status.last_at, 101);
        assert_eq!(status.category, "node_response_or_state");
        assert!(!serde_json::to_string(status).unwrap().contains(secret));
        let disk = anyhow::Error::from(std::io::Error::other(secret));
        assert!(diagnostics.record(&disk, 160, instant + Duration::from_secs(60)));
        assert_eq!(diagnostics.error.as_ref().unwrap().category, "filesystem");
        diagnostics.error.as_mut().unwrap().consecutive_errors = u32::MAX;
        diagnostics.record(&error, 161, instant + Duration::from_secs(61));
        assert_eq!(
            diagnostics.error.as_ref().unwrap().consecutive_errors,
            u32::MAX
        );
        diagnostics.recovered();
        assert!(diagnostics.error.is_none());
        assert!(!diagnostics.record(&error, 162, instant + Duration::from_secs(62)));
        assert_eq!(diagnostics.error.as_ref().unwrap().consecutive_errors, 1);
        assert_eq!(diagnostics.error.as_ref().unwrap().first_at, 162);
    }

    fn owner_only(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }
    fn config(dir: &TempDir) -> FaucetConfig {
        let secret = [41; 32];
        let public = crypto::public_key(&secret).unwrap();
        let key_file = dir.path().join("key.json");
        std::fs::write(
            &key_file,
            serde_json::to_vec(&json!({"secret":hex::encode(secret),"public":hex::encode(public)}))
                .unwrap(),
        )
        .unwrap();
        owner_only(&key_file);
        FaucetConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            rpc_url: "http://127.0.0.1:1/rpc".into(),
            chain_id: hex::encode([7; 32]),
            key_file,
            database: dir.path().join("faucet.sqlite"),
            origins: vec!["https://faucet.example".into()],
            payout: "1000000000000".into(),
            max_fee: "1000000".into(),
            cooldown_seconds: 86400,
            subnet_cooldown_seconds: 60,
            subnet_daily_claims: 10,
            hourly_claims: 100,
            daily_claims: 250,
            lifetime_claims: 1000,
            recent_block_seconds: 180,
            confirmations: 2,
            expiry_blocks: 2,
        }
    }
    fn recipient(n: u8) -> String {
        address::encode(&crypto::public_key(&[n; 32]).unwrap(), &[7; 32]).unwrap()
    }

    #[test]
    fn transaction_lifetime_defaults_to_two_without_an_arbitrary_upper_cap() {
        let dir = TempDir::new().unwrap();
        let config = config(&dir);
        let mut value = serde_json::to_value(&config).unwrap();
        value.as_object_mut().unwrap().remove("expiry_blocks");
        let mut parsed: FaucetConfig = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.expiry_blocks, 2);
        for lifetime in [2, 101, 10_000, u64::MAX] {
            parsed.expiry_blocks = lifetime;
            parsed.validate().unwrap();
        }
        parsed.expiry_blocks = 0;
        assert!(parsed.validate().is_err());
    }

    #[tokio::test]
    async fn dropping_faucet_stops_http_and_polling_tasks() {
        let directory = TempDir::new().unwrap();
        let server = serve(config(&directory)).await.unwrap();
        let address = server.address;
        let polling = server.poll.abort_handle();
        let http = server.task.abort_handle();
        tokio::task::yield_now().await;
        drop(server);
        tokio::time::timeout(Duration::from_secs(2), async {
            while !polling.is_finished() || !http.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping faucet left a service task alive");
        // The listener is released, so a replacement cannot accidentally leave
        // the old signer operating beside it.
        let replacement = TcpListener::bind(address).await.unwrap();
        drop(replacement);
    }

    async fn streaming_rpc_reply(
        body: Vec<u8>,
        finish: bool,
        advertised_length: Option<usize>,
    ) -> (SocketAddr, JoinHandle<()>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut length = 0;
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            stream.read_exact(&mut vec![0; length]).await.unwrap();
            let header = match advertised_length {
                Some(length) => format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n"),
                None => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".into(),
            };
            stream.get_mut().write_all(header.as_bytes()).await.unwrap();
            for part in body.chunks(64 * 1024) {
                let header = format!("{:x}\r\n", part.len());
                if stream.get_mut().write_all(header.as_bytes()).await.is_err()
                    || stream.get_mut().write_all(part).await.is_err()
                    || stream.get_mut().write_all(b"\r\n").await.is_err()
                {
                    return;
                }
            }
            if finish {
                let _ = stream.get_mut().write_all(b"0\r\n\r\n").await;
            } else {
                // No terminal chunk: an oversized reply must be rejected while
                // streaming, before EOF or the request timeout is reached.
                std::future::pending::<()>().await;
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn rpc_limits_follow_node_frames_for_snapshots_and_reject_oversize_before_eof() {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let large = json!({"result":{"data":"x".repeat(RPC_REPLY_BYTES + 1024)}});
        // Governed snapshot content can exceed the fixed cap for other replies.
        for (method, value) in [
            ("broadcasttransaction", json!({"result":{"transaction_id":"00"}})),
            ("snapshot", large.clone()),
        ] {
            let (address, task) =
                streaming_rpc_reply(serde_json::to_vec(&value).unwrap(), true, None).await;
            let url = format!("http://{address}/rpc");
            assert_eq!(
                node_rpc::<Value>(&client, &url, method, json!({}))
                    .await
                    .unwrap(),
                value["result"]
            );
            task.await.unwrap();
        }
        // Only the fields the faucet reads are kept from a large snapshot.
        let snapshot = json!({"result":{
            "status":{"chain_id":hex::encode([7; 32]),"height":9,"tip":hex::encode([1; 32]),"state_root":hex::encode([2; 32]),"settings":{"block_bytes":16384,"minimum_fee_rate":1,"interval":15,"lead":1}},
            "proposals":{"items":vec![json!({"payments":vec![[255u8; 32]; 16]}); 4096]},
            "account":{"account":{"nonce":3,"ordinary":"5"}},
            "payment_available_hash":"5"
        }});
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert!(bytes.len() > RPC_REPLY_BYTES);
        let (address, task) = streaming_rpc_reply(bytes, true, None).await;
        let parsed: NodeSnapshot =
            node_rpc(&client, &format!("http://{address}/rpc"), "snapshot", json!({}))
                .await
                .unwrap();
        task.await.unwrap();
        assert_eq!(parsed.status.height, 9);
        assert_eq!(parsed.status.settings.block_bytes, 16384);
        assert_eq!(parsed.account.unwrap().account.nonce, 3);
        for (method, body, length) in [
            ("preparetransaction", serde_json::to_vec(&large).unwrap(), None),
            (
                "snapshot",
                Vec::new(),
                Some(crate::node::MAX_RESPONSE_FRAME + 1),
            ),
        ] {
            let (address, task) = streaming_rpc_reply(body, false, length).await;
            let url = format!("http://{address}/rpc");
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                node_rpc::<Value>(&client, &url, method, json!({})),
            )
            .await;
            task.abort();
            let _ = task.await;
            assert_eq!(
                result
                    .expect("oversized response waited for EOF")
                    .unwrap_err()
                    .to_string(),
                "RPC reply is too large"
            );
        }
    }

    fn record(n: u8, time: i64) -> Claim {
        Claim {
            address: recipient(n),
            amount_hashes: "1000000000000".into(),
            created: time,
            nonce: 0,
            txid: hex::encode([n; 32]),
            raw: format!("{n:02x}"),
            status: "pending".into(),
            height: 1,
            expiry: 21,
        }
    }
    fn finish(ledger: &Ledger, claim: &Claim) {
        ledger
            .db
            .execute(
                "UPDATE claims SET status='expired' WHERE txid=?1",
                [&claim.txid],
            )
            .unwrap();
    }

    #[test]
    fn subnet_and_configuration_are_strict() {
        assert_eq!(
            subnet("192.0.2.17").unwrap(),
            subnet("::ffff:192.0.2.200").unwrap()
        );
        assert_eq!(
            subnet("2001:db8:5:6::1").unwrap(),
            subnet("2001:db8:5:6::ffff").unwrap()
        );
        // One delegated /56 shares an allowance across its /64 networks.
        assert_eq!(
            subnet("2001:db8:5:6::1").unwrap(),
            subnet("2001:db8:5:ff::1").unwrap()
        );
        assert_eq!(subnet("2001:db8:5:6::1").unwrap(), "2001:db8:5:0::/56");
        assert_ne!(
            subnet("2001:db8:5:6::1").unwrap(),
            subnet("2001:db8:5:106::1").unwrap()
        );
        for bad in ["", "192.0.2.1, 127.0.0.1", "192.0.2.1:90", "fe80::1%eth0"] {
            assert!(subnet(bad).is_err());
        }
        let dir = TempDir::new().unwrap();
        let original = config(&dir);
        original.validate().unwrap();
        let mut legacy = serde_json::to_value(&original).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("subnet_cooldown_seconds");
        legacy
            .as_object_mut()
            .unwrap()
            .remove("subnet_daily_claims");
        let legacy = serde_json::from_value::<FaucetConfig>(legacy).unwrap();
        assert_eq!(legacy.subnet_cooldown_seconds, 60);
        assert_eq!(legacy.subnet_daily_claims, 10);
        for duration in [0, 31_536_001] {
            let mut c = original.clone();
            c.subnet_cooldown_seconds = duration;
            assert!(c.validate().is_err());
        }
        for allowance in [0, 1_000_001] {
            let mut c = original.clone();
            c.subnet_daily_claims = allowance;
            assert!(c.validate().is_err());
        }
        let mut c = original.clone();
        c.bind = "0.0.0.0:1234".parse().unwrap();
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.rpc_url = "https://example.test/rpc".into();
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.origins = vec!["https://example.test/path".into()];
        assert!(c.validate().is_err());
        let mut c = original.clone();
        c.payout = "-1".into();
        assert!(c.validate().is_err());
        let mut c = original;
        c.hourly_claims = 1001;
        assert!(c.validate().is_err());
    }

    #[test]
    fn durable_quotas_count_pending_and_expired_without_resetting_on_restart() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        c.hourly_claims = 2;
        c.daily_claims = 3;
        c.lifetime_claims = 4;
        let sender = crypto::public_key(&[41; 32]).unwrap();
        let mut ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        let a = record(1, 100000);
        ledger.reserve(&c, &a, "subnet-a").unwrap();
        assert!(ledger.reserve(&c, &record(2, 100001), "subnet-b").is_err()); // one outstanding globally
        finish(&ledger, &a);
        assert!(ledger.reserve(&c, &record(1, 100002), "subnet-c").is_err()); // same address
        assert!(ledger.reserve(&c, &record(3, 100003), "subnet-a").is_err()); // same subnet
        let b = record(2, 100004);
        ledger.reserve(&c, &b, "subnet-b").unwrap();
        finish(&ledger, &b);
        drop(ledger);
        let mut ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        assert!(!ledger.budget(&c, 100005).unwrap());
        assert!(ledger.reserve(&c, &record(4, 100006), "subnet-d").is_err()); // hourly cap
        let d = record(4, 104000);
        ledger.reserve(&c, &d, "subnet-d").unwrap();
        finish(&ledger, &d);
        assert!(ledger.reserve(&c, &record(5, 108000), "subnet-e").is_err()); // daily cap
        let e = record(5, 200000);
        ledger.reserve(&c, &e, "subnet-e").unwrap();
        finish(&ledger, &e);
        assert!(ledger.reserve(&c, &record(6, 300000), "subnet-f").is_err()); // lifetime cap
        assert!(Ledger::open(&c.database, &[8; 32], &sender, &c.payout).is_err());
        assert!(Ledger::open(&c.database, &[7; 32], &sender, "2").is_ok());
        assert!(
            Ledger::open(
                &c.database,
                &[7; 32],
                &crypto::public_key(&[42; 32]).unwrap(),
                &c.payout
            )
            .is_err()
        );
    }

    fn legacy_ledger(c: &FaucetConfig) -> Connection {
        let db = Connection::open(&c.database).unwrap();
        db.execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE claims(address TEXT NOT NULL,subnet TEXT NOT NULL,created INTEGER NOT NULL,nonce TEXT NOT NULL,txid TEXT PRIMARY KEY,raw TEXT NOT NULL,status TEXT NOT NULL CHECK(status IN ('pending','confirmed','expired')),height INTEGER NOT NULL,expiry INTEGER NOT NULL,receipt_height INTEGER,receipt_hash TEXT);").unwrap();
        for (key, value) in [
            ("chain", c.chain_id.clone()),
            (
                "sender",
                hex::encode(crypto::public_key(&[41; 32]).unwrap()),
            ),
            ("payout", c.payout.clone()),
        ] {
            db.execute("INSERT INTO meta VALUES(?1,?2)", params![key, value])
                .unwrap();
        }
        for n in 1..=3 {
            let claim = record(n, 100_000 + n as i64);
            let (status, receipt_height, receipt_hash) = match n {
                1 => ("confirmed", Some(2), Some(hex::encode([9; 32]))),
                2 => ("expired", None, None),
                _ => ("pending", None, None),
            };
            db.execute(
                "INSERT INTO claims VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    claim.address,
                    format!("subnet-{n}"),
                    claim.created,
                    (n - 1).to_string(),
                    claim.txid,
                    claim.raw,
                    status,
                    claim.height,
                    claim.expiry,
                    receipt_height,
                    receipt_hash
                ],
            )
            .unwrap();
        }
        db
    }

    fn legacy_rows(db: &Connection) -> Vec<Vec<rusqlite::types::Value>> {
        db.prepare("SELECT address,subnet,created,nonce,txid,raw,status,height,expiry,receipt_height,receipt_hash FROM claims ORDER BY rowid").unwrap()
            .query_map([], |row| (0..11).map(|index| row.get(index)).collect()).unwrap()
            .collect::<rusqlite::Result<_>>().unwrap()
    }

    #[test]
    fn payout_migration_preserves_claims_receipts_cooldowns_and_count_caps() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        c.hourly_claims = 4;
        c.daily_claims = 4;
        c.lifetime_claims = 4;
        let db = legacy_ledger(&c);
        let before = legacy_rows(&db);
        drop(db);
        c.payout = "1000000000000000".into();
        let sender = crypto::public_key(&[41; 32]).unwrap();
        let mut ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        assert_eq!(
            legacy_rows(&ledger.db),
            before,
            "migration does not rewrite existing claim fields"
        );
        assert_eq!(
            ledger
                .db
                .query_row::<String, _, _>("SELECT value FROM meta WHERE key='payout'", [], |r| r
                    .get(0))
                .unwrap(),
            "1000000000000"
        );
        assert_eq!(
            ledger
                .db
                .query_row::<String, _, _>(
                    "SELECT value FROM meta WHERE key='schema_version'",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            "2"
        );
        for n in 1..=3 {
            assert_eq!(
                ledger.last(&recipient(n)).unwrap().unwrap().amount_hashes,
                "1000000000000"
            );
        }
        let pending = ledger.pending().unwrap().unwrap();
        assert_eq!(pending.raw, record(3, 100_003).raw);
        assert_eq!(pending.nonce, 2);
        assert!(
            ledger
                .eligible(&c, &recipient(1), "fresh-subnet", 100_004)
                .is_err()
        );
        assert!(
            ledger
                .eligible(&c, &recipient(4), "subnet-1", 100_004)
                .is_err()
        );
        let mut newer = record(4, 100_004);
        newer.amount_hashes = c.payout.clone();
        assert!(
            ledger.reserve(&c, &newer, "fresh-subnet").is_err(),
            "old pending claim still blocks new signing"
        );
        finish(&ledger, &pending);
        ledger.reserve(&c, &newer, "fresh-subnet").unwrap();
        finish(&ledger, &newer);
        assert!(
            !ledger.budget(&c, 100_005).unwrap(),
            "old claims still count toward limits"
        );
        drop(ledger);
        c.payout = "2".into();
        let ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        assert_eq!(
            ledger.last(&recipient(1)).unwrap().unwrap().amount_hashes,
            "1000000000000"
        );
        assert_eq!(
            ledger.last(&recipient(4)).unwrap().unwrap().amount_hashes,
            "1000000000000000"
        );
        assert!(
            !ledger.budget(&c, 200_000).unwrap(),
            "lifetime usage survives later payout changes"
        );
    }

    #[test]
    fn payout_migration_rejects_invalid_history_and_unknown_schema_atomically() {
        let dir = TempDir::new().unwrap();
        let c = config(&dir);
        let db = legacy_ledger(&c);
        let before = legacy_rows(&db);
        let sender = crypto::public_key(&[41; 32]).unwrap();
        db.execute("UPDATE meta SET value='bad' WHERE key='payout'", [])
            .unwrap();
        assert!(Ledger::open(&c.database, &[7; 32], &sender, "1000000000000000").is_err());
        assert_eq!(legacy_rows(&db), before);
        assert_eq!(
            db.query_row::<u64, _, _>(
                "SELECT COUNT(*) FROM pragma_table_info('claims') WHERE name='amount_hashes'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        db.execute("DELETE FROM meta WHERE key='payout'", [])
            .unwrap();
        assert!(
            Ledger::open(&c.database, &[7; 32], &sender, &c.payout).is_err(),
            "cannot infer old payments from current config"
        );
        db.execute("INSERT INTO meta VALUES('payout',?1)", [&c.payout])
            .unwrap();
        drop(Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap());
        db.execute("UPDATE meta SET value='3' WHERE key='schema_version'", [])
            .unwrap();
        assert!(Ledger::open(&c.database, &[7; 32], &sender, &c.payout).is_err());
        db.execute("UPDATE meta SET value='2' WHERE key='schema_version'", [])
            .unwrap();
        for invalid in ["0", "", "01", "-1", "1 exa"] {
            db.execute(
                "UPDATE claims SET amount_hashes=?1 WHERE txid=?2",
                params![invalid, record(1, 0).txid],
            )
            .unwrap();
            assert!(
                Ledger::open(&c.database, &[7; 32], &sender, &c.payout).is_err(),
                "invalid historical amount {invalid}"
            );
        }
        db.execute("UPDATE claims SET amount_hashes=?1", [&c.payout])
            .unwrap();
        db.execute("ALTER TABLE claims DROP COLUMN amount_hashes", [])
            .unwrap();
        assert!(
            Ledger::open(&c.database, &[7; 32], &sender, &c.payout).is_err(),
            "v2 must not backfill missing amounts from the old baseline"
        );
    }

    #[test]
    fn shared_subnet_cooldown_is_separate_exact_and_durable() {
        let dir = TempDir::new().unwrap();
        let c = config(&dir);
        let sender = crypto::public_key(&[41; 32]).unwrap();
        let mut ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        let first = record(1, 100_000);
        ledger.reserve(&c, &first, "same-network").unwrap();
        finish(&ledger, &first);
        let wait = cooldown(&ledger.db, &c, &recipient(2), "same-network", 100_013)
            .unwrap()
            .unwrap();
        assert_eq!(wait.retry_after_seconds, 47);
        assert_eq!(wait.scope, "network");
        assert!(
            ledger
                .eligible(&c, &recipient(2), "same-network", 100_059)
                .is_err()
        );
        ledger
            .eligible(&c, &recipient(2), "same-network", 100_060)
            .unwrap();
        let own = cooldown(&ledger.db, &c, &recipient(1), "other-network", 100_060)
            .unwrap()
            .unwrap();
        assert_eq!(own.retry_after_seconds, 86_340);
        assert_eq!(own.scope, "address");
        let second = record(2, 100_060);
        ledger.reserve(&c, &second, "same-network").unwrap();
        finish(&ledger, &second);
        drop(ledger);
        let ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        let other = cooldown(&ledger.db, &c, &recipient(3), "same-network", 100_061)
            .unwrap()
            .unwrap();
        assert_eq!(other.retry_after_seconds, 59);
        let own = cooldown(&ledger.db, &c, &recipient(1), "same-network", 100_061)
            .unwrap()
            .unwrap();
        assert_eq!(own.retry_after_seconds, 86_339);
        assert_eq!(own.scope, "address");
        assert_eq!(
            ledger
                .db
                .query_row::<u64, _, _>("SELECT COUNT(*) FROM claims", [], |r| r.get(0))
                .unwrap(),
            2
        );
        let mut capped = c.clone();
        capped.hourly_claims = 2;
        assert!(!ledger.budget(&capped, 100_061).unwrap());
        assert!(
            ledger
                .eligible(&capped, &recipient(4), "other-network", 100_061)
                .is_err()
        );
        let mut longer_network = c;
        longer_network.subnet_cooldown_seconds = 100_000;
        let wait = cooldown(
            &ledger.db,
            &longer_network,
            &recipient(1),
            "same-network",
            100_061,
        )
        .unwrap()
        .unwrap();
        assert_eq!(wait.retry_after_seconds, 99_999);
        assert_eq!(wait.scope, "network");
    }

    #[test]
    fn signer_rejects_every_changed_intent_field() {
        let sender = crypto::public_key(&[41; 32]).unwrap();
        let operation = Operation::TransferExact {
            recipient: crypto::public_key(&[3; 32]).unwrap(),
            amount: 100u32.into(),
        };
        let good = TransactionBody {
            data: Vec::new(),
            sender,
            nonce: 9,
            anchor: [38; 32],
            expiry_blocks: 2,
            fee: 10u32.into(),
            operation: operation.clone(),
        };
        let verify = |body: &TransactionBody| {
            verify_intent(body, sender, 9, [38; 32], 2, &operation, &10u32.into())
        };
        verify(&good).unwrap();
        let mut free = good.clone();
        free.fee = Amount::zero();
        verify(&free).unwrap();
        for n in 1..9 {
            let mut changed = good.clone();
            match n {
                1 => changed.sender = crypto::public_key(&[4; 32]).unwrap(),
                2 => changed.nonce = 10,
                3 => changed.expiry_blocks = 3,
                4 => changed.fee = 11u32.into(),
                5 => changed.anchor[0] ^= 1,
                6 => {
                    changed.operation = {
                        changed.data = vec![1];
                        operation.clone()
                    }
                }
                7 => {
                    changed.operation = Operation::TransferExact {
                        recipient: sender,
                        amount: 101u32.into(),
                    }
                }
                _ => {
                    changed.operation = Operation::TransferExact {
                        recipient: crypto::public_key(&[5; 32]).unwrap(),
                        amount: 100u32.into(),
                    }
                }
            }
            assert!(verify(&changed).is_err(), "changed field {n}");
        }
    }

    #[derive(Default)]
    struct MockNode {
        height: u64,
        nonce: u64,
        transactions: Vec<Transaction>,
        blocks: BTreeMap<u64, Block>,
        broadcast_error: bool,
        malicious_prepare: bool,
        block_bytes: u64,
        fee_rate: u64,
        interval: u64,
        receipts: usize,
        /// Receipt lookups that named transaction IDs, so the node loaded a block.
        loaded_blocks: usize,
        /// Recipients that already have accounts and pay no creation weight.
        existing: Vec<PublicKey>,
        /// After this many receipt lookups, these blocks replace the branch.
        switch_after: Option<(usize, Vec<Block>)>,
        /// The next receipt lookup signals the first and waits for the second.
        receipt_gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
        /// Admission refusals: the next call of the method is answered with
        /// the status and `Retry-After`, without running.
        refusals: Vec<(&'static str, StatusCode, Option<&'static str>)>,
        prepared: usize,
    }
    fn mock_hash(node: &MockNode, height: u64) -> Hash {
        codec::block_hash(node.blocks.get(&height).unwrap_or(&block(height, vec![])))
    }
    async fn mock_rpc(
        State(node): State<Arc<Mutex<MockNode>>>,
        Json(request): Json<Value>,
    ) -> Response {
        let method = request["method"].as_str().unwrap();
        if method == "blockreceipt" {
            // Waiting here holds nothing, so other calls are answered meanwhile.
            let gate = node.lock().await.receipt_gate.take();
            if let Some((entered, release)) = gate {
                entered.notify_one();
                release.notified().await;
            }
        }
        let mut node = node.lock().await;
        if let Some(index) = node.refusals.iter().position(|(m, ..)| *m == method) {
            let (_, status, retry_after) = node.refusals.remove(index);
            let mut response = (
                status,
                Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"node is busy"}})),
            )
                .into_response();
            if let Some(wait) = retry_after {
                response
                    .headers_mut()
                    .insert("retry-after", HeaderValue::from_static(wait));
            }
            return response;
        }
        let p = &request["params"];
        let result = match method {
            "snapshot" => {
                json!({"status":{"chain_id":hex::encode([7;32]),"height":node.height,"tip":hex::encode(codec::block_hash(node.blocks.get(&node.height).unwrap_or(&block(node.height,vec![])))),"state_root":hex::encode([0;32]),"settings":{"block_bytes":node.block_bytes,"minimum_fee_rate":node.fee_rate,"interval":node.interval}},"payment_available_hash":"1000000000000000000","account":{"account":{"ordinary":"1000000000000000000","nonce":node.nonce}}})
            }
            "preparetransaction" => {
                node.prepared += 1;
                let mut operation: Operation =
                    serde_json::from_value(p["operation"].clone()).unwrap();
                if node.malicious_prepare {
                    operation = Operation::TransferExact {
                        recipient: crypto::public_key(&[17; 32]).unwrap(),
                        amount: 1u32.into(),
                    };
                }
                let new_account = match &operation {
                    Operation::TransferExact { recipient, .. } => {
                        !node.existing.contains(recipient)
                    }
                    _ => true,
                };
                let mut body = TransactionBody {
                    data: Vec::new(),
                    sender: hex::decode(p["sender"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    nonce: p["nonce"].as_u64().unwrap(),
                    anchor: parse_hash(p["anchor"].as_str().unwrap()).unwrap(),
                    expiry_blocks: p["expiry_blocks"].as_u64().unwrap(),
                    fee: Amount::zero(),
                    operation,
                };
                {
                    // The automatic fee pays for its own encoded length, as on a node.
                    let weight = loop {
                        let encoded = codec::encode(&Transaction {
                            body: body.clone(),
                            signature: [0; 64],
                        });
                        let weight = encoded.len() as u64
                            + if new_account { fees::ACCOUNT_WEIGHT } else { 0 };
                        let fee = (Amount::from(weight) * node.fee_rate
                            + Amount::from(fees::FEE_SCALE - 1))
                            / fees::FEE_SCALE;
                        if fee == body.fee {
                            break weight;
                        }
                        body.fee = fee;
                    };
                    let mut result =
                        serde_json::to_value(wallet::unsigned(&body, &[7; 32])).unwrap();
                    result["fee_quote"] = json!({"chain_id":hex::encode([7; 32]),"tip":hex::encode(body.anchor),"anchor":hex::encode(body.anchor),"state_root":hex::encode([0;32]),"height":node.height,"anchor_height":node.height,"expiry_blocks":body.expiry_blocks,"expiry_height":node.height.checked_add(body.expiry_blocks).unwrap(),"weight":weight.to_string()});
                    result
                }
            }
            "broadcasttransaction" => {
                let transaction =
                    wallet::decode_signed(p["raw"].as_str().unwrap(), &[7; 32]).unwrap();
                let txid = codec::transaction_id(&transaction);
                if !node
                    .transactions
                    .iter()
                    .any(|t| codec::transaction_id(t) == txid)
                {
                    node.transactions.push(transaction);
                }
                if node.broadcast_error {
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                json!({"transaction_id":hex::encode(txid)})
            }
            // Whole blocks are never requested: getblock is deliberately absent.
            "blockreceipt" => {
                node.receipts += 1;
                let height = p["height"].as_u64().unwrap();
                let ids = p["txids"].as_array().unwrap();
                // The node's own limits: active heights and at most 64 IDs.
                if height > node.height || ids.len() > crate::node::MAX_RECEIPT_TXIDS {
                    return Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"invalid receipt request"}})).into_response();
                }
                if !ids.is_empty() {
                    node.loaded_blocks += 1;
                }
                let block = node
                    .blocks
                    .get(&height)
                    .cloned()
                    .unwrap_or_else(|| block(height, vec![]));
                let included = ids
                    .iter()
                    .map(|id| {
                        block
                            .transactions
                            .iter()
                            .any(|t| hex::encode(codec::transaction_id(t)) == id.as_str().unwrap())
                    })
                    .collect::<Vec<_>>();
                let hash = hex::encode(codec::block_hash(&block));
                let mut result = json!({"height":height,"hash":hash,"included":included});
                if let Some(checked) = p.get("checked") {
                    let at = checked["height"].as_u64().unwrap();
                    let canonical = at <= node.height
                        && hex::encode(mock_hash(&node, at)) == checked["hash"].as_str().unwrap();
                    result["checked_canonical"] = json!(canonical);
                }
                if node
                    .switch_after
                    .as_ref()
                    .is_some_and(|(after, ..)| node.receipts >= *after)
                {
                    let (_, branch) = node.switch_after.take().unwrap();
                    for replacement in branch {
                        node.blocks.insert(replacement.height, replacement);
                    }
                }
                result
            }
            other => panic!("unexpected RPC {other}"),
        };
        Json(json!({"jsonrpc":"2.0","id":1,"result":result})).into_response()
    }
    async fn mock() -> (Arc<Mutex<MockNode>>, SocketAddr, JoinHandle<()>) {
        let node = Arc::new(Mutex::new(MockNode {
            height: 1,
            block_bytes: 16_384,
            fee_rate: 1,
            interval: 15,
            ..Default::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routes = Router::new()
            .route("/rpc", post(mock_rpc))
            .with_state(node.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        (node, address, task)
    }
    fn block(height: u64, transactions: Vec<Transaction>) -> Block {
        Block {
            header: Header {
                version: 1,
                previous: [0; 32],
                merkle_root: [0; 32],
                timestamp: 0,
                bits: 0x2100ffff,
                nonce: height as u32,
            },
            height,
            miner: crypto::public_key(&[41; 32]).unwrap(),
            state_root: [0; 32],
            extranonce: [0; 8],
            transactions,
        }
    }

    #[tokio::test]
    async fn uncertain_submission_survives_restart_and_confirmation_requires_actual_receipt() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "waiting_for_mining");
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "ready");
        node.lock().await.broadcast_error = true;
        let result = engine.claim(&recipient(3), "a").await.unwrap();
        assert_eq!(result["status"], "pending");
        let raw = engine.ledger.pending().unwrap().unwrap().raw;
        assert_eq!(node.lock().await.transactions.len(), 1);
        drop(engine);
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        assert_eq!(engine.ledger.pending().unwrap().unwrap().raw, raw);
        let repeated = engine.claim(&recipient(3), "another-subnet").await.unwrap();
        assert_eq!(repeated["txid"], result["txid"]);
        assert!(engine.claim(&recipient(4), "b").await.is_err());
        {
            let mut node = node.lock().await;
            node.height = 3;
            node.broadcast_error = false;
        }
        engine.refresh().await.unwrap();
        assert_eq!(node.lock().await.transactions.len(), 1); // identical rebroadcast, no replacement
        {
            let mut node = node.lock().await;
            node.nonce = 1;
            let transactions = node.transactions.clone();
            node.blocks.insert(3, block(3, transactions));
        }
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "pending"
        );
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "confirmed"
        );
        assert!(engine.ledger.pending().unwrap().is_none());
        // A replacement block that still contains the payment only moves its
        // receipt. It neither pauses payouts nor pays the recipient again.
        node.lock().await.blocks.get_mut(&3).unwrap().header.nonce = 99;
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let moved: String = engine
            .ledger
            .db
            .query_row(
                "SELECT receipt_hash FROM claims WHERE status='confirmed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            moved,
            hex::encode(codec::block_hash(&node.lock().await.blocks[&3]))
        );
        // A canonical receipt is verified by its block hash alone, which commits
        // to the payment; no block body is loaded.
        let loaded = node.lock().await.loaded_blocks;
        engine.refresh().await.unwrap();
        assert_eq!(node.lock().await.loaded_blocks, loaded);
        assert_eq!(
            engine.claim(&recipient(3), "a").await.unwrap()["txid"],
            result["txid"]
        );
        assert_eq!(
            engine.claim(&recipient(4), "b").await.unwrap()["status"],
            "pending"
        );
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 1);
        assert_eq!(node.lock().await.transactions.len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn changed_payout_retries_original_pending_bytes_and_preserves_mixed_receipts() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        node.lock().await.broadcast_error = true;
        let original = engine.claim(&recipient(3), "old-subnet").await.unwrap();
        let original_raw = engine.ledger.pending().unwrap().unwrap().raw;
        assert_eq!(original["amount_hashes"], "1000000000000");
        drop(engine);
        // Recreate the previous release's exact schema around this genuine
        // signed, ambiguously submitted claim to exercise the upgrade path.
        let db = Connection::open(&c.database).unwrap();
        db.execute("ALTER TABLE claims DROP COLUMN amount_hashes", [])
            .unwrap();
        db.execute("DELETE FROM meta WHERE key='schema_version'", [])
            .unwrap();
        let before = legacy_rows(&db);
        drop(db);
        c.payout = "1000000000000000".into();
        c.expiry_blocks = 7;
        let mut engine = Engine::open(c.clone()).unwrap();
        assert_eq!(legacy_rows(&engine.ledger.db), before);
        engine.refresh().await.unwrap();
        let status = engine.status(Some(&recipient(3)), "old-subnet").unwrap();
        assert_eq!(status["amount_hashes"], c.payout);
        assert_eq!(status["claim"]["amount_hashes"], "1000000000000");
        let duplicate = engine.claim(&recipient(3), "fresh-subnet").await.unwrap();
        assert_eq!(duplicate["txid"], original["txid"]);
        assert_eq!(duplicate["amount_hashes"], "1000000000000");
        assert!(duplicate["retry_after_seconds"].as_u64().unwrap() > 86_000);
        node.lock().await.height = 3;
        engine.refresh().await.unwrap();
        assert_eq!(engine.ledger.pending().unwrap().unwrap().raw, original_raw);
        assert_eq!(node.lock().await.transactions.len(), 1);
        {
            let mut node = node.lock().await;
            node.nonce = 1;
            node.height = 4;
            let transactions = node.transactions.clone();
            node.blocks.insert(3, block(3, transactions));
            node.broadcast_error = false;
        }
        engine.refresh().await.unwrap();
        let confirmed = engine.claim(&recipient(3), "fresh-subnet").await.unwrap();
        assert_eq!(confirmed["status"], "confirmed");
        assert_eq!(confirmed["amount_hashes"], "1000000000000");
        assert!(engine.claim(&recipient(4), "old-subnet").await.is_err());
        let newer = engine.claim(&recipient(4), "fresh-subnet").await.unwrap();
        assert_eq!(newer["amount_hashes"], "1000000000000000");
        let claim = engine.ledger.pending().unwrap().unwrap();
        let tx = wallet::decode_signed(&claim.raw, &[7; 32]).unwrap();
        assert_eq!(tx.body.nonce, 1);
        assert_eq!(
            tx.body.operation.clone(),
            Operation::TransferExact {
                recipient: address::decode(&recipient(4), &[7; 32]).unwrap(),
                amount: amount("1000000000000000").unwrap(),
            }
        );
        drop(engine);
        let mut engine = Engine::open(c).unwrap();
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "old-subnet").unwrap()["claim"]["amount_hashes"],
            "1000000000000"
        );
        assert_eq!(
            engine.status(Some(&recipient(4)), "fresh-subnet").unwrap()["claim"]["amount_hashes"],
            "1000000000000000"
        );
        assert_eq!(engine.ledger.pending().unwrap().unwrap().raw, claim.raw);
        assert_eq!(node.lock().await.transactions.len(), 2);
        // Stored amounts are checked against the signed fixed intent before a retry.
        engine
            .ledger
            .db
            .execute(
                "UPDATE claims SET amount_hashes='1' WHERE txid=?1",
                [&claim.txid],
            )
            .unwrap();
        node.lock().await.height = 5;
        assert!(engine.refresh().await.is_err());
        assert_eq!(node.lock().await.transactions.len(), 2);
        task.abort();
    }

    #[tokio::test]
    async fn expiry_keeps_quotas_and_shorter_chains_wait_without_new_bytes() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        let result = engine.claim(&recipient(3), "a").await.unwrap();
        node.lock().await.height = 4; // The next block is outside the signed two-block window.
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "expired"
        );
        assert_eq!(
            engine.claim(&recipient(3), "a").await.unwrap()["txid"],
            result["txid"]
        );
        assert!(engine.claim(&recipient(4), "a").await.is_err()); // subnet quota survived expiry
        engine.claim(&recipient(4), "b").await.unwrap();
        assert_eq!(node.lock().await.transactions.len(), 2);
        // A chain below the anchor neither pauses the faucet nor signs new bytes.
        // The identical bytes wait out their lifetime on whichever chain wins.
        node.lock().await.height = 3;
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        assert_eq!(engine.state().unwrap(), "pending");
        assert!(engine.claim(&recipient(5), "c").await.is_err());
        assert_eq!(node.lock().await.transactions.len(), 2);
        node.lock().await.height = 6;
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(4)), "b").unwrap()["claim"]["status"],
            "expired"
        );
        engine.claim(&recipient(5), "c").await.unwrap();
        // The next payment reuses the unconsumed nonce, so only one can ever apply.
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 0);
        assert_eq!(node.lock().await.transactions.len(), 3);
        task.abort();
    }

    #[tokio::test]
    async fn changed_quote_or_unrepresentable_ledger_expiry_never_signs_or_reserves() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        node.lock().await.height = 3;
        assert!(
            engine
                .claim(&recipient(3), "a")
                .await
                .unwrap_err()
                .to_string()
                .contains("snapshot changed")
        );
        assert!(engine.ledger.pending().unwrap().is_none());
        assert!(node.lock().await.transactions.is_empty());
        engine.refresh().await.unwrap();
        engine.config.expiry_blocks = i64::MAX as u64;
        assert!(
            engine
                .claim(&recipient(3), "a")
                .await
                .unwrap_err()
                .to_string()
                .contains("ledger integer storage")
        );
        engine.config.expiry_blocks = u64::MAX;
        assert!(
            engine
                .claim(&recipient(3), "a")
                .await
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
        assert!(engine.ledger.pending().unwrap().is_none());
        assert!(node.lock().await.transactions.is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn orphaned_pending_anchor_expires_without_replacement_signing() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        engine.claim(&recipient(3), "a").await.unwrap();
        let raw = engine.ledger.pending().unwrap().unwrap().raw;
        let mut replaced = block(2, vec![]);
        replaced.header.nonce = 99;
        node.lock().await.blocks.insert(2, replaced);
        // A routine one-block reorganization orphans the anchor. The bytes can
        // never apply on the new branch; they wait out their lifetime and expire.
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        assert_eq!(engine.state().unwrap(), "pending");
        assert_eq!(engine.ledger.pending().unwrap().unwrap().raw, raw);
        assert_eq!(node.lock().await.transactions.len(), 1);
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        assert!(engine.ledger.pending().unwrap().is_none());
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "expired"
        );
        assert_eq!(engine.state().unwrap(), "ready");
        engine.claim(&recipient(4), "b").await.unwrap();
        let next = wallet::decode_signed(&engine.ledger.pending().unwrap().unwrap().raw, &[7; 32])
            .unwrap();
        assert_eq!(next.body.nonce, 0);
        assert_eq!(next.body.anchor, codec::block_hash(&block(4, vec![])));
        assert_eq!(node.lock().await.transactions.len(), 2);
        // A restart applies the same accounting instead of pausing.
        drop(engine);
        let mut engine = Engine::open(c).unwrap();
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        task.abort();
    }

    #[tokio::test]
    async fn malicious_preparation_is_not_signed_or_reserved() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c).unwrap();
        engine.refresh().await.unwrap();
        {
            let mut node = node.lock().await;
            node.height = 2;
            node.malicious_prepare = true;
        }
        engine.refresh().await.unwrap();
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        assert!(engine.ledger.pending().unwrap().is_none());
        assert!(node.lock().await.transactions.is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn status_and_claim_share_exact_cooldown_without_leaking_other_claims() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (mock_node, rpc, mock_task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c).unwrap();
        engine.refresh().await.unwrap();
        mock_node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));
        let network = private_client_subnet(&engine.subnet_key, &headers).unwrap();
        let first = record(1, now() - 17);
        engine
            .ledger
            .reserve(&engine.config.clone(), &first, &network)
            .unwrap();
        finish(&engine.ledger, &first);
        let app = App::new(
            engine,
            vec!["https://faucet.example".into()],
            vec!["faucet.example".into()],
        );
        let engine = app.engine.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router(app)).await.unwrap();
        });
        let client = reqwest::Client::new();
        let base = format!("http://{local}");
        let before = now();
        let response = client
            .get(format!("{base}/faucet/status"))
            .query(&[("address", recipient(2))])
            .header("host", "faucet.example")
            .header("x-real-ip", "192.0.2.222")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let status: Value = response.json().await.unwrap();
        let after = now();
        assert_eq!(status["state"], "cooldown");
        assert_eq!(status["available"], false);
        assert_eq!(status["cooldown_scope"], "network");
        let retry = status["retry_after_seconds"].as_i64().unwrap();
        assert!((first.created + 60 - after..=first.created + 60 - before).contains(&retry));
        assert!(status.get("claim").is_none());
        assert!(status.get("diagnostic").is_none());
        let rendered = status.to_string();
        for private in [&first.address, &first.txid, &network, "192.0.2"] {
            assert!(!rendered.contains(private));
        }
        let before = now();
        let denied = client
            .post(format!("{base}/faucet/claim"))
            .header("host", "faucet.example")
            .header("origin", "https://faucet.example")
            .header("x-real-ip", "192.0.2.42")
            .json(&json!({"address":recipient(2)}))
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::TOO_MANY_REQUESTS);
        let header_retry = denied.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<i64>()
            .unwrap();
        let body: Value = denied.json().await.unwrap();
        let after = now();
        assert_eq!(body["retry_after_seconds"], header_retry);
        assert!((first.created + 60 - after..=first.created + 60 - before).contains(&header_retry));
        assert_eq!(body["cooldown_scope"], "network");
        assert!(mock_node.lock().await.transactions.is_empty());
        let own: Value = client
            .get(format!("{base}/faucet/status"))
            .query(&[("address", recipient(1))])
            .header("host", "faucet.example")
            .header("x-real-ip", "198.51.100.1")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(own["cooldown_scope"], "address");
        assert_eq!(own["claim"]["txid"], first.txid);
        assert!(own["retry_after_seconds"].as_u64().unwrap() > 86_000);
        // Advance the fixture's stored claim age without waiting a real minute.
        engine
            .lock()
            .await
            .ledger
            .db
            .execute(
                "UPDATE claims SET created=?1 WHERE txid=?2",
                params![now() - 61, first.txid],
            )
            .unwrap();
        let ready: Value = client
            .get(format!("{base}/faucet/status"))
            .query(&[("address", recipient(2))])
            .header("host", "faucet.example")
            .header("x-real-ip", "192.0.2.9")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(ready["available"], true);
        assert_eq!(ready["retry_after_seconds"], 0);
        assert!(ready.get("claim").is_none());
        let paid = client
            .post(format!("{base}/faucet/claim"))
            .header("host", "faucet.example")
            .header("origin", "https://faucet.example")
            .header("x-real-ip", "192.0.2.9")
            .json(&json!({"address":recipient(2)}))
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), StatusCode::OK);
        let paid: Value = paid.json().await.unwrap();
        assert_eq!(paid["status"], "pending");
        assert_eq!(mock_node.lock().await.transactions.len(), 1);
        assert_eq!(
            engine
                .lock()
                .await
                .ledger
                .db
                .query_row::<u64, _, _>("SELECT COUNT(*) FROM claims", [], |r| r.get(0))
                .unwrap(),
            2
        );
        task.abort();
        mock_task.abort();
    }

    #[tokio::test]
    async fn http_rejects_cross_origin_missing_ip_unknown_fields_and_large_bodies() {
        let dir = TempDir::new().unwrap();
        let c = config(&dir);
        let app = App::new(
            Engine::open(c).unwrap(),
            vec!["https://faucet.example".into()],
            vec!["faucet.example".into()],
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router(app)).await.unwrap();
        });
        let client = reqwest::Client::new();
        let base = format!("http://{local}");
        let result = client
            .get(format!("{base}/faucet/status"))
            .header("host", "faucet.example")
            .header("x-real-ip", "192.0.2.1")
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let body: Value = result.json().await.unwrap();
        assert_eq!(body["state"], "waiting_for_mining");
        let post = || {
            client
                .post(format!("{base}/faucet/claim"))
                .header("host", "faucet.example")
        };
        assert_eq!(
            post()
                .header("x-real-ip", "192.0.2.1")
                .json(&json!({"address":recipient(3)}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post()
                .header("origin", "https://evil.example")
                .header("x-real-ip", "192.0.2.1")
                .json(&json!({"address":recipient(3)}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post()
                .header("origin", "https://faucet.example")
                .json(&json!({"address":recipient(3)}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let authorized = || {
            post()
                .header("origin", "https://faucet.example")
                .header("x-real-ip", "192.0.2.1")
        };
        assert_eq!(
            authorized()
                .json(&json!({"address":recipient(3),"amount":"100"}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            authorized()
                .json(&json!({"address":"x".repeat(2000)}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            authorized()
                .json(&json!({"address":recipient(3)}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let preflight = client
            .request(Method::OPTIONS, format!("{base}/faucet/claim"))
            .header("host", "faucet.example")
            .header("origin", "https://faucet.example")
            .header("x-real-ip", "192.0.2.1")
            .send()
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight.headers()["access-control-allow-origin"],
            "https://faucet.example"
        );
        task.abort();
    }

    async fn ready_engine(
        dir: &TempDir,
        adjust: impl FnOnce(&mut FaucetConfig),
    ) -> (Engine, FaucetConfig, Arc<Mutex<MockNode>>, JoinHandle<()>) {
        let mut c = config(dir);
        adjust(&mut c);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "ready");
        (engine, c, node, task)
    }

    #[tokio::test]
    async fn foreign_nonce_spend_pauses_without_rescanning_until_accepted() {
        let dir = TempDir::new().unwrap();
        let (mut engine, c, node, task) = ready_engine(&dir, |c| c.expiry_blocks = 200).await;
        engine.claim(&recipient(3), "a").await.unwrap();
        // Another signer consumed the nonce; the recorded bytes never appear.
        {
            let mut node = node.lock().await;
            node.nonce = 1;
            node.height = 150;
        }
        // The long lifetime window is inspected in bounded steps.
        engine.refresh().await.unwrap();
        assert_eq!(engine.fault, Some("verifying_payments"));
        engine.refresh().await.unwrap();
        let error = engine.refresh().await.unwrap_err();
        assert_eq!(engine.fault, Some("nonce_conflict"));
        let mut diagnostics = RefreshDiagnostics::default();
        diagnostics.record(&error, 1, Instant::now());
        assert_eq!(diagnostics.error.unwrap().category, "nonce_conflict");
        assert_eq!(engine.state().unwrap(), "unavailable");
        assert!(engine.claim(&recipient(4), "b").await.is_err());
        // A completed search is not repeated: one canonical check per refresh,
        // answered from the node's index without loading a block.
        let (before, loaded) = {
            let node = node.lock().await;
            (node.receipts, node.loaded_blocks)
        };
        for _ in 0..3 {
            assert!(engine.refresh().await.is_err());
        }
        assert_eq!(node.lock().await.receipts - before, 3);
        assert_eq!(node.lock().await.loaded_blocks, loaded);
        assert_eq!(node.lock().await.transactions.len(), 1);
        // After review the operator accepts the external spend; nothing is deleted.
        let summary = maintain(&c, Maintenance::AcceptSpentNonce(0)).unwrap();
        assert_eq!(summary["nonce_floor"], "1");
        assert_eq!(summary["claims"]["expired"], 1);
        assert!(summary["pending"].is_null());
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        assert_eq!(engine.state().unwrap(), "ready");
        engine.claim(&recipient(4), "b").await.unwrap();
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 1);
        task.abort();
    }

    #[tokio::test]
    async fn expired_claim_included_after_reorganization_is_confirmed_once() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let first = engine.claim(&recipient(3), "a").await.unwrap();
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "expired"
        );
        engine.claim(&recipient(4), "b").await.unwrap();
        assert_eq!(node.lock().await.transactions.len(), 2);
        // A competing branch that included the first payment becomes canonical.
        {
            let mut node = node.lock().await;
            let mut branch = block(3, vec![node.transactions[0].clone()]);
            branch.header.nonce = 77;
            node.blocks.insert(3, branch);
            node.nonce = 1;
            node.height = 6;
        }
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let paid = engine.status(Some(&recipient(3)), "a").unwrap();
        assert_eq!(paid["claim"]["status"], "confirmed");
        assert_eq!(paid["claim"]["txid"], first["txid"]);
        // The same-nonce replacement can never apply, so it is not reported paid.
        assert!(engine.ledger.pending().unwrap().is_none());
        assert_eq!(
            engine.status(Some(&recipient(4)), "b").unwrap()["claim"]["status"],
            "expired"
        );
        engine.claim(&recipient(5), "c").await.unwrap();
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 1);
        task.abort();
    }

    #[tokio::test]
    async fn reorganized_receipt_without_its_payment_is_retried_then_expired() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let first = engine.claim(&recipient(3), "a").await.unwrap();
        {
            let mut node = node.lock().await;
            let transactions = node.transactions.clone();
            node.blocks.insert(3, block(3, transactions));
            node.nonce = 1;
            node.height = 4;
        }
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "confirmed"
        );
        // A node behind the receipt pauses until it can show the payment again.
        node.lock().await.height = 2;
        assert!(engine.refresh().await.is_err());
        assert_eq!(engine.fault, Some("node_behind_ledger"));
        assert_eq!(engine.state().unwrap(), "unavailable");
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        // The receipt block is replaced without the payment and the nonce is
        // unused again. The bytes are retried while valid, then expire.
        {
            let mut node = node.lock().await;
            let mut branch = block(3, vec![]);
            branch.header.nonce = 55;
            node.blocks.insert(3, branch);
            node.nonce = 0;
        }
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "expired"
        );
        engine.claim(&recipient(4), "b").await.unwrap();
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 0);
        assert_ne!(next.txid, first["txid"]);
        task.abort();
    }

    #[tokio::test]
    async fn payment_included_at_its_expiry_height_confirms_instead_of_expiring() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        engine.claim(&recipient(3), "a").await.unwrap();
        {
            let mut node = node.lock().await;
            let transactions = node.transactions.clone();
            node.blocks.insert(4, block(4, transactions));
            node.nonce = 1;
            node.height = 4;
        }
        // Included in the last block of its lifetime, below confirmation depth.
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "pending"
        );
        node.lock().await.height = 5;
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "confirmed"
        );
        task.abort();
    }

    #[tokio::test]
    async fn more_same_nonce_claims_than_one_receipt_lookup_names_still_settle() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        // Congestion keeps each payment out of its two-block window, so every
        // claim expires with its nonce unused and the next one signs it again.
        let expired = crate::node::MAX_RECEIPT_TXIDS + 6;
        for n in 0..expired {
            engine
                .claim(&recipient(100 + n as u8), &format!("net-{n}"))
                .await
                .unwrap();
            node.lock().await.height += 2;
            engine.refresh().await.unwrap();
            assert!(engine.ledger.pending().unwrap().is_none());
        }
        let paid = engine.claim(&recipient(200), "net-paid").await.unwrap();
        assert_eq!(engine.ledger.unsettled(0).unwrap().len(), expired + 1);
        {
            let mut node = node.lock().await;
            let payment = node.transactions.last().unwrap().clone();
            let at = node.height + 1;
            node.blocks.insert(at, block(at, vec![payment]));
            node.nonce = 1;
            node.height = at + 1;
        }
        // Each lookup names only the claims whose window covers its height, so
        // none exceeds the node's limit, and the windows are searched in steps.
        for _ in 0..2 {
            engine.refresh().await.unwrap();
            assert_eq!(engine.fault, Some("verifying_payments"));
        }
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let status = engine.status(Some(&recipient(200)), "net-paid").unwrap();
        assert_eq!(status["claim"]["status"], "confirmed");
        assert_eq!(status["claim"]["txid"], paid["txid"]);
        assert_eq!(engine.ledger.unsettled(0).unwrap().len(), expired);
        engine.claim(&recipient(201), "net-next").await.unwrap();
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 1);
        task.abort();
    }

    #[tokio::test]
    async fn an_old_expired_claim_does_not_widen_the_inclusion_search() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        engine.claim(&recipient(3), "a").await.unwrap();
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        // Visitors return long after that claim expired; the next claim signs
        // the same unused nonce.
        node.lock().await.height = 5_000;
        engine.refresh().await.unwrap();
        let paid = engine.claim(&recipient(4), "b").await.unwrap();
        let before = {
            let mut node = node.lock().await;
            let payment = node.transactions[1].clone();
            node.blocks.insert(5_001, block(5_001, vec![payment]));
            node.nonce = 1;
            node.height = 5_002;
            node.receipts
        };
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let status = engine.status(Some(&recipient(4)), "b").unwrap();
        assert_eq!(status["claim"]["status"], "confirmed");
        assert_eq!(status["claim"]["txid"], paid["txid"]);
        // Only heights inside a recorded window are inspected: 3, 4 and 5,001.
        assert_eq!(node.lock().await.receipts - before, 3);
        task.abort();
    }

    #[tokio::test]
    async fn branch_switch_between_receipt_lookups_restarts_the_search() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let first = engine.claim(&recipient(3), "a").await.unwrap();
        {
            let mut node = node.lock().await;
            let payment = node.transactions[0].clone();
            node.blocks.insert(4, block(4, vec![payment.clone()]));
            // Height 3 is inspected on this branch. Before height 4 is, the node
            // switches to one that includes the payment at height 3 instead.
            let mut moved = block(3, vec![payment]);
            moved.header.nonce = 88;
            let mut empty = block(4, vec![]);
            empty.header.nonce = 89;
            node.switch_after = Some((node.receipts + 1, vec![moved, empty]));
            node.nonce = 1;
            node.height = 4;
        }
        // Blocks of two branches never prove the payment absent, so the search
        // starts again on the new branch and finds it.
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let paid = engine.status(Some(&recipient(3)), "a").unwrap();
        assert_eq!(paid["claim"]["status"], "confirmed");
        assert_eq!(paid["claim"]["txid"], first["txid"]);
        let receipt: String = engine
            .ledger
            .db
            .query_row(
                "SELECT receipt_hash FROM claims WHERE status='confirmed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipt, hex::encode(mock_hash(&*node.lock().await, 3)));
        task.abort();
    }

    #[test]
    fn local_payout_estimate_matches_consensus_fee_rules() {
        let dir = TempDir::new().unwrap();
        let mut engine = Engine::open(config(&dir)).unwrap();
        let chain = crate::config::Config::devnet();
        let mut state = crate::state::State::genesis(&chain);
        engine.tip = Some([3; 32]);
        let existing = crypto::public_key(&[10; 32]).unwrap();
        state.world.put(existing, Default::default(), &chain).unwrap();
        for (rate, nonce, payout) in [
            (1, 0, "1"),
            (7, 300, "1000000000000"),
            (900_000, u64::MAX - 1, "5"),
        ] {
            state.settings.minimum_fee_rate = rate;
            engine.settings = Some(NodeSettings {
                block_bytes: 16_384,
                minimum_fee_rate: rate,
                interval: 15,
            });
            engine.nonce = nonce;
            engine.payout = amount(payout).unwrap();
            for (new_account, recipient) in [
                (true, crypto::public_key(&[9; 32]).unwrap()),
                (false, existing),
            ] {
                let (weight, fee) = engine.payout_requirements(new_account).unwrap().unwrap();
                let body = TransactionBody {
                    sender: engine.sender,
                    nonce,
                    fee: fee.clone(),
                    anchor: [3; 32],
                    expiry_blocks: engine.config.expiry_blocks,
                    operation: Operation::TransferExact {
                        recipient,
                        amount: engine.payout.clone(),
                    },
                    data: Vec::new(),
                };
                let quote = fees::quote(
                    &chain,
                    &state,
                    &Transaction {
                        body,
                        signature: [0; 64],
                    },
                )
                .unwrap();
                assert_eq!(
                    (quote.weight, quote.minimum_fee),
                    (weight, fee),
                    "rate {rate}, new account {new_account}"
                );
            }
        }
    }

    #[tokio::test]
    async fn governed_fee_and_capacity_limits_pause_before_signing_or_reserving() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let (weight, fee) = engine.payout_requirements(true).unwrap().unwrap();
        assert!(weight > fees::ACCOUNT_WEIGHT && fee == 2u32.into());
        let (light, _) = engine.payout_requirements(false).unwrap().unwrap();
        assert_eq!(light + fees::ACCOUNT_WEIGHT, weight);
        // Recipient 9 already has an account, so its payment is lighter.
        node.lock()
            .await
            .existing
            .push(address::decode(&recipient(9), &[7; 32]).unwrap());
        let refused = |engine: &Engine| {
            assert!(engine.ledger.last(&recipient(3)).unwrap().is_none());
            assert!(engine.ledger.last(&recipient(9)).unwrap().is_none());
        };
        // A higher governed fee rate exceeds the operator's allowance for a new
        // account. That claim is refused at its exact quote without reserving.
        node.lock().await.fee_rate = 1_000_000;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "fee_cap_exceeded");
        assert_eq!(engine.status(None, "a").unwrap()["available"], false);
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        refused(&engine);
        // When even an existing account's payment exceeds it, nothing is prepared.
        node.lock().await.fee_rate = 10_000_000;
        engine.refresh().await.unwrap();
        assert_eq!(engine.availability().unwrap(), "fee_cap_exceeded");
        assert!(engine.claim(&recipient(9), "a").await.is_err());
        refused(&engine);
        // Capacity below a payment's weight could never include it.
        {
            let mut node = node.lock().await;
            node.fee_rate = 1;
            node.block_bytes = light - 1;
        }
        engine.refresh().await.unwrap();
        assert_eq!(engine.availability().unwrap(), "capacity_exceeded");
        assert!(engine.claim(&recipient(9), "a").await.is_err());
        node.lock().await.block_bytes = weight - 1;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "capacity_exceeded");
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        refused(&engine);
        assert!(node.lock().await.transactions.is_empty());
        node.lock().await.block_bytes = weight;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "ready");
        // The status states describe a new account's payment. A claim to an
        // existing account that fits is still paid while either state holds.
        node.lock().await.block_bytes = weight - 1;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "capacity_exceeded");
        assert_eq!(
            engine.claim(&recipient(9), "a").await.unwrap()["status"],
            "pending"
        );
        assert_eq!(node.lock().await.transactions.len(), 1);
        task.abort();
    }

    #[test]
    fn mining_freshness_follows_the_governed_interval() {
        let dir = TempDir::new().unwrap();
        let mut engine = Engine::open(config(&dir)).unwrap();
        let Some(earlier) = Instant::now().checked_sub(Duration::from_secs(1000)) else {
            return;
        };
        engine.last_advance = Some(earlier);
        engine.last_success = Some(Instant::now());
        let settings = |interval| NodeSettings {
            block_bytes: 16_384,
            minimum_fee_rate: 1,
            interval,
        };
        engine.settings = Some(settings(15));
        assert!(!engine.mining());
        engine.settings = Some(settings(60));
        assert!(!engine.mining());
        // Hour-long blocks keep twelve intervals of freshness, past the 3600 s cap.
        engine.settings = Some(settings(3600));
        assert!(engine.mining());
    }

    #[tokio::test]
    async fn clock_behind_recorded_claims_pauses_until_the_operator_clamps() {
        let dir = TempDir::new().unwrap();
        let (mut engine, c, _node, task) = ready_engine(&dir, |_| {}).await;
        // Within the tolerance the quota clock simply never moves backwards.
        let ahead = record(1, now() + 100);
        engine.ledger.reserve(&c, &ahead, "early").unwrap();
        finish(&engine.ledger, &ahead);
        assert!(engine.ledger.clock(now()).unwrap() >= ahead.created);
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        // Claims from a clock that ran far ahead pause payouts instead of
        // extending every window until that false time passes.
        let future = record(2, now() + 30 * 86_400);
        engine.ledger.reserve(&c, &future, "later").unwrap();
        finish(&engine.ledger, &future);
        assert!(engine.refresh().await.is_err());
        assert_eq!(engine.fault, Some("clock_behind_ledger"));
        assert_eq!(engine.state().unwrap(), "unavailable");
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        let summary = maintain(&c, Maintenance::ClampFutureClaims).unwrap();
        assert!(summary["latest_created"].as_i64().unwrap() <= now());
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        assert_eq!(engine.state().unwrap(), "ready");
        // Clamped claims restart their cooldowns from the corrected time.
        let wait = cooldown(&engine.ledger.db, &c, &recipient(2), "later", now())
            .unwrap()
            .unwrap();
        assert!(wait.retry_after_seconds > 86_000 && wait.retry_after_seconds <= 86_400);
        engine.claim(&recipient(3), "a").await.unwrap();
        task.abort();
    }

    #[test]
    fn each_client_network_receives_only_a_share_of_the_daily_allowance() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        c.subnet_daily_claims = 3;
        let sender = crypto::public_key(&[41; 32]).unwrap();
        let mut ledger = Ledger::open(&c.database, &[7; 32], &sender, &c.payout).unwrap();
        for index in ["claim_created", "claim_nonce", "claim_receipt"] {
            assert_eq!(
                ledger
                    .db
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?1",
                        [index],
                        |r| r.get::<_, u64>(0)
                    )
                    .unwrap(),
                1
            );
        }
        // Every refresh reads the newest receipt from its partial index instead
        // of sorting all confirmed claims.
        let plan = ledger
            .db
            .prepare(&format!(
                "EXPLAIN QUERY PLAN SELECT {CLAIM_COLUMNS},receipt_height,receipt_hash FROM claims WHERE status='confirmed' ORDER BY receipt_height DESC,rowid DESC LIMIT 1"
            ))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains("claim_receipt"))
                && !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "{plan:?}"
        );
        let start = 1_000_000;
        for n in 0..3u8 {
            let claim = record(n + 1, start + 60 * i64::from(n));
            ledger.reserve(&c, &claim, "net").unwrap();
            finish(&ledger, &claim);
        }
        assert_eq!(ledger.lifetime, 3);
        // Fresh addresses no longer bypass the network's daily share.
        let wait = cooldown(&ledger.db, &c, &recipient(9), "net", start + 180)
            .unwrap()
            .unwrap();
        assert_eq!(wait.scope, "network");
        assert_eq!(wait.retry_after_seconds, 86_400 - 180);
        assert!(ledger.reserve(&c, &record(9, start + 180), "net").is_err());
        ledger
            .eligible(&c, &recipient(9), "other", start + 180)
            .unwrap();
        let last = cooldown(&ledger.db, &c, &recipient(9), "net", start + 86_399)
            .unwrap()
            .unwrap();
        assert_eq!(last.retry_after_seconds, 1);
        ledger
            .eligible(&c, &recipient(9), "net", start + 86_400)
            .unwrap();
        // A smaller share counts every claim still inside the window.
        c.subnet_daily_claims = 1;
        let smaller = cooldown(&ledger.db, &c, &recipient(9), "net", start + 86_400)
            .unwrap()
            .unwrap();
        assert_eq!(smaller.retry_after_seconds, 120);
    }

    #[test]
    fn signer_file_must_be_private_and_subnet_digests_use_a_derived_key() {
        let dir = TempDir::new().unwrap();
        let c = config(&dir);
        let engine = Engine::open(c.clone()).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-real-ip", HeaderValue::from_static("192.0.2.1"));
        let digest = private_client_subnet(&engine.subnet_key, &headers).unwrap();
        let derived = crypto::tagged_hash("Hashstash/FaucetSubnetKey/v1", &[41; 32]);
        let keyed = [&derived[..], b"192.0.2.0/24"].concat();
        assert_eq!(
            digest,
            hex::encode(crypto::tagged_hash("Hashstash/FaucetSubnet/v1", &keyed))
        );
        let direct = [&[41u8; 32][..], b"192.0.2.0/24"].concat();
        assert_ne!(
            digest,
            hex::encode(crypto::tagged_hash("Hashstash/FaucetSubnet/v1", &direct))
        );
        drop(engine);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&c.key_file, std::fs::Permissions::from_mode(0o644))
                .unwrap();
            assert!(Engine::open(c.clone()).is_err());
            assert!(maintain(&c, Maintenance::Inspect).is_err());
            owner_only(&c.key_file);
            let link = dir.path().join("linked.json");
            std::os::unix::fs::symlink(&c.key_file, &link).unwrap();
            let mut linked = c.clone();
            linked.key_file = link;
            assert!(Engine::open(linked).is_err());
        }
        // The alternate field name is still accepted; a malformed secret is not.
        let secret = hex::encode([41; 32]);
        std::fs::write(
            &c.key_file,
            serde_json::to_vec(&json!({"private_key":secret})).unwrap(),
        )
        .unwrap();
        owner_only(&c.key_file);
        assert_eq!(
            read_signer(&c.key_file).unwrap().1,
            crypto::public_key(&[41; 32]).unwrap()
        );
        std::fs::write(
            &c.key_file,
            serde_json::to_vec(&json!({"secret":7,"private_key":secret})).unwrap(),
        )
        .unwrap();
        assert!(read_signer(&c.key_file).is_err());
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn one_client_network_cannot_hold_every_http_session() {
        let dir = TempDir::new().unwrap();
        let app = App::new(
            Engine::open(config(&dir)).unwrap(),
            vec!["https://faucet.example".into()],
            vec!["faucet.example".into()],
        );
        let (clients, status_source) = (app.clients.clone(), app.status.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router(app)).await.unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let status = move |ip: String| {
            let client = client.clone();
            async move {
                client
                    .get(format!("http://{local}/faucet/status"))
                    .header("host", "faucet.example")
                    .header("x-real-ip", ip)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        // Holding the status ledger connection keeps admitted requests in flight.
        let held = status_source.reader.lock().unwrap();
        let waiting = (1..=CLIENT_SESSIONS)
            .map(|n| tokio::spawn(status(format!("192.0.2.{n}"))))
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(5), async {
            while clients.0.lock().unwrap().get("192.0.2.0/24") != Some(&CLIENT_SESSIONS) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            status("192.0.2.99".into()).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Another network is still admitted and waits for the ledger.
        let other = tokio::spawn(status("198.51.100.7".into()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!other.is_finished());
        drop(held);
        for request in waiting {
            assert_eq!(request.await.unwrap(), StatusCode::OK);
        }
        assert_eq!(other.await.unwrap(), StatusCode::OK);
        assert!(clients.0.lock().unwrap().is_empty());
        server.abort();
    }

    /// The next receipt lookup the mock node answers waits for the second
    /// signal after giving the first.
    fn gate_receipts(
        node: &mut MockNode,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let gate = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(tokio::sync::Notify::new()),
        );
        node.receipt_gate = Some(gate.clone());
        gate
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn status_and_claims_proceed_while_a_refresh_waits_for_the_node() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, mock_task) = ready_engine(&dir, |_| {}).await;
        // A confirmed receipt makes every refresh look up its block.
        engine.claim(&recipient(3), "a").await.unwrap();
        {
            let mut node = node.lock().await;
            let transactions = node.transactions.clone();
            node.blocks.insert(3, block(3, transactions));
            node.nonce = 1;
            node.height = 4;
        }
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "confirmed"
        );
        let key = hex::encode(engine.sender);
        let app = App::new(
            engine,
            vec!["https://faucet.example".into()],
            vec!["faucet.example".into()],
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes = router(app.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, routes).await.unwrap();
        });
        // The next refresh's receipt lookup waits until the test releases it,
        // as a slow or throttled node's would.
        let (entered, release) = gate_receipts(&mut *node.lock().await);
        let refresh = {
            let (engine, client) = (app.engine.clone(), app.node.clone());
            tokio::spawn(async move { poll_once(&mut Shared(engine), &client, &key).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let started = Instant::now();
        let status: Value = client
            .get(format!("{base}/faucet/status"))
            .query(&[("address", recipient(4))])
            .header("host", "faucet.example")
            .header("x-real-ip", "192.0.2.4")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(status["state"], "ready");
        // A claim takes the engine between the refresh's steps and is paid.
        let paid = client
            .post(format!("{base}/faucet/claim"))
            .header("host", "faucet.example")
            .header("origin", "https://faucet.example")
            .header("x-real-ip", "192.0.2.4")
            .json(&json!({"address":recipient(4)}))
            .send()
            .await
            .unwrap();
        assert_eq!(paid.status(), StatusCode::OK);
        assert_eq!(paid.json::<Value>().await.unwrap()["status"], "pending");
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(!refresh.is_finished());
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), refresh)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let engine = app.engine.lock().await;
        assert!(engine.fault.is_none());
        assert_eq!(
            engine.ledger.pending().unwrap().unwrap().address,
            recipient(4)
        );
        assert_eq!(node.lock().await.transactions.len(), 2);
        server.abort();
        mock_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_claim_reserved_during_refresh_lookups_is_accounted_on_the_next_refresh() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let first = engine.claim(&recipient(3), "a").await.unwrap();
        node.lock().await.height = 4;
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "expired"
        );
        // That payment is included after all, on a branch of the same height.
        let (entered, release) = {
            let mut node = node.lock().await;
            let mut branch = block(3, vec![node.transactions[0].clone()]);
            branch.header.nonce = 77;
            node.blocks.insert(3, branch);
            node.nonce = 1;
            gate_receipts(&mut node)
        };
        let key = hex::encode(engine.sender);
        let client = engine.node.clone();
        let engine = Arc::new(Mutex::new(engine));
        let refresh = {
            let (engine, client) = (engine.clone(), client.clone());
            tokio::spawn(async move { poll_once(&mut Shared(engine), &client, &key).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        // While the search waits for the node, a claim signs the nonce that
        // the adopted snapshot still shows unused.
        let mut held = Held(Some(engine.clone().lock_owned().await));
        let second = claim_with(&mut held, &client, recipient(4), "b".into())
            .await
            .unwrap();
        drop(held);
        assert_eq!(second["status"], "pending");
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), refresh)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut engine = engine.lock().await;
        // What the search found predates that reservation. Payouts pause
        // until the next refresh accounts for both claims with the nonce.
        assert_eq!(engine.fault, Some("verifying_payments"));
        assert_eq!(engine.state().unwrap(), "unavailable");
        assert!(engine.ledger.pending().unwrap().is_some());
        engine.refresh().await.unwrap();
        assert!(engine.fault.is_none());
        let paid = engine.status(Some(&recipient(3)), "a").unwrap();
        assert_eq!(paid["claim"]["status"], "confirmed");
        assert_eq!(paid["claim"]["txid"], first["txid"]);
        // The later bytes with the same nonce can never apply.
        assert_eq!(
            engine.status(Some(&recipient(4)), "b").unwrap()["claim"]["status"],
            "expired"
        );
        assert!(engine.ledger.pending().unwrap().is_none());
        engine.claim(&recipient(5), "c").await.unwrap();
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw, &[7; 32]).unwrap().body.nonce, 1);
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_claim_queued_behind_a_failed_refresh_never_uses_its_snapshot() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |c| c.expiry_blocks = 20).await;
        let first = engine.claim(&recipient(3), "a").await.unwrap();
        {
            let mut node = node.lock().await;
            let transactions = node.transactions.clone();
            node.blocks.insert(3, block(3, transactions));
            node.nonce = 1;
            node.height = 4;
        }
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.status(Some(&recipient(3)), "a").unwrap()["claim"]["status"],
            "confirmed"
        );
        // A reorganization drops the payment, so its nonce is unused again,
        // and the busy node refuses the lookup that would show it.
        let (entered, release) = {
            let mut node = node.lock().await;
            let mut branch = block(3, vec![]);
            branch.header.nonce = 55;
            node.blocks.insert(3, branch);
            node.nonce = 0;
            node.height = 5;
            node.refusals
                .push(("blockreceipt", StatusCode::SERVICE_UNAVAILABLE, None));
            gate_receipts(&mut node)
        };
        let key = hex::encode(engine.sender);
        let client = engine.node.clone();
        let engine = Arc::new(Mutex::new(engine));
        let refresh = {
            let (engine, client) = (engine.clone(), client.clone());
            tokio::spawn(async move { poll_once(&mut Shared(engine), &client, &key).await })
        };
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        // Queue the refresh's last step and then a claim behind the engine,
        // so the claim takes the engine as soon as that step releases it.
        let held = engine.clone().lock_owned().await;
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !node.lock().await.refusals.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let claim = {
            let (engine, client) = (engine.clone(), client.clone());
            tokio::spawn(async move {
                let mut held = Held(Some(engine.lock_owned().await));
                claim_with(&mut held, &client, recipient(4), "b".into()).await
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(held);
        let error = tokio::time::timeout(Duration::from_secs(5), refresh)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.is::<NodeBusy>());
        // That claim would have signed the payment's nonce again from the
        // unaccounted snapshot. The step that adopted it also paused claims.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), claim)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        let mut engine = engine.lock().await;
        assert_eq!(node.lock().await.prepared, 1);
        assert_eq!(
            engine.refresh_diagnostics.error.as_ref().unwrap().category,
            "node_busy"
        );
        assert_eq!(
            engine.published.answer(None, "b").unwrap()["state"],
            "waiting_for_mining"
        );
        assert!(engine.ledger.last(&recipient(4)).unwrap().is_none());
        // The next refreshes account the payment again and retry its bytes.
        engine.refresh().await.unwrap();
        engine.refresh().await.unwrap();
        let retried = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(retried.txid, first["txid"]);
        assert_eq!(engine.state().unwrap(), "pending");
        assert_eq!(engine.published.answer(None, "b").unwrap()["state"], "pending");
        assert_eq!(node.lock().await.transactions.len(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn node_admission_refusals_are_resent_after_their_wait_and_reported_as_busy() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        // A refused request did not run. After a short Retry-After it is
        // resent once, so the claim is paid instead of failing as if the
        // node were down.
        node.lock().await.refusals.extend([
            ("snapshot", StatusCode::SERVICE_UNAVAILABLE, Some("1")),
            ("preparetransaction", StatusCode::TOO_MANY_REQUESTS, Some("1")),
        ]);
        let started = Instant::now();
        engine.refresh().await.unwrap();
        assert_eq!(
            engine.claim(&recipient(3), "a").await.unwrap()["status"],
            "pending"
        );
        assert!(started.elapsed() >= Duration::from_secs(2));
        {
            let node = node.lock().await;
            assert!(node.refusals.is_empty());
            assert_eq!((node.prepared, node.transactions.len()), (1, 1));
        }
        // A longer wait, none, or a second refusal ends the request as
        // node_busy, never as a transport fault, and the next refresh waits
        // as long as the node asked.
        for (refusals, wait) in [
            (
                vec![("snapshot", StatusCode::SERVICE_UNAVAILABLE, Some("30"))],
                Duration::from_secs(30),
            ),
            (
                vec![("snapshot", StatusCode::TOO_MANY_REQUESTS, None)],
                POLL_INTERVAL,
            ),
            (
                vec![
                    ("snapshot", StatusCode::TOO_MANY_REQUESTS, Some("1")),
                    ("snapshot", StatusCode::SERVICE_UNAVAILABLE, Some("1")),
                ],
                POLL_INTERVAL,
            ),
        ] {
            node.lock().await.refusals.extend(refusals);
            let error = engine.refresh().await.unwrap_err();
            assert!(node.lock().await.refusals.is_empty());
            let mut diagnostics = RefreshDiagnostics::default();
            diagnostics.record(&error, 1, Instant::now());
            assert_eq!(diagnostics.error.unwrap().category, "node_busy");
            assert_eq!(poll_wait(&Err(error)), wait);
        }
        let busy = |seconds| -> Result<()> {
            Err(NodeBusy {
                retry_after: Some(Duration::from_secs(seconds)),
            }
            .into())
        };
        assert_eq!(poll_wait(&busy(3600)), MAX_POLL_WAIT);
        assert_eq!(poll_wait(&Ok(())), POLL_INTERVAL);
        assert_eq!(poll_wait(&Err(anyhow!("transport"))), POLL_INTERVAL);
        task.abort();
    }

    #[tokio::test]
    async fn http_connections_must_send_heads_promptly_and_are_capped() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = TempDir::new().unwrap();
        let server = serve(config(&dir)).await.unwrap();
        let opened = Instant::now();
        let mut held = Vec::new();
        for _ in 0..HTTP_CONNECTIONS {
            held.push(tokio::net::TcpStream::connect(server.address).await.unwrap());
        }
        // One connection over the cap is closed before anything is read.
        let mut refused = tokio::net::TcpStream::connect(server.address).await.unwrap();
        let mut byte = [0; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), refused.read(&mut byte))
            .await
            .expect("a connection over the cap was held");
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert!(opened.elapsed() < crate::local_http::HEAD_TIMEOUT);
        // A partial request head is closed unanswered at the head deadline.
        held[0]
            .write_all(b"GET /faucet/status HTTP/1.1\r\nHost: faucet.example\r\n")
            .await
            .unwrap();
        let closed = tokio::time::timeout(
            crate::local_http::HEAD_TIMEOUT + Duration::from_secs(3),
            held[0].read(&mut byte),
        )
        .await
        .expect("a partial head was held past the deadline");
        assert!(matches!(closed, Ok(0) | Err(_)));
        server.stop().await;
    }
}
