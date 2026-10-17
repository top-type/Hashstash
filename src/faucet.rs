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
use rusqlite::{Connection, OptionalExtension, params};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, IgnoredAny},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, oneshot},
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
/// Block receipts inspected per refresh while locating a consumed nonce.
const SCAN_BLOCKS_PER_REFRESH: u64 = 64;
/// Reorganized receipts accounted again per refresh.
const RECEIPT_REPAIRS_PER_REFRESH: usize = 8;
/// Concurrent HTTP requests one client network may hold.
const CLIENT_SESSIONS: usize = 4;

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

/// Loads the dedicated signer from a regular, owner-only file and wipes every
/// parsed copy of the secret.
fn read_signer(path: &Path) -> Result<(Zeroizing<[u8; 32]>, PublicKey)> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "faucet key must be a regular file of at most 4096 bytes"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "faucet key file must be owner-only (0600)"
        );
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    ensure!(bytes.len() <= 4096, "key file is too large");
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

struct Ledger {
    db: Connection,
    /// Every recorded claim, maintained by reservation so status never counts
    /// the whole ledger.
    lifetime: u64,
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
        Ok(Self { db, lifetime })
    }
    fn pending(&self) -> Result<Option<Claim>> {
        Ok(self
            .db
            .query_row(
                &format!("SELECT {CLAIM_COLUMNS} FROM claims WHERE status='pending'"),
                [],
                row_claim,
            )
            .optional()?)
    }
    fn last(&self, address: &str) -> Result<Option<Claim>> {
        Ok(self.db.query_row(&format!("SELECT {CLAIM_COLUMNS} FROM claims WHERE address=?1 ORDER BY created DESC,rowid DESC LIMIT 1"), [address], row_claim).optional()?)
    }
    /// The newest confirmed claim with its recorded receipt height and hash.
    fn top_receipt(&self) -> Result<Option<(Claim, u64, String)>> {
        Ok(self.db.query_row(&format!("SELECT {CLAIM_COLUMNS},receipt_height,receipt_hash FROM claims WHERE status='confirmed' ORDER BY receipt_height DESC,rowid DESC LIMIT 1"), [], |r| Ok((row_claim(r)?, r.get(9)?, r.get(10)?))).optional()?)
    }
    /// Every claim signed with `nonce` that is not a confirmed payment.
    fn unsettled(&self, nonce: u64) -> Result<Vec<Claim>> {
        let mut query = self.db.prepare(&format!(
            "SELECT {CLAIM_COLUMNS} FROM claims WHERE nonce=?1 AND status<>'confirmed' ORDER BY rowid"
        ))?;
        let rows = query.query_map([nonce.to_string()], row_claim)?;
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
    /// The quota clock. It never moves behind recorded claims; a wall clock far
    /// behind them pauses payouts instead of stretching old windows.
    fn clock(&self, wall: i64) -> Result<i64> {
        let latest: Option<i64> =
            self.db
                .query_row("SELECT MAX(created) FROM claims", [], |r| r.get(0))?;
        match latest {
            Some(latest) if latest > wall.saturating_add(CLOCK_TOLERANCE_SECONDS) => {
                Err(Fault("clock_behind_ledger").into())
            }
            Some(latest) => Ok(wall.max(latest)),
            None => Ok(wall),
        }
    }
    fn budget(&self, c: &FaucetConfig, time: i64) -> Result<bool> {
        if self.lifetime >= c.lifetime_claims {
            return Ok(false);
        }
        for (period, cap) in [(3600, c.hourly_claims), (86400, c.daily_claims)] {
            let used: u64 = self.db.query_row(
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
}

/// Calls the loopback node. Snapshot replies grow with governed content, so they
/// follow the node's own response frame; other replies keep a small fixed cap.
async fn node_rpc<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
) -> Result<T> {
    let limit = if method == "snapshot" {
        crate::node::MAX_RESPONSE_FRAME
    } else {
        RPC_REPLY_BYTES
    };
    let mut response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await?
        .error_for_status()?;
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

enum Receipts {
    /// The newest confirmed receipt is canonical; this is its nonce.
    Verified(Option<u64>),
    /// More reorganized receipts remain for the next refresh.
    Repairing,
}

enum Located {
    Found(u64, Hash, String),
    Missing,
    Incomplete,
}

/// Progress locating which recorded claim consumed one nonce. Inspected heights
/// are trusted only while the highest inspected block remains canonical.
struct Scan {
    nonce: u64,
    txids: Vec<String>,
    low: u64,
    next: u64,
    checked: Option<(u64, Hash)>,
    found: Option<(u64, Hash, String)>,
}
impl Scan {
    fn new(nonce: u64, txids: Vec<String>, low: u64) -> Self {
        Self {
            nonce,
            txids,
            low,
            next: low,
            checked: None,
            found: None,
        }
    }
}

struct Engine {
    config: FaucetConfig,
    chain: Hash,
    secret: Zeroizing<[u8; 32]>,
    subnet_key: Zeroizing<[u8; 32]>,
    sender: PublicKey,
    payout: Amount,
    maximum_fee: Amount,
    ledger: Ledger,
    client: reqwest::Client,
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
        let subnet_key = Zeroizing::new(crypto::tagged_hash(
            "Hashstash/FaucetSubnetKey/v1",
            &secret[..],
        ));
        let chain = parse_hash(&config.chain_id)?;
        let payout = amount(&config.payout)?;
        let maximum_fee = amount(&config.max_fee)?;
        let ledger = Ledger::open(&config.database, &chain, &sender, &payout.to_str_radix(10))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            // The node RPC is loopback only; environment proxies never relay it.
            .no_proxy()
            .build()?;
        Ok(Self {
            config,
            chain,
            secret,
            subnet_key,
            sender,
            payout,
            maximum_fee,
            ledger,
            client,
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
        })
    }
    // Exclusive access keeps these futures Send: the ledger connection is not Sync.
    async fn rpc<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T> {
        node_rpc(&self.client, &self.config.rpc_url, method, params).await
    }
    async fn block_receipt(
        &mut self,
        height: u64,
        txids: &[String],
    ) -> Result<(Hash, Vec<bool>)> {
        let receipt: BlockReceipt = self
            .rpc("blockreceipt", json!({"height":height,"txids":txids}))
            .await?;
        ensure!(
            receipt.height == height && receipt.included.len() == txids.len(),
            "node returned another block receipt"
        );
        Ok((parse_hash(&receipt.hash)?, receipt.included))
    }
    fn mining(&self) -> bool {
        // Freshness follows the governed interval, so slower blocks never make
        // the faucet unavailable for most of every interval.
        let interval = self.settings.map_or(0, |s| s.interval);
        let window = self
            .config
            .recent_block_seconds
            .max(interval.saturating_mul(FRESHNESS_INTERVALS));
        self.last_advance
            .is_some_and(|v| v.elapsed() < Duration::from_secs(window))
            && self
                .last_success
                .is_some_and(|v| v.elapsed() < Duration::from_secs(20))
    }
    /// Best-effort quota time for display; claims use the strict ledger clock.
    fn display_time(&self) -> i64 {
        self.ledger.clock(now()).unwrap_or_else(|_| now())
    }
    /// The exact weight and automatic fee of this faucet's payment to a new
    /// account under the latest governed settings, derived as node preparation
    /// derives them: the fee's own encoded length is part of its charge.
    fn payout_requirements(&self) -> Result<Option<(u64, Amount)>> {
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
                .checked_add(fees::ACCOUNT_WEIGHT)
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
    fn state(&self) -> Result<&'static str> {
        if self.fault.is_some() {
            return Ok("unavailable");
        }
        if !self.mining() {
            return Ok("waiting_for_mining");
        }
        if self.ledger.pending()?.is_some() {
            return Ok("pending");
        }
        let time = match self.ledger.clock(now()) {
            Ok(time) => time,
            Err(error) if error.is::<Fault>() => return Ok("unavailable"),
            Err(error) => return Err(error),
        };
        if !self.ledger.budget(&self.config, time)? {
            return Ok("quota_reached");
        }
        // A payment to a new account is the costliest claim. Governance can make
        // it unincludable or more expensive than the operator's fee allowance.
        if let (Some(settings), Some((weight, fee))) = (self.settings, self.payout_requirements()?)
        {
            if weight > settings.block_bytes {
                return Ok("capacity_exceeded");
            }
            if fee > self.maximum_fee {
                return Ok("fee_cap_exceeded");
            }
        }
        if self.funds < &self.payout + &self.maximum_fee {
            return Ok("unfunded");
        }
        Ok("ready")
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
    fn claim_json(&self, claim: &Claim, time: i64) -> Value {
        json!({"status":claim.status,"txid":claim.txid,"chain_id":self.config.chain_id,"amount_hashes":claim.amount_hashes,"retry_after_seconds":(claim.created.saturating_add(self.config.cooldown_seconds as i64).saturating_sub(time)).max(0)})
    }
    fn status(&self, recipient: Option<&str>, client_subnet: &str) -> Result<Value> {
        let state = self.state()?;
        // Refresh diagnostics stay in the operator journal, never in public status.
        let mut result = json!({"enabled":true,"chain_id":self.config.chain_id,"amount_hashes":self.config.payout,"available":state=="ready","mining_active":self.mining(),"state":state,"cooldown_seconds":self.config.cooldown_seconds,"address":address::encode(&self.sender,&self.chain)?});
        if let Some(recipient) = recipient {
            let key = address::decode(recipient, &self.chain)?;
            let canonical = address::encode(&key, &self.chain)?;
            let time = self.display_time();
            let waiting = cooldown(
                &self.ledger.db,
                &self.config,
                &canonical,
                client_subnet,
                time,
            )?;
            result["retry_after_seconds"] = json!(waiting.map_or(0, |v| v.retry_after_seconds));
            if let Some(wait) = waiting {
                result["cooldown_scope"] = json!(wait.scope);
                if state == "ready" {
                    result["state"] = json!("cooldown");
                    result["available"] = json!(false);
                }
            }
            if let Some(claim) = self.ledger.last(&canonical)?
                && self.fault.is_none()
                && (claim.status != "confirmed"
                    || self
                        .last_success
                        .is_some_and(|v| v.elapsed() < Duration::from_secs(20)))
            {
                result["claim"] = self.claim_json(&claim, time);
            }
        }
        Ok(result)
    }
    /// Tests refresh under the engine; the poll loop fetches the snapshot
    /// without holding it and then calls `apply`.
    #[cfg(test)]
    async fn refresh(&mut self) -> Result<()> {
        let snapshot = self
            .rpc("snapshot", json!({"key":hex::encode(self.sender)}))
            .await?;
        self.apply(snapshot).await
    }
    async fn apply(&mut self, snapshot: NodeSnapshot) -> Result<()> {
        let status = snapshot.status;
        ensure!(
            status.chain_id == self.config.chain_id,
            "node changed network"
        );
        let height = status.height;
        let tip = parse_hash(&status.tip)?;
        let state_root = parse_hash(&status.state_root)?;
        ensure!(height <= i64::MAX as u64, "unsupported chain height");
        if self.height.is_some_and(|v| height > v) {
            self.last_advance = Some(Instant::now());
        }
        self.height = Some(height);
        self.tip = Some(tip);
        self.state_root = Some(state_root);
        self.settings = Some(status.settings);
        // A missing account is expected until the dedicated mining payout is funded.
        match snapshot.account {
            None => {
                self.funds = Amount::zero();
                self.nonce = 0;
            }
            Some(account) => {
                self.funds = snapshot_payment_funds(&snapshot.payment_available_hash)?;
                self.nonce = account.account.nonce;
            }
        }
        match self.reconcile(height).await {
            Ok(hold) => {
                self.fault = hold;
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
    }
    /// Accounts for every faucet nonce the canonical chain consumed, and returns
    /// a pause category while that accounting is incomplete. Reorganizations
    /// relocate, retry or expire records automatically. Each nonce pays at most
    /// one recorded claim, so no repair can create another payment.
    async fn reconcile(&mut self, height: u64) -> Result<Option<&'static str>> {
        self.ledger.clock(now())?;
        let top = match self.verify_receipts(height).await? {
            Receipts::Verified(top) => top,
            Receipts::Repairing => return Ok(Some("verifying_payments")),
        };
        let floor = match top {
            Some(nonce) => Some(nonce.saturating_add(1)),
            None => self.ledger.first_nonce()?,
        }
        .max(self.ledger.nonce_floor()?);
        let pending = match self.ledger.pending()? {
            Some(claim) => {
                self.verify_stored(&claim)?;
                if floor.is_some_and(|floor| claim.nonce < floor) {
                    // A recorded payment already settled this nonce on this chain.
                    self.ledger.expire(&claim.txid)?;
                    None
                } else {
                    Some(claim)
                }
            }
            None => None,
        };
        if let Some(floor) = floor
            && floor < self.nonce
            && let Some(hold) = self.settle(floor, height).await?
        {
            return Ok(Some(hold));
        }
        // Only bytes whose nonce is still unused here may be retried or expired.
        if let Some(claim) = pending
            && claim.nonce >= self.nonce
        {
            // Neither an orphaned anchor nor a shorter chain can include the
            // bytes after their lifetime, so they expire with the nonce unused.
            if height >= claim.expiry {
                self.ledger.expire(&claim.txid)?;
            } else if self.mining() {
                // Any RPC error is uncertain. Keep the durable pending record and its
                // quota reservation; a later poll retries exactly these signed bytes.
                let _ = self
                    .rpc::<IgnoredAny>("broadcasttransaction", json!({"raw":claim.raw}))
                    .await;
            }
        }
        Ok(None)
    }
    /// Checks the newest confirmed receipt with one block-hash lookup. Its block
    /// commits to all older receipts. A receipt that left the canonical chain is
    /// accounted again from its nonce.
    async fn verify_receipts(&mut self, height: u64) -> Result<Receipts> {
        for _ in 0..RECEIPT_REPAIRS_PER_REFRESH {
            let Some((claim, at, hash)) = self.ledger.top_receipt()? else {
                return Ok(Receipts::Verified(None));
            };
            if height < at {
                // A shorter chain cannot show yet whether this payment survived.
                return Err(Fault("node_behind_ledger").into());
            }
            let (canonical, included) = self
                .block_receipt(at, std::slice::from_ref(&claim.txid))
                .await?;
            if hex::encode(canonical) == hash {
                ensure!(
                    included == [true],
                    "confirmed faucet receipt lacks its payment"
                );
                return Ok(Receipts::Verified(Some(claim.nonce)));
            }
            let status = if self.ledger.pending()?.is_some() {
                "expired"
            } else {
                "pending"
            };
            self.ledger.db.execute(
                "UPDATE claims SET status=?1,receipt_height=NULL,receipt_hash=NULL WHERE txid=?2 AND status='confirmed'",
                params![status, claim.txid],
            )?;
            self.scan = None;
        }
        Ok(Receipts::Repairing)
    }
    /// Finds the recorded claim that consumed `nonce` and confirms it at depth.
    /// A consumed nonce matching no recorded claim means the key signed elsewhere.
    async fn settle(&mut self, nonce: u64, height: u64) -> Result<Option<&'static str>> {
        let claims = self.ledger.unsettled(nonce)?;
        let (Some(low), Some(high)) = (
            claims.iter().map(|c| c.height.saturating_add(1)).min(),
            claims.iter().map(|c| c.expiry).max(),
        ) else {
            return Err(Fault("nonce_conflict").into());
        };
        let txids = claims.into_iter().map(|c| c.txid).collect();
        match self.locate(nonce, txids, low, high.min(height)).await? {
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
            Located::Missing => Err(Fault("nonce_conflict").into()),
            Located::Incomplete => Ok(Some("verifying_payments")),
        }
    }
    /// Searches heights `low..=high` for any of `txids`, resuming earlier progress
    /// while it remains canonical and inspecting a bounded number of blocks.
    async fn locate(
        &mut self,
        nonce: u64,
        txids: Vec<String>,
        low: u64,
        high: u64,
    ) -> Result<Located> {
        let mut scan = match self.scan.take() {
            Some(scan) if scan.nonce == nonce && scan.txids == txids && scan.low == low => scan,
            _ => Scan::new(nonce, txids, low),
        };
        if let Some((at, hash, txid)) = scan.found.clone() {
            if at <= high {
                let (canonical, included) =
                    self.block_receipt(at, std::slice::from_ref(&txid)).await?;
                if canonical == hash && included == [true] {
                    self.scan = Some(scan);
                    return Ok(Located::Found(at, hash, txid));
                }
            }
            scan = Scan::new(nonce, scan.txids, low);
        } else if let Some((at, hash)) = scan.checked
            && (at > high || self.block_receipt(at, &[]).await?.0 != hash)
        {
            scan = Scan::new(nonce, scan.txids, low);
        }
        let end = high.min(scan.next.saturating_add(SCAN_BLOCKS_PER_REFRESH - 1));
        while scan.next <= end {
            let at = scan.next;
            let (hash, included) = self.block_receipt(at, &scan.txids).await?;
            if let Some(index) = included.iter().position(|found| *found) {
                let txid = scan.txids[index].clone();
                scan.found = Some((at, hash, txid.clone()));
                self.scan = Some(scan);
                return Ok(Located::Found(at, hash, txid));
            }
            scan.checked = Some((at, hash));
            scan.next = at + 1;
        }
        let complete = scan.next > high;
        self.scan = Some(scan);
        Ok(if complete {
            Located::Missing
        } else {
            Located::Incomplete
        })
    }
    /// A stored claim must still be exactly its signed fixed intent before it
    /// is retried.
    fn verify_stored(&self, claim: &Claim) -> Result<()> {
        let tx = wallet::decode_signed(&claim.raw)?;
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
    async fn claim(&mut self, recipient: &str, client_subnet: &str) -> Result<Value> {
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
            let mut result = self.claim_json(&existing, time);
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
            return Ok(result);
        }
        ensure!(
            self.state()? == "ready",
            "Faucet is waiting for mining, funds, or its next allowance"
        );
        self.ledger
            .eligible(&self.config, &canonical, client_subnet, time)?;
        let height = self.height.context("missing chain height")?;
        let anchor = self.tip.context("missing quoted tip")?;
        let state_root = self.state_root.context("missing quoted state root")?;
        let settings = self.settings.context("missing governed settings")?;
        let expiry = height
            .checked_add(self.config.expiry_blocks)
            .context("expiry overflow")?;
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
        let result: Value = self.rpc("preparetransaction",json!({"sender":hex::encode(self.sender),"operation":operation,"nonce":self.nonce,"anchor":hex::encode(anchor),"expiry_blocks":self.config.expiry_blocks,"extra_fee":"0"})).await?;
        let quote = &result["fee_quote"];
        ensure!(
            quote["chain_id"] == self.config.chain_id
                && quote["tip"] == hex::encode(anchor)
                && quote["state_root"] == hex::encode(state_root)
                && quote["height"] == height
                && quote["anchor"] == hex::encode(anchor)
                && quote["anchor_height"] == height
                && quote["expiry_blocks"] == self.config.expiry_blocks
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
            self.nonce,
            anchor,
            self.config.expiry_blocks,
            &operation,
            &self.maximum_fee,
        )?;
        let tx = crypto::sign(&body, &self.secret)?;
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
        self.ledger.reserve(&self.config, &claim, client_subnet)?;
        let _ = self
            .rpc::<IgnoredAny>("broadcasttransaction", json!({"raw":claim.raw}))
            .await;
        Ok(self.claim_json(&claim, claim.created))
    }
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
    origins: Arc<Vec<String>>,
    hosts: Arc<Vec<String>>,
    sessions: Arc<Semaphore>,
    clients: Arc<ClientSessions>,
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

fn private_client_subnet(engine: &Engine, headers: &HeaderMap) -> Option<String> {
    let client = one_header(headers, "x-real-ip").and_then(|v| subnet(v).ok())?;
    let mut private_subnet = Zeroizing::new(Vec::with_capacity(32 + client.len()));
    private_subnet.extend_from_slice(&engine.subnet_key[..]);
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
    let engine = app.engine.lock().await;
    let Some(client) = private_client_subnet(&engine, &headers) else {
        return failure(StatusCode::FORBIDDEN, "Client address required");
    };
    match engine.status(query.address.as_deref(), &client) {
        Ok(v) => Json(v).into_response(),
        Err(_) => failure(StatusCode::BAD_REQUEST, "Invalid test-network address"),
    }
}
async fn claim_handler(
    State(app): State<App>,
    headers: HeaderMap,
    Json(request): Json<ClaimRequest>,
) -> Response {
    let mut engine = app.engine.lock().await;
    // Store only a keyed digest of the subnet, never the visitor's literal IP.
    let Some(client) = private_client_subnet(&engine, &headers) else {
        return failure(StatusCode::FORBIDDEN, "Client address required");
    };
    if address::decode(&request.address, &engine.chain).is_err() {
        return failure(StatusCode::BAD_REQUEST, "Invalid test-network address");
    }
    match engine.claim(&request.address, &client).await {
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
    let engine = Arc::new(Mutex::new(Engine::open(config.clone())?));
    let listener = TcpListener::bind(config.bind).await?;
    let address = listener.local_addr()?;
    let hosts = config
        .origins
        .iter()
        .map(|s| s.split_once("://").expect("validated origin").1.to_owned())
        .collect();
    let app = App {
        engine: engine.clone(),
        origins: Arc::new(config.origins.clone()),
        hosts: Arc::new(hosts),
        sessions: Arc::new(Semaphore::new(16)),
        clients: Arc::default(),
    };
    let routes = router(app);
    let poll = tokio::spawn(async move {
        loop {
            // The snapshot is the largest reply. Fetch it without holding the
            // engine, so visitors wait only for local accounting and receipts.
            let (client, url, key) = {
                let engine = engine.lock().await;
                (
                    engine.client.clone(),
                    engine.config.rpc_url.clone(),
                    hex::encode(engine.sender),
                )
            };
            let snapshot =
                node_rpc::<NodeSnapshot>(&client, &url, "snapshot", json!({"key":key})).await;
            let mut engine = engine.lock().await;
            let refreshed = match snapshot {
                Ok(snapshot) => engine.apply(snapshot).await,
                Err(error) => Err(error),
            };
            match refreshed {
                Ok(()) => engine.refresh_diagnostics.recovered(),
                Err(error) => {
                    engine.last_success = None;
                    if engine
                        .refresh_diagnostics
                        .record(&error, now(), Instant::now())
                    {
                        let status = engine.refresh_diagnostics.error.as_ref().unwrap();
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
            engine.report_state();
            drop(engine);
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, routes)
            .with_graceful_shutdown(async {
                let _ = shutdown.await;
            })
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
    }
    async fn mock_rpc(
        State(node): State<Arc<Mutex<MockNode>>>,
        Json(request): Json<Value>,
    ) -> Response {
        let mut node = node.lock().await;
        let p = &request["params"];
        let result = match request["method"].as_str().unwrap() {
            "snapshot" => {
                json!({"status":{"chain_id":hex::encode([7;32]),"height":node.height,"tip":hex::encode(codec::block_hash(node.blocks.get(&node.height).unwrap_or(&block(node.height,vec![])))),"state_root":hex::encode([0;32]),"settings":{"block_bytes":node.block_bytes,"minimum_fee_rate":node.fee_rate,"interval":node.interval}},"payment_available_hash":"1000000000000000000","account":{"account":{"ordinary":"1000000000000000000","nonce":node.nonce}}})
            }
            "preparetransaction" => {
                let mut operation: Operation =
                    serde_json::from_value(p["operation"].clone()).unwrap();
                if node.malicious_prepare {
                    operation = Operation::TransferExact {
                        recipient: crypto::public_key(&[17; 32]).unwrap(),
                        amount: 1u32.into(),
                    };
                }
                let body = TransactionBody {
                    data: Vec::new(),
                    sender: hex::decode(p["sender"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    nonce: p["nonce"].as_u64().unwrap(),
                    anchor: parse_hash(p["anchor"].as_str().unwrap()).unwrap(),
                    expiry_blocks: p["expiry_blocks"].as_u64().unwrap(),
                    fee: 2u32.into(),
                    operation,
                };
                {
                    let mut result =
                        serde_json::to_value(wallet::unsigned(&body, &[7; 32])).unwrap();
                    let weight = codec::encode(&Transaction {
                        body: body.clone(),
                        signature: [0; 64],
                    })
                    .len()
                        + 1024;
                    result["fee_quote"] = json!({"chain_id":hex::encode([7; 32]),"tip":hex::encode(body.anchor),"anchor":hex::encode(body.anchor),"state_root":hex::encode([0;32]),"height":node.height,"anchor_height":node.height,"expiry_blocks":body.expiry_blocks,"expiry_height":node.height.checked_add(body.expiry_blocks).unwrap(),"weight":weight.to_string()});
                    result
                }
            }
            "broadcasttransaction" => {
                let transaction = wallet::decode_signed(p["raw"].as_str().unwrap()).unwrap();
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
                if height > node.height {
                    return Json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unknown active height"}})).into_response();
                }
                let block = node
                    .blocks
                    .get(&height)
                    .cloned()
                    .unwrap_or_else(|| block(height, vec![]));
                let included = p["txids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| {
                        block
                            .transactions
                            .iter()
                            .any(|t| hex::encode(codec::transaction_id(t)) == id.as_str().unwrap())
                    })
                    .collect::<Vec<_>>();
                json!({"height":height,"hash":hex::encode(codec::block_hash(&block)),"included":included})
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
        assert_eq!(
            engine.claim(&recipient(3), "a").await.unwrap()["txid"],
            result["txid"]
        );
        assert_eq!(
            engine.claim(&recipient(4), "b").await.unwrap()["status"],
            "pending"
        );
        let next = engine.ledger.pending().unwrap().unwrap();
        assert_eq!(wallet::decode_signed(&next.raw).unwrap().body.nonce, 1);
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
        let tx = wallet::decode_signed(&claim.raw).unwrap();
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
        assert_eq!(wallet::decode_signed(&next.raw).unwrap().body.nonce, 0);
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
        let next = wallet::decode_signed(&engine.ledger.pending().unwrap().unwrap().raw).unwrap();
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
        let network = private_client_subnet(&engine, &headers).unwrap();
        let first = record(1, now() - 17);
        engine
            .ledger
            .reserve(&engine.config.clone(), &first, &network)
            .unwrap();
        finish(&engine.ledger, &first);
        let engine = Arc::new(Mutex::new(engine));
        let app = App {
            engine: engine.clone(),
            origins: Arc::new(vec!["https://faucet.example".into()]),
            hosts: Arc::new(vec!["faucet.example".into()]),
            sessions: Arc::new(Semaphore::new(16)),
            clients: Arc::default(),
        };
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
        let app = App {
            engine: Arc::new(Mutex::new(Engine::open(c).unwrap())),
            origins: Arc::new(vec!["https://faucet.example".into()]),
            hosts: Arc::new(vec!["faucet.example".into()]),
            sessions: Arc::new(Semaphore::new(16)),
            clients: Arc::default(),
        };
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
        // A completed search is not repeated: one canonical check per refresh.
        let before = node.lock().await.receipts;
        for _ in 0..3 {
            assert!(engine.refresh().await.is_err());
        }
        assert_eq!(node.lock().await.receipts - before, 3);
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
        assert_eq!(wallet::decode_signed(&next.raw).unwrap().body.nonce, 1);
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
        assert_eq!(wallet::decode_signed(&next.raw).unwrap().body.nonce, 1);
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
        assert_eq!(wallet::decode_signed(&next.raw).unwrap().body.nonce, 0);
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

    #[test]
    fn local_payout_estimate_matches_consensus_fee_rules() {
        let dir = TempDir::new().unwrap();
        let mut engine = Engine::open(config(&dir)).unwrap();
        let chain = crate::config::Config::devnet();
        let mut state = crate::state::State::genesis(&chain);
        engine.tip = Some([3; 32]);
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
            let (weight, fee) = engine.payout_requirements().unwrap().unwrap();
            let body = TransactionBody {
                sender: engine.sender,
                nonce,
                fee: fee.clone(),
                anchor: [3; 32],
                expiry_blocks: engine.config.expiry_blocks,
                operation: Operation::TransferExact {
                    recipient: crypto::public_key(&[9; 32]).unwrap(),
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
                "rate {rate}"
            );
        }
    }

    #[tokio::test]
    async fn governed_fee_and_capacity_limits_pause_before_signing_or_reserving() {
        let dir = TempDir::new().unwrap();
        let (mut engine, _, node, task) = ready_engine(&dir, |_| {}).await;
        let (weight, fee) = engine.payout_requirements().unwrap().unwrap();
        assert!(weight > fees::ACCOUNT_WEIGHT && fee == 2u32.into());
        // A higher governed fee rate exceeds the operator's fee allowance.
        node.lock().await.fee_rate = 1_000_000;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "fee_cap_exceeded");
        assert_eq!(engine.status(None, "a").unwrap()["available"], false);
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        // Capacity below a new account's payment weight could never include it.
        {
            let mut node = node.lock().await;
            node.fee_rate = 1;
            node.block_bytes = weight - 1;
        }
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "capacity_exceeded");
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        assert!(engine.ledger.last(&recipient(3)).unwrap().is_none());
        assert!(node.lock().await.transactions.is_empty());
        node.lock().await.block_bytes = weight;
        engine.refresh().await.unwrap();
        assert_eq!(engine.state().unwrap(), "ready");
        engine.claim(&recipient(3), "a").await.unwrap();
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
        for index in ["claim_created", "claim_nonce"] {
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
        let digest = private_client_subnet(&engine, &headers).unwrap();
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
    async fn one_client_network_cannot_hold_every_http_session() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(Engine::open(config(&dir)).unwrap()));
        let clients = Arc::new(ClientSessions::default());
        let app = App {
            engine: engine.clone(),
            origins: Arc::new(vec!["https://faucet.example".into()]),
            hosts: Arc::new(vec!["faucet.example".into()]),
            sessions: Arc::new(Semaphore::new(16)),
            clients: clients.clone(),
        };
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
        // Local accounting holds the engine, so admitted requests stay in flight.
        let held = engine.lock().await;
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
        // Another network is still admitted and waits for the engine.
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
}
