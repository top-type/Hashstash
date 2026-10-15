//! An opt-in dispenser of already mined test funds. It has no consensus privileges.
//! The dedicated signer only authorizes fixed, exact transfers. Signed claims and
//! quotas are committed together before any network submission can take place.
use crate::{address, codec, crypto, types::*, wallet};
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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore, oneshot},
    task::JoinHandle,
};
use zeroize::Zeroizing;

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
    pub hourly_claims: u64,
    pub daily_claims: u64,
    pub lifetime_claims: u64,
    pub recent_block_seconds: u64,
    pub confirmations: u64,
    pub expiry_blocks: u64,
}

fn default_subnet_cooldown() -> u64 {
    60
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
            (1..=100).contains(&self.confirmations) && (1..=100).contains(&self.expiry_blocks),
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

fn snapshot_payment_funds(snapshot: &Value) -> Result<Amount> {
    // New outcome balances can differ. The default account is FAIL and must
    // never be mistaken for the amount an ordinary payment can spend in both.
    ensure!(
        snapshot["status"]["protocol_version"].as_u64()
            == Some(u64::from(crate::config::PROTOCOL_VERSION)),
        "unsupported protocol version"
    );
    let value = &snapshot["payment_available_hash"];
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
            let o = v.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", o[0], o[1], o[2], o[3])
        }
    })
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
    let subnet_wait = remaining(subnet_created, c.subnet_cooldown_seconds);
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
        tx.commit()?;
        Ok(Self { db })
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
    fn budget(&self, c: &FaucetConfig, time: i64) -> Result<bool> {
        for (period, cap) in [
            (3600, c.hourly_claims),
            (86400, c.daily_claims),
            (i64::MAX, c.lifetime_claims),
        ] {
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
        }
        tx.execute("INSERT INTO claims(address,subnet,created,nonce,txid,raw,status,height,expiry,amount_hashes) VALUES(?1,?2,?3,?4,?5,?6,'pending',?7,?8,?9)", params![claim.address,subnet,claim.created,claim.nonce.to_string(),claim.txid,claim.raw,claim.height,claim.expiry,claim.amount_hashes])?;
        tx.commit()?;
        Ok(())
    }
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
        let category = if let Some(e) = error.downcast_ref::<reqwest::Error>() {
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

struct Engine {
    config: FaucetConfig,
    chain: Hash,
    secret: Zeroizing<[u8; 32]>,
    sender: PublicKey,
    payout: Amount,
    maximum_fee: Amount,
    ledger: Ledger,
    client: reqwest::Client,
    height: Option<u64>,
    nonce: u64,
    funds: Amount,
    last_advance: Option<Instant>,
    last_success: Option<Instant>,
    refresh_diagnostics: RefreshDiagnostics,
    fault: bool,
}

impl Engine {
    fn open(config: FaucetConfig) -> Result<Self> {
        config.validate()?;
        ensure!(
            std::fs::metadata(&config.key_file)?.len() <= 4096,
            "key file is too large"
        );
        let bytes = Zeroizing::new(std::fs::read(&config.key_file)?);
        let key: Value = serde_json::from_slice(&bytes)?;
        let secret = Zeroizing::new(
            hex::decode(
                key.get("secret")
                    .or_else(|| key.get("private_key"))
                    .and_then(Value::as_str)
                    .context("private key missing")?,
            )?
            .try_into()
            .map_err(|_| anyhow!("invalid private key"))?,
        );
        let sender = crypto::public_key(&secret)?;
        if let Some(public) = key.get("public").or_else(|| key.get("public_key")) {
            ensure!(
                public.as_str() == Some(hex::encode(sender).as_str()),
                "key file mismatch"
            );
        }
        let chain = parse_hash(&config.chain_id)?;
        let payout = amount(&config.payout)?;
        let maximum_fee = amount(&config.max_fee)?;
        let ledger = Ledger::open(&config.database, &chain, &sender, &payout.to_str_radix(10))?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            config,
            chain,
            secret,
            sender,
            payout,
            maximum_fee,
            ledger,
            client,
            height: None,
            nonce: 0,
            funds: Amount::zero(),
            last_advance: None,
            last_success: None,
            refresh_diagnostics: RefreshDiagnostics::default(),
            fault: false,
        })
    }
    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        // Receipt verification must accept every block the node can serve.
        // Ordinary method replies retain the smaller faucet-specific limit.
        let limit = if method == "getblock" {
            crate::node::MAX_RESPONSE_FRAME
        } else {
            4 * 1024 * 1024
        };
        let mut response = self
            .client
            .post(&self.config.rpc_url)
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
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value.get("error").is_none_or(Value::is_null),
            "node refused faucet request"
        );
        value.get("result").cloned().context("missing RPC result")
    }
    fn mining(&self) -> bool {
        self.last_advance
            .is_some_and(|v| v.elapsed() < Duration::from_secs(self.config.recent_block_seconds))
            && self
                .last_success
                .is_some_and(|v| v.elapsed() < Duration::from_secs(20))
    }
    fn state(&self) -> Result<&'static str> {
        if self.fault {
            return Ok("unavailable");
        }
        if !self.mining() {
            return Ok("waiting_for_mining");
        }
        if self.ledger.pending()?.is_some() {
            return Ok("pending");
        }
        if !self.ledger.budget(&self.config, now())? {
            return Ok("quota_reached");
        }
        if self.funds < &self.payout + &self.maximum_fee {
            return Ok("unfunded");
        }
        Ok("ready")
    }
    fn claim_json(&self, claim: &Claim) -> Value {
        json!({"status":claim.status,"txid":claim.txid,"chain_id":self.config.chain_id,"amount_hashes":claim.amount_hashes,"retry_after_seconds":(claim.created.saturating_add(self.config.cooldown_seconds as i64).saturating_sub(now())).max(0)})
    }
    fn status(&self, recipient: Option<&str>, client_subnet: &str) -> Result<Value> {
        let state = self.state()?;
        let mut result = json!({"enabled":true,"chain_id":self.config.chain_id,"amount_hashes":self.config.payout,"available":state=="ready","mining_active":self.mining(),"state":state,"cooldown_seconds":self.config.cooldown_seconds,"address":address::encode(&self.sender,&self.chain)?});
        result["diagnostic"] = json!(self.refresh_diagnostics.error);
        if let Some(recipient) = recipient {
            let key = address::decode(recipient, &self.chain)?;
            let canonical = address::encode(&key, &self.chain)?;
            let waiting = cooldown(
                &self.ledger.db,
                &self.config,
                &canonical,
                client_subnet,
                now(),
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
                && !self.fault
                && (claim.status != "confirmed"
                    || self
                        .last_success
                        .is_some_and(|v| v.elapsed() < Duration::from_secs(20)))
            {
                result["claim"] = self.claim_json(&claim);
            }
        }
        Ok(result)
    }
    async fn refresh(&mut self) -> Result<()> {
        let snapshot = self
            .rpc("snapshot", json!({"key":hex::encode(self.sender)}))
            .await?;
        let status = &snapshot["status"];
        ensure!(
            status["chain_id"].as_str() == Some(self.config.chain_id.as_str()),
            "node changed network"
        );
        let height = status["height"].as_u64().context("missing height")?;
        ensure!(height <= i64::MAX as u64, "unsupported chain height");
        if self.height.is_some_and(|v| height > v) {
            self.last_advance = Some(Instant::now());
        }
        self.height = Some(height);
        let anchor: Option<(u64,String)> = self.ledger.db.query_row("SELECT receipt_height,receipt_hash FROM claims WHERE status='confirmed' ORDER BY receipt_height DESC LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((h, hash)) = anchor {
            if height < h {
                self.fault = true;
                anyhow::bail!("confirmed faucet payment was reorganized");
            }
            let block: Block =
                serde_json::from_value(self.rpc("getblock", json!({"height":h})).await?)?;
            if hex::encode(crypto::sha256d(&codec::header_bytes(&block.header))) != hash {
                self.fault = true;
                anyhow::bail!("confirmed faucet payment was reorganized");
            }
        }
        // A missing account is expected until the dedicated mining payout is funded.
        if snapshot["account"].is_null() {
            self.funds = Amount::zero();
            self.nonce = 0;
        } else {
            self.funds = snapshot_payment_funds(&snapshot)?;
            self.nonce = snapshot["account"]["account"]["nonce"]
                .as_u64()
                .context("missing account nonce")?;
        }
        if let Some(claim) = self.ledger.pending()? {
            self.reconcile(&claim, height).await?;
        }
        self.last_success = Some(Instant::now());
        Ok(())
    }
    async fn reconcile(&mut self, claim: &Claim, height: u64) -> Result<()> {
        if height < claim.height {
            self.fault = true;
            anyhow::bail!("pending faucet payment crossed a deep reorganization");
        }
        let tx = wallet::decode_signed(&claim.raw)?;
        let operation = Operation::TransferExact {
            recipient: address::decode(&claim.address, &self.chain)?,
            amount: amount(&claim.amount_hashes)?,
        };
        verify_intent(
            &tx.body,
            self.chain,
            self.sender,
            claim.nonce,
            claim.expiry,
            &operation,
            &tx.body.fee,
        )?;
        ensure!(
            hex::encode(codec::transaction_id(&tx)) == claim.txid
                && tx.body.sender == self.sender
                && tx.body.chain_id == self.chain
                && tx.body.nonce == claim.nonce
                && tx.body.expiry_height == claim.expiry,
            "invalid stored faucet transaction"
        );
        if self.nonce > claim.nonce {
            let mut found = None;
            for h in claim.height.saturating_add(1)..=height.min(claim.expiry) {
                let block: Block =
                    serde_json::from_value(self.rpc("getblock", json!({"height":h})).await?)?;
                if block
                    .transactions
                    .iter()
                    .any(|t| hex::encode(codec::transaction_id(t)) == claim.txid)
                {
                    found = Some((
                        h,
                        hex::encode(crypto::sha256d(&codec::header_bytes(&block.header))),
                    ));
                    break;
                }
            }
            let Some((h, hash)) = found else {
                self.fault = true;
                anyhow::bail!("faucet nonce consumed without its recorded payment");
            };
            if height.saturating_sub(h).saturating_add(1) >= self.config.confirmations {
                self.ledger.db.execute("UPDATE claims SET status='confirmed',receipt_height=?1,receipt_hash=?2 WHERE txid=?3 AND status='pending'",params![h,hash,claim.txid])?;
            }
        } else if height > claim.expiry {
            self.ledger.db.execute(
                "UPDATE claims SET status='expired' WHERE txid=?1 AND status='pending'",
                [&claim.txid],
            )?;
        } else if self.mining() && !self.fault {
            // Any RPC error is uncertain. Keep the durable pending record and its
            // quota reservation; a later poll retries exactly these signed bytes.
            let _ = self
                .rpc("broadcasttransaction", json!({"raw":claim.raw}))
                .await;
        }
        Ok(())
    }
    async fn claim(&mut self, recipient: &str, client_subnet: &str) -> Result<Value> {
        ensure!(!self.fault, "Faucet needs operator review");
        let key = address::decode(recipient, &self.chain)?;
        ensure!(key != self.sender, "choose a visitor wallet");
        let canonical = address::encode(&key, &self.chain)?;
        if let Some(existing) = self.ledger.last(&canonical)?
            && (existing.status == "pending"
                || existing
                    .created
                    .saturating_add(self.config.cooldown_seconds as i64)
                    > now())
        {
            ensure!(
                existing.status != "confirmed"
                    || self
                        .last_success
                        .is_some_and(|v| v.elapsed() < Duration::from_secs(20)),
                "Faucet is verifying its payment history"
            );
            let mut result = self.claim_json(&existing);
            if let Some(wait) = cooldown(
                &self.ledger.db,
                &self.config,
                &canonical,
                client_subnet,
                now(),
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
            .eligible(&self.config, &canonical, client_subnet, now())?;
        let height = self.height.context("missing chain height")?;
        let expiry = height
            .checked_add(self.config.expiry_blocks)
            .context("expiry overflow")?;
        let operation = Operation::TransferExact {
            recipient: key,
            amount: self.payout.clone(),
        };
        let result = self.rpc("preparetransaction",json!({"sender":hex::encode(self.sender),"operation":operation,"nonce":self.nonce,"expiry_height":expiry,"extra_fee":"0"})).await?;
        let envelope = wallet::UnsignedEnvelope {
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
        verify_intent(
            &body,
            self.chain,
            self.sender,
            self.nonce,
            expiry,
            &operation,
            &self.maximum_fee,
        )?;
        let tx = crypto::sign(&body, &self.secret)?;
        let claim = Claim {
            address: canonical,
            amount_hashes: self.payout.to_str_radix(10),
            created: now(),
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
            .rpc("broadcasttransaction", json!({"raw":claim.raw}))
            .await;
        Ok(self.claim_json(&claim))
    }
}

fn verify_intent(
    body: &TransactionBody,
    chain: Hash,
    sender: PublicKey,
    nonce: u64,
    expiry: u64,
    operation: &Operation,
    maximum: &Amount,
) -> Result<()> {
    ensure!(
        body.chain_id == chain
            && body.sender == sender
            && body.nonce == nonce
            && body.expiry_height == expiry
            && !body.fee.is_zero()
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
    let mut response = if !allowed {
        failure(StatusCode::FORBIDDEN, "Faucet website request required")
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
    let mut private_subnet = Zeroizing::new(engine.secret.to_vec());
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
    };
    let routes = router(app);
    let poll = tokio::spawn(async move {
        loop {
            let mut engine = engine.lock().await;
            match engine.refresh().await {
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
            "status":{"protocol_version":crate::config::PROTOCOL_VERSION},
            "account":{"account":{"ordinary":"1000"}},
            "pass":{"account":{"ordinary":"250"}},
            "payment_available_hash":"250"
        });
        assert_eq!(snapshot_payment_funds(&snapshot).unwrap(), 250u32.into());
        snapshot["payment_available_hash"] = json!("0");
        assert_eq!(snapshot_payment_funds(&snapshot).unwrap(), Amount::zero());
        snapshot
            .as_object_mut()
            .unwrap()
            .remove("payment_available_hash");
        assert!(snapshot_payment_funds(&snapshot).is_err());
        snapshot["status"]["protocol_version"] = json!(13);
        assert!(snapshot_payment_funds(&snapshot).is_err());
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
            hourly_claims: 100,
            daily_claims: 250,
            lifetime_claims: 1000,
            recent_block_seconds: 180,
            confirmations: 2,
            expiry_blocks: 20,
        }
    }
    fn recipient(n: u8) -> String {
        address::encode(&crypto::public_key(&[n; 32]).unwrap(), &[7; 32]).unwrap()
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
    async fn rpc_streaming_limits_allow_full_blocks_and_reject_oversize_before_eof() {
        let directory = TempDir::new().unwrap();
        let mut engine = Engine::open(config(&directory)).unwrap();
        let large = json!({"result":{"data":"x".repeat(4 * 1024 * 1024 + 1024)}});
        for (method, value) in [
            ("snapshot", json!({"result":{"height":7}})),
            ("getblock", large.clone()),
        ] {
            let (address, task) =
                streaming_rpc_reply(serde_json::to_vec(&value).unwrap(), true, None).await;
            engine.config.rpc_url = format!("http://{address}/rpc");
            assert_eq!(
                engine.rpc(method, json!({})).await.unwrap(),
                value["result"]
            );
            task.await.unwrap();
        }
        for (method, body, length) in [
            ("snapshot", serde_json::to_vec(&large).unwrap(), None),
            (
                "getblock",
                Vec::new(),
                Some(crate::node::MAX_RESPONSE_FRAME + 1),
            ),
        ] {
            let (address, task) = streaming_rpc_reply(body, false, length).await;
            engine.config.rpc_url = format!("http://{address}/rpc");
            let result =
                tokio::time::timeout(Duration::from_secs(2), engine.rpc(method, json!({}))).await;
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
        assert_ne!(
            subnet("2001:db8:5:6::1").unwrap(),
            subnet("2001:db8:5:7::1").unwrap()
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
        assert_eq!(
            serde_json::from_value::<FaucetConfig>(legacy)
                .unwrap()
                .subnet_cooldown_seconds,
            60
        );
        for duration in [0, 31_536_001] {
            let mut c = original.clone();
            c.subnet_cooldown_seconds = duration;
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
            chain_id: [7; 32],
            sender,
            nonce: 9,
            expiry_height: 22,
            fee: 10u32.into(),
            operation: operation.clone(),
        };
        let verify = |body: &TransactionBody| {
            verify_intent(body, [7; 32], sender, 9, 22, &operation, &10u32.into())
        };
        verify(&good).unwrap();
        for n in 0..9 {
            let mut changed = good.clone();
            match n {
                0 => changed.chain_id = [8; 32],
                1 => changed.sender = crypto::public_key(&[4; 32]).unwrap(),
                2 => changed.nonce = 10,
                3 => changed.expiry_height = 23,
                4 => changed.fee = 11u32.into(),
                5 => changed.fee = Amount::zero(),
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
    }
    async fn mock_rpc(
        State(node): State<Arc<Mutex<MockNode>>>,
        Json(request): Json<Value>,
    ) -> Response {
        let mut node = node.lock().await;
        let p = &request["params"];
        let result = match request["method"].as_str().unwrap() {
            "snapshot" => {
                json!({"status":{"protocol_version":crate::config::PROTOCOL_VERSION,"chain_id":hex::encode([7;32]),"height":node.height},"payment_available_hash":"1000000000000000000","account":{"account":{"ordinary":"1000000000000000000","nonce":node.nonce}}})
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
                    chain_id: [7; 32],
                    sender: hex::decode(p["sender"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    nonce: p["nonce"].as_u64().unwrap(),
                    expiry_height: p["expiry_height"].as_u64().unwrap(),
                    fee: 2u32.into(),
                    operation,
                };
                serde_json::to_value(wallet::unsigned(&body)).unwrap()
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
            "getblock" => {
                serde_json::to_value(node.blocks.get(&p["height"].as_u64().unwrap()).unwrap())
                    .unwrap()
            }
            other => panic!("unexpected RPC {other}"),
        };
        Json(json!({"jsonrpc":"2.0","id":1,"result":result})).into_response()
    }
    async fn mock() -> (Arc<Mutex<MockNode>>, SocketAddr, JoinHandle<()>) {
        let node = Arc::new(Mutex::new(MockNode {
            height: 1,
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
        // Changing the canonical receipt halts new payouts instead of paying again.
        node.lock().await.blocks.get_mut(&3).unwrap().header.nonce = 99;
        assert!(engine.refresh().await.is_err());
        assert!(engine.fault);
        assert!(
            engine
                .status(Some(&recipient(3)), "a")
                .unwrap()
                .get("claim")
                .is_none()
        );
        assert!(engine.claim(&recipient(3), "a").await.is_err());
        assert!(engine.claim(&recipient(4), "b").await.is_err());
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
    async fn expiry_keeps_quotas_and_pending_reorganization_pauses_without_resending() {
        let dir = TempDir::new().unwrap();
        let mut c = config(&dir);
        let (node, rpc, task) = mock().await;
        c.rpc_url = format!("http://{rpc}/rpc");
        let mut engine = Engine::open(c.clone()).unwrap();
        engine.refresh().await.unwrap();
        node.lock().await.height = 2;
        engine.refresh().await.unwrap();
        let result = engine.claim(&recipient(3), "a").await.unwrap();
        node.lock().await.height = 23;
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
        node.lock().await.height = 22;
        assert!(engine.refresh().await.is_err());
        assert!(engine.fault);
        assert_eq!(engine.state().unwrap(), "unavailable");
        assert!(engine.claim(&recipient(5), "c").await.is_err());
        assert_eq!(node.lock().await.transactions.len(), 2);
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
}
