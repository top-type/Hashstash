//! Optional, trusted custodian. This service has no consensus privileges.
//! Customer liabilities and exact signed bytes are durable before broadcast.
use crate::{address, codec, crypto, mail, types::*, wallet};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, anyhow, ensure};
use hkdf::Hkdf;
use num_traits::Zero;
use rusqlite::{Connection, OptionalExtension, params};
use secp256k1::{Parity, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;

pub const SUBJECT: &str = "hashstash.mix/1";
pub const MAX_ADDRESSES: usize = 8;

fn atoms(s: &str) -> Result<Amount> {
    ensure!(
        !s.is_empty()
            && s.len() <= 155
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0')),
        "invalid amount"
    );
    let n = Amount::parse_bytes(s.as_bytes(), 10).context("invalid amount")?;
    ensure!(n.bits() <= 512, "oversized amount");
    Ok(n)
}
fn hash(s: &str) -> Result<Hash> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid hash"
    );
    hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("invalid hash"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixerConfig {
    pub rpc_url: String,
    pub chain_id: String,
    pub key_file: PathBuf,
    pub database: PathBuf,
    pub status_file: PathBuf,
    pub denomination_atoms: String,
    pub service_fee_bps: u16,
    pub payout_fee_cap_atoms: String,
    pub minimum_deposits: u16,
    pub confirmations: u16,
    pub timeout_seconds: u64,
    pub poll_seconds: u64,
    pub max_deposits: u32,
}
impl MixerConfig {
    pub fn read(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::metadata(path)?.len() <= 16384,
            "configuration is too large"
        );
        let c: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        hash(&self.chain_id)?;
        let u = reqwest::Url::parse(&self.rpc_url)?;
        ensure!(
            u.scheme() == "http"
                && u.host_str()
                    .and_then(|v| v.parse::<IpAddr>().ok())
                    .is_some_and(|v| v.is_loopback())
                && u.username().is_empty()
                && u.password().is_none()
                && u.query().is_none()
                && u.fragment().is_none(),
            "mixer requires a private loopback RPC"
        );
        ensure!(
            !atoms(&self.denomination_atoms)?.is_zero()
                && !atoms(&self.payout_fee_cap_atoms)?.is_zero(),
            "positive denomination and fee cap required"
        );
        ensure!(
            self.service_fee_bps <= 1000
                && (2..=100).contains(&self.minimum_deposits)
                && (2..=100).contains(&self.confirmations),
            "invalid fee or confirmation/batch policy"
        );
        ensure!(
            (60..=2_592_000).contains(&self.timeout_seconds)
                && (2..=300).contains(&self.poll_seconds)
                && (1..=100_000).contains(&self.max_deposits),
            "invalid service bounds"
        );
        ensure!(
            self.database != self.key_file
                && self.status_file != self.database
                && self.status_file != self.key_file,
            "service paths must differ"
        );
        Ok(())
    }
    pub fn terms(&self, public: &PublicKey) -> Value {
        // serde_json's default Map is sorted; every string here is ASCII.
        json!({"version":1,"chain_id":self.chain_id,"public_key":hex::encode(public),"denomination_atoms":self.denomination_atoms,"service_fee_bps":self.service_fee_bps,"payout_fee_cap_atoms":self.payout_fee_cap_atoms,"minimum_deposits":self.minimum_deposits,"confirmations":self.confirmations,"timeout_seconds":self.timeout_seconds,"max_addresses":MAX_ADDRESSES})
    }
    pub fn descriptor(&self, public: &PublicKey) -> Result<Value> {
        let terms = self.terms(public);
        Ok(
            json!({"terms_id":terms_id(&terms)?,"terms":terms,"address":address::encode(public,&hash(&self.chain_id)?)?}),
        )
    }
}
pub fn terms_id(terms: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(terms)?)))
}

pub fn init_key(path: &Path, chain_id: &str) -> Result<Value> {
    let chain = hash(chain_id)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    loop {
        getrandom::fill(secret.as_mut()).map_err(|e| anyhow!("randomness: {e}"))?;
        if SecretKey::from_byte_array(*secret).is_ok() {
            break;
        }
    }
    let public = crypto::public_key(&secret)?;
    let encoded = Zeroizing::new(format!(
        "{{\"private_key\":\"{}\",\"public_key\":\"{}\"}}\n",
        hex::encode(*secret),
        hex::encode(public)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    Ok(json!({"public_key":hex::encode(public),"address":address::encode(&public,&chain)?}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    private_key: String,
    public_key: String,
}
fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        std::fs::metadata(path)?.len() <= 4096,
        "key file is too large"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
            "key file permissions must exclude group and other users"
        );
    }
    let bytes = Zeroizing::new(std::fs::read(path)?);
    let mut k: KeyFile = serde_json::from_slice(&bytes)?;
    let secret = Zeroizing::new(hash(&k.private_key)?);
    use zeroize::Zeroize;
    k.private_key.zeroize();
    ensure!(
        hex::encode(crypto::public_key(&secret)?) == k.public_key,
        "key file public key differs"
    );
    Ok(secret)
}
pub fn describe(c: &MixerConfig) -> Result<Value> {
    c.validate()?;
    c.descriptor(&crypto::public_key(&*read_key(&c.key_file)?)?)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Plaintext {
    recipient: String,
    subject: String,
    body: String,
}

/// Uses the same x-only ECDH, HKDF and AEAD domains as the browser, tested
/// against its independently generated public fixture. No key leaves service memory.
fn decrypt(secret: &[u8; 32], tx: &Transaction) -> Result<Plaintext> {
    let e = mail::decode(&tx.body.data).context("not a mail envelope")?;
    let own = crypto::public_key(secret)?;
    let mut key = SecretKey::from_byte_array(*secret)?;
    let pair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &key);
    if pair.x_only_public_key().1 == Parity::Odd {
        key = key.negate();
    }
    let ephemeral = hash(&e.ephemeral_key)?;
    let peer = XOnlyPublicKey::from_byte_array(ephemeral)?.public_key(Parity::Even);
    let shared = Zeroizing::new(secp256k1::ecdh::shared_secret_point(&peer, &key));
    let role = if own == tx.body.sender {
        "sender"
    } else {
        "recipient"
    };
    let mut common = b"Hashstash/Mail/v2\0".to_vec();
    common.extend(tx.body.chain_id);
    common.extend(tx.body.sender);
    common.extend(tx.body.nonce.to_le_bytes());
    common.extend(ephemeral);
    let mut info = format!("Hashstash/Mail/v2/{role}\0").into_bytes();
    info.extend(&common);
    info.extend(own);
    let mut wrap_key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&tx.body.chain_id), &shared[..32])
        .expand(&info, wrap_key.as_mut())
        .map_err(|_| anyhow!("HKDF failed"))?;
    let mut aad = common.clone();
    aad.extend(format!("/{role}").as_bytes());
    let (iv, wrapped) = if role == "sender" {
        (&e.sender_iv, &e.sender_key)
    } else {
        (&e.recipient_iv, &e.recipient_key)
    };
    let iv = hex::decode(iv)?;
    let wrapped = hex::decode(wrapped)?;
    let content_key = Zeroizing::new(
        Aes256Gcm::new_from_slice(wrap_key.as_ref())
            .map_err(|_| anyhow!("key length"))?
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &wrapped,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("not addressed to this key"))?,
    );
    let iv = hex::decode(e.iv)?;
    let ciphertext = hex::decode(e.ciphertext)?;
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(&content_key)
            .map_err(|_| anyhow!("key length"))?
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &ciphertext,
                    aad: &common,
                },
            )
            .map_err(|_| anyhow!("message authentication failed"))?,
    );
    ensure!(plain.len() == 1152, "bad padding length");
    let n = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    ensure!(
        n <= 1150 && plain[n + 2..].iter().all(|v| *v == 0),
        "bad padding"
    );
    let decoded: Plaintext = serde_json::from_slice(&plain[2..n + 2])?;
    ensure!(
        serde_json::to_vec(&decoded)? == plain[2..n + 2],
        "noncanonical message"
    );
    ensure!(
        decoded.subject.len() <= 96
            && decoded.body.len() <= 768
            && !decoded.subject.trim().is_empty()
            && !decoded.body.trim().is_empty(),
        "message text bounds"
    );
    ensure!(
        [&decoded.subject, &decoded.body]
            .iter()
            .all(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t')),
        "invalid message controls"
    );
    let recipient = hash(&decoded.recipient)?;
    ensure!(
        crypto::valid_key(&recipient) && (role == "sender" || recipient == own),
        "wrong encrypted recipient"
    );
    Ok(decoded)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instructions {
    terms: String,
    addresses: Vec<String>,
}
fn instructions(
    body: &str,
    expected: &str,
    chain: &Hash,
    sender: &PublicKey,
    custodian: &PublicKey,
) -> Result<Vec<String>> {
    ensure!(
        body.len() <= 768 && body.is_ascii(),
        "oversized instructions"
    );
    let i: Instructions = serde_json::from_str(body)?;
    ensure!(
        serde_json::to_string(&i)? == body && i.terms == expected,
        "terms or encoding differ"
    );
    ensure!(
        !i.addresses.is_empty() && i.addresses.len() <= MAX_ADDRESSES,
        "invalid number of addresses"
    );
    let mut seen = BTreeSet::new();
    for a in &i.addresses {
        let k = address::decode(a, chain)?;
        ensure!(
            address::encode(&k, chain)? == *a && k != *sender && k != *custodian && seen.insert(k),
            "duplicate, noncanonical or unsafe payout address"
        );
    }
    Ok(i.addresses)
}
fn service_fee(d: &Amount, bps: u16) -> Amount {
    (d * u32::from(bps) + Amount::from(9999u32)) / 10000u32
}
fn affordable_slots(
    balance: &Amount,
    d: &Amount,
    fee: &Amount,
    cap: &Amount,
    addresses: usize,
) -> usize {
    // A refund allowance stays reserved even if all requested slots fit.
    if balance <= cap {
        return 0;
    }
    let budget = balance - cap;
    let per = d + fee + cap;
    (0..addresses)
        .take_while(|i| &per * Amount::from(i + 1) <= budget)
        .count()
}

#[derive(Clone)]
struct Deposit {
    id: String,
    sender: String,
    remaining: Amount,
    deadline: u64,
    height: u64,
    block: String,
    state: String,
}
#[derive(Clone)]
struct Outgoing {
    id: i64,
    deposit: String,
    slot: Option<i64>,
    amount: Amount,
    service: Amount,
    cap: Amount,
    nonce: u64,
    expiry: u64,
    height: u64,
    txid: String,
    raw: String,
}

struct Ledger {
    db: Connection,
}
impl Ledger {
    fn open(path: &Path, binding: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let parent = path.parent().context("ledger requires private directory")?;
            ensure!(
                std::fs::metadata(parent)?.permissions().mode() & 0o077 == 0,
                "ledger directory must be private (0700)"
            );
            if !path.exists() {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?
                    .sync_all()?;
            }
            ensure!(
                std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                "ledger file must be private (0600)"
            );
        }
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(100))?;
        // Retains the write lock for this connection, preventing duplicate runners.
        db.execute_batch("PRAGMA locking_mode=EXCLUSIVE; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS deposits(id TEXT PRIMARY KEY,sender TEXT NOT NULL,amount TEXT NOT NULL,remaining TEXT NOT NULL,deadline INTEGER NOT NULL,height INTEGER NOT NULL,block TEXT NOT NULL,state TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS slots(id INTEGER PRIMARY KEY,deposit TEXT NOT NULL,address TEXT NOT NULL,state TEXT NOT NULL,UNIQUE(deposit,address));
          CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,deposit TEXT NOT NULL,slot INTEGER,amount TEXT NOT NULL,service TEXT NOT NULL,cap TEXT NOT NULL,nonce TEXT NOT NULL,expiry INTEGER NOT NULL,height INTEGER NOT NULL,txid TEXT NOT NULL UNIQUE,raw TEXT NOT NULL,state TEXT NOT NULL,receipt_height INTEGER,receipt_hash TEXT,actual_fee TEXT);
          CREATE UNIQUE INDEX IF NOT EXISTS one_pending_mixer_payment ON outbox((1)) WHERE state='pending';")?;
        let got: Option<String> = db
            .query_row("SELECT v FROM meta WHERE k='binding'", [], |r| r.get(0))
            .optional()?;
        if let Some(got) = got {
            ensure!(
                got == binding,
                "ledger belongs to different chain, key, terms or schema"
            );
        } else {
            db.execute("INSERT INTO meta VALUES('binding',?1)", [binding])?;
        }
        Ok(Self { db })
    }
    fn get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .db
            .query_row("SELECT v FROM meta WHERE k=?1", [key], |r| r.get(0))
            .optional()?)
    }
    fn set(&self, key: &str, value: &str) -> Result<()> {
        self.db.execute(
            "INSERT INTO meta VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            params![key, value],
        )?;
        Ok(())
    }
    fn checkpoint(&mut self, cursor: &str, anchor: &str, height: u64) -> Result<()> {
        let tx = self.db.transaction()?;
        for (k, v) in [
            ("cursor", cursor.to_owned()),
            ("anchor", anchor.to_owned()),
            ("anchor_height", height.to_string()),
        ] {
            tx.execute(
                "INSERT INTO meta VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                params![k, v],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn deposits(&self) -> Result<Vec<Deposit>> {
        let mut statement = self.db.prepare("SELECT id,sender,remaining,deadline,height,block,state FROM deposits ORDER BY height,id")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, sender, remaining, deadline, height, block, state)| {
                Ok(Deposit {
                    id,
                    sender,
                    remaining: atoms(&remaining)?,
                    deadline,
                    height,
                    block,
                    state,
                })
            })
            .collect()
    }
    fn pending(&self) -> Result<Option<Outgoing>> {
        let row = self.db.query_row("SELECT id,deposit,slot,amount,service,cap,nonce,expiry,height,txid,raw FROM outbox WHERE state='pending'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional()?;
        row.map(
            |(id, deposit, slot, a, s, c, n, expiry, height, txid, raw)| {
                Ok(Outgoing {
                    id,
                    deposit,
                    slot,
                    amount: atoms(&a)?,
                    service: atoms(&s)?,
                    cap: atoms(&c)?,
                    nonce: n.parse()?,
                    expiry,
                    height,
                    txid,
                    raw,
                })
            },
        )
        .transpose()
    }
    fn add(&mut self, d: &Deposit, addresses: &[String], maximum: u32) -> Result<()> {
        let tx = self.db.transaction()?;
        let count: u32 = tx.query_row("SELECT COUNT(*) FROM deposits", [], |r| r.get(0))?;
        ensure!(
            count < maximum,
            "mixer ledger capacity reached; operator review required"
        );
        tx.execute(
            "INSERT INTO deposits VALUES(?1,?2,?3,?3,?4,?5,?6,?7)",
            params![
                d.id,
                d.sender,
                d.remaining.to_str_radix(10),
                d.deadline,
                d.height,
                d.block,
                d.state
            ],
        )?;
        for a in addresses {
            tx.execute(
                "INSERT INTO slots(deposit,address,state) VALUES(?1,?2,'queued')",
                params![d.id, a],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn journal(&mut self, o: &Outgoing) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute("INSERT INTO outbox(deposit,slot,amount,service,cap,nonce,expiry,height,txid,raw,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending')",params![o.deposit,o.slot,o.amount.to_str_radix(10),o.service.to_str_radix(10),o.cap.to_str_radix(10),o.nonce.to_string(),o.expiry,o.height,o.txid,o.raw])?;
        if let Some(slot) = o.slot {
            ensure!(
                tx.execute(
                    "UPDATE slots SET state='pending' WHERE id=?1 AND state='ready'",
                    [slot]
                )? == 1,
                "slot was already assigned"
            );
        }
        tx.commit()?;
        Ok(())
    }
    fn settle(&mut self, o: &Outgoing, fee: &Amount, height: u64, block: &str) -> Result<()> {
        ensure!(
            *fee <= o.cap,
            "receipt exceeded reserved network-fee allowance"
        );
        let tx = self.db.transaction()?;
        let s: String = tx.query_row(
            "SELECT remaining FROM deposits WHERE id=?1",
            [&o.deposit],
            |r| r.get(0),
        )?;
        let remaining = atoms(&s)?;
        let debit = &o.amount + fee + &o.service;
        ensure!(remaining >= debit, "payment exceeded customer allocation");
        let left = remaining - debit;
        tx.execute("UPDATE deposits SET remaining=?1,state=CASE WHEN ?1='0' THEN 'complete' WHEN ?2 THEN 'refund' ELSE state END WHERE id=?3",params![left.to_str_radix(10),o.slot.is_none(),o.deposit])?;
        tx.execute("UPDATE outbox SET state='confirmed',receipt_height=?1,receipt_hash=?2,actual_fee=?3 WHERE id=?4 AND state='pending'",params![height,block,fee.to_str_radix(10),o.id])?;
        if let Some(slot) = o.slot {
            tx.execute("UPDATE slots SET state='paid' WHERE id=?1", [slot])?;
        } else {
            // A confirmed refund ends this request's payout plan, even when a
            // smaller exact fee leaves refundable dust in the customer balance.
            tx.execute(
                "UPDATE slots SET state='cancelled' WHERE deposit=?1 AND state IN ('queued','ready')",
                [&o.deposit],
            )?;
        }
        tx.execute(
            "INSERT INTO meta VALUES('last_nonce',?1) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [o.nonce
                .checked_add(1)
                .context("nonce overflow")?
                .to_string()],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn expire(&mut self, o: &Outgoing) -> Result<()> {
        let tx = self.db.transaction()?;
        tx.execute(
            "UPDATE outbox SET state='expired' WHERE id=?1 AND state='pending'",
            [o.id],
        )?;
        if let Some(slot) = o.slot {
            tx.execute("UPDATE slots SET state='ready' WHERE id=?1", [slot])?;
        }
        tx.commit()?;
        Ok(())
    }
}

pub struct Mixer {
    c: MixerConfig,
    secret: Zeroizing<[u8; 32]>,
    public: PublicKey,
    chain: Hash,
    terms: String,
    ledger: Ledger,
    client: reqwest::Client,
    execute: bool,
}
impl Mixer {
    pub fn open(c: MixerConfig, execute: bool) -> Result<Self> {
        c.validate()?;
        let secret = read_key(&c.key_file)?;
        let public = crypto::public_key(&secret)?;
        let chain = hash(&c.chain_id)?;
        let terms = terms_id(&c.terms(&public))?;
        let binding = format!("mixer1:{}:{}:{}", c.chain_id, hex::encode(public), terms);
        let ledger = Ledger::open(&c.database, &binding)?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            c,
            secret,
            public,
            chain,
            terms,
            ledger,
            client,
            execute,
        })
    }
    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let mut r = self
            .client
            .post(&self.c.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await?
            .error_for_status()?;
        let limit = if method == "getblock" {
            crate::node::MAX_RESPONSE_FRAME
        } else {
            4 * 1024 * 1024
        };
        ensure!(
            r.content_length().unwrap_or(0) <= limit as u64,
            "RPC reply too large"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = r.chunk().await? {
            ensure!(
                chunk.len() <= limit.saturating_sub(bytes.len()),
                "RPC reply too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            v.get("error").is_none_or(Value::is_null),
            "node refused mixer request"
        );
        v.get("result").cloned().context("missing RPC result")
    }
    fn pause<T>(&self, reason: &str) -> Result<T> {
        self.ledger.set("paused", reason)?;
        anyhow::bail!("{reason}")
    }
    async fn block(&self, height: u64) -> Result<Block> {
        serde_json::from_value(self.rpc("getblock", json!({"height":height})).await?)
            .map_err(Into::into)
    }
    async fn anchor(&self, height: u64, expected: &str, tipheight: u64) -> Result<()> {
        if height > tipheight {
            return self.pause("canonical history moved below a recorded receipt");
        }
        let b = self.block(height).await?;
        if hex::encode(crypto::sha256d(&codec::header_bytes(&b.header))) != expected {
            return self.pause(
                "recorded canonical history was reorganized; operator reconciliation required",
            );
        }
        Ok(())
    }
    async fn scan(&mut self, height: u64, clock: u64) -> Result<bool> {
        let cursor = self.ledger.get("cursor")?;
        let anchor = self.ledger.get("anchor")?;
        if let (Some(a), Some(h)) = (anchor.as_ref(), self.ledger.get("anchor_height")?) {
            self.anchor(h.parse()?, a, height).await?;
        }
        let mut p = json!({"limit":50});
        if let (Some(c), Some(a)) = (cursor, anchor) {
            p["after"] = json!(c);
            p["anchor"] = json!(a);
        }
        let page = self.rpc("explorer_mail", p).await?;
        ensure!(
            page["chain_id"] == self.c.chain_id
                && page["ready"] == true
                && integer(&page, "indexed_height")? == height,
            "mail index is not caught up"
        );
        let a = text(&page, "anchor")?.to_owned();
        self.anchor(height, &a, height).await?;
        let messages = page["messages"].as_array().context("missing messages")?;
        ensure!(messages.len() <= 50, "mail page overflow");
        for item in messages {
            let h = integer(item, "height")?;
            if height.saturating_sub(h).saturating_add(1) < u64::from(self.c.confirmations) {
                return Ok(true);
            }
            let id = text(item, "txid")?;
            let known: bool = self.ledger.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM deposits WHERE id=?1)",
                [id],
                |r| r.get(0),
            )?;
            if !known {
                let b = self.block(h).await?;
                ensure!(
                    hex::encode(crypto::sha256d(&codec::header_bytes(&b.header)))
                        == text(item, "block_hash")?,
                    "mail page changed during scan"
                );
                let tx = b
                    .transactions
                    .iter()
                    .find(|t| hex::encode(codec::transaction_id(t)) == id)
                    .context("mail transaction missing from canonical block")?;
                crypto::verify(tx)?;
                if let Operation::TransferExact {
                    recipient, amount, ..
                } = tx.body.operation.clone()
                    && recipient == self.public
                    && !amount.is_zero()
                    && tx.body.sender != self.public
                    && tx.body.chain_id == self.chain
                {
                    // A valid envelope sent to this custodian is refundable even
                    // when its encrypted instructions cannot be understood.
                    let parsed = decrypt(&self.secret, tx).and_then(|plain| {
                        ensure!(plain.subject == SUBJECT, "not mixer instructions");
                        instructions(
                            &plain.body,
                            &self.terms,
                            &self.chain,
                            &tx.body.sender,
                            &self.public,
                        )
                    });
                    let (state, addresses) = match parsed {
                        Ok(a) => ("queued", a),
                        Err(_) => ("refund", Vec::new()),
                    };
                    let d = Deposit {
                        id: id.into(),
                        sender: hex::encode(tx.body.sender),
                        remaining: amount,
                        deadline: clock
                            .checked_add(self.c.timeout_seconds)
                            .context("deadline overflow")?,
                        height: h,
                        block: text(item, "block_hash")?.into(),
                        state: state.into(),
                    };
                    self.ledger.add(&d, &addresses, self.c.max_deposits)?;
                }
            }
            let c = format!("{}:{}", h, integer(item, "position")?);
            self.ledger.checkpoint(&c, &a, height)?;
        }
        self.ledger
            .checkpoint(text(&page, "scan_cursor")?, &a, height)?;
        Ok(page["next_cursor"].is_null())
    }
    async fn reconcile(&mut self, o: &Outgoing, height: u64, nonce: u64) -> Result<()> {
        let signed = wallet::decode_signed(&o.raw)?;
        crypto::verify(&signed)?;
        let d = self
            .ledger
            .deposits()?
            .into_iter()
            .find(|d| d.id == o.deposit)
            .context("missing deposit")?;
        let recipient = if let Some(slot) = o.slot {
            let a: String = self.ledger.db.query_row(
                "SELECT address FROM slots WHERE id=?1 AND deposit=?2",
                params![slot, o.deposit],
                |r| r.get(0),
            )?;
            address::decode(&a, &self.chain)?
        } else {
            hash(&d.sender)?
        };
        verify_intent(
            &signed.body,
            self.chain,
            self.public,
            o.nonce,
            o.expiry,
            &recipient,
            &o.amount,
            &o.cap,
        )?;
        ensure!(
            hex::encode(codec::transaction_id(&signed)) == o.txid,
            "stored signed transaction changed"
        );
        if nonce > o.nonce {
            if nonce != o.nonce.checked_add(1).context("nonce overflow")? {
                return self.pause("custodian nonce consumed outside recorded payment");
            }
            let mut included = None;
            for h in o.height.saturating_add(1)..=height.min(o.expiry) {
                let b = self.block(h).await?;
                if b.transactions.iter().any(|t| t == &signed) {
                    included = Some((
                        h,
                        hex::encode(crypto::sha256d(&codec::header_bytes(&b.header))),
                    ));
                    break;
                }
            }
            let Some((included_height, included_hash)) = included else {
                return self.pause(
                    "custodian nonce consumed without its exact recorded canonical payment",
                );
            };
            let receipt = self
                .rpc("explorer_transaction", json!({"txid":o.txid}))
                .await?;
            let r = &receipt["transaction"];
            if r["status"] != "confirmed" {
                return self.pause("custodian nonce consumed without canonical recorded payout");
            }
            let h = integer(r, "height")?;
            if h != included_height || text(r, "block_hash")? != included_hash {
                return self.pause("canonical payout and fee receipt disagree");
            }
            self.anchor(h, text(r, "block_hash")?, height).await?;
            let b = self.block(h).await?;
            if !b
                .transactions
                .iter()
                .any(|t| codec::transaction_id(t) == codec::transaction_id(&signed) && t == &signed)
            {
                return self.pause("payout receipt differs from exact signed transaction");
            }
            if height.saturating_sub(h).saturating_add(1) >= u64::from(self.c.confirmations) {
                let fee = atoms(text(r, "fee")?)?;
                ensure!(
                    fee == signed.body.fee,
                    "canonical fee receipt differs from signed exact charge"
                );
                self.ledger.settle(o, &fee, h, text(r, "block_hash")?)?;
            }
        } else if nonce < o.nonce || height < o.height {
            return self.pause("custodian nonce or height rolled backwards");
        } else if height > o.expiry {
            self.ledger.expire(o)?;
        } else if self.execute {
            let _ = self.rpc("broadcasttransaction", json!({"raw":o.raw})).await;
        }
        Ok(())
    }
    async fn quote(
        &self,
        recipient: PublicKey,
        amount: &Amount,
        nonce: u64,
        expiry: u64,
        cap: &Amount,
    ) -> Result<Amount> {
        let operation = Operation::TransferExact {
            recipient,
            amount: amount.clone(),
        };
        let q=self.rpc("fee_quote",json!({"sender":hex::encode(self.public),"operation":operation,"nonce":nonce,"expiry_height":expiry,"extra_fee":"0"})).await?;
        let fee = atoms(text(&q, "fee")?)?;
        ensure!(fee <= *cap, "network fee exceeds published allowance");
        Ok(fee)
    }
    // Keep the independently checked payment, fee and chain context explicit.
    #[allow(clippy::too_many_arguments)]
    async fn send(
        &mut self,
        d: &Deposit,
        slot: Option<i64>,
        recipient: PublicKey,
        amount: Amount,
        service: Amount,
        cap: Amount,
        height: u64,
        nonce: u64,
    ) -> Result<()> {
        let expiry = height.checked_add(20).context("expiry overflow")?;
        let exact_fee = self.quote(recipient, &amount, nonce, expiry, &cap).await?;
        ensure!(
            d.remaining >= &amount + &service + &cap,
            "customer budget exceeded"
        );
        if !self.execute {
            return Ok(());
        }
        let operation = Operation::TransferExact {
            recipient,
            amount: amount.clone(),
        };
        let result=self.rpc("preparetransaction",json!({"sender":hex::encode(self.public),"operation":operation,"nonce":nonce,"expiry_height":expiry,"fee":exact_fee.to_str_radix(10)})).await?;
        let body = wallet::decode_unsigned(&wallet::UnsignedEnvelope {
            format: text(&result, "format")?.into(),
            body: text(&result, "body")?.into(),
        })?;
        ensure!(
            body.fee == exact_fee,
            "prepared payout changed exact quoted fee"
        );
        verify_intent(
            &body,
            self.chain,
            self.public,
            nonce,
            expiry,
            &recipient,
            &amount,
            &exact_fee,
        )?;
        let signed = crypto::sign(&body, &self.secret)?;
        let o = Outgoing {
            id: 0,
            deposit: d.id.clone(),
            slot,
            amount,
            service,
            cap,
            nonce,
            expiry,
            height,
            txid: hex::encode(codec::transaction_id(&signed)),
            raw: wallet::signed_hex(&signed),
        };
        self.ledger.journal(&o)?;
        let _ = self.rpc("broadcasttransaction", json!({"raw":o.raw})).await;
        Ok(())
    }
    pub async fn tick(&mut self) -> Result<&'static str> {
        if self.ledger.get("paused")?.is_some() {
            return Ok("operator_review");
        }
        let s = self
            .rpc("snapshot", json!({"key":hex::encode(self.public)}))
            .await?;
        let status = &s["status"];
        if status["chain_id"] != self.c.chain_id
            || integer(status, "protocol_version")? != u64::from(crate::config::PROTOCOL_VERSION)
        {
            return self.pause("wrong node chain or protocol");
        }
        let height = integer(status, "height")?;
        let clock = integer(status, "clock")?;
        ensure!(
            height <= i64::MAX as u64 && clock <= i64::MAX as u64,
            "height or clock outside ledger range"
        );
        let nonce = if s["account"].is_null() {
            0
        } else {
            integer(&s["account"]["account"], "nonce")?
        };
        if let Some(last) = self.ledger.get("last_nonce")?
            && nonce < last.parse::<u64>()?
        {
            return self.pause("custodian nonce moved backwards");
        }
        let deposits = self.ledger.deposits()?;
        // Canonicality of the newest receipt on a linked chain covers ancestors.
        let newest_deposit = deposits
            .iter()
            .max_by_key(|d| d.height)
            .map(|d| (d.height, d.block.clone()));
        let newest_payment:Option<(u64,String)>=self.ledger.db.query_row("SELECT receipt_height,receipt_hash FROM outbox WHERE state='confirmed' ORDER BY receipt_height DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        for (h, b) in newest_deposit.into_iter().chain(newest_payment) {
            self.anchor(h, &b, height).await?;
        }
        if let Some(o) = self.ledger.pending()? {
            self.reconcile(&o, height, nonce).await?;
            self.ledger.set("last_nonce", &nonce.to_string())?;
            return Ok("confirming_payment");
        }
        if let Some(last) = self.ledger.get("last_nonce")?
            && nonce != last.parse::<u64>()?
        {
            return self.pause("custodian account used outside its durable journal");
        }
        self.ledger.set("last_nonce", &nonce.to_string())?;
        if !self.scan(height, clock).await? {
            return Ok("scanning_or_confirming_deposits");
        }
        let funds = if s["account"].is_null() {
            Amount::zero()
        } else {
            atoms(text(&s, "payment_available_hash")?)?
        };
        let deposits = self.ledger.deposits()?;
        let obligations: Amount = deposits.iter().map(|d| d.remaining.clone()).sum();
        if funds < obligations {
            return self
                .pause("ordinary funds do not cover all customer liabilities in both outcomes");
        }
        let cap = atoms(&self.c.payout_fee_cap_atoms)?;
        let denomination = atoms(&self.c.denomination_atoms)?;
        let service = service_fee(&denomination, self.c.service_fee_bps);
        let mut candidates = Vec::new();
        let mut ready = Vec::new();
        let mut senders = BTreeSet::new();
        for d in &deposits {
            if d.remaining.is_zero() {
                continue;
            }
            let mut statement=self.ledger.db.prepare("SELECT id,address,state FROM slots WHERE deposit=?1 AND state IN ('queued','ready') ORDER BY id")?;
            let slots = statement
                .query_map([&d.id], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(statement);
            let possible =
                affordable_slots(&d.remaining, &denomination, &service, &cap, slots.len());
            if d.state == "refund" || clock >= d.deadline || slots.is_empty() || possible == 0 {
                // Invalid instructions wait for the same advertised deadline.
                if d.state == "refund" && clock < d.deadline {
                    continue;
                }
                let expiry = height.checked_add(20).context("expiry overflow")?;
                let quote = self
                    .quote(hash(&d.sender)?, &d.remaining, nonce, expiry, &cap)
                    .await?;
                if d.remaining <= quote {
                    continue;
                }
                let amount = &d.remaining - &quote;
                // Sign the quote as the cap: a price increase safely expires the
                // attempt; a decrease leaves a durable, refundable dust credit.
                self.send(
                    d,
                    None,
                    hash(&d.sender)?,
                    amount,
                    Amount::zero(),
                    quote,
                    height,
                    nonce,
                )
                .await?;
                return Ok(if self.execute {
                    "refunding"
                } else {
                    "would_refund"
                });
            }
            senders.insert(d.sender.clone());
            for (id, a, state) in slots.into_iter().take(possible) {
                if state == "ready" {
                    ready.push((d.clone(), id, a));
                } else {
                    candidates.push((d.clone(), id, a));
                }
            }
        }
        if ready.is_empty() {
            if senders.len() < usize::from(self.c.minimum_deposits) {
                return Ok("waiting_for_depositors");
            }
            if self.execute {
                let batch = self.ledger.db.transaction()?;
                for (_, id, _) in &candidates {
                    batch.execute(
                        "UPDATE slots SET state='ready' WHERE id=?1 AND state='queued'",
                        [id],
                    )?;
                }
                batch.commit()?;
            }
            ready = candidates;
        }
        let Some(index) = random_index(ready.len())? else {
            return Ok("waiting_for_depositors");
        };
        let (d, slot, a) = &ready[index];
        self.send(
            d,
            Some(*slot),
            address::decode(a, &self.chain)?,
            denomination,
            service,
            cap,
            height,
            nonce,
        )
        .await?;
        Ok(if self.execute { "paying" } else { "would_pay" })
    }
    pub fn write_status(&self, state: &str) -> Result<()> {
        let deposits: u64 = self.ledger.db.query_row(
            "SELECT COUNT(*) FROM deposits WHERE remaining!='0'",
            [],
            |r| r.get(0),
        )?;
        let slots: u64 = self.ledger.db.query_row(
            "SELECT COUNT(*) FROM slots s JOIN deposits d ON d.id=s.deposit WHERE s.state IN ('queued','ready') AND d.state='queued' AND d.remaining!='0'",
            [],
            |r| r.get(0),
        )?;
        let paid: u64 = self.ledger.db.query_row(
            "SELECT COUNT(*) FROM outbox WHERE state='confirmed' AND slot IS NOT NULL",
            [],
            |r| r.get(0),
        )?;
        let descriptor = self.c.descriptor(&self.public)?;
        let status = json!({"descriptor":descriptor,"state":state,"execute":self.execute,"active_deposits":deposits,"queued_outputs":slots,"confirmed_outputs":paid,"operator_review":self.ledger.get("paused")?.is_some()});
        // Contains no deposit IDs, sender/address mapping, ciphertext or secrets.
        let temporary = self.c.status_file.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec(&status)?)?;
        std::fs::rename(temporary, &self.c.status_file)?;
        Ok(())
    }
    pub async fn run(mut self, once: bool) -> Result<()> {
        loop {
            let state = match self.tick().await {
                Ok(s) => s,
                Err(error) => {
                    // Errors contain local invariants or transport diagnostics;
                    // remote error bodies and decrypted content are never used.
                    eprintln!("mixer unavailable: {error}");
                    if self.ledger.get("paused")?.is_some() {
                        "operator_review"
                    } else {
                        "unavailable"
                    }
                }
            };
            self.write_status(state)?;
            println!("mixer state: {state}");
            if let Some(reason) = self.ledger.get("paused")? {
                eprintln!("mixer paused: {reason}");
            }
            if once {
                return Ok(());
            }
            tokio::select! {_=tokio::signal::ctrl_c()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(self.c.poll_seconds))=>{}}
        }
    }
}
fn random_index(n: usize) -> Result<Option<usize>> {
    if n == 0 {
        return Ok(None);
    }
    let n = u64::try_from(n)?;
    let limit = u64::MAX - u64::MAX % n;
    loop {
        let mut b = [0; 8];
        getrandom::fill(&mut b).map_err(|e| anyhow!("randomness: {e}"))?;
        let r = u64::from_le_bytes(b);
        if r < limit {
            return Ok(Some((r % n) as usize));
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn verify_intent(
    body: &TransactionBody,
    chain: Hash,
    sender: PublicKey,
    nonce: u64,
    expiry: u64,
    recipient: &PublicKey,
    amount: &Amount,
    cap: &Amount,
) -> Result<()> {
    ensure!(
        body.chain_id == chain
            && body.sender == sender
            && body.nonce == nonce
            && body.expiry_height == expiry
            && !body.fee.is_zero()
            && body.fee <= *cap,
        "prepared payout changed identity, nonce, expiry or fee"
    );
    ensure!(
        body.data.is_empty()
            && body.operation
                == Operation::TransferExact {
                    recipient: *recipient,
                    amount: amount.clone(),
                },
        "prepared payout changed operation or added data"
    );
    Ok(())
}

#[cfg(test)]
#[path = "mixer_ledger_tests.rs"]
mod ledger_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }
    fn config(dir: &Path) -> MixerConfig {
        MixerConfig {
            rpc_url: "http://127.0.0.1:1".into(),
            chain_id: "07".repeat(32),
            key_file: dir.join("signer.json"),
            database: dir.join("ledger.sqlite"),
            status_file: dir.join("status.json"),
            denomination_atoms: "100".into(),
            service_fee_bps: 100,
            payout_fee_cap_atoms: "10".into(),
            minimum_deposits: 2,
            confirmations: 2,
            timeout_seconds: 3600,
            poll_seconds: 2,
            max_deposits: 100,
        }
    }
    fn public(n: u8) -> PublicKey {
        crypto::public_key(&[n; 32]).unwrap()
    }
    fn block(height: u64, previous: Hash) -> Block {
        Block {
            header: Header {
                version: 20,
                previous,
                merkle_root: [0; 32],
                timestamp: height as u32,
                bits: 0x207fffff,
                nonce: 0,
            },
            height,
            miner: public(3),
            state_root: [0; 32],
            extranonce: [0; 8],
            transactions: vec![],
        }
    }
    fn block_hash(b: &Block) -> String {
        hex::encode(crypto::sha256d(&codec::header_bytes(&b.header)))
    }
    fn deposit(id: u8, sender: u8) -> Deposit {
        Deposit {
            id: format!("{id:02x}").repeat(32),
            sender: hex::encode(public(sender)),
            remaining: 250u32.into(),
            deadline: 3700,
            height: 1,
            block: "ab".repeat(32),
            state: "queued".into(),
        }
    }
    fn fixture() -> (Transaction, Value) {
        let f: Value =
            serde_json::from_str(include_str!("../tests/fixtures/mail-v2.json")).unwrap();
        let tx = Transaction {
            body: TransactionBody {
                chain_id: hash(text(&f["identity"], "chain_id").unwrap()).unwrap(),
                sender: hash(text(&f["identity"], "sender").unwrap()).unwrap(),
                nonce: text(&f["identity"], "nonce").unwrap().parse().unwrap(),
                fee: 1u32.into(),
                expiry_height: 100,
                operation: Operation::TransferExact {
                    recipient: public(4),
                    amount: 1u32.into(),
                },
                data: hex::decode(text(&f, "data_hex").unwrap()).unwrap(),
            },
            signature: [0; 64],
        };
        (tx, f)
    }
    #[test]
    fn browser_fixture_decrypts_for_recipient_and_sender_on_any_operation() {
        let (mut tx, f) = fixture();
        for role in ["sender", "recipient"] {
            let secret = hash(text(&f["private_keys"], role).unwrap()).unwrap();
            let p = decrypt(&secret, &tx).unwrap();
            assert_eq!(p.subject, f["plaintext"]["subject"]);
            assert_eq!(p.body, f["plaintext"]["body"]);
        }
        let secret = hash(text(&f["private_keys"], "recipient").unwrap()).unwrap();
        let data = tx.body.data.clone();
        tx.body.operation = {
            tx.body.data = data;
            Operation::Support {
                round: 0,
                proposal: [1; 32],
                amount: 1u32.into(),
            }
        };
        assert!(decrypt(&secret, &tx).is_ok());
        assert!(decrypt(&[9; 32], &tx).is_err());
        tx.body.nonce -= 1;
        assert!(decrypt(&secret, &tx).is_err());
        tx.body.nonce += 1;
        tx.body.chain_id[0] ^= 1;
        assert!(decrypt(&secret, &tx).is_err());
    }
    #[test]
    fn terms_are_sorted_stable_and_bind_every_policy() {
        let d = private_dir();
        let mut c = config(d.path());
        let key = public(1);
        let t = c.terms(&key);
        let encoded = serde_json::to_string(&t).unwrap();
        assert!(encoded.starts_with("{\"chain_id\":"));
        let id = terms_id(&t).unwrap();
        assert_eq!(c.descriptor(&key).unwrap()["terms_id"], id);
        c.service_fee_bps += 1;
        assert_ne!(terms_id(&c.terms(&key)).unwrap(), id);
        assert_eq!(t["max_addresses"], 8);
        assert_eq!(t["minimum_deposits"], 2);
    }
    #[test]
    fn instructions_reject_aliases_duplicates_foreign_chain_and_wrong_terms() {
        let chain = [7; 32];
        let sender = public(1);
        let custodian = public(2);
        let target = address::encode(&public(3), &chain).unwrap();
        let body = serde_json::to_string(&Instructions {
            terms: "ab".repeat(32),
            addresses: vec![target.clone()],
        })
        .unwrap();
        assert_eq!(
            instructions(&body, &"ab".repeat(32), &chain, &sender, &custodian).unwrap(),
            vec![target.clone()]
        );
        for addresses in [
            vec![target.clone(), target],
            vec![address::encode(&sender, &chain).unwrap()],
            vec![address::encode(&custodian, &chain).unwrap()],
            vec![address::encode(&public(3), &[8; 32]).unwrap()],
            vec![],
        ] {
            let b = serde_json::to_string(&Instructions {
                terms: "ab".repeat(32),
                addresses,
            })
            .unwrap();
            assert!(instructions(&b, &"ab".repeat(32), &chain, &sender, &custodian).is_err());
        }
        assert!(instructions(&body, &"cd".repeat(32), &chain, &sender, &custodian).is_err());
        assert!(
            instructions(&(body + " "), &"ab".repeat(32), &chain, &sender, &custodian).is_err()
        );
    }
    #[test]
    fn each_request_reserves_its_own_payouts_and_refund_fee() {
        let d = 100u32.into();
        let cap = 10u32.into();
        let fee = service_fee(&d, 100);
        assert_eq!(fee, 1u32.into());
        assert_eq!(service_fee(&1u32.into(), 1), 1u32.into());
        assert_eq!(affordable_slots(&231u32.into(), &d, &fee, &cap, 8), 1);
        assert_eq!(affordable_slots(&232u32.into(), &d, &fee, &cap, 8), 2);
        assert_eq!(affordable_slots(&10000u32.into(), &d, &fee, &cap, 1), 1);
        assert_eq!(affordable_slots(&10u32.into(), &d, &fee, &cap, 8), 0);
    }
    #[test]
    fn key_creation_never_replaces_and_descriptor_contains_no_secret() {
        let d = private_dir();
        let c = config(d.path());
        let first = init_key(&c.key_file, &c.chain_id).unwrap();
        assert!(init_key(&c.key_file, &c.chain_id).is_err());
        let descriptor = describe(&c).unwrap();
        assert_eq!(descriptor["address"], first["address"]);
        assert!(!descriptor.to_string().contains("private_key"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&c.key_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn ledger_locks_runner_and_binds_terms_chain_and_key() {
        let dir = private_dir();
        let path = dir.path().join("ledger.sqlite");
        let first = Ledger::open(&path, "one").unwrap();
        assert!(Ledger::open(&path, "one").is_err());
        drop(first);
        assert!(Ledger::open(&path, "two").is_err());
        assert!(Ledger::open(&path, "one").is_ok());
    }
    #[test]
    fn journal_survives_restart_prevents_double_payment_and_keeps_unused_cap() {
        let dir = private_dir();
        let path = dir.path().join("ledger.sqlite");
        let mut l = Ledger::open(&path, "one").unwrap();
        let d = deposit(1, 3);
        l.add(&d, &["address".into()], 100).unwrap();
        l.db.execute("UPDATE slots SET state='ready'", []).unwrap();
        let o = Outgoing {
            id: 0,
            deposit: d.id.clone(),
            slot: Some(1),
            amount: 100u32.into(),
            service: 1u32.into(),
            cap: 10u32.into(),
            nonce: 0,
            expiry: 20,
            height: 2,
            txid: "11".repeat(32),
            raw: "exact signed bytes".into(),
        };
        l.journal(&o).unwrap();
        assert!(l.journal(&o).is_err());
        drop(l);
        let mut l = Ledger::open(&path, "one").unwrap();
        let got = l.pending().unwrap().unwrap();
        assert_eq!(got.raw, o.raw);
        assert!(l.settle(&got, &11u32.into(), 3, &"22".repeat(32)).is_err());
        l.settle(&got, &3u32.into(), 3, &"22".repeat(32)).unwrap();
        assert!(l.pending().unwrap().is_none());
        assert_eq!(l.deposits().unwrap()[0].remaining, 146u32.into());
        assert_eq!(l.get("last_nonce").unwrap().unwrap(), "1");
    }
    #[test]
    fn strict_signer_rejects_operation_fee_nonce_and_data_substitution() {
        let recipient = public(2);
        let amount: Amount = 100u32.into();
        let cap: Amount = 10u32.into();
        let mut body = TransactionBody {
            data: Vec::new(),
            chain_id: [7; 32],
            sender: public(1),
            nonce: 0,
            expiry_height: 20,
            fee: cap.clone(),
            operation: Operation::TransferExact {
                recipient,
                amount: amount.clone(),
            },
        };
        let check = |b: &TransactionBody| {
            verify_intent(b, [7; 32], public(1), 0, 20, &recipient, &amount, &cap)
        };
        assert!(check(&body).is_ok());
        body.fee += 1u32;
        assert!(check(&body).is_err());
        body.fee -= 1u32;
        body.nonce = 1;
        assert!(check(&body).is_err());
        body.nonce = 0;
        body.operation = {
            body.data = b"extra".to_vec();
            body.operation.clone()
        };
        assert!(check(&body).is_err());
    }
    struct Mock {
        chain: String,
        public: PublicKey,
        height: u64,
        clock: u64,
        nonce: u64,
        funds: Amount,
        blocks: BTreeMap<u64, Block>,
        submitted: Vec<String>,
        phase: String,
    }
    impl Mock {
        fn new(public: PublicKey) -> Self {
            let mut blocks = BTreeMap::new();
            let mut prev = [0; 32];
            for h in 0..=10 {
                let b = block(h, prev);
                prev = hash(&block_hash(&b)).unwrap();
                blocks.insert(h, b);
            }
            Self {
                chain: "07".repeat(32),
                public,
                height: 10,
                clock: 100,
                nonce: 0,
                funds: 500u32.into(),
                blocks,
                submitted: vec![],
                phase: "auction".into(),
            }
        }
        fn include_last(&mut self) {
            let raw = self.submitted.last().unwrap();
            let t = wallet::decode_signed(raw).unwrap();
            if t.body.nonce < self.nonce {
                return;
            }
            assert_eq!(t.body.nonce, self.nonce);
            let Operation::TransferExact { amount, .. } = t.body.operation.clone() else {
                panic!()
            };
            self.funds -= amount + Amount::from(3u32);
            self.nonce += 1;
            let previous = hash(&block_hash(self.blocks.get(&self.height).unwrap())).unwrap();
            self.height += 1;
            let mut b = block(self.height, previous);
            b.transactions.push(t);
            b.header.merkle_root = [self.nonce as u8; 32];
            let previous = hash(&block_hash(&b)).unwrap();
            self.blocks.insert(self.height, b);
            self.height += 1;
            self.blocks
                .insert(self.height, block(self.height, previous));
            self.clock += 20;
        }
    }
    async fn mock_rpc(
        State(state): State<Arc<Mutex<Mock>>>,
        Json(req): Json<Value>,
    ) -> Json<Value> {
        let mut m = state.lock().unwrap();
        let p = &req["params"];
        let result = match req["method"].as_str().unwrap() {
            "snapshot" => {
                json!({"status":{"chain_id":m.chain,"protocol_version":crate::config::PROTOCOL_VERSION,"height":m.height,"clock":m.clock,"phase":m.phase},"account":{"account":{"nonce":m.nonce}},"payment_available_hash":m.funds.to_str_radix(10)})
            }
            "getblock" => {
                serde_json::to_value(m.blocks.get(&integer(p, "height").unwrap()).unwrap()).unwrap()
            }
            "explorer_mail" => {
                json!({"chain_id":m.chain,"ready":true,"indexed_height":m.height,"anchor":block_hash(m.blocks.get(&m.height).unwrap()),"messages":[],"next_cursor":null,"scan_cursor":format!("{}:9223372036854775807",m.height)})
            }
            "fee_quote" => json!({"fee":"3"}),
            "preparetransaction" => serde_json::to_value(wallet::unsigned(&TransactionBody {
                data: Vec::new(),
                chain_id: hash(&m.chain).unwrap(),
                sender: m.public,
                nonce: integer(p, "nonce").unwrap(),
                expiry_height: integer(p, "expiry_height").unwrap(),
                fee: atoms(text(p, "fee").unwrap()).unwrap(),
                operation: serde_json::from_value(p["operation"].clone()).unwrap(),
            }))
            .unwrap(),
            "broadcasttransaction" => {
                let raw = text(p, "raw").unwrap().to_owned();
                let t = wallet::decode_signed(&raw).unwrap();
                m.submitted.push(raw);
                json!({"txid":hex::encode(codec::transaction_id(&t))})
            }
            "explorer_transaction" => {
                let txid = text(p, "txid").unwrap();
                let b = m
                    .blocks
                    .values()
                    .find(|b| {
                        b.transactions
                            .iter()
                            .any(|t| hex::encode(codec::transaction_id(t)) == txid)
                    })
                    .unwrap();
                json!({"transaction":{"status":"confirmed","height":b.height,"block_hash":block_hash(b),"fee":"3"}})
            }
            _ => panic!("unexpected method"),
        };
        Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
    }
    async fn fixture_service(
        execute: bool,
    ) -> (
        tempfile::TempDir,
        Mixer,
        Arc<Mutex<Mock>>,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = private_dir();
        let mut c = config(dir.path());
        init_key(&c.key_file, &c.chain_id).unwrap();
        let public = crypto::public_key(&read_key(&c.key_file).unwrap()).unwrap();
        let state = Arc::new(Mutex::new(Mock::new(public)));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        c.rpc_url = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/", post(mock_rpc))
            .with_state(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut mixer = Mixer::open(c, execute).unwrap();
        for (id, sender, target) in [(1, 11, 21), (2, 12, 23)] {
            let mut d = deposit(id, sender);
            d.block = block_hash(state.lock().unwrap().blocks.get(&1).unwrap());
            mixer
                .ledger
                .add(
                    &d,
                    &[
                        address::encode(&public_key(target), &mixer.chain).unwrap(),
                        address::encode(&public_key(target + 1), &mixer.chain).unwrap(),
                    ],
                    100,
                )
                .unwrap();
        }
        (dir, mixer, state, server)
    }
    fn public_key(n: u8) -> PublicKey {
        public(n)
    }
    #[tokio::test]
    async fn whole_batch_can_finish_after_first_depositor_runs_out_and_refunds_are_exact() {
        let (_dir, mut mixer, state, server) = fixture_service(true).await;
        for _ in 0..30 {
            mixer.tick().await.unwrap();
            if mixer.ledger.pending().unwrap().is_some() {
                state.lock().unwrap().include_last();
            }
            if mixer
                .ledger
                .deposits()
                .unwrap()
                .iter()
                .all(|d| d.remaining.is_zero())
            {
                break;
            }
        }
        assert!(
            mixer
                .ledger
                .deposits()
                .unwrap()
                .iter()
                .all(|d| d.remaining.is_zero())
        );
        let paid: u32 = mixer
            .ledger
            .db
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE state='confirmed' AND slot IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paid, 4);
        assert_eq!(state.lock().unwrap().funds, 4u32.into()); // four earned service fees
        server.abort();
    }
    #[tokio::test]
    async fn refunded_requests_do_not_leave_phantom_queued_outputs() {
        let (_dir, mut mixer, state, server) = fixture_service(true).await;
        // Complete one real output, then let both customers' remaining slots expire.
        assert_eq!(mixer.tick().await.unwrap(), "paying");
        state.lock().unwrap().include_last();
        assert_eq!(mixer.tick().await.unwrap(), "confirming_payment");
        state.lock().unwrap().clock = 3701;
        for _ in 0..2 {
            assert_eq!(mixer.tick().await.unwrap(), "refunding");
            state.lock().unwrap().include_last();
            assert_eq!(mixer.tick().await.unwrap(), "confirming_payment");
        }
        assert!(
            mixer
                .ledger
                .deposits()
                .unwrap()
                .iter()
                .all(|d| d.remaining.is_zero())
        );
        mixer.write_status("waiting_for_depositors").unwrap();
        let status: Value =
            serde_json::from_slice(&std::fs::read(&mixer.c.status_file).unwrap()).unwrap();
        assert_eq!(status["active_deposits"], 0);
        assert_eq!(status["confirmed_outputs"], 1);
        assert_eq!(status["queued_outputs"], 0);
        let cancelled: u32 = mixer
            .ledger
            .db
            .query_row(
                "SELECT COUNT(*) FROM slots WHERE state='cancelled'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(cancelled, 3);
        assert_eq!(state.lock().unwrap().funds, 1u32.into()); // only the earned service fee remains
        server.abort();
    }
    #[tokio::test]
    async fn observe_mode_never_signs_and_initial_rest_allows_payments() {
        let (_dir, mut mixer, state, server) = fixture_service(false).await;
        assert_eq!(mixer.tick().await.unwrap(), "would_pay");
        assert!(state.lock().unwrap().submitted.is_empty());
        assert!(mixer.ledger.pending().unwrap().is_none());
        mixer.execute = true;
        state.lock().unwrap().phase = "rest".into();
        assert_eq!(mixer.tick().await.unwrap(), "paying");
        assert_eq!(state.lock().unwrap().submitted.len(), 1);
        server.abort();
    }
    #[tokio::test]
    async fn same_sender_multiple_addresses_does_not_satisfy_batch() {
        let (_dir, mut mixer, state, server) = fixture_service(true).await;
        mixer
            .ledger
            .db
            .execute("UPDATE deposits SET sender=?1", [hex::encode(public(11))])
            .unwrap();
        assert_eq!(mixer.tick().await.unwrap(), "waiting_for_depositors");
        assert!(state.lock().unwrap().submitted.is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn reorg_or_external_nonce_consumption_pauses_durably() {
        let (_dir, mut mixer, state, server) = fixture_service(false).await;
        mixer.tick().await.unwrap();
        state.lock().unwrap().nonce = 1;
        assert!(mixer.tick().await.is_err());
        assert_eq!(mixer.tick().await.unwrap(), "operator_review");
        server.abort();
        let (_dir, mut mixer, state, server) = fixture_service(false).await;
        state
            .lock()
            .unwrap()
            .blocks
            .get_mut(&1)
            .unwrap()
            .header
            .nonce += 1;
        assert!(mixer.tick().await.is_err());
        assert!(mixer.ledger.get("paused").unwrap().is_some());
        assert!(state.lock().unwrap().submitted.is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn customer_liabilities_are_checked_in_common_spendable_balance() {
        let (_dir, mut mixer, state, server) = fixture_service(true).await;
        state.lock().unwrap().funds = 499u32.into();
        assert!(mixer.tick().await.is_err());
        assert!(mixer.ledger.get("paused").unwrap().is_some());
        assert!(state.lock().unwrap().submitted.is_empty());
        server.abort();
    }
    #[tokio::test]
    async fn consumed_pending_nonce_without_exact_recorded_payment_pauses() {
        let (_dir, mut mixer, state, server) = fixture_service(true).await;
        assert_eq!(mixer.tick().await.unwrap(), "paying");
        let original = mixer.ledger.pending().unwrap().unwrap().raw;
        state.lock().unwrap().nonce = 1;
        assert!(mixer.tick().await.is_err());
        assert!(mixer.ledger.get("paused").unwrap().is_some());
        assert_eq!(mixer.ledger.pending().unwrap().unwrap().raw, original);
        assert_eq!(state.lock().unwrap().submitted.len(), 1);
        server.abort();
    }
    fn encrypt_instructions(
        body: &TransactionBody,
        recipient: PublicKey,
        terms: &str,
        addresses: Vec<String>,
    ) -> Vec<u8> {
        let plain = Plaintext {
            recipient: hex::encode(recipient),
            subject: SUBJECT.into(),
            body: serde_json::to_string(&Instructions {
                terms: terms.into(),
                addresses,
            })
            .unwrap(),
        };
        let encoded = serde_json::to_vec(&plain).unwrap();
        let mut padded = vec![0; 1152];
        padded[..2].copy_from_slice(&(encoded.len() as u16).to_be_bytes());
        padded[2..2 + encoded.len()].copy_from_slice(&encoded);
        let mut ephemeral = SecretKey::from_byte_array([55; 32]).unwrap();
        let pair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &ephemeral);
        if pair.x_only_public_key().1 == Parity::Odd {
            ephemeral = ephemeral.negate();
        }
        let ep = pair.x_only_public_key().0.serialize();
        let content = [61; 32];
        let iv = [62; 12];
        let mut common = b"Hashstash/Mail/v2\0".to_vec();
        common.extend(body.chain_id);
        common.extend(body.sender);
        common.extend(body.nonce.to_le_bytes());
        common.extend(ep);
        let ciphertext = Aes256Gcm::new_from_slice(&content)
            .unwrap()
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &padded,
                    aad: &common,
                },
            )
            .unwrap();
        let wrap = |candidate: PublicKey, role: &str, nonce: &[u8; 12]| {
            let peer = XOnlyPublicKey::from_byte_array(candidate)
                .unwrap()
                .public_key(Parity::Even);
            let shared = secp256k1::ecdh::shared_secret_point(&peer, &ephemeral);
            let mut info = format!("Hashstash/Mail/v2/{role}\0").into_bytes();
            info.extend(&common);
            info.extend(candidate);
            let mut k = [0; 32];
            Hkdf::<Sha256>::new(Some(&body.chain_id), &shared[..32])
                .expand(&info, &mut k)
                .unwrap();
            let mut aad = common.clone();
            aad.extend(format!("/{role}").as_bytes());
            Aes256Gcm::new_from_slice(&k)
                .unwrap()
                .encrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: &content,
                        aad: &aad,
                    },
                )
                .unwrap()
        };
        let e = mail::Envelope {
            ephemeral_key: hex::encode(ep),
            iv: hex::encode(iv),
            ciphertext: hex::encode(ciphertext),
            recipient_iv: hex::encode([63; 12]),
            recipient_key: hex::encode(wrap(recipient, "recipient", &[63; 12])),
            sender_iv: hex::encode([64; 12]),
            sender_key: hex::encode(wrap(body.sender, "sender", &[64; 12])),
        };
        [mail::PREFIX, serde_json::to_vec(&e).unwrap().as_slice()].concat()
    }
    async fn actual_rpc(
        State(n): State<Arc<crate::node::Node>>,
        Json(r): Json<Value>,
    ) -> Json<Value> {
        let result = tokio::task::spawn_blocking(move || {
            n.rpc(r["method"].as_str().unwrap(), r["params"].clone())
        })
        .await
        .unwrap();
        Json(match result {
            Ok(v) => json!({"jsonrpc":"2.0","id":1,"result":v}),
            Err(_) => {
                json!({"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"node request failed"}})
            }
        })
    }
    async fn caught_up_tick(m: &mut Mixer) -> &'static str {
        for _ in 0..500 {
            match m.tick().await {
                Ok(v) => return v,
                Err(e) => {
                    assert!(
                        m.ledger.get("paused").unwrap().is_none(),
                        "service pause: {e:#}"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        panic!("actual node/index did not catch up")
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actual_node_deposit_decryption_batch_payout_refund_and_restart() {
        let dir = private_dir();
        let mut nc = crate::config::Config::testnet();
        nc.network = "isolated-mixer-lifecycle".into();
        nc.initial_bits = 0x2003ffff;
        nc.limit_bits = nc.initial_bits;
        nc.validate().unwrap();
        let n = Arc::new(
            crate::node::Node::open(&dir.path().join("node.sqlite"), nc.clone(), public(91))
                .unwrap(),
        );
        for _ in 0..30 {
            n.mine(1_000_000).unwrap();
        }
        let mut c = config(dir.path());
        c.chain_id = hex::encode(nc.chain_id());
        init_key(&c.key_file, &c.chain_id).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        c.rpc_url = format!("http://{}/", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/", post(actual_rpc))
            .with_state(n.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut mixer = Mixer::open(c.clone(), true).unwrap();
        for (nonce, recipient) in [(0, public(41)), (1, public(42))] {
            let tx = crypto::sign(
                &TransactionBody {
                    data: Vec::new(),
                    chain_id: nc.chain_id(),
                    sender: public(91),
                    nonce,
                    fee: 100u32.into(),
                    expiry_height: 1000,
                    operation: Operation::TransferExact {
                        recipient,
                        amount: 400u32.into(),
                    },
                },
                &[91; 32],
            )
            .unwrap();
            n.submit_transaction(tx).unwrap();
            n.mine(1_000_000).unwrap();
        }
        for (sender, target) in [(41, 51), (42, 53)] {
            let mut body = TransactionBody {
                data: Vec::new(),
                chain_id: nc.chain_id(),
                sender: public(sender),
                nonce: 0,
                fee: 100u32.into(),
                expiry_height: 1000,
                operation: Operation::TransferExact {
                    recipient: mixer.public,
                    amount: 250u32.into(),
                },
            };
            let addresses = vec![
                address::encode(&public(target), &mixer.chain).unwrap(),
                address::encode(&public(target + 1), &mixer.chain).unwrap(),
            ];
            let data = encrypt_instructions(&body, mixer.public, &mixer.terms, addresses);
            body.operation = {
                body.data = data;
                body.operation
            };
            let tx = crypto::sign(&body, &[sender; 32]).unwrap();
            n.submit_transaction(tx).unwrap();
            n.mine(1_000_000).unwrap();
            n.mine(1_000_000).unwrap();
            let state = caught_up_tick(&mut mixer).await;
            if sender == 41 {
                assert_eq!(state, "waiting_for_depositors");
                assert!(mixer.ledger.pending().unwrap().is_none());
            } else {
                assert_eq!(state, "paying");
            }
        }
        // Crash/restart after journal + broadcast but before confirmation must
        // preserve exactly the same signed bytes and the sole outstanding nonce.
        let before = mixer.ledger.pending().unwrap().unwrap().raw;
        drop(mixer);
        mixer = Mixer::open(c, true).unwrap();
        assert_eq!(mixer.ledger.pending().unwrap().unwrap().raw, before);
        for _ in 0..40 {
            if mixer.ledger.pending().unwrap().is_some() {
                n.mine(1_000_000).unwrap();
                n.mine(1_000_000).unwrap();
            }
            caught_up_tick(&mut mixer).await;
            if mixer
                .ledger
                .deposits()
                .unwrap()
                .iter()
                .all(|d| d.remaining.is_zero())
            {
                break;
            }
        }
        assert_eq!(mixer.ledger.deposits().unwrap().len(), 2);
        assert!(
            mixer
                .ledger
                .deposits()
                .unwrap()
                .iter()
                .all(|d| d.remaining.is_zero())
        );
        let paid: u32 = mixer
            .ledger
            .db
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE slot IS NOT NULL AND state='confirmed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(paid, 4);
        for target in 51..=54 {
            let a = n
                .rpc("snapshot", json!({"key":hex::encode(public(target))}))
                .unwrap();
            assert_eq!(a["payment_available_hash"], "100");
        }
        let a = n
            .rpc("snapshot", json!({"key":hex::encode(mixer.public)}))
            .unwrap();
        assert_eq!(a["payment_available_hash"], "4");
        server.abort();
    }
}
