//! Local wallet selection and keys. This database is independent of chain state.
use crate::{
    address, crypto, local_files,
    types::{Hash, PublicKey},
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use ring::aead;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    num::NonZeroU32,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_WALLETS: usize = 256;

/// `hashstash-node-wallet-lock-v1`, the optional passphrase lock of the hot
/// secrets at rest. PBKDF2-HMAC-SHA256 with 600,000 iterations over the
/// passphrase bytes and a random 16-byte salt derives a ChaCha20-Poly1305 key.
/// The count is part of the format, so the stored lock cannot lower it.
const LOCK_FORMAT: &str = "hashstash-node-wallet-lock-v1";
const LOCK_ITERATIONS: u32 = 600_000;
const SALT_BYTES: usize = 16;
const TAG_BYTES: usize = 16;
/// A sealed secret: a random nonce, the encrypted 32-byte key and its tag.
const SEALED_BYTES: usize = aead::NONCE_LEN + 32 + TAG_BYTES;
const KEY_CONTEXT: &[u8] = b"Hashstash/node-wallet-key/v1\0";
const CHECK_CONTEXT: &[u8] = b"Hashstash/node-wallet-lock/v1\0";
const MIN_PASSPHRASE_BYTES: usize = 8;
const MAX_PASSPHRASE_BYTES: usize = 1024;

/// The wallet passphrase from `run --wallet-passphrase-file`, wiped on drop.
pub struct WalletPassphrase(Zeroizing<Vec<u8>>);
impl WalletPassphrase {
    /// Reads an owner-only passphrase file (`local_files::read_private`).
    pub fn read(path: &Path) -> Result<Self> {
        // Room for a byte-order mark and a line ending around the longest one.
        let bytes = local_files::read_private(path, MAX_PASSPHRASE_BYTES + 5)
            .with_context(|| format!("cannot read wallet passphrase {}", path.display()))?;
        Self::from_file(&bytes)
    }
    /// The file's text without a leading UTF-8 byte-order mark and one
    /// trailing line ending, which editors and PowerShell add.
    fn from_file(bytes: &[u8]) -> Result<Self> {
        let text = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
        let text = text
            .strip_suffix(b"\r\n")
            .or_else(|| text.strip_suffix(b"\n"))
            .unwrap_or(text);
        ensure!(
            (MIN_PASSPHRASE_BYTES..=MAX_PASSPHRASE_BYTES).contains(&text.len())
                && std::str::from_utf8(text).is_ok_and(|text| !text.chars().any(char::is_control)),
            "wallet passphrase must be one line of {MIN_PASSPHRASE_BYTES} to {MAX_PASSPHRASE_BYTES} bytes of UTF-8 text without control characters"
        );
        Ok(Self(Zeroizing::new(text.to_vec())))
    }
}

/// The passphrase-derived key, wiped on drop. The ChaCha20-Poly1305 key
/// schedule is rebuilt for each operation; ring does not wipe that copy, which
/// holds nothing beyond the hot secrets a running node keeps in memory anyway.
struct Seal(Zeroizing<[u8; 32]>);
impl Seal {
    fn derive(passphrase: &WalletPassphrase, salt: &[u8]) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(LOCK_ITERATIONS).expect("positive iteration count"),
            salt,
            &passphrase.0,
            key.as_mut(),
        );
        Self(key)
    }
    fn cipher(&self) -> aead::LessSafeKey {
        aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, self.0.as_ref())
                .expect("a 32-byte ChaCha20-Poly1305 key"),
        )
    }
    /// `nonce || ciphertext || tag` under a fresh random nonce. The plaintext
    /// is encrypted in place, in a buffer reserved at its final size.
    fn seal(&self, plain: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; aead::NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
        let mut sealed = Zeroizing::new(Vec::with_capacity(
            aead::NONCE_LEN + plain.len() + TAG_BYTES,
        ));
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(plain);
        let tag = self
            .cipher()
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(context),
                &mut sealed[aead::NONCE_LEN..],
            )
            .map_err(|_| anyhow!("cannot encrypt a wallet key"))?;
        sealed.extend_from_slice(tag.as_ref());
        Ok(std::mem::take(&mut *sealed))
    }
    /// The plaintext, or None when the key or authenticated data differs.
    fn open(&self, sealed: &[u8], context: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (nonce, encrypted) = sealed.split_first_chunk::<{ aead::NONCE_LEN }>()?;
        let mut buffer = Zeroizing::new(encrypted.to_vec());
        let plain = self
            .cipher()
            .open_in_place(
                aead::Nonce::assume_unique_for_key(*nonce),
                aead::Aad::from(context),
                &mut buffer,
            )
            .ok()?
            .len();
        buffer.truncate(plain);
        Some(buffer)
    }
}
/// Each sealed secret is bound to its account, so rows cannot be swapped.
fn key_context(public: &PublicKey) -> Vec<u8> {
    [KEY_CONTEXT, public.as_slice()].concat()
}
/// The check value seals nothing under the salt, and identifies a wrong
/// passphrase before any key is opened.
fn check_context(salt: &[u8]) -> Vec<u8> {
    [CHECK_CONTEXT, salt].concat()
}

struct Entry {
    name: String,
    public: PublicKey,
    secret: Option<Zeroizing<[u8; 32]>>,
}
impl Entry {
    fn id(&self) -> String {
        format!("{}:{}", self.mode(), hex::encode(self.public))
    }
    fn mode(&self) -> &'static str {
        if self.secret.is_some() {
            "hot"
        } else {
            "watch"
        }
    }
    fn metadata(&self, chain_id: &Hash) -> Value {
        json!({"id":self.id(),"name":self.name,"public_key":hex::encode(self.public),"mode":self.mode(),"address":address::encode(&self.public,chain_id).expect("stored public key is validated")})
    }
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum ManageRequest {
    Create {
        #[serde(default)]
        name: String,
        revision: u64,
    },
    Import {
        #[serde(default)]
        name: String,
        private_key: String,
        public_key: Option<String>,
        revision: u64,
    },
    Watch {
        #[serde(default)]
        name: String,
        public_key: String,
        revision: u64,
    },
    Select {
        id: String,
        revision: u64,
    },
    Export {
        id: String,
        revision: u64,
    },
}
impl Drop for ManageRequest {
    fn drop(&mut self) {
        if let Self::Import { private_key, .. } = self {
            private_key.zeroize();
        }
    }
}
impl ManageRequest {
    fn revision(&self) -> u64 {
        match self {
            Self::Create { revision, .. }
            | Self::Import { revision, .. }
            | Self::Watch { revision, .. }
            | Self::Select { revision, .. }
            | Self::Export { revision, .. } => *revision,
        }
    }
}

pub(crate) struct WalletStore {
    connection: Connection,
    entries: BTreeMap<String, Entry>,
    active: String,
    revision: u64,
    fresh: bool,
    chain_id: Hash,
    /// The node's peer transport identity, which no wallet account may share.
    reserved: Option<PublicKey>,
    /// Present when a passphrase locks this store: new hot secrets are saved
    /// only sealed.
    seal: Option<Seal>,
}
/// The rollback journal SQLite keeps beside `path`.
fn journal_path(path: &Path) -> PathBuf {
    let mut journal = path.as_os_str().to_owned();
    journal.push("-journal");
    journal.into()
}

/// Copies wallet storage from its earlier stem-based name, which another
/// chain database may share, when this chain database has none of its own.
/// The original stays for any other node that still uses it.
fn adopt_legacy(chain_path: &Path, path: &Path) -> Result<()> {
    let Some(legacy) = local_files::legacy_sidecar(chain_path, "wallets.sqlite") else {
        return Ok(());
    };
    if std::fs::symlink_metadata(path).is_ok()
        || !std::fs::symlink_metadata(&legacy).is_ok_and(|m| m.is_file())
    {
        return Ok(());
    }
    // A consistent snapshot, written under a temporary name restricted
    // before it holds any key, then moved into place.
    let mut unique = [0u8; 8];
    getrandom::fill(&mut unique).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .context("wallet storage path needs a file name")?
            .to_string_lossy(),
        hex::encode(unique)
    ));
    let copied = (|| -> Result<()> {
        local_files::create_private(&temporary)?;
        let source = Connection::open_with_flags(&legacy, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        source.execute(
            "VACUUM INTO ?1",
            [temporary
                .to_str()
                .context("wallet storage path is not valid Unicode")?],
        )?;
        drop(source);
        std::fs::rename(&temporary, path)?;
        Ok(())
    })();
    if copied.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    copied.with_context(|| format!("cannot copy wallet storage {}", legacy.display()))?;
    eprintln!(
        "Copied wallet storage {} to {}, its name for this chain database. The original keeps its keys for any other chain database that shared its name; remove it once no node uses it.",
        legacy.display(),
        path.display()
    );
    Ok(())
}

impl WalletStore {
    #[cfg(test)]
    pub fn open(chain_path: &Path, chain_id: Hash) -> Result<Self> {
        Self::open_locked(chain_path, chain_id, None)
    }
    #[cfg(test)]
    fn open_locked(
        chain_path: &Path,
        chain_id: Hash,
        passphrase: Option<&WalletPassphrase>,
    ) -> Result<Self> {
        let store = Self::open_unrecorded(chain_path, chain_id, passphrase)?;
        store.record_network()?;
        Ok(store)
    }
    /// Load and validate the store without recording the network opening it.
    /// A node checks its wallets before the chain replay, and records the
    /// network only once its chain database has accepted this configuration.
    /// Without a passphrase hot secrets are stored unencrypted, so the
    /// database and its journal are owner-only (`local_files::restrict_to_owner`)
    /// either way. The journal persists (TRUNCATE mode) with that protection
    /// instead of being recreated with the directory's defaults for every write.
    ///
    /// A passphrase seals every hot secret (`hashstash-node-wallet-lock-v1`):
    /// the first start with one encrypts the saved plaintext keys in one
    /// transaction, and a locked store refuses to open without it.
    pub fn open_unrecorded(
        chain_path: &Path,
        chain_id: Hash,
        passphrase: Option<&WalletPassphrase>,
    ) -> Result<Self> {
        let path = local_files::sidecar(chain_path, "wallets.sqlite");
        ensure!(
            path != chain_path,
            "chain database path conflicts with wallet storage"
        );
        adopt_legacy(chain_path, &path)?;
        let journal = journal_path(&path);
        local_files::create_private(&path)
            .with_context(|| format!("cannot open wallet storage {}", path.display()))?;
        local_files::create_private(&journal)?;
        let mut connection = Connection::open(&path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=TRUNCATE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS wallets(id TEXT PRIMARY KEY,name TEXT NOT NULL,public BLOB NOT NULL,secret BLOB);
            CREATE TABLE IF NOT EXISTS wallet_selection(singleton INTEGER PRIMARY KEY CHECK(singleton=1),active TEXT NOT NULL,revision TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS wallet_network(singleton INTEGER PRIMARY KEY CHECK(singleton=1),chain_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS wallet_lock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),format TEXT NOT NULL,salt BLOB NOT NULL,check_value BLOB NOT NULL);")?;
        // SQLite discards an empty journal beside a new, empty database and
        // creates its own for the schema; restrict that one before any key.
        if journal.exists() {
            local_files::restrict_to_owner(&journal)?;
        }
        let selection: Option<(String, String)> = connection
            .query_row(
                "SELECT active,revision FROM wallet_selection WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (active, revision) = if let Some((active, revision)) = selection {
            (
                active,
                revision.parse::<u64>().context("invalid wallet revision")?,
            )
        } else {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(
                tx.query_row("SELECT COUNT(*) FROM wallets", [], |r| r.get::<_, u64>(0))? == 0,
                "wallet store is missing its selection"
            );
            tx.execute(
                "INSERT INTO wallet_selection(singleton,active,revision) VALUES(1,'','0')",
                [],
            )?;
            tx.commit()?;
            (String::new(), 0)
        };
        let lock: Option<(String, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT format,salt,check_value FROM wallet_lock WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        // A lock created by this start, saved below with the sealed keys.
        let mut new_lock = None;
        let seal = match (lock, passphrase) {
            (None, None) => None,
            (Some(_), None) => bail!(
                "wallet storage {} is encrypted; start the node with --wallet-passphrase-file",
                path.display()
            ),
            (Some((format, salt, check)), Some(passphrase)) => {
                ensure!(
                    format == LOCK_FORMAT && salt.len() == SALT_BYTES,
                    "wallet storage {} uses an unsupported encryption format",
                    path.display()
                );
                let seal = Seal::derive(passphrase, &salt);
                ensure!(
                    seal.open(&check, &check_context(&salt))
                        .is_some_and(|plain| plain.is_empty()),
                    "wrong wallet passphrase for {}",
                    path.display()
                );
                Some(seal)
            }
            (None, Some(passphrase)) => {
                let mut salt = [0u8; SALT_BYTES];
                getrandom::fill(&mut salt).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
                let seal = Seal::derive(passphrase, &salt);
                new_lock = Some((salt, seal.seal(&[], &check_context(&salt))?));
                Some(seal)
            }
        };
        // Unencrypted keys to seal now: every key when a passphrase is first
        // set, or one an earlier release saved beside the lock.
        let mut unsealed = Vec::new();
        let entries = {
            let mut statement = connection.prepare("SELECT id,name,public,secret FROM wallets")?;
            let mut rows = statement.query([])?;
            let mut entries = BTreeMap::new();
            while let Some(row) = rows.next()? {
                ensure!(entries.len() < MAX_WALLETS, "too many saved wallets");
                let id: String = row.get(0)?;
                let name: String = row.get(1)?;
                check_name(&name)?;
                let public: PublicKey = row
                    .get::<_, Vec<u8>>(2)?
                    .try_into()
                    .map_err(|_| anyhow!("invalid saved public key"))?;
                ensure!(crypto::valid_key(&public), "invalid saved public key");
                let secret = match row.get::<_, Option<Vec<u8>>>(3)?.map(Zeroizing::new) {
                    None => None,
                    Some(bytes) => {
                        let opened = match &seal {
                            Some(seal) if bytes.len() == SEALED_BYTES => seal
                                .open(&bytes, &key_context(&public))
                                .context("a saved private key cannot be decrypted; the wallet storage is damaged")?,
                            Some(_) if bytes.len() == 32 => {
                                unsealed.push(id.clone());
                                bytes
                            }
                            _ => bytes,
                        };
                        ensure!(opened.len() == 32, "invalid saved private key");
                        let mut key = Zeroizing::new([0u8; 32]);
                        key.copy_from_slice(&opened);
                        ensure!(
                            crypto::public_key(&key)? == public,
                            "saved public/private key mismatch"
                        );
                        Some(key)
                    }
                };
                let entry = Entry {
                    name,
                    public,
                    secret,
                };
                ensure!(id == entry.id(), "saved wallet identity mismatch");
                entries.insert(id, entry);
            }
            entries
        };
        ensure!(
            (entries.is_empty() && active.is_empty()) || entries.contains_key(&active),
            "selected wallet is missing"
        );
        // The lock and every sealed key replace the plaintext in one
        // transaction; secure_delete zeroes the replaced bytes in the file.
        if let Some(seal) = &seal
            && (new_lock.is_some() || !unsealed.is_empty())
        {
            let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            check_saved_revision(&tx, revision)?;
            if let Some((salt, check)) = &new_lock {
                tx.execute(
                    "INSERT INTO wallet_lock(singleton,format,salt,check_value) VALUES(1,?1,?2,?3)",
                    params![LOCK_FORMAT, salt.as_slice(), check],
                )?;
            }
            for id in &unsealed {
                let entry = &entries[id];
                let secret = entry.secret.as_ref().context("invalid saved private key")?;
                let sealed = seal.seal(secret.as_ref(), &key_context(&entry.public))?;
                ensure!(
                    tx.execute(
                        "UPDATE wallets SET secret=?1 WHERE id=?2 AND length(secret)=32",
                        params![sealed, id],
                    )? == 1,
                    "wallet storage changed in another process; restart this node"
                );
            }
            tx.commit()?;
            if !unsealed.is_empty() {
                eprintln!(
                    "Encrypted {} saved hot key{} in wallet storage {} with the wallet passphrase. Copies of the file made earlier, and the disk's free space, may still hold them unencrypted: see WALLETS.md.",
                    unsealed.len(),
                    if unsealed.len() == 1 { "" } else { "s" },
                    path.display()
                );
            }
        }
        // Wallets are never deleted, so a store without any holds no choice to
        // preserve: startup flags seed it, even after an earlier first start
        // failed or ran without them.
        let fresh = entries.is_empty();
        Ok(Self {
            connection,
            entries,
            active,
            revision,
            fresh,
            chain_id,
            reserved: None,
            seal,
        })
    }
    /// Keys are independent of chain state and may be shared by networks that
    /// use the same storage: say so when another network opens it.
    pub fn record_network(&self) -> Result<()> {
        let chain_id = hex::encode(self.chain_id);
        let previous: Option<String> = self
            .connection
            .query_row(
                "SELECT chain_id FROM wallet_network WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if previous.as_deref() != Some(chain_id.as_str()) {
            if let Some(previous) = &previous {
                eprintln!(
                    "Warning: wallet storage {} was last opened for chain {previous}; this network is {chain_id}. Its saved keys are shared by both networks.",
                    self.connection.path().unwrap_or("(unknown path)"),
                );
            }
            self.connection.execute(
                "INSERT INTO wallet_network(singleton,chain_id) VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET chain_id=excluded.chain_id",
                params![chain_id],
            )?;
        }
        Ok(())
    }
    /// Peer identities are public network identities. Refuse one that a saved
    /// account uses, and every later account that would use it.
    pub fn reserve_peer_identity(&mut self, public: PublicKey) -> Result<()> {
        ensure!(
            self.entries.values().all(|entry| entry.public != public),
            "peer identity must differ from every server wallet account"
        );
        self.reserved = Some(public);
        Ok(())
    }
    pub fn seed_hot(&mut self, secret: [u8; 32]) -> Result<()> {
        let secret = Zeroizing::new(secret);
        let public = crypto::public_key(&secret)?;
        if self.fresh {
            self.add_select(Entry {
                name: String::new(),
                public,
                secret: Some(secret),
            })?;
        } else if let Some(warning) = self.unapplied_seed("--wallet-key", "hot", &public) {
            eprintln!("{warning}");
        }
        self.fresh = false;
        Ok(())
    }
    pub fn seed_watch(&mut self, public: PublicKey) -> Result<()> {
        ensure!(crypto::valid_key(&public), "invalid watch public key");
        if self.fresh {
            self.add_select(Entry {
                name: String::new(),
                public,
                secret: None,
            })?;
        } else if let Some(warning) = self.unapplied_seed("--watch-key", "watch", &public) {
            eprintln!("{warning}");
        }
        self.fresh = false;
        Ok(())
    }
    /// A store holding wallets keeps its saved selection over startup flags.
    /// Report it whenever that selection is not the requested wallet.
    fn unapplied_seed(&self, flag: &str, mode: &str, public: &PublicKey) -> Option<String> {
        if self.active == format!("{mode}:{}", hex::encode(public)) {
            return None;
        }
        let saved = self.entries.get(&self.active).map_or_else(
            || "no wallet selected".to_owned(),
            |entry| {
                format!(
                    "{} wallet {}",
                    entry.mode(),
                    address::encode(&entry.public, &self.chain_id)
                        .expect("stored public key is validated")
                )
            },
        );
        Some(format!(
            "Warning: {flag} was not applied: this node's wallet storage keeps its saved selection ({saved}). Import or select the account through the private Wallet tools instead."
        ))
    }
    pub fn status(&self) -> Value {
        let Some(entry) = self.entries.get(&self.active) else {
            return json!({"wallet_id":null,"wallet_revision":self.revision,
                "public_key":null,"address":null,"address_hrp":address::hrp(&self.chain_id),"wallet_mode":"none","wallet_enabled":false,"wallets":[]});
        };
        json!({"wallet_id":self.active,"wallet_revision":self.revision,
            "public_key":hex::encode(entry.public),"wallet_mode":entry.mode(),"wallet_enabled":entry.secret.is_some(),
            "address":address::encode(&entry.public,&self.chain_id).expect("stored public key is validated"),"address_hrp":address::hrp(&self.chain_id),
            "wallets":self.entries.values().map(|entry|entry.metadata(&self.chain_id)).collect::<Vec<_>>()})
    }
    pub fn hot_enabled(&self) -> bool {
        self.entries
            .get(&self.active)
            .is_some_and(|entry| entry.secret.is_some())
    }
    pub fn selected_secret(&self, expected_sender: &PublicKey, revision: u64) -> Result<&[u8; 32]> {
        self.check_revision(revision)?;
        let entry = self
            .entries
            .get(&self.active)
            .context("no wallet is selected")?;
        ensure!(
            entry.public == *expected_sender,
            "selected wallet differs from expected sender"
        );
        entry
            .secret
            .as_deref()
            .context("selected wallet is watch-only")
    }
    fn check_revision(&self, revision: u64) -> Result<()> {
        ensure!(
            revision == self.revision,
            "wallet selection changed; refresh and try again"
        );
        Ok(())
    }
    /// Applies one wallet action and returns its JSON response body.
    pub fn manage(&mut self, request: ManageRequest) -> Result<Zeroizing<Vec<u8>>> {
        self.check_revision(request.revision())?;
        match &request {
            ManageRequest::Create { name, .. } => {
                let (secret, public) = loop {
                    let mut secret = Zeroizing::new([0; 32]);
                    getrandom::fill(secret.as_mut())
                        .map_err(|e| anyhow!("randomness unavailable: {e}"))?;
                    if let Ok(public) = crypto::public_key(&secret) {
                        break (secret, public);
                    }
                };
                let name = check_name(name)?;
                self.add_select(Entry {
                    name,
                    public,
                    secret: Some(secret),
                })?;
            }
            ManageRequest::Import {
                name,
                private_key,
                public_key,
                ..
            } => {
                ensure!(
                    private_key.len() == 64,
                    "private key must contain 64 hex characters"
                );
                let mut secret = Zeroizing::new([0u8; 32]);
                hex::decode_to_slice(private_key, secret.as_mut())?;
                let public = crypto::public_key(&secret)?;
                let name = check_name(name)?;
                if let Some(expected) = public_key {
                    ensure!(
                        expected.len() == 64 && hex::decode(expected)? == public,
                        "public/private key mismatch"
                    );
                }
                self.add_select(Entry {
                    name,
                    public,
                    secret: Some(secret),
                })?;
            }
            ManageRequest::Watch {
                name, public_key, ..
            } => {
                let public = if public_key.len() == 64
                    && public_key.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    hex::decode(public_key)?
                        .try_into()
                        .map_err(|_| anyhow!("invalid public key length"))?
                } else {
                    address::decode(public_key, &self.chain_id)?
                };
                ensure!(crypto::valid_key(&public), "invalid public key");
                let name = check_name(name)?;
                self.add_select(Entry {
                    name,
                    public,
                    secret: None,
                })?;
            }
            ManageRequest::Select { id, .. } => self.select(id)?,
            ManageRequest::Export { id, .. } => {
                let entry = self.entries.get(id).context("unknown wallet")?;
                let secret = entry
                    .secret
                    .as_ref()
                    .context("watch-only wallets have no private key")?;
                return Ok(backup_body(secret, &entry.public));
            }
        }
        self.fresh = false;
        Ok(Zeroizing::new(serde_json::to_vec(&self.status())?))
    }
    fn add_select(&mut self, entry: Entry) -> Result<()> {
        ensure!(
            self.reserved != Some(entry.public),
            "peer identity must differ from every server wallet account"
        );
        let id = entry.id();
        if self.entries.contains_key(&id) {
            return self.select(&id);
        }
        ensure!(
            self.entries.len() < MAX_WALLETS,
            "saved wallet limit reached"
        );
        let revision = self
            .revision
            .checked_add(1)
            .context("wallet revision exhausted")?;
        // A locked store saves a new hot secret only sealed.
        let sealed = match (&entry.secret, &self.seal) {
            (Some(secret), Some(seal)) => {
                Some(seal.seal(secret.as_ref(), &key_context(&entry.public))?)
            }
            _ => None,
        };
        let stored: Option<&[u8]> = match &sealed {
            Some(sealed) => Some(sealed),
            None => entry.secret.as_ref().map(|s| s.as_slice()),
        };
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_saved_revision(&tx, self.revision)?;
        tx.execute(
            "INSERT INTO wallets(id,name,public,secret) VALUES(?1,?2,?3,?4)",
            params![id, entry.name, entry.public.as_slice(), stored],
        )?;
        tx.execute(
            "UPDATE wallet_selection SET active=?1,revision=?2 WHERE singleton=1",
            params![id, revision.to_string()],
        )?;
        tx.commit()?;
        self.entries.insert(id.clone(), entry);
        self.active = id;
        self.revision = revision;
        Ok(())
    }
    fn select(&mut self, id: &str) -> Result<()> {
        ensure!(self.entries.contains_key(id), "unknown wallet");
        if self.active == id {
            return Ok(());
        }
        let revision = self
            .revision
            .checked_add(1)
            .context("wallet revision exhausted")?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_saved_revision(&tx, self.revision)?;
        tx.execute(
            "UPDATE wallet_selection SET active=?1,revision=?2 WHERE singleton=1",
            params![id, revision.to_string()],
        )?;
        tx.commit()?;
        self.active = id.into();
        self.revision = revision;
        Ok(())
    }
}
const BACKUP_PREFIX: &[u8] = br#"{"format":"hashstash-private-v1","private_key":""#;
const BACKUP_MIDDLE: &[u8] = br#"","public_key":""#;
const BACKUP_SUFFIX: &[u8] = br#""}"#;
const BACKUP_BYTES: usize =
    BACKUP_PREFIX.len() + 64 + BACKUP_MIDDLE.len() + 64 + BACKUP_SUFFIX.len();
/// The `hashstash-private-v1` backup, the one response that carries a key.
/// Its JSON is written straight into a buffer reserved at its exact size, so
/// no reallocation leaves a copy behind, and wiped on drop after the node
/// writes it to the client. No `Value` or `String` holds the hex.
fn backup_body(secret: &[u8; 32], public: &PublicKey) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new([0u8; 64]);
    hex::encode_to_slice(secret, encoded.as_mut()).expect("64 bytes hold a hex-encoded key");
    let mut body = Zeroizing::new(Vec::with_capacity(BACKUP_BYTES));
    body.extend_from_slice(BACKUP_PREFIX);
    body.extend_from_slice(encoded.as_ref());
    body.extend_from_slice(BACKUP_MIDDLE);
    body.extend_from_slice(hex::encode(public).as_bytes());
    body.extend_from_slice(BACKUP_SUFFIX);
    debug_assert_eq!(body.len(), BACKUP_BYTES);
    body
}
fn check_name(name: &str) -> Result<String> {
    let name = name.trim();
    ensure!(
        name.len() <= 80 && !name.chars().any(char::is_control),
        "wallet name must be at most 80 bytes without control characters"
    );
    Ok(name.to_owned())
}
fn check_saved_revision(tx: &rusqlite::Transaction<'_>, expected: u64) -> Result<()> {
    let revision: String = tx.query_row(
        "SELECT revision FROM wallet_selection WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        revision == expected.to_string(),
        "wallet storage changed in another process; restart this node"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manage(store: &mut WalletStore, mut request: Value) -> Value {
        request["revision"] = json!(store.revision);
        let body = store
            .manage(serde_json::from_value(request).unwrap())
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn exported_backups_are_built_in_one_wiped_buffer() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = WalletStore::open(&dir.path().join("chain.sqlite"), [1; 32]).unwrap();
        let status = manage(
            &mut store,
            json!({"action":"import","private_key":hex::encode([3;32])}),
        );
        let request = json!({"action":"export","id":status["wallet_id"],"revision":store.revision});
        let body: Zeroizing<Vec<u8>> = store
            .manage(serde_json::from_value(request).unwrap())
            .unwrap();
        // The exact reserved size was enough, so the buffer never moved.
        assert_eq!(body.len(), BACKUP_BYTES);
        assert!(body.capacity() >= BACKUP_BYTES);
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap(),
            json!({"format":"hashstash-private-v1","private_key":hex::encode([3;32]),
                "public_key":hex::encode(crypto::public_key(&[3;32]).unwrap())})
        );
        let watch = manage(
            &mut store,
            json!({"action":"watch","public_key":hex::encode(crypto::public_key(&[4;32]).unwrap())}),
        );
        let refused = json!({"action":"export","id":watch["wallet_id"],"revision":store.revision});
        assert!(
            store
                .manage(serde_json::from_value(refused).unwrap())
                .is_err()
        );
    }

    fn passphrase(text: &str) -> WalletPassphrase {
        WalletPassphrase::from_file(text.as_bytes()).unwrap()
    }
    fn holds(file: &[u8], secret: &[u8; 32]) -> bool {
        file.windows(32).any(|window| window == secret)
    }

    #[test]
    fn a_passphrase_encrypts_saved_hot_keys_and_is_then_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let wallets = path.with_extension("wallets.sqlite");
        let file = || std::fs::read(&wallets).unwrap();
        // Keys saved unencrypted, as before any passphrase.
        let mut store = WalletStore::open(&path, [1; 32]).unwrap();
        let imported = manage(
            &mut store,
            json!({"action":"import","private_key":hex::encode([3;32])}),
        );
        let watched = crypto::public_key(&[4; 32]).unwrap();
        manage(
            &mut store,
            json!({"action":"watch","public_key":hex::encode(watched)}),
        );
        let saved = store.status();
        drop(store);
        assert!(holds(&file(), &[3; 32]));

        // The first start with a passphrase seals them, changing nothing else.
        let phrase = passphrase("correct horse battery staple\r\n");
        let mut locked = WalletStore::open_locked(&path, [1; 32], Some(&phrase)).unwrap();
        assert_eq!(locked.status(), saved);
        // A key created while the store is locked is saved only sealed.
        let created = manage(&mut locked, json!({"action":"create"}));
        let created_secret = **locked.entries[created["wallet_id"].as_str().unwrap()]
            .secret
            .as_ref()
            .unwrap();
        let with_created = locked.status();
        drop(locked);
        let bytes = file();
        assert!(
            !holds(&bytes, &[3; 32]) && !holds(&bytes, &created_secret),
            "no key is left unencrypted in the file"
        );
        assert_eq!(std::fs::metadata(journal_path(&wallets)).unwrap().len(), 0);
        let rows = || -> Vec<(String, Option<Vec<u8>>)> {
            let connection = Connection::open(&wallets).unwrap();
            let mut statement = connection
                .prepare("SELECT id,secret FROM wallets ORDER BY id")
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let sealed: Vec<_> = rows()
            .into_iter()
            .filter_map(|(id, secret)| Some((id, secret?)))
            .collect();
        assert_eq!(sealed.len(), 2, "the watch-only entry holds no secret");
        assert!(
            sealed
                .iter()
                .all(|(_, secret)| secret.len() == SEALED_BYTES)
        );

        // Without the passphrase, or with another one, the store stays closed.
        let missing = WalletStore::open(&path, [1; 32]).err().unwrap().to_string();
        assert!(missing.contains("--wallet-passphrase-file"), "{missing}");
        let other = passphrase("correct horse battery stapler");
        let wrong = WalletStore::open_locked(&path, [1; 32], Some(&other))
            .err()
            .unwrap()
            .to_string();
        assert!(wrong.contains("wrong wallet passphrase"), "{wrong}");
        // The same text, saved with a byte-order mark and another line
        // ending, opens every key; a backup is the original key.
        let same = passphrase("\u{feff}correct horse battery staple\n");
        let mut reopened = WalletStore::open_locked(&path, [1; 32], Some(&same)).unwrap();
        assert_eq!(reopened.status(), with_created);
        let request =
            json!({"action":"export","id":imported["wallet_id"],"revision":reopened.revision});
        let backup = reopened
            .manage(serde_json::from_value(request).unwrap())
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&backup).unwrap()["private_key"],
            hex::encode([3; 32])
        );
        drop(reopened);

        // Each sealed key is bound to its account: swapped rows do not open.
        let connection = Connection::open(&wallets).unwrap();
        let put = |id: &str, secret: &[u8]| {
            connection
                .execute(
                    "UPDATE wallets SET secret=?1 WHERE id=?2",
                    params![secret, id],
                )
                .unwrap();
        };
        put(&sealed[0].0, &sealed[1].1);
        put(&sealed[1].0, &sealed[0].1);
        let swapped = WalletStore::open_locked(&path, [1; 32], Some(&phrase))
            .err()
            .unwrap()
            .to_string();
        assert!(swapped.contains("cannot be decrypted"), "{swapped}");
        put(&sealed[0].0, &sealed[0].1);
        put(&sealed[1].0, &sealed[1].1);
        // A key an earlier release saved unencrypted beside the lock is
        // sealed at the next start.
        let late = crypto::public_key(&[5; 32]).unwrap();
        connection
            .execute(
                "INSERT INTO wallets(id,name,public,secret) VALUES(?1,'',?2,?3)",
                params![
                    format!("hot:{}", hex::encode(late)),
                    late.as_slice(),
                    [5u8; 32].as_slice()
                ],
            )
            .unwrap();
        drop(connection);
        let resealed = WalletStore::open_locked(&path, [1; 32], Some(&phrase)).unwrap();
        assert_eq!(resealed.entries.len(), 4);
        drop(resealed);
        assert!(!holds(&file(), &[5; 32]));
        assert!(
            rows()
                .iter()
                .all(|(_, secret)| secret.as_ref().is_none_or(|s| s.len() == SEALED_BYTES))
        );

        // A store opened with a passphrase before it held any key is locked too.
        let empty = dir.path().join("empty.sqlite");
        let mut fresh = WalletStore::open_locked(&empty, [1; 32], Some(&phrase)).unwrap();
        fresh.seed_hot([6; 32]).unwrap();
        drop(fresh);
        assert!(!holds(
            &std::fs::read(empty.with_extension("wallets.sqlite")).unwrap(),
            &[6; 32]
        ));
        assert!(WalletStore::open(&empty, [1; 32]).is_err());
    }

    #[test]
    fn wallet_passphrase_files_hold_one_line_of_text() {
        for (file, text) in [
            ("eight ch", "eight ch"),
            ("  spaced words  \n", "  spaced words  "),
            ("windows line\r\n", "windows line"),
            ("\u{feff}marked UTF-8\r\n", "marked UTF-8"),
            ("pässwörter", "pässwörter"),
        ] {
            assert_eq!(passphrase(file).0.as_slice(), text.as_bytes(), "{file:?}");
        }
        let invalid: [&[u8]; 7] = [
            b"seven c",
            b"\n",
            b"two line endings\n\n",
            b"two\nlines here",
            b"tab\tinside it",
            b"\xff\xfe not text",
            &[b'x'; MAX_PASSPHRASE_BYTES + 1],
        ];
        for invalid in invalid {
            assert!(WalletPassphrase::from_file(invalid).is_err(), "{invalid:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet-passphrase");
        local_files::write_private(&path, b"from a private file\n").unwrap();
        assert_eq!(
            WalletPassphrase::read(&path).unwrap().0.as_slice(),
            b"from a private file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                WalletPassphrase::read(&path).is_err(),
                "a file others can read"
            );
        }
    }

    #[test]
    fn new_wallet_names_are_optional_and_never_generated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let mut store = WalletStore::open(&path, [1; 32]).unwrap();
        let imported = crypto::public_key(&[2; 32]).unwrap();
        for request in [
            json!({"action":"create"}),
            json!({"action":"create","name":""}),
            json!({"action":"import","private_key":hex::encode([2;32])}),
            json!({"action":"watch","public_key":hex::encode(imported)}),
        ] {
            let status = manage(&mut store, request);
            assert!(
                status["wallets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|entry| entry["name"] == "")
            );
        }
        assert_eq!(store.entries.len(), 4);
        let saved = store.status();
        drop(store);
        assert_eq!(WalletStore::open(&path, [1; 32]).unwrap().status(), saved);
        assert_eq!(check_name("   ").unwrap(), "");
        assert!(check_name(&"x".repeat(81)).is_err());
        assert!(check_name("bad\0name").is_err());
    }

    #[test]
    fn startup_wallets_have_empty_names_and_preserve_saved_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let chain_id = [1; 32];
        let public = crypto::public_key(&[3; 32]).unwrap();
        for hot in [false, true] {
            let path = dir
                .path()
                .join(if hot { "hot.sqlite" } else { "watch.sqlite" });
            let mut store = WalletStore::open(&path, chain_id).unwrap();
            if hot {
                store.seed_hot([3; 32]).unwrap();
            } else {
                store.seed_watch(public).unwrap();
            }
            assert_eq!(store.status()["wallets"][0]["name"], "");
        }

        let path = dir.path().join("legacy.sqlite");
        let mut store = WalletStore::open(&path, chain_id).unwrap();
        let saved = manage(
            &mut store,
            json!({"action":"watch","name":"Existing custom label","public_key":hex::encode(public)}),
        );
        drop(store);
        let mut reopened = WalletStore::open(&path, chain_id).unwrap();
        reopened.seed_hot([4; 32]).unwrap();
        reopened
            .seed_watch(crypto::public_key(&[5; 32]).unwrap())
            .unwrap();
        assert_eq!(reopened.status(), saved);
        let duplicate = manage(
            &mut reopened,
            json!({"action":"watch","public_key":hex::encode(public)}),
        );
        assert_eq!(duplicate, saved);
        assert_eq!(duplicate["wallets"][0]["name"], "Existing custom label");
    }

    #[test]
    fn empty_stores_are_seeded_and_ignored_startup_wallets_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let public = crypto::public_key(&[3; 32]).unwrap();
        // A first start that failed later, or ran without flags, leaves an
        // empty saved selection; the flags still seed that store.
        for hot in [true, false] {
            let path = dir.path().join(format!("empty-{hot}.sqlite"));
            drop(WalletStore::open(&path, [1; 32]).unwrap());
            let mut empty = WalletStore::open(&path, [1; 32]).unwrap();
            assert!(empty.fresh);
            if hot {
                empty.seed_hot([3; 32]).unwrap();
            } else {
                empty.seed_watch(public).unwrap();
            }
            assert_eq!(empty.entries.len(), 1);
            let mode = if hot { "hot" } else { "watch" };
            assert_eq!(empty.active, format!("{mode}:{}", hex::encode(public)));
            drop(empty);
            let reopened = WalletStore::open(&path, [1; 32]).unwrap();
            assert!(!reopened.fresh);
            assert_eq!(reopened.status()["wallet_mode"], mode);
        }
        // A store holding wallets keeps its selection and says so.
        let path = dir.path().join("chain.sqlite");
        let mut store = WalletStore::open(&path, [1; 32]).unwrap();
        manage(
            &mut store,
            json!({"action":"import","private_key":hex::encode([3;32])}),
        );
        drop(store);
        let mut saved = WalletStore::open(&path, [1; 32]).unwrap();
        assert!(
            saved
                .unapplied_seed("--wallet-key", "hot", &public)
                .is_none()
        );
        let watch = saved
            .unapplied_seed("--watch-key", "watch", &public)
            .unwrap();
        assert!(
            watch.contains("--watch-key was not applied") && watch.contains("hot wallet hsh"),
            "{watch}"
        );
        let before = saved.status();
        saved.seed_watch(public).unwrap();
        saved.seed_hot([4; 32]).unwrap();
        assert_eq!(saved.status(), before);
    }

    #[test]
    fn peer_identity_is_never_a_saved_seeded_or_imported_account() {
        let dir = tempfile::tempdir().unwrap();
        let saved = crypto::public_key(&[6; 32]).unwrap();
        let peer = crypto::public_key(&[7; 32]).unwrap();
        let mut store = WalletStore::open(&dir.path().join("chain.sqlite"), [1; 32]).unwrap();
        manage(
            &mut store,
            json!({"action":"watch","public_key":hex::encode(saved)}),
        );
        let error = store.reserve_peer_identity(saved).unwrap_err();
        assert!(error.to_string().contains("peer identity"), "{error}");
        store.reserve_peer_identity(peer).unwrap();
        for mut request in [
            json!({"action":"import","private_key":hex::encode([7; 32])}),
            json!({"action":"watch","public_key":hex::encode(peer)}),
        ] {
            request["revision"] = json!(store.revision);
            let error = store
                .manage(serde_json::from_value(request).unwrap())
                .unwrap_err();
            assert!(error.to_string().contains("peer identity"), "{error}");
        }
        assert_eq!(store.entries.len(), 1);
        let mut fresh = WalletStore::open(&dir.path().join("fresh.sqlite"), [1; 32]).unwrap();
        fresh.reserve_peer_identity(peer).unwrap();
        assert!(fresh.seed_hot([7; 32]).is_err());
        assert!(fresh.seed_watch(peer).is_err());
        assert!(fresh.entries.is_empty());
    }

    #[test]
    fn stored_hot_keys_are_owner_only_and_record_their_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let wallets = path.with_extension("wallets.sqlite");
        let mut store = WalletStore::open(&path, [1; 32]).unwrap();
        manage(&mut store, json!({"action":"create"}));
        drop(store);
        let network = |store: &WalletStore| -> String {
            store
                .connection
                .query_row("SELECT chain_id FROM wallet_network", [], |r| r.get(0))
                .unwrap()
        };
        // The journal persists (TRUNCATE mode), so its protection does too.
        let journal = journal_path(&wallets);
        assert_eq!(std::fs::metadata(&journal).unwrap().len(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&wallets), 0o600);
            assert_eq!(mode(&journal), 0o600);
            for file in [&wallets, &journal] {
                std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
            }
            drop(WalletStore::open(&path, [1; 32]).unwrap());
            assert_eq!(
                mode(&wallets),
                0o600,
                "existing permissive storage is tightened"
            );
            assert_eq!(mode(&journal), 0o600);
        }
        assert!(wallets.exists());
        let reopened = WalletStore::open(&path, [2; 32]).unwrap();
        assert_eq!(network(&reopened), hex::encode([2; 32]));
        assert_eq!(
            reopened.entries.len(),
            1,
            "keys remain shared across networks"
        );
    }

    /// `net.db` and `net.sqlite` once shared `net.wallets.sqlite`. Each now
    /// has its own store; an existing stem-named store is copied, not moved.
    #[test]
    fn chain_databases_with_one_stem_get_separate_wallet_storage() {
        let dir = tempfile::tempdir().unwrap();
        let sqlite = dir.path().join("net.sqlite");
        let mut shared = WalletStore::open(&sqlite, [1; 32]).unwrap();
        manage(
            &mut shared,
            json!({"action":"import","private_key":hex::encode([3;32])}),
        );
        let saved = shared.status();
        drop(shared);
        let legacy = dir.path().join("net.wallets.sqlite");
        assert!(legacy.exists());
        let db = dir.path().join("net.db");
        let mut copied = WalletStore::open(&db, [1; 32]).unwrap();
        assert_eq!(copied.status(), saved, "an upgrade keeps the keys it used");
        let own = dir.path().join("net.db-wallets.sqlite");
        assert!(own.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&own).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // The stores now diverge: changes to one never reach the other.
        manage(&mut copied, json!({"action":"create"}));
        drop(copied);
        assert_eq!(WalletStore::open(&sqlite, [1; 32]).unwrap().status(), saved);
        assert_eq!(WalletStore::open(&db, [1; 32]).unwrap().entries.len(), 2);
        assert!(!std::fs::read_dir(dir.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
        // A new store under a name of its own copies nothing.
        let fresh = WalletStore::open(&dir.path().join("other.db"), [1; 32]).unwrap();
        assert!(fresh.entries.is_empty());
    }
}
