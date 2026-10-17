//! Local wallet selection and keys. This database is independent of chain state.
use crate::{
    address, crypto,
    types::{Hash, PublicKey},
};
use anyhow::{Context, Result, anyhow, ensure};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use zeroize::{Zeroize, Zeroizing};

const MAX_WALLETS: usize = 256;

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
}
/// Hot secrets are stored unencrypted, so the database is owner-only on Unix.
/// SQLite gives its rollback journal the database file's mode. Windows files
/// inherit the containing folder's ACL.
fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("cannot open wallet storage {}", path.display()))?;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("cannot restrict wallet storage {}", path.display()))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl WalletStore {
    #[cfg(test)]
    pub fn open(chain_path: &Path, chain_id: Hash) -> Result<Self> {
        let store = Self::open_unrecorded(chain_path, chain_id)?;
        store.record_network()?;
        Ok(store)
    }
    /// Load and validate the store without recording the network opening it.
    /// A node checks its wallets before the chain replay, and records the
    /// network only once its chain database has accepted this configuration.
    pub fn open_unrecorded(chain_path: &Path, chain_id: Hash) -> Result<Self> {
        let path = chain_path.with_extension("wallets.sqlite");
        ensure!(
            path != chain_path,
            "chain database path conflicts with wallet storage"
        );
        restrict_permissions(&path)?;
        let mut connection = Connection::open(&path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS wallets(id TEXT PRIMARY KEY,name TEXT NOT NULL,public BLOB NOT NULL,secret BLOB);
            CREATE TABLE IF NOT EXISTS wallet_selection(singleton INTEGER PRIMARY KEY CHECK(singleton=1),active TEXT NOT NULL,revision TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS wallet_network(singleton INTEGER PRIMARY KEY CHECK(singleton=1),chain_id TEXT NOT NULL);")?;
        let selection: Option<(String, String)> = connection
            .query_row(
                "SELECT active,revision FROM wallet_selection WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let fresh = selection.is_none();
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
                let secret = row
                    .get::<_, Option<Vec<u8>>>(3)?
                    .map(|bytes| {
                        let bytes = Zeroizing::new(bytes);
                        ensure!(bytes.len() == 32, "invalid saved private key");
                        let mut key = Zeroizing::new([0u8; 32]);
                        key.copy_from_slice(&bytes);
                        ensure!(
                            crypto::public_key(&key)? == public,
                            "saved public/private key mismatch"
                        );
                        Ok::<_, anyhow::Error>(key)
                    })
                    .transpose()?;
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
        Ok(Self {
            connection,
            entries,
            active,
            revision,
            fresh,
            chain_id,
        })
    }
    /// Keys are independent of chain state, but sidecar names derive from the
    /// chain path's stem: say so when another network opens this store.
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
    /// A saved selection, even an empty one, survives startup flags. Report it
    /// whenever that selection is not the requested wallet.
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
    pub fn manage(&mut self, request: ManageRequest) -> Result<Value> {
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
                // The exported hex leaves through the response; it is not wiped.
                return Ok(
                    json!({"format":"hashstash-private-v1","private_key":hex::encode(secret.as_slice()),"public_key":hex::encode(entry.public)}),
                );
            }
        }
        self.fresh = false;
        Ok(self.status())
    }
    fn add_select(&mut self, entry: Entry) -> Result<()> {
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_saved_revision(&tx, self.revision)?;
        tx.execute(
            "INSERT INTO wallets(id,name,public,secret) VALUES(?1,?2,?3,?4)",
            params![
                id,
                entry.name,
                entry.public.as_slice(),
                entry.secret.as_ref().map(|s| s.as_slice())
            ],
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
        store
            .manage(serde_json::from_value(request).unwrap())
            .unwrap()
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
    fn ignored_startup_wallets_are_reported_unless_already_selected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.sqlite");
        let public = crypto::public_key(&[3; 32]).unwrap();
        drop(WalletStore::open(&path, [1; 32]).unwrap());
        let mut empty = WalletStore::open(&path, [1; 32]).unwrap();
        let warning = empty.unapplied_seed("--wallet-key", "hot", &public).unwrap();
        assert!(warning.contains("--wallet-key was not applied") && warning.contains("no wallet selected"));
        empty.seed_hot([3; 32]).unwrap();
        assert!(empty.entries.is_empty());
        manage(&mut empty, json!({"action":"import","private_key":hex::encode([3;32])}));
        assert!(empty.unapplied_seed("--wallet-key", "hot", &public).is_none());
        let watch = empty.unapplied_seed("--watch-key", "watch", &public).unwrap();
        assert!(watch.contains("hot wallet hsh"), "{watch}");
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = || std::fs::metadata(&wallets).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(), 0o600);
            std::fs::set_permissions(&wallets, std::fs::Permissions::from_mode(0o644)).unwrap();
            drop(WalletStore::open(&path, [1; 32]).unwrap());
            assert_eq!(mode(), 0o600, "existing permissive storage is tightened");
        }
        assert!(wallets.exists());
        let reopened = WalletStore::open(&path, [2; 32]).unwrap();
        assert_eq!(network(&reopened), hex::encode([2; 32]));
        assert_eq!(reopened.entries.len(), 1, "keys remain shared across networks");
    }
}
