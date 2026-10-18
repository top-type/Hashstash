//! Bounded peer discovery policy. This is transport policy, never consensus.
use crate::types::Hash;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

pub const MAX_ADDRESSES: usize = 32;
pub const MAX_BOOK: usize = 256;
pub const MAX_SEEDS: usize = 16;
pub const MAX_SEED_RESULTS: usize = 8;
pub const MAX_PER_SOURCE: usize = 32;
pub const MAX_PER_GROUP: usize = 16;
pub const MAX_PERSISTED_BYTES: usize = 128 * 1024;
/// Learned endpoints sharing one IP address, whatever their ports.
pub const MAX_PER_IP: usize = 2;
/// Consecutive failures after which a never-verified learned entry is dropped.
pub const MAX_UNVERIFIED_FAILURES: u32 = 3;
/// The last verified outbound peers, in distinct network groups, saved with
/// the book and tried first after a restart.
pub const MAX_ANCHORS: usize = 2;
const MAX_AGE: u64 = 7 * 24 * 3600;
const CONFIGURED: &str = "configured";
/// How long every requester receives the same address sample.
const ADVERTISED_SAMPLE_SECONDS: u64 = 6 * 3600;

#[derive(Clone, Debug, Default)]
pub struct Options {
    pub enabled: bool,
    pub seeds: Vec<String>,
    pub advertise: Option<SocketAddr>,
    /// Explicit isolated-network opt-in. Never enabled by public discovery.
    pub allow_private: bool,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.seeds.len() <= MAX_SEEDS, "at most 16 discovery seeds");
        ensure!(
            self.enabled
                || (self.seeds.is_empty() && self.advertise.is_none() && !self.allow_private),
            "discovery options require peer discovery"
        );
        for seed in &self.seeds {
            validate_seed(seed)?;
        }
        if let Some(address) = self.advertise {
            ensure!(
                allowed(address, self.allow_private),
                "advertised peer must be a routable numeric endpoint (private networks require explicit opt-in)"
            );
        }
        Ok(())
    }
}

pub fn validate_seed(seed: &str) -> Result<()> {
    ensure!(
        !seed.is_empty() && seed.len() <= 260 && seed.is_ascii(),
        "invalid seed length or characters"
    );
    if let Ok(address) = seed.parse::<SocketAddr>() {
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified(),
            "invalid seed endpoint"
        );
        return Ok(());
    }
    let (host, port) = seed.rsplit_once(':').context("seed requires HOST:PORT")?;
    ensure!(
        port.parse::<u16>().is_ok_and(|p| p != 0),
        "invalid seed port"
    );
    ensure!(
        host.len() <= 253
            && host.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')),
        "invalid seed hostname"
    );
    Ok(())
}

pub fn normalized(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|v| SocketAddr::new(IpAddr::V4(v), address.port()))
            .unwrap_or(address),
        _ => address,
    }
}

/// Conservative global-unicast policy: reject local, special-use and transition ranges.
pub fn public_address(address: SocketAddr) -> bool {
    if address.port() == 0 {
        return false;
    }
    match normalized(address).ip() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            // Global-unicast 2000::/3, excluding IETF protocol assignments,
            // documentation and 6to4 (which can tunnel nonpublic IPv4).
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
pub fn allowed(address: SocketAddr, private: bool) -> bool {
    let address = normalized(address);
    address.port() != 0
        && !address.ip().is_unspecified()
        && !address.ip().is_multicast()
        && (!matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast()))
        && (private || public_address(address))
}
pub fn group(address: SocketAddr) -> String {
    match normalized(address).ip() {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("v4:{}:{}", b[0], b[1])
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            format!("v6:{:x}:{:x}", s[0], s[1])
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub address: SocketAddr,
    pub source: String,
    pub added: u64,
    pub last_success: u64,
    pub last_attempt: u64,
    pub failures: u32,
    pub next_attempt: u64,
    #[serde(skip)]
    pub explicit: bool,
    /// Configured for this run; such peers are never advertised.
    #[serde(skip)]
    pub configured: bool,
    #[serde(skip)]
    pub busy: bool,
    #[serde(skip)]
    pub last_discovery: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    chain: Hash,
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    anchors: Vec<SocketAddr>,
}
/// The address sample every requester receives, and the recent peers it
/// was drawn from.
struct Sample {
    at: u64,
    eligible: Vec<SocketAddr>,
    addresses: Vec<SocketAddr>,
}

pub struct AddressBook {
    path: PathBuf,
    chain: Hash,
    pub options: Options,
    local: SocketAddr,
    entries: BTreeMap<SocketAddr, Entry>,
    /// Saved verified rows dated after this host's clock. They stay on disk
    /// and are admitted once the clock reaches them, so a clock that is
    /// behind at startup cannot erase the persisted book.
    dormant: Vec<Entry>,
    /// Saved rows that looked expired at startup. A clock running fast must
    /// not erase them either, so they stay on disk until this run verifies a
    /// peer, which shows that the clock and network work.
    stale: Vec<Entry>,
    verified_this_run: bool,
    /// The last verified outbound peers, most recent first, in distinct groups.
    anchors: Vec<SocketAddr>,
    /// Anchors saved by the previous run that this run has not tried yet.
    reconnect: Vec<SocketAddr>,
    /// The sidecar bytes last read or durably written.
    persisted: Option<Vec<u8>>,
    /// Unpredictable per-process order for replacement and equal-age probes.
    salt: Hash,
    advertised_cache: Option<Sample>,
    pub last_error: Option<String>,
    /// A rejected sidecar that was moved aside at startup.
    pub load_error: Option<String>,
}
impl AddressBook {
    pub fn open(
        path: PathBuf,
        chain: Hash,
        options: Options,
        local: SocketAddr,
        configured: &[SocketAddr],
        at: u64,
    ) -> Result<Self> {
        options.validate()?;
        let mut salt = [0u8; 32];
        getrandom::fill(&mut salt)
            .map_err(|e| anyhow::anyhow!("peer discovery randomness unavailable: {e}"))?;
        let mut book = Self {
            path,
            chain,
            options,
            local: normalized(local),
            entries: BTreeMap::new(),
            dormant: Vec::new(),
            stale: Vec::new(),
            verified_this_run: false,
            anchors: Vec::new(),
            reconnect: Vec::new(),
            persisted: None,
            salt,
            advertised_cache: None,
            last_error: None,
            load_error: None,
        };
        book.remove_stale_temporaries();
        if let Err(error) = book.load(at) {
            // The sidecar is a discovery hint with no consensus role. Keep a
            // rejected file for inspection and continue with configured peers
            // and seeds rather than failing every restart.
            book.entries.clear();
            book.dormant.clear();
            book.stale.clear();
            book.anchors.clear();
            book.reconnect.clear();
            book.persisted = None;
            let mut aside = book.path.clone().into_os_string();
            aside.push(".invalid");
            let aside = PathBuf::from(aside);
            fs::rename(&book.path, &aside)
                .with_context(|| format!("{error:#}; moving the peer address book aside failed"))?;
            let message = format!(
                "peer address book rejected and moved to {}: {error:#}",
                aside.display()
            );
            eprintln!("{message}");
            book.load_error = Some(message);
        }
        for address in configured {
            book.insert(*address, CONFIGURED.into(), true, at);
            // The flag also covers an entry first learned from gossip.
            match book.entries.get_mut(&normalized(*address)) {
                Some(entry) => entry.configured = true,
                None => {
                    book.last_error = Some(format!("configured peer {address} was not admitted"))
                }
            }
        }
        Ok(book)
    }
    fn load(&mut self, at: u64) -> Result<()> {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return Ok(());
        };
        ensure!(
            metadata.is_file(),
            "peer address book must be a regular file, not a symbolic link"
        );
        let file = fs::File::open(&self.path)?;
        ensure!(
            file.metadata()?.len() <= MAX_PERSISTED_BYTES as u64,
            "peer address book exceeds byte limit"
        );
        let mut bytes = Vec::new();
        file.take(MAX_PERSISTED_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= MAX_PERSISTED_BYTES,
            "peer address book exceeds byte limit"
        );
        let saved: Saved = serde_json::from_slice(&bytes).context("invalid peer address book")?;
        ensure!(
            saved.version == 1 && saved.chain == self.chain,
            "peer address book belongs to another chain or version"
        );
        ensure!(
            saved.entries.len() <= MAX_BOOK,
            "peer address book entry limit"
        );
        for entry in saved.entries {
            // Persistence never bypasses filtering, source quotas or time checks.
            if entry.last_success == 0 || entry.source.len() > 64 {
                continue;
            }
            if entry.last_success > at {
                self.dormant.push(entry);
            } else if at - entry.last_success > MAX_AGE {
                self.stale.push(entry);
            } else {
                self.restore(entry, at);
            }
        }
        // Anchors keep distinct groups. One whose row is dormant or stale stays
        // saved with that row; only admitted ones are reconnected.
        for anchor in saved.anchors.into_iter().map(normalized) {
            if self.anchors.len() < MAX_ANCHORS
                && !self.anchors.iter().any(|a| group(*a) == group(anchor))
            {
                self.anchors.push(anchor);
            }
        }
        self.reconnect = self.anchors.clone();
        self.persisted = Some(bytes);
        Ok(())
    }
    /// Admit one saved verified row, keeping its contact history.
    fn restore(&mut self, entry: Entry, at: u64) {
        if at.saturating_sub(entry.last_success) > MAX_AGE {
            return;
        }
        if self.insert(entry.address, entry.source.clone(), false, at) {
            let current = self.entries.get_mut(&normalized(entry.address)).unwrap();
            current.last_success = entry.last_success;
            current.last_attempt = entry.last_attempt.min(at);
            current.added = entry.added.min(at);
            current.failures = entry.failures.min(16);
            current.next_attempt = entry.next_attempt.min(at + 60);
        }
    }
    /// Interrupted saves leave `<stem>.<32 hex>.tmp` siblings that are never read.
    fn remove_stale_temporaries(&self) {
        let (Some(parent), Some(stem)) = (
            self.path.parent(),
            self.path.file_stem().and_then(|s| s.to_str()),
        ) else {
            return;
        };
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        let Ok(listing) = fs::read_dir(parent) else {
            return;
        };
        for item in listing.flatten() {
            let name = item.file_name();
            let random = name
                .to_str()
                .and_then(|n| n.strip_prefix(stem))
                .and_then(|n| n.strip_prefix('.'))
                .and_then(|n| n.strip_suffix(".tmp"));
            if random.is_some_and(|r| r.len() == 32 && r.bytes().all(|b| b.is_ascii_hexdigit()))
                && item.file_type().is_ok_and(|t| t.is_file())
            {
                let _ = fs::remove_file(item.path());
            }
        }
    }
    fn rank(&self, address: SocketAddr) -> Hash {
        let mut bytes = self.salt.to_vec();
        bytes.extend_from_slice(address.to_string().as_bytes());
        crate::crypto::sha256d(&bytes)
    }
    pub fn is_self(&self, address: SocketAddr) -> bool {
        let address = normalized(address);
        address == self.local
            || self.options.advertise.map(normalized) == Some(address)
            || (self.local.ip().is_unspecified()
                && address.port() == self.local.port()
                && address.ip().is_loopback())
    }
    fn insert(&mut self, address: SocketAddr, source: String, explicit: bool, at: u64) -> bool {
        let address = normalized(address);
        if self.is_self(address) || !allowed(address, self.options.allow_private || explicit) {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.explicit |= explicit;
            return false;
        }
        self.entries.retain(|_, entry| {
            entry.explicit
                || entry.busy
                || at.saturating_sub(entry.last_success.max(entry.added)) <= MAX_AGE
        });
        let network = group(address);
        if !explicit
            && (self.entries.values().filter(|e| e.source == source).count() >= MAX_PER_SOURCE
                || self
                    .entries
                    .values()
                    .filter(|e| group(e.address) == network && !e.explicit)
                    .count()
                    >= MAX_PER_GROUP
                || self
                    .entries
                    .values()
                    .filter(|e| e.address.ip() == address.ip() && !e.explicit)
                    .count()
                    >= MAX_PER_IP)
        {
            return false;
        }
        if self.entries.len() >= MAX_BOOK {
            // Replace instead of refusing. An operator's explicit endpoint
            // displaces any learned entry; a learned address displaces only an
            // unverified one, failed entries first, otherwise in salted order.
            let victim = self
                .entries
                .values()
                .filter(|e| !e.explicit && !e.busy && (explicit || e.last_success == 0))
                .max_by_key(|e| (e.last_success == 0, e.failures, self.rank(e.address)))
                .map(|e| e.address);
            let Some(victim) = victim else {
                if explicit {
                    self.last_error = Some(format!("explicit peer {address} was not admitted"));
                }
                return false;
            };
            self.entries.remove(&victim);
        }
        self.entries.insert(
            address,
            Entry {
                address,
                source,
                added: at,
                last_success: 0,
                last_attempt: 0,
                failures: 0,
                next_attempt: 0,
                explicit,
                configured: false,
                busy: false,
                last_discovery: 0,
            },
        );
        true
    }
    pub fn add_seed(&mut self, address: SocketAddr, seed: &str, at: u64) -> bool {
        // Seeds are operator input, but DNS responses still cannot nominate LAN endpoints.
        let explicit = seed.parse::<SocketAddr>().is_ok();
        self.insert(
            address,
            format!(
                "seed:{}",
                &hex::encode(crate::crypto::sha256d(seed.as_bytes()))[..16]
            ),
            explicit,
            at,
        )
    }
    pub fn learn(&mut self, source: SocketAddr, addresses: &[SocketAddr], at: u64) {
        for address in addresses.iter().take(MAX_ADDRESSES) {
            self.insert(*address, group(source), false, at);
        }
    }
    pub fn advertisement(&mut self, source: SocketAddr, address: SocketAddr, at: u64) {
        // An inbound node can nominate only its observed source IP, never a victim IP.
        if normalized(source).ip() == normalized(address).ip() {
            self.learn(source, &[address], at);
        }
    }
    pub fn advertised(&mut self, at: u64, random: u64) -> Vec<SocketAddr> {
        // Operator-configured peers are private topology and are not gossiped.
        let own = self.options.advertise.map(normalized);
        let eligible = self
            .entries
            .values()
            .filter(|e| {
                e.last_success > 0
                    && at.saturating_sub(e.last_success) < 3600
                    && !e.configured
                    && e.source != CONFIGURED
                    && Some(e.address) != own
                    && allowed(e.address, self.options.allow_private)
            })
            .map(|e| e.address)
            .collect::<Vec<_>>();
        // Every requester receives the same random sample for a fixed
        // interval, whatever peers are verified meanwhile, so repeated or
        // provoked queries cannot enumerate recent peers. A sample that
        // already lists every eligible peer hides nothing and follows changes.
        let reuse = self.advertised_cache.as_ref().is_some_and(|cached| {
            at.saturating_sub(cached.at) < ADVERTISED_SAMPLE_SECONDS
                && (cached.addresses.len() >= MAX_ADDRESSES || cached.eligible == eligible)
        });
        if !reuse {
            let mut ranked: Vec<_> = eligible
                .iter()
                .map(|address| {
                    let mut bytes = self.rank(*address).to_vec();
                    bytes.extend_from_slice(&random.to_le_bytes());
                    (crate::crypto::sha256d(&bytes), *address)
                })
                .collect();
            ranked.sort();
            let mut addresses: Vec<_> = own.into_iter().collect();
            addresses.extend(
                ranked
                    .into_iter()
                    .map(|(_, address)| address)
                    .take(MAX_ADDRESSES - addresses.len()),
            );
            self.advertised_cache = Some(Sample {
                at,
                eligible,
                addresses,
            });
        }
        self.advertised_cache
            .as_ref()
            .map_or_else(Vec::new, |cached| cached.addresses.clone())
    }
    /// Whether this node synchronized successfully with a book entry at this
    /// source IP during the last hour.
    pub fn verified_ip(&self, ip: IpAddr, at: u64) -> bool {
        let ip = normalized(SocketAddr::new(ip, 1)).ip();
        self.entries.values().any(|e| {
            e.address.ip() == ip && e.last_success > 0 && at.saturating_sub(e.last_success) < 3600
        })
    }
    pub fn next(&mut self, at: u64, maximum: usize) -> Vec<SocketAddr> {
        let ready: Vec<_> = self
            .dormant
            .iter()
            .filter(|e| e.last_success <= at)
            .cloned()
            .collect();
        if !ready.is_empty() {
            self.dormant.retain(|e| e.last_success > at);
            for entry in ready {
                self.restore(entry, at);
            }
        }
        self.entries.retain(|_, entry| {
            entry.explicit
                || entry.busy
                || at.saturating_sub(entry.last_success.max(entry.added)) <= MAX_AGE
        });
        let healthy_groups = self
            .entries
            .values()
            .filter(|e| {
                e.last_success > 0 && e.failures < 3 && at.saturating_sub(e.last_success) < 3600
            })
            .map(|e| group(e.address))
            .collect::<BTreeSet<_>>();
        let protect_healthy = !healthy_groups.is_empty();
        let mut unknown_busy = self
            .entries
            .values()
            .filter(|e| e.busy && e.last_success == 0)
            .count();
        // Equal attempt times, including never-tried entries, use a salted
        // order rather than numeric address order an advertiser could choose.
        let mut candidates = self
            .entries
            .values()
            .filter(|e| !e.busy && e.next_attempt <= at)
            .map(|e| {
                (
                    e.last_attempt,
                    self.rank(e.address),
                    e.address,
                    e.last_success > 0,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort();
        let mut selected = Vec::new();
        let mut groups = self
            .entries
            .values()
            .filter(|e| e.busy)
            .map(|e| group(e.address))
            .collect::<BTreeSet<_>>();
        // The previous run's anchors come first, once each: a book that an
        // attacker's verified addresses have since crowded cannot displace
        // the peers this node last synchronized with.
        let mut reconnect = std::mem::take(&mut self.reconnect);
        reconnect.retain(|address| {
            let Some(entry) = self.entries.get_mut(address) else {
                return false;
            };
            if entry.busy || entry.next_attempt > at {
                return true;
            }
            let network = group(*address);
            if selected.len() >= maximum.min(2)
                || (!self.options.allow_private && groups.contains(&network))
            {
                return true;
            }
            groups.insert(network);
            entry.busy = true;
            entry.last_attempt = at;
            selected.push(*address);
            false
        });
        self.reconnect = reconnect;
        // Reserve one slot for established paths. An untrusted book flood must
        // never queue both slots for minutes ahead of an already healthy peer.
        // Within each class oldest-attempt rotation preserves fairness.
        for phase in 0..3 {
            for &(_, _, address, verified) in &candidates {
                if selected.len() >= maximum.min(2) {
                    break;
                }
                if self.entries[&address].busy
                    || (phase == 0 && !verified)
                    || (phase == 1 && verified)
                    || (phase == 2 && protect_healthy && !verified)
                {
                    continue;
                }
                if protect_healthy && !verified && unknown_busy >= 1 {
                    continue;
                }
                let network = group(address);
                if !self.options.allow_private
                    && (groups.contains(&network)
                        || (protect_healthy && !verified && healthy_groups.contains(&network)))
                {
                    continue;
                }
                groups.insert(network);
                let entry = self.entries.get_mut(&address).unwrap();
                entry.busy = true;
                entry.last_attempt = at;
                selected.push(address);
                if !verified {
                    unknown_busy += 1;
                }
                if phase < 2 {
                    break;
                }
            }
        }
        selected
    }
    pub fn finished(&mut self, address: SocketAddr, success: bool, at: u64, jitter: u64) {
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.busy = false;
            if success {
                entry.last_success = at;
                entry.failures = 0;
                self.verified_this_run = true;
                // This outbound peer becomes the newest anchor, replacing an
                // older one in its group.
                self.anchors
                    .retain(|a| *a != address && group(*a) != group(address));
                self.anchors.insert(0, address);
                self.anchors.truncate(MAX_ANCHORS);
            } else {
                entry.failures = entry.failures.saturating_add(1).min(16);
            }
            entry.next_attempt = at
                + crate::network_guard::retry_delay(entry.failures, jitter)
                    .as_secs()
                    .max(1);
            // A learned address that never answered is dropped after a few
            // consecutive failures instead of cycling until it expires.
            if !entry.explicit
                && entry.last_success == 0
                && entry.failures >= MAX_UNVERIFIED_FAILURES
            {
                self.entries.remove(&address);
            }
        }
    }
    pub fn needs_discovery(&mut self, address: SocketAddr, at: u64) -> bool {
        if let Some(entry) = self.entries.get_mut(&address)
            && (entry.last_discovery == 0 || at.saturating_sub(entry.last_discovery) >= 60)
        {
            entry.last_discovery = at;
            return true;
        }
        false
    }
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// The persisted form: verified entries, then dormant rows not yet loaded.
    fn serialized(&self) -> Result<Vec<u8>> {
        let mut entries: Vec<Entry> = self
            .entries
            .values()
            .filter(|e| e.last_success > 0)
            .cloned()
            .collect();
        let stale = if self.verified_this_run {
            &[][..]
        } else {
            &self.stale[..]
        };
        for entry in self.dormant.iter().chain(stale) {
            if entries.len() >= MAX_BOOK {
                break;
            }
            if !self.entries.contains_key(&normalized(entry.address)) {
                entries.push(entry.clone());
            }
        }
        let anchors = self
            .anchors
            .iter()
            .filter(|a| entries.iter().any(|e| e.address == **a))
            .copied()
            .collect();
        let bytes = serde_json::to_vec(&Saved {
            version: 1,
            chain: self.chain,
            entries,
            anchors,
        })?;
        ensure!(
            bytes.len() <= MAX_PERSISTED_BYTES,
            "peer address book persistence limit"
        );
        Ok(bytes)
    }
    /// Bytes to write when they differ from the last durable copy. An
    /// unchanged book is never rewritten or synced.
    pub fn pending_save(&self) -> Result<Option<Vec<u8>>> {
        let bytes = self.serialized()?;
        Ok((self.persisted.as_deref() != Some(bytes.as_slice())).then_some(bytes))
    }
    pub fn mark_saved(&mut self, bytes: Vec<u8>) {
        self.persisted = Some(bytes);
    }
    pub fn save(&mut self) -> Result<()> {
        if let Some(bytes) = self.pending_save()? {
            Self::persist(&self.path, &bytes)?;
            self.persisted = Some(bytes);
        }
        Ok(())
    }
    /// Atomically replace the sidecar. This performs file I/O and an fsync;
    /// callers run it without holding the discovery lock.
    pub fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.is_file(),
                "peer address book must be a regular file, not a symbolic link"
            );
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| anyhow::anyhow!("peer persistence randomness unavailable: {e}"))?;
        let temporary = path.with_extension(format!("{}.tmp", hex::encode(random)));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let written = file.write_all(bytes).and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        // Rename replaces an existing file atomically on Unix and Windows, so
        // there is never a moment without a book.
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        Ok(())
    }
}

pub fn path_for(database: &Path, chain: Hash) -> PathBuf {
    crate::local_files::sidecar(database, &format!("peers-{}.json", hex::encode(chain)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn book(path: PathBuf) -> AddressBook {
        AddressBook::open(
            path,
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[],
            100,
        )
        .unwrap()
    }
    #[test]
    fn full_unverified_book_cannot_starve_a_healthy_peer() {
        let dir = tempfile::tempdir().unwrap();
        let mut book = book(dir.path().join("book"));
        let good = "8.8.8.8:9".parse().unwrap();
        book.add_seed(good, "8.8.8.8:9", 100);
        book.finished(good, true, 100, 0);
        for source in 1..20 {
            for destination in 1..33 {
                book.learn(
                    SocketAddr::from(([20, source, 1, 1], 9)),
                    &[SocketAddr::from(([30, source, destination, 1], 9))],
                    100,
                );
            }
        }
        assert_eq!(book.entries().count(), MAX_BOOK);
        let first = book.next(110, 2);
        assert!(first.contains(&good));
        assert_eq!(first.len(), 2);
        // Leave the unknown probe hanging. The known path must resume again,
        // rather than waiting behind every never-tested entry.
        book.finished(good, true, 110, 0);
        assert_eq!(book.next(120, 1), vec![good]);
        book.finished(good, true, 120, 0);
        assert!(book.next(120, 1).is_empty());
        assert_eq!(
            book.entries()
                .filter(|e| e.busy && e.last_success == 0)
                .count(),
            1
        );
    }
    #[test]
    fn destination_groups_dns_syntax_and_backoff_are_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut book = book(dir.path().join("book"));
        for n in 1..40 {
            book.learn(
                SocketAddr::from(([40, n, 1, 1], 9)),
                &[SocketAddr::from(([11, 1, n, 1], 9))],
                100,
            );
        }
        assert_eq!(book.entries().count(), MAX_PER_GROUP);
        assert_eq!(book.next(100, 2).len(), 1); // one /16 cannot occupy both slots
        let address = book.entries().find(|e| e.busy).unwrap().address;
        book.finished(address, false, 100, 0);
        let next = book.entries[&address].next_attempt;
        assert!(next > 100);
        assert_eq!(book.entries[&address].failures, 1);
        book.finished(address, false, next, 0);
        assert!(book.entries[&address].next_attempt > next);
        for seed in [
            "localhost:18481",
            "seed.example:18481",
            "[2606:4700::1]:18481",
        ] {
            assert!(validate_seed(seed).is_ok());
        }
        for seed in [
            "https://seed.example:18481",
            "user@seed.example:1",
            "seed:0",
            "seed:65536",
            "a..b:1",
            "-host:1",
            "host:1/path",
        ] {
            assert!(validate_seed(seed).is_err(), "{seed}");
        }
        let n = book.entries().count();
        book.add_seed("127.0.0.1:9".parse().unwrap(), "dns.example:9", 100);
        assert_eq!(book.entries().count(), n);
    }
    fn invalid_path(path: &Path) -> PathBuf {
        let mut aside = path.as_os_str().to_owned();
        aside.push(".invalid");
        PathBuf::from(aside)
    }
    #[test]
    fn oversized_sidecars_are_rejected_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("book");
        fs::write(&path, vec![b' '; MAX_PERSISTED_BYTES + 1]).unwrap();
        // A rejected hint file is moved aside; startup continues with the
        // configured peer instead of failing on every restart.
        let configured: SocketAddr = "8.8.8.8:9".parse().unwrap();
        let book = AddressBook::open(
            path.clone(),
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[configured],
            100,
        )
        .unwrap();
        assert!(book.load_error.as_ref().unwrap().contains("byte limit"));
        assert_eq!(
            book.entries().map(|e| e.address).collect::<Vec<_>>(),
            [configured]
        );
        assert!(!path.exists());
        assert_eq!(
            fs::read(invalid_path(&path)).unwrap().len(),
            MAX_PERSISTED_BYTES + 1
        );
    }
    #[test]
    fn stale_learned_hints_expire_while_explicit_bootstrap_is_retained() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let source = "8.8.8.8:9".parse().unwrap();
        let learned = "9.9.9.9:9".parse().unwrap();
        b.add_seed(source, "8.8.8.8:9", 100);
        b.learn(source, &[learned], 100);
        b.next(100 + MAX_AGE + 1, 0);
        assert_eq!(b.entries().count(), 1);
        assert_eq!(b.entries().next().unwrap().address, source);
    }
    #[cfg(unix)]
    #[test]
    fn address_book_symlinks_are_never_followed_or_overwritten() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("preserved");
        fs::write(&target, b"preserved").unwrap();
        let path = dir.path().join("book");
        let mut b = book(path.clone());
        symlink(&target, &path).unwrap();
        assert!(b.save().is_err());
        let reopened = AddressBook::open(
            path.clone(),
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[],
            100,
        )
        .unwrap();
        assert!(reopened.load_error.is_some());
        // Only the link itself is moved aside; its target is never touched.
        assert!(
            fs::symlink_metadata(invalid_path(&path))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(fs::symlink_metadata(&path).is_err());
        assert_eq!(fs::read(target).unwrap(), b"preserved");
    }
    #[test]
    fn filters_nonpublic_and_mapped_ranges() {
        for ip in [
            "127.0.0.1:1",
            "10.2.3.4:1",
            "100.64.0.1:1",
            "192.0.2.1:1",
            "198.19.1.1:1",
            "203.0.113.1:1",
            "224.0.0.1:1",
            "[::1]:1",
            "[::ffff:127.0.0.1]:1",
            "[2001:db8::1]:1",
            "[2002:7f00:1::]:1",
            "[fc00::1]:1",
            "[fe80::1]:1",
        ] {
            assert!(!public_address(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8:18481", "[2606:4700:4700::1111]:18481"] {
            assert!(public_address(ip.parse().unwrap()), "{ip}");
        }
    }
    #[test]
    fn bounds_sources_buckets_self_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let opts = Options {
            enabled: true,
            advertise: Some("9.9.9.9:9".parse().unwrap()),
            ..Default::default()
        };
        let mut book = AddressBook::open(
            path.clone(),
            [1; 32],
            opts.clone(),
            "0.0.0.0:9".parse().unwrap(),
            &[],
            100,
        )
        .unwrap();
        for a in 1..100 {
            book.learn(
                "8.8.8.8:9".parse().unwrap(),
                &[SocketAddr::from(([11, a, 1, 1], 9))],
                100,
            );
        }
        assert_eq!(book.entries().count(), MAX_PER_SOURCE);
        book.learn(
            "7.7.7.7:9".parse().unwrap(),
            &["9.9.9.9:9".parse().unwrap(), "127.0.0.1:9".parse().unwrap()],
            100,
        );
        assert_eq!(book.entries().count(), MAX_PER_SOURCE);
        assert_eq!(
            book.advertised(100, 0),
            vec!["9.9.9.9:9".parse::<SocketAddr>().unwrap()]
        );
        let addr = book.next(100, 2)[0];
        book.finished(addr, true, 101, 0);
        book.save().unwrap();
        let loaded = AddressBook::open(
            path.clone(),
            [1; 32],
            opts.clone(),
            "0.0.0.0:9".parse().unwrap(),
            &[],
            102,
        )
        .unwrap();
        assert_eq!(loaded.entries().count(), 1);
        assert_eq!(loaded.entries().next().unwrap().address, addr);
        // An unchanged book is not rewritten.
        assert!(loaded.pending_save().unwrap().is_none());
        let other = AddressBook::open(
            path.clone(),
            [2; 32],
            opts,
            "0.0.0.0:9".parse().unwrap(),
            &[],
            102,
        )
        .unwrap();
        assert!(other.load_error.as_ref().unwrap().contains("another chain"));
        assert_eq!(other.entries().count(), 0);
        assert!(invalid_path(&path).is_file());
    }
    #[test]
    fn a_clock_behind_saved_contacts_keeps_them_on_disk_until_it_catches_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut original = book(path.clone());
        let peer: SocketAddr = "8.8.8.8:9".parse().unwrap();
        original.add_seed(peer, "dns.example:9", 1_000);
        original.next(1_000, 2);
        original.finished(peer, true, 1_000, 0);
        original.save().unwrap();
        let saved = fs::read(&path).unwrap();
        // A host booting with its clock far behind (no RTC, before NTP).
        let mut early = book(path.clone());
        assert_eq!(early.entries().count(), 0);
        assert!(early.pending_save().unwrap().is_none());
        early.save().unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        // Other changes are persisted together with the dormant row.
        let learned: SocketAddr = "9.9.9.9:9".parse().unwrap();
        early.learn("7.7.7.7:9".parse().unwrap(), &[learned], 100);
        early.next(100, 2);
        early.finished(learned, true, 101, 0);
        early.save().unwrap();
        let mut corrected = AddressBook::open(
            path,
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[],
            500,
        )
        .unwrap();
        assert_eq!(corrected.entries().count(), 1);
        assert!(corrected.next(1_001, 0).is_empty());
        let mut known: Vec<_> = corrected.entries().map(|e| e.address).collect();
        known.sort();
        assert_eq!(known, [peer, learned]);
        assert_eq!(
            corrected
                .entries()
                .find(|e| e.address == peer)
                .unwrap()
                .last_success,
            1_000
        );
    }
    #[test]
    fn a_clock_ahead_keeps_apparently_expired_contacts_until_a_peer_is_verified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut original = book(path.clone());
        let peer: SocketAddr = "8.8.8.8:9".parse().unwrap();
        original.add_seed(peer, "dns.example:9", 100);
        original.next(100, 2);
        original.finished(peer, true, 100, 0);
        original.save().unwrap();
        let saved = fs::read(&path).unwrap();
        let open = |at| {
            AddressBook::open(
                path.clone(),
                [1; 32],
                Options {
                    enabled: true,
                    ..Default::default()
                },
                "0.0.0.0:9".parse().unwrap(),
                &[],
                at,
            )
            .unwrap()
        };
        let ahead = 100 + MAX_AGE + 10;
        let mut fast = open(ahead);
        assert_eq!(fast.entries().count(), 0);
        let learned: SocketAddr = "9.9.9.9:9".parse().unwrap();
        fast.learn("7.7.7.7:9".parse().unwrap(), &[learned], ahead);
        fast.save().unwrap();
        assert_eq!(fs::read(&path).unwrap(), saved);
        // After the clock is corrected the saved contact still loads.
        assert_eq!(open(200).entries().count(), 1);
        // Once this run verifies a peer, rows that really expired are dropped.
        fast.next(ahead, 2);
        fast.finished(learned, true, ahead, 0);
        fast.save().unwrap();
        assert_eq!(
            open(ahead).entries().map(|e| e.address).collect::<Vec<_>>(),
            [learned]
        );
    }
    #[test]
    fn full_books_replace_learned_entries_and_always_admit_operator_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut b = book(path.clone());
        // One IP cannot occupy more than two learned entries via its ports.
        for port in 1..10 {
            b.advertisement(
                "8.8.8.8:1".parse().unwrap(),
                SocketAddr::from(([8, 8, 8, 8], port)),
                100,
            );
        }
        assert_eq!(b.entries().count(), MAX_PER_IP);
        for entry in b.entries.values_mut() {
            entry.last_success = 100;
        }
        // Fill the book with verified learned peers across many groups.
        let mut verified = Vec::new();
        'fill: for source in 1..=40u8 {
            for host in 1..=16u8 {
                if b.entries().count() >= MAX_BOOK {
                    break 'fill;
                }
                let address = SocketAddr::from(([30, source, host, 1], 9));
                b.learn(SocketAddr::from(([20, source, 1, 1], 9)), &[address], 100);
                if b.entries.contains_key(&address) {
                    b.entries.get_mut(&address).unwrap().last_success = 100;
                    verified.push(address);
                }
            }
        }
        assert_eq!(b.entries().count(), MAX_BOOK);
        // A learned newcomer cannot displace verified peers.
        let newcomer = "40.1.1.1:9".parse().unwrap();
        b.learn("50.1.1.1:9".parse().unwrap(), &[newcomer], 100);
        assert!(!b.entries.contains_key(&newcomer));
        // An unverified entry is replaced instead of blocking new addresses.
        let unverified = verified.pop().unwrap();
        b.entries.get_mut(&unverified).unwrap().last_success = 0;
        b.learn("50.1.1.1:9".parse().unwrap(), &[newcomer], 100);
        assert!(b.entries.contains_key(&newcomer));
        assert!(!b.entries.contains_key(&unverified));
        b.entries.get_mut(&newcomer).unwrap().last_success = 100;
        b.save().unwrap();
        // Persisted verified entries never crowd out configured endpoints
        // or numeric seeds.
        let configured: SocketAddr = "60.1.1.1:9".parse().unwrap();
        let mut reopened = AddressBook::open(
            path,
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[configured],
            101,
        )
        .unwrap();
        assert!(reopened.entries.get(&configured).unwrap().explicit);
        assert!(reopened.add_seed("61.1.1.1:9".parse().unwrap(), "61.1.1.1:9", 101));
        assert_eq!(reopened.entries().count(), MAX_BOOK);
        assert!(reopened.last_error.is_none());
        // A learned address that never answers is dropped after repeated failures.
        let failing = reopened.entries().find(|e| !e.explicit).unwrap().address;
        reopened.entries.get_mut(&failing).unwrap().last_success = 0;
        for attempt in 0..MAX_UNVERIFIED_FAILURES {
            assert!(reopened.entries.contains_key(&failing));
            reopened.finished(failing, false, 200 + u64::from(attempt), 0);
        }
        assert!(!reopened.entries.contains_key(&failing));
    }
    #[test]
    fn configured_peers_are_not_gossiped_and_samples_are_stable() {
        let dir = tempfile::tempdir().unwrap();
        let configured: SocketAddr = "8.8.8.8:9".parse().unwrap();
        let mut b = AddressBook::open(
            dir.path().join("book"),
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[configured],
            100,
        )
        .unwrap();
        b.next(100, 1);
        b.finished(configured, true, 100, 0);
        assert!(b.verified_ip("8.8.8.8".parse().unwrap(), 101));
        assert!(!b.verified_ip("8.8.4.4".parse().unwrap(), 101));
        assert!(b.advertised(101, 0).is_empty());
        for n in 1..=40u8 {
            let address = SocketAddr::from(([30, n, 1, 1], 9));
            b.learn(SocketAddr::from(([20, n, 1, 1], 9)), &[address], 100);
            b.entries.get_mut(&address).unwrap().last_success = 100;
        }
        let first = b.advertised(101, 3);
        assert_eq!(first.len(), MAX_ADDRESSES);
        assert!(!first.contains(&configured));
        // Repeated requests cannot page through the whole set, even when a
        // requester gets more of its own addresses verified meanwhile.
        for (n, random) in [5, 17, 29].into_iter().enumerate() {
            let address = SocketAddr::from(([31, n as u8, 1, 1], 9));
            b.learn(SocketAddr::from(([21, n as u8, 1, 1], 9)), &[address], 102);
            b.entries.get_mut(&address).unwrap().last_success = 102;
            assert_eq!(b.advertised(102, random), first);
        }
        // The sample is redrawn only after a fixed interval.
        let later = 101 + ADVERTISED_SAMPLE_SECONDS;
        for entry in b.entries.values_mut() {
            entry.last_success = later;
        }
        let redrawn = b.advertised(later, 7);
        assert_eq!(redrawn.len(), MAX_ADDRESSES);
        assert_ne!(redrawn, first);
        assert!(!redrawn.contains(&configured));
        // A configured peer stays private even when its saved entry was
        // learned from gossip.
        let path = dir.path().join("learned");
        let mut saved = book(path.clone());
        let learned: SocketAddr = "9.9.9.9:9".parse().unwrap();
        saved.learn("7.7.7.7:9".parse().unwrap(), &[learned], 100);
        saved.finished(learned, true, 100, 0);
        assert_eq!(saved.advertised(100, 0), [learned]);
        saved.save().unwrap();
        let mut reopened = AddressBook::open(
            path,
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[learned],
            101,
        )
        .unwrap();
        assert_ne!(reopened.entries[&learned].source, CONFIGURED);
        assert!(reopened.advertised(101, 0).is_empty());
    }
    #[test]
    fn interrupted_save_temporaries_are_removed_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.peers-ab.json");
        let stale = dir
            .path()
            .join(format!("node.peers-ab.{}.tmp", "0f".repeat(16)));
        let unrelated = dir.path().join("node.peers-ab.notes.tmp");
        fs::write(&stale, b"partial").unwrap();
        fs::write(&unrelated, b"kept").unwrap();
        let mut b = book(path.clone());
        assert!(!stale.exists());
        assert!(unrelated.exists());
        b.save().unwrap();
        b.save().unwrap();
        assert!(path.is_file());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
    #[test]
    fn the_last_verified_outbound_peers_are_reconnected_first_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut b = book(path.clone());
        // Twenty verified peers in distinct groups, all last tried long ago.
        let peers: Vec<SocketAddr> = (1..=20u8)
            .map(|n| SocketAddr::from(([30, n, 1, 1], 9)))
            .collect();
        let sibling = SocketAddr::from(([30, 18, 2, 1], 9));
        for (n, peer) in peers.iter().chain([&sibling]).enumerate() {
            b.learn(SocketAddr::from(([20, n as u8, 1, 1], 9)), &[*peer], 100);
            let entry = b.entries.get_mut(peer).unwrap();
            (entry.last_success, entry.last_attempt) = (100, 100);
        }
        // This node last synchronized with three of them. Anchors keep
        // distinct groups, so the newest replaces its group's older one.
        let (first, second) = (peers[17], peers[18]);
        for (anchor, at) in [(sibling, 150), (first, 200), (second, 200)] {
            b.entries.get_mut(&anchor).unwrap().last_attempt = at;
            b.finished(anchor, true, at, 0);
        }
        assert_eq!(b.anchors, [second, first]);
        b.save().unwrap();
        // After a restart they are tried first, although rotation by oldest
        // attempt would try every other verified peer before them.
        let mut reopened = AddressBook::open(
            path,
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[],
            300,
        )
        .unwrap();
        let mut next = reopened.next(300, 2);
        next.sort();
        assert_eq!(next, [first, second]);
        // Only once: afterwards the usual rotation resumes.
        reopened.finished(first, true, 300, 0);
        reopened.finished(second, true, 300, 0);
        let rotation = reopened.next(400, 2);
        assert_eq!(rotation.len(), 2);
        assert!(!rotation.contains(&first) && !rotation.contains(&second));
        // A book saved before anchors existed still loads.
        let old = dir.path().join("old.json");
        fs::write(
            &old,
            serde_json::to_vec(&serde_json::json!({"version":1,"chain":vec![1; 32],"entries":[]}))
                .unwrap(),
        )
        .unwrap();
        assert!(book(old).load_error.is_none());
    }
    #[test]
    fn source_host_cannot_advertise_a_victim_or_grow_existing_lifetime() {
        let dir = tempfile::tempdir().unwrap();
        let mut book = AddressBook::open(
            dir.path().join("book"),
            [1; 32],
            Options {
                enabled: true,
                ..Default::default()
            },
            "0.0.0.0:9".parse().unwrap(),
            &[],
            100,
        )
        .unwrap();
        book.advertisement(
            "8.8.8.8:99".parse().unwrap(),
            "9.9.9.9:9".parse().unwrap(),
            100,
        );
        assert_eq!(book.entries().count(), 0);
        book.advertisement(
            "8.8.8.8:99".parse().unwrap(),
            "8.8.8.8:9".parse().unwrap(),
            100,
        );
        assert_eq!(book.entries().count(), 1);
        book.learn(
            "9.9.9.9:9".parse().unwrap(),
            &["8.8.8.8:9".parse().unwrap()],
            1000,
        );
        assert_eq!(book.entries().next().unwrap().added, 100);
    }
}
