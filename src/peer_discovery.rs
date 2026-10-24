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
/// The last outbound peers that advanced this node, in distinct network
/// groups, saved with the book and tried first after a restart.
pub const MAX_ANCHORS: usize = 2;
const MAX_AGE: u64 = 7 * 24 * 3600;
/// A learned entry that never answered expires this long after it was added.
const UNVERIFIED_AGE: u64 = 24 * 3600;
/// Operator-chosen entries (configured peers and seeds) and peers that
/// recently advanced this node are synchronized about this often, ahead of
/// the rotation through other verified peers.
pub const PREFERRED_INTERVAL: u64 = 15;
/// How long a peer whose block became the tip stays preferred.
pub const PRODUCTIVE_WINDOW: u64 = 3600;
/// An unknown entry in a network group that already holds a healthy
/// verified peer is probed at most this often.
const HEALTHY_GROUP_PROBE_INTERVAL: u64 = 600;
/// Consecutive failed or stalled contacts past six double an entry's retry
/// delay beyond a minute, up to this many seconds.
const MAX_RETRY_SECONDS: u64 = 3600;
const CONFIGURED: &str = "configured";
/// The source of seed results, followed by a digest of the seed.
const SEED_SOURCE: &str = "seed:";
/// How long every requester receives the same address sample.
const ADVERTISED_SAMPLE_SECONDS: u64 = 6 * 3600;

/// What one outbound synchronization with a book entry achieved. Only
/// `Current` and `Advanced` count as success: a completed exchange that held
/// an outbound slot without advancing this node does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contact {
    /// Connecting or the exchange failed.
    Failed,
    /// The exchange delivered nothing new, and took longer than one read
    /// allowance or was cut off for that.
    Stalled,
    /// The exchange completed promptly with nothing new: as far as the peer
    /// shows, it is not ahead of this node.
    Current,
    /// A block the peer delivered became the tip. It may hold more, so it is
    /// synchronized again at once.
    Advanced,
}
impl Contact {
    pub fn success(self) -> bool {
        matches!(self, Self::Current | Self::Advanced)
    }
}
/// How an address reached the book.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// A configured peer or numeric seed, which may be private when the
    /// operator configures it.
    Explicit,
    /// A DNS seed result: operator input, but only a public address.
    Seed,
    /// Learned from another peer.
    Gossip,
    /// Announced by an inbound peer for its own source address.
    Own,
}
/// An entry the operator chose: a configured peer or a seed result. Learned
/// quotas, displacement and the drop of never-verified entries after
/// repeated failures do not apply to it.
fn operator_input(entry: &Entry) -> bool {
    entry.explicit || entry.source.starts_with(SEED_SOURCE)
}
/// Seconds until an entry with `failures` consecutive failed or stalled
/// contacts is tried again: as for configured peers up to a minute, then,
/// unless the operator named the endpoint itself (`explicit`), doubling up
/// to an hour, so an address that went silent or keeps stalling costs an
/// attempt an hour rather than one a minute until it expires.
fn retry_seconds(failures: u32, jitter: u64, explicit: bool) -> u64 {
    if failures <= 6 || explicit {
        return crate::network_guard::retry_delay(failures, jitter)
            .as_secs()
            .max(1);
    }
    let base = (60u64 << (failures - 6).min(6)).min(MAX_RETRY_SECONDS);
    base + jitter % (base / 4)
}

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
    /// When a synchronization with this entry last made one of its blocks
    /// the tip.
    #[serde(skip)]
    pub advanced: u64,
    /// Its last synchronization did, so it is tried again at once.
    #[serde(skip)]
    pub ahead: bool,
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
    /// The last outbound peers that advanced this node, most recent first,
    /// in distinct groups.
    anchors: Vec<SocketAddr>,
    /// The entry in the exploring outbound slot (see `next`).
    exploring: Option<SocketAddr>,
    /// When an unknown entry in a healthy group was last probed.
    healthy_probe: u64,
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
            exploring: None,
            healthy_probe: 0,
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
            book.insert(*address, CONFIGURED.into(), Origin::Explicit, at);
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
        let origin = if entry.source.starts_with(SEED_SOURCE) {
            Origin::Seed
        } else {
            Origin::Gossip
        };
        if self.insert(entry.address, entry.source.clone(), origin, at) {
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
    /// Drop learned entries without a successful contact for `MAX_AGE`, and
    /// learned ones that never answered `UNVERIFIED_AGE` after they were
    /// added, so addresses gossiped into a group that is never probed do not
    /// hold quotas for a week. Explicit and busy entries stay.
    fn expire(&mut self, at: u64) {
        self.entries.retain(|_, entry| {
            let limit = if entry.last_success == 0 && !operator_input(entry) {
                UNVERIFIED_AGE
            } else {
                MAX_AGE
            };
            entry.explicit
                || entry.busy
                || at.saturating_sub(entry.last_success.max(entry.added)) <= limit
        });
    }
    /// Whether a learned `address` from `source` fits the learned-entry
    /// quotas per source, network group and IP address. A full group or IP
    /// makes room by displacing an unverified entry: any, for an inbound peer
    /// announcing its own address (`own`), and otherwise only one another
    /// source supplied that would still hold more of them than the
    /// newcomer's, so entries one source gossiped in cannot squat an honest
    /// node's address or group. Nothing is displaced unless the newcomer
    /// then fits both.
    fn make_room(&mut self, address: SocketAddr, source: &str, own: bool) -> bool {
        if self.entries.values().filter(|e| e.source == source).count() >= MAX_PER_SOURCE {
            return false;
        }
        let network = group(address);
        let mut victims = Vec::new();
        for (by_group, limit) in [(true, MAX_PER_GROUP), (false, MAX_PER_IP)] {
            let members: Vec<&Entry> = self
                .entries
                .values()
                .filter(|e| {
                    !operator_input(e)
                        && !victims.contains(&e.address)
                        && if by_group {
                            group(e.address) == network
                        } else {
                            e.address.ip() == address.ip()
                        }
                })
                .collect();
            if members.len() < limit {
                continue;
            }
            let held = |s: &str| members.iter().filter(|e| e.source == s).count();
            let mine = held(source);
            let victim = members
                .iter()
                .filter(|e| {
                    e.last_success == 0
                        && !e.busy
                        && (own || (e.source != source && held(&e.source) > mine + 1))
                })
                .max_by_key(|e| (held(&e.source), e.failures, self.rank(e.address)))
                .map(|e| e.address);
            let Some(victim) = victim else {
                return false;
            };
            victims.push(victim);
        }
        for victim in victims {
            self.entries.remove(&victim);
        }
        true
    }
    fn insert(&mut self, address: SocketAddr, source: String, origin: Origin, at: u64) -> bool {
        let address = normalized(address);
        let explicit = origin == Origin::Explicit;
        if self.is_self(address) || !allowed(address, self.options.allow_private || explicit) {
            return false;
        }
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.explicit |= explicit;
            // A learned entry a seed also returns becomes operator input.
            if origin == Origin::Seed && !operator_input(entry) {
                entry.source = source;
            }
            return false;
        }
        self.expire(at);
        let operator = explicit || origin == Origin::Seed;
        if !operator && !self.make_room(address, &source, origin == Origin::Own) {
            return false;
        }
        if self.entries.len() >= MAX_BOOK {
            // Replace instead of refusing. An operator's endpoint or seed
            // result displaces any learned entry; a learned address displaces
            // only an unverified one, failed entries first, otherwise in
            // salted order.
            let victim = self
                .entries
                .values()
                .filter(|e| !operator_input(e) && !e.busy && (operator || e.last_success == 0))
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
                advanced: 0,
                ahead: false,
            },
        );
        true
    }
    pub fn add_seed(&mut self, address: SocketAddr, seed: &str, at: u64) -> bool {
        // Seeds are operator input, but DNS responses still cannot nominate LAN endpoints.
        let origin = if seed.parse::<SocketAddr>().is_ok() {
            Origin::Explicit
        } else {
            Origin::Seed
        };
        self.insert(
            address,
            format!(
                "{SEED_SOURCE}{}",
                &hex::encode(crate::crypto::sha256d(seed.as_bytes()))[..16]
            ),
            origin,
            at,
        )
    }
    pub fn learn(&mut self, source: SocketAddr, addresses: &[SocketAddr], at: u64) {
        for address in addresses.iter().take(MAX_ADDRESSES) {
            self.insert(*address, group(source), Origin::Gossip, at);
        }
    }
    pub fn advertisement(&mut self, source: SocketAddr, address: SocketAddr, at: u64) {
        // An inbound node can nominate only its observed source IP, never a victim IP.
        if normalized(source).ip() == normalized(address).ip() {
            self.insert(address, group(source), Origin::Own, at);
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
        self.expire(at);
        let healthy_groups = self
            .entries
            .values()
            .filter(|e| {
                e.last_success > 0 && e.failures < 3 && at.saturating_sub(e.last_success) < 3600
            })
            .map(|e| group(e.address))
            .collect::<BTreeSet<_>>();
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
            .map(|e| (e.last_attempt, self.rank(e.address), e.address))
            .collect::<Vec<_>>();
        candidates.sort();
        let candidates: Vec<SocketAddr> = candidates.into_iter().map(|(_, _, a)| a).collect();
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
        // The two outbound slots have roles, so neither a flood of unknown
        // addresses nor many verified ones that answer slowly can keep
        // productive and operator-chosen peers waiting their turn in a full
        // rotation. An anchor takes the synchronizing slot.
        while selected.len() < maximum.min(2) {
            let exploring = self.exploring.is_none();
            let Some(address) = self.pick(
                at,
                exploring,
                &candidates,
                &groups,
                &healthy_groups,
                unknown_busy,
            ) else {
                break;
            };
            groups.insert(group(address));
            let entry = self.entries.get_mut(&address).unwrap();
            entry.busy = true;
            entry.last_attempt = at;
            if entry.last_success == 0 {
                unknown_busy += 1;
            }
            if exploring {
                self.exploring = Some(address);
            }
            selected.push(address);
        }
        selected
    }
    /// Operator-chosen entries: configured peers and seed results.
    fn chosen(entry: &Entry) -> bool {
        operator_input(entry) || entry.configured
    }
    /// Operator-chosen entries, and peers that advanced this node within
    /// `PRODUCTIVE_WINDOW` and have not failed or stalled since.
    fn preferred(entry: &Entry, at: u64) -> bool {
        Self::chosen(entry)
            || (entry.advanced > 0 && at.saturating_sub(entry.advanced) < PRODUCTIVE_WINDOW)
    }
    /// A ready entry, of `candidates` least recently tried first, for a free
    /// outbound slot in a network group no busy entry uses.
    ///
    /// The synchronizing slot takes, in order: a peer whose last session
    /// advanced this node, which may hold more; a preferred peer not tried
    /// for `PREFERRED_INTERVAL`, operator-chosen ones first; the verified
    /// peer tried least recently; an unknown probe. The exploring slot takes
    /// a peer that advanced this node, then an unknown probe, then verified
    /// and last preferred peers.
    ///
    /// While a recent healthy peer exists, at most one unknown entry is
    /// probed at a time and, except at most once per
    /// `HEALTHY_GROUP_PROBE_INTERVAL`, none in a group such a peer is in.
    /// Unverified configured peers and seeds are preferred peers instead.
    fn pick(
        &mut self,
        at: u64,
        exploring: bool,
        candidates: &[SocketAddr],
        groups: &BTreeSet<String>,
        healthy: &BTreeSet<String>,
        unknown_busy: usize,
    ) -> Option<SocketAddr> {
        let protect_healthy = !healthy.is_empty();
        let ready: Vec<&Entry> = candidates
            .iter()
            .filter_map(|address| self.entries.get(address))
            .filter(|e| {
                !e.busy && (self.options.allow_private || !groups.contains(&group(e.address)))
            })
            .collect();
        let find =
            |wanted: &dyn Fn(&Entry) -> bool| ready.iter().find(|e| wanted(e)).map(|e| e.address);
        let ahead = || find(&|e| e.ahead);
        let due = |preferred: fn(&Entry, u64) -> bool| {
            find(&|e| preferred(e, at) && at >= e.last_attempt.saturating_add(PREFERRED_INTERVAL))
        };
        // Peers that relayed a block first can earn preference, so they never
        // delay the operator's own choices.
        let due = || due(|e, _| Self::chosen(e)).or_else(|| due(Self::preferred));
        let verified = || find(&|e| e.last_success > 0);
        let preferred = || find(&|e| Self::preferred(e, at));
        let probe = || {
            if protect_healthy && unknown_busy >= 1 {
                return None;
            }
            find(&|e| {
                e.last_success == 0 && !(protect_healthy && healthy.contains(&group(e.address)))
            })
        };
        let background = || {
            let allowed = protect_healthy
                && unknown_busy == 0
                && at
                    >= self
                        .healthy_probe
                        .saturating_add(HEALTHY_GROUP_PROBE_INTERVAL);
            if allowed {
                find(&|e| e.last_success == 0)
            } else {
                None
            }
        };
        if exploring {
            if let Some(address) = ahead().or_else(probe) {
                return Some(address);
            }
            if let Some(address) = background() {
                self.healthy_probe = at;
                return Some(address);
            }
            verified().or_else(preferred)
        } else {
            ahead().or_else(due).or_else(verified).or_else(probe)
        }
    }
    pub fn finished(&mut self, address: SocketAddr, contact: Contact, at: u64, jitter: u64) {
        if self.exploring == Some(address) {
            self.exploring = None;
        }
        let Some(entry) = self.entries.get_mut(&address) else {
            return;
        };
        entry.busy = false;
        entry.ahead = contact == Contact::Advanced;
        if contact.success() {
            entry.last_success = at;
            entry.failures = 0;
        } else {
            entry.failures = entry.failures.saturating_add(1).min(16);
            // A peer that advanced this node keeps its preference only while
            // its sessions keep completing promptly.
            entry.advanced = 0;
        }
        entry.next_attempt = if entry.ahead {
            at
        } else {
            at + retry_seconds(entry.failures, jitter, entry.explicit)
        };
        // A learned address that never answered is dropped after a few
        // consecutive failures instead of cycling until it expires.
        let unanswered = !operator_input(entry)
            && entry.last_success == 0
            && entry.failures >= MAX_UNVERIFIED_FAILURES;
        if contact == Contact::Advanced {
            entry.advanced = at;
            // This outbound peer becomes the newest anchor, replacing an
            // older one in its group: only a peer that advanced this node,
            // not one that merely answered.
            self.anchors
                .retain(|a| *a != address && group(*a) != group(address));
            self.anchors.insert(0, address);
            self.anchors.truncate(MAX_ANCHORS);
        }
        self.verified_this_run |= contact.success();
        if unanswered {
            self.entries.remove(&address);
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
        book.finished(good, Contact::Current, 100, 0);
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
        book.finished(good, Contact::Current, 110, 0);
        assert_eq!(book.next(120, 1), vec![good]);
        book.finished(good, Contact::Current, 120, 0);
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
        book.finished(address, Contact::Failed, 100, 0);
        let next = book.entries[&address].next_attempt;
        assert!(next > 100);
        assert_eq!(book.entries[&address].failures, 1);
        book.finished(address, Contact::Failed, next, 0);
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
        book.finished(addr, Contact::Current, 101, 0);
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
        original.finished(peer, Contact::Current, 1_000, 0);
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
        early.finished(learned, Contact::Current, 101, 0);
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
        original.finished(peer, Contact::Current, 100, 0);
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
        fast.finished(learned, Contact::Current, ahead, 0);
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
            reopened.finished(failing, Contact::Failed, 200 + u64::from(attempt), 0);
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
        b.finished(configured, Contact::Current, 100, 0);
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
        saved.finished(learned, Contact::Current, 100, 0);
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
        // Synchronizing with three of them last advanced this node. Anchors
        // keep distinct groups, so the newest replaces its group's older
        // one. A peer that merely answered, as all twenty did, is no anchor.
        let (first, second) = (peers[17], peers[18]);
        b.finished(peers[0], Contact::Current, 250, 0);
        for (anchor, at) in [(sibling, 150), (first, 200), (second, 200)] {
            b.entries.get_mut(&anchor).unwrap().last_attempt = at;
            b.finished(anchor, Contact::Advanced, at, 0);
        }
        b.finished(peers[1], Contact::Current, 250, 0);
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
        reopened.finished(first, Contact::Current, 300, 0);
        reopened.finished(second, Contact::Current, 300, 0);
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
    /// Run the scheduler second by second from `start` for `seconds` with two
    /// outbound slots, each session with `address` taking and ending as
    /// `session(address)` says. Returns how often each address was tried.
    fn simulate(
        book: &mut AddressBook,
        start: u64,
        seconds: u64,
        session: impl Fn(SocketAddr) -> (u64, Contact),
    ) -> BTreeMap<SocketAddr, usize> {
        let mut busy: Vec<(u64, SocketAddr, Contact)> = Vec::new();
        let mut tried = BTreeMap::new();
        for at in start..start + seconds {
            busy.retain(|&(end, address, contact)| {
                if end > at {
                    return true;
                }
                book.finished(address, contact, at, 0);
                false
            });
            for address in book.next(at, 2 - busy.len()) {
                let (took, contact) = session(address);
                *tried.entry(address).or_default() += 1;
                busy.push((at + took, address, contact));
            }
        }
        tried
    }
    fn verified(book: &mut AddressBook, peers: &[SocketAddr], last_attempt: u64) {
        for (n, address) in peers.iter().enumerate() {
            let source = SocketAddr::from(([20, n as u8, 1, 1], 9));
            book.learn(source, &[*address], 100);
            let entry = book.entries.get_mut(address).unwrap();
            (entry.last_success, entry.last_attempt) = (100, last_attempt);
        }
    }
    #[test]
    fn slow_empty_sessions_lose_their_turn_while_operator_peers_keep_theirs() {
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
        // Forty verified addresses in distinct groups, all due before the
        // configured peer, answer each session just before it is cut off
        // and deliver nothing.
        let slow: Vec<SocketAddr> = (1..=40u8)
            .map(|n| SocketAddr::from(([30, n, 1, 1], 9)))
            .collect();
        verified(&mut b, &slow, 50);
        b.entries.get_mut(&configured).unwrap().last_attempt = 100;
        let tried = simulate(&mut b, 1000, 600, |address| {
            if address == configured {
                (2, Contact::Current)
            } else {
                (30, Contact::Stalled)
            }
        });
        // The configured peer is synchronized about every PREFERRED_INTERVAL
        // plus one stalled session, not once per pass through all of them.
        assert!(tried[&configured] >= 10, "{tried:?}");
        // A stalled session is no success: it neither refreshes the entry's
        // verification nor makes it an anchor, and it backs off.
        for address in &slow {
            let entry = &b.entries[address];
            assert_eq!(entry.last_success, 100);
            assert_eq!(
                entry.failures as usize + usize::from(entry.busy),
                tried.get(address).copied().unwrap_or(0)
            );
        }
        assert!(b.anchors.is_empty());
    }
    #[test]
    fn a_peer_that_advanced_this_node_is_synchronized_again_at_once_and_stays_preferred() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let peers: Vec<SocketAddr> = (1..=10u8)
            .map(|n| SocketAddr::from(([30, n, 1, 1], 9)))
            .collect();
        verified(&mut b, &peers, 100);
        for (n, address) in peers.iter().enumerate() {
            b.entries.get_mut(address).unwrap().last_attempt = 100 + n as u64;
        }
        // The peer tried most recently delivered a block that became the tip.
        // It may hold more, so it is tried again at once, ahead of peers
        // tried earlier, for as long as it keeps advancing this node.
        let productive = peers[9];
        b.finished(productive, Contact::Advanced, 200, 0);
        assert_eq!(b.next(200, 1), [productive]);
        b.finished(productive, Contact::Advanced, 201, 0);
        assert_eq!(b.next(201, 1), [productive]);
        assert_eq!(b.anchors, [productive]);
        // Once it has nothing more, it returns to the rotation.
        b.finished(productive, Contact::Current, 202, 0);
        let both = b.next(210, 2);
        assert!(!both.contains(&productive), "{both:?}");
        let synchronizing = both
            .into_iter()
            .find(|address| Some(*address) != b.exploring)
            .unwrap();
        b.finished(synchronizing, Contact::Current, 216, 0);
        // It stays preferred: PREFERRED_INTERVAL after its last attempt the
        // synchronizing slot takes it before peers tried long before.
        assert_eq!(b.next(201 + PREFERRED_INTERVAL, 1), [productive]);
        b.finished(productive, Contact::Current, 217, 0);
        // Only for a while after it last advanced this node.
        let later = 201 + PRODUCTIVE_WINDOW;
        assert!(AddressBook::preferred(&b.entries[&productive], later - 1));
        assert!(!AddressBook::preferred(&b.entries[&productive], later));
        // Peers that merely answered are no anchors.
        assert_eq!(b.anchors, [productive]);
    }
    #[test]
    fn operator_chosen_peers_are_due_before_peers_that_relayed_a_block() {
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
        let relays: Vec<SocketAddr> = (1..=3u8)
            .map(|n| SocketAddr::from(([30, n, 1, 1], 9)))
            .collect();
        verified(&mut b, &relays, 100);
        // Each relay delivered a block that became the tip, then had nothing
        // more. Any well connected source can earn that.
        for (n, relay) in relays.iter().enumerate() {
            b.finished(*relay, Contact::Advanced, 200, 0);
            b.finished(*relay, Contact::Current, 201, 0);
            b.entries.get_mut(relay).unwrap().last_attempt = 100 + n as u64;
            assert!(AddressBook::preferred(&b.entries[relay], 201));
        }
        // The configured peer was synchronized after all of them.
        let entry = b.entries.get_mut(&configured).unwrap();
        (entry.last_success, entry.last_attempt) = (250, 250);
        // Once every one is due, the exploring slot takes the peer tried
        // least recently, but the synchronizing slot the configured peer.
        assert_eq!(b.next(300, 2), [relays[0], configured]);
        // A relay whose session stalls loses its preference at once; one
        // that keeps answering promptly keeps it.
        b.finished(relays[0], Contact::Stalled, 330, 0);
        assert!(!AddressBook::preferred(&b.entries[&relays[0]], 330));
        assert!(AddressBook::preferred(&b.entries[&relays[1]], 330));
        b.finished(configured, Contact::Stalled, 330, 0);
        assert!(AddressBook::preferred(&b.entries[&configured], 330));
    }
    #[test]
    fn verified_entries_that_keep_failing_are_retried_at_most_hourly() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let peer: SocketAddr = "30.1.1.1:9".parse().unwrap();
        b.learn("20.1.1.1:9".parse().unwrap(), &[peer], 100);
        b.finished(peer, Contact::Current, 100, 0);
        // A session that completed slowly with nothing new is a failure.
        b.finished(peer, Contact::Stalled, 200, 0);
        let entry = &b.entries[&peer];
        assert_eq!((entry.last_success, entry.failures), (100, 1));
        let mut at = 200;
        let mut delays = Vec::new();
        for _ in 0..15 {
            b.finished(peer, Contact::Failed, at, 0);
            let next = b.entries[&peer].next_attempt;
            delays.push(next - at);
            at = next;
        }
        // Up to a minute as before, then doubling to an hour. A verified
        // entry is kept until it expires.
        assert_eq!(
            delays,
            [
                4, 8, 16, 32, 60, 120, 240, 480, 960, 1920, 3600, 3600, 3600, 3600, 3600
            ]
        );
        assert!(retry_seconds(16, u64::MAX, false) < MAX_RETRY_SECONDS * 5 / 4);
        // Endpoints the operator named are retried at least once a minute, as
        // configured peers are in closed mode.
        let configured: SocketAddr = "8.8.8.8:9".parse().unwrap();
        let mut b = AddressBook::open(
            dir.path().join("configured"),
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
        for at in 100..116 {
            b.finished(configured, Contact::Failed, at, 0);
        }
        assert_eq!(b.entries[&configured].next_attempt, 115 + 60);
        assert!(b.entries.contains_key(&configured));
    }
    #[test]
    fn gossip_cannot_squat_an_honest_address_or_network_group() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let gossip = |n: u8| SocketAddr::from(([20, n, 1, 1], 9));
        let honest = |port: u16| SocketAddr::from(([9, 9, 9, 9], port));
        // One peer gossips two bogus ports for an honest node's address.
        b.learn(gossip(1), &[honest(1), honest(2)], 100);
        assert_eq!(b.entries().count(), MAX_PER_IP);
        // The real endpoint, gossiped by another peer, still gets in: one of
        // the bogus entries makes room.
        b.learn(gossip(2), &[honest(18481)], 100);
        assert!(b.entries.contains_key(&honest(18481)));
        let squatted = |b: &AddressBook| {
            b.entries()
                .filter(|e| e.address.ip() == honest(1).ip())
                .count()
        };
        assert_eq!(squatted(&b), MAX_PER_IP);
        // Gossiping the displaced port again cannot push it out in turn.
        let displaced = [honest(1), honest(2)]
            .into_iter()
            .find(|address| !b.entries.contains_key(address))
            .unwrap();
        b.learn(gossip(1), &[displaced], 100);
        assert!(!b.entries.contains_key(&displaced));
        assert!(b.entries.contains_key(&honest(18481)));
        // The node announcing its own address makes room for it.
        b.advertisement(honest(5000), honest(18482), 100);
        assert!(b.entries.contains_key(&honest(18482)));
        assert_eq!(squatted(&b), MAX_PER_IP);
        // A network group one source gossiped full leaves room for another
        // source's entry, but not the other way round.
        for host in 1..=20 {
            b.learn(gossip(1), &[SocketAddr::from(([7, 7, host, 1], 9))], 100);
        }
        let grouped =
            |b: &AddressBook| b.entries().filter(|e| group(e.address) == "v4:7:7").count();
        assert_eq!(grouped(&b), MAX_PER_GROUP);
        let other = SocketAddr::from(([7, 7, 200, 1], 9));
        b.learn(gossip(2), &[other], 100);
        assert!(b.entries.contains_key(&other));
        let again = SocketAddr::from(([7, 7, 201, 1], 9));
        b.learn(gossip(1), &[again], 100);
        assert!(!b.entries.contains_key(&again));
        assert_eq!(grouped(&b), MAX_PER_GROUP);
    }
    #[test]
    fn a_learned_address_that_still_would_not_fit_displaces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let gossip = |n: u8| SocketAddr::from(([20, n, 1, 1], 9));
        let member = |host: u8, port: u16| SocketAddr::from(([7, 7, host, 1], port));
        // Two verified endpoints share one address, in a network group that
        // one source otherwise gossiped full.
        for port in [1, 2] {
            b.learn(gossip(3), &[member(1, port)], 100);
            b.finished(member(1, port), Contact::Current, 100, 0);
        }
        for host in 2..=20 {
            b.learn(gossip(1), &[member(host, 9)], 100);
        }
        let before: Vec<SocketAddr> = b.entries().map(|e| e.address).collect();
        assert_eq!(before.len(), MAX_PER_GROUP);
        // Another source's endpoint at that address would find room in the
        // group but none at its address, so nothing is displaced for it.
        b.learn(gossip(2), &[member(1, 3)], 100);
        assert_eq!(b.entries().map(|e| e.address).collect::<Vec<_>>(), before);
    }
    #[test]
    fn seed_results_bypass_learned_quotas_and_are_never_dropped_for_failures() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let gossip = |n: u8| SocketAddr::from(([20, n, 1, 1], 9));
        let honest = |port: u16| SocketAddr::from(([9, 9, 9, 9], port));
        // Two peers each gossip a bogus port for the seed's address, so
        // gossip of the real endpoint finds no room.
        b.learn(gossip(1), &[honest(1)], 100);
        b.learn(gossip(2), &[honest(2)], 100);
        b.learn(gossip(3), &[honest(18481)], 100);
        assert!(!b.entries.contains_key(&honest(18481)));
        // The seed's own DNS result is operator input and still gets in, but
        // never a private address.
        assert!(b.add_seed(honest(18481), "seed.example:18481", 100));
        assert!(!b.add_seed("10.1.1.1:18481".parse().unwrap(), "seed.example:18481", 100));
        // It is kept however often it fails; a learned entry that never
        // answered is dropped.
        for n in 0..2 * MAX_UNVERIFIED_FAILURES {
            b.finished(honest(18481), Contact::Failed, 200 + u64::from(n), 0);
            b.finished(honest(1), Contact::Failed, 200 + u64::from(n), 0);
        }
        assert!(b.entries.contains_key(&honest(18481)));
        assert!(!b.entries.contains_key(&honest(1)));
        // A learned entry that never answered expires a day after it was
        // added rather than a week.
        b.next(100 + UNVERIFIED_AGE, 0);
        assert!(b.entries.contains_key(&honest(2)));
        b.next(101 + UNVERIFIED_AGE, 0);
        assert!(!b.entries.contains_key(&honest(2)));
        assert!(b.entries.contains_key(&honest(18481)));
        // A learned entry a seed also returns becomes operator input.
        b.learn(gossip(4), &[honest(3)], 200);
        b.add_seed(honest(3), "seed.example:18481", 200);
        assert!(operator_input(&b.entries[&honest(3)]));
    }
    #[test]
    fn unknown_entries_in_a_healthy_group_are_still_probed_at_a_low_rate() {
        let dir = tempfile::tempdir().unwrap();
        let mut b = book(dir.path().join("book"));
        let healthy: SocketAddr = "30.1.1.1:9".parse().unwrap();
        let unknown: SocketAddr = "30.1.2.1:9".parse().unwrap();
        b.learn("20.1.1.1:9".parse().unwrap(), &[healthy], 1000);
        b.learn("20.2.1.1:9".parse().unwrap(), &[unknown], 1000);
        b.finished(healthy, Contact::Current, 1000, 0);
        // Ordinary probes skip a group that holds a healthy peer, but one is
        // probed there now and then.
        assert_eq!(b.next(1001, 1), [unknown]);
        b.finished(unknown, Contact::Failed, 1001, 0);
        assert_eq!(b.next(1010, 1), [healthy]);
        b.finished(healthy, Contact::Current, 1010, 0);
        let early = 1000 + HEALTHY_GROUP_PROBE_INTERVAL;
        assert_eq!(b.next(early, 1), [healthy]);
        b.finished(healthy, Contact::Current, early, 0);
        assert_eq!(b.next(early + 1, 1), [unknown]);
    }
}
