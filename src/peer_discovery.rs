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
const MAX_AGE: u64 = 7 * 24 * 3600;

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
}

pub struct AddressBook {
    path: PathBuf,
    chain: Hash,
    pub options: Options,
    local: SocketAddr,
    entries: BTreeMap<SocketAddr, Entry>,
    pub last_error: Option<String>,
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
        let mut book = Self {
            path,
            chain,
            options,
            local: normalized(local),
            entries: BTreeMap::new(),
            last_error: None,
        };
        if let Ok(metadata) = fs::symlink_metadata(&book.path) {
            ensure!(
                metadata.is_file(),
                "peer address book must be a regular file, not a symbolic link"
            );
            let file = fs::File::open(&book.path)?;
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
            let saved: Saved =
                serde_json::from_slice(&bytes).context("invalid peer address book")?;
            ensure!(
                saved.version == 1 && saved.chain == chain,
                "peer address book belongs to another chain or version"
            );
            ensure!(
                saved.entries.len() <= MAX_BOOK,
                "peer address book entry limit"
            );
            for entry in saved.entries {
                // Persistence never bypasses filtering, source quotas or future-time checks.
                if entry.last_success == 0
                    || entry.last_success > at
                    || at.saturating_sub(entry.last_success) > MAX_AGE
                    || entry.source.len() > 64
                {
                    continue;
                }
                if book.insert(entry.address, entry.source.clone(), false, at) {
                    let current = book.entries.get_mut(&normalized(entry.address)).unwrap();
                    current.last_success = entry.last_success;
                    current.added = entry.added.min(at);
                    current.failures = entry.failures.min(16);
                    current.next_attempt = entry.next_attempt.min(at + 60);
                }
            }
        }
        for address in configured {
            book.insert(*address, "configured".into(), true, at);
        }
        Ok(book)
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
                    >= MAX_PER_GROUP)
        {
            return false;
        }
        if self.entries.len() >= MAX_BOOK {
            return false;
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
    pub fn advertised(&self, at: u64, random: u64) -> Vec<SocketAddr> {
        let mut result = self
            .entries
            .values()
            .filter(|e| {
                e.last_success > 0
                    && at.saturating_sub(e.last_success) < 3600
                    && allowed(e.address, self.options.allow_private)
            })
            .map(|e| e.address)
            .collect::<Vec<_>>();
        if let Some(address) = self.options.advertise {
            result.push(address);
        }
        result.sort();
        result.dedup();
        if !result.is_empty() {
            let offset = (random % result.len() as u64) as usize;
            result.rotate_left(offset);
        }
        result.truncate(MAX_ADDRESSES);
        result
    }
    pub fn next(&mut self, at: u64, maximum: usize) -> Vec<SocketAddr> {
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
        let mut candidates = self
            .entries
            .values()
            .filter(|e| !e.busy && e.next_attempt <= at)
            .map(|e| (e.last_attempt, e.address, e.last_success > 0))
            .collect::<Vec<_>>();
        candidates.sort();
        let mut selected = Vec::new();
        let mut groups = self
            .entries
            .values()
            .filter(|e| e.busy)
            .map(|e| group(e.address))
            .collect::<BTreeSet<_>>();
        // Reserve one slot for established paths. An untrusted book flood must
        // never queue both slots for minutes ahead of an already healthy peer.
        // Within each class oldest-attempt rotation preserves fairness.
        for phase in 0..3 {
            for &(_, address, verified) in &candidates {
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
            } else {
                entry.failures = entry.failures.saturating_add(1).min(16);
            }
            entry.next_attempt = at
                + crate::network_guard::retry_delay(entry.failures, jitter)
                    .as_secs()
                    .max(1);
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
    pub fn save(&mut self) -> Result<()> {
        let saved = Saved {
            version: 1,
            chain: self.chain,
            entries: self
                .entries
                .values()
                .filter(|e| e.last_success > 0)
                .cloned()
                .collect(),
        };
        let bytes = serde_json::to_vec(&saved)?;
        ensure!(
            bytes.len() <= MAX_PERSISTED_BYTES,
            "peer address book persistence limit"
        );
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            ensure!(
                metadata.is_file(),
                "peer address book must be a regular file, not a symbolic link"
            );
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| anyhow::anyhow!("peer persistence randomness unavailable: {e}"))?;
        let temporary = self
            .path
            .with_extension(format!("{}.tmp", hex::encode(random)));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let written = file.write_all(&bytes).and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        // Unix replacement is atomic. Windows replacement can lose only the
        // discovery-hint sidecar if interrupted; it never touches chain state.
        #[cfg(windows)]
        if self.path.exists() {
            fs::remove_file(&self.path)?;
        }
        if let Err(error) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        Ok(())
    }
}

pub fn path_for(database: &Path, chain: Hash) -> PathBuf {
    database.with_extension(format!("peers-{}.json", hex::encode(chain)))
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
    #[test]
    fn oversized_sidecars_are_rejected_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("book");
        fs::write(&path, vec![b' '; MAX_PERSISTED_BYTES + 1]).unwrap();
        assert!(
            AddressBook::open(
                path,
                [1; 32],
                Options {
                    enabled: true,
                    ..Default::default()
                },
                "0.0.0.0:9".parse().unwrap(),
                &[],
                100
            )
            .is_err()
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
        assert!(
            AddressBook::open(
                path,
                [1; 32],
                Options {
                    enabled: true,
                    ..Default::default()
                },
                "0.0.0.0:9".parse().unwrap(),
                &[],
                100
            )
            .is_err()
        );
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
        assert!(
            AddressBook::open(path, [2; 32], opts, "0.0.0.0:9".parse().unwrap(), &[], 102).is_err()
        );
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
