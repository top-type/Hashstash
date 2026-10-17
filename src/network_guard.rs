//! Local admission policy. These limits never change block or transaction validity.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// Accounting holds only token buckets and counters. A panic while it was
/// held leaves at most one stale count, so admission keeps using it rather
/// than refusing every later connection for the life of the process.
fn accounting<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

pub const MAX_TRACKED_IPS: usize = 1024;
pub const MAX_JSON_DEPTH: usize = 64;
pub const MAX_JSON_VALUES: usize = 2_000_000;
/// Sustained peer work refill. Outgoing batches are sized so one reply,
/// including the recipient's loose-transaction and mempool terms, fits it.
pub const PEER_WORK_PER_SECOND: u64 = 16_384;
/// Buffered incoming peer frame bytes across all inbound sessions. The budget
/// grows to at least two of the largest validated frames.
pub const PEER_FRAME_MEMORY: u64 = 64 * 1024 * 1024;
/// Inbound peer sessions open to any source, plus slots that only configured,
/// pinned or recently verified peers may use when the general slots are full.
pub const INBOUND_PEER_SLOTS: usize = 16;
pub const RESERVED_PEER_SLOTS: usize = 4;
/// Concurrent inbound sessions from one public network group (IPv4 /16, IPv6 /32).
pub const PEER_SLOTS_PER_GROUP: usize = 2;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum Surface {
    Rpc,
    Peer,
    Stratum,
}
/// Connections this node opened are accounted separately from traffic that
/// arrives from the same address, so inbound abuse cannot block them.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
enum Direction {
    Inbound,
    Outbound,
}
type Key = (IpAddr, Surface, Direction);

/// Local capacity was unavailable. This is never evidence of peer misbehavior.
#[derive(Debug)]
pub struct Busy(&'static str);
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Busy {}

fn public(ip: IpAddr) -> bool {
    crate::peer_discovery::public_address(SocketAddr::new(ip, 1))
}
/// Admission identity. IPv4-mapped addresses share the IPv4 record, and a
/// global IPv6 host is accounted by its /64 because it normally controls one.
pub fn admission_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None if (v.segments()[0] & 0xe000) == 0x2000 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(v) & !u128::from(u64::MAX)))
            }
            None => ip,
        },
        _ => ip,
    }
}
/// Inbound slot diversity group: IPv4 /16 or IPv6 /32 for public addresses.
/// Loopback and private addresses are operator-controlled and keep per-address
/// accounting only.
pub fn network_group(ip: IpAddr) -> Option<IpAddr> {
    let ip = admission_address(ip);
    if !public(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, 0, 0))
        }
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(u128::from(v) & !(u128::MAX >> 32))),
    })
}

#[derive(Clone, Copy)]
struct Policy {
    connections: usize,
    requests: u64,
    request_burst: u64,
    bytes: u64,
    byte_burst: u64,
    work: u64,
    work_burst: u64,
}
impl Surface {
    fn policy(self) -> Policy {
        const MIB: u64 = 1024 * 1024;
        match self {
            Self::Rpc => Policy {
                connections: 8,
                requests: 512,
                request_burst: 1024,
                bytes: 32 * MIB,
                byte_burst: 66 * MIB,
                work: 131_072,
                work_burst: 1_048_576,
            },
            Self::Peer => Policy {
                connections: 4,
                requests: 32,
                request_burst: 64,
                bytes: 8 * MIB,
                byte_burst: 66 * MIB,
                work: PEER_WORK_PER_SECOND,
                work_burst: 65_536,
            },
            Self::Stratum => Policy {
                connections: 16,
                requests: 32,
                request_burst: 64,
                bytes: MIB,
                byte_burst: 2 * MIB,
                work: 1024,
                // A valid block can contain the full 4096-signature preset,
                // in addition to its share/header check.
                work_burst: 8192,
            },
        }
    }
}

struct Bucket {
    tokens: u64,
    last: Instant,
    remainder: u128,
}
impl Bucket {
    fn new(capacity: u64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last: now,
            remainder: 0,
        }
    }
    fn take(&mut self, amount: u64, rate: u64, capacity: u64, now: Instant) -> bool {
        let units = now
            .duration_since(self.last)
            .as_nanos()
            .saturating_mul(rate as u128)
            .saturating_add(self.remainder);
        self.last = now;
        self.tokens = self
            .tokens
            .saturating_add((units / 1_000_000_000).min(u64::MAX as u128) as u64)
            .min(capacity);
        self.remainder = if self.tokens == capacity {
            0
        } else {
            units % 1_000_000_000
        };
        if amount > self.tokens {
            false
        } else {
            self.tokens -= amount;
            true
        }
    }
}
struct Record {
    active: usize,
    last: Instant,
    cooldown: Instant,
    strikes: u32,
    requests: Bucket,
    bytes: Bucket,
    work: Bucket,
}
impl Record {
    fn new(p: Policy, now: Instant) -> Self {
        Self {
            active: 0,
            last: now,
            cooldown: now,
            strikes: 0,
            requests: Bucket::new(p.request_burst, now),
            bytes: Bucket::new(p.byte_burst, now),
            work: Bucket::new(p.work_burst, now),
        }
    }
    fn penalize(&mut self, now: Instant) {
        if now.duration_since(self.last) > Duration::from_secs(60) {
            self.strikes = 0;
        }
        self.strikes = self.strikes.saturating_add(1).min(7);
        self.last = now;
        self.cooldown = now + Duration::from_millis((250u64 << (self.strikes - 1)).min(16_000));
    }
}
#[derive(Default)]
pub struct NetworkGuard {
    max_frame_bytes: AtomicU64,
    max_peer_work: AtomicU64,
    loopback_rpc_is_proxy: bool,
    records: Mutex<HashMap<Key, Record>>,
    frame_memory: Mutex<u64>,
}
pub struct Session {
    guard: Arc<NetworkGuard>,
    key: Key,
    request_bucket: Mutex<Bucket>,
    reserved_frame: Mutex<u64>,
}
impl NetworkGuard {
    /// A loopback reverse proxy represents many public visitors. Keep its
    /// aggregate quotas, but never turn one malformed visitor into an IP ban
    /// of the whole website. Direct remote clients retain normal cooldowns.
    /// Only the separate, restricted public-web listener uses this guard.
    pub fn for_public_web() -> Self {
        Self {
            loopback_rpc_is_proxy: true,
            ..Default::default()
        }
    }
    pub fn with_frame_limit(maximum: usize) -> Self {
        Self {
            max_frame_bytes: AtomicU64::new(maximum as u64),
            ..Default::default()
        }
    }
    fn policy(&self, surface: Surface) -> Policy {
        let mut policy = surface.policy();
        if surface != Surface::Stratum {
            policy.byte_burst = policy
                .byte_burst
                .max(self.max_frame_bytes.load(Ordering::Relaxed));
        }
        if surface == Surface::Peer {
            policy.work_burst = policy
                .work_burst
                .max(self.max_peer_work.load(Ordering::Relaxed));
        }
        policy
    }
    /// The largest single valid peer message must remain admissible, even on a
    /// genesis whose signature limit exceeds the baseline work burst. Refill
    /// rates and other quotas do not change.
    pub fn allow_work(&self, maximum: usize) -> Result<()> {
        let maximum = u64::try_from(maximum)?;
        let previous = self.max_peer_work.fetch_max(maximum, Ordering::Relaxed);
        if maximum <= previous {
            return Ok(());
        }
        let mut records = accounting(&self.records);
        let base = Surface::Peer.policy().work_burst;
        for ((_, surface, _), record) in records.iter_mut() {
            if *surface == Surface::Peer {
                let (old, new) = (base.max(previous), base.max(maximum));
                record.work.tokens = record.work.tokens.saturating_add(new - old).min(new);
            }
        }
        Ok(())
    }
    fn frame_memory_limit(&self) -> u64 {
        PEER_FRAME_MEMORY.max(
            self.max_frame_bytes
                .load(Ordering::Relaxed)
                .saturating_mul(2),
        )
    }
    /// A validated historical capacity increase extends the one-frame burst.
    /// Throughput, connection, request and work quotas remain local policy.
    pub fn allow_frame(&self, maximum: usize) -> Result<()> {
        let maximum = u64::try_from(maximum)?;
        let previous = self.max_frame_bytes.fetch_max(maximum, Ordering::Relaxed);
        if maximum <= previous {
            return Ok(());
        }
        let mut records = accounting(&self.records);
        for ((_, surface, _), record) in records.iter_mut() {
            if *surface != Surface::Stratum {
                let old = surface.policy().byte_burst.max(previous);
                let new = surface.policy().byte_burst.max(maximum);
                record.bytes.tokens = record.bytes.tokens.saturating_add(new - old).min(new);
            }
        }
        Ok(())
    }
    fn penalize(&self, ip: IpAddr, surface: Surface, record: &mut Record, now: Instant) {
        if !(self.loopback_rpc_is_proxy && surface == Surface::Rpc && ip.is_loopback()) {
            record.penalize(now);
        }
    }
    pub fn admit(self: &Arc<Self>, ip: IpAddr, surface: Surface) -> Result<Session> {
        self.admit_at(ip, surface, Direction::Inbound, Instant::now())
    }
    /// Account a connection this node opens. Its record, cooldown and
    /// connection count are separate from inbound traffic from that address.
    pub fn admit_outbound(self: &Arc<Self>, ip: IpAddr, surface: Surface) -> Result<Session> {
        self.admit_at(ip, surface, Direction::Outbound, Instant::now())
    }
    fn admit_at(
        self: &Arc<Self>,
        ip: IpAddr,
        surface: Surface,
        direction: Direction,
        now: Instant,
    ) -> Result<Session> {
        let ip = admission_address(ip);
        let key = (ip, surface, direction);
        let mut records = accounting(&self.records);
        if !records.contains_key(&key) {
            if records.len() >= MAX_TRACKED_IPS {
                // Prefer records whose cooldown has ended, so creating new
                // records does not cheaply erase an active penalty.
                let oldest = records
                    .iter()
                    .filter(|(_, r)| r.active == 0)
                    .min_by_key(|(_, r)| (r.cooldown > now, r.last))
                    .map(|(k, _)| *k);
                let Some(oldest) = oldest else {
                    return Err(anyhow!("network accounting capacity reached"));
                };
                records.remove(&oldest);
            }
            records.insert(key, Record::new(self.policy(surface), now));
        }
        let record = records.get_mut(&key).unwrap();
        ensure!(now >= record.cooldown, "temporary network cooldown");
        ensure!(
            record.active < self.policy(surface).connections,
            "per-address connection limit"
        );
        let p = self.policy(surface);
        if !record.requests.take(1, p.requests, p.request_burst, now) {
            self.penalize(ip, surface, record, now);
            return Err(anyhow!("connection rate limit"));
        }
        record.active += 1;
        record.last = now;
        Ok(Session {
            guard: self.clone(),
            key,
            request_bucket: Mutex::new(Bucket::new(16, now)),
            reserved_frame: Mutex::new(0),
        })
    }
    pub fn tracked_addresses(&self) -> usize {
        accounting(&self.records).len()
    }
}
impl Session {
    pub fn request(&self) -> Result<()> {
        self.charge(1, 0, 0, true)
    }
    pub fn bytes(&self, bytes: usize) -> Result<()> {
        self.charge(0, bytes as u64, 0, true)
    }
    pub fn work(&self, work: usize) -> Result<()> {
        self.charge(0, 0, work as u64, true)
    }
    /// Charge a reply this node chose to send. The budget still bounds
    /// amplification, but exhausting it never penalizes the recipient.
    pub fn outgoing(&self, bytes: usize, work: usize) -> Result<()> {
        self.charge(0, bytes as u64, work as u64, false)
    }
    /// Reserve node-wide memory for one complete incoming frame before its
    /// body is read. The reservation covers decoding and processing of that
    /// message and is released by the session's next frame or its close.
    /// Connections this node opened are bounded separately and never wait on
    /// inbound traffic.
    pub fn reserve_frame(&self, bytes: usize) -> Result<()> {
        let mut held = accounting(&self.reserved_frame);
        let mut total = accounting(&self.guard.frame_memory);
        *total = total.saturating_sub(*held);
        *held = 0;
        if self.key.2 == Direction::Outbound {
            return Ok(());
        }
        let bytes = bytes as u64;
        if total.saturating_add(bytes) > self.guard.frame_memory_limit() {
            return Err(Busy("peer frame memory budget exhausted").into());
        }
        *total += bytes;
        *held = bytes;
        Ok(())
    }
    fn charge(&self, requests: u64, bytes: u64, work: u64, penalize: bool) -> Result<()> {
        let now = Instant::now();
        if self.key.1 == Surface::Stratum && requests > 0 {
            let mut bucket = accounting(&self.request_bucket);
            ensure!(
                bucket.take(requests, 8, 16, now),
                "mining session request rate limit"
            );
        }
        let mut records = accounting(&self.guard.records);
        let record = records
            .get_mut(&self.key)
            .expect("active sessions retain their accounting entry");
        ensure!(now >= record.cooldown, "temporary network cooldown");
        let p = self.guard.policy(self.key.1);
        if !record
            .requests
            .take(requests, p.requests, p.request_burst, now)
            || !record.bytes.take(bytes, p.bytes, p.byte_burst, now)
            || !record.work.take(work, p.work, p.work_burst, now)
        {
            if !penalize {
                return Err(Busy("outgoing network budget exhausted").into());
            }
            self.guard.penalize(self.key.0, self.key.1, record, now);
            return Err(anyhow!("network rate budget exhausted"));
        }
        record.last = now;
        Ok(())
    }
    /// Only malformed framing/JSON and explicit resource violations trigger this.
    /// Ordinary stale transactions, unknown parents and competing forks do not.
    pub fn malformed(&self) {
        if let Some(record) = accounting(&self.guard.records).get_mut(&self.key) {
            self.guard
                .penalize(self.key.0, self.key.1, record, Instant::now());
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(record) = accounting(&self.guard.records).get_mut(&self.key) {
            record.active = record.active.saturating_sub(1);
        }
        let held = *self
            .reserved_frame
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        if held > 0 {
            let mut total = accounting(&self.guard.frame_memory);
            *total = total.saturating_sub(held);
        }
    }
}

#[derive(Default)]
struct SlotCounts {
    general: usize,
    reserved: usize,
    groups: HashMap<IpAddr, usize>,
}
/// Inbound peer session capacity. Public network groups have a concurrency
/// cap, and protected peers keep reserved capacity while general slots are full.
#[derive(Default)]
pub struct PeerSlots {
    counts: Mutex<SlotCounts>,
}
pub struct PeerSlot {
    slots: Arc<PeerSlots>,
    group: Option<IpAddr>,
    reserved: bool,
}
impl PeerSlots {
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, protected: bool) -> Option<PeerSlot> {
        let group = network_group(ip);
        let mut counts = accounting(&self.counts);
        if !protected
            && group.is_some_and(|g| {
                counts.groups.get(&g).copied().unwrap_or(0) >= PEER_SLOTS_PER_GROUP
            })
        {
            return None;
        }
        let reserved = if counts.general < INBOUND_PEER_SLOTS {
            false
        } else if protected && counts.reserved < RESERVED_PEER_SLOTS {
            true
        } else {
            return None;
        };
        if reserved {
            counts.reserved += 1;
        } else {
            counts.general += 1;
        }
        if let Some(group) = group {
            *counts.groups.entry(group).or_default() += 1;
        }
        Some(PeerSlot {
            slots: self.clone(),
            group,
            reserved,
        })
    }
}
impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut counts = accounting(&self.slots.counts);
        if self.reserved {
            counts.reserved = counts.reserved.saturating_sub(1);
        } else {
            counts.general = counts.general.saturating_sub(1);
        }
        if let Some(group) = self.group
            && let Some(count) = counts.groups.get_mut(&group)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.groups.remove(&group);
            }
        }
    }
}

/// Check allocation-relevant JSON shape before serde constructs any JSON tree.
/// Syntax, escaped strings and number types are subsequently checked by serde.
pub fn preflight_json(bytes: &[u8]) -> Result<()> {
    preflight_json_with_value_limit(bytes, MAX_JSON_VALUES)
}
/// Typed peer decoding does not allocate a generic Value for every scalar byte.
pub(crate) fn preflight_json_with_value_limit(bytes: &[u8], max_values: usize) -> Result<()> {
    preflight_json_value_count(bytes, max_values).map(|_| ())
}
pub(crate) fn preflight_json_value_count(bytes: &[u8], max_values: usize) -> Result<usize> {
    preflight_json_with_limits(bytes, max_values, 1024)
}
fn preflight_json_with_limits(bytes: &[u8], max_values: usize, max_string: usize) -> Result<usize> {
    #[derive(Clone, Copy)]
    struct Container {
        kind: u8,
        count: usize,
        content: bool,
    }
    let mut stack: Vec<Container> = Vec::with_capacity(MAX_JSON_DEPTH);
    let mut quoted = false;
    let mut escaped = false;
    let mut string_bytes = 0usize;
    let mut values = 0usize;
    let mut string_start = 0;
    for (index, &b) in bytes.iter().enumerate() {
        if quoted {
            if !escaped && b == b'"' {
                if string_bytes > max_string {
                    let decoded: String = serde_json::from_slice(&bytes[string_start..=index])?;
                    ensure!(
                        decoded.len() <= max_string,
                        "JSON string exceeds protocol bound"
                    );
                }
                quoted = false;
                continue;
            }
            string_bytes += 1;
            ensure!(
                string_bytes <= max_string.saturating_mul(6),
                "JSON encoded string exceeds protocol bound"
            );
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            }
            continue;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        if let Some(top) = stack.last_mut()
            && b != b']'
            && b != b'}'
        {
            top.content = true;
        }
        match b {
            b'"' => {
                quoted = true;
                string_bytes = 0;
                string_start = index;
                values += 1;
            }
            b'[' | b'{' => {
                ensure!(
                    stack.len() < MAX_JSON_DEPTH,
                    "JSON nesting exceeds protocol bound"
                );
                stack.push(Container {
                    kind: b,
                    count: 0,
                    content: false,
                });
                values += 1;
            }
            b']' | b'}' => {
                let top = stack
                    .pop()
                    .ok_or_else(|| anyhow!("unbalanced JSON container"))?;
                ensure!(
                    (top.kind == b'[' && b == b']') || (top.kind == b'{' && b == b'}'),
                    "mismatched JSON container"
                );
                if top.kind == b'[' {
                    ensure!(
                        top.count + usize::from(top.content) <= 100_000,
                        "JSON array exceeds protocol bound"
                    );
                }
            }
            b',' => {
                if let Some(top) = stack.last_mut()
                    && top.kind == b'['
                {
                    top.count += 1;
                    ensure!(top.count < 100_000, "JSON array exceeds protocol bound");
                }
                values += 1;
            }
            b':' => {
                if let Some(top) = stack.last_mut()
                    && top.kind == b'{'
                {
                    top.count += 1;
                    ensure!(top.count <= 128, "JSON object exceeds protocol bound");
                }
            }
            _ => {}
        }
        ensure!(
            values <= max_values,
            "JSON value count exceeds protocol bound"
        );
    }
    ensure!(
        !quoted && !escaped && stack.is_empty(),
        "truncated JSON container or string"
    );
    Ok(values)
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    preflight_json(bytes)?;
    let value: Value = serde_json::from_slice(bytes)?;
    json_bounds(&value)?;
    Ok(value)
}
/// Only the designated raw transaction or data field may exceed the ordinary
/// JSON string bound. All other fields retain their existing limits.
pub(crate) fn parse_rpc_json(bytes: &[u8], max_raw_hex: usize) -> Result<Value> {
    preflight_json_with_limits(bytes, MAX_JSON_VALUES, max_raw_hex.max(1024))?;
    let mut value: Value = serde_json::from_slice(bytes)?;
    match value.get("method").and_then(Value::as_str) {
        Some("broadcasttransaction") => {
            bounded_string_field(&mut value, "/params/raw", max_raw_hex)?;
        }
        Some("preparetransaction" | "fee_quote" | "transfer_quote") => {
            bounded_data_field(&mut value, "/params/data_hex", max_raw_hex)?;
        }
        _ => json_bounds(&value)?,
    }
    Ok(value)
}

/// The HTTP caller selects this parser only for the authenticated hot-wallet
/// endpoint. Wallet management and other endpoints do not inherit this exception.
pub(crate) fn parse_wallet_json(bytes: &[u8], max_data_hex: usize) -> Result<Value> {
    preflight_json_with_limits(bytes, MAX_JSON_VALUES, max_data_hex.max(1024))?;
    let mut value: Value = serde_json::from_slice(bytes)?;
    bounded_data_field(&mut value, "/data_hex", max_data_hex)?;
    Ok(value)
}

fn bounded_data_field(value: &mut Value, path: &str, maximum: usize) -> Result<()> {
    // Optional request fields already accept null as absence. Byte syntax and
    // the complete transaction size are checked by the wallet request handler.
    if value.pointer(path).is_some_and(Value::is_null) {
        return json_bounds(value);
    }
    bounded_string_field(value, path, maximum)
}

fn bounded_string_field(value: &mut Value, path: &str, maximum: usize) -> Result<()> {
    let Some(field) = value.pointer_mut(path) else {
        return json_bounds(value);
    };
    let field = field.take();
    ensure!(
        field.as_str().is_some_and(|s| s.len() <= maximum),
        "transaction byte string exceeds bound or is not a string"
    );
    json_bounds(value)?;
    *value
        .pointer_mut(path)
        .expect("field retained during bounds check") = field;
    Ok(())
}
fn json_bounds(value: &Value) -> Result<()> {
    match value {
        Value::String(s) => ensure!(s.len() <= 1024, "JSON string exceeds protocol bound"),
        Value::Array(a) => {
            for v in a {
                json_bounds(v)?;
            }
        }
        Value::Object(o) => {
            for (k, v) in o {
                ensure!(k.len() <= 128, "JSON key exceeds protocol bound");
                json_bounds(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn retry_delay(failures: u32, jitter: u64) -> Duration {
    let base = if failures == 0 {
        1000
    } else {
        (1000u64 << failures.min(6)).min(60_000)
    };
    Duration::from_millis(base + jitter % ((base / 4).max(1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validated_capacity_growth_extends_existing_sessions_once() {
        let guard = Arc::new(NetworkGuard::default());
        let peer = guard
            .admit("127.0.0.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        let expanded = 100 * 1024 * 1024;
        guard.allow_frame(expanded).unwrap();
        assert!(peer.bytes(expanded).is_ok());
        guard.allow_frame(expanded).unwrap();
        assert!(
            peer.bytes(expanded).is_err(),
            "unchanged allowance must not refill tokens"
        );
    }
    #[test]
    fn larger_peer_frames_receive_one_bounded_burst_without_relaxing_other_quotas() {
        const FRAME: usize = 97 * 1024 * 1024;
        let guard = Arc::new(NetworkGuard::with_frame_limit(FRAME));
        let ip = "127.0.0.1".parse().unwrap();
        let peer = guard.admit(ip, Surface::Peer).unwrap();
        assert!(peer.bytes(FRAME).is_ok());
        assert!(peer.bytes(FRAME).is_err());
        assert_eq!(
            guard.policy(Surface::Peer).bytes,
            Surface::Peer.policy().bytes
        );
        assert_eq!(guard.policy(Surface::Peer).connections, 4);
        assert_eq!(guard.policy(Surface::Stratum).byte_burst, 2 * 1024 * 1024);
        let old = Arc::new(NetworkGuard::default());
        assert!(old.admit(ip, Surface::Peer).unwrap().bytes(FRAME).is_err());
    }
    #[test]
    fn rpc_raw_transaction_exception_does_not_relax_other_fields() {
        let raw = "ab".repeat(600);
        let wire = serde_json::to_vec(&serde_json::json!({
            "jsonrpc":"2.0","id":1,"method":"broadcasttransaction","params":{"raw":raw}
        }))
        .unwrap();
        assert!(parse_json(&wire).is_err());
        assert!(parse_rpc_json(&wire, 32768).is_ok());
        for value in [
            serde_json::json!({"method":"submittransaction","params":{"raw":raw}}),
            serde_json::json!({"method":"broadcasttransaction","params":{"raw":"00","other":raw}}),
            serde_json::json!({"method":"broadcasttransaction","raw":raw,"params":{"raw":"00"}}),
            serde_json::json!({"method":"broadcasttransaction","params":{"raw":"00".repeat(16385)}}),
            serde_json::json!({"method":"broadcasttransaction","params":{"raw":[raw]}}),
        ] {
            assert!(parse_rpc_json(&serde_json::to_vec(&value).unwrap(), 32768).is_err());
        }
    }

    #[test]
    fn rpc_data_exception_is_limited_to_exact_methods_and_params_field() {
        let data = "00aaff".repeat(1_000); // 3,000 binary bytes, including zeroes.
        for method in ["preparetransaction", "fee_quote", "transfer_quote"] {
            let value = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"data_hex":data}});
            let wire = serde_json::to_vec(&value).unwrap();
            assert!(parse_json(&wire).is_err());
            assert_eq!(parse_rpc_json(&wire, 32_768).unwrap(), value);
            assert_eq!(parse_rpc_json(&wire, data.len()).unwrap(), value);
            assert!(parse_rpc_json(&wire, data.len() - 1).is_err());
            for params in [
                serde_json::json!({}),
                serde_json::json!({"data_hex":""}),
                serde_json::json!({"data_hex":null}),
            ] {
                assert!(
                    parse_rpc_json(
                        &serde_json::to_vec(&serde_json::json!({"method":method,"params":params}))
                            .unwrap(),
                        32_768
                    )
                    .is_ok()
                );
            }
        }
        for value in [
            serde_json::json!({"method":"submittransaction","params":{"data_hex":data}}),
            serde_json::json!({"method":"PrepareTransaction","params":{"data_hex":data}}),
            serde_json::json!({"method":"broadcasttransaction","params":{"raw":"00","data_hex":data}}),
            serde_json::json!({"method":"preparetransaction","data_hex":data,"params":{}}),
            serde_json::json!({"method":"preparetransaction","params":{"operation":{"data_hex":data}}}),
            serde_json::json!({"method":"preparetransaction","params":{"data_hex":"00","other":data}}),
            serde_json::json!({"method":"fee_quote","params":{"data_hex":"00","raw":data}}),
            serde_json::json!({"method":"transfer_quote","params":{"data_hex":data},"id":"x".repeat(1025)}),
            serde_json::json!({"method":"preparetransaction","params":{"data_hex":[data]}}),
            serde_json::json!({"method":"preparetransaction","params":{"data_hex":123}}),
            serde_json::json!({"method":"preparetransaction","params":{"data_hex":"00".repeat(16_385)}}),
            serde_json::json!({"envelope":{"method":"preparetransaction","params":{"data_hex":data}}}),
        ] {
            assert!(parse_rpc_json(&serde_json::to_vec(&value).unwrap(), 32_768).is_err());
        }
    }

    #[test]
    fn hot_wallet_data_exception_only_allows_the_top_level_data_field() {
        let data = "80ff00".repeat(1_000);
        let value = serde_json::json!({"data_hex":data,"operation":{"Donate":{"amount":"1","decision":null,"outcome":null}}});
        let wire = serde_json::to_vec(&value).unwrap();
        assert_eq!(parse_wallet_json(&wire, 32_768).unwrap(), value);
        assert!(parse_rpc_json(&wire, 32_768).is_err());
        assert!(parse_json(&wire).is_err());
        assert!(parse_wallet_json(&wire, data.len() - 1).is_err());
        for value in [
            serde_json::json!({}),
            serde_json::json!({"data_hex":""}),
            serde_json::json!({"data_hex":null}),
        ] {
            assert_eq!(
                parse_wallet_json(&serde_json::to_vec(&value).unwrap(), 32_768).unwrap(),
                value
            );
        }
        for value in [
            serde_json::json!({"method":"preparetransaction","params":{"data_hex":data}}),
            serde_json::json!({"method":"broadcasttransaction","params":{"raw":data}}),
            serde_json::json!({"data_hex":"00","operation":{"data_hex":data}}),
            serde_json::json!({"data_hex":data,"name":"x".repeat(1025)}),
            serde_json::json!({"data_hex":{"bytes":data}}),
            serde_json::json!({"data_hex":[data]}),
            serde_json::json!({"data_hex":false}),
            serde_json::json!({"data_hex":"00".repeat(16_385)}),
        ] {
            assert!(parse_wallet_json(&serde_json::to_vec(&value).unwrap(), 32_768).is_err());
        }
        // The raw allocation preflight also bounds escaped strings before serde.
        let escaped = format!("{{\"data_hex\":\"{}\"}}", "\\u0061".repeat(6_000));
        assert_eq!(
            parse_wallet_json(escaped.as_bytes(), 32_768).unwrap()["data_hex"],
            "a".repeat(6_000)
        );
        let oversized = format!("{{\"data_hex\":\"{}\"}}", "\\u0061".repeat(32_769));
        assert!(parse_wallet_json(oversized.as_bytes(), 32_768).is_err());
    }
    #[test]
    fn roles_are_isolated_and_tracking_is_bounded() {
        let guard = Arc::new(NetworkGuard::default());
        let ip = "127.0.0.1".parse().unwrap();
        let peer = guard.admit(ip, Surface::Peer).unwrap();
        peer.malformed();
        assert!(guard.admit(ip, Surface::Peer).is_err());
        assert!(guard.admit(ip, Surface::Rpc).is_ok());
        drop(peer);
        for n in 0..MAX_TRACKED_IPS + 10 {
            drop(
                guard
                    .admit(
                        IpAddr::from([10, (n / 256) as u8, (n % 256) as u8, 1]),
                        Surface::Peer,
                    )
                    .unwrap(),
            );
        }
        assert!(guard.tracked_addresses() <= MAX_TRACKED_IPS);
    }
    #[test]
    fn quotas_recover_and_cooldowns_are_temporary() {
        let guard = Arc::new(NetworkGuard::default());
        let ip = "127.0.0.1".parse().unwrap();
        let now = Instant::now();
        let session = guard
            .admit_at(ip, Surface::Peer, Direction::Inbound, now)
            .unwrap();
        session.malformed();
        drop(session);
        assert!(
            guard
                .admit_at(
                    ip,
                    Surface::Peer,
                    Direction::Inbound,
                    now + Duration::from_secs(20)
                )
                .is_ok()
        );
        let mut bucket = Bucket::new(10, now);
        assert!(bucket.take(10, 2, 10, now));
        assert!(!bucket.take(1, 2, 10, now));
        assert!(bucket.take(2, 2, 10, now + Duration::from_secs(1)));
    }
    #[test]
    fn public_proxy_cannot_be_banned_by_one_visitor_but_quotas_still_apply() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            let ip = ip.parse().unwrap();
            let session = guard.admit(ip, Surface::Rpc).unwrap();
            session.malformed();
            assert!(
                session
                    .bytes(Surface::Rpc.policy().byte_burst as usize + 1)
                    .is_err()
            );
            assert!(session.work(1_048_577).is_err());
            assert!(guard.admit(ip, Surface::Rpc).is_ok());
            assert!(session.request().is_ok());
        }
        let ip = "127.0.0.1".parse().unwrap();
        let held: Vec<_> = (0..8)
            .map(|_| guard.admit(ip, Surface::Rpc).unwrap())
            .collect();
        assert!(guard.admit(ip, Surface::Rpc).is_err());
        drop(held);
        let remote = "192.0.2.1".parse().unwrap();
        let visitor = guard.admit(remote, Surface::Rpc).unwrap();
        visitor.malformed();
        assert!(guard.admit(remote, Surface::Rpc).is_err());
        let peer = guard.admit(ip, Surface::Peer).unwrap();
        peer.malformed();
        assert!(guard.admit(ip, Surface::Peer).is_err());
        let private = Arc::new(NetworkGuard::default());
        let local = private.admit(ip, Surface::Rpc).unwrap();
        local.malformed();
        assert!(private.admit(ip, Surface::Rpc).is_err());
    }
    #[test]
    fn global_ipv6_hosts_are_accounted_by_slash_64_and_cooldowns_survive_churn() {
        let guard = Arc::new(NetworkGuard::default());
        let host = |n: u16| IpAddr::from([0x2001, 0x4860, 7, 9, 0, 0, 0, n]);
        let held: Vec<_> = (1..=4)
            .map(|n| guard.admit(host(n), Surface::Peer).unwrap())
            .collect();
        // Fresh source addresses in the same /64 share one connection cap.
        assert!(guard.admit(host(5), Surface::Peer).is_err());
        assert!(
            guard
                .admit(IpAddr::from([0x2001, 0x4860, 7, 10, 0, 0, 0, 1]), Surface::Peer)
                .is_ok()
        );
        for _ in 0..4 {
            held[0].malformed();
        }
        drop(held);
        assert!(guard.admit(host(77), Surface::Peer).is_err());
        // Link-local and unique-local hosts on one LAN keep separate records.
        let local: Vec<_> = (1..=5u16)
            .map(|n| {
                guard
                    .admit(IpAddr::from([0xfe80, 0, 0, 0, 0, 0, 0, n]), Surface::Peer)
                    .unwrap()
            })
            .collect();
        drop(local);
        // Record churn evicts expired records before ones still cooling down.
        for n in 0..MAX_TRACKED_IPS + 8 {
            drop(
                guard
                    .admit(
                        IpAddr::from([10, 9, (n / 256) as u8, (n % 256) as u8]),
                        Surface::Peer,
                    )
                    .unwrap(),
            );
        }
        assert!(guard.admit(host(78), Surface::Peer).is_err());
        assert_eq!(
            network_group(host(1)),
            network_group(IpAddr::from([0x2001, 0x4860, 1, 1, 1, 1, 1, 1]))
        );
        assert_ne!(
            network_group("8.8.1.1".parse().unwrap()),
            network_group("8.9.1.1".parse().unwrap())
        );
        assert_eq!(network_group("127.0.0.1".parse().unwrap()), None);
        assert_eq!(network_group("10.1.2.3".parse().unwrap()), None);
    }
    #[test]
    fn outbound_accounting_is_separate_and_own_replies_never_penalize() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let inbound: Vec<_> = (0..4)
            .map(|_| guard.admit(ip, Surface::Peer).unwrap())
            .collect();
        inbound[0].malformed();
        assert!(guard.admit(ip, Surface::Peer).is_err());
        // Inbound cooldown and connection use from a shared address cannot
        // block this node's own outbound synchronization to it.
        let outbound = guard.admit_outbound(ip, Surface::Peer).unwrap();
        let error = outbound.outgoing(0, 65_537).unwrap_err();
        assert!(error.is::<Busy>());
        assert!(outbound.outgoing(0, 65_536).is_ok());
        drop(outbound);
        assert!(guard.admit_outbound(ip, Surface::Peer).is_ok());
        guard.allow_work(100_000).unwrap();
        let other = guard
            .admit_outbound("192.0.2.8".parse().unwrap(), Surface::Peer)
            .unwrap();
        assert!(other.work(100_000).is_ok());
        assert_eq!(guard.policy(Surface::Peer).work_burst, 100_000);
        assert_eq!(guard.policy(Surface::Stratum).work_burst, 8192);
        assert_eq!(guard.policy(Surface::Rpc).work_burst, 1_048_576);
    }
    #[test]
    fn inbound_frame_memory_is_bounded_and_released() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let half = (PEER_FRAME_MEMORY / 2) as usize;
        let first = guard.admit(ip, Surface::Peer).unwrap();
        let second = guard.admit(ip, Surface::Peer).unwrap();
        let third = guard.admit(ip, Surface::Peer).unwrap();
        first.reserve_frame(half).unwrap();
        second.reserve_frame(half).unwrap();
        assert!(third.reserve_frame(1).unwrap_err().is::<Busy>());
        // A session's next frame replaces its previous reservation.
        first.reserve_frame(half).unwrap();
        first.reserve_frame(1).unwrap();
        third.reserve_frame(half - 1).unwrap();
        drop(second);
        third.reserve_frame(half).unwrap();
        let outbound = guard.admit_outbound(ip, Surface::Peer).unwrap();
        outbound.reserve_frame(usize::MAX).unwrap();
        drop((first, third));
        assert_eq!(*guard.frame_memory.lock().unwrap(), 0);
        let larger = Arc::new(NetworkGuard::with_frame_limit(100 * 1024 * 1024));
        let session = larger.admit(ip, Surface::Peer).unwrap();
        assert!(session.reserve_frame(200 * 1024 * 1024).is_ok());
    }
    #[test]
    fn inbound_peer_slots_require_network_diversity_and_keep_reserved_capacity() {
        let slots = Arc::new(PeerSlots::default());
        let public = |a: u8, b: u8, c: u8| IpAddr::from([8, a, b, c]);
        // Two addresses in one public /16 hold at most two sessions.
        let same: Vec<_> = (1..=4)
            .filter_map(|n| slots.try_acquire(public(1, n, 1), false))
            .collect();
        assert_eq!(same.len(), 2);
        let ipv6 = |n: u16| IpAddr::from([0x2001, 0x4860, n, 0, 0, 0, 0, 1]);
        let v6: Vec<_> = (1..=3)
            .filter_map(|n| slots.try_acquire(ipv6(n), false))
            .collect();
        assert_eq!(v6.len(), 2);
        // Filling the general slots needs many distinct groups.
        let mut held = Vec::new();
        for group in 2..=7 {
            for host in 1..=2 {
                held.push(slots.try_acquire(public(group, host, 1), false).unwrap());
            }
        }
        assert!(slots.try_acquire(public(30, 1, 1), false).is_none());
        // A configured or verified peer still connects, without a group cap.
        let protected: Vec<_> = (1..=RESERVED_PEER_SLOTS)
            .map(|n| slots.try_acquire(public(1, 9, n as u8), true).unwrap())
            .collect();
        assert!(slots.try_acquire(public(40, 1, 1), true).is_none());
        drop(protected);
        drop(held);
        // Loopback and private sources keep per-address accounting only.
        let local: Vec<_> = (0..INBOUND_PEER_SLOTS - 4)
            .map(|_| slots.try_acquire("127.0.0.1".parse().unwrap(), false).unwrap())
            .collect();
        assert_eq!(local.len(), INBOUND_PEER_SLOTS - 4);
        drop((same, local));
        assert_eq!(slots.counts.lock().unwrap().general, 2);
    }
    #[test]
    fn a_panic_during_accounting_never_disables_admission() {
        let guard = Arc::new(NetworkGuard::default());
        let slots = Arc::new(PeerSlots::default());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = guard.admit(ip, Surface::Peer).unwrap();
        session.reserve_frame(1024).unwrap();
        let slot = slots.try_acquire(ip, false).unwrap();
        fn poison<T: Send>(lock: &Mutex<T>) {
            std::thread::scope(|scope| {
                let holder = scope.spawn(|| {
                    let _held = lock.lock();
                    panic!("accounting panic");
                });
                assert!(holder.join().is_err());
            });
        }
        poison(&guard.records);
        poison(&guard.frame_memory);
        poison(&slots.counts);
        assert!(guard.records.is_poisoned() && slots.counts.is_poisoned());
        // Charges, frame reservations, releases and new admissions continue.
        session.work(1).unwrap();
        session.reserve_frame(2048).unwrap();
        drop(session);
        assert_eq!(*accounting(&guard.frame_memory), 0);
        assert!(guard.admit(ip, Surface::Peer).is_ok());
        drop(slot);
        assert!(slots.try_acquire(ip, false).is_some());
        assert_eq!(accounting(&slots.counts).general, 0);
    }
    #[test]
    fn json_preflight_rejects_excess_shape_before_decoding() {
        assert!(parse_json(br#"{"a":[1,"quoted \\\" string",{}]}"#).is_ok());
        assert!(
            preflight_json(format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes()).is_err()
        );
        assert!(preflight_json(format!("\"{}\"", "x".repeat(6145)).as_bytes()).is_err());
        assert!(preflight_json(b"[1,2").is_err());
        assert!(parse_json(format!("\"{}\"", "x".repeat(1025)).as_bytes()).is_err());
    }
}
