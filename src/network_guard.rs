//! Local admission policy. These limits never change block or transaction validity.
use anyhow::{Result, anyhow, ensure};
use serde_json::Value;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
/// Inbound peer sessions open to any source. When they are full, configured
/// or pinned peers have their own reserved slots, and discovery peers verified
/// in the last hour have separate ones that remain subject to group caps.
pub const INBOUND_PEER_SLOTS: usize = 16;
pub const RESERVED_PEER_SLOTS: usize = 4;
pub const VERIFIED_PEER_SLOTS: usize = 4;
/// Concurrent inbound sessions from one network group (IPv4 /16, IPv6 /32).
pub const PEER_SLOTS_PER_GROUP: usize = 2;
/// Stratum connections awaiting authorization that any source may use, plus
/// slots that only addresses which recently authorized may use when those are full.
pub const STRATUM_PENDING_SLOTS: usize = 128;
pub const RESERVED_STRATUM_PENDING: usize = 32;
/// Concurrent pending Stratum sessions from one group (IPv4 /24, IPv6 /48)
/// whose addresses have not recently authorized.
pub const STRATUM_PENDING_PER_GROUP: usize = 8;
/// Addresses remembered after a successful Stratum authorization.
pub const STRATUM_TRUSTED_ADDRESSES: usize = 256;
pub const STRATUM_AUTHORIZATION_WINDOW: Duration = Duration::from_secs(10);
/// Waiting for authorization is charged to the source address. An attempt
/// reserves a whole window from a budget of four windows that refills at half
/// a second per second; the unused part returns when the session authorizes
/// or closes, however it closes.
const PENDING_WINDOW_MS: u64 = STRATUM_AUTHORIZATION_WINDOW.as_millis() as u64;
const PENDING_BUDGET_MS: u64 = 4 * PENDING_WINDOW_MS;
const PENDING_REFILL_MS: u64 = 500;
/// Requests per second, and burst, for one Stratum session.
const SESSION_REQUESTS: u64 = 8;
const SESSION_REQUEST_BURST: u64 = 16;
/// Lines an authorized Stratum worker may send past its session rate while
/// its difficulty is raised. They are checked for a block, otherwise refused.
const WORKER_OVERRUN: u64 = 8;
const WORKER_OVERRUN_BURST: u64 = 64;
/// Public website sessions in total. A loopback reverse proxy may carry all of
/// them; one visitor, connecting directly or named by that proxy, may hold
/// only a browser's six parallel connections and an eighth of the work budget.
pub const PUBLIC_WEB_SESSIONS: usize = 32;
pub const PUBLIC_WEB_VISITOR_SESSIONS: usize = 6;
const PUBLIC_WEB_VISITOR_WORK_SHARE: u64 = 8;

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
    /// A public website visitor named by the loopback reverse proxy. Its
    /// record is separate from the proxy's own and from direct connections.
    Forwarded,
}
type Key = (IpAddr, Surface, Direction);

/// Local capacity was unavailable. This is never evidence of peer misbehavior.
#[derive(Debug)]
pub struct Busy(pub &'static str);
impl std::fmt::Display for Busy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for Busy {}

/// One client's own admission quota refused it: a temporary cooldown, or a
/// connection, request, byte or work budget that refills over time.
/// `retry_after` is when the same charge would be admitted again, counting
/// any cooldown it started; `None` means the charge exceeds the quota's whole
/// burst, so waiting cannot help. A refused charge never ran its work, so an
/// HTTP client is told to wait (429 with Retry-After) instead of losing the
/// connection.
#[derive(Debug)]
pub struct Limited {
    pub reason: &'static str,
    pub retry_after: Option<Duration>,
}
impl std::fmt::Display for Limited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}
impl std::error::Error for Limited {}
fn limited(reason: &'static str, retry_after: Option<Duration>) -> anyhow::Error {
    Limited {
        reason,
        retry_after,
    }
    .into()
}

/// Loopback, link-local, unique-local, private and shared (CGNAT) sources
/// belong to networks the operator controls.
fn local_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_private()
                || v.is_link_local()
                || (a == 100 && (64..=127).contains(&b))
        }
        IpAddr::V6(v) => {
            let first = v.segments()[0];
            v.is_loopback()
                || v.is_unspecified()
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
        }
    }
}
/// Admission identity. IPv4-mapped addresses share the IPv4 record, a 6to4
/// source is accounted by the /48 its IPv4 host controls, and another global
/// IPv6 host by its /64 because it normally controls one.
pub fn admission_address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None if v.segments()[0] == 0x2002 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(v) & !(u128::MAX >> 48)))
            }
            None if (v.segments()[0] & 0xe000) == 0x2000 => {
                IpAddr::V6(Ipv6Addr::from(u128::from(v) & !u128::from(u64::MAX)))
            }
            None => ip,
        },
        _ => ip,
    }
}
/// Inbound diversity group: IPv4 /16 or IPv6 /32, with a 6to4 source grouped
/// with the IPv4 /16 it embeds. Only sources on local networks keep
/// per-address accounting alone; routable special ranges such as Teredo are
/// grouped conservatively by /32.
pub fn network_group(ip: IpAddr) -> Option<IpAddr> {
    let ip = admission_address(ip);
    if local_source(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            IpAddr::V4(Ipv4Addr::new(a, b, 0, 0))
        }
        IpAddr::V6(v) if v.segments()[0] == 0x2002 => {
            let [a, b] = v.segments()[1].to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(a, b, 0, 0))
        }
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(u128::from(v) & !(u128::MAX >> 32))),
    })
}
/// Who delivered peer data: a network group, or the address on a local network.
pub fn peer_source(ip: IpAddr) -> IpAddr {
    network_group(ip).unwrap_or_else(|| admission_address(ip))
}
/// Pending Stratum group: IPv4 /24 or IPv6 /48, which one operator or site
/// normally holds. As for network groups, only sources on local networks keep
/// per-address accounting.
fn pending_group(ip: IpAddr) -> Option<IpAddr> {
    let ip = admission_address(ip);
    if local_source(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(v) => IpAddr::V4(Ipv4Addr::from(u32::from(v) & !0xff)),
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(u128::from(v) & !(u128::MAX >> 48))),
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
    /// Return unused tokens, never beyond capacity.
    fn give(&mut self, amount: u64, rate: u64, capacity: u64, now: Instant) {
        self.take(0, rate, capacity, now);
        self.tokens = self.tokens.saturating_add(amount).min(capacity);
        if self.tokens == capacity {
            self.remainder = 0;
        }
    }
    /// After a `take` at some instant refused `amount`, how long from that
    /// instant until the bucket holds it. `None` when it never can.
    fn wait(&self, amount: u64, rate: u64, capacity: u64) -> Option<Duration> {
        if amount > capacity || rate == 0 {
            return None;
        }
        let missing = u128::from(amount.saturating_sub(self.tokens));
        let units = (missing * 1_000_000_000).saturating_sub(self.remainder);
        let nanos = units.div_ceil(u128::from(rate));
        Some(Duration::from_nanos(nanos.min(u64::MAX as u128) as u64))
    }
    /// Tokens available at `now`, without changing the bucket.
    fn level(&self, rate: u64, capacity: u64, now: Instant) -> u64 {
        let units = now
            .duration_since(self.last)
            .as_nanos()
            .saturating_mul(rate as u128)
            .saturating_add(self.remainder);
        self.tokens
            .saturating_add((units / 1_000_000_000).min(u64::MAX as u128) as u64)
            .min(capacity)
    }
}
struct Record {
    active: usize,
    last: Instant,
    cooldown: Instant,
    /// Until when a connection refused before its session started goes
    /// unanswered, because this address was already told when to return.
    answered_until: Instant,
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
            answered_until: now,
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
    /// A refusal that a bucket's `wait` describes, after any cooldown it set.
    fn refusal(&self, reason: &'static str, wait: Option<Duration>, now: Instant) -> anyhow::Error {
        let cooling = self.cooldown.saturating_duration_since(now);
        limited(reason, wait.map(|wait| wait.max(cooling)))
    }
}
/// Incoming frame bytes buffered by inbound sessions.
#[derive(Default)]
struct FrameMemory {
    total: u64,
    /// Held by sessions other than configured or pinned peers.
    shared: u64,
    /// Shared bytes held by each network group.
    groups: HashMap<IpAddr, u64>,
}
#[derive(Default)]
pub struct NetworkGuard {
    max_frame_bytes: AtomicU64,
    max_peer_work: AtomicU64,
    loopback_rpc_is_proxy: bool,
    records: Mutex<HashMap<Key, Record>>,
    frame_memory: Mutex<FrameMemory>,
}
pub struct Session {
    guard: Arc<NetworkGuard>,
    key: Key,
    group: Option<IpAddr>,
    /// A configured or pinned peer, which may use the whole frame budget.
    operator: bool,
    /// The public website visitor the proxy named for this session, if any.
    visitor: OnceLock<Key>,
    /// A quota already refused this session and accounted for it.
    refused: AtomicBool,
    request_bucket: Mutex<Bucket>,
    overrun_bucket: Mutex<Bucket>,
    worker: AtomicBool,
    reserved_frame: Mutex<u64>,
}
impl NetworkGuard {
    /// A loopback reverse proxy represents many public visitors. Keep its
    /// aggregate quotas, but never turn one malformed visitor into an IP ban
    /// of the whole website. Direct remote clients retain normal cooldowns.
    /// Visitors, direct or named by the proxy, also have their own smaller
    /// session and work caps, so one cannot take the whole website.
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
    /// The loopback reverse proxy's own record on the public-web guard.
    fn is_proxy(&self, key: Key) -> bool {
        self.loopback_rpc_is_proxy
            && key.1 == Surface::Rpc
            && key.2 == Direction::Inbound
            && key.0.is_loopback()
    }
    fn key_policy(&self, key: Key) -> Policy {
        let mut policy = self.policy(key.1);
        if self.loopback_rpc_is_proxy && key.1 == Surface::Rpc {
            if self.is_proxy(key) {
                policy.connections = PUBLIC_WEB_SESSIONS;
            } else {
                policy.connections = PUBLIC_WEB_VISITOR_SESSIONS;
                policy.work /= PUBLIC_WEB_VISITOR_WORK_SHARE;
                policy.work_burst /= PUBLIC_WEB_VISITOR_WORK_SHARE;
            }
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
    /// The node-wide frame budget; the part that sessions other than
    /// configured or pinned peers may share, which leaves one largest frame
    /// to those peers; and one network group's limit within that share.
    fn frame_memory_limits(&self) -> (u64, u64, u64) {
        let frame = self.max_frame_bytes.load(Ordering::Relaxed);
        let total = PEER_FRAME_MEMORY.max(frame.saturating_mul(2));
        let shared = total.saturating_sub(frame);
        let groups = (INBOUND_PEER_SLOTS / PEER_SLOTS_PER_GROUP) as u64;
        (total, shared, frame.max(shared / groups))
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
    fn penalize(&self, key: Key, record: &mut Record, now: Instant) {
        if !self.is_proxy(key) {
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
        self.enter(&mut records, key, now)?;
        Ok(Session {
            guard: self.clone(),
            key,
            group: network_group(ip),
            operator: false,
            visitor: OnceLock::new(),
            refused: AtomicBool::new(false),
            request_bucket: Mutex::new(Bucket::new(SESSION_REQUEST_BURST, now)),
            overrun_bucket: Mutex::new(Bucket::new(WORKER_OVERRUN_BURST, now)),
            worker: AtomicBool::new(false),
            reserved_frame: Mutex::new(0),
        })
    }
    /// Admit one more connection to `key`'s record, creating it if needed.
    fn enter(&self, records: &mut HashMap<Key, Record>, key: Key, now: Instant) -> Result<()> {
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
                    return Err(Busy("network accounting capacity reached").into());
                };
                records.remove(&oldest);
            }
            records.insert(key, Record::new(self.key_policy(key), now));
        }
        let record = records.get_mut(&key).unwrap();
        if now < record.cooldown {
            let refusal = "temporary network cooldown";
            return Err(record.refusal(refusal, Some(Duration::ZERO), now));
        }
        let p = self.key_policy(key);
        if record.active >= p.connections {
            // A slot frees when one of this address's sessions ends.
            return Err(limited(
                "per-address connection limit",
                Some(Duration::from_secs(1)),
            ));
        }
        if !record.requests.take(1, p.requests, p.request_burst, now) {
            self.penalize(key, record, now);
            let wait = record.requests.wait(1, p.requests, p.request_burst);
            return Err(record.refusal("connection rate limit", wait, now));
        }
        record.active += 1;
        record.last = now;
        Ok(())
    }
    /// Whether to answer an inbound connection from `ip` that was refused
    /// before its session started, telling it to return after `window` (its
    /// Retry-After). One such answer per address and window is sent; further
    /// refused attempts before then are closed unanswered, so a client that
    /// waits as told is always answered while a flood earns at most one short
    /// reply per window. The public website's proxy carries many visitors and
    /// is answered every time; an address without an accounting record (the
    /// table was full) never is.
    pub fn answer_refusal(&self, ip: IpAddr, surface: Surface, window: Duration) -> bool {
        self.answer_refusal_at(ip, surface, window, Instant::now())
    }
    fn answer_refusal_at(
        &self,
        ip: IpAddr,
        surface: Surface,
        window: Duration,
        now: Instant,
    ) -> bool {
        let key = (admission_address(ip), surface, Direction::Inbound);
        if self.is_proxy(key) {
            return true;
        }
        let mut records = accounting(&self.records);
        let Some(record) = records.get_mut(&key) else {
            return false;
        };
        if now < record.answered_until {
            return false;
        }
        record.answered_until = now + window;
        true
    }
    pub fn tracked_addresses(&self) -> usize {
        accounting(&self.records).len()
    }
    #[cfg(test)]
    pub fn frame_memory_in_use(&self) -> u64 {
        accounting(&self.frame_memory).total
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
    /// Mark a configured or pinned peer's session. It may use the frame
    /// memory that other inbound sessions must leave free.
    pub fn operator(mut self) -> Self {
        self.operator = true;
        self
    }
    /// Release the previous frame's memory before another frame is read.
    pub fn begin_frame(&self) -> Result<()> {
        let mut held = accounting(&self.reserved_frame);
        let mut memory = accounting(&self.guard.frame_memory);
        self.release_frame(&mut memory, std::mem::take(&mut *held));
        Ok(())
    }
    /// Reserve node-wide memory for the next bytes of the current frame before
    /// they are read, so buffered memory is always paid for with bytes
    /// actually sent. A configured or pinned peer can always buffer one
    /// largest frame; other sessions share the rest, at most one largest frame
    /// or an equal share of the general slots per network group. The
    /// reservation also covers decoding and processing of that message and is
    /// released by the session's next frame or its close. Connections this
    /// node opened are bounded separately and never wait on inbound traffic.
    pub fn reserve_frame(&self, bytes: usize) -> Result<()> {
        if self.key.2 == Direction::Outbound {
            return Ok(());
        }
        let mut held = accounting(&self.reserved_frame);
        let mut memory = accounting(&self.guard.frame_memory);
        let bytes = bytes as u64;
        let (total, shared, group) = self.guard.frame_memory_limits();
        let group_fits = self.group.is_none_or(|g| {
            memory
                .groups
                .get(&g)
                .copied()
                .unwrap_or(0)
                .saturating_add(bytes)
                <= group
        });
        let fits = memory.total.saturating_add(bytes) <= total
            && (self.operator || (memory.shared.saturating_add(bytes) <= shared && group_fits));
        if !fits {
            return Err(Busy("peer frame memory budget exhausted").into());
        }
        memory.total += bytes;
        if !self.operator {
            memory.shared += bytes;
            if let Some(g) = self.group {
                *memory.groups.entry(g).or_default() += bytes;
            }
        }
        *held += bytes;
        Ok(())
    }
    fn release_frame(&self, memory: &mut FrameMemory, held: u64) {
        memory.total = memory.total.saturating_sub(held);
        if self.operator {
            return;
        }
        memory.shared = memory.shared.saturating_sub(held);
        if let Some(g) = self.group
            && let Some(count) = memory.groups.get_mut(&g)
        {
            *count = count.saturating_sub(held);
            if *count == 0 {
                memory.groups.remove(&g);
            }
        }
    }
    /// Mark an authorized Stratum worker. An address cooldown, which another
    /// session from a shared address can cause, then no longer ends this
    /// session's requests; its budgets still apply.
    pub fn authorize_worker(&self) {
        self.worker.store(true, Ordering::Relaxed);
    }
    /// Charge one line from an authorized Stratum worker. Within the session
    /// rate it is an ordinary request. Past it, the line draws on a separate
    /// overrun allowance and no address request unit, so one fast worker
    /// neither drains the budget of other sessions at its address nor is
    /// disconnected while its difficulty is raised. `Ok(false)` marks such a
    /// line. Bytes are always charged to the address.
    pub fn worker_line(&self, bytes: usize) -> Result<bool> {
        let now = Instant::now();
        let within = accounting(&self.request_bucket).take(
            1,
            SESSION_REQUESTS,
            SESSION_REQUEST_BURST,
            now,
        );
        if !within {
            let mut overrun = accounting(&self.overrun_bucket);
            ensure!(
                overrun.take(1, WORKER_OVERRUN, WORKER_OVERRUN_BURST, now),
                "mining session request rate limit"
            );
        }
        self.charge_address(u64::from(within), bytes as u64, 0, true, now)?;
        Ok(within)
    }
    fn charge(&self, requests: u64, bytes: u64, work: u64, penalize: bool) -> Result<()> {
        let now = Instant::now();
        if self.key.1 == Surface::Stratum && requests > 0 {
            let mut bucket = accounting(&self.request_bucket);
            ensure!(
                bucket.take(requests, SESSION_REQUESTS, SESSION_REQUEST_BURST, now),
                "mining session request rate limit"
            );
        }
        self.charge_address(requests, bytes, work, penalize, now)
    }
    fn charge_address(
        &self,
        requests: u64,
        bytes: u64,
        work: u64,
        penalize: bool,
        now: Instant,
    ) -> Result<()> {
        let mut records = accounting(&self.guard.records);
        // A visitor named by the proxy pays from its own record first, so one
        // past its share cannot spend the budget that all visitors share.
        for key in [self.visitor.get().copied(), Some(self.key)]
            .into_iter()
            .flatten()
        {
            let record = records
                .get_mut(&key)
                .expect("active sessions retain their accounting entry");
            if !self.worker.load(Ordering::Relaxed) && now < record.cooldown {
                self.refused.store(true, Ordering::Relaxed);
                let refusal = "temporary network cooldown";
                return Err(record.refusal(refusal, Some(Duration::ZERO), now));
            }
            let p = self.guard.key_policy(key);
            // The first bucket that refuses says when this charge fits again.
            let wait = if !record
                .requests
                .take(requests, p.requests, p.request_burst, now)
            {
                Some(record.requests.wait(requests, p.requests, p.request_burst))
            } else if !record.bytes.take(bytes, p.bytes, p.byte_burst, now) {
                Some(record.bytes.wait(bytes, p.bytes, p.byte_burst))
            } else if !record.work.take(work, p.work, p.work_burst, now) {
                Some(record.work.wait(work, p.work, p.work_burst))
            } else {
                None
            };
            if let Some(wait) = wait {
                self.refused.store(true, Ordering::Relaxed);
                if !penalize {
                    return Err(record.refusal("outgoing network budget exhausted", wait, now));
                }
                self.guard.penalize(key, record, now);
                return Err(record.refusal("network rate budget exhausted", wait, now));
            }
            record.last = now;
        }
        Ok(())
    }
    /// Only malformed framing/JSON and explicit resource violations trigger this.
    /// Ordinary stale transactions, unknown parents and competing forks do not.
    pub fn malformed(&self) {
        let key = self.visitor.get().copied().unwrap_or(self.key);
        if let Some(record) = accounting(&self.guard.records).get_mut(&key) {
            self.guard.penalize(key, record, Instant::now());
        }
    }
    /// A client broke HTTP framing or let its request deadline pass. This cools
    /// down a remote client or a visitor the proxy named, but never local
    /// software on loopback, and adds nothing to a refusal already accounted.
    pub fn framing_error(&self) {
        let key = self.visitor.get().copied().unwrap_or(self.key);
        if !self.refused.load(Ordering::Relaxed)
            && (key.2 == Direction::Forwarded || !key.0.is_loopback())
        {
            self.malformed();
        }
    }
    /// Whether this session comes from the public website's loopback proxy.
    pub fn proxied(&self) -> bool {
        self.guard.is_proxy(self.key)
    }
    /// Account the rest of a proxied session to the visitor its proxy named.
    /// That visitor's own record caps it, and the proxy's record still caps
    /// all visitors together.
    pub fn forwarded_for(&self, client: IpAddr) -> Result<()> {
        ensure!(self.proxied(), "only a public website proxy names visitors");
        let key = (admission_address(client), Surface::Rpc, Direction::Forwarded);
        let mut records = accounting(&self.guard.records);
        ensure!(self.visitor.get().is_none(), "visitor already named");
        if let Err(error) = self.guard.enter(&mut records, key, Instant::now()) {
            self.refused.store(true, Ordering::Relaxed);
            return Err(error);
        }
        self.visitor
            .set(key)
            .expect("the accounting lock serializes visitor naming");
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let mut records = accounting(&self.guard.records);
        for key in [Some(self.key), self.visitor.get().copied()]
            .into_iter()
            .flatten()
        {
            if let Some(record) = records.get_mut(&key) {
                record.active = record.active.saturating_sub(1);
            }
        }
        drop(records);
        let held = *self
            .reserved_frame
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        if held > 0 {
            let mut memory = accounting(&self.guard.frame_memory);
            self.release_frame(&mut memory, held);
        }
    }
}

/// How much an inbound source is trusted for capacity, least first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerClass {
    General,
    /// A discovery peer this node synchronized with during the last hour.
    /// Any remote can arrange that, so its network group stays capped.
    Verified,
    /// A configured or pinned peer address the operator chose.
    Operator,
}
#[derive(Default)]
struct SlotCounts {
    general: usize,
    verified: usize,
    operator: usize,
    /// Sessions per network group, and how many of them use verified slots.
    groups: HashMap<IpAddr, (usize, usize)>,
}
/// Inbound peer session capacity. Network groups have a concurrency cap.
/// While the general slots are full, configured and pinned peers keep slots
/// no other source can use, and recently verified discovery peers keep
/// separate slots, at most one per network group.
#[derive(Default)]
pub struct PeerSlots {
    counts: Mutex<SlotCounts>,
}
pub struct PeerSlot {
    slots: Arc<PeerSlots>,
    group: Option<IpAddr>,
    pool: PeerClass,
}
impl PeerSlots {
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, class: PeerClass) -> Option<PeerSlot> {
        // Only an operator-chosen address is exempt from network diversity.
        let group = (class != PeerClass::Operator)
            .then(|| network_group(ip))
            .flatten();
        let mut counts = accounting(&self.counts);
        let (sessions, verified) = group
            .and_then(|g| counts.groups.get(&g).copied())
            .unwrap_or_default();
        if sessions >= PEER_SLOTS_PER_GROUP {
            return None;
        }
        let pool = if counts.general < INBOUND_PEER_SLOTS {
            PeerClass::General
        } else if class == PeerClass::Verified
            && counts.verified < VERIFIED_PEER_SLOTS
            && verified == 0
        {
            PeerClass::Verified
        } else if class == PeerClass::Operator && counts.operator < RESERVED_PEER_SLOTS {
            PeerClass::Operator
        } else {
            return None;
        };
        match pool {
            PeerClass::General => counts.general += 1,
            PeerClass::Verified => counts.verified += 1,
            PeerClass::Operator => counts.operator += 1,
        }
        if let Some(group) = group {
            let entry = counts.groups.entry(group).or_default();
            entry.0 += 1;
            entry.1 += usize::from(pool == PeerClass::Verified);
        }
        Some(PeerSlot {
            slots: self.clone(),
            group,
            pool,
        })
    }
}
impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut counts = accounting(&self.slots.counts);
        let count = match self.pool {
            PeerClass::General => &mut counts.general,
            PeerClass::Verified => &mut counts.verified,
            PeerClass::Operator => &mut counts.operator,
        };
        *count = count.saturating_sub(1);
        if let Some(group) = self.group
            && let Some(entry) = counts.groups.get_mut(&group)
        {
            entry.0 = entry.0.saturating_sub(1);
            entry.1 = entry
                .1
                .saturating_sub(usize::from(self.pool == PeerClass::Verified));
            if entry.0 == 0 {
                counts.groups.remove(&group);
            }
        }
    }
}

struct PendingSource {
    active: usize,
    budget: Bucket,
}
#[derive(Default)]
struct PendingCounts {
    general: usize,
    reserved: usize,
    groups: HashMap<IpAddr, usize>,
    sources: HashMap<IpAddr, PendingSource>,
    trusted: HashMap<IpAddr, u64>,
    sequence: u64,
}
/// Stratum connections awaiting authorization. A source that has not recently
/// authorized pays for the time it holds a slot, and its public group has a
/// concurrency cap. Addresses that recently authorized are not charged and
/// keep reserved slots while the general slots are full.
#[derive(Default)]
pub struct StratumPending {
    counts: Mutex<PendingCounts>,
}
pub struct PendingSlot {
    pending: Arc<StratumPending>,
    address: IpAddr,
    group: Option<IpAddr>,
    reserved: bool,
    charged: bool,
    started: Instant,
    released: bool,
}
impl StratumPending {
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PendingSlot> {
        self.try_acquire_at(ip, Instant::now())
    }
    fn try_acquire_at(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Option<PendingSlot> {
        let address = admission_address(ip);
        let mut counts = accounting(&self.counts);
        let counts = &mut *counts;
        let slot = |group, reserved, charged| PendingSlot {
            pending: self.clone(),
            address,
            group,
            reserved,
            charged,
            started: now,
            released: false,
        };
        if counts.trusted.contains_key(&address) {
            let reserved = if counts.general < STRATUM_PENDING_SLOTS {
                false
            } else if counts.reserved < RESERVED_STRATUM_PENDING {
                true
            } else {
                return None;
            };
            if reserved {
                counts.reserved += 1;
            } else {
                counts.general += 1;
            }
            return Some(slot(None, reserved, false));
        }
        let group = pending_group(address);
        if counts.general >= STRATUM_PENDING_SLOTS
            || group.is_some_and(|g| {
                counts.groups.get(&g).copied().unwrap_or(0) >= STRATUM_PENDING_PER_GROUP
            })
        {
            return None;
        }
        if !counts.sources.contains_key(&address) {
            if counts.sources.len() >= MAX_TRACKED_IPS {
                // Forget the idle source with the most budget left, so new
                // records do not cheaply erase the charge of a recent one.
                let fullest = counts
                    .sources
                    .iter()
                    .filter(|(_, source)| source.active == 0)
                    .max_by_key(|(_, source)| {
                        source
                            .budget
                            .level(PENDING_REFILL_MS, PENDING_BUDGET_MS, now)
                    })
                    .map(|(address, _)| *address)?;
                counts.sources.remove(&fullest);
            }
            counts.sources.insert(
                address,
                PendingSource {
                    active: 0,
                    budget: Bucket::new(PENDING_BUDGET_MS, now),
                },
            );
        }
        let source = counts.sources.get_mut(&address)?;
        if !source
            .budget
            .take(PENDING_WINDOW_MS, PENDING_REFILL_MS, PENDING_BUDGET_MS, now)
        {
            return None;
        }
        source.active += 1;
        counts.general += 1;
        if let Some(group) = group {
            *counts.groups.entry(group).or_default() += 1;
        }
        Some(slot(group, false, true))
    }
}
impl PendingSlot {
    /// The session authorized. Its address may later wait uncharged and use
    /// reserved slots, and dropping this slot releases it.
    pub fn authorized(self) {
        let mut counts = accounting(&self.pending.counts);
        let counts = &mut *counts;
        if counts.trusted.len() >= STRATUM_TRUSTED_ADDRESSES
            && !counts.trusted.contains_key(&self.address)
            && let Some(oldest) = counts
                .trusted
                .iter()
                .min_by_key(|(_, sequence)| **sequence)
                .map(|(address, _)| *address)
        {
            counts.trusted.remove(&oldest);
        }
        counts.sequence += 1;
        counts.trusted.insert(self.address, counts.sequence);
    }
    #[cfg(test)]
    fn close_at(mut self, now: Instant) {
        self.release(now);
    }
    /// Release the slot and charge the time it was held to its source.
    fn release(&mut self, now: Instant) {
        if std::mem::replace(&mut self.released, true) {
            return;
        }
        let mut counts = accounting(&self.pending.counts);
        let counts = &mut *counts;
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
        if self.charged
            && let Some(source) = counts.sources.get_mut(&self.address)
        {
            source.active = source.active.saturating_sub(1);
            let held = now
                .duration_since(self.started)
                .as_millis()
                .min(PENDING_WINDOW_MS as u128) as u64;
            source.budget.give(
                PENDING_WINDOW_MS - held,
                PENDING_REFILL_MS,
                PENDING_BUDGET_MS,
                now,
            );
        }
    }
}
impl Drop for PendingSlot {
    fn drop(&mut self) {
        self.release(Instant::now());
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
    fn refusals_say_when_the_same_charge_fits_again() {
        let wait = |error: anyhow::Error| {
            let limited = error.downcast::<Limited>().expect("a quota refusal");
            (limited.reason, limited.retry_after)
        };
        let now = Instant::now();
        let mut bucket = Bucket::new(10, now);
        assert!(bucket.take(10, 4, 10, now));
        assert!(!bucket.take(3, 4, 10, now));
        assert_eq!(bucket.wait(3, 4, 10), Some(Duration::from_millis(750)));
        assert_eq!(bucket.wait(11, 4, 10), None);
        assert!(!bucket.take(3, 4, 10, now + Duration::from_millis(749)));
        assert!(bucket.take(3, 4, 10, now + Duration::from_millis(750)));

        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let session = guard.admit(ip, Surface::Rpc).unwrap();
        session.work(1_048_576).unwrap();
        // One second of refill is missing. The 250 ms cooldown the refusal
        // starts ends sooner, so the answer is when the charge fits again.
        let refused = Instant::now();
        let (reason, retry) = wait(session.work(131_072).unwrap_err());
        assert_eq!(reason, "network rate budget exhausted");
        let retry = retry.unwrap();
        assert!(
            retry > Duration::from_millis(900) && retry <= Duration::from_secs(1),
            "{retry:?}"
        );
        // A new connection during the cooldown is told when it ends.
        let (reason, retry) = wait(
            guard
                .admit_at(ip, Surface::Rpc, Direction::Inbound, refused)
                .err()
                .unwrap(),
        );
        assert_eq!(reason, "temporary network cooldown");
        let retry = retry.unwrap();
        assert!(
            retry > Duration::from_millis(200)
                && retry <= Duration::from_millis(250) + refused.elapsed(),
            "{retry:?}"
        );
        // A charge above the whole burst can never be admitted.
        let other = guard.admit("192.0.2.10".parse().unwrap(), Surface::Rpc);
        let (_, retry) = wait(other.unwrap().work(1_048_577).unwrap_err());
        assert_eq!(retry, None);
        // An exhausted reply budget says when to retry and starts no cooldown.
        let outbound = guard.admit_outbound(ip, Surface::Peer).unwrap();
        outbound.outgoing(0, 65_536).unwrap();
        let (reason, retry) = wait(outbound.outgoing(0, 16_384).unwrap_err());
        assert_eq!(reason, "outgoing network budget exhausted");
        assert!(retry.unwrap() <= Duration::from_secs(1));
        assert!(guard.admit_outbound(ip, Surface::Peer).is_ok());
    }
    #[test]
    fn refused_connections_are_answered_once_per_retry_window() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "192.0.2.12".parse().unwrap();
        let second = Duration::from_secs(1);
        let now = Instant::now();
        // Only an address the accounting table holds is answered.
        assert!(!guard.answer_refusal_at(ip, Surface::Rpc, second, now));
        drop(
            guard
                .admit_at(ip, Surface::Rpc, Direction::Inbound, now)
                .unwrap(),
        );
        assert!(guard.answer_refusal_at(ip, Surface::Rpc, second, now));
        // Attempts before the Retry-After it was given are closed unanswered;
        // one that waits as told is answered again.
        let early = now + Duration::from_millis(999);
        assert!(!guard.answer_refusal_at(ip, Surface::Rpc, second, early));
        assert!(guard.answer_refusal_at(ip, Surface::Rpc, second, now + second));
        // Windows are per address and service.
        drop(
            guard
                .admit_at(ip, Surface::Stratum, Direction::Inbound, now)
                .unwrap(),
        );
        assert!(guard.answer_refusal_at(ip, Surface::Stratum, second, early));
        // The public website's proxy speaks for many visitors: every refused
        // connection of its own is answered.
        let public = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        drop(
            public
                .admit_at(proxy, Surface::Rpc, Direction::Inbound, now)
                .unwrap(),
        );
        for _ in 0..3 {
            assert!(public.answer_refusal_at(proxy, Surface::Rpc, second, now));
        }
        let visitor: IpAddr = "192.0.2.13".parse().unwrap();
        drop(
            public
                .admit_at(visitor, Surface::Rpc, Direction::Inbound, now)
                .unwrap(),
        );
        assert!(public.answer_refusal_at(visitor, Surface::Rpc, second, now));
        assert!(!public.answer_refusal_at(visitor, Surface::Rpc, second, now));
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
        // The proxy carries the whole public pool for every visitor together.
        let held: Vec<_> = (0..PUBLIC_WEB_SESSIONS)
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
    fn proxy_named_visitors_spend_only_their_share_of_the_shared_budget() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let visitor = |client: &str| -> Result<Session> {
            let session = guard.admit(proxy, Surface::Rpc)?;
            session.forwarded_for(client.parse()?)?;
            Ok(session)
        };
        let share = (Surface::Rpc.policy().work_burst / PUBLIC_WEB_VISITOR_WORK_SHARE) as usize;
        let first = visitor("192.0.2.1").unwrap();
        assert!(first.work(share).is_ok());
        // A second share is refused by the visitor's own record, and the
        // refusal cools down only that visitor, never the proxy.
        assert!(first.work(share).is_err());
        assert!(visitor("192.0.2.1").is_err());
        assert!(guard.admit(proxy, Surface::Rpc).is_ok());
        // Eight full shares empty the budget all visitors share. A further
        // visitor is then refused without a cooldown of its own.
        let others: Vec<_> = (2..=8)
            .map(|n| visitor(&format!("192.0.2.{n}")).unwrap())
            .collect();
        for other in &others {
            assert!(other.work(share).is_ok());
        }
        let late = visitor("192.0.2.9").unwrap();
        assert!(late.work(share).is_err());
        drop(late);
        assert!(visitor("192.0.2.9").is_ok());
        // Unnamed proxy sessions, such as local tools, use the shared record.
        let unnamed = guard.admit(proxy, Surface::Rpc).unwrap();
        assert!(unnamed.work(share).is_err());
        assert!(unnamed.request().is_ok());
        // Only the proxy's own sessions may name a visitor.
        let client: IpAddr = "192.0.2.20".parse().unwrap();
        let direct = guard.admit("198.51.100.1".parse().unwrap(), Surface::Rpc);
        assert!(direct.unwrap().forwarded_for(client).is_err());
        let private = Arc::new(NetworkGuard::default());
        let local = private.admit(proxy, Surface::Rpc).unwrap();
        assert!(local.forwarded_for(client).is_err());
    }
    #[test]
    fn one_public_visitor_holds_only_a_browser_worth_of_sessions() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let name = |client: &str| -> Result<Session> {
            let session = guard.admit(proxy, Surface::Rpc)?;
            session.forwarded_for(client.parse()?)?;
            Ok(session)
        };
        // Addresses in one global IPv6 /64 are one visitor.
        let mut held: Vec<_> = (1..=PUBLIC_WEB_VISITOR_SESSIONS)
            .map(|n| name(&format!("2001:db8:5::{n}")).unwrap())
            .collect();
        let error = name("2001:db8:5::99").err().unwrap();
        assert_eq!(error.to_string(), "per-address connection limit");
        assert!(name("2001:db8:6::1").is_ok());
        held.pop();
        assert!(name("2001:db8:5::99").is_ok());
        // Direct remote clients have the same cap, below the public pool.
        let remote: IpAddr = "198.51.100.2".parse().unwrap();
        let direct: Vec<_> = (0..PUBLIC_WEB_VISITOR_SESSIONS)
            .map(|_| guard.admit(remote, Surface::Rpc).unwrap())
            .collect();
        assert!(guard.admit(remote, Surface::Rpc).is_err());
        drop(direct);
        // Released visitor sessions also release the proxy's.
        let more: Vec<_> = (held.len()..PUBLIC_WEB_SESSIONS)
            .map(|_| guard.admit(proxy, Surface::Rpc).unwrap())
            .collect();
        assert!(guard.admit(proxy, Surface::Rpc).is_err());
        drop((held, more));
        assert!(guard.admit(proxy, Surface::Rpc).is_ok());
    }
    #[test]
    fn framing_errors_cool_down_only_remote_clients_and_named_visitors() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let remote: IpAddr = "198.51.100.3".parse().unwrap();
        guard.admit(proxy, Surface::Rpc).unwrap().framing_error();
        assert!(guard.admit(proxy, Surface::Rpc).is_ok());
        guard.admit(remote, Surface::Rpc).unwrap().framing_error();
        assert!(guard.admit(remote, Surface::Rpc).is_err());
        // A loopback visitor named by the proxy has a record of its own.
        let local_visitor = guard.admit(proxy, Surface::Rpc).unwrap();
        local_visitor.forwarded_for(proxy).unwrap();
        local_visitor.framing_error();
        let later = guard.admit(proxy, Surface::Rpc).unwrap();
        assert!(later.forwarded_for(proxy).is_err());
        assert!(guard.admit(proxy, Surface::Rpc).is_ok());
        // Private loopback clients are local software and keep no cooldown.
        let private = Arc::new(NetworkGuard::default());
        private.admit(proxy, Surface::Rpc).unwrap().framing_error();
        assert!(private.admit(proxy, Surface::Rpc).is_ok());
        // A refusal is accounted once, not again as a framing error.
        let visitor = guard.admit(proxy, Surface::Rpc).unwrap();
        let client: IpAddr = "203.0.113.9".parse().unwrap();
        visitor.forwarded_for(client).unwrap();
        assert!(visitor.work(1_048_576).is_err());
        visitor.framing_error();
        let records = guard.records.lock().unwrap();
        assert_eq!(records[&(client, Surface::Rpc, Direction::Forwarded)].strikes, 1);
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
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        for local in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert_eq!(network_group(ip(local)), None, "{local}");
        }
        // Routable special ranges are grouped too: a 6to4 source with the
        // IPv4 /16 it embeds, and is accounted by its /48; Teredo and other
        // ranges conservatively by /32.
        assert_eq!(
            network_group(ip("2002:808:101::1")),
            network_group(ip("8.8.200.1"))
        );
        assert_eq!(
            admission_address(ip("2002:808:101:ffff::1")),
            admission_address(ip("2002:808:101:1::2"))
        );
        assert_ne!(
            admission_address(ip("2002:808:101::1")),
            admission_address(ip("2002:808:102::1"))
        );
        assert_eq!(
            network_group(ip("2001:0:4136:e378::1")),
            network_group(ip("2001:0:5ef5:79fd::1"))
        );
        assert!(network_group(ip("2001:0:4136:e378::1")).is_some());
        assert!(network_group(ip("192.0.2.1")).is_some());
        assert_eq!(peer_source(ip("10.1.2.3")), ip("10.1.2.3"));
        assert_eq!(peer_source(ip("8.8.1.1")), ip("8.8.0.0"));
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
        // Past the whole burst: refused without penalty, and no wait helps.
        let error = outbound.outgoing(0, 65_537).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Limited>(),
            Some(Limited {
                retry_after: None,
                ..
            })
        ));
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
    fn inbound_frame_memory_is_paid_for_and_keeps_an_operator_share() {
        const MIB: usize = 1024 * 1024;
        // Frames of up to 16 MiB: a 64 MiB budget, 48 MiB of it shared, and
        // at most one such frame per network group.
        let guard = Arc::new(NetworkGuard::with_frame_limit(16 * MIB));
        let public = |a: u8, b: u8| IpAddr::from([8, a, b, 1]);
        let first = guard.admit(public(1, 1), Surface::Peer).unwrap();
        first.begin_frame().unwrap();
        for _ in 0..16 {
            first.reserve_frame(MIB).unwrap();
        }
        let neighbour = guard.admit(public(1, 2), Surface::Peer).unwrap();
        assert!(neighbour.reserve_frame(1).unwrap_err().is::<Busy>());
        // Sessions in other groups that stall after one frame's bytes fill
        // the shared part; nobody else in it can buffer more.
        let stalled: Vec<_> = (2..=3)
            .map(|a| {
                let session = guard.admit(public(a, 1), Surface::Peer).unwrap();
                session.reserve_frame(16 * MIB).unwrap();
                session
            })
            .collect();
        let general = guard.admit(public(9, 1), Surface::Peer).unwrap();
        assert!(general.reserve_frame(1).unwrap_err().is::<Busy>());
        // A configured peer can still buffer one largest frame, even from a
        // group that already holds its own.
        let configured = guard.admit(public(1, 3), Surface::Peer).unwrap().operator();
        configured.reserve_frame(16 * MIB).unwrap();
        assert!(configured.reserve_frame(1).unwrap_err().is::<Busy>());
        // A session's next frame releases its previous reservation.
        first.begin_frame().unwrap();
        neighbour.reserve_frame(16 * MIB).unwrap();
        let outbound = guard.admit_outbound(public(9, 2), Surface::Peer).unwrap();
        outbound.reserve_frame(usize::MAX).unwrap();
        drop((first, neighbour, stalled, configured, outbound));
        general.reserve_frame(16 * MIB).unwrap();
        drop(general);
        let memory = guard.frame_memory.lock().unwrap();
        assert_eq!(
            (memory.total, memory.shared, memory.groups.len()),
            (0, 0, 0)
        );
        drop(memory);
        // Without a larger validated frame the 64 MiB baseline is shared.
        let local = Arc::new(NetworkGuard::default());
        let session = local
            .admit("127.0.0.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        session.reserve_frame(PEER_FRAME_MEMORY as usize).unwrap();
        assert!(session.reserve_frame(1).unwrap_err().is::<Busy>());
    }
    #[test]
    fn inbound_peer_slots_require_network_diversity_and_keep_reserved_capacity() {
        let slots = Arc::new(PeerSlots::default());
        let public = |a: u8, b: u8, c: u8| IpAddr::from([8, a, b, c]);
        // Two addresses in one public /16 hold at most two sessions.
        let same: Vec<_> = (1..=4)
            .filter_map(|n| slots.try_acquire(public(1, n, 1), PeerClass::General))
            .collect();
        assert_eq!(same.len(), 2);
        let ipv6 = |n: u16| IpAddr::from([0x2001, 0x4860, n, 0, 0, 0, 0, 1]);
        let v6: Vec<_> = (1..=3)
            .filter_map(|n| slots.try_acquire(ipv6(n), PeerClass::General))
            .collect();
        assert_eq!(v6.len(), 2);
        // Filling the general slots needs many distinct groups.
        let mut held = Vec::new();
        for group in 2..=7 {
            for host in 1..=2 {
                held.push(
                    slots
                        .try_acquire(public(group, host, 1), PeerClass::General)
                        .unwrap(),
                );
            }
        }
        assert!(
            slots
                .try_acquire(public(30, 1, 1), PeerClass::General)
                .is_none()
        );
        // Recently verified discovery peers remain group-capped and take at
        // most one verified slot per group, so verified addresses in one /16
        // gain nothing, and verified peers never use configured capacity.
        let verified: Vec<_> = (1..=8)
            .filter_map(|n| slots.try_acquire(public(30, n, 1), PeerClass::Verified))
            .collect();
        assert_eq!(verified.len(), 1);
        assert!(
            slots
                .try_acquire(public(1, 7, 1), PeerClass::Verified)
                .is_none()
        );
        let verified: Vec<_> = (31..=40)
            .filter_map(|group| slots.try_acquire(public(group, 1, 1), PeerClass::Verified))
            .chain(verified)
            .collect();
        assert_eq!(verified.len(), VERIFIED_PEER_SLOTS);
        // A configured or pinned peer still connects, without a group cap.
        let protected: Vec<_> = (1..=RESERVED_PEER_SLOTS)
            .map(|n| {
                slots
                    .try_acquire(public(1, 9, n as u8), PeerClass::Operator)
                    .unwrap()
            })
            .collect();
        assert!(
            slots
                .try_acquire(public(40, 1, 1), PeerClass::Operator)
                .is_none()
        );
        drop((protected, verified));
        drop(held);
        // Loopback and private sources keep per-address accounting only.
        let local: Vec<_> = (0..INBOUND_PEER_SLOTS - 4)
            .map(|_| {
                slots
                    .try_acquire("127.0.0.1".parse().unwrap(), PeerClass::General)
                    .unwrap()
            })
            .collect();
        assert_eq!(local.len(), INBOUND_PEER_SLOTS - 4);
        drop((same, local));
        let counts = slots.counts.lock().unwrap();
        assert_eq!(
            (counts.general, counts.verified, counts.operator),
            (2, 0, 0)
        );
        assert_eq!(counts.groups.len(), 1);
    }
    #[test]
    fn a_panic_during_accounting_never_disables_admission() {
        let guard = Arc::new(NetworkGuard::default());
        let slots = Arc::new(PeerSlots::default());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let session = guard.admit(ip, Surface::Peer).unwrap();
        session.reserve_frame(1024).unwrap();
        let slot = slots.try_acquire(ip, PeerClass::General).unwrap();
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
        session.begin_frame().unwrap();
        session.reserve_frame(2048).unwrap();
        drop(session);
        assert_eq!(accounting(&guard.frame_memory).total, 0);
        assert!(guard.admit(ip, Surface::Peer).is_ok());
        drop(slot);
        assert!(slots.try_acquire(ip, PeerClass::General).is_some());
        assert_eq!(accounting(&slots.counts).general, 0);
    }
    #[test]
    fn pending_stratum_sources_pay_for_waiting_however_they_close() {
        let pending = Arc::new(StratumPending::default());
        let now = Instant::now();
        let ip: IpAddr = "8.1.1.1".parse().unwrap();
        // A fresh source may wait in four slots at once.
        let held: Vec<_> = (0..4)
            .map(|_| pending.try_acquire_at(ip, now).unwrap())
            .collect();
        assert!(pending.try_acquire_at(ip, now).is_none());
        // Closing cleanly just before the window ends costs nearly the whole
        // window, so rotating sockets cannot hold slots for free.
        let closed = now + Duration::from_millis(9_900);
        for slot in held {
            slot.close_at(closed);
        }
        assert!(pending.try_acquire_at(ip, closed).is_none());
        let refilled = now + Duration::from_secs(20);
        let one = pending.try_acquire_at(ip, refilled).unwrap();
        assert!(pending.try_acquire_at(ip, refilled).is_none());
        one.close_at(refilled);
        // Prompt authorizations cost only their short wait.
        let honest: IpAddr = "8.1.2.1".parse().unwrap();
        for attempt in 0..16u64 {
            let start = now + Duration::from_millis(200 * attempt);
            pending
                .try_acquire_at(honest, start)
                .unwrap()
                .close_at(start + Duration::from_millis(200));
        }
        let later = now + Duration::from_millis(3_200);
        let concurrent: Vec<_> = (0..3)
            .map(|_| pending.try_acquire_at(honest, later).unwrap())
            .collect();
        for slot in concurrent {
            slot.close_at(later);
        }
        let counts = pending.counts.lock().unwrap();
        assert_eq!((counts.general, counts.reserved), (0, 0));
        assert!(counts.groups.is_empty());
    }
    #[test]
    fn pending_stratum_groups_are_capped_and_recent_workers_keep_reserved_slots() {
        let pending = Arc::new(StratumPending::default());
        let now = Instant::now();
        let v4 = |c: u8, d: u8| IpAddr::from([8, 1, c, d]);
        // An operator's address authorizes once while capacity is available.
        let worker = v4(200, 1);
        pending.try_acquire_at(worker, now).unwrap().authorized();
        // Four addresses in one public /24 share eight slots.
        let mut held = Vec::new();
        for host in 1..=4 {
            for _ in 0..4 {
                held.extend(pending.try_acquire_at(v4(1, host), now));
            }
        }
        assert_eq!(held.len(), STRATUM_PENDING_PER_GROUP);
        // Fresh /64s inside one public /48 share them too.
        let v6 = |n: u16| IpAddr::from([0x2001, 0x4860, 7, n, 0, 0, 0, 1]);
        let mut prefixes = Vec::new();
        for n in 1..=12 {
            prefixes.extend(pending.try_acquire_at(v6(n), now));
        }
        assert_eq!(prefixes.len(), STRATUM_PENDING_PER_GROUP);
        held.extend(prefixes);
        // Filling the general slots takes sixteen distinct groups.
        for group in 2..=15 {
            for host in 1..=2 {
                for _ in 0..4 {
                    held.push(pending.try_acquire_at(v4(group, host), now).unwrap());
                }
            }
        }
        assert_eq!(held.len(), STRATUM_PENDING_SLOTS);
        assert!(pending.try_acquire_at(v4(99, 1), now).is_none());
        // The address that authorized still connects, uncharged and outside
        // the group cap, through the reserved slots.
        let reserved: Vec<_> = (0..RESERVED_STRATUM_PENDING)
            .map(|_| pending.try_acquire_at(worker, now).unwrap())
            .collect();
        assert!(pending.try_acquire_at(worker, now).is_none());
        held.pop().unwrap().close_at(now);
        assert!(pending.try_acquire_at(v4(99, 1), now).is_some());
        drop((held, reserved));
        let counts = pending.counts.lock().unwrap();
        assert_eq!((counts.general, counts.reserved), (0, 0));
        assert!(counts.groups.is_empty());
        assert!(counts.sources.values().all(|source| source.active == 0));
    }
    #[test]
    fn authorized_workers_outlast_address_cooldowns_and_throttle_past_their_rate() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let worker = guard.admit(ip, Surface::Stratum).unwrap();
        worker.authorize_worker();
        let other = guard.admit(ip, Surface::Stratum).unwrap();
        other.malformed();
        // A cooldown from another session at the address refuses new
        // connections and unauthenticated requests, not the worker.
        assert!(guard.admit(ip, Surface::Stratum).is_err());
        assert!(other.request().is_err());
        assert!(worker.worker_line(100).unwrap());
        assert!(worker.work(1).is_ok());
        // Past its session rate a worker is throttled rather than refused
        // until its overrun allowance runs out.
        let (mut within, mut throttled) = (1, 0);
        let error = loop {
            match worker.worker_line(100) {
                Ok(true) => within += 1,
                Ok(false) => throttled += 1,
                Err(error) => break error,
            }
        };
        assert!(error.to_string().contains("session request rate limit"));
        assert!((16..=18).contains(&within), "{within}");
        assert!((64..=67).contains(&throttled), "{throttled}");
        // Throttled lines spend no address request units and the overrun
        // never penalizes the address.
        let records = guard.records.lock().unwrap();
        let record = &records[&(ip, Surface::Stratum, Direction::Inbound)];
        assert!(record.requests.tokens >= 64 - 2 - within as u64);
        assert_eq!(record.strikes, 1);
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
