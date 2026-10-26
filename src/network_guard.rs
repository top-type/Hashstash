//! Local admission policy. These limits never change block or transaction validity.
use anyhow::{Context, Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

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
/// grows to at least one largest validated frame for configured and pinned
/// peers plus one for each of half the general slots' network groups.
pub const PEER_FRAME_MEMORY: u64 = 64 * 1024 * 1024;
/// An inbound frame that holds more than this much shared frame memory must
/// keep arriving: at least `FRAME_PROGRESS_BYTES` in every
/// `FRAME_PROGRESS_WINDOW` (64 KiB/s), or it is closed without a cooldown.
pub const FRAME_PROGRESS_HOLD: u64 = 1024 * 1024;
pub const FRAME_PROGRESS_BYTES: u64 = 128 * 1024;
pub const FRAME_PROGRESS_WINDOW: Duration = Duration::from_secs(2);
/// Inbound peer sessions open to any source. When they are full, configured
/// or pinned peers have their own reserved slots, and discovery peers verified
/// in the last hour have separate ones that remain subject to group caps.
/// Any other newcomer takes over an unprotected general slot instead.
pub const INBOUND_PEER_SLOTS: usize = 16;
pub const RESERVED_PEER_SLOTS: usize = 4;
pub const VERIFIED_PEER_SLOTS: usize = 4;
/// Concurrent inbound sessions from one network group (IPv4 /16, IPv6 /32)
/// within its cap. While general slots are free, a newcomer from a group at
/// its cap whose address holds none of the group's sessions takes one beyond
/// the cap; once they are full, such sessions are the first taken over.
pub const PEER_SLOTS_PER_GROUP: usize = 2;
/// A newcomer never takes over the slot of a session admitted less than this
/// long ago, one ordinary peer read allowance, so an honest session has time
/// to finish its exchange before sources that keep reconnecting can displace
/// it. Only an address holding more of its group's sessions than a
/// newcomer from that group gives one up sooner, and so does a session its
/// group holds beyond its cap once the general slots are full.
pub const EVICTION_GRACE: Duration = Duration::from_secs(15);
/// A source that delivered a new valid block or transaction keeps its general
/// inbound sessions from eviction this long. Eviction spares at most
/// `PROTECTED_USEFUL` such sessions, the most recent deliverers, the oldest
/// session of `PROTECTED_GROUPS` network groups ranked by a key no source
/// knows, and `PROTECTED_LONGEST` of the longest-connected others, and never
/// so many that fewer than `EVICTABLE_GENERAL` sessions other than configured
/// or pinned peers remain candidates.
pub const USEFUL_PEER_WINDOW: Duration = Duration::from_secs(600);
const USEFUL_PEER_SOURCES: usize = 256;
const PROTECTED_USEFUL: usize = 4;
const PROTECTED_GROUPS: usize = 4;
const PROTECTED_LONGEST: usize = 4;
const EVICTABLE_GENERAL: usize = INBOUND_PEER_SLOTS / 4;
/// Stratum connections awaiting authorization that any source may use, plus
/// slots that only addresses which recently authorized may use when those are full.
pub const STRATUM_PENDING_SLOTS: usize = 128;
pub const RESERVED_STRATUM_PENDING: usize = 32;
/// Concurrent pending Stratum sessions from one group (IPv4 /24, IPv6 /48)
/// whose addresses have not recently authorized.
pub const STRATUM_PENDING_PER_GROUP: usize = 8;
/// Addresses remembered after a successful Stratum authorization.
pub const STRATUM_TRUSTED_ADDRESSES: usize = 256;
/// A saved trusted-address file larger than this is ignored.
const STRATUM_TRUSTED_FILE_BYTES: u64 = 64 * 1024;
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
/// Every member address is charged together with one aggregate record for its
/// wider prefix: an IPv4 /24, a native IPv6 /48, the IPv4 /24 a 6to4 source
/// embeds and, on RPC, all of loopback. An aggregate has this many times a
/// member's connection, request, byte and work budgets, so the holder of a
/// whole prefix gets at most that many address budgets, not one per address
/// or /64. Other local networks keep per-address records only.
pub const AGGREGATE_SHARE: u64 = 4;
/// Distinct members of an aggregate penalized within a minute after which
/// the aggregate cools down, escalating as one address does with each further
/// penalty. Loopback's aggregate never cools down: local software must not
/// lock out the operator.
const AGGREGATE_STRIKES: usize = 4;
/// Public website sessions in total. A loopback reverse proxy may carry all of
/// them; one visitor, connecting directly or named by that proxy, may hold
/// only a browser's six parallel connections and a share of the request,
/// byte and work budgets.
pub const PUBLIC_WEB_SESSIONS: usize = 32;
pub const PUBLIC_WEB_VISITOR_SESSIONS: usize = 6;
/// A visitor's share is one over the number of visitor shares active in the
/// last `PUBLIC_WEB_VISITOR_ACTIVITY`, kept between these bounds, so a few
/// addresses cannot take the whole budget while many are active. A network
/// counts one share per active address, up to the `AGGREGATE_SHARE` its
/// aggregate may spend. The count is recomputed at most once per
/// `PUBLIC_WEB_SHARE_REFRESH`, not on every charge.
const PUBLIC_WEB_VISITOR_SHARE: u64 = 8;
const PUBLIC_WEB_MAX_VISITOR_SHARE: u64 = 32;
const PUBLIC_WEB_VISITOR_ACTIVITY: Duration = Duration::from_secs(10);
const PUBLIC_WEB_SHARE_REFRESH: Duration = Duration::from_millis(100);
/// One over this much of the proxy's request, work and byte bursts is kept
/// for wallet-critical calls: other calls must leave it in the bucket. The
/// proxy's request refill is this much above what visitors' shares together
/// refill, because every call spends request units before it is known.
const PUBLIC_WEB_ESSENTIAL_SHARE: u64 = 4;
/// A public reply whose method price is flat, such as an explorer read, pays
/// one work unit per this many bytes it returns. Public work bursts admit the
/// work of one largest reply.
pub const REPLY_BYTES_PER_WORK: u64 = 1024;

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
/// A record for one admission address, or the aggregate of its prefix.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
enum Scope {
    Address,
    Aggregate,
}
type Key = (IpAddr, Surface, Direction, Scope);

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
/// The address with only its first `bits` bits kept.
fn masked(ip: IpAddr, bits: u32) -> IpAddr {
    match ip {
        IpAddr::V4(v) => IpAddr::V4(Ipv4Addr::from(
            u32::from(v) & u32::MAX.checked_shl(32 - bits.min(32)).unwrap_or(0),
        )),
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(
            u128::from(v) & u128::MAX.checked_shl(128 - bits.min(128)).unwrap_or(0),
        )),
    }
}
/// IPv4-mapped IPv6 addresses are the IPv4 address.
fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    }
}
/// Admission identity. IPv4-mapped addresses share the IPv4 record, a 6to4
/// source is accounted by the /48 its IPv4 host controls, and another global
/// IPv6 host by its /64 because it normally controls one.
pub fn admission_address(ip: IpAddr) -> IpAddr {
    match unmapped(ip) {
        IpAddr::V6(v) if v.segments()[0] == 0x2002 => masked(IpAddr::V6(v), 48),
        IpAddr::V6(v) if (v.segments()[0] & 0xe000) == 0x2000 => masked(IpAddr::V6(v), 64),
        ip => ip,
    }
}
/// The prefix whose members share one aggregate record with this admission
/// address on `surface`, if any: IPv4 /24, native IPv6 /48, for a 6to4 /48
/// the IPv4 /24 it embeds, shared with that IPv4 network, and all of loopback
/// on RPC. Other local networks keep per-address accounting alone.
fn aggregate_prefix(ip: IpAddr, surface: Surface) -> Option<IpAddr> {
    if ip.is_loopback() {
        return (surface == Surface::Rpc).then_some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
    if local_source(ip) {
        return None;
    }
    Some(match ip {
        IpAddr::V4(_) => masked(ip, 24),
        IpAddr::V6(v) if v.segments()[0] == 0x2002 => {
            let [a, b] = v.segments()[1].to_be_bytes();
            let [c, _] = v.segments()[2].to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(a, b, c, 0))
        }
        IpAddr::V6(_) => masked(ip, 48),
    })
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
        IpAddr::V4(_) => masked(ip, 16),
        IpAddr::V6(v) if v.segments()[0] == 0x2002 => {
            let [a, b] = v.segments()[1].to_be_bytes();
            IpAddr::V4(Ipv4Addr::new(a, b, 0, 0))
        }
        IpAddr::V6(_) => masked(ip, 32),
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
        IpAddr::V4(_) => masked(ip, 24),
        IpAddr::V6(_) => masked(ip, 48),
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
impl Policy {
    fn scaled(self, factor: u64) -> Self {
        Self {
            connections: self
                .connections
                .saturating_mul(usize::try_from(factor).unwrap_or(usize::MAX)),
            requests: self.requests.saturating_mul(factor),
            request_burst: self.request_burst.saturating_mul(factor),
            bytes: self.bytes.saturating_mul(factor),
            byte_burst: self.byte_burst.saturating_mul(factor),
            work: self.work.saturating_mul(factor),
            work_burst: self.work_burst.saturating_mul(factor),
        }
    }
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
    /// When a connection or charge of this record was last admitted.
    admitted: Option<Instant>,
    cooldown: Instant,
    /// Until when a connection refused before its session started goes
    /// unanswered, because this address was already told when to return.
    answered_until: Instant,
    strikes: u32,
    /// When this record was last penalized. Its strikes lapse after a minute
    /// without a penalty, however busy it stays meanwhile.
    penalized: Instant,
    /// When an aggregate last took a strike, and its distinct members
    /// penalized since a minute without strikes, up to `AGGREGATE_STRIKES`.
    struck: Instant,
    members: Vec<IpAddr>,
    requests: Bucket,
    bytes: Bucket,
    work: Bucket,
}
impl Record {
    fn new(p: Policy, now: Instant) -> Self {
        Self {
            active: 0,
            last: now,
            admitted: None,
            cooldown: now,
            answered_until: now,
            strikes: 0,
            penalized: now,
            struck: now,
            members: Vec::new(),
            requests: Bucket::new(p.request_burst, now),
            bytes: Bucket::new(p.byte_burst, now),
            work: Bucket::new(p.work_burst, now),
        }
    }
    fn penalize(&mut self, now: Instant) {
        if now.saturating_duration_since(self.penalized) > Duration::from_secs(60) {
            self.strikes = 0;
        }
        self.strikes = self.strikes.saturating_add(1).min(7);
        self.penalized = now;
        self.last = now;
        self.cooldown = now + Duration::from_millis((250u64 << (self.strikes - 1)).min(16_000));
    }
    /// An aggregate's `member` was penalized, or was refused because the
    /// members together exhausted one of the aggregate's budgets. Once enough
    /// distinct members did so within a minute, never one member alone, the
    /// whole prefix cools down, escalating with each further strike from 250
    /// milliseconds to 16 seconds as for one address.
    fn strike(&mut self, member: IpAddr, now: Instant) {
        if now.duration_since(self.struck) > Duration::from_secs(60) {
            self.strikes = 0;
            self.members.clear();
        }
        self.struck = now;
        if self.members.len() < AGGREGATE_STRIKES {
            if !self.members.contains(&member) {
                self.members.push(member);
            }
            if self.members.len() < AGGREGATE_STRIKES {
                return;
            }
        }
        self.strikes = self.strikes.saturating_add(1).min(7);
        self.cooldown = now + Duration::from_millis((250u64 << (self.strikes - 1)).min(16_000));
    }
    /// A refusal that a bucket's `wait` describes, after any cooldown it set.
    fn refusal(&self, reason: &'static str, wait: Option<Duration>, now: Instant) -> anyhow::Error {
        let cooling = self.cooldown.saturating_duration_since(now);
        limited(reason, wait.map(|wait| wait.max(cooling)))
    }
}
/// Peer frames decoded at once, inbound or outbound: each builds its decoded
/// message beside the frame's bytes. The node runs this many peer parsers.
pub const PEER_DECODERS: usize = 2;
/// Incoming frame bytes buffered by inbound sessions.
#[derive(Default)]
struct FrameMemory {
    total: u64,
    /// Held by sessions other than configured or pinned peers.
    shared: u64,
    /// Shared bytes held by each network group.
    groups: HashMap<IpAddr, u64>,
    /// Frames being decoded, whose messages are built beside their bytes.
    decoding: u64,
}
/// A frame being decoded (`Session::decoding`); dropping it ends that.
pub struct FrameDecoding {
    guard: Arc<NetworkGuard>,
    bytes: u64,
}
impl Drop for FrameDecoding {
    fn drop(&mut self) {
        let mut memory = accounting(&self.guard.frame_memory);
        memory.decoding = memory.decoding.saturating_sub(self.bytes);
    }
}
#[derive(Default)]
pub struct NetworkGuard {
    max_frame_bytes: AtomicU64,
    max_peer_work: AtomicU64,
    /// The work of one largest valid RPC request at the current capacity.
    max_rpc_work: AtomicU64,
    loopback_rpc_is_proxy: bool,
    records: Mutex<HashMap<Key, Record>>,
    /// The public website's visitor share and when it was computed.
    share_cache: Mutex<Option<(Instant, u64)>>,
    frame_memory: Mutex<FrameMemory>,
}
pub struct Session {
    guard: Arc<NetworkGuard>,
    key: Key,
    /// The aggregate record charged together with `key`, if any.
    aggregate: Option<Key>,
    group: Option<IpAddr>,
    /// A configured or pinned peer, which may use the whole frame budget.
    operator: bool,
    /// The public website visitor the proxy named for this session, and its
    /// aggregate, if any.
    visitor: OnceLock<(Key, Option<Key>)>,
    /// A quota already refused this session and accounted for it.
    refused: AtomicBool,
    /// Charges from now on are for a public call that is not wallet-critical,
    /// so they leave the proxy's essential reserve in place.
    nonessential: AtomicBool,
    request_bucket: Mutex<Bucket>,
    overrun_bucket: Mutex<Bucket>,
    worker: AtomicBool,
    /// An authorized Stratum worker from an operator-trusted prefix: it no
    /// longer counts toward its address's or network's connections and pays
    /// only its own session limits.
    released: AtomicBool,
    reserved_frame: Mutex<u64>,
    /// Inbound frames begun by this session.
    frames: AtomicU64,
}
impl NetworkGuard {
    /// A loopback reverse proxy represents many public visitors. Keep its
    /// aggregate quotas, but never turn one malformed visitor into an IP ban
    /// of the whole website. Direct remote clients retain normal cooldowns.
    /// Visitors, direct or named by the proxy, also have their own smaller
    /// session caps and a share of its other budgets, so one cannot take the
    /// whole website, and wallet-critical calls keep a reserve of it.
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
    fn policy_at(&self, surface: Surface, frame: u64) -> Policy {
        let mut policy = surface.policy();
        if surface != Surface::Stratum {
            policy.byte_burst = policy.byte_burst.max(frame);
        }
        if surface == Surface::Peer {
            policy.work_burst = policy
                .work_burst
                .max(self.max_peer_work.load(Ordering::Relaxed));
            // One synchronization session charges one address record for a
            // largest frame each way, its reply and its push, and a peer
            // synchronizes about once a second. Once two such frames exceed
            // the baseline, the record's burst holds both and its refill
            // rate renews them every second, so honest peers keep up with
            // the governed capacity.
            let session = frame.saturating_mul(2);
            policy.bytes = policy.bytes.max(session);
            policy.byte_burst = policy.byte_burst.max(session);
        }
        if surface == Surface::Rpc {
            policy.work_burst = policy
                .work_burst
                .max(self.max_rpc_work.load(Ordering::Relaxed));
        }
        policy
    }
    #[cfg(test)]
    fn policy(&self, surface: Surface) -> Policy {
        self.policy_at(surface, self.max_frame_bytes.load(Ordering::Relaxed))
    }
    /// The loopback reverse proxy's own record on the public-web guard.
    fn is_proxy(&self, key: Key) -> bool {
        self.loopback_rpc_is_proxy
            && key.1 == Surface::Rpc
            && key.2 == Direction::Inbound
            && key.3 == Scope::Address
            && key.0.is_loopback()
    }
    /// The aggregate record charged together with a member's, if any. The
    /// proxy is itself the record all its visitors share, and connections
    /// this node opens are its own choice.
    fn aggregate_of(&self, key: Key) -> Option<Key> {
        if key.3 == Scope::Aggregate || key.2 == Direction::Outbound || self.is_proxy(key) {
            return None;
        }
        aggregate_prefix(key.0, key.1).map(|prefix| (prefix, key.1, key.2, Scope::Aggregate))
    }
    /// The proxy's request, byte and work reserve for wallet-critical calls.
    fn essential_reserve() -> (u64, u64, u64) {
        let base = Surface::Rpc.policy();
        (
            base.request_burst / PUBLIC_WEB_ESSENTIAL_SHARE,
            base.byte_burst / PUBLIC_WEB_ESSENTIAL_SHARE,
            base.work_burst / PUBLIC_WEB_ESSENTIAL_SHARE,
        )
    }
    /// A visitor's share of the proxy's budgets: one over the number of
    /// visitor shares (named or direct) holding a session or admitted in the
    /// last ten seconds, within bounds. Each such address is one share, and
    /// the addresses of one /24 or /48 count at most the four shares their
    /// aggregate may spend, so visitors' refill rates together stay within
    /// the proxy's while at most 32 shares are active, and the many addresses
    /// of one prefix cannot shrink everyone else's share further. An attempt
    /// that admission refused counts not at all. The share is reused for
    /// `PUBLIC_WEB_SHARE_REFRESH`, so a charge does not scan the table each
    /// time. Unused on the private guard.
    fn visitor_share(&self, records: &HashMap<Key, Record>, now: Instant) -> u64 {
        if !self.loopback_rpc_is_proxy {
            return PUBLIC_WEB_VISITOR_SHARE;
        }
        let mut cached = accounting(&self.share_cache);
        if let Some((at, share)) = *cached
            && now >= at
            && now.duration_since(at) < PUBLIC_WEB_SHARE_REFRESH
        {
            return share;
        }
        let share = self.count_visitor_shares(records, now);
        *cached = Some((now, share));
        share
    }
    /// The visitor share as of `now`, counted afresh.
    fn count_visitor_shares(&self, records: &HashMap<Key, Record>, now: Instant) -> u64 {
        let mut members: HashMap<Key, u64> = HashMap::new();
        let mut shares = 0u64;
        for (key, record) in records {
            let active = record.active > 0
                || record.admitted.is_some_and(|at| {
                    now.saturating_duration_since(at) < PUBLIC_WEB_VISITOR_ACTIVITY
                });
            if key.1 != Surface::Rpc || key.3 != Scope::Address || self.is_proxy(*key) || !active {
                continue;
            }
            match self.aggregate_of(*key) {
                Some(aggregate) => {
                    let counted = members.entry(aggregate).or_default();
                    if *counted < AGGREGATE_SHARE {
                        *counted += 1;
                        shares += 1;
                    }
                }
                None => shares += 1,
            }
        }
        shares.clamp(PUBLIC_WEB_VISITOR_SHARE, PUBLIC_WEB_MAX_VISITOR_SHARE)
    }
    fn key_policy_at(&self, key: Key, share: u64, frame: u64) -> Policy {
        let mut policy = self.policy_at(key.1, frame);
        if self.loopback_rpc_is_proxy && key.1 == Surface::Rpc {
            let base = Surface::Rpc.policy();
            // The work one largest public reply pays for its bytes, and the
            // work one largest request, such as a broadcast, is charged.
            let reply_work = frame / REPLY_BYTES_PER_WORK;
            let largest_work = reply_work.max(self.max_rpc_work.load(Ordering::Relaxed));
            if self.is_proxy(key) {
                policy.connections = PUBLIC_WEB_SESSIONS;
                // Visitors' shares together refill at most the base request
                // rate, so the reserve above it stays for calls that every
                // request pays before it is known. One largest reply or
                // request still fits above the essential reserve.
                let (requests, bytes, work) = Self::essential_reserve();
                policy.requests = base
                    .requests
                    .saturating_add(base.requests / PUBLIC_WEB_ESSENTIAL_SHARE);
                policy.request_burst = base.request_burst.saturating_add(requests);
                policy.byte_burst = base.byte_burst.max(frame.saturating_add(bytes));
                policy.work_burst = base.work_burst.max(largest_work.saturating_add(work));
            } else {
                // Refill rates are the visitor's current share. Bursts stay
                // an eighth whatever the share, and still admit one largest
                // reply's bytes and work and one largest request's work, so
                // how many others are active changes how long a call waits,
                // never whether it can fit. Only wallet-critical calls may
                // spend the work burst beyond the ordinary one
                // (`essential_work_at`).
                let burst = PUBLIC_WEB_VISITOR_SHARE;
                policy.connections = PUBLIC_WEB_VISITOR_SESSIONS;
                policy.requests = (base.requests / share).max(1);
                policy.request_burst = (base.request_burst / burst).max(1);
                policy.bytes = (base.bytes / share).max(1);
                policy.byte_burst = (base.byte_burst / burst).max(frame);
                policy.work = (base.work / share).max(1);
                policy.work_burst = Self::ordinary_visitor_work(frame).max(largest_work);
            }
        }
        if key.3 == Scope::Aggregate {
            policy = policy.scaled(AGGREGATE_SHARE);
        }
        policy
    }
    fn key_policy(&self, key: Key, share: u64) -> Policy {
        self.key_policy_at(key, share, self.max_frame_bytes.load(Ordering::Relaxed))
    }
    /// A public visitor's ordinary work burst: an eighth of the base, and at
    /// least the work one largest reply pays for its bytes.
    fn ordinary_visitor_work(frame: u64) -> u64 {
        (Surface::Rpc.policy().work_burst / PUBLIC_WEB_VISITOR_SHARE)
            .max(frame / REPLY_BYTES_PER_WORK)
    }
    /// The top of a public visitor's (or its aggregate's) work burst `p`
    /// that only wallet-critical calls may spend: what the allowance for one
    /// largest request, such as a broadcast of a largest transaction, adds
    /// to the ordinary burst. Other calls, such as explorer and governance
    /// reads, leave it, so one visitor's share of them stays what it was
    /// before governance raised capacity, about a tenth of the proxy's pool
    /// at the governed maximum, however large that allowance grows. Zero for
    /// the proxy's own record and on the private guard.
    fn essential_work_at(&self, key: Key, p: &Policy, frame: u64) -> u64 {
        if !self.loopback_rpc_is_proxy || key.1 != Surface::Rpc || self.is_proxy(key) {
            return 0;
        }
        let ordinary = Self::ordinary_visitor_work(frame);
        let ordinary = match key.3 {
            Scope::Address => ordinary,
            Scope::Aggregate => ordinary.saturating_mul(AGGREGATE_SHARE),
        };
        p.work_burst.saturating_sub(ordinary)
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
        for (key, record) in records.iter_mut() {
            if key.1 == Surface::Peer {
                let factor = if key.3 == Scope::Aggregate {
                    AGGREGATE_SHARE
                } else {
                    1
                };
                let old = base.max(previous).saturating_mul(factor);
                let new = base.max(maximum).saturating_mul(factor);
                record.work.tokens = record.work.tokens.saturating_add(new - old).min(new);
            }
        }
        Ok(())
    }
    /// The work of one largest valid RPC request, such as the broadcast of a
    /// largest transaction at a governed capacity, must remain admissible:
    /// every RPC work burst, a public visitor's and the proxy's above its
    /// reserve included, grows to at least `maximum`. A request within the
    /// governed transaction size is then never refused as larger than a
    /// whole burst, which would also penalize its sender. Like the peer
    /// allowance it only grows; refill rates do not change.
    pub fn allow_rpc_work(&self, maximum: usize) -> Result<()> {
        let maximum = u64::try_from(maximum)?;
        if maximum <= self.max_rpc_work.load(Ordering::Relaxed) {
            return Ok(());
        }
        let mut records = accounting(&self.records);
        let share = self.visitor_share(&records, Instant::now());
        let old: Vec<(Key, u64)> = records
            .keys()
            .filter(|key| key.1 == Surface::Rpc)
            .map(|key| (*key, self.key_policy(*key, share).work_burst))
            .collect();
        if maximum <= self.max_rpc_work.fetch_max(maximum, Ordering::Relaxed) {
            return Ok(());
        }
        for (key, old) in old {
            let new = self.key_policy(key, share).work_burst;
            let record = records
                .get_mut(&key)
                .expect("held under the accounting lock");
            record.work.tokens = record
                .work
                .tokens
                .saturating_add(new.saturating_sub(old))
                .min(new);
        }
        Ok(())
    }
    /// The node-wide budget for buffered frames; the part that sessions
    /// other than configured or pinned peers may share, which leaves one
    /// largest frame to those peers; and one network group's limit within
    /// that share. Half the general slots' groups can each buffer one largest
    /// frame at once, so one group can hold at most a quarter of the shared
    /// part. The whole frame memory budget also keeps one largest frame for
    /// each of the PEER_DECODERS frames being decoded, whose messages are
    /// built beside their buffered bytes: that reserve is not part of the
    /// buffered budget returned here.
    fn frame_memory_limits(&self) -> (u64, u64, u64) {
        let (total, decoding) = self.frame_memory_budget();
        let frame = self.max_frame_bytes.load(Ordering::Relaxed);
        let groups = (INBOUND_PEER_SLOTS / PEER_SLOTS_PER_GROUP) as u64;
        let buffered = total.saturating_sub(decoding);
        let shared = buffered.saturating_sub(frame);
        (buffered, shared, frame.max(shared / groups))
    }
    /// The whole frame memory budget and its reserve for decoding frames.
    fn frame_memory_budget(&self) -> (u64, u64) {
        let frame = self.max_frame_bytes.load(Ordering::Relaxed);
        let groups = (INBOUND_PEER_SLOTS / PEER_SLOTS_PER_GROUP) as u64;
        let decoding = frame.saturating_mul(PEER_DECODERS as u64);
        let total = PEER_FRAME_MEMORY.max(
            frame
                .saturating_mul(groups / 2 + 1)
                .saturating_add(decoding),
        );
        (total, decoding)
    }
    /// The current largest validated frame, which sets the one-frame byte
    /// burst, the peer byte burst and refill of two frames, and the frame
    /// memory budget. An increase extends existing records' bursts at once;
    /// a decrease lowers them again, clamping records' byte tokens to the
    /// new bursts. Other throughput, connection, request and work quotas
    /// remain local policy.
    pub fn set_frame(&self, maximum: usize) -> Result<()> {
        let maximum = u64::try_from(maximum)?;
        let previous = self.max_frame_bytes.swap(maximum, Ordering::Relaxed);
        if maximum == previous {
            return Ok(());
        }
        let mut records = accounting(&self.records);
        let share = self.visitor_share(&records, Instant::now());
        for (key, record) in records.iter_mut() {
            if key.1 == Surface::Stratum {
                continue;
            }
            // Public work bursts also admit one largest reply's work.
            let old = self.key_policy_at(*key, share, previous);
            let new = self.key_policy_at(*key, share, maximum);
            for (bucket, old, new) in [
                (&mut record.bytes, old.byte_burst, new.byte_burst),
                (&mut record.work, old.work_burst, new.work_burst),
            ] {
                bucket.tokens = bucket
                    .tokens
                    .saturating_add(new.saturating_sub(old))
                    .min(new);
            }
        }
        Ok(())
    }
    /// Penalize `key` for a violation by `member`, the address charged. A
    /// member cools down by itself and strikes its aggregate; an aggregate
    /// that its members together exhausted takes a strike for `member`. The
    /// public website's proxy never cools down, and neither does loopback's
    /// aggregate.
    fn punish(&self, records: &mut HashMap<Key, Record>, key: Key, member: IpAddr, now: Instant) {
        if self.is_proxy(key) {
            return;
        }
        let aggregate = match key.3 {
            Scope::Address => {
                if let Some(record) = records.get_mut(&key) {
                    record.penalize(now);
                }
                self.aggregate_of(key)
            }
            Scope::Aggregate => Some(key),
        };
        if let Some(aggregate) = aggregate.filter(|key| !key.0.is_loopback())
            && let Some(record) = records.get_mut(&aggregate)
        {
            record.strike(member, now);
        }
    }
    pub fn admit(self: &Arc<Self>, ip: IpAddr, surface: Surface) -> Result<Session> {
        self.admit_at(ip, surface, Direction::Inbound, Instant::now())
    }
    /// Admit an inbound connection from a configured or pinned peer address,
    /// which the operator chose: a session that may use the frame memory
    /// other inbound sessions must leave free (`Session::operator`), charged
    /// to the address's own record only. Neighbours in its /24 or /48 whose
    /// violations cool that prefix's aggregate down, or who hold its
    /// connections, therefore cannot refuse it; its own budgets and
    /// cooldowns still apply.
    pub fn admit_operator(self: &Arc<Self>, ip: IpAddr, surface: Surface) -> Result<Session> {
        self.admit_operator_at(ip, surface, Instant::now())
    }
    fn admit_operator_at(
        self: &Arc<Self>,
        ip: IpAddr,
        surface: Surface,
        now: Instant,
    ) -> Result<Session> {
        let session = self.admit_with(ip, surface, Direction::Inbound, false, now)?;
        Ok(session.operator())
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
        self.admit_with(ip, surface, direction, true, now)
    }
    /// Admit a connection, charging its prefix's aggregate too when
    /// `aggregated` and the address has one.
    fn admit_with(
        self: &Arc<Self>,
        ip: IpAddr,
        surface: Surface,
        direction: Direction,
        aggregated: bool,
        now: Instant,
    ) -> Result<Session> {
        let mut ip = admission_address(ip);
        // Every loopback source of the public website is its one proxy.
        if self.loopback_rpc_is_proxy
            && surface == Surface::Rpc
            && direction == Direction::Inbound
            && ip.is_loopback()
        {
            ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        }
        let key = (ip, surface, direction, Scope::Address);
        let aggregate = self.aggregate_of(key).filter(|_| aggregated);
        let mut records = accounting(&self.records);
        self.enter(&mut records, &[Some(key), aggregate], now)?;
        Ok(Session {
            guard: self.clone(),
            key,
            aggregate,
            group: network_group(ip),
            operator: false,
            visitor: OnceLock::new(),
            refused: AtomicBool::new(false),
            nonessential: AtomicBool::new(false),
            request_bucket: Mutex::new(Bucket::new(SESSION_REQUEST_BURST, now)),
            overrun_bucket: Mutex::new(Bucket::new(WORKER_OVERRUN_BURST, now)),
            worker: AtomicBool::new(false),
            released: AtomicBool::new(false),
            reserved_frame: Mutex::new(0),
            frames: AtomicU64::new(0),
        })
    }
    /// Admit one more connection to each of `keys`' records, creating them if
    /// needed. A member and its aggregate are admitted together or not at all.
    fn enter(
        &self,
        records: &mut HashMap<Key, Record>,
        keys: &[Option<Key>],
        now: Instant,
    ) -> Result<()> {
        let keys: Vec<Key> = keys.iter().flatten().copied().collect();
        for &key in &keys {
            if records.contains_key(&key) {
                continue;
            }
            if records.len() >= MAX_TRACKED_IPS {
                // Prefer records whose cooldown has ended, so creating new
                // records does not cheaply erase an active penalty.
                let oldest = records
                    .iter()
                    .filter(|(k, r)| r.active == 0 && !keys.contains(k))
                    .min_by_key(|(_, r)| (r.cooldown > now, r.last))
                    .map(|(k, _)| *k);
                let Some(oldest) = oldest else {
                    return Err(Busy("network accounting capacity reached").into());
                };
                records.remove(&oldest);
            }
            let share = self.visitor_share(records, now);
            records.insert(key, Record::new(self.key_policy(key, share), now));
        }
        let share = self.visitor_share(records, now);
        for &key in &keys {
            let p = self.key_policy(key, share);
            let record = records.get_mut(&key).expect("tracked above");
            if now < record.cooldown {
                let refusal = "temporary network cooldown";
                return Err(record.refusal(refusal, Some(Duration::ZERO), now));
            }
            if record.active >= p.connections {
                // A slot frees when one of this address's sessions ends.
                let reason = match key.3 {
                    Scope::Address => "per-address connection limit",
                    Scope::Aggregate => "per-network connection limit",
                };
                return Err(limited(reason, Some(Duration::from_secs(1))));
            }
            record.requests.take(0, p.requests, p.request_burst, now);
            if record.requests.tokens == 0 {
                let wait = record.requests.wait(1, p.requests, p.request_burst);
                self.punish(records, key, keys[0].0, now);
                return Err(records[&key].refusal("connection rate limit", wait, now));
            }
        }
        for &key in &keys {
            let p = self.key_policy(key, share);
            let record = records.get_mut(&key).expect("tracked above");
            record.requests.take(1, p.requests, p.request_burst, now);
            record.active += 1;
            record.last = now;
            record.admitted = Some(now);
        }
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
        let key = (
            admission_address(ip),
            surface,
            Direction::Inbound,
            Scope::Address,
        );
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
    /// Frame memory buffered or held by frames being decoded.
    #[cfg(test)]
    pub fn frame_memory_in_use(&self) -> u64 {
        let memory = accounting(&self.frame_memory);
        memory.total + memory.decoding
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
    /// Mark the rest of this public session as a call that is not
    /// wallet-critical: its requests, work and reply bytes must leave the
    /// proxy's essential reserve in place. Charges made before the call is
    /// known, such as for a JSON-RPC request's unit and bytes, may use the
    /// whole budget.
    pub fn nonessential(&self) {
        self.nonessential.store(true, Ordering::Relaxed);
    }
    /// Mark a configured or pinned peer's session. It may use the frame
    /// memory that other inbound sessions must leave free.
    pub fn operator(mut self) -> Self {
        self.operator = true;
        self
    }
    /// Release the previous frame's memory before another frame is read.
    pub fn begin_frame(&self) -> Result<()> {
        self.frame_processed();
        self.frames.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    /// The current frame's message was decoded and processed, and none of
    /// its memory is held any longer: release its reservation now, so a peer
    /// that stops reading a reply or never sends its next frame holds none.
    pub fn frame_processed(&self) {
        let mut held = accounting(&self.reserved_frame);
        let mut memory = accounting(&self.guard.frame_memory);
        self.release_frame(&mut memory, std::mem::take(&mut *held));
    }
    /// The number of frames this session has begun and the shared frame
    /// memory it holds, for a session whose frames use the shared budget;
    /// `None` for configured or pinned peers and connections this node opened.
    pub fn frame_progress(&self) -> Option<(u64, u64)> {
        (self.key.2 != Direction::Outbound && !self.operator).then(|| {
            (
                self.frames.load(Ordering::Relaxed),
                *accounting(&self.reserved_frame),
            )
        })
    }
    /// Reserve node-wide memory for the next bytes of the current frame before
    /// they are read, so buffered memory is always paid for with bytes
    /// actually sent. A configured or pinned peer can always buffer one
    /// largest frame; other sessions share the rest, at most one largest frame
    /// or an equal share of the general slots per network group. The
    /// reservation also covers the decoded message, once the frame's bytes
    /// are gone, while it is processed, and is released once that is done
    /// (`frame_processed`), or by the session's next frame or its close;
    /// while the frame is decoded, `decoding` accounts the message built
    /// beside its bytes. Connections this node opened are bounded
    /// separately and never wait on inbound traffic.
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
    /// Account a frame of `bytes` being decoded, inbound or outbound: its
    /// message is built beside the frame's bytes, which a reservation keeps
    /// until the message has been processed. At most PEER_DECODERS frames
    /// decode at once, within the reserve the frame memory budget keeps for
    /// them, so this never refuses. Dropping the result ends it.
    pub fn decoding(&self, bytes: usize) -> FrameDecoding {
        let bytes = bytes as u64;
        let mut memory = accounting(&self.guard.frame_memory);
        memory.decoding = memory.decoding.saturating_add(bytes);
        FrameDecoding {
            guard: self.guard.clone(),
            bytes,
        }
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
    /// session's requests. A worker from a prefix the operator trusts
    /// (`--stratum-trusted`) also stops counting toward its address's and
    /// network's connection limits and pays no address or network budget:
    /// the worker registry and its own session limits bound it instead.
    pub fn authorize_worker(&self, trusted: bool) {
        self.worker.store(true, Ordering::Relaxed);
        if trusted && !self.released.swap(true, Ordering::Relaxed) {
            let mut records = accounting(&self.guard.records);
            for key in [Some(self.key), self.aggregate].into_iter().flatten() {
                if let Some(record) = records.get_mut(&key) {
                    record.active = record.active.saturating_sub(1);
                }
            }
        }
    }
    /// The admission address this session is accounted to.
    pub fn address(&self) -> IpAddr {
        self.key.0
    }
    /// Charge one line from an authorized Stratum worker. Within the session
    /// rate it is an ordinary request. Past it, the line draws on a separate
    /// overrun allowance and no address request unit, so one fast worker
    /// neither drains the budget of other sessions at its address nor is
    /// disconnected while its difficulty is raised. Bytes are charged to the
    /// address too. Other sources can exhaust the address and network budgets
    /// a worker shares, so their refusal only restricts the line and never
    /// penalizes or disconnects the worker. `Err` means the overrun allowance
    /// is spent as well.
    pub fn worker_line(&self, bytes: usize) -> Result<WorkerLine> {
        let now = Instant::now();
        let within =
            accounting(&self.request_bucket).take(1, SESSION_REQUESTS, SESSION_REQUEST_BURST, now);
        if !within {
            let mut overrun = accounting(&self.overrun_bucket);
            ensure!(
                overrun.take(1, WORKER_OVERRUN, WORKER_OVERRUN_BURST, now),
                "mining session request rate limit"
            );
        }
        let shared = self.worker_charge(u64::from(within), bytes as u64, 0, now);
        Ok(match shared {
            _ if !within => WorkerLine::Throttled,
            Ok(()) => WorkerLine::Admitted,
            Err(error) => WorkerLine::Refused(error),
        })
    }
    /// Charge an authorized worker's accepted share or solved block to its
    /// address and network work budgets, as its lines are charged.
    pub fn worker_work(&self, work: usize) -> Result<()> {
        self.worker_charge(0, 0, work as u64, Instant::now())
    }
    /// Charge an authorized worker's address and network records, unless the
    /// operator trusts its prefix. A refusal penalizes no one.
    fn worker_charge(&self, requests: u64, bytes: u64, work: u64, now: Instant) -> Result<()> {
        if self.released.load(Ordering::Relaxed) {
            return Ok(());
        }
        self.charge_address(requests, bytes, work, false, now)
            .map_err(|error| match error.downcast::<Limited>() {
                Ok(refusal) => limited("network rate budget exhausted", refusal.retry_after),
                Err(error) => error,
            })
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
    /// Every record this session pays from, most specific first, with the
    /// member address charged: the visitor its proxy named and that visitor's
    /// aggregate, then its own address and aggregate.
    fn keys(&self) -> [Option<(Key, IpAddr)>; 4] {
        let own = self.key.0;
        let (visitor, visitor_aggregate) = match self.visitor.get() {
            Some((key, aggregate)) => (Some((*key, key.0)), aggregate.map(|a| (a, key.0))),
            None => (None, None),
        };
        [
            visitor,
            visitor_aggregate,
            Some((self.key, own)),
            self.aggregate.map(|a| (a, own)),
        ]
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
        let share = self.guard.visitor_share(&records, now);
        let frame = self.guard.max_frame_bytes.load(Ordering::Relaxed);
        let keys = self.keys();
        let nonessential = self.nonessential.load(Ordering::Relaxed);
        // A charge is admitted by every record or by none, so a visitor past
        // its share, or members past their aggregate, spend nothing. The
        // first record that refuses says when this charge fits again.
        for (key, member) in keys.into_iter().flatten() {
            let p = self.guard.key_policy_at(key, share, frame);
            // A call that is not wallet-critical leaves the proxy's essential
            // reserve, and a visitor's allowance for one largest request.
            let (request_floor, byte_floor, work_floor) = match nonessential {
                false => (0, 0, 0),
                true if self.guard.is_proxy(key) => NetworkGuard::essential_reserve(),
                true => (0, 0, self.guard.essential_work_at(key, &p, frame)),
            };
            let record = records
                .get_mut(&key)
                .expect("active sessions retain their accounting entry");
            if !self.worker.load(Ordering::Relaxed) && now < record.cooldown {
                self.refused.store(true, Ordering::Relaxed);
                let refusal = "temporary network cooldown";
                return Err(record.refusal(refusal, Some(Duration::ZERO), now));
            }
            record.requests.take(0, p.requests, p.request_burst, now);
            record.bytes.take(0, p.bytes, p.byte_burst, now);
            record.work.take(0, p.work, p.work_burst, now);
            let (requests, bytes, work) = (
                requests.saturating_add(request_floor),
                bytes.saturating_add(byte_floor),
                work.saturating_add(work_floor),
            );
            let wait = if record.requests.tokens < requests {
                Some(record.requests.wait(requests, p.requests, p.request_burst))
            } else if record.bytes.tokens < bytes {
                Some(record.bytes.wait(bytes, p.bytes, p.byte_burst))
            } else if record.work.tokens < work {
                Some(record.work.wait(work, p.work, p.work_burst))
            } else {
                None
            };
            if let Some(wait) = wait {
                self.refused.store(true, Ordering::Relaxed);
                if !penalize {
                    return Err(record.refusal("outgoing network budget exhausted", wait, now));
                }
                self.guard.punish(&mut records, key, member, now);
                return Err(records[&key].refusal("network rate budget exhausted", wait, now));
            }
        }
        for (key, _) in keys.into_iter().flatten() {
            let p = self.guard.key_policy_at(key, share, frame);
            let record = records.get_mut(&key).expect("checked above");
            record
                .requests
                .take(requests, p.requests, p.request_burst, now);
            record.bytes.take(bytes, p.bytes, p.byte_burst, now);
            record.work.take(work, p.work, p.work_burst, now);
            record.last = now;
            record.admitted = Some(now);
        }
        Ok(())
    }
    /// Return `work` this session paid and did not use, such as the unused
    /// part of a reply's reservation, to every record that paid it.
    pub fn refund_work(&self, work: usize) {
        if work == 0 {
            return;
        }
        let now = Instant::now();
        let mut records = accounting(&self.guard.records);
        let share = self.guard.visitor_share(&records, now);
        for (key, _) in self.keys().into_iter().flatten() {
            let p = self.guard.key_policy(key, share);
            if let Some(record) = records.get_mut(&key) {
                record.work.give(work as u64, p.work, p.work_burst, now);
            }
        }
    }
    /// The visitor that this proxied session tried to name was refused:
    /// return the connection unit the proxy's record paid when the session
    /// was admitted, before anyone knew whose it was. Attempts that a
    /// visitor's own quota or cooldown refuses then never spend the request
    /// budget that all visitors share. Call it once, after `forwarded_for`
    /// failed.
    pub fn refund_refused_visitor(&self) {
        if !self.proxied() || self.visitor.get().is_some() {
            return;
        }
        let now = Instant::now();
        let mut records = accounting(&self.guard.records);
        let share = self.guard.visitor_share(&records, now);
        let p = self.guard.key_policy(self.key, share);
        if let Some(record) = records.get_mut(&self.key) {
            record.requests.give(1, p.requests, p.request_burst, now);
        }
    }
    /// The network whose public sessions this one counts with when the
    /// public session pool is full: its /24 or /48 aggregate, or on a local
    /// network its own address. `None` for the public website's proxy, which
    /// carries many visitors behind its own limits.
    pub fn network(&self) -> Option<IpAddr> {
        if self.proxied() {
            return None;
        }
        Some(self.aggregate.map_or(self.key.0, |aggregate| aggregate.0))
    }
    /// The network whose share of the public reply allowance a reply to
    /// this session uses: that of the visitor its proxy named, else its own,
    /// as an IPv4 /24 or IPv6 /48, or one address on a local network. The
    /// proxy's sessions that name no visitor count as its own address.
    pub fn reply_network(&self) -> IpAddr {
        let (key, aggregate) = self
            .visitor
            .get()
            .copied()
            .unwrap_or((self.key, self.aggregate));
        aggregate.map_or(key.0, |aggregate| aggregate.0)
    }
    /// Only malformed framing/JSON and explicit resource violations trigger this.
    /// Ordinary stale transactions, unknown parents and competing forks do not.
    pub fn malformed(&self) {
        let key = self.visitor.get().map_or(self.key, |(key, _)| *key);
        let mut records = accounting(&self.guard.records);
        self.guard.punish(&mut records, key, key.0, Instant::now());
    }
    /// A client broke HTTP framing or let its request deadline pass. This cools
    /// down a remote client or a visitor the proxy named, but never local
    /// software on loopback, and adds nothing to a refusal already accounted.
    pub fn framing_error(&self) {
        let key = self.visitor.get().map_or(self.key, |(key, _)| *key);
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
    /// That visitor's own record and its aggregate cap it, and the proxy's
    /// record still caps all visitors together.
    pub fn forwarded_for(&self, client: IpAddr) -> Result<()> {
        ensure!(self.proxied(), "only a public website proxy names visitors");
        let key = (
            admission_address(client),
            Surface::Rpc,
            Direction::Forwarded,
            Scope::Address,
        );
        let aggregate = self.guard.aggregate_of(key);
        let mut records = accounting(&self.guard.records);
        ensure!(self.visitor.get().is_none(), "visitor already named");
        if let Err(error) = self
            .guard
            .enter(&mut records, &[Some(key), aggregate], Instant::now())
        {
            self.refused.store(true, Ordering::Relaxed);
            return Err(error);
        }
        self.visitor
            .set((key, aggregate))
            .expect("the accounting lock serializes visitor naming");
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let released = *self.released.get_mut();
        let mut records = accounting(&self.guard.records);
        for (key, _) in self.keys().into_iter().flatten() {
            // A trusted worker released its own records at authorization.
            if released && (key == self.key || Some(key) == self.aggregate) {
                continue;
            }
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
    /// Any remote can arrange that, so its network group stays capped and a
    /// general slot it holds can be taken over like any other.
    Verified,
    /// A configured or pinned peer address the operator chose.
    Operator,
}
/// A session holding a general or verified inbound slot.
struct Occupant {
    /// The session source's admission address.
    source: IpAddr,
    /// Its network group, or the address on a local network.
    group: IpAddr,
    /// The group its slot counts against for diversity, if any.
    counted: Option<IpAddr>,
    class: PeerClass,
    /// The slots it holds one of: general or verified.
    pool: PeerClass,
    /// When it was admitted. For `EVICTION_GRACE` after that no newcomer
    /// takes its slot over, so it has time to finish an exchange.
    since: Instant,
    evict: Arc<Notify>,
}
/// How a newcomer from a network group that holds its cap gets a session
/// (`SlotCounts::group_turn`).
enum GroupTurn {
    /// It takes over this session of the group's.
    TakeOver(u64),
    /// It takes a free general slot beyond the cap.
    Beyond,
}
#[derive(Default)]
struct SlotCounts {
    general: usize,
    verified: usize,
    operator: usize,
    /// Sessions per network group, and how many of them use verified slots.
    groups: HashMap<IpAddr, (usize, usize)>,
    /// General- and verified-slot sessions, oldest first.
    occupants: BTreeMap<u64, Occupant>,
    admitted: u64,
    /// When each source last delivered a new valid block or transaction.
    useful: HashMap<IpAddr, Instant>,
    /// When each source last delivered a block that became the tip.
    advanced: HashMap<IpAddr, Instant>,
    /// When each source last delivered headers or blocks of a branch that
    /// claims more work than the tip and is not adopted yet.
    progressed: HashMap<IpAddr, Instant>,
    /// Ranks network groups for eviction protection. It never leaves this
    /// process, so no source can tell which groups it favours.
    key: [u8; 32],
    /// `EVICTION_GRACE`, which only integration tests shorten.
    grace: Duration,
}
impl SlotCounts {
    /// Whether `occupant` has had its grace period, so a newcomer may take
    /// its slot over.
    fn settled(&self, occupant: &Occupant, now: Instant) -> bool {
        now.saturating_duration_since(occupant.since) >= self.grace
    }
    /// When `source` last delivered a new valid block or transaction, if
    /// that was recent.
    fn useful_since(&self, source: IpAddr, now: Instant) -> Option<Instant> {
        self.useful
            .get(&source)
            .copied()
            .filter(|at| now.saturating_duration_since(*at) < USEFUL_PEER_WINDOW)
    }
    /// Whether `source` delivered a new valid block or transaction recently.
    fn useful_at(&self, source: IpAddr, now: Instant) -> bool {
        self.useful_since(source, now).is_some()
    }
    /// The sessions network groups hold beyond their cap, which took general
    /// slots while those were free (`group_turn`): each group's sessions
    /// after its `PEER_SLOTS_PER_GROUP` oldest.
    fn beyond_cap(&self) -> HashSet<u64> {
        let mut seen: HashMap<IpAddr, usize> = HashMap::new();
        self.occupants
            .iter()
            .filter(|(_, occupant)| {
                occupant.counted.is_some_and(|group| {
                    let held = seen.entry(group).or_default();
                    *held += 1;
                    *held > PEER_SLOTS_PER_GROUP
                })
            })
            .map(|(id, _)| *id)
            .collect()
    }
    /// The general-slot session a newcomer takes over when every slot it may
    /// use is full. A session its group holds beyond its cap goes first,
    /// whatever its age: such sessions only used general slots while they
    /// were free. Otherwise configured and pinned peers are never evicted,
    /// and no session is before its grace period (`EVICTION_GRACE`) has
    /// passed since its admission. Of the others, the sessions of the sources
    /// that most recently delivered a new block or transaction, the oldest
    /// session of a few groups ranked by a keyed hash and the
    /// longest-connected others are spared, each within its bound and never
    /// so many that fewer than `EVICTABLE_GENERAL` candidates remain. Of the
    /// rest, the newest session of the group holding the most general slots
    /// goes. However many groups or useful sources the occupants span, a
    /// newcomer is therefore refused only while configured and pinned peers
    /// and sessions still in their grace period hold every general slot.
    fn victim(&self, now: Instant) -> Option<u64> {
        let mut held: HashMap<IpAddr, usize> = HashMap::new();
        for occupant in self.occupants.values() {
            if occupant.pool == PeerClass::General {
                *held.entry(occupant.group).or_default() += 1;
            }
        }
        let beyond = self.beyond_cap();
        let excess = self
            .occupants
            .iter()
            .filter(|(id, occupant)| occupant.pool == PeerClass::General && beyond.contains(*id))
            .max_by_key(|(id, occupant)| (held[&occupant.group], **id))
            .map(|(id, _)| *id);
        if excess.is_some() {
            return excess;
        }
        let mut candidates: Vec<(u64, &Occupant)> = self
            .occupants
            .iter()
            .filter(|(_, occupant)| {
                occupant.pool == PeerClass::General
                    && occupant.class != PeerClass::Operator
                    && self.settled(occupant, now)
            })
            .map(|(id, occupant)| (*id, occupant))
            .collect();
        let spare = |candidates: &[(u64, &Occupant)], wanted: usize| {
            wanted.min(candidates.len().saturating_sub(EVICTABLE_GENERAL))
        };
        let mut useful: Vec<(Instant, u64)> = candidates
            .iter()
            .filter_map(|(id, occupant)| {
                self.useful
                    .get(&occupant.source)
                    .filter(|at| now.saturating_duration_since(**at) < USEFUL_PEER_WINDOW)
                    .map(|at| (*at, *id))
            })
            .collect();
        useful.sort_by(|a, b| b.cmp(a));
        let protected: HashSet<u64> = useful
            .iter()
            .take(spare(&candidates, PROTECTED_USEFUL))
            .map(|(_, id)| *id)
            .collect();
        candidates.retain(|(id, _)| !protected.contains(id));
        // Candidates are oldest first, so a group's first is its oldest.
        let mut seen = HashSet::new();
        let mut oldest: Vec<([u8; 32], u64)> = candidates
            .iter()
            .filter(|(_, occupant)| seen.insert(occupant.group))
            .map(|(id, occupant)| (self.rank(occupant.group), *id))
            .collect();
        oldest.sort_unstable();
        let protected: HashSet<u64> = oldest
            .iter()
            .take(spare(&candidates, PROTECTED_GROUPS))
            .map(|(_, id)| *id)
            .collect();
        candidates.retain(|(id, _)| !protected.contains(id));
        let longest = spare(&candidates, PROTECTED_LONGEST);
        candidates.drain(..longest);
        candidates
            .into_iter()
            .max_by_key(|(id, occupant)| (held[&occupant.group], *id))
            .map(|(id, _)| id)
    }
    /// The verified-slot session a recently verified newcomer takes over
    /// when every verified slot is full: the longest-held one past its grace
    /// period whose source has not delivered anything new recently. Any
    /// remote can arrange to be verified, so these slots are not first-come
    /// until their sessions' deadlines.
    fn verified_victim(&self, now: Instant) -> Option<u64> {
        self.occupants
            .iter()
            .find(|(_, occupant)| {
                occupant.pool == PeerClass::Verified
                    && self.settled(occupant, now)
                    && !self.useful_at(occupant.source, now)
            })
            .map(|(id, _)| *id)
    }
    /// How a newcomer from `source` gets a session of network group `group`,
    /// which holds its cap, if at all. The cap orders evictions rather than
    /// letting the holders of the group's sessions keep its other members
    /// out. An address holding more of the group's sessions than the
    /// newcomer's would gives its oldest up at once. Otherwise only a
    /// newcomer whose address holds none of them gets one: while general
    /// slots are free (`free`) it takes one beyond the cap, so the cap never
    /// refuses a member while there is room. Once they are full it takes
    /// over one of the group's sessions past its grace period: the newest
    /// beyond the cap, or else the one whose source delivered something new
    /// least recently, the oldest among equals, however recently that was.
    /// (A newcomer from another group takes over a session beyond a cap
    /// whatever its age: see `victim`.) Only sessions in slots the newcomer
    /// may use are candidates.
    fn group_turn(
        &self,
        group: IpAddr,
        source: IpAddr,
        class: PeerClass,
        free: bool,
        now: Instant,
    ) -> Option<GroupTurn> {
        let members: Vec<(u64, &Occupant)> = self
            .occupants
            .iter()
            .filter(|(_, occupant)| occupant.counted == Some(group))
            .map(|(id, occupant)| (*id, occupant))
            .collect();
        let held = |address: IpAddr| members.iter().filter(|(_, o)| o.source == address).count();
        let own = held(source);
        let usable: Vec<&(u64, &Occupant)> = members
            .iter()
            .filter(|(_, o)| {
                o.pool == PeerClass::General
                    || (class == PeerClass::Verified && o.pool == PeerClass::Verified)
            })
            .collect();
        // Members are oldest first, so the first of the most held is oldest.
        let crowded = usable
            .iter()
            .filter(|(_, o)| held(o.source) > own + 1)
            .max_by_key(|(id, o)| (held(o.source), std::cmp::Reverse(*id)));
        if let Some((id, _)) = crowded {
            return Some(GroupTurn::TakeOver(*id));
        }
        if own > 0 {
            return None;
        }
        if free {
            return Some(GroupTurn::Beyond);
        }
        let settled: Vec<&&(u64, &Occupant)> = usable
            .iter()
            .filter(|(_, o)| self.settled(o, now))
            .collect();
        let beyond = self.beyond_cap();
        let excess = settled
            .iter()
            .filter(|(id, _)| beyond.contains(id))
            .max_by_key(|(id, _)| *id);
        excess
            .or_else(|| {
                settled
                    .iter()
                    .min_by_key(|(id, o)| (self.useful_since(o.source, now), *id))
            })
            .map(|(id, _)| GroupTurn::TakeOver(*id))
    }
    /// End session `id`'s hold on its slot and group, and tell it to close.
    fn evict(&mut self, id: u64) {
        let evicted = self.occupants.remove(&id).expect("victims hold slots");
        if let Some(g) = evicted.counted
            && let Some(entry) = self.groups.get_mut(&g)
        {
            entry.0 = entry.0.saturating_sub(1);
            entry.1 = entry
                .1
                .saturating_sub(usize::from(evicted.pool == PeerClass::Verified));
            if entry.0 == 0 {
                self.groups.remove(&g);
            }
        }
        match evicted.pool {
            PeerClass::Verified => self.verified = self.verified.saturating_sub(1),
            _ => self.general = self.general.saturating_sub(1),
        }
        evicted.evict.notify_one();
    }
    /// A network group's place in the order of eviction protection.
    fn rank(&self, group: IpAddr) -> [u8; 32] {
        let bytes = match group {
            IpAddr::V4(v) => v.octets().to_vec(),
            IpAddr::V6(v) => v.octets().to_vec(),
        };
        crate::crypto::hmac_sha256(&self.key, &[&bytes])
    }
}
/// Inbound peer session capacity. Network groups have a concurrency cap,
/// which a newcomer from a group holding it exceeds while general slots are
/// free and otherwise rotates rather than being kept out
/// (`SlotCounts::group_turn`). While the general slots are full, sessions
/// beyond their group's cap go first, configured and pinned peers keep slots
/// no other source can use, recently verified discovery peers keep separate
/// slots, at most one per network group, which they take over from each
/// other (`SlotCounts::verified_victim`), and any other newcomer takes over
/// an unprotected general session's slot (`SlotCounts::victim`). A session
/// that loses its slot is told to close; no session within its group's cap
/// loses it within `EVICTION_GRACE` of its admission.
pub struct PeerSlots {
    counts: Mutex<SlotCounts>,
}
impl Default for PeerSlots {
    fn default() -> Self {
        let mut key = [0u8; 32];
        let _ = getrandom::fill(&mut key);
        Self::with_group_key(key)
    }
}
pub struct PeerSlot {
    slots: Arc<PeerSlots>,
    group: Option<IpAddr>,
    pool: PeerClass,
    /// The general or verified slot's place among occupants.
    occupant: Option<u64>,
    evict: Arc<Notify>,
}
impl PeerSlot {
    /// Notified when a newcomer took over this slot. The session should
    /// close: its capacity already belongs to the newcomer.
    pub fn eviction(&self) -> Arc<Notify> {
        self.evict.clone()
    }
}
impl PeerSlots {
    /// Slots whose eviction protection ranks network groups by `key`.
    fn with_group_key(key: [u8; 32]) -> Self {
        Self {
            counts: Mutex::new(SlotCounts {
                key,
                grace: EVICTION_GRACE,
                ..Default::default()
            }),
        }
    }
    /// Shorten the grace period before a session's slot may be taken over,
    /// so an integration test can show a takeover without holding sessions
    /// for a whole read allowance.
    #[cfg(feature = "test-fixtures")]
    pub fn set_grace(&self, grace: Duration) {
        accounting(&self.counts).grace = grace;
    }
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr, class: PeerClass) -> Option<PeerSlot> {
        self.try_acquire_at(ip, class, Instant::now())
    }
    fn try_acquire_at(
        self: &Arc<Self>,
        ip: IpAddr,
        class: PeerClass,
        now: Instant,
    ) -> Option<PeerSlot> {
        // Only an operator-chosen address is exempt from network diversity.
        let group = (class != PeerClass::Operator)
            .then(|| network_group(ip))
            .flatten();
        let source = admission_address(ip);
        let mut counts = accounting(&self.counts);
        let counts = &mut *counts;
        if let Some(g) = group
            && counts
                .groups
                .get(&g)
                .is_some_and(|(sessions, _)| *sessions >= PEER_SLOTS_PER_GROUP)
        {
            let free = counts.general < INBOUND_PEER_SLOTS;
            match counts.group_turn(g, source, class, free, now)? {
                // The session taken over held a slot the newcomer may use,
                // which it then takes.
                GroupTurn::TakeOver(id) => counts.evict(id),
                // It takes a free general slot below, and the group holds
                // more sessions than its cap until some end or are taken
                // over.
                GroupTurn::Beyond => {}
            }
        }
        let verified = group
            .and_then(|g| counts.groups.get(&g))
            .map_or(0, |(_, verified)| *verified);
        let verifiable = class == PeerClass::Verified && verified == 0;
        let pool = if counts.general < INBOUND_PEER_SLOTS {
            PeerClass::General
        } else if verifiable && counts.verified < VERIFIED_PEER_SLOTS {
            PeerClass::Verified
        } else if let Some(id) = verifiable.then(|| counts.verified_victim(now)).flatten() {
            // Recently verified newcomers take over each other's slots.
            counts.evict(id);
            PeerClass::Verified
        } else if class == PeerClass::Operator && counts.operator < RESERVED_PEER_SLOTS {
            PeerClass::Operator
        } else {
            // The newcomer takes over an unprotected general slot instead of
            // waiting for one of the sessions holding them all to end.
            let id = counts.victim(now)?;
            counts.evict(id);
            PeerClass::General
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
        let evict = Arc::new(Notify::new());
        let occupant = (pool != PeerClass::Operator).then(|| {
            let id = counts.admitted;
            counts.admitted += 1;
            counts.occupants.insert(
                id,
                Occupant {
                    source,
                    group: peer_source(ip),
                    counted: group,
                    class,
                    pool,
                    since: now,
                    evict: evict.clone(),
                },
            );
            id
        });
        Some(PeerSlot {
            slots: self.clone(),
            group,
            pool,
            occupant,
            evict,
        })
    }
    /// A source delivered a new valid block or transaction, which protects its
    /// general inbound sessions from eviction for `USEFUL_PEER_WINDOW`.
    pub fn delivered(&self, ip: IpAddr) {
        self.delivered_at(ip, Instant::now());
    }
    fn delivered_at(&self, ip: IpAddr, now: Instant) {
        let mut counts = accounting(&self.counts);
        Self::credit(&mut counts.useful, admission_address(ip), now);
    }
    /// A source delivered a block that became the tip. Besides counting as a
    /// delivery, this tells the discovery scheduler that synchronizing with
    /// it advanced this node (`advanced_since`). Only proof of work earns it:
    /// unlike a new transaction, which any funded sender can supply.
    pub fn advanced(&self, ip: IpAddr) {
        self.advanced_at(ip, Instant::now());
    }
    fn advanced_at(&self, ip: IpAddr, now: Instant) {
        let source = admission_address(ip);
        let mut counts = accounting(&self.counts);
        Self::credit(&mut counts.useful, source, now);
        Self::credit(&mut counts.advanced, source, now);
    }
    /// A source delivered headers or new blocks of a branch that claims more
    /// work than the tip, which this node holds but has not adopted yet:
    /// progress toward a reorganization although none of its blocks became
    /// the tip. It tells the discovery scheduler that synchronizing with it
    /// made progress (`progressed_since`), and protects no inbound session.
    /// Only proof of work earns it, more than the tip's.
    pub fn progressed(&self, ip: IpAddr) {
        self.progressed_at(ip, Instant::now());
    }
    fn progressed_at(&self, ip: IpAddr, now: Instant) {
        let mut counts = accounting(&self.counts);
        Self::credit(&mut counts.progressed, admission_address(ip), now);
    }
    /// Record `source`'s credit at `now`, forgetting the oldest source's once
    /// `USEFUL_PEER_SOURCES` are remembered.
    fn credit(credits: &mut HashMap<IpAddr, Instant>, source: IpAddr, now: Instant) {
        if credits.len() >= USEFUL_PEER_SOURCES
            && !credits.contains_key(&source)
            && let Some(oldest) = credits
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(source, _)| *source)
        {
            credits.remove(&oldest);
        }
        credits.insert(source, now);
    }
    /// Whether `ip`'s source delivered a new valid block or transaction at
    /// or after `since`.
    #[cfg(test)]
    pub(crate) fn delivered_since(&self, ip: IpAddr, since: Instant) -> bool {
        accounting(&self.counts)
            .useful
            .get(&admission_address(ip))
            .is_some_and(|at| *at >= since)
    }
    /// Whether `ip`'s source delivered a block that became the tip at or
    /// after `since`.
    pub fn advanced_since(&self, ip: IpAddr, since: Instant) -> bool {
        accounting(&self.counts)
            .advanced
            .get(&admission_address(ip))
            .is_some_and(|at| *at >= since)
    }
    /// Whether `ip`'s source delivered headers or new blocks of a branch
    /// that claims more work than the tip at or after `since`.
    pub fn progressed_since(&self, ip: IpAddr, since: Instant) -> bool {
        accounting(&self.counts)
            .progressed
            .get(&admission_address(ip))
            .is_some_and(|at| *at >= since)
    }
    /// Whether `ip`'s source is credited with a recent delivery.
    #[cfg(test)]
    pub(crate) fn delivered_recently(&self, ip: IpAddr) -> bool {
        accounting(&self.counts)
            .useful
            .contains_key(&admission_address(ip))
    }
}
impl Drop for PeerSlot {
    fn drop(&mut self) {
        let mut counts = accounting(&self.slots.counts);
        if let Some(id) = self.occupant
            && counts.occupants.remove(&id).is_none()
        {
            // Evicted: the newcomer holds this capacity, and the group count
            // was released then.
            return;
        }
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

/// How an authorized Stratum worker's line was charged.
pub enum WorkerLine {
    /// Within its session rate and every budget it pays.
    Admitted,
    /// Past its session rate, on the overrun allowance.
    Throttled,
    /// Refused by an address or network budget that other sessions share.
    Refused(anyhow::Error),
}
/// The group whose authorized Stratum workers share one cap: the pending
/// group (IPv4 /24, IPv6 /48), or the address itself on a local network.
pub fn stratum_group(ip: IpAddr) -> IpAddr {
    let address = admission_address(ip);
    pending_group(address).unwrap_or(address)
}
/// The shortest trusted prefix, IPv4 then IPv6, that `--stratum-trusted`
/// accepts outside local networks: the network groups peer diversity uses. A
/// broader public prefix would exempt much of the internet from the pending
/// limits, so only `--stratum-trusted-broad` names one.
pub const TRUSTED_PREFIX_MINIMUM: (u8, u8) = (16, 32);

/// An address prefix the operator names, such as `203.0.113.0/24`,
/// `2001:db8:7::/48` or one address, whose Stratum sources always count as
/// recently authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedPrefix {
    network: IpAddr,
    length: u8,
}
impl TrustedPrefix {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = unmapped(ip);
        ip.is_ipv4() == self.network.is_ipv4() && masked(ip, self.length.into()) == self.network
    }
    /// A prefix of any length, even one shorter than `TRUSTED_PREFIX_MINIMUM`
    /// outside local networks, for an operator who means to trust it.
    pub fn broad(text: &str) -> Result<Self> {
        Self::parse(text)
    }
    /// Whether every address in the prefix belongs to a local network:
    /// loopback, private, shared (CGNAT), link-local or unique-local.
    fn local(&self) -> bool {
        let within = |network: IpAddr, length: u8| {
            self.length >= length && masked(self.network, length.into()) == network
        };
        let v4 = |octets: [u8; 4], length| within(IpAddr::from(octets), length);
        let v6 = |first: u16, length| within(IpAddr::from([first, 0, 0, 0, 0, 0, 0, 0]), length);
        match self.network {
            IpAddr::V4(_) => {
                v4([10, 0, 0, 0], 8)
                    || v4([127, 0, 0, 0], 8)
                    || v4([172, 16, 0, 0], 12)
                    || v4([192, 168, 0, 0], 16)
                    || v4([169, 254, 0, 0], 16)
                    || v4([100, 64, 0, 0], 10)
            }
            IpAddr::V6(_) => {
                within(IpAddr::V6(Ipv6Addr::LOCALHOST), 128) || v6(0xfc00, 7) || v6(0xfe80, 10)
            }
        }
    }
    fn parse(text: &str) -> Result<Self> {
        let (address, length) = match text.split_once('/') {
            Some((address, length)) => (address, Some(length)),
            None => (text, None),
        };
        let address = unmapped(
            address
                .parse::<IpAddr>()
                .context("a trusted prefix is an IP address, optionally with /LENGTH")?,
        );
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        let length = match length {
            Some(length) => {
                ensure!(
                    !length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()),
                    "invalid prefix length"
                );
                length.parse::<u8>().context("invalid prefix length")?
            }
            None => maximum,
        };
        ensure!(length <= maximum, "prefix length exceeds the address");
        Ok(Self {
            network: masked(address, length.into()),
            length,
        })
    }
}
impl FromStr for TrustedPrefix {
    type Err = anyhow::Error;
    /// A prefix outside local networks must be at least
    /// `TRUSTED_PREFIX_MINIMUM` long; see [TrustedPrefix::broad].
    fn from_str(text: &str) -> Result<Self> {
        let prefix = Self::parse(text)?;
        let (v4, v6) = TRUSTED_PREFIX_MINIMUM;
        let minimum = if prefix.network.is_ipv4() { v4 } else { v6 };
        ensure!(
            prefix.length >= minimum || prefix.local(),
            "a trusted prefix outside local networks must be at least /{v4} for IPv4 or /{v6} \
             for IPv6; use --stratum-trusted-broad to trust a broader prefix deliberately"
        );
        Ok(prefix)
    }
}
impl std::fmt::Display for TrustedPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.length)
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
    /// Prefixes whose addresses always count as trusted.
    allowed: Vec<TrustedPrefix>,
    /// The trusted addresses changed since they were last saved.
    unsaved: bool,
}
impl PendingCounts {
    /// Remember an address that authorized, as the most recent, forgetting
    /// the least recent beyond `STRATUM_TRUSTED_ADDRESSES`.
    fn trust(&mut self, address: IpAddr) {
        if self.trusted.len() >= STRATUM_TRUSTED_ADDRESSES
            && !self.trusted.contains_key(&address)
            && let Some(oldest) = self
                .trusted
                .iter()
                .min_by_key(|(_, sequence)| **sequence)
                .map(|(address, _)| *address)
        {
            self.trusted.remove(&oldest);
        }
        self.sequence += 1;
        self.trusted.insert(address, self.sequence);
        self.unsaved = true;
    }
}
/// The saved form of the trusted addresses, least recent first.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedTrusted {
    version: u8,
    addresses: Vec<IpAddr>,
}
/// Stratum connections awaiting authorization. A source that has not recently
/// authorized pays for the time it holds a slot, and its public group has a
/// concurrency cap. Addresses that recently authorized, which survive restarts
/// through `load_trusted` and `unsaved_trusted`, and addresses in prefixes the
/// operator allowed are not charged and keep reserved slots while the
/// general slots are full.
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
    /// A prefix the operator named holds the source.
    allowed: bool,
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
        let allowed = counts.allowed.iter().any(|prefix| prefix.contains(ip));
        let slot = |group, reserved, charged| PendingSlot {
            pending: self.clone(),
            address,
            group,
            reserved,
            charged,
            allowed,
            started: now,
            released: false,
        };
        if allowed || counts.trusted.contains_key(&address) {
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
    /// Prefixes whose addresses always count as recently authorized.
    pub fn allow(&self, prefixes: &[TrustedPrefix]) {
        accounting(&self.counts).allowed = prefixes.to_vec();
    }
    /// Restore the addresses that authorized before a restart, least recent
    /// first, after any already remembered in this run. A missing file holds
    /// none. A file that is not a regular file, is too large or does not
    /// parse is refused whole, and the next save replaces it.
    pub fn load_trusted(&self, path: &Path) -> Result<()> {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Ok(());
        };
        ensure!(
            metadata.is_file(),
            "{} must be a regular file, not a symbolic link",
            path.display()
        );
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(STRATUM_TRUSTED_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= STRATUM_TRUSTED_FILE_BYTES,
            "{} exceeds its size limit",
            path.display()
        );
        let saved: SavedTrusted = serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid {}", path.display()))?;
        ensure!(
            saved.version == 1 && saved.addresses.len() <= STRATUM_TRUSTED_ADDRESSES,
            "unsupported version or too many addresses in {}",
            path.display()
        );
        let mut counts = accounting(&self.counts);
        let mut newer: Vec<(u64, IpAddr)> = counts.trusted.drain().map(|(a, s)| (s, a)).collect();
        newer.sort();
        let unsaved = !newer.is_empty();
        for address in saved
            .addresses
            .into_iter()
            .map(admission_address)
            .chain(newer.into_iter().map(|(_, address)| address))
        {
            counts.trust(address);
        }
        counts.unsaved = unsaved;
        Ok(())
    }
    /// The trusted addresses to save, least recent first, when they changed
    /// since the last save. A failed save calls `save_failed`.
    pub fn unsaved_trusted(&self) -> Option<Vec<u8>> {
        let mut counts = accounting(&self.counts);
        if !std::mem::take(&mut counts.unsaved) {
            return None;
        }
        let mut addresses: Vec<(u64, IpAddr)> =
            counts.trusted.iter().map(|(a, s)| (*s, *a)).collect();
        addresses.sort();
        serde_json::to_vec(&SavedTrusted {
            version: 1,
            addresses: addresses.into_iter().map(|(_, address)| address).collect(),
        })
        .ok()
    }
    pub fn save_failed(&self) {
        accounting(&self.counts).unsaved = true;
    }
    /// Replace the saved trusted addresses atomically with an owner-only file,
    /// never through a symbolic link. This performs file I/O and an fsync.
    pub fn persist_trusted(path: &Path, bytes: &[u8]) -> Result<()> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.is_file(),
                "{} must be a regular file, not a symbolic link",
                path.display()
            );
        }
        let mut random = [0u8; 16];
        getrandom::fill(&mut random)
            .map_err(|e| anyhow!("file name randomness unavailable: {e}"))?;
        let temporary = path.with_extension(format!("{}.tmp", hex::encode(random)));
        if let Err(error) = crate::local_files::write_private(&temporary, bytes)
            .and_then(|()| fs::rename(&temporary, path).map_err(anyhow::Error::from))
        {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }
}
impl PendingSlot {
    /// Whether a prefix the operator named (`--stratum-trusted`) holds the
    /// source, rather than a recent authorization alone.
    pub fn operator_trusted(&self) -> bool {
        self.allowed
    }
    /// The session authorized. Its address may later wait uncharged and use
    /// reserved slots, and dropping this slot releases it.
    pub fn authorized(self) {
        accounting(&self.pending.counts).trust(self.address);
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
/// The longest JSON object key the bounded parsers accept.
pub const MAX_JSON_KEY_BYTES: usize = 128;
/// Object keys serde_json reserves for its own types. With its `raw_value`
/// feature, which axum enables for the whole build, `serde_json::Value`
/// reads an object whose first key is `$serde_json::private::RawValue` as
/// the JSON text held in its string value; `arbitrary_precision` reserves a
/// key of the same prefix for numbers.
const RESERVED_JSON_KEY_PREFIX: &str = "$serde_json::private::";
/// Whether `key` may name a member of JSON this node reads or writes: within
/// the key bound and not reserved by serde_json. Anything the node echoes as
/// a key, such as a Stratum extension name, must pass this too, so its
/// replies stay JSON that it and serde_json-based clients read as written.
pub fn json_key_allowed(key: &str) -> bool {
    key.len() <= MAX_JSON_KEY_BYTES && !key.starts_with(RESERVED_JSON_KEY_PREFIX)
}
/// A JSON value read exactly as its text spells it. serde_json's own `Value`
/// deserializer would replace an object led by the RawValue key with the
/// document in its string, after the preflight bounded only that string, and
/// would accept the key elsewhere in an object, where the node's sorted
/// output can put it first and make its reply unreadable to serde_json.
/// This reader keeps every key a plain string and refuses reserved keys.
struct PlainJson;
impl<'de> serde::de::DeserializeSeed<'de> for PlainJson {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> serde::de::Visitor<'de> for PlainJson {
    type Value = Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number))
    }
    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element_seed(PlainJson)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.starts_with(RESERVED_JSON_KEY_PREFIX) {
                return Err(serde::de::Error::custom("JSON key reserved by serde_json"));
            }
            // A repeated key keeps its last value, as serde_json's own does.
            object.insert(key, map.next_value_seed(PlainJson)?);
        }
        Ok(Value::Object(object))
    }
}
/// One JSON text, with nothing but whitespace after it, read as its text
/// spells it (see `PlainJson`) and otherwise unbounded: the parsers here
/// bound it first, and so does the RPC client's reply budget, which counts
/// values in the reply's text.
pub(crate) fn plain_json(bytes: &[u8]) -> serde_json::Result<Value> {
    use serde::de::DeserializeSeed;
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = PlainJson.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    preflight_json(bytes)?;
    let value = plain_json(bytes)?;
    json_bounds(&value)?;
    Ok(value)
}
/// Only the designated raw transaction or data field may exceed the ordinary
/// JSON string bound. All other fields retain their existing limits.
pub(crate) fn parse_rpc_json(bytes: &[u8], max_raw_hex: usize) -> Result<Value> {
    preflight_json_with_limits(bytes, MAX_JSON_VALUES, max_raw_hex.max(1024))?;
    let mut value = plain_json(bytes)?;
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
    let mut value = plain_json(bytes)?;
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
                ensure!(json_key_allowed(k), "JSON key exceeds protocol bound");
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
        guard.set_frame(expanded).unwrap();
        // A peer's burst holds a session's two largest frames, its reply and
        // its push; spend both.
        assert!(peer.bytes(expanded).is_ok());
        assert!(peer.bytes(expanded).is_ok());
        guard.set_frame(expanded).unwrap();
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
        // One synchronization session's two largest frames, a reply and a
        // push, fit a peer's burst, and its refill renews them each second.
        let peer = guard.admit(ip, Surface::Peer).unwrap();
        assert!(peer.bytes(FRAME).is_ok());
        assert!(peer.bytes(FRAME).is_ok());
        assert!(peer.bytes(FRAME).is_err());
        assert_eq!(guard.policy(Surface::Peer).bytes, 2 * FRAME as u64);
        assert_eq!(
            guard.policy(Surface::Rpc).bytes,
            Surface::Rpc.policy().bytes
        );
        assert_eq!(guard.policy(Surface::Rpc).byte_burst, FRAME as u64);
        assert_eq!(guard.policy(Surface::Peer).connections, 4);
        assert_eq!(guard.policy(Surface::Stratum).byte_burst, 2 * 1024 * 1024);
        let old = Arc::new(NetworkGuard::default());
        assert!(old.admit(ip, Surface::Peer).unwrap().bytes(FRAME).is_err());
        // Below the baseline nothing changes.
        let small = Arc::new(NetworkGuard::with_frame_limit(3 * 1024 * 1024));
        assert_eq!(
            small.policy(Surface::Peer).bytes,
            Surface::Peer.policy().bytes
        );
        assert_eq!(
            small.policy(Surface::Peer).byte_burst,
            Surface::Peer.policy().byte_burst
        );
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
        let share = (Surface::Rpc.policy().work_burst / PUBLIC_WEB_VISITOR_SHARE) as usize;
        let first = visitor("192.0.1.1").unwrap();
        assert!(first.work(share).is_ok());
        // A second share is refused by the visitor's own record, and the
        // refusal cools down only that visitor, never the proxy.
        assert!(first.work(share).is_err());
        assert!(visitor("192.0.1.1").is_err());
        assert!(guard.admit(proxy, Surface::Rpc).is_ok());
        // Eight full shares, from eight networks, empty the budget all
        // visitors share. A further visitor, whose own share is smaller now
        // that nine are active, is then refused without a cooldown of its own.
        let others: Vec<_> = (2..=8)
            .map(|n| visitor(&format!("192.0.{n}.1")).unwrap())
            .collect();
        for other in &others {
            assert!(other.work(share).is_ok());
        }
        let late = visitor("192.0.9.1").unwrap();
        assert!(late.work(1000).is_err());
        drop(late);
        assert!(visitor("192.0.9.1").is_ok());
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
        let named = (client, Surface::Rpc, Direction::Forwarded, Scope::Address);
        assert_eq!(records[&named].strikes, 1);
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
                .admit(
                    IpAddr::from([0x2001, 0x4860, 7, 10, 0, 0, 0, 1]),
                    Surface::Peer
                )
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
        // Frames of up to 16 MiB: an 80 MiB budget, 64 MiB of it shared, and
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
        // Sessions in three other groups that stall after one frame's bytes
        // fill the shared part; nobody else in it can buffer more.
        let stalled: Vec<_> = (2..=4)
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
        let ipv6 = |n: u16| IpAddr::from([0x2001, 0x4860, n, 0, 0, 0, 0, 1]);
        // Two sessions of a public /16, or of an IPv6 /32, fit its cap. While
        // general slots are free, other addresses from it take free ones
        // beyond the cap, but an address already holding one of the group's
        // sessions takes no second.
        let same: Vec<_> = (1..=4)
            .filter_map(|n| slots.try_acquire(public(1, n, 1), PeerClass::General))
            .collect();
        assert_eq!(same.len(), 4);
        assert!(
            slots
                .try_acquire(public(1, 1, 1), PeerClass::General)
                .is_none()
        );
        let v6: Vec<_> = (1..=3)
            .filter_map(|n| slots.try_acquire(ipv6(n), PeerClass::General))
            .collect();
        assert_eq!(v6.len(), 3);
        // Once the general slots are full, sessions beyond a cap are the
        // first taken over, whatever their age: the newest of the group
        // holding the most general slots first.
        let others: Vec<_> = (21..=29)
            .map(|a| {
                slots
                    .try_acquire(public(a, 1, 1), PeerClass::General)
                    .unwrap()
            })
            .collect();
        assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
        let newcomers: Vec<_> = (41..=43)
            .map(|a| {
                slots
                    .try_acquire(public(a, 1, 1), PeerClass::General)
                    .unwrap()
            })
            .collect();
        let gone: Vec<_> = same.iter().chain(&v6).chain(&others).collect();
        assert!(taken_over(&slots, &same[3]) && taken_over(&slots, &v6[2]));
        assert!(taken_over(&slots, &same[2]));
        assert_eq!(gone.iter().filter(|s| taken_over(&slots, s)).count(), 3);
        // Then every session is within its group's cap and its grace period.
        assert!(
            slots
                .try_acquire(public(44, 1, 1), PeerClass::General)
                .is_none()
        );
        drop((same, v6, others, newcomers));
        // Two addresses in one public /16 and two in an IPv6 /32 hold their
        // groups' caps.
        let same: Vec<_> = (1..=2)
            .map(|n| {
                slots
                    .try_acquire(public(1, n, 1), PeerClass::General)
                    .unwrap()
            })
            .collect();
        let v6: Vec<_> = (1..=2)
            .map(|n| slots.try_acquire(ipv6(n), PeerClass::General).unwrap())
            .collect();
        // A full general pool takes over an unprotected session's slot rather
        // than refusing a newcomer, once that session has had its grace
        // period. With configured or pinned peers holding twelve slots, the
        // four others are all candidates, and the newest session of a group
        // holding two goes.
        let operators: Vec<_> = (1..=12)
            .map(|n| {
                slots
                    .try_acquire(public(50, n, 1), PeerClass::Operator)
                    .unwrap()
            })
            .collect();
        assert!(
            slots
                .try_acquire(public(30, 1, 1), PeerClass::General)
                .is_none()
        );
        let settled = Instant::now() + EVICTION_GRACE;
        let newcomer = slots
            .try_acquire_at(public(30, 1, 1), PeerClass::General, settled)
            .unwrap();
        let id = v6[1].occupant.unwrap();
        assert!(!slots.counts.lock().unwrap().occupants.contains_key(&id));
        drop((newcomer, v6));
        // Once configured and pinned peers hold every general slot, other
        // newcomers are refused. Recently verified discovery peers remain
        // group-capped and take at most one verified slot per group, so
        // verified addresses in one /16 gain nothing, and verified peers
        // never use configured capacity.
        drop(same);
        let held: Vec<_> = (13..=16)
            .map(|n| {
                slots
                    .try_acquire(public(50, n, 1), PeerClass::Operator)
                    .unwrap()
            })
            .chain(operators)
            .collect();
        assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
        assert!(
            slots
                .try_acquire(public(30, 1, 1), PeerClass::General)
                .is_none()
        );
        let verified: Vec<_> = (1..=8)
            .filter_map(|n| slots.try_acquire(public(30, n, 1), PeerClass::Verified))
            .collect();
        assert_eq!(verified.len(), 1);
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
        drop(local);
        let counts = slots.counts.lock().unwrap();
        assert_eq!(
            (counts.general, counts.verified, counts.operator),
            (0, 0, 0)
        );
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
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
        worker.authorize_worker(false);
        let other = guard.admit(ip, Surface::Stratum).unwrap();
        other.malformed();
        // A cooldown from another session at the address refuses new
        // connections and unauthenticated requests, not the worker.
        assert!(guard.admit(ip, Surface::Stratum).is_err());
        assert!(other.request().is_err());
        assert!(matches!(worker.worker_line(100), Ok(WorkerLine::Admitted)));
        assert!(worker.worker_work(1).is_ok());
        // Past its session rate a worker is throttled rather than refused
        // until its overrun allowance runs out.
        let (mut within, mut throttled) = (1, 0);
        let error = loop {
            match worker.worker_line(100) {
                Ok(WorkerLine::Admitted) => within += 1,
                Ok(WorkerLine::Throttled) => throttled += 1,
                Ok(WorkerLine::Refused(error)) => panic!("{error}"),
                Err(error) => break error,
            }
        };
        assert!(error.to_string().contains("session request rate limit"));
        assert!((16..=18).contains(&within), "{within}");
        assert!((64..=67).contains(&throttled), "{throttled}");
        // Throttled lines spend no address request units and the overrun
        // never penalizes the address.
        let records = guard.records.lock().unwrap();
        let record = &records[&(ip, Surface::Stratum, Direction::Inbound, Scope::Address)];
        assert!(record.requests.tokens >= 64 - 2 - within as u64);
        assert_eq!(record.strikes, 1);
    }
    #[test]
    fn shared_budgets_other_sources_drain_restrict_a_worker_without_penalty() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        let worker = guard.admit(ip, Surface::Stratum).unwrap();
        worker.authorize_worker(false);
        // Other devices at the address, and their neighbours in the /24, use
        // up the request budget the worker shares with them.
        let other = guard.admit(ip, Surface::Stratum).unwrap();
        while other.charge_address(1, 0, 0, true, Instant::now()).is_ok() {}
        // The worker's line is restricted, not a reason to close it, and the
        // refusal penalizes neither the address nor its network.
        let key = (ip, Surface::Stratum, Direction::Inbound, Scope::Address);
        let aggregate = (
            masked(ip, 24),
            Surface::Stratum,
            Direction::Inbound,
            Scope::Aggregate,
        );
        let penalties = |records: &HashMap<Key, Record>| {
            let network = &records[&aggregate];
            (
                records[&key].strikes,
                network.strikes,
                network.members.len(),
            )
        };
        let before = penalties(&guard.records.lock().unwrap());
        match worker.worker_line(100) {
            Ok(WorkerLine::Refused(error)) => {
                let refusal = error.downcast::<Limited>().unwrap();
                assert_eq!(refusal.reason, "network rate budget exhausted");
                assert!(refusal.retry_after.is_some());
            }
            _ => panic!("a drained address budget did not restrict the line"),
        }
        assert_eq!(penalties(&guard.records.lock().unwrap()), before);
        // A share's work charge is not refused for another session's requests.
        assert!(worker.worker_work(1).is_ok());
    }
    #[test]
    fn trusted_workers_leave_the_address_connection_limits_and_shared_budgets() {
        let guard = Arc::new(NetworkGuard::default());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let limit = Surface::Stratum.policy().connections;
        // A marketplace proxy behind one address: once authorized, a trusted
        // worker no longer holds one of its address's connections.
        let workers: Vec<Session> = (0..limit * 2)
            .map(|_| {
                let session = guard.admit(ip, Surface::Stratum).unwrap();
                session.authorize_worker(true);
                session
            })
            .collect();
        let mut pending: Vec<Session> = (0..limit)
            .map(|_| guard.admit(ip, Surface::Stratum).unwrap())
            .collect();
        let refused = guard.admit(ip, Surface::Stratum).err().unwrap();
        let reason = refused.downcast::<Limited>().unwrap().reason;
        assert_eq!(reason, "per-address connection limit");
        // Its lines pay only its own session limits, whatever other sessions
        // at the address spend.
        pending.pop();
        let other = guard.admit(ip, Surface::Stratum).unwrap();
        while other.request().is_ok() {}
        for worker in &workers {
            assert!(matches!(worker.worker_line(100), Ok(WorkerLine::Admitted)));
            assert!(worker.worker_work(8192).is_ok());
        }
        // Closing the workers leaves the counts of the remaining sessions.
        drop(workers);
        let key = (ip, Surface::Stratum, Direction::Inbound, Scope::Address);
        let aggregate = (
            masked(ip, 24),
            Surface::Stratum,
            Direction::Inbound,
            Scope::Aggregate,
        );
        let records = guard.records.lock().unwrap();
        assert_eq!(records[&key].active, limit);
        assert_eq!(records[&aggregate].active, limit);
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
    /// Found by the stratum_session fuzz target (fuzz/regressions/stratum_session/):
    /// with serde_json's `raw_value` feature, which axum enables, its `Value`
    /// read an object led by the RawValue key as the document in its string,
    /// past the preflight's bounds, and kept the key anywhere else in an
    /// object, from where sorted output wrote JSON no serde_json parser reads.
    #[test]
    fn json_parsers_refuse_keys_serde_json_reserves() {
        const RAW: &str = "$serde_json::private::RawValue";
        let deep = format!("{}{}", "[".repeat(120), "]".repeat(120));
        // The key with each of `chars` written as a JSON unicode escape: a
        // backslash, `u` and four hex digits, assembled here rather than spelled.
        let escaped = |chars: &[char]| -> String {
            let key: String = RAW
                .chars()
                .map(|c| {
                    if chars.contains(&c) {
                        format!("{}u{:04x}", '\\', u32::from(c))
                    } else {
                        c.to_string()
                    }
                })
                .collect();
            assert!(key.len() > RAW.len() && !key.contains(RAW), "{key}");
            key
        };
        let dollar = escaped(&['$']);
        let colons = escaped(&[':']);
        let several = escaped(&['$', ':', 'R']);
        type Parser = fn(&[u8]) -> Result<Value>;
        let parsers: [(&str, Parser); 3] = [
            ("ordinary", parse_json),
            ("rpc", |bytes| parse_rpc_json(bytes, 32_768)),
            ("wallet", |bytes| parse_wallet_json(bytes, 32_768)),
        ];
        for (name, parse) in parsers {
            for refused in [
                format!(r#"{{"{RAW}":"[1,2]"}}"#),
                format!(r#"{{"{RAW}":false}}"#),
                format!(r#"{{"a":1,"{RAW}":2}}"#),
                format!(r#"{{"id":1,"params":{{"{RAW}":"{deep}"}}}}"#),
                format!(r#"[{{"x":[{{"{RAW}":"{{}}"}}]}}]"#),
                // An embedded document written with escapes in its string.
                r#"{"$serde_json::private::RawValue":"{\"k\":3}"}"#.to_owned(),
                // JSON escapes spell the same key, first or later: the refusal
                // follows the decoded key, as serde_json's own reader does.
                format!(r#"{{"{dollar}":"[1]"}}"#),
                format!(r#"{{"{colons}":"[1]"}}"#),
                format!(r#"{{"a":1,"{several}":2}}"#),
                r#"{"$serde_json::private::Number":"1"}"#.to_owned(),
            ] {
                let error = parse(refused.as_bytes()).unwrap_err().to_string();
                assert!(error.contains("reserved"), "{name} {refused}: {error}");
            }
            // Other keys, and the token as a string value, are ordinary JSON.
            for accepted in [
                r#"{"$ref":1,"$serde_json":2}"#.to_owned(),
                format!(r#"{{"id":"{RAW}","params":["{RAW}"]}}"#),
            ] {
                let value = parse(accepted.as_bytes()).unwrap();
                assert_eq!(value, serde_json::from_str::<Value>(&accepted).unwrap());
                let written = serde_json::to_vec(&value).unwrap();
                assert_eq!(
                    parse(&written).unwrap(),
                    value,
                    "{name} reads back {accepted}"
                );
            }
        }
        assert!(json_key_allowed("version-rolling"));
        assert!(json_key_allowed(&"k".repeat(MAX_JSON_KEY_BYTES)));
        assert!(!json_key_allowed(&"k".repeat(MAX_JSON_KEY_BYTES + 1)));
        assert!(!json_key_allowed(RAW));
    }
    #[test]
    fn addresses_in_one_prefix_share_an_aggregate_while_other_prefixes_stay_independent() {
        let guard = Arc::new(NetworkGuard::default());
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let reason = |error: anyhow::Error| error.downcast::<Limited>().unwrap().reason;
        let burst = Surface::Rpc.policy().work_burst as usize;
        // Each /64 carved from one native /48 has a whole address budget, but
        // 64 of them spending a sixteenth each exhaust the prefix's four.
        let carved = |n: u16| IpAddr::from([0x2001, 0xdb8, 0x77, n, 0, 0, 0, 1]);
        for n in 0..64 {
            let session = guard.admit(carved(n), Surface::Rpc).unwrap();
            session.work(burst / 16).unwrap();
        }
        let late = guard.admit(carved(64), Surface::Rpc).unwrap();
        let error = late.work(burst / 16).unwrap_err();
        assert_eq!(reason(error), "network rate budget exhausted");
        // The refusal was the prefix's: the newcomer kept its own budget and
        // no cooldown, and a /64 in another /48 is independent.
        drop(late);
        assert!(guard.admit(carved(64), Surface::Rpc).is_ok());
        let other = IpAddr::from([0x2001, 0xdb8, 0x78, 0, 0, 0, 0, 1]);
        assert!(
            guard
                .admit(other, Surface::Rpc)
                .unwrap()
                .work(burst)
                .is_ok()
        );
        // IPv4 addresses share their /24, and a 6to4 source the /24 its
        // IPv4 host belongs to.
        for host in 1..=3 {
            let address = IpAddr::from([198, 51, 100, host]);
            guard
                .admit(address, Surface::Rpc)
                .unwrap()
                .work(burst)
                .unwrap();
        }
        let tunnel = ip("2002:c633:6404:7::1");
        guard
            .admit(tunnel, Surface::Rpc)
            .unwrap()
            .work(burst)
            .unwrap();
        let neighbour = guard.admit(ip("198.51.100.5"), Surface::Rpc).unwrap();
        assert!(neighbour.work(burst / 2).is_err());
        let next = guard.admit(ip("198.51.101.5"), Surface::Rpc).unwrap();
        assert!(next.work(burst).is_ok());
        // Concurrent sessions of a prefix share its connection cap too.
        let held: Vec<_> = (0..32)
            .map(|n| guard.admit(carved(100 + n / 8), Surface::Rpc).unwrap())
            .collect();
        let error = guard.admit(carved(200), Surface::Rpc).err().unwrap();
        assert_eq!(reason(error), "per-network connection limit");
        drop(held);
        // On RPC every loopback address, ::1 included, is one local source.
        for host in 2..=5 {
            let local = IpAddr::from([127, 0, 0, host]);
            guard
                .admit(local, Surface::Rpc)
                .unwrap()
                .work(burst)
                .unwrap();
        }
        for local in ["127.0.0.9", "::1", "127.255.0.1"] {
            let session = guard.admit(ip(local), Surface::Rpc).unwrap();
            assert!(session.work(burst / 2).is_err(), "{local}");
        }
        // Peers and miners on loopback, and other local networks, keep
        // per-address accounting.
        let peer_burst = Surface::Peer.policy().work_burst as usize;
        for host in 2..=9 {
            let local = IpAddr::from([127, 0, 0, host]);
            guard
                .admit(local, Surface::Peer)
                .unwrap()
                .work(peer_burst)
                .unwrap();
            let private = IpAddr::from([10, 0, 0, host]);
            guard
                .admit(private, Surface::Rpc)
                .unwrap()
                .work(burst)
                .unwrap();
        }
        // Connections this node opens are never aggregated.
        for host in 1..=8 {
            let destination = IpAddr::from([198, 51, 102, host]);
            let session = guard.admit_outbound(destination, Surface::Peer).unwrap();
            session.outgoing(0, peer_burst).unwrap();
        }
    }
    #[test]
    fn a_prefix_cools_down_only_when_several_of_its_members_misbehave() {
        let guard = Arc::new(NetworkGuard::default());
        let host = |n: u8| IpAddr::from([203, 0, 113, n]);
        // However often one member misbehaves, only it cools down.
        let noisy = guard.admit(host(1), Surface::Peer).unwrap();
        for _ in 0..6 {
            noisy.malformed();
        }
        assert!(guard.admit(host(1), Surface::Peer).is_err());
        assert!(guard.admit(host(2), Surface::Peer).is_ok());
        // Once four distinct members did so within a minute, a fresh member
        // of the prefix is refused and told when the prefix cools off.
        for n in 2..=4 {
            guard.admit(host(n), Surface::Peer).unwrap().malformed();
        }
        let error = guard.admit(host(9), Surface::Peer).err().unwrap();
        let limited = error.downcast::<Limited>().unwrap();
        assert_eq!(limited.reason, "temporary network cooldown");
        assert!(limited.retry_after.unwrap() <= Duration::from_millis(250));
        assert!(
            guard
                .admit("203.0.114.9".parse().unwrap(), Surface::Peer)
                .is_ok()
        );
        // Local software on loopback never cools the operator out of RPC.
        for n in 2..=9 {
            let local = IpAddr::from([127, 0, 0, n]);
            guard.admit(local, Surface::Rpc).unwrap().malformed();
        }
        assert!(
            guard
                .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
                .is_ok()
        );
    }
    #[test]
    fn strikes_lapse_a_minute_after_the_last_penalty_however_busy_the_record_stays() {
        let now = Instant::now();
        let mut record = Record::new(Surface::Rpc.policy(), now);
        record.penalize(now);
        record.penalize(now + Duration::from_secs(1));
        assert_eq!(record.strikes, 2);
        // Admitted calls kept the record active meanwhile.
        let later = now + Duration::from_secs(70);
        record.last = later;
        record.penalize(later);
        assert_eq!(record.strikes, 1);
        assert_eq!(record.cooldown, later + Duration::from_millis(250));
    }
    #[test]
    fn wallet_calls_keep_a_reserve_that_flooding_visitors_cannot_spend() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let visitor = |n: u8, essential: bool| -> Session {
            let session = guard.admit(proxy, Surface::Rpc).unwrap();
            session.forwarded_for(IpAddr::from([203, 0, n, 1])).unwrap();
            if !essential {
                session.nonessential();
            }
            session
        };
        // Sixteen visitors from sixteen networks flood explorer reads until
        // their own shares, or the shared budget outside the reserve, refuse.
        let mut admitted = 0;
        for n in 1..=16 {
            let flood = visitor(n, false);
            while flood.work(4_160).is_ok() {
                admitted += 1;
            }
        }
        // Sixteen shares could have spent the whole budget; they spent about
        // three quarters of it (189 such reads), plus any refill meanwhile.
        assert!((180..=191).contains(&admitted), "{admitted}");
        // A seventeenth visitor's further explorer read is refused, but its
        // snapshot and broadcast are admitted from the reserve.
        assert!(visitor(17, false).work(4_160).is_err());
        let wallet = visitor(17, true);
        for _ in 0..10 {
            wallet.work(4_610).unwrap();
        }
    }
    #[test]
    fn one_visitor_fetching_large_blocks_cannot_starve_another_visitors_snapshot() {
        const MIB: usize = 1024 * 1024;
        let guard = Arc::new(NetworkGuard::for_public_web());
        guard.set_frame(200 * MIB).unwrap();
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let visitor = |client: &str, essential: bool| -> Session {
            let session = guard.admit(proxy, Surface::Rpc).unwrap();
            session.forwarded_for(client.parse().unwrap()).unwrap();
            if !essential {
                session.nonessential();
            }
            session
        };
        // One maximal reply always fits a visitor's burst, above the reserve.
        let blocks = visitor("198.51.100.1", false);
        blocks.outgoing(200 * MIB, 0).unwrap();
        // The next waits for that visitor's own eighth of the byte rate.
        let error = blocks.outgoing(MIB, 0).unwrap_err();
        let wait = error.downcast::<Limited>().unwrap().retry_after.unwrap();
        assert!(wait >= Duration::from_millis(240), "{wait:?}");
        // Another visitor's explorer reply waits for the shared budget to
        // refill, but its snapshot reply is served from the reserve.
        assert!(visitor("192.0.2.1", false).outgoing(4 * MIB, 0).is_err());
        let wallet = visitor("192.0.2.1", true);
        for _ in 0..16 {
            wallet.outgoing(64 * 1024, 0).unwrap();
        }
    }
    #[test]
    fn a_largest_reply_and_a_page_load_fit_a_visitor_however_many_networks_are_active() {
        const MIB: usize = 1024 * 1024;
        let guard = Arc::new(NetworkGuard::for_public_web());
        guard.set_frame(200 * MIB).unwrap();
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let visitor = |client: IpAddr| -> Session {
            let session = guard.admit(proxy, Surface::Rpc).unwrap();
            session.forwarded_for(client).unwrap();
            session
        };
        // Counted afresh: charges reuse a share for up to 100 milliseconds.
        let share = || guard.count_visitor_shares(&guard.records.lock().unwrap(), Instant::now());
        // Forty /64s of one /48 count at most the four shares their aggregate
        // may spend: the share stays an eighth.
        for n in 0..40 {
            visitor(IpAddr::from([0x2001, 0xdb8, 0x77, n, 0, 0, 0, 1]))
                .request()
                .unwrap();
        }
        assert_eq!(share(), PUBLIC_WEB_VISITOR_SHARE);
        // A visitor in a cooldown that admission refuses counts not at all.
        let refused: IpAddr = "198.51.100.200".parse().unwrap();
        let named = (refused, Surface::Rpc, Direction::Forwarded, Scope::Address);
        guard.records.lock().unwrap().insert(named, {
            let mut record = Record::new(guard.key_policy(named, 8), Instant::now());
            record.cooldown = Instant::now() + Duration::from_secs(60);
            record
        });
        let session = guard.admit(proxy, Surface::Rpc).unwrap();
        assert!(session.forwarded_for(refused).is_err());
        assert_eq!(share(), PUBLIC_WEB_VISITOR_SHARE);
        // Thirty-two other networks make one call each: every visitor now
        // refills at a thirty-second of the shared rates.
        for n in 1..=32 {
            visitor(IpAddr::from([203, 0, n, 1])).request().unwrap();
        }
        assert_eq!(share(), PUBLIC_WEB_MAX_VISITOR_SHARE);
        // An explorer reply of 200 MiB pays 204,800 work units, more than a
        // thirty-second of the shared work burst. It still fits at once, and
        // the next one waits for refill instead of never fitting.
        let reader = visitor("192.0.2.7".parse().unwrap());
        reader.nonessential();
        let work = 200 * MIB / REPLY_BYTES_PER_WORK as usize;
        reader.outgoing(200 * MIB, work).unwrap();
        let error = reader.outgoing(200 * MIB, work).unwrap_err();
        let wait = error.downcast::<Limited>().unwrap().retry_after;
        assert!(wait.is_some_and(|wait| wait > Duration::ZERO), "{wait:?}");
        // A browser loading the wallet twice, with its scripts and startup
        // calls, makes about 48 requests through the proxy, each a named
        // connection and a request. None is refused.
        let browser: IpAddr = "192.0.2.8".parse().unwrap();
        for _ in 0..48 {
            visitor(browser).request().unwrap();
        }
    }
    #[test]
    fn the_visitor_share_counts_each_prefix_up_to_its_aggregate_and_is_reused_briefly() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let now = Instant::now();
        let direct = |ip: IpAddr| {
            guard
                .admit_at(ip, Surface::Rpc, Direction::Inbound, now)
                .unwrap()
        };
        // Two /24s with six active addresses each, as the finding's attack
        // used, count four shares each: what their aggregates may spend, not
        // one each as before. Two lone addresses add one each.
        let mut held = Vec::new();
        for net in [1u8, 2] {
            for host in 1..=6 {
                held.push(direct(IpAddr::from([198, 51, net, host])));
            }
        }
        for net in [3u8, 4] {
            held.push(direct(IpAddr::from([198, 51, net, 1])));
        }
        let counted = guard.count_visitor_shares(&guard.records.lock().unwrap(), now);
        assert_eq!(counted, 10);
        // The shares' request refill together stays within the base rate the
        // proxy keeps above its reserve, unlike two networks taking it all.
        let first = now + PUBLIC_WEB_SHARE_REFRESH;
        let share = guard.visitor_share(&guard.records.lock().unwrap(), first);
        assert_eq!(share, 10);
        let rate = |ip: IpAddr| {
            let key = (ip, Surface::Rpc, Direction::Inbound, Scope::Address);
            let aggregate = guard.aggregate_of(key).unwrap();
            guard.key_policy(aggregate, share).requests
        };
        let base = Surface::Rpc.policy().requests;
        let together = 2 * rate("198.51.1.1".parse().unwrap())
            + 2 * guard
                .key_policy(
                    (
                        "198.51.3.1".parse().unwrap(),
                        Surface::Rpc,
                        Direction::Inbound,
                        Scope::Address,
                    ),
                    share,
                )
                .requests;
        assert!(together <= base, "{together}");
        let proxy = (
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Surface::Rpc,
            Direction::Inbound,
            Scope::Address,
        );
        assert_eq!(
            guard.key_policy(proxy, share).requests,
            base + base / PUBLIC_WEB_ESSENTIAL_SHARE
        );
        // Charges and admissions reuse the share for 100 milliseconds instead
        // of scanning the accounting table each time, then count it afresh.
        for net in 10u8..30 {
            held.push(
                guard
                    .admit_at(
                        IpAddr::from([203, 0, net, 1]),
                        Surface::Rpc,
                        Direction::Inbound,
                        first,
                    )
                    .unwrap(),
            );
        }
        let soon = first + Duration::from_millis(50);
        assert_eq!(
            guard.visitor_share(&guard.records.lock().unwrap(), soon),
            10
        );
        let later = first + PUBLIC_WEB_SHARE_REFRESH;
        assert_eq!(
            guard.visitor_share(&guard.records.lock().unwrap(), later),
            30
        );
    }
    #[test]
    fn refused_visitors_and_page_floods_leave_the_proxys_request_reserve() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        // A visitor in a long cooldown keeps trying through the proxy, more
        // times than the proxy's whole request burst. Each attempt is refused
        // by the visitor's own record and returns the unit the proxy paid to
        // admit its connection.
        let cooling: IpAddr = "198.51.100.77".parse().unwrap();
        let named = (cooling, Surface::Rpc, Direction::Forwarded, Scope::Address);
        guard.records.lock().unwrap().insert(named, {
            let mut record = Record::new(guard.key_policy(named, 8), Instant::now());
            record.cooldown = Instant::now() + Duration::from_secs(60);
            record
        });
        for _ in 0..2_000 {
            let session = guard.admit(proxy, Surface::Rpc).unwrap();
            assert!(session.forwarded_for(cooling).is_err());
            session.refund_refused_visitor();
        }
        // Wallet calls of other visitors are still admitted.
        let wallet = guard.admit(proxy, Surface::Rpc).unwrap();
        wallet.forwarded_for("192.0.2.40".parse().unwrap()).unwrap();
        wallet.request().unwrap();
        drop(wallet);
        // Page loads are not wallet-critical: their request units leave a
        // quarter of the proxy's base burst, which a wallet call may spend.
        let pages = guard.admit(proxy, Surface::Rpc).unwrap();
        pages.nonessential();
        while pages.request().is_ok() {}
        let level = guard.records.lock().unwrap()[&(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Surface::Rpc,
            Direction::Inbound,
            Scope::Address,
        )]
            .requests
            .tokens;
        let (floor, _, _) = NetworkGuard::essential_reserve();
        assert!((floor..floor + 8).contains(&level), "{level}");
        let wallet = guard.admit(proxy, Surface::Rpc).unwrap();
        wallet.request().unwrap();
    }
    #[test]
    fn every_rpc_work_burst_admits_one_largest_request() {
        // A broadcast of a 64 MiB transaction pays about 1.98 million units,
        // more than the private RPC burst of 1,048,576; one of 8 MiB pays
        // about 250,000, more than a visitor's 197,632 burst.
        let largest = 1_980_000;
        let private = Arc::new(NetworkGuard::default());
        let local = private
            .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
            .unwrap();
        assert!(private.policy(Surface::Rpc).work_burst < largest as u64);
        // Once the capacity's largest request is allowed, an existing session
        // is admitted at once, and a lower allowance changes nothing.
        private.allow_rpc_work(largest).unwrap();
        private.allow_rpc_work(1).unwrap();
        assert_eq!(private.policy(Surface::Rpc).work_burst, largest as u64);
        local.work(largest).unwrap();
        // A public visitor's burst, and the proxy's above its reserve, too.
        let public = Arc::new(NetworkGuard::for_public_web());
        public.set_frame(193 * 1024 * 1024).unwrap();
        let visitor = public
            .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
            .unwrap();
        visitor
            .forwarded_for("198.51.100.90".parse().unwrap())
            .unwrap();
        let broadcast = 250_000;
        let named = visitor.visitor.get().unwrap().0;
        assert!(public.key_policy(named, 8).work_burst < broadcast as u64);
        public.allow_rpc_work(broadcast).unwrap();
        visitor.work(broadcast).unwrap();
    }
    #[test]
    fn only_wallet_critical_calls_spend_the_largest_request_allowance() {
        // At the governed maximum one largest request, a broadcast of a
        // 64 MiB transaction, pays about 1.98 million units, and every
        // visitor's work burst grows to admit it. Before, every call could
        // spend that growth: one visitor's explorer and governance reads
        // took the proxy's whole pool above its reserve in one burst,
        // denying those reads to everyone else.
        let largest = 1_980_000;
        let guard = Arc::new(NetworkGuard::for_public_web());
        guard.set_frame(193 * 1024 * 1024).unwrap();
        guard.allow_rpc_work(largest as usize).unwrap();
        let proxy = (
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Surface::Rpc,
            Direction::Inbound,
            Scope::Address,
        );
        let pool = guard.key_policy(proxy, 8).work_burst - NetworkGuard::essential_reserve().2;
        assert!(pool >= largest);
        let visitor = |n: u8| {
            let session = guard
                .admit("127.0.0.1".parse().unwrap(), Surface::Rpc)
                .unwrap();
            session
                .forwarded_for(IpAddr::from([198, 51, 100, n]))
                .unwrap();
            session
        };
        // One visitor's reads now stop at its ordinary burst, the work of one
        // largest reply (197,632 at the 193 MiB response limit): about a
        // tenth of that pool, as before governance raised capacity.
        let reader = visitor(1);
        reader.nonessential();
        let mut spent = 0;
        while reader.outgoing(0, 4096).is_ok() {
            spent += 4096;
        }
        assert!(spent > 190_000 && spent * 10 <= pool, "{spent} of {pool}");
        // Such a refusal only asks the reader to wait for its refill.
        let refusal = reader.outgoing(0, 4096).unwrap_err();
        assert!(
            refusal
                .downcast_ref::<Limited>()
                .unwrap()
                .retry_after
                .is_some()
        );
        // A read pricier than that ordinary burst never runs on the public
        // listener, as before.
        let pricey = visitor(2);
        pricey.nonessential();
        let refusal = pricey.outgoing(0, 197_633).unwrap_err();
        assert!(
            refusal
                .downcast_ref::<Limited>()
                .unwrap()
                .retry_after
                .is_none()
        );
        // A wallet-critical call may still spend the whole burst: a largest
        // broadcast fits a visitor's, even after the reads above.
        visitor(3).work(largest as usize).unwrap();
    }
    #[test]
    fn unused_reserved_work_returns_to_every_record_that_paid_it() {
        let guard = Arc::new(NetworkGuard::for_public_web());
        let proxy: IpAddr = "127.0.0.1".parse().unwrap();
        let visitor = guard.admit(proxy, Surface::Rpc).unwrap();
        visitor
            .forwarded_for("198.51.100.92".parse().unwrap())
            .unwrap();
        let burst = guard
            .key_policy(visitor.visitor.get().unwrap().0, 8)
            .work_burst as usize;
        visitor.outgoing(0, burst).unwrap();
        assert!(visitor.outgoing(0, 20_000).is_err());
        visitor.refund_work(burst / 2);
        visitor.outgoing(0, burst / 2 - 1_000).unwrap();
        assert!(visitor.outgoing(0, 20_000).is_err());
        // A direct client's own record and its aggregate are refunded too.
        let direct = guard
            .admit("198.51.101.1".parse().unwrap(), Surface::Rpc)
            .unwrap();
        direct.outgoing(0, burst).unwrap();
        direct.refund_work(burst);
        direct.outgoing(0, burst - 1_000).unwrap();
    }
    #[test]
    fn a_lower_frame_allowance_lowers_byte_bursts_and_frame_memory_again() {
        const MIB: usize = 1024 * 1024;
        let guard = Arc::new(NetworkGuard::default());
        let baseline = guard.frame_memory_limits();
        let peer = guard
            .admit("8.1.1.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        guard.set_frame(100 * MIB).unwrap();
        assert!(guard.frame_memory_limits().0 > baseline.0);
        // A peer's burst holds a session's two largest frames.
        assert_eq!(guard.policy(Surface::Peer).byte_burst, 200 * MIB as u64);
        // When the validated capacity falls again, so do the frame budget,
        // the one-frame byte burst and tokens already held above it.
        guard.set_frame(0).unwrap();
        assert_eq!(guard.frame_memory_limits(), baseline);
        let base = Surface::Peer.policy().byte_burst;
        assert_eq!(guard.policy(Surface::Peer).byte_burst, base);
        let error = peer.bytes(base as usize + 1).unwrap_err();
        assert_eq!(error.downcast::<Limited>().unwrap().retry_after, None);
        let records = guard.records.lock().unwrap();
        assert!(
            records
                .values()
                .all(|record| record.bytes.tokens <= 4 * base)
        );
        let address = (
            peer.key.0,
            Surface::Peer,
            Direction::Inbound,
            Scope::Address,
        );
        assert!(records[&address].bytes.tokens <= base);
        drop(records);
        // A raise extends the burst again, refilling held tokens at once.
        guard.set_frame(100 * MIB).unwrap();
        let records = guard.records.lock().unwrap();
        assert_eq!(records[&address].bytes.tokens, 200 * MIB as u64);
    }
    #[test]
    fn frames_being_decoded_are_accounted_within_the_frame_memory_budget() {
        const MIB: usize = 1024 * 1024;
        const FRAME: u64 = 100 * MIB as u64;
        let guard = Arc::new(NetworkGuard::with_frame_limit(FRAME as usize));
        // The budget keeps one largest frame for each decoding worker beside
        // the five that buffered frames may hold: a decoded message exists
        // beside its frame's bytes until decoding ends.
        let (total, reserve) = guard.frame_memory_budget();
        assert_eq!(reserve, PEER_DECODERS as u64 * FRAME);
        assert_eq!(total, 5 * FRAME + reserve);
        assert_eq!(guard.frame_memory_limits().0, 5 * FRAME);
        let session = guard
            .admit("8.1.1.1".parse().unwrap(), Surface::Peer)
            .unwrap();
        session.begin_frame().unwrap();
        session.reserve_frame(MIB).unwrap();
        let decoding = session.decoding(MIB);
        assert_eq!(guard.frame_memory_in_use(), 2 * MIB as u64);
        // Decoding ends with its worker; the frame's reservation remains for
        // the decoded message until it has been processed.
        drop(decoding);
        assert_eq!(guard.frame_memory_in_use(), MIB as u64);
        session.frame_processed();
        assert_eq!(guard.frame_memory_in_use(), 0);
        // At the baseline the 64 MiB budget includes the reserve.
        let small = Arc::new(NetworkGuard::with_frame_limit(3 * MIB));
        let (total, reserve) = small.frame_memory_budget();
        assert_eq!((total, reserve), (PEER_FRAME_MEMORY, 6 * MIB as u64));
        assert_eq!(small.frame_memory_limits().0, total - reserve);
    }
    #[test]
    fn a_slow_maximal_frame_from_one_group_does_not_block_another_groups_frame() {
        const FRAME: usize = 64 * 1024 * 1024;
        let guard = Arc::new(NetworkGuard::with_frame_limit(FRAME));
        let group = |a: u8| IpAddr::from([8, a, 1, 1]);
        // Each of four groups holds a whole stalled frame; a fifth, and a
        // second frame in a group, find the shared part full.
        let stalled: Vec<_> = (1..=4)
            .map(|a| {
                let session = guard.admit(group(a), Surface::Peer).unwrap();
                session.reserve_frame(FRAME).unwrap();
                session
            })
            .collect();
        let fifth = guard.admit(group(5), Surface::Peer).unwrap();
        assert!(fifth.reserve_frame(1).unwrap_err().is::<Busy>());
        let sibling = guard
            .admit(IpAddr::from([8, 1, 2, 1]), Surface::Peer)
            .unwrap();
        assert!(sibling.reserve_frame(1).unwrap_err().is::<Busy>());
        // Configured and pinned peers still receive one.
        let configured = guard.admit(group(6), Surface::Peer).unwrap().operator();
        configured.reserve_frame(FRAME).unwrap();
        assert_eq!(configured.frame_progress(), None);
        assert_eq!(stalled[0].frame_progress(), Some((0, FRAME as u64)));
        stalled[0].begin_frame().unwrap();
        assert_eq!(stalled[0].frame_progress(), Some((1, 0)));
        fifth.reserve_frame(FRAME).unwrap();
    }
    /// Whether `slot` lost its general slot to a newcomer.
    fn taken_over(slots: &PeerSlots, slot: &PeerSlot) -> bool {
        let id = slot.occupant.expect("a general slot");
        !accounting(&slots.counts).occupants.contains_key(&id)
    }
    #[tokio::test]
    async fn a_full_general_pool_evicts_the_newest_session_of_the_most_represented_group() {
        use tokio::time::timeout;
        let slots = Arc::new(PeerSlots::default());
        let now = Instant::now();
        let public = |a: u8, b: u8| IpAddr::from([8, a, b, 1]);
        let evicted = |slot: &PeerSlot| {
            let eviction = slot.eviction();
            async move {
                timeout(Duration::from_millis(50), eviction.notified())
                    .await
                    .is_ok()
            }
        };
        // Twelve groups hold a general slot each, and groups 1 to 4 a second.
        let mut held = Vec::new();
        for (a, b) in (1..=12).map(|a| (a, 1)).chain((1..=4).map(|a| (a, 2))) {
            let slot = slots.try_acquire_at(public(a, b), PeerClass::General, now);
            held.push(slot.unwrap());
        }
        // At most four groups' oldest sessions and the four longest-connected
        // others are spared, and every session during its grace period. The
        // second sessions are the newest and belong to the most represented
        // groups, so group 4's goes first; its session is told to close at
        // once.
        assert!(
            slots
                .try_acquire_at(public(20, 1), PeerClass::General, now)
                .is_none()
        );
        let now = now + EVICTION_GRACE;
        let newcomer = slots
            .try_acquire_at(public(20, 1), PeerClass::General, now)
            .unwrap();
        assert!(evicted(&held[15]).await);
        assert!(!evicted(&held[14]).await);
        assert_eq!(held.iter().filter(|s| taken_over(&slots, s)).count(), 1);
        // A source that delivered a new block keeps its sessions: group 3's
        // second is spared, and group 2's goes next.
        slots.delivered_at(public(3, 2), now);
        let second = slots
            .try_acquire_at(public(21, 1), PeerClass::General, now)
            .unwrap();
        assert!(taken_over(&slots, &held[13]) && !taken_over(&slots, &held[14]));
        assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
        drop((held, newcomer, second));
        let counts = slots.counts.lock().unwrap();
        assert_eq!(
            (counts.general, counts.verified, counts.operator),
            (0, 0, 0)
        );
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
    }
    #[test]
    fn eviction_protection_is_bounded_however_many_groups_or_useful_sources_hold_slots() {
        let now = Instant::now();
        let public = |a: u8, b: u8| IpAddr::from([8, a, b, 1]);
        let fill = |slots: &Arc<PeerSlots>, sources: Vec<(IpAddr, PeerClass)>| -> Vec<PeerSlot> {
            let held: Vec<_> = sources
                .into_iter()
                .map(|(ip, class)| slots.try_acquire_at(ip, class, now).unwrap())
                .collect();
            assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
            held
        };
        // Sixteen groups each hold one general slot. A newcomer from a
        // seventeenth still takes one over once their grace periods are
        // over, and so does every later newcomer from yet another group:
        // one session each, never a refusal.
        let slots = Arc::new(PeerSlots::default());
        let held = fill(
            &slots,
            (1..=16)
                .map(|a| (public(a, 1), PeerClass::General))
                .collect(),
        );
        let mut newcomers = Vec::new();
        for a in 17..=60 {
            let at = now + EVICTION_GRACE * u32::from(a - 16);
            let slot = slots.try_acquire_at(public(a, 1), PeerClass::General, at);
            newcomers.push(slot.unwrap());
            let gone = held
                .iter()
                .chain(&newcomers)
                .filter(|s| taken_over(&slots, s));
            assert_eq!(gone.count(), newcomers.len());
            assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
        }
        drop((held, newcomers));
        // Eight groups of two recently verified peers, four of whose sources
        // delivered something new, cannot keep a newcomer out either, and the
        // session it takes over is not one of those sources'.
        let slots = Arc::new(PeerSlots::default());
        let sources = (1..=8).flat_map(|a| [public(a, 1), public(a, 2)]);
        let held = fill(
            &slots,
            sources.map(|ip| (ip, PeerClass::Verified)).collect(),
        );
        for a in 1..=4 {
            slots.delivered_at(public(a, 2), now);
        }
        let settled = now + EVICTION_GRACE;
        let newcomer = slots.try_acquire_at(public(30, 1), PeerClass::General, settled);
        assert!(newcomer.is_some());
        let gone: Vec<usize> = (0..held.len())
            .filter(|n| taken_over(&slots, &held[*n]))
            .collect();
        assert_eq!(gone.len(), 1);
        assert!(![1, 3, 5, 7].contains(&gone[0]), "{gone:?}");
        drop((held, newcomer));
        // Configured and pinned peers are never taken over: with twelve of
        // them, the four other sessions are the only candidates, and only
        // when they hold every general slot are newcomers refused.
        let slots = Arc::new(PeerSlots::default());
        let operators = (1..=12).map(|n| (public(40, n), PeerClass::Operator));
        let others = (1..=4).map(|a| (public(a, 1), PeerClass::General));
        let held = fill(&slots, operators.chain(others).collect());
        let mut newcomers = Vec::new();
        for a in 50..=53 {
            newcomers.push(
                slots
                    .try_acquire_at(public(a, 1), PeerClass::General, settled)
                    .unwrap(),
            );
        }
        assert!(held[..12].iter().all(|s| !taken_over(&slots, s)));
        let gone = held[12..]
            .iter()
            .chain(&newcomers)
            .filter(|s| taken_over(&slots, s));
        assert_eq!(gone.count(), 4);
        drop((held, newcomers));
        let all = (1..=16)
            .map(|n| (public(41, n), PeerClass::Operator))
            .collect();
        let operators = fill(&slots, all);
        assert!(
            slots
                .try_acquire_at(public(54, 1), PeerClass::General, now)
                .is_none()
        );
        drop(operators);
        let counts = slots.counts.lock().unwrap();
        assert_eq!(
            (counts.general, counts.verified, counts.operator),
            (0, 0, 0)
        );
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
    }
    #[test]
    fn trusted_stratum_addresses_survive_a_restart_and_operator_prefixes_always_qualify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.stratum-trusted.json");
        let now = Instant::now();
        let v4 = |c: u8, d: u8| IpAddr::from([8, 1, c, d]);
        let worker = v4(200, 1);
        let before = Arc::new(StratumPending::default());
        assert!(before.unsaved_trusted().is_none());
        before.try_acquire_at(worker, now).unwrap().authorized();
        let bytes = before.unsaved_trusted().unwrap();
        assert!(before.unsaved_trusted().is_none(), "saved once per change");
        StratumPending::persist_trusted(&path, &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // After a restart the general slots fill from sixteen groups, and the
        // worker that authorized before it still has a reserved slot.
        let after = Arc::new(StratumPending::default());
        after.load_trusted(&path).unwrap();
        assert!(after.unsaved_trusted().is_none());
        let mut held = Vec::new();
        for c in 1..=16 {
            for d in 1..=2 {
                for _ in 0..4 {
                    held.push(after.try_acquire_at(v4(c, d), now).unwrap());
                }
            }
        }
        assert!(after.try_acquire_at(v4(99, 1), now).is_none());
        held.push(after.try_acquire_at(worker, now).unwrap());
        // So does any address in a prefix the operator trusts.
        let farm: IpAddr = "203.0.113.77".parse().unwrap();
        assert!(after.try_acquire_at(farm, now).is_none());
        after.allow(&["203.0.113.0/24".parse().unwrap()]);
        held.push(after.try_acquire_at(farm, now).unwrap());
        assert_eq!(accounting(&after.counts).reserved, 2);
        drop(held);
        // A damaged file is refused whole, and a missing one holds nothing.
        fs::write(&path, b"{\"version\":1,\"addresses\":[\"8.1.200").unwrap();
        assert!(StratumPending::default().load_trusted(&path).is_err());
        let missing = dir.path().join("missing.json");
        assert!(StratumPending::default().load_trusted(&missing).is_ok());
        // Saving replaces the damaged file.
        StratumPending::persist_trusted(&path, &bytes).unwrap();
        assert!(StratumPending::default().load_trusted(&path).is_ok());
        let prefix = |text: &str| text.parse::<TrustedPrefix>();
        assert!(prefix("203.0.113.0/33").is_err() && prefix("x/8").is_err());
        assert!(
            prefix("2001:db8::/48")
                .unwrap()
                .contains("2001:db8:0:ffff::1".parse().unwrap())
        );
        assert!(
            !prefix("2001:db8::/48")
                .unwrap()
                .contains("2001:db9::1".parse().unwrap())
        );
        let mapped = prefix("::ffff:203.0.113.5").unwrap();
        assert_eq!(mapped.to_string(), "203.0.113.5/32");
        assert!(mapped.contains("203.0.113.5".parse().unwrap()));
    }
    #[test]
    fn a_session_keeps_its_slot_for_its_grace_period_however_newcomers_churn() {
        let slots = Arc::new(PeerSlots::default());
        let now = Instant::now();
        let public = |a: u8| IpAddr::from([8, a, 1, 1]);
        let held: Vec<_> = (1..=16)
            .map(|a| {
                slots
                    .try_acquire_at(public(a), PeerClass::General, now)
                    .unwrap()
            })
            .collect();
        // An honest newcomer takes over a slot whose session had its grace
        // period.
        let start = now + EVICTION_GRACE;
        let honest = slots
            .try_acquire_at(public(40), PeerClass::General, start)
            .unwrap();
        // A source reconnecting from ever new groups, once a second, takes
        // over the other sessions in turn, but never the honest one while it
        // may still be exchanging.
        let mut churn = Vec::new();
        for n in 1..EVICTION_GRACE.as_secs() as u8 {
            let at = start + Duration::from_secs(n.into());
            churn.push(
                slots
                    .try_acquire_at(public(40 + n), PeerClass::General, at)
                    .unwrap(),
            );
            assert!(!taken_over(&slots, &honest));
        }
        let last = start + EVICTION_GRACE - Duration::from_millis(1);
        churn.push(
            slots
                .try_acquire_at(public(70), PeerClass::General, last)
                .unwrap(),
        );
        assert!(held.iter().all(|slot| taken_over(&slots, slot)));
        // Once every unprotected session is within its grace period, a
        // newcomer is refused rather than displacing one of them.
        assert!(
            slots
                .try_acquire_at(public(71), PeerClass::General, last)
                .is_none()
        );
        assert!(!taken_over(&slots, &honest));
        // Afterwards the honest session is a candidate like any other.
        let after = start + EVICTION_GRACE;
        let next = slots.try_acquire_at(public(71), PeerClass::General, after);
        assert!(next.is_some() && taken_over(&slots, &honest));
        drop((held, honest, churn, next));
        let counts = slots.counts.lock().unwrap();
        assert_eq!((counts.general, counts.verified), (0, 0));
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
    }
    #[test]
    fn a_network_group_at_its_cap_rotates_rather_than_locking_its_members_out() {
        let now = Instant::now();
        let member = |c: u8| IpAddr::from([8, 1, c, 1]);
        // One address holds both of its /16's sessions. Another member of
        // that /16 still gets one at once: the address holding more than its
        // share gives its oldest up, however recently it was admitted.
        let slots = Arc::new(PeerSlots::default());
        let squatter: Vec<_> = (0..2)
            .map(|_| {
                slots
                    .try_acquire_at(member(1), PeerClass::General, now)
                    .unwrap()
            })
            .collect();
        let honest = slots
            .try_acquire_at(member(2), PeerClass::General, now)
            .unwrap();
        assert!(taken_over(&slots, &squatter[0]) && !taken_over(&slots, &squatter[1]));
        // Reconnecting cannot take that session back while the honest one
        // holds the group's other slot, however long it has run.
        let later = now + EVICTION_GRACE * 2;
        assert!(
            slots
                .try_acquire_at(member(1), PeerClass::General, later)
                .is_none()
        );
        assert!(!taken_over(&slots, &honest));
        drop((squatter, honest));
        // Two addresses holding one session each, however recently admitted
        // and whatever they delivered, cannot keep a third out while general
        // slots are free: it takes one beyond the cap, and nobody's session
        // is taken over.
        let slots = Arc::new(PeerSlots::default());
        let (first, second) = (
            slots
                .try_acquire_at(member(1), PeerClass::General, now)
                .unwrap(),
            slots
                .try_acquire_at(member(2), PeerClass::General, now)
                .unwrap(),
        );
        slots.delivered_at(member(1), now);
        slots.delivered_at(member(2), now);
        let third = slots
            .try_acquire_at(member(3), PeerClass::General, now)
            .unwrap();
        assert!(!taken_over(&slots, &first) && !taken_over(&slots, &second));
        // Reconnecting before the grace period ends does not help them keep
        // it out either.
        drop((first, third));
        let first = slots
            .try_acquire_at(member(1), PeerClass::General, now)
            .unwrap();
        let third = slots
            .try_acquire_at(member(3), PeerClass::General, now)
            .unwrap();
        assert_eq!(slots.counts.lock().unwrap().general, 3);
        drop((first, second, third));
        // Once the general slots are full, members keep their grace periods
        // against each other, but a newcomer from another group takes over
        // the session beyond the cap at once, whatever its age.
        let slots = Arc::new(PeerSlots::default());
        let held: Vec<_> = (1..=3)
            .map(|c| {
                slots
                    .try_acquire_at(member(c), PeerClass::General, now)
                    .unwrap()
            })
            .chain((2..=14).map(|a| {
                slots
                    .try_acquire_at(IpAddr::from([8, a, 1, 1]), PeerClass::General, now)
                    .unwrap()
            }))
            .collect();
        assert_eq!(slots.counts.lock().unwrap().general, INBOUND_PEER_SLOTS);
        assert!(
            slots
                .try_acquire_at(member(4), PeerClass::General, now)
                .is_none()
        );
        let outsider = slots
            .try_acquire_at(IpAddr::from([8, 20, 1, 1]), PeerClass::General, now)
            .unwrap();
        assert!(taken_over(&slots, &held[2]));
        assert_eq!(held.iter().filter(|s| taken_over(&slots, s)).count(), 1);
        // A member newcomer then takes over the member session past its grace
        // period whose source delivered something new least recently,
        // however recently that was.
        slots.delivered_at(member(1), now);
        slots.delivered_at(member(2), now + Duration::from_secs(1));
        let settled = now + EVICTION_GRACE;
        let fourth = slots
            .try_acquire_at(member(4), PeerClass::General, settled)
            .unwrap();
        assert!(taken_over(&slots, &held[0]) && !taken_over(&slots, &held[1]));
        drop((held, outsider, fourth));
        let counts = slots.counts.lock().unwrap();
        assert_eq!(counts.general, 0);
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
    }
    #[test]
    fn recently_verified_peers_take_over_each_others_slots_after_their_grace_period() {
        let slots = Arc::new(PeerSlots::default());
        let now = Instant::now();
        let public = |a: u8| IpAddr::from([8, a, 1, 1]);
        // Configured peers hold every general slot, four recently verified
        // peers the verified ones.
        let operators: Vec<_> = (1..=16)
            .map(|n| {
                slots
                    .try_acquire_at(IpAddr::from([9, 1, 1, n]), PeerClass::Operator, now)
                    .unwrap()
            })
            .collect();
        let verified: Vec<_> = (1..=4)
            .map(|a| {
                slots
                    .try_acquire_at(public(a), PeerClass::Verified, now)
                    .unwrap()
            })
            .collect();
        assert!(verified.iter().all(|slot| slot.pool == PeerClass::Verified));
        // A fifth waits while they are within their grace periods, then takes
        // over the longest-held one whose source delivered nothing new.
        assert!(
            slots
                .try_acquire_at(public(5), PeerClass::Verified, now)
                .is_none()
        );
        slots.delivered_at(public(1), now);
        let settled = now + EVICTION_GRACE;
        let fifth = slots
            .try_acquire_at(public(5), PeerClass::Verified, settled)
            .unwrap();
        assert_eq!(fifth.pool, PeerClass::Verified);
        assert!(!taken_over(&slots, &verified[0]) && taken_over(&slots, &verified[1]));
        assert!(eviction_notified(&verified[1]));
        // Other newcomers never take a verified slot.
        assert!(
            slots
                .try_acquire_at(public(6), PeerClass::General, settled)
                .is_none()
        );
        drop((operators, verified, fifth));
        let counts = slots.counts.lock().unwrap();
        assert_eq!(
            (counts.general, counts.verified, counts.operator),
            (0, 0, 0)
        );
        assert!(counts.groups.is_empty() && counts.occupants.is_empty());
    }
    /// Whether `slot`'s session was told to close.
    fn eviction_notified(slot: &PeerSlot) -> bool {
        let notified = slot.eviction();
        let waiting = notified.notified();
        tokio::pin!(waiting);
        // A stored permit completes the first poll at once.
        let waker = std::task::Waker::noop();
        waiting
            .as_mut()
            .poll(&mut std::task::Context::from_waker(waker))
            .is_ready()
    }
    #[test]
    fn configured_and_pinned_addresses_are_not_refused_through_their_prefix_aggregate() {
        let now = Instant::now();
        let neighbour = |d: u8| IpAddr::from([8, 1, 1, d]);
        let pinned = neighbour(200);
        // Four neighbours in the pinned peer's /24 misbehave, so the /24
        // cools down for all its members.
        let guard = Arc::new(NetworkGuard::default());
        for d in 1..=4 {
            let session = guard
                .admit_at(neighbour(d), Surface::Peer, Direction::Inbound, now)
                .unwrap();
            session.malformed();
        }
        let refused = guard
            .admit_at(neighbour(5), Surface::Peer, Direction::Inbound, now)
            .err()
            .unwrap();
        assert!(refused.to_string().contains("cooldown"), "{refused:#}");
        assert!(
            guard
                .admit_at(pinned, Surface::Peer, Direction::Inbound, now)
                .is_err()
        );
        // The pinned address is charged to its own record only, and keeps
        // its share of frame memory.
        let session = guard.admit_operator_at(pinned, Surface::Peer, now).unwrap();
        session.request().unwrap();
        session.bytes(1024).unwrap();
        assert_eq!(session.frame_progress(), None);
        drop(session);
        // Nor can neighbours holding every connection the /24 may have keep
        // it out. Its own address's limits still apply.
        let guard = Arc::new(NetworkGuard::default());
        let held: Vec<_> = (1..=4)
            .flat_map(|d| [d; 4])
            .map(|d| {
                guard
                    .admit_at(neighbour(d), Surface::Peer, Direction::Inbound, now)
                    .unwrap()
            })
            .collect();
        let refused = guard
            .admit_at(pinned, Surface::Peer, Direction::Inbound, now)
            .err()
            .unwrap();
        assert!(refused.to_string().contains("per-network"), "{refused:#}");
        let own: Vec<_> = (0..4)
            .map(|_| guard.admit_operator_at(pinned, Surface::Peer, now).unwrap())
            .collect();
        assert!(guard.admit_operator_at(pinned, Surface::Peer, now).is_err());
        drop((held, own));
    }
    #[test]
    fn only_a_block_that_became_the_tip_counts_as_advancing_this_node() {
        let slots = PeerSlots::default();
        let now = Instant::now();
        let (relayer, miner) = (IpAddr::from([8, 1, 1, 1]), IpAddr::from([8, 2, 1, 1]));
        slots.delivered_at(relayer, now);
        slots.advanced_at(miner, now);
        assert!(slots.delivered_since(relayer, now) && !slots.advanced_since(relayer, now));
        // A tip block is also a delivery, which protects inbound sessions.
        assert!(slots.delivered_since(miner, now) && slots.advanced_since(miner, now));
        let later = now + Duration::from_secs(1);
        assert!(!slots.delivered_since(miner, later) && !slots.advanced_since(miner, later));
        // Credit belongs to the admission address: an IPv6 host's /64.
        let host = |n: u16| IpAddr::from([0x2001, 0x4860, 1, 2, 0, 0, 0, n]);
        slots.advanced_at(host(1), later);
        assert!(slots.advanced_since(host(2), later));
        // Headers or blocks of a heavier branch not adopted yet are progress,
        // but neither advance this node nor protect inbound sessions.
        let follower = IpAddr::from([8, 3, 1, 1]);
        slots.progressed_at(follower, later);
        assert!(slots.progressed_since(follower, later));
        assert!(!slots.advanced_since(follower, now) && !slots.delivered_since(follower, now));
        assert!(!slots.progressed_since(miner, now) && !slots.progressed_since(relayer, now));
    }
    #[test]
    fn broad_public_trusted_prefixes_need_an_explicit_override() {
        let prefix = |text: &str| text.parse::<TrustedPrefix>();
        // A /0, or any public prefix shorter than IPv4 /16 or IPv6 /32, would
        // treat much of the internet as the operator's own miners.
        for broad in [
            "0.0.0.0/0",
            "::/0",
            "198.50.0.0/15",
            "2001:db8::/31",
            "11.0.0.0/8",
            "0.0.0.0/1",
            "172.32.0.0/12",
            "100.128.0.0/10",
            "fe00::/8",
            "::ffff:0.0.0.0/96",
        ] {
            let error = prefix(broad).unwrap_err().to_string();
            assert!(
                error.contains("--stratum-trusted-broad") || error.contains("exceeds"),
                "{broad}: {error}"
            );
        }
        for narrow in [
            "198.51.0.0/16",
            "2001:db8::/32",
            "203.0.113.9",
            "2001:db8::7",
        ] {
            assert!(prefix(narrow).is_ok(), "{narrow}");
        }
        // The operator's own local networks may be named whole.
        for local in [
            "10.0.0.0/8",
            "127.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "fd00::/8",
            "fc00::/7",
            "fe80::/10",
            "::1",
        ] {
            assert!(prefix(local).is_ok(), "{local}");
        }
        // The explicit override accepts any length, and keeps parsing exact.
        let everything = TrustedPrefix::broad("0.0.0.0/0").unwrap();
        assert!(everything.contains("8.8.8.8".parse().unwrap()));
        assert!(!everything.contains("2001:db8::1".parse().unwrap()));
        assert!(TrustedPrefix::broad("::/0").is_ok());
        assert!(TrustedPrefix::broad("0.0.0.0/33").is_err());
        assert!(TrustedPrefix::broad("miner.example/8").is_err());
    }
    #[test]
    fn pending_slots_tell_operator_prefixes_from_recent_authorizations() {
        let pending = Arc::new(StratumPending::default());
        let now = Instant::now();
        let farm: IpAddr = "203.0.113.77".parse().unwrap();
        let miner: IpAddr = "198.51.100.8".parse().unwrap();
        pending.allow(&["203.0.113.0/24".parse().unwrap()]);
        let slot = pending.try_acquire_at(farm, now).unwrap();
        assert!(slot.operator_trusted());
        let first = pending.try_acquire_at(miner, now).unwrap();
        assert!(!first.operator_trusted());
        first.authorized();
        // A recent authorization keeps reserved slots, but only an operator
        // prefix lifts the limits of authorized workers.
        let again = pending.try_acquire_at(miner, now).unwrap();
        assert!(!again.operator_trusted() && !again.charged);
        drop((slot, again));
    }
    #[test]
    fn authorized_workers_are_grouped_by_their_network() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        assert_eq!(stratum_group(ip("198.51.100.7")), ip("198.51.100.0"));
        assert_eq!(stratum_group(ip("::ffff:198.51.100.7")), ip("198.51.100.0"));
        assert_eq!(stratum_group(ip("2001:db8:7:9::1")), ip("2001:db8:7::"));
        // A local network keeps one group per address.
        assert_eq!(stratum_group(ip("192.168.1.20")), ip("192.168.1.20"));
        assert_eq!(stratum_group(ip("127.0.88.4")), ip("127.0.88.4"));
    }
}
