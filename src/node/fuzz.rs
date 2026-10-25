//! The node's private readers of hostile network input, each run over one
//! byte slice exactly as its listener runs it, for the fuzz targets in `fuzz/`
//! and their stable-toolchain runner in `tests/fuzz_parsers.rs`. Every reader
//! uses a fresh admission record, so one input's charges and cooldowns never
//! decide how a later input is read; an inbound peer session, which needs a
//! connection, and the held-header counts are here too. This is not a stable
//! interface.
use super::*;

const LISTENER: &str = "127.0.0.1:18480";

/// Each harness thread drives the async readers on its own runtime. A byte
/// slice never waits, so no input depends on wall-clock time.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    thread_local! {
        static RUNTIME: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("fuzz harness runtime");
    }
    RUNTIME.with(|runtime| runtime.block_on(future))
}

fn loopback(guard: NetworkGuard, surface: Surface) -> Result<Session> {
    Arc::new(guard).admit(IpAddr::from([127, 0, 0, 1]), surface)
}

/// The HTTP head and body reader of the private listener, or, with `public`,
/// of the public-web listener behind its loopback proxy, which also reads the
/// proxy's `X-Real-IP` visitor header. Returns the method, target and body.
pub fn http_request(
    raw: &[u8],
    public: bool,
    transaction_bytes: usize,
    session_token: Option<&str>,
) -> Result<(String, String, Vec<u8>)> {
    let guard = if public {
        NetworkGuard::for_public_web()
    } else {
        NetworkGuard::default()
    };
    let admission = loopback(guard, Surface::Rpc)?;
    let mut read = BufReader::new(raw);
    let request = block_on(read_http(
        &mut read,
        LISTENER.parse()?,
        &admission,
        public,
        transaction_bytes,
        session_token,
    ))?;
    Ok((request.method, request.path, request.body))
}

/// The `/rpc` body parser: the raw transaction or data field may use the
/// whole body, every other string keeps the ordinary JSON bounds.
pub fn rpc_body(bytes: &[u8]) -> Result<Value> {
    network_guard::parse_rpc_json(bytes, bytes.len())
}

/// The hot-wallet (`/api/wallet`) body parser.
pub fn wallet_body(bytes: &[u8]) -> Result<Value> {
    network_guard::parse_wallet_json(bytes, bytes.len())
}

/// One length-prefixed plain peer frame of at most `maximum` payload bytes,
/// read as a peer session reads it, then decoded with `limits`.
pub fn peer_frame(raw: &[u8], maximum: usize, limits: peer_wire::Limits) -> Result<PeerPacket> {
    let admission = loopback(NetworkGuard::default(), Surface::Peer)?;
    let mut read = BufReader::new(raw);
    let payload = block_on(read_peer_frame(&mut read, maximum, &admission))?;
    peer_wire::decode(&payload, limits)
}

/// One inbound peer connection on `stream`, served as the peer listener
/// serves a connection it accepted, less its slot selection: header
/// requests, the locator request, the push after it, or an address request.
/// Unlike the readers above, the session is admitted by the node's own
/// guard, as its frame allowance follows the node's capacity, so a caller
/// connects from a fresh source address to start without that address's
/// charges and cooldowns. Returns how the session ended.
pub async fn peer_session(node: &Node, stream: TcpStream) -> Result<()> {
    let admission = node.guard.admit(stream.peer_addr()?.ip(), Surface::Peer)?;
    super::peer_session(node.clone(), stream, admission, None).await
}

/// The headers the node holds for presync: all of them, those of chains
/// that claimed more work than the tip, and those a header download pins.
pub fn held_headers(node: &Node) -> Result<(usize, usize, usize)> {
    let inner = node.locked()?;
    Ok((
        inner.chain.held_header_count(),
        inner.chain.admitted_header_count(),
        inner.chain.pinned_header_count(),
    ))
}

/// A public-web JSON-RPC call: the public method allowlist, the visitor's
/// metered work and the public error mapping, from one visitor's session.
pub fn public_rpc(node: &Node, method: &str, params: Value) -> Result<Value> {
    let admission = Arc::new(NetworkGuard::for_public_web())
        .admit(IpAddr::from([192, 0, 2, 1]), Surface::Rpc)?;
    node.public_rpc(method, params, &admission)
}

/// How one in-memory Stratum session went.
pub struct StratumSession {
    /// How the session ended once its input ran out, or why it closed earlier.
    pub ended: Result<()>,
    /// Every line the session wrote, in order.
    pub replies: Vec<u8>,
    /// Mining workers still registered with the node after the session closed.
    pub workers: usize,
}

/// One mining connection with extranonce 1, served exactly as the Stratum
/// listener serves it with `password` and the default share difficulty: the
/// session reads `raw` as everything the miner sent, then sees it disconnect.
pub fn stratum_session(node: &Node, raw: &[u8], password: Option<&str>) -> StratumSession {
    // Sessions hand parsing and templates to a blocking pool, whose threads
    // a runtime joins when dropped. Joining threads from a thread-local
    // destructor deadlocks on Windows, so this runtime is never dropped.
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("fuzz harness runtime")
    });
    let mut replies = Vec::new();
    let ended = match loopback(NetworkGuard::default(), Surface::Stratum) {
        Ok(admission) => runtime.block_on(stratum_lines(
            node.clone(),
            raw,
            &mut replies,
            password.map(str::to_owned),
            DEFAULT_STRATUM_SHARE_DIFFICULTY,
            1u32.to_le_bytes(),
            admission,
            None,
        )),
        Err(error) => Err(error),
    };
    let workers = node.mining.unpoisoned().workers.len();
    StratumSession {
        ended,
        replies,
        workers,
    }
}
