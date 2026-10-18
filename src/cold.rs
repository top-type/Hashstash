//! Standalone, local-only transaction review and signing. No node or peer client.
use crate::{
    address, codec, crypto,
    types::{Hash, PublicKey, TransactionBody},
    wallet,
};
use anyhow::{Result, anyhow, ensure};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CONTROL_REQUEST: usize = 128 * 1024;
/// Default ceiling for one unsigned export. Governance can raise block capacity
/// past it; `hashstash-cold --max-review-bytes` raises this local limit.
pub const DEFAULT_MAX_REVIEW_REQUEST: usize = 64 * 1024 * 1024;
/// An open wallet locks itself after this long without an authorized request.
pub const DEFAULT_IDLE_LOCK: Duration = Duration::from_secs(5 * 60);
const IDLE_LOCKED: &str = "Wallet locked after a period without use; open it again";
/// Default ceiling on the payments one grant review lists. Each is key-checked,
/// address-encoded and shown as two fields, so bytes alone do not bound the
/// work; `hashstash-cold --max-review-payments` raises it.
pub const DEFAULT_MAX_REVIEW_PAYMENTS: usize = 4096;
/// Connections served at once. A browser opens at most six to one origin;
/// further connections, from anything else on loopback, are closed unread.
pub const MAX_CONNECTIONS: usize = 16;

/// Keeps a loaded key out of the crash dumps the signer can refuse itself. On
/// Unix its core file size limit becomes zero, and on Linux the process is
/// also marked not dumpable, which keeps other programs of the same account
/// from attaching a debugger to read its memory. On Windows the launcher
/// excludes the signer from Windows Error Reporting instead.
pub fn suppress_core_dumps() -> Result<()> {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, setrlimit};
        let none = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        setrlimit(Resource::Core, none).map_err(|e| anyhow!("cannot disable core dumps: {e}"))?;
    }
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|e| anyhow!("cannot mark the signer not dumpable: {e}"))?;
    Ok(())
}

/// Local bounds on one offline review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewLimits {
    /// Bytes of one unsigned export request.
    pub bytes: usize,
    /// Grant payments in one reviewed transaction.
    pub payments: usize,
}
impl Default for ReviewLimits {
    fn default() -> Self {
        Self {
            bytes: DEFAULT_MAX_REVIEW_REQUEST,
            payments: DEFAULT_MAX_REVIEW_PAYMENTS,
        }
    }
}
const INDEX: &str = include_str!("../cold-ui/index.html");
const SCRIPT: &str = include_str!("../cold-ui/app.js");
const SHARES: &str = include_str!("../ui/shares.js");
const AMOUNTS: &str = include_str!("../ui/amounts.js");
const STYLE: &str = include_str!("../cold-ui/style.css");

struct Review {
    token: String,
    body: TransactionBody,
    /// The selected network the review showed; the signature binds it.
    chain_id: Hash,
    long_lifetime: bool,
}

#[derive(Default)]
struct WalletState {
    secret: Option<Zeroizing<[u8; 32]>>,
    /// Derived once when a key is loaded, so status needs no further key copies.
    public: Option<PublicKey>,
    /// The network salting a v2 passphrase key; selecting another network locks it.
    derived_for: Option<Hash>,
    /// A generated key whose backup the operator has not yet confirmed saving.
    backup_pending: bool,
    review: Option<Review>,
    chain_id: Option<Hash>,
    /// The last authorized request that left a wallet open.
    last_used: Option<Instant>,
    /// The idle lock closed the wallet, and none has been opened since.
    idle_locked: bool,
}

impl WalletState {
    fn clear_wallet(&mut self) {
        self.secret = None;
        self.public = None;
        self.derived_for = None;
        self.backup_pending = false;
        self.review = None;
        self.last_used = None;
        self.idle_locked = false;
    }
    /// Locks a wallet left unused for `idle`.
    fn expire(&mut self, idle: Duration) {
        if self.secret.is_some() && self.last_used.is_none_or(|used| used.elapsed() >= idle) {
            self.clear_wallet();
            self.idle_locked = true;
        }
    }
    fn touch(&mut self) {
        self.last_used = self.secret.is_some().then(Instant::now);
    }
    fn load(&mut self, secret: Zeroizing<[u8; 32]>, derived_for: Option<Hash>) -> Result<()> {
        self.public = Some(crypto::public_key(&secret)?);
        self.secret = Some(secret);
        self.derived_for = derived_for;
        self.backup_pending = false;
        Ok(())
    }
    fn backup(&self) -> Result<Value> {
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| anyhow!("Open a wallet first"))?;
        let private_key = Zeroizing::new(hex::encode(secret.as_slice()));
        Ok(
            json!({"format":"hashstash-private-v1","private_key":private_key.as_str(),"public_key":self.public.map(hex::encode)}),
        )
    }
    fn status(&self) -> Result<Value> {
        let public = self.public;
        // An unsaved generated key must not be funded: no address or
        // watch-only export until its backup is confirmed.
        let shown = public.filter(|_| !self.backup_pending);
        let encoded = shown
            .as_ref()
            .zip(self.chain_id.as_ref())
            .map(|(key, chain)| address::encode(key, chain))
            .transpose()?;
        let chain = self.chain_id.map(hex::encode);
        let watch = shown.map(hex::encode).map(|public| {
            if let (Some(address), Some(chain)) = (encoded.as_ref(), chain.as_ref()) {
                json!({"format":"hashstash-watch-v2","public_key":public,"address":address,"chain_id":chain})
            } else {
                json!({"format":"hashstash-watch-v1","public_key":public})
            }
        });
        Ok(
            json!({"public_key":public.map(hex::encode),"chain_id":chain,"address":encoded,"watch":watch,"unlocked":public.is_some(),"backup_pending":self.backup_pending,"idle_locked":self.idle_locked}),
        )
    }
}

#[derive(Clone)]
struct App {
    wallet: Arc<Mutex<WalletState>>,
    jobs: Arc<Semaphore>,
    host: String,
    origin: String,
    token: String,
    limits: ReviewLimits,
    idle_lock: Duration,
}

/// Signer settings beyond its listening address.
#[derive(Clone)]
pub struct ColdOptions {
    /// A trusted network identity from a local config or explicit argument.
    pub chain_id: Option<Hash>,
    /// Bounds one unsigned export request and the grant it may list.
    pub limits: ReviewLimits,
    /// The browser session token, 64 lowercase hexadecimal characters, or a
    /// random one. It is delivered only in the launch URL, never served.
    pub token: Option<String>,
    /// An open wallet locks after this long without an authorized request.
    pub idle_lock: Duration,
}

impl Default for ColdOptions {
    fn default() -> Self {
        Self {
            chain_id: None,
            limits: ReviewLimits::default(),
            token: None,
            idle_lock: DEFAULT_IDLE_LOCK,
        }
    }
}

pub struct ColdServer {
    pub address: SocketAddr,
    token: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    sweeper: JoinHandle<()>,
}

impl ColdServer {
    /// The browser session token. Loopback is shared by every local account
    /// and service, so only whoever started the signer receives it.
    pub fn token(&self) -> &str {
        &self.token
    }
    /// The interface with its session token in the URL fragment, which the
    /// browser never sends; the page then removes it from the address bar.
    pub fn launch_url(&self) -> String {
        format!("http://{}/#token={}", self.address, self.token)
    }
    pub async fn stop(mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
        self.sweeper.abort();
    }
}

fn token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("OS randomness: {e}"))?;
    Ok(hex::encode(bytes))
}

fn error(code: StatusCode, message: &str) -> Response {
    (code, Json(json!({"error": message}))).into_response()
}

async fn protect(State(app): State<App>, request: Request, next: Next) -> Response {
    let headers = request.headers();
    let one = |name: &str| {
        let mut values = headers.get_all(name).iter();
        let value = values.next()?.to_str().ok()?;
        if values.next().is_some() {
            None
        } else {
            Some(value)
        }
    };
    let same_origin = one("origin").is_none_or(|v| v == app.origin);
    let same_site = one("sec-fetch-site").is_none_or(|v| v == "same-origin" || v == "none");
    let allowed = one("host") == Some(app.host.as_str()) && same_origin && same_site;
    let authorized = request.method() != Method::POST
        || (one("origin") == Some(app.origin.as_str())
            && one("x-hashstash-cold-token") == Some(app.token.as_str())
            && one("content-type")
                .is_some_and(|v| v.split(';').next() == Some("application/json")));
    let mut response = if allowed && authorized {
        next.run(request).await
    } else {
        error(StatusCode::FORBIDDEN, "Local session required")
    };
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

/// Starts one loopback listener. The signer never connects to a node or a peer.
pub async fn serve(address: SocketAddr) -> Result<ColdServer> {
    serve_with_chain(address, None).await
}

/// Supplies a trusted chain identity from a local config or explicit argument.
pub async fn serve_with_chain(address: SocketAddr, chain_id: Option<Hash>) -> Result<ColdServer> {
    serve_with_limits(address, chain_id, ReviewLimits::default()).await
}

/// `limits` bounds one unsigned export request and the grant it may list.
pub async fn serve_with_limits(
    address: SocketAddr,
    chain_id: Option<Hash>,
    limits: ReviewLimits,
) -> Result<ColdServer> {
    serve_with_options(
        address,
        ColdOptions {
            chain_id,
            limits,
            ..ColdOptions::default()
        },
    )
    .await
}

/// Starts one loopback listener with explicit settings.
pub async fn serve_with_options(address: SocketAddr, options: ColdOptions) -> Result<ColdServer> {
    ensure!(
        address.ip().is_loopback() && address.is_ipv4(),
        "cold signer requires IPv4 loopback"
    );
    ensure!(
        options.limits.bytes >= MAX_CONTROL_REQUEST,
        "review limit must be at least {MAX_CONTROL_REQUEST} bytes"
    );
    ensure!(
        options.limits.payments > 0,
        "review payment limit must be positive"
    );
    ensure!(!options.idle_lock.is_zero(), "idle lock must be positive");
    let session_token = match options.token {
        Some(chosen) => {
            ensure!(
                chosen.len() == 64
                    && chosen
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "session token must be 64 lowercase hexadecimal characters"
            );
            chosen
        }
        None => token()?,
    };
    let listener = TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let app = App {
        wallet: Arc::new(Mutex::new(WalletState {
            chain_id: options.chain_id,
            ..WalletState::default()
        })),
        jobs: Arc::new(Semaphore::new(1)),
        host: address.to_string(),
        origin: format!("http://{address}"),
        token: session_token.clone(),
        limits: options.limits,
        idle_lock: options.idle_lock,
    };
    // Requests apply the idle lock themselves; this also wipes a forgotten
    // key while nobody uses the signer.
    let sweeper = {
        let wallet = Arc::downgrade(&app.wallet);
        let idle = app.idle_lock;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(idle.min(Duration::from_secs(1)));
            loop {
                tick.tick().await;
                let Some(wallet) = wallet.upgrade() else {
                    break;
                };
                // A busy signer is in use; its next request checks again.
                if let Ok(mut state) = wallet.try_lock() {
                    state.expire(idle);
                }
            }
        })
    };
    let routes = Router::new()
        .route(
            "/",
            get(|| async { ([("content-type", "text/html; charset=utf-8")], INDEX) }),
        )
        .route(
            "/app.js",
            get(|| async { ([("content-type", "text/javascript; charset=utf-8")], SCRIPT) }),
        )
        .route(
            "/shares.js",
            get(|| async { ([("content-type", "text/javascript; charset=utf-8")], SHARES) }),
        )
        .route(
            "/amounts.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    AMOUNTS,
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async { ([("content-type", "text/css; charset=utf-8")], STYLE) }),
        )
        .route("/api/session", get(session))
        .route("/api/network", post(network))
        .route("/api/unlock", post(unlock))
        .route("/api/generate", post(generate))
        .route("/api/backup", post(backup))
        .route("/api/import", post(import))
        .route("/api/lock", post(lock))
        .route(
            "/api/review",
            post(review).layer(DefaultBodyLimit::max(options.limits.bytes)),
        )
        .route("/api/cancel", post(cancel))
        .route("/api/sign", post(sign))
        .layer(DefaultBodyLimit::max(MAX_CONTROL_REQUEST))
        .layer(middleware::from_fn_with_state(app.clone(), protect))
        .with_state(app.clone());
    let (shutdown, receive) = oneshot::channel();
    let task = tokio::spawn(async move {
        crate::local_http::serve(
            listener,
            routes,
            MAX_CONNECTIONS,
            crate::local_http::HEAD_TIMEOUT,
            async {
                let _ = receive.await;
            },
        )
        .await;
        if let Ok(mut state) = app.wallet.lock() {
            *state = WalletState::default();
        }
    });
    Ok(ColdServer {
        address,
        token: session_token,
        shutdown: Some(shutdown),
        task,
        sweeper,
    })
}

/// Status only. Loopback is shared by every local account and service, so
/// the session token is never served here; the page reads its launch URL.
async fn session(State(app): State<App>) -> Response {
    // A long review holds the wallet lock; wait for it off the async workers.
    let wallet = app.wallet.clone();
    let idle = app.idle_lock;
    let status = tokio::task::spawn_blocking(move || {
        let mut state = wallet.lock().map_err(|_| anyhow!("Signer unavailable"))?;
        // Reading status never extends an idle wallet's lifetime.
        state.expire(idle);
        state.status()
    })
    .await;
    match status {
        Ok(Ok(mut status)) => {
            status["format"] = json!("hashstash-cold-v1");
            status["max_review_bytes"] = json!(app.limits.bytes);
            status["max_review_payments"] = json!(app.limits.payments);
            status["idle_lock_seconds"] = json!(app.idle_lock.as_secs());
            Json(status).into_response()
        }
        Ok(Err(problem)) => error(StatusCode::INTERNAL_SERVER_ERROR, &problem.to_string()),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Signer unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    chain_id: String,
}

async fn network(State(app): State<App>, bytes: Bytes) -> Response {
    job(app, move |state| {
        state.review = None;
        let request: Network =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid network request"))?;
        ensure!(
            request.chain_id.len() == 64,
            "Chain ID must contain 64 hexadecimal characters"
        );
        let mut chain = [0; 32];
        hex::decode_to_slice(request.chain_id, &mut chain)
            .map_err(|_| anyhow!("Invalid chain ID"))?;
        // A v2 passphrase account exists only on the network that salted it.
        if state.derived_for.is_some_and(|salt| salt != chain) {
            state.clear_wallet();
        }
        state.chain_id = Some(chain);
        state.status()
    })
    .await
}

/// Request bodies carrying secrets are reused in place when unshared, so the
/// wiped buffer is the one that held the request.
fn secret_body(bytes: Bytes) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::from(bytes))
}

async fn job<F>(app: App, work: F) -> Response
where
    F: FnOnce(&mut WalletState) -> Result<Value> + Send + 'static,
{
    let Ok(permit) = app.jobs.clone().try_acquire_owned() else {
        return error(StatusCode::CONFLICT, "Signer busy");
    };
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut state = app
            .wallet
            .lock()
            .map_err(|_| anyhow!("Signer unavailable"))?;
        // An idle wallet locks before any request can use it. A request that
        // needed it then says why, whichever check locked it.
        state.expire(app.idle_lock);
        let result = work(&mut state);
        let idle_locked = state.idle_locked;
        state.touch();
        match result {
            Err(_) if idle_locked => Err(anyhow!(IDLE_LOCKED)),
            other => other,
        }
    })
    .await
    {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(problem)) => error(StatusCode::BAD_REQUEST, &problem.to_string()),
        Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "Signer unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    passphrase: String,
    /// Required: v2 for passphrase accounts, v1 only to restore legacy ones.
    scheme: Option<String>,
}

async fn unlock(State(app): State<App>, bytes: Bytes) -> Response {
    let bytes = secret_body(bytes);
    job(app, move |state| {
        // A new import always invalidates the old wallet and pending review.
        state.clear_wallet();
        let mut request: Unlock =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid passphrase request"))?;
        let derived = match request.scheme.as_deref() {
            Some(wallet::PASSPHRASE_V2_SCHEME) => match state.chain_id {
                Some(chain) => wallet::derive_secret_v2(&request.passphrase, &chain)
                    .map(|key| (key, Some(chain))),
                None => Err(anyhow!(
                    "Select the network first: v2 passphrase accounts belong to one network"
                )),
            },
            Some(wallet::PASSPHRASE_SCHEME) => {
                wallet::derive_secret(&request.passphrase).map(|key| (key, None))
            }
            _ => Err(anyhow!("Choose a passphrase scheme")),
        };
        request.passphrase.zeroize();
        let (secret, derived_for) = derived?;
        state.load(secret, derived_for)?;
        state.status()
    })
    .await
}

/// Creates a random key from OS randomness and returns its only backup. Any
/// local process can read the session token, so the key is never released
/// again: until the operator confirms saving it, the signer shows no address
/// or watch-only export and reviews nothing, and a reload must generate anew.
async fn generate(State(app): State<App>) -> Response {
    job(app, |state| {
        state.clear_wallet();
        let secret = loop {
            let mut secret = Zeroizing::new([0u8; 32]);
            getrandom::fill(secret.as_mut()).map_err(|e| anyhow!("OS randomness: {e}"))?;
            if crypto::public_key(&secret).is_ok() {
                break secret;
            }
        };
        state.load(secret, None)?;
        state.backup_pending = true;
        let mut status = state.status()?;
        status["backup"] = state.backup()?;
        Ok(status)
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    saved: bool,
}

/// Records that the operator stored a generated key's backup. It never
/// returns the key: that left the signer once, in the /api/generate response.
async fn backup(State(app): State<App>, bytes: Bytes) -> Response {
    job(app, move |state| {
        let request: Backup =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid backup request"))?;
        ensure!(state.backup_pending, "No unsaved generated key");
        ensure!(
            request.saved,
            "The backup is shown only once, when the key is generated. Lock and generate a new key if it was not saved"
        );
        state.backup_pending = false;
        state.status()
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    private_key: String,
}

async fn import(State(app): State<App>, bytes: Bytes) -> Response {
    let bytes = secret_body(bytes);
    job(app, move |state| {
        state.clear_wallet();
        let request: Import =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid private key request"))?;
        let private_key = Zeroizing::new(request.private_key);
        let text = private_key.trim();
        ensure!(
            text.len() == 64,
            "Private key must contain 64 hexadecimal characters"
        );
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(text, secret.as_mut())
            .map_err(|_| anyhow!("Invalid private key hexadecimal encoding"))?;
        state.load(secret, None)?;
        state.status()
    })
    .await
}

async fn lock(State(app): State<App>) -> Response {
    job(app, |state| {
        state.clear_wallet();
        let mut status = state.status()?;
        status["locked"] = json!(true);
        Ok(status)
    })
    .await
}

async fn cancel(State(app): State<App>) -> Response {
    job(app, |state| {
        state.review = None;
        Ok(json!({"cancelled":true}))
    })
    .await
}

async fn review(State(app): State<App>, bytes: Bytes) -> Response {
    let limits = app.limits;
    job(app, move |state| {
        state.review = None;
        let public = state.public.ok_or_else(|| anyhow!("Open a wallet first"))?;
        ensure!(
            !state.backup_pending,
            "Save the new key's backup and confirm it before reviewing transactions"
        );
        // Only the operator selects the network, and the signature binds that
        // selection. Export context is checked against it, never adopted.
        let selected = state.chain_id.ok_or_else(|| {
            anyhow!("Select this signer's network before reviewing; the signature is bound to it")
        })?;
        let envelope = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("Invalid unsigned transaction envelope"))?;
        // Count grant payments before the per-payment key checks and fields.
        let body = wallet::decode_unsigned_shape(&envelope)?;
        let payments = wallet::grant_payments(&body);
        ensure!(
            payments <= limits.payments,
            "This grant lists {payments} payments; this signer reviews at most {}. Restart hashstash-cold with --max-review-payments to review it",
            limits.payments
        );
        wallet::validate_body(&body)?;
        let chain_id = wallet::unsigned_chain(&envelope)?;
        ensure!(
            body.sender == public,
            "Transaction sender does not match this wallet"
        );
        ensure!(
            chain_id == selected,
            "Export network context differs from the selected network"
        );
        let review_token = token()?;
        let fields: Vec<_> = wallet::review(&body, Some(&selected))
            .into_iter()
            .map(|field| json!({"label":field.label,"value":field.value}))
            .collect();
        let body_hex = hex::encode(codec::encode(&body));
        let long_lifetime = wallet::long_lifetime(&body);
        state.review = Some(Review {
            token: review_token.clone(),
            body,
            chain_id: selected,
            long_lifetime,
        });
        let mut status = state.status()?;
        status["review_token"] = json!(review_token);
        status["fields"] = json!(fields);
        status["body"] = json!(body_hex);
        status["confirm_lifetime"] = json!(long_lifetime);
        Ok(status)
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sign {
    review_token: String,
    /// Required for lifetimes above `wallet::LONG_LIFETIME_BLOCKS`.
    #[serde(default)]
    confirm_lifetime: bool,
}

async fn sign(State(app): State<App>, bytes: Bytes) -> Response {
    job(app, move |state| {
        let request: Sign = serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid sign request"))?;
        let secret = state.secret.as_ref().ok_or_else(|| anyhow!("Open a wallet first"))?;
        let review = state.review.as_ref().ok_or_else(|| anyhow!("Review the transaction first"))?;
        ensure!(review.token == request.review_token, "Review changed; review the transaction again");
        ensure!(
            !review.long_lifetime || request.confirm_lifetime,
            "Confirm the long transaction lifetime before signing"
        );
        let transaction = crypto::sign(&review.chain_id, &review.body, secret)?;
        crypto::verify(&review.chain_id, &transaction)?;
        state.review = None;
        Ok(json!({"raw":wallet::signed_hex(&transaction),"txid":hex::encode(codec::transaction_id(&transaction))}))
    }).await
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    /// Runs in a child test process, since the change applies to a whole
    /// process and cannot be undone.
    #[test]
    fn the_signer_process_cannot_dump_core() {
        const CHILD: &str = "HASHSTASH_CORE_DUMP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            super::suppress_core_dumps().unwrap();
            let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
            assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
            assert_eq!(
                rustix::process::dumpable_behavior().unwrap(),
                rustix::process::DumpableBehavior::NotDumpable
            );
            return;
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cold::tests::the_signer_process_cannot_dump_core",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let output = String::from_utf8_lossy(&child.stdout);
        assert!(
            child.status.success() && output.contains("1 passed"),
            "{output}"
        );
    }
}
