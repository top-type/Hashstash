//! Standalone, local-only transaction review and signing. No node or peer client.
use crate::{
    address, codec, crypto,
    types::{Hash, TransactionBody},
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
};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, oneshot},
    task::JoinHandle,
};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CONTROL_REQUEST: usize = 128 * 1024;
const INDEX: &str = include_str!("../cold-ui/index.html");
const SCRIPT: &str = include_str!("../cold-ui/app.js");
const SHARES: &str = include_str!("../ui/shares.js");
const AMOUNTS: &str = include_str!("../ui/amounts.js");
const STYLE: &str = include_str!("../cold-ui/style.css");

struct Review {
    token: String,
    body: TransactionBody,
}

#[derive(Default)]
struct WalletState {
    secret: Option<Zeroizing<[u8; 32]>>,
    review: Option<Review>,
    chain_id: Option<Hash>,
}

impl WalletState {
    fn clear_wallet(&mut self) {
        self.secret = None;
        self.review = None;
    }
    fn status(&self) -> Result<Value> {
        let public = self
            .secret
            .as_ref()
            .map(|secret| crypto::public_key(secret))
            .transpose()?;
        let encoded = public
            .as_ref()
            .zip(self.chain_id.as_ref())
            .map(|(key, chain)| address::encode(key, chain))
            .transpose()?;
        let public = public.map(hex::encode);
        let chain = self.chain_id.map(hex::encode);
        let watch = public.as_ref().map(|public| {
            if let (Some(address), Some(chain)) = (encoded.as_ref(), chain.as_ref()) {
                json!({"format":"hashstash-watch-v2","public_key":public,"address":address,"chain_id":chain})
            } else {
                json!({"format":"hashstash-watch-v1","public_key":public})
            }
        });
        Ok(
            json!({"public_key":public,"chain_id":chain,"address":encoded,"watch":watch,"unlocked":public.is_some()}),
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
}

pub struct ColdServer {
    pub address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ColdServer {
    pub async fn stop(mut self) {
        if let Some(stop) = self.shutdown.take() {
            let _ = stop.send(());
        }
        let _ = self.task.await;
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
    ensure!(
        address.ip().is_loopback() && address.is_ipv4(),
        "cold signer requires IPv4 loopback"
    );
    let listener = TcpListener::bind(address).await?;
    let address = listener.local_addr()?;
    let app = App {
        wallet: Arc::new(Mutex::new(WalletState {
            chain_id,
            ..WalletState::default()
        })),
        jobs: Arc::new(Semaphore::new(1)),
        host: address.to_string(),
        origin: format!("http://{address}"),
        token: token()?,
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
        .route("/api/import", post(import))
        .route("/api/lock", post(lock))
        .route(
            "/api/review",
            post(review).layer(DefaultBodyLimit::disable()),
        )
        .route("/api/cancel", post(cancel))
        .route("/api/sign", post(sign))
        .layer(DefaultBodyLimit::max(MAX_CONTROL_REQUEST))
        .layer(middleware::from_fn_with_state(app.clone(), protect))
        .with_state(app.clone());
    let (shutdown, receive) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, routes)
            .with_graceful_shutdown(async {
                let _ = receive.await;
            })
            .await;
        if let Ok(mut state) = app.wallet.lock() {
            *state = WalletState::default();
        }
    });
    Ok(ColdServer {
        address,
        shutdown: Some(shutdown),
        task,
    })
}

async fn session(State(app): State<App>) -> Response {
    let Ok(state) = app.wallet.lock() else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "Signer unavailable");
    };
    match state.status() {
        Ok(mut status) => {
            status["format"] = json!("hashstash-cold-v1");
            status["token"] = json!(app.token);
            Json(status).into_response()
        }
        Err(problem) => error(StatusCode::INTERNAL_SERVER_ERROR, &problem.to_string()),
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
        state.chain_id = Some(chain);
        state.status()
    })
    .await
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
        work(&mut state)
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
}

async fn unlock(State(app): State<App>, bytes: Bytes) -> Response {
    let bytes = Zeroizing::new(bytes.to_vec());
    job(app, move |state| {
        // A new import always invalidates the old wallet and pending review.
        state.clear_wallet();
        let mut request: Unlock =
            serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid passphrase request"))?;
        let derived = wallet::derive_secret(&request.passphrase);
        request.passphrase.zeroize();
        let secret = derived?;
        state.secret = Some(secret);
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
    let bytes = Zeroizing::new(bytes.to_vec());
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
        crypto::public_key(&secret)?;
        state.secret = Some(secret);
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
    job(app, move |state| {
        state.review = None;
        let secret = state
            .secret
            .as_ref()
            .ok_or_else(|| anyhow!("Open a wallet first"))?;
        let envelope = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow!("Invalid unsigned transaction envelope"))?;
        let body = wallet::decode_unsigned(&envelope)?;
        ensure!(
            body.sender == crypto::public_key(secret)?,
            "Transaction sender does not match this wallet"
        );
        ensure!(
            state.chain_id.is_none_or(|chain| chain == body.chain_id),
            "Transaction belongs to another network; change the selected network to review it"
        );
        state.chain_id = Some(body.chain_id);
        let review_token = token()?;
        let fields: Vec<_> = wallet::review(&body)
            .into_iter()
            .map(|field| json!({"label":field.label,"value":field.value}))
            .collect();
        let body_hex = hex::encode(codec::encode(&body));
        state.review = Some(Review {
            token: review_token.clone(),
            body,
        });
        let mut status = state.status()?;
        status["review_token"] = json!(review_token);
        status["fields"] = json!(fields);
        status["body"] = json!(body_hex);
        Ok(status)
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sign {
    review_token: String,
}

async fn sign(State(app): State<App>, bytes: Bytes) -> Response {
    job(app, move |state| {
        let request: Sign = serde_json::from_slice(&bytes).map_err(|_| anyhow!("Invalid sign request"))?;
        let secret = state.secret.as_ref().ok_or_else(|| anyhow!("Open a wallet first"))?;
        let review = state.review.as_ref().ok_or_else(|| anyhow!("Review the transaction first"))?;
        ensure!(review.token == request.review_token, "Review changed; review the transaction again");
        let transaction = crypto::sign(&review.body, secret)?;
        crypto::verify(&transaction)?;
        state.review = None;
        Ok(json!({"raw":wallet::signed_hex(&transaction),"txid":hex::encode(codec::transaction_id(&transaction))}))
    }).await
}
