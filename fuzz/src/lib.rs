//! Fuzz targets for every Hashstash parser that reads hostile input. The
//! cargo-fuzz binaries in `fuzz_targets/` run them under libFuzzer's coverage
//! guidance; `tests/fuzz_parsers.rs` runs the same targets from the same seeds
//! with a seeded mutator on the stable toolchain, and replays every input kept
//! under `fuzz/regressions/`.
//!
//! A target returns a short label naming what the input was accepted as or
//! why it was rejected; the stable runner keeps inputs with new labels. A
//! target panics only when the code under test panics or breaks one of the
//! invariants checked here: canonical decoding (one encoding per value),
//! agreement between the peer preflight and the consensus codec, agreement
//! between the bounded JSON parsers, the discovery address book's bounds, and
//! read-only RPC methods leaving the node unchanged.

use hashstash::{
    address, chat, codec,
    config::Config,
    crypto, mail, math, network_guard,
    node::{self, Node},
    peer_auth::{Channel, PeerPin, Policy},
    peer_wire::{self, Limits, Message, Sync},
    proposal_data,
    types::*,
    wallet,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, OnceLock},
};
use tokio::io::AsyncWriteExt;

/// How a target runs one input.
pub enum Run {
    /// A parser of one byte string.
    Bytes(fn(&[u8]) -> String),
    /// JSON-RPC dispatch on a disposable fixture node (see `fixture_node`).
    Node(fn(&Node, &[u8]) -> String),
}

pub struct Target {
    pub name: &'static str,
    pub run: Run,
    /// Valid and near-valid inputs the mutations start from. Node targets
    /// receive the fixture node, whose chain the seeds refer to.
    pub seeds: fn(Option<&Node>) -> Vec<Vec<u8>>,
    /// Tokens the mutator splices in: magic values, field names, delimiters.
    pub dictionary: &'static [&'static [u8]],
    /// The longest input worth trying; every parser bound is below it.
    pub max_len: usize,
    /// Relative cost of one input, so the stable runner can share a budget.
    pub cost: u32,
}

pub const TARGETS: &[Target] = &[
    Target {
        name: "peer_wire",
        run: Run::Bytes(peer_wire_message),
        seeds: peer_wire_seeds,
        dictionary: PEER_TOKENS,
        max_len: 64 * 1024,
        cost: 1,
    },
    Target {
        name: "codec_transaction",
        run: Run::Bytes(codec_transaction),
        seeds: transaction_seeds,
        dictionary: PEER_TOKENS,
        max_len: 16 * 1024,
        cost: 2,
    },
    Target {
        name: "codec_block",
        run: Run::Bytes(codec_block),
        seeds: block_seeds,
        dictionary: PEER_TOKENS,
        max_len: 64 * 1024,
        cost: 4,
    },
    Target {
        name: "json",
        run: Run::Bytes(json_body),
        seeds: json_seeds,
        dictionary: JSON_TOKENS,
        max_len: 16 * 1024,
        cost: 1,
    },
    Target {
        name: "http_request",
        run: Run::Bytes(http_request),
        seeds: http_seeds,
        dictionary: HTTP_TOKENS,
        max_len: 24 * 1024,
        cost: 1,
    },
    Target {
        name: "rpc_params",
        run: Run::Node(rpc_params),
        seeds: rpc_seeds,
        dictionary: RPC_TOKENS,
        max_len: 8 * 1024,
        cost: 8,
    },
    Target {
        name: "mail_envelope",
        run: Run::Bytes(mail_envelope),
        seeds: mail_seeds,
        dictionary: JSON_TOKENS,
        max_len: 4 * 1024,
        cost: 1,
    },
    Target {
        name: "plain_text",
        run: Run::Bytes(plain_text),
        seeds: text_seeds,
        dictionary: TEXT_TOKENS,
        max_len: 4 * 1024,
        cost: 1,
    },
    Target {
        name: "address",
        run: Run::Bytes(account_text),
        seeds: address_seeds,
        dictionary: ADDRESS_TOKENS,
        max_len: 256,
        cost: 1,
    },
    Target {
        name: "signed_record",
        run: Run::Bytes(signed_record),
        seeds: signed_record_seeds,
        dictionary: HEX_TOKENS,
        max_len: 32 * 1024,
        cost: 2,
    },
    Target {
        name: "unsigned_envelope",
        run: Run::Bytes(unsigned_envelope),
        seeds: unsigned_envelope_seeds,
        dictionary: JSON_TOKENS,
        max_len: 32 * 1024,
        cost: 2,
    },
    Target {
        name: "peer_channel",
        run: Run::Bytes(peer_channel),
        seeds: channel_seeds,
        dictionary: PEER_TOKENS,
        max_len: 2 * 1024,
        cost: 6,
    },
    Target {
        name: "address_book",
        run: Run::Bytes(address_book),
        seeds: address_book_seeds,
        dictionary: BOOK_TOKENS,
        max_len: 4 * 1024,
        cost: 8,
    },
];

pub fn target(name: &str) -> &'static Target {
    TARGETS
        .iter()
        .find(|target| target.name == name)
        .unwrap_or_else(|| panic!("unknown fuzz target {name}"))
}

/// One libFuzzer input; the cargo-fuzz binaries call only this.
pub fn fuzz_one(name: &str, data: &[u8]) {
    match target(name).run {
        Run::Bytes(run) => {
            run(data);
        }
        Run::Node(run) => {
            static FIXTURE: OnceLock<(tempfile::TempDir, Node)> = OnceLock::new();
            let (_, node) = FIXTURE.get_or_init(|| {
                let directory = tempfile::tempdir().expect("fixture directory");
                let node = fixture_node(directory.path());
                (directory, node)
            });
            run(node, data);
        }
    }
}

// ---------------------------------------------------------------------------
// Shared fixtures: the devnet chain, fixed public test keys and sample records.

/// Public test secrets only; never use these keys for funds.
fn secret(n: u8) -> [u8; 32] {
    [n; 32]
}
fn key(n: u8) -> PublicKey {
    crypto::public_key(&secret(n)).expect("fixture key")
}
fn config() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(Config::devnet)
}
fn chain_id() -> Hash {
    static CHAIN: OnceLock<Hash> = OnceLock::new();
    *CHAIN.get_or_init(|| config().chain_id())
}
fn genesis() -> Block {
    codec::genesis_block(config()).expect("devnet genesis")
}
fn genesis_hash() -> Hash {
    static HASH: OnceLock<Hash> = OnceLock::new();
    *HASH.get_or_init(|| codec::block_hash(&genesis()))
}

/// The node's own peer limits, and much tighter ones with the same frame size.
fn limits() -> [Limits; 2] {
    [
        Limits::from_config(config()),
        Limits {
            block_bytes: 4096,
            transaction_bytes: 2048,
            block_transactions: 4,
        },
    ]
}

fn mail_fixture() -> Vec<u8> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../tests/fixtures/mail-v2.json")).expect("fixture");
    hex::decode(fixture["data_hex"].as_str().expect("data_hex")).expect("fixture hex")
}

fn proposal_text() -> &'static [u8] {
    "Fund the shared relay for one season. 🌱".as_bytes()
}

fn sample_bodies() -> Vec<TransactionBody> {
    let body = |nonce: u64, operation: Operation, data: Vec<u8>| TransactionBody {
        sender: key(1),
        nonce,
        fee: 1000u32.into(),
        anchor: genesis_hash(),
        expiry_blocks: 100,
        operation,
        data,
    };
    let large = Amount::from(1u32) << 511usize;
    let mut payments: Vec<_> = (2..5u8)
        .map(|n| GrantPayment {
            recipient: key(n),
            amount: Amount::from(u32::from(n) * 1000),
        })
        .collect();
    payments.sort_by_key(|payment| payment.recipient);
    let description: Hash = Sha256::digest(proposal_text()).into();
    vec![
        body(
            0,
            Operation::TransferExact {
                recipient: key(2),
                amount: 5u32.into(),
            },
            Vec::new(),
        ),
        body(
            1,
            Operation::TransferExact {
                recipient: key(3),
                amount: large.clone(),
            },
            b"Hello from the fuzz corpus".to_vec(),
        ),
        body(
            2,
            Operation::TransferExact {
                recipient: key(2),
                amount: 1u32.into(),
            },
            mail_fixture(),
        ),
        body(
            3,
            Operation::Deposit {
                amount: Amount::from(10u32).pow(20),
                decision: None,
                outcome: None,
            },
            Vec::new(),
        ),
        body(
            4,
            Operation::Deposit {
                amount: 7u32.into(),
                decision: Some([4; 32]),
                outcome: Some(Outcome::Pass),
            },
            Vec::new(),
        ),
        body(
            5,
            Operation::Redeem {
                shares: large,
                decision: Some([5; 32]),
                outcome: Some(Outcome::Fail),
            },
            Vec::new(),
        ),
        body(
            6,
            Operation::Propose {
                round: 2,
                description,
                proposal: Proposal::Grant { payments },
                support: 9u32.into(),
            },
            proposal_text().to_vec(),
        ),
        body(
            7,
            Operation::Propose {
                round: 3,
                description: [6; 32],
                proposal: Proposal::Parameter {
                    parameter: Parameter::MaxPriceChangeBps,
                    old: 1000,
                    new: 500,
                },
                support: 1u32.into(),
            },
            Vec::new(),
        ),
        body(
            8,
            Operation::Support {
                round: 2,
                proposal: [7; 32],
                amount: 3u32.into(),
            },
            Vec::new(),
        ),
        body(
            u64::MAX - 1,
            Operation::Refund {
                round: u64::MAX,
                proposal: [8; 32],
            },
            Vec::new(),
        ),
    ]
}
fn sample_transactions() -> Vec<Transaction> {
    sample_bodies()
        .iter()
        .map(|body| crypto::sign(&chain_id(), body, &secret(1)).expect("fixture signature"))
        .collect()
}
fn sample_blocks() -> Vec<Block> {
    let genesis = genesis();
    let mut next = genesis.clone();
    next.header.previous = codec::block_hash(&genesis);
    next.height = 1;
    next.miner = key(9);
    next.transactions = sample_transactions().into_iter().take(3).collect();
    if let Ok(root) = codec::merkle_root(&next) {
        next.header.merkle_root = root;
    }
    vec![genesis, next]
}

fn rejected(error: impl std::fmt::Display) -> String {
    format!("rejected: {error}")
}

// ---------------------------------------------------------------------------
// Peer wire frames and the canonical codec.

/// A count in words: labels lose their digits when the stable runner compares them.
fn how_many(count: usize) -> &'static str {
    match count {
        0 => "no",
        1 => "one",
        _ => "several",
    }
}

fn message_kind(message: &Message) -> String {
    match message {
        Message::Ack => "ack".into(),
        Message::GetAddresses { advertise, .. } => {
            format!("get addresses, advertised {}", advertise.is_some())
        }
        Message::Addresses { addresses, .. } => format!("{} addresses", how_many(addresses.len())),
        Message::GetHeaders { locator, .. } => {
            format!("get headers, {} locators", how_many(locator.len()))
        }
        Message::Headers { headers, .. } => format!("{} headers", how_many(headers.len())),
        Message::Sync(sync) => format!(
            "sync: {} locators, {} blocks, {} transactions",
            how_many(sync.locator.len()),
            how_many(sync.blocks.len()),
            how_many(sync.transactions.len())
        ),
    }
}

/// A peer message, directly and behind the plain transport's length prefix.
pub fn peer_wire_message(data: &[u8]) -> String {
    let [wide, tight] = limits();
    let decoded = peer_wire::decode(data, wide);
    if let Ok(message) = &decoded {
        let encoded = peer_wire::encode(message, wide).expect("a decoded peer message re-encodes");
        assert!(encoded == data, "a peer message has exactly one encoding");
    }
    // Tighter limits only ever reject more.
    if let Ok(message) = peer_wire::decode(data, tight) {
        assert_eq!(decoded.as_ref().ok(), Some(&message));
    }
    // A plain peer session reads one length-prefixed frame, then decodes it.
    if let Ok(framed) = peer_wire::frame(data, wide.frame_bytes()) {
        let read = node::fuzz::peer_frame(&framed, wide.frame_bytes(), wide);
        assert_eq!(read.as_ref().ok(), decoded.as_ref().ok());
    }
    // The input as a raw stream, length prefix included.
    let _ = node::fuzz::peer_frame(data, wide.frame_bytes(), wide);
    match decoded {
        Ok(message) => message_kind(&message),
        Err(error) => rejected(error),
    }
}

fn operation_kind(operation: &Operation) -> &'static str {
    match operation {
        Operation::TransferExact { .. } => "transfer",
        Operation::Deposit { .. } => "deposit",
        Operation::Redeem { .. } => "redeem",
        Operation::Propose {
            proposal: Proposal::Grant { .. },
            ..
        } => "grant proposal",
        Operation::Propose { .. } => "parameter proposal",
        Operation::Support { .. } => "support",
        Operation::Refund { .. } => "refund",
    }
}

/// Everything a node, wallet or explorer derives from a decoded record.
fn inspect_transaction(tx: &Transaction) {
    let chain = chain_id();
    codec::transaction_id(tx);
    let _ = crypto::verify(&chain, tx);
    wallet::review(&tx.body, Some(&chain));
    wallet::review(&tx.body, None);
    wallet::long_lifetime(&tx.body);
    wallet::grant_payments(&tx.body);
    if mail::from_transaction(tx).is_some() {
        assert!(chat::from_transaction(tx).is_none(), "mail is never chat");
    }
    if let Some(text) = chat::from_transaction(tx) {
        assert_eq!(text.as_bytes(), tx.body.data);
    }
    if let Some(text) = proposal_data::from_transaction(tx) {
        assert_eq!(text.as_bytes(), tx.body.data);
    }
}

/// The peer wire carries and accepts every canonical record within its limits.
fn assert_relayed(message: Sync, limits: Limits) {
    let message = Message::Sync(message);
    let bytes =
        peer_wire::encode(&message, limits).expect("the peer wire encodes a canonical record");
    let decoded =
        peer_wire::decode(&bytes, limits).expect("the peer wire accepts a canonical record");
    assert_eq!(decoded, message);
}

pub fn codec_transaction(data: &[u8]) -> String {
    let tx: Transaction = match codec::decode(data, data.len()) {
        Ok(tx) => tx,
        Err(error) => return rejected(error),
    };
    assert!(codec::encode(&tx) == data, "one encoding per transaction");
    inspect_transaction(&tx);
    for limits in limits() {
        if data.len() <= limits.transaction_bytes {
            assert_relayed(
                Sync {
                    chain: chain_id(),
                    locator: Vec::new(),
                    blocks: Vec::new(),
                    transactions: vec![tx.clone()],
                },
                limits,
            );
        }
    }
    // The signed-record text form is the same record, checked for local shape.
    let shape = wallet::validate_body(&tx.body);
    let record = wallet::decode_signed_record(&wallet::signed_hex(&tx));
    assert_eq!(record.as_ref().ok(), shape.is_ok().then_some(&tx));
    format!(
        "{} with {} shape",
        operation_kind(&tx.body.operation),
        if shape.is_ok() { "valid" } else { "invalid" }
    )
}

pub fn codec_block(data: &[u8]) -> String {
    let block = match codec::decode_block(data, data.len()) {
        Ok(block) => block,
        Err(error) => return rejected(error),
    };
    assert!(codec::encode(&block) == data, "one encoding per block");
    codec::block_hash(&block);
    codec::is_current_header(&block.header);
    let _ = codec::merkle_root(&block);
    let _ = codec::body_size(&block);
    let _ = codec::coinbase(&block);
    if let Ok(target) = math::target_from_bits(block.header.bits) {
        let _ = math::check_pow(&block.header, &target);
    }
    for tx in &block.transactions {
        inspect_transaction(tx);
    }
    for limits in limits() {
        if data.len() <= limits.block_bytes
            && block.transactions.len() <= limits.block_transactions
            && block
                .transactions
                .iter()
                .all(|tx| codec::encode(tx).len() <= limits.transaction_bytes)
        {
            assert_relayed(
                Sync {
                    chain: chain_id(),
                    locator: vec![block.header.previous],
                    blocks: vec![block.clone()],
                    transactions: Vec::new(),
                },
                limits,
            );
        }
    }
    format!(
        "block with {} transactions",
        how_many(block.transactions.len())
    )
}

const PEER_TOKENS: &[&[u8]] = &[
    b"HSP2PBIN",
    &[0],
    &[1],
    &[0xfa],
    &[0xfb, 0xff, 0xff],
    &[0xfb, 0xfb, 0x00],
    &[0xfc, 0xff, 0xff, 0xff, 0xff],
    &[0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    &[0xfd, 0, 0, 0, 0, 1, 0, 0, 0],
    &[0xfe],
    &[0x05, 0x00, 0x00, 0x20],
    &[0xff, 0xff, 0x7f, 0x20],
    &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
    &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
];

fn peer_wire_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let [wide, _] = limits();
    let v4: SocketAddr = "198.51.100.7:18481".parse().expect("address");
    let v6: SocketAddr = "[2001:db8::1]:18481".parse().expect("address");
    let blocks = sample_blocks();
    let transactions = sample_transactions();
    let messages = [
        Message::Ack,
        Message::GetAddresses {
            chain: chain_id(),
            node: [3; 32],
            advertise: None,
        },
        Message::GetAddresses {
            chain: chain_id(),
            node: [3; 32],
            advertise: Some(v6),
        },
        Message::Addresses {
            chain: chain_id(),
            node: [4; 32],
            addresses: vec![v4, v6, v4],
        },
        Message::GetHeaders {
            chain: chain_id(),
            version: peer_wire::TRANSPORT_VERSION,
            capacity: 16_384,
            locator: vec![[1; 32], genesis_hash()],
        },
        Message::Headers {
            chain: chain_id(),
            version: peer_wire::TRANSPORT_VERSION,
            headers: blocks.iter().map(|block| block.header.clone()).collect(),
        },
        Message::Sync(Sync {
            chain: chain_id(),
            locator: vec![genesis_hash(), [1; 32]],
            blocks: Vec::new(),
            transactions: Vec::new(),
        }),
        Message::Sync(Sync {
            chain: chain_id(),
            locator: vec![genesis_hash()],
            blocks: blocks.clone(),
            transactions: Vec::new(),
        }),
        Message::Sync(Sync {
            chain: chain_id(),
            locator: Vec::new(),
            blocks: Vec::new(),
            transactions,
        }),
    ];
    messages
        .iter()
        .map(|message| peer_wire::encode(message, wide).expect("seed message"))
        .collect()
}

fn transaction_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    sample_transactions().iter().map(codec::encode).collect()
}

fn block_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    sample_blocks().iter().map(codec::encode).collect()
}

// ---------------------------------------------------------------------------
// JSON bodies, HTTP heads and JSON-RPC dispatch.

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// The bounded JSON parsers: generic (also every Stratum line), `/rpc` bodies
/// and hot-wallet bodies, which differ only in one raw byte-string field.
pub fn json_body(data: &[u8]) -> String {
    let preflight = network_guard::preflight_json(data);
    let parsed = network_guard::parse_json(data);
    let rpc = node::fuzz::rpc_body(data);
    let wallet = node::fuzz::wallet_body(data);
    node::rpc_json_values(data);
    if preflight.is_err() {
        assert!(parsed.is_err(), "parsed JSON its preflight rejected");
    }
    let value = match &parsed {
        Ok(value) => value,
        Err(error) => return rejected(error),
    };
    let unbounded: Value =
        serde_json::from_slice(data).expect("serde accepts what the bounded parser accepted");
    assert_eq!(&unbounded, value);
    // Each body parser lifts the string bound of one field, and requires that
    // field to be a string (or null where it is optional).
    let field = match value.get("method").and_then(Value::as_str) {
        Some("broadcasttransaction") => Some(("/params/raw", false)),
        Some("preparetransaction" | "fee_quote" | "transfer_quote") => {
            Some(("/params/data_hex", true))
        }
        _ => None,
    };
    let byte_field = |path: &str, optional: bool| {
        value
            .pointer(path)
            .is_none_or(|field| field.is_string() || (optional && field.is_null()))
    };
    if field.is_none_or(|(path, optional)| byte_field(path, optional)) {
        assert_eq!(
            rpc.as_ref().ok(),
            Some(value),
            "an ordinary body is an RPC body"
        );
    }
    if byte_field("/data_hex", true) {
        assert_eq!(
            wallet.as_ref().ok(),
            Some(value),
            "an ordinary body is a wallet body"
        );
    }
    format!("json {}", json_kind(value))
}

pub const JSON_TOKENS: &[&[u8]] = &[
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b"\\",
    b"\\\"",
    b"\\u0000",
    b"\\ud800",
    b"\\udfff",
    b":",
    b",",
    b"null",
    b"true",
    b"-0",
    b"1e999",
    b"0.0000000000000000000001",
    b"18446744073709551616",
    b"-9223372036854775809",
    b"\"method\"",
    b"\"params\"",
    b"\"broadcasttransaction\"",
    b"\"preparetransaction\"",
    b"\"raw\"",
    b"\"data_hex\"",
    b"\"ephemeral_key\"",
    b"\"ciphertext\"",
    b"\"format\"",
    b"\"chain_id\"",
    b"\"body\"",
    b"hashstash.mail/2\n",
];

fn json_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let deep = format!("{}0{}", "[".repeat(64), "]".repeat(64));
    let escaped = format!("\"{}\"", "\\u0061".repeat(1024));
    [
        json!({"jsonrpc":"2.0","id":1,"method":"status","params":{}}).to_string(),
        json!({"id":2,"method":"broadcasttransaction","params":{"raw":"00".repeat(600)}})
            .to_string(),
        json!({"id":3,"method":"preparetransaction","params":{"sender":"00","data_hex":null}})
            .to_string(),
        json!({"id":4,"method":"mining.submit","params":["worker","1","00000000","6553f100","00000001"]})
            .to_string(),
        json!({"operation":{"TransferExact":{"recipient":[1,2],"amount":"5"}},"data_hex":"abcd"})
            .to_string(),
        json!([1, -2.5, "text \u{1f331}", null, true, {"nested": {"k": []}}]).to_string(),
        deep,
        escaped,
    ]
    .into_iter()
    .map(String::into_bytes)
    .collect()
}

/// The session token the private-listener inputs carry and present.
const SESSION_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// The first byte selects the listener (bit 0: public web) and whether the
/// private listener has a session token (bit 1); the rest is the request.
pub fn http_request(data: &[u8]) -> String {
    let Some((&mode, raw)) = data.split_first() else {
        return "empty".into();
    };
    let public = mode & 1 != 0;
    let token = (mode & 2 != 0).then_some(SESSION_TOKEN);
    match node::fuzz::http_request(raw, public, 16 * 1024, token) {
        Ok((method, path, body)) => {
            assert!(path.starts_with('/'), "{path}");
            assert!(!method.is_empty() && method.bytes().all(|b| b.is_ascii_graphic()));
            assert!(body.len() <= raw.len());
            if method == "POST" {
                let wallet = path == "/api/wallet" || path == "/api/wallet/manage";
                assert!(path == "/rpc" || wallet, "{path}");
                assert!(
                    !(public && wallet),
                    "public web never routes a wallet endpoint"
                );
                if let (true, Some(token)) = (wallet, token) {
                    let presented = raw
                        .windows(token.len())
                        .any(|window| window == token.as_bytes());
                    assert!(presented, "a wallet request carries the session token");
                }
            } else {
                assert!(body.is_empty(), "only POST requests carry a body");
            }
            let method = if ["GET", "POST"].contains(&method.as_str()) {
                method.as_str()
            } else {
                "other method"
            };
            format!(
                "accepted {method} {}",
                if public { "public" } else { "private" }
            )
        }
        Err(error) => rejected(error),
    }
}

pub const HTTP_TOKENS: &[&[u8]] = &[
    b"\r\n",
    b"\r\n\r\n",
    b": ",
    b"\n",
    b"\t",
    b" ",
    b"GET ",
    b"POST ",
    b"PUT ",
    b" HTTP/1.1",
    b" HTTP/1.0",
    b"/rpc",
    b"/api/wallet",
    b"/api/wallet/manage",
    b"/api/session",
    b"Host: ",
    b"127.0.0.1:18480",
    b"localhost:18480",
    b"[::1]:18480",
    b"Content-Length: ",
    b"Content-Type: application/json",
    b"Transfer-Encoding: chunked",
    b"Origin: http://127.0.0.1:18480",
    b"Sec-Fetch-Site: cross-site",
    b"X-Real-IP: ",
    b"203.0.113.9",
    b"::ffff:127.0.0.1",
    b"X-Hashstash-Token: ",
    SESSION_TOKEN.as_bytes(),
    b"18446744073709551616",
];

fn http_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let rpc = br#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#;
    let post = |mode: u8, path: &str, host: &str, extra: &str, body: &[u8]| {
        let mut request = vec![mode];
        request.extend_from_slice(
            format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        request.extend_from_slice(body);
        request
    };
    let get = |mode: u8, request: &str| [&[mode], request.as_bytes()].concat();
    let token = format!("X-Hashstash-Token: {SESSION_TOKEN}\r\n");
    vec![
        get(0, "GET / HTTP/1.1\r\nHost: 127.0.0.1:18480\r\n\r\n"),
        get(
            0,
            "GET /api/session HTTP/1.0\r\nHost: localhost:18480\r\nSec-Fetch-Site: same-origin\r\nContent-Length: 0\r\n\r\n",
        ),
        post(
            0,
            "/rpc",
            "127.0.0.1:18480",
            "Origin: http://127.0.0.1:18480\r\n",
            rpc,
        ),
        post(
            2,
            "/api/wallet",
            "127.0.0.1:18480",
            &token,
            br#"{"operation":null}"#,
        ),
        post(2, "/api/wallet/manage", "localhost:18480", &token, b"{}"),
        post(
            1,
            "/rpc",
            "explorer.example.org",
            "X-Real-IP: 198.51.100.7\r\nOrigin: https://explorer.example.org\r\n",
            rpc,
        ),
        get(
            1,
            "GET /explorer.js HTTP/1.1\r\nHost: [2001:db8::1]:443\r\nX-Real-IP: 2001:db8::7\r\n\r\n",
        ),
    ]
}

/// Methods the JSON-RPC dispatch serves; the last is unknown on purpose.
/// `mine` is left out: it mines up to 1000 blocks by design.
const RPC_METHODS: &[&str] = &[
    "address",
    "validateaddress",
    "status",
    "config",
    "fee_quote",
    "transfer_quote",
    "governance",
    "proposals",
    "support",
    "mempool",
    "account",
    "stash_quote",
    "quote",
    "deposit",
    "redeem",
    "snapshot",
    "grant_quote",
    "mining",
    "preparetransaction",
    "broadcasttransaction",
    "getblock",
    "blockreceipt",
    "peers",
    "peerstatus",
    "submittransaction",
    "submitblock",
    "explorer_blocks",
    "explorer_transactions",
    "explorer_block",
    "explorer_transaction",
    "explorer_account",
    "explorer_governance",
    "explorer_chat",
    "explorer_mail",
    "unknown",
];
/// The only methods that may change what the node reports.
const RPC_WRITES: &[&str] = &["broadcasttransaction", "submittransaction", "submitblock"];

fn observed(node: &Node) -> Vec<Value> {
    let status = node.status().expect("fixture status");
    ["tip", "state_root", "height", "issued", "mempool"]
        .iter()
        .map(|field| status[field].clone())
        .collect()
}

/// The method an `rpc_params` input's first byte selects.
pub fn rpc_method(selector: u8) -> &'static str {
    RPC_METHODS[usize::from(selector & 0x7f) % RPC_METHODS.len()]
}

/// The first byte selects the method (low seven bits) and the public-web
/// path (high bit); the rest is the `params` value as a client sends it.
pub fn rpc_params(node: &Node, data: &[u8]) -> String {
    let Some((&selector, body)) = data.split_first() else {
        return "empty".into();
    };
    let method = rpc_method(selector);
    let public = selector & 0x80 != 0;
    let params = match network_guard::parse_json(body) {
        Ok(params) => params,
        Err(error) => return rejected(error),
    };
    let before = observed(node);
    let result = if public {
        node::fuzz::public_rpc(node, method, params)
    } else {
        node.rpc(method, params)
    };
    if !RPC_WRITES.contains(&method) {
        assert_eq!(observed(node), before, "{method} changed the node");
    }
    match result {
        Ok(_) => format!("{method} answered"),
        Err(error) => format!("{method} {}", rejected(error)),
    }
}

pub const RPC_TOKENS: &[&[u8]] = &[
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b":",
    b",",
    b"null",
    b"true",
    b"-1",
    b"0",
    b"18446744073709551615",
    b"4294967296",
    b"9223372036854775807",
    b"\"0\"",
    b"\"115792089237316195423570985008687907853269984665640564039457584007913129639936\"",
    b"\"sender\"",
    b"\"recipient\"",
    b"\"amount\"",
    b"\"operation\"",
    b"\"TransferExact\"",
    b"\"Deposit\"",
    b"\"Redeem\"",
    b"\"Propose\"",
    b"\"Support\"",
    b"\"Refund\"",
    b"\"fee\"",
    b"\"extra_fee\"",
    b"\"expiry_blocks\"",
    b"\"nonce\"",
    b"\"anchor\"",
    b"\"data_hex\"",
    b"\"key\"",
    b"\"keys\"",
    b"\"kind\"",
    b"\"deposit\"",
    b"\"withdraw\"",
    b"\"redeem\"",
    b"\"all\"",
    b"\"outcome\"",
    b"\"pass\"",
    b"\"fail\"",
    b"\"round\"",
    b"\"proposal\"",
    b"\"offset\"",
    b"\"limit\"",
    b"\"format\"",
    b"\"hex\"",
    b"\"tip\"",
    b"\"height\"",
    b"\"hash\"",
    b"\"txid\"",
    b"\"txids\"",
    b"\"checked\"",
    b"\"before\"",
    b"\"before_height\"",
    b"\"tx_offset\"",
    b"\"cursor\"",
    b"\"after\"",
    b"\"address\"",
    b"\"public_key\"",
    b"\"raw\"",
    b"\"transaction\"",
    b"\"block\"",
    b"\"4294967296:0\"",
    b"\"18446744073709551615:9223372036854775807\"",
];

fn rpc_seeds(node: Option<&Node>) -> Vec<Vec<u8>> {
    let node = node.expect("RPC seeds name the fixture node's chain");
    let chain = chain_id();
    let status = node.status().expect("fixture status");
    let tip = status["tip"].clone();
    let height = status["height"].as_u64().unwrap_or(0);
    let miner = address::encode(&key(1), &chain).expect("miner address");
    let other = address::encode(&key(2), &chain).expect("address");
    let tx = sample_transactions().remove(0);
    let txid = hex::encode(codec::transaction_id(&tx));
    let operation = |operation: Operation| serde_json::to_value(operation).expect("operation");
    let transfer = operation(Operation::TransferExact {
        recipient: key(2),
        amount: 1u32.into(),
    });
    let deposit = operation(Operation::Deposit {
        amount: 1000u32.into(),
        decision: None,
        outcome: None,
    });
    let grant = operation(sample_bodies()[6].operation.clone());
    let calls = [
        ("address", json!({"public_key": hex::encode(key(1))})),
        ("validateaddress", json!({"address": miner})),
        ("status", json!({})),
        ("config", json!({})),
        ("fee_quote", json!({"sender": miner, "operation": transfer})),
        ("fee_quote", json!([])),
        (
            "transfer_quote",
            json!({"sender": miner, "recipient": other, "amount": "5", "data_hex": "48656c6c6f"}),
        ),
        ("governance", json!({})),
        (
            "proposals",
            json!({"offset": 0, "limit": 8, "round": 0, "tip": tip}),
        ),
        (
            "support",
            json!({"key": miner, "proposal": txid, "round": 0}),
        ),
        (
            "mempool",
            json!({"offset": 0, "limit": 128, "format": "hex"}),
        ),
        ("account", json!({"key": miner, "outcome": "pass"})),
        (
            "stash_quote",
            json!({"key": miner, "kind": "withdraw", "all": true}),
        ),
        ("quote", json!({"amount": "1000", "kind": "deposit"})),
        ("deposit", json!({"amount": "1000"})),
        ("redeem", json!({"amount": "10", "outcome": "fail"})),
        ("snapshot", json!({"key": miner, "keys": [miner, other]})),
        ("grant_quote", json!({"amount": "1000"})),
        ("mining", json!({})),
        (
            "preparetransaction",
            json!({"sender": miner, "operation": deposit, "fee": "1000", "expiry_blocks": 64}),
        ),
        (
            "preparetransaction",
            json!({"sender": other, "operation": grant, "data_hex": hex::encode(proposal_text())}),
        ),
        (
            "broadcasttransaction",
            json!({"raw": wallet::signed_hex(&tx)}),
        ),
        ("getblock", json!({"height": height})),
        ("getblock", json!({"hash": hex::encode(genesis_hash())})),
        (
            "blockreceipt",
            json!({"height": 0, "txids": [txid], "checked": {"height": 0, "hash": hex::encode(genesis_hash())}}),
        ),
        ("peers", json!({})),
        ("peerstatus", json!({})),
        ("submittransaction", json!({"transaction": tx})),
        ("submitblock", json!({"block": sample_blocks()[1]})),
        (
            "explorer_blocks",
            json!({"limit": 5, "before_height": height}),
        ),
        ("explorer_transactions", json!({"limit": 3})),
        (
            "explorer_block",
            json!({"height": 1, "limit": 2, "tx_offset": 0}),
        ),
        ("explorer_transaction", json!({"txid": txid})),
        ("explorer_account", json!({"address": miner, "limit": 5})),
        ("explorer_governance", json!({})),
        (
            "explorer_chat",
            json!({"limit": 5, "cursor": format!("{height}:0")}),
        ),
        (
            "explorer_mail",
            json!({"after": "0:0", "anchor": hex::encode(genesis_hash())}),
        ),
    ];
    let mut seeds = Vec::new();
    for (method, params) in calls {
        let index = RPC_METHODS
            .iter()
            .position(|known| *known == method)
            .expect("seeded method") as u8;
        for selector in [index, index | 0x80] {
            seeds.push([&[selector], params.to_string().as_bytes()].concat());
        }
    }
    seeds
}

/// A disposable devnet node with a few blocks mined to fixture key 1 and,
/// where the build funds mining, one pending transfer for the mempool,
/// explorer and quote paths.
pub fn fixture_node(directory: &Path) -> Node {
    let node =
        Node::open(&directory.join("fuzz.sqlite"), config().clone(), key(1)).expect("fixture node");
    for _ in 0..3 {
        node.mine(1_000_000).expect("fixture block");
    }
    let prepared = node.rpc(
        "preparetransaction",
        json!({
            "sender": hex::encode(key(1)),
            "operation": serde_json::to_value(Operation::TransferExact {
                recipient: key(2),
                amount: 1u32.into(),
            })
            .expect("operation"),
            "data_hex": hex::encode("A pending fuzz fixture message"),
        }),
    );
    // The export carries its fee quote beside the envelope fields.
    if let Ok(mut prepared) = prepared
        && let Some(fields) = prepared.as_object_mut()
        && fields.remove("fee_quote").is_some()
        && let Ok(envelope) = serde_json::from_value::<wallet::UnsignedEnvelope>(prepared)
        && let Ok(body) = wallet::decode_unsigned(&envelope)
        && let Ok(tx) = crypto::sign(&chain_id(), &body, &secret(1))
    {
        let _ = node.submit_transaction(tx);
    }
    node
}

// ---------------------------------------------------------------------------
// Application data in transactions, account text and wallet exports.

/// Encrypted-mail envelopes carried in transaction data.
pub fn mail_envelope(data: &[u8]) -> String {
    match mail::decode(data) {
        Some(envelope) => {
            let encoded = [
                mail::PREFIX,
                &serde_json::to_vec(&envelope).expect("envelope JSON"),
            ]
            .concat();
            assert!(encoded == data, "one encoding per mail envelope");
            assert!(
                chat::decode(data, data.len()).is_none(),
                "mail is never chat"
            );
            "envelope".into()
        }
        None => match data.strip_prefix(mail::PREFIX) {
            None => "no mail prefix".into(),
            Some(body) => match serde_json::from_slice::<mail::Envelope>(body) {
                Ok(_) => "envelope fields rejected".into(),
                Err(error) => format!("envelope JSON {:?}", error.classify()),
            },
        },
    }
}

/// Public chat text and proposal rationale, both plain text in data.
pub fn plain_text(data: &[u8]) -> String {
    let chat = chat::decode(data, data.len());
    if let Some(text) = chat {
        assert_eq!(text.as_bytes(), data);
        assert!(!text.starts_with("hashstash.mail/"));
    }
    let tx = Transaction {
        body: TransactionBody {
            sender: key(1),
            nonce: 0,
            fee: 0u32.into(),
            anchor: [0; 32],
            expiry_blocks: 1,
            operation: Operation::Propose {
                round: 0,
                description: Sha256::digest(data).into(),
                proposal: Proposal::Parameter {
                    parameter: Parameter::Interval,
                    old: 15,
                    new: 16,
                },
                support: 1u32.into(),
            },
            data: data.to_vec(),
        },
        signature: [0; 64],
    };
    let rationale = proposal_data::from_transaction(&tx);
    if let Some(text) = &rationale {
        assert_eq!(text.as_bytes(), data);
    }
    format!("chat {} rationale {}", chat.is_some(), rationale.is_some())
}

const TEXT_TOKENS: &[&[u8]] = &[
    b"hashstash.mail/",
    b"hashstash.mail/2\n",
    b"\n",
    b"\r",
    b"\t",
    b"\0",
    b" ",
    "\u{200b}".as_bytes(),
    "\u{feff}".as_bytes(),
    "\u{3000}".as_bytes(),
    "\u{e0001}".as_bytes(),
    "\u{1f331}".as_bytes(),
    &[0xc0, 0x80],
    &[0xed, 0xa0, 0x80],
    &[0xf4, 0x90, 0x80, 0x80],
];

fn mail_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    vec![mail_fixture(), mail::PREFIX.to_vec()]
}

fn text_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    [
        "Hello, chain.",
        "multi\nline\r\n\ttext",
        proposal_text_str(),
        "\u{200b}\u{3000}",
        "hashstash.mail/3\n{}",
    ]
    .iter()
    .map(|text| text.as_bytes().to_vec())
    .collect()
}
fn proposal_text_str() -> &'static str {
    std::str::from_utf8(proposal_text()).expect("text")
}

/// Account text: Bech32m addresses, hexadecimal keys and hashes.
pub fn account_text(data: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(data) else {
        return "not UTF-8".into();
    };
    let chain = chain_id();
    let any = address::decode_any(text);
    if let Ok((prefix, public)) = &any {
        // The prefix names only the first eight bytes of a chain identity.
        let mut named = [0u8; 32];
        hex::decode_to_slice(&prefix[3..], &mut named[..8]).expect("checked prefix");
        let encoded = address::encode(public, &named).expect("a decoded key encodes");
        assert_eq!(
            encoded,
            text.to_ascii_lowercase(),
            "one spelling per address"
        );
    }
    let decoded = address::decode(text, &chain);
    assert!(decoded.is_err() || any.is_ok());
    let account = node::parse_account(text, &chain);
    if let Ok(public) = &account {
        assert!(crypto::valid_key(public));
    }
    let _ = node::parse_key(text);
    let _ = node::parse_hash(text);
    match (any, account) {
        (Ok((prefix, _)), _) => format!(
            "address for {} network",
            if prefix == address::hrp(&chain) {
                "this"
            } else {
                "another"
            }
        ),
        (Err(_), Ok(_)) => "hexadecimal key".into(),
        (Err(error), Err(_)) => rejected(error),
    }
}

const ADDRESS_TOKENS: &[&[u8]] = &[
    b"hsh",
    b"1",
    b"q",
    b"p",
    b"z",
    b"Q",
    b"0x",
    b"0000000000000000000000000000000000000000000000000000000000000000",
];

fn address_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let chain = chain_id();
    let mut seeds = vec![
        address::encode(&key(1), &chain).expect("address"),
        address::encode(&key(2), &[0xab; 32]).expect("address"),
        address::encode(&key(3), &chain)
            .expect("address")
            .to_ascii_uppercase(),
        hex::encode(key(4)),
    ];
    seeds.push(format!(" {} ", seeds[0]));
    seeds.into_iter().map(String::into_bytes).collect()
}

/// Signed transaction records as the CLI, browser and cold wallets exchange them.
pub fn signed_record(data: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(data) else {
        return "not UTF-8".into();
    };
    match wallet::decode_signed_record(text) {
        Ok(tx) => {
            assert_eq!(
                wallet::signed_hex(&tx),
                text.trim().to_ascii_lowercase(),
                "one encoding per signed record"
            );
            inspect_transaction(&tx);
            let verified = wallet::decode_signed(text, &chain_id());
            format!(
                "{} signed for {} network",
                operation_kind(&tx.body.operation),
                if verified.is_ok() { "this" } else { "another" }
            )
        }
        Err(error) => rejected(error),
    }
}

const HEX_TOKENS: &[&[u8]] = &[b"00", b"ff", b"fd", b"fe", b"FF", b" ", b"\n", b"0x", b"g"];

fn signed_record_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    sample_transactions()
        .iter()
        .map(|tx| wallet::signed_hex(tx).into_bytes())
        .collect()
}

/// Unsigned exports, which a cold signer reviews before it signs.
pub fn unsigned_envelope(data: &[u8]) -> String {
    let envelope: wallet::UnsignedEnvelope = match serde_json::from_slice(data) {
        Ok(envelope) => envelope,
        Err(error) => return format!("envelope JSON {:?}", error.classify()),
    };
    let shape = wallet::decode_unsigned_shape(&envelope);
    match wallet::decode_unsigned(&envelope) {
        Ok(body) => {
            assert_eq!(shape.as_ref().ok(), Some(&body));
            let chain = wallet::unsigned_chain(&envelope).expect("decoded export names a chain");
            let again = wallet::unsigned(&body, &chain);
            assert_eq!(again.format, envelope.format);
            assert_eq!(again.chain_id, envelope.chain_id);
            assert_eq!(
                again.body,
                envelope.body.trim().to_ascii_lowercase(),
                "one encoding per export"
            );
            inspect_transaction(&Transaction {
                body: body.clone(),
                signature: [0; 64],
            });
            format!("export of {}", operation_kind(&body.operation))
        }
        Err(error) => rejected(error),
    }
}

fn unsigned_envelope_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    sample_bodies()
        .iter()
        .map(|body| serde_json::to_vec(&wallet::unsigned(body, &chain_id())).expect("export"))
        .collect()
}

// ---------------------------------------------------------------------------
// The authenticated peer transport.

const PEER_ADDRESS: ([u8; 4], u16) = ([127, 0, 0, 1], 18481);

/// Fixed fuzz identities: the server and client pin each other at loopback.
fn channel_policies() -> &'static (Arc<Policy>, Arc<Policy>) {
    static POLICIES: OnceLock<(Arc<Policy>, Arc<Policy>)> = OnceLock::new();
    POLICIES.get_or_init(|| {
        let pin = |n: u8| PeerPin {
            address: SocketAddr::from(PEER_ADDRESS),
            public_key: key(n),
        };
        (
            Policy::new(secret(11), vec![pin(12)]).expect("server policy"),
            Policy::new(secret(12), vec![pin(11)]).expect("client policy"),
        )
    })
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("peer channel runtime")
    })
}

/// A pinned peer server reading one client. The first byte selects the
/// stage: with bit 1 the rest is the unauthenticated client hello and proof;
/// otherwise a genuine handshake completes first and the rest follows it,
/// sealed by the client as one frame (bit 0) or raw, so a pinned but hostile
/// peer controls the frame length, sequence and signature.
pub fn peer_channel(data: &[u8]) -> String {
    let Some((&mode, rest)) = data.split_first() else {
        return "empty".into();
    };
    let (server, client) = channel_policies();
    let guard = Arc::new(network_guard::NetworkGuard::default());
    let ip = IpAddr::from(PEER_ADDRESS.0);
    let [wide, _] = limits();
    let admit = |inbound: bool| {
        if inbound {
            guard.admit(ip, network_guard::Surface::Peer)
        } else {
            guard.admit_outbound(ip, network_guard::Surface::Peer)
        }
        .expect("fresh guard admits loopback")
    };
    let server_admission = admit(true);
    runtime().block_on(async {
        if mode & 2 != 0 {
            let mut stream = tokio::io::join(rest, tokio::io::sink());
            return match Channel::accept(&mut stream, server, ip, chain_id(), &server_admission)
                .await
            {
                Ok(_) => panic!("a handshake proof was forged"),
                Err(error) => format!("hello {}", rejected(error)),
            };
        }
        let client_admission = admit(false);
        let (mut client_end, mut server_end) = tokio::io::duplex(rest.len() + 64 * 1024);
        let peer = SocketAddr::from(PEER_ADDRESS);
        let (connected, accepted) = tokio::join!(
            Channel::connect(&mut client_end, client, peer, chain_id(), &client_admission),
            Channel::accept(&mut server_end, server, ip, chain_id(), &server_admission)
        );
        let mut sender = connected.expect("fixture handshake");
        let mut channel = accepted.expect("fixture handshake");
        let bytes = if mode & 1 != 0 {
            match sender.seal(rest.to_vec()) {
                Ok(sealed) => sealed,
                Err(error) => return format!("seal {}", rejected(error)),
            }
        } else {
            rest.to_vec()
        };
        client_end.write_all(&bytes).await.expect("buffered write");
        drop(client_end);
        let frame = match channel
            .receive(&mut server_end, wide.frame_bytes(), &server_admission)
            .await
        {
            Ok(frame) => frame,
            Err(error) => return format!("frame {}", rejected(error)),
        };
        let workers = Arc::new(tokio::sync::Semaphore::new(1));
        match channel.open(frame, &server_admission, workers).await {
            Ok(payload) => {
                assert!(mode & 1 != 0, "an unsealed frame was authenticated");
                assert_eq!(payload, rest);
                match peer_wire::decode(&payload, wide) {
                    Ok(message) => message_kind(&message),
                    Err(error) => format!("payload {}", rejected(error)),
                }
            }
            Err(error) => format!("signature {}", rejected(error)),
        }
    })
}

fn channel_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let mut hello = vec![2];
    hello.extend_from_slice(b"HSP2PAUT");
    hello.extend_from_slice(&chain_id());
    hello.extend_from_slice(&key(12));
    hello.extend_from_slice(&[5; 32]);
    hello.extend_from_slice(&[0; 64]);
    let mut raw = vec![0];
    raw.extend_from_slice(&9u32.to_be_bytes());
    raw.extend_from_slice(&0u64.to_be_bytes());
    raw.extend_from_slice(&[0; 64]);
    raw.extend_from_slice(b"HSP2PBIN\x01");
    let mut seeds = vec![hello, raw];
    seeds.extend(
        peer_wire_seeds(None)
            .into_iter()
            .map(|payload| [&[1], &payload[..]].concat()),
    );
    seeds
}

// ---------------------------------------------------------------------------
// Peer discovery gossip.

/// Reads the operations of an `address_book` input.
struct Script<'a> {
    data: &'a [u8],
}
impl Script<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(first)
    }
    fn bytes<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (taken, rest) = self.data.split_first_chunk::<N>()?;
        self.data = rest;
        Some(*taken)
    }
    fn address(&mut self) -> Option<SocketAddr> {
        let ip = if self.byte()? & 1 == 0 {
            IpAddr::from(self.bytes::<4>()?)
        } else {
            IpAddr::from(self.bytes::<16>()?)
        };
        Some(SocketAddr::new(ip, u16::from_be_bytes(self.bytes::<2>()?)))
    }
}

const BOOK_LOCAL: &str = "0.0.0.0:18481";
const BOOK_ADVERTISED: &str = "203.0.114.5:18481";

/// Gossip from hostile peers into a discovery address book. The input is a
/// script of operations: a source's address list, a source's advertisement
/// of itself, the sample this node would advertise, the peers it would try
/// next and their results, each after a scripted delay. After every step the
/// book keeps its documented bounds; finally its saved form reopens cleanly.
pub fn address_book(data: &[u8]) -> String {
    use hashstash::peer_discovery::{
        self as discovery, AddressBook, MAX_ADDRESSES, MAX_BOOK, MAX_PER_GROUP, MAX_PER_IP,
        MAX_PER_SOURCE, MAX_PERSISTED_BYTES, Options,
    };
    use std::collections::BTreeMap;
    thread_local! {
        static DIRECTORY: tempfile::TempDir = tempfile::tempdir().expect("book directory");
    }
    let path = DIRECTORY.with(|directory| directory.path().join("peers.json"));
    let _ = std::fs::remove_file(&path);
    let options = || Options {
        enabled: true,
        seeds: Vec::new(),
        advertise: Some(BOOK_ADVERTISED.parse().expect("address")),
        allow_private: false,
    };
    let local: SocketAddr = BOOK_LOCAL.parse().expect("address");
    let mut at = 1_800_000_000u64;
    let mut book = AddressBook::open(path.clone(), chain_id(), options(), local, &[], at)
        .expect("empty address book");
    let check = |book: &AddressBook| {
        let mut sources = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut ips = BTreeMap::new();
        let mut count = 0;
        for entry in book.entries() {
            count += 1;
            assert!(!entry.explicit, "gossip made an explicit entry");
            assert!(
                discovery::allowed(entry.address, false),
                "learned the nonpublic address {}",
                entry.address
            );
            assert_eq!(discovery::normalized(entry.address), entry.address);
            *sources.entry(entry.source.clone()).or_insert(0) += 1;
            *groups.entry(discovery::group(entry.address)).or_insert(0) += 1;
            *ips.entry(entry.address.ip()).or_insert(0) += 1;
        }
        assert!(count <= MAX_BOOK);
        assert!(
            sources.values().all(|&n| n <= MAX_PER_SOURCE),
            "{sources:?}"
        );
        assert!(groups.values().all(|&n| n <= MAX_PER_GROUP), "{groups:?}");
        assert!(ips.values().all(|&n| n <= MAX_PER_IP), "{ips:?}");
    };
    let mut script = Script { data };
    let mut tried = Vec::new();
    let mut steps = 0;
    while steps < 64
        && let Some(operation) = script.byte()
    {
        steps += 1;
        // Up to about nine hours per step, so retention and retries expire.
        at += u64::from(operation >> 3) * 997;
        match operation & 7 {
            0 | 1 => {
                let Some(source) = script.address() else {
                    break;
                };
                let count = script
                    .byte()
                    .map_or(0, |n| usize::from(n) % (MAX_ADDRESSES + 4));
                let addresses: Vec<_> = (0..count).map_while(|_| script.address()).collect();
                book.learn(source, &addresses, at);
            }
            2 => {
                let (Some(source), Some(address)) = (script.address(), script.address()) else {
                    break;
                };
                book.advertisement(source, address, at);
            }
            3 => {
                let random = u64::from_le_bytes(script.bytes::<8>().unwrap_or_default());
                let sample = book.advertised(at, random);
                assert!(sample.len() <= MAX_ADDRESSES);
                let own = discovery::normalized(BOOK_ADVERTISED.parse().expect("address"));
                for address in sample {
                    assert!(
                        address == own || book.entries().any(|entry| entry.address == address),
                        "advertised {address}, which the book does not hold"
                    );
                }
            }
            4 | 5 => {
                let maximum = usize::from(script.byte().unwrap_or(4) % 16);
                let next = book.next(at, maximum);
                assert!(next.len() <= maximum);
                tried.extend(next);
            }
            _ => {
                let Some(flags) = script.byte() else { break };
                if let Some(address) = tried.pop() {
                    book.finished(address, flags & 1 != 0, at, u64::from(flags));
                }
                if flags & 2 != 0 {
                    for address in tried.drain(..) {
                        book.finished(address, false, at, 0);
                    }
                }
            }
        }
        check(&book);
    }
    let held = book.entries().count();
    let Some(bytes) = book.pending_save().expect("a bounded book saves") else {
        return format!("{} entries, nothing verified", how_many(held));
    };
    assert!(bytes.len() <= MAX_PERSISTED_BYTES);
    std::fs::write(&path, &bytes).expect("saved book");
    let reopened =
        AddressBook::open(path, chain_id(), options(), local, &[], at).expect("the book reopens");
    assert!(reopened.load_error.is_none(), "{:?}", reopened.load_error);
    check(&reopened);
    format!("{} entries, saved", how_many(held))
}

/// Address-book script fragments: IPv4 and IPv6 records, public and not.
const BOOK_TOKENS: &[&[u8]] = &[
    &[0, 8, 8, 8, 8, 0x48, 0x31],
    &[0, 127, 0, 0, 1, 0x48, 0x31],
    &[0, 203, 0, 114, 5, 0x48, 0x31],
    &[0, 192, 168, 1, 1, 0x48, 0x31],
    &[0, 0, 0, 0, 0, 0, 0],
    &[
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 4, 4, 0x48, 0x31,
    ],
    &[
        1, 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x48, 0x31,
    ],
    &[
        1, 0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x48, 0x31,
    ],
];

fn address_book_seeds(_: Option<&Node>) -> Vec<Vec<u8>> {
    let v4 = |a: [u8; 4], port: u16| [&[0][..], &a, &port.to_be_bytes()].concat();
    let source = v4([203, 0, 114, 9], 18481);
    let mut learn = vec![0];
    learn.extend_from_slice(&source);
    learn.push(6);
    for n in 1..=6u8 {
        learn.extend(v4([8, 8, n, 1], 18481));
    }
    let mut seed = learn.clone();
    // Advertise, sample, try three, succeed with one and fail the rest.
    seed.push(2);
    seed.extend_from_slice(&source);
    seed.extend_from_slice(&source);
    seed.extend([4, 3, 6, 1, 3 | 8, 0, 0, 0, 0, 0, 0, 0, 0, 6, 2]);
    let mut v6 = vec![1, 1];
    v6.extend_from_slice(&[
        0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ]);
    v6.extend_from_slice(&18481u16.to_be_bytes());
    v6.push(1);
    v6.extend(v4([10, 0, 0, 1], 18481));
    vec![learn, seed, v6]
}
