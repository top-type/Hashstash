use anyhow::{Context, Result, anyhow, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use hashstash::{
    address,
    config::Config,
    crypto, fees, math,
    node::{self, Node, ServerOptions},
    types::{Amount, Hash, Operation, PublicKey, TransactionBody},
};
use num_traits::{One, Zero};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "hashstash",
    version,
    about = "Hashstash experimental full node — stash your hashes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
// Parsed once at startup; keep command arguments together without heap indirection.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Create a private-development genesis configuration. It is not a public-network genesis.
    Init {
        #[arg(long, default_value = "hashstash-devnet.json")]
        config: PathBuf,
        /// Initial aggregate SHA256d hashrate, such as 100T or 1.5P hashes/second.
        /// Initial work uses this rate and the configured target block interval.
        #[arg(long)]
        hashrate: Option<String>,
        /// Development block counts, or longer block counts for interactive use.
        #[arg(long, value_enum, default_value = "dev")]
        preset: InitPreset,
    },
    /// Generate a BIP340 key file. Existing files are never overwritten.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate a dedicated peer transport identity. Prints only its public key.
    PeerKeygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Validate dedicated peer identity and pins without starting listeners.
    PeerKeycheck {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, required_unless_present = "peer_discovery")]
        peer_pin: Vec<hashstash::peer_auth::PeerPin>,
        #[arg(long)]
        peer_discovery: bool,
        #[arg(long)]
        miner: String,
    },
    /// Print only the public key from a key file.
    PublicKey {
        #[arg(long)]
        key: PathBuf,
    },
    /// Encode an existing public key as a checksummed address for one network.
    Address {
        #[arg(
            long,
            conflicts_with = "public_key",
            required_unless_present = "public_key"
        )]
        key: Option<PathBuf>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(
            long,
            conflicts_with = "chain_id",
            required_unless_present = "chain_id"
        )]
        config: Option<PathBuf>,
        #[arg(long)]
        chain_id: Option<String>,
    },
    /// Validate an address for the selected network and print its raw public key.
    DecodeAddress {
        #[arg(long)]
        address: String,
        #[arg(
            long,
            conflicts_with = "chain_id",
            required_unless_present = "chain_id"
        )]
        config: Option<PathBuf>,
        #[arg(long)]
        chain_id: Option<String>,
    },
    /// Print a public network descriptor for the offline signer.
    Network {
        #[arg(long)]
        config: PathBuf,
    },
    /// Sign a TransactionBody JSON document offline, using a local key file.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        body: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign and submit any protocol operation, filling the block anchor and account nonce.
    Send {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(
            long,
            conflicts_with = "operation_file",
            required_unless_present = "operation_file"
        )]
        operation: Option<String>,
        #[arg(long)]
        operation_file: Option<PathBuf>,
        /// Exact total fee in whole atoms (1000 atoms = 1 hash); quote the minimum when omitted.
        #[arg(long, conflicts_with = "extra_fee")]
        fee: Option<String>,
        /// Extra fee in whole atoms, shared using the governed fee split; zero when omitted.
        #[arg(long)]
        extra_fee: Option<String>,
        /// Optional uninterpreted bytes, encoded as hexadecimal.
        #[arg(long)]
        data_hex: Option<String>,
        #[arg(long)]
        nonce: Option<u64>,
        /// Validity after the signed anchor block; defaults to 2 blocks.
        #[arg(long)]
        expiry_blocks: Option<u64>,
    },
    /// Prepare an unsigned transaction for the offline signer. No private key is used.
    Prepare {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        #[arg(long)]
        sender: String,
        #[arg(
            long,
            conflicts_with = "operation_file",
            required_unless_present = "operation_file"
        )]
        operation: Option<String>,
        #[arg(long)]
        operation_file: Option<PathBuf>,
        /// Exact total fee in whole atoms (1000 atoms = 1 hash); quote the minimum when omitted.
        #[arg(long, conflicts_with = "extra_fee")]
        fee: Option<String>,
        /// Extra fee in whole atoms, shared using the governed fee split; zero when omitted.
        #[arg(long)]
        extra_fee: Option<String>,
        /// Optional uninterpreted bytes, encoded as hexadecimal.
        #[arg(long)]
        data_hex: Option<String>,
        /// Validity after the signed anchor block; defaults to 2 blocks.
        #[arg(long)]
        expiry_blocks: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Broadcast canonical signed transaction hex from the offline signer.
    Broadcast {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        #[arg(
            long,
            conflicts_with = "raw_file",
            required_unless_present = "raw_file"
        )]
        raw: Option<String>,
        #[arg(long)]
        raw_file: Option<PathBuf>,
    },
    /// Run a persistent node, RPC, peer listener and solo Stratum V1 server.
    Run {
        #[arg(long, default_value = "hashstash-devnet.json")]
        config: PathBuf,
        #[arg(long, default_value = "hashstash.sqlite")]
        data: PathBuf,
        #[arg(long)]
        miner: String,
        /// Seed a fresh wallet store with this private key file. Saved wallet selection is preserved.
        #[arg(long, conflicts_with = "watch_key")]
        wallet_key: Option<PathBuf>,
        /// Seed a fresh wallet store with this public key. Without wallet flags the store starts empty.
        #[arg(long)]
        watch_key: Option<String>,
        #[arg(long, default_value = "127.0.0.1:18480")]
        rpc: SocketAddr,
        /// Optional restricted website and public RPC; never exposes server wallets.
        #[arg(long)]
        public_web: Option<SocketAddr>,
        #[arg(long, default_value = "127.0.0.1:18481")]
        p2p: SocketAddr,
        #[arg(long, default_value = "127.0.0.1:18482")]
        stratum: SocketAddr,
        /// Run only validation, relay and wallet services; do not bind the mining listener.
        #[arg(long, conflicts_with_all = ["stratum_password_file", "stratum_advertise"])]
        no_stratum: bool,
        /// Share difficulty for connected miners; independent of network difficulty.
        #[arg(long, default_value_t = 65_536.0)]
        stratum_share_difficulty: f64,
        /// Reachable Stratum HOST:PORT shown by the interface; does not change binding.
        #[arg(long)]
        stratum_advertise: Option<String>,
        #[arg(long)]
        peer: Vec<SocketAddr>,
        /// Join the public authenticated network and discover additional peers.
        #[arg(long)]
        peer_discovery: bool,
        /// Bootstrap endpoint (numeric IP or DNS HOST:PORT); repeat for independent seeds.
        #[arg(long, requires = "peer_discovery")]
        seed: Vec<String>,
        /// Public numeric IP:PORT reachable by other nodes; forward this port through NAT.
        #[arg(long, requires = "peer_discovery")]
        advertise_peer: Option<SocketAddr>,
        /// Permit local/private gossip for an explicitly selected isolated network.
        #[arg(
            long,
            visible_alias = "allow-private-peers",
            requires = "peer_discovery"
        )]
        allow_private_peer_discovery: bool,
        /// Dedicated peer identity. Discovery creates one beside the database if omitted.
        #[arg(long)]
        peer_key_file: Option<PathBuf>,
        /// Pinned numeric IP:PORT=PUBLIC_KEY. Requires authenticated transport, with no legacy fallback.
        #[arg(long, requires = "peer_key_file")]
        peer_pin: Vec<hashstash::peer_auth::PeerPin>,
        /// File containing the optional Stratum password; no spending key is needed by the node.
        #[arg(long)]
        stratum_password_file: Option<PathBuf>,
    },
    /// Call a JSON-RPC method. Params may be inline JSON or a JSON file.
    Rpc {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        method: String,
        #[arg(long, default_value = "{}")]
        params: String,
        #[arg(long)]
        params_file: Option<PathBuf>,
    },
    /// CPU-mine a bounded number of development blocks through a running node.
    Mine {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        #[arg(long, default_value_t = 1)]
        count: u64,
        #[arg(long, default_value_t = 1_000_000)]
        attempts: u64,
        /// Address or raw public key; omitted uses the configured mining recipient.
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Send an exact recipient amount, paying fees on top.
    Transfer {
        #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
        url: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        /// Whole monetary atoms (1000 atoms = 1 hash).
        amount: String,
        /// Exact total fee in whole atoms (1000 atoms = 1 hash); quote the minimum when omitted.
        #[arg(long, conflicts_with = "extra_fee")]
        fee: Option<String>,
        /// Extra fee in whole atoms, shared using the governed fee split; zero when omitted.
        #[arg(long)]
        extra_fee: Option<String>,
        /// Optional uninterpreted bytes, encoded as hexadecimal.
        #[arg(long)]
        data_hex: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum InitPreset {
    Dev,
    Slow,
}

fn parse_hashrate(text: &str) -> Result<Amount> {
    let mut value = text.trim();
    ensure!(!value.is_empty() && value.len() <= 128, "invalid hashrate");
    if value.to_ascii_lowercase().ends_with("h/s") {
        value = value[..value.len() - 3].trim_end();
    }
    let power = match value.as_bytes().last().map(u8::to_ascii_uppercase) {
        Some(b'K') => 3,
        Some(b'M') => 6,
        Some(b'G') => 9,
        Some(b'T') => 12,
        Some(b'P') => 15,
        Some(b'E') => 18,
        _ => 0,
    };
    if power > 0 {
        value = value[..value.len() - 1].trim_end();
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or("");
    ensure!(
        parts.next().is_none()
            && !whole.is_empty()
            && whole.bytes().all(|b| b.is_ascii_digit())
            && fraction.bytes().all(|b| b.is_ascii_digit())
            && (!value.contains('.') || !fraction.is_empty()),
        "hashrate must be a positive decimal with optional K, M, G, T, P or E suffix"
    );
    let scale = Amount::from(10u32).pow(power);
    let denominator = Amount::from(10u32).pow(fraction.len() as u32);
    let digits = Amount::parse_bytes(format!("{whole}{fraction}").as_bytes(), 10)
        .context("invalid hashrate")?;
    let numerator = digits * scale;
    ensure!(
        (&numerator % &denominator).is_zero(),
        "hashrate must resolve to a whole number of hashes per second"
    );
    let rate = numerator / denominator;
    ensure!(
        !rate.is_zero() && rate.bits() <= 256,
        "hashrate outside supported range"
    );
    Ok(rate)
}

fn calibrate_initial_target(config: &mut Config, hashrate: &str) -> Result<()> {
    // Estimate initial work from the current target interval.
    let calibration_seconds = config.initial.interval;
    let expected = parse_hashrate(hashrate)? * calibration_seconds;
    let space = Amount::one() << 256usize;
    ensure!(
        expected < space,
        "initial expected work exceeds the proof-of-work range"
    );
    let target = (&space / expected) - 1u32;
    ensure!(
        !target.is_zero(),
        "initial expected work exceeds the proof-of-work range"
    );
    let limit = math::target_from_bits(config.limit_bits)?;
    let bits = math::bits_from_target(&target);
    ensure!(
        math::target_from_bits(bits)? <= limit,
        "hashrate is too low for this network's proof-of-work limit"
    );
    config.initial_bits = bits;
    config.validate()?;
    Ok(())
}

fn initial_config(preset: InitPreset, hashrate: Option<&str>) -> Result<Config> {
    let mut config = match preset {
        InitPreset::Dev => Config::devnet(),
        InitPreset::Slow => Config::slow_testnet(),
    };
    // New CLI-created chains start their timestamp schedule at creation.
    config.genesis_time = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    if let Some(rate) = hashrate {
        calibrate_initial_target(&mut config, rate)?;
        let mut unique = [0u8; 8];
        getrandom::fill(&mut unique).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
        config.network = format!("hashstash-private-{}", hex::encode(unique));
    }
    config.validate()?;
    Ok(config)
}
fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )?)
}
fn write_new(path: &Path, value: &impl serde::Serialize, private: bool) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    {
        let _ = private;
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "create {} (existing files are not overwritten)",
            path.display()
        )
    })?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
fn key_file(path: &Path) -> Result<([u8; 32], PublicKey)> {
    let v = read_json(path)?;
    let (private_field, public_field) = if let Some(format) = v.get("format") {
        ensure!(
            format == "hashstash-private-v1",
            "unsupported private wallet format"
        );
        ("private_key", "public_key")
    } else {
        ("secret", "public")
    };
    let secret = node::parse_hash(
        v.get(private_field)
            .and_then(Value::as_str)
            .context("key file requires a private key")?,
    )?;
    let public = crypto::public_key(&secret)?;
    if let Some(p) = v.get(public_field) {
        ensure!(
            node::parse_key(p.as_str().context("public key must be hexadecimal text")?)? == public,
            "key file public/secret mismatch"
        );
    }
    Ok((secret, public))
}

fn address_chain(config: Option<&Path>, chain_id: Option<&str>) -> Result<Hash> {
    if let Some(path) = config {
        let config: Config = serde_json::from_value(read_json(path)?)?;
        config.validate()?;
        Ok(config.chain_id())
    } else {
        node::parse_hash(chain_id.context("supply --config or --chain-id")?)
    }
}

// Address strings are a convenience at the command boundary. Signed operation
// bytes retain the existing public-key representation.
fn operation_addresses(mut operation: Value, chain_id: &Hash) -> Result<Value> {
    for path in ["/TransferExact/recipient"] {
        if let Some(value) = operation.pointer_mut(path)
            && let Some(text) = value.as_str()
        {
            *value = serde_json::to_value(node::parse_account(text, chain_id)?)?;
        }
    }
    if let Some(payments) = operation
        .pointer_mut("/Propose/proposal/Grant/payments")
        .and_then(Value::as_array_mut)
    {
        for payment in payments.iter_mut() {
            if let Some(value) = payment.get_mut("recipient")
                && let Some(text) = value.as_str()
            {
                *value = serde_json::to_value(node::parse_account(text, chain_id)?)?;
            }
        }
        let mut combined = std::collections::BTreeMap::<PublicKey, Amount>::new();
        for payment in payments.iter() {
            let payment: hashstash::types::GrantPayment = serde_json::from_value(payment.clone())?;
            ensure!(
                crypto::valid_key(&payment.recipient),
                "invalid grant recipient"
            );
            ensure!(!payment.amount.is_zero(), "zero grant payment");
            *combined.entry(payment.recipient).or_default() += payment.amount;
        }
        let canonical = combined
            .into_iter()
            .map(|(recipient, amount)| hashstash::types::GrantPayment { recipient, amount })
            .collect::<Vec<_>>();
        ensure!(
            hashstash::types::grant_total(&canonical)?.bits() <= 512,
            "grant total exceeds supported HASH range"
        );
        *payments = canonical
            .into_iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()?;
    }
    Ok(operation)
}

fn transaction_fee_request(fee: Option<String>, extra_fee: Option<String>) -> Result<Value> {
    ensure!(
        fee.is_none() || extra_fee.is_none(),
        "choose an exact fee or an extra fee, not both"
    );
    let request = if let Some(value) = fee {
        fee_amount(&value)?;
        json!({"fee":value})
    } else {
        let value = extra_fee.unwrap_or_else(|| "0".into());
        fee_amount(&value)?;
        json!({"extra_fee":value})
    };
    Ok(request)
}

fn prepared_envelope(mut response: Value) -> Result<hashstash::wallet::UnsignedEnvelope> {
    let quote = response
        .as_object_mut()
        .and_then(|object| object.remove("fee_quote"));
    let envelope = serde_json::from_value(response)?;
    if let Some(quote) = quote {
        let body = hashstash::wallet::decode_unsigned(&envelope)?;
        let exact = fee_amount(quote["fee"].as_str().context("missing exact fee quote")?)?;
        let minimum = fee_amount(
            quote["minimum_fee"]
                .as_str()
                .context("missing minimum fee quote")?,
        )?;
        ensure!(
            body.fee == exact && exact >= minimum,
            "prepared fee differs from its quote"
        );
    }
    Ok(envelope)
}

fn requested_data(input: &str) -> Result<Vec<u8>> {
    ensure!(
        input.len().is_multiple_of(2),
        "transaction data must contain complete hex bytes"
    );
    hex::decode(input).context("transaction data must be hexadecimal bytes")
}

fn add_requested_data(request: &mut Value, input: Option<String>) -> Result<()> {
    let data = requested_data(input.as_deref().unwrap_or(""))?;
    if !data.is_empty() {
        request["data_hex"] = json!(hex::encode(data));
    }
    Ok(())
}

fn verify_prepared_data(body: &TransactionBody, request: &Value) -> Result<()> {
    let data = match request.get("data_hex") {
        Some(value) => requested_data(
            value
                .as_str()
                .context("transaction data must be hexadecimal bytes")?,
        )?,
        None => Vec::new(),
    };
    ensure!(body.data == data, "prepared transaction has different data");
    Ok(())
}

fn fee_amount(text: &str) -> Result<Amount> {
    ensure!(
        !text.is_empty()
            && text.len() <= 155
            && (text == "0" || !text.starts_with('0'))
            && text.bytes().all(|byte| byte.is_ascii_digit()),
        "fee must be a canonical nonnegative integer"
    );
    let amount = Amount::parse_bytes(text.as_bytes(), 10).context("invalid fee")?;
    ensure!(amount.bits() <= 512, "fee exceeds supported HASH range");
    Ok(amount)
}

/// Recompute a quoted fee using independently fetched network settings and the
/// exact requested extra; the node cannot silently enlarge the signed payment.
fn verify_automatic_fee(
    body: &TransactionBody,
    quote: &Value,
    status: &Value,
    extra: &Amount,
) -> Result<()> {
    let quoted = |name: &str| -> Result<Amount> {
        fee_amount(quote[name].as_str().context("missing fee quote field")?)
    };
    let price = fee_amount(
        status["fee_policy"]["minimum_fee_rate"]
            .as_str()
            .context("missing minimum fee rate")?,
    )?;
    ensure!(
        quoted("minimum_fee_rate")? == price,
        "fee setting changed while preparing; retry the transaction"
    );
    let creation = quoted("account_creation_fee")?;
    let grant_recipients = match &body.operation {
        Operation::Propose {
            proposal: hashstash::types::Proposal::Grant { payments },
            ..
        } => {
            ensure!(!payments.is_empty(), "empty grant recipient list");
            u64::try_from(payments.len())?
        }
        _ => 0,
    };
    ensure!(
        quoted("grant_recipient_fee")? == &price * grant_recipients,
        "invalid grant recipient fee quote"
    );
    let encoded_len = hashstash::codec::encode(&hashstash::types::Transaction {
        body: body.clone(),
        signature: [0; 64],
    })
    .len();
    let grant_weight = grant_recipients
        .checked_mul(fees::ACCOUNT_WEIGHT)
        .context("grant weight overflow")?;
    let base_weight = u64::try_from(encoded_len)?
        .checked_add(grant_weight)
        .context("transaction weight overflow")?;
    let reported_weight = quoted("weight")?;
    // Account creation still consumes weight when its governed fee is zero.
    // Infer its presence from the only two valid weights, then verify the fee.
    let creates_account = reported_weight != Amount::from(base_weight);
    let weight = if creates_account {
        ensure!(
            matches!(&body.operation, Operation::TransferExact { recipient, .. } if *recipient != body.sender),
            "invalid account creation weight quote"
        );
        base_weight
            .checked_add(fees::ACCOUNT_WEIGHT)
            .context("transaction weight overflow")?
    } else {
        base_weight
    };
    ensure!(
        creation
            == if creates_account {
                price.clone()
            } else {
                Amount::zero()
            },
        "invalid account creation fee quote"
    );
    let minimum = (Amount::from(weight) * price + Amount::from(fees::FEE_SCALE - 1))
        / Amount::from(fees::FEE_SCALE);
    let exact = &minimum + extra;
    ensure!(
        reported_weight == Amount::from(weight)
            && quoted("minimum_fee")? == minimum
            && quoted("extra_fee")? == *extra
            && quoted("fee")? == exact
            && body.fee == exact,
        "prepared fee does not match the network fee calculation"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_prepared_body(
    body: &TransactionBody,
    sender: PublicKey,
    operation: &Operation,
    nonce: u64,
    anchor: Hash,
    expiry_blocks: u64,
    request: &Value,
) -> Result<()> {
    verify_prepared_data(body, request)?;
    ensure!(
        body.sender == sender,
        "prepared transaction has another sender"
    );
    ensure!(
        body.nonce == nonce,
        "prepared transaction has another nonce"
    );
    ensure!(
        body.anchor == anchor && body.expiry_blocks == expiry_blocks,
        "prepared transaction has another anchor or lifetime"
    );
    ensure!(
        body.operation == *operation,
        "prepared transaction has another operation"
    );
    if let Some(exact) = request.get("fee").and_then(Value::as_str) {
        ensure!(
            body.fee == fee_amount(exact)?,
            "prepared transaction has another fee"
        );
    }
    Ok(())
}

fn verify_prepared_snapshot(body: &TransactionBody, quote: &Value, status: &Value) -> Result<()> {
    let tip = node::parse_hash(status["tip"].as_str().context("missing status tip")?)?;
    let height = status["height"].as_u64().context("invalid status height")?;
    let expiry = height
        .checked_add(body.expiry_blocks)
        .context("expiry height overflow")?;
    ensure!(
        body.anchor == tip,
        "prepared transaction has another anchor"
    );
    for field in ["chain_id", "tip", "state_root", "height"] {
        ensure!(
            !status[field].is_null() && quote[field] == status[field],
            "preparation snapshot changed; refresh before preparing"
        );
    }
    ensure!(
        quote["anchor"].as_str() == Some(hex::encode(body.anchor).as_str())
            && quote["anchor_height"].as_u64() == Some(height)
            && quote["expiry_blocks"].as_u64() == Some(body.expiry_blocks)
            && quote["expiry_height"].as_u64() == Some(expiry)
            && quote["nonce"].as_u64() == Some(body.nonce),
        "prepared transaction metadata differs from its signed anchor or lifetime"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_operation(
    url: &str,
    key: &Path,
    operation: Value,
    fee: Option<String>,
    extra_fee: Option<String>,
    data_hex: Option<String>,
    nonce: Option<u64>,
    expiry_blocks: Option<u64>,
) -> Result<Value> {
    let (secret, sender) = key_file(key)?;
    let status = node::call_rpc(url, "status", json!({})).await?;
    let mut fee_request = transaction_fee_request(fee, extra_fee)?;
    add_requested_data(&mut fee_request, data_hex)?;
    let chain_id = node::parse_hash(status["chain_id"].as_str().context("missing chain id")?)?;
    let operation = operation_addresses(operation, &chain_id)?;
    let operation: Operation = serde_json::from_value(operation)?;
    let expiry_blocks =
        expiry_blocks.unwrap_or_else(|| hashstash::wallet::default_expiry_blocks(&operation));
    ensure!(expiry_blocks > 0, "expiry blocks must be positive");
    let account = node::call_rpc(url, "account", json!({"key":hex::encode(sender)})).await?;
    let anchor = node::parse_hash(status["tip"].as_str().context("missing status tip")?)?;
    let nonce = if let Some(n) = nonce {
        n
    } else {
        let mut n = account["account"]["nonce"]
            .as_u64()
            .context("invalid nonce")?;
        let mut offset = 0;
        while offset < node::MAX_ADAPTIVE_MEMPOOL {
            let pending =
                node::call_rpc(url, "mempool", json!({"offset":offset,"format":"hex"})).await?;
            let page = pending.as_array().context("invalid mempool response")?;
            ensure!(page.len() <= 128, "mempool page exceeds requested limit");
            if page.is_empty() {
                break;
            }
            for v in page {
                let tx = hashstash::wallet::decode_signed(
                    v.get("raw")
                        .and_then(Value::as_str)
                        .context("mempool signed transaction missing")?,
                )?;
                if tx.body.sender == sender {
                    n = n.max(tx.body.nonce.checked_add(1).context("nonce exhausted")?);
                }
            }
            offset += page.len();
        }
        n
    };
    let body: TransactionBody = {
        let mut request = fee_request;
        request["sender"] = json!(hex::encode(sender));
        request["operation"] = serde_json::to_value(&operation)?;
        request["nonce"] = json!(nonce);
        request["anchor"] = json!(hex::encode(anchor));
        request["expiry_blocks"] = json!(expiry_blocks);
        let response = node::call_rpc(url, "preparetransaction", request.clone()).await?;
        let quote = response.get("fee_quote").cloned().unwrap_or(Value::Null);
        let envelope = prepared_envelope(response)?;
        let body = hashstash::wallet::decode_unsigned(&envelope)?;
        ensure!(
            hashstash::wallet::unsigned_chain(&envelope)? == chain_id,
            "prepared export has another network context"
        );
        verify_prepared_body(
            &body,
            sender,
            &operation,
            nonce,
            anchor,
            expiry_blocks,
            &request,
        )?;
        verify_prepared_snapshot(&body, &quote, &status)?;
        if request.get("fee").is_none() {
            verify_automatic_fee(
                &body,
                &quote,
                &status,
                &fee_amount(
                    request["extra_fee"]
                        .as_str()
                        .context("missing requested extra fee")?,
                )?,
            )?;
        }
        body
    };
    node::call_rpc(
        url,
        "submittransaction",
        serde_json::to_value(crypto::sign(&body, &secret)?)?,
    )
    .await
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            config,
            hashrate,
            preset,
        } => {
            let c = initial_config(preset, hashrate.as_deref())?;
            write_new(&config, &c, false)?;
            println!(
                "Created {}\nChain ID: {}",
                config.display(),
                hex::encode(c.chain_id())
            );
        }
        Command::PeerKeygen { out } => {
            println!(
                "{}",
                hex::encode(hashstash::peer_auth::generate_key_file(&out)?)
            );
        }
        Command::PeerKeycheck {
            key_file,
            peer_pin,
            peer_discovery,
            miner,
        } => {
            let policy = if peer_discovery {
                hashstash::peer_auth::Policy::discovery_from_file(&key_file, peer_pin)?
            } else {
                hashstash::peer_auth::Policy::from_file(&key_file, peer_pin)?
            };
            ensure!(
                policy.public_key() != node::parse_key(&miner)?,
                "peer identity must differ from the mining payout identity"
            );
            println!("{}", hex::encode(policy.public_key()));
        }
        Command::Keygen { out } => {
            let (secret, public) = loop {
                let mut secret = [0u8; 32];
                getrandom::fill(&mut secret).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
                if let Ok(public) = crypto::public_key(&secret) {
                    break (secret, public);
                }
            };
            write_new(
                &out,
                &json!({"secret":hex::encode(secret), "public":hex::encode(public)}),
                true,
            )?;
            println!(
                "Public key: {}\nPrivate key saved in {}",
                hex::encode(public),
                out.display()
            );
        }
        Command::PublicKey { key } => {
            println!("{}", hex::encode(key_file(&key)?.1));
        }
        Command::Address {
            key,
            public_key,
            config,
            chain_id,
        } => {
            let public = if let Some(path) = key {
                key_file(&path)?.1
            } else {
                node::parse_key(public_key.as_deref().context("public key missing")?)?
            };
            println!(
                "{}",
                address::encode(
                    &public,
                    &address_chain(config.as_deref(), chain_id.as_deref())?
                )?
            );
        }
        Command::DecodeAddress {
            address: text,
            config,
            chain_id,
        } => {
            println!(
                "{}",
                hex::encode(address::decode(
                    &text,
                    &address_chain(config.as_deref(), chain_id.as_deref())?
                )?)
            );
        }
        Command::Network { config } => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"format":"hashstash-network-v1","chain_id":hex::encode(address_chain(Some(&config), None)?)})
                )?
            );
        }
        Command::Sign { key, body, out } => {
            let (secret, public) = key_file(&key)?;
            let body: TransactionBody = serde_json::from_value(read_json(&body)?)?;
            hashstash::wallet::validate_body(&body)?;
            ensure!(
                body.sender == public,
                "transaction sender differs from signing key"
            );
            let signed = crypto::sign(&body, &secret)?;
            write_new(&out, &signed, false)?;
            println!("Signed transaction saved in {}", out.display());
        }
        Command::Send {
            url,
            key,
            operation,
            operation_file,
            fee,
            extra_fee,
            data_hex,
            nonce,
            expiry_blocks,
        } => {
            let operation = if let Some(file) = operation_file {
                read_json(&file)?
            } else {
                serde_json::from_str(operation.as_deref().context("operation missing")?)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &send_operation(
                        &url,
                        &key,
                        operation,
                        fee,
                        extra_fee,
                        data_hex,
                        nonce,
                        expiry_blocks
                    )
                    .await?
                )?
            );
        }
        Command::Prepare {
            url,
            sender,
            operation,
            operation_file,
            fee,
            extra_fee,
            data_hex,
            expiry_blocks,
            out,
        } => {
            let operation = if let Some(file) = operation_file {
                read_json(&file)?
            } else {
                serde_json::from_str(operation.as_deref().context("operation missing")?)?
            };
            let status = node::call_rpc(&url, "status", json!({})).await?;
            let chain_id =
                node::parse_hash(status["chain_id"].as_str().context("missing chain id")?)?;
            let operation = operation_addresses(operation, &chain_id)?;
            let parsed_operation: Operation = serde_json::from_value(operation.clone())?;
            let expiry_blocks = expiry_blocks
                .unwrap_or_else(|| hashstash::wallet::default_expiry_blocks(&parsed_operation));
            ensure!(expiry_blocks > 0, "expiry blocks must be positive");
            let mut request = transaction_fee_request(fee, extra_fee)?;
            add_requested_data(&mut request, data_hex)?;
            request["sender"] = json!(sender);
            request["operation"] = operation;
            let anchor = node::parse_hash(status["tip"].as_str().context("missing status tip")?)?;
            request["anchor"] = json!(hex::encode(anchor));
            request["expiry_blocks"] = json!(expiry_blocks);
            let automatic = request.get("fee").is_none();
            let response = node::call_rpc(&url, "preparetransaction", request.clone()).await?;
            let quote = response.get("fee_quote").cloned().unwrap_or(Value::Null);
            // Check the returned wire package before saving it for the offline signer.
            let envelope = prepared_envelope(response)?;
            let body = hashstash::wallet::decode_unsigned(&envelope)?;
            verify_prepared_data(&body, &request)?;
            ensure!(
                hashstash::wallet::unsigned_chain(&envelope)? == chain_id,
                "prepared export has another network context"
            );
            ensure!(
                body.sender
                    == node::parse_account(
                        request["sender"].as_str().context("missing sender")?,
                        &chain_id
                    )?,
                "prepared transaction has another sender"
            );
            ensure!(
                body.operation
                    == serde_json::from_value::<Operation>(request["operation"].clone())?,
                "prepared transaction has another operation"
            );
            ensure!(
                body.anchor == anchor && body.expiry_blocks == expiry_blocks,
                "prepared transaction has another anchor or lifetime"
            );
            verify_prepared_snapshot(&body, &quote, &status)?;
            if automatic {
                verify_automatic_fee(
                    &body,
                    &quote,
                    &status,
                    &fee_amount(
                        request["extra_fee"]
                            .as_str()
                            .context("missing requested extra fee")?,
                    )?,
                )?;
            } else {
                ensure!(
                    body.fee
                        == fee_amount(request["fee"].as_str().context("missing requested fee")?)?,
                    "prepared transaction has another fee"
                );
            }
            write_new(&out, &envelope, false)?;
            println!("Unsigned transaction saved in {}", out.display());
        }
        Command::Broadcast { url, raw, raw_file } => {
            let raw = if let Some(file) = raw_file {
                fs::read_to_string(file)?
            } else {
                raw.context("signed transaction missing")?
            };
            let raw = raw.trim();
            hashstash::wallet::decode_signed(raw)?;
            let result = node::call_rpc(&url, "broadcasttransaction", json!({"raw":raw})).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Run {
            config,
            data,
            miner,
            wallet_key,
            watch_key,
            rpc,
            public_web,
            p2p,
            stratum,
            no_stratum,
            stratum_share_difficulty,
            stratum_advertise,
            peer,
            peer_discovery,
            seed,
            advertise_peer,
            allow_private_peer_discovery,
            peer_key_file,
            peer_pin,
            stratum_password_file,
        } => {
            let c: Config = serde_json::from_value(read_json(&config)?)?;
            let chain_id = c.chain_id();
            let mut node = Node::open(&data, c, node::parse_account(&miner, &chain_id)?)?;
            if peer_discovery {
                let options = hashstash::peer_discovery::Options {
                    enabled: true,
                    seeds: seed,
                    advertise: advertise_peer,
                    allow_private: allow_private_peer_discovery,
                };
                options.validate()?;
                let key_path = match peer_key_file {
                    Some(path) => path,
                    None => {
                        let path = data.with_extension("peer-key.json");
                        if !path.exists() {
                            hashstash::peer_auth::generate_key_file(&path)?;
                        }
                        path
                    }
                };
                node = node
                    .with_peer_auth(hashstash::peer_auth::Policy::discovery_from_file(
                        &key_path, peer_pin,
                    )?)?
                    .with_discovery(options)?;
            } else if let Some(path) = peer_key_file {
                node =
                    node.with_peer_auth(hashstash::peer_auth::Policy::from_file(&path, peer_pin)?)?;
            }
            if let Some(path) = wallet_key {
                ensure!(
                    rpc.ip().is_loopback(),
                    "a local wallet requires a loopback RPC address"
                );
                node = node.with_wallet(key_file(&path)?.0)?;
            }
            if let Some(public) = watch_key {
                node = node.with_watch_key(node::parse_account(&public, &chain_id)?)?;
            }
            let password = stratum_password_file
                .map(fs::read_to_string)
                .transpose()?
                .map(|s| s.trim_end_matches(['\r', '\n']).to_owned());
            let server = node::serve(
                node.clone(),
                ServerOptions {
                    rpc,
                    public_web,
                    p2p,
                    stratum,
                    stratum_enabled: !no_stratum,
                    stratum_share_difficulty,
                    stratum_advertise,
                    peers: peer,
                    stratum_password: password,
                },
            )
            .await?;
            if let Some(address) = server.public_web {
                println!("Public web: http://{address}/");
            }
            println!(
                "Hashstash node started\nRPC: http://{}/rpc\nPeer: {}\nStratum: {}\n{}",
                server.rpc,
                server.p2p,
                if server.stratum_enabled {
                    format!("stratum+tcp://{}", server.stratum)
                } else {
                    "disabled".to_owned()
                },
                serde_json::to_string_pretty(&node.status()?)?
            );
            tokio::signal::ctrl_c().await?;
            server.stop().await;
        }
        Command::Rpc {
            url,
            method,
            params,
            params_file,
        } => {
            let p = if let Some(path) = params_file {
                read_json(&path)?
            } else {
                serde_json::from_str(&params)?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&node::call_rpc(&url, &method, p).await?)?
            );
        }
        Command::Mine {
            url,
            count,
            attempts,
            recipient,
        } => {
            let mut params = json!({"count":count,"attempts":attempts});
            if let Some(recipient) = recipient {
                params["recipient"] = json!(recipient);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&node::call_rpc(&url, "mine", params).await?)?
            );
        }
        Command::Transfer {
            url,
            key,
            recipient,
            amount,
            fee,
            extra_fee,
            data_hex,
        } => {
            let operation = json!({"TransferExact":{"recipient":recipient,"amount":amount}});
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &send_operation(&url, &key, operation, fee, extra_fee, data_hex, None, None)
                        .await?
                )?
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_combines_grant_recipients_before_signing() {
        let chain = [9; 32];
        let a = crypto::public_key(&[7; 32]).unwrap();
        let b = crypto::public_key(&[8; 32]).unwrap();
        let input = json!({"Propose":{"proposal":{"Grant":{"payments":[
            {"recipient":address::encode(&b,&chain).unwrap(),"amount":"2"},
            {"recipient":a,"amount":"3"},
            {"recipient":b,"amount":"4"}
        ]}}}});
        let result = operation_addresses(input, &chain).unwrap();
        let payments: Vec<hashstash::types::GrantPayment> =
            serde_json::from_value(result["Propose"]["proposal"]["Grant"]["payments"].clone())
                .unwrap();
        assert_eq!(payments.len(), 2);
        assert_eq!(
            hashstash::types::grant_total(&payments).unwrap(),
            9u32.into()
        );
        assert_eq!(
            payments.iter().find(|p| p.recipient == b).unwrap().amount,
            6u32.into()
        );
        let mut zero = result.clone();
        zero["Propose"]["proposal"]["Grant"]["payments"][0]["amount"] = json!("0");
        assert!(operation_addresses(zero, &chain).is_err());
    }

    #[test]
    fn cli_grant_list_is_not_limited_to_sixteen_recipients() {
        let chain = [9; 32];
        let entries: Vec<_> = (1..=40u8)
            .map(|index| {
                let key = crypto::public_key(&[index; 32]).unwrap();
                json!({"recipient":address::encode(&key, &chain).unwrap(),"amount":"1"})
            })
            .collect();
        let result = operation_addresses(
            json!({"Propose":{"proposal":{"Grant":{"payments":entries}}}}),
            &chain,
        )
        .unwrap();
        let payments: Vec<hashstash::types::GrantPayment> =
            serde_json::from_value(result["Propose"]["proposal"]["Grant"]["payments"].clone())
                .unwrap();
        assert_eq!(payments.len(), 40);
        assert_eq!(
            hashstash::types::grant_total(&payments).unwrap(),
            40u32.into()
        );
    }

    #[test]
    fn fee_arguments_are_exact_or_quoted_and_reject_obsolete_flags() {
        assert_eq!(
            transaction_fee_request(None, None).unwrap(),
            json!({"extra_fee":"0"})
        );
        assert_eq!(
            transaction_fee_request(Some("20".into()), None).unwrap(),
            json!({"fee":"20"})
        );
        assert_eq!(
            transaction_fee_request(None, Some("3".into())).unwrap(),
            json!({"extra_fee":"3"})
        );
        assert!(transaction_fee_request(Some("20".into()), Some("3".into())).is_err());
        for malformed in ["-1", "1.5", "", "one"] {
            assert!(transaction_fee_request(Some(malformed.into()), None).is_err());
            assert!(transaction_fee_request(None, Some(malformed.into())).is_err());
        }
        for command in ["send", "transfer", "prepare"] {
            let mut args = vec!["hashstash", command];
            if command == "prepare" {
                args.extend(["--sender", "key", "--operation", "{}", "--out", "out.json"]);
            } else {
                args.extend(["--key", "key.json"]);
                if command == "send" {
                    args.extend(["--operation", "{}"]);
                } else {
                    args.extend(["--recipient", "address", "--amount", "1"]);
                }
            }
            for valid in ["--fee", "--extra-fee"] {
                let mut selected = args.clone();
                selected.extend([valid, "2"]);
                assert!(Cli::try_parse_from(selected).is_ok());
            }
            for invalid in [
                vec!["--fee", "2", "--extra-fee", "1"],
                vec!["--max-fee", "2"],
                vec!["--priority-fee", "1"],
            ] {
                let mut selected = args.clone();
                selected.extend(invalid);
                assert!(Cli::try_parse_from(selected).is_err());
            }
        }
    }

    #[test]
    fn cli_checks_every_authorized_field_before_signing_node_response() {
        let sender = crypto::public_key(&[7; 32]).unwrap();
        let operation = Operation::TransferExact {
            recipient: crypto::public_key(&[6; 32]).unwrap(),
            amount: 5u32.into(),
        };
        let body = TransactionBody {
            sender,
            nonce: 4,
            anchor: [38; 32],
            expiry_blocks: 25,
            fee: 20u32.into(),
            operation: operation.clone(),
            data: vec![],
        };
        let request = json!({"fee":"20"});
        let check = |body: &TransactionBody| {
            verify_prepared_body(body, sender, &operation, 4, [38; 32], 25, &request)
        };
        assert!(check(&body).is_ok());
        let status = json!({"chain_id":hex::encode([9; 32]),"tip":hex::encode(body.anchor),"height":20,"state_root":hex::encode([44;32])});
        let mut snapshot_quote = status.clone();
        snapshot_quote["anchor"] = json!(hex::encode(body.anchor));
        snapshot_quote["anchor_height"] = json!(20);
        snapshot_quote["expiry_blocks"] = json!(25);
        snapshot_quote["expiry_height"] = json!(45);
        snapshot_quote["nonce"] = json!(body.nonce);
        assert!(verify_prepared_snapshot(&body, &snapshot_quote, &status).is_ok());
        for (field, value) in [
            ("chain_id", json!(hex::encode([8; 32]))),
            ("tip", json!(hex::encode([8; 32]))),
            ("state_root", json!(hex::encode([8; 32]))),
            ("height", json!(21)),
            ("anchor", json!(hex::encode([8; 32]))),
            ("anchor_height", json!(21)),
            ("expiry_blocks", json!(26)),
            ("expiry_height", json!(46)),
            ("nonce", json!(body.nonce + 1)),
        ] {
            let mut changed = snapshot_quote.clone();
            changed[field] = value;
            assert!(
                verify_prepared_snapshot(&body, &changed, &status).is_err(),
                "accepted altered {field}"
            );
        }
        for field in 1..8 {
            let mut changed = body.clone();
            match field {
                1 => changed.sender = crypto::public_key(&[8; 32]).unwrap(),
                2 => changed.nonce += 1,
                3 => changed.expiry_blocks += 1,
                4 => changed.fee += 1u32,
                5 => changed.data.push(1),
                6 => {
                    changed.operation = Operation::Refund {
                        round: 3,
                        proposal: [4; 32],
                    }
                }
                7 => changed.anchor[0] ^= 1,
                _ => unreachable!(),
            }
            assert!(check(&changed).is_err());
        }
        let mut response =
            serde_json::to_value(hashstash::wallet::unsigned(&body, &[9; 32])).unwrap();
        response["fee_quote"] = json!({"fee":"20","minimum_fee":"10"});
        assert_eq!(
            hashstash::wallet::decode_unsigned(&prepared_envelope(response.clone()).unwrap())
                .unwrap(),
            body
        );
        let mut mismatch = response.clone();
        mismatch["fee_quote"]["fee"] = json!("21");
        assert!(prepared_envelope(mismatch).is_err());
        let mut underpriced = response.clone();
        underpriced["fee_quote"]["minimum_fee"] = json!("21");
        assert!(prepared_envelope(underpriced).is_err());
        response["unexpected"] = json!(true);
        assert!(prepared_envelope(response).is_err());
    }

    #[test]
    fn cli_data_parser_preserves_bytes_and_rejects_malformed_or_oversized_hex() {
        assert_eq!(requested_data("").unwrap(), Vec::<u8>::new());
        assert_eq!(
            requested_data("0000aAfF80").unwrap(),
            vec![0, 0, 170, 255, 128]
        );
        let every_byte: Vec<u8> = (0..=255).collect();
        assert_eq!(
            requested_data(&hex::encode(&every_byte)).unwrap(),
            every_byte
        );
        let maximum = "ab".repeat(32 * 1024 * 1024 + 1);
        assert_eq!(
            requested_data(&maximum).unwrap().len(),
            32 * 1024 * 1024 + 1
        );
        assert!(requested_data(&(maximum + "00")).is_ok());
        for malformed in ["0", "000", "gg", "0x01", "00 01", " 00", "00\n", "００"] {
            assert!(requested_data(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn cli_data_request_omits_empty_payloads_and_rejects_malformed_bytes() {
        let base = json!({"fee":"20"});
        for input in [None, Some(String::new())] {
            let mut request = base.clone();
            add_requested_data(&mut request, input).unwrap();
            assert_eq!(request, base);
            assert!(request.get("data_hex").is_none());
        }
        let mut request = base.clone();
        add_requested_data(&mut request, Some("0000AaFF".into())).unwrap();
        assert_eq!(request, json!({"fee":"20","data_hex":"0000aaff"}));
        for malformed in ["a", "zz"] {
            let mut request = base.clone();
            assert!(add_requested_data(&mut request, Some(malformed.into())).is_err());
            assert_eq!(request, base);
        }
    }

    #[test]
    fn cli_prepared_data_must_match_authorized_bytes_including_absence() {
        let sender = crypto::public_key(&[7; 32]).unwrap();
        let operation = Operation::TransferExact {
            recipient: crypto::public_key(&[6; 32]).unwrap(),
            amount: 5u32.into(),
        };
        let make_body = |data| TransactionBody {
            sender,
            nonce: 4,
            anchor: [38; 32],
            expiry_blocks: 25,
            fee: 20u32.into(),
            operation: operation.clone(),
            data,
        };
        let body = make_body(vec![0, 170, 255]);
        for spelling in ["00AAFF", "00aAfF", "00aaff"] {
            let request = json!({"fee":"20","data_hex":spelling});
            verify_prepared_data(&body, &request).unwrap();
            verify_prepared_body(&body, sender, &operation, 4, [38; 32], 25, &request).unwrap();
            for changed in [
                vec![0, 171, 255],
                vec![0, 170],
                vec![0, 170, 255, 0],
                vec![255, 170, 0],
                vec![],
            ] {
                let changed = make_body(changed);
                assert!(verify_prepared_data(&changed, &request).is_err());
                assert!(
                    verify_prepared_body(&changed, sender, &operation, 4, [38; 32], 25, &request)
                        .is_err()
                );
            }
        }
        let empty_body = make_body(vec![]);
        for request in [json!({}), json!({"data_hex":""})] {
            verify_prepared_data(&empty_body, &request).unwrap();
            assert!(
                verify_prepared_data(&body, &request).is_err(),
                "node added unrequested data"
            );
        }
        for invalid in [
            json!({"data_hex":null}),
            json!({"data_hex":0}),
            json!({"data_hex":[0,170,255]}),
            json!({"data_hex":"0"}),
        ] {
            assert!(verify_prepared_data(&body, &invalid).is_err());
        }
    }

    #[test]
    fn cli_recomputes_exact_fee_and_rejects_inflated_or_inconsistent_quotes() {
        let sender = crypto::public_key(&[7; 32]).unwrap();
        let status = json!({"fee_policy":{"minimum_fee_rate":"100"}});
        let extra = Amount::from(3u32);
        for (recipient, creation) in [
            (crypto::public_key(&[6; 32]).unwrap(), 0u64),
            (crypto::public_key(&[8; 32]).unwrap(), 100u64),
            (sender, 0u64),
        ] {
            let mut body = TransactionBody {
                sender,
                nonce: 0,
                anchor: [38; 32],
                expiry_blocks: 100,
                fee: 0u32.into(),
                operation: Operation::TransferExact {
                    recipient,
                    amount: 1u32.into(),
                },
                data: vec![0, 1, 255],
            };
            let (weight, minimum) = loop {
                let weight = hashstash::codec::encode(&hashstash::types::Transaction {
                    body: body.clone(),
                    signature: [0; 64],
                })
                .len() as u64
                    + if creation == 0 { 0 } else { 1024 };
                let minimum = Amount::from((weight * 100).div_ceil(1024));
                let exact = &minimum + &extra;
                if body.fee == exact {
                    break (weight, minimum);
                }
                body.fee = exact;
            };
            let quote = json!({"minimum_fee_rate":"100","weight":weight.to_string(),"minimum_fee":minimum.to_string(),"account_creation_fee":creation.to_string(),"grant_recipient_fee":"0","extra_fee":"3","fee":body.fee.to_string()});
            assert!(verify_automatic_fee(&body, &quote, &status, &extra).is_ok());
            assert!(verify_automatic_fee(&body, &Value::Null, &status, &extra).is_err());
            assert!(verify_automatic_fee(&body, &quote, &Value::Null, &extra).is_err());
            assert!(verify_automatic_fee(&body, &quote, &status, &4u32.into()).is_err());
            let mut inflated = body.clone();
            inflated.fee = Amount::one() << 400usize;
            let mut inflated_quote = quote.clone();
            inflated_quote["fee"] = json!(inflated.fee.to_string());
            assert!(verify_automatic_fee(&inflated, &inflated_quote, &status, &extra).is_err());
            for field in [
                "weight",
                "minimum_fee",
                "account_creation_fee",
                "grant_recipient_fee",
                "extra_fee",
                "fee",
                "minimum_fee_rate",
            ] {
                let mut altered = quote.clone();
                altered[field] = json!("999999");
                assert!(
                    verify_automatic_fee(&body, &altered, &status, &extra).is_err(),
                    "{field}"
                );
                altered.as_object_mut().unwrap().remove(field);
                assert!(
                    verify_automatic_fee(&body, &altered, &status, &extra).is_err(),
                    "missing {field}"
                );
            }
        }
    }

    #[test]
    fn cli_zero_fee_rate_preserves_creation_weight_and_exact_extra() {
        let sender = crypto::public_key(&[7; 32]).unwrap();
        let other = crypto::public_key(&[8; 32]).unwrap();
        let status = json!({"fee_policy":{"minimum_fee_rate":"0"}});
        for (recipient, creation_weight) in [(sender, 0), (other, 0), (other, 1024)] {
            for extra in [0u32, 7] {
                let body = TransactionBody {
                    sender,
                    nonce: 0,
                    anchor: [38; 32],
                    expiry_blocks: 100,
                    fee: extra.into(),
                    operation: Operation::TransferExact {
                        recipient,
                        amount: 1u32.into(),
                    },
                    data: vec![],
                };
                let weight = hashstash::codec::encode(&hashstash::types::Transaction {
                    body: body.clone(),
                    signature: [0; 64],
                })
                .len() as u64
                    + creation_weight;
                let quote = json!({"minimum_fee_rate":"0","weight":weight.to_string(),
                    "minimum_fee":"0","account_creation_fee":"0","grant_recipient_fee":"0",
                    "extra_fee":extra.to_string(),"fee":extra.to_string()});
                verify_automatic_fee(&body, &quote, &status, &extra.into()).unwrap();
                for (field, value) in [
                    ("weight", (weight + 1).to_string()),
                    ("account_creation_fee", "1".into()),
                    ("minimum_fee", "1".into()),
                    ("fee", (extra + 1).to_string()),
                ] {
                    let mut changed = quote.clone();
                    changed[field] = json!(value);
                    assert!(verify_automatic_fee(&body, &changed, &status, &extra.into()).is_err());
                }
            }
        }
    }

    #[test]
    fn hashrate_units_are_exact_and_invalid_inputs_are_rejected() {
        for (input, expected) in [
            ("1", "1"),
            ("2k", "2000"),
            ("1.25M", "1250000"),
            ("7G", "7000000000"),
            ("100T", "100000000000000"),
            ("1.5P", "1500000000000000"),
            ("1.25E", "1250000000000000000"),
            (" 100 TH/s ", "100000000000000"),
            ("0.000001M", "1"),
        ] {
            assert_eq!(
                parse_hashrate(input).unwrap().to_string(),
                expected,
                "{input}"
            );
        }
        for input in [
            "",
            "0",
            "-1",
            "+1",
            ".1T",
            "1.",
            "1.2.3T",
            "1e3",
            "NaN",
            "inf",
            "0.1",
            "0.0000001M",
            "1Q",
            "1 2T",
            "T",
            "ï¼‘T",
        ] {
            assert!(parse_hashrate(input).is_err(), "{input}");
        }
        assert!(parse_hashrate(&"9".repeat(100)).is_err());
    }

    #[test]
    fn automatic_grant_fee_checks_every_prepaid_recipient() {
        use hashstash::types::{GrantPayment, Proposal};
        let mut payments: Vec<_> = (1..=40u8)
            .map(|index| GrantPayment {
                recipient: crypto::public_key(&[index; 32]).unwrap(),
                amount: 1u32.into(),
            })
            .collect();
        payments.sort_by_key(|p| p.recipient);
        let mut body = TransactionBody {
            sender: crypto::public_key(&[6; 32]).unwrap(),
            nonce: 0,
            fee: 0u32.into(),
            anchor: [38; 32],
            expiry_blocks: 100,
            data: vec![],
            operation: Operation::Propose {
                round: 0,
                description: [1; 32],
                proposal: Proposal::Grant { payments },
                support: 1u32.into(),
            },
        };
        let (weight, minimum) = loop {
            let weight = hashstash::codec::encode(&hashstash::types::Transaction {
                body: body.clone(),
                signature: [0; 64],
            })
            .len() as u64
                + 40 * fees::ACCOUNT_WEIGHT;
            let minimum = Amount::from((weight * 100).div_ceil(fees::FEE_SCALE));
            if body.fee == minimum {
                break (weight, minimum);
            }
            body.fee = minimum;
        };
        let status = json!({"fee_policy":{"minimum_fee_rate":"100"}});
        let mut quote = json!({"minimum_fee_rate":"100","weight":weight.to_string(),"minimum_fee":minimum.to_string(),"account_creation_fee":"0","grant_recipient_fee":"4000","extra_fee":"0","fee":body.fee.to_string()});
        assert!(verify_automatic_fee(&body, &quote, &status, &0u32.into()).is_ok());
        quote["grant_recipient_fee"] = json!("100");
        assert!(verify_automatic_fee(&body, &quote, &status, &0u32.into()).is_err());
    }

    #[test]
    fn initial_target_matches_estimated_hashes_without_changing_other_settings() {
        let mut config = Config::slow_testnet();
        let mut original = serde_json::to_value(&config).unwrap();
        let expected = Amount::from(100u32) * Amount::from(10u32).pow(12) * 15u32;
        calibrate_initial_target(&mut config, "100T").unwrap();
        let target = math::target_from_bits(config.initial_bits).unwrap();
        let work = math::work(&target);
        assert!(work >= expected);
        assert!((&work - &expected) * 10_000u32 < expected);
        assert_eq!(math::bits_from_target(&target), config.initial_bits);
        original["initial_bits"] = json!(config.initial_bits);
        assert_eq!(serde_json::to_value(&config).unwrap(), original);
        config.validate().unwrap();
    }

    #[test]
    fn calibration_rejects_unrepresentable_hashrates() {
        let mut config = Config::devnet();
        assert!(
            calibrate_initial_target(
                &mut config,
                &((Amount::one() << 256usize) - 1u32).to_string()
            )
            .is_err()
        );
        config.initial.interval = 1;
        assert!(calibrate_initial_target(&mut config, "1").is_err());
        assert!(calibrate_initial_target(&mut config, "0").is_err());
        config.initial.interval = 2;
        calibrate_initial_target(&mut config, "1").unwrap();
        assert_eq!(config.initial_bits, config.limit_bits);
    }

    #[test]
    fn calibrated_networks_have_timestamp_target_and_fresh_identity() {
        let first = initial_config(InitPreset::Slow, Some("100T")).unwrap();
        let second = initial_config(InitPreset::Slow, Some("100T")).unwrap();
        assert!(first.network.starts_with("hashstash-private-"));
        assert_ne!(first.chain_id(), second.chain_id());
        assert_eq!(first.initial.interval, 15);
        assert!(first.genesis_time > 1_770_000_000);
        let ordinary = initial_config(InitPreset::Dev, None).unwrap();
        assert_eq!(ordinary.initial.interval, 15);
    }

    #[test]
    fn new_genesis_file_never_overwrites_an_existing_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let original = Config::devnet();
        write_new(&path, &original, false).unwrap();
        let before = fs::read(&path).unwrap();
        let calibrated = initial_config(InitPreset::Slow, Some("100T")).unwrap();
        assert!(write_new(&path, &calibrated, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
