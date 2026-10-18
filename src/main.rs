use anyhow::{Context, Result, anyhow, ensure};
use clap::{Args, Parser, Subcommand, ValueEnum};
use hashstash::{
    address,
    config::Config,
    crypto, fees, math,
    node::{self, Node, RpcClient, RpcLimits, ServerOptions},
    types::{Amount, Hash, Operation, PublicKey, TransactionBody},
    wallet,
};
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

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
        /// The slow preset is for shared networks and requires --hashrate.
        #[arg(long, value_enum, default_value = "dev")]
        preset: InitPreset,
        /// Keep the presets' development proof-of-work limit (about two hashes
        /// per block) for a slow network that never leaves trusted peers.
        #[arg(long, conflicts_with = "hashrate")]
        uncalibrated: bool,
        /// Genesis Unix time in seconds; defaults to this computer's clock.
        /// Block 1 must be later, so a fast clock delays every node's first block.
        #[arg(long)]
        genesis_time: Option<u32>,
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
    /// Low-level automation signer for a TransactionBody JSON or unsigned export.
    /// It prints a review to stderr but does not ask; prefer the cold signer.
    Sign {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        body: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Genesis configuration of the network the signature is bound to.
        #[arg(
            long,
            conflicts_with = "chain_id",
            required_unless_present = "chain_id"
        )]
        config: Option<PathBuf>,
        /// Chain ID of that network, instead of --config.
        #[arg(long)]
        chain_id: Option<String>,
    },
    /// Sign and submit any protocol operation, filling the block anchor and account nonce.
    Send {
        #[command(flatten)]
        endpoint: Endpoint,
        #[command(flatten)]
        network: NetworkPin,
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
        #[command(flatten)]
        options: TransactionArgs,
        /// Validity after the signed anchor block; defaults to 2 blocks.
        #[arg(long)]
        expiry_blocks: Option<u64>,
    },
    /// Prepare an unsigned transaction for the offline signer. No private key is used.
    Prepare {
        #[command(flatten)]
        endpoint: Endpoint,
        #[command(flatten)]
        network: NetworkPin,
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
        #[command(flatten)]
        options: TransactionArgs,
        /// Validity after the signed anchor block; defaults to 2 blocks.
        #[arg(long)]
        expiry_blocks: Option<u64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Broadcast canonical signed transaction hex from the offline signer.
    Broadcast {
        #[command(flatten)]
        endpoint: Endpoint,
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
        /// Seed a wallet store that holds no wallets with this private key file. A store holding wallets keeps its saved selection.
        #[arg(long, conflicts_with = "watch_key")]
        wallet_key: Option<PathBuf>,
        /// Seed a wallet store that holds no wallets with this public key. Without wallet flags the store starts empty.
        #[arg(long)]
        watch_key: Option<String>,
        /// Owner-only file holding a passphrase that encrypts the wallet store's hot keys. The first start with it encrypts the saved keys; afterwards the store opens only with it.
        #[arg(long)]
        wallet_passphrase_file: Option<PathBuf>,
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
        /// Address or CIDR prefix of the operator's miners, which always keep reserved Stratum slots.
        #[arg(long, conflicts_with = "no_stratum")]
        stratum_trusted: Vec<hashstash::network_guard::TrustedPrefix>,
        /// Accept untrusted peers (a non-loopback --p2p or --peer-discovery) on a
        /// network whose easiest target makes blocks practically free.
        #[arg(long)]
        allow_easy_target: bool,
        /// Allow the development `mine` RPC although this network's proof of
        /// work is not a development target or untrusted peers reach the node.
        #[arg(long)]
        dev_rpc: bool,
        /// Make the checks `run` makes before it opens the database, then exit
        /// without opening it or binding any listener.
        #[arg(long)]
        preflight: bool,
    },
    /// Call a JSON-RPC method. Params may be inline JSON or a JSON file.
    /// Replies are bounded only by the response frame; query endpoints you trust.
    Rpc {
        #[command(flatten)]
        endpoint: Endpoint,
        method: String,
        #[arg(long, default_value = "{}")]
        params: String,
        #[arg(long)]
        params_file: Option<PathBuf>,
    },
    /// CPU-mine a bounded number of development blocks through a running node.
    /// The node refuses this outside a development network unless run with --dev-rpc.
    Mine {
        #[command(flatten)]
        endpoint: Endpoint,
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
        #[command(flatten)]
        endpoint: Endpoint,
        #[command(flatten)]
        network: NetworkPin,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        recipient: String,
        #[arg(long)]
        /// Whole monetary atoms (1000 atoms = 1 hash).
        amount: String,
        #[command(flatten)]
        options: TransactionArgs,
    },
}

/// The RPC endpoint of a networked command.
#[derive(Args)]
struct Endpoint {
    #[arg(long, default_value = "http://127.0.0.1:18480/rpc")]
    url: String,
    /// Permit plain HTTP to non-loopback endpoints, whose replies anyone on the path can forge.
    #[arg(long)]
    insecure_http: bool,
}
impl Endpoint {
    fn client(&self) -> Result<RpcClient> {
        RpcClient::new(&self.url, self.insecure_http)
    }
}

/// The network a signed or prepared transaction is intended for.
#[derive(Args)]
struct NetworkPin {
    /// Genesis configuration of the intended network; a non-loopback --url requires a pin.
    #[arg(long = "config", conflicts_with = "chain_id")]
    network_config: Option<PathBuf>,
    /// Chain ID of the intended network, instead of --config.
    #[arg(long)]
    chain_id: Option<String>,
    /// A second endpoint, ideally run by someone else, that must hold the anchor
    /// block on its canonical chain of the same network before signing or saving.
    #[arg(long)]
    anchor_url: Option<String>,
}
impl NetworkPin {
    fn chain(&self) -> Result<Option<Hash>> {
        if self.network_config.is_none() && self.chain_id.is_none() {
            return Ok(None);
        }
        address_chain(self.network_config.as_deref(), self.chain_id.as_deref()).map(Some)
    }
    /// The --anchor-url client, under the same transport rules as --url.
    fn anchor_client(&self, endpoint: &Endpoint) -> Result<Option<RpcClient>> {
        self.anchor_url
            .as_deref()
            .map(|url| RpcClient::new(url, endpoint.insecure_http).context("invalid --anchor-url"))
            .transpose()
    }
}

/// Fee, data and nonce choices shared by send, transfer and prepare.
#[derive(Args)]
struct TransactionArgs {
    /// Exact total fee in whole atoms (1000 atoms = 1 hash); quote the minimum when omitted.
    #[arg(long, conflicts_with_all = ["extra_fee", "max_fee"])]
    fee: Option<String>,
    /// Extra fee in whole atoms, shared using the governed fee split; zero when omitted.
    #[arg(long)]
    extra_fee: Option<String>,
    /// Highest automatically quoted total fee in whole atoms; defaults to the extra fee plus 1000.
    #[arg(long)]
    max_fee: Option<String>,
    /// Optional uninterpreted bytes, encoded as hexadecimal.
    #[arg(long)]
    data_hex: Option<String>,
    /// Exact nonce; by default the endpoint's pending nonce for this sender.
    #[arg(long)]
    nonce: Option<u64>,
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
    let initial = math::target_from_bits(bits)?;
    ensure!(
        initial <= limit,
        "hashrate is too low for this network's proof-of-work limit"
    );
    config.initial_bits = bits;
    // The easiest target stays within 2^CALIBRATED_LIMIT_RANGE_BITS of the
    // calibration, so neither a stall nor a backdated first block can make
    // blocks practically free; the shift keeps the compact form exact.
    config.limit_bits =
        math::bits_from_target(&limit.min(initial << CALIBRATED_LIMIT_RANGE_BITS));
    config.validate()?;
    Ok(())
}
/// How far below its calibrated initial difficulty a new network can ease.
const CALIBRATED_LIMIT_RANGE_BITS: usize = 8;

fn initial_config(
    preset: InitPreset,
    hashrate: Option<&str>,
    uncalibrated: bool,
    genesis_time: Option<u32>,
) -> Result<Config> {
    // The slow preset's longer rounds are for a shared network, which needs a
    // proof-of-work limit calibrated to its miners rather than the presets'.
    ensure!(
        hashrate.is_some() || uncalibrated || matches!(preset, InitPreset::Dev),
        "--preset slow needs --hashrate with the network's expected hashrate, or --uncalibrated to keep the development proof-of-work limit"
    );
    let mut config = match preset {
        InitPreset::Dev => Config::devnet(),
        InitPreset::Slow => Config::slow_testnet(),
    };
    // New CLI-created chains start their timestamp schedule at creation.
    config.genesis_time = match genesis_time {
        Some(time) => time,
        None => u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        )?,
    };
    if let Some(rate) = hashrate {
        calibrate_initial_target(&mut config, rate)?;
        let mut unique = [0u8; 8];
        getrandom::fill(&mut unique).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
        config.network = format!("hashstash-private-{}", hex::encode(unique));
    }
    config.validate()?;
    Ok(config)
}

/// Genesis time of the built-in presets; no release of this program predates it.
const CLOCK_FLOOR: u64 = 1_770_000_000;

/// Genesis time is part of the chain identity and block 1 must follow it, so
/// flag a genesis that correct clocks would see as future, or an implausible clock.
fn genesis_warnings(config: &Config, now: u64) -> Vec<String> {
    let mut warnings = Vec::new();
    let genesis = u64::from(config.genesis_time);
    if genesis > now.saturating_add(config.future_seconds.into()) {
        warnings.push(format!(
            "genesis time is {} seconds after this computer's clock; nodes defer block 1 until {}",
            genesis - now,
            utc_text(genesis)
        ));
    }
    if now < CLOCK_FLOOR {
        warnings.push(format!(
            "this computer's clock reads {}, earlier than this release; check it before sharing the configuration",
            utc_text(now)
        ));
    }
    warnings.extend(proof_of_work_warning(config));
    warnings
}

/// Everything `init` reports about a configuration it is about to write.
fn config_warnings(config: &Config, now: u64) -> Vec<String> {
    let mut warnings = config.sanity_warnings();
    warnings.extend(genesis_warnings(config, now));
    warnings
}

/// How cheap the easiest permitted target is, for a genesis whose limit
/// makes blocks practically free, such as the presets' uncalibrated one.
/// Fixture networks need a test build and are never shared: never flagged.
fn easy_limit(config: &Config) -> Option<String> {
    if config.test_work || !node::easy_proof_of_work(config) {
        return None;
    }
    let work = node::limit_work(config).map_or_else(|_| "?".to_owned(), |work| work.to_string());
    Some(format!(
        "the easiest permitted target needs only {work} expected hashes per block: after a stall or a backdated start, blocks and every proof-of-work-gated defence cost practically nothing"
    ))
}

fn proof_of_work_warning(config: &Config) -> Option<String> {
    easy_limit(config).map(|limit| {
        format!(
            "{limit}; a network that untrusted peers can reach needs {}",
            shared_calibration(config)
        )
    })
}

/// The calibration that clears the easy limit. Calibrating sets the easiest
/// target 2^CALIBRATED_LIMIT_RANGE_BITS times easier than the initial one,
/// so a lower rate still leaves the limit under EASY_LIMIT_WORK.
fn shared_calibration(config: &Config) -> String {
    let work = u128::from(node::EASY_LIMIT_WORK) << CALIBRATED_LIMIT_RANGE_BITS;
    let rate = work.div_ceil(u128::from(config.initial.interval.max(1)));
    format!(
        "init --hashrate {} or more at {}-second blocks (its easiest target is {} times easier than the calibrated one)",
        hashrate_text(rate),
        config.initial.interval,
        1u32 << CALIBRATED_LIMIT_RANGE_BITS
    )
}

/// A hash rate as `init --hashrate` reads it, rounded up to a tenth of its
/// largest whole prefix, so the text is never below `rate`.
fn hashrate_text(rate: u128) -> String {
    let (prefix, scale) = [("E", 18), ("P", 15), ("T", 12), ("G", 9), ("M", 6), ("K", 3)]
        .into_iter()
        .map(|(prefix, power)| (prefix, 10u128.pow(power)))
        .find(|(_, scale)| rate >= *scale)
        .unwrap_or(("", 1));
    if scale == 1 {
        return rate.to_string();
    }
    let tenths = rate.saturating_mul(10).div_ceil(scale);
    match tenths % 10 {
        0 => format!("{}{prefix}", tenths / 10),
        tenth => format!("{}.{tenth}{prefix}", tenths / 10),
    }
}

/// Why `run` would expose an easy-target network to untrusted peers: through
/// discovery or a listener beyond loopback. None for a calibrated or fixture
/// network, or one that only loopback and configured peers can reach.
fn easy_target_exposure(config: &Config, p2p: SocketAddr, peer_discovery: bool) -> Option<String> {
    let limit = easy_limit(config)?;
    let how = if peer_discovery {
        "--peer-discovery".to_owned()
    } else if !p2p.ip().is_loopback() {
        format!("--p2p {p2p}")
    } else {
        return None;
    };
    Some(format!("{how} accepts untrusted peers, but {limit}"))
}

/// Render Unix seconds as proleptic Gregorian UTC, without a time-zone database.
fn utc_text(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Civil-from-days over 400-year eras of 146,097 days, with March-based years.
    let shifted = days + 719_468;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// The Linux launcher's rule: one printable ASCII token of at most 256
/// characters. An empty file must not silently become the empty password.
fn stratum_password(text: &str) -> Result<String> {
    let password = text.trim_end_matches(['\r', '\n']);
    ensure!(
        !password.is_empty()
            && password.len() <= 256
            && password.bytes().all(|b| b.is_ascii_graphic()),
        "Stratum password must be one nonempty printable ASCII token of at most 256 characters"
    );
    Ok(password.to_owned())
}

/// Create the automatic discovery identity without ever leaving a partial file
/// under its final name: write a temporary file, then link it into place without
/// overwriting. An empty file from an interrupted earlier start is replaced.
fn ensure_peer_key_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.len() == 0 => {
            fs::remove_file(path)
                .with_context(|| format!("remove empty peer identity {}", path.display()))?;
        }
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {}", path.display()));
        }
    }
    let name = path
        .file_name()
        .context("peer identity path needs a file name")?;
    let mut unique = [0u8; 8];
    getrandom::fill(&mut unique).map_err(|e| anyhow!("randomness unavailable: {e}"))?;
    let temporary = path.with_file_name(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        hex::encode(unique)
    ));
    if let Err(error) = hashstash::peer_auth::generate_key_file(&temporary) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    let published = publish_new(&temporary, path, |from, to| fs::hard_link(from, to));
    if published.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    published.with_context(|| format!("publish peer identity {}", path.display()))?;
    #[cfg(unix)]
    {
        // Make the new directory entry durable as well as the file contents.
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        fs::File::open(parent.unwrap_or(Path::new(".")))?.sync_all()?;
    }
    Ok(())
}

/// Move a complete temporary file to `path` unless a file is already there.
/// `link` adds the name without replacing; where hard links are unsupported
/// (FAT volumes, some network mounts) the file is renamed while `path` is
/// still absent, which only two simultaneous first starts could race.
fn publish_new(
    temporary: &Path,
    path: &Path,
    link: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    match link(temporary, path) {
        Ok(()) => {}
        // A concurrent start published its identity first; keep that one.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return fs::rename(temporary, path);
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        },
    }
    fs::remove_file(temporary)
}

/// Peer transport keys are public network identities; never link one to a
/// server wallet account the operator also configured. Saved and later wallet
/// accounts are refused by the node's wallet store once peer auth is set.
fn check_peer_identity(
    peer: PublicKey,
    wallet: Option<PublicKey>,
    watch: Option<PublicKey>,
) -> Result<()> {
    ensure!(
        wallet != Some(peer) && watch != Some(peer),
        "peer identity must differ from the server wallet account"
    );
    Ok(())
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
    if private {
        // Owner-only before any key byte is written, on Windows too.
        hashstash::local_files::restrict_to_owner(path)?;
    }
    // Key files pass through this buffer; wipe it rather than freeing it intact.
    file.write_all(&Zeroizing::new(serde_json::to_vec_pretty(value)?))?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

/// A spending key file, in the legacy `secret`/`public` form or the
/// `hashstash-private-v1` export. Secret text is wiped when the record drops.
#[derive(Deserialize)]
struct SpendingKeyFile {
    format: Option<String>,
    private_key: Option<String>,
    public_key: Option<String>,
    secret: Option<String>,
    public: Option<String>,
}
impl Drop for SpendingKeyFile {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.secret.zeroize();
    }
}
fn key_file(path: &Path) -> Result<(Zeroizing<[u8; 32]>, PublicKey)> {
    let bytes = Zeroizing::new(fs::read(path).with_context(|| format!("read {}", path.display()))?);
    let file: SpendingKeyFile = serde_json::from_slice(&bytes)?;
    let (private_field, public_field) = if let Some(format) = &file.format {
        ensure!(
            format == "hashstash-private-v1",
            "unsupported private wallet format"
        );
        (&file.private_key, &file.public_key)
    } else {
        (&file.secret, &file.public)
    };
    let mut secret = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(
        private_field
            .as_deref()
            .context("key file requires a private key")?,
        secret.as_mut(),
    )
    .map_err(|_| anyhow!("expected 32-byte hexadecimal value"))?;
    let public = crypto::public_key(&secret)?;
    if let Some(p) = public_field {
        ensure!(
            node::parse_key(p)? == public,
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

/// The node-derived part of an automatic fee may be at most 1000 atoms (1 hash)
/// unless `--max-fee` raises the ceiling.
const DEFAULT_QUOTED_FEE_CEILING: u32 = 1000;

/// The exact total an automatic quote may reach. Its rate comes from the
/// endpoint, so a local ceiling bounds what a dishonest endpoint can charge.
/// An exact `--fee` is its own ceiling.
fn fee_ceiling(request: &Value, max_fee: Option<&str>) -> Result<Option<Amount>> {
    if request.get("fee").is_some() {
        ensure!(
            max_fee.is_none(),
            "an exact fee cannot be combined with a fee ceiling"
        );
        return Ok(None);
    }
    let extra = fee_amount(
        request["extra_fee"]
            .as_str()
            .context("missing requested extra fee")?,
    )?;
    let ceiling = match max_fee {
        Some(text) => fee_amount(text)?,
        None => &extra + DEFAULT_QUOTED_FEE_CEILING,
    };
    ensure!(
        ceiling >= extra,
        "fee ceiling is below the requested extra fee"
    );
    Ok(Some(ceiling))
}

fn check_fee_ceiling(fee: &Amount, ceiling: Option<&Amount>) -> Result<()> {
    if let Some(ceiling) = ceiling {
        ensure!(
            fee <= ceiling,
            "quoted fee of {fee} atoms exceeds the {ceiling} atom ceiling; pass --max-fee or an exact --fee to authorize it"
        );
    }
    Ok(())
}

/// The components of an automatic fee, as recomputed locally.
struct FeeBreakdown {
    rate: Amount,
    weight: u64,
    minimum: Amount,
    account_creation: Amount,
}

/// Recompute a quoted fee from the status fee rate and the exact requested
/// extra. Both come from the same endpoint, so this proves only that its
/// replies agree; the caller's fee ceiling bounds a dishonest endpoint.
fn verify_automatic_fee(
    body: &TransactionBody,
    quote: &Value,
    status: &Value,
    extra: &Amount,
) -> Result<FeeBreakdown> {
    let quoted = |name: &str| -> Result<Amount> {
        fee_amount(quote[name].as_str().context("missing fee quote field")?)
    };
    let price = fee_amount(
        status["fee_policy"]["minimum_fee_rate"]
            .as_str()
            .context("missing minimum fee rate")?,
    )?;
    ensure!(
        price.bits() <= 64,
        "minimum fee rate exceeds its consensus range"
    );
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
    // Account and record creation still consume weight when the governed fee
    // is zero. A Propose always creates its records; whether a recipient
    // account or the sender's support record exists is known only to the
    // node, so infer that from the only two valid weights, then verify fees.
    let extra_weight = reported_weight != Amount::from(base_weight);
    let creates_record = match &body.operation {
        Operation::Propose { .. } => true,
        Operation::Support { .. } => extra_weight,
        _ => false,
    };
    let creates_account = extra_weight && !creates_record;
    ensure!(
        !creates_account
            || matches!(&body.operation, Operation::TransferExact { recipient, .. } if *recipient != body.sender),
        "invalid account creation weight quote"
    );
    let weight = base_weight
        .checked_add(if creates_account { fees::ACCOUNT_WEIGHT } else { 0 })
        .and_then(|n| n.checked_add(if creates_record { fees::RECORD_WEIGHT } else { 0 }))
        .context("transaction weight overflow")?;
    let charge = |created: bool| {
        if created {
            price.clone()
        } else {
            Amount::zero()
        }
    };
    ensure!(
        creation == charge(creates_account),
        "invalid account creation fee quote"
    );
    ensure!(
        quoted("record_fee")? == charge(creates_record),
        "invalid governance record fee quote"
    );
    let minimum = (Amount::from(weight) * &price + Amount::from(fees::FEE_SCALE - 1))
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
    Ok(FeeBreakdown {
        rate: price,
        weight,
        minimum,
        account_creation: creation,
    })
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

/// A non-loopback endpoint must be pinned to the intended network, and a
/// pinned network must match the network the endpoint reports.
fn pinned_network(pin: Option<Hash>, reported: Hash, loopback: bool) -> Result<Hash> {
    match pin {
        Some(pinned) => {
            ensure!(
                pinned == reported,
                "RPC endpoint is on network {}, not the selected {}",
                hex::encode(reported),
                hex::encode(pinned)
            );
            Ok(pinned)
        }
        None => {
            ensure!(
                loopback,
                "a non-loopback --url requires --config or --chain-id for the intended network"
            );
            Ok(reported)
        }
    }
}

/// Lookups, one second apart, while a second endpoint receives or indexes a fresh anchor.
const ANCHOR_ATTEMPTS: u32 = 10;

/// Confirm through a second endpoint that the anchor is a canonical block of
/// the selected network. Signatures commit to the selected chain ID, so a
/// foreign anchor cannot make them valid on another network; this check
/// catches an anchor the selected network would reject before anything is
/// signed. The second endpoint is trusted for this fact alone.
async fn confirm_anchor(
    client: &RpcClient,
    chain_id: &Hash,
    anchor: &Hash,
    height: u64,
) -> Result<()> {
    let status = client.call("status", json!({}), RpcLimits::SMALL).await?;
    ensure!(
        status["chain_id"].as_str() == Some(hex::encode(chain_id).as_str()),
        "--anchor-url is on another network"
    );
    let anchor = hex::encode(anchor);
    let mut attempt = 1;
    let reply = loop {
        match client
            .call(
                "explorer_block",
                json!({"hash":anchor,"limit":1}),
                RpcLimits::SMALL,
            )
            .await
        {
            Ok(reply) => break reply,
            Err(error) if attempt == ANCHOR_ATTEMPTS => {
                return Err(error.context("--anchor-url does not report the anchor block"));
            }
            Err(_) => {
                attempt += 1;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };
    let block = &reply["block"];
    ensure!(
        block["hash"].as_str() == Some(anchor.as_str())
            && block["height"].as_u64() == Some(height)
            && block["status"] == "confirmed",
        "--anchor-url does not hold anchor {anchor} at height {height} on its canonical chain"
    );
    Ok(())
}

enum NonceSource {
    Requested(u64),
    Discovered(node::PendingNonce),
}
impl NonceSource {
    fn value(&self) -> u64 {
        match self {
            Self::Requested(nonce) => *nonce,
            Self::Discovered(found) => found.nonce,
        }
    }
}

/// A preparation whose every signed field has been checked against the request.
struct Prepared {
    envelope: wallet::UnsignedEnvelope,
    body: TransactionBody,
    chain_id: Hash,
    anchor_height: u64,
    anchor_confirmed: bool,
    nonce: NonceSource,
    fee: Option<(FeeBreakdown, Amount)>,
    scheduled_change: Option<String>,
}
impl Prepared {
    /// Context the signed body alone does not show, including what the endpoint chose.
    fn notes(&self, client: &RpcClient) -> Vec<String> {
        let mut notes = vec![format!(
            "Anchor height: {}; includable through block {}",
            self.anchor_height,
            self.anchor_height.saturating_add(self.body.expiry_blocks)
        )];
        if self.anchor_confirmed {
            notes.push(
                "Anchor check: a canonical block of this network at --anchor-url".to_owned(),
            );
        } else if !client.is_loopback() {
            notes.push(
                "warning: only this remote endpoint vouches for the anchor block; a dishonest one can anchor it where it never confirms. Add --anchor-url with a second endpoint, or prepare through a loopback node".to_owned(),
            );
        }
        notes.push(match &self.nonce {
            NonceSource::Requested(_) => "Nonce source: --nonce".to_owned(),
            NonceSource::Discovered(found) => match found.pending {
                Some(pending) => format!(
                    "Nonce source: account nonce {} reported by the endpoint, after {} signed pending transaction(s) from this sender",
                    found.account_nonce, pending
                ),
                None => format!(
                    "Nonce source: account nonce {} reported by the endpoint, pending nonce {} as the endpoint reports it, unverified",
                    found.account_nonce, found.nonce
                ),
            },
        });
        notes.push(match &self.fee {
            Some((fee, ceiling)) => format!(
                "Fee quote: minimum {} atoms for weight {} at {} atoms per {} weight, including account creation {} atoms; ceiling {} atoms",
                fee.minimum,
                fee.weight,
                fee.rate,
                fees::FEE_SCALE,
                fee.account_creation,
                ceiling
            ),
            None => "Fee source: exact --fee".to_owned(),
        });
        notes.extend(self.scheduled_change.clone());
        if !client.is_loopback()
            && self.body.expiry_blocks > wallet::default_expiry_blocks(&self.body.operation)
        {
            let nonce = self.body.nonce;
            notes.push(format!(
                "warning: a remote endpoint can withhold this transaction for its {}-block lifetime. If it never confirms, cancel it through a node you trust with another nonce-{nonce} transaction paying a higher fee for its weight, such as a 1-atom transfer to yourself with --nonce {nonce}. If the account's next nonce there is lower, submit those lower-nonce transactions with the cancellation, or wait out the lifetime",
                self.body.expiry_blocks
            ));
        }
        notes
    }
}

/// Prepare through the endpoint, then verify network, sender, nonce, anchor,
/// lifetime, operation, data and fee before anything is signed or exported.
async fn prepare_verified(
    client: &RpcClient,
    anchor_client: Option<&RpcClient>,
    network: &NetworkPin,
    sender: &str,
    operation: Value,
    options: TransactionArgs,
    expiry_blocks: Option<u64>,
) -> Result<Prepared> {
    let status = client.call("status", json!({}), RpcLimits::SMALL).await?;
    let reported = node::parse_hash(status["chain_id"].as_str().context("missing chain id")?)?;
    let chain_id = pinned_network(network.chain()?, reported, client.is_loopback())?;
    let sender = node::parse_account(sender, &chain_id)?;
    let mut request = transaction_fee_request(options.fee, options.extra_fee)?;
    let ceiling = fee_ceiling(&request, options.max_fee.as_deref())?;
    add_requested_data(&mut request, options.data_hex)?;
    let operation = operation_addresses(operation, &chain_id)?;
    let operation: Operation = serde_json::from_value(operation)?;
    let expiry_blocks = expiry_blocks.unwrap_or_else(|| wallet::default_expiry_blocks(&operation));
    ensure!(expiry_blocks > 0, "expiry blocks must be positive");
    // A remote endpoint could pick a nonce above the account's next one and
    // withhold the signed result until a lower-nonce payment makes it valid.
    // Beyond the default lifetime that window is the user's, and so is the nonce.
    ensure!(
        client.is_loopback()
            || options.nonce.is_some()
            || expiry_blocks <= wallet::default_expiry_blocks(&operation),
        "a remote endpoint cannot choose the nonce of a {expiry_blocks}-block transaction; check the account's next nonce on a node you trust and pass --nonce"
    );
    let anchor = node::parse_hash(status["tip"].as_str().context("missing status tip")?)?;
    let anchor_height = status["height"].as_u64().context("invalid status height")?;
    let nonce = match options.nonce {
        Some(nonce) => NonceSource::Requested(nonce),
        None => NonceSource::Discovered(
            client
                .pending_nonce(&chain_id, &sender, node::ScanBudget::DEFAULT)
                .await?,
        ),
    };
    request["sender"] = json!(hex::encode(sender));
    request["operation"] = serde_json::to_value(&operation)?;
    request["nonce"] = json!(nonce.value());
    request["anchor"] = json!(hex::encode(anchor));
    request["expiry_blocks"] = json!(expiry_blocks);
    let response = client
        .call(
            "preparetransaction",
            request.clone(),
            RpcLimits::echoing(&request)?,
        )
        .await?;
    let quote = response.get("fee_quote").cloned().unwrap_or(Value::Null);
    // Check the returned wire package before signing or saving it.
    let envelope = prepared_envelope(response)?;
    let body = wallet::decode_unsigned(&envelope)?;
    ensure!(
        wallet::unsigned_chain(&envelope)? == chain_id,
        "prepared export has another network context"
    );
    verify_prepared_body(
        &body,
        sender,
        &operation,
        nonce.value(),
        anchor,
        expiry_blocks,
        &request,
    )?;
    verify_prepared_snapshot(&body, &quote, &status)?;
    let fee = match ceiling {
        Some(ceiling) => {
            let breakdown = verify_automatic_fee(
                &body,
                &quote,
                &status,
                &fee_amount(
                    request["extra_fee"]
                        .as_str()
                        .context("missing requested extra fee")?,
                )?,
            )?;
            check_fee_ceiling(&body.fee, Some(&ceiling))?;
            Some((breakdown, ceiling))
        }
        None => None,
    };
    if let Some(anchor_client) = anchor_client {
        confirm_anchor(anchor_client, &chain_id, &anchor, anchor_height).await?;
    }
    Ok(Prepared {
        envelope,
        body,
        chain_id,
        anchor_height,
        anchor_confirmed: anchor_client.is_some(),
        nonce,
        fee,
        scheduled_change: scheduled_change_note(&quote),
    })
}

/// A warning for a fee-rate increase or capacity decrease that the endpoint
/// reports within this lifetime. Advisory only: the signed body is unchanged.
fn scheduled_change_note(quote: &Value) -> Option<String> {
    let change = quote.get("scheduled_change")?;
    if change["valid_after"] != false {
        return None;
    }
    let height = change["effective_height"].as_u64()?;
    Some(match change["parameter"].as_str()? {
        "MinimumFeeRate" => format!(
            "warning: the minimum fee rises to {} atoms from block {height}; this transaction is valid only before that block unless --fee or --extra-fee covers it",
            change["minimum_fee"].as_str()?
        ),
        "BlockBytes" => format!(
            "warning: block capacity falls to {} from block {height}; this transaction is valid only before that block",
            change["value"].as_str()?
        ),
        _ => return None,
    })
}

/// Review lines for a body about to be signed or exported. `· HASH` values
/// are raw atoms; long data is abbreviated after its byte count.
fn review_lines(body: &TransactionBody, chain_id: Option<&Hash>) -> Vec<String> {
    wallet::review(body, chain_id)
        .into_iter()
        .map(|field| {
            let mut value = field.value;
            if field.label == "Data hex" && value.len() > 128 {
                value.truncate(128);
                value.push_str("...");
            }
            match field.label.strip_suffix(" · HASH") {
                Some(label) => format!("{label}: {value} atoms"),
                None => format!("{}: {value}", field.label),
            }
        })
        .collect()
}

/// Reviews go to stderr so stdout stays machine-readable.
fn print_review(title: &str, body: &TransactionBody, chain_id: Option<&Hash>, notes: &[String]) {
    eprintln!("{title}");
    for line in review_lines(body, chain_id).iter().chain(notes) {
        eprintln!("  {line}");
    }
}

/// Broadcast canonical signed bytes, which every listener accepts. The endpoint
/// must report the locally computed transaction ID.
async fn broadcast_signed(
    client: &RpcClient,
    transaction: &hashstash::types::Transaction,
    raw: &str,
) -> Result<Value> {
    let id = hex::encode(hashstash::codec::transaction_id(transaction));
    let result = client
        .call(
            "broadcasttransaction",
            json!({"raw":raw}),
            RpcLimits::SMALL,
        )
        .await?;
    ensure!(
        result["transaction_id"].as_str() == Some(id.as_str()),
        "RPC endpoint reported another transaction ID"
    );
    Ok(result)
}

/// The key file is read for its public key, then again only to sign, so the
/// secret is not held in memory across RPC round trips.
async fn send_operation(
    endpoint: &Endpoint,
    key: &Path,
    network: &NetworkPin,
    operation: Value,
    options: TransactionArgs,
    expiry_blocks: Option<u64>,
) -> Result<Value> {
    let (client, anchor_client) = (endpoint.client()?, network.anchor_client(endpoint)?);
    let sender = key_file(key)?.1;
    let prepared = prepare_verified(
        &client,
        anchor_client.as_ref(),
        network,
        &hex::encode(sender),
        operation,
        options,
        expiry_blocks,
    )
    .await?;
    print_review(
        "Signing transaction:",
        &prepared.body,
        Some(&prepared.chain_id),
        &prepared.notes(&client),
    );
    let signed = {
        let (secret, public) = key_file(key)?;
        ensure!(
            public == sender,
            "key file changed while preparing the transaction"
        );
        crypto::sign(&prepared.chain_id, &prepared.body, &secret)?
    };
    let result = broadcast_signed(&client, &signed, &wallet::signed_hex(&signed)).await?;
    Ok(json!({"txid":result["transaction_id"]}))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init {
            config,
            hashrate,
            preset,
            uncalibrated,
            genesis_time,
        } => {
            let c = initial_config(preset, hashrate.as_deref(), uncalibrated, genesis_time)?;
            for warning in config_warnings(&c, node::now()) {
                eprintln!("warning: {warning}");
            }
            write_new(&config, &c, false)?;
            println!(
                "Created {}\nChain ID: {}\nGenesis time: {} ({})",
                config.display(),
                hex::encode(c.chain_id()),
                c.genesis_time,
                utc_text(c.genesis_time.into())
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
                let mut secret = Zeroizing::new([0u8; 32]);
                getrandom::fill(secret.as_mut())
                    .map_err(|e| anyhow!("randomness unavailable: {e}"))?;
                if let Ok(public) = crypto::public_key(&secret) {
                    break (secret, public);
                }
            };
            // Serialize borrowed text so no intermediate JSON tree copies the secret.
            #[derive(Serialize)]
            struct NewKeyFile<'a> {
                public: String,
                secret: &'a str,
            }
            let secret_hex = Zeroizing::new(hex::encode(secret.as_slice()));
            write_new(
                &out,
                &NewKeyFile {
                    public: hex::encode(public),
                    secret: &secret_hex,
                },
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
        Command::Sign {
            key,
            body,
            out,
            config,
            chain_id,
        } => {
            let (secret, public) = key_file(&key)?;
            // The operator names the network; the signature binds it. An
            // unsigned export's own context must agree and is never adopted.
            let chain_id = address_chain(config.as_deref(), chain_id.as_deref())?;
            let input = read_json(&body)?;
            let body = if input.get("format").is_some() {
                let envelope: wallet::UnsignedEnvelope = serde_json::from_value(input)?;
                let body = wallet::decode_unsigned(&envelope)?;
                ensure!(
                    wallet::unsigned_chain(&envelope)? == chain_id,
                    "unsigned export was prepared for another network"
                );
                body
            } else {
                let body: TransactionBody = serde_json::from_value(input)?;
                hashstash::wallet::validate_body(&body)?;
                body
            };
            ensure!(
                body.sender == public,
                "transaction sender differs from signing key"
            );
            let default_lifetime = wallet::default_expiry_blocks(&body.operation);
            let mut notes = Vec::new();
            if body.expiry_blocks > default_lifetime {
                notes.push(format!(
                    "warning: lifetime of {} blocks exceeds the {default_lifetime}-block default",
                    body.expiry_blocks
                ));
            }
            print_review("Signing transaction:", &body, Some(&chain_id), &notes);
            let signed = crypto::sign(&chain_id, &body, &secret)?;
            write_new(&out, &signed, false)?;
            println!("Signed transaction saved in {}", out.display());
        }
        Command::Send {
            endpoint,
            network,
            key,
            operation,
            operation_file,
            options,
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
                    &send_operation(&endpoint, &key, &network, operation, options, expiry_blocks)
                        .await?
                )?
            );
        }
        Command::Prepare {
            endpoint,
            network,
            sender,
            operation,
            operation_file,
            options,
            expiry_blocks,
            out,
        } => {
            let operation = if let Some(file) = operation_file {
                read_json(&file)?
            } else {
                serde_json::from_str(operation.as_deref().context("operation missing")?)?
            };
            let (client, anchor_client) = (endpoint.client()?, network.anchor_client(&endpoint)?);
            let prepared = prepare_verified(
                &client,
                anchor_client.as_ref(),
                &network,
                &sender,
                operation,
                options,
                expiry_blocks,
            )
            .await?;
            print_review(
                "Prepared transaction:",
                &prepared.body,
                Some(&prepared.chain_id),
                &prepared.notes(&client),
            );
            write_new(&out, &prepared.envelope, false)?;
            println!("Unsigned transaction saved in {}", out.display());
        }
        Command::Broadcast {
            endpoint,
            raw,
            raw_file,
        } => {
            let raw = if let Some(file) = raw_file {
                fs::read_to_string(file)?
            } else {
                raw.context("signed transaction missing")?
            };
            let raw = raw.trim();
            // The endpoint verifies the signature for its own chain ID.
            let transaction = hashstash::wallet::decode_signed_record(raw)?;
            let result = broadcast_signed(&endpoint.client()?, &transaction, raw).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Command::Run {
            config,
            data,
            miner,
            wallet_key,
            watch_key,
            wallet_passphrase_file,
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
            stratum_trusted,
            allow_easy_target,
            dev_rpc,
            preflight,
        } => {
            let c: Config = serde_json::from_value(read_json(&config)?)?;
            // A hand-edited genesis can be valid yet unsafe to operate.
            for warning in c.sanity_warnings() {
                eprintln!("warning: {warning}");
            }
            // Refused before the database opens: the operator chose the
            // listener, so this is a configuration error, not a runtime one.
            if let Some(exposure) = easy_target_exposure(&c, p2p, peer_discovery) {
                ensure!(
                    allow_easy_target,
                    "{exposure}; create the network with {}, or pass --allow-easy-target to run it anyway",
                    shared_calibration(&c)
                );
                eprintln!("warning: {exposure}");
            }
            let chain_id = c.chain_id();
            // Check wallet seeds and the password before opening the database.
            let wallet = match &wallet_key {
                Some(path) => {
                    ensure!(
                        rpc.ip().is_loopback(),
                        "a local wallet requires a loopback RPC address"
                    );
                    Some(key_file(path)?)
                }
                None => None,
            };
            let watch = watch_key
                .map(|public| node::parse_account(&public, &chain_id))
                .transpose()?;
            let wallet_passphrase = wallet_passphrase_file
                .as_deref()
                .map(node::WalletPassphrase::read)
                .transpose()?;
            let password = stratum_password_file
                .map(fs::read_to_string)
                .transpose()?
                .map(|text| stratum_password(&text))
                .transpose()?;
            // serve() enforces this too; checking here fails before the replay.
            ensure!(
                no_stratum || stratum.ip().is_loopback() || password.is_some(),
                "a non-loopback Stratum listener requires a password; pass --stratum-password-file"
            );
            // An installer's check: the service's own options, refused here
            // rather than in a restart loop.
            if preflight {
                println!("Run options are valid. No database opened and no listeners started.");
                return Ok(());
            }
            let mut node = Node::open_with_wallet_passphrase(
                &data,
                c,
                node::parse_account(&miner, &chain_id)?,
                wallet_passphrase.as_ref(),
            )?;
            // The derived key stays with the wallet store; the passphrase goes.
            drop(wallet_passphrase);
            let wallet_public = wallet.as_ref().map(|(_, public)| *public);
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
                        // Earlier releases named it from the stem alone, so
                        // net.db and net.sqlite shared one identity.
                        hashstash::local_files::adopt_legacy_secret(&data, "peer-key.json")?;
                        let path = hashstash::local_files::sidecar(&data, "peer-key.json");
                        ensure_peer_key_file(&path)?;
                        path
                    }
                };
                let policy =
                    hashstash::peer_auth::Policy::discovery_from_file(&key_path, peer_pin)?;
                check_peer_identity(policy.public_key(), wallet_public, watch)?;
                node = node.with_peer_auth(policy)?.with_discovery(options)?;
            } else if let Some(path) = peer_key_file {
                let policy = hashstash::peer_auth::Policy::from_file(&path, peer_pin)?;
                check_peer_identity(policy.public_key(), wallet_public, watch)?;
                node = node.with_peer_auth(policy)?;
            }
            if let Some((secret, _)) = &wallet {
                node = node.with_wallet(**secret)?;
            }
            drop(wallet);
            if let Some(public) = watch {
                node = node.with_watch_key(public)?;
            }
            if dev_rpc {
                node = node.with_dev_rpc();
            }
            if let Some(address) = public_web.filter(|address| !address.ip().is_loopback()) {
                eprintln!(
                    "warning: public web on {address} is plain HTTP; serve browsers only through an HTTPS reverse proxy"
                );
            }
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
                    stratum_trusted,
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
            endpoint,
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
                serde_json::to_string_pretty(
                    &endpoint
                        .client()?
                        .call(&method, p, RpcLimits::FRAME)
                        .await?
                )?
            );
        }
        Command::Mine {
            endpoint,
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
                serde_json::to_string_pretty(
                    &endpoint
                        .client()?
                        .call("mine", params, RpcLimits::SMALL)
                        .await?
                )?
            );
        }
        Command::Transfer {
            endpoint,
            network,
            key,
            recipient,
            amount,
            options,
        } => {
            let operation = json!({"TransferExact":{"recipient":recipient,"amount":amount}});
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &send_operation(&endpoint, &key, &network, operation, options, None).await?
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
            for valid in ["--fee", "--extra-fee", "--max-fee", "--nonce"] {
                let mut selected = args.clone();
                selected.extend([valid, "2"]);
                assert!(Cli::try_parse_from(selected).is_ok());
            }
            // --max-fee is a ceiling for automatic quotes; an exact fee needs none.
            let mut ceiling = args.clone();
            ceiling.extend(["--extra-fee", "1", "--max-fee", "20"]);
            assert!(Cli::try_parse_from(ceiling).is_ok());
            for invalid in [
                vec!["--fee", "2", "--extra-fee", "1"],
                vec!["--fee", "2", "--max-fee", "2"],
                vec!["--config", "network.json", "--chain-id", "00"],
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
            let quote = json!({"minimum_fee_rate":"100","weight":weight.to_string(),"minimum_fee":minimum.to_string(),"account_creation_fee":creation.to_string(),"grant_recipient_fee":"0","record_fee":"0","extra_fee":"3","fee":body.fee.to_string()});
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
                "record_fee",
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
    fn consistent_inflated_fee_rate_is_refused_by_the_local_ceiling() {
        // One endpoint answers both status and the quote, so a dishonest one can
        // report a single inflated rate consistently. Only the ceiling stops it.
        let rate = 1u64 << 40;
        let mut body = TransactionBody {
            sender: crypto::public_key(&[7; 32]).unwrap(),
            nonce: 0,
            anchor: [38; 32],
            expiry_blocks: 2,
            fee: 0u32.into(),
            operation: Operation::TransferExact {
                recipient: crypto::public_key(&[6; 32]).unwrap(),
                amount: 1u32.into(),
            },
            data: vec![],
        };
        let weight = loop {
            let weight = hashstash::codec::encode(&hashstash::types::Transaction {
                body: body.clone(),
                signature: [0; 64],
            })
            .len() as u64;
            let minimum = (Amount::from(weight) * rate + 1023u32) / 1024u32;
            if body.fee == minimum {
                break weight;
            }
            body.fee = minimum;
        };
        let status = json!({"fee_policy":{"minimum_fee_rate":rate.to_string()}});
        let quote = json!({"minimum_fee_rate":rate.to_string(),"weight":weight.to_string(),
            "minimum_fee":body.fee.to_string(),"account_creation_fee":"0","grant_recipient_fee":"0",
            "record_fee":"0","extra_fee":"0","fee":body.fee.to_string()});
        let breakdown = verify_automatic_fee(&body, &quote, &status, &Amount::zero()).unwrap();
        assert_eq!(breakdown.minimum, body.fee);
        assert_eq!(breakdown.rate, Amount::from(rate));
        let request = json!({"extra_fee":"0"});
        let default = fee_ceiling(&request, None).unwrap();
        assert_eq!(default, Some(1000u32.into()));
        assert!(check_fee_ceiling(&body.fee, default.as_ref()).is_err());
        let raised = fee_ceiling(&request, Some(&body.fee.to_string())).unwrap();
        check_fee_ceiling(&body.fee, raised.as_ref()).unwrap();
        let below = fee_ceiling(&request, Some(&(&body.fee - 1u32).to_string())).unwrap();
        assert!(check_fee_ceiling(&body.fee, below.as_ref()).is_err());
        // The default ceiling sits above the requested extra; exact fees need none.
        assert_eq!(
            fee_ceiling(&json!({"extra_fee":"5"}), None).unwrap(),
            Some(1005u32.into())
        );
        assert_eq!(fee_ceiling(&json!({"fee":"5"}), None).unwrap(), None);
        check_fee_ceiling(&(Amount::one() << 400usize), None).unwrap();
        assert!(fee_ceiling(&json!({"fee":"5"}), Some("6")).is_err());
        assert!(fee_ceiling(&json!({"extra_fee":"5"}), Some("4")).is_err());
        assert!(fee_ceiling(&json!({"extra_fee":"5"}), Some("-1")).is_err());
        // Consensus rates are u64; a larger reported rate is not a network setting.
        let huge = (Amount::one() << 64usize).to_string();
        let mut quote = quote;
        quote["minimum_fee_rate"] = json!(huge);
        assert!(
            verify_automatic_fee(
                &body,
                &quote,
                &json!({"fee_policy":{"minimum_fee_rate":huge}}),
                &Amount::zero()
            )
            .is_err()
        );
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
                    "record_fee":"0","extra_fee":extra.to_string(),"fee":extra.to_string()});
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
                + 40 * fees::ACCOUNT_WEIGHT
                + fees::RECORD_WEIGHT;
            let minimum = Amount::from((weight * 100).div_ceil(fees::FEE_SCALE));
            if body.fee == minimum {
                break (weight, minimum);
            }
            body.fee = minimum;
        };
        let status = json!({"fee_policy":{"minimum_fee_rate":"100"}});
        let mut quote = json!({"minimum_fee_rate":"100","weight":weight.to_string(),"minimum_fee":minimum.to_string(),"account_creation_fee":"0","grant_recipient_fee":"4000","record_fee":"100","extra_fee":"0","fee":body.fee.to_string()});
        assert!(verify_automatic_fee(&body, &quote, &status, &0u32.into()).is_ok());
        for (field, value) in [("grant_recipient_fee", "100"), ("record_fee", "0")] {
            let mut altered = quote.clone();
            altered[field] = json!(value);
            assert!(verify_automatic_fee(&body, &altered, &status, &0u32.into()).is_err());
        }
        // Audit F046: a Propose always pays for its proposal record.
        quote["weight"] = json!((weight - fees::RECORD_WEIGHT).to_string());
        assert!(verify_automatic_fee(&body, &quote, &status, &0u32.into()).is_err());
    }

    #[test]
    fn prepared_notes_warn_about_a_change_due_within_the_lifetime() {
        // Audit F157: the endpoint reports a pending fee-rate increase or
        // capacity decrease; the CLI warns instead of silently signing.
        let change = |parameter: &str, valid: bool| {
            json!({"scheduled_change":{"parameter":parameter,"value":"2","activation_height":11,
                "effective_height":12,"minimum_fee":"3","valid_after":valid}})
        };
        let note = scheduled_change_note(&change("MinimumFeeRate", false)).unwrap();
        assert!(note.contains("3 atoms from block 12"), "{note}");
        let note = scheduled_change_note(&change("BlockBytes", false)).unwrap();
        assert!(note.contains("capacity falls to 2 from block 12"), "{note}");
        assert!(scheduled_change_note(&change("MinimumFeeRate", true)).is_none());
        assert!(scheduled_change_note(&json!({})).is_none());
    }

    #[test]
    fn prepared_notes_warn_when_only_a_remote_endpoint_vouches_for_the_anchor() {
        // A single remote endpoint is trusted for the anchor: remind the user
        // of --anchor-url or a loopback node, and only in that case.
        let body = TransactionBody {
            sender: crypto::public_key(&[7; 32]).unwrap(),
            nonce: 0,
            anchor: [38; 32],
            expiry_blocks: 2,
            fee: 1u32.into(),
            operation: Operation::TransferExact {
                recipient: crypto::public_key(&[6; 32]).unwrap(),
                amount: 1u32.into(),
            },
            data: vec![],
        };
        let notes = |client: &RpcClient, anchor_confirmed| {
            Prepared {
                envelope: wallet::unsigned(&body, &[9; 32]),
                body: body.clone(),
                chain_id: [9; 32],
                anchor_height: 20,
                anchor_confirmed,
                nonce: NonceSource::Requested(0),
                fee: None,
                scheduled_change: None,
            }
            .notes(client)
        };
        let warnings = |notes: Vec<String>| {
            notes
                .into_iter()
                .filter(|note| note.starts_with("warning:") && note.contains("--anchor-url"))
                .collect::<Vec<_>>()
        };
        let remote = RpcClient::new("http://localhost:9/rpc", true).unwrap();
        let local = RpcClient::new("http://127.0.0.1:9/rpc", false).unwrap();
        let reminder = warnings(notes(&remote, false));
        assert_eq!(reminder.len(), 1, "{reminder:?}");
        assert!(reminder[0].contains("loopback node"), "{reminder:?}");
        assert!(warnings(notes(&remote, true)).is_empty());
        assert!(warnings(notes(&local, false)).is_empty());
    }

    #[test]
    fn automatic_support_fee_accepts_record_weight_only_with_its_charge() {
        // Audit F046: a new support record pays record weight; adding to the
        // sender's existing record does not. Only the node knows which.
        let status = json!({"fee_policy":{"minimum_fee_rate":"100"}});
        for record in [0, fees::RECORD_WEIGHT] {
            let mut body = TransactionBody {
                sender: crypto::public_key(&[6; 32]).unwrap(),
                nonce: 0,
                fee: 0u32.into(),
                anchor: [38; 32],
                expiry_blocks: 100,
                data: vec![],
                operation: Operation::Support {
                    round: 0,
                    proposal: [3; 32],
                    amount: 1u32.into(),
                },
            };
            let (weight, minimum) = loop {
                let weight = hashstash::codec::encode(&hashstash::types::Transaction {
                    body: body.clone(),
                    signature: [0; 64],
                })
                .len() as u64
                    + record;
                let minimum = Amount::from((weight * 100).div_ceil(fees::FEE_SCALE));
                if body.fee == minimum {
                    break (weight, minimum);
                }
                body.fee = minimum;
            };
            let charge = if record == 0 { "0" } else { "100" };
            let quote = json!({"minimum_fee_rate":"100","weight":weight.to_string(),"minimum_fee":minimum.to_string(),"account_creation_fee":"0","grant_recipient_fee":"0","record_fee":charge,"extra_fee":"0","fee":body.fee.to_string()});
            verify_automatic_fee(&body, &quote, &status, &0u32.into()).unwrap();
            for (field, value) in [
                ("record_fee", if record == 0 { "100" } else { "0" }),
                ("account_creation_fee", "100"),
            ] {
                let mut altered = quote.clone();
                altered[field] = json!(value);
                assert!(verify_automatic_fee(&body, &altered, &status, &0u32.into()).is_err());
            }
        }
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
        // The easiest target is 256 times the calibrated one, not the preset limit.
        let limit = math::target_from_bits(config.limit_bits).unwrap();
        assert_eq!(limit, &target << 8usize);
        assert!(limit < math::target_from_bits(Config::slow_testnet().limit_bits).unwrap());
        original["initial_bits"] = json!(config.initial_bits);
        original["limit_bits"] = json!(config.limit_bits);
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
        let first = initial_config(InitPreset::Slow, Some("100T"), false, None).unwrap();
        let second = initial_config(InitPreset::Slow, Some("100T"), false, None).unwrap();
        assert!(first.network.starts_with("hashstash-private-"));
        assert_ne!(first.chain_id(), second.chain_id());
        assert_eq!(first.initial.interval, 15);
        assert!(first.genesis_time > 1_770_000_000);
        let ordinary = initial_config(InitPreset::Dev, None, false, None).unwrap();
        assert_eq!(ordinary.initial.interval, 15);
    }

    #[test]
    fn new_genesis_file_never_overwrites_an_existing_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("network.json");
        let original = Config::devnet();
        write_new(&path, &original, false).unwrap();
        let before = fs::read(&path).unwrap();
        let calibrated = initial_config(InitPreset::Slow, Some("100T"), false, None).unwrap();
        assert!(write_new(&path, &calibrated, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn genesis_time_is_selectable_readable_and_checked_against_the_clock() {
        for (seconds, text) in [
            (0, "1970-01-01 00:00:00 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (1_770_000_000, "2026-02-02 02:40:00 UTC"),
            (4_102_444_799, "2099-12-31 23:59:59 UTC"),
            (u64::from(u32::MAX), "2106-02-07 06:28:15 UTC"),
        ] {
            assert_eq!(utc_text(seconds), text);
        }
        // Calibrated, so only the clock can be flagged in every build.
        let pinned =
            initial_config(InitPreset::Dev, Some("100T"), false, Some(1_800_000_000)).unwrap();
        assert_eq!(pinned.genesis_time, 1_800_000_000);
        assert!(initial_config(InitPreset::Dev, None, false, Some(u32::MAX)).is_err());
        let now = 1_800_000_000u64;
        assert!(genesis_warnings(&pinned, now).is_empty());
        assert!(genesis_warnings(&pinned, now - u64::from(pinned.future_seconds)).is_empty());
        let early = genesis_warnings(&pinned, now - u64::from(pinned.future_seconds) - 1);
        assert_eq!(early.len(), 1);
        assert!(early[0].contains("defer block 1"), "{early:?}");
        let stale = genesis_warnings(&Config::devnet(), CLOCK_FLOOR - 1);
        assert!(stale.iter().any(|w| w.contains("earlier than this release")));
    }

    #[test]
    fn init_reports_unsafe_but_valid_genesis_fields_with_its_clock_warnings() {
        let now = 1_800_000_000u64;
        for preset in [InitPreset::Dev, InitPreset::Slow] {
            let c = initial_config(preset, Some("100T"), false, Some(now as u32)).unwrap();
            assert!(config_warnings(&c, now).is_empty());
        }
        // Audit F116/R31: genesis stays representability-only, so a
        // hand-edited value still validates and is only reported.
        // Calibrated, so a build without test fixtures adds no easy-limit warning.
        let mut c = initial_config(InitPreset::Dev, Some("100T"), false, Some(now as u32)).unwrap();
        c.max_signatures = 0;
        c.validate().unwrap();
        let warnings = config_warnings(&c, now - u64::from(c.future_seconds) - 1);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("max_signatures is 0"));
        assert!(warnings[1].contains("defer block 1"));
    }

    #[test]
    fn shared_presets_need_calibration_and_an_easy_limit_is_flagged() {
        let refused = initial_config(InitPreset::Slow, None, false, None).unwrap_err();
        assert!(refused.to_string().contains("--hashrate"), "{refused}");
        let now = 1_800_000_000;
        let flagged = |config: &Config| {
            genesis_warnings(config, now)
                .iter()
                .any(|warning| warning.contains("practically nothing"))
        };
        // Outside fixture builds a preset is a production-denominated network.
        let mut uncalibrated =
            initial_config(InitPreset::Slow, None, true, Some(1_800_000_000)).unwrap();
        uncalibrated.test_work = false;
        assert_eq!(uncalibrated.limit_bits, 0x207fffff);
        assert!(node::easy_proof_of_work(&uncalibrated));
        assert!(flagged(&uncalibrated));
        let warning = proof_of_work_warning(&uncalibrated).unwrap();
        assert!(warning.contains("needs only 2 expected hashes"), "{warning}");
        assert!(warning.contains("init --hashrate 73.4G or more"), "{warning}");
        let mut dev = initial_config(InitPreset::Dev, None, false, Some(1_800_000_000)).unwrap();
        dev.test_work = false;
        assert!(flagged(&dev));
        // Fixture networks need a test build and are never flagged.
        dev.test_work = true;
        assert!(!flagged(&dev));
        let mut calibrated =
            initial_config(InitPreset::Slow, Some("100T"), false, Some(1_800_000_000)).unwrap();
        calibrated.test_work = false;
        assert!(!node::easy_proof_of_work(&calibrated) && !flagged(&calibrated));
        // Calibrating eases the limit 256-fold, so a rate below 2^40 hashes
        // per block (73.3 GH/s at 15 seconds) still leaves it easy, and the
        // warning names the rate that clears it rather than just --hashrate.
        for preset in [InitPreset::Dev, InitPreset::Slow] {
            let mut low = initial_config(preset, Some("73G"), false, Some(1_800_000_000)).unwrap();
            low.test_work = false;
            assert!(flagged(&low));
            let warning = proof_of_work_warning(&low).unwrap();
            assert!(
                warning.contains("needs init --hashrate 73.4G or more at 15-second blocks"),
                "{warning}"
            );
            let mut named =
                initial_config(preset, Some("73.4G"), false, Some(1_800_000_000)).unwrap();
            named.test_work = false;
            assert!(!node::easy_proof_of_work(&named) && !flagged(&named));
        }
        assert_eq!(hashrate_text(73_300_775_186), "73.4G");
        assert_eq!(hashrate_text(100_000_000_000_000), "100T");
        assert_eq!(hashrate_text(1_050), "1.1K");
        assert_eq!(hashrate_text(999), "999");
        // The boundary: a limit just below 2^32 expected hashes is easy.
        let mut boundary = calibrated.clone();
        boundary.limit_bits = math::bits_from_target(&((Amount::one() << 224usize) - 1u32));
        assert!(!node::easy_proof_of_work(&boundary));
        boundary.limit_bits = math::bits_from_target(&(Amount::one() << 225usize));
        assert!(node::easy_proof_of_work(&boundary));
    }

    #[test]
    fn run_refuses_untrusted_peers_on_an_easy_target() {
        let mut easy = Config::slow_testnet();
        easy.test_work = false;
        let loopback: SocketAddr = "127.0.0.1:18481".parse().unwrap();
        let any: SocketAddr = "0.0.0.0:18481".parse().unwrap();
        let lan: SocketAddr = "[fd00::1]:18481".parse().unwrap();
        // Loopback with configured peers only stays a private network.
        assert!(easy_target_exposure(&easy, loopback, false).is_none());
        for (p2p, discovery, how) in [
            (loopback, true, "--peer-discovery"),
            (any, false, "--p2p 0.0.0.0:18481"),
            (lan, false, "--p2p [fd00::1]:18481"),
        ] {
            let exposure = easy_target_exposure(&easy, p2p, discovery).unwrap();
            assert!(exposure.starts_with(how), "{exposure}");
            assert!(exposure.contains("practically nothing"), "{exposure}");
        }
        let mut calibrated = easy.clone();
        calibrate_initial_target(&mut calibrated, "100T").unwrap();
        assert!(easy_target_exposure(&calibrated, any, true).is_none());
        let mut fixture = easy;
        fixture.test_work = true;
        assert!(easy_target_exposure(&fixture, any, true).is_none());
    }

    #[test]
    fn stratum_password_files_follow_the_launcher_token_rule() {
        assert_eq!(stratum_password("token\r\n").unwrap(), "token");
        assert_eq!(stratum_password("a!~Z9").unwrap(), "a!~Z9");
        assert_eq!(stratum_password(&"x".repeat(256)).unwrap().len(), 256);
        for invalid in [
            String::new(),
            "\n".into(),
            "\r\n\r\n".into(),
            " ".into(),
            "two words".into(),
            "tab\there".into(),
            " leading".into(),
            "trailing ".into(),
            "pässword".into(),
            "line\nbreak".into(),
            "x".repeat(257),
        ] {
            assert!(stratum_password(&invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn peer_identity_must_differ_from_server_wallet_accounts() {
        let peer = crypto::public_key(&[3; 32]).unwrap();
        let other = crypto::public_key(&[4; 32]).unwrap();
        check_peer_identity(peer, None, None).unwrap();
        check_peer_identity(peer, Some(other), None).unwrap();
        check_peer_identity(peer, None, Some(other)).unwrap();
        assert!(check_peer_identity(peer, Some(peer), None).is_err());
        assert!(check_peer_identity(peer, None, Some(peer)).is_err());
    }

    #[test]
    fn automatic_peer_identity_is_published_whole_and_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("chain.peer-key.json");
        ensure_peer_key_file(&path).unwrap();
        let first = fs::read(&path).unwrap();
        hashstash::peer_auth::Policy::discovery_from_file(&path, Vec::new()).unwrap();
        ensure_peer_key_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), first);
        // Only the published identity remains; no temporary copy of its secret.
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        // An empty file left by an interrupted earlier start is not an identity.
        fs::write(&path, b"").unwrap();
        ensure_peer_key_file(&path).unwrap();
        let replaced = fs::read(&path).unwrap();
        assert!(!replaced.is_empty() && replaced != first);
        hashstash::peer_auth::Policy::discovery_from_file(&path, Vec::new()).unwrap();
        // Anything else is left for the operator to inspect.
        fs::write(&path, b"{").unwrap();
        ensure_peer_key_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn identity_publication_falls_back_where_hard_links_are_unsupported() {
        let directory = tempfile::tempdir().unwrap();
        let (temporary, path) = (directory.path().join("new.tmp"), directory.path().join("key"));
        type Link = fn(&Path, &Path) -> std::io::Result<()>;
        let unsupported: Link = |_, _| Err(std::io::ErrorKind::Unsupported.into());
        let existing: Link = |_, _| Err(std::io::ErrorKind::AlreadyExists.into());
        fs::write(&temporary, b"whole").unwrap();
        publish_new(&temporary, &path, unsupported).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"whole");
        assert!(!temporary.exists());
        // A file already published is kept, whichever way publication failed.
        for link in [unsupported, existing] {
            fs::write(&temporary, b"other").unwrap();
            publish_new(&temporary, &path, link).unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"whole");
            assert!(!temporary.exists());
        }
    }

    #[test]
    fn key_files_parse_both_formats_and_reject_mismatches() {
        let directory = tempfile::tempdir().unwrap();
        let secret = [19u8; 32];
        let public = crypto::public_key(&secret).unwrap();
        let other = crypto::public_key(&[20; 32]).unwrap();
        let (s, p, o) = (hex::encode(secret), hex::encode(public), hex::encode(other));
        for (name, contents, valid) in [
            ("legacy", json!({"secret":s,"public":p}), true),
            ("bare", json!({"secret":s}), true),
            (
                "export",
                json!({"format":"hashstash-private-v1","private_key":s,"public_key":p,"name":"kept"}),
                true,
            ),
            ("mismatch", json!({"secret":s,"public":o}), false),
            ("format", json!({"format":"other","private_key":s}), false),
            ("field", json!({"format":"hashstash-private-v1","secret":s}), false),
            ("short", json!({"secret":hex::encode([19u8; 31])}), false),
            ("text", json!({"secret":"zz".repeat(32)}), false),
            ("type", json!({"secret":7}), false),
        ] {
            let path = directory.path().join(name);
            fs::write(&path, serde_json::to_vec(&contents).unwrap()).unwrap();
            match key_file(&path) {
                Ok((parsed, key)) => {
                    assert!(valid, "{name}");
                    assert_eq!((*parsed, key), (secret, public));
                }
                Err(_) => assert!(!valid, "{name}"),
            }
        }
    }

    #[test]
    fn pinned_network_is_required_for_remote_endpoints_and_must_match() {
        let (a, b) = ([1; 32], [2; 32]);
        assert_eq!(pinned_network(None, a, true).unwrap(), a);
        assert!(pinned_network(None, a, false).is_err());
        assert_eq!(pinned_network(Some(a), a, false).unwrap(), a);
        assert_eq!(pinned_network(Some(a), a, true).unwrap(), a);
        assert!(pinned_network(Some(b), a, true).is_err());
        assert!(pinned_network(Some(b), a, false).is_err());
    }

    #[test]
    fn review_lines_show_atoms_network_and_abbreviated_data() {
        let chain = [9; 32];
        let recipient = crypto::public_key(&[6; 32]).unwrap();
        let body = TransactionBody {
            sender: crypto::public_key(&[7; 32]).unwrap(),
            nonce: 4,
            anchor: [38; 32],
            expiry_blocks: 25,
            fee: 20u32.into(),
            operation: Operation::TransferExact {
                recipient,
                amount: 5u32.into(),
            },
            data: vec![0xab; 200],
        };
        let lines = review_lines(&body, Some(&chain));
        for expected in [
            "Fee: 20 atoms".to_owned(),
            "Recipient receives: 5 atoms".to_owned(),
            "Total debit: 25 atoms".to_owned(),
            "Nonce: 4".to_owned(),
            format!("Recipient: {}", address::encode(&recipient, &chain).unwrap()),
            format!("Network · signed: {}", hex::encode(chain)),
            "Data bytes: 200".to_owned(),
            format!("Data hex: {}...", "ab".repeat(64)),
        ] {
            assert!(lines.contains(&expected), "{expected} not in {lines:?}");
        }
        assert!(lines.iter().all(|line| !line.contains("HASH")));
    }
}
