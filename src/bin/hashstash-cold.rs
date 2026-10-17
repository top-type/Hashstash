use anyhow::{Context, Result, ensure};
use clap::Parser;
use hashstash::{config::Config, types::Hash};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

#[derive(Parser)]
#[command(
    name = "hashstash-cold",
    version,
    about = "Hashstash offline transaction signer"
)]
struct Options {
    /// Local browser port. Use 0 to choose a free port.
    #[arg(long, default_value_t = 19580)]
    port: u16,
    /// Local genesis configuration used to derive this network's identity.
    #[arg(long, conflicts_with = "chain_id")]
    config: Option<PathBuf>,
    /// Full 32-byte network identity, written as 64 hexadecimal characters.
    #[arg(long)]
    chain_id: Option<String>,
    /// Largest unsigned export accepted for review, in bytes.
    #[arg(long, default_value_t = hashstash::cold::DEFAULT_MAX_REVIEW_REQUEST)]
    max_review_bytes: usize,
    /// Seconds without use after which an open wallet locks itself.
    #[arg(
        long,
        default_value_t = hashstash::cold::DEFAULT_IDLE_LOCK.as_secs(),
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    idle_lock_seconds: u64,
}

/// A launcher that opens the browser itself may choose the session token.
/// The environment, unlike the command line, is readable only by this account.
const TOKEN_VARIABLE: &str = "HASHSTASH_COLD_TOKEN";

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    let chain: Option<Hash> = if let Some(path) = options.config {
        ensure!(
            std::fs::metadata(&path)?.len() <= 128 * 1024,
            "configuration file is too large"
        );
        let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Some(config.chain_id())
    } else if let Some(id) = options.chain_id {
        ensure!(
            id.len() == 64,
            "chain ID must contain 64 hexadecimal characters"
        );
        Some(
            hex::decode(id)?
                .try_into()
                .ok()
                .context("invalid chain ID length")?,
        )
    } else {
        None
    };
    let configured = chain.is_some();
    let token = match std::env::var(TOKEN_VARIABLE) {
        Ok(token) => Some(token),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error).context(TOKEN_VARIABLE),
    };
    let server = hashstash::cold::serve_with_options(
        SocketAddr::from((Ipv4Addr::LOCALHOST, options.port)),
        hashstash::cold::ColdOptions {
            chain_id: chain,
            max_review: options.max_review_bytes,
            token,
            idle_lock: Duration::from_secs(options.idle_lock_seconds),
        },
    )
    .await?;
    // The session token is never served over loopback; only this launch URL
    // carries it to the browser.
    println!("Hashstash cold signer: {}", server.launch_url());
    if !configured {
        println!("No network configured: select it in the signer before reviewing transactions.");
    }
    tokio::signal::ctrl_c().await?;
    server.stop().await;
    Ok(())
}
