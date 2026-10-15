use anyhow::{Context, Result, ensure};
use clap::Parser;
use hashstash::{config::Config, types::Hash};
use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
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
}

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
    let server = hashstash::cold::serve_with_chain(
        SocketAddr::from((Ipv4Addr::LOCALHOST, options.port)),
        chain,
    )
    .await?;
    println!("Hashstash cold signer: http://{}/", server.address);
    tokio::signal::ctrl_c().await?;
    server.stop().await;
    Ok(())
}
