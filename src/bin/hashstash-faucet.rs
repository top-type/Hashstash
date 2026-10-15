use anyhow::{Result, ensure};
use clap::Parser;
use hashstash::faucet::{FaucetConfig, serve};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hashstash-faucet",
    version,
    about = "Optional, funded Hashstash test faucet"
)]
struct Options {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    ensure!(
        std::fs::metadata(&options.config)?.len() <= 16_384,
        "faucet configuration is too large"
    );
    let config: FaucetConfig = serde_json::from_slice(&std::fs::read(options.config)?)?;
    let server = serve(config).await?;
    println!("Hashstash faucet: {}", server.address);
    tokio::signal::ctrl_c().await?;
    server.stop().await;
    Ok(())
}
