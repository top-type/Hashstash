use anyhow::{Result, ensure};
use clap::Parser;
use hashstash::faucet::{FaucetConfig, Maintenance, maintain, serve};
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
    /// Print a summary of the faucet ledger and exit.
    #[arg(long, conflicts_with_all = ["accept_spent_nonce", "clamp_future_claims"])]
    inspect: bool,
    /// After review, record that the faucet key spent NONCE and every lower
    /// nonce outside this ledger, then exit. Stop the service first.
    #[arg(long, value_name = "NONCE", conflicts_with = "clamp_future_claims")]
    accept_spent_nonce: Option<u64>,
    /// After verifying the host clock, move claim times recorded in the future
    /// to now, then exit. Stop the service first.
    #[arg(long)]
    clamp_future_claims: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let options = Options::parse();
    ensure!(
        std::fs::metadata(&options.config)?.len() <= 16_384,
        "faucet configuration is too large"
    );
    let config: FaucetConfig = serde_json::from_slice(&std::fs::read(options.config)?)?;
    let maintenance = if options.inspect {
        Some(Maintenance::Inspect)
    } else if let Some(nonce) = options.accept_spent_nonce {
        Some(Maintenance::AcceptSpentNonce(nonce))
    } else if options.clamp_future_claims {
        Some(Maintenance::ClampFutureClaims)
    } else {
        None
    };
    if let Some(action) = maintenance {
        println!("{}", serde_json::to_string_pretty(&maintain(&config, action)?)?);
        return Ok(());
    }
    let server = serve(config).await?;
    println!("Hashstash faucet: {}", server.address);
    tokio::signal::ctrl_c().await?;
    server.stop().await;
    Ok(())
}
