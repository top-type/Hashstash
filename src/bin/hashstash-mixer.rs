use anyhow::Result;
use clap::{Parser, Subcommand};
use hashstash::mixer::{Mixer, MixerConfig, describe, init_key};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hashstash-mixer",
    version,
    about = "Optional trusted custodian for fixed-denomination payments"
)]
struct Options {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Validate public configuration without reading keys or opening a ledger.
    CheckConfig {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a new isolated signer. Never replaces an existing key.
    InitKey {
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        chain_id: String,
    },
    /// Print public terms and their canonical identifier, never private material.
    Describe {
        #[arg(long)]
        config: PathBuf,
    },
    /// Observe by default; --execute explicitly enables signed payouts/refunds.
    Run {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        once: bool,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    match Options::parse().command {
        Command::CheckConfig { config } => {
            MixerConfig::read(&config)?;
            println!("{{\"valid\":true}}");
        }
        Command::InitKey { key_file, chain_id } => println!(
            "{}",
            serde_json::to_string(&init_key(&key_file, &chain_id)?)?
        ),
        Command::Describe { config } => println!(
            "{}",
            serde_json::to_string(&describe(&MixerConfig::read(&config)?)?)?
        ),
        Command::Run {
            config,
            execute,
            once,
        } => {
            Mixer::open(MixerConfig::read(&config)?, execute)?
                .run(once)
                .await?
        }
    }
    Ok(())
}
