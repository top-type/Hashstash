//! Deterministic, isolated browser-review history. Never connects to a peer.
use anyhow::{Context, Result, ensure};
use hashstash::{address, codec, config::Config, crypto, node::Node, state, types::*};
use serde_json::{Value, json};
use std::path::PathBuf;

const OWNER: [u8; 32] = [91; 32];
const RECIPIENT: [u8; 32] = [92; 32];

fn signed(
    node: &Node,
    config: &Config,
    operation: Operation,
    data: Vec<u8>,
    offset: u64,
) -> Result<Transaction> {
    let public = crypto::public_key(&OWNER)?;
    let account = node.rpc("account", json!({"key":hex::encode(public)}))?;
    let nonce = account["account"]["nonce"]
        .as_u64()
        .context("nonce missing")?
        + offset;
    let status = node.status()?;
    let anchor: Hash = hex::decode(status["tip"].as_str().context("tip missing")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid tip hash length"))?;
    let quote = node.rpc("fee_quote", json!({"sender":hex::encode(public), "operation":operation, "data_hex":hex::encode(&data), "extra_fee":"1", "nonce":nonce, "anchor":hex::encode(anchor), "expiry_blocks":2}))?;
    let fee: Amount = quote["fee"].as_str().context("fee missing")?.parse()?;
    crypto::sign(
        &TransactionBody {
            chain_id: config.chain_id(),
            sender: public,
            nonce,
            fee,
            anchor,
            expiry_blocks: 2,
            operation,
            data,
        },
        &OWNER,
    )
}

fn main() -> Result<()> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("output directory required")?,
    );
    ensure!(
        !directory.join("chain.sqlite").exists(),
        "fixture already exists"
    );
    std::fs::create_dir_all(&directory)?;
    let mut config = Config::testnet();
    config.network = "hashstash-isolated-explorer-review".into();
    config.initial_bits = 0x2003ffff;
    config.limit_bits = config.initial_bits;
    config.validate()?;
    std::fs::write(
        directory.join("network.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    let owner = crypto::public_key(&OWNER)?;
    let recipient = crypto::public_key(&RECIPIENT)?;
    let node = Node::open(&directory.join("chain.sqlite"), config.clone(), owner)?;
    for _ in 0..200 {
        if node.status()?["phase"] == "auction" {
            break;
        }
        node.mine(1_000_000)?;
    }
    ensure!(
        node.status()?["phase"] == "auction",
        "initial rest did not finish"
    );
    for _ in 0..5 {
        node.mine(1_000_000)?;
    }
    let transfer = signed(
        &node,
        &config,
        Operation::TransferExact {
            recipient,
            amount: 100u32.into(),
        },
        b"<script>alert('not executable')</script>\0\xff".to_vec(),
        0,
    )?;
    let transfer_id = codec::transaction_id(&transfer);
    node.submit_transaction(transfer)?;
    node.mine(1_000_000)?;
    let status = node.status()?;
    let round = status["auction_round"]
        .as_u64()
        .context("auction round missing")?;
    let old = status["settings"]["lead"]
        .as_u64()
        .context("lead missing")?;
    let action = Proposal::Parameter {
        parameter: Parameter::Lead,
        old,
        new: old * 2,
    };
    let description = [7; 32];
    let proposal = state::proposal_id(&config.chain_id(), round, &description, &action);
    node.submit_transaction(signed(
        &node,
        &config,
        Operation::Propose {
            round,
            description,
            proposal: action,
            support: 10u32.into(),
        },
        Vec::new(),
        0,
    )?)?;
    node.mine(1_000_000)?;
    node.submit_transaction(signed(
        &node,
        &config,
        Operation::Support {
            round,
            proposal,
            amount: 10u32.into(),
        },
        Vec::new(),
        0,
    )?)?;
    node.mine(1_000_000)?;
    for _ in 0..32 {
        if node.status()?["phase"] == "governance" {
            break;
        }
        node.mine(1_000_000)?;
    }
    ensure!(
        node.status()?["phase"] == "governance",
        "governance did not start"
    );
    let gov = node.rpc("governance", json!({}))?;
    let decision: Hash = serde_json::from_value(gov["phase"]["Governance"]["id"].clone())?;
    node.submit_transaction(signed(
        &node,
        &config,
        Operation::Deposit {
            amount: 80u32.into(),
            decision: Some(decision),
            outcome: Some(Outcome::Pass),
        },
        Vec::new(),
        0,
    )?)?;
    node.mine(1_000_000)?;
    for _ in 0..64 {
        if node.status()?["phase"] == "rest" {
            break;
        }
        node.mine(1_000_000)?;
    }
    ensure!(
        node.status()?["phase"] == "rest",
        "governance did not resolve"
    );
    let pending = signed(
        &node,
        &config,
        Operation::TransferExact {
            recipient,
            amount: 5u32.into(),
        },
        Vec::new(),
        0,
    )?;
    let info: Value = json!({
        "isolated":true,"public_experiment_contacted":false,
        "chain_id":hex::encode(config.chain_id()), "height":node.status()?["height"],
        "owner_key":hex::encode(owner),"owner":address::encode(&owner,&config.chain_id())?,
        "recipient":address::encode(&recipient,&config.chain_id())?,
        "transfer":hex::encode(transfer_id),"proposal":hex::encode(proposal),
        "pending_id":hex::encode(codec::transaction_id(&pending)),"pending_raw":hex::encode(codec::encode(&pending)),
    });
    std::fs::write(
        directory.join("fixture.json"),
        serde_json::to_vec_pretty(&info)?,
    )?;
    println!(
        "{}",
        json!({"directory":directory,"height":info["height"],"isolated":true})
    );
    Ok(())
}
