#[cfg(not(target_pointer_width = "64"))]
compile_error!(
    "Hashstash requires a 64-bit target for canonical capacity and configuration ranges"
);

pub mod address;
pub mod batch;
pub mod chain;
pub mod chat;
pub mod codec;
pub mod cold;
pub mod config;
pub mod consensus;
pub mod crypto;
pub mod explorer;
pub mod faucet;
pub mod fees;
pub mod mail;
pub mod math;
pub mod network_guard;
pub mod node;
pub mod peer_auth;
pub mod peer_discovery;
pub mod peer_wire;
pub mod proposal_data;
pub mod state;
pub mod tree;
pub mod types;
pub mod wallet;
mod wallet_store;
