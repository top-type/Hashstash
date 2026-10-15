//! Network-specific Bech32m account addresses. Consensus still uses 32-byte keys.
use crate::{
    crypto,
    types::{Hash, PublicKey},
};
use anyhow::{Context, Result, ensure};
use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};

pub const ADDRESS_LENGTH: usize = 78;
pub const HRP_LENGTH: usize = 19;

/// A 64-bit fingerprint identifies the chain in the address presentation layer.
pub fn hrp(chain_id: &Hash) -> String {
    format!("hsh{}", hex::encode(&chain_id[..8]))
}

pub fn encode(public: &PublicKey, chain_id: &Hash) -> Result<String> {
    ensure!(crypto::valid_key(public), "invalid BIP340 public key");
    Ok(bech32::encode::<Bech32m>(
        Hrp::parse(&hrp(chain_id))?,
        public,
    )?)
}

pub fn decode(value: &str, chain_id: &Hash) -> Result<PublicKey> {
    let (prefix, public) = decode_any(value)?;
    ensure!(
        prefix == hrp(chain_id),
        "address belongs to another network"
    );
    Ok(public)
}

/// Validate an address without asserting which network it belongs to.
/// Callers authorizing a transaction must use `decode` with its chain identity.
pub fn decode_any(value: &str) -> Result<(String, PublicKey)> {
    ensure!(
        value.len() == ADDRESS_LENGTH,
        "Hashstash address must contain 78 characters"
    );
    let checked = CheckedHrpstring::new::<Bech32m>(value).context("invalid Bech32m address")?;
    let prefix = checked.hrp().to_string().to_ascii_lowercase();
    ensure!(
        prefix.len() == HRP_LENGTH
            && prefix.starts_with("hsh")
            && prefix.as_bytes()[3..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "invalid Hashstash address prefix"
    );
    let bytes: Vec<u8> = checked.byte_iter().collect();
    let public: PublicKey = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("address must encode a 32-byte public key"))?;
    ensure!(
        crypto::valid_key(&public),
        "invalid BIP340 public key in address"
    );
    // byte_iter discards leftover bits. A canonical re-encoding also checks that
    // all four padding bits are zero, without accepting a second spelling.
    let canonical = bech32::encode::<Bech32m>(Hrp::parse(&prefix)?, &public)?;
    ensure!(
        canonical == value.to_ascii_lowercase(),
        "noncanonical address padding"
    );
    Ok((prefix, public))
}
