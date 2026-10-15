//! Cryptographic authorization. Hash arrays always contain raw digest bytes.
use crate::{
    codec,
    types::{Hash, PublicKey, Transaction, TransactionBody},
};
use anyhow::{Result, ensure};
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};

pub const TRANSACTION_TAG: &str = "Hashstash/anchored-transaction";

pub fn sha256d(bytes: &[u8]) -> Hash {
    Sha256::digest(Sha256::digest(bytes)).into()
}

/// BIP340's tagged SHA256 construction; this is a single SHA256, not SHA256d.
pub fn tagged_hash(tag: &str, bytes: &[u8]) -> Hash {
    let tag_digest = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_digest);
    h.update(tag_digest);
    h.update(bytes);
    h.finalize().into()
}

pub fn valid_key(key: &PublicKey) -> bool {
    XOnlyPublicKey::from_byte_array(*key).is_ok()
}

pub fn public_key(secret: &[u8; 32]) -> Result<PublicKey> {
    let key = SecretKey::from_byte_array(*secret)?;
    let pair = Keypair::from_secret_key(&Secp256k1::new(), &key);
    Ok(pair.x_only_public_key().0.serialize())
}

pub fn sign(body: &TransactionBody, secret: &[u8; 32]) -> Result<Transaction> {
    ensure!(
        body.sender == public_key(secret)?,
        "secret does not authorize the sender"
    );
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(*secret)?);
    let message = tagged_hash(TRANSACTION_TAG, &codec::encode(body));
    // Fresh BIP340 auxiliary randomness hardens nonce generation against side channels.
    let mut auxiliary = [0u8; 32];
    getrandom::fill(&mut auxiliary).map_err(|e| anyhow::anyhow!("OS randomness: {e}"))?;
    let signature = secp.sign_schnorr_with_aux_rand(&message, &pair, &auxiliary);
    Ok(Transaction {
        body: body.clone(),
        signature: *signature.as_ref(),
    })
}

pub fn verify(tx: &Transaction) -> Result<()> {
    let key = XOnlyPublicKey::from_byte_array(tx.body.sender)?;
    let signature = Signature::from_byte_array(tx.signature);
    let message = tagged_hash(TRANSACTION_TAG, &codec::encode(&tx.body));
    Secp256k1::verification_only().verify_schnorr(&signature, &message, &key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Operation;

    #[test]
    fn official_bip340_vectors() {
        let secp = Secp256k1::new();
        let mut count = 0;
        for line in include_str!("../tests/data/bip340.csv").lines().skip(1) {
            if line.trim().is_empty() {
                continue;
            }
            let row: Vec<_> = line.split(',').collect();
            let key: [u8; 32] = hex::decode(row[2]).unwrap().try_into().unwrap();
            let message = hex::decode(row[4]).unwrap();
            let signature: [u8; 64] = hex::decode(row[5]).unwrap().try_into().unwrap();
            let verified = XOnlyPublicKey::from_byte_array(key).ok().is_some_and(|pk| {
                secp.verify_schnorr(&Signature::from_byte_array(signature), &message, &pk)
                    .is_ok()
            });
            assert_eq!(verified, row[6] == "TRUE", "BIP340 vector {}", row[0]);
            if !row[1].is_empty() {
                let secret: [u8; 32] = hex::decode(row[1]).unwrap().try_into().unwrap();
                let aux: [u8; 32] = hex::decode(row[3]).unwrap().try_into().unwrap();
                assert_eq!(public_key(&secret).unwrap(), key);
                let pair =
                    Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(secret).unwrap());
                let got = secp.sign_schnorr_with_aux_rand(&message, &pair, &aux);
                assert_eq!(
                    got.as_ref(),
                    signature.as_slice(),
                    "BIP340 signature {}",
                    row[0]
                );
            }
            count += 1;
        }
        assert!(count >= 19);
    }

    #[test]
    fn authorization_binds_every_transaction_field() {
        let key = [1u8; 32];
        let body = TransactionBody {
            data: Vec::new(),
            chain_id: [7; 32],
            sender: public_key(&key).unwrap(),
            nonce: 4,
            fee: 1u32.into(),
            anchor: [0; 32],
            expiry_blocks: 100,
            operation: Operation::TransferExact {
                recipient: public_key(&[2; 32]).unwrap(),
                amount: 2u32.into(),
            },
        };
        let signed = sign(&body, &key).unwrap();
        verify(&signed).unwrap();
        let mut changed = signed.clone();
        changed.body.chain_id[0] ^= 1;
        assert!(verify(&changed).is_err());
        changed = signed.clone();
        changed.body.nonce += 1;
        assert!(verify(&changed).is_err());
        changed = signed.clone();
        changed.body.fee += 1u32;
        assert!(verify(&changed).is_err());
        changed = signed.clone();
        changed.body.expiry_blocks += 1;
        assert!(verify(&changed).is_err());
        changed = signed.clone();
        changed.body.anchor[0] ^= 1;
        assert!(verify(&changed).is_err());
        changed = signed.clone();
        changed.signature[63] ^= 1;
        assert!(verify(&changed).is_err());
        assert!(sign(&body, &[2; 32]).is_err());
    }
    #[test]
    fn anchored_transactions_use_a_distinct_signing_domain() {
        let secret = [1; 32];
        let body = TransactionBody {
            chain_id: [1; 32],
            sender: public_key(&secret).unwrap(),
            nonce: 0,
            fee: 1u32.into(),
            anchor: [3; 32],
            expiry_blocks: 2,
            operation: Operation::TransferExact {
                recipient: public_key(&secret).unwrap(),
                amount: 1u32.into(),
            },
            data: vec![],
        };
        let secp = Secp256k1::new();
        let pair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(secret).unwrap());
        let former_digest = tagged_hash("Hashstash/Transaction", &codec::encode(&body));
        let signature = secp.sign_schnorr_with_aux_rand(&former_digest, &pair, &[0; 32]);
        let former_domain = Transaction {
            body: body.clone(),
            signature: *signature.as_ref(),
        };
        assert!(verify(&former_domain).is_err());
        verify(&sign(&body, &secret).unwrap()).unwrap();
    }
}
