//! Cross-language chain-bound signing vector. `tests/data/transaction-signing.json`
//! was built by independent Python code (hashlib and the soak harness's BIP340
//! signer); `scripts/test_soak.py` checks the harness against the same file.
use hashstash::{
    codec, crypto,
    types::{Hash, Operation, Outcome, Transaction, TransactionBody},
};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::Value;

fn field<const N: usize>(vector: &Value, name: &str) -> [u8; N] {
    hex::decode(vector[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn chain_bound_signing_vector_matches_the_node() {
    let vector: Value =
        serde_json::from_str(include_str!("data/transaction-signing.json")).unwrap();
    let secret: [u8; 32] = field(&vector, "secret_key");
    let chain: Hash = field(&vector, "chain_id");
    let message: Hash = field(&vector, "message");
    let signature: [u8; 64] = field(&vector, "signature");
    let raw = hex::decode(vector["body"].as_str().unwrap()).unwrap();
    let body = codec::decode::<TransactionBody>(&raw, raw.len()).unwrap();
    assert_eq!(codec::encode(&body), raw);
    assert_eq!(body.sender, crypto::public_key(&secret).unwrap());
    assert_eq!(
        hex::encode(body.sender),
        vector["public_key"].as_str().unwrap()
    );
    assert!(matches!(
        body.operation,
        Operation::Deposit {
            outcome: Some(Outcome::Pass),
            ..
        }
    ));
    assert_eq!(crypto::signing_message(&chain, &body), message);
    // BIP340 with zero auxiliary randomness is deterministic, so libsecp256k1
    // reproduces the independent signer's bytes exactly.
    let secp = Secp256k1::new();
    let pair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array(secret).unwrap());
    let auxiliary: [u8; 32] = field(&vector, "auxiliary");
    assert_eq!(
        secp.sign_schnorr_with_aux_rand(&message, &pair, &auxiliary)
            .as_ref(),
        &signature
    );
    let tx = Transaction { body, signature };
    crypto::verify(&chain, &tx).unwrap();
    let mut other = chain;
    other[31] ^= 1;
    assert!(crypto::verify(&other, &tx).is_err());
    // The domain the soak harness used before it bound the chain ID.
    let unbound = crypto::tagged_hash("Hashstash/anchor-only-transaction", &raw);
    assert_ne!(unbound, message);
}
