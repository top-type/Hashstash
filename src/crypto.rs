//! Cryptographic authorization. Hash arrays always contain raw digest bytes.
use crate::{
    codec,
    types::{Hash, PublicKey, Transaction, TransactionBody},
};
use anyhow::{Context, Result, ensure};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const TRANSACTION_TAG: &str = "Hashstash/anchor-only-transaction";

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

/// HMAC-SHA256 (RFC 2104) of the concatenated `parts`. Key-derived pads are
/// wiped; the hash engine's internal state is not.
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Hash {
    let mut block = Zeroizing::new([0u8; 64]);
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut pad = Zeroizing::new([0u8; 64]);
    pad.iter_mut().zip(block.iter()).for_each(|(p, k)| *p = k ^ 0x36);
    let mut inner = Sha256::new();
    inner.update(pad.as_slice());
    parts.iter().for_each(|part| inner.update(part));
    let inner = Zeroizing::new(<[u8; 32]>::from(inner.finalize()));
    pad.iter_mut().zip(block.iter()).for_each(|(p, k)| *p = k ^ 0x5c);
    let mut outer = Sha256::new();
    outer.update(pad.as_slice());
    outer.update(inner.as_slice());
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) filling `out`.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) -> Result<()> {
    ensure!(iterations > 0, "PBKDF2 needs at least one iteration");
    for (index, chunk) in out.chunks_mut(32).enumerate() {
        let block = u32::try_from(index + 1)
            .context("PBKDF2 output is too long")?
            .to_be_bytes();
        let mut u = Zeroizing::new(hmac_sha256(password, &[salt, &block]));
        let mut t = Zeroizing::new(*u);
        for _ in 1..iterations {
            let next = hmac_sha256(password, &[u.as_slice()]);
            *u = next;
            t.iter_mut().zip(u.iter()).for_each(|(t, u)| *t ^= u);
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    Ok(())
}

/// The Salsa20/8 core of RFC 7914 section 3, applied in place.
fn salsa20_8(block: &mut [u32; 16]) {
    let mut x = *block;
    let mut step = |a: usize, b: usize, c: usize, shift: u32| {
        x[a] ^= x[b].wrapping_add(x[c]).rotate_left(shift);
    };
    for _ in 0..4 {
        for [a, b, c, d] in [[0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11]] {
            step(b, a, d, 7);
            step(c, b, a, 9);
            step(d, c, b, 13);
            step(a, d, c, 18);
        }
        for [a, b, c, d] in [[0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]] {
            step(b, a, d, 7);
            step(c, b, a, 9);
            step(d, c, b, 13);
            step(a, d, c, 18);
        }
    }
    block
        .iter_mut()
        .zip(x.iter())
        .for_each(|(b, x)| *b = b.wrapping_add(*x));
    x.zeroize();
}

/// scryptBlockMix of RFC 7914 section 4 over 2r 64-byte words.
fn block_mix(input: &[u32], output: &mut [u32], r: usize) {
    let mut t = [0u32; 16];
    t.copy_from_slice(&input[(2 * r - 1) * 16..]);
    for i in 0..2 * r {
        t.iter_mut()
            .zip(&input[i * 16..(i + 1) * 16])
            .for_each(|(t, x)| *t ^= x);
        salsa20_8(&mut t);
        let at = if i % 2 == 0 { i / 2 } else { r + i / 2 } * 16;
        output[at..at + 16].copy_from_slice(&t);
    }
    t.zeroize();
}

/// scrypt (RFC 7914) with N = 2^log_n, filling `out`. Memory use is
/// 128 * r * N bytes; every intermediate buffer is wiped before returning.
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<()> {
    ensure!(
        (1..=31).contains(&log_n) && r > 0 && p > 0 && u64::from(r) * u64::from(p) < 1 << 30,
        "invalid scrypt parameters"
    );
    let n = 1usize << log_n;
    let r = usize::try_from(r)?;
    let words = r.checked_mul(32).context("scrypt block is too large")?;
    let block_bytes = words.checked_mul(4).context("scrypt block is too large")?;
    let mut b = Zeroizing::new(vec![
        0u8;
        block_bytes
            .checked_mul(usize::try_from(p)?)
            .context("scrypt state is too large")?
    ]);
    pbkdf2_sha256(password, salt, 1, &mut b)?;
    let mut v = Zeroizing::new(Vec::new());
    let v_words = words.checked_mul(n).context("scrypt memory is too large")?;
    v.try_reserve_exact(v_words)
        .context("scrypt memory is unavailable")?;
    v.resize(v_words, 0u32);
    let mut x = Zeroizing::new(vec![0u32; words]);
    let mut y = Zeroizing::new(vec![0u32; words]);
    for chunk in b.chunks_exact_mut(block_bytes) {
        for (word, bytes) in x.iter_mut().zip(chunk.chunks_exact(4)) {
            *word = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
        }
        for i in 0..n {
            v[i * words..(i + 1) * words].copy_from_slice(&x);
            block_mix(&x, &mut y, r);
            std::mem::swap(&mut *x, &mut *y);
        }
        for _ in 0..n {
            // Integerify: the low word of the last 64-byte block; N is at most 2^31.
            let j = x[(2 * r - 1) * 16] as usize & (n - 1);
            x.iter_mut()
                .zip(&v[j * words..(j + 1) * words])
                .for_each(|(x, v)| *x ^= v);
            block_mix(&x, &mut y, r);
            std::mem::swap(&mut *x, &mut *y);
        }
        for (bytes, word) in chunk.chunks_exact_mut(4).zip(x.iter()) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }
    pbkdf2_sha256(password, &b, 1, out)
}

pub fn valid_key(key: &PublicKey) -> bool {
    XOnlyPublicKey::from_byte_array(*key).is_ok()
}

/// Library key objects are erased after use; the secp256k1 crate cannot
/// guarantee that no other copy remains (see `non_secure_erase`).
pub fn public_key(secret: &[u8; 32]) -> Result<PublicKey> {
    let mut pair = Keypair::from_seckey_byte_array(&Secp256k1::new(), *secret)?;
    let public = pair.x_only_public_key().0.serialize();
    pair.non_secure_erase();
    Ok(public)
}

pub fn sign(body: &TransactionBody, secret: &[u8; 32]) -> Result<Transaction> {
    ensure!(
        body.sender == public_key(secret)?,
        "secret does not authorize the sender"
    );
    let secp = Secp256k1::new();
    let mut pair = Keypair::from_seckey_byte_array(&secp, *secret)?;
    let message = tagged_hash(TRANSACTION_TAG, &codec::encode(body));
    // Fresh BIP340 auxiliary randomness hardens nonce generation against side channels.
    let mut auxiliary = Zeroizing::new([0u8; 32]);
    let random = getrandom::fill(auxiliary.as_mut());
    let signature = random.map(|()| secp.sign_schnorr_with_aux_rand(&message, &pair, &auxiliary));
    pair.non_secure_erase();
    let signature = signature.map_err(|e| anyhow::anyhow!("OS randomness: {e}"))?;
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
    use secp256k1::SecretKey;

    // Expected values: RFC 4231 (HMAC), RFC 7914 sections 11-12 (PBKDF2 and
    // scrypt), cross-checked with Node.js/OpenSSL; not produced by this code.
    #[test]
    fn hmac_pbkdf2_and_scrypt_match_published_vectors() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], &[b"Hi ", b"There"])),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex::encode(hmac_sha256(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        let mut out = [0u8; 64];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out).unwrap();
        assert_eq!(
            hex::encode(out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        pbkdf2_sha256(b"Password", b"NaCl", 80_000, &mut out).unwrap();
        assert_eq!(
            hex::encode(out),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
        );
        for (password, salt, log_n, r, p, expected) in [
            (
                &b""[..],
                &b""[..],
                4,
                1,
                1,
                "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
            ),
            (
                &b"password"[..],
                &b"NaCl"[..],
                10,
                8,
                16,
                "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
            ),
            (
                &b"pleaseletmein"[..],
                &b"SodiumChloride"[..],
                14,
                8,
                1,
                "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887",
            ),
        ] {
            scrypt(password, salt, log_n, r, p, &mut out).unwrap();
            assert_eq!(hex::encode(out), expected, "scrypt N=2^{log_n} r={r} p={p}");
        }
        for (log_n, r, p) in [(0, 8, 1), (32, 8, 1), (4, 0, 1), (4, 1, 0), (4, 1 << 15, 1 << 15)] {
            assert!(scrypt(b"x", b"y", log_n, r, p, &mut out).is_err());
        }
        assert!(pbkdf2_sha256(b"x", b"y", 0, &mut out).is_err());
    }

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
        changed.body.sender[0] ^= 1;
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
        for tag in ["Hashstash/Transaction", "Hashstash/anchored-transaction"] {
            let former_digest = tagged_hash(tag, &codec::encode(&body));
            let signature = secp.sign_schnorr_with_aux_rand(&former_digest, &pair, &[0; 32]);
            let former_domain = Transaction {
                body: body.clone(),
                signature: *signature.as_ref(),
            };
            assert!(
                verify(&former_domain).is_err(),
                "accepted former domain {tag}"
            );
        }
        verify(&sign(&body, &secret).unwrap()).unwrap();
    }
}
