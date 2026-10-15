import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
export { schnorr, sha256 };
export const validSecret = bytes => secp256k1.utils.isValidSecretKey(bytes);
export const validPublic = bytes => {
  try { schnorr.utils.lift_x(BigInt('0x' + Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''))); return bytes.length === 32; }
  catch { return false; }
};
// BIP340 identities use the even-Y representative. Normalize the secret and
// lift the peer with prefix 02 before ECDH; return only the shared x-coordinate.
export const ecdhXOnly = (secret, publicKey) => {
  if (!validSecret(secret) || !validPublic(publicKey)) throw new Error('Invalid messaging key.');
  const normalized = Uint8Array.from(secret);
  let shared;
  try {
    if (secp256k1.getPublicKey(normalized)[0] === 3) {
      const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      let scalar = order - BigInt('0x' + Array.from(normalized,b=>b.toString(16).padStart(2,'0')).join(''));
      for (let i=31;i>=0;i--) { normalized[i]=Number(scalar&255n); scalar>>=8n; }
    }
    const peer = new Uint8Array(33); peer[0]=2; peer.set(publicKey,1);
    shared = secp256k1.getSharedSecret(normalized,peer,true);
    return shared.slice(1);
  } finally { normalized.fill(0); shared?.fill(0); }
};
