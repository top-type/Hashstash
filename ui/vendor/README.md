# Browser cryptography

`noble.js` is bundled locally from exact npm releases `@noble/curves` 2.4.0 and
`@noble/hashes` 2.4.0, using esbuild 0.28.2. No CDN, runtime downloads or external
scripts are used. It exposes secp256k1 BIP340 Schnorr signing/verification,
key validation, SHA256 and x-only ECDH for encrypted mail. Both libraries use the MIT license; copies are here.

Sources: https://github.com/paulmillr/noble-curves and
https://github.com/paulmillr/noble-hashes. Registry package integrity hashes are
locked in `scripts/browser-crypto/pnpm-lock.yaml`. `noble.sha256` identifies the
committed generated asset, but the build rewrites it, so it is not a check on
its own. `scripts/test_vendor_integrity.cjs` (part of the frontend suite) pins
the reviewed SHA-256 of `noble.js` separately from the build output; any change
to the bundle must also change that pin in review.

Rebuild with Node.js and pnpm: in `scripts/browser-crypto`, run
`pnpm install --frozen-lockfile`, then `pnpm build`. `pnpm run check` rebuilds
into a temporary directory and fails unless every committed vendor file matches
the clean build byte for byte. Run
`node scripts/test_browser_wallet.cjs` from the repository root for official
BIP340 vectors, Rust transaction/address vectors and wallet isolation checks.

Private keys belong to this browser profile and origin, stored in localStorage.
They never enter node requests. Browser storage is not a backup: export the
private key before clearing site data, changing profiles or moving endpoints.
This hot wallet trusts the served page code and other code executing on the same
origin; HTTPS protects delivery in transit, not a compromised host. Watch-only
and offline signing remain available. Passphrase import names its scheme:
`hashstash-passphrase-v2` stretches the phrase with scrypt (implemented in
`browser-wallet.js` on this SHA256) salted by the chain ID; the unstretched
`hashstash-passphrase-v1` remains for restoring legacy accounts only.
