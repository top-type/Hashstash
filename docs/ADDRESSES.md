# Hashstash addresses

Wallets display checksummed addresses for receiving HASH, grant recipients, and watch-only accounts. An address represents a public key on a particular network. Address encoding does not itself change account keys, signed transaction bytes, signatures, or balances.

## Format

Hashstash uses [Bech32m from BIP 350](https://bips.dev/350/). The human-readable prefix is `hsh` followed by the first eight bytes of the chain ID written as sixteen lowercase hexadecimal characters. This is a 64-bit network fingerprint. The data encodes the existing 32-byte BIP340 x-only public key directly, with no witness version or script. The six-character checksum covers both prefix and data. A canonical address is 78 characters.

Encoders produce lowercase. Decoders accept all-uppercase addresses too, reject mixed case, require the exact payload length and canonical zero padding, validate the curve point, and check the expected network prefix. Bech32 checksums are not accepted in place of Bech32m. Input fields may trim surrounding whitespace. Invalid input is rejected rather than corrected automatically.

The checksum detects accidental changes; it does not establish who owns an address. Transactions continue to commit to the complete 32-byte chain ID. Watch-only descriptor files also include that complete ID and validate it independently of the fingerprint.

The current release supports protocol 26. A fresh network has a different chain ID and therefore different addresses, even when using the same private keys. Depositing or withdrawing Stash preserves addresses and account keys.

## Wallet use

Use **Copy address** on Wallet or Payments. Checksummed recipients must match the connected network. Payments, encrypted Mail, grant proposals and Watch account require a checksummed address. Raw public keys remain in private backups and technical interfaces. Explicit imports of public-key descriptor files are converted into addresses for the connected chain.

The offline signer obtains its network from a local configuration, a pasted chain ID, or the public descriptor exported under Explorer → Network → Identity. No node connection is needed. Its transaction review displays sender and recipient addresses derived from the actual signed body. Selecting another network invalidates any previous review.

## Command line

```powershell
# Encode a wallet's public key for this chain.
.\bin\hashstash.exe address --key .\wallet.json --config .\network.json

# Validate an address and print its underlying public key.
.\bin\hashstash.exe decode-address --address '<address>' --config .\network.json

# Export the public network identity for the cold signer.
.\bin\hashstash.exe network --config .\network.json

# Pay or mine to an address.
.\bin\hashstash.exe transfer --key .\wallet.json --recipient '<address>' --amount 10
.\bin\hashstash.exe mine --recipient '<address>' --count 1
```

`address` also accepts `--public-key HEX` instead of `--key`. Both conversion commands accept `--chain-id HEX` instead of `--config`. The convenience transfer command and `send`/`prepare` recipient strings validate against the connected node's chain. Raw hexadecimal keys and byte-array operation fields remain available for existing scripts. `run --miner` and `run --watch-key` accept either a network-matching address or a raw public key.

Read-only RPC `address` takes `{public_key}` and returns its current-network address. `validateaddress` takes `{address}` and strictly validates it against the connected chain. Both return `{address, public_key, address_hrp}`. Session metadata exposes these addresses without revealing private keys.
