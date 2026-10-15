# Hashstash

Hashstash 0.36.0 implements protocol 26: an account-based SHA256d chain with a dynamic reserve curve, revenue buffer, market-based governance, browser wallets, public transaction text and recipient-hidden encrypted mail. It uses compact binary records, direct transaction data and exact signed fees with a governed minimum rate. The complete genesis configuration identifies the chain.

This is experimental software for development and testing. The security review remains incomplete; the recorded tests do not establish production security or economic stability. Use an isolated network for development and keep private keys and live databases outside the repository.

Mining issues hashes in proportion to each canonical block's expected work. Stash represents shares in the reserve curve. Buying stash moves hashes into reserve and mints shares; selling burns shares and releases hashes along the same curve. One displayed hash equals 10^18 raw hash atoms; one displayed stash equals 10^36 share atoms. RPC and CLI use integer atoms; work and mining speed use EH and EH/s.

Binary amounts contain only their nonzero magnitude bytes and a compact length; zero has an empty payload. Integers and collection lengths use canonical variable-width encoding. Signatures occupy exactly 64 bytes and mining extranonces exactly eight, with no length prefix. Account records contain cash, shares, nonce and epoch; transfer records contain only recipient and amount. The [wire format](docs/CONSENSUS.md) specifies the exact encoding.

## Mining and launch

Timestamp ASERT targets 15 seconds per block initially. Governance can select any changed whole-second interval from 1 through 60. Governance durations and grant budgets use scheduled seconds: each block advances their clock by its parent's target interval. Changing the interval preserves their nominal time scale; actual elapsed time still varies with mining. Transaction expiry, confirmations and timestamp samples remain block counts. Only canonical work creates issuance; losing blocks receive no reward.

Mining creates spendable hashes from the first block. Stash trading is available immediately: a voluntary deposit starts an empty reserve at the fixed share scale and a flat curve. Account balances never convert automatically. The initial rest period delays only the first governance auction. There is no premine.

An optional solo Stratum V1 server supports external SHA256d ASICs, reporting shares, extranonce and BIP310 version rolling. Its configured recipient receives blocks; worker labels do not select payout accounts. Mining settings are node configuration, separate from visitor wallets. The HST6 coinbase commits to transactions and resulting state as one Merkle leaf. See [mining](docs/MINING.md).

## Reserve, revenue and governance

Each transaction signs the exact fee it will pay. The minimum is its weight times the governed minimum rate, rounded up. Creating a payment recipient adds 1,024 weight; a grant proposal prepays 1,024 weight per payout. The rate begins at one raw atom per 1,024 weight and changes only by a successful governance proposal to halve or double it. Block usage does not adjust it. The governed miner percentage splits the entire paid fee, initially 50/50 with waiting revenue.

The non-miner share of fees and winning auction bids supply a waiting revenue buffer. Revenue immediately replenishes a nonflat reserve until its ratio reaches 100%, preserving the marginal price; excess revenue waits. Grants use waiting revenue first, then reserve, reducing the ratio without rewriting stash balances. See [the reserve rules](docs/RESERVE.md).

Decisions create PASS and FAIL states that initially share the same account root. Full account cash and Stash are available in both alternatives automatically. Trades affect the selected side; payments and fees debit both. Payment availability is therefore the smaller cash balance. Full-window price averages and the frozen PASS margin determine the winner, with equal scores selecting FAIL. A grant lists recipients and exact amounts within the ordinary block-byte and block-weight limits. Its combined amount is escrowed on PASS at activation, then all recipients are paid together only if PASS wins. Resolution selects one root; it does not rewrite every account. Approved parameters activate after rest.

## Wallet and public views

The browser Wallet creates/imports keys and adds watch-only accounts. Keys and signing stay in that browser. Storage is unencrypted; keep a private backup before clearing site data. The separate cold signer reviews and signs exports locally. Server wallets remain separate, opt-in operator tools and never populate visitor wallets.

Explorer links blocks, transactions, accounts, governance and network details without requiring a wallet. Chat displays public UTF-8 attached to any transaction; there is no separate message transaction or composer. Mail encrypts a recipient, subject and body inside any transaction's data using ephemeral secp256k1 ECDH, HKDF-SHA256 and AES-256-GCM. Its fixed-size envelopes are discovered locally from a common indexed feed. The public transaction action, publishing account, payment amounts and timing remain visible. Static wallet-key compromise can expose earlier mail; this is not forward-secret messaging.

The optional [mixer](docs/MIXER.md) is a separate trusted custodian service, not a consensus feature. Its operator owns a dedicated signing key and durable private ledger; it does not access visitor keys or node-wallet accounts. Customers make ordinary deposits carrying encrypted payout instructions. The operator learns their address mapping and controls the deposited funds. The service is explicitly configured and started separately, requires mining confirmations and ordinary hash funding. Wallets can prepare a deposit from a reviewed custodian descriptor; no custodian is implicitly trusted.

## Develop and test

Use a Rust toolchain supporting edition 2024 and the dependencies in `Cargo.lock`, a C compiler and linker, Node.js 20.19 or newer, and Python 3.12. PowerShell 7 is needed for the Windows launchers. SQLite and secp256k1 build from bundled sources. Keep the committed lockfiles when reproducing a build.

From the repository root:

```text
cargo build --release --locked --bins
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
node scripts/test_all_frontend.cjs
```

Run the Python suite with the newly built CLI so its compatibility checks are included. On PowerShell:

```powershell
$env:HASHSTASH_TEST_BINARY = (Resolve-Path ./target/release/hashstash.exe).Path
python -B -m unittest discover -s scripts -p 'test_*.py'
```

On Linux or macOS:

```sh
HASHSTASH_TEST_BINARY="$PWD/target/release/hashstash" python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

The committed UI and cryptography bundle are sufficient for normal builds and frontend tests. To regenerate that bundle, follow [the pinned browser build instructions](ui/vendor/README.md). Record compiler and runtime versions with test results when comparing runs. [Validation history](docs/VALIDATION.md) records earlier checks; its counts are not a current-release test guarantee.

## Run an isolated local network

```powershell
cargo build --release --locked --bins
.\Start-Testnet.ps1 -Fresh -NoBrowser
```

The launcher uses current presets, creates a distinct chain identity and records exact owned process identities. It does not enable browser CPU mining. `-SeedWallets` opts into private server wallets for isolated tests. `Stop-Testnet.ps1` stops only verified owned processes and preserves chain data. Consult [the local testnet guide](docs/TESTNET.md) for operating details.

For a direct node, keep private RPC loopback-only and select a mining payout public key. To join a public network, obtain its genesis configuration and a reachable bootstrap endpoint, then enable `--peer-discovery --seed HOST:PORT`. The node creates a dedicated transport identity when none is supplied, authenticates connections, learns other peers and persists reachable endpoints for recovery. Add `--advertise-peer IP:PORT` when your P2P listener is publicly reachable. Mining is optional: `--no-stratum` runs a validating node. The Linux installer is in [deploy/linux](deploy/linux/README.md). Do not expose development mutation RPCs publicly.

Peer synchronization uses bounded binary frames carrying compact block and transaction records. Nodes must use the same protocol and genesis configuration. Discovery exchanges are chain-bound and bounded, exclude private gossip by default, and verify endpoints before relaying them. Explicit identity pins remain enforced; the existing pinned-only mode is available for closed networks. RPC and Stratum use JSON interfaces. See [node operation](docs/RUNNING.md#peers).

## Documentation and scope

- [Protocol specification](docs/SPECIFICATION.md) and [consensus encodings](docs/CONSENSUS.md)
- [Node operation](docs/RUNNING.md), [network limits](docs/NETWORK-HARDENING.md), [mining](docs/MINING.md)
- [Wallets](docs/WALLETS.md), [addresses](docs/ADDRESSES.md), [Reserve and revenue](docs/RESERVE.md), [Explorer](docs/EXPLORER.md)
- [Chat](docs/CHAT.md), [Mail](docs/MAIL.md), [optional mixer](docs/MIXER.md), [faucet](docs/FAUCET.md), [validation](docs/VALIDATION.md), [audit findings](docs/AUDIT.md)

Peer authentication proves transport-key possession and message integrity; it does not encrypt transport or make an unknown peer trustworthy. Discovery bounds storage, source concentration and concurrent dialing, but cannot prevent every partition, compromised peer, distributed denial of service or eclipse. Validation and traffic work are bounded, while live account state, disk history and restart replay still grow. Test results document exercised behavior, not a proof of production security or economic stability.

