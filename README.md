# Hashstash

Hashstash is a proof-of-work blockchain with two kinds of holdings: **hashes**, which you can spend, and **stash**, which you obtain by depositing hashes into a shared reserve. Its governance system uses trading in two possible outcomes—PASS and FAIL—to decide grants and changes to network settings.

This repository contains the node, browser wallet, explorer, messaging tools and optional faucet and mixer services. The current version is **0.36.0**, implementing protocol **26**. It is experimental software; its security and economic design have not received a complete independent audit.

## How it works

### Mining creates hashes

Miners compete to find valid SHA256d proofs of work. Nodes check the blocks and follow the valid chain with the most accumulated work. Each block creates hashes in proportion to the expected work required by its difficulty: one exahash of expected work creates one hash. This measures the work implied by the target, rather than a miner's unobservable number of attempts.

Hashes pay for transfers, Stash deposits, proposal bids and transaction fees. A wallet holds the private key that authorizes spending; the blockchain records the account's balances. The network starts with zero issued hashes.

### Stash draws its value from a reserve

Depositing hashes adds them to the shared reserve and creates stash for the depositor. Withdrawing burns stash and returns hashes from that reserve. The conversion follows a mathematical curve, and the wallet quotes the amount you will receive before you sign. Stash stays in its owner's account; payments use hashes.

The curve starts at a fixed exchange rate. When governance draws a grant from the reserve, the curve becomes more sensitive to trading: deposits raise its price and withdrawals lower it. Grant funding leaves the current quoted price and everyone's stash quantities unchanged, but reduces the hashes available to back withdrawals. A displayed stash value is therefore an estimate at the current price; the amount received from a withdrawal depends on its size and fees.

### Revenue replenishes the reserve and funds grants

Transaction fees are divided between the block's miner and network revenue. Winning proposal bids also become revenue. Revenue replenishes a reserve that has funded grants, gradually returning its curve to a fixed exchange rate. Once that reserve is replenished, further revenue waits in a separate balance.

A grant proposes payments to specified accounts. It uses waiting revenue first, then draws any shortfall from the reserve, subject to the network's funding rules. Recipients receive the payments if the proposal passes.

### Governance compares two possible outcomes

A proposal can request a grant or change one network setting. An auction selects which proposal goes to a decision: the proposal with the highest total bid must hold the lead for the required period. The winning bids become revenue. Contributors to losing proposals can reclaim their bids.

During the decision, the chain maintains two versions of its balances and reserve:

- **PASS** represents approval. For a grant, this version sets aside the proposed payments.
- **FAIL** represents rejection and keeps those funds.

Each account starts with its full holdings in both versions. You can trade stash separately in each outcome. Ordinary payments and fees apply to both, so you must have enough hashes in each. These are alternative futures: when the decision ends, one becomes the continuing state and the other is discarded.

The network compares the average stash price across the full decision period. PASS must exceed FAIL by the configured margin; a tie means FAIL. A passing grant pays its recipients at settlement. A passing setting change takes effect after the following rest period. The price comparison is the decision rule, not proof that a proposal is beneficial.

Governance timing uses a clock advanced by each block's target interval. Actual waiting time depends on mining. The [protocol specification](docs/SPECIFICATION.md) lists the settings, permitted ranges, funding rules and exact settlement calculation.

## Using Hashstash

The browser **Wallet** creates or imports keys, displays balances and signs transactions locally. Back up its keys: browser storage is unencrypted and clearing site data can erase them. A separate cold signer can review and sign exported transactions offline.

**Stash** quotes deposits and withdrawals. **Governance** shows proposals and outcome markets. The **Explorer** provides blocks, transactions, accounts and network details without requiring a wallet.

**Chat** displays public text attached to transactions. **Mail** encrypts messages inside transaction data; the underlying transactions remain public, and compromise of a wallet key can expose past mail. The optional faucet distributes an operator's funds. The optional mixer holds deposits in the custody of its operator, who controls those funds and can see their deposit-to-payout mapping.

## Build and run

Use a Rust toolchain supporting edition 2024, a C compiler and linker, Node.js 20.19 or newer, and Python 3.12. Windows launchers require PowerShell 7. Keep the committed lockfiles when building.

```text
cargo build --release --locked --bins
```

To start an isolated local network on Windows:

```powershell
.\Start-Testnet.ps1 -Fresh -NoBrowser
```

The launcher creates a network configuration and records the processes it owns. `Stop-Testnet.ps1` stops those processes and preserves their data. See [local networks](docs/TESTNET.md) for mining and test-wallet options.

To join an existing network, obtain its exact genesis configuration and a reachable seed from its operators. Follow [node operation](docs/RUNNING.md#joining-a-public-network) or the [Linux deployment guide](deploy/linux/README.md). Keep private keys, live databases and service credentials outside this repository.

## Develop and test

```text
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
node scripts/test_all_frontend.cjs
```

Run the Python tests with a freshly built CLI. On PowerShell:

```powershell
$env:HASHSTASH_TEST_BINARY = (Resolve-Path ./target/release/hashstash.exe).Path
python -B -m unittest discover -s scripts -p 'test_*.py'
```

On Linux or macOS:

```sh
HASHSTASH_TEST_BINARY="$PWD/target/release/hashstash" python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

The committed browser bundle supports normal builds and frontend tests. See [browser build instructions](ui/vendor/README.md) to regenerate it, and [validation](docs/VALIDATION.md) for test coverage and limits.

## Reference

- [Protocol specification](docs/SPECIFICATION.md), [consensus encoding](docs/CONSENSUS.md), [reserve mathematics](docs/RESERVE.md)
- [Node operation](docs/RUNNING.md), [mining](docs/MINING.md), [network controls](docs/NETWORK-HARDENING.md)
- [Wallets](docs/WALLETS.md), [addresses](docs/ADDRESSES.md), [explorer](docs/EXPLORER.md)
- [Chat](docs/CHAT.md), [Mail](docs/MAIL.md), [faucet](docs/FAUCET.md), [mixer](docs/MIXER.md)
- [Validation](docs/VALIDATION.md), [security review](docs/AUDIT.md)
