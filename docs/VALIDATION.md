# Validation guide

Run checks from the repository root using the source and lockfiles you intend to ship. Record the commit, operating system, compiler versions, commands, failures and skips with the results. A passing run applies to that build and platform; it does not establish results for another release or deployment.

## Build and core checks

Install the [build prerequisites](../README.md) first. The Rust build needs a C compiler and linker compatible with the selected Rust target. Windows GNU builds need the matching MinGW tools on `PATH`; MSVC builds need the Visual C++ build tools.

```text
cargo build --release --locked --bins
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
node scripts/test_all_frontend.cjs
```

The Rust command runs library, binary and integration tests. Some tests launch temporary local nodes or exercise large grant lists and can take several minutes. Keep the complete output: a total from one test executable is not the total for the all-target run.

The frontend runner discovers the maintained JavaScript suites and fails if its suite list is incomplete. It covers address and amount handling, signing, transaction review, wallet state, governance views, fees, quote refreshes, Explorer, Chat, Mail and faucet interfaces. Browser mocks and cryptographic fixtures exercise logic; they do not replace a manual browser check of layout and interaction.

## Python checks

Point `HASHSTASH_TEST_BINARY` at the executable just built. Without it, the installed-CLI compatibility test skips rather than validating that interface.

PowerShell:

```powershell
$env:HASHSTASH_TEST_BINARY = (Resolve-Path .\target\release\hashstash.exe).Path
python -B -m unittest discover -s scripts -p 'test_*.py'
```

Bash:

```bash
HASHSTASH_TEST_BINARY="$PWD/target/release/hashstash" \
  python3 -B -m unittest discover -s scripts -p 'test_*.py'
```

Discovery runs the Python unit tests, including activity planning, custody and retry rules, campaign completion checks, and rental-monitor parsing. Several `test_*.py` files are standalone integration programs rather than unittest suites; discovery alone does not run their scenarios.

## What the regression tests cover

| Area | Representative tests |
| --- | --- |
| Issuance, canonical work and timestamp difficulty | [canonical work](../tests/canonical_work.rs), [timestamp DAA](../tests/timestamp_daa.rs), [reorganization](../tests/reorg_stress.rs) |
| Simultaneous clearing, proportional refunds and exact price bounds | [batch clearing](../tests/batch_clearing.rs), [consensus permutations and leading blocks](../tests/batch_consensus.rs) |
| Reserve trades, integer rounding and revenue | [dynamic curve](../tests/dynamic_curve.rs), [revenue buffer](../tests/revenue_buffer.rs), [empty genesis](../tests/open_genesis.rs) |
| Grant funding, outcome selection and atomic payouts | [multiple recipients](../tests/multi_grants.rs), [half-reserve grant](../tests/half_reserve_grant.rs), [automatic outcomes](../tests/automatic_outcomes.rs) |
| Governed settings, exact fees and capacity | [parameters](../tests/governance_parameters.rs), [fees](../tests/exact_fees.rs), [total fee allocation](../tests/governed_total_fees.rs), [block selection](../tests/selection_budget.rs), [capacity changes and transport](../tests/open_governance_transport.rs) |
| Canonical encoding and signing | [codec vectors](../tests/codec_vectors.rs), [browser vectors](../tests/browser_wallet_vectors.rs), [cold wallet](../tests/cold_wallet.rs), [wallet formats](../tests/wallet_formats.rs) |
| Peer authentication, discovery and hostile input | [authenticated transport](../tests/peer_transport_authenticated.rs), [discovery](../tests/peer_discovery.rs), [hostile network input](../tests/network_hostile.rs) |
| Mining protocol and share accounting | [Stratum shares](../tests/stratum_shares.rs), [adversarial mining](../tests/mining_adversarial.rs) |
| Explorer, public RPC and application data | [snapshot history](../tests/snapshot_history.rs), [public web](../tests/public_web.rs), [Chat RPC](../tests/explorer_chat_rpc.rs), [Mail index](../tests/explorer_mail.rs) |
| Controller signing boundaries and campaign decisions | [controller tests](../scripts/test_chain_activity.py), [planning tests](../scripts/test_activity_plan.py), [campaign tests](../scripts/test_pass_campaign.py) |

The frontend checks include direct proposals for all nine settings, exact u64 values above JavaScript’s safe-integer range, zero minimum fees, exact offline review, and complete transaction/message records larger than 32 MiB. Capacity checks separately cover current block weight and representation limits; they do not assert that every valid record fits every transport interface.

The executable tests and their assertions define the coverage. Public fixture keys are deterministic test inputs and must never hold real funds. Test vectors prove agreement on specific inputs; they do not by themselves establish interoperability with every external implementation.

## Isolated process and network scenarios

The [local testnet guide](TESTNET.md) describes creating a disposable three-node network with its own configuration, databases, keys and ports. Use the manifest from that fixture for scripts that accept a manifest. These scripts deliberately submit transactions, mine easy-target blocks or create competing branches; never point them at a live chain.

| Program | Purpose and required inputs |
| --- | --- |
| [test_network.py](../scripts/test_network.py) | End-to-end transactions, governance, relay and reorganization; takes a fixture manifest and an optional report path |
| [test_reserve_network.py](../scripts/test_reserve_network.py) | Reserve, revenue and grant accounting across nodes; takes a fixture manifest and required report path |
| [test_economic_adversarial.py](../scripts/test_economic_adversarial.py) | Specific adversarial economic scenarios; takes a fixture manifest and required report path |
| [test_load.py](../scripts/test_load.py) | Transaction waves, occupancy and conservation; takes a fixture manifest, required report path and bounded workload options |
| [test_stratum_wire.py](../scripts/test_stratum_wire.py) | Stratum protocol scenarios using an explicitly selected node executable and report path |
| [test_wallet_adversarial.py](../scripts/test_wallet_adversarial.py) | Wallet and cold-signer rejection scenarios; select the rebuilt executables, disposable directory, unused ports and report path |

Read each program's `--help` before running it. Pass explicit paths for generated reports and fixture directories. Use a fresh fixture for independent scenarios whose setup expects an empty chain. Stop test nodes through their owning launcher and manifest when finished.

PowerShell launcher tests are separate from Rust, JavaScript and Python unittest discovery. They cover process ownership, configuration and startup/shutdown behavior; inspect their inputs and run them only in a disposable local environment. Linux shell and service-installation checks likewise require the intended platform. Report unrun platform checks as unrun.

## Interpreting results

For a protocol change, check the relevant state transition, rejection cases, deterministic replay and reorganization behavior, then run the full Rust suite. For wallet changes, check both hot and offline signing paths and rerun the frontend suites. For wire-format changes, verify canonical vectors and peer/CLI interoperability as well as local round trips.

Review dependency advisories against the exact locked versions separately from functional tests. An empty advisory result is time-dependent and does not establish that dependencies or their uses are safe.

Local tests establish only their exercised behavior. They do not prove economic stability, resistance to coordinated trading, sustained ASIC delivery, hardware location, production uptime or an independent security audit. Deployment claims require observations from the actual processes and chain being described. See [review scope and limitations](AUDIT.md).
