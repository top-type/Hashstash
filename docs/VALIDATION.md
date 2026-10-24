# Validation guide

Run checks from the repository root using the source and lockfiles you intend to ship. Record the commit, operating system, compiler versions, commands, failures and skips with the results. A passing run applies to that build and platform; it does not establish results for another release or deployment.

## Build and core checks

Install the [build prerequisites](../README.md) first. The Rust build needs a C compiler and linker compatible with the selected Rust target. Windows GNU builds need the matching MinGW tools on `PATH`; MSVC builds need the Visual C++ build tools.

```text
cargo build --release --locked --bins
cargo test --all-targets --locked
cargo test --all-targets --locked --features test-fixtures --target-dir target/fixtures
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --all-targets --locked --features test-fixtures --target-dir target/fixtures -- -D warnings
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
| Anchored lifetimes, expiry and branch validity | [anchor boundaries and replay](../tests/transaction_anchors.rs), [wallet intent](../tests/exact_wallet.rs), [controller retries](../scripts/test_chain_activity.py) |
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
| [soak.py](../scripts/soak.py) | Long chaos soak on a network it starts itself; takes a `test-fixtures` executable, report path, duration, node count, seed and base port (see [Chaos soak](#chaos-soak)) |

Read each program's `--help` before running it. Pass explicit paths for generated reports and fixture directories. Use a fresh fixture for independent scenarios whose setup expects an empty chain. Stop test nodes through their owning launcher and manifest when finished.

## Chaos soak

[soak.py](../scripts/soak.py) runs a long randomized workload against a network it creates and owns, while it kills, restarts and partitions the nodes. Unlike the manifest-driven programs above, it starts its own nodes and never connects to an existing network. It needs only Python's standard library and a `test-fixtures` executable. Run it on Linux or WSL; it uses `SIGKILL`, `SIGINT`, `/proc` and loopback aliases.

```bash
cargo build --release --locked --features test-fixtures --target-dir target/fixtures --bin hashstash
python3 scripts/soak.py --binary target/fixtures/release/hashstash \
  --duration 30m --nodes 5 --seed 1 --base-port 47480 --report soak-report.json
```

The run directory (a new temporary directory, or `--workdir`) holds a `network.json` derived from `config/testnet.json` with `test_work: true`, a unique network name and a low difficulty floor (`--initial-bits`, about 4096 expected hashes per block). Mining every `--block-interval` seconds is faster than the 15-second target, so the timestamp adjustment (anchored at block 1) raises difficulty by about one half-life every 70 blocks; once a block needs more than `--max-block-hashes`, the harness mines only at the target interval, which stops the climb. At the defaults that point comes near the end of a 30-minute run; longer runs then slow to the target interval unless `--block-interval` is raised. Node *i* listens on `base+10i` (RPC), `+1` (peer) and `+2` (Stratum). Every directed peer link goes through a harness proxy on the next port block, and node *i* dials from its own address `127.0.0.(11+i)`, so partitions cut exact links and each peer has its own admission accounting. The directory, including databases and node logs, is removed after a passing run unless `--keep` or `--workdir` is given, and kept after a failure.

The workload signs transactions locally with BIP340 (checked first against `tests/data/bip340.csv`) after the node prepares their bodies, and broadcasts some to a different node than the one that prepared them. Python unit discovery runs [test_soak.py](../scripts/test_soak.py), which checks that signer and the harness's body patching against the independent encoder in `chain_activity.py`. The workload covers:

- transfers between seeded wallets and up to `--max-accounts` newly created accounts, with chat text and structurally valid encrypted-mail envelopes as transaction data;
- deposits and redeems at rest and in both PASS and FAIL during decisions, with a seeded favorite side per decision;
- grant proposals (most asking for all waiting revenue plus part of reserve, so a winning grant bends the PASS curve and trading can decide it; some unfundable), safe parameter proposals, support and refunds during auctions;
- same-nonce fee bumps and underbids of still-pooled transactions;
- submissions that are invalid by construction: random and truncated bytes, trailing bytes, corrupted or wrong-key signatures, far-future nonces, unknown anchors, zero lifetimes; plus overspends, stale replays, blocks re-mined with valid proof of work but invalid bodies, and malformed RPC requests.

Mining moves randomly between nodes about every `--block-interval` seconds. Chaos events come from a shuffled deck so every type recurs: `kill -9` and restart (checkpoint and history replay), `kill -9` inside a multi-block mining burst, isolation of one node, a split into two groups (sometimes killing a node inside one), a graceful stop followed by a restart with a random subset of peers, `kill -9` of every node at once, and malformed peer input from a separate address. After each heal or restart, and every `--converge-interval` seconds, mining pauses until all nodes agree.

| Check | What must hold |
| --- | --- |
| `conservation` | In each world, tracked account hashes + reserve + revenue + grant escrow + auction escrow = issued, for every new tip on every node (one atomic `snapshot` per 256 keys) |
| `share_conservation`, `share_supply` | Tracked shares equal the world's account shares, which equal its curve shares |
| `curve_bounds`, `grant_capacity`, `fail_world_grant_escrow`, `snapshot_consistency` | Reserve within curve mass and zero together; capacity = revenue + reserve − 1; no FAIL grant escrow; status and governance agree within one snapshot |
| `convergence`, `explorer_ready` | All running nodes reach one tip and state root within `--converge-timeout`, and each explorer index reaches its tip within `--explorer-timeout`. Mining pauses meanwhile; because nodes keep the first-seen of equal-work tips, competing tips at the top height get one tie-breaking block every `--tie-break-after` seconds |
| `restart_ready`, `restart_durability`, `graceful_shutdown`, `node_alive` | Nodes answer RPC within `--start-timeout`, keep every block they reported before `kill -9`, exit 0 on Ctrl+C, and never exit on their own |
| `mempool_*` | Pooled transactions hash to their IDs, have unique sender nonces continuing the account nonce, have live anchors on the active branch, fit one block and include no invalid submission |
| `garbage_rejected`, `garbage_block_rejected`, `fee_replacement`, `rpc_garbage_survived`, `peer_garbage_survived` | Invalid-by-construction input is rejected, a replaced fee never pools beside its replacement, and malformed input never stops a node |
| `transaction_id`, `prepared_body` | Returned IDs match the signed bytes; prepared bodies keep the requested sender and lifetime |
| `node_log_clean` | No panic, `ERROR`, `Error:`, fatal or "unavailable" lines in node output |
| `rpc_latency`, `rpc_available` | Every `--probe-interval` seconds, from a separate loopback address, `status` (published snapshot) and genesis `getblock` (main state lock) answer within `--max-rpc-latency`, detecting read-path and lock stalls |
| `rss_bound`, `rss_growth`, `disk_bound`, `disk_per_block` | Memory and data-directory size stay within the `--max-*` bounds |

The JSON report has `passed`, every check's count and violations, each violation with its node, tip and the preceding chaos and transaction events, the chaos timeline with convergence times, reorganization depths, governance coverage (phases, decisions, settings changes), workload counts by kind with rejections grouped by node error, RPC latency percentiles, and per-node restarts, memory and disk. The process exits non-zero on any violation or harness error. Rejections of valid-looking transactions are expected under forks, expiries and cross-node submission (reported with a `cross-node` suffix); they are counted, not failed.

The seed fixes keys and every randomized choice of the workload, miner and chaos schedules; thread timing is not deterministic, so reproduce a failure with the report's `reproduce.command` and, if needed, several runs or a longer duration. Linux's default ephemeral port range (32768–60999) includes the default ports, so a restarting node can find its port briefly held by a client socket; the harness retries that start and counts it under `workload.environment`. Conservation relies on the harness creating every account; it is meaningful only on the network the harness started. A passing soak covers the exercised schedules on one machine; it does not establish behavior under real network latency, adversarial peers at scale or production issuance.

PowerShell launcher tests are separate from Rust, JavaScript and Python unittest discovery. They cover process ownership, configuration and startup/shutdown behavior; inspect their inputs and run them only in a disposable local environment. Linux shell and service-installation checks likewise require the intended platform. Report unrun platform checks as unrun.

## Interpreting results

For a protocol change, check the relevant state transition, rejection cases, deterministic replay and reorganization behavior, then run the full Rust suite. For wallet changes, check both hot and offline signing paths and rerun the frontend suites. For wire-format changes, verify canonical vectors and peer/CLI interoperability as well as local round trips.

Review dependency advisories against the exact locked versions separately from functional tests. An empty advisory result is time-dependent and does not establish that dependencies or their uses are safe.

Local tests establish only their exercised behavior. They do not prove economic stability, resistance to coordinated trading, sustained ASIC delivery, hardware location, production uptime or an independent security audit. Deployment claims require observations from the actual processes and chain being described. See [review scope and limitations](AUDIT.md).

Funded economic process tests use a separately built `test-fixtures` executable and an explicit `test_work: true` configuration. Their reports identify the accelerated one-expected-hash-per-atom issuance. Ordinary builds reject those networks. Production issuance is checked separately at one petahash per atom, including zero-reward blocks, per-block rounding and branch changes; accelerated balances do not establish production funding.
