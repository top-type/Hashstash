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
node fuzz/js/mail_envelope.cjs
```

The Rust command runs library, binary and integration tests. Some tests launch temporary local nodes or exercise large grant lists and can take several minutes. Keep the complete output: a total from one test executable is not the total for the all-target run. Unit tests that need accelerated test funding are reported as ignored without `test-fixtures`, and fixture-only integration tests are skipped; the second command runs them.

Formatting needs the `rustfmt` component and Clippy the `clippy` component of the same toolchain. A newer Clippy can add lints that `-D warnings` denies, so record the toolchain with the results; continuous integration pins the one the gate was last recorded with.

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
| Grant funding, outcome selection and atomic payouts | [multiple recipients](../tests/multi_grants.rs), [half-reserve grant](../tests/half_reserve_grant.rs), [automatic outcomes](../tests/automatic_outcomes.rs), [decision rules and auction leadership](../tests/governance_decisions.rs) |
| Governed settings, exact fees and capacity | [parameters](../tests/governance_parameters.rs), [fees](../tests/exact_fees.rs), [total fee allocation](../tests/governed_total_fees.rs), [block selection](../tests/selection_budget.rs), [capacity changes and transport](../tests/open_governance_transport.rs) |
| Anchored lifetimes, expiry and branch validity | [anchor boundaries and replay](../tests/transaction_anchors.rs), [wallet intent](../tests/exact_wallet.rs), [controller retries](../scripts/test_chain_activity.py) |
| Canonical encoding and signing | [codec vectors](../tests/codec_vectors.rs), [browser vectors](../tests/browser_wallet_vectors.rs), [cold wallet](../tests/cold_wallet.rs), [wallet formats](../tests/wallet_formats.rs) |
| Peer authentication, discovery and hostile input | [authenticated transport](../tests/peer_transport_authenticated.rs), [discovery](../tests/peer_discovery.rs), [hostile network input](../tests/network_hostile.rs) |
| Mining protocol and share accounting | [Stratum shares](../tests/stratum_shares.rs), [adversarial mining](../tests/mining_adversarial.rs) |
| Explorer, public RPC and application data | [snapshot history](../tests/snapshot_history.rs), [public web](../tests/public_web.rs), [Chat RPC](../tests/explorer_chat_rpc.rs), [Mail index](../tests/explorer_mail.rs) |
| Controller signing boundaries and campaign decisions | [controller tests](../scripts/test_chain_activity.py), [planning tests](../scripts/test_activity_plan.py), [campaign tests](../scripts/test_pass_campaign.py) |

The frontend checks include direct proposals for all nine settings, exact u64 values above JavaScript’s safe-integer range, zero minimum fees, exact offline review, and complete transaction/message records larger than 32 MiB. Capacity checks separately cover current block weight and representation limits; they do not assert that every valid record fits every transport interface.

The executable tests and their assertions define the coverage. Public fixture keys are deterministic test inputs and must never hold real funds. Test vectors prove agreement on specific inputs; they do not by themselves establish interoperability with every external implementation.

## Fuzzing

Each parser of hostile input has a fuzz target in [`fuzz/src/lib.rs`](../fuzz/src/lib.rs). Besides the absence of panics, each target checks invariants: one encoding per decoded value, agreement between the peer preflight and the consensus codec, agreement between the bounded JSON parsers, the discovery address book's bounds, and that read-only RPC methods leave the node unchanged.

| Target | Input |
| --- | --- |
| `peer_wire` | Peer messages, directly and behind the plain transport's length prefix |
| `peer_channel` | Unauthenticated peer hellos, then any frame a pinned peer sends after a genuine handshake |
| `codec_transaction`, `codec_block` | Canonical consensus records, which the peer wire must also relay |
| `json` | The generic, `/rpc` and hot-wallet JSON body parsers; Stratum lines use the generic one |
| `http_request` | Request heads and bodies on the private and public-web listeners |
| `rpc_params` | JSON-RPC methods and parameters, private and public, on a fixture node |
| `address` | Bech32m addresses, hexadecimal keys and hashes |
| `signed_record`, `unsigned_envelope` | Signed hexadecimal records and the unsigned exports a cold signer reviews |
| `mail_envelope`, `plain_text` | Encrypted-mail envelopes, chat text and proposal rationale in transaction data |
| `address_book` | Discovery gossip into the peer address book, and the book's saved form |
| `stratum_session` | Everything a miner sends on one mining connection: line framing, subscribe and authorize, `mining.configure` with version rolling and minimum difficulty, difficulty suggestions and share submissions, on a fixture node. Replies must be JSON lines, and a closed session must leave no worker registered |

The ordinary Rust suite runs each target from its fixed seeds and kept regressions for a fixed number of mutated inputs ([stable runner](../tests/fuzz_parsers.rs)), keeping inputs whose outcome is new, replays every input kept under `fuzz/regressions/`, and sends mutated Stratum lines and HTTP requests through live listeners. It never reads a libFuzzer corpus, which is local and untracked, so its runs are the same on every machine. A longer run on the stable toolchain, which also starts from any corpus under `HASHSTASH_FUZZ_CORPUS` (default `fuzz/corpus`):

```text
HASHSTASH_FUZZ_SECONDS=600 cargo test --release --features test-fixtures --test fuzz_parsers -- --ignored --nocapture fuzz_for_a_bounded_time
```

`HASHSTASH_FUZZ_TARGETS` selects targets by name, separated by commas, and `HASHSTASH_FUZZ_SEED` repeats a run. A failing input is saved in hexadecimal under `HASHSTASH_FUZZ_ARTIFACTS`, by default in the system temporary directory. Once its cause is fixed, keep the input as `fuzz/regressions/<target>/<name>.hex`, with a `#` comment saying what it found, and add a named regression test.

Coverage-guided fuzzing uses cargo-fuzz and libFuzzer on a nightly toolchain. Copying the lockfile keeps shared dependencies at the versions the node ships with; the stable runner writes the seed corpora:

```text
cp Cargo.lock fuzz/Cargo.lock
HASHSTASH_FUZZ_CORPUS="$PWD/fuzz/corpus" cargo test --release --features test-fixtures --test fuzz_parsers -- --ignored write_seed_corpus
cargo +nightly fuzz run peer_wire fuzz/corpus/peer_wire -- -max_total_time=600
```

Without nightly, the same libFuzzer binaries build on stable with the SanitizerCoverage flags cargo-fuzz passes, less its address sanitizer. Run each binary in `fuzz/target/x86_64-unknown-linux-gnu/release/` with its corpus directory and libFuzzer options, such as `-max_total_time=600`:

```text
RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks' \
  cargo build --release --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --bins
```

The browser's mail envelope parser has its own property check, `node fuzz/js/mail_envelope.cjs [iterations] [seed]`. It also requires the browser to reach the node's verdict on each vector in [`fuzz/mail-envelope-vectors.json`](../fuzz/mail-envelope-vectors.json), which the Rust suite checks against the node. Regenerate the vectors with the ignored `write_mail_envelope_vectors` test and review every changed verdict: it changes what counts as mail.

A run that finds nothing shows only that the inputs it tried passed. Mutation from seeds without coverage feedback reaches less code than libFuzzer, and neither replaces the targeted regression tests.

## Windows checks

On Windows the library tests also read back the access list of each secret file written on NTFS with `icacls`: one protected entry granting the current account full control, nothing inherited. Where the volume keeps access lists, failing to set one is an error rather than a warning; a test gives a file a list that its owner cannot change and requires the restriction to fail, or, for an account whose privileges still allow the change, to leave the file owner-only. Only a volume without access lists, such as FAT or exFAT, produces a warning. The library tests also check that a symbolic link to a peer identity is refused; creating the link needs Developer Mode or administrator rights, and the check reports itself skipped without them. [`scripts/test_cold_launcher.ps1`](../scripts/test_cold_launcher.ps1) starts `Start-ColdWallet.ps1` for a fixture chain and checks the token hand-off: the token reaches the signer only through its environment, never its command line or `/api/session`, and every POST needs it. It stops only the signer it started: any process of the selected executable that was not running before the launch, also when the launcher fails after starting it.

## Continuous integration

[`ci.yml`](../.github/workflows/ci.yml) runs on every push and pull request: formatting and the two Clippy configurations, as separate jobs; on Linux the release build, both Rust suites, the frontend checks, Python unittest discovery and the wallet, address and mail programs on disposable nodes; on Windows the fixture suite, the checks above, the frontend checks and both Clippy configurations; and one minute of libFuzzer per target. Within a job, every check runs once the build it needs succeeded, even after another check failed, so one run reports every failing check.

A nightly schedule gives each fuzz target its own job: 15 minutes of libFuzzer, then 10 minutes of the stable runner from the same corpus. Each job minimizes its target's corpus with `cargo fuzz cmin` and keeps it, and a final job saves the corpora in the Actions cache, where every later run, nightly or per push, starts from them; a target whose job kept none keeps its previous corpus. A failing input is kept as a `fuzz-artifacts-<target>` artifact, also when the job fails or is cancelled. The nightly schedule also runs the live network suites on disposable three-node networks with [`ci_network_suites.sh`](../scripts/ci_network_suites.sh), the Linux counterpart of `Start-Testnet.ps1 -Fresh -SeedWallets`. The workflow runs both Rust suites with `--release`: the shipped profile keeps overflow checks and the code has no debug-only assertions, so the checks are the same as the commands above and finish sooner.

## Recorded results

The latest full run of this guide, with every audit workstream merged:

| Item | Record |
| --- | --- |
| Source | `audit-fixes` at `233a795` (all workstreams merged) plus the R15 and R34 review commits through the formatting-only commit `742233e`; this record changes only this file |
| Platform | Windows 11 Home 10.0.26200 x86-64, with Ubuntu under WSL 2 for the Linux builds |
| Toolchains | rustc, Cargo and Clippy 1.97.1 (2026-07-14) for x86_64-unknown-linux-gnu; rustfmt 1.9.0 of the same release on Windows; Node.js 24.20.0 on Windows; Python 3.14.4 under WSL |

| Check | Result |
| --- | --- |
| `cargo build --release --locked --bins` | Passed |
| `cargo test --all-targets --locked` | 440 passed, 56 ignored (debug, about 5 minutes) |
| The same with `test-fixtures` | 796 passed, 8 ignored (`--release`; the merged tree before these commits: 793 passed, 8 ignored) |
| Both Clippy commands | Passed |
| `cargo fmt --check` | Passed, as does `rustfmt --check --edition 2024 fuzz/src/lib.rs fuzz/fuzz_targets/*.rs` |
| Frontend runner and mail property check | 24 suites passed; 117 shared vectors and 20,000 mutations |
| Python unittest discovery | 210 tests passed with `HASHSTASH_TEST_BINARY` set to the fixture build |
| Wallet CLI, wallet manager, addresses, wallet adversarial, mail wire | 16, 8, 4, 53 and 15 checks passed on disposable nodes (fixture build) |
| Live network suites | With the fixture build: `test_network`, `test_economic_adversarial` and `test_load` (twelve 64-transaction waves, no refusals) passed on one fresh three-node network, and `test_reserve_network` through `ci_network_suites.sh` on another; `test_stratum_wire.py`: 201 assertions passed |
| Windows, natively | 333 library unit tests (1 ignored) and 30 command-line unit tests passed, including the access-list, fail-closed and link checks; the in-process fuzz targets, `stratum_session` included, and the listener tests passed; `test_cold_launcher.ps1` passed under Windows PowerShell 5.1 and, with a stand-in signer that never became ready, stopped that signer. These were cross-built for x86_64-pc-windows-gnu with Rust 1.96.0 and MinGW-w64. Integration tests that embed build-host paths cannot run from such a build, and Clippy did not run for Windows; the Windows CI job covers both |
| Fuzzing | `stratum_session` under libFuzzer (stable toolchain, SanitizerCoverage, no address sanitizer) for 300 seconds, 2.1 million inputs, then the stable runner for 120 seconds from that corpus: no failures. The earlier run of the other targets (the stable runner for 480 seconds per target, libFuzzer for 300) found and fixed a panic when `fee_quote` or `transfer_quote` received non-object parameters, and the browser opening a byte-order-mark-prefixed envelope that the node does not index as mail |

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
| [test_wallet_cli.py](../scripts/test_wallet_cli.py), [test_wallet_manager.py](../scripts/test_wallet_manager.py), [test_addresses.py](../scripts/test_addresses.py) | CLI preparation, cold signing, wallet management and address round trips on their own disposable nodes; select the fixture executables, a disposable directory and report path; ports are chosen by the system |
| [test_mail_wire.py](../scripts/test_mail_wire.py) | End-to-end encrypted mail on one disposable chain; select the fixture executable and report path |

Read each program's `--help` before running it. Pass explicit paths for generated reports and fixture directories. Use a fresh fixture for independent scenarios whose setup expects an empty chain. Stop test nodes through their owning launcher and manifest when finished.

PowerShell launcher tests are separate from Rust, JavaScript and Python unittest discovery. They cover process ownership, configuration and startup/shutdown behavior; inspect their inputs and run them only in a disposable local environment. Linux shell and service-installation checks likewise require the intended platform. Report unrun platform checks as unrun.

## Interpreting results

For a protocol change, check the relevant state transition, rejection cases, deterministic replay and reorganization behavior, then run the full Rust suite. For wallet changes, check both hot and offline signing paths and rerun the frontend suites. For wire-format changes, verify canonical vectors and peer/CLI interoperability as well as local round trips.

Review dependency advisories against the exact locked versions separately from functional tests. An empty advisory result is time-dependent and does not establish that dependencies or their uses are safe.

Local tests establish only their exercised behavior. They do not prove economic stability, resistance to coordinated trading, sustained ASIC delivery, hardware location, production uptime or an independent security audit. Deployment claims require observations from the actual processes and chain being described. See [review scope and limitations](AUDIT.md).

Funded economic process tests use a separately built `test-fixtures` executable and an explicit `test_work: true` configuration. Their reports identify the accelerated one-expected-hash-per-atom issuance. Ordinary builds reject those networks. Production issuance is checked separately at one petahash per atom, including zero-reward blocks, per-block rounding and branch changes; accelerated balances do not establish production funding.
