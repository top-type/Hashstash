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

The shipped release profile keeps overflow checks but compiles out `debug_assert!`, which guards internal invariants such as a wallet backup's fixed length. The debug-profile commands above check them; so does the release profile with debug assertions turned on, which finishes sooner:

```text
CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true cargo test --release --all-targets --locked --features test-fixtures --target-dir target/debug-assertions
```

`ui/vendor/noble.js`, the browser wallets' signing and encryption library, must be the clean build of the locked registry packages. With Node.js 22 or 24, which ship corepack, this installs the pnpm that `package.json` names, checked against its hash, then rebuilds the bundle and compares every byte with the committed files:

```text
cd scripts/browser-crypto
corepack pnpm install --frozen-lockfile
corepack pnpm run check
```

Release binaries for Linux servers come from `bash scripts/release.sh --verify` on the validated commit: a normal build (never `test-fixtures`) with `--locked`, the pinned toolchain and remapped build paths, rebuilt from scratch and compared byte for byte, with `SHA256SUMS` and `BUILDINFO` written beside the binaries. A second builder with the same Rust and C compiler versions must obtain the same `SHA256SUMS` ([launch runbook](LAUNCH.md#2-build-and-pin-the-release)). Before launch, that commit also needs a green run of the full continuous-integration gate, recorded under [release gate](#release-gate).

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

Discovery runs the Python unit tests, including activity planning, custody and retry rules, campaign completion checks, rental-monitor parsing, and the rules the continuous-integration workflow must keep. Several `test_*.py` files are standalone integration programs rather than unittest suites; discovery alone does not run their scenarios (see [isolated process and network scenarios](#isolated-process-and-network-scenarios)).

## What the regression tests cover

| Area | Representative tests |
| --- | --- |
| Issuance, canonical work and timestamp difficulty | [canonical work](../tests/canonical_work.rs), [timestamp DAA](../tests/timestamp_daa.rs), [reorganization](../tests/reorg_stress.rs) |
| Simultaneous clearing, proportional refunds and exact price bounds | [batch clearing](../tests/batch_clearing.rs), [consensus permutations and leading blocks](../tests/batch_consensus.rs) |
| Reserve trades, integer rounding and revenue | [dynamic curve](../tests/dynamic_curve.rs), [revenue buffer](../tests/revenue_buffer.rs), [empty genesis](../tests/open_genesis.rs) |
| Grant funding, outcome selection and atomic payouts | [multiple recipients](../tests/multi_grants.rs), [half-reserve grant](../tests/half_reserve_grant.rs), [automatic outcomes](../tests/automatic_outcomes.rs), [decision rules and auction leadership](../tests/governance_decisions.rs) |
| Governed settings, exact fees and capacity | [parameters](../tests/governance_parameters.rs), [fees](../tests/exact_fees.rs), [total fee allocation](../tests/governed_total_fees.rs), [block selection](../tests/selection_budget.rs), [capacity changes and transport](../tests/open_governance_transport.rs) |
| Anchored lifetimes, expiry and branch validity | [anchor boundaries and replay](../tests/transaction_anchors.rs), [wallet intent](../tests/exact_wallet.rs), [controller retries](../scripts/test_chain_activity.py) |
| Canonical encoding and signing | [codec vectors](../tests/codec_vectors.rs), [state commitment vectors](../tests/commitment_encoding.rs), [browser vectors](../tests/browser_wallet_vectors.rs), [cold wallet](../tests/cold_wallet.rs), [wallet formats](../tests/wallet_formats.rs) |
| Peer authentication, discovery and hostile input | [authenticated transport](../tests/peer_transport_authenticated.rs), [discovery](../tests/peer_discovery.rs), [hostile network input](../tests/network_hostile.rs) |
| Mining protocol and share accounting | [Stratum shares](../tests/stratum_shares.rs), [adversarial mining](../tests/mining_adversarial.rs) |
| Explorer, public RPC and application data | [snapshot history](../tests/snapshot_history.rs), [public web](../tests/public_web.rs), [Chat RPC](../tests/explorer_chat_rpc.rs), [Mail index](../tests/explorer_mail.rs) |
| Controller signing boundaries and campaign decisions | [controller tests](../scripts/test_chain_activity.py), [planning tests](../scripts/test_activity_plan.py), [campaign tests](../scripts/test_pass_campaign.py) |

The frontend checks include direct proposals for all nine settings, exact u64 values above JavaScript’s safe-integer range, zero minimum fees, exact offline review, and complete transaction/message records larger than 32 MiB. Capacity checks separately cover current block weight and representation limits; they do not assert that every valid record fits every transport interface.

The executable tests and their assertions define the coverage. Public fixture keys are deterministic test inputs and must never hold real funds. Test vectors prove agreement on specific inputs; they do not by themselves establish interoperability with every external implementation.

## Fuzzing

Each parser of hostile input has a fuzz target in [`fuzz/src/lib.rs`](../fuzz/src/lib.rs), and so do synchronization from a hostile peer and serving one. Besides the absence of panics, each target checks invariants: one encoding per decoded value, agreement between the peer preflight and the consensus codec, agreement between the bounded JSON parsers, the discovery address book's bounds, that read-only RPC methods leave the node unchanged, that a node serving a hostile peer answers in protocol order with replies that fit the capacity the peer declared and follow the node's active chain, and that after either peer session a node's tip is its active block, its held headers stay within their bounds and a replay of its active chain reaches the same state root.

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
| `peer_sync` | The replies of a peer that a fixture node synchronizes from over loopback, each session from another loopback address: header replies into the held-header store with its download pins, then a block batch and its validation, from seeds that extend the chain, reorganize it to a heavier branch from genesis, or withhold blocks, deliver part of a branch, and repeat or reverse headers. Each request the node sends must decode canonically; afterwards its tip must be its active block, and a changed tip must match a replay of the active chain in a fresh node |
| `peer_serve` | Everything a host that connects to a fixture node's peer port sends, one message after each reply, each session from another loopback address: header requests with hostile locators, transport versions and declared capacities, one round past their limit, the locator request and the push after it, address requests and messages out of order, from seeds that also push an extension of the chain and a heavier branch from genesis. Each reply must fit the frame the requester can receive, decode within its declared capacity with one encoding, keep to protocol order and match the active chain from the locator's best match; afterwards the node must settle as after `peer_sync` |

The ordinary Rust suite runs each target from its fixed seeds and kept regressions for a fixed number of mutated inputs ([stable runner](../tests/fuzz_parsers.rs)), keeping inputs whose outcome is new, replays every input kept under `fuzz/regressions/`, and sends mutated Stratum lines and HTTP requests through live listeners. It never reads a libFuzzer corpus, which is local and untracked, so its runs are the same on every machine. A longer run on the stable toolchain, which also starts from any corpus under `HASHSTASH_FUZZ_CORPUS` (default `fuzz/corpus`):

```text
HASHSTASH_FUZZ_SECONDS=600 cargo test --release --features test-fixtures --test fuzz_parsers -- --ignored --nocapture fuzz_for_a_bounded_time
```

`HASHSTASH_FUZZ_TARGETS` selects targets by name, separated by commas, and `HASHSTASH_FUZZ_SEED` repeats a run. A failing input is saved in hexadecimal under `HASHSTASH_FUZZ_ARTIFACTS`, by default in the system temporary directory. Once its cause is fixed, keep the input as `fuzz/regressions/<target>/<name>.hex`, with a `#` comment saying what it found, and add a named regression test.

Coverage-guided fuzzing uses cargo-fuzz and libFuzzer on a nightly toolchain; these are the dated nightly and the cargo-fuzz version continuous integration pins. Copying the lockfile keeps shared dependencies at the versions the node ships with, and `fuzz/Cargo.toml` pins `libfuzzer-sys` exactly; the stable runner writes the seed corpora; `--debug-assertions` also checks the invariants the shipped build compiles out:

```text
rustup toolchain install nightly-2026-10-10 --profile minimal
cargo +nightly-2026-10-10 install cargo-fuzz --version 0.13.2 --locked
cp Cargo.lock fuzz/Cargo.lock
HASHSTASH_FUZZ_CORPUS="$PWD/fuzz/corpus" cargo test --release --features test-fixtures --test fuzz_parsers -- --ignored write_seed_corpus
cargo +nightly-2026-10-10 fuzz run --release --debug-assertions peer_wire fuzz/corpus/peer_wire -- -max_total_time=600
```

Without nightly, the same libFuzzer binaries build on stable with the SanitizerCoverage flags cargo-fuzz passes, less its address sanitizer. Run each binary in `fuzz/target/x86_64-unknown-linux-gnu/release/` with its corpus directory and libFuzzer options, such as `-max_total_time=600`:

```text
RUSTFLAGS='-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing -Cdebug-assertions -Coverflow-checks' \
  cargo build --release --manifest-path fuzz/Cargo.toml --target x86_64-unknown-linux-gnu --bins
```

The browser's mail envelope parser has its own property check, `node fuzz/js/mail_envelope.cjs [iterations] [seed]`. It also requires the browser to reach the node's verdict on each vector in [`fuzz/mail-envelope-vectors.json`](../fuzz/mail-envelope-vectors.json), which the Rust suite checks against the node. Regenerate the vectors with the ignored `write_mail_envelope_vectors` test and review every changed verdict: it changes what counts as mail.

A run that finds nothing shows only that the inputs it tried passed. Mutation from seeds without coverage feedback reaches less code than libFuzzer, and neither replaces the targeted regression tests.

## Windows checks

On Windows the library tests also read back the access list of each secret file written on NTFS with `icacls`: one protected entry granting the current account full control, nothing inherited. In a folder whose inherited list lets the Users group read, a new secret file already has that list while the handle that created it is still open, and a file created inside a private staging folder inherits only the current account's entry; restricting an existing file removes entries granted explicitly to other accounts. Where the volume keeps access lists, failing to set one is an error rather than a warning; a test gives a file a list that its owner cannot change and requires the restriction to fail, or, for an account whose privileges still allow the change, to leave the file owner-only. Only a volume without access lists, such as FAT or exFAT, produces a warning. The library tests also check that the key reader refuses a key whose list lets the Users group read it, and that a symbolic link to a peer identity is refused; creating the link needs Developer Mode or administrator rights, and the check reports itself skipped without them. [`scripts/test_cold_launcher.ps1`](../scripts/test_cold_launcher.ps1) starts `Start-ColdWallet.ps1` for a fixture chain and checks the token hand-off: the token reaches the signer only through its environment, never its command line or `/api/session`, and every POST needs it; without the token `/api/session` names no network or account. Its copy of the launcher's readiness check refuses a listener on the port that another process owns, and never accepts one that does not answer as the signer. It stops only the signer it started: any process of the selected executable that was not running before the launch, also when the launcher fails after starting it. It also checks the launcher's Windows Error Reporting exclusion of the signer under a test key of the current account, which it removes, never the real `ExcludedApplications` key; `-RegistryOnly` runs just that check, without a signer build.

Windows PowerShell 5.1, the version Windows ships, differs from PowerShell 7 in two ways that have broken these scripts. Started with `-File`, as a shortcut or a scheduled task starts a script, it leaves `$PSScriptRoot` empty while it evaluates parameter defaults; and under `$ErrorActionPreference = 'Stop'` a native command's redirected error output ends the script. The launchers therefore set path defaults in their bodies, which [`operator_files.rs`](../tests/operator_files.rs) checks for every script, and continuous integration runs every launcher test, [`test_rental_launcher_guard.ps1`](../scripts/test_rental_launcher_guard.ps1) and [`test_launcher.ps1`](../scripts/test_launcher.ps1) among them, with `powershell -File`.

## Continuous integration

[`ci.yml`](../.github/workflows/ci.yml) is configured to run on every push and pull request: formatting and the two Clippy configurations, as separate jobs; on Linux the release build, both Rust suites, the frontend checks, the browser cryptography rebuild, Python unittest discovery, and the standalone programs on disposable nodes (wallet CLI, wallet manager, addresses, adversarial wallet, mail wire, the independent Stratum worker, peer discovery across processes, and production issuance on the normal build); the fixture suite again with debug assertions; on Windows the fixture suite, the checks above, every PowerShell launcher test, the frontend checks and both Clippy configurations; and one minute of libFuzzer per target. Each check is its own step and runs once the build it needs succeeded, even after another check failed, so one run reports every failing check; the frontend runner itself stops at its first failing suite. PowerShell takes a step's result from its last command alone, so each Windows step that PowerShell runs holds one command, and each launcher test runs in its own Windows PowerShell 5.1, whose exit code says whether the test passed.

The full gate also gives each fuzz target its own job: 15 minutes of libFuzzer, then 10 minutes of the stable runner from the same corpus. Each job minimizes its target's corpus with `cargo fuzz cmin` and keeps it, and on the nightly and manual runs a final job saves the corpora in the Actions cache, where every later run, nightly or per push, starts from them; a target whose job kept none keeps its previous corpus. A failing input is kept as a `fuzz-artifacts-<target>` artifact, also when the job fails or is cancelled. The full gate also runs the live network suites on disposable three-node networks with [`ci_network_suites.sh`](../scripts/ci_network_suites.sh), the Linux counterpart of `Start-Testnet.ps1 -Fresh -SeedWallets`. It runs nightly and on manual dispatch, which GitHub starts only from the workflow on the default branch, and on every push of a `v*` tag or a `release/*` branch, which runs it on exactly the pushed commit.

Every action is pinned to a full commit and every toolchain and installed tool to an exact version: Rust 1.97.1; Node.js 22.22.1, whose corepack also checks the pnpm hash, and Python 3.12.15, of the line [README.md](../README.md) names; for libFuzzer, nightly-2026-10-10 and cargo-fuzz 0.13.2; for the bundle rebuild, the pnpm in `scripts/browser-crypto/package.json`, which corepack checks against its hash. A moved tag or branch upstream therefore cannot change what a run executes. [`test_ci_workflow.py`](../scripts/test_ci_workflow.py), which unittest discovery runs, checks these rules, the one-command PowerShell steps, and that every standalone test program and launcher test runs in a job.

The workflow runs the Rust suites with `--release`, the shipped profile, which keeps overflow checks and compiles out `debug_assert!`; `grep -rn debug_assert src` lists the invariants that only those check. The debug-assertions job and every fuzz build, libFuzzer and the stable runner alike, turn them on.

### Release gate

The network launches from one commit. That exact commit needs a green run of the full gate before launch, recorded here:

| Item | Record |
| --- | --- |
| Release commit | Not yet chosen |
| Full-gate run | Not yet run |

As of 2026-10-25 the workflow has never run on GitHub: the repository's only branch is `main` at `cfaaeb8`, which has no workflow, and `audit-fixes` has not been pushed. Every result below is a local run, and some jobs have not run anywhere: the Windows job's MSVC build, its fixture suite, access-list tests and Clippy runs, the PowerShell 7 launcher step, and `cargo fuzz` on the pinned nightly with its address sanitizer. A first run often needs fixes, so push as soon as the branch is ready rather than on the day before launch. To run the gate on the release commit:

1. Push the release branch. Its push and pull-request runs cover every job except the per-target fuzz jobs and the network suites.
2. Push a `release/<version>` branch, or the release tag, at the release commit, for example `git push origin RELEASE_COMMIT:refs/heads/release/0.43.0`. That run is the full gate on that commit.
3. Record the commit, the run's address and its result in the table above. After any fix, repeat on the new commit: a run on another commit does not count.

Nightly runs and manual dispatch become available once the workflow is on the default branch.

## Recorded results

The latest full run of this guide, with every audit workstream and the R15 and R34 review commits merged, before the other review branches (see the integration run below):

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

The integration run after the other review branches were merged on top (the R01, R02, R03, R04, R05, R06, R08, R09, R11, R12, R13, R16, R17, R20, R22, R23, R25, R30 and R40 review commits, with `cargo fmt` over the merged tree) repeated part of this guide under WSL 2 and on Windows: `cargo fmt --check` and the fuzz `rustfmt` check passed; the `test-fixtures` suite with `--release` passed 823 tests, 8 ignored; the frontend runner passed its 24 suites; the seven self-contained Python unit scripts passed; and `test_network`, `test_economic_adversarial` and `test_load` (twelve 64-transaction waves, no refusals) passed with the fixture build on one fresh three-node network. Clippy, the plain suite, the Windows native checks and fuzzing were not repeated, and continuous integration had not run them either (see the [release gate](#release-gate)).

The 0.43.0 release preparation (the version bump, the peer protocol and storage markers, the release script and the launch documents, on `audit-fixes` at `c1ae19c`) repeated these under WSL 2 with rustc, Cargo and Clippy 1.97.1 and on Windows with rustfmt 1.9.0 and Node.js: `cargo fmt --check` and the fuzz `rustfmt` check passed; both Clippy configurations passed; the `test-fixtures` suite with `--release` passed 827 tests, 8 ignored, and the later `operator_files` run passed 10 (one earlier full run failed once in `stratum_shares::shares_difficulty_changes_duplicates_blocks_and_reorgs`, a solved block on the job after a reorganization that was not accepted under full parallel load; it passed ten runs alone and the next full run); the frontend runner passed its 24 suites and the mail property check its 117 vectors and 20,000 mutations; the seven self-contained Python unit scripts passed; and `test_network` (12 checks), `test_economic_adversarial` (10), `test_load` (twelve 64-transaction waves, no refusals) and `test_reserve_network` (12) passed through `ci_network_suites.sh` with the fixture build on fresh three-node networks. `scripts/release.sh --verify` produced byte-identical binaries from two from-scratch builds, and a copy of the source at another path gave the same `SHA256SUMS`. A 0.42.0 node and this build, given the same genesis file, refused each other at the first message in plain and pinned transport, and this build refused the 0.42.0 database, each naming that release; 0.42.0 still opened its database afterwards.

A Windows run on `audit-fixes` at `c1ae19c` then cross-built every target for x86_64-pc-windows-gnu (Rust 1.97.1, MinGW-w64 GCC 13) under WSL 2 and ran the results natively on Windows 11 10.0.26200, from a non-elevated account with Developer Mode on, so the symbolic-link checks ran. All 76 test executables ran, the integration tests included: two junctions under `C:\mnt\c` let the WSL paths that `CARGO_BIN_EXE_hashstash` and `CARGO_MANIFEST_DIR` embed name the real files. It found two tests that failed only on Windows, a faucet key fixture that kept the access list of a temporary folder other accounts could read, and a test that deleted a database the node held open, and the two Windows PowerShell 5.1 faults above. After the fixes, 824 tests passed and 8 were ignored both natively on Windows and under WSL 2; both Clippy configurations passed for both targets; and under Windows PowerShell 5.1 every launcher test script passed, as did `Start-Devnet.ps1` and `Start-RentalTest.ps1` with `Stop-RentalTest.ps1`, started by hand.

The continuous-integration and fuzzing changes for review items L006, L032, L033, L062, L079, L080 and L081 (on `audit-fixes` at `cbe0fe2`, changing only the workflow, the fuzz targets and runner, the workflow tests, one frontend suite's wait and these documents) were checked on 2026-10-25 under WSL 2 with rustc and Clippy 1.97.1, Node.js 22.22.1 and Python 3.14.4, and on Windows 11 with Node.js 24.20.0 and Windows PowerShell 5.1, using the workflow's own commands where it has them:

- The `test-fixtures` suite with `--release` passed 830 tests, 8 ignored; with debug assertions, as the new job runs it, also 830 passed, 8 ignored; the plain suite with `--release` passed 467 tests, 60 ignored; both Clippy configurations passed; `cargo fmt --check` and the fuzz `rustfmt` check passed.
- `peer_sync` ran 3,000 inputs in the ordinary suite under WSL 2 (54 outcomes) and natively on Windows from a cross-built x86_64-pc-windows-gnu test binary (52 outcomes), which also passed `peer_wire`, `peer_channel`, `codec_block`, `rpc_params` and `stratum_session`. The stable runner fuzzed it for 300 seconds from the seed corpus: 195,633 inputs, 81 outcomes, no failure. Built for libFuzzer on the stable toolchain (SanitizerCoverage, debug assertions, no address sanitizer) and started from the 18 seeds, it ran 72,940 inputs in 301 seconds, reached 8,267 coverage points with 840 new inputs and a peak of 51 MB, and found nothing. The fuzz crate type-checked with `--cfg fuzzing` and the node's lockfile, which leaves only `arbitrary` and `jobserver` unpinned. No nightly toolchain or cargo-fuzz was installed, so `cargo fuzz` itself did not run.
- `test_ci_workflow.py` passed its eight tests, each of which fails on the workflow at `cbe0fe2`; Python unittest discovery passed 226 tests with the normal build.
- The frontend runner passed its 24 suites, twice, and the mail property check its 117 vectors and 20,000 mutations. The bundle rebuild with pnpm 10.34.6 matched the committed files byte for byte with Node.js 22 under WSL 2 and Node.js 24 on Windows.
- The wallet CLI (16 checks), wallet manager (8), addresses (4), adversarial wallet (53) and mail wire (15) programs and the independent Stratum worker (201 assertions) passed with the fixture build, and peer discovery across processes (3 checks) and production issuance (5) with the normal build.
- With a cross-built normal build, each launcher test passed in its own Windows PowerShell 5.1 started with `-File`: `test_cold_launcher.ps1` (14 checks), `test_launcher.ps1`, `test_config_launcher.ps1` (18), `test_mining_launcher.ps1` (22), `test_fresh_wallet_launcher.ps1` (10), `test_wallet_launcher.ps1` (11) and `test_rental_launcher_guard.ps1`. PowerShell 7 is not installed on that machine, so the PowerShell 7 cold-launcher step did not run, and neither did the Windows job's MSVC build, its fixture suite, its access-list tests or its Clippy runs.
- `ci_network_suites.sh` passed `test_network` (12 checks), `test_economic_adversarial` (10) and `test_load` (twelve 64-transaction waves, no refusals) on one fresh network, and `test_reserve_network` (12) on another. A first attempt at the funded network did not start: another process held the first node's port, which lies in Linux's ephemeral port range.
- Every pinned action commit was the commit that its named release tag, or `master`, resolved to on GitHub, and cargo-fuzz 0.13.2 and the 2026-10-10 nightly existed.

The review of those changes (on the merged `audit-fixes` at `2458a95`, adding `peer_serve`, the held-header bound checks, `peer_sync` labels that name header errors, a fuzz-only node hook for an inbound peer session and the held-header counts, and exact Node.js and Python versions) was checked on 2026-10-25 under WSL 2 with rustc and Clippy 1.97.1, Node.js 22.22.1 and Python 3.14.4, and on Windows 11 with rustfmt 1.9.0, Node.js 24.20.0 and Python 3.12.10:

- The `test-fixtures` suite with `--release` passed 934 tests, 9 ignored; with debug assertions, as the debug-assertions job runs it, 934 passed and 9 were ignored, the first such run of the merged tree with the debug assertions the specification and clearing changes added. Both Clippy configurations, `cargo fmt --check` and the fuzz `rustfmt` check passed. One earlier full run failed once in `operator_files::linux_installer_checks_with_this_binary`, whose installer check was terminated and its staging directory gone while other checkouts' suites shared the WSL instance; it passed alone and in the full run above.
- `peer_serve` ran 3,000 inputs in the ordinary suite under WSL 2 (85 outcomes) and natively on Windows from a cross-built x86_64-pc-windows-gnu test binary (86 outcomes), where `peer_sync` and both seed tests also passed; its seeds reach every branch of the inbound handler. The stable runner fuzzed `peer_serve` and `peer_sync` together for 300 seconds from the seed and libFuzzer corpora: 481,887 and 476,235 inputs, 150 and 94 outcomes (`peer_sync` reached 81 in the earlier 300-second run, before its outcomes named header errors), no failure. Built for libFuzzer on the stable toolchain (SanitizerCoverage, debug assertions, no address sanitizer) from its seeds, `peer_serve` ran 64,335 inputs in 301 seconds, reached 7,963 coverage points with 906 new inputs and a peak of 50 MB, and found nothing. Comparing either reply check with the wrong active block made the ordinary suite fail at once.
- `test_ci_workflow.py` passed its eight tests; the exact-version test fails on the previous workflow, whose Node.js and Python versions floated. Node.js 22.22.1 and Python 3.12.15 are in the manifests that `actions/setup-node` and `actions/setup-python` install from, for the runners the jobs use. The seven self-contained Python unit scripts and `test_soak.py` passed, the frontend runner its 24 suites and the mail property check its 117 vectors and 20,000 mutations.

The workflow itself has still not run on GitHub, so the [release gate](#release-gate) stays open.

## Isolated process and network scenarios

The [local testnet guide](TESTNET.md) describes creating a disposable three-node network with its own configuration, databases, keys and ports. Use the manifest from that fixture for scripts that accept a manifest. These scripts deliberately submit transactions, mine easy-target blocks or create competing branches; never point them at a live chain.

| Program | Purpose and required inputs |
| --- | --- |
| [test_network.py](../scripts/test_network.py) | End-to-end transactions, governance, relay and reorganization; takes a fixture manifest and an optional report path |
| [test_reserve_network.py](../scripts/test_reserve_network.py) | Reserve, revenue and grant accounting across nodes; takes a fixture manifest and required report path |
| [test_economic_adversarial.py](../scripts/test_economic_adversarial.py) | Specific adversarial economic scenarios; takes a fixture manifest and required report path |
| [test_load.py](../scripts/test_load.py) | Transaction waves, occupancy and conservation; takes a fixture manifest, required report path and bounded workload options |
| [test_stratum_wire.py](../scripts/test_stratum_wire.py) | Stratum protocol scenarios from an independent Python worker; select a `test-fixtures` executable and report path |
| [test_production_issuance.py](../scripts/test_production_issuance.py) | Production issuance on an unfunded loopback devnet: the normal build initializes it, refuses accelerated issuance and mines blocks at one petahash per atom; select a normal build and a new report path |
| [test_wallet_adversarial.py](../scripts/test_wallet_adversarial.py) | Wallet and cold-signer rejection scenarios; select the rebuilt executables, disposable directory, unused ports and report path |
| [test_wallet_cli.py](../scripts/test_wallet_cli.py), [test_wallet_manager.py](../scripts/test_wallet_manager.py), [test_addresses.py](../scripts/test_addresses.py) | CLI preparation, cold signing, wallet management and address round trips on their own disposable nodes; select the fixture executables, a disposable directory and report path; ports are chosen by the system |
| [test_mail_wire.py](../scripts/test_mail_wire.py) | End-to-end encrypted mail on one disposable chain; select the fixture executable and report path |
| [test_peer_discovery_process.py](../scripts/test_peer_discovery_process.py) | Three discovery nodes on a disposable loopback devnet: joining through one seed, block relay after the seed exits, and recovery from the saved address book; select any build and a new report path. Discovery accepts untrusted peers, so it runs the nodes with `--allow-easy-target` and `--dev-rpc` |
| [soak.py](../scripts/soak.py) | Long chaos soak on a network it starts itself; takes a `test-fixtures` executable, report path, duration, node count, seed and base port (see [Chaos soak](#chaos-soak)) |

Read each program's `--help` before running it. Pass explicit paths for generated reports and fixture directories. Use a fresh fixture for independent scenarios whose setup expects an empty chain. Stop test nodes through their owning launcher and manifest when finished.

Continuous integration runs every program in this table except the soak: the four network suites in the full gate, the others on every push. [`test_full_audit_wallets.py`](../scripts/test_full_audit_wallets.py) and [`test_full_audit_wallet_launchers.ps1`](../scripts/test_full_audit_wallet_launchers.ps1) rerun suites that it runs directly, in relocated directories and ports.

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

PowerShell launcher tests are separate from Rust, JavaScript and Python unittest discovery. They cover process ownership, configuration and startup/shutdown behavior; inspect their inputs and run them only in a disposable local environment. The Windows job runs each of them, except the full-audit wrapper of two others, in its own Windows PowerShell 5.1, and `test_cold_launcher.ps1` also under PowerShell 7. Run them the same way, for example `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\test_rental_launcher_guard.ps1 -Executable target\release\hashstash.exe`: the child's exit code says whether the test passed, whereas a direct call leaves the last native command's code behind, which a passing test can set by checking a refusal. Linux shell and service-installation checks likewise require the intended platform. Report unrun platform checks as unrun.

## Interpreting results

For a protocol change, check the relevant state transition, rejection cases, deterministic replay and reorganization behavior, then run the full Rust suite. For wallet changes, check both hot and offline signing paths and rerun the frontend suites. For wire-format changes, verify canonical vectors and peer/CLI interoperability as well as local round trips.

Review dependency advisories against the exact locked versions separately from functional tests. An empty advisory result is time-dependent and does not establish that dependencies or their uses are safe.

Local tests establish only their exercised behavior. They do not prove economic stability, resistance to coordinated trading, sustained ASIC delivery, hardware location, production uptime or an independent security audit. Deployment claims require observations from the actual processes and chain being described. See [review scope and limitations](AUDIT.md).

Funded economic process tests use a separately built `test-fixtures` executable and an explicit `test_work: true` configuration. Their reports identify the accelerated one-expected-hash-per-atom issuance. Ordinary builds reject those networks. Production issuance is checked separately at one petahash per atom, including zero-reward blocks, per-block rounding and branch changes; accelerated balances do not establish production funding.
