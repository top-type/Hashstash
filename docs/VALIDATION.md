# Hashstash 0.34.0 validation

This is a historical record, retained with its original results and subsequent review notes. The repository now contains version 0.36.0; the totals below do not claim that version was rerun against every historical check. Referenced `work/...` receipts belong to the original private workspace and are not distributed with the source. See [the current development commands](../README.md#develop-and-test) to repeat the maintained checks.

Validation covers immediate trading from genesis, reserve accounting, governance and the current record domains. Transactions share the governed block capacity. Grant lists have no independent recipient-count cap: their signed bytes and prepaid execution weight must fit the proposal block.

Run `cargo test --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo fmt --check`, and `node scripts/test_all_frontend.cjs` from the project root. Maintained Python tests use the rebuilt executable selected by `HASHSTASH_TEST_BINARY`. Independent network scenarios use disposable loopback chains.

The baseline full local run on October 15, 2026 passed these checks. Each Rust total is one complete all-target run; the separate release benchmark repeats an existing test and is not added to the total.

| Check | Result |
| --- | --- |
| Rust, Windows | 391 tests passed; no failures or skips |
| Rust, Linux | 391 tests passed; no failures or skips |
| Frontend | 24 suites, 15,007 assertions passed |
| Python unit discovery with rebuilt CLI | 142 tests passed, no skips |
| Wallet and address integration | 28 checks passed |
| Adversarial wallet validation | 44 checks passed |
| Encrypted-mail wire integration | 16 checks passed |
| Stratum wire integration | 24 scenarios, 202 assertions passed |
| Independent reserve network | 11 checks passed |
| Independent adversarial economics | 8 checks passed |
| Clippy and formatting | Windows all-target warnings denied; formatting check passed |
| Release executables | Windows and Linux builds passed |
| Windows launchers | 62 checks across five suites; rental-version guard and 15 script parse checks passed |
| Linux launchers and installer preflights | 46 launcher, 12 node installer and 7 mixer installer checks passed |
| Three-node load | 3,072 transactions in 12 waves; 66.4-67.2% execution-weight occupancy; balances, fees and node agreement verified |
| Restart after load | All three nodes reopened at height 306 with identical tip, state root, balances and governance |

Rust documentation tests ran on both platforms and collected zero examples. All six Linux shell scripts passed Bash syntax checks. The browser cryptography bundle reproduced byte-for-byte from its installed pinned dependencies.

Grant tests cover canonical ordering, duplicates, aggregate funding and budgets, upfront recipient work, miner overlap, exact PASS payments, FAIL with no payments, atomic rejection, rollback and deterministic replay. The largest capacity-derived list has 31,714 recipients; the next recipient is rejected. Settlement is tested over 10,000 existing accounts with an actual 2,048-byte closing block body fully occupied by ordinary transaction data. Mandatory settlement does not consume that block's ordinary capacity.

Capacity checks cover transactions larger than the former 4 KiB limit, a real browser signature over 256 KiB of data, large cold-signer imports, governed capacity reductions, peer relay, and historical messages after a capacity reduction. RPC proposal pages are bounded before generic JSON allocation; wallet snapshots omit full pending payloads, while hex retrieval preserves complete signed records. Paging tests check that no overflow row is skipped or repeated.

The reserve-network scenarios cover immediate voluntary trading, fee conservation, waiting revenue, a buffered grant that resolves as a price tie, a reserve-funded grant paying every recipient, and exact rollback and replay across competing branches. Browser signing checks use an independent encoder and reject changed recipients, amounts, ordering and stale asynchronous reviews.

This run found and fixed CRLF line endings in the Linux deployment files and stale assumptions in the load-test setup. Linux deployment text now uses LF, with a repository line-ending policy and archive verification. No Rust, consensus or wallet implementation changes were required.

An immediate pre-restart comparison failed without retaining its differing snapshots. A subsequent probe captured nodes at heights 306/303/303 converging to identical state within 0.5 seconds; the controlled restart then preserved exact state. The original comparison's exact cause was not established retrospectively.

Workspace logs and receipts are under `work/local-test-current`. Python and independent network checks used Windows node SHA256 `c08a6534b5e2e98e94a14f9cd683b14520ff65d930f7d3589af5f615493f281a`. Disposable processes were stopped and generated fixture databases and keys removed. Cloud services were not accessed or changed.

The subsequent local correctness review fixed mixer status after refunds: unfilled payout slots are cancelled when the refund confirms, and the queue excludes refunded or completed requests. Its regression first reproduced three phantom queued outputs after one payout and two refunds, then passed with exact customer balances and the earned service fee preserved. Block-persistence tests interrupt three SQL write stages and verify unchanged history after reopening and successful identical retry.

The Mail sender-verification gap was reproduced and fixed locally. The feed now carries canonical signed transaction bytes. Before decryption or cache advancement, the browser verifies BIP340 signatures, transaction IDs, chain identity and the signed sender, nonce, ciphertext and operation. Cache restoration repeats verification; unsigned checkpoints are not reused. Tests cover fabricated feed metadata, unsigned or damaged records, cache corruption, all operation layouts, Rust/browser signing interoperability, large grant carriers and derived-index rebuilds. This authenticates the publishing key but does not independently prove chain inclusion, confirmation counts or completeness of the node's history. Browser assets remain trusted.

Further pagination checks fixed account-event cursors above 100,000 and block transaction offsets above the former hardcoded 4,096 limit. Existing response count and byte bounds remain. Four new mixer tests cover 11 injected SQL failures across deposits, outgoing journals, payouts, refunds and expiry; each checks rollback, reopening and retry. These simulate statement failures, not disk corruption or power loss.

After these changes, Windows and Linux each passed all 400 Rust tests with no failures or skips. All 24 frontend suites passed (15,357 assertions); Windows Clippy with warnings denied and formatting passed. Both platforms' release executables and local packages were rebuilt. Current receipts are under `work/bug-hunt-current`; the baseline integration receipts remain under `work/local-test-current`.

The dependency review queried the npm registry for 29 locked browser packages and OSV for 225 crates.io versions. The browser audit reported no known advisories. Rustls was updated from 0.23.45 to 0.23.46; the precise lockfile update changes only that package. The subsequent OSV check no longer matches the four rustls advisories. Bincode 1.3.3 retains [an informational unmaintained notice](https://rustsec.org/advisories/RUSTSEC-2025-0141.html); replacing its protocol encoding requires a separate review. Cargo-audit was unavailable, so this is package/version advisory matching, not complete reachability analysis or a guarantee of safety. Evidence and official release sources are in `work/bug-hunt-current/dependencies`.

The broad security review remains incomplete. Automated cybersecurity filtering interrupted the earlier delegated consensus, network and wallet reviews. The specifically requested Mail remediation and the local correctness checks above are complete; they do not substitute for a complete independent security audit. Cloud services were not accessed or changed.

A same-chain deployment preflight found that an idle genesis was counted as ASERT delay: the day spent waiting before mining would have reduced the second block to the easiest target. ASERT now anchors each branch to its first mined block while retaining the economic schedule. The first two blocks use initial difficulty. Delayed-start, competing-anchor, reorganization, reopen and interval-governance regressions passed, followed by 402 Rust tests on each platform, 24 frontend suites (15,357 assertions), Clippy, formatting and both release builds. Receipts are under `work/testnet-current`. This changes consensus validation: all existing height-zero nodes must be upgraded before any mining starts. It does not change ASERT behavior after later mining outages.

Local tests do not establish production security or physical ASIC delivery.
