# Changelog

## 0.43.0

The release for the launch network. It covers every change since 0.42.0 (commit `cfaaeb8`): the audit fixes (findings F001 to F180), the review follow-ups (R01 to R42) and the release preparation. The [launch runbook](docs/LAUNCH.md) turns the required actions below into steps.

**0.43.0 is incompatible with 0.42.0 in consensus, signatures, peer protocol and storage.** Its blocks commit to a different state encoding (every state root changes, genesis included), its transaction signatures bind the chain ID, and its peers and databases carry new format markers. A 0.42.0 chain cannot be continued or upgraded in place, and the two releases cannot share a network. Breaking changes are marked **Breaking** below.

### Required operator actions

1. **Every node runs 0.43.0; there is no mixed network.** A 0.42.0 node and a 0.43.0 node refuse each other at the first message. The refusing node records an error naming the other release (see [Peer protocol](#peer-protocol-and-synchronization)).
2. **Create a fresh genesis with 0.43.0** (`hashstash init --config network.json --preset slow --hashrate RATE`) and distribute that one file unchanged, with its SHA256 and chain ID, to every operator. Do not reuse a 0.42.0 `network.json`: the same file would give the new chain the old chain's ID, and so its addresses and wallet storage, while its blocks are incompatible. `--preset slow` now refuses to run without `--hashrate` (or an explicit `--uncalibrated`).
3. **Start every node on a new, empty database** (`--data` path, or an empty `/var/lib/hashstash`). 0.43.0 refuses a database holding 0.42.0 blocks with an error that names that release; keep old data only for the old release.
4. **Fund accounts again on the new chain.** Keys remain valid, but balances do not carry over, and every transaction signed or exported by 0.42.0 is invalid under the chain-bound signature domain. Prepare and sign transactions again with 0.43.0 tools. `hashstash sign` now needs `--config` or `--chain-id`; the cold signer needs the new network selected (Explorer → Network → Identity → Export network).
5. **Reinstall the Linux service from this source snapshot.** The installer pins version 0.43.0 and the binary's full SHA256 and refuses to replace an existing installation. Review the new `node.env` fields `ALLOW_EASY_TARGET` and `STRATUM_TRUSTED` and the changed nginx template (nginx 1.15.7 or later).
6. **Give every non-loopback Stratum listener a password file.** `run` refuses to start one without it.
7. **Update tools that use the private RPC session token.** `GET /api/session` no longer returns it; read the owner-only `<data>.session-token` file written at each start (for example `chain.session-token` beside `chain.sqlite`).
8. **Handle HTTP 429 and 503 with `Retry-After`** in any client, monitor or proxy of the node's HTTP listeners. Admission refusals are now answered instead of dropping the connection.
9. **Use a new faucet ledger** for the new network, and review the faucet's new `subnet_daily_claims` setting.

### Consensus

All of the following are **Breaking**: a 0.42.0 node rejects 0.43.0 blocks and the reverse.

- **State commitment (R04).** Every authenticated state map is committed as a binary Patricia trie over `tagged_hash("Hashstash/TriePath", key)`, with `TrieLeaf`, `TrieBranch` and `TrieEmpty` tags, instead of a treap whose depth users could grind. Depth is at most 256 for any keys. Every state root changes, genesis included. Independent vectors in `tests/commitment_encoding.rs` pin whole state roots and phase commitments ([consensus format](docs/CONSENSUS.md#state-commitments)).
- **Proposal actions and phase commitment.** A proposal's action is stored once in a write-once `actions` map committed after the proposals root; `ProposalRecord` keeps round, proposer, description, support and refund height. The phase is committed without the decision's copy of its proposal.
- **Chain-bound signatures.** The signing message is `tagged_hash("Hashstash/chain-bound-transaction", chain_id || encode(body))`. The chain ID is still not part of the transaction bytes; each node verifies against its own chain ID, so a signature takes effect on one network only.
- **Proposal IDs bind the proposer (F075):** `tagged_hash("Hashstash/proposal", encode((chain_id, round, proposer, description, proposal)))`, with a committed `proposer` field. A copied pending Propose from another sender registers a separate proposal.
- **Decision ID (F179, F108)** hashes `(chain_id, round, proposal_id, height, parent_hash)`, so same-parent siblings share it.
- **Symmetric PASS and FAIL opening (F010).** FAIL sets the grant's reserve shortfall aside as waiting revenue, so both outcomes open on identical curves; neither world replenishes during a decision, and the selected world refills in its resolution block. A grant draws all waiting revenue but at most half of the reserve. The winning bid becomes revenue only after the grant is reserved.
- **Empty worlds (F014).** A block in which either world holds no Stash adds no PASS lead.
- **Auctions (F016).** A proposal that cannot open its decision is cancelled when it reaches the top instead of taking the lead. When a leader is cancelled, the most recently displaced active proposal resumes its recorded lead start. At the auction timeout an eligible leader opens its decision even before its lead matures.
- **Record weight (F046).** Every Propose, and a Support that creates the sender's support record for a proposal, adds 1,024 execution weight. Fee quotes report it as `record_fee`.
- **Governed-parameter bounds (F012, F015, F028, R01, R05).** BlockBytes is from 4,096 through 64 MiB at genesis and under governance. Governed changes, not genesis, must also keep: BlockBytes and Interval within half or twice the old value; Interval at most the ASERT half-life and at least a quarter of its genesis value; Lead at most half of the auction timeout less one interval; Rest at most 2^22 seconds; DecisionBlocks at least 3 and at most 2^22 seconds long; MaxPriceChangeBps from 1 through 9,999; a positive MinimumFeeRate of at most a doubling per decision and 2^16 times the genesis rate; a PASS margin reachable within the decision; and a schedule representable through the whole remaining height range. An overflowing Rest deadline saturates instead of invalidating blocks.
- **Flat-curve execution (F005).** Each order on a flat curve receives its rounded-down output at the exact price and pays the least input for it; the rest is refunded. When inexact sales alone break the price bound on a flat world, the budget search falls back to the sale side, then to both sides. A world refilled to flat stays tradeable.
- **Bounded batch clearing (F006, F047).** Clearing spends at most 1,024 curve evaluations per world, with a deterministic conservative fallback, logarithm precision sized to the inputs (4b+128 bits, at most 2,048) and a specified root search.
- **ASERT anchor (F029).** The first-block anchor is bounded below by the second block's timestamp less one interval.
- **Common credits (F158, F160)** require identical account existence and nonce in both worlds, and broken invariants in execution return errors instead of panicking.

The coinbase height push, the canonical codec and the pinned `bincode`, `serde` and `num-bigint` encodings are unchanged and now pinned by vectors.

### Peer protocol and synchronization

- **Breaking: peer protocol generation marker.** Every peer payload starts with `HSP2P043` instead of `HSP2PBIN`, and the authenticated handshake with `HSP2A043` instead of `HSP2PAUT`; the marker is part of the signed handshake transcript. The suffix names the release that introduced the rules a node enforces. For the same genesis file, 0.42.0 and 0.43.0 compute the same chain ID and share the framing, so without the marker they exchanged addresses and records that failed validation on the other side ("no common ancestor", "early eof"). Now a node refuses another generation's first frame or greeting before decoding it, closes, and records "peer runs Hashstash 0.42.0 or earlier (peer protocol HSP2PBIN)" in the `peers` RPC. A 0.42.0 node refuses this release's frames as an invalid format, which the 0.43.0 side reports as a peer that closed the connection on a header request, a locator request or the authentication handshake, naming 0.42.0 as a possible cause. `tests/node_transport.rs` checks both directions.
- **Headers-first synchronization (R09), transport version 2.** Outbound sessions open with up to four header requests (tag 4) answered by at most 2,000 consecutive 80-byte headers (tag 5). A node counts a branch's claimed work from its headers before holding any, so a heavier branch is followed whatever its blocks' size or its distance; held headers are bounded at 65,536 and admitted ones persisted in a `held_headers` table. Peers that close two consecutive sessions on a header request are synchronized by blocks only for ten minutes (`version1_peers` in `peerstatus`).
- **Side branches.** Declined side blocks are presynced as headers (at most 32,768) instead of refused for good. Side-branch storage draws on a budget refilled by active-chain growth; replay of side blocks is bounded before it runs and executed off the node lock. Stale losing branches are pruned at startup.
- **Admission and slots.** Peer record admission follows the greatest validated capacity plus 1 KiB instead of a 32 MiB floor; a connection's first message is bounded to a locator request; buffered frame memory is reserved as bytes arrive and shared node-wide. Inbound peers have 16 general slots with group caps and reserved slots for configured, pinned and verified peers; a newcomer can evict an unprotected session. Admission is charged per address and per prefix (IPv4 /24, IPv6 /48, 6to4's embedded /24).
- **Discovery.** Address-book replacement instead of refusal, two learned endpoints per IP, configured peers not gossiped, anchors (the last two verified outbound peers) tried first after a restart, atomic saves.

### Signing and keys

- **Breaking:** chain-bound transaction signatures (above). Every signer binds its selected network: the CLI, node wallet, faucet, browser wallet and cold signer. `hashstash sign` requires `--config` or `--chain-id` and refuses an export prepared for another network.
- **Passphrase keys.** New `hashstash-passphrase-v2`: scrypt (N = 2^17, r = 8, p = 1) salted with the chain ID, at least 16 printable ASCII characters. The unsalted v1 scheme is restore-only behind an explicit acknowledgement.
- **Encrypted keys at rest (R13).** Browser wallets can seal saved keys under a passphrase (`hashstash-browser-lock-v1`: PBKDF2-HMAC-SHA256, 600,000 iterations, AES-256-GCM), with an idle lock and timed clipboard clearing. `run --wallet-passphrase-file PATH` encrypts the node wallet's hot keys (`hashstash-node-wallet-lock-v1`, ChaCha20-Poly1305); an encrypted store opens only with the passphrase, and 0.42.0 refuses it.
- **Cold signer.** Random key generation with a one-time backup, reviews only for an operator-selected network, warnings and confirmation for lifetimes above 1,000 blocks, review limits (`--max-review-bytes`, `--max-review-payments`), a session token delivered only in the launch URL's fragment, an idle lock (`--idle-lock-seconds`, default five minutes), at most 16 connections, and core dumps disabled.
- **Secret files.** Wallet stores, key files, peer identities, faucet keys and session tokens are owner-only on every platform; on Windows a failure to restrict a file on an NTFS volume is an error, and key files that other accounts can read are refused.

### Storage

- **Breaking: storage format marker.** The chain database records `hashstash-storage-043` in its metadata. A database holding 0.42.0 blocks (same configuration row, no marker) is refused at startup by name instead of failing replay with "unknown parent"; an empty one takes the marker. 0.42.0 refuses a 0.43.0 database because its blocks do not validate there.
- **State checkpoints (R08).** The node saves the state 31 blocks below the tip every 1,024 heights and at a clean stop, keeping two, and starts from the newest one that its own executable saved after verifying its root, audit, index entries and descendants. Any doubt, or a different binary, means a full replay ("Ignoring state checkpoints saved by another build"). A crash replays at most about 1,055 blocks.
- **Startup.** The derived index rebuild commits in batches of 4,096 blocks and the WAL is truncated afterwards; invalid losing-branch blocks move to `rejected_blocks`; the SQLite build must be able to store the largest valid block.
- **File names.** Files beside a chain database are named from its full file name. `NAME.sqlite` keeps `NAME.wallets.sqlite`, `NAME.explorer.sqlite`, `NAME.peer-key.json`, `NAME.session-token`, `NAME.peers-CHAIN_ID.json` and the new `NAME.stratum-trusted.json`; any other name `F` uses `F-wallets.sqlite` and so on.
- **Explorer index** schema bumped (rebuilt at first start); transaction data is stored in its own table; reorganization recovery uses chain checkpoints; the worker is supervised and retries.
- **Dependencies.** `rusqlite` 0.39 with bundled SQLite 3.51.3 (CVE-2025-29087, CVE-2025-6965).

### Node, RPC and HTTP

- **429 and 503 refusals.** Admission refusals (cooldowns, exhausted request, byte or work budgets, connection quotas) are answered with HTTP 429 and `Retry-After`; busy shared capacity with 503 and `Retry-After: 1`; a charge that can never fit with 400. Accept-time answers are limited to one per `Retry-After` window per address. The CLI, web UI and faucet report the message and the wait.
- **Lock scheduling (R02, R03, R07).** Newcomer selections share a node-wide lock-time budget (relays and the operator 200 ms/s, public broadcasts 50 ms/s); relayed newcomers queue; blocks are executed off the node lock; batch trades are cleared only when a template is built, outside the lock.
- **Block submission (L021, L090).** A copy or child of a block being validated goes on as soon as that block is stored, ahead of the transaction admission its storing starts, instead of waiting for that admission too. Reorg replay for a block that would become the tip is sized by time: one historical block in its first node-lock hold, then as many as fit 50 ms at the pace the previous hold measured, at most eight, instead of always eight.
- **Mempool.** No hard count gate: selection ranks by fee rate, with a backlog of 256 entries that lost only to capacity; spends from accounts that a pending transfer creates wait for the funding; a validity refusal holds that sender nonce for relayed and broadcast copies until the pool or tip changes.
- **RPC.** New `blockreceipt`; `account.pending_nonce`; keyed snapshots carry `sender_mempool`; `proposals` pages by round with a tip pin; `support` reports a status; fee quotes report `record_fee` and a `scheduled_change` due within the lifetime; large grants are summarized in snapshots; reads are priced by the work they do. Conditional trades are refused at a decision's last tip ("conditional trading is closed").
- **Development mining.** `mine` runs only on a development network that untrusted peers cannot reach, unless `--dev-rpc`.
- **Public website.** The node accounts each visitor named by the loopback proxy's `X-Real-IP` (6 sessions, a share of the budgets), keeps a quarter of the budget for wallet calls, and requires request heads within 5 seconds. Session tokens are never served over HTTP.
- **Process health.** A poisoned lock or a panic in a long-lived task exits with status 70 for a supervised restart.
- **`peerstatus`** adds `transport_version`, `version1_peers`, `capacity_allowance` and listener accept errors; `chain_stalled` scales with the governed interval.

### Mining

- **Breaking for operators:** a non-loopback Stratum listener requires `--stratum-password-file`.
- Unauthorized connections use a separate 128-slot pool with a 10-second authorization window charged to a per-address budget; the 256 most recently authorized addresses, and `--stratum-trusted ADDRESS[/LENGTH]` prefixes, keep 32 reserved slots (persisted in `NAME.stratum-trusted.json`). Authorized workers ignore cooldowns, so a solved block is never discarded by a budget.
- Job retention retires the oldest same-parent job instead of flushing all; same-parent refreshes reach a connection at most every two seconds; rate-based vardiff; `blocks_found` counts only selected blocks.
- **Templates (L022, L071, L091).** Each template build is claimed for the tip it extends, so one parent is never built twice at once and an older build never replaces a newer one. A build that a new tip overtakes stops at its next step on every attempt. After three such builds, as during catch-up, Stratum and the development `mine` method get an empty template for the current tip, which is not stored, and Stratum asks for the full one at its next refresh. A template that cannot be finished with its whole selection logs the first transaction it left out, and later templates for that tip leave it out with its sender's later nonces; they stay pooled for the next tip.

### Command line and genesis

- `init`: `--preset slow` requires `--hashrate` or `--uncalibrated`; `--hashrate` caps the easiest target at 256 times the calibrated one; `--genesis-time`; warnings for an easy limit (naming the minimum rate, 73.4G at 15-second blocks), a future genesis and unsafe but valid genesis values.
- `run`: refuses a non-loopback `--p2p` or `--peer-discovery` on an easy proof-of-work limit unless `--allow-easy-target`; `--preflight` makes every pre-database check and exits; refuses a peer identity equal to a wallet key, an empty or malformed Stratum password file, and warns when `--public-web` serves plain HTTP on a non-loopback address.
- RPC client: plain HTTP only to loopback unless `--insecure-http`, no proxies or redirects, bounded replies; `send`, `transfer` and `prepare` cap automatic fees (`--max-fee`), accept `--nonce` and `--anchor-url`, require a network pin for a non-loopback `--url`, verify remote nonce claims and print a review before signing.

### Deployment

- `deploy/linux/install.sh` pins 0.43.0, stages every input in a private directory before hashing and installing it, runs the service's own `run --preflight` in `--check`, and never replaces existing files. The unit adds system-call, namespace, `/proc` and core-dump confinement, restart back-off (`RestartSteps=8`, `RestartMaxDelaySec=2min`) and an out-of-memory message.
- `node.env` gains `ALLOW_EASY_TARGET` and `STRATUM_TRUSTED`. The nginx template overwrites `X-Real-IP`, limits each client to 2 JSON-RPC requests per second (burst 20) and 6 connections, all clients to 32, and needs nginx 1.15.7 or later.
- `scripts/release.sh` builds the release binaries reproducibly (`--locked`, pinned toolchain, remapped paths, no `test-fixtures`) and writes `SHA256SUMS` and `BUILDINFO`; `--verify` rebuilds and compares.

### Faucet

- Reorg-safe accounting: consumed nonces are reconciled on every refresh, reorganized receipts relocated or expired, and each nonce pays at most one claim. New operator commands `--inspect`, `--accept-spent-nonce` and `--clamp-future-claims`.
- Limits: `subnet_daily_claims` per IPv4 /24 or IPv6 /56 (default 10), exact fee and capacity checks before signing, claims deferred before a scheduled fee or capacity change, 64 connections with a 5-second head deadline, and 429/503 handling.

### Wallet and interface

- Nonces predicted from the whole pool, quoted weight re-derived before signing, submissions followed by sender nonce ("No longer pending", "Mined or replaced"), governed bounds checked before signing, partial grant summaries, fee-locked outcome accounts named, mail scans that resume at fork heights, and visible escapes for bidirectional and invisible characters in Chat, Mail, proposals and the Explorer.

### Validation

- Continuous integration (`.github/workflows/ci.yml`): formatting, Clippy in both configurations, Linux and Windows suites, frontend and Python checks, nightly network suites, and fuzzing.
- Fourteen coverage-guided fuzz targets over every parser of hostile input, a stable seeded runner in the test suite, and kept regression inputs.

### Accepted limitations

These are documented design limits, unchanged by this release; tell users about them. See [the launch runbook](docs/LAUNCH.md#15-limitations-users-must-be-told).

- Stash orders have no limit price or minimum output; orders sharing a block, which a miner can arrange, move each other's price within the per-block bound.
- The default PASS margin is 0 basis points. On flat or nearly flat curves integer rounding alone can move a price, and at the genesis exchange rate nothing moves, so a revenue-funded grant or setting change on that baseline resolves FAIL.
- A bidder with liquidity can delay another proposal's opening until the auction timeout at the cost of fees.
- Each block issues whole atoms of one petahash of expected work; the remainder is discarded, which loses a large share of issuance on a small network.
- Peer transport is authenticated but not encrypted, and Stratum V1 is plain TCP.
- Mail has no forward secrecy: a compromised account key exposes past mail.
