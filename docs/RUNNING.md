# Node operation

Hashstash 0.38.0 accepts protocol 28 configurations and compact binary records. The node requires a 64-bit target. Genesis identifies the chain. A database must use its exact genesis configuration; changing that configuration creates a different identity, affecting addresses, application caches and chain-scoped faucet ledgers.

Source builds place executables in `target/release`; packaged releases place them in `bin`. The PowerShell launchers prefer the source build when present. Examples using `bin` assume the packaged layout.

```sh
hashstash init --config network.json --preset slow
hashstash keygen --out miner.key
hashstash run --config network.json --data chain.sqlite --miner PUBLIC_KEY --rpc 127.0.0.1:18480 --p2p 0.0.0.0:18481 --stratum 0.0.0.0:18482 --peer-discovery --seed SEED_HOST:18481 --advertise-peer YOUR_PUBLIC_IP:18481
```

The node needs only the public mining key. Keep any private backup inaccessible to untrusted users. `--no-stratum` disables the mining listener without disabling validation or relay. Mining payout and listener/password/reporting settings are operator configuration, not wallet controls. See [mining](MINING.md) and [Linux deployment](../deploy/linux/README.md).

`--wallet-key PATH` and `--watch-key ADDRESS` are mutually exclusive opt-in server-wallet modes for private operator tooling. Without them the server wallet database starts empty. Browser wallets are independent and sign locally. The separate cold signer requires no node connection to review/sign exported transactions. See [wallets](WALLETS.md).

## API boundaries

Private JSON-RPC is POST `/rpc`, envelope `{jsonrpc:"2.0",id,method,params}`. RPC must bind loopback. Public-web mode exposes an allowlist of reads and signed-transaction submission without server-wallet management, secret material, software mining, configuration changes or arbitrary private methods. Serve browser wallets through HTTPS or localhost.

JSON amounts are canonical nonnegative decimal integer strings; hashes and keys use documented hex strings or 32-byte arrays. RPC currency values are raw atoms. The UI converts 10^18 atoms to one hash and 10^36 share atoms to one stash.

Read methods include status, config, snapshot, account, governance, proposals, support, quote, stash_quote, fee_quote, grant_quote, mining, getblock, peers and peerstatus. Explorer has separately paginated public methods documented [here](EXPLORER.md). Snapshot binds related reads to one published tip/state. Quotes are estimates under their stated state; the exact signed fee and minimum outputs determine execution.

`proposals` and `mempool` accept `offset` and `limit` (up to 128); response byte and JSON-value budgets may end a page sooner. Advance the offset by the number of rows returned until an empty page. Snapshots include pending transaction metadata and operations, without arbitrary data or signatures. For complete large pending transactions, request `mempool` with `format: "hex"`; each row contains `txid` and the full signed `raw` record. Default JSON mode preserves the ordinary transaction fields when they fit the bounded JSON page.

Private development methods can mine or submit candidate blocks. Use those only on explicitly selected disposable fixtures. Public signed transactions carry their sender, nonce, chain ID, exact fee, expiry and operation/data; the node verifies them before mempool admission. Wallet mutation endpoints require their local session token and exact wallet revision.

## Peers

Peers exchange length-framed binary synchronization batches containing chain identity, block locators, canonical block records and canonical signed transactions. Each batch is limited to 128 locator hashes, 32 blocks and 256 loose transactions, with separate byte limits. RPC and Stratum remain JSON interfaces. See [network controls](NETWORK-HARDENING.md#binary-peer-transport) for framing and allocation limits.

Configured peers must use the same binary transport and chain identity. Transport keys are separate service identities.

### Joining a public network

Obtain the network's exact genesis configuration and a reachable seed from its operators. Do not create a new genesis to join an existing chain. Start with `--peer-discovery --seed HOST:PORT`; repeat `--seed` for independent bootstrap sources. There are no universal or hardcoded test-network seeds. DNS seeds resolve to numeric endpoints; discovered addresses are always numeric. `--peer IP:PORT` can also provide an explicitly configured bootstrap endpoint.

Discovery uses signed transport sessions. If `--peer-key-file` is absent, the node creates a dedicated `chain.peer-key.json` beside `chain.sqlite`, without overwriting an existing identity. It never uses a wallet, faucet or mining secret. A successful seed synchronization is followed by address exchange. The node checks learned endpoints by synchronizing with them before relaying them, remembers reachable peers in `chain.peers-CHAIN_ID.json`, retries with backoff, and continues through those peers if the initial seed disappears. Restarting with the same database reloads that chain's peer book even without a seed argument. Losing all saved peers still requires a reachable bootstrap source.

To accept inbound joins, bind `--p2p 0.0.0.0:18481`, open/forward that TCP port, and set `--advertise-peer YOUR_PUBLIC_IP:18481`. Use `[IPv6]:PORT` for IPv6 endpoints. No NAT traversal or automatic public-IP lookup is performed. An outbound-only node can still discover, validate and relay by polling its peers, but it does not advertise an unreachable listener. The public protocol rejects private/reserved gossip; isolated LAN/test fixtures must explicitly select `--allow-private-peer-discovery` (alias `--allow-private-peers`). Never enable that option on a public seed.

Discovery limits the book to 256 endpoints, each exchange to 32, each source network to 32 candidates, and each destination network to 16 candidates. Source/destination groups are IPv4 /16 or IPv6 /32. At most two outgoing sessions run concurrently, spread across destination groups in public mode. These controls reduce address poisoning and concentration; they do not prove operator independence or eliminate Sybil/eclipse attacks. Use several independent seeds and pinned known peers where available.

### Fixed pinned networks

For closed authenticated transport, create a separate identity with `peer-keygen`, validate with `peer-keycheck`, supply `--peer-key-file`, and pin each `--peer` endpoint with `--peer-pin IP:PORT=PUBLIC_KEY`. Omit `--peer-discovery`. All configured endpoints must have pins in this mode, and discovery is disabled. Wrong key/chain/challenge, changed frames or sequence errors fail closed; there is no downgrade retry.

Open discovery can retain known pins: add `--peer-discovery` alongside the dedicated key and pins. Those endpoint pins are still enforced; an incoming source IP with configured pins must prove one of its pinned keys. Unknown addresses may prove a new transport identity and join. `peer-keycheck --peer-discovery` validates this policy with zero or more pins. Public-key possession is not a trusted real-world identity, and all received blocks/transactions still undergo ordinary validation. Nodes without either authenticated mode retain legacy compact-binary synchronization for explicit peers. Transport signatures provide integrity, not confidentiality.

## Mining and transactions

Stratum V1 serves an HST6 coinbase as the sole Merkle leaf of a Bitcoin-format 80-byte header. External miners supply nonce/extranonce/version rolling and valid timestamps. Current jobs retain their reporting target. Non-block shares are statistics; only accepted canonical work creates hashes. Losing-parent work is rejected. Process counters reset on restart and a found block can later be reorganized out.

Mempool holds at most 4096 transactions. Selection accepts at most 8192 candidates, verifies each unique candidate once, applies operations atomically with bounded retries, and prioritizes fee rate subject to nonce/state dependencies. A pending transaction is not guaranteed inclusion. The declared exact fee is paid in full and must meet the governed weight-based minimum. All of it is split by the governed miner percentage. Block usage does not change the minimum rate.

## Persistence and resources

Each accepted block and selected tip update is committed transactionally in SQLite. Startup validates saved bodies and rebuilds derived indexes. Current tip publication includes block and state together. Reorganizations restore accounts, reserve shape, revenue, grants, fees and governance as one state; no decision is irreversible.

Retained blocks and live account/proposal state grow. The node has bounded hot caches: 128 historical states, 256 header/work entries and an 8 MiB SQLite page cache; deep traversal uses disk-backed temporary storage. These limits do not bound every allocation or total restart time. There is no pruning policy. Back up a stopped database or use SQLite's backup facilities; never edit tables manually.

RPC, peers and Stratum have separate admission, byte/work budgets and worker pools. HTTP reads, peer connections and handshakes time out after 15 seconds. Peer synchronization reads allow additional time for validated block capacity; automatic discovery synchronization attempts allow five times that read allowance overall. Stratum authorization must finish within 30 seconds; authenticated idle miners may wait for work. Requests and decoded structures have explicit size/depth/value limits. Future-dated candidates, unknown parents and deferred history are retryable. Repeated permanently invalid full bodies have a bounded short-lived cache. See [network controls](NETWORK-HARDENING.md) for limits and remaining risks.

Current settings expose eight governance parameters: BlockBytes, Interval, Lead, Rest, Duration, MinerFeePercent, PassMarginBps and MinimumFeeRate. Each proposal sets an exact new value. MinimumFeeRate starts at one raw atom per 1,024 weight and may be set to zero. Interval and Duration use positive whole scheduled seconds; Lead and Rest also allow zero. BlockBytes must cover 1,024 weight and fit the host allocation representation. MinerFeePercent remains 0–100 and PassMarginBps is an unsigned basis-point margin. The node checks integer representation and scheduled deadlines; transport and API admission apply their own resource limits. auction_timeout also uses scheduled seconds. Each block advances economic time by its parent's interval, so an interval change preserves nominal durations. Signed expiry heights, confirmation depth and timestamp sample counts retain their block units. [Consensus](CONSENSUS.md) specifies the byte format and arithmetic.
