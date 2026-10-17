# Solo mining

Hashstash exposes optional Stratum V1 for SHA256d ASICs. Mining configuration belongs to the node operator. Wallet selection and the public UI cannot change the payout identity or start software mining. A Stratum username is only a worker label: every accepted block pays the node's configured public key or address. Pool share accounting and multi-user payouts are not implemented.

```sh
hashstash run --config network.json --data chain.sqlite --miner '<address>' --rpc 127.0.0.1:18480 --p2p 0.0.0.0:18481 --stratum 0.0.0.0:18482 --stratum-share-difficulty 65536 --stratum-advertise example.net:18482 --stratum-password-file mining-password
```

`--stratum-advertise` takes a bare reachable `HOST:PORT`; the interface adds the `stratum+tcp://` scheme, and startup rejects a value containing one. Use a password file whenever Stratum binds a non-loopback address.

Optional `--stratum-password-file PATH` requires its password at authorization. Restrict file access and never put credentials into a public endpoint. `--no-stratum` runs a validating/relaying node without a mining listener. Keep private RPC loopback-only. The public browser page exposes mining status under Explorer → Network, without administrative controls.

For a fresh network, `init --preset slow --hashrate 100T` calibrates initial work to estimated hashrate. The resulting configuration fixes a new chain identity; do not edit the genesis of a running chain. ASIC work on an extremely easy development target can overwhelm a small node. The three presets alone do not establish production safety.

## Reporting shares and block rewards

Share difficulty is a reporting threshold, not block difficulty or a payout contract. The assigned reporting target is capped at the network difficulty so valid blocks can be reported. Each job retains its own assigned difficulty. `mining.suggest_difficulty` respects the configured reporting floor before that cap. BIP310 minimum-difficulty requests are accepted only if compatible with the easiest representable network target; otherwise they return false.

Only canonical blocks earn issuance. Each block contributes floor(2^256/(target+1)) physical expected hashes. The block issues one atom (0.001 hash) per whole petahash of expected work and discards any smaller fraction. A low-work block can therefore issue zero atoms. Losing-parent jobs are rejected; losing blocks cannot later earn rewards. Transaction fees transfer existing hashes: the miner receives the governed percentage of each entire actual paid fee and revenue receives the remainder.

Accepted/rejected shares, workers and estimated hashrate are local statistics and reset on process restart. A found block may be removed by reorganization. Worker labels and counters do not authenticate hardware or geographical location. Short hashrate estimates are noisy.

## Time and wire format

Timestamp ASERT uses a default 15-second interval. Governance may set any positive whole-second interval that keeps the scheduled clock and deadlines representable. The presets fix a 900-second half-life, 11-header median and 120-second future allowance. Each timestamp must exceed its parent median and remain within the future allowance. ASERT starts from each branch's first mined block, so an unmined genesis can wait without creating a difficulty catch-up period. The first two blocks use the initial target. Later target changes preserve the accumulated branch schedule. Auction lead and rest use scheduled seconds, advancing by the parent's target interval per block. Decisions last a fixed number of blocks and count which completed parent prices lead. Revenue replenishment has no time schedule. Changing the interval preserves auction and rest durations in scheduled seconds; decision length, transaction lifetimes and confirmation counts remain block-based. Header timestamps do not determine these phases.

The 80-byte header has fixed version 0x20000005 and rolling mask 0x1fffe000. The sole coinbase leaf contains HST!, the payout key and a commitment to ordered transactions plus resulting state. Stratum sends an empty Merkle branch. Four-byte server extranonce and four-byte worker extranonce fill the eight-byte input slot. Nonce, valid nTime, extranonce and negotiated version bits may be rolled without recomputing the account transition. The [consensus format](CONSENSUS.md) gives exact encodings.

Supported methods are mining.configure, mining.subscribe, mining.authorize, mining.submit, mining.extranonce.subscribe and mining.suggest_difficulty. New tips replace active work. Pending transaction changes refresh shared cached templates, with periodic refresh as fallback. At most eight active-tip jobs are retained per connection. Duplicate headers across job IDs are rejected.

BIP310 negotiation fixes the exact version mask for six-field submissions. For proxies that never request version rolling, submissions may contain an optional sixth version-bits field within the fixed `1fffe000` mask. An explicit failed request disables this fallback. All submitted bits enter the reconstructed header and its proof-of-work check; bits outside the applicable mask are rejected.

Connections, validation workers, traffic, parsing, jobs and duplicate tracking are bounded. Authorization must finish within 30 seconds. An authorized solo worker may wait for a block without submitting a reporting share. Valid non-block shares are acknowledged without full block execution. See [network controls](NETWORK-HARDENING.md).

## Verification

`python scripts/test_stratum_wire.py` starts a disposable loopback node, independently constructs HST! coinbases and headers, submits reporting shares and blocks, and checks commitment, fees, canonical issuance, timestamp changes, losing-parent rejection and restart persistence. This is a software wire check, not evidence of every ASIC's compatibility. Run `cargo test --locked --test stratum_shares --test mining_adversarial` for bounded-session and competing-work tests. See [validation](VALIDATION.md) for completed results.
