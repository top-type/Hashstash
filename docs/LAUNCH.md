# Launch runbook

This runbook takes a new public Hashstash network from a reviewed source commit to a running chain with seeds, miners, a public website and monitoring. It is written for 0.43.0, whose [release notes](../CHANGELOG.md) list every change and required action since 0.42.0. It assumes the [Linux deployment](../deploy/linux/README.md) on Debian or Ubuntu hosts; [node operation](RUNNING.md), [mining](MINING.md) and [network controls](NETWORK-HARDENING.md) give the details behind each step.

Work through it in order. Each section ends with a check; do not continue past a failed check. Run a complete rehearsal on a throwaway genesis before launch day (section 10): every command below works the same way on it.

## 1 Roles, hosts and schedule

Name one person for each role before starting. One person may hold several roles, but each signs off its own checks.

| Role | Holds | Responsible for |
| --- | --- | --- |
| Release manager | Build machine, release signing key | Source commit, reproducible build, `SHA256SUMS` |
| Genesis author | Trusted preparation machine | Calibration, `network.json`, chain ID |
| Node operators | Their hosts, peer identities, Stratum passwords | Installation, firewalls, monitoring, backups |
| Treasury | Offline payout and funding keys | Payout addresses, faucet funding |
| Web operator | nginx host, TLS certificates | Public wallet website |

Plan at least three seed nodes with different providers and regions, plus the mining nodes. Record for every host its public IPv4 address, region, P2P port (18481), Stratum port (18482, mining nodes only), private RPC port (18480, 19480, ... per region), public-web port (18483, website hosts only), payout public key and peer public key.

A five-day schedule:

| Day | Work | Section |
| --- | --- | --- |
| T-5 | Freeze the source commit, run the validation gate, build and verify the release | 2 |
| T-4 | Provision hosts, generate keys, write `node.env` files, open firewalls | 5 to 8 |
| T-3 | Full rehearsal on a throwaway genesis: install, mine, back up, restore, fail over | 10 |
| T-2 | Fix what the rehearsal found; collect miners' committed hashrate | 3 |
| T-1 | Create, publish and pin the launch genesis; install every node | 3, 4, 9 |
| T0 | Start seeds, then miners; verify; open the website; announce | 11 |
| T+1 onwards | Monitor, back up, respond | 12 to 14 |

All hosts must keep accurate time (chrony or systemd-timesyncd). A block more than 120 seconds ahead of a node's clock is deferred, and timestamps drive difficulty.

## 2 Build and pin the release

On a clean Linux machine (WSL 2 works), check out the frozen commit and run the [validation gate](VALIDATION.md#build-and-core-checks) on it. Then build the release:

```sh
git checkout RELEASE_COMMIT
bash scripts/release.sh --verify
```

`scripts/release.sh` builds `hashstash`, `hashstash-cold` and `hashstash-faucet` with `--locked`, without the `test-fixtures` feature, with the pinned Rust toolchain (1.97.1 unless `RUST_TOOLCHAIN` names another) and with the checkout, Cargo and target paths remapped, so the result does not depend on where it was built. `--verify` builds a second time from scratch and fails unless the binaries are identical. It refuses a checkout with uncommitted changes; when git cannot read the checkout (for example a Windows checkout built under WSL) it warns and records no commit, so build releases from a Linux clone. The output directory, by default `target/dist/hashstash-0.43.0-linux-x86_64/`, holds the binaries, `SHA256SUMS` and `BUILDINFO` (source commit, `Cargo.lock` hash, compiler, C compiler and C library versions).

Have a second person build the same commit on another machine with the same Rust and C compiler versions and compare `SHA256SUMS`; they must be identical. Then sign the file with the release manager's key, for example `gpg --armor --detach-sign SHA256SUMS`, and keep `BUILDINFO` with the deployment record.

Check: both builds agree, `./hashstash --version` prints `hashstash 0.43.0`, and `sha256sum -c SHA256SUMS` passes.

## 3 Create and calibrate the genesis

The genesis file fixes the network's identity, initial difficulty, easiest permitted target and initial governance settings. Every node must use the same file; create it once, on the genesis author's machine, with the release binary.

Choose `RATE`, the aggregate SHA256d hashrate expected in the first hours: the sum of the miners' committed machines and rentals, not their hoped-for growth. Calibration sets the initial target so that `RATE` finds one block per 15-second interval, and sets the easiest permitted target 256 times easier.

- Too high a `RATE` makes the first blocks slow until difficulty eases (the ASERT half-life is 900 seconds). Too low a `RATE` makes them fast until it rises. Stay within a factor of two to four of the real figure.
- Difficulty can never fall below the easiest target, so the chain cannot follow a hashrate collapse of more than 256 times.
- A public listener needs a `RATE` of at least 73.4G (2^40 hashes per block at 15 seconds); the node refuses an easier genesis behind a public P2P listener or discovery.
- Issuance discards the fraction of a whole petahash of expected work in each block. At 100 TH/s about a third of work-implied issuance is lost; at about 7 PH/s or more the loss is below 1% ([mining](MINING.md)). Tell miners what loss to expect at the launch rate.

Create the file:

```sh
./hashstash init --config network.json --preset slow --hashrate 2P
./hashstash network --config network.json
sha256sum network.json
```

Replace `2P` with your `RATE` (`K`, `M`, `G`, `T`, `P` and `E` suffixes are accepted). `init` records this computer's clock as the genesis time, prints it and the chain ID, and gives the network a random name, so every run creates a different chain. Creating the genesis a day early costs nothing: difficulty is anchored at the first mined blocks, so waiting before mining does not lower it. Do not set a genesis time in the future; nodes defer block 1 until it.

The slow preset's settings are the reviewed launch values: 15-second interval, 16 KiB blocks, 240-block decisions, 300-second auction lead, 3,600-second auction timeout, 10,800-second rest, a 10% per-block price bound, a 50% miner fee share, a minimum fee of one raw atom per 1,024 weight and a PASS margin of 0 basis points. Each of them can later change only by a governance decision, within the [governed bounds](SPECIFICATION.md). Treat any edit of the generated file as a protocol decision: make it before publishing, then repeat the `network` and `sha256sum` commands and a `run --preflight` on the edited file.

Check: `init` printed no warning, `network` prints the chain ID that `init` printed, and the genesis author has recorded the file's SHA256, chain ID, genesis time and `RATE`.

## 4 Distribute and pin the binary and genesis

Publish, through at least two independent channels (for example the project website over HTTPS and a signed announcement):

- the release binaries, `SHA256SUMS` and its signature;
- `network.json`, its SHA256 and its chain ID;
- the seed endpoints (section 6) and the public website address.

Every operator, and every user who runs a node, verifies the signature on `SHA256SUMS`, runs `sha256sum -c SHA256SUMS` and `sha256sum network.json`, and compares `./hashstash network --config network.json` with the published chain ID. The Linux installer takes both recorded hashes (`--sha256`, `--genesis-sha256`) and refuses any other file. Never change `network.json` after publication: any change is a different network.

Check: each operator has confirmed both hashes and the chain ID by a channel other than the one the files arrived through.

## 5 Keys and secrets

Use a separate key for every role. Create spending keys on an offline machine; only public keys reach the servers.

| Secret | Create with | Kept | Used by |
| --- | --- | --- | --- |
| Payout key, one per mining node | `hashstash keygen --out region-a-miner.key`, or the cold signer's **New random key** | Offline, two backups | Nobody online; the node needs only the public key (`MINER_PUBLIC_KEY`) |
| Peer transport identity, one per node | `hashstash peer-keygen --out region-a-peer.json` | `/etc/hashstash/peer-identity.json`, installed by `--peer-key-file` | That node only |
| Stratum password, one per mining node | A random token, for example `openssl rand -hex 32 > mining-password` | `/etc/hashstash/stratum-password` | That node and its miners |
| Faucet key (optional) | `hashstash keygen --out faucet.key` | Faucet host, owner-only | The faucet daemon |
| Treasury and funding keys | Cold signer, **New random key** | Offline | Signed offline, broadcast through the website |
| TLS private key | certbot | nginx host | nginx |
| Node wallet passphrase (only if server wallets are used) | A long random value | A file outside the data directory and its backups | `run --wallet-passphrase-file` |

On the preparation machine:

```sh
install -d -m 700 ~/hashstash-keys
./hashstash keygen --out ~/hashstash-keys/region-a-miner.key
./hashstash public-key --key ~/hashstash-keys/region-a-miner.key
./hashstash address --key ~/hashstash-keys/region-a-miner.key --config network.json
./hashstash peer-keygen --out ~/hashstash-keys/region-a-peer.json
```

`keygen` and `peer-keygen` never overwrite a file and write it owner-only. `peer-keygen` prints only the public key; exchange peer public keys between operators through a trusted channel. Keep key files outside any source checkout. A peer identity proves only that a node holds that key; it is not a spending key, and `run` refuses one equal to a wallet key. Use new keys for the launch rather than keys used on test networks, and record which public key belongs to which host. Keys are not bound to a network, but balances and addresses are, so nothing from an earlier network carries over.

Check: every payout key has two offline backups that someone other than its creator has restored with `public-key`, and no private key is on a server except peer identities, Stratum passwords and the faucet key.

## 6 Seeds and peers

Two peer modes can be combined:

- **Pinned backbone.** Operator nodes name each other in `PEERS` and pin each endpoint's transport key in `PEER_PINS`, with `PEER_KEY_FILE` set. A wrong key or chain fails closed, with no unauthenticated fallback. Use it between the seeds and mining nodes the operators run.
- **Discovery.** `PEER_DISCOVERY=true` joins the authenticated public network: `PEER_SEEDS` names bootstrap endpoints (DNS names allowed), and `PEER_ADVERTISE` the node's own public `IPv4:PORT` for inbound joins. Discovery still needs `PEER_KEY_FILE`, and keeps any configured pins enforced. Use it on the seeds so that users' nodes can join.

For launch, run every seed with discovery and the backbone pins, advertising its public address, and list all seeds in each other's `PEER_SEEDS`. Users join with:

```sh
hashstash run --config network.json --data chain.sqlite --miner PAYOUT_PUBLIC_KEY --peer-discovery --seed seed-a.example.net:18481 --seed seed-b.example.net:18481 --no-stratum
```

Discovery refuses private and reserved addresses, keeps at most 256 endpoints and caps candidates per network group. It does not prove that peers are independent operators, so publish several seeds run by different people. There are no hardcoded seeds.

Firewalls: allow TCP 18481 from everywhere on seeds and from the backbone peers elsewhere; Stratum 18482 only from the miners' addresses where possible; 80 and 443 on the website host; SSH only from administrators. Keep the private RPC port and the public-web upstream port closed externally.

A node from another release is refused at the first message. Its error appears in the `peers` RPC, for example "peer runs Hashstash 0.42.0 or earlier (peer protocol HSP2PBIN)"; a node that closes on this release's requests is reported as possibly running "Hashstash 0.42.0 or earlier", following another genesis, or being at its connection limits.

Check: `peer-keycheck` passes for every node's identity and pins (the installer's `--check` runs it), and every seed is reachable on 18481 from outside its provider.

## 7 Stratum

Enable Stratum (`STRATUM_ENABLED=true`) only on nodes that serve miners; set it to `false` on seeds and website nodes. A Stratum listener on a public address requires the password file, and the node refuses to start without one.

- Stratum V1 is plain TCP: the password and all shares are visible to anyone on the path, and a rental provider sees the password. Use a different random password per node and never reuse it elsewhere. Restrict 18482 to the miners' addresses with the firewall where they are known.
- `STRATUM_TRUSTED` lists the operator's own miners' and rental proxies' addresses or prefixes (for example `STRATUM_TRUSTED=198.51.100.0/24`), at least /16 for IPv4 or /32 for IPv6 outside local networks. They always keep reserved slots, so a flood of unauthenticated connections cannot lock them out, and 16 of the 64 authorized worker slots that other holders of the password cannot take. Once authorized they are not limited to 16 connections per address. The 256 addresses that most recently authorized also keep reserved waiting slots, in `chain.stratum-trusted.json`.
- Other sources hold at most 48 authorized workers when `STRATUM_TRUSTED` is set, at most 16 per /24 or /48, and at most 16 connections per address, so a marketplace proxy outside `STRATUM_TRUSTED` delivers at most 16 rigs per node from one address. A newcomer replaces a worker without a valid share for five minutes when the slots are full ([mining](MINING.md)).
- `STRATUM_ADVERTISE` is the endpoint shown to users, for example `STRATUM_ADVERTISE=mining-a.example.com:18482`; it does not change the bind address.
- `SHARE_DIFFICULTY` is only the reporting threshold. Size it to about one report every few seconds per machine; the node raises a worker's difficulty when it reports more than two shares per second over 30 seconds, and lowers it again when reports slow below one per four seconds.
- Every block found through a node pays that node's `MINER_PUBLIC_KEY`, whatever the worker name. There is no pool accounting.

Check: a test miner connects with the password, `run-node.sh snapshot` shows it under the mining section's `workers_connected` and its `accepted_shares` rise, and a connection without the password is refused.

## 8 Public website behind nginx and TLS

On the website host set `PUBLIC_WEB_PORT=18483` in `node.env` and install `deploy/linux/public-web.nginx.template` as the [deployment guide](../deploy/linux/README.md#public-wallet-website) describes: a DNS name, a trusted certificate (certbot with automatic renewal and an nginx reload hook), nginx 1.15.7 or later, HTTPS only. The template overwrites `X-Real-IP`, which the node uses to account each visitor, and limits each client to 2 JSON-RPC requests per second and 6 connections. Never proxy the private RPC port. Users' keys stay in their browsers, so the website host must be trusted like wallet software: deploy only the release's files, restrict administrative access, and publish the `https://` address only.

Check: from another network, `https://` loads with a valid certificate, `http://` redirects, a private method such as `peers` is refused, and a burst of requests receives HTTP 429 with `Retry-After` rather than dropped connections.

## 9 Install the nodes

On each host, after copying the release binary, `network.json`, its `node.env`, its peer identity and, for mining nodes, its Stratum password:

```sh
bash deploy/linux/install.sh \
  --binary ./hashstash --sha256 RECORDED_BINARY_SHA256 \
  --genesis ./network.json --genesis-sha256 RECORDED_GENESIS_SHA256 \
  --node-env ./node.env --stratum-password-file ./mining-password \
  --peer-key-file ./region-a-peer.json --check
sudo bash deploy/linux/install.sh \
  --binary ./hashstash --sha256 RECORDED_BINARY_SHA256 \
  --genesis ./network.json --genesis-sha256 RECORDED_GENESIS_SHA256 \
  --node-env ./node.env --stratum-password-file ./mining-password \
  --peer-key-file ./region-a-peer.json
```

The check runs every startup check of the service, including the calibration guard, without opening a database or a listener. The installer pins the binary under `/opt/hashstash/0.43.0-SHA256/`, puts configuration in `/etc/hashstash` and data in `/var/lib/hashstash`, and never enables or starts the service. Start from an empty `/var/lib/hashstash`: this release refuses a database that holds blocks of 0.42.0 or earlier, naming that release. Delete secret copies from the upload location afterwards.

Check: `--check` prints "Configuration and payout public key are valid", and `systemd-analyze security hashstash` shows the confinement described in the deployment guide.

## 10 Rehearsal

Two or three days before launch, run the whole procedure on a throwaway genesis created the same way (`./hashstash init --config rehearsal.json --preset slow --hashrate 2P`), on the real hosts, with real miners for at least an hour:

1. Install every node, start them, and confirm convergence (section 11).
2. Send transactions through the website, sign one offline with the cold signer and broadcast it, and run a small governance round if time allows.
3. Back up one node and restore it (section 13); stop a seed and confirm the others keep the chain moving; restart a node and time its start.
4. Kill a node's process and confirm systemd restarts it (`NRestarts`), then `systemctl reset-failed hashstash`.
5. Measure memory (`systemctl show -p MemoryCurrent,MemoryPeak hashstash`) and disk growth per hour.
6. Exercise the incident checks in section 14 and the monitoring alerts in section 12.

Then stop every rehearsal node, move its `/var/lib/hashstash` aside and empty it, and replace the rehearsal genesis with the launch genesis using a new installation. Never reuse rehearsal data on the launch chain.

## 11 Launch day

1. Start the seeds: `sudo systemctl enable --now hashstash`. On each, `run-node.sh snapshot` must show height 0 and the same `tip` (the genesis block hash) and `chain_id` as on every other node, and `peerstatus` must show each configured peer `reachable` with a recent `last_success`.
2. Start the mining nodes, then point the miners at them. Watch for the first blocks: heights rise, `blocks_found` increases on the mining node that found each one, and every node reports the same `tip` and `state_root` at the same height.
3. Watch the block rate for the first hour. If blocks are far slower or faster than 15 seconds, difficulty adjusts with a 900-second half-life; do not change the genesis.
4. Open the public website and check a wallet's balance, a transfer and an Explorer page.
5. Announce: the chain ID, `network.json` and its SHA256, the release and its `SHA256SUMS`, the seeds, the website, and the limitations in section 15.
6. Fund and start the faucet, if any, only after the chain has run for a while ([faucet](FAUCET.md)); give it a new ledger and only a limited balance.

Abort criteria before announcing: nodes disagree on the genesis tip, a state root differs at the same height, a node crash-loops, or blocks cannot be found. Before the announcement a genesis can still be replaced: stop all nodes, empty their data directories, create a new genesis and publish its new chain ID. After users hold balances it cannot.

## 12 Monitoring

Poll every node about every 10 seconds and alert on the following. The `run-node.sh` helper reads through the private RPC on the host:

```sh
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh snapshot
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh peers
sudo -u hashstash /opt/hashstash/0.43.0-RECORDED_BINARY_SHA256/hashstash rpc --url http://127.0.0.1:18480/rpc peerstatus
```

| Signal | Where | Alert when |
| --- | --- | --- |
| Chain progress | `peerstatus` `chain_stalled`, `seconds_without_new_tip` | Stalled (twelve governed intervals, at least 180 seconds, without a new tip); also true when nobody mines |
| Agreement | `snapshot` `height`, `tip`, `state_root` on all nodes | Two nodes report different tips or state roots at the same height for more than a few blocks |
| Peers | `peerstatus` per peer `reachable`, `last_success`, `consecutive_failures`, `stalled` | A configured peer is stalled (90 seconds without an exchange) or failures keep rising |
| Peer errors | `peers` (the last 64 events) | Repeated errors naming another release, another genesis or "different genesis configuration"; an unknown source repeatedly sending invalid data |
| Header-closing peers | `peerstatus` `version1_peers` | Not empty: a peer closes on header requests (another release, another genesis, or overloaded) |
| Listeners | `peerstatus` `listeners` | Accept errors |
| Discovery | `peerstatus` `discovery` `known`, `verified`, `last_error`, `load_error` | Verified count falls toward zero, or an error is set |
| Mining | `snapshot` mining section: `workers_connected`, `accepted_shares`, `rejected_shares`, `blocks_found`, `hashrate_hps` | Workers disconnect, rejected shares grow faster than accepted ones, or no blocks are found for longer than expected |
| Process | `journalctl -u hashstash`, `systemctl show -p NRestarts hashstash` | Any `fatal:` line (exit status 70, or 74 after block commits kept failing), `hashstash was killed for exceeding its memory limit`, or a rising restart count |
| Storage | `status` or `peerstatus` `storage`: `degraded`, `failed_commits`, `last_error`, `checkpoint_error` | `degraded` true (blocks cannot be stored, for example on a full disk; the tip is frozen and the node exits with status 74 after a minute of failures), or a `checkpoint_error` |
| Startup | Journal | `Ignoring state checkpoints saved by another build` other than once after a binary change; `Could not save a state checkpoint`; `Moved N stored side-branch block(s) that fail validation into rejected_blocks` |
| Other journal lines | Journal | `listener accept failed`, `New tip publication deferred`, `Pending transaction recovery deferred`, `Explorer ... unavailable`, `Selection kept N of M transactions`, `Pruned N stored losing-branch block(s)` (informational) |
| Memory | `systemctl show -p MemoryCurrent,MemoryPeak hashstash` | Above about 80% of `MemoryHigh`; raise the limits from measurements before they bind |
| Disk | Size and free space of `/var/lib/hashstash` | Free space below 20%, or growth far from the measured rate (16 KiB blocks every 15 seconds allow about 94 MB per day of bodies before indexes and up to four saved states); below 512 MiB free the node declines side-branch blocks and skips state checkpoints |
| Website | nginx access log status codes, certificate expiry | Many 429 or 503 answers, 5xx answers, a certificate expiring within 14 days |

Admission refusals and node lock time are not exported as counters in this release. Watch them indirectly: HTTP 429 (a client's budget or cooldown) and 503 (busy shared capacity) in the nginx log and in client reports, `rate budget` errors in RPC replies, public broadcasts refused with 429 while relayed transactions queue, and Stratum rejected-share counts. A sustained rise in any of them under ordinary traffic means more capacity or tighter proxy limits are needed.

## 13 Backups and restore

The chain itself is replicated by every node; a node that loses its data can resynchronize from peers. Backups shorten recovery and keep the node's own files: its peer book, trusted Stratum addresses, Explorer index and, if used, server wallets. The irreplaceable secrets are the offline payout, treasury and faucet keys (section 5), and each node's peer identity and Stratum password.

The node holds its database exclusively while it runs, so back it up stopped, one node at a time so that the others keep the network going:

```sh
sudo systemctl stop hashstash
sudo tar --numeric-owner -C /var/lib -czf /root/hashstash-backup-$(date -u +%Y%m%dT%H%M%SZ).tar.gz hashstash
sudo tar --numeric-owner -C /etc -czf /root/hashstash-etc-$(date -u +%Y%m%dT%H%M%SZ).tar.gz hashstash
sudo systemctl start hashstash
```

Keep the SQLite WAL files with the database; never copy a running database file by itself. `/etc/hashstash` holds the peer identity and Stratum password, so encrypt that archive and store it away from the host. A stop saves a state checkpoint, so the restart validates only about 31 blocks.

To restore, on the same release:

```sh
sudo systemctl stop hashstash
sudo mv /var/lib/hashstash /var/lib/hashstash.failed
sudo tar --numeric-owner -C /var/lib -xzf /root/hashstash-backup-STAMP.tar.gz
sudo systemctl start hashstash
```

The node starts from the newest state checkpoint that its own binary saved and that passes its checks, validating the blocks above it; with another binary, or any doubt, it revalidates all stored history, which takes longer and needs the memory of the full state. It then synchronizes the blocks it is missing from its peers. Compare its `tip` and `state_root` with another node's at the same height before relying on it. A database from another network or release is refused at startup; never edit tables by hand.

Check during the rehearsal: a restored node rejoins and agrees with the others, and the restore time is written down.

## 14 Incident response

Keep an operators' channel that does not depend on the network. For every incident record the time, heights, tips, the affected nodes and what was changed.

**Chain halt** (`chain_stalled` on every node). Check that miners are connected and submitting (`workers_connected`, `accepted_shares`), that Stratum is reachable, and that host clocks are correct. Difficulty eases with a 900-second half-life down to the easiest target, so a partial loss of hashrate slows blocks rather than stopping them; a loss of more than 256 times cannot be absorbed and needs hashrate to return. If one node is stalled and others are not, inspect its `peerstatus` and `peers` and restart it.

**Crash loop.** Read the journal. Exit status 70 follows a panic or a poisoned lock; exit status 74 follows a minute of failed block commits (read `last_error` in the journal's `fatal:` line; usually a full disk, which must be freed before the restart can help); the unit restarts with back-off. An out-of-memory kill needs higher `MemoryHigh` and `MemoryMax` (a drop-in through `systemctl edit hashstash`), not waiting. After fixing the cause run `systemctl reset-failed hashstash`. Keep the journal and, if needed, a copy of the stopped data directory for the developers.

**Split or deep reorganization.** Nodes follow the valid branch with the most work and synchronize headers first, so an honest heavier branch is adopted automatically if it needs at most 65,536 headers past a node's stored fork point before it claims more work than that node's tip, and a reorganization restores balances, governance and decisions together. After a longer partition, about 11 days of evenly split 15-second blocks and longer when the split is uneven, nodes on the lighter side never switch by themselves: resynchronize each of them as described below. Compare tips, state roots and `peers` errors to find the branch's source. Check that every node runs the same binary SHA256 and genesis SHA256. If a branch with less work is being mined deliberately, or a deeper reorganization than expected happens, tell exchanges, the faucet operator and users to wait for more confirmations; the faucet's `confirmations` setting can be raised. There are no consensus checkpoints and no administrative override. If nodes running the same release disagree about a block's validity, stop announcing, have operators stop their miners, keep the data directories, and escalate as a consensus bug.

To resynchronize a node left on a lighter branch beyond that bound ([specification](SPECIFICATION.md#12-records-storage-and-networking)), start it on an empty data directory in pinned-only mode, connected only to nodes known to be on the heavier branch:

```sh
sudo systemctl stop hashstash
sudo mv /var/lib/hashstash /var/lib/hashstash.lighter
sudo install -d -o hashstash -g hashstash -m 750 /var/lib/hashstash
# Only if this node keeps server wallets:
sudo cp -p /var/lib/hashstash.lighter/chain.wallets.sqlite /var/lib/hashstash/
sudoedit /etc/hashstash/node.env
sudo systemctl start hashstash
```

In `node.env` set `PEER_DISCOVERY=false`, remove `PEER_SEEDS` and `PEER_ADVERTISE`, list only heavier-side nodes in `PEERS` and give each its pin in `PEER_PINS` (the peer public keys recorded in section 1), and keep `PEER_KEY_FILE` so that pinned peers still recognise the node. `PEERS` without `PEER_KEY_FILE` cannot be used: such a node connects without authentication, and every launch node refuses it. Each listed peer must run discovery or pin this node, as the backbone does (section 6). Once `run-node.sh snapshot` shows the same `tip` as those nodes at the same height, the node has passed the branch it left: restore its usual `node.env`, restart it, and keep `/var/lib/hashstash.lighter` until it is back in service. A user's node is recovered the same way with `--peer-key-file`, `--peer` and `--peer-pin`, without `--peer-discovery`, so publish the peer public keys of heavier-side seeds with the incident notice.

**Governance attack.** Watch `governance` and the Governance page for proposals and decisions. Defences are economic and bounded: a hostile proposal must win the auction with bids that become revenue, and then PASS must lead a strict majority of the decision's blocks by the margin. Counter-bidding and trading in the decision's outcomes are the responses; there is no veto. Governed changes are bounded (capacity from 4,096 bytes to 64 MiB and at most halved or doubled per decision, fee rate at most doubled, interval and durations bounded, price bound below 100%), a passed setting takes effect only after the rest period, and a grant can draw at most half of the reserve. Expect auction delay by well-funded bidders (section 15); it costs them fees but cannot end a round without a decision.

**Floods.** HTTP 429 and 503 answers are the node protecting itself. If honest users are refused, tighten the nginx per-client limits or add website capacity; do not raise the node's budgets without measurements. Operator miners in `STRATUM_TRUSTED` keep their Stratum slots; peers keep reserved slots for configured and pinned endpoints.

**Key compromise.** A peer identity: generate a new one, update every peer's pins through the trusted channel, then replace `/etc/hashstash/peer-identity.json` with it (owner `hashstash`, mode 0600; the installer never replaces an existing identity) and restart the node. A Stratum password: replace `/etc/hashstash/stratum-password`, restart the node and update the miners. A payout key: move its funds with the cold signer at once, then set a new `MINER_PUBLIC_KEY` in `/etc/hashstash/node.env` and restart. The faucet key: stop the faucet and move its remaining funds. A website host: take it offline, warn users not to enter keys there, and rebuild it.

**Old-release peers.** Errors naming Hashstash 0.42.0 mean someone runs the old release against the new seeds. They are refused and cannot affect the chain; contact the operator if known.

## 15 Limitations users must be told

Publish these with the launch announcement and on the website. They are documented, accepted limits of this release, not defects being fixed.

- **No limit prices.** A Stash order states only the amount to spend or sell. All orders in a block clear together at one price, bounded to a 10% move per block, so another order in the same block, which a miner can place, moves the price paid. Keep trade expiry short (the default is two blocks) and size orders with that bound in mind ([specification](SPECIFICATION.md#amount-only-block-clearing)).
- **PASS margin 0 on flat curves.** The launch genesis requires PASS to beat FAIL by 0 basis points. On a flat or nearly flat curve integer rounding alone can move a price slightly, and at the genesis exchange rate no trade moves it at all, so a revenue-funded grant or setting change decided on that baseline resolves FAIL. Outcomes reflect trading, not merit ([price comparison](SPECIFICATION.md#7-price-comparison-and-resolution)).
- **Auction griefing.** A bidder with enough funds can delay another proposal's decision until the auction timeout, for example with higher grants that sales later make unfundable, at the cost of fees. Whoever leads at the timeout opens its decision.
- **Reward rounding.** Each block issues whole atoms of one petahash of expected work and discards the rest, so on a small network a large share of work earns nothing, and the reward per hash jumps at each whole petahash ([mining](MINING.md)).
- **Long partitions need manual recovery.** A node follows a heavier branch by itself only if that branch needs at most 65,536 headers past their last shared block before it claims more work than the node's tip. After a split of more than about 11 days of evenly split 15-second blocks, nodes on the lighter side stay on it until their operators resynchronize them (section 14), and what was confirmed only on that side is undone when they switch ([specification](SPECIFICATION.md#12-records-storage-and-networking)).
- **No transport encryption.** Peer traffic is authenticated but readable, Stratum V1 is plain TCP including its password, and the private RPC must stay on loopback. Only the public website uses TLS.
- **Mail without forward secrecy.** Mail ciphertext is permanent on the chain; anyone who later obtains an account's key can read all its past mail ([mail](MAIL.md)). Transaction senders, amounts and timing are public.

Also tell users that browser keys are unencrypted unless they set a wallet passphrase, that the website must be trusted like wallet software, that a transaction is final only after enough confirmations, and that this software has not had a complete independent audit ([security review](AUDIT.md)).
