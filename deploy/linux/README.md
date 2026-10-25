# Linux nodes

One persistent Hashstash 0.43.0 node per Linux host, managed by systemd. Each node exposes P2P, optionally exposes solo Stratum V1, keeps RPC on loopback, and pays its own configured public key. There is no wallet private key on the server and no software miner in this service. A dedicated peer transport key, when enabled, is separate from all spending keys.

These files target Debian/Ubuntu with Bash, GNU coreutils, `awk`, `flock`, `useradd`, and systemd. The listener setup uses public IPv4; advertised Stratum endpoints may use DNS. No cloud provider is required by the scripts.

## Build and pin

Build on Linux for the servers' architecture. A Rust toolchain supporting the locked dependencies and edition 2024, a C compiler, and a linker are needed. SQLite and secp256k1 compile from bundled sources; OpenSSL development libraries are not required.

```sh
bash scripts/release.sh --verify
cat target/dist/hashstash-*-linux-*/SHA256SUMS target/dist/hashstash-*-linux-*/BUILDINFO
```

`scripts/release.sh` runs `cargo build --locked --release --bins` with the pinned toolchain and remapped build paths, checks the reported version, writes `SHA256SUMS` and `BUILDINFO` (source commit, `Cargo.lock` hash and compiler versions), and with `--verify` rebuilds from scratch and requires identical binaries. A second builder with the same toolchain and C compiler should get the same `SHA256SUMS`; the [launch runbook](../../docs/LAUNCH.md#2-build-and-pin-the-release) describes the comparison and signing. Keep the exact source snapshot, `Cargo.lock`, compiler versions, and binary SHA256 with the deployment record. Use that recorded SHA256 during installation; a hash obtained only from an untrusted download does not establish its origin. Copy the same built binary to hosts with a compatible architecture and Linux runtime. Use a normal build without the `test-fixtures` feature and a configuration with `test_work: false`. The installer accepts only the release of its own source snapshot, version 0.43.0, and pins it with the complete binary hash under `/opt/hashstash/`; it will not silently upgrade an existing installation. Use the installer from the same source snapshot as the binary.

## Prepare shared and per-node files

Choose **one** reviewed genesis `network.json`, record its SHA256 and chain ID, and distribute it unchanged to all hosts. Do not run `init` separately on each host. Every genesis field contributes to network identity. Initial difficulty, the fixed target limit and initial settings belong in this shared file; a node's mining public key does not. Create it with `init --preset slow --hashrate RATE` for the miners' expected aggregate hashrate: this service binds P2P to `0.0.0.0`, and `run` refuses that for a genesis whose easiest target needs fewer than 2^32 expected hashes per block, such as the presets' uncalibrated limit (see [running a node](../../docs/RUNNING.md)). Calibration sets the easiest target 256 times easier than the calibrated one, so at 15-second blocks `RATE` must be at least about 73.4G (2^40 hashes per block). For a deliberately smaller network, add `ALLOW_EASY_TARGET=true` to `node.env`; the service then runs with `--allow-easy-target` and logs a warning. The installer's `--check` runs the service's own `run` options with `--preflight`, so a genesis the service would refuse fails there instead of in a restart loop.

The governed miner percentage starts at 50% and applies to the entire exact signed fee; integer rounding goes to waiting revenue. The signed fee must meet the governed minimum rate times transaction weight, rounded up per 1,024 units. Block usage does not adjust that rate. During a decision, each account has its own full cash balance in both alternative worlds; outcome trades affect only that world's cash, while payments and fees must be affordable in both. At the block's opening, every order needs its input in the selected world and every fee needs cash in both outcomes. Same-block withdrawal proceeds, refunds and incoming transfers cannot fund another input or fee.

Decision lengths use blocks. Auction lead, rest and auction timeouts use scheduled seconds; each block advances that clock by its parent’s governed target interval. Grants are fully escrowed at decision start. Revenue replenishes a nonflat reserve during block processing and waits outside a flat reserve. Header timestamps drive ASERT. Each transaction signs a recent block hash and a lifetime, defaulting to the next two blocks. That anchor must remain on the branch accepting the transaction; an orphaned anchor invalidates it. Retries preserve the signed anchor and lifetime.

```sh
sha256sum network.json
./hashstash network --config network.json
cp deploy/linux/node.env.example node.env
```

Create or select each payout key on a trusted offline machine, and copy **only its 64-character public key** into that node's `MINER_PUBLIC_KEY`. Keep each private key and backup off the hosts. Use different public keys for independently identifiable regional payouts. The installer verifies that the supplied public key is valid; the example intentionally has no usable default key.

Edit the other fields in `node.env`. It is plain `KEY=value` data, with no quotes, shell substitutions, or inline comments. `PEERS` is a space-separated list of literal IPv4 addresses and ports, not DNS names. A three-region layout can use:

| Host | Local RPC port | P2P port | Stratum port | Peers |
| --- | ---: | ---: | ---: | --- |
| Region A | 18480 | 18481 | 18482 | B's IP:18481 and C's IP:18481 |
| Region B | 19480 | 18481 | 18482 | A's IP:18481 and C's IP:18481 |
| Region C | 20480 | 18481 | 18482 | A's IP:18481 and B's IP:18481 |

Set `STRATUM_ADVERTISE` to each host's reachable address, for example `mining-a.example.com:18482`. This changes the displayed endpoint, not its bind address. `SHARE_DIFFICULTY` is the reporting threshold, separate from network difficulty. For example, 524288 gives approximately one qualifying report every 11 seconds at 200 TH/s when the network target is harder; this setting does not fix block spacing.

Supply a separate mining password as a file, containing one nonempty ASCII token of at most 256 characters. It may differ by node. It authorizes Stratum submissions only; it grants no access to balances, RPC, or SSH. Stratum V1 uses plain TCP, so do not reuse a wallet, login, or other service password. The installer does not generate signing keys or print the password.

`STRATUM_ENABLED=true` is the default. Set it to `false` for a validating/relaying node that does not accept miners: no mining listener is bound and no mining password is required. Keep the port, advertised address and reporting fields valid so the configuration remains explicit when enabling mining later. Stopping the node or disabling its listener does not cancel a rental or stop an external ASIC.

`STRATUM_TRUSTED` lists, separated by spaces, the addresses or prefixes of miners the operator controls or has rented, for example `STRATUM_TRUSTED=198.51.100.0/24 2001:db8:10::/48`. Each entry outside local networks must be at least /16 for IPv4 or /32 for IPv6; the launcher refuses a broader one such as `0.0.0.0/0`, which would treat every source as the operator's. List a deliberately broader prefix in `STRATUM_TRUSTED_BROAD` instead. Trusted sources keep reserved slots while they wait for authorization, keep 16 of the node's 64 authorized worker slots for themselves (without `STRATUM_TRUSTED`, other sources may use all 64), and, once authorized, are not limited by their address's 16 connections or its budgets.

## Pin peer identities

For a fixed operator-managed network, create a fresh dedicated transport identity for each node on a trusted preparation machine. This key only authenticates peer traffic; do not use a payout, visitor, activity or faucet key. The command prints only its public key and writes a new owner-only file without overwriting an existing file:

```sh
install -d -m 700 ~/hashstash-keys
./hashstash peer-keygen --out ~/hashstash-keys/region-a-peer.json
```

Keep identity files outside any source checkout and out of shared or group-writable directories; `.gitignore` ignores `*peer*.json` only as a backstop. Exchange the public keys through an independently trusted channel. Set `PEER_KEY_FILE=/etc/hashstash/peer-identity.json` in each node's environment and set `PEER_PINS` to space-separated `IPv4:PORT=PUBLIC_KEY` entries. The endpoints must match `PEERS` exactly: one pin per peer, no duplicates, valid ports and IPv4 addresses without leading zeros. The incoming source IP must match the pin, so account for NAT before configuring it. Supply that node's identity with the installer's `--peer-key-file` argument. The installer validates its dedicated format, key agreement, owner-only permissions and separation from the payout key without opening listeners, then installs it as `hashstash:hashstash` mode `0600` under the root-owned configuration directory. It rejects symlink sources and never reads a wallet key format as a transport key.

Pinned transport fails closed when a key or pin is wrong; there is no unauthenticated retry. Omitting both settings selects unauthenticated transport. Authentication protects identity and message integrity, not traffic confidentiality. A fixed set of peers on one provider remains vulnerable to provider/network outages, partitions and compromised peers; it is not an eclipse-resistant discovery network. See [network hardening](../../docs/NETWORK-HARDENING.md).

## Install, then start

Pass the binary and genesis hashes recorded on the trusted preparation machine:

```sh
bash deploy/linux/install.sh \
  --binary /path/hashstash --sha256 RECORDED_BINARY_SHA256 \
  --genesis /path/network.json --genesis-sha256 RECORDED_GENESIS_SHA256 \
  --node-env /path/node.env --stratum-password-file /path/mining-password \
  --peer-key-file ~/hashstash-keys/region-a-peer.json --check

sudo bash deploy/linux/install.sh \
  --binary /path/hashstash --sha256 RECORDED_BINARY_SHA256 \
  --genesis /path/network.json --genesis-sha256 RECORDED_GENESIS_SHA256 \
  --node-env /path/node.env --stratum-password-file /path/mining-password \
  --peer-key-file ~/hashstash-keys/region-a-peer.json
```

Omit `--stratum-password-file` when `STRATUM_ENABLED=false`. Omit `--peer-key-file` only when both peer-authentication settings are absent. `--check` validates inputs without installing or opening listeners. The installer first copies every input into a new private directory under `TMPDIR` (default `/tmp`), refusing a location another account could modify, then hashes, validates, runs and installs only those copies and re-hashes the installed binary and genesis. That directory must allow execution. On a host with a `noexec` `/tmp`, give `TMPDIR` to the installer itself, because `sudo` does not pass on an exported value: create a root-owned directory with `sudo install -d -m 700 /root/hashstash-stage` and run `sudo env TMPDIR=/root/hashstash-stage bash deploy/linux/install.sh ...`. For the unprivileged `--check`, use a directory you own, for example `install -d -m 700 ~/hashstash-stage` and `TMPDIR=~/hashstash-stage bash deploy/linux/install.sh ... --check`. Installation creates a dedicated unprivileged account, root-owned non-secret configuration in `/etc/hashstash`, a pinned binary, and the service definition. The database and its auxiliary files live in `/var/lib/hashstash`. Repeating the installation accepts identical files and refuses conflicts; it never replaces configuration, identities or chain data. It neither enables nor starts the service.

Before starting, allow inbound TCP P2P from the configured peer hosts and Stratum only when enabled and required by miners. Allow SSH from the administrator's addresses. Keep the RPC port closed to public traffic. The service binds P2P and enabled Stratum to `0.0.0.0` and RPC to `127.0.0.1`.

```sh
sudo systemctl enable --now hashstash
sudo systemctl status hashstash
sudo journalctl -u hashstash -n 50 --no-pager
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh snapshot
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh peers
sudo -u hashstash /opt/hashstash/0.43.0-RECORDED_BINARY_SHA256/hashstash rpc --url http://127.0.0.1:18480/rpc peerstatus
```

These reads do not mine or submit transactions. `snapshot` includes chain height, tip, state root, issuance, phase, and Stratum worker/share counters; `peers` lists endpoints. `peerstatus` adds transport mode, successful exchange times, failures and stalled indicators. Its chain-stalled indicator also becomes true normally when there are no miners. Compare chain IDs first and tip/state roots at the same height across regions. A reachable RPC or connected worker alone does not establish that mining has produced valid blocks. Observe accepted shares, accepted blocks, payout balances, and peer convergence during the first mining run. Use a modest polling interval, such as 10 seconds.

Point an ASIC or rental provider to `stratum+tcp://HOST:STRATUM_PORT`, with a worker label and the mining password. All work connected to a node pays that node's configured public key. This is a solo server, not a proportional pool that distributes rewards among worker usernames.

Plan rentals around the node's Stratum limits. A node serves at most 64 authorized connections. Sources outside `STRATUM_TRUSTED` hold at most 48 of them when it is set, at most 16 from one IPv4 /24 or IPv6 /48, and at most 16 connections from one address. A marketplace that opens one connection per rig from a shared proxy address therefore delivers at most 16 rigs per node from that address unless the address is in `STRATUM_TRUSTED`; ask the provider for its proxy addresses, trust them, or spread the rigs over several nodes. A proxy may also authorize several rig names on one connection. Give the provider the node's own address, not a port forward that makes every miner arrive from one address. When the slots are full, a newly authorized connection replaces one that has sent no valid share for five minutes, so keep the reporting difficulty low enough that each rig reports a share every few seconds.

## Dashboard through SSH

Preserve the remote RPC port as the local forwarding port. The HTTP server checks the Host header's port, so mapping another local port to it is rejected. For the three-node example, run these on the administrator's machine:

```sh
ssh -N -L 127.0.0.1:18480:127.0.0.1:18480 admin@region-a
ssh -N -L 127.0.0.1:19480:127.0.0.1:19480 admin@region-b
ssh -N -L 127.0.0.1:20480:127.0.0.1:20480 admin@region-c
```

Open `http://127.0.0.1:18480`, `:19480`, or `:20480` locally. The interface creates, imports, stores and signs with wallets in that browser. Optional server wallets are separate private API/CLI tools. Browser storage is scoped to the exact website origin and network: switching between a forwarded URL and a public HTTPS URL does not carry wallets across. Export a backup before moving or clearing browser data.

## Public wallet website

Add `PUBLIC_WEB_PORT=18483` to `node.env` to enable the separate public surface on `127.0.0.1:18483`. Omitting the field leaves it disabled. This listener serves the interface and an allowlist of chain reads, unsigned transaction preparation and signed transaction broadcast. It never exposes the private node wallet, wallet exports, software mining or block submission. The ordinary RPC listener remains private and must not be used as the reverse proxy's upstream.

Use `public-web.nginx.template` with `PUBLIC_HOST` replaced by the server's DNS name, or by its actual IPv4 address. It needs nginx 1.15.7 or later, for its `limit_req ... delay=` setting; check with `nginx -v` and `nginx -t`. The upstream is only the restricted port 18483. The template sets client request/connection limits and HTTPS delivery; it requires a trusted certificate before activation. Do not serve a hot wallet over public HTTP or instruct users to bypass a certificate warning. Localhost remains suitable for development.

Prefer a DNS name. Browsers honour the template's Strict-Transport-Security header only for DNS names; RFC 6797 has them ignore it for IP-address hosts, and an IP address cannot be preloaded. On an IP-literal site, every visit that starts at `http://` can be intercepted by an on-path attacker who suppresses the port-80 redirect and serves a look-alike wallet; existing HTTPS-origin wallets stay unreadable to it, but keys created or imported there are exposed. Publish and bookmark the `https://` address, and tell users never to create or import a wallet on a page reached through `http://`.

Every public visitor reaches the node from the proxy's loopback address. The template overwrites `X-Real-IP` with the connecting address, and the node accepts that header only from loopback: each visitor's own record allows 6 concurrent sessions and a share of the request, byte and work refill rates, an eighth while at most eight visitor shares are active and less when more are (at an eighth, 16,384 work units and 4 MiB per second). Each active address is one share, but the addresses of one /24 or /48 count at most four shares, which is also all they get together. A visitor's bursts stay an eighth however many are active (128 requests, about three wallet page loads) and always admit one largest reply and the work it pays (197,632 units at the 193 MiB response limit), and the work of one largest request at the current capacity, though only wallet-critical calls may spend that request allowance beyond the rest of the burst. All visitors together still share one record of 32 sessions, 640 requests and 131,072 work units per second (work burst 1,048,576), and a quarter of its request, byte and work bursts is kept for wallet balance polls, transfer and Stash quotes, support checks, preparation and broadcast (see [network controls](../../docs/NETWORK-HARDENING.md)). Run the proxy on the same host, and never let it forward a client-supplied `X-Real-IP`; a proxy on another address counts as one visitor. The template also limits each client address to 2 JSON-RPC requests per second with a burst of 20 and to 6 connections (4 for JSON-RPC), which only paces ordinary use. Its connections to the node are capped at the node's 32 public sessions by the upstream's `max_conns`, and a request that finds all of them in use, or finds the node not running, is answered 503 with `Retry-After`. nginx also answers 502 when the node closes a connection without replying, as when it stops, a worker fails or it is killed, but that request may have run: the template answers 503 only when the request never reached the node (`$upstream_connect_time` is `-`) and keeps any other 502, which the web wallet treats as an unknown outcome rather than a refusal. There is deliberately no connection limit shared by all clients: a few addresses sending or reading slowly could hold every place of one and shut everyone else out. nginx buffers request bodies and replies, so a slow client holds only its own connections, never a node session. Open client connections are bounded by nginx's `worker_connections` (768 in Debian's `nginx.conf`); raise it, with `worker_rlimit_nofile`, for a busy site, since each address may hold 6. The client chooses a request's cost, and prices differ widely:

- A wallet's snapshot poll usually costs a few hundred units, plus 512 for each account valuation on a curved Stash. It summarizes large grants, so it stays bounded even during a large-grant decision.
- A transaction preparation or broadcast costs about 4,350 units. An explorer account, transaction, chat or mail page costs 4,160, and every explorer reply also pays one unit per KiB it returns.
- After a grant draws on the reserve, the Stash curve is no longer flat. A large `quote` then costs up to 512 units per bit of the world's account cash, about 20,000 units at 40 bits.
- During a decision on a grant with N payments, `governance`, `proposals` and `explorer_governance` cost about N units each.
- A preparation or quote that lists a grant of N payments costs about N more units, because those are priced before they are validated. A list sent to any other method costs nothing beyond its bytes.

One address can therefore spend at most its share. Keeping the shared budget outside the wallet reserve empty takes many addresses in distinct /24s or /48s, about 16 sending explorer requests at 2 per second; wallet calls stay admissible meanwhile, though enough addresses sending large quotes or preparations can still exhaust the reserve too. Page and script requests must leave the reserve of requests in place as well, and a proxied connection whose visitor is refused gives back the request unit it took, so emptying that reserve takes more than 40 addresses in at least 11 distinct /24s or /48s, many more within the template's per-address rates. Raising the rate lets fewer clients deny other calls, and enough addresses can always exhaust a shared quota. Watch for `rate budget` errors, especially during large-grant decisions, and lower the rate or add capacity as needed.

For a DNS name, issue an ordinary certificate through the same webroot, for example `certbot certonly --webroot --webroot-path /var/www/hashstash-acme -d PUBLIC_HOST --cert-name PUBLIC_HOST`. Let’s Encrypt supports IP address certificates with its short-lived profile. Certbot 5.4 or later supports obtaining them through an HTTP webroot challenge. After registering the certificate account and accepting its subscriber agreement, issuance for an IP address uses:

```sh
certbot certonly --preferred-profile shortlived \
  --webroot --webroot-path /var/www/hashstash-acme \
  --ip-address PUBLIC_HOST --cert-name PUBLIC_HOST
```

Serve only `/.well-known/acme-challenge/` from that webroot on port 80 during setup. Then activate the complete HTTPS proxy, and allow public TCP 80 and 443 in both firewalls. Keep 18483 and the private RPC port closed externally. Run `certbot renew` at least twice daily and configure a deploy hook that validates and reloads nginx after renewal. Verify a renewal dry run, certificate validation from another machine, and public rejection of private methods before accepting wallets. Certificate guidance: [Let’s Encrypt's Certbot instructions](https://letsencrypt.org/2026/03/11/shorter-certs-certbot/).

Keys stay in each visitor's browser profile. Public hosting still requires trusting the delivered wallet code: HTTPS protects transport, not a compromised host. The watch-only and disconnected signer workflow remains available.

## Stop, preserve, upgrade

```sh
sudo systemctl stop hashstash
```

systemd sends SIGINT, which the node handles for shutdown. Keep the complete `/var/lib/hashstash` directory, including SQLite WAL files, together with the exact genesis, binary pin and protected dedicated peer identity. Take a filesystem copy or snapshot after stopping the service; do not copy a running SQLite database file by itself. Each node must have its own database directory. Protect and test restoring backups. Never put peer private identities in public deployment receipts. A rotated transport key requires updating other nodes' pins through the trusted channel.

Upgrades are an explicit maintenance step: stop the service, preserve a backup, verify the new release and its chain compatibility, then change the binary pin and any reviewed service files. The installer intentionally refuses to perform this replacement automatically. Never change the genesis file to upgrade a running chain. This release cannot continue a chain created by an earlier one: its blocks commit to another state encoding, its signatures bind the chain ID, and its peers refuse earlier releases' messages. Install it with a new genesis and an empty `/var/lib/hashstash`; it refuses a database holding blocks of 0.42.0 or earlier, naming that release (see the [release notes](../../CHANGELOG.md)). A node uses only the state checkpoints its own executable saved, so the first start of a different binary revalidates all stored history (the journal says `Ignoring state checkpoints saved by another build; replaying all stored history`) and saves a new checkpoint; allow for that start's time and memory.

The supplied service runs without capabilities and also restricts system calls to `@system-service` (others fail with `EPERM`), namespaces, kernel and control-group interfaces, writable executable memory, other processes in `/proc`, and core dumps (`LimitCORE=0`). Directives unknown to an older systemd are ignored with a log warning; review `systemd-analyze security hashstash` after installation. It sets `MemoryHigh=512M`, `MemoryMax=1G` and `TasksMax=128`. These are operator safeguards, not proven capacity requirements: a valid larger state or replay may exceed them and be killed by the kernel. The node holds the whole account state in memory. A start from a state checkpoint decodes one copy of that state and then validates the blocks above it, so it needs about the memory the running node holds, in every phase: during a decision the checkpoint stores the PASS outcome's account records only where they differ from the FAIL outcome's, and a start restores them sharing the rest, as execution keeps them, rather than as a second copy of every account. Size the limits from measurements of your node rather than from these defaults: `systemctl show -p MemoryCurrent,MemoryPeak hashstash` shortly after a restart and during normal running (`MemoryPeak` needs systemd 255 or later), then set `MemoryHigh` above the observed peak and `MemoryMax` with headroom above it, for example in a drop-in created by `sudo systemctl edit hashstash`. Measurements of normal running do not show memory that peers can fill on demand, and it grows with the greatest block capacity governance has validated (`capacity_allowance` in `peerstatus`): buffered inbound frames, up to five frame allowances of about twice that capacity and at least 64 MiB in all, two decoded frames, and the pending pool and its published copy, each within one block's bytes; the public website adds up to 64 MiB of replies waiting for slow readers. Keep `MemoryMax` at least 128 MiB plus 20 times that capacity above the measured peak. The defaults leave that room at the launch capacity of 16 KiB, but it is about 450 MiB at 16 MiB blocks and about 1.4 GiB at the 64 MiB maximum, so raise both limits before governance raises capacity that far, not after an out-of-memory kill. The node checks this itself at startup, every minute and whenever that capacity changes: while its control group's memory limit (`MemoryMax`, or a lower limit of a group above it) is below its resident memory plus that room, it logs `warning: this node's memory limit of ... MiB leaves less than ...` (repeated hourly), and `peerstatus` reports `memory.short` as `true`, with `memory.limit`, `memory.resident` and `memory.peer_fillable` in bytes. Watch for either. When the kernel kills the node for exceeding `MemoryMax`, the unit logs `hashstash was killed for exceeding its memory limit`; each restart would hit the same limit again, so raise it instead of waiting. Monitor memory pressure, OOM restarts, disk growth (up to four saved states are kept; below 512 MiB free the node declines side-branch blocks and skips state checkpoints), peers and restart time. Header metadata and replay paths use bounded caches/disk indexes, but account state and retained history still grow. History is not pruned. The default 16 KiB block capacity and a 15-second observed interval alone permit about 94 MB/day of block bodies before database/index overhead; actual growth follows mining and transactions.

A panic while the node holds its shared chain, snapshot or wallet state, or a panic in a long-lived listener, peer-synchronization or discovery loop, ends the process with exit status 70 instead of leaving a running node that can no longer validate or has silently stopped a service. Likewise, once eight block commits in a row have failed over at least a minute, as on a full disk, the node exits with status 74 instead of running on a frozen tip; until then `status` and `peerstatus` report `storage.degraded`. Free space before the restart. A panic in a single connection or RPC request ends only that connection or request. The service restarts any failed exit after 10 seconds and has no start limit, so a fault that a peer can repeat cannot stop it permanently. On systemd 254 or later the delay grows with every automatic restart since the service was last restarted by hand or reset, up to 2 minutes after eight of them (`RestartSteps=8`, `RestartMaxDelaySec=2min`; older versions ignore these and keep the 10-second delay). A successful run does not reset that count, however long it lasts, so after dealing with a crash run `sudo systemctl reset-failed hashstash` (or restart the service by hand) to return to the 10-second delay; `systemctl show -p NRestarts hashstash` shows the count. The restart revalidates history from disk: from the newest state checkpoint that passes its checks, revalidating the stored blocks above it, or, without one, all of history. A checkpoint is saved every 1,024 blocks and at a clean stop, so a crash replays at most about 1,055 blocks and a stop and start about 31. A start is not cut short by a start timeout (`Type=simple`), and the stop timeout (`TimeoutStopSec=90`) covers saving a checkpoint; if a very large state takes longer, the interrupted save is discarded and the previous checkpoint serves. Alert on repeated restarts in the journal (`journalctl -u hashstash`), since a crash loop still needs an operator.

Run `bash deploy/linux/test-launcher.sh` for isolated launcher argument/admission regressions. It uses a stub binary and temporary files, never the host service paths. `bash deploy/linux/test-install-check.sh /absolute/path/hashstash` exercises read-only installation checks with the real Linux release; it creates only disposable fixture identities/configuration, plus a short-lived staging directory in `/run/lock` where that is a `noexec` mount, and does not install, enable or start a service. On Linux, `cargo test --locked --test operator_files` runs both scripts against the freshly built binary and checks that the installer's pinned version matches `Cargo.toml`. 
