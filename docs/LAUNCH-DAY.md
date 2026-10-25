# Launch day

This is the exact sequence for launching the public Hashstash 0.43.0 network on your own Linux servers: every server a public discovery seed, Stratum for your ASICs on the servers other than the web host, and the wallet website and faucet on one of the servers behind nginx and TLS. The [launch runbook](LAUNCH.md) explains the reasons behind each step; this page is the order of commands. `scripts/launch-kit.sh` writes every server's files and its `INSTALL.md`, so most steps below are "run step N of that server's `INSTALL.md`".

The network's parameters:

| | |
| --- | --- |
| Expected hashrate | 1.67 PH/s, 1 EH of expected work per 10 minutes |
| Genesis | `hashstash init --preset slow --hashrate 1.67P`, created once on launch day with the normal release build |
| Blocks | 15 seconds, 16 KiB; about 25 PH of expected work, so 25 atoms (0.025 hash) per block and about 1 hash per 10 minutes; 0.2% of work-implied issuance is discarded by rounding |
| Difficulty | ASERT with a 900-second half-life; the easiest permitted target is 256 times easier than the initial one |
| Ports | P2P 18481 public on every server; Stratum 18482 from your miners only, on every server except the web host; 80 and 443 on the web host; private RPC 18480, 19480, 20480, ... on loopback only |

Nothing here needs a cloud provider account or API key: the kit takes the servers' public IPv4 addresses, which the provider's dashboard shows. Never put a provider API key, a private key or a password into the kit, the repository or a chat.

## Before launch day (T-4 to T-1)

1. **Servers (T-4).** Note each server's public IPv4 address. IPv6-only servers are not supported: `deploy/linux/run-node.sh` binds P2P to `0.0.0.0`. Choose the web host and, preferably, a DNS name for it with an A record pointing at it (browsers apply HSTS only to names; without one, the site needs a six-day IP-address certificate from the certbot snap). Install the latest updates, and check the clock on every server: `timedatectl show -p NTPSynchronized --value` must print `yes`.
2. **Payout key (T-4).** On an offline machine, `hashstash keygen --out payout.key` and `hashstash public-key --key payout.key`. Back the key file up twice. Only the 64-character public key goes into the kit (`--payout-keys`); one key for all servers or one per server. The payout key never comes online: the faucet is funded from it through an unsigned transfer that the offline machine signs with the release's `hashstash-cold` (step 7), so keep that binary there too.
3. **Miner addresses (T-4).** Collect the public addresses or prefixes your ASICs (or their proxy) connect from, at least /16 for IPv4 and /32 for IPv6. They become `STRATUM_TRUSTED` and the only sources the firewall lets reach Stratum (`--miner-prefixes`). For rental marketplaces with unknown addresses add `--stratum-public`; the Stratum password still applies.
4. **Rehearse locally (T-4)** on a Linux machine or WSL 2, with the normal release build of the release commit and a test-fixtures build of it:

   ```sh
   cargo build --release --locked --bins
   CARGO_TARGET_DIR=target/fixtures cargo build --release --locked --bins --features test-fixtures
   python3 scripts/launch_rehearsal.py --release-dir target/release --fixture-release-dir target/fixtures/release
   ```

   It generates kits for three loopback "servers", runs each server's installer check, and starts the nodes with the kit's `run-node.sh` and `node.env`. On a real 1.67P genesis it checks seed-to-seed discovery and convergence, Stratum on the two servers that run it and none on the web host, the public web listener, and an outsider running the kit's published join command. On an uncalibrated rehearsal genesis made through the same kit with the backbone pinned, it mines blocks over Stratum on two servers, has an outsider join with the published command and reach the seeds' tip, has a node that knows one seed and advertises itself passed on to that outsider through gossip, and exercises the faucet with nginx's headers. With the test-fixtures build it funds the faucet as `INSTALL.md` step 11 does (prepared on the web host, signed by `hashstash-cold`, broadcast) and completes three claims, each sent the moment a new block arrives and each paid on its first attempt; a release build issues nothing for CPU-mined blocks. Every process it starts is stopped at the end. It does not exercise nginx, certbot, ufw, the systemd units, `archive-old-node.sh` against a real installation, or your ASICs: item 7 does.
5. **Build the release (T-3)**, as in step 1 below. Launch day reuses this build.
6. **Optional: pin the backbone (T-3).** With pins, each seed accepts the other seeds only with their own transport keys. Copy the release `hashstash` binary to every server and run there `install -d -m 700 /root/hashstash-keys && ./hashstash peer-keygen --out /root/hashstash-keys/peer-identity.json`; it prints the public key. Pass the keys as `--peer-pins IP1=KEY1,IP2=KEY2,...` to both the rehearsal kit (item 7) and the launch kit (step 2). The identity stays in `/root/hashstash-keys`, which `INSTALL.md` step 5 reuses and `archive-old-node.sh` never touches. Without pins, each server generates its identity in step 5 of the first kit it installs and reuses it afterwards.
7. **Rehearse on the real servers (T-2)**, as [section 10 of the runbook](LAUNCH.md#10-rehearsal) requires: nginx, certbot, ufw, the faucet under systemd and its offline funding, `archive-old-node.sh` against the earlier installation, and your ASICs all run here before launch day. Generate a throwaway kit with exactly the options of step 2 and its own `--out`:

   ```sh
   bash scripts/launch-kit.sh ... --out ~/hashstash-rehearsal-kit     # the options of step 2
   ```

   It is a real 1.67P genesis; never publish its values. Then follow steps 3 to 8 below with it on every server: copy and archive (step 3; `INSTALL.md` step 0 puts each kit in a new directory named after its chain), install (4), including `INSTALL.md` step 8 on the web host (nginx and the certificate, which stay for launch day), start the seeds (5), mine with the ASICs for at least an hour (6), fund the faucet through the offline flow with a small amount (change `12000` in `faucet-funding.json` to, say, `1000`: an hour of mining issues about 6,000 atoms) and start it (7), and enable the website (8). Work through the rest of runbook section 10 as time allows: a transaction through the website, an offline-signed one, a backup and restore of one node, a stopped seed, a killed process. Then rehearse the rollback: stop the faucet and the node (`sudo systemctl stop hashstash-faucet hashstash`) and run `sudo bash archive-old-node.sh` on every server, which must end with `No Hashstash service or process is running.` Pause the ASICs until launch-day step 6: they keep the Stratum password, which the launch reuses from `/root/hashstash-keys`. This takes any earlier network on these servers down at T-2; if it must stay up until launch day, rehearse on new servers made from the same image instead.
8. **Fix what the rehearsals found (T-1).** If the fix changes the release commit, rebuild the release (item 5) and repeat the affected parts of both rehearsals.

## 1 Build and verify the release

Build once, at T-3, on a Linux clone of the repository (not a Windows checkout built under WSL, whose commit `release.sh` cannot record):

```sh
git clone https://github.com/top-type/Hashstash.git hashstash-release
cd hashstash-release
git checkout RELEASE_COMMIT
bash scripts/release.sh --verify
cd target/dist/hashstash-0.43.0-linux-x86_64
sha256sum -c SHA256SUMS
./hashstash --version
cd -
```

Check: both builds are byte-identical (`--verify`), `sha256sum -c` prints `OK` for `hashstash`, `hashstash-cold` and `hashstash-faucet`, and the version is `hashstash 0.43.0`. If a second person can build the same commit, compare `SHA256SUMS`; sign it (`gpg --armor --detach-sign SHA256SUMS`). On launch day, repeat only the `sha256sum -c SHA256SUMS` and `--version` checks on that build.

## 2 Create the genesis and the kit, once

From the same checkout, with the release built at T-3:

```sh
bash scripts/launch-kit.sh \
  --seeds IP1,IP2,IP3 --web-host IP1 --domain wallet.example.com \
  --stratum-hosts IP2,IP3 \
  --hashrate 1.67P --binary target/dist/hashstash-0.43.0-linux-x86_64/hashstash \
  --miner-prefixes 198.51.100.0/24 --payout-keys PAYOUT_PUBLIC_KEY \
  --admin-prefixes YOUR_ADMIN_ADDRESS/32 \
  --out ~/hashstash-launch
```

Add `--peer-pins` from item 6 of the T-4 to T-1 list if you pinned. Leave out `--admin-prefixes` if your own address changes: SSH then stays open to everyone, rate-limited (the provider's web console remains a way in either way). Do not pass `--genesis-time`: the genesis time is the clock at `init`, and the kit refuses one more than 120 seconds ahead because `init` warns about it.

`--stratum-hosts IP2,IP3` is the kit's default, written out: Stratum on every seed except the web host. [Section 7 of the runbook](LAUNCH.md#7-stratum) keeps Stratum off seeds when dedicated mining nodes serve the miners; on this network every server is a seed, so the seeds other than the web host serve the miners, and the web host, which holds the faucet's key and serves the wallet, runs none. `--stratum-hosts all` would include it.

The kit:

- verifies the release files against `SHA256SUMS` and refuses a test-fixtures build;
- runs `init --preset slow --hashrate 1.67P` exactly once, refusing to continue if it prints any warning, and runs the node's own startup checks on the genesis behind public P2P and discovery, which refuse an uncalibrated limit;
- validates every input strictly: numeric public IPv4 seeds (no private, reserved or documentation ranges), no duplicates, the web host among the seeds, narrow miner prefixes without host bits, distinct ports that leave 80 and 443 to nginx, 64-hex keys;
- writes `server-N-IP/` for every server and `README.md`, `ANNOUNCEMENT.md` and `launch-values.env` with the chain ID, `network.json` SHA256, release hashes and the directory each server's files go to (`KIT_REMOTE_DIR`, named after the chain ID). It never overwrites an existing directory and never embeds a secret.

Record the chain ID and the `network.json` SHA256 from `launch-values.env`. Never run the kit with `--hashrate` a second time for the launch: each run creates a different chain. To regenerate the files for the same chain, use `--genesis ~/hashstash-launch/genesis/network.json` and a new `--out`.

Before installing, publish `SHA256SUMS` (and its signature), the `network.json` SHA256 and the chain ID through a second channel, so that every server's values can be compared with it.

## 3 Stop and archive the old nodes (every server)

Copy each server's directory (`INSTALL.md` step 0), then run steps 1 and 2. Step 0 copies the kit into a new directory named after its chain ID and creation time (`KIT_REMOTE_DIR`), refusing one that exists, so the launch kit never lands inside the rehearsal's kit; run every later step from that directory. `archive-old-node.sh` stops and disables every `hashstash*` service, refuses to go on while a Hashstash process started by hand still runs (`--stop-processes` stops those with SIGINT), and moves `/var/lib/hashstash`, `/etc/hashstash`, the faucet's files and the old units into `/root/hashstash-archive-STAMP`. Nothing is deleted, and the 0.42.0 data is never reused: 0.43.0 refuses a database holding 0.42.0 blocks, naming that release, and refuses 0.42.0 peers at their first message. It leaves `/root/hashstash-keys`, nginx, `/etc/letsencrypt` and the firewall in place. Stop or repoint any miner still pointed at the old Stratum, and keep the ASICs paused until step 6.

Check on every server: `No Hashstash service or process is running.`

## 4 Install every server

Run `INSTALL.md` steps 3 to 7 on each server: verify the release and genesis hashes against the published values (step 3 must print the chain ID published in step 2; any other value means the wrong kit), check the payout address (4), generate the peer identity and Stratum password on the server or reuse those of the rehearsal (5), run `deploy/install.sh --check` and then the install (6, with the pinned hashes; it neither enables nor starts the node), and apply the firewall (7). On the web host, also run `INSTALL.md` step 8 (nginx and the certificate) unless the on-host rehearsal already did: the certificate stays in `/etc/letsencrypt`, and step 12 needs it.

Check on every server: the installer printed `Configuration and payout public key are valid` and `Installed.`; `ufw status` shows 18481 open, 18482 only from your miners (or open, with `--stratum-public`) on the Stratum servers and denied on the web host, 80 and 443 only on the web host, and the RPC port denied. On the web host, `/etc/letsencrypt/live/HOST/` holds the certificate. From another network, `nc -vz IP 18481` connects for every server once its node runs.

## 5 Start the seeds

On every server, within a few minutes of each other, `INSTALL.md` step 9:

```sh
sudo systemctl enable --now hashstash
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh snapshot | grep -E '"(chain_id|height|tip|state_root)"'
sudo -u hashstash "$(cat /etc/hashstash/binary.path)" rpc --url http://127.0.0.1:RPC_PORT/rpc peerstatus
```

Check before going on: every server reports the published `chain_id`, height 0 and the same `tip` (the genesis block); `peerstatus` shows `transport` `authenticated-discovery`, `discovery.verified` equal to the number of other seeds, and each configured peer `reachable` with a recent `last_success`; the journal has no `fatal:` line. In the local rehearsal all three seeds verified each other within two seconds.

## 6 Start the miners

Point the ASICs at the Stratum servers (`INSTALL.md` step 10): `stratum+tcp://IP:18482` on every server except the web host, any worker name, and that server's Stratum password (`sudo cat /etc/hashstash/stratum-password`). Every block found through a server pays that server's `MINER_PUBLIC_KEY`.

Check during the first hour: heights rise on every server at the same `tip` and `state_root`; `workers_connected` counts your rigs, `accepted_shares` rises faster than `rejected_shares`, and `blocks_found` rises on the server that found each block. Blocks average 15 seconds once the hashrate matches the calibration. If the real hashrate differs, difficulty moves by a factor of two per 900 seconds of schedule error; do not change the genesis. `SHARE_DIFFICULTY` (65536) is only the reporting threshold, and the node raises a fast worker's difficulty by itself; for a fleet of fast machines, about machine hashrate times 5 seconds divided by 2^32 (131072 for 100 TH/s) avoids the first adjustments (`--share-difficulty`).

## 7 Fund and start the faucet

After the chain has run for a while and your payout key holds coins, run the web host's `INSTALL.md` step 11: install the pinned `hashstash-faucet` binary, its account, configuration and service, and generate the faucet key on the server. Then fund it without bringing the payout key online ([section 5 of the runbook](LAUNCH.md#5-keys-and-secrets)): on the web host, `hashstash prepare` writes an unsigned transfer to the faucet's address through the node's own private RPC, using only the payout public key; on the offline machine, `hashstash-cold` reviews and signs it with the payout key; back on the web host, `hashstash broadcast` sends the signed result. The transfer is prepared with a 240-block lifetime (an hour at 15-second blocks): the default two blocks are 30 seconds, too short for the round trip. Then start the faucet.

The default payout is 0.01 hash per claim (`--faucet-payout 10` atoms), at most 250 claims a day and 1,000 in the ledger's lifetime, one claim per address per day and ten per /24 or /48 a day. Each payment also pays its fee: 1 atom to an existing account and 2 to a new one at the launch fee rate. About 12 hashes (12,000 atoms) therefore cover the lifetime allowance; `INSTALL.md` step 11 uses that amount, about two hours of the network's issuance.

The faucet trusts only the `X-Real-IP` header and only an allowed `Host`: nginx overwrites `X-Real-IP` with the connecting address in the `/faucet/` route ([faucet](FAUCET.md#website-and-proxy)), and the faucet listens on loopback only.

Check: `broadcast` printed the transaction ID; the journal says `Hashstash faucet: 127.0.0.1:18484`; `curl -s -H 'Host: wallet.example.com' -H 'X-Real-IP: 192.0.2.1' http://127.0.0.1:18484/faucet/status` shows the chain ID and, after the funding transfer is confirmed and a new block arrives, `"state":"ready"`; the same request without `X-Real-IP` gets HTTP 403.

## 8 Enable the website

Run the web host's `INSTALL.md` step 12: install the full nginx site and reload; `nginx -t` fails if the certificate of step 4 is missing. From another network check that `https://` loads with a valid certificate, `http://` redirects, `/faucet-config.json` names the HTTPS origin and the chain ID, a private method such as `peers` is refused on `/rpc`, and Wallet shows **Get test hashes** while the faucet is funded.

## 9 Announce

Abort instead of announcing if nodes disagree on the genesis tip, a state root differs at the same height, a node crash-loops, or no blocks are found. Otherwise publish the kit's `ANNOUNCEMENT.md` through at least two channels with `network.json`, `SHA256SUMS` and its signature: it carries the chain ID, the hashes, the seeds, the website, the command for joining with `--peer-discovery` and every seed, and the limitations below. Keep every seed in the join command: each seed lists the others as configured peers, which a node never passes on, so a node that knows a single seed learns from it only nodes that advertise themselves.

### Disclosure: accepted limitations

Tell users, with the announcement and on the website (the full text is [section 15 of the runbook](LAUNCH.md#15-limitations-users-must-be-told), which `ANNOUNCEMENT.md` copies verbatim):

- **No limit prices.** Stash orders state only the amount; all orders in a block clear at one price, which may move up to 10% per block, and another order in the same block (which a miner can place) moves the price paid.
- **PASS margin 0 on flat curves.** At the genesis exchange rate no trade moves the price, so a revenue-funded grant or setting change decided on a flat curve resolves FAIL. Outcomes reflect trading, not merit.
- **Auction griefing.** A well-funded bidder can delay another proposal's decision until the auction timeout, at the cost of fees.
- **Reward rounding.** Each block issues whole atoms of one petahash of expected work and discards the rest. At 1.67 PH/s that is 25 atoms per block and 0.2% lost; at much lower hashrate the loss grows.
- **Long partitions need manual recovery.** After a split longer than about 11 days of evenly split blocks, nodes on the lighter side stay there until their operators resynchronize them.
- **No transport encryption.** Peer traffic is authenticated but readable, Stratum V1 including its password is plain TCP, and the private RPC must stay on loopback. Only the website uses TLS.
- **Mail without forward secrecy.** Mail ciphertext stays on the chain; whoever later obtains an account's key can read all its past mail. Senders, amounts and timing are public.

Also: browser keys are unencrypted unless a wallet passphrase is set; the website must be trusted like wallet software (bookmark the `https://` address); a transaction is final only after enough confirmations; the faucet's limits are per address and network, not per person; and the software has not had a complete independent audit.

## 10 Monitoring after launch

Poll every server about every 10 seconds, with alerts as in [section 12 of the runbook](LAUNCH.md#12-monitoring). The essential ones for the first days:

| Watch | Command (on the server) | Act when |
| --- | --- | --- |
| Agreement | `run-node.sh snapshot`: `height`, `tip`, `state_root` | Two servers differ at the same height for more than a few blocks |
| Progress | `peerstatus`: `chain_stalled`, `seconds_without_new_tip` | Stalled: check miners, Stratum and clocks |
| Peers | `peerstatus`: `discovery.verified`, `peers[].reachable` | Verified falls toward zero or a seed stays unreachable |
| Mining | `snapshot` mining section | Workers drop, rejected shares outgrow accepted ones |
| Process | `journalctl -u hashstash`, `systemctl show -p NRestarts hashstash` | Any `fatal:` line, an out-of-memory kill, rising restarts |
| Memory, disk | `systemctl show -p MemoryCurrent,MemoryPeak hashstash`, `df -h /var/lib/hashstash` | Above 80% of `MemoryHigh` (512M); free disk below 20% |
| Website, faucet | nginx access log, `journalctl -u hashstash-faucet`, certificate expiry | Many 429/503/5xx answers, faucet `nonce_conflict` or `node_busy`, a certificate expiring within 14 days (2 days for a six-day IP-address certificate) |

Back up each server one at a time with the service stopped ([section 13](LAUNCH.md#13-backups-and-restore)); `/etc/hashstash` holds the peer identity and Stratum password, and `/etc/hashstash-faucet` the faucet key, so encrypt those archives. Once the encrypted backup of `/etc/hashstash` exists, remove the staging copies on each server: `shred -u /root/hashstash-keys/*` (the last section of its `INSTALL.md`).

## Rollback

- **Before the announcement**, any failed check can still restart the launch. Stop the faucet and every node (`sudo systemctl stop hashstash-faucet hashstash`), run `archive-old-node.sh` on every server (it moves the abandoned chain's data and configuration aside), create a new genesis and kit with `--hashrate 1.67P` and the same other options (the same `--peer-pins`: the identities stay in `/root/hashstash-keys`) into a new `--out`, and publish the new chain ID. Then copy each server's new directory (`INSTALL.md` step 0, as in step 3 here; it goes to a new directory named after the new chain ID) and continue from step 4: `INSTALL.md` step 3 must print the new chain ID. Never reuse a data directory across geneses. If `/root/hashstash-keys` was emptied meanwhile, restore each server's peer identity from the archive first: `install -m 600 /root/hashstash-archive-STAMP/etc/hashstash/peer-identity.json /root/hashstash-keys/`.
- **After the announcement** the genesis is fixed: users hold balances on it. Handle incidents as in [section 14 of the runbook](LAUNCH.md#14-incident-response): restart a crashed node (`systemctl reset-failed hashstash` after fixing the cause), resynchronize a node on a lighter branch in pinned-only mode, rotate a compromised peer identity, Stratum password or faucet key. There is no rollback to 0.42.0: the releases are incompatible.
- **Faucet:** `sudo systemctl stop hashstash-faucet` pauses it; move its remaining funds with its key if it is compromised. Keep its SQLite ledger; never delete it to clear a pending claim.
- **Website:** to take it offline without touching the node, put the ACME bootstrap site back (`sudo install -m 644 nginx/acme-bootstrap.conf /etc/nginx/sites-available/hashstash && sudo nginx -t && sudo systemctl reload nginx`). If the web host may be compromised, tell users not to enter keys there and rebuild it.
- **Miners:** a stalled or split chain is not fixed by repointing miners in a hurry; first confirm which tip every server follows.
