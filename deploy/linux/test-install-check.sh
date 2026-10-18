#!/usr/bin/env bash
# Read-only installer preflights with a real Linux release. No service changes.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ $# == 1 ]] || { printf 'Usage: bash test-install-check.sh /absolute/path/hashstash\n' >&2; exit 1; }
binary=$(realpath -e -- "$1")
fixture=$(mktemp -d /tmp/hashstash-install-check.XXXXXXXX)
[[ "$fixture" == /tmp/hashstash-install-check.* && -d "$fixture" ]] || exit 1
trap 'rm -rf -- "$fixture"' EXIT
checks=0
binary_hash=$(sha256sum -- "$binary"); binary_hash=${binary_hash%% *}
# The service binds P2P to 0.0.0.0, which run allows only on a calibrated genesis.
"$binary" init --config "$fixture/network.json" --preset dev --hashrate 100T > "$fixture/init.out"
genesis_hash=$(sha256sum -- "$fixture/network.json"); genesis_hash=${genesis_hash%% *}
own=$("$binary" peer-keygen --out "$fixture/peer.json")
other=$("$binary" peer-keygen --out "$fixture/other-peer.json")
miner=$("$binary" peer-keygen --out "$fixture/payout-fixture.json")
[[ "$own" =~ ^[0-9a-f]{64}$ && $("$binary" peer-keycheck --key-file "$fixture/peer.json" --miner "$miner" --peer-pin "192.0.2.2:18481=$other") == "$own" ]]
checks=$((checks+1))
base() {
  cat > "$fixture/node.env" <<EOF
MINER_PUBLIC_KEY=$miner
RPC_PORT=18480
P2P_PORT=18481
STRATUM_PORT=18482
STRATUM_ENABLED=false
STRATUM_ADVERTISE=miner.example:18482
SHARE_DIFFICULTY=65536
PEERS=192.0.2.2:18481
PEER_KEY_FILE=/etc/hashstash/peer-identity.json
PEER_PINS=192.0.2.2:18481=$other
EOF
}
stage_tmpdir= candidate= candidate_hash= genesis_file= genesis_pin=
check() {
  TMPDIR=${stage_tmpdir:-${TMPDIR:-/tmp}} bash "$repo/deploy/linux/install.sh" --binary "${candidate:-$binary}" --sha256 "${candidate_hash:-$binary_hash}" \
    --genesis "${genesis_file:-$fixture/network.json}" --genesis-sha256 "${genesis_pin:-$genesis_hash}" \
    --node-env "$fixture/node.env" "$@" --check > "$fixture/out" 2> "$fixture/err"
}
pass() { check "$@" || { cat "$fixture/err" >&2; exit 1; }; checks=$((checks+1)); }
reject() { if check "$@"; then printf 'Unexpected install-check acceptance\n' >&2; exit 1; fi; checks=$((checks+1)); }
base; pass --peer-key-file "$fixture/peer.json"
# Inputs are staged privately; a directory other accounts can rename into is refused.
mkdir -- "$fixture/shared"; chmod 777 -- "$fixture/shared"
stage_tmpdir=$fixture/shared; reject --peer-key-file "$fixture/peer.json"
grep -Fq 'staging directory is modifiable by another account' "$fixture/err"; checks=$((checks+1))
chmod 1777 -- "$fixture/shared"; pass --peer-key-file "$fixture/peer.json"; stage_tmpdir=
[[ -z $(ls -A -- "$fixture/shared") ]]; checks=$((checks+1))
# A staged binary that cannot run at all is reported as such, not as another release.
candidate=$fixture/unrunnable; { printf '\177ELF'; head -c 60 /dev/zero; } > "$candidate"; chmod 755 -- "$candidate"
candidate_hash=$(sha256sum -- "$candidate"); candidate_hash=${candidate_hash%% *}
reject --peer-key-file "$fixture/peer.json"; candidate= candidate_hash=
grep -Fq 'staged binary cannot be executed' "$fixture/err"; checks=$((checks+1))
# Debian and Ubuntu mount the sticky /run/lock noexec; staging there names the cause.
if [[ ,$(findmnt -no OPTIONS --target /run/lock 2>/dev/null), == *,noexec,* && -d /run/lock && -k /run/lock && -w /run/lock ]]; then
  stage_tmpdir=/run/lock; reject --peer-key-file "$fixture/peer.json"; stage_tmpdir=
  grep -Fq 'staging directory does not allow execution' "$fixture/err"; checks=$((checks+1))
fi
chmod 644 "$fixture/peer.json"; reject --peer-key-file "$fixture/peer.json"; chmod 600 "$fixture/peer.json"
ln -s "$fixture/peer.json" "$fixture/peer-link.json"; reject --peer-key-file "$fixture/peer-link.json"
"$binary" keygen --out "$fixture/wallet.json" > "$fixture/keygen.out"
reject --peer-key-file "$fixture/wallet.json"
reject
sed -i "s/^MINER_PUBLIC_KEY=.*/MINER_PUBLIC_KEY=$own/" "$fixture/node.env"; reject --peer-key-file "$fixture/peer.json"
base; sed -i "s/^PEER_PINS=.*/PEER_PINS=192.0.2.2:18481=$own/" "$fixture/node.env"; reject --peer-key-file "$fixture/peer.json"
base; sed -i 's/^STRATUM_ENABLED=false/STRATUM_ENABLED=true/' "$fixture/node.env"; reject --peer-key-file "$fixture/peer.json"
printf 'test-mining-password\n' > "$fixture/password"; pass --peer-key-file "$fixture/peer.json" --stratum-password-file "$fixture/password"
base; sed -i '/^PEER_KEY_FILE=/d; /^PEER_PINS=/d' "$fixture/node.env"; pass
reject --peer-key-file "$fixture/peer.json"
# The uncalibrated development limit of a production-denominated genesis: the
# preflight refuses it behind the service's 0.0.0.0 P2P listener, as the
# service itself would at every restart, unless node.env allows it.
"$binary" init --config "$fixture/easy.json" --preset dev > "$fixture/init.out" 2>&1
sed -i 's/"test_work": true/"test_work": false/' "$fixture/easy.json"
genesis_file=$fixture/easy.json; genesis_pin=$(sha256sum -- "$genesis_file"); genesis_pin=${genesis_pin%% *}
base; sed -i '/^PEER_KEY_FILE=/d; /^PEER_PINS=/d' "$fixture/node.env"; reject
grep -Fq -- '--allow-easy-target' "$fixture/err"; checks=$((checks+1))
printf 'ALLOW_EASY_TARGET=true\n' >> "$fixture/node.env"; pass
genesis_file= genesis_pin=
printf '%s real-binary read-only Linux installation checks passed\n' "$checks"
