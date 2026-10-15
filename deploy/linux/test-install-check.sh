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
"$binary" init --config "$fixture/network.json" --preset dev > "$fixture/init.out"
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
check() {
  bash "$repo/deploy/linux/install.sh" --binary "$binary" --sha256 "$binary_hash" \
    --genesis "$fixture/network.json" --genesis-sha256 "$genesis_hash" \
    --node-env "$fixture/node.env" "$@" --check > "$fixture/out" 2> "$fixture/err"
}
pass() { check "$@" || { cat "$fixture/err" >&2; exit 1; }; checks=$((checks+1)); }
reject() { if check "$@"; then printf 'Unexpected install-check acceptance\n' >&2; exit 1; fi; checks=$((checks+1)); }
base; pass --peer-key-file "$fixture/peer.json"
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
printf '%s real-binary read-only Linux installation checks passed\n' "$checks"
