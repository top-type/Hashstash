#!/usr/bin/env bash
# Local argument-validation tests only. No service or network operations.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
fixture=$(mktemp -d /tmp/hashstash-launcher-test.XXXXXXXX)
[[ "$fixture" == /tmp/hashstash-launcher-test.* && -d "$fixture" ]] || exit 1
trap 'rm -rf -- "$fixture"' EXIT
checks=0
key=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
peer_key=c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
cat > "$fixture/binary" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >> "$HASHSTASH_TEST_ARGS"
EOF
chmod 755 "$fixture/binary"
printf '{}\n' > "$fixture/network.json"
printf 'fixture-password\n' > "$fixture/password"
printf 'dedicated key validation is delegated to the real binary\n' > "$fixture/peer.json"
chmod 600 "$fixture/peer.json"
export HASHSTASH_TEST_ARGS="$fixture/args"
base() {
  cat > "$fixture/node.env" <<EOF
MINER_PUBLIC_KEY=$key
RPC_PORT=18480
P2P_PORT=18481
STRATUM_PORT=18482
STRATUM_ADVERTISE=miner.example:18482
SHARE_DIFFICULTY=65536
PEERS=192.0.2.2:18481
EOF
}
auth() { printf 'PEER_KEY_FILE=%s\nPEER_PINS=192.0.2.2:18481=%s\n' "$fixture/peer.json" "$peer_key" >> "$fixture/node.env"; }
discovery() { printf 'PEER_DISCOVERY=true\nPEER_SEEDS=seed.example:18481 192.0.2.3:18481\nPEER_ADVERTISE=192.0.2.1:18481\n' >> "$fixture/node.env"; }
launch() { bash "$repo/deploy/linux/run-node.sh" "$@" "$fixture/node.env" "$fixture/binary" "$fixture/network.json" "$fixture/password" > "$fixture/out" 2> "$fixture/err"; }
pass() { : > "$fixture/args"; launch "$1" || { cat "$fixture/err" >&2; exit 1; }; checks=$((checks+1)); }
reject() { : > "$fixture/args"; if launch "${1:-run}"; then printf 'Unexpected acceptance: %s\n' "$2" >&2; exit 1; fi; [[ ! -s "$fixture/args" ]] || { printf 'Invalid input reached binary: %s\n' "$2" >&2; exit 1; }; checks=$((checks+1)); }
has() { grep -Fxq -- "$1" "$fixture/args"; checks=$((checks+1)); }
lacks() { ! grep -Fxq -- "$1" "$fixture/args"; checks=$((checks+1)); }
replace() { sed -i "s|^$1=.*|$1=$2|" "$fixture/node.env"; }
# Check mode starts the node only as a preflight, which opens and binds nothing.
preflight() { has run; has --preflight; [[ $(grep -Fxc -- run "$fixture/args") == $(grep -Fxc -- --preflight "$fixture/args") ]]; checks=$((checks+1)); }
base; pass run; has --stratum; has --stratum-password-file; lacks --wallet; lacks --preflight; lacks --allow-easy-target
# An easy-target genesis behind the 0.0.0.0 P2P listener runs only when node.env says so.
base; printf 'ALLOW_EASY_TARGET=true\n' >> "$fixture/node.env"; pass run; has --allow-easy-target; lacks --preflight
pass check; preflight; has --allow-easy-target
base; printf 'ALLOW_EASY_TARGET=false\n' >> "$fixture/node.env"; pass run; lacks --allow-easy-target; pass check; preflight; lacks --allow-easy-target
for enabled in '' maybe True 1; do base; printf 'ALLOW_EASY_TARGET=%s\n' "$enabled" >> "$fixture/node.env"; reject run 'invalid easy-target mode'; done
base; auth; pass run; has --peer-key-file; has --peer-pin; has "192.0.2.2:18481=$peer_key"
base; auth; pass check; has peer-keycheck; preflight
base; auth; pass run; lacks --peer-discovery; lacks --seed; lacks --advertise-peer
base; auth; discovery; pass run
has --peer-discovery; has --seed; has seed.example:18481; has 192.0.2.3:18481; has --advertise-peer; has 192.0.2.1:18481
has --peer-key-file; has --peer-pin; has "192.0.2.2:18481=$peer_key"; has --peer; has 192.0.2.2:18481
[[ $(grep -Fxc -- --seed "$fixture/args") == 2 ]]; checks=$((checks+1))
pass check; has peer-keycheck; has --peer-discovery; has --peer-pin; preflight
base; auth; discovery; replace PEER_PINS ''; pass run; has --peer-key-file; has --peer-discovery; lacks --peer-pin
pass check; has peer-keycheck; has --peer-discovery; lacks --peer-pin
base; auth; discovery; replace PEERS ''; replace PEER_PINS ''; replace PEER_SEEDS ''; replace PEER_ADVERTISE ''; pass run; has --peer-discovery; lacks --peer; lacks --seed; lacks --advertise-peer
base; auth; discovery; replace PEER_PINS "192.0.2.3:18481=$peer_key"; pass run; has "192.0.2.3:18481=$peer_key"
base; auth; discovery; replace PEER_PINS "192.0.2.4:18481=$peer_key"; pass check; has "192.0.2.4:18481=$peer_key"
base; auth; discovery; replace PEER_SEEDS '[2001:db8::3]:18481'; replace PEER_ADVERTISE '[2001:db8::1]:18481'; pass run; has '[2001:db8::3]:18481'; has '[2001:db8::1]:18481'
base; auth; replace PEERS '[2001:db8::2]:18481'; replace PEER_PINS "[2001:db8::2]:18481=$peer_key"; pass run; has "[2001:db8::2]:18481=$peer_key"; lacks --peer-discovery
for endpoint in '[2001:db8:0:0:0:0:0:2]:18481' '[2001:db8:1:2:3:4:5::]:18481'; do
  base; auth; discovery; replace PEER_ADVERTISE "$endpoint"; pass run; has "$endpoint"
done
base; printf 'STRATUM_ENABLED=false\n' >> "$fixture/node.env"; rm -- "$fixture/password"; pass run; has --no-stratum; lacks --stratum; lacks --stratum-password-file; pass check
printf 'fixture-password\n' > "$fixture/password"
base; printf 'STRATUM_TRUSTED=198.51.100.0/24 2001:db8:10::/48 192.0.2.9\n' >> "$fixture/node.env"; pass run
[[ $(grep -Fxc -- --stratum-trusted "$fixture/args") == 3 ]]; checks=$((checks+1)); has 198.51.100.0/24; has 2001:db8:10::/48; has 192.0.2.9
base; pass run; lacks --stratum-trusted
for prefix in 'miner.example' '192.0.2.0/24;id' '192.0.2.0/1234'; do
  base; printf 'STRATUM_TRUSTED=%s\n' "$prefix" >> "$fixture/node.env"; reject run "trusted prefix $prefix"
done
base; printf 'STRATUM_ENABLED=false\nSTRATUM_TRUSTED=192.0.2.9\n' >> "$fixture/node.env"; rm -- "$fixture/password"; reject run 'trusted prefix without Stratum'
printf 'fixture-password\n' > "$fixture/password"
# A public prefix shorter than IPv4 /16 or IPv6 /32 would exempt much of the
# internet from the pending limits; only STRATUM_TRUSTED_BROAD accepts one.
for prefix in 0.0.0.0/0 ::/0 198.50.0.0/15 2001:db8::/31 11.0.0.0/8 172.32.0.0/12 100.128.0.0/10 fe00::/8; do
  base; printf 'STRATUM_TRUSTED=%s\n' "$prefix" >> "$fixture/node.env"; reject run "broad trusted prefix $prefix"
done
base; printf 'STRATUM_TRUSTED=198.51.0.0/16 2001:db8::/32 10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 100.64.0.0/10 fd00::/8 fe80::/10\n' >> "$fixture/node.env"; pass run
[[ $(grep -Fxc -- --stratum-trusted "$fixture/args") == 8 ]]; checks=$((checks+1)); lacks --stratum-trusted-broad
base; printf 'STRATUM_TRUSTED=192.0.2.9\nSTRATUM_TRUSTED_BROAD=0.0.0.0/0 ::/0\n' >> "$fixture/node.env"; pass run
[[ $(grep -Fxc -- --stratum-trusted-broad "$fixture/args") == 2 ]]; checks=$((checks+1)); has 0.0.0.0/0; has ::/0; has --stratum-trusted
for prefix in 'miner.example' '0.0.0.0/0;id' '0.0.0.0/1234'; do
  base; printf 'STRATUM_TRUSTED_BROAD=%s\n' "$prefix" >> "$fixture/node.env"; reject run "broad trusted prefix $prefix"
done
base; printf 'STRATUM_ENABLED=false\nSTRATUM_TRUSTED_BROAD=0.0.0.0/0\n' >> "$fixture/node.env"; rm -- "$fixture/password"; reject run 'broad trusted prefix without Stratum'
printf 'fixture-password\n' > "$fixture/password"
for endpoint in 256.0.0.1:18481 01.0.0.1:18481 1.2.3.4:0 1.2.3.4:65536 1.2.3.4:018481 0.0.0.0:18481 255.255.255.255:18481 bad.example:18481; do
  base; replace PEERS "$endpoint"; reject run "peer $endpoint"
  base; auth; replace PEER_PINS "$endpoint=$peer_key"; reject run "pin $endpoint"
done
base; replace PEERS '192.0.2.2:18481 192.0.2.2:18481'; reject run 'duplicate peers'
base; auth; replace PEER_PINS "192.0.2.3:18481=$peer_key"; reject run 'mismatched pins'
base; auth; replace PEER_PINS "192.0.2.2:18481=$peer_key 192.0.2.2:18481=$peer_key"; reject run 'duplicate pins'
base; auth; replace PEER_PINS ''; reject run 'missing pins'
for enabled in '' maybe True 1; do base; auth; printf 'PEER_DISCOVERY=%s\n' "$enabled" >> "$fixture/node.env"; reject run 'invalid discovery mode'; done
base; discovery; reject run 'discovery requires a dedicated peer identity'
base; auth; discovery; replace PEER_DISCOVERY false; reject run 'discovery fields cannot silently apply to pinned-only mode'
base; auth; printf 'PEER_SEEDS=seed.example:18481\n' >> "$fixture/node.env"; reject run 'seeds require explicit discovery'
base; auth; printf 'PEER_ADVERTISE=192.0.2.1:18481\n' >> "$fixture/node.env"; reject run 'advertise requires explicit discovery'
for endpoint in https://seed.example:18481 seed.example:0 seed.example:65536 seed.example:018481 -seed.example:18481 seed-.example:18481 seed..example:18481 .seed.example:18481 seed.example.:18481 'seed.example:18481/path' 'user@seed.example:18481' 'seed.example:18481;echo' 256.0.0.1:18481 01.0.0.1:18481 '[2001:db8:::3]:18481' '[2001:db8::1::3]:18481' '[2001:db8:3]:18481' '[2001:db8:1:2:3:4:5:6::]:18481' '[2001:db8:1:2:3:4:5:6:7]:18481' '[::]:18481' '[fe80::1%eth0]:18481'; do
  base; auth; discovery; replace PEER_SEEDS "$endpoint"; reject run "invalid seed $endpoint"
done
for endpoint in seed.example:18481 0.0.0.0:18481 255.255.255.255:18481 1.2.3.4:0 1.2.3.4:65536 1.2.3.4:018481 '[2001:db8:::1]:18481' '[2001:db8::1::2]:18481' '[::]:18481'; do
  base; auth; discovery; replace PEER_ADVERTISE "$endpoint"; reject run "invalid advertisement $endpoint"
done
base; auth; discovery; replace PEER_SEEDS 'seed.example:18481 SEED.example:18481'; reject run 'case-insensitive duplicate DNS seeds'
base; auth; discovery; replace PEER_SEEDS "$(printf 'a%.0s' {1..64}).example:18481"; reject run 'overlong DNS label'
base; auth; discovery; replace PEER_SEEDS "$(printf 'seed.example:18481 %.0s' {1..65})"; reject run 'too many seeds'
base; auth; discovery; replace PEER_PINS "192.0.2.2:18481=$peer_key 192.0.2.2:18481=$peer_key"; reject run 'discovery never relaxes duplicate pin validation'
base; auth; discovery; replace PEER_PINS '192.0.2.2:18481=not-a-key'; reject run 'discovery never relaxes pin key validation'
base; auth; replace PEER_KEY_FILE ''; reject run 'missing identity'
base; auth; replace PEER_KEY_FILE 'relative.json'; reject run 'relative identity'
ln -s "$fixture/peer.json" "$fixture/peer-link.json"
base; auth; replace PEER_KEY_FILE "$fixture/peer-link.json"; reject run 'symlink identity'
base; printf 'STRATUM_ENABLED=maybe\n' >> "$fixture/node.env"; reject run 'invalid mining mode'
base; printf 'PEERS=192.0.2.3:18481\n' >> "$fixture/node.env"; reject run 'duplicate field'
base; printf 'UNRECOGNIZED=yes\n' >> "$fixture/node.env"; reject run 'unknown field'
base; replace PEERS "\$(touch $fixture/should-not-exist)"; reject run 'shell substitution treated as data'
[[ ! -e "$fixture/should-not-exist" ]]; checks=$((checks+1))
base; auth; discovery; replace PEER_SEEDS "\$(touch $fixture/should-not-exist)"; reject run 'seed shell substitution treated as data'
base; auth; discovery; replace PEER_ADVERTISE "\$(touch $fixture/should-not-exist)"; reject run 'advertise shell substitution treated as data'
[[ ! -e "$fixture/should-not-exist" ]]; checks=$((checks+1))
base; auth; : > "$fixture/args"
bash "$repo/deploy/linux/run-node.sh" check "$fixture/node.env" "$fixture/binary" "$fixture/network.json" "$fixture/password" "$fixture/peer.json" > "$fixture/out"; has peer-keycheck
if bash "$repo/deploy/linux/run-node.sh" run "$fixture/node.env" "$fixture/binary" "$fixture/network.json" "$fixture/password" "$fixture/peer.json" > "$fixture/out" 2> "$fixture/err"; then exit 1; fi
checks=$((checks+1))
printf '%s isolated Linux launcher checks passed\n' "$checks"
