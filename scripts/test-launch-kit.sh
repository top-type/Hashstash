#!/usr/bin/env bash
# Regression tests for scripts/launch-kit.sh: strict input validation and the
# generated files, with a stub binary. With the paths of a real hashstash (and
# hashstash-faucet) build, it also generates a kit from that build and runs
# the installer's read-only --check on every server's files. Temporary files
# only; no network, service or root access.
#   bash scripts/test-launch-kit.sh [/path/hashstash /path/hashstash-faucet]
set -euo pipefail
export LC_ALL=C
(( $# == 0 || $# == 2 )) || { printf 'Usage: bash scripts/test-launch-kit.sh [/path/hashstash /path/hashstash-faucet]\n' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
kit=$repo/scripts/launch-kit.sh
version=$(sed -n 's/^version=\([0-9][0-9.]*\)$/\1/p' "$repo/deploy/linux/install.sh")
fixture=$(mktemp -d "${TMPDIR:-/tmp}/hashstash-launch-kit-test.XXXXXXXX")
[[ -d "$fixture" && "$fixture" == */hashstash-launch-kit-test.* ]] || exit 1
trap 'rm -rf -- "$fixture"' EXIT
checks=0
seeds=45.32.10.1,45.32.20.2,45.32.30.3
key=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
key2=c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
key3=f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
pin1=1111111111111111111111111111111111111111111111111111111111111111
pin2=2222222222222222222222222222222222222222222222222222222222222222
pin3=3333333333333333333333333333333333333333333333333333333333333333
serial=0
fresh() { serial=$((serial + 1)); out=$fixture/kit-$serial; }
generate() { fresh; bash "$kit" "$@" --out "$out" > "$fixture/out" 2> "$fixture/err"; }
base=(--seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16)
pass() {
    generate "$@" || { cat "$fixture/err" >&2; printf 'Unexpected refusal: %s\n' "$*" >&2; exit 1; }
    checks=$((checks + 1))
}
# A refusal must name the problem and leave no partial kit behind.
reject() {
    local expected=$1; shift
    if generate "$@"; then printf 'Unexpected acceptance: %s\n' "$*" >&2; exit 1; fi
    grep -Fq -- "$expected" "$fixture/err" || { printf 'Expected "%s" for %s, got: %s\n' "$expected" "$*" "$(cat "$fixture/err")" >&2; exit 1; }
    [[ ! -e "$out" ]] || { printf 'Refused kit left output behind: %s\n' "$*" >&2; exit 1; }
    checks=$((checks + 1))
}
has() { grep -Fxq -- "$2" "$1" || { printf 'Missing line in %s: %s\n' "$1" "$2" >&2; exit 1; }; checks=$((checks + 1)); }
lacks() { ! grep -Fq -- "$2" "$1" || { printf 'Unexpected text in %s: %s\n' "$1" "$2" >&2; exit 1; }; checks=$((checks + 1)); }
contains() { grep -Fq -- "$2" "$1" || { printf 'Missing text in %s: %s\n' "$1" "$2" >&2; exit 1; }; checks=$((checks + 1)); }

# ------------------------------------------------------------ refusals
if bash "$kit" > /dev/null 2>&1; then printf 'No arguments accepted\n' >&2; exit 1; fi; checks=$((checks + 1))
bash "$kit" --help | grep -Fq -- '--seeds LIST'; checks=$((checks + 1))
reject '--seeds is required' --web-host 45.32.10.1 --hashrate 1.67P
reject '--web-host is required' --seeds "$seeds" --hashrate 1.67P
reject '--hashrate is required' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16
reject 'unknown argument: --seed' "${base[@]}" --seed 45.32.10.1
reject '--seeds given twice' "${base[@]}" --seeds "$seeds"
reject 'missing value for --domain' "${base[@]}" --domain
reject 'missing value for --domain' "${base[@]}" --domain --rehearsal
reject 'must not contain spaces' "${base[@]}" --domain 'wallet example.com'
reject 'at least two servers' --seeds 45.32.10.1 --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
many=$(printf '45.32.1.%d,' {1..17}); many=${many%,}
reject 'at most 16 servers' --seeds "$many" --web-host 45.32.1.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
reject 'listed twice' --seeds 45.32.10.1,45.32.20.2,45.32.10.1 --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
for bad in 045.32.10.1 256.1.1.1 45.32.10 45.32.10.1.5 seed.example.com 45.32.10.1:18481 4532101 0x2d.32.10.1; do
    reject 'not a numeric IPv4 address' --seeds "$bad,45.32.20.2" --web-host 45.32.20.2 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
done
reject 'must not contain spaces' --seeds ' 45.32.10.1,45.32.20.2' --web-host 45.32.20.2 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
for bad in 2001:db8::1 '[2001:db8::1]' ::ffff:45.32.10.1; do
    reject 'IPv6 seed' --seeds "$bad,45.32.20.2" --web-host 45.32.20.2 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
done
# The node never gossips these, so a seed there could not be discovered.
for reserved in 10.0.0.1 127.0.0.1 127.0.0.21 172.16.0.1 172.31.255.1 192.168.1.1 100.64.0.1 100.127.0.1 169.254.1.1 \
    192.0.2.1 198.51.100.1 203.0.113.1 192.0.0.1 192.88.99.1 198.18.0.1 198.19.0.1 0.1.2.3 224.0.0.1 239.1.1.1 255.255.255.255; do
    reject 'reserved address' --seeds "$reserved,45.32.20.2" --web-host 45.32.20.2 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
done
for public in 172.15.0.1 172.32.0.1 100.63.0.1 100.128.0.1 192.169.0.1 198.17.0.1 198.20.0.1 203.0.114.1 223.255.255.1; do
    pass --seeds "$public,45.32.20.2" --web-host 45.32.20.2 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
done
reject 'empty entry' --seeds 45.32.10.1,,45.32.20.2 --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
reject 'empty entry' --seeds 45.32.10.1,45.32.20.2, --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
reject 'is not one of --seeds' --seeds "$seeds" --web-host 45.32.40.4 --hashrate 1.67P --miner-prefixes 98.10.0.0/16
for bad in example x.-wallet.example.com wallet-.example.com wallet..example.com wallet.example.com. .example.com \
    wallet_1.example.com 45.32.10.1 wallet.example.123 "$(printf 'a%.0s' {1..64}).example.com" 'wallet.example.com/x' 'user@wallet.example.com'; do
    reject 'is not a DNS name' "${base[@]}" --domain "$bad"
done
for name in p2p stratum rpc web faucet ssh; do
    for bad in 0 65536 18481x 018481 -1; do
        reject "" "${base[@]}" "--$name-port" "$bad"
    done
done
reject 'is used for both P2P and Stratum' "${base[@]}" --stratum-port 18481
reject 'is used for both' "${base[@]}" --faucet-port 18483
reject 'is used for both P2P and RPC of server 2' "${base[@]}" --rpc-port 17481
reject 'choose a lower --rpc-port' "${base[@]}" --rpc-port 64480
reject 'is not one of --seeds' "${base[@]}" --stratum-hosts 45.32.40.4
reject 'lists 45.32.20.2 twice' "${base[@]}" --stratum-hosts 45.32.20.2,45.32.20.2
reject 'give --miner-prefixes' --seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P
reject 'need at least one Stratum server' "${base[@]}" --stratum-hosts none
reject 'need at least one Stratum server' --seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P --stratum-hosts none --stratum-public
for bad in 98.10.0.1/16 98.10.0.0/33 98.10.0.0/016 98.10.0.0/ miners.example 98.10.0.0/16/1 2001:db8::1/129 2001:db8::/32x 2001:db8::1:/64 2001:db8:::/48; do
    reject 'without host bits' --seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes "$bad"
done
for broad in 0.0.0.0/0 98.0.0.0/8 98.10.0.0/15 2001:db8::/31 ::/0 11.0.0.0/8 172.32.0.0/12; do
    reject 'broader than /16' --seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes "$broad"
done
reject 'lists 98.10.0.0/16 twice' --seeds "$seeds" --web-host 45.32.10.1 --hashrate 1.67P --miner-prefixes 98.10.0.0/16,98.10.0.0/16
reject 'allows everyone' "${base[@]}" --admin-prefixes 0.0.0.0/0
reject 'without host bits' "${base[@]}" --admin-prefixes 203.0.113.5/24
reject 'one key for every server or exactly 3' "${base[@]}" --payout-keys "$key,$key2"
for bad in "${key:1}" "${key}0" "${key:1}g" REPLACE_WITH_PAYOUT_PUBLIC_KEY; do
    reject 'is not a 64-character hexadecimal public key' "${base[@]}" --payout-keys "$bad"
done
pins="45.32.10.1=$pin1,45.32.20.2=$pin2,45.32.30.3=$pin3"
reject 'exactly one key for every seed' "${base[@]}" --peer-pins "45.32.10.1=$pin1,45.32.20.2=$pin2"
reject 'lists 45.32.10.1 twice' "${base[@]}" --peer-pins "45.32.10.1=$pin1,45.32.10.1=$pin2,45.32.30.3=$pin3"
reject 'the same key as' "${base[@]}" --peer-pins "45.32.10.1=$pin1,45.32.20.2=$pin1,45.32.30.3=$pin3"
reject 'is not one of --seeds' "${base[@]}" --peer-pins "45.32.40.4=$pin1,45.32.20.2=$pin2,45.32.30.3=$pin3"
reject 'must be IP=PEER_PUBLIC_KEY' "${base[@]}" --peer-pins "45.32.10.1:$pin1,45.32.20.2=$pin2,45.32.30.3=$pin3"
reject 'not a 64-character hexadecimal public key' "${base[@]}" --peer-pins "45.32.10.1=${pin1:1},45.32.20.2=$pin2,45.32.30.3=$pin3"
reject 'equals a payout key' "${base[@]}" --payout-keys "$key" --peer-pins "45.32.10.1=$key,45.32.20.2=$pin2,45.32.30.3=$pin3"
for bad in 1.67X 1.67PP P .5P 1.P 1,67P -1P; do
    reject '' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --hashrate "$bad"
done
reject 'below 73.4G' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --hashrate 73G
reject 'below 73.4G' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --hashrate 100
pass --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --hashrate 73.4G
pass --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --hashrate 2e
reject 'more than 48 hours ahead' "${base[@]}" --genesis-time $(( $(date +%s) + 3 * 86400 ))
for bad in 1.5 0 4294967296 01790000000 soon; do reject '--genesis-time must be Unix seconds' "${base[@]}" --genesis-time "$bad"; done
reject 'needs --binary' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --genesis "$repo/config/devnet.json"
reject 'do not combine it with --hashrate' "${base[@]}" --genesis "$repo/config/devnet.json"
for bad in 0 1e-13 2e18 abc -5; do reject '' "${base[@]}" --share-difficulty "$bad"; done
for bad in 0 01 1.5 x; do reject '--faucet-payout must be a positive whole number' "${base[@]}" --faucet-payout "$bad"; done
mkdir -- "$fixture/existing"
if bash "$kit" "${base[@]}" --out "$fixture/existing" > /dev/null 2> "$fixture/err"; then exit 1; fi
grep -Fq 'already exists' "$fixture/err"; [[ -z $(ls -A -- "$fixture/existing") ]]; checks=$((checks + 1))
if bash "$kit" "${base[@]}" --out "$fixture/missing-parent/kit" > /dev/null 2> "$fixture/err"; then exit 1; fi
grep -Fq 'parent directory of --out does not exist' "$fixture/err"; checks=$((checks + 1))
# A rehearsal accepts loopback seeds and marks every file.
pass --rehearsal --seeds 127.0.0.21,127.0.0.22 --web-host 127.0.0.21 --hashrate 1M --miner-prefixes 127.0.0.0/8
contains "$out/server-1-127.0.0.21/node.env" 'REHEARSAL ONLY'; contains "$out/README.md" 'REHEARSAL ONLY'; has "$out/launch-values.env" REHEARSAL=true
reject 'IPv6 seed' --rehearsal --seeds ::1,127.0.0.22 --web-host 127.0.0.22 --hashrate 1M --miner-prefixes 127.0.0.0/8
reject 'not a usable unicast address' --rehearsal --seeds 0.0.0.0,127.0.0.22 --web-host 127.0.0.22 --hashrate 1M --miner-prefixes 127.0.0.0/8

# ------------------------------------------------------ generated files
pass "${base[@]}" --domain Wallet.Example.COM --payout-keys "$key,$key2,$key3" --admin-prefixes 203.0.113.0/24,2001:db8:5::/48
s1=$out/server-1-45.32.10.1 s2=$out/server-2-45.32.20.2 s3=$out/server-3-45.32.30.3
for dir in "$s1" "$s2" "$s3"; do
    for file in INSTALL.md node.env firewall.sh archive-old-node.sh deploy/install.sh deploy/run-node.sh deploy/hashstash.service; do
        [[ -f "$dir/$file" ]] || { printf 'Missing %s/%s\n' "$dir" "$file" >&2; exit 1; }
    done
    cmp -s "$dir/deploy/install.sh" "$repo/deploy/linux/install.sh"; cmp -s "$dir/deploy/run-node.sh" "$repo/deploy/linux/run-node.sh"
    bash -n "$dir/firewall.sh"; bash -n "$dir/archive-old-node.sh"
    has "$dir/node.env" PEER_DISCOVERY=true; has "$dir/node.env" PEER_KEY_FILE=/etc/hashstash/peer-identity.json
    has "$dir/node.env" P2P_PORT=18481; has "$dir/node.env" STRATUM_PORT=18482; has "$dir/node.env" STRATUM_ENABLED=true
    has "$dir/node.env" STRATUM_TRUSTED=98.10.0.0/16; has "$dir/node.env" SHARE_DIFFICULTY=65536
    lacks "$dir/node.env" PEER_PINS; lacks "$dir/node.env" ALLOW_EASY_TARGET
    has "$dir/firewall.sh" "ufw allow 18481/tcp comment 'hashstash p2p'"
    has "$dir/firewall.sh" "ufw allow from 98.10.0.0/16 to any port 18482 proto tcp comment 'hashstash stratum'"
    lacks "$dir/firewall.sh" 'ufw allow 18482'; lacks "$dir/firewall.sh" 'ufw limit 22'
    has "$dir/firewall.sh" "ufw allow from 203.0.113.0/24 to any port 22 proto tcp comment 'hashstash-kit ssh'"
    has "$dir/firewall.sh" "ufw allow from 2001:db8:5::/48 to any port 22 proto tcp comment 'hashstash-kit ssh'"
    # Every placeholder is rendered; without a release the values say so.
    if grep -Eq '@[A-Z][A-Z0-9_]*@' "$dir"/INSTALL.md "$dir"/node.env; then printf 'Unrendered token in %s\n' "$dir" >&2; exit 1; fi
    checks=$((checks + 1))
    contains "$dir/INSTALL.md" REPLACE_WITH_GENESIS_SHA256
    contains "$dir/INSTALL.md" 'generated without the release'
    lacks "$dir/INSTALL.md" '"secret"'
done
has "$s1/node.env" MINER_PUBLIC_KEY=$key; has "$s2/node.env" MINER_PUBLIC_KEY=$key2; has "$s3/node.env" MINER_PUBLIC_KEY=$key3
has "$s1/node.env" 'PEERS=45.32.20.2:18481 45.32.30.3:18481'; has "$s1/node.env" 'PEER_SEEDS=45.32.20.2:18481 45.32.30.3:18481'
has "$s2/node.env" 'PEER_SEEDS=45.32.10.1:18481 45.32.30.3:18481'; has "$s3/node.env" 'PEER_SEEDS=45.32.10.1:18481 45.32.20.2:18481'
has "$s1/node.env" PEER_ADVERTISE=45.32.10.1:18481; has "$s2/node.env" PEER_ADVERTISE=45.32.20.2:18481
has "$s1/node.env" RPC_PORT=18480; has "$s2/node.env" RPC_PORT=19480; has "$s3/node.env" RPC_PORT=20480
has "$s1/node.env" PUBLIC_WEB_PORT=18483; lacks "$s2/node.env" PUBLIC_WEB_PORT; lacks "$s3/node.env" PUBLIC_WEB_PORT
has "$s1/node.env" STRATUM_ADVERTISE=wallet.example.com:18482; has "$s2/node.env" STRATUM_ADVERTISE=45.32.20.2:18482
has "$s1/firewall.sh" "ufw allow 443/tcp comment 'hashstash website'"; lacks "$s2/firewall.sh" 'ufw allow 443'; lacks "$s2/firewall.sh" 'ufw allow 80'
has "$s1/firewall.sh" "ufw deny 18480/tcp comment 'hashstash rpc (loopback only)'"; has "$s2/firewall.sh" "ufw deny 19480/tcp comment 'hashstash rpc (loopback only)'"
[[ ! -e "$s2/nginx" && ! -e "$s2/faucet" && -f "$s1/nginx/hashstash-public.conf" && -f "$s1/nginx/acme-bootstrap.conf" ]]; checks=$((checks + 1))
# The generated node.env passes the real launcher's validation and becomes the expected run options.
cat > "$fixture/stub-run" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$STUB_ARGS"
EOF
chmod 755 "$fixture/stub-run"
printf 'test-password\n' > "$fixture/password"; printf 'stub\n' > "$fixture/peer.json"; chmod 600 "$fixture/peer.json"
for dir in "$s1" "$s2"; do
    sed "s|^PEER_KEY_FILE=.*|PEER_KEY_FILE=$fixture/peer.json|" "$dir/node.env" > "$fixture/node.env"
    STUB_ARGS=$fixture/args bash "$repo/deploy/linux/run-node.sh" run "$fixture/node.env" "$fixture/stub-run" "$fixture/password" "$fixture/password"
    has "$fixture/args" --peer-discovery; has "$fixture/args" --advertise-peer; has "$fixture/args" --stratum-trusted
    [[ $(grep -Fxc -- --seed "$fixture/args") == 2 && $(grep -Fxc -- --peer "$fixture/args") == 2 ]]; checks=$((checks + 1))
done
has "$fixture/args" 45.32.20.2:18481; lacks "$fixture/args" --public-web
# nginx: the template with the host and the faucet routes; X-Real-IP is always overwritten.
site=$s1/nginx/hashstash-public.conf
has "$site" '    server_name wallet.example.com;'; has "$site" '    ssl_certificate /etc/letsencrypt/live/wallet.example.com/fullchain.pem;'
has "$site" '    location / { return 308 https://wallet.example.com$request_uri; }'
if grep -v '^[[:space:]]*#' "$site" | grep -q PUBLIC_HOST; then printf 'PUBLIC_HOST left in %s\n' "$site" >&2; exit 1; fi
checks=$((checks + 1))
[[ $(grep -c 'proxy_set_header X-Real-IP $remote_addr;' "$site") == 2 ]]; checks=$((checks + 1))
faucet_block=$(sed -n '/^    location \/faucet\/ {$/,/^    }$/p' "$site")
for line in 'proxy_set_header Host $host;' 'proxy_set_header X-Real-IP $remote_addr;' 'proxy_set_header X-Forwarded-For "";' 'proxy_pass http://127.0.0.1:18484;' 'client_max_body_size 1k;'; do
    grep -Fq -- "$line" <<< "$faucet_block" || { printf 'faucet location lacks %s\n' "$line" >&2; exit 1; }; checks=$((checks + 1))
done
root_block=$(sed -n '/^    location \/ {$/,/^    }$/p' "$site")
[[ "$root_block" == *'proxy_pass http://hashstash_public;'* && "$root_block" != *proxy_set_header* ]]; checks=$((checks + 1))
contains "$site" "return 200 '{\"url\":\"https://wallet.example.com\",\"chain_id\":\"REPLACE_WITH_CHAIN_ID\"}';"
contains "$site" 'server 127.0.0.1:18483 max_conns=32;'
# Everything outside the inserted faucet routes is the template, unchanged except for the host.
diff <(grep -v -e 'wallet.example.com' -e '^# ' "$site" | sed '/# Faucet (docs\/FAUCET.md)/,/^    }$/d; /# The faucet trusts only X-Real-IP/,/^    }$/d') \
     <(grep -v -e PUBLIC_HOST -e '^# ' "$repo/deploy/linux/public-web.nginx.template") > /dev/null; checks=$((checks + 1))
has "$s1/nginx/acme-bootstrap.conf" '    server_name wallet.example.com;'
has "$s1/faucet/config.json" '  "origins": ["https://wallet.example.com"],'
has "$s1/faucet/config.json" '  "rpc_url": "http://127.0.0.1:18480/rpc",'
has "$s1/faucet/config.json" '  "bind": "127.0.0.1:18484",'
has "$s1/faucet/config.json" '  "payout": "10",'
has "$s1/faucet/config.json" '  "key_file": "/etc/hashstash-faucet/faucet.key",'
contains "$s1/faucet/hashstash-faucet.service" "ExecStart=/opt/hashstash-faucet/$version-REPLACE_WITH_HASHSTASH_FAUCET_SHA256/hashstash-faucet --config /etc/hashstash-faucet/config.json"
lacks "$s1/faucet/hashstash-faucet.service" FAUCET_PIN
contains "$s1/INSTALL.md" '## 11 Faucet'; lacks "$s2/INSTALL.md" '## 11 Faucet'; lacks "$s2/INSTALL.md" '## 8 nginx'
contains "$s1/INSTALL.md" 'certbot certonly --webroot --webroot-path /var/www/hashstash-acme -d wallet.example.com'
contains "$s1/INSTALL.md" 'scp -r kit-'
contains "$out/genesis/create-genesis.sh" 'init --config "$here/network.json" --preset slow --hashrate 1.67P'
bash -n "$out/genesis/create-genesis.sh"; checks=$((checks + 1))
contains "$out/ANNOUNCEMENT.md" '## Limitations users must be told'
contains "$out/ANNOUNCEMENT.md" '**No limit prices.**'
contains "$out/ANNOUNCEMENT.md" '](docs/SPECIFICATION.md#amount-only-block-clearing)'
contains "$out/README.md" '--peer-discovery --seed 45.32.10.1:18481 --seed 45.32.20.2:18481 --seed 45.32.30.3:18481 --no-stratum'
lacks "$out/README.md" '@'
[[ -z $(find "$out" -perm /022 -type f) ]]; checks=$((checks + 1))

# Variants: an IP-literal website, Stratum on one server, open Stratum, pins.
pass --seeds "$seeds" --web-host 45.32.20.2 --hashrate 1.67P --stratum-hosts 45.32.30.3 --stratum-public --peer-pins "$pins"
s1=$out/server-1-45.32.10.1 s2=$out/server-2-45.32.20.2 s3=$out/server-3-45.32.30.3
has "$s1/node.env" STRATUM_ENABLED=false; has "$s2/node.env" STRATUM_ENABLED=false; has "$s3/node.env" STRATUM_ENABLED=true
lacks "$s3/node.env" STRATUM_TRUSTED; has "$s2/node.env" STRATUM_ADVERTISE=45.32.20.2:18482
has "$s3/firewall.sh" "ufw allow 18482/tcp comment 'hashstash stratum (public, password required)'"
has "$s1/firewall.sh" "ufw deny 18482/tcp comment 'hashstash stratum (disabled here)'"
has "$s1/firewall.sh" "ufw limit 22/tcp comment 'hashstash-kit ssh (rate-limited)'"
has "$s1/node.env" "PEER_PINS=45.32.20.2:18481=$pin2 45.32.30.3:18481=$pin3"
has "$s3/node.env" "PEER_PINS=45.32.10.1:18481=$pin1 45.32.20.2:18481=$pin2"
has "$s1/node.env" MINER_PUBLIC_KEY=REPLACE_WITH_PAYOUT_PUBLIC_KEY
contains "$s1/INSTALL.md" "peer-keycheck --key-file /root/hashstash-keys/peer-identity.json --peer-discovery"
contains "$s1/INSTALL.md" "prints exactly \`$pin1\`"
contains "$s1/INSTALL.md" '## 5 Payout key'; contains "$s1/INSTALL.md" 'sed -i'
lacks "$s1/INSTALL.md" stratum-password; contains "$s3/INSTALL.md" '--stratum-password-file /root/hashstash-keys/stratum-password'
has "$s2/node.env" PUBLIC_WEB_PORT=18483; lacks "$s1/node.env" PUBLIC_WEB_PORT
has "$s2/faucet/config.json" '  "origins": ["https://45.32.20.2"],'
has "$s2/faucet/config.json" '  "rpc_url": "http://127.0.0.1:19480/rpc",'
has "$s2/nginx/hashstash-public.conf" '    server_name 45.32.20.2;'
contains "$s2/INSTALL.md" '--preferred-profile shortlived --webroot --webroot-path /var/www/hashstash-acme --ip-address 45.32.20.2'
pass "${base[@]}" --p2p-port 28481 --stratum-port 28482 --rpc-port 28480 --web-port 28483 --faucet-port 28484 --ssh-port 2222 --share-difficulty 1e-3 --faucet-payout 250
s1=$out/server-1-45.32.10.1
has "$s1/node.env" P2P_PORT=28481; has "$s1/node.env" SHARE_DIFFICULTY=1e-3; has "$out/server-3-45.32.30.3/node.env" RPC_PORT=30480
has "$s1/firewall.sh" "ufw limit 2222/tcp comment 'hashstash-kit ssh (rate-limited)'"
contains "$s1/nginx/hashstash-public.conf" 'server 127.0.0.1:28483 max_conns=32;'
contains "$s1/nginx/hashstash-public.conf" 'proxy_pass http://127.0.0.1:28484;'
has "$s1/faucet/config.json" '  "payout": "250",'

# ------------------------------------------------------ stub binary
stub=$fixture/dist
mkdir -- "$stub"
cat > "$stub/hashstash" <<'EOF'
#!/usr/bin/env bash
# Stub of the release CLI for launch-kit tests.
case "$1" in
    --version) printf 'hashstash %s\n' "${STUB_VERSION:?}" ;;
    init)
        [[ -z "${STUB_INIT_FAIL:-}" ]] || exit 1
        [[ ! -e "$3" ]] || exit 1
        printf '{\n  "network": "stub-network",\n  "test_work": %s,\n  "genesis_time": 1792900000,\n  "initial_bits": 1\n}\n' "${STUB_TEST_WORK:-false}" > "$3"
        printf 'Created %s\n' "$3"
        [[ -z "${STUB_INIT_WARN:-}" ]] || printf 'warning: stub warning\n' >&2 ;;
    network) printf '{\n  "chain_id": "%s",\n  "format": "hashstash-network-v1"\n}\n' "$(printf 'ab%.0s' {1..32})" ;;
    run)
        [[ " $* " == *" --preflight "* ]] || exit 1
        if [[ -n "${STUB_EASY:-}" && " $* " != *" --allow-easy-target "* ]]; then printf 'easy target\n' >&2; exit 1; fi ;;
    address) [[ "$3" != "${STUB_BAD_KEY:-none}" ]] || exit 1; printf 'hsh1stub\n' ;;
esac
EOF
printf '#!/usr/bin/env bash\nprintf "hashstash-faucet %%s\\n" "${STUB_VERSION:?}"\n' > "$stub/hashstash-faucet"
chmod 755 "$stub/hashstash" "$stub/hashstash-faucet"
export STUB_VERSION=$version
withbin=("${base[@]}" --binary "$stub/hashstash")
reject 'no SHA256SUMS beside --binary' "${withbin[@]}"
(cd "$stub" && sha256sum hashstash hashstash-faucet > SHA256SUMS)
pass "${withbin[@]}" --payout-keys "$key" --domain wallet.example.com
s1=$out/server-1-45.32.10.1 s2=$out/server-2-45.32.20.2
binary_sha=$(sha256sum "$stub/hashstash" | cut -d' ' -f1); faucet_sha=$(sha256sum "$stub/hashstash-faucet" | cut -d' ' -f1)
chain=$(printf 'ab%.0s' {1..32})
genesis_sha=$(sha256sum "$out/genesis/network.json" | cut -d' ' -f1)
has "$out/launch-values.env" HASHSTASH_SHA256=$binary_sha; has "$out/launch-values.env" CHAIN_ID=$chain
has "$out/launch-values.env" GENESIS_SHA256=$genesis_sha; has "$out/launch-values.env" GENESIS_TIME=1792900000
has "$out/launch-values.env" EASY_TARGET=false
for dir in "$s1" "$s2"; do
    cmp -s "$dir/network.json" "$out/genesis/network.json"; checks=$((checks + 1))
    (cd "$dir/release" && sha256sum --quiet -c SHA256SUMS); checks=$((checks + 1))
    cmp -s "$dir/release/hashstash" "$stub/hashstash"; checks=$((checks + 1))
    contains "$dir/INSTALL.md" "--sha256 $binary_sha"; contains "$dir/INSTALL.md" "--genesis-sha256 $genesis_sha"
    lacks "$dir/INSTALL.md" REPLACE_WITH; lacks "$dir/INSTALL.md" 'generated without the release'
done
[[ -f "$s1/release/hashstash-faucet" && ! -e "$s2/release/hashstash-faucet" ]]; checks=$((checks + 1))
contains "$s1/faucet/hashstash-faucet.service" "ExecStart=/opt/hashstash-faucet/$version-$faucet_sha/hashstash-faucet"
contains "$s1/faucet/config.json" "\"chain_id\": \"$chain\""
contains "$s1/nginx/hashstash-public.conf" "\"chain_id\":\"$chain\"}';"
[[ ! -e "$out/genesis/create-genesis.sh" ]]; checks=$((checks + 1))
# An existing genesis is used byte for byte.
printf '{\n  "network": "given",\n  "test_work": false,\n  "genesis_time": 1792800000,\n  "initial_bits": 2\n}\n' > "$fixture/given.json"
pass --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --binary "$stub/hashstash" --genesis "$fixture/given.json"
cmp -s "$out/server-3-45.32.30.3/network.json" "$fixture/given.json"; checks=$((checks + 1))
has "$out/launch-values.env" NETWORK=given
# The release files must match their SHA256SUMS, name both binaries and run as this version.
cp -a "$stub" "$fixture/dist2"
printf 'x' >> "$fixture/dist2/hashstash-faucet"
reject 'do not match their SHA256SUMS' "${base[@]}" --binary "$fixture/dist2/hashstash"
(cd "$fixture/dist2" && sha256sum hashstash > SHA256SUMS)
reject 'does not list hashstash-faucet' "${base[@]}" --binary "$fixture/dist2/hashstash"
STUB_VERSION=0.42.0 reject "reports 'hashstash 0.42.0'" "${withbin[@]}"
# A test-fixtures build, an init warning, a failing init or an easy genesis is
# refused, and the partial kit is removed.
STUB_TEST_WORK=true reject 'test-fixtures build' "${withbin[@]}"
STUB_INIT_WARN=1 reject 'init printed a warning' "${withbin[@]}"
STUB_INIT_FAIL=1 reject 'probe genesis' "${withbin[@]}"
STUB_EASY=1 reject 'too easy for a public network' "${withbin[@]}"
STUB_BAD_KEY=$key2 reject "payout key $key2 is not a valid public key" "${withbin[@]}" --payout-keys "$key2"
printf '{\n  "network": "fixture",\n  "test_work": true,\n  "genesis_time": 1\n}\n' > "$fixture/fixture.json"
reject 'test-fixture genesis' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 --binary "$stub/hashstash" --genesis "$fixture/fixture.json"
# ... except in a rehearsal, which marks the easy genesis in every node.env.
STUB_EASY=1 pass --rehearsal "${withbin[@]}"
has "$out/server-2-45.32.20.2/node.env" ALLOW_EASY_TARGET=true; has "$out/launch-values.env" EASY_TARGET=true
STUB_TEST_WORK=true pass --rehearsal "${withbin[@]}"
has "$out/launch-values.env" FIXTURE_BUILD=true

# ------------------------------------------------------ real build
if (( $# == 2 )); then
    real=$fixture/real
    mkdir -- "$real"
    cp -- "$(realpath -e -- "$1")" "$real/hashstash"
    cp -- "$(realpath -e -- "$2")" "$real/hashstash-faucet"
    (cd "$real" && sha256sum hashstash hashstash-faucet > SHA256SUMS)
    mode=()
    "$real/hashstash" init --config "$fixture/probe.json" --preset dev --uncalibrated > /dev/null 2>&1
    if grep -q '"test_work": true' "$fixture/probe.json"; then
        # A test-fixtures build: refused for a launch, accepted for a rehearsal.
        reject 'test-fixtures build' "${base[@]}" --binary "$real/hashstash"
        mode=(--rehearsal)
    fi
    {
        pass "${mode[@]}" "${base[@]}" --binary "$real/hashstash" --domain wallet.example.com --payout-keys "$key,$key2,$key3"
        [[ -n $(sed -n 's/^CHAIN_ID=\([0-9a-f]\{64\}\)$/\1/p' "$out/launch-values.env") ]]; checks=$((checks + 1))
        sha=$(sed -n 's/^HASHSTASH_SHA256=//p' "$out/launch-values.env"); genesis_sha=$(sed -n 's/^GENESIS_SHA256=//p' "$out/launch-values.env")
        # INSTALL.md steps 3, 4 and 6 (--check) on every server, with keys made here.
        n=0
        for dir in "$out"/server-*; do
            n=$((n + 1))
            (cd "$dir/release" && sha256sum --quiet -c SHA256SUMS)
            "$dir/release/hashstash" peer-keygen --out "$fixture/peer-$n.json" > /dev/null
            printf '%s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$fixture/password-$n"
            (cd "$dir" && bash deploy/install.sh --binary release/hashstash --sha256 "$sha" --genesis network.json \
                --genesis-sha256 "$genesis_sha" --node-env node.env --peer-key-file "$fixture/peer-$n.json" \
                --stratum-password-file "$fixture/password-$n" --check) > "$fixture/install.out" 2> "$fixture/install.err" \
                || { cat "$fixture/install.err" >&2; exit 1; }
            grep -Fq 'Configuration and payout public key are valid' "$fixture/install.out"; checks=$((checks + 1))
        done
        (( n == 3 )); checks=$((checks + 1))
        if (( ${#mode[@]} == 0 )); then
            # A release refuses the uncalibrated limit behind discovery, and so does the kit.
            "$real/hashstash" init --config "$fixture/easy.json" --preset slow --uncalibrated > /dev/null 2>&1
            reject 'too easy for a public network' --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 \
                --binary "$real/hashstash" --genesis "$fixture/easy.json"
            pass --rehearsal --seeds "$seeds" --web-host 45.32.10.1 --miner-prefixes 98.10.0.0/16 \
                --binary "$real/hashstash" --genesis "$fixture/easy.json"
            has "$out/server-1-45.32.10.1/node.env" ALLOW_EASY_TARGET=true
        fi
    }
fi
printf '%s launch-kit checks passed\n' "$checks"
