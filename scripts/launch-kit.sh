#!/usr/bin/env bash
# Generate the per-server launch files of a new public Hashstash network.
#
#   bash scripts/launch-kit.sh --seeds IP1,IP2[,...] --web-host IP --out DIR \
#     (--hashrate RATE | --genesis network.json) [--binary RELEASE/hashstash] [options]
#
# Run it on the trusted preparation machine (Linux; WSL 2 works) from the
# checkout the release was built from. It needs no network access, no cloud
# account and no secret: every private key and password is generated later on
# the server that uses it, and only public values (addresses, public keys,
# hashes) are written here. See docs/LAUNCH-DAY.md for the launch sequence.
#
# Servers and roles
#   --seeds LIST            Public IPv4 address of every server, comma-separated
#                           (2 to 16). Every server is a discovery seed on the P2P
#                           port, advertises its own address and seeds from the others.
#   --web-host IP           The server (one of --seeds) that serves the public
#                           wallet website and the faucet behind nginx and TLS.
#   --domain NAME           DNS name of the web host (recommended: browsers apply
#                           HSTS only to names). Without it the site uses the IP.
#   --stratum-hosts LIST    Servers that run Stratum for miners: IPs, "all" or
#                           "none". Default: every seed except the web host,
#                           which holds the faucet key and serves the wallet
#                           (docs/LAUNCH.md section 7); "all" includes it.
#   --miner-prefixes LIST   Your miners' addresses or prefixes (IPv4 /16 or
#                           longer, IPv6 /32 or longer outside local networks).
#                           They become STRATUM_TRUSTED, and only they may reach
#                           the Stratum port through the firewall.
#   --stratum-public        Also open the Stratum port to everyone (rental
#                           marketplaces with unknown addresses). The password
#                           still protects it.
#   --admin-prefixes LIST   Addresses or prefixes allowed to SSH. Default: SSH
#                           from anywhere, rate-limited.
#   --ssh-port PORT         SSH port kept open by the firewall (default 22).
# Genesis and release
#   --hashrate RATE         Expected aggregate SHA256d hashrate for
#                           init --preset slow --hashrate (for example 1.67P).
#   --genesis-time UNIX     Genesis time for init (default: the clock at init).
#                           At most 120 seconds ahead, as init warns about any
#                           later time (48 hours with --rehearsal).
#   --binary PATH           The release's hashstash binary, normally
#                           target/dist/hashstash-VERSION-linux-ARCH/hashstash
#                           beside its SHA256SUMS. With --hashrate the genesis is
#                           created now; every hash is filled in and the release
#                           is copied into each server's directory.
#   --genesis PATH          Use this existing genesis instead of creating one
#                           (needs --binary; not with --hashrate).
# Keys (public values only)
#   --payout-keys LIST      Payout PUBLIC keys (64 hex): one for every server, or
#                           one per server in --seeds order. Default: a
#                           placeholder that INSTALL.md tells you to replace.
#   --peer-pins LIST        IP=PEER_PUBLIC_KEY for every seed, from peer-keygen
#                           run on each server beforehand: pins the backbone.
# Tuning
#   --share-difficulty N    SHARE_DIFFICULTY reporting threshold (default 65536).
#   --faucet-payout ATOMS   Faucet payment per claim in atoms (default 10 =
#                           0.01 hash; 1,000 atoms are one hash).
#   --p2p-port, --stratum-port, --rpc-port, --web-port, --faucet-port PORT
#                           Defaults 18481, 18482, 18480, 18483, 18484. Server N
#                           uses RPC port --rpc-port + 1000*(N-1), so SSH tunnels
#                           to several dashboards do not collide. Ports 80 and
#                           443 belong to nginx.
# Output
#   --out DIR               New directory for the kit; it must not exist.
#   --rehearsal             Local rehearsal only: also accept private and loopback
#                           addresses, an easy-target genesis (ALLOW_EASY_TARGET)
#                           and builds without SHA256SUMS or with test fixtures.
#                           Every generated file is marked REHEARSAL.
set -euo pipefail
export LC_ALL=C
umask 022
shopt -u patsub_replacement 2>/dev/null || true
fail() { printf 'launch-kit: %s\n' "$*" >&2; exit 1; }
warn() { printf 'launch-kit: warning: %s\n' "$*" >&2; }
usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; }

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
deploy=$root/deploy/linux
version=$(sed -n 's/^version=\([0-9][0-9.]*\)$/\1/p' "$deploy/install.sh")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'cannot read the release version from deploy/linux/install.sh'
for file in install.sh run-node.sh hashstash.service hashstash-faucet.service public-web.nginx.template; do
    [[ -f "$deploy/$file" ]] || fail "missing deploy/linux/$file"
done
for command in sha256sum awk sed realpath mktemp grep cp; do
    command -v "$command" >/dev/null || fail "missing command: $command"
done

seeds_arg= web_host= domain= hashrate= genesis_time= binary= genesis_in= out=
miner_prefixes_arg= admin_prefixes_arg= payout_keys_arg= peer_pins_arg= stratum_hosts_arg=
stratum_public=false rehearsal=false
share_difficulty=65536 faucet_payout=10 ssh_port=22
p2p_port=18481 stratum_port=18482 rpc_port=18480 web_port=18483 faucet_port=18484
declare -A given=()
(( $# )) || { usage >&2; exit 1; }
while (( $# )); do
    option=$1
    case "$option" in
        -h|--help) usage; exit 0 ;;
        --stratum-public|--rehearsal)
            [[ ! ${given[$option]+x} ]] || fail "$option given twice"
            given[$option]=1
            case "$option" in --stratum-public) stratum_public=true ;; --rehearsal) rehearsal=true ;; esac
            shift ;;
        --seeds|--web-host|--domain|--hashrate|--genesis-time|--binary|--genesis|--out|--miner-prefixes|--admin-prefixes|--payout-keys|--peer-pins|--stratum-hosts|--share-difficulty|--faucet-payout|--ssh-port|--p2p-port|--stratum-port|--rpc-port|--web-port|--faucet-port)
            [[ ! ${given[$option]+x} ]] || fail "$option given twice"
            given[$option]=1
            (( $# >= 2 )) || fail "missing value for $option"
            value=$2
            [[ -n "$value" && "$value" != -* ]] || fail "missing value for $option"
            [[ "$value" =~ ^[[:graph:]]+$ ]] || fail "$option must not contain spaces or control characters"
            case "$option" in
                --seeds) seeds_arg=$value ;; --web-host) web_host=$value ;; --domain) domain=${value,,} ;;
                --hashrate) hashrate=$value ;; --genesis-time) genesis_time=$value ;;
                --binary) binary=$value ;; --genesis) genesis_in=$value ;; --out) out=$value ;;
                --miner-prefixes) miner_prefixes_arg=$value ;; --admin-prefixes) admin_prefixes_arg=$value ;;
                --payout-keys) payout_keys_arg=${value,,} ;; --peer-pins) peer_pins_arg=$value ;;
                --stratum-hosts) stratum_hosts_arg=$value ;; --share-difficulty) share_difficulty=$value ;;
                --faucet-payout) faucet_payout=$value ;; --ssh-port) ssh_port=$value ;;
                --p2p-port) p2p_port=$value ;; --stratum-port) stratum_port=$value ;;
                --rpc-port) rpc_port=$value ;; --web-port) web_port=$value ;; --faucet-port) faucet_port=$value ;;
            esac
            shift 2 ;;
        *) fail "unknown argument: $option (see --help)" ;;
    esac
done

# ---------------------------------------------------------------- validation
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
# Canonical dotted-quad IPv4: four decimal octets, no leading zeros, each at most 255.
ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local octet
    for octet in "${BASH_REMATCH[@]:1}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] && (( 10#$octet <= 255 )) || return 1
    done
}
# The node's discovery policy (public_address in src/peer_discovery.rs):
# local, special-use, documentation and multicast ranges are never gossiped.
ipv4_public() {
    local a b c _
    IFS=. read -r a b c _ <<< "$1"
    ! (( a == 0 || a == 10 || a == 127 || a >= 224
        || (a == 100 && b >= 64 && b <= 127) || (a == 169 && b == 254)
        || (a == 172 && b >= 16 && b <= 31)
        || (a == 192 && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113) ))
}
# What a rehearsal still refuses: "this network", multicast and broadcast.
ipv4_usable() {
    local a _
    IFS=. read -r a _ <<< "$1"
    (( a != 0 && a < 224 ))
}
# Eight 16-bit groups of a strictly written IPv6 address (hex groups, at most
# one "::", no zone or embedded IPv4), printed as decimal numbers.
ipv6_groups() {
    local address=$1 head tail group count
    local left=() right=() all=()
    [[ "$address" =~ ^[0-9a-fA-F:]+$ && "$address" != *:::* && ${#address} -le 39 ]] || return 1
    # A single colon may not start or end the address ("1::2:" is not "1::2").
    [[ ( "$address" != :* || "$address" == ::* ) && ( "$address" != *: || "$address" == *:: ) ]] || return 1
    if [[ "$address" == *::* ]]; then
        head=${address%%::*}; tail=${address#*::}
        [[ "$tail" != *::* ]] || return 1
        [[ -z "$head" ]] || IFS=: read -r -a left <<< "$head"
        [[ -z "$tail" ]] || IFS=: read -r -a right <<< "$tail"
        count=$(( 8 - ${#left[@]} - ${#right[@]} ))
        (( count >= 1 )) || return 1
        all=("${left[@]}")
        while (( count-- )); do all+=(0); done
        all+=("${right[@]}")
    else
        [[ "$address" != :* && "$address" != *: ]] || return 1
        IFS=: read -r -a all <<< "$address"
    fi
    (( ${#all[@]} == 8 )) || return 1
    for group in "${all[@]}"; do
        [[ "$group" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
        printf '%d ' "$((16#$group))"
    done
}
# ADDRESS[/LENGTH] with no host bits set. Sets prefix_family (4 or 6),
# prefix_length and prefix_groups (IPv6) or prefix_value (IPv4).
parse_prefix() {
    local text=$1 address length= a b c d groups g bits
    address=${text%%/*}
    if [[ "$text" == */* ]]; then
        length=${text#*/}
        [[ "$length" =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 1
    fi
    if ipv4 "$address"; then
        length=${length:-32}
        (( length <= 32 )) || return 1
        IFS=. read -r a b c d <<< "$address"
        prefix_value=$(( (a << 24) | (b << 16) | (c << 8) | d ))
        (( length == 32 || (prefix_value & ((1 << (32 - length)) - 1)) == 0 )) || return 1
        prefix_family=4 prefix_length=$length
        return 0
    fi
    groups=$(ipv6_groups "$address") || return 1
    length=${length:-128}
    (( length <= 128 )) || return 1
    read -r -a prefix_groups <<< "$groups"
    for g in 0 1 2 3 4 5 6 7; do
        bits=$(( length - 16 * g ))
        if (( bits <= 0 )); then
            (( prefix_groups[g] == 0 )) || return 1
        elif (( bits < 16 )); then
            (( (prefix_groups[g] & (0xffff >> bits)) == 0 )) || return 1
        fi
    done
    prefix_family=6 prefix_length=$length
}
# Whether the node accepts the parsed prefix in STRATUM_TRUSTED: at least /16
# (IPv4) or /32 (IPv6), unless it lies inside a local network (TrustedPrefix).
prefix_narrow() {
    if (( prefix_family == 4 )); then
        local a=$(( prefix_value >> 24 )) b=$(( (prefix_value >> 16) & 255 ))
        (( prefix_length >= 16 )) && return 0
        (( prefix_length >= 8 && (a == 10 || a == 127) )) && return 0
        (( prefix_length >= 12 && a == 172 && (b & 0xf0) == 16 )) && return 0
        (( prefix_length >= 10 && a == 100 && (b & 0xc0) == 64 )) && return 0
        return 1
    fi
    (( prefix_length >= 32 )) && return 0
    (( prefix_length >= 7 && (prefix_groups[0] & 0xfe00) == 0xfc00 )) && return 0
    (( prefix_length >= 10 && (prefix_groups[0] & 0xffc0) == 0xfe80 )) && return 0
    return 1
}
# A DNS name: lowercase LDH labels, a dot, an alphabetic top-level label.
valid_domain() {
    local name=$1 label
    local labels=()
    [[ ${#name} -le 253 && "$name" =~ ^[a-z0-9.-]+$ && "$name" == *.* && "$name" != .* && "$name" != *. && "$name" != *..* ]] || return 1
    IFS=. read -r -a labels <<< "$name"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
    [[ "${labels[-1]}" =~ ^[a-z]([a-z0-9-]*[a-z0-9])?$ ]]
}
split_list() { local IFS=,; read -r -a split_result <<< "$1"; [[ "$1" != *, && "$1" != ,* && "$1" != *,,* ]]; }

[[ -n "$seeds_arg" ]] || fail '--seeds is required'
[[ -n "$web_host" ]] || fail '--web-host is required'
[[ -n "$out" ]] || fail '--out is required'
split_list "$seeds_arg" || fail '--seeds has an empty entry'
seeds=("${split_result[@]}")
(( ${#seeds[@]} >= 2 )) || fail '--seeds needs at least two servers, so that every seed has another to bootstrap from'
(( ${#seeds[@]} <= 16 )) || fail '--seeds allows at most 16 servers (the node accepts at most 16 discovery seeds)'
declare -A seed_index=()
for i in "${!seeds[@]}"; do
    ip=${seeds[$i]}
    if [[ "$ip" == \[* || "$ip" == *::* || "$ip" == *:*:* ]]; then
        fail "IPv6 seed $ip is not supported: deploy/linux/run-node.sh binds P2P to 0.0.0.0 (IPv4 only), so an IPv6 advertisement would be unreachable; give the server's public IPv4 address"
    fi
    ipv4 "$ip" || fail "seed $ip is not a numeric IPv4 address (four decimal octets, no leading zeros, no port: the P2P port is --p2p-port)"
    if [[ "$rehearsal" == true ]]; then
        ipv4_usable "$ip" || fail "seed $ip is not a usable unicast address"
    else
        ipv4_public "$ip" || fail "seed $ip is a private, loopback, documentation or other reserved address; discovery refuses it on a public network (use --rehearsal only for a local rehearsal)"
    fi
    [[ ! ${seed_index[$ip]+x} ]] || fail "seed $ip is listed twice"
    seed_index[$ip]=$i
done
[[ ${seed_index[$web_host]+x} ]] || fail "--web-host $web_host is not one of --seeds"
if [[ -n "$domain" ]]; then
    valid_domain "$domain" || fail "--domain $domain is not a DNS name (lowercase letters, digits and hyphens in dot-separated labels, with an alphabetic top-level label)"
fi
public_host=${domain:-$web_host}

for name in p2p_port stratum_port rpc_port web_port faucet_port ssh_port; do
    valid_port "${!name}" || fail "--${name//_/-} must be a port from 1 to 65535"
done
declare -A port_owner=()
claim_port() {
    [[ ! ${port_owner[$1]+x} ]] || fail "port $1 is used for both ${port_owner[$1]} and $2"
    port_owner[$1]=$2
}
# nginx binds 80 and 443 on every address of the web host, which every
# server's P2P, Stratum and SSH ports share and any server's RPC may be.
claim_port 80 'the website (nginx)'; claim_port 443 'the website (nginx)'
claim_port "$p2p_port" P2P; claim_port "$stratum_port" Stratum; claim_port "$web_port" 'public web'
claim_port "$faucet_port" faucet; claim_port "$ssh_port" SSH
rpc_ports=()
for i in "${!seeds[@]}"; do
    port=$(( 10#$rpc_port + 1000 * i ))
    (( port <= 65535 )) || fail "RPC port of server $((i + 1)) would be $port; choose a lower --rpc-port"
    claim_port "$port" "RPC of server $((i + 1))"
    rpc_ports+=("$port")
done

declare -A stratum_on=()
case "$stratum_hosts_arg" in
    '') for ip in "${seeds[@]}"; do [[ "$ip" == "$web_host" ]] || stratum_on[$ip]=1; done ;;
    all) for ip in "${seeds[@]}"; do stratum_on[$ip]=1; done ;;
    none) ;;
    *)
        split_list "$stratum_hosts_arg" || fail '--stratum-hosts has an empty entry'
        for ip in "${split_result[@]}"; do
            [[ ${seed_index[$ip]+x} ]] || fail "--stratum-hosts $ip is not one of --seeds"
            [[ ! ${stratum_on[$ip]+x} ]] || fail "--stratum-hosts lists $ip twice"
            stratum_on[$ip]=1
        done ;;
esac
miner_prefixes=()
if [[ -n "$miner_prefixes_arg" ]]; then
    split_list "$miner_prefixes_arg" || fail '--miner-prefixes has an empty entry'
    declare -A prefix_seen=()
    for prefix in "${split_result[@]}"; do
        parse_prefix "$prefix" || fail "--miner-prefixes $prefix is not an IP address or a network prefix ADDRESS/LENGTH without host bits"
        prefix_narrow || fail "--miner-prefixes $prefix is broader than /16 (IPv4) or /32 (IPv6) outside local networks; the node refuses it in STRATUM_TRUSTED"
        [[ ! ${prefix_seen[${prefix,,}]+x} ]] || fail "--miner-prefixes lists $prefix twice"
        prefix_seen[${prefix,,}]=1
        miner_prefixes+=("$prefix")
    done
    (( ${#miner_prefixes[@]} <= 64 )) || fail '--miner-prefixes allows at most 64 entries'
fi
if (( ${#stratum_on[@]} )); then
    (( ${#miner_prefixes[@]} )) || [[ "$stratum_public" == true ]] \
        || fail 'Stratum runs on at least one server: give --miner-prefixes (only they reach the Stratum port), add --stratum-public to open it to everyone, or --stratum-hosts none'
else
    (( ${#miner_prefixes[@]} == 0 )) && [[ "$stratum_public" == false ]] \
        || fail '--miner-prefixes and --stratum-public need at least one Stratum server'
fi
admin_prefixes=()
if [[ -n "$admin_prefixes_arg" ]]; then
    split_list "$admin_prefixes_arg" || fail '--admin-prefixes has an empty entry'
    for prefix in "${split_result[@]}"; do
        parse_prefix "$prefix" || fail "--admin-prefixes $prefix is not an IP address or a network prefix ADDRESS/LENGTH without host bits"
        (( prefix_length > 0 )) || fail "--admin-prefixes $prefix allows everyone; omit --admin-prefixes for rate-limited SSH from anywhere"
        admin_prefixes+=("$prefix")
    done
fi

payout_keys=()
if [[ -n "$payout_keys_arg" ]]; then
    split_list "$payout_keys_arg" || fail '--payout-keys has an empty entry'
    payout_keys=("${split_result[@]}")
    (( ${#payout_keys[@]} == 1 || ${#payout_keys[@]} == ${#seeds[@]} )) \
        || fail "--payout-keys needs one key for every server or exactly ${#seeds[@]} (one per seed, in --seeds order)"
    for key in "${payout_keys[@]}"; do
        [[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "--payout-keys $key is not a 64-character hexadecimal public key"
    done
fi
payout_for() { # index -> key or placeholder
    if (( ${#payout_keys[@]} == 0 )); then printf 'REPLACE_WITH_PAYOUT_PUBLIC_KEY'
    elif (( ${#payout_keys[@]} == 1 )); then printf '%s' "${payout_keys[0]}"
    else printf '%s' "${payout_keys[$1]}"; fi
}
declare -A pin_of=()
if [[ -n "$peer_pins_arg" ]]; then
    split_list "$peer_pins_arg" || fail '--peer-pins has an empty entry'
    declare -A pin_keys=()
    for entry in "${split_result[@]}"; do
        [[ "$entry" == *=* ]] || fail "--peer-pins $entry must be IP=PEER_PUBLIC_KEY"
        ip=${entry%%=*}; key=${entry#*=}; key=${key,,}
        [[ ${seed_index[$ip]+x} ]] || fail "--peer-pins $ip is not one of --seeds"
        [[ ! ${pin_of[$ip]+x} ]] || fail "--peer-pins lists $ip twice"
        [[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "--peer-pins key for $ip is not a 64-character hexadecimal public key"
        [[ ! ${pin_keys[$key]+x} ]] || fail "--peer-pins gives $ip the same key as ${pin_keys[$key]}; every server needs its own peer identity"
        for payout in "${payout_keys[@]}"; do
            [[ "$key" != "$payout" ]] || fail "--peer-pins key for $ip equals a payout key; a peer identity must be a dedicated peer-keygen key"
        done
        pin_keys[$key]=$ip
        pin_of[$ip]=$key
    done
    (( ${#pin_of[@]} == ${#seeds[@]} )) || fail '--peer-pins needs exactly one key for every seed'
fi

[[ "$share_difficulty" =~ ^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$ ]] \
    && awk -v v="$share_difficulty" 'BEGIN { exit !(v >= 1e-12 && v <= 1e18) }' \
    || fail '--share-difficulty must be a number from 1e-12 to 1e18'
[[ "$faucet_payout" =~ ^[1-9][0-9]{0,8}$ ]] || fail '--faucet-payout must be a positive whole number of atoms, at most 999999999'
# The faucet's lifetime allowance with its fees: a payment to a new account
# pays ceil((bytes + 1024) / 1024) = 2 atoms at the launch fee rate.
faucet_funding=$(( 1000 * (faucet_payout + 2) ))

if [[ -n "$genesis_in" ]]; then
    [[ -z "$hashrate" && -z "$genesis_time" ]] || fail '--genesis uses an existing genesis; do not combine it with --hashrate or --genesis-time'
    [[ -n "$binary" ]] || fail '--genesis needs --binary to read the chain ID'
else
    [[ -n "$hashrate" ]] || fail '--hashrate is required (or --genesis with an existing file)'
    [[ "$hashrate" =~ ^([0-9]+(\.[0-9]+)?)([KMGTPEkmgtpe]?)$ ]] || fail "--hashrate $hashrate must be a number with an optional K, M, G, T, P or E suffix, such as 1.67P"
    multiplier=1
    case "${BASH_REMATCH[3]^^}" in K) multiplier=1e3 ;; M) multiplier=1e6 ;; G) multiplier=1e9 ;; T) multiplier=1e12 ;; P) multiplier=1e15 ;; E) multiplier=1e18 ;; esac
    # A public listener needs an easiest target of at least 2^40 hashes per 15-second block.
    if ! awk -v v="${BASH_REMATCH[1]}" -v m="$multiplier" 'BEGIN { exit !(v * m * 15 >= 1099511627776) }'; then
        [[ "$rehearsal" == true ]] || fail "--hashrate $hashrate is below 73.4G; the node refuses so easy a genesis behind public P2P and discovery"
    fi
    if [[ -n "$genesis_time" ]]; then
        [[ "$genesis_time" =~ ^[1-9][0-9]{0,9}$ ]] && (( genesis_time <= 4294967295 )) || fail '--genesis-time must be Unix seconds'
        now=$(date +%s)
        (( genesis_time <= now + 172800 )) || fail '--genesis-time is more than 48 hours ahead; nodes defer block 1 until then'
        # init warns about a genesis more than future_seconds (120) ahead, and a
        # launch genesis must have no warning (docs/LAUNCH.md section 3).
        (( genesis_time <= now + 120 )) || [[ "$rehearsal" == true ]] \
            || fail "--genesis-time is $(( genesis_time - now )) seconds ahead; init warns about any genesis more than 120 seconds ahead and a launch genesis must have no warning: omit --genesis-time (the genesis time is then the clock at init) or give one at most 120 seconds ahead"
        (( genesis_time <= now )) || warn "--genesis-time is $(( genesis_time - now )) seconds in the future: no block can be mined before it"
        (( genesis_time >= now - 30 * 86400 )) || warn '--genesis-time is more than 30 days in the past'
    fi
fi

[[ ! -e "$out" && ! -L "$out" ]] || fail "--out $out already exists; the kit never overwrites a kit or a genesis, so choose a new directory"
out_parent=$(dirname -- "$out")
[[ -d "$out_parent" ]] || fail "parent directory of --out does not exist: $out_parent"
out=$(realpath -m -- "$out")

# ------------------------------------------------------------- release check
binary_sha= faucet_sha= faucet_binary= release_dir= sums_file= buildinfo= fixture=false
probe=
created=false
cleanup() {
    [[ -z "$probe" ]] || rm -rf -- "$probe"
    if [[ "$created" == true ]]; then rm -rf -- "$out"; fi
}
trap cleanup EXIT
if [[ -n "$binary" ]]; then
    binary=$(realpath -e -- "$binary") || fail "--binary not found"
    [[ -f "$binary" && -x "$binary" ]] || fail "--binary is not an executable file: $binary"
    reported=$("$binary" --version 2>/dev/null) || fail "--binary cannot run on this machine: $binary"
    [[ "$reported" == "hashstash $version" ]] || fail "--binary reports '$reported'; this checkout's deploy files are for hashstash $version"
    release_dir=$(dirname -- "$binary")
    if [[ -f "$release_dir/SHA256SUMS" ]]; then
        sums_file=$release_dir/SHA256SUMS
        (cd -- "$release_dir" && sha256sum --quiet -c SHA256SUMS) || fail "the files beside --binary do not match their SHA256SUMS"
        binary_sha=$(awk '$2 == "hashstash" || $2 == "*hashstash" { print $1 }' "$sums_file")
        faucet_sha=$(awk '$2 == "hashstash-faucet" || $2 == "*hashstash-faucet" { print $1 }' "$sums_file")
        [[ "$binary_sha" =~ ^[0-9a-f]{64}$ ]] || fail 'SHA256SUMS does not list hashstash'
        [[ "$(sha256sum -- "$binary" | awk '{print $1}')" == "$binary_sha" ]] || fail '--binary is not the hashstash listed in SHA256SUMS'
        [[ "$faucet_sha" =~ ^[0-9a-f]{64}$ && -f "$release_dir/hashstash-faucet" ]] || fail 'SHA256SUMS does not list hashstash-faucet beside --binary'
        faucet_binary=$release_dir/hashstash-faucet
        if [[ -f "$release_dir/BUILDINFO" ]]; then buildinfo=$release_dir/BUILDINFO; fi
    else
        [[ "$rehearsal" == true ]] || fail "no SHA256SUMS beside --binary; pass the scripts/release.sh output (target/dist/hashstash-$version-linux-ARCH/hashstash)"
        binary_sha=$(sha256sum -- "$binary" | awk '{print $1}')
        if [[ -f "$release_dir/hashstash-faucet" ]]; then
            faucet_binary=$release_dir/hashstash-faucet
            faucet_sha=$(sha256sum -- "$faucet_binary" | awk '{print $1}')
        fi
    fi
    if [[ -n "$faucet_binary" ]]; then
        reported=$("$faucet_binary" --version 2>/dev/null) || fail "hashstash-faucet beside --binary cannot run"
        [[ "$reported" == "hashstash-faucet $version" ]] || fail "hashstash-faucet beside --binary reports '$reported', not $version"
    fi
    probe=$(mktemp -d "${TMPDIR:-/tmp}/hashstash-launch-kit.XXXXXXXX")
    # A test-fixtures build writes fixture genesis files (test_work), which no
    # release accepts: refuse such a binary for a launch.
    "$binary" init --config "$probe/probe.json" --preset dev --uncalibrated > /dev/null 2>&1 || fail '--binary could not create a probe genesis'
    if grep -q '"test_work": true' "$probe/probe.json"; then
        fixture=true
        [[ "$rehearsal" == true ]] || fail '--binary is a test-fixtures build; build the release with scripts/release.sh'
    fi
fi

mkdir -- "$out"
created=true
genesis= chain_id= genesis_sha= genesis_unix= network_name= easy=false
mkdir -- "$out/genesis"
if [[ -n "$genesis_in" ]]; then
    genesis_in=$(realpath -e -- "$genesis_in") || fail '--genesis not found'
    [[ -f "$genesis_in" ]] || fail "--genesis is not a file: $genesis_in"
    (( $(wc -c < "$genesis_in") <= 65536 )) || fail '--genesis is too large to be a genesis file'
    cp -- "$genesis_in" "$out/genesis/network.json"
    genesis=$out/genesis/network.json
elif [[ -n "$binary" ]]; then
    genesis=$out/genesis/network.json
    init_args=(init --config "$genesis" --preset slow --hashrate "$hashrate")
    [[ -z "$genesis_time" ]] || init_args+=(--genesis-time "$genesis_time")
    "$binary" "${init_args[@]}" > "$out/genesis/init-output.txt" 2> "$probe/init-warnings.txt" \
        || { cat "$probe/init-warnings.txt" >&2; fail 'init failed'; }
    if [[ -s "$probe/init-warnings.txt" ]]; then
        cat "$probe/init-warnings.txt" >&2
        [[ "$rehearsal" == true ]] || fail 'init printed a warning; a launch genesis must have none (docs/LAUNCH.md section 3)'
        cat "$probe/init-warnings.txt" >> "$out/genesis/init-output.txt"
    fi
fi
if [[ -n "$genesis" ]]; then
    "$binary" network --config "$genesis" > "$out/genesis/network-descriptor.json" 2> "$probe/network.err" \
        || { cat "$probe/network.err" >&2; fail 'the genesis is not valid for this release'; }
    chain_id=$(sed -n 's/^ *"chain_id": "\([0-9a-f]\{64\}\)",\{0,1\}$/\1/p' "$out/genesis/network-descriptor.json")
    [[ "$chain_id" =~ ^[0-9a-f]{64}$ ]] || fail 'could not read the chain ID'
    genesis_sha=$(sha256sum -- "$genesis" | awk '{print $1}')
    (cd -- "$out/genesis" && sha256sum network.json > network.json.sha256)
    genesis_unix=$(sed -n 's/^ *"genesis_time": \([0-9]*\),$/\1/p' "$genesis")
    network_name=$(sed -n 's/^ *"network": "\([^"]*\)",$/\1/p' "$genesis")
    if grep -q '"test_work": true' "$genesis"; then
        [[ "$rehearsal" == true ]] || fail 'the genesis is a test-fixture genesis (test_work); a launch genesis never is'
    fi
    # The service's own checks before it opens a database: the calibration
    # guard refuses an easy genesis behind 0.0.0.0 P2P and discovery.
    check_key=$(payout_for 0)
    [[ "$check_key" =~ ^[0-9a-f]{64}$ ]] || check_key=79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
    preflight=(run --config "$genesis" --data "$probe/preflight.sqlite" --miner "$check_key"
        --p2p "0.0.0.0:$p2p_port" --no-stratum --peer-discovery --preflight)
    if ! "$binary" "${preflight[@]}" > /dev/null 2> "$probe/preflight.err"; then
        if "$binary" "${preflight[@]}" --allow-easy-target > /dev/null 2>&1; then
            [[ "$rehearsal" == true ]] || { cat "$probe/preflight.err" >&2; fail 'the genesis is too easy for a public network: create it with init --preset slow --hashrate RATE'; }
            easy=true
            warn 'easy-target genesis: every node.env gets ALLOW_EASY_TARGET=true (rehearsal only)'
        else
            cat "$probe/preflight.err" >&2
            fail 'the node refuses this genesis'
        fi
    fi
    for i in "${!seeds[@]}"; do
        key=$(payout_for "$i")
        if [[ "$key" == REPLACE_* ]]; then continue; fi
        "$binary" address --public-key "$key" --config "$genesis" > /dev/null 2>&1 \
            || fail "payout key $key is not a valid public key"
    done
fi

commit=unavailable
if command -v git >/dev/null && git -C "$root" rev-parse --verify -q HEAD > /dev/null 2>&1; then
    commit=$(git -C "$root" rev-parse HEAD)
    [[ -z $(git -C "$root" status --porcelain --untracked-files=no 2>/dev/null) ]] || commit="$commit (with uncommitted changes)"
fi
generated_at=$(date +%s)
generated=$(date -u -d "@$generated_at" +%Y-%m-%dT%H:%M:%SZ)
# Every kit is copied to its own new directory on the servers, named after
# its chain and creation time: a kit copied over an earlier one (a rehearsal,
# a preview or an abandoned genesis) would land inside it instead.
kit_tag=preview
[[ -z "$chain_id" ]] || kit_tag=${chain_id:0:12}
remote_dir=/root/hashstash-kit-$kit_tag-$(date -u -d "@$generated_at" +%Y%m%dT%H%M%SZ)
banner=
[[ "$rehearsal" == false ]] || banner='REHEARSAL ONLY - NOT FOR THE LAUNCH NETWORK. '

# ------------------------------------------------------------------ helpers
declare -A vars=()
# Replace @NAME@ tokens from vars in a template read from stdin.
render() {
    local text key
    text=$(cat; printf x); text=${text%x}
    for key in "${!vars[@]}"; do text=${text//@$key@/${vars[$key]}}; done
    if [[ "$text" =~ @[A-Z][A-Z0-9_]*@ ]]; then fail "internal error: unrendered token ${BASH_REMATCH[0]}"; fi
    printf '%s' "$text"
}
or_placeholder() { if [[ -n "$1" ]]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }
vars[VERSION]=$version
vars[BANNER]=$banner
vars[PUBLIC_HOST]=$public_host
vars[CHAIN_ID]=$(or_placeholder "$chain_id" REPLACE_WITH_CHAIN_ID)
vars[GENESIS_SHA256]=$(or_placeholder "$genesis_sha" REPLACE_WITH_GENESIS_SHA256)
vars[BINARY_SHA256]=$(or_placeholder "$binary_sha" REPLACE_WITH_HASHSTASH_SHA256)
vars[FAUCET_SHA256]=$(or_placeholder "$faucet_sha" REPLACE_WITH_HASHSTASH_FAUCET_SHA256)
vars[P2P_PORT]=$p2p_port
vars[STRATUM_PORT]=$stratum_port
vars[WEB_PORT]=$web_port
vars[FAUCET_PORT]=$faucet_port
vars[COMMIT]=$commit
vars[GENERATED]=$generated
vars[REMOTE_DIR]=$remote_dir
vars[FUNDING]=$faucet_funding
vars[FUNDING_HASH]=$(( faucet_payout + 2 ))
vars[FAUCET_PAYOUT]=$faucet_payout

# ------------------------------------------------------------ static files
archive_script() {
    cat <<'EOF'
#!/usr/bin/env bash
# Stop any earlier Hashstash node and faucet on this server and move their
# files aside, so that the new release installs on an empty data directory.
# Nothing is deleted: everything moves into /root/hashstash-archive-STAMP.
# A 0.42.0 database must never be reused; 0.43.0 refuses it by name.
#   sudo bash archive-old-node.sh                    stop the services, archive
#   sudo bash archive-old-node.sh --stop-processes   also SIGINT hashstash
#                                                    processes started by hand
set -euo pipefail
fail() { printf 'archive-old-node: %s\n' "$*" >&2; exit 1; }
(( EUID == 0 )) || fail 'run with sudo'
stop_processes=false
case "${1:-}" in
    '') ;;
    --stop-processes) stop_processes=true ;;
    *) fail "unknown argument: $1" ;;
esac
# Process names are truncated to 15 characters (hashstash-fauce).
processes() { ps -eo pid=,comm= | awk '$2 == "hashstash" || $2 == "hashstash-fauce" { print $1 }'; }
for unit in $(systemctl list-units --all --no-legend --plain 'hashstash*' 2>/dev/null | awk '{ print $1 }'); do
    printf 'Stopping %s\n' "$unit"
    systemctl stop "$unit" || fail "could not stop $unit"
done
for unit in $(systemctl list-unit-files --no-legend 'hashstash*' 2>/dev/null | awk '$2 == "enabled" { print $1 }'); do
    printf 'Disabling %s\n' "$unit"
    systemctl disable "$unit" || printf 'warning: could not disable %s; disable it by hand\n' "$unit" >&2
done
pids=$(processes | tr '\n' ' ')
if [[ -n "${pids// /}" ]]; then
    ps -o pid,user,etime,args -p "$(tr ' ' ',' <<< "${pids% }")" || true
    [[ "$stop_processes" == true ]] || fail 'Hashstash processes started outside systemd are running (above); stop them (kill -INT PID) or rerun with --stop-processes'
    # shellcheck disable=SC2086
    kill -INT $pids 2>/dev/null || true
    for _ in $(seq 90); do
        [[ -z "$(processes)" ]] && break
        sleep 1
    done
    [[ -z "$(processes)" ]] || fail 'Hashstash processes did not stop within 90 seconds; stop them by hand'
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
archive=/root/hashstash-archive-$stamp
install -d -m 700 "$archive"
moved=0
for path in /var/lib/hashstash /etc/hashstash /var/lib/hashstash-faucet /etc/hashstash-faucet \
    /usr/local/libexec/hashstash /etc/systemd/system/hashstash.service /etc/systemd/system/hashstash.service.d \
    /etc/systemd/system/hashstash-faucet.service /etc/systemd/system/hashstash-faucet.service.d; do
    if [[ -e "$path" || -L "$path" ]]; then
        destination=$archive$(dirname -- "$path")
        install -d -m 700 "$destination"
        mv -- "$path" "$destination/"
        printf 'Moved %s to %s\n' "$path" "$destination/"
        moved=$((moved + 1))
    fi
done
systemctl daemon-reload
systemctl reset-failed 'hashstash*' 2>/dev/null || true
if (( moved == 0 )); then
    rmdir -- "$archive"
    printf 'Nothing to archive: no earlier Hashstash files in the service paths.\n'
else
    printf 'Archived %s item(s) in %s\n' "$moved" "$archive"
fi
if account=$(getent passwd hashstash); then
    IFS=: read -r _ _ uid _ _ home shell <<< "$account"
    if [[ "$uid" == 0 || "$home" != /var/lib/hashstash || "$shell" != /usr/sbin/nologin || $(id -gn hashstash) != hashstash ]]; then
        printf 'warning: the existing hashstash account (%s) is not the dedicated service account install.sh expects; fix or remove it (userdel hashstash) before installing\n' "$account" >&2
    fi
fi
if grep -rls hashstash /etc/nginx/sites-enabled 2>/dev/null; then
    printf 'note: the nginx site(s) above still proxy to the old node; INSTALL.md replaces them\n'
fi
printf 'Old pinned binaries in /opt/hashstash are left in place; the new release installs into its own hash-named directory.\n'
printf 'If an earlier node ran from another directory, its database stays where its --data pointed; the new node never reads it.\n'
[[ -z "$(processes)" ]] || fail 'a Hashstash process is still running'
printf 'No Hashstash service or process is running.\n'
EOF
}

acme_bootstrap() {
    render <<'EOF'
# @BANNER@Temporary site for the first certificate on @PUBLIC_HOST@: it serves
# only the ACME webroot. Replace it with hashstash-public.conf once the
# certificate exists (INSTALL.md).
server {
    listen 80 default_server;
    server_name @PUBLIC_HOST@;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/hashstash-acme;
        try_files $uri =404;
    }
    location / { return 503; }
}
EOF
}

# The repository's public-web template with the host, the node's public-web
# port and the faucet routes of docs/FAUCET.md.
public_site() {
    local template faucet
    # The host replaces PUBLIC_HOST in directives; comments keep the template's wording.
    template=$(awk -v host="$public_host" '/^[[:space:]]*#/ { print; next } { gsub(/PUBLIC_HOST/, host); print }' \
        "$deploy/public-web.nginx.template"; printf x)
    template=${template%x}
    [[ $(grep -cx '    location / {' <<< "$template") == 1 ]] || fail 'unexpected public-web.nginx.template: no single "location / {" block'
    [[ $(grep -c 'server 127.0.0.1:18483 max_conns=' <<< "$template") == 1 ]] || fail 'unexpected public-web.nginx.template upstream'
    ! grep -v '^[[:space:]]*#' <<< "$template" | grep -q PUBLIC_HOST || fail 'internal error: PUBLIC_HOST left in the nginx site'
    template=${template//server 127.0.0.1:18483 max_conns=/server 127.0.0.1:$web_port max_conns=}
    faucet=$(render <<'EOF'
    # Faucet (docs/FAUCET.md). The wallet reads this descriptor; it must
    # name this exact HTTPS origin and the network's chain ID.
    location = /faucet-config.json {
        default_type application/json;
        # A block with its own add_header inherits none of the server's.
        add_header Cache-Control no-store always;
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
        return 200 '{"url":"https://@PUBLIC_HOST@","chain_id":"@CHAIN_ID@"}';
    }
    # The faucet trusts only X-Real-IP, so it is overwritten with the
    # connecting address here. Setting any proxy_set_header in a location
    # drops the server-level ones, so all of them are repeated.
    location /faucet/ {
        client_max_body_size 1k;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_pass http://127.0.0.1:@FAUCET_PORT@;
    }
EOF
)
    template=${template/$'\n    location / {\n'/$'\n'"$faucet"$'\n    location / {\n'}
    printf '# %sGenerated by scripts/launch-kit.sh from deploy/linux/public-web.nginx.template\n# for %s, with the faucet routes of docs/FAUCET.md.\n%s' "$banner" "$public_host" "$template"
}

faucet_config() {
    vars[ORIGIN]="https://$public_host"
    vars[FAUCET_RPC]=$1
    render <<'EOF'
{
  "bind": "127.0.0.1:@FAUCET_PORT@",
  "rpc_url": "http://127.0.0.1:@FAUCET_RPC@/rpc",
  "chain_id": "@CHAIN_ID@",
  "key_file": "/etc/hashstash-faucet/faucet.key",
  "database": "/var/lib/hashstash-faucet/claims.sqlite",
  "origins": ["@ORIGIN@"],
  "payout": "@FAUCET_PAYOUT@",
  "max_fee": "10",
  "cooldown_seconds": 86400,
  "subnet_cooldown_seconds": 60,
  "subnet_daily_claims": 10,
  "hourly_claims": 100,
  "daily_claims": 250,
  "lifetime_claims": 1000,
  "recent_block_seconds": 180,
  "confirmations": 2,
  "expiry_blocks": 2
}
EOF
}

# ufw rules for one server.
firewall_script() {
    local ip=$1 is_web=$2 is_stratum=$3 rpc=$4 prefix
    printf '#!/usr/bin/env bash\n'
    printf '# %sFirewall of server %s, generated by scripts/launch-kit.sh.\n' "$banner" "$ip"
    printf '# Review the rules, then: sudo bash firewall.sh\n'
    printf '# P2P is public; Stratum only from the miners; RPC, the public-web upstream\n'
    printf '# and the faucet listen on loopback only and are denied here as well.\n'
    printf 'set -euo pipefail\n'
    printf '(( EUID == 0 )) || { echo "run with sudo" >&2; exit 1; }\n'
    printf 'command -v ufw >/dev/null || { echo "install ufw first: apt-get install -y ufw" >&2; exit 1; }\n'
    printf '# Rules that already exist are kept. Review them: one left from an earlier\n'
    printf '# setup (for example Stratum open to everyone) still applies.\n'
    printf "echo 'Existing ufw rules (kept; remove unwanted ones with: ufw delete NUMBER):'\n"
    printf 'ufw status numbered || true\n'
    printf 'ufw default deny incoming\n'
    printf 'ufw default allow outgoing\n'
    printf '# SSH first, so that enabling the firewall keeps this session.\n'
    if (( ${#admin_prefixes[@]} )); then
        for prefix in "${admin_prefixes[@]}"; do
            printf "ufw allow from %s to any port %s proto tcp comment 'hashstash-kit ssh'\n" "$prefix" "$ssh_port"
        done
    else
        printf "ufw limit %s/tcp comment 'hashstash-kit ssh (rate-limited)'\n" "$ssh_port"
    fi
    printf "ufw allow %s/tcp comment 'hashstash p2p'\n" "$p2p_port"
    if [[ "$is_stratum" == true ]]; then
        if [[ "$stratum_public" == true ]]; then
            printf "ufw allow %s/tcp comment 'hashstash stratum (public, password required)'\n" "$stratum_port"
        else
            for prefix in "${miner_prefixes[@]}"; do
                printf "ufw allow from %s to any port %s proto tcp comment 'hashstash stratum'\n" "$prefix" "$stratum_port"
            done
        fi
    else
        printf "ufw deny %s/tcp comment 'hashstash stratum (disabled here)'\n" "$stratum_port"
    fi
    if [[ "$is_web" == true ]]; then
        printf "ufw allow 80/tcp comment 'hashstash website (ACME and redirect)'\n"
        printf "ufw allow 443/tcp comment 'hashstash website'\n"
    fi
    printf "ufw deny %s/tcp comment 'hashstash rpc (loopback only)'\n" "$rpc"
    printf "ufw deny %s/tcp comment 'hashstash public-web upstream (nginx only)'\n" "$web_port"
    printf "ufw deny %s/tcp comment 'hashstash faucet (nginx only)'\n" "$faucet_port"
    printf 'ufw --force enable\n'
    printf 'ufw status verbose\n'
}

# ------------------------------------------------------------- per server
server_dirs=()
summary_rows=()
web_dir= web_rpc=
for i in "${!seeds[@]}"; do
    ip=${seeds[$i]}
    n=$((i + 1))
    rpc=${rpc_ports[$i]}
    is_web=false is_stratum=false
    if [[ "$ip" == "$web_host" ]]; then is_web=true; fi
    if [[ ${stratum_on[$ip]+x} ]]; then is_stratum=true; fi
    dir_name="server-$n-$ip"
    dir=$out/$dir_name
    server_dirs+=("$dir_name")
    mkdir -- "$dir" "$dir/deploy"
    cp -- "$deploy/install.sh" "$deploy/run-node.sh" "$deploy/hashstash.service" "$dir/deploy/"
    roles="seed"
    [[ "$is_stratum" == false ]] || roles+=", Stratum"
    [[ "$is_web" == false ]] || roles+=", website and faucet"
    payout=$(payout_for "$i")
    others=() pins=()
    for j in "${!seeds[@]}"; do
        if (( j == i )); then continue; fi
        others+=("${seeds[$j]}:$p2p_port")
        [[ -z "$peer_pins_arg" ]] || pins+=("${seeds[$j]}:$p2p_port=${pin_of[${seeds[$j]}]}")
    done
    advertise_host=$ip
    [[ "$is_web" == false || -z "$domain" ]] || advertise_host=$domain
    {
        printf '# %sHashstash %s node.env for server %s (%s): %s.\n' "$banner" "$version" "$n" "$ip" "$roles"
        printf '# Generated by scripts/launch-kit.sh on %s. Plain KEY=value data.\n' "$generated"
        printf '# Payout PUBLIC key; its private key stays offline.\n'
        printf 'MINER_PUBLIC_KEY=%s\n' "$payout"
        printf '# Private RPC, bound to 127.0.0.1 only (dashboard through an SSH tunnel).\n'
        printf 'RPC_PORT=%s\n' "$rpc"
        printf 'P2P_PORT=%s\n' "$p2p_port"
        printf 'STRATUM_PORT=%s\n' "$stratum_port"
        printf 'STRATUM_ENABLED=%s\n' "$is_stratum"
        printf 'STRATUM_ADVERTISE=%s:%s\n' "$advertise_host" "$stratum_port"
        printf 'SHARE_DIFFICULTY=%s\n' "$share_difficulty"
        if [[ "$is_stratum" == true ]] && (( ${#miner_prefixes[@]} )); then
            printf '# Your miners: they keep reserved Stratum slots.\n'
            printf 'STRATUM_TRUSTED=%s\n' "${miner_prefixes[*]}"
        fi
        printf '# The other seeds, also as configured peers for reserved slots and health checks.\n'
        printf 'PEERS=%s\n' "${others[*]}"
        printf 'PEER_KEY_FILE=/etc/hashstash/peer-identity.json\n'
        if (( ${#pins[@]} )); then
            printf '# Backbone pins: each other seed must prove its peer-keygen key.\n'
            printf 'PEER_PINS=%s\n' "${pins[*]}"
        fi
        printf '# Public discovery: outsiders join with --peer-discovery --seed %s:%s.\n' "$ip" "$p2p_port"
        printf 'PEER_DISCOVERY=true\n'
        printf 'PEER_SEEDS=%s\n' "${others[*]}"
        printf 'PEER_ADVERTISE=%s:%s\n' "$ip" "$p2p_port"
        if [[ "$is_web" == true ]]; then
            printf '# The restricted website listener on 127.0.0.1, reached only through nginx.\n'
            printf 'PUBLIC_WEB_PORT=%s\n' "$web_port"
        fi
        if [[ "$easy" == true ]]; then
            printf '# REHEARSAL ONLY: the rehearsal genesis is not calibrated.\n'
            printf 'ALLOW_EASY_TARGET=true\n'
        fi
    } > "$dir/node.env"
    firewall_script "$ip" "$is_web" "$is_stratum" "$rpc" > "$dir/firewall.sh"
    archive_script > "$dir/archive-old-node.sh"
    if [[ -n "$genesis" ]]; then
        cp -- "$genesis" "$dir/network.json"
        cp -- "$out/genesis/network.json.sha256" "$dir/network.json.sha256"
    fi
    if [[ -n "$binary" ]]; then
        mkdir -- "$dir/release"
        cp -- "$binary" "$dir/release/hashstash"
        release_files=(hashstash)
        if [[ "$is_web" == true && -n "$faucet_binary" ]]; then
            cp -- "$faucet_binary" "$dir/release/hashstash-faucet"
            release_files+=(hashstash-faucet)
        fi
        [[ -z "$buildinfo" ]] || cp -- "$buildinfo" "$dir/release/BUILDINFO"
        (cd -- "$dir/release" && sha256sum "${release_files[@]}" > SHA256SUMS)
        if [[ -n "$sums_file" ]]; then cp -- "$sums_file" "$dir/release/SHA256SUMS.release"; fi
    fi
    if [[ "$is_web" == true ]]; then
        web_dir=$dir_name web_rpc=$rpc
        mkdir -- "$dir/nginx" "$dir/faucet"
        acme_bootstrap > "$dir/nginx/acme-bootstrap.conf"
        public_site > "$dir/nginx/hashstash-public.conf"
        faucet_config "$rpc" > "$dir/faucet/config.json"
        pin=$version-${vars[FAUCET_SHA256]}
        sed "s|/opt/hashstash-faucet/FAUCET_PIN/|/opt/hashstash-faucet/$pin/|" "$deploy/hashstash-faucet.service" > "$dir/faucet/hashstash-faucet.service"
    fi
    summary_rows+=("| $n | \`$ip\` | $roles | $rpc | \`$dir_name/\` |")

    # INSTALL.md, section by section.
    vars[N]=$n vars[IP]=$ip vars[DIR]=$dir_name vars[RPC]=$rpc vars[ROLES]=$roles
    vars[PAYOUT]=$payout vars[SEED_LIST]="${others[*]}"
    vars[PIN]=${pin_of[$ip]:-}
    vars[TRUSTED]=${miner_prefixes[*]:-}
    if [[ "$stratum_public" == true ]]; then
        vars[STRATUM_REACH]='The firewall opens the port to everyone (`--stratum-public`); only the password keeps others out.'
    else
        vars[STRATUM_REACH]="Only the miner sources ${miner_prefixes[*]:-} reach the port through the firewall."
    fi
    (( ${#miner_prefixes[@]} == 0 )) || vars[STRATUM_REACH]+=" They are in \`STRATUM_TRUSTED\` and keep reserved slots."
    vars[KIT_OUT]=$(basename -- "$out")
    if (( ${#payout_keys[@]} == 1 )); then
        vars[FUND_SENDER]=${payout_keys[0]}
        vars[FUND_SENDER_NOTE]="the payout key every server mines to (\`${payout_keys[0]}\`)"
    else
        vars[FUND_SENDER]=PAYOUT_PUBLIC_KEY
        vars[FUND_SENDER_NOTE]='the payout key of a Stratum server that has found blocks: replace `PAYOUT_PUBLIC_KEY` below with its public key'
    fi
    {
        render <<'EOF'
# Server @N@: `@IP@` (@ROLES@)

@BANNER@Hashstash @VERSION@ install steps for this server, generated by `scripts/launch-kit.sh` on @GENERATED@ from source commit @COMMIT@. Follow `docs/LAUNCH-DAY.md` in the source checkout for the order across servers; this file is the order on this server.

Run the commands as root (or with `sudo`) on this server, from `@REMOTE_DIR@` (step 0), in order. Each step ends with a check: stop at the first failure.

| Value | |
| --- | --- |
| Release | `hashstash @VERSION@` |
| `hashstash` SHA256 | `@BINARY_SHA256@` |
| `network.json` SHA256 | `@GENESIS_SHA256@` |
| Chain ID | `@CHAIN_ID@` |
| P2P (public) | `@IP@:@P2P_PORT@` |
| Private RPC (loopback only) | `127.0.0.1:@RPC@` |
| Kit directory on this server | `@REMOTE_DIR@` |

Before step 3, compare the two SHA256 values and the chain ID with the values published through your second channel (docs/LAUNCH.md section 4).

## 0 Copy this directory to the server

On the preparation machine, from the directory that holds `@KIT_OUT@/`. Each kit goes to a new directory of its own, named after its chain ID and creation time, so that it never lands inside an earlier kit (a rehearsal, a preview or an abandoned genesis) on the server:

```sh
ssh root@@IP@ "test ! -e @REMOTE_DIR@ || { echo '@REMOTE_DIR@ exists: this kit was copied before' >&2; exit 1; }" \
  && scp -r @KIT_OUT@/@DIR@ root@@IP@:@REMOTE_DIR@
ssh root@@IP@
cd @REMOTE_DIR@
```

Check: `scp` copied the files and `pwd` prints `@REMOTE_DIR@`. Run every later step from this directory, never from another kit's directory on the server.

## 1 Host preparation

```sh
timedatectl show -p NTPSynchronized --value     # must print: yes
apt-get update && apt-get install -y ufw openssl
nproc; free -m; df -h /var/lib
```

Check: the clock is synchronized (a block more than 120 seconds ahead of a node's clock is deferred), at least 1 GiB of memory and 20 GiB of free disk.

## 2 Stop and archive any earlier Hashstash node

```sh
sudo bash archive-old-node.sh
```

It stops and disables every `hashstash*` service, refuses to continue while a Hashstash process started by hand still runs (rerun with `--stop-processes` to stop those with SIGINT), and moves `/var/lib/hashstash`, `/etc/hashstash`, the faucet's files and the old service files into `/root/hashstash-archive-STAMP`. Nothing is deleted. Old 0.42.0 data must never be reused: 0.43.0 refuses a 0.42.0 database by name. It leaves `/root/hashstash-keys`, nginx, `/etc/letsencrypt` and the firewall alone.

Check: it ends with `No Hashstash service or process is running.`

## 3 Verify the release and the genesis

```sh
(cd release && sha256sum -c SHA256SUMS)
echo "@BINARY_SHA256@  release/hashstash" | sha256sum -c -
echo "@GENESIS_SHA256@  network.json" | sha256sum -c -
./release/hashstash --version
./release/hashstash network --config network.json
```

Check: every line says `OK`, the version is `hashstash @VERSION@`, and `chain_id` is `@CHAIN_ID@` and equals the chain ID published through your second channel. Any other chain ID means an old or wrong kit: stop, and copy the right one (step 0).

EOF
        if [[ -z "$binary" ]]; then
            render <<'EOF'
> This kit was generated without the release: the values above are placeholders. Regenerate it with `--binary` (and the launch genesis) before installing; until then only steps 1, 2, 7 and the nginx preparation in step 8 can be done.

EOF
        fi
        if [[ "$payout" == REPLACE_* ]]; then
            render <<'EOF'
## 4 Payout key

No payout key was given to the kit. Put this node's payout PUBLIC key (from `hashstash keygen` on your offline machine; never the private key) into `node.env`:

```sh
sed -i 's/^MINER_PUBLIC_KEY=.*/MINER_PUBLIC_KEY=YOUR_64_HEX_PUBLIC_KEY/' node.env
./release/hashstash address --public-key "$(sed -n 's/^MINER_PUBLIC_KEY=//p' node.env)" --config network.json
```

Check: `address` prints the payout address you expect.

EOF
        else
            render <<'EOF'
## 4 Payout key

`node.env` pays every block found through this node to the public key `@PAYOUT@`. Its private key stays offline.

```sh
./release/hashstash address --public-key @PAYOUT@ --config network.json
```

Check: the printed address is the payout address you expect.

EOF
        fi
        render <<'EOF'
## 5 Keys, generated on this server

These never leave the server except in the encrypted backups of docs/LAUNCH.md section 13. `/root/hashstash-keys` (root only) keeps them for a reinstall: `archive-old-node.sh` never touches it, so a rehearsal's or an abandoned genesis's identity and password are reused here.

```sh
install -d -m 700 /root/hashstash-keys
EOF
        if [[ -n "${pin_of[$ip]:-}" ]]; then
            render <<'EOF'
# The peer identity was generated here before the kit (its public key is pinned by the other seeds).
./release/hashstash peer-keycheck --key-file /root/hashstash-keys/peer-identity.json --peer-discovery --miner "$(sed -n 's/^MINER_PUBLIC_KEY=//p' node.env)"
EOF
        else
            render <<'EOF'
test -e /root/hashstash-keys/peer-identity.json || ./release/hashstash peer-keygen --out /root/hashstash-keys/peer-identity.json
./release/hashstash peer-keycheck --key-file /root/hashstash-keys/peer-identity.json --peer-discovery --miner "$(sed -n 's/^MINER_PUBLIC_KEY=//p' node.env)"
EOF
        fi
        if [[ "$is_stratum" == true ]]; then
            render <<'EOF'
test -e /root/hashstash-keys/stratum-password || (umask 077; openssl rand -hex 32 > /root/hashstash-keys/stratum-password)
EOF
        fi
        printf '```\n\n'
        if [[ -n "${pin_of[$ip]:-}" ]]; then
            render <<'EOF'
Check: `peer-keycheck` prints exactly `@PIN@`, the key the other seeds pin. Any other key, or a missing file, means the wrong identity: the other seeds would refuse this node. If `/root/hashstash-keys/peer-identity.json` was removed after an earlier installation, `archive-old-node.sh` kept the installed copy; restore it with `install -m 600 /root/hashstash-archive-STAMP/etc/hashstash/peer-identity.json /root/hashstash-keys/` and run the check again.

EOF
        else
            render <<'EOF'
Check: `peer-keycheck` prints this node's peer public key; record it with the server. (To pin the backbone, generate the identity on every server before generating the kit and pass the keys with `--peer-pins`.)

EOF
        fi
        if [[ "$is_stratum" == true ]]; then
            render <<'EOF'
Step 6 installs the Stratum password as `/etc/hashstash/stratum-password`; step 10 gives it to your miners. Stratum V1 is plain TCP: never reuse this value elsewhere.

EOF
        fi
        printf '## 6 Install (does not start the node)\n\n```sh\n'
        install_args="--binary release/hashstash --sha256 ${vars[BINARY_SHA256]} \\\\
  --genesis network.json --genesis-sha256 ${vars[GENESIS_SHA256]} \\\\
  --node-env node.env --peer-key-file /root/hashstash-keys/peer-identity.json"
        [[ "$is_stratum" == false ]] || install_args+=" \\\\
  --stratum-password-file /root/hashstash-keys/stratum-password"
        printf 'bash deploy/install.sh %b --check\n' "$install_args"
        printf 'sudo bash deploy/install.sh %b\n' "$install_args"
        printf '```\n\n'
        render <<'EOF'
Check: `--check` prints `Configuration and payout public key are valid` and the chain ID, and the install prints `Installed.` The node is installed but not started. The installed copies of the staged keys are in `/etc/hashstash`. Keep the staging copies in `/root/hashstash-keys` until the network is announced: a reinstall before then (docs/LAUNCH-DAY.md, rollback) reuses them. After the announcement, once your encrypted backup holds `/etc/hashstash` (docs/LAUNCH.md section 13), remove them (the last section of this file).

## 7 Firewall

```sh
cat firewall.sh
sudo bash firewall.sh
```

Check: `ufw status` shows @P2P_PORT@/tcp open to everyone, SSH open as you intended, and the RPC port @RPC@ denied; remove any older rule that opens more. Rate-limited SSH refuses a seventh connection from one address within 30 seconds; wait and retry. If you also use a Vultr firewall group, give it the same rules.

EOF
        if [[ "$is_web" == true ]]; then
            if [[ -n "$domain" ]]; then
                vars[CERT_NOTE]="Point the DNS name \`$domain\` (A record) at \`$ip\` first."
                vars[CERT_INSTALL]='apt-get install -y nginx certbot'
                vars[CERTBOT]=certbot
                vars[CERT_REQUEST]="--webroot --webroot-path /var/www/hashstash-acme -d $domain --cert-name $domain"
                vars[CERT_CHECK]=''
            else
                vars[CERT_NOTE]="Without a DNS name the certificate is a short-lived (six-day) IP-address certificate. That needs certbot 5.4 or later, which only the certbot snap provides (Ubuntu 24.04 ships 2.9), so these commands replace the distribution's certbot with the snap: one certbot and one renewal timer remain, and the snap renews the certificate automatically (on Debian, \`apt-get install -y snapd\` first). Browsers never apply HSTS to an IP address. Prefer a DNS name (\`--domain\`)."
                vars[CERT_INSTALL]="apt-get install -y nginx
apt-get remove -y certbot           # the distribution's certbot predates IP-address certificates
snap install --classic certbot
ln -sf /snap/bin/certbot /usr/bin/certbot
/snap/bin/certbot --version         # must print certbot 5.4.0 or later"
                vars[CERTBOT]=/snap/bin/certbot
                vars[CERT_REQUEST]="--preferred-profile shortlived --webroot --webroot-path /var/www/hashstash-acme --ip-address $ip --cert-name $ip"
                vars[CERT_CHECK]=' `certbot --version` printed 5.4.0 or later (stop otherwise: an older certbot refuses the IP-address options),'
            fi
            render <<'EOF'
## 8 nginx and TLS (before launch day is fine)

@CERT_NOTE@ nginx 1.15.7 or later is required. Run step 7 first: it opens port 80 for the certificate's HTTP challenge. If the on-host rehearsal (docs/LAUNCH-DAY.md) already ran this step for this host, skip it: the certificate, its renewal hook and nginx stay in place.

```sh
@CERT_INSTALL@
nginx -v
install -d -m 755 /var/www/hashstash-acme
install -m 644 nginx/acme-bootstrap.conf /etc/nginx/sites-available/hashstash
ln -sf /etc/nginx/sites-available/hashstash /etc/nginx/sites-enabled/hashstash
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
@CERTBOT@ certonly @CERT_REQUEST@
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
printf '#!/bin/sh\nnginx -t && systemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/hashstash-nginx.sh
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/hashstash-nginx.sh
@CERTBOT@ renew --dry-run
```

Check:@CERT_CHECK@ certbot saved a certificate under `/etc/letsencrypt/live/@PUBLIC_HOST@/` and the dry run succeeded. The full site is enabled in step 12, after the node runs.

EOF
        fi
        render <<'EOF'
## 9 Start the node (launch day, in the order of docs/LAUNCH-DAY.md)

```sh
sudo systemctl enable --now hashstash
sudo systemctl status hashstash --no-pager
sudo journalctl -u hashstash -n 30 --no-pager
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh snapshot | head -40
sudo -u hashstash "$(cat /etc/hashstash/binary.path)" rpc --url http://127.0.0.1:@RPC@/rpc peerstatus
```

Check: `snapshot` shows `chain_id` `@CHAIN_ID@`, and before mining height 0 with the same `tip` on every server. Once the other seeds run, `peerstatus` shows `transport` `authenticated-discovery`, `discovery.verified` of at least 1, and each configured peer (@SEED_LIST@) `reachable` with a recent `last_success`.

EOF
        if [[ "$is_stratum" == true ]]; then
            render <<'EOF'
## 10 Miners

Point your ASICs at `stratum+tcp://@IP@:@STRATUM_PORT@` with any worker name (for example `rig01`) and the password installed in step 6; read it once and give it to your miners over a private channel:

```sh
sudo cat /etc/hashstash/stratum-password
```

@STRATUM_REACH@ Every block found here pays this node's `MINER_PUBLIC_KEY`, whatever the worker name.

```sh
sudo -u hashstash /usr/local/libexec/hashstash/run-node.sh snapshot | grep -E '"(workers_connected|accepted_shares|rejected_shares|blocks_found|hashrate_hps)"'
```

Check: `workers_connected` counts your rigs, `accepted_shares` rises, and after the first blocks `blocks_found` rises on the node that found them.

EOF
        fi
        if [[ "$is_web" == true ]]; then
            render <<'EOF'
## 11 Faucet (after the chain has run for a while)

Install the faucet binary pinned by its hash, its account, configuration and service, then create its key here:

```sh
echo "@FAUCET_SHA256@  release/hashstash-faucet" | sha256sum -c -
sudo install -d -o root -g root -m 755 /opt/hashstash-faucet /opt/hashstash-faucet/@VERSION@-@FAUCET_SHA256@
sudo install -o root -g root -m 755 release/hashstash-faucet /opt/hashstash-faucet/@VERSION@-@FAUCET_SHA256@/hashstash-faucet
getent passwd hashstash-faucet || sudo useradd --system --user-group --home-dir /var/lib/hashstash-faucet --no-create-home --shell /usr/sbin/nologin hashstash-faucet
sudo install -d -o root -g hashstash-faucet -m 750 /etc/hashstash-faucet
sudo install -d -o hashstash-faucet -g hashstash-faucet -m 700 /var/lib/hashstash-faucet
sudo install -o root -g hashstash-faucet -m 640 faucet/config.json /etc/hashstash-faucet/config.json
sudo install -o root -g root -m 644 faucet/hashstash-faucet.service /etc/systemd/system/hashstash-faucet.service
sudo sh -c 'umask 077; "$(cat /etc/hashstash/binary.path)" keygen --out /etc/hashstash-faucet/faucet.key'
sudo chown hashstash-faucet:hashstash-faucet /etc/hashstash-faucet/faucet.key
sudo "$(cat /etc/hashstash/binary.path)" address --key /etc/hashstash-faucet/faucet.key --config /etc/hashstash/network.json
sudo systemctl daemon-reload
```

Check: `keygen` printed the faucet's public key and `address` its funding address. The key never leaves this server.

### Fund it, signed offline

The payout key never comes online (docs/LAUNCH.md section 5). This server prepares an unsigned transfer through its own private RPC, which needs no key; your offline machine signs it with the release's `hashstash-cold`; this server broadcasts the signed result. @FUNDING@ atoms (@FUNDING_HASH@ hashes) cover the faucet's lifetime allowance of 1,000 claims of @FAUCET_PAYOUT@ atoms with their fees (at most 2 atoms each). The sender is @FUND_SENDER_NOTE@. On this server:

```sh
./release/hashstash rpc --url http://127.0.0.1:@RPC@/rpc account --params '{"key":"@FUND_SENDER@"}' | grep payment_available_hash
faucet_address=$(sudo "$(cat /etc/hashstash/binary.path)" address --key /etc/hashstash-faucet/faucet.key --config /etc/hashstash/network.json)
printf '{"TransferExact":{"recipient":"%s","amount":"@FUNDING@"}}\n' "$faucet_address" > faucet-funding.json
./release/hashstash prepare --url http://127.0.0.1:@RPC@/rpc --config network.json --sender @FUND_SENDER@ \
  --operation-file faucet-funding.json --expiry-blocks 240 --out faucet-funding.unsigned.json
```

Check: the sender's `payment_available_hash` exceeds @FUNDING@ atoms plus a few for the fee, and `prepare` printed its review (the faucet address as recipient, @FUNDING@ atoms, the fee and a 240-block lifetime, one hour at 15-second blocks: two blocks would be 30 seconds, too short for the round trip) and saved `faucet-funding.unsigned.json`, which holds no secret.

Move `faucet-funding.unsigned.json` to the offline machine, for example with `scp root@@IP@:@REMOTE_DIR@/faucet-funding.unsigned.json .` on your workstation and then removable media. There, start `hashstash-cold --config network.json` from the release (checked against `SHA256SUMS`) and open the address it prints; open the payout key (**Private key**, the file `hashstash keygen` wrote); import the unsigned file and choose **Review**. Compare the recipient with the faucet address, the amount (@FUNDING_HASH@ hashes) and the fee, choose **Sign transaction**, save the signed result as `faucet-funding.signed.txt` and **Lock** the signer. Bring that file back into this directory and, within the hour, broadcast it:

```sh
./release/hashstash broadcast --url http://127.0.0.1:@RPC@/rpc --raw-file faucet-funding.signed.txt
```

Check: `broadcast` prints the `transaction_id`. If the lifetime has passed, prepare and sign again; never broadcast an old signed file instead.

Then start the faucet and check it from this server, as nginx will call it:

```sh
sudo systemctl enable --now hashstash-faucet
sudo journalctl -u hashstash-faucet -n 20 --no-pager
curl -s -H 'Host: @PUBLIC_HOST@' -H 'X-Real-IP: 192.0.2.1' http://127.0.0.1:@FAUCET_PORT@/faucet/status
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: @PUBLIC_HOST@' http://127.0.0.1:@FAUCET_PORT@/faucet/status
```

Check: the journal says `Hashstash faucet: 127.0.0.1:@FAUCET_PORT@`; the first status shows `"chain_id":"@CHAIN_ID@"` and, once a new block has arrived and the transfer is confirmed, `"state":"ready"`; the second request, without `X-Real-IP`, gets `403`.

## 12 Website

```sh
sudo install -m 644 nginx/hashstash-public.conf /etc/nginx/sites-available/hashstash
sudo nginx -t && sudo systemctl reload nginx
```

Check: `nginx -t` succeeds (it fails if step 8 has not obtained the certificate). From another network:

```sh
curl -sI https://@PUBLIC_HOST@/ | head -1                                    # HTTP/2 200 (or HTTP/1.1 200)
curl -sI http://@PUBLIC_HOST@/ | grep -i '^location'                          # https://@PUBLIC_HOST@/
curl -s https://@PUBLIC_HOST@/faucet-config.json                              # {"url":"https://@PUBLIC_HOST@","chain_id":"@CHAIN_ID@"}
curl -s -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"peers","params":{}}' https://@PUBLIC_HOST@/rpc   # refused: private method
curl -s https://@PUBLIC_HOST@/faucet/status                                   # faucet state
```

Then open `https://@PUBLIC_HOST@/` in a browser: Wallet shows **Get test hashes** while the faucet is funded.

EOF
        fi
        render <<'EOF'
## Monitoring and rollback

Poll `run-node.sh snapshot` and `peerstatus` every 10 seconds and alert as in docs/LAUNCH.md section 12. For a dashboard, tunnel the private RPC from your machine with `ssh -N -L 127.0.0.1:@RPC@:127.0.0.1:@RPC@ root@@IP@` and open `http://127.0.0.1:@RPC@`. Rollback and abort criteria are in docs/LAUNCH-DAY.md; a rollback before the announcement copies the new kit to its own directory (step 0) and reinstalls from step 3 here.

After the announcement, back up `/etc/hashstash` encrypted (docs/LAUNCH.md section 13), then remove the staging copies of step 5: `shred -u /root/hashstash-keys/*`.
EOF
    } > "$dir/INSTALL.md"
done

# ------------------------------------------------------------- top level
seed_flags= seed_endpoints=
for ip in "${seeds[@]}"; do
    seed_flags+=" --seed $ip:$p2p_port"
    seed_endpoints+="${seed_endpoints:+, }\`$ip:$p2p_port\`"
done
vars[SEED_FLAGS]=$seed_flags
vars[SEED_ENDPOINTS]=$seed_endpoints
vars[HASHRATE]=${hashrate:-from the supplied genesis}
vars[GENESIS_TIME]=${genesis_unix:-at genesis creation}
vars[NETWORK_NAME]=${network_name:-at genesis creation}
vars[WEB_DIR]=$web_dir
vars[WEB_RPC]=$web_rpc
if [[ -z "$genesis" ]]; then
    vars[GENESIS_TIME_ARG]=${genesis_time:+ --genesis-time $genesis_time}
    vars[HASHRATE]=$hashrate
    render > "$out/genesis/create-genesis.sh" <<'EOF'
#!/usr/bin/env bash
# @BANNER@Create THE launch genesis once, on launch day, on the preparation
# machine, with the verified release binary. Then regenerate the kit with
#   bash scripts/launch-kit.sh ... --binary RELEASE/hashstash --genesis THIS_DIR/network.json --out NEW_DIR
set -euo pipefail
binary=${1:?usage: bash create-genesis.sh /path/to/release/hashstash}
[[ "$("$binary" --version)" == "hashstash @VERSION@" ]] || { echo "need hashstash @VERSION@" >&2; exit 1; }
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ ! -e "$here/network.json" ]] || { echo "network.json already exists: never create a second genesis" >&2; exit 1; }
"$binary" init --config "$here/network.json" --preset slow --hashrate @HASHRATE@@GENESIS_TIME_ARG@
"$binary" network --config "$here/network.json"
(cd -- "$here" && sha256sum network.json | tee network.json.sha256)
EOF
fi
{
    render <<'EOF'
# Hashstash @VERSION@ launch kit

@BANNER@Generated by `scripts/launch-kit.sh` on @GENERATED@ from source commit @COMMIT@. The launch sequence across servers is `docs/LAUNCH-DAY.md` in the source checkout; each server's own steps are in its `INSTALL.md`.

| Value | |
| --- | --- |
| Release | `hashstash @VERSION@` |
| `hashstash` SHA256 | `@BINARY_SHA256@` |
| `hashstash-faucet` SHA256 | `@FAUCET_SHA256@` |
| `network.json` SHA256 | `@GENESIS_SHA256@` |
| Chain ID | `@CHAIN_ID@` |
| Network name | `@NETWORK_NAME@` |
| Genesis time (Unix) | `@GENESIS_TIME@` |
| Calibration hashrate | `@HASHRATE@` |
| Website | `https://@PUBLIC_HOST@/` |

| # | Server | Roles | Private RPC port | Directory |
| --- | --- | --- | --- | --- |
EOF
    printf '%s\n' "${summary_rows[@]}"
    render <<'EOF'

Copy each `server-N-IP/` directory to its server, into `@REMOTE_DIR@` (`INSTALL.md` step 0). Nothing in this kit is secret: peer identities, Stratum passwords and the faucet key are generated on the servers; payout keys appear only as public keys.

Users join with:

```sh
hashstash run --config network.json --data chain.sqlite --miner YOUR_PAYOUT_PUBLIC_KEY --peer-discovery@SEED_FLAGS@ --no-stratum
```

Give users every seed, as this command does. Each seed lists the others as configured peers, and a node never passes configured peers on, so a node that knows one seed learns from it only the nodes that advertise themselves (`--advertise-peer`), not the other seeds.

`ANNOUNCEMENT.md` is a draft of the launch announcement with these values and the limitations users must be told.
EOF
    if [[ -z "$genesis" ]]; then
        render <<'EOF'

**No genesis yet.** On launch day run `bash genesis/create-genesis.sh RELEASE/hashstash` once, then regenerate the kit into a new directory with `--binary RELEASE/hashstash --genesis genesis/network.json`; install only from that kit.
EOF
    fi
} > "$out/README.md"
{
    render <<'EOF'
# Draft launch announcement

@BANNER@Publish through at least two independent channels, and only after docs/LAUNCH-DAY.md says the network passed its checks.

The Hashstash @VERSION@ network is live.

- Website: https://@PUBLIC_HOST@/ (bookmark the `https://` address; never create or import a wallet on a page reached through `http://`)
- Chain ID: `@CHAIN_ID@`
- Genesis `network.json` SHA256: `@GENESIS_SHA256@` (attach the file)
- Release `SHA256SUMS` (attach it and its signature): `hashstash` `@BINARY_SHA256@`, `hashstash-faucet` `@FAUCET_SHA256@`
- Seeds (P2P): @SEED_ENDPOINTS@

To run your own node, verify the files, then:

```sh
sha256sum -c SHA256SUMS
sha256sum network.json
./hashstash network --config network.json     # must print the chain ID above
./hashstash run --config network.json --data chain.sqlite --miner YOUR_PAYOUT_PUBLIC_KEY --peer-discovery@SEED_FLAGS@ --no-stratum
```

EOF
    # The accepted limitations, verbatim from the runbook (one source of truth).
    awk '/^## 15 Limitations users must be told/ { on = 1; sub(/^## 15 /, "## "); } on' "$root/docs/LAUNCH.md" \
        | sed 's|](\([A-Z][A-Z-]*\.md\)|](docs/\1|g; s|(section \([0-9][0-9]*\))|(docs/LAUNCH.md section \1)|g'
} > "$out/ANNOUNCEMENT.md"
grep -q '^## Limitations users must be told' "$out/ANNOUNCEMENT.md" || fail 'docs/LAUNCH.md has no section 15 with the limitations'
{
    printf '# %sPublic launch values (no secrets). Generated %s.\n' "$banner" "$generated"
    printf 'VERSION=%s\nCOMMIT=%s\n' "$version" "$commit"
    printf 'HASHSTASH_SHA256=%s\nHASHSTASH_FAUCET_SHA256=%s\n' "${vars[BINARY_SHA256]}" "${vars[FAUCET_SHA256]}"
    printf 'GENESIS_SHA256=%s\nCHAIN_ID=%s\nGENESIS_TIME=%s\nNETWORK=%s\nHASHRATE=%s\n' \
        "${vars[GENESIS_SHA256]}" "${vars[CHAIN_ID]}" "${vars[GENESIS_TIME]}" "${vars[NETWORK_NAME]}" "${vars[HASHRATE]}"
    printf 'SEEDS=%s\nWEB_HOST=%s\nWEBSITE=https://%s/\n' "${seeds[*]}" "$web_host" "$public_host"
    printf 'STRATUM_HOSTS=%s\nKIT_REMOTE_DIR=%s\nFAUCET_FUNDING_ATOMS=%s\n' "$(for ip in "${seeds[@]}"; do [[ ! ${stratum_on[$ip]+x} ]] || printf '%s ' "$ip"; done | sed 's/ $//')" "$remote_dir" "$faucet_funding"
    printf 'P2P_PORT=%s\nSTRATUM_PORT=%s\n' "$p2p_port" "$stratum_port"
    printf 'REHEARSAL=%s\nEASY_TARGET=%s\nFIXTURE_BUILD=%s\n' "$rehearsal" "$easy" "$fixture"
} > "$out/launch-values.env"
chmod -R go-w -- "$out"
find "$out" -name '*.sh' -exec chmod 755 {} +
created=false
printf 'Launch kit written to %s\n' "$out"
for dir_name in "${server_dirs[@]}"; do printf '  %s/\n' "$dir_name"; done
printf 'On each server it goes into %s (INSTALL.md step 0).\n' "$remote_dir"
if [[ -n "$chain_id" ]]; then
    printf 'Chain ID: %s\nnetwork.json SHA256: %s\n' "$chain_id" "$genesis_sha"
else
    printf 'No genesis yet: run %s/genesis/create-genesis.sh on launch day, then regenerate the kit with --genesis.\n' "$out"
fi
