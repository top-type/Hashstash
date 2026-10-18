#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# node.env is a small data file, never sourced as shell code.
fail() { printf 'Hashstash: %s\n' "$*" >&2; exit 1; }
mode=${1:-run}
env_file=${2:-/etc/hashstash/node.env}
binary=${3:-}
genesis=${4:-/etc/hashstash/network.json}
password_file=${5:-/etc/hashstash/stratum-password}
peer_key_check=${6:-}
[[ $# -le 6 ]] || fail 'too many arguments'
case "$mode" in run|check|snapshot|peers) ;; *) fail 'mode must be run, check, snapshot, or peers' ;; esac
[[ -z "$peer_key_check" || "$mode" == check ]] || fail 'peer identity override is for read-only installation checks only'
if [[ -z "$binary" ]]; then
    IFS= read -r binary < /etc/hashstash/binary.path || [[ -n "$binary" ]]
fi
[[ "$binary" = /* && -x "$binary" ]] || fail 'binary must be an executable absolute path'
[[ -f "$env_file" ]] || fail 'node.env is missing'

declare -A settings=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" == *=* ]] || fail 'node.env requires KEY=value lines'
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
        MINER_PUBLIC_KEY|RPC_PORT|P2P_PORT|STRATUM_PORT|STRATUM_ADVERTISE|SHARE_DIFFICULTY|PEERS|PUBLIC_WEB_PORT|STRATUM_ENABLED|PEER_KEY_FILE|PEER_PINS|PEER_DISCOVERY|PEER_SEEDS|PEER_ADVERTISE|ALLOW_EASY_TARGET) ;;
        *) fail "unknown node.env field: $key" ;;
    esac
    [[ ! ${settings[$key]+present} ]] || fail "duplicate node.env field: $key"
    settings[$key]=$value
done < "$env_file"
for key in MINER_PUBLIC_KEY RPC_PORT P2P_PORT STRATUM_PORT STRATUM_ADVERTISE SHARE_DIFFICULTY PEERS; do
    [[ ${settings[$key]+present} ]] || fail "missing node.env field: $key"
done
stratum_enabled=${settings[STRATUM_ENABLED]:-true}
[[ "$stratum_enabled" == true || "$stratum_enabled" == false ]] || fail 'STRATUM_ENABLED must be true or false'
peer_discovery=${settings[PEER_DISCOVERY]-false}
[[ "$peer_discovery" == true || "$peer_discovery" == false ]] || fail 'PEER_DISCOVERY must be true or false'
allow_easy_target=${settings[ALLOW_EASY_TARGET]-false}
[[ "$allow_easy_target" == true || "$allow_easy_target" == false ]] || fail 'ALLOW_EASY_TARGET must be true or false'
[[ ${settings[MINER_PUBLIC_KEY]} =~ ^[0-9a-fA-F]{64}$ ]] || fail 'MINER_PUBLIC_KEY must be a 32-byte hexadecimal public key'
valid_port() { [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$1 <= 65535 )); }
valid_ipv4_endpoint() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]+)$ ]] || return 1
    local octet port=${BASH_REMATCH[5]}
    local octets=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}")
    for octet in "${octets[@]}"; do
        (( 10#$octet <= 255 )) || return 1
        [[ "$octet" == 0 || "$octet" != 0* ]] || return 1
    done
    [[ "$1" != 0.0.0.0:* && "$1" != 255.255.255.255:* ]] && valid_port "$port"
}
valid_ipv6() {
    local address=$1 remainder group compressed=false
    local groups=()
    [[ "$address" =~ ^[0-9a-fA-F:]+$ && "$address" != :: && "$address" != *:::* ]] || return 1
    if [[ "$address" == *::* ]]; then
        compressed=true
        remainder=${address#*::}
        [[ "$remainder" != *::* ]] || return 1
        address=${address/::/:}
        address=${address#:}; address=${address%:}
    else
        [[ "$address" != :* && "$address" != *: ]] || return 1
    fi
    IFS=: read -r -a groups <<< "$address"
    if [[ "$compressed" == true ]]; then
        (( ${#groups[@]} < 8 )) || return 1
    else
        (( ${#groups[@]} == 8 )) || return 1
    fi
    for group in "${groups[@]}"; do [[ "$group" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1; done
}
valid_endpoint() {
    if [[ "$1" =~ ^\[([0-9a-fA-F:]+)\]:([0-9]+)$ ]]; then
        local address=${BASH_REMATCH[1]} port=${BASH_REMATCH[2]}
        valid_ipv6 "$address" && valid_port "$port"
    else
        valid_ipv4_endpoint "$1"
    fi
}
valid_seed() {
    [[ ${#1} -le 320 ]] || return 1
    if [[ "$1" == \[* || "$1" =~ ^[0-9.]+: ]]; then valid_endpoint "$1"; return; fi
    [[ "$1" =~ ^([a-zA-Z0-9.-]+):([0-9]+)$ ]] || return 1
    local host=${BASH_REMATCH[1]} port=${BASH_REMATCH[2]} label
    local labels=()
    [[ ${#host} -le 253 && "$host" != .* && "$host" != *. && "$host" != *..* ]] && valid_port "$port" || return 1
    IFS=. read -r -a labels <<< "$host"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && "$label" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
    done
}
for key in RPC_PORT P2P_PORT STRATUM_PORT; do
    valid_port "${settings[$key]}" || fail "$key must be a port from 1 to 65535"
done
if [[ ${settings[PUBLIC_WEB_PORT]+present} ]]; then
    valid_port "${settings[PUBLIC_WEB_PORT]}" || fail 'PUBLIC_WEB_PORT must be a valid port'
    for key in RPC_PORT P2P_PORT STRATUM_PORT; do
        [[ ${settings[PUBLIC_WEB_PORT]} != "${settings[$key]}" ]] || fail 'public web and node listener ports must differ'
    done
fi
[[ ${settings[RPC_PORT]} != "${settings[P2P_PORT]}" && ${settings[RPC_PORT]} != "${settings[STRATUM_PORT]}" && ${settings[P2P_PORT]} != "${settings[STRATUM_PORT]}" ]] || fail 'listener ports must differ'
advertise=${settings[STRATUM_ADVERTISE]}
[[ "$advertise" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*:([0-9]+)$ ]] && valid_port "${BASH_REMATCH[1]}" || fail 'STRATUM_ADVERTISE must be an IPv4 address or DNS name followed by :PORT'
[[ ${#advertise} -le 320 && "$advertise" != 0.0.0.0:* ]] || fail 'STRATUM_ADVERTISE must identify a reachable host'
difficulty=${settings[SHARE_DIFFICULTY]}
[[ "$difficulty" =~ ^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$ ]] || fail 'SHARE_DIFFICULTY must be a positive number'
LC_ALL=C awk -v value="$difficulty" 'BEGIN { exit !(value >= 1e-12 && value <= 1e18) }' || fail 'SHARE_DIFFICULTY must be between 1e-12 and 1e18'
peers=()
read -r -a peers <<< "${settings[PEERS]}"
(( ${#peers[@]} <= 64 )) || fail 'too many peers'
for peer in "${peers[@]}"; do
    valid_endpoint "$peer" || fail 'PEERS must contain numeric IPv4:PORT or [IPv6]:PORT endpoints'
done
seeds=()
read -r -a seeds <<< "${settings[PEER_SEEDS]:-}"
(( ${#seeds[@]} <= 64 )) || fail 'too many peer seeds'
declare -A seed_set=()
for seed in "${seeds[@]}"; do
    valid_seed "$seed" || fail 'PEER_SEEDS must contain HOST:PORT or [IPv6]:PORT endpoints'
    normalized_seed=${seed,,}
    [[ ! ${seed_set[$normalized_seed]+present} ]] || fail 'duplicate peer seed'
    seed_set[$normalized_seed]=1
done
peer_advertise=${settings[PEER_ADVERTISE]:-}
[[ -z "$peer_advertise" ]] || valid_endpoint "$peer_advertise" || fail 'PEER_ADVERTISE must be a numeric IPv4:PORT or [IPv6]:PORT endpoint'
if [[ "$peer_discovery" == false ]]; then
    (( ${#seeds[@]} == 0 )) && [[ -z "$peer_advertise" ]] || fail 'PEER_SEEDS and PEER_ADVERTISE require PEER_DISCOVERY=true'
fi
declare -A peer_set=() pin_set=()
for peer in "${peers[@]}"; do
    [[ ! ${peer_set[$peer]+present} ]] || fail 'duplicate configured peer'
    peer_set[$peer]=1
done
peer_key=${settings[PEER_KEY_FILE]:-}
peer_pins=()
read -r -a peer_pins <<< "${settings[PEER_PINS]:-}"
if [[ -n "$peer_key" || "$peer_discovery" == true ]] || (( ${#peer_pins[@]} )); then
    [[ "$peer_key" = /* ]] || fail 'PEER_KEY_FILE must be an absolute path'
    (( ${#peer_pins[@]} <= 64 )) || fail 'too many peer pins'
    if [[ "$peer_discovery" == false ]]; then
        (( ${#peer_pins[@]} > 0 && ${#peer_pins[@]} == ${#peers[@]} )) || fail 'authenticated peers require exactly one pin per configured peer (1..64)'
    fi
    for pin in "${peer_pins[@]}"; do
        [[ "$pin" == *=* && "${pin#*=}" =~ ^[0-9a-fA-F]{64}$ ]] || fail 'PEER_PINS must contain IP:PORT=PUBLIC_KEY entries'
        address=${pin%%=*}
        valid_endpoint "$address" || fail 'invalid PEER_PINS endpoint'
        [[ ! ${pin_set[$address]+present} ]] || fail 'duplicate peer pin'
        [[ "$peer_discovery" == true || ${peer_set[$address]+present} ]] || fail 'PEER_PINS must match PEERS exactly in pinned-only mode'
        pin_set[$address]=1
    done
    key_to_check=${peer_key_check:-$peer_key}
    [[ -r "$key_to_check" && -f "$key_to_check" && ! -L "$key_to_check" ]] || fail 'peer identity must be an existing readable regular file, not a symlink'
elif [[ -n "$peer_key_check" ]]; then
    fail 'peer identity supplied without authenticated peer configuration'
fi

case "$mode" in
    snapshot|peers)
        exec "$binary" rpc --url "http://127.0.0.1:${settings[RPC_PORT]}/rpc" "$mode"
        ;;
esac
[[ -r "$genesis" ]] || fail 'genesis file is unreadable'
if [[ "$stratum_enabled" == true ]]; then
[[ -r "$password_file" ]] || fail 'Stratum password file is unreadable'
# The password authorizes mining only. It is not a wallet key or logged argument.
password=$(< "$password_file")
password=${password%$'\r'}
[[ -n "$password" && ${#password} -le 256 && "$password" =~ ^[[:graph:]]+$ ]] || fail 'Stratum password must be one nonempty ASCII token, at most 256 characters'
unset password
fi
args=(run --config "$genesis" --data /var/lib/hashstash/chain.sqlite
    --miner "${settings[MINER_PUBLIC_KEY]}"
    --rpc "127.0.0.1:${settings[RPC_PORT]}"
    --p2p "0.0.0.0:${settings[P2P_PORT]}")
if [[ "$stratum_enabled" == true ]]; then
    args+=(--stratum "0.0.0.0:${settings[STRATUM_PORT]}" --stratum-advertise "$advertise"
        --stratum-share-difficulty "$difficulty" --stratum-password-file "$password_file")
else
    args+=(--no-stratum)
fi
for peer in "${peers[@]}"; do args+=(--peer "$peer"); done
if [[ "$peer_discovery" == true ]]; then
    args+=(--peer-discovery)
    for seed in "${seeds[@]}"; do args+=(--seed "$seed"); done
    [[ -z "$peer_advertise" ]] || args+=(--advertise-peer "$peer_advertise")
fi
if [[ -n "$peer_key" ]]; then
    args+=(--peer-key-file "$peer_key")
    for pin in "${peer_pins[@]}"; do args+=(--peer-pin "$pin"); done
fi
if [[ ${settings[PUBLIC_WEB_PORT]+present} ]]; then
    # A separate restricted API, reached through the HTTPS reverse proxy only.
    args+=(--public-web "127.0.0.1:${settings[PUBLIC_WEB_PORT]}")
fi
# P2P always binds 0.0.0.0, so only a calibrated genesis runs without this.
[[ "$allow_easy_target" == false ]] || args+=(--allow-easy-target)
if [[ "$mode" == check ]]; then
    "$binary" network --config "$genesis" > /dev/null
    "$binary" address --public-key "${settings[MINER_PUBLIC_KEY]}" --config "$genesis" > /dev/null
    if [[ -n "$peer_key" ]]; then
        auth_args=(peer-keycheck --key-file "$key_to_check" --miner "${settings[MINER_PUBLIC_KEY]}")
        [[ "$peer_discovery" == false ]] || auth_args+=(--peer-discovery)
        for pin in "${peer_pins[@]}"; do auth_args+=(--peer-pin "$pin"); done
        "$binary" "${auth_args[@]}" > /dev/null
    fi
    # Every refusal run makes before it opens the database, such as an easy
    # proof-of-work limit behind the public P2P listener, fails here rather
    # than in the service's restart loop.
    "$binary" "${args[@]}" --preflight > /dev/null
    printf 'Configuration and payout public key are valid. No listeners started.\n'
    exit 0
fi
# No wallet key, watch key, or software miner is started by this service.
exec "$binary" "${args[@]}"
