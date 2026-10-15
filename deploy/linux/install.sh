#!/usr/bin/env bash
set -euo pipefail
umask 077
fail() { printf 'Hashstash install: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sudo bash install.sh --binary /path/hashstash --sha256 HEX \
  --genesis /path/network.json --genesis-sha256 HEX --node-env /path/node.env \
  [--stratum-password-file /path/mining-password] \
  [--peer-key-file /path/dedicated-peer-identity.json] [--check]

Installs Hashstash 0.40.0 without starting or enabling it. Existing files must
match exactly; configuration and databases are never replaced. --check performs
read-only input validation and needs no root privileges.
EOF
}
binary= sha256= genesis= genesis_sha256= node_env= password_file= peer_key_file= check=false
while (( $# )); do
    case "$1" in
        --binary|--sha256|--genesis|--genesis-sha256|--node-env|--stratum-password-file|--peer-key-file)
            (( $# >= 2 )) || fail "missing value for $1"
            case "$1" in
                --binary) binary=$2 ;; --sha256) sha256=$2 ;; --genesis) genesis=$2 ;;
                --genesis-sha256) genesis_sha256=$2 ;;
                --node-env) node_env=$2 ;; --stratum-password-file) password_file=$2 ;;
                --peer-key-file) peer_key_file=$2 ;;
            esac
            shift 2 ;;
        --check) check=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; fail "unknown argument: $1" ;;
    esac
done
[[ -n "$binary" && -n "$genesis" && -n "$node_env" ]] || { usage >&2; exit 1; }
[[ "$sha256" =~ ^[0-9a-fA-F]{64}$ ]] || fail '--sha256 must be the expected binary SHA256'
[[ "$genesis_sha256" =~ ^[0-9a-fA-F]{64}$ ]] || fail '--genesis-sha256 must be the expected shared genesis SHA256'
sha256=${sha256,,}
genesis_sha256=${genesis_sha256,,}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
for command in sha256sum realpath cmp stat install awk od tr; do command -v "$command" >/dev/null || fail "missing command: $command"; done
binary=$(realpath -e -- "$binary")
genesis=$(realpath -e -- "$genesis")
node_env=$(realpath -e -- "$node_env")
if [[ -n "$password_file" ]]; then password_file=$(realpath -e -- "$password_file"); fi
if [[ -n "$peer_key_file" ]]; then
    [[ -f "$peer_key_file" && ! -L "$peer_key_file" ]] || fail 'peer identity source must be a regular file, not a symlink'
    peer_key_file=$(realpath -e -- "$peer_key_file")
fi
peer_key_destination= stratum_enabled=true
while IFS= read -r line || [[ -n "$line" ]]; do
    line=${line%$'\r'}
    if [[ "$line" == PEER_KEY_FILE=* ]]; then peer_key_destination=${line#*=}; fi
    if [[ "$line" == STRATUM_ENABLED=* ]]; then stratum_enabled=${line#*=}; fi
done < "$node_env"
[[ "$stratum_enabled" != true || -n "$password_file" ]] || fail 'enabled Stratum requires --stratum-password-file'
if [[ -n "$peer_key_destination" || -n "$peer_key_file" ]]; then
    [[ "$peer_key_destination" == /etc/hashstash/peer-identity.json && -n "$peer_key_file" ]] || fail 'pinned installation requires PEER_KEY_FILE=/etc/hashstash/peer-identity.json and --peer-key-file source'
fi
[[ -f "$binary" && -x "$binary" ]] || fail 'binary is not an executable file'
actual=$(sha256sum -- "$binary"); actual=${actual%% *}
[[ "$actual" == "$sha256" ]] || fail 'binary SHA256 does not match'
[[ $(od -An -tx1 -N4 -- "$binary" | tr -d ' \n') == 7f454c46 ]] || fail 'binary must be a Linux ELF executable'
actual=$(sha256sum -- "$genesis"); actual=${actual%% *}
[[ "$actual" == "$genesis_sha256" ]] || fail 'shared genesis SHA256 does not match'
[[ $("$binary" --version) == 'hashstash 0.40.0' ]] || fail 'expected Hashstash 0.40.0 Linux binary'
bash "$script_dir/run-node.sh" check "$node_env" "$binary" "$genesis" "$password_file" "$peer_key_file"
printf 'Shared genesis SHA256: %s\n' "$(sha256sum -- "$genesis" | awk '{print $1}')"
"$binary" network --config "$genesis"
if [[ "$check" == true ]]; then exit 0; fi
(( EUID == 0 )) || fail 'installation requires root; use --check for read-only validation'
for command in getent useradd flock systemctl; do command -v "$command" >/dev/null || fail "missing command: $command"; done
# Serialize repeat installs. No service state is changed by this script.
exec 9>/run/lock/hashstash-install.lock
flock -n 9 || fail 'another Hashstash installer is running'
binary_dest="/opt/hashstash/0.40.0-$sha256/hashstash"
pointer=$(mktemp)
trap 'rm -f -- "$pointer"' EXIT
printf '%s\n' "$binary_dest" > "$pointer"
sources=("$binary" "$genesis" "$node_env" "$pointer" "$script_dir/run-node.sh" "$script_dir/hashstash.service")
destinations=("$binary_dest" /etc/hashstash/network.json /etc/hashstash/node.env /etc/hashstash/binary.path /usr/local/libexec/hashstash/run-node.sh /etc/systemd/system/hashstash.service)
modes=(755 640 640 640 755 644)
groups=(root hashstash hashstash hashstash root root)
owners=(root root root root root root)
if [[ -n "$password_file" ]]; then
    sources+=("$password_file"); destinations+=(/etc/hashstash/stratum-password); modes+=(640); groups+=(hashstash); owners+=(root)
fi
if [[ -n "$peer_key_file" ]]; then
    # Dedicated transport keys only: peer-keycheck above rejects wallet formats.
    # The service must own its 0600 key; the parent configuration directory is root-owned.
    sources+=("$peer_key_file"); destinations+=("$peer_key_destination"); modes+=(600); groups+=(hashstash); owners+=(hashstash)
fi
for directory in /opt/hashstash /etc/hashstash /var/lib/hashstash /usr/local/libexec/hashstash "$(dirname -- "$binary_dest")"; do
    [[ ! -L "$directory" ]] || fail "refusing symlink directory: $directory"
    [[ ! -e "$directory" || -d "$directory" ]] || fail "not a directory: $directory"
done
# All content conflicts are checked before creating the service account or files.
for index in "${!sources[@]}"; do
    destination=${destinations[$index]}
    [[ ! -L "$destination" ]] || fail "refusing symlink file: $destination"
    if [[ -e "$destination" ]]; then
        [[ -f "$destination" ]] && cmp -s -- "${sources[$index]}" "$destination" || fail "existing file differs; preserved: $destination"
        [[ $(stat -c '%U:%G:%a' -- "$destination") == "${owners[$index]}:${groups[$index]}:${modes[$index]}" ]] || fail "existing file has unexpected owner or permissions; preserved: $destination"
    fi
done
if getent passwd hashstash >/dev/null; then
    IFS=: read -r _ _ account_uid _ _ account_home account_shell < <(getent passwd hashstash)
    [[ "$account_uid" != 0 && "$account_home" == /var/lib/hashstash && "$account_shell" == /usr/sbin/nologin && $(id -gn hashstash) == hashstash ]] || fail 'existing hashstash account does not match the dedicated service account'
else
    [[ ! -e /var/lib/hashstash ]] || fail 'data directory exists without the service account; preserved'
    useradd --system --user-group --home-dir /var/lib/hashstash --no-create-home --shell /usr/sbin/nologin hashstash
fi
if [[ -d /var/lib/hashstash ]]; then
    [[ $(stat -c '%U:%G' /var/lib/hashstash) == hashstash:hashstash ]] || fail 'existing data directory has another owner; preserved'
else
    install -d -o hashstash -g hashstash -m 750 /var/lib/hashstash
fi
for directory in /opt/hashstash "$(dirname -- "$binary_dest")" /usr/local/libexec/hashstash; do
    if [[ ! -d "$directory" ]]; then install -d -o root -g root -m 755 "$directory"; fi
    [[ $(stat -c '%U:%a' -- "$directory") == root:755 ]] || fail "unexpected directory owner or permissions: $directory"
done
if [[ ! -d /etc/hashstash ]]; then install -d -o root -g hashstash -m 750 /etc/hashstash; fi
[[ $(stat -c '%U:%G:%a' /etc/hashstash) == root:hashstash:750 ]] || fail 'unexpected /etc/hashstash owner or permissions'
for index in "${!sources[@]}"; do
    destination=${destinations[$index]}
    if [[ ! -e "$destination" ]]; then
        install -o "${owners[$index]}" -g "${groups[$index]}" -m "${modes[$index]}" -- "${sources[$index]}" "$destination"
    fi
done
systemctl daemon-reload
printf 'Installed. Service was not enabled or started; existing chain data was preserved.\n'
printf 'After configuring the host firewall: sudo systemctl enable --now hashstash\n'
