#!/usr/bin/env bash
set -euo pipefail
umask 077
fail() { printf 'Mixer install: %s\n' "$*" >&2; exit 1; }
[[ $# == 3 || ( $# == 4 && "$4" == --check ) ]] || fail 'usage: install-mixer.sh /path/hashstash-mixer SHA256 /path/config.json [--check]'
[[ -f "$1" && ! -L "$1" && -f "$3" && ! -L "$3" ]] || fail 'binary and configuration must be regular files, not symlinks'
binary=$(realpath -e -- "$1")
expected=$2
config=$(realpath -e -- "$3")
[[ "$expected" =~ ^[0-9a-f]{64}$ && -f "$binary" && -x "$binary" ]] || fail 'invalid binary or checksum'
actual=$(sha256sum -- "$binary"); actual=${actual%% *}
[[ "$actual" == "$expected" ]] || fail 'binary checksum differs'
[[ $("$binary" --version) == 'hashstash-mixer 0.36.0' ]] || fail 'unexpected mixer version'
"$binary" check-config --config "$config"
if [[ ${4:-} == --check ]]; then printf '%s\n' 'Mixer input validation passed; no changes made.'; exit 0; fi
(( EUID == 0 )) || fail 'requires root; --check is read-only'
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
destination=/usr/local/libexec/hashstash/hashstash-mixer
conf_destination=/etc/hashstash-mixer/config.json
unit=/etc/systemd/system/hashstash-mixer.service
exec 9>/run/lock/hashstash-mixer-install.lock
flock -n 9 || fail 'another mixer installer is running'
for directory in /usr/local/libexec/hashstash /etc/hashstash-mixer /var/lib/hashstash-mixer /var/lib/hashstash-mixer-status; do
    [[ ! -L "$directory" ]] || fail "destination directory is a symlink: $directory"
done
# Existing configuration, keys and ledgers are never replaced.
for pair in "$binary|$destination" "$config|$conf_destination" "$script_dir/hashstash-mixer.service|$unit"; do
    source=${pair%%|*}; target=${pair#*|}
    [[ ! -L "$target" ]] || fail "destination is a symlink: $target"
    [[ ! -e "$target" ]] || cmp -s -- "$source" "$target" || fail "existing file differs: $target"
done
getent passwd hashstash-mixer >/dev/null || useradd --system --home-dir /var/lib/hashstash-mixer --shell /usr/sbin/nologin hashstash-mixer
install -d -m 755 /usr/local/libexec/hashstash
install -d -m 750 -o root -g hashstash-mixer /etc/hashstash-mixer
install -d -m 700 -o hashstash-mixer -g hashstash-mixer /var/lib/hashstash-mixer
install -d -m 755 -o hashstash-mixer -g hashstash-mixer /var/lib/hashstash-mixer-status
[[ -e "$destination" ]] || install -m 755 -o root -g root -- "$binary" "$destination"
[[ -e "$conf_destination" ]] || install -m 640 -o root -g hashstash-mixer -- "$config" "$conf_destination"
[[ -e "$unit" ]] || install -m 644 -o root -g root -- "$script_dir/hashstash-mixer.service" "$unit"
systemctl daemon-reload
printf '%s\n' 'Installed without starting or enabling. Generate a dedicated signer, verify public terms, and run observe-only before enabling execution.'
