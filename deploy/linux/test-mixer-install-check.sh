#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { printf '%s\n' 'usage: test-mixer-install-check.sh /path/hashstash-mixer' >&2; exit 1; }
binary=$(realpath -e -- "$1")
scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
config="$temporary/config.json"
cat > "$config" <<'JSON'
{"rpc_url":"http://127.0.0.1:20490/","chain_id":"0707070707070707070707070707070707070707070707070707070707070707","key_file":"/nonexistent-mixer-check/key.json","database":"/nonexistent-mixer-check/ledger.sqlite","status_file":"/nonexistent-mixer-check/status.json","denomination_atoms":"1000000000000000","service_fee_bps":100,"payout_fee_cap_atoms":"1000000","minimum_deposits":4,"confirmations":6,"timeout_seconds":3600,"poll_seconds":10,"max_deposits":100000}
JSON
digest=$(sha256sum -- "$binary"); digest=${digest%% *}
# This succeeds despite inaccessible nonexistent key/ledger paths and performs
# no service/user/filesystem installation, even when the test runs as root.
bash "$scripts/install-mixer.sh" "$binary" "$digest" "$config" --check >/dev/null
if bash "$scripts/install-mixer.sh" "$binary" "${digest:1}0" "$config" --check >/dev/null 2>&1; then echo 'wrong checksum accepted' >&2; exit 1; fi
ln -s -- "$config" "$temporary/config-link.json"
if bash "$scripts/install-mixer.sh" "$binary" "$digest" "$temporary/config-link.json" --check >/dev/null 2>&1; then echo 'symlink input accepted' >&2; exit 1; fi
printf '{}\n' > "$temporary/invalid.json"
if bash "$scripts/install-mixer.sh" "$binary" "$digest" "$temporary/invalid.json" --check >/dev/null 2>&1; then echo 'invalid configuration accepted' >&2; exit 1; fi
sed 's/127.0.0.1/192.0.2.1/' "$config" > "$temporary/remote.json"
if bash "$scripts/install-mixer.sh" "$binary" "$digest" "$temporary/remote.json" --check >/dev/null 2>&1; then echo 'remote RPC accepted' >&2; exit 1; fi
grep -q 'ExecStart=.* run .* --execute$' "$scripts/hashstash-mixer.service"
! grep -Eq 'systemctl (start|enable|restart)' "$scripts/install-mixer.sh"
printf '%s\n' 'Mixer installer: 7 preflight and activation-safety checks passed.'
