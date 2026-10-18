#!/bin/bash
# Live network suites on a disposable three-node fixture testnet: the Linux
# counterpart of Start-Testnet.ps1 -Fresh -SeedWallets, on loopback only.
#   scripts/ci_network_suites.sh BINARY DIRECTORY BASE_PORT [SUITE...]
# BINARY is a test-fixtures build; DIRECTORY must not exist yet; the nodes
# listen on BASE_PORT + 10 * i + {0: RPC, 1: P2P, 2: Stratum}. Each SUITE
# (default: test_network test_economic_adversarial test_load, in that order;
# test_network funds the chain the other two use) runs against the same
# network with a report and log in DIRECTORY. test_reserve_network expects a
# fresh chain, so run it alone on a second invocation. Only the nodes this
# script started are stopped.
set -euo pipefail
[ $# -ge 3 ] || { sed -n '2,12p' "$0"; exit 2; }
binary=$(realpath "$1")
root=$(realpath -m "$2")
base=$3
shift 3
suites=("$@")
[ ${#suites[@]} -gt 0 ] || suites=(test_network test_economic_adversarial test_load)
repository=$(cd "$(dirname "$0")/.." && pwd)
[ ! -e "$root" ] || { echo "refusing to reuse $root" >&2; exit 2; }
mkdir -p "$root"

python3 - "$repository/config/testnet.json" "$root/network.json" <<'EOF'
import json, sys, time
config = json.load(open(sys.argv[1]))
config['test_work'] = True  # accelerated fixture issuance; test-fixtures builds only
config['network'] = 'hashstash-ci-' + time.strftime('%Y%m%d-%H%M%S', time.gmtime())
config['genesis_time'] = int(time.time()) - 1
json.dump(config, open(sys.argv[2], 'w'), indent=2)
EOF
"$binary" network --config "$root/network.json" > /dev/null

pids=()
stop() {
  if [ ${#pids[@]} -gt 0 ]; then
    kill "${pids[@]}" 2> /dev/null || true
    wait "${pids[@]}" 2> /dev/null || true
  fi
}
trap stop EXIT
for i in 0 1 2; do
  directory=$root/node-$((i + 1))
  mkdir -p "$directory"
  "$binary" keygen --out "$directory/miner.key" > /dev/null
  "$binary" public-key --key "$directory/miner.key" > "$directory/public_key"
done
for i in 0 1 2; do
  directory=$root/node-$((i + 1))
  rpc=$((base + 10 * i))
  arguments=(run --config "$root/network.json" --data "$directory/chain.sqlite"
    --miner "$(cat "$directory/public_key")" --wallet-key "$directory/miner.key"
    --rpc "127.0.0.1:$rpc" --p2p "127.0.0.1:$((rpc + 1))" --stratum "127.0.0.1:$((rpc + 2))")
  [ "$i" -ne 0 ] || arguments+=(--stratum-share-difficulty 65536)
  for j in 0 1 2; do
    [ "$j" -eq "$i" ] || arguments+=(--peer "127.0.0.1:$((base + 10 * j + 1))")
  done
  "$binary" "${arguments[@]}" > "$directory/stdout.log" 2> "$directory/stderr.log" &
  pids+=($!)
done

# The manifest scripts/test_network.py and the other suites read.
python3 - "$root" "$binary" "$base" "${pids[@]}" <<'EOF'
import datetime, json, sys, time, urllib.request
root, binary, base, pids = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4:]
def status(port):
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}/rpc',
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'status', 'params': {}}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=2) as response:
        return json.load(response)['result']
chain = ''
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    try:
        chain = status(base)['chain_id']
        for i in (1, 2):
            status(base + 10 * i)
        break
    except Exception:
        time.sleep(0.5)
if not chain:
    sys.exit('fixture nodes did not start; see node-*/stderr.log')
nodes = []
for i, pid in enumerate(pids):
    directory = f'{root}/node-{i + 1}'
    nodes.append({'name': f'node-{i + 1}', 'pid': int(pid), 'rpc_port': base + 10 * i,
                  'p2p_port': base + 10 * i + 1, 'stratum_port': base + 10 * i + 2,
                  'public_key': open(f'{directory}/public_key').read().strip(),
                  'key_file': f'{directory}/miner.key', 'data_file': f'{directory}/chain.sqlite',
                  'directory': directory, 'executable': binary,
                  'stdout_file': f'{directory}/stdout.log', 'stderr_file': f'{directory}/stderr.log'})
manifest = {'schema_version': 1, 'directory': root, 'config': f'{root}/network.json',
            'executable': binary, 'base_port': base,
            'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'chain_id': chain, 'nodes': nodes, 'seed_wallets': True, 'test_work': True,
            'mining': {'bind_ip': '127.0.0.1', 'share_difficulty': 65536.0, 'advertise': '',
                       'password_file': ''}}
json.dump(manifest, open(f'{root}/manifest.json', 'w'), indent=2)
print(f'network {chain} at {root}')
EOF

failed=0
for suite in "${suites[@]}"; do
  started=$SECONDS
  status=0
  timeout 3600 python3 -B "$repository/scripts/$suite.py" "$root/manifest.json" \
    --report "$root/$suite-report.json" > "$root/$suite.log" 2>&1 || status=$?
  echo "== $suite: exit $status after $((SECONDS - started)) s"
  grep -vE '^\s*$' "$root/$suite.log" | tail -n 8 || true
  [ "$status" -eq 0 ] || failed=1
done
exit "$failed"
