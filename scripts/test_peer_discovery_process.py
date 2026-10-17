"""Independent local-process joining, seed loss, and persisted-peer recovery.

Only disposable devnet databases and loopback listeners are used. The supplied
binary is never pointed at public nodes or existing runtime manifests.
"""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def rpc(port, method, params=None):
    request = urllib.request.Request(
        f'http://127.0.0.1:{port}/rpc',
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params or {}}).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=2) as response:
        value = json.load(response)
    if value.get('error'):
        raise RuntimeError(value['error'])
    return value['result']


def wait(predicate, label, seconds=40):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, RuntimeError) as error:
            last = str(error)
        time.sleep(.15)
    raise AssertionError(f'{label}: timed out; last error: {last}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    assert not args.output.exists(), 'Evidence must not be overwritten'
    report = {'scope': 'disposable loopback devnet only', 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'started_at_epoch': time.time(), 'checks': [], 'processes': [], 'passed': False}
    handles = []
    logs = []
    reservations = []
    with tempfile.TemporaryDirectory(prefix='hashstash-discovery-process-') as temporary:
        base = Path(temporary)
        config = base / 'network.json'
        subprocess.run([str(binary), 'init', '--config', str(config)], check=True, capture_output=True, text=True)
        network = json.loads(config.read_text())
        assert network['initial_bits'] == 0x207fffff
        network['network'] = 'isolated-peer-recovery-' + base.name
        config.write_text(json.dumps(network))
        ports = {}
        for name in ['a', 'b', 'c']:
            ports[name] = []
            for _ in range(2):
                reservation = socket.socket()
                reservation.bind(('127.0.0.1', 0))
                ports[name].append(reservation.getsockname()[1])
                reservations.append(reservation)
        # Only public bytes; no wallet or spending key is created by this test.
        miner = '13ccb9dcae7a2f81f9b95ba67f084c44542b26d937880023917265a43fca8f79'

        def start(name, seed=None):
            port, peerport = ports[name]
            command = [str(binary), 'run', '--config', str(config), '--data', str(base / (name + '.sqlite')),
                       '--miner', miner, '--rpc', f'127.0.0.1:{port}', '--p2p', f'127.0.0.1:{peerport}',
                       '--no-stratum', '--peer-discovery', '--allow-private-peers',
                       '--advertise-peer', f'127.0.0.1:{peerport}']
            if seed:
                command += ['--seed', f'localhost:{ports[seed][1]}']
            log = (base / (name + '-' + str(len(handles)) + '.log')).open('w+')
            logs.append(log)
            for reserved in reservations[:]:
                if reserved.getsockname()[1] in ports[name]:
                    reserved.close()
                    reservations.remove(reserved)
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            handles.append(process)
            report['processes'].append({'name': name, 'pid': process.pid, 'seed': seed, 'rpc_port': port, 'p2p_port': peerport})
            wait(lambda: process.poll() is None and rpc(port, 'peerstatus'), f'{name} start')
            return process

        def stop(process):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        def known(name, other):
            status = rpc(ports[name][0], 'peerstatus')
            assert status['transport'] == 'authenticated-discovery'
            assert status['discovery']['enabled']
            endpoint = f'127.0.0.1:{ports[other][1]}'
            return any(p['address'] == endpoint and p.get('last_success', 0) > 0
                       for p in status['discovery']['peers'])

        def height(name, value):
            return rpc(ports[name][0], 'status')['height'] == value

        try:
            a = start('a')
            b = start('b', 'a')
            wait(lambda: known('a', 'b') and known('b', 'a'), 'seed learns reachable advertised node')
            c = start('c', 'a')
            wait(lambda: known('c', 'b') and known('b', 'c'), 'joiner discovers third node through sole seed')
            report['checks'].append('Three independent processes join using DNS bootstrap, then authenticate learned peers')
            stop(a)
            rpc(ports['b'][0], 'mine', {'count': 2, 'attempts': 100000})
            wait(lambda: height('c', 2), 'blocks propagate after seed stops')
            assert rpc(ports['b'][0], 'status')['tip'] == rpc(ports['c'][0], 'status')['tip']
            report['checks'].append('New blocks propagate between discovered peers after the original seed exits')
            old_key = hashlib.sha256((base / 'c.peer-key.json').read_bytes()).hexdigest()
            stop(c)
            c = start('c')
            wait(lambda: known('c', 'b'), 'restart reconnects from persisted address book without seed')
            assert hashlib.sha256((base / 'c.peer-key.json').read_bytes()).hexdigest() == old_key
            rpc(ports['b'][0], 'mine', {'count': 1, 'attempts': 100000})
            wait(lambda: height('c', 3), 'restarted node catches up without seed')
            assert rpc(ports['b'][0], 'status')['tip'] == rpc(ports['c'][0], 'status')['tip']
            report['checks'].append('Restart without any seed reuses transport identity, recovers peers, and catches up')
            report['final_peers'] = {name: rpc(ports[name][0], 'peerstatus') for name in ['b', 'c']}
            report['final_status'] = {name: rpc(ports[name][0], 'status') for name in ['b', 'c']}
            report['passed'] = True
        except BaseException as error:
            report['error'] = repr(error)
            raise
        finally:
            for process in reversed(handles):
                stop(process)
            for reservation in reservations:
                reservation.close()
            report['owned_processes_exited'] = all(p.poll() is not None for p in handles)
            report['finished_at_epoch'] = time.time()
            report['logs'] = []
            for log in logs:
                log.flush()
                log.seek(0)
                report['logs'].append(log.read())
                log.close()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'checks': report['checks'], 'owned_processes_exited': report['owned_processes_exited']}))


if __name__ == '__main__':
    main()
