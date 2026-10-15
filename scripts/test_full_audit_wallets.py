"""Run maintained wallet suites with explicitly isolated directories and ports.

Only the suites' fixture allocation and port-zero requests are redirected.
Assertions and application inputs remain unchanged. No live chain is accessed.
"""
import argparse
import importlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=REPO / 'work/wallet-audit')
    parser.add_argument('--base-port', type=int, default=28080)
    parser.add_argument('--node', type=Path, default=REPO / 'target/release/hashstash.exe')
    parser.add_argument('--cold', type=Path, default=REPO / 'target/release/hashstash-cold.exe')
    parser.add_argument('--report-prefix', default='full-audit-wallet')
    options = parser.parse_args()
    options.directory.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=options.directory)).resolve()
    if not 1024 <= options.base_port <= 64935:
        parser.error('--base-port must be from 1024 to 64935')
    node, cold = options.node.resolve(), options.cold.resolve()
    assert options.report_prefix and all(c.isalnum() or c in '-_' for c in options.report_prefix)
    original_popen, original_mkdtemp = subprocess.Popen, tempfile.mkdtemp
    next_port, started = options.base_port, time.monotonic()
    processes, results = [], []

    def port():
        nonlocal next_port
        while next_port < options.base_port + 600:
            candidate = next_port
            next_port += 1
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', candidate))
                except OSError:
                    continue
            return candidate
        raise RuntimeError('No audit fixture ports available')

    def popen(arguments, *args, **kwargs):
        if isinstance(arguments, (list, tuple)):
            arguments = list(arguments)
            for index, value in enumerate(arguments):
                if value == '127.0.0.1:0':
                    arguments[index] = '127.0.0.1:' + str(port())
                elif value == '0' and index and arguments[index - 1] == '--port':
                    arguments[index] = str(port())
        process = original_popen(arguments, *args, **kwargs)
        processes.append(process)
        return process

    def mkdtemp(*args, **kwargs):
        kwargs['dir'] = directory
        return original_mkdtemp(*args, **kwargs)

    try:
        for name in ('test_wallet_cli', 'test_wallet_manager', 'test_addresses'):
            report = directory / (options.report_prefix + '-' + name.removeprefix('test_') + '.json')
            with patch.object(sys, 'argv', [name, '--node', str(node), '--cold', str(cold), '--report', str(report)]), \
                    patch.object(tempfile, 'mkdtemp', mkdtemp), patch.object(subprocess, 'Popen', popen):
                importlib.import_module(name).main()
            results.append(json.loads(report.read_text(encoding='utf-8')))
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        result = {
            'passed': len(results) == 3 and all(item.get('passed') for item in results),
            'directory': str(directory), 'base_port': options.base_port, 'last_port': next_port - 1,
            'elapsed_seconds': round(time.monotonic() - started, 3), 'suites': results,
            'processes_stopped': all(process.poll() is not None for process in processes),
        }
        (directory / (options.report_prefix + '-maintained.json')).write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    assert result['passed'] and result['processes_stopped']


if __name__ == '__main__':
    main()
