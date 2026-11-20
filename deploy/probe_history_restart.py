#!/usr/bin/env python3
"""Check durable history using a separate simulated agent, never the host service."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request


def api(path):
    with urllib.request.urlopen('http://127.0.0.1:18767/api/' + path, timeout=3) as response:
        return json.load(response)['result']


def start(binary, directory):
    process = subprocess.Popen([binary, '--sim', '--listen', '127.0.0.1:18767', '--data', str(directory)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('test agent exited')
            try:
                api('state')
                return process
            except OSError:
                time.sleep(.1)
        raise RuntimeError('test agent not ready')
    except BaseException:
        process.terminate()
        process.wait(timeout=5)
        raise


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix='vpnguard-history-probe-') as temporary:
        directory = Path(temporary)
        process = start(binary, directory)
        try:
            time.sleep(11)
            before = api('history')
            if not before['t']:
                raise RuntimeError('no measurements collected')
        finally:
            process.terminate()
            process.wait(timeout=5)
        checkpoint = directory / 'telemetry.json'
        archive = json.loads(checkpoint.read_text())
        if not archive['samples'] or checkpoint.stat().st_size > 4 << 20 or checkpoint.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError('invalid shutdown checkpoint or permissions')
        time.sleep(7)
        process = start(binary, directory)
        try:
            restored = api('history')
            if not set(before['t']).intersection(restored['t']) or not restored['storage']['savedAt']:
                raise RuntimeError('history not restored')
            if not any(value is None for series in restored['series'].values() for value in series):
                raise RuntimeError('offline interval was not shown as missing')
            print(json.dumps({'restartPreservedHistory': True, 'shutdownCheckpoint': True,
                              'offlineGap': True, 'mode': '0600', 'productionServiceTouched': False}))
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
