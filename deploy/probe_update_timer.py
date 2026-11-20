#!/usr/bin/env python3
"""Exercise the real systemd timer against sandbox files; never call real network/service operations."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def child(directory):
    spec = importlib.util.spec_from_file_location('guard', directory / 'guarded_update.py')
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    guard.DATA = directory / 'data'
    guard.BINARY = directory / 'current'
    calls = []
    guard.run = lambda *args, **kwargs: calls.append(args) or ''
    guard.restore_network = lambda state: None
    job = json.loads((directory / 'job.json').read_text())
    guard.rollback(directory, job)
    (directory / 'calls.json').write_text(json.dumps(calls))


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('root required')
    if len(sys.argv) == 3 and sys.argv[1] == 'child':
        child(Path(sys.argv[2]))
    else:
        os.umask(0o077)
        directory = Path(tempfile.mkdtemp(prefix='vpnguard-timer-probe-', dir='/var/tmp'))
        (directory / 'data').mkdir()
        for name in ['config.json', 'routes.json']:
            (directory / name).write_text('{}')
            (directory / 'data' / name).write_text('changed')
        (directory / 'previous-binary').write_text('previous')
        (directory / 'current').write_text('candidate')
        (directory / 'job.json').write_text(json.dumps({'status': 'installed', 'version': 'probe', 'network': {}}))
        for name in ['guarded_update.py', 'probe_update_timer.py']:
            shutil.copyfile(Path(__file__).with_name(name), directory / name)
        unit = 'vpnguard-timer-probe-' + directory.name.rsplit('-', 1)[1]
        subprocess.run(['systemd-run', '--unit=' + unit, '--on-active=2s', '--timer-property=AccuracySec=1s',
                        '/usr/bin/python3', str(directory / 'probe_update_timer.py'), 'child', str(directory)], check=True)
        print(json.dumps({'directory': str(directory), 'timer': unit}))
