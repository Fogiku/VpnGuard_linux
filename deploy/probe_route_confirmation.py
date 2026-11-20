#!/usr/bin/env python3
"""Exercise confirmation and timeout using profile names; packet routing stays unchanged."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.request

DATA = Path('/var/lib/vpnguard')


def api(path, body=None):
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    request = urllib.request.Request('http://127.0.0.1:8765/api/' + path, data=data,
                                     headers={'Content-Type': 'application/json', 'X-VG': '1', 'X-VG-Route-Confirm': '1'})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.load(response)
    if result.get('error'):
        raise RuntimeError(result['error'])
    return result['result']


def pids():
    return {name: subprocess.check_output(['systemctl', 'show', name, '-p', 'MainPID', '--value'], text=True).strip()
            for name in ['meduzavpnd', 'vpnguard-nfqws2']}


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def write_original(raw):
    temporary = DATA / 'routes.probe.tmp'
    with temporary.open('wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, DATA / 'routes.json')


def change_name(record, label):
    routes = json.loads(base64.b64decode(record['original']))
    routes['profiles'][0]['name'] += label
    api('routes', {'routes': routes})
    change = json.loads((DATA / 'routes-pending.json').read_text())
    if change['status'] != 'awaiting_confirmation' or change['kernelChanged']:
        raise RuntimeError('probe did not remain a metadata-only confirmation operation')
    return change


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['begin-ack', 'finish-ack', 'finish-direct', 'begin-timeout', 'check-timeout'])
    parser.add_argument('record')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root required')
    os.umask(0o077)
    path = Path(args.record)
    if args.action == 'begin-ack':
        for _ in range(30):
            state = api('state')
            if state['routingReady'] and state['routes']['applyInfo'] and not state['routes']['pending']:
                break
            time.sleep(.2)
        else:
            raise RuntimeError('initial routing is not ready')
        raw = (DATA / 'routes.json').read_bytes()
        record = {'original': base64.b64encode(raw).decode(), 'originalSha256': hashlib.sha256(raw).hexdigest(), 'pids': pids()}
        write_json(path, record)
        change = change_name(record, ' [confirmation probe]')
        record['ackId'] = change['id']
        write_json(path, record)
        print(json.dumps({'id': change['id'], 'status': change['status'], 'kernelChanged': False}))
        return
    record = json.loads(path.read_text())
    original = base64.b64decode(record['original'])
    if args.action in {'finish-ack', 'finish-direct'}:
        if args.action == 'finish-direct':
            pending = api('state')['routes']['pending']
            if not pending or pending['id'] != record['ackId']:
                raise RuntimeError('direct confirmation checkpoint missing')
            api('routeconfirm', {'id': pending['id']})
        state = api('state')
        if state['routes']['pending'] or not any(e['id'] == record['ackId'] and e['status'] == 'committed' for e in state['routes']['events']):
            raise RuntimeError('operation was not confirmed')
        api('routes', {'routes': json.loads(original)})
        pending = api('state')['routes']['pending']
        api('routeconfirm', {'id': pending['id']})
        if json.loads((DATA / 'routes.json').read_bytes()) != json.loads(original):
            raise RuntimeError('route model changed during probe; refusing to overwrite it')
        write_original(original)
        field = 'browserAckVerified' if args.action == 'finish-ack' else 'directAckVerified'
        record[field] = True
        write_json(path, record)
        print(json.dumps({field: True, 'originalModelRestored': True}))
    elif args.action == 'begin-timeout':
        if not record.get('browserAckVerified') or (DATA / 'routes.json').read_bytes() != original:
            raise RuntimeError('positive proof or original model missing')
        change = change_name(record, ' [timeout probe]')
        record['timeoutId'], record['deadline'] = change['id'], change['deadline']
        write_json(path, record)
        print(json.dumps({'id': change['id'], 'deadline': change['deadline'], 'kernelChanged': False}))
    else:
        state = api('state')
        if state['routes']['pending'] or not state['routingReady']:
            print(json.dumps({'status': 'waiting', 'secondsToDeadline': max(0, record['deadline'] - int(time.time()))}))
            return
        if (DATA / 'routes.json').read_bytes() != original:
            raise RuntimeError('timeout did not restore original routes byte for byte')
        if not any(e['id'] == record['timeoutId'] and e['status'] == 'recovered' for e in state['routes']['events']):
            raise RuntimeError('recovery event missing')
        if pids() != record['pids']:
            raise RuntimeError('VPN processes restarted')
        record['timeoutVerified'] = True
        write_json(path, record)
        print(json.dumps({'timeoutVerified': True, 'vpnProcessesPreserved': True, 'originalModelRestored': True}))


if __name__ == '__main__':
    main()
