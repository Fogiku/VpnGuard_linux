#!/usr/bin/env python3
"""Recover a durable route transaction without loading or running agent modules."""
import base64
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def run(*args, input=None):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=40)
    if p.returncode:
        raise RuntimeError(f'{args[0]} {args[1:]}: {p.stderr.strip()}')
    return p.stdout


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_file(path, contents):
    temporary = path.with_suffix('.recovery.tmp')
    with temporary.open('wb') as stream:
        stream.write(contents)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    sync_directory(path.parent)


def atomic_json(path, value):
    atomic_file(path, json.dumps(value, ensure_ascii=False, indent=2).encode())


def legacy_resources():
    return [dict(owner=owner, mark=mark, mask=mask, table=table, priority=priority) for owner, mark, mask, table, priority in [
        ('meduza', 0x11, 0xffffffff, '101', 1101), ('awg', 0x12, 0xffffffff, '102', 1102),
        ('zapret', 0x13, 0xffffffff, 'main', 1200), ('direct', 0x14, 0xffffffff, 'main', 1200),
        ('block', 0x1f, 0xffffffff, '', 0), ('zapret.raw', 0x40000000, 0x40000000, 'main', 1201),
    ]]


def validate_resources(resources):
    legacy = legacy_resources()
    if not isinstance(resources, list) or not 6 <= len(resources) <= 103 or resources[:6] != legacy:
        raise RuntimeError('invalid route resource registry')
    owners, marks, tables = set(), set(), set()
    for i, r in enumerate(resources):
        if not isinstance(r, dict) or set(r) != set(legacy[0]):
            raise RuntimeError('invalid route resource entry')
        if not isinstance(r['owner'], str) or not r['owner'] or r['owner'] in owners or r['mark'] in marks:
            raise RuntimeError('duplicate route resource')
        if i >= 6:
            table = r['table']
            if (not isinstance(table, str) or not re.fullmatch(r'1[0-9]{2}', table) or not 103 <= int(table) <= 199
                    or type(r['mark']) is not int or not 0x20 <= r['mark'] <= 0xfe
                    or r['mask'] != 0xffffffff or r['priority'] != 1000 + int(table)):
                raise RuntimeError('invalid extra VPN resource')
        owners.add(r['owner'])
        marks.add(r['mark'])
        if r['table'] not in {'', 'main'}:
            if r['table'] in tables:
                raise RuntimeError('duplicate route table')
            tables.add(r['table'])
    return resources


def resource_tables(resources):
    return [r['table'] for r in resources if r['table'] not in {'', 'main'}]


def owned_rule(line, resources=None):
    fields = line.split()
    if len(fields) != 7 or fields[1:4] != ['from', 'all', 'fwmark'] or fields[5] != 'lookup':
        return None
    priority = fields[0].rstrip(':')
    parts = fields[4].split('/')
    try:
        mark = int(parts[0], 16 if parts[0].startswith('0x') else 10)
        mask = int(parts[1], 16 if parts[1].startswith('0x') else 10) if len(parts) == 2 else 0xffffffff
    except ValueError:
        return None
    if len(parts) > 2 or not any(r['priority'] and (str(r['priority']), r['mark'], r['mask'], r['table']) ==
                                (priority, mark, mask, fields[6]) for r in (resources if resources is not None else legacy_resources())):
        return None
    return ['priority', priority, *fields[1:]]


def defaults(resources=None):
    result = {t: [] for t in resource_tables(resources if resources is not None else legacy_resources())}
    for line in run('ip', '-4', '-o', 'route', 'show', 'table', 'all').splitlines():
        fields = line.split()
        if fields and fields[0] == 'default' and 'table' in fields:
            table = fields[fields.index('table') + 1]
            if table in result:
                result[table].append(' '.join(f for f in fields if f != 'linkdown'))
    return result


def restore_network(before):
    resources = validate_resources(before.get('resources', legacy_resources()))
    current = defaults(resources)
    saved = before.get('defaults') or {}
    for table in resource_tables(resources):
        routes = saved.get(table) or []
        if current[table] != routes:
            if current[table]:
                run('ip', '-4', 'route', 'flush', 'table', table, 'default')
            for line in routes:
                run('ip', '-4', 'route', 'add', *line.split())
    for line in run('ip', '-4', '-o', 'rule', 'show').splitlines():
        rule = owned_rule(line, resources)
        if rule:
            run('ip', '-4', 'rule', 'del', *rule)
    for rule in before.get('rules') or []:
        run('ip', '-4', 'rule', 'add', *rule)
    run('nft', '-f', '-', input='table inet vpnguard\ndelete table inet vpnguard\n' + before['nft'])


def restore_files(directory, change):
    path = directory / 'routes.json'
    if change['routesExisted']:
        atomic_file(path, base64.b64decode(change['routesFile'] or ''))
    else:
        path.unlink(missing_ok=True)
        sync_directory(directory)
    config_file = directory / 'config.json'
    config = json.loads(config_file.read_text()) if config_file.exists() else {}
    for key, value in change['network'].items():
        if key not in {'net.pinFlows', 'net.localNetworks'}:
            raise RuntimeError('unknown network setting in journal')
        if value is None:
            config.pop(key, None)
        else:
            config[key] = value
    atomic_json(config_file, config)


def event(directory, change, status):
    path = directory / 'route-events.json'
    events = json.loads(path.read_text()) if path.exists() else []
    if events and events[-1]['id'] == change['id'] and events[-1]['status'] == status:
        return
    events.append({'at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
                   'id': change['id'], 'reason': change['reason'], 'status': status})
    atomic_json(path, events[-50:])


def recover(mode, directory, identifier):
    pending = directory / 'routes-pending.json'
    stopped = False
    change = None
    def read():
        if not pending.exists():
            return None
        change = json.loads(pending.read_text())
        return change if change['id'] == identifier else None
    with (directory / 'routes.lock').open('a') as lease:
        try:
            try:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                change = read()
                if not change or change['status'] in {'committed', 'aborted'}:
                    return
                if mode == 'recover':
                    stopped = True
                    run('systemctl', 'stop', 'vpnguard')
                fcntl.flock(lease, fcntl.LOCK_EX)
            change = read()
            if not change:
                return
            if change['status'] not in {'committed', 'aborted'}:
                if mode == 'recover' and not stopped:
                    stopped = True
                    run('systemctl', 'stop', 'vpnguard')
                if change['kernelChanged']:
                    restore_network(change['before'])
                restore_files(directory, change)
                event(directory, change, 'recovered')
            elif change['status'] == 'committed':
                if change['keepLast']:
                    atomic_json(directory / 'routes-last.json', change)
                else:
                    (directory / 'routes-last.json').unlink(missing_ok=True)
                event(directory, change, 'committed')
            pending.unlink(missing_ok=True)
            sync_directory(directory)
            print(json.dumps({'id': identifier, 'result': 'recovered_or_finalized'}))
        except Exception:
            if change:
                try:
                    event(directory, change, 'recovery_failed')
                except Exception:
                    pass
            raise
        finally:
            if stopped:
                run('systemctl', 'start', 'vpnguard')


if __name__ == '__main__':
    mode, directory, identifier = sys.argv[1:]
    if mode not in {'recover', 'startup', 'isolated'} or not re.fullmatch(r'[0-9]+', identifier):
        raise SystemExit('invalid recovery request')
    if mode == 'isolated' and os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise SystemExit('isolated mode requires a separate network namespace')
    os.umask(0o077)
    recover(mode, Path(directory).resolve(), identifier)
