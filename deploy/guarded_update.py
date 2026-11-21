#!/usr/bin/env python3
"""Update only the agent. A separate systemd timer restores the prior release."""
import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE = Path('/var/backups/vpnguard/updates')
DATA = Path('/var/lib/vpnguard')
BINARY = Path('/usr/local/bin/vpnguard')

_spec = importlib.util.spec_from_file_location('vpnguard_route_registry', Path(__file__).with_name('route_guard.py'))
route_registry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(route_registry)


def run(*args, input=None, check=True):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=40)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {p.stderr.strip()}')
    return p.stdout


def atomic_json(path, value):
    temp = path.with_suffix('.tmp')
    with temp.open('w') as f:
        json.dump(value, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def event(job, status, description):
    path = DATA / 'updates.json'
    events = json.loads(path.read_text()) if path.exists() else []
    events.append({'at': datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
                   'version': job['version'], 'status': status, 'description': description})
    atomic_json(path, events[-200:])


def owned_rule(line, resources=None):
    return route_registry.owned_rule(line, resources)


def defaults(resources=None):
    result = {t: [] for t in route_registry.resource_tables(resources if resources is not None else route_registry.legacy_resources())}
    for line in run('ip', '-4', '-N', '-o', 'route', 'show', 'table', 'all').splitlines():
        f = line.split()
        if not f or f[0] != 'default' or 'table' not in f:
            continue
        table = f[f.index('table') + 1]
        if table in result:
            result[table].append([x for x in f if x != 'linkdown'])
    return result


def snapshot():
    with urllib.request.urlopen('http://127.0.0.1:8765/api/state', timeout=10) as response:
        state = json.load(response)['result']
    resources = route_registry.validate_resources(state.get('routeResources', route_registry.legacy_resources()))
    tables = run('nft', 'list', 'tables').splitlines()
    return {
        'nft': run('nft', 'list', 'table', 'inet', 'vpnguard') if 'table inet vpnguard' in tables else '',
        'resources': resources,
        'rules': [rule for line in run('ip', '-4', '-N', '-o', 'rule', 'show').splitlines() if (rule := owned_rule(line, resources))],
        'defaults': defaults(resources),
    }


def restore_network(state):
    resources = route_registry.validate_resources(state.get('resources', route_registry.legacy_resources()))
    current = defaults(resources)
    for table, routes in state['defaults'].items():
        if current[table] == routes:
            continue
        if current[table]:
            run('ip', '-4', 'route', 'flush', 'table', table, 'default')
        for route in routes:
            run('ip', '-4', 'route', 'add', *route)
    for line in run('ip', '-4', '-N', '-o', 'rule', 'show').splitlines():
        rule = owned_rule(line, resources)
        if rule:
            run('ip', '-4', 'rule', 'del', *rule)
    for rule in state['rules']:
        run('ip', '-4', 'rule', 'add', *rule)
    run('nft', '-f', '-', input='table inet vpnguard\ndelete table inet vpnguard\n' + state['nft'])


def identity():
    status = json.loads(run('meduzavpn', 'status', '--json'))
    return {
        'meduzaPid': run('systemctl', 'show', 'meduzavpnd', '-p', 'MainPID', '--value').strip(),
        'nfqwsPid': run('systemctl', 'show', 'vpnguard-nfqws2', '-p', 'MainPID', '--value').strip(),
        'wgIdentity': hashlib.sha256(run('wg', 'show', 'wg_server', 'peers').encode()).hexdigest(),
        'wgConfig': hashlib.sha256(Path('/etc/wireguard/wg_server.conf').read_bytes()).hexdigest(),
        'tunnel': {k: status.get(k) for k in ['state', 'protocol', 'interface', 'endpoint', 'since_unix']},
        'routeModel': hashlib.sha256((DATA / 'routes.json').read_bytes()).hexdigest(),
    }


def health(job):
    if hashlib.sha256(BINARY.read_bytes()).hexdigest() != job['sha256']:
        raise RuntimeError('installed binary SHA256 mismatch')
    with urllib.request.urlopen('http://127.0.0.1:8765/api/state', timeout=10) as response:
        state = json.load(response)['result']
    if state['version'] != job['version'] or not state.get('routingReady'):
        raise RuntimeError('agent version/startup is not ready')
    if identity() != job['identity']:
        raise RuntimeError('tunnel process, WG identity or route configuration changed')
    settings = json.loads((DATA / 'config.json').read_text())
    if any(settings.get(key) != value for key, value in job.get('settings', {}).items()):
        raise RuntimeError('network settings do not match the release')
    if settings.get('dns.enabled', 'true') == 'true' and (settings.get('dns.serveWG') == 'true' or settings.get('dns.lanAddress')):
        service = state.get('dnsService') or {}
        if not service.get('ready') or not service.get('enabled') or service.get('simulated'):
            raise RuntimeError('client DNS listeners are not ready')
        listeners = service.get('listeners') or []
        required = []
        if settings.get('dns.serveWG') == 'true':
            required.append(('WG', settings.get('wg.subnet', '10.253.0') + '.1:53', settings.get('wg.iface', 'wg_server')))
        if settings.get('dns.lanAddress'):
            required.append(('LAN', settings['dns.lanAddress'] + ':53', None))
        for kind, address, interface in required:
            if not any(item.get('kind') == kind and item.get('address') == address and item.get('interface')
                       and (interface is None or item['interface'] == interface) for item in listeners):
                raise RuntimeError('client DNS binding missing: ' + address)
    iface = job['identity']['tunnel']['interface']
    code = run('curl', '-q', '--interface', iface, '-sS', '--connect-timeout', '5', '--max-time', '10',
               '-o', '/dev/null', '-w', '%{http_code}', 'https://example.com').strip()
    if code != '200':
        raise RuntimeError('HTTPS through the tunnel did not return 200')
    for unit in ['ssh', 'vpnguard', 'meduzavpnd', 'wg-quick@wg_server']:
        if run('systemctl', 'is-active', unit).strip() != 'active':
            raise RuntimeError('inactive service: ' + unit)


def install_binary(source):
    temp = BINARY.with_name('vpnguard.new')
    shutil.copyfile(source, temp)
    os.chmod(temp, 0o755)
    with temp.open('rb') as f:
        os.fsync(f.fileno())
    os.replace(temp, BINARY)


def rollback(directory, job):
    if job['status'] in ['confirmed', 'rolled_back']:
        return
    failures = []
    try:
        run('systemctl', 'stop', 'vpnguard')
        # Serialize release rollback with a route recovery worker from the candidate.
        with (DATA / 'routes.lock').open('a') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX)
            run('systemctl', 'stop', 'vpnguard')
            pending = DATA / 'routes-pending.json'
            if pending.exists():
                raw = pending.read_bytes()
                atomic = directory / 'route-pending-before-version-rollback.json'
                atomic.write_bytes(raw)
                os.chmod(atomic, 0o600)
                try:
                    timer = json.loads(raw).get('timer', '')
                except (ValueError, AttributeError):
                    timer = ''
                pending.unlink()
                if re.fullmatch(r'vpnguard-routes-[0-9]+', timer):
                    run('systemctl', 'stop', timer + '.timer', check=False)
            install_binary(directory / 'previous-binary')
            for name in ['config.json', 'routes.json']:
                shutil.copyfile(directory / name, DATA / name)
                os.chmod(DATA / name, 0o600)
            restore_network(job['network'])
    except Exception as exc:
        failures.append(str(exc))
    finally:
        try:
            run('systemctl', 'start', 'vpnguard')
        except Exception as exc:
            failures.append(str(exc))
    job['status'] = 'rollback_failed' if failures else 'rolled_back'
    job['errors'] = failures
    atomic_json(directory / 'job.json', job)
    event(job, job['status'], 'Возврат предыдущей версии.' + (' Ошибки: ' + '; '.join(failures) if failures else ''))
    if failures:
        raise RuntimeError('; '.join(failures))


def prepare(candidate, version, sha, settings=None):
    if (DATA / "routes-pending.json").exists():
        raise RuntimeError("route change awaiting confirmation or rollback")
    settings = settings or {}
    if set(settings) - {'net.pinFlows', 'net.localNetworks', 'dns.serveWG', 'dns.lanAddress', 'dns.allowLAN', 'wg.dns'} or any(not isinstance(v, str) for v in settings.values()):
        raise RuntimeError('only declared network settings may be changed by this updater')
    candidate = Path(candidate).resolve()
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != sha:
        raise RuntimeError('candidate SHA256 mismatch')
    directory = BASE / datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    directory.mkdir(mode=0o700, parents=True)
    shutil.copyfile(BINARY, directory / 'previous-binary')
    shutil.copyfile(candidate, directory / 'candidate')
    os.chmod(directory / 'candidate', 0o755)
    if hashlib.sha256((directory / 'candidate').read_bytes()).hexdigest() != sha:
        raise RuntimeError('copied candidate SHA256 mismatch')
    for name in ['config.json', 'routes.json']:
        shutil.copyfile(DATA / name, directory / name)
    config = json.loads((DATA / 'config.json').read_text())
    # /run and the backup volume may both be mounted noexec.
    with tempfile.TemporaryDirectory(prefix='.vpnguard-check-', dir=BINARY.parent) as work:
        executable = Path(work) / 'vpnguard'
        shutil.copyfile(directory / 'candidate', executable)
        if hashlib.sha256(executable.read_bytes()).hexdigest() != sha:
            raise RuntimeError('validation copy SHA256 mismatch')
        executable.chmod(0o700)
        if run(str(executable), '--version').strip() != version:
            raise RuntimeError('candidate version mismatch')
        if settings:
            validation = directory / 'validation'
            validation.mkdir(mode=0o700)
            atomic_json(validation / 'config.json', {**config, **settings})
            run(str(executable), '--check-network-settings', '--data', str(validation))
    if settings:
        if settings.get('net.pinFlows') == 'true' and config.get('net.pinFlows', 'false') != 'true':
            audit = directory / 'audit_conntrack_marks.py'
            shutil.copyfile(Path(__file__).with_name('audit_conntrack_marks.py'), audit)
            run('/usr/bin/python3', str(audit), '--require-free')
    # The timer executes a root-owned copy, independent of the agent and staging folder.
    shutil.copyfile(Path(__file__), directory / 'guard.py')
    shutil.copyfile(Path(__file__).with_name('route_guard.py'), directory / 'route_guard.py')
    job = {'version': version, 'sha256': sha, 'status': 'prepared', 'settings': settings,
           'network': snapshot(), 'identity': identity(), 'timer': 'vpnguard-update-' + directory.name}
    if job['identity']['tunnel']['state'] != 'connected':
        raise RuntimeError('working tunnel is required before deployment')
    atomic_json(directory / 'job.json', job)
    event(job, 'prepared', 'Подготовлена резервная копия агента, настроек и сетевого состояния.')
    try:
        run('systemd-run', '--unit=' + job['timer'], '--on-active=240s', '--timer-property=AccuracySec=1s',
            '/usr/bin/python3', str(directory / 'guard.py'), 'rollback', str(directory))
    except Exception:
        # No installation mutation has occurred. A late timer also sees this terminal status.
        job['status'] = 'rolled_back'
        atomic_json(directory / 'job.json', job)
        event(job, job['status'], 'Не удалось запустить таймер защиты. Прежняя версия сохранена.')
        raise
    try:
        if settings:
            atomic_json(DATA / 'config.json', {**config, **settings})
        install_binary(directory / 'candidate')
        job['status'] = 'installed'
        atomic_json(directory / 'job.json', job)
        event(job, 'installed', 'Агент обновлён; ожидаются проверка канала и подтверждение по новому SSH-подключению.')
        run('systemctl', 'restart', 'vpnguard')
    except Exception:
        rollback(directory, job)
        raise
    print(json.dumps({'job': str(directory), 'version': version, 'status': job['status']}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'check', 'confirm', 'rollback'])
    parser.add_argument('path')
    parser.add_argument('--version')
    parser.add_argument('--sha256')
    parser.add_argument('--settings', help='JSON file with declared network settings')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root required')
    os.umask(0o077)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (BASE / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'prepare':
            # Do not overlap an unconfirmed release or rollback timer.
            for old in BASE.glob('*/job.json'):
                if json.loads(old.read_text())['status'] not in ['confirmed', 'rolled_back']:
                    raise RuntimeError('unfinished prior update: ' + str(old.parent))
            if not args.version or not args.sha256:
                parser.error('--version and --sha256 required')
            settings = json.loads(Path(args.settings).read_text()) if args.settings else None
            prepare(args.path, args.version, args.sha256, settings)
            return
        directory = Path(args.path).resolve()
        if directory.parent != BASE or not (directory / 'job.json').is_file():
            raise RuntimeError('invalid update job')
        job = json.loads((directory / 'job.json').read_text())
        if args.action == 'rollback':
            rollback(directory, job)
        else:
            if job['status'] != 'installed':
                raise RuntimeError('update is not awaiting confirmation')
            health(job)
            if args.action == 'confirm':
                job['status'] = 'confirmed'
                atomic_json(directory / 'job.json', job)
                event(job, 'confirmed', 'Проверены новая версия, SSH, HTTPS через VPN и сохранение процессов туннелей, WG-клиентов и правил.')
                run('systemctl', 'stop', job['timer'] + '.timer', check=False)
            print(json.dumps({'version': job['version'], 'status': job['status'], 'health': 'ok'}))


if __name__ == '__main__':
    main()
