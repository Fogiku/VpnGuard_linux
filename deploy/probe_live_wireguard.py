#!/usr/bin/env python3
"""A temporary, nonpersistent WG peer tests the real gateway; existing peers are not edited."""
import ipaddress
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid


def run(*args, input=None, check=True):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=20)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} failed: {p.stderr.strip()}')
    return p.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dns', action='store_true', help='also query the WG gateway DNS from the temporary peer')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('root required')
    config = json.loads(Path('/var/lib/vpnguard/config.json').read_text())
    if config.get('net.pinFlows') != 'true':
        raise RuntimeError('flow pinning must be enabled for this probe')
    routes = json.loads(Path('/var/lib/vpnguard/routes.json').read_text())
    profile = routes['profiles'][0]
    if profile['rules'][-1]['exit'] != 'meduza':
        raise RuntimeError('probe expects the default profile to use MeduzaVPN')
    server = config.get('wg.iface', 'wg_server')
    ip = config.get('wg.subnet', '192.168.15') + '.250'
    for line in run('wg', 'show', server, 'allowed-ips').splitlines():
        for item in re.split(r'[\s,]+', line)[1:]:
            if item and item != '(none)' and ipaddress.ip_address(ip) in ipaddress.ip_network(item):
                raise RuntimeError('probe address overlaps an existing peer')
    set_name = 'c_' + re.sub(r'[^a-zA-Z0-9]', '_', profile['id'])
    current_set = run('nft', 'list', 'set', 'inet', 'vpnguard', set_name)
    if re.search(r'(?<![0-9.])' + re.escape(ip) + r'(?![0-9.])', current_set):
        raise RuntimeError('probe address is already present in the profile set')
    original_peers = run('wg', 'show', server, 'peers')
    original_config = Path('/etc/wireguard/' + server + '.conf').read_bytes()
    suffix = uuid.uuid4().hex[:8]
    iface, comment = 'vgp' + suffix, 'release_probe_' + suffix
    private = run('wg', 'genkey')
    public = run('wg', 'pubkey', input=private + '\n')
    server_public = run('wg', 'show', server, 'public-key')
    port = run('wg', 'show', server, 'listen-port')
    destination = socket.getaddrinfo('example.com', 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    namespace = subprocess.Popen(['unshare', '--net', 'sleep', '90'])
    peer_added = element_added = interface_created = False
    handle = None
    try:
        pid = str(namespace.pid)
        for _ in range(100):
            if os.readlink('/proc/self/ns/net') != os.readlink('/proc/' + pid + '/ns/net'):
                break
            time.sleep(.01)
        else:
            raise RuntimeError('namespace creation timeout')
        run('ip', 'link', 'add', iface, 'type', 'wireguard')
        interface_created = True
        run('ip', 'link', 'set', iface, 'netns', pid)
        run('wg', 'set', server, 'peer', public, 'allowed-ips', ip + '/32')
        peer_added = True
        run('nft', 'add', 'element', 'inet', 'vpnguard', set_name, '{', ip, '}')
        element_added = True
        script = f'insert rule inet vpnguard forward ip saddr {ip} ct mark & 0x00ff0000 == 0x00110000 counter comment "{comment}"\n'
        run('nft', '-f', '-', input=script)
        chain = json.loads(run('nft', '-j', '-a', 'list', 'chain', 'inet', 'vpnguard', 'forward'))
        handle = next(v['rule']['handle'] for v in chain['nftables'] if v.get('rule', {}).get('comment') == comment)
        client = f'[Interface]\nPrivateKey = {private}\n[Peer]\nPublicKey = {server_public}\nEndpoint = 127.0.0.1:{port}\nAllowedIPs = 0.0.0.0/0\n'
        run('nsenter', '-t', pid, '-n', 'wg', 'setconf', iface, '/dev/stdin', input=client)
        run('nsenter', '-t', pid, '-n', 'ip', 'addr', 'add', ip + '/32', 'dev', iface)
        run('nsenter', '-t', pid, '-n', 'ip', 'link', 'set', iface, 'mtu', '1280', 'up')
        run('nsenter', '-t', pid, '-n', 'ip', 'route', 'add', 'default', 'dev', iface)
        code = run('nsenter', '-t', pid, '-n', 'curl', '-q', '-sS', '--connect-timeout', '5', '--max-time', '12',
                   '--resolve', 'example.com:443:' + destination, '-o', '/dev/null', '-w', '%{http_code}', 'https://example.com')
        if code != '200':
            raise RuntimeError('WG client HTTPS did not return 200')
        chain = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'vpnguard', 'forward'))
        packets = sum(expr['counter']['packets'] for v in chain['nftables'] if v.get('rule', {}).get('comment') == comment
                      for expr in v['rule']['expr'] if 'counter' in expr)
        if packets < 1:
            raise RuntimeError('client packets did not carry the pinned VPN mark')
        result = {'https': code, 'pinnedClientPackets': packets, 'temporaryClient': True}
        if args.dns:
            probe = Path(__file__).with_name('probe_dns_client.py')
            gateway = config.get('wg.subnet', '192.168.15') + '.1'
            result['dns'] = json.loads(run('nsenter', '-t', pid, '-n', 'python3', str(probe), gateway))
    finally:
        if handle is not None:
            # A concurrent agent apply may have replaced the table; never use a stale handle.
            try:
                current = json.loads(run('nft', '-j', '-a', 'list', 'chain', 'inet', 'vpnguard', 'forward'))
                for entry in current['nftables']:
                    if entry.get('rule', {}).get('comment') == comment:
                        run('nft', 'delete', 'rule', 'inet', 'vpnguard', 'forward', 'handle', str(entry['rule']['handle']), check=False)
            except (RuntimeError, ValueError):
                pass
        if element_added:
            run('nft', 'delete', 'element', 'inet', 'vpnguard', set_name, '{', ip, '}', check=False)
        if peer_added:
            run('wg', 'set', server, 'peer', public, 'remove', check=False)
        if interface_created:
            run('nsenter', '-t', str(namespace.pid), '-n', 'ip', 'link', 'delete', iface, check=False)
            run('ip', 'link', 'delete', iface, check=False)
        namespace.terminate()
        namespace.wait(timeout=5)
    if run('wg', 'show', server, 'peers') != original_peers or Path('/etc/wireguard/' + server + '.conf').read_bytes() != original_config:
        raise RuntimeError('existing peer configuration changed')
    result['existingPeersAndFilePreserved'] = True
    print(json.dumps(result))


if __name__ == '__main__':
    main()
