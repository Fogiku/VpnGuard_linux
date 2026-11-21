"""Sample IPv4 TCP/UDP on one WG interface. PCAP and nDPI CSV are anonymous RAM files."""
import csv
import ctypes
import io
import json
import os
import re
import resource
import shutil
import socket
import struct
import subprocess
import sys
import time


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError('cannot restrict classifier')
    if os.getuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)


def capture(iface, stream):
    # SOCK_DGRAM removes the link header, including on L3 WireGuard interfaces.
    stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 1024, 101))
    count = 0
    buf = bytearray(1024)
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, 0) as sock:
        sock.bind((iface, 0x0800))
        start = time.time_ns() // 1000000
        deadline = time.monotonic() + 2
        while count < 128:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                size, _ = sock.recvfrom_into(buf, len(buf), socket.MSG_TRUNC)
            except socket.timeout:
                break
            if size < 20 or buf[0] >> 4 != 4 or buf[9] not in (6, 17):
                continue
            stamp = time.time_ns() // 1000
            used = min(size, len(buf))
            stream.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000, used, size))
            stream.write(buf[:used])
            count += 1
        end = time.time_ns() // 1000000
        # PACKET_STATISTICS contains packet and kernel-drop counts.
        _, drops = struct.unpack('=II', sock.getsockopt(263, 6, 8))
    stream.flush()
    return start, end, count, drops


def sample(iface):
    reader = shutil.which('ndpiReader')
    if not reader:
        return {'error': 'missing'}
    revision = subprocess.run([reader, '--extcap-version'], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, preexec_fn=limits, timeout=3)
    if b'extcap {version=4.2.0}' not in revision.stdout.splitlines():
        return {'error': 'version'}
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', iface):
        return {'error': 'interface'}
    interfaces = subprocess.run(['wg', 'show', 'interfaces'], capture_output=True, timeout=2, check=True)
    if iface.encode() not in interfaces.stdout.split():
        return {'error': 'interface'}
    with os.fdopen(os.memfd_create('vg-sample'), 'w+b') as pcap, os.fdopen(os.memfd_create('vg-labels'), 'w+b') as output:
        start, end, count, drops = capture(iface, pcap)
        result = dict(start=start, end=end, packets=count, csv='')
        if drops:
            return {'error': 'drops'}
        if not count:
            return result
        fds = (pcap.fileno(), output.fileno())
        for fd in fds:
            os.fchmod(fd, 0o600)
            if os.getuid() == 0:
                os.fchown(fd, 65534, 65534)
        subprocess.run([reader, '-i', '/proc/self/fd/%d' % fds[0], '-d', '-v', '2',
                        '-C', '/proc/self/fd/%d' % fds[1]], pass_fds=fds, timeout=4,
                       check=True, cwd='/', preexec_fn=limits, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output.seek(0)
        # Project the export before it crosses the worker boundary (no SNI, URLs or payload).
        cols = '#flow_id protocol first_seen last_seen src_ip src_port dst_ip dst_port ndpi_proto_num ndpi_proto'.split()
        rows = csv.DictReader(io.StringIO(output.read().decode('utf-8', errors='replace')))
        if not rows.fieldnames or not set(cols).issubset(rows.fieldnames):
            return {'error': 'format'}
        safe = io.StringIO()
        writer = csv.writer(safe)
        writer.writerow(cols)
        for i, row in enumerate(rows):
            if i >= count:
                return {'error': 'format'}
            writer.writerow([row[k] for k in cols])
        result['csv'] = safe.getvalue()
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(sample(sys.argv[1])))
    except PermissionError:
        print('{"error":"permission"}')
    except OSError:
        print('{"error":"interface"}')
    except (ValueError, subprocess.SubprocessError, csv.Error):
        print('{"error":"reader"}')
