#!/usr/bin/env python3
"""Bounded, read-only IPv4 conntrack snapshot. No payload or application inference."""
import json
import socket
import struct
import time


def attributes(data):
    result = {}
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise ValueError('truncated attribute')
        size, kind = struct.unpack_from('=HH', data, pos)
        if size < 4 or pos + size > len(data):
            raise ValueError('invalid attribute length')
        key = kind & 0x3fff
        if key in result:
            raise ValueError('duplicate attribute')
        result[key] = data[pos + 4:pos + size]
        pos += (size + 3) & ~3
    return result


def flow(data):
    if len(data) < 4 or data[0] != socket.AF_INET:
        return None
    attrs = attributes(data[4:])
    original = attributes(attrs.get(1, b''))
    ip = attributes(original.get(1, b''))
    proto = attributes(original.get(2, b''))
    number = proto.get(1, b'')
    if number not in (b'\x06', b'\x11'):
        return None
    if any(len(ip.get(k, b'')) != 4 for k in (1, 2)):
        raise ValueError('invalid IPv4 tuple')
    if any(len(proto.get(k, b'')) != 2 for k in (2, 3)):
        raise ValueError('invalid ports')
    mark = attrs.get(8, b'\0' * 4)
    if len(mark) != 4:
        raise ValueError('invalid mark')
    identity = attrs.get(12)
    zone = attrs.get(18, b'\0\0')
    if (identity is not None and len(identity) != 4) or len(zone) != 2:
        raise ValueError('invalid conntrack identity')
    return {'protocol': 'tcp' if number == b'\x06' else 'udp',
            'source': socket.inet_ntop(socket.AF_INET, ip[1]),
            'destination': socket.inet_ntop(socket.AF_INET, ip[2]),
            'sourcePort': struct.unpack('!H', proto[2])[0],
            'destinationPort': struct.unpack('!H', proto[3])[0],
            'mark': struct.unpack('!I', mark)[0],
            'conntrackId': struct.unpack('!I', identity)[0] if identity is not None else None,
            'zone': struct.unpack('!H', zone)[0],
            'application': 'Unknown', 'classificationSource': 'none'}


def snapshot(limit=512, seconds=2):
    if not 1 <= limit <= 4096 or not 0 < seconds <= 10:
        raise ValueError('invalid snapshot budget')
    rows = []
    seen = 0
    deadline = time.monotonic() + seconds
    sequence = 1
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.bind((0, 0))
        sock.sendto(struct.pack('=IHHII', 20, 0x101, 0x301, sequence, 0)
                    + struct.pack('=BBH', socket.AF_INET, 0, 0), (0, 0))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('conntrack snapshot deadline exceeded')
            sock.settimeout(remaining)
            data, ancillary, recv_flags, sender = sock.recvmsg(1024 * 1024)
            if recv_flags & socket.MSG_TRUNC or sender[0] != 0:
                raise ValueError('invalid netlink datagram')
            pos = 0
            while pos < len(data):
                if pos + 16 > len(data):
                    raise ValueError('truncated netlink header')
                size, kind, flags, seq, pid = struct.unpack_from('=IHHII', data, pos)
                if size < 16 or pos + size > len(data):
                    raise ValueError('invalid netlink length')
                body = data[pos + 16:pos + size]
                pos += (size + 3) & ~3
                if seq != sequence:
                    raise ValueError('unexpected netlink sequence')
                if flags & 0x10:
                    raise RuntimeError('interrupted conntrack dump')
                if kind in (2, 3):
                    if len(body) < 4:
                        raise ValueError('missing netlink status')
                    error = struct.unpack_from('=i', body)[0]
                    if error:
                        raise OSError(abs(error), 'conntrack dump failed')
                    if kind == 3:
                        return {'rows': rows, 'seen': seen, 'truncated': False}
                    continue
                if kind != 0x100:
                    raise ValueError('unexpected netlink message')
                seen += 1
                row = flow(body)
                if row is not None:
                    rows.append(row)
                if seen >= limit:
                    return {'rows': rows, 'seen': seen, 'truncated': True}


if __name__ == '__main__':
    print(json.dumps(snapshot()))
