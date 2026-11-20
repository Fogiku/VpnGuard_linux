#!/usr/bin/env python3
"""Read IPv4 conntrack marks via netlink. Do not print addresses or payloads."""
import argparse
import json
import socket
import struct


def audit(mask=0x00ff0000):
    # Constants from linux/netfilter/nfnetlink{,_conntrack}.h and linux/netlink.h.
    sequence = 1
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.settimeout(10)
        sock.bind((0, 0))
        request = struct.pack('=IHHII', 20, 0x101, 0x301, sequence, 0) + struct.pack('=BBH', socket.AF_INET, 0, 0)
        sock.sendto(request, (0, 0))
        total = marked = conflicts = 0
        while True:
            data = sock.recv(1024 * 1024)
            offset = 0
            while offset + 16 <= len(data):
                length, kind, flags, seq, pid = struct.unpack_from('=IHHII', data, offset)
                if length < 16 or offset + length > len(data):
                    raise RuntimeError('malformed netlink message')
                message = data[offset:offset + length]
                offset += (length + 3) & ~3
                if seq != sequence:
                    continue
                if flags & 0x10:
                    raise RuntimeError('conntrack dump interrupted; repeat the audit')
                if kind == 2:
                    error = struct.unpack_from('=i', message, 16)[0]
                    if error:
                        raise OSError(-error, 'conntrack netlink request failed')
                    continue
                if kind == 3:
                    return {'family': 'IPv4', 'entries': total, 'nonzeroMarks': marked,
                            'mask': hex(mask), 'entriesUsingReservedBits': conflicts}
                if kind != 0x100:
                    continue
                total += 1
                mark = 0
                pos = 20
                while pos + 4 <= len(message):
                    size, attribute = struct.unpack_from('=HH', message, pos)
                    if size < 4 or pos + size > len(message):
                        raise RuntimeError('malformed conntrack attribute')
                    if attribute & 0x3fff == 8 and size == 8:  # CTA_MARK, network byte order
                        mark = struct.unpack_from('!I', message, pos + 4)[0]
                    pos += (size + 3) & ~3
                marked += int(mark != 0)
                conflicts += int(bool(mark & mask))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--require-free', action='store_true')
    args = parser.parse_args()
    result = audit()
    print(json.dumps(result))
    if args.require_free and result['entriesUsingReservedBits']:
        raise SystemExit('reserved conntrack bits already in use')
