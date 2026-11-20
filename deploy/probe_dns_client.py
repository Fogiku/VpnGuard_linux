#!/usr/bin/env python3
"""Explicit DNS queries to one server; never changes OS DNS configuration."""
import argparse
import json
import os
import socket
import struct


def query(server, port, kind, tcp):
    identifier = struct.unpack('!H', os.urandom(2))[0]
    name = b'\x07example\x03com\x00'
    packet = struct.pack('!HHHHHH', identifier, 0x100, 1, 0, 0, 0) + name + struct.pack('!HH', kind, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as client:
        client.settimeout(4)
        if tcp:
            client.connect((server, port))
            client.sendall(struct.pack('!H', len(packet)) + packet)
            def exact(size):
                result = b''
                while len(result) < size:
                    chunk = client.recv(size - len(result))
                    if not chunk:
                        raise RuntimeError('DNS TCP closed early')
                    result += chunk
                return result
            reply = exact(struct.unpack('!H', exact(2))[0])
        else:
            client.connect((server, port))
            client.send(packet)
            reply = client.recv(65535)
    response_id, flags, _, answers, _, _ = struct.unpack('!HHHHHH', reply[:12])
    if response_id != identifier or not flags & 0x8000 or flags & 15 != (5 if kind == 28 else 0):
        raise RuntimeError('unexpected DNS response')
    if kind == 1 and (not answers or flags & 0x200):
        raise RuntimeError('A response empty or truncated')
    if kind == 28 and answers:
        raise RuntimeError('AAAA was not refused')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('server')
    parser.add_argument('--port', type=int, default=53)
    args = parser.parse_args()
    for kind, tcp in [(1, False), (1, True), (28, False), (28, True)]:
        query(args.server, args.port, kind, tcp)
    print(json.dumps({'udpA': True, 'tcpA': True, 'udpAAAARefused': True, 'tcpAAAARefused': True}))


if __name__ == '__main__':
    main()
