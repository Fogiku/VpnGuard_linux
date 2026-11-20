#!/usr/bin/env python3
"""Generate synthetic traffic locally and run nDPI on a PCAP, never an interface."""
import argparse
import csv
import json
from pathlib import Path
import socket
import struct
import subprocess
import re


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(proto, sport, dport, payload):
    src, dst = socket.inet_aton('192.0.2.10'), socket.inet_aton('198.51.100.20')
    if proto == 17:
        segment = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    else:
        segment = struct.pack('!HHIIBBHHH', sport, dport, 1, 1, 80, 24, 65535, 0, 0) + payload
        pseudo = src + dst + struct.pack('!BBH', 0, proto, len(segment))
        segment = segment[:16] + struct.pack('!H', checksum(pseudo + segment)) + segment[18:]
    header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(segment), 1, 0, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    return bytes.fromhex('0200000000020200000000010800') + header + segment


def fixture(path):
    dns = struct.pack('!HHHHHH', 123, 256, 1, 0, 0, 0) + b'\x07example\x04test\0' + struct.pack('!HH', 1, 1)
    packets = [packet(6, 41001, 80, b'GET / HTTP/1.1\r\nHost: example.test\r\nUser-Agent: OfflineFixture\r\n\r\n'),
               packet(17, 41002, 53, dns),
               packet(17, 41003, 443, b'opaque-test-payload-which-is-not-quic')]
    with path.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, data in enumerate(packets):
            stream.write(struct.pack('<IIII', 1700000000 + i, 0, len(data), len(data)))
            stream.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('reader', type=Path)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    args.directory.mkdir(parents=True, exist_ok=True)
    pcap = args.directory / 'synthetic.pcap'
    output = args.directory / 'flows.csv'
    fixture(pcap)
    result = subprocess.run([str(args.reader.resolve()), '-i', str(pcap.resolve()), '-d', '-v', '2', '-C', str(output.resolve())],
                            text=True, capture_output=True, timeout=10, check=True)
    rows = list(csv.DictReader(output.read_text().splitlines()))
    by_port = {int(row['src_port']): row['ndpi_proto'] for row in rows}
    if by_port.get(41001) != 'HTTP' or by_port.get(41002) != 'DNS':
        raise RuntimeError('synthetic HTTP/DNS classification failed')
    if 41003 in by_port and by_port[41003] != 'Unknown':
        raise RuntimeError('opaque UDP/443 incorrectly classified')
    unknown = re.search(r'UDP 192\.0\.2\.10:41003 -> 198\.51\.100\.20:443 .*?\[proto: 0/Unknown\].*?\[Confidence: Unknown\]', result.stdout)
    if not unknown:
        raise RuntimeError('opaque flow missing from Unknown report')
    if len(rows) not in (2, 3) or 'Using nDPI (4.2.0)' not in result.stdout:
        raise RuntimeError('unexpected reader version or export schema')
    report = {'readerVersion': '4.2.0', 'packageVersion': '4.2-2.1build1',
              'guessDisabled': True, 'input': 'synthetic PCAP only',
              'checks': {'http': True, 'dns': True, 'opaqueUdp443Unknown': True},
              'csvRows': len(rows), 'unknownExportedToCsv': 41003 in by_port,
              'productionCapture': False}
    (args.directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
