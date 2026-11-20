#!/usr/bin/env python3
"""Bounded self-test capture, loopback only. No production interface option."""
import argparse
import csv
import json
import os
from pathlib import Path
import signal
import resource
import socket
import struct
import subprocess
import tempfile
import threading
import time


def validate_pcap(data):
    if len(data) < 24 or len(data) > 150000:
        raise ValueError('invalid capture size')
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}.get(data[:4])
    if not endian:
        raise ValueError('unsupported PCAP format')
    major, minor, zone, accuracy, snaplen, linktype = struct.unpack_from(endian + 'HHIIII', data, 4)
    if (major, minor, linktype) != (2, 4, 1) or snaplen != 1024:
        raise ValueError('unsupported PCAP header')
    pos, count = 24, 0
    while pos < len(data):
        if pos + 16 > len(data):
            raise ValueError('truncated packet header')
        sec, usec, size, wire_size = struct.unpack_from(endian + 'IIII', data, pos)
        if size > 1024 or size > wire_size or pos + 16 + size > len(data):
            raise ValueError('invalid packet length')
        pos += 16 + size
        count += 1
    if not 1 <= count <= 128:
        raise ValueError('invalid packet count')
    return count


def probe(reader=None, library=None):
    # Only test-owned traffic. No DNS names, credentials or user payloads.
    with socket.socket() as server, tempfile.TemporaryDirectory(prefix='vg-dpi-', dir='/dev/shm') as directory:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port = server.getsockname()[1]
        pcap = Path(directory) / 'capture.pcap'
        process = subprocess.Popen(['tcpdump', '--immediate-mode', '-i', 'lo', '-p', '-n', '-U', '-s', '1024',
                                    '-c', '128', '-w', str(pcap), 'ip and tcp and host 127.0.0.1 and port ' + str(port)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            # Wait for tcpdump's positive readiness, bounded independently.
            ready = threading.Event()
            diagnostics = []
            def stderr_reader():
                for line in process.stderr:
                    diagnostics.append(line)
                    if 'listening on lo' in line:
                        ready.set()
            thread = threading.Thread(target=stderr_reader, daemon=True)
            thread.start()
            if not ready.wait(2):
                raise RuntimeError('capture did not become ready')
            start = time.time()
            with socket.create_connection(('127.0.0.1', port), timeout=1) as client:
                connection, address = server.accept()
                with connection:
                    client.sendall(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n')
                    connection.recv(1024)
                    connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
                    client.recv(1024)
            time.sleep(0.2)
            process.send_signal(signal.SIGINT)
            process.wait(timeout=2)
            thread.join(timeout=1)
            if process.returncode != 0 or not any('0 packets dropped by kernel' in line for line in diagnostics):
                raise RuntimeError('capture failed or dropped packets')
            count = validate_pcap(pcap.read_bytes())
            capture_seconds = time.time() - start
            http_detected = None
            if reader:
                output = Path(directory) / 'flows.csv'
                def limits():
                    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
                    resource.setrlimit(resource.RLIMIT_AS, (256 << 20, 256 << 20))
                    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
                env = dict(os.environ)
                if library:
                    env['LD_LIBRARY_PATH'] = str(Path(library).resolve())
                subprocess.run([str(Path(reader).resolve()), '-i', str(pcap), '-d', '-v', '2', '-C', str(output)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=3, check=True, preexec_fn=limits)
                if output.stat().st_size > 1 << 20:
                    raise ValueError('DPI output too large')
                rows = list(csv.DictReader(output.read_text().splitlines()))
                http_detected = (len(rows) == 1 and rows[0]['ndpi_proto'] == 'HTTP'
                                 and rows[0]['src_ip'] == '127.0.0.1' and rows[0]['dst_ip'] == '127.0.0.1'
                                 and rows[0]['protocol'] == '6' and int(rows[0]['dst_port']) == port)
                if not http_detected:
                    raise RuntimeError('test HTTP flow not detected')
            return {'packets': count, 'captureSeconds': round(capture_seconds, 3),
                    'loopbackOnly': True, 'kernelDrops': 0, 'httpDetected': http_detected,
                    'temporaryFilesRemovedOnReturn': True}
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--reader')
    parser.add_argument('--library')
    args = parser.parse_args()
    print(json.dumps(probe(args.reader, args.library)))
