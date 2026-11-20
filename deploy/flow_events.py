#!/usr/bin/env python3
"""Read-only conntrack event observer. No initial dump or mutation of sysctls.

Only NEW observed in this epoch establishes a lifetime. UPDATE without NEW is
ignored. Any transport/parser failure invalidates all lifetime evidence.
"""
import argparse
import json
import socket
import struct
import time
import uuid

from flow_snapshot import flow


class Registry:
    def __init__(self, limit=512):
        self.limit = limit
        self.reset()

    def reset(self):
        self.epoch = uuid.uuid4().hex
        self.serial = 0
        self.rows = {}

    @staticmethod
    def key(row):
        if row['conntrackId'] is None:
            return None
        return (row['zone'], row['conntrackId'], row['protocol'], row['source'],
                row['sourcePort'], row['destination'], row['destinationPort'])

    def apply(self, kind, flags, row, at):
        key = self.key(row)
        if key is None:
            return
        if kind == 0x102:  # IPCTNL_MSG_CT_DELETE
            self.rows.pop(key, None)
        elif kind == 0x100 and flags & 0x400:  # NLM_F_CREATE: NEW, not UPDATE
            if key not in self.rows and len(self.rows) >= self.limit:
                self.reset()
                raise RuntimeError('lifetime registry limit exceeded')
            self.serial += 1
            self.rows[key] = {'generation': self.epoch + ':' + str(self.serial),
                              'observedNewAt': at, 'row': row}
        elif kind == 0x100 and key in self.rows:
            self.rows[key]['row'] = row

    def datagram(self, data, sender, recv_flags, at):
        try:
            if recv_flags & socket.MSG_TRUNC or sender[0] != 0:
                raise ValueError('invalid event datagram')
            pos = 0
            while pos < len(data):
                if pos + 16 > len(data):
                    raise ValueError('truncated event header')
                size, kind, flags, seq, pid = struct.unpack_from('=IHHII', data, pos)
                if size < 20 or pos + size > len(data) or seq != 0 or flags & 0x10:
                    raise ValueError('invalid event message')
                body = data[pos + 16:pos + size]
                pos += (size + 3) & ~3
                if kind not in (0x100, 0x102):
                    raise ValueError('unexpected event type')
                row = flow(body)
                if row is not None:
                    self.apply(kind, flags, row, at)
        except Exception:
            self.reset()
            raise


def observe(seconds=10, probe=False):
    if not 0 < seconds <= 60:
        raise ValueError('invalid observation budget')
    registry = Registry()
    # NEW, UPDATE, DESTROY multicast groups. No NETLINK_NO_ENOBUFS suppression.
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.bind((0, 7))
        probe_socket = None
        probe_port = None
        if probe:
            probe_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe_socket.bind(('127.0.0.1', 0))
            probe_port = probe_socket.getsockname()[1]
            probe_socket.sendto(b'vpnguard-event-test', ('127.0.0.1', probe_port))
        deadline = time.monotonic() + seconds
        try:
            while time.monotonic() < deadline:
                sock.settimeout(max(0.001, deadline - time.monotonic()))
                try:
                    data, ancillary, flags, sender = sock.recvmsg(1 << 20)
                except socket.timeout:
                    break
                registry.datagram(data, sender, flags, time.time())
            matched = any(r['row']['source'] == '127.0.0.1' and r['row']['sourcePort'] == probe_port
                          for r in registry.rows.values()) if probe else None
            return {'observedLifetimes': len(registry.rows), 'probeObserved': matched,
                    'scope': 'events since subscription only; no DPI assignment'}
        except Exception:
            registry.reset()
            raise
        finally:
            if probe_socket:
                probe_socket.close()
            # Ending subscription also ends continuity; no evidence survives.
            registry.reset()


def stream_events():
    registry = Registry()
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        sock.bind((0, 7))
        next_heartbeat = time.monotonic()
        try:
            while True:
                now = time.monotonic()
                if now >= next_heartbeat:
                    print(json.dumps({'epoch': registry.epoch, 'rows': list(registry.rows.values())}), flush=True)
                    next_heartbeat = now + 1
                sock.settimeout(max(0.001, next_heartbeat - time.monotonic()))
                try:
                    data, ancillary, flags, sender = sock.recvmsg(1 << 20)
                except socket.timeout:
                    continue
                registry.datagram(data, sender, flags, time.time())
        finally:
            registry.reset()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--seconds', type=float, default=10)
    parser.add_argument('--probe-loopback', action='store_true')
    args = parser.parse_args()
    result = observe(args.seconds, args.probe_loopback)
    print(json.dumps(result))
    if args.probe_loopback and not result['probeObserved']:
        raise SystemExit('loopback NEW event not observed')
