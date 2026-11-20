import socket
import struct
import unittest
from flow_events import Registry
from test_flow_snapshot import attr


class EventTests(unittest.TestCase):
    def test_netlink_new_and_destroy(self):
        ip = attr(1, socket.inet_aton('192.0.2.1')) + attr(2, socket.inet_aton('198.51.100.1'))
        proto = attr(1, b'\x11') + attr(2, struct.pack('!H', 1234)) + attr(3, struct.pack('!H', 443))
        body = bytes([socket.AF_INET, 0, 0, 0]) + attr(1, attr(1, ip) + attr(2, proto)) + attr(12, struct.pack('!I', 12))
        def message(kind, flags):
            return struct.pack('=IHHII', 16 + len(body), kind, flags, 0, 0) + body
        r = Registry()
        r.datagram(message(0x100, 0x600), (0, 1), 0, 1)
        self.assertEqual(len(r.rows), 1)
        r.datagram(message(0x102, 0), (0, 3), 0, 2)
        self.assertFalse(r.rows)

    def row(self, identity=12):
        return dict(conntrackId=identity, zone=0, protocol='udp', source='192.0.2.1',
                    sourcePort=1234, destination='198.51.100.1', destinationPort=443)

    def test_reuse_destroy_and_orphan_update(self):
        r = Registry()
        row = self.row()
        r.apply(0x100, 0, row, 1)
        self.assertFalse(r.rows)
        r.apply(0x100, 0x600, row, 2)
        first = next(iter(r.rows.values()))['generation']
        r.apply(0x100, 0, row, 3)
        self.assertEqual(next(iter(r.rows.values()))['generation'], first)
        r.apply(0x102, 0, row, 4)
        self.assertFalse(r.rows)
        r.apply(0x100, 0x600, row, 5)
        self.assertNotEqual(next(iter(r.rows.values()))['generation'], first)
        r.apply(0x100, 0x600, row, 6)
        self.assertEqual(next(iter(r.rows.values()))['observedNewAt'], 6)

    def test_failure_restart_and_limit_invalidate_all(self):
        r = Registry(limit=1)
        r.apply(0x100, 0x600, self.row(), 1)
        epoch = r.epoch
        with self.assertRaises(RuntimeError):
            r.apply(0x100, 0x600, self.row(13), 2)
        self.assertFalse(r.rows)
        self.assertNotEqual(r.epoch, epoch)
        for data, sender, flags in [(b'x', (0, 0), 0), (b'', (1, 0), 0),
                                    (b'', (0, 0), socket.MSG_TRUNC),
                                    (struct.pack('=IHHIIi', 20, 2, 0, 0, 0, -105), (0, 0), 0)]:
            r.apply(0x100, 0x600, self.row(), 1)
            with self.assertRaises(ValueError):
                r.datagram(data, sender, flags, 3)
            self.assertFalse(r.rows)

    def test_missing_id_cannot_establish_lifetime(self):
        r = Registry()
        r.apply(0x100, 0x600, self.row(None), 1)
        self.assertFalse(r.rows)


if __name__ == '__main__':
    unittest.main()
