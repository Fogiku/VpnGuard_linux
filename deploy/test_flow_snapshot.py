import socket
import struct
import unittest

from flow_snapshot import attributes, flow, snapshot


def attr(kind, data):
    value = struct.pack('=HH', len(data) + 4, kind) + data
    return value + b'\0' * (-len(value) % 4)


class FlowSnapshotTests(unittest.TestCase):
    def test_original_tuple_not_nat_reply(self):
        ip = attr(1, socket.inet_aton('192.168.15.2')) + attr(2, socket.inet_aton('1.1.1.1'))
        proto = attr(1, b'\x11') + attr(2, struct.pack('!H', 12345)) + attr(3, struct.pack('!H', 443))
        data = bytes([socket.AF_INET, 0, 0, 0]) + attr(1, attr(1, ip) + attr(2, proto))
        data += attr(2, b'ignored reply tuple') + attr(8, struct.pack('!I', 0x1020000))
        row = flow(data)
        self.assertEqual((row['source'], row['destinationPort'], row['mark']), ('192.168.15.2', 443, 0x1020000))
        self.assertEqual(row['application'], 'Unknown')  # UDP/443 does not prove QUIC.
        self.assertIsNone(row['conntrackId'])
        self.assertEqual(row['zone'], 0)
        tagged = flow(data + attr(12, struct.pack('!I', 123)) + attr(18, struct.pack('!H', 42)))
        self.assertEqual((tagged['conntrackId'], tagged['zone']), (123, 42))
        for broken in (attr(12, b'x'), attr(18, b'x')):
            with self.assertRaises(ValueError):
                flow(data + broken)

    def test_malformed_and_duplicate_attributes(self):
        for data in (b'\0', struct.pack('=HH', 3, 1), struct.pack('=HH', 20, 1), attr(1, b'a') * 2):
            with self.subTest(data=data), self.assertRaises(ValueError):
                attributes(data)

    def test_budget_validation(self):
        for limit, seconds in ((0, 2), (4097, 2), (512, 0), (512, 11)):
            with self.subTest(limit=limit, seconds=seconds), self.assertRaises(ValueError):
                snapshot(limit, seconds)

    def test_other_family_excluded(self):
        self.assertIsNone(flow(bytes([socket.AF_INET6, 0, 0, 0])))


if __name__ == '__main__':
    unittest.main()
