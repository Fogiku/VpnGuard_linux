import struct
import unittest
from dpi_loopback_capture import validate_pcap


class CaptureValidationTests(unittest.TestCase):
    def test_packet_limits_and_truncation(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 1024, 1)
        record = struct.pack('<IIII', 1, 0, 4, 4) + b'test'
        self.assertEqual(validate_pcap(header + record), 1)
        self.assertEqual(validate_pcap(header + record * 128), 128)
        for bad in (header, header + record[:-1], header + record * 129,
                    header + struct.pack('<IIII', 1, 0, 1025, 1025) + b'x' * 1025,
                    header + struct.pack('<IIII', 1, 0, 4, 3) + b'test',
                    b'bad!' + header[4:] + record, header[:20] + struct.pack('<I', 113) + record):
            with self.subTest(size=len(bad)), self.assertRaises(ValueError):
                validate_pcap(bad)


if __name__ == '__main__':
    unittest.main()
