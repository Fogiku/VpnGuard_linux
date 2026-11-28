import ipaddress
import unittest
from passive_dpi import lan_filter


class LANFilterTest(unittest.TestCase):
    def test_only_external_client_pairs(self):
        addr = ipaddress.IPv4Address
        allow = lan_filter(addr('192.168.1.44'), [ipaddress.ip_network('8.9.0.0/16')])
        def pair(a,b):
            return bytes(12) + addr(a).packed + addr(b).packed
        for a,b in [('192.168.1.44','8.8.8.8'), ('8.8.8.8','192.168.1.44')]:
            self.assertTrue(allow(pair(a,b)))
        for peer in ('8.9.2.3','192.168.1.1','10.1.2.3','224.0.0.1','127.0.0.1'):
            self.assertFalse(allow(pair('192.168.1.44',peer)))
        self.assertFalse(allow(pair('192.168.1.45','8.8.8.8')))
