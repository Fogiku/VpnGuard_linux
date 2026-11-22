"""Correlate TCP tuples including ambiguity and an opt-in isolated kernel test."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import ssl
import threading
from unittest import mock
import unittest

from flow_snapshot import match_tcp


class PathObservationTests(unittest.TestCase):
    def test_full_tuple_and_ambiguous_zones(self):
        row = dict(protocol="tcp", source="192.0.2.2", sourcePort=30000,
                   destination="192.0.2.3", destinationPort=443,
                   mark=0x80110008, zone=2, conntrackId=0)
        args = (row["source"], 30000, row["destination"], 443)
        def lookup(rows, truncated=False):
            return match_tcp(dict(rows=rows, truncated=truncated), *args)
        self.assertEqual(lookup([row])["pinByte"], 0x11)
        self.assertEqual(lookup([row, dict(row, zone=3)])["status"], "ambiguous")
        self.assertEqual(lookup([row], True)["status"], "incomplete")
        for change in [dict(sourcePort=30001), dict(destinationPort=80), dict(protocol="udp"),
                       dict(source=row["destination"]), dict(destination=row["source"])]:
            self.assertEqual(lookup([dict(row, **change)])["status"], "missing")

    @unittest.skipUnless(os.getenv("VPNGUARD_PATH_NETNS") == "1", "requires disposable Linux netns")
    def test_live_socket(self):
        if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
            self.fail("run in a separate network namespace")
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
        subprocess.run(["nft", "-f", "-"], input=b"""
table inet vpnguard {
 chain mark_test { type filter hook output priority mangle; policy accept;
    ip daddr 127.0.0.1 tcp flags syn ct mark set 0x80110008
 }
}
""", check=True)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with socket.create_connection(listener.getsockname()) as client:
                accepted, _ = listener.accept()
                with accepted:
                    source, sport = client.getsockname()
                    destination, dport = client.getpeername()
                    raw = subprocess.check_output([
                        sys.executable, str(Path(__file__).with_name("flow_snapshot.py")),
                        "--match-tcp", source, str(sport), destination, str(dport)])
                    result = json.loads(raw)
                    self.assertEqual((result["status"], result["pinByte"]), ("matched", 17))
                    self.assertEqual(result["nftObservation"], "equal_at_both_reads")
                    self.assertRegex(result["nftTableSHA256"], "^[0-9a-f]{64}$")

        # Exercise the client through the same stdin helper protocol in this netns.
        from probe_client_path import measure
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp, "cert.pem")
            key = Path(tmp, "key.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-subj", "/CN=localhost", "-addext",
                            "subjectAltName=IP:127.0.0.1", "-out", cert, "-keyout", key],
                           check=True, capture_output=True)
            ssh = Path(tmp, "ssh")
            ssh.write_text("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n"
                           "  if [ \"$1\" = python3 ]; then exec \"$@\"; fi\n"
                           "  shift\ndone\nexit 1\n")
            ssh.chmod(0o700)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            with socket.socket() as server:
                server.bind(("127.0.0.1", 443))
                server.listen()
                server.settimeout(10)
                def reply():
                    raw, _ = server.accept()
                    with ctx.wrap_socket(raw, server_side=True) as tls:
                        tls.settimeout(10)
                        if tls.recv(4096).startswith(b"HEAD / "):
                            tls.sendall(b"HTTP/1.1 204 No Content\r\n\r\n")
                thread = threading.Thread(target=reply, daemon=True)
                thread.start()
                with mock.patch.dict(os.environ, {"SSL_CERT_FILE": str(cert),
                                                  "PATH": tmp + os.pathsep + os.environ["PATH"]}):
                    report = measure("127.0.0.1", "test-gateway", False)
                thread.join(12)
            self.assertEqual(report["http"], 204)
            self.assertTrue(report["tls"])
            self.assertEqual(report["flow"]["status"], "matched")
            self.assertEqual(report["flow"]["pinByte"], 17)
