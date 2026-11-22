"""Exercise the Chromium observations against a disposable local HTTPS endpoint."""
import errno
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


@unittest.skipUnless(os.getenv("VPNGUARD_TEST_BROWSER"), "optional Playwright browser")
class BrowserEgressTests(unittest.TestCase):
    def test_https_peer_and_media(self):
        from probe_client_playback import egress_config, inspect_egress, record_media_peer, sync_playwright

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"fixture"
                mime = "text/plain"
                if self.path == "/ip":
                    body = json.dumps({"ip": self.client_address[0]}).encode()
                    mime = "application/json"
                elif self.path.startswith("/videoplayback"):
                    mime = "video/mp4"
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/ip")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as tmp, ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            key, cert = Path(tmp, "key.pem"), Path(tmp, "cert.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=localhost", "-keyout", key, "-out", cert], check=True, capture_output=True)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                origin = f"https://media.googlevideo.com:{port}"
                with sync_playwright() as pw:
                    browser = pw.chromium.launch(channel=os.environ["VPNGUARD_TEST_BROWSER"], args=[
                        "--no-proxy-server", "--host-resolver-rules=MAP media.googlevideo.com 127.0.0.1"])
                    ctx = browser.new_context(ignore_https_errors=True)
                    for path, prefix, family, status in [
                            ("/ip", "127.0.0.1", 4, "matched"), ("/ip", "192.0.2.0/24", 4, "outside_expected"),
                            ("/ip", "2001:db8::/32", 6, "wrong_family"), ("/redirect", "127.0.0.1", 4, "unavailable"),
                            ("/", "127.0.0.1", 4, "unavailable")]:
                        config = egress_config([f"https://127.0.0.1:{port}{path}", prefix], family)
                        result = inspect_egress(ctx, *config)
                        self.assertEqual(result["status"], status, result)
                    if socket.has_ipv6:
                        class IPv6Server(ThreadingHTTPServer):
                            address_family = socket.AF_INET6
                        try:
                            server6 = IPv6Server(("::1", 0), Handler)
                        except OSError as exc:
                            if exc.errno not in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
                                raise
                        else:
                            with server6:
                                server6.socket = tls.wrap_socket(server6.socket, server_side=True)
                                worker = threading.Thread(target=server6.serve_forever, daemon=True)
                                worker.start()
                                try:
                                    config = egress_config([f"https://[::1]:{server6.server_port}/ip", "::1"], 6)
                                    result = inspect_egress(ctx, *config)
                                    self.assertEqual((result["status"], result.get("address")), ("matched", "::1"))
                                finally:
                                    server6.shutdown()
                                    worker.join()
                    page = ctx.new_page()
                    peers = {"peers": [], "truncated": False}
                    session = ctx.new_cdp_session(page)
                    session.on("Network.responseReceived", lambda e: record_media_peer(e, peers))
                    session.send("Network.enable")
                    page.goto(origin)
                    page.evaluate("async () => (await fetch('/videoplayback?private=value')).arrayBuffer()")
                    self.assertEqual(peers["peers"], [dict(address="127.0.0.1", port=port, protocol="http/1.0")])
                    browser.close()
            finally:
                server.shutdown()
                thread.join()
