"""Offline acceptance tests. Set VPNGUARD_TEST_BROWSER to msedge or chromium."""
import os
import unittest


@unittest.skipUnless(os.getenv("VPNGUARD_TEST_BROWSER"), "optional Playwright browser")
class ClientPlaybackTest(unittest.TestCase):
    def test_video_and_empty_page(self):
        from probe_client_playback import conclusion, playback, sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel=os.environ["VPNGUARD_TEST_BROWSER"])
            page = browser.new_page()
            page.set_content("""
                <div id="movie_player"><video class="html5-main-video" muted autoplay></video></div>
                <canvas></canvas><script>
                const canvas = document.querySelector('canvas');
                const ctx = canvas.getContext('2d');
                setInterval(() => {
                    ctx.fillStyle = Math.random() > 0.5 ? 'blue' : 'red';
                    ctx.fillRect(0, 0, 100, 100);
                }, 50);
                document.querySelector('video').srcObject = canvas.captureStream(20);
                </script>""")
            state, duration = playback(page, 12)
            self.assertEqual(state, "playing")
            self.assertGreaterEqual(duration, 5)
            page.set_content("<p>Page opened</p>")
            self.assertEqual(playback(page, 1), ("unconfirmed", 0))
            browser.close()

        success = {"control_http": 200, "playback": state}
        missed = {"control_http": 200, "playback": "unconfirmed"}
        self.assertEqual(conclusion([missed, missed]), "repeated_unconfirmed")
        self.assertEqual(conclusion([success, missed]), "inconclusive")
        self.assertEqual(conclusion([dict(success, control_http=503)]), "control_inconclusive")

    def test_gateway_hello(self):
        from probe_client_playback import discord_gateway, sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(channel=os.environ["VPNGUARD_TEST_BROWSER"])
            for payload, expected in [('{"op":10,"d":{"heartbeat_interval":45000}}', "hello"),
                                      ('{"op":10}', "unexpected_message"),
                                      ('invalid', "unexpected_message")]:
                page = browser.new_page()
                page.route_web_socket("**/gateway.discord.gg/**", lambda ws: ws.send(payload))
                # Install the WebSocket route before loading the document that opens it.
                page.route("https://example.test/", lambda route: route.fulfill(
                    content_type="text/html", body="<html></html>"))
                page.goto("https://example.test/")
                self.assertEqual(discord_gateway(page), expected)
                page.close()
            browser.close()
