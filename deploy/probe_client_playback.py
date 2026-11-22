"""Client-side YouTube playback, Discord Gateway and control measurements. Requires Playwright."""
import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from playwright.sync_api import Error, sync_playwright


def navigation(page, url, timeout):
    try:
        response = page.goto(url, wait_until="commit", timeout=timeout)
        return response.status if response else None
    except Error:
        return None


SAMPLE = """() => {
    const video = document.querySelector('#movie_player video.html5-main-video');
    if (!video || document.querySelector('.ad-showing, .ad-interrupting')) return null;
    video.muted = true;
    if (video.paused && !video.ended) video.play().catch(() => {});
    const quality = video.getVideoPlaybackQuality();
    return {time: video.currentTime, frames: quality.totalVideoFrames - quality.droppedVideoFrames,
            source: video.currentSrc, seeking: video.seeking, error: !!video.error};
}"""


def playback(page, seconds):
    start = time.monotonic()
    previous = None
    continuous = longest = 0.0
    while time.monotonic() - start < seconds:
        page.wait_for_timeout(500)
        sample = page.evaluate(SAMPLE)
        now = time.monotonic()
        if sample and sample["error"]:
            return "media_error", round(longest, 1)
        if sample and previous and sample["source"] == previous["source"]:
            elapsed = now - previous["at"]
            delta = sample["time"] - previous["time"]
            if (not sample["seeking"] and not previous["seeking"] and
                    sample["frames"] > previous["frames"] and 0 < delta <= elapsed + 0.5):
                continuous += min(delta, elapsed)
                longest = max(longest, continuous)
                if longest >= 5:
                    return "playing", round(longest, 1)
            else:
                continuous = 0
        else:
            continuous = 0
        if sample:
            sample["at"] = now
        previous = sample
    return "unconfirmed", round(longest, 1)


def discord_gateway(page):
    return page.evaluate("""() => new Promise(resolve => {
        const socket = new WebSocket('wss://gateway.discord.gg/?v=10&encoding=json');
        const timer = setTimeout(() => finish('timeout'), 10000);
        function finish(result) {
            clearTimeout(timer);
            socket.onerror = socket.onclose = socket.onmessage = null;
            socket.close();
            resolve(result);
        }
        socket.onerror = () => finish('connection_error');
        socket.onclose = () => finish('closed_before_hello');
        socket.onmessage = event => {
            try {
                const data = JSON.parse(event.data);
                const interval = data?.d?.heartbeat_interval;
                finish(data?.op === 10 && Number.isFinite(interval) && interval > 0
                    ? 'hello' : 'unexpected_message');
            } catch {
                finish('unexpected_message');
            }
        };
    })""")


def egress_config(values, family):
    url, prefix = values
    target = urlsplit(url)
    if target.scheme != "https" or not target.hostname or target.fragment or target.username is not None:
        raise ValueError("expected an HTTPS reflector URL without credentials or fragment")
    network = ipaddress.ip_network(prefix)
    if network.version != family:
        raise ValueError("expected an IPv%d network" % family)
    return url, network


def inspect_egress(context, url, network):
    result = dict(target_sha256=hashlib.sha256(url.encode()).hexdigest(),
                  expected=str(network), status="unavailable")
    page = context.new_page()
    try:
        page.set_extra_http_headers({"Cache-Control": "no-cache"})
        response = page.goto(url, wait_until="domcontentloaded", timeout=7000)
        if not response or response.request.redirected_from or response.from_service_worker or not response.ok:
            return result
        if response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return result
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("ip"), str):
            return result
        address = ipaddress.ip_address(data["ip"])
        result["address"] = str(address)
        if address.version != network.version:
            result["status"] = "wrong_family"
        else:
            result["status"] = "matched" if address in network else "outside_expected"
    except (Error, ValueError):
        pass
    finally:
        page.close()
    return result


def record_media_peer(event, summary):
    response = event["response"]
    url = urlsplit(response["url"])
    if (url.scheme != "https" or not (url.hostname or "").endswith(".googlevideo.com")
            or url.path != "/videoplayback" or not 200 <= response["status"] < 300
            or not response.get("mimeType", "").lower().startswith(("audio/", "video/"))
            or any(response.get(key) for key in ("fromDiskCache", "fromPrefetchCache", "fromServiceWorker"))):
        return
    try:
        ip = str(ipaddress.ip_address(response.get("remoteIPAddress", "").strip("[]")))
    except ValueError:
        return
    port = response.get("remotePort")
    if type(port) is not int or not 1 <= port <= 65535:
        return
    peer = dict(address=ip, port=port, protocol=response.get("protocol") or "unknown")
    if peer not in summary["peers"]:
        if len(summary["peers"]) >= 16:
            summary["truncated"] = True
            return
        summary["peers"].append(peer)


def measure(browser, target, control, discord=False, egress=None):
    context = browser.new_context()
    try:
        control_page = context.new_page()
        sample = {"utc": datetime.now(timezone.utc).isoformat(),
                  "control_http": navigation(control_page, control, 10000)}
        control_page.close()
        if discord:
            gateway_page = context.new_page()
            try:
                sample["discord_gateway"] = discord_gateway(gateway_page)
            except Error:
                sample["discord_gateway"] = "observation_interrupted"
            gateway_page.close()
        if target:
            page = context.new_page()
            media = {"peers": [], "truncated": False, "observer": "available"}
            try:
                session = context.new_cdp_session(page)
                session.on("Network.responseReceived", lambda event: record_media_peer(event, media))
                session.send("Network.enable")
                session.send("Network.setCacheDisabled", {"cacheDisabled": True})
            except Error:
                media["observer"] = "unavailable"
            page_status = navigation(page, target, 15000)
            state, duration = "page_failed", 0
            if page_status is not None and 200 <= page_status < 300:
                try:
                    state, duration = playback(page, 20)
                except Error:
                    state = "observation_interrupted"
            sample.update(page_http=page_status, playback=state, continuous_seconds=duration, media_network=media)
        if egress:
            sample["egress"] = {key: inspect_egress(context, *config) for key, config in egress.items()}
        return sample
    finally:
        context.close()


def conclusion(samples):
    if any(s["control_http"] is None or not 200 <= s["control_http"] < 300 for s in samples):
        return "control_inconclusive"
    states = {s["playback"] for s in samples}
    if states == {"playing"}:
        return "playback_observed"
    if len(samples) > 1 and len(states) == 1 and "observation_interrupted" not in states:
        return "repeated_playback_failure" if states <= {"page_failed", "media_error"} else "repeated_unconfirmed"
    return "inconclusive"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--video-id")
    parser.add_argument("--discord", action="store_true", help="Check Discord Gateway WebSocket Hello")
    parser.add_argument("--control", required=True, help="Independent HTTPS URL expected to return 2xx")
    parser.add_argument("--path-label", required=True, help="Operator label for the configured client path")
    parser.add_argument("--runs", type=int, choices=range(1, 6), default=2)
    parser.add_argument("--channel", choices=["msedge", "chrome", "chromium"])
    parser.add_argument("--lab-session", help="Shared ID for one isolated Linux A/B run")
    parser.add_argument("--profile-revision", help="Operator-supplied candidate profile revision")
    for family in (4, 6):
        parser.add_argument("--egress-v%d" % family, nargs=2, metavar=("HTTPS_URL", "EXPECTED_CIDR"),
                            help="Check the source address returned by your HTTPS JSON reflector")
    args = parser.parse_args()
    try:
        egress = {"v%d" % family: egress_config(values, family)
                  for family, values in ((4, args.egress_v4), (6, args.egress_v6)) if values}
    except ValueError as exc:
        parser.error(str(exc))
    if args.lab_session is not None or args.profile_revision is not None:
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", v or "")
                   for v in (args.lab_session, args.profile_revision)):
            parser.error("provide both lab session and profile revision (1-96 identifier characters)")
    if not args.video_id and not args.discord:
        parser.error("select --video-id or --discord or both")
    if args.video_id and not re.fullmatch(r"[A-Za-z0-9_-]{11}", args.video_id):
        parser.error("expected an 11-character YouTube video ID")
    if urlsplit(args.control).scheme != "https" or not urlsplit(args.control).hostname:
        parser.error("expected an HTTPS control URL")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel=args.channel)
        try:
            lab = None
            if args.lab_session:
                from compare_client_profiles import lab_context
                try:
                    lab = lab_context(args.lab_session, args.profile_revision, args.control,
                                      browser.version, args.channel)
                except (OSError, ValueError) as exc:
                    parser.error(str(exc))
            target = "https://www.youtube.com/watch?v=" + args.video_id if args.video_id else None
            samples = [measure(browser, target, args.control, args.discord, egress) for _ in range(args.runs)]
        finally:
            browser.close()
    report = {"schema": 2 if args.discord else 1, "source": "client_browser",
              "operator_path_label": args.path_label, "samples": samples}
    if lab:
        report.update(schema=3, lab=lab)
    if args.video_id:
        report.update(video_id=args.video_id, result=conclusion(samples))
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Error:
        sys.exit("Browser unavailable or session interrupted. Verify Playwright and the selected browser.")
