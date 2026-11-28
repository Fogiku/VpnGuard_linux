"""Measure Discord and a control from one client, then submit evidence to its gateway."""
import argparse
import json
import re
import subprocess
import sys

from probe_client_path import measure, measure_discord


def collect(peer, control, sudo):
    samples = []
    for _ in range(2):
        app = measure_discord(peer, sudo)
        check = measure(control, peer, sudo)
        flow = app["flow"]
        other = check["flow"]
        samples.append(dict(utc=app["utc"], outcome=app["discord_gateway"],
                            controlHTTP=check["http"], controlTLS=check["tls"],
                            controlUTC=check["utc"], controlPolicy=other.get("policyRevision"),
                            controlCorrelation=other.get("correlation"),
                            correlation=flow.get("correlation"), exit=flow.get("pinnedExit"),
                            policy=flow.get("policyRevision"), profile=flow.get("profileSHA256")))
        if app["discord_gateway"] == "hello":
            break
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway", required=True, help="SSH host alias of the gateway")
    parser.add_argument("--control", default="example.org", help="Independent HTTPS control hostname")
    parser.add_argument("--sudo", action="store_true", help="Read conntrack with sudo -n")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args.gateway):
        parser.error("invalid gateway alias")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", args.control) or args.control.lower().rstrip(".") == "gateway.discord.gg":
        parser.error("choose an independent control host")
    body = {"samples": collect(args.gateway, args.control, args.sudo)}
    reply = subprocess.run(["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                            "-o", "ConnectTimeout=5", args.gateway, "curl", "-fsS", "--max-time", "135",
                            "-H", "X-VG:1", "--data-binary", "@-", "http://127.0.0.1:8765/api/discord-flow-draft"],
                           input=json.dumps(body), text=True, capture_output=True, timeout=145, check=True)
    result = json.loads(reply.stdout)
    if "error" in result:
        sys.exit(result["error"])
    print(json.dumps(dict(**body, result=result["result"]), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, ImportError, subprocess.SubprocessError) as exc:
        sys.exit(str(exc))
