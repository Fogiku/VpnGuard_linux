"""Correlate a live HTTPS control or Discord Gateway connection with an IPv4 gateway snapshot."""
import argparse
import http.client
import json
import math
from pathlib import Path
import re
import socket
import ssl
import subprocess
from datetime import datetime, timezone


def observe(peer, tls, sudo):
    src, sport = tls.getsockname()
    dst, dport = tls.getpeername()
    cmd = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", "ConnectTimeout=5", peer]
    if sudo:
        cmd.extend(["sudo", "-n"])
    cmd.extend(["python3", "-", "--match-tcp", src, str(sport), dst, str(dport)])
    helper = Path(__file__).with_name("flow_snapshot.py").read_bytes()
    try:
        proc = subprocess.run(cmd, input=helper, capture_output=True, timeout=15)
        if proc.returncode == 0:
            result = json.loads(proc.stdout)
            if isinstance(result, dict) and result.get("status") in {
                    "matched", "missing", "ambiguous", "incomplete"}:
                return result
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return {"status": "gateway_unavailable"}


def measure(host, gateway, sudo):
    result = {"utc": datetime.now(timezone.utc).isoformat(), "source": "client_tls_control",
              "tls": False, "http": None, "flow": {"status": "unobserved"}}
    try:
        address = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        with socket.create_connection(address, timeout=7) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                result["tls"] = True
                result["flow"] = observe(gateway, tls, sudo)
                tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
                with http.client.HTTPResponse(tls) as response:
                    response.begin()
                    result["http"] = response.status
    except (OSError, http.client.HTTPException) as exc:
        result["error"] = type(exc).__name__
    return result


def discord_hello(message):
    if not isinstance(message, str):
        return False
    try:
        data = json.loads(message)
    except (ValueError, RecursionError):
        return False
    if not isinstance(data, dict) or type(data.get("op")) is not int or data["op"] != 10:
        return False
    details = data.get("d")
    interval = details.get("heartbeat_interval") if isinstance(details, dict) else None
    return (type(interval) in (int, float) and 0 < interval <= 2**53
            and math.isfinite(interval))


def measure_discord(gateway, sudo, host="gateway.discord.gg"):
    from websockets.exceptions import ConnectionClosed, WebSocketException
    from websockets.sync.client import connect

    result = {"utc": datetime.now(timezone.utc).isoformat(), "source": "client_discord_gateway",
              "discord_gateway": "unobserved", "flow": {"status": "unobserved"}}
    try:
        address = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        with socket.create_connection(address, timeout=7) as raw:
            with connect(f"wss://{host}/?v=10&encoding=json", sock=raw, proxy=None,
                         open_timeout=7, close_timeout=2, max_size=16384) as ws:
                # Observe this socket even if the gateway's first message isn't Hello.
                try:
                    result["discord_gateway"] = "hello" if discord_hello(ws.recv(timeout=10)) else "unexpected_message"
                except ConnectionClosed:
                    result["discord_gateway"] = "closed_before_hello"
                    return result
                except TimeoutError:
                    result["discord_gateway"] = "timeout"
                result["flow"] = observe(gateway, ws.socket, sudo)
    except (OSError, WebSocketException) as exc:
        if result["discord_gateway"] == "unobserved":
            result["discord_gateway"] = "connection_error"
        result["error"] = type(exc).__name__
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--discord", action="store_true", help="Observe the socket of a Discord Gateway Hello")
    mode.add_argument("--host", help="IPv4-capable HTTPS control hostname")
    parser.add_argument("--gateway", required=True, help="Configured SSH host alias")
    parser.add_argument("--sudo", action="store_true", help="Use sudo -n for the read-only snapshot")
    args = parser.parse_args()
    if args.host and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", args.host):
        parser.error("expected ASCII hostname")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", args.gateway):
        parser.error("expected SSH host alias")
    if args.discord:
        try:
            result = measure_discord(args.gateway, args.sudo)
        except ImportError:
            parser.exit(2, "Discord probe requires websockets==16.0 on the client.\n")
    else:
        result = measure(args.host, args.gateway, args.sudo)
    print(json.dumps(result, indent=2))
