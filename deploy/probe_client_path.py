"""Correlate a live client TLS control connection with an IPv4 gateway snapshot."""
import argparse
import http.client
import json
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="IPv4-capable HTTPS control hostname")
    parser.add_argument("--gateway", required=True, help="Configured SSH host alias")
    parser.add_argument("--sudo", action="store_true", help="Use sudo -n for the read-only snapshot")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", args.host):
        parser.error("expected ASCII hostname")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", args.gateway):
        parser.error("expected SSH host alias")
    print(json.dumps(measure(args.host, args.gateway, args.sudo), indent=2))
