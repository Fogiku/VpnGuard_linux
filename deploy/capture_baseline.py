#!/usr/bin/env python3
"""Read-only inspection plus a root-only backup; does not change services/network."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time


def command(*args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    return {"exit": p.returncode, "output": p.stdout, "error": p.stderr}


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root to back up private configuration")
    os.umask(0o077)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = Path("/var/backups/vpnguard") / ("baseline-" + stamp)
    directory.mkdir(parents=True, mode=0o700)
    paths = ["/usr/local/bin/vpnguard", "/var/lib/vpnguard", "/etc/wireguard",
             "/etc/vpnguard", "/etc/meduzavpn", "/etc/netplan",
             "/etc/systemd/system/vpnguard.service", "/etc/systemd/system/vpnguard.service.d"]
    with tarfile.open(directory / "private-backup.tar.gz", "w:gz") as archive:
        for name in paths:
            if Path(name).exists():
                archive.add(name, arcname=name.lstrip("/"))
    for label, args in {
        "rules": ["ip", "-4", "rule", "show"],
        "routes": ["ip", "-4", "route", "show", "table", "all"],
        "nft": ["nft", "list", "ruleset"],
        "unit": ["systemctl", "cat", "vpnguard"],
    }.items():
        (directory / (label + ".json")).write_text(json.dumps(command(*args), indent=2))
    status = command("meduzavpn", "status", "--json")
    data = json.loads(status["output"]) if status["exit"] == 0 else {}
    summary = {
        "capturedAt": datetime.datetime.now().astimezone().isoformat(),
        "host": command("hostname")["output"].strip(),
        "backupDirectory": str(directory),
        "binarySha256": hashlib.sha256(Path("/usr/local/bin/vpnguard").read_bytes()).hexdigest(),
        "meduza": {key: data.get(key) for key in ["state", "protocol", "interface", "location", "rx_bytes", "tx_bytes"]},
        "services": {unit: command("systemctl", "is-active", unit)["output"].strip()
                     for unit in ["ssh", "vpnguard", "meduzavpnd", "wg-quick@wg_server"]},
    }
    peers = command("wg", "show", "wg_server", "latest-handshakes")
    ages = [int(time.time()) - int(line.split()[1]) for line in peers["output"].splitlines() if len(line.split()) == 2 and line.split()[1] != "0"]
    summary["wireguard"] = {"peersWithHandshake": len(ages), "peersSeenWithin180Seconds": sum(0 <= age <= 180 for age in ages)}
    probe = command("curl", "-q", "--interface", data.get("interface") or "meduza0",
                    "-sS", "--connect-timeout", "5", "--max-time", "10", "-o", "/dev/null",
                    "-w", "%{http_code}", "https://example.com")
    summary["tunnelHttpsProbe"] = {"exit": probe["exit"], "httpCode": probe["output"]}
    (directory / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
