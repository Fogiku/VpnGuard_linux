#!/usr/bin/env python3
"""Installer early-command: verify payload and select exactly one authorised disk."""
import json
from pathlib import Path
import subprocess
import sys
import time
import hashlib
from verify_payload import verify

def select_disk(disks, serial):
    matches = [d for d in disks if d.get("type") == "disk" and str(d.get("serial") or "").strip() == serial]
    if len(matches) != 1:
        raise ValueError("Target serial must match exactly one disk")
    d = matches[0]
    if d.get("tran") == "usb" or int(d.get("size") or 0) < 32 * 1024**3:
        raise ValueError("Target is USB or smaller than 32 GiB")
    return d["path"]

def check(root):
    verify(root)
    settings = json.loads((root / "install.json").read_text())
    if not settings.get("captureReady") or (root.parent / "CAPTURE-INCOMPLETE").exists():
        raise ValueError("Run START-INSTALL.cmd on the target Windows PC first")
    if not Path("/sys/firmware/efi").is_dir():
        raise ValueError("UEFI boot is required")
    # Unsigned DKMS drivers cannot be enrolled without a physical MOK confirmation.
    for p in Path("/sys/firmware/efi/efivars").glob("SecureBoot-*"):
        if settings.get("installAwg", False) and p.read_bytes()[4:5] == b"\x01":
            raise ValueError("Secure Boot must be disabled before unattended AmneziaWG installation")
    macs = [p.read_text().strip().lower() for p in Path("/sys/class/net").glob("*/address")]
    if settings["wanMac"] not in macs:
        raise ValueError("Authorised Ethernet MAC is not present on this computer")
    subprocess.run(["udevadm", "settle"], check=True)
    data = json.loads(subprocess.check_output(["lsblk", "-bdJ", "-o", "PATH,SERIAL,TRAN,SIZE,TYPE"]))
    target = select_disk(data["blockdevices"], settings["diskSerial"])
    # The install medium must never be selected, even with an unusual transport identifier.
    mounts = subprocess.check_output(["lsblk", "-nr", "-o", "MOUNTPOINTS", target], text=True)
    if "/cdrom" in mounts or "/isodevice" in mounts:
        raise ValueError("Target contains the installation medium")
    if settings.get("requireSshApproval", True):
        expected = {"diskSerial": settings["diskSerial"],
                    "manifestSha256": hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest()}
        approval = Path("/run/vpnguard-install-approved.json")
        print("VpnGuard: waiting for SSH verification before disk partitioning", flush=True)
        while True:
            if approval.exists():
                if json.loads(approval.read_text()) != expected:
                    raise ValueError("SSH approval does not match this disk and payload")
                break
            time.sleep(2)
    path = Path("/autoinstall.yaml")
    import yaml  # supplied by the Ubuntu Server installation environment
    config = yaml.safe_load(path.read_text())
    ai = config.get("autoinstall", config)
    ai["storage"] = {"layout": {"name": "direct", "match": {"path": target}}}
    path.write_text(yaml.safe_dump(config))
    print("VpnGuard: verified installation target " + target + " serial " + settings["diskSerial"])

if __name__ == "__main__":
    try:
        check(Path(sys.argv[1]))
    except Exception as e:
        print("VpnGuard installation stopped BEFORE disk partitioning: " + str(e), file=sys.stderr)
        sys.exit(1)
