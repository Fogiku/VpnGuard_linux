#!/usr/bin/env python3
"""Enable the prepared administrator key in the live installer before disk checks."""
import json
import os
import pwd
import re
from pathlib import Path
import sys
from verify_payload import verify


def enable(root):
    root = Path(root).resolve()
    verify(root)
    settings = json.loads((root / "install.json").read_text())
    if not settings.get("captureReady"):
        raise ValueError("Target capture is not ready")
    macs = {p.read_text().strip().lower() for p in Path("/sys/class/net").glob("*/address")}
    if settings["wanMac"].lower() not in macs:
        raise ValueError("Captured target network adapter is absent")
    key = (root / "admin.pub").read_text().strip()
    if not re.fullmatch(r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+(?: [^\r\n]*)?", key):
        raise ValueError("Invalid installer administrator key")
    user = pwd.getpwnam(settings.get("installerUsername", "vgrecovery"))
    directory = Path(user.pw_dir) / ".ssh"
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("Refusing linked SSH directory")
    path = directory / "authorized_keys"
    if path.is_symlink():
        raise ValueError("Refusing linked authorized_keys")
    entry = 'from="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12" ' + key
    existing = path.read_text() if path.exists() else ""
    if entry not in existing.splitlines():
        path.write_text(existing.rstrip() + "\n" + entry + "\n")
    directory.chmod(0o700)
    path.chmod(0o600)
    os.chown(directory, user.pw_uid, user.pw_gid)
    os.chown(path, user.pw_uid, user.pw_gid)
    print("VpnGuard installer SSH key enabled for recovery user; disk contents unchanged")


if __name__ == "__main__":
    enable(Path(sys.argv[1]))
