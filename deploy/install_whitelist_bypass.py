#!/usr/bin/env python3
"""Install the pinned Telemost creator and systemd unit from a release archive."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("archive", type=Path)
parser.add_argument("cookies", type=Path)
args = parser.parse_args()
digests = {
    "x86_64": "cd799a23264fae10ff67692ee21e607b98e642fb951cea4c425070ada33285cd",
    "aarch64": "ccb083b05ac8263a6bb19f9d31e9305023030bac846a5f7695ad5f1fce791a6e",
}
def install(src, target, mode):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as temp:
        try:
            shutil.copyfileobj(src, temp)
            temp.flush()
            os.fchmod(temp.fileno(), mode)
            os.replace(temp.name, target)
        finally:
            Path(temp.name).unlink(missing_ok=True)

with args.archive.open("rb") as src:
    digest = hashlib.sha256()
    for chunk in iter(lambda: src.read(1048576), b""):
        digest.update(chunk)
    if digest.hexdigest() != digests.get(platform.machine()):
        raise SystemExit("Archive checksum or architecture mismatch")
    with zipfile.ZipFile(src) as archive:
        names = [n for n in archive.namelist() if Path(n).name == "headless-telemost-creator"]
        if platform.machine() == "aarch64":
            names = [n for n in names if "arm64" in Path(n).parts]
        if len(names) != 1:
            raise SystemExit("Creator binary missing")
        with archive.open(names[0]) as binary:
            install(binary, "/usr/local/libexec/vpnguard-telemost-creator", 0o755)
with args.cookies.open("rb") as cookies:
    install(cookies, "/etc/vpnguard/whitelist-bypass/cookies-yandex.json", 0o600)
with Path(__file__).with_name("vpnguard-whitelist-bypass.service").open("rb") as unit:
    install(unit, "/etc/systemd/system/vpnguard-whitelist-bypass.service", 0o644)
subprocess.run(["systemctl", "daemon-reload"], check=True)
