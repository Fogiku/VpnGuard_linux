"""Detached worker for an update selected in the gateway UI."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

RECEIPT = Path("/run/vpnguard-repository-update.json")
MAX_BINARY = 64 * 1024 * 1024


def record(state):
    temp = RECEIPT.with_suffix(".tmp")
    temp.write_text(json.dumps(state))
    temp.replace(RECEIPT)


def download(url, candidate, checksum):
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(url, timeout=25) as response, candidate.open("xb") as target:
        while chunk := response.read(128 * 1024):
            size += len(chunk)
            if size > MAX_BINARY:
                raise ValueError("release binary exceeds size limit")
            digest.update(chunk)
            target.write(chunk)
    if digest.hexdigest() != checksum:
        raise ValueError("release binary SHA256 mismatch")
    candidate.chmod(0o700)


def install(directory, feed, version, arch, checksum, requester):
    state = dict(version=version, requester=requester, status="downloading")
    record(state)
    try:
        candidate = directory / "vpnguard"
        download(feed + "vpnguard-linux-" + arch, candidate, checksum)
        result = subprocess.run(
            [sys.executable, "-I", str(directory / "guarded_update.py"), "prepare",
             str(candidate), "--version", version, "--sha256", checksum],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        state.update(job=Path(json.loads(result.stdout)["job"]).name, status="installed")
    except Exception as exc:
        detail = exc.stderr.strip().splitlines()[-1:] if isinstance(exc, subprocess.CalledProcessError) else []
        state.update(status="failed", message=detail[0] if detail else str(exc))
        raise
    finally:
        record(state)


if __name__ == "__main__":
    os.umask(0o077)
    staging = Path(__file__).resolve().parent
    try:
        install(staging, *sys.argv[1:])
    finally:
        if staging.parent == Path("/run") and staging.name.startswith("vpnguard-release-"):
            shutil.rmtree(staging)
