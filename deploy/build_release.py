"""Build the release feed from a clean, tagged source checkout into a separate directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def build(directory):
    repo = Path(__file__).resolve().parent.parent
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

    source = git("rev-parse", "HEAD")
    match = re.search(r'^const Version = "(\d+\.\d+(?:\.\d+)?)"$', (repo / "core.go").read_text(), re.M)
    version = match.group(1)
    if git("rev-parse", f"v{version}^{{commit}}") != source or git("status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("build from a clean checkout of the matching source tag")
    if directory.resolve().is_relative_to(repo):
        raise ValueError("choose an output directory outside the source checkout")
    directory.mkdir(parents=True, exist_ok=True)
    manifest = dict(version=version, source=source, sha256={}, helpers={})
    for arch in ("amd64", "arm64"):
        binary = directory / ("vpnguard-linux-" + arch)
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOWORK="off")
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", binary.resolve(), "."],
                       cwd=repo, env=env, check=True)
        manifest["sha256"][arch] = hashlib.sha256(binary.read_bytes()).hexdigest()
    for name in ("guarded_update.py", "route_guard.py"):
        manifest["helpers"][name] = hashlib.sha256((repo / "deploy" / name).read_bytes()).hexdigest()
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    build(parser.parse_args().directory)
