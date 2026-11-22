"""Build the release feed from a clean, tagged source checkout into a separate directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def release_changes(log, version):
    sections = re.split(r"^## ", log, flags=re.M)
    for section in sections[1:]:
        lines = section.splitlines()
        if lines and lines[0].split(" ", 1)[0] == version:
            changes = [line[2:].strip() for line in lines[1:] if line.startswith("- ")]
            if changes and all(changes):
                return changes
    raise ValueError(f"missing release notes for {version}")


def build(directory):
    repo = Path(__file__).resolve().parent.parent
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

    source = git("rev-parse", "HEAD")
    match = re.search(r'^const Version = "(\d+\.\d+(?:\.\d+)?)"$', (repo / "core.go").read_text(encoding="utf-8"), re.M)
    version = match.group(1)
    if git("rev-parse", f"v{version}^{{commit}}") != source or git("status", "--porcelain", "--untracked-files=normal"):
        raise RuntimeError("build from a clean checkout of the matching source tag")
    if directory.resolve().is_relative_to(repo):
        raise ValueError("choose an output directory outside the source checkout")
    directory.mkdir(parents=True, exist_ok=True)
    manifest = dict(version=version, source=source, sha256={}, helpers={},
                    changes=release_changes((repo / "CHANGELOG.md").read_text(encoding="utf-8"), version))
    for arch in ("amd64", "arm64"):
        binary = directory / ("vpnguard-linux-" + arch)
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOWORK="off")
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", binary.resolve(), "."],
                       cwd=repo, env=env, check=True)
        manifest["sha256"][arch] = hashlib.sha256(binary.read_bytes()).hexdigest()
    for name in ("guarded_update.py", "route_guard.py"):
        manifest["helpers"][name] = hashlib.sha256((repo / "deploy" / name).read_bytes()).hexdigest()
    data = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    if len(data) > 8192:
        raise ValueError("release manifest exceeds the updater limit")
    (directory / "manifest.json").write_bytes(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    build(parser.parse_args().directory)
