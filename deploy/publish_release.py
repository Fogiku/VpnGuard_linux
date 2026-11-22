"""Validate a release branch in isolation. --publish promotes the checked commits."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode
from urllib.request import urlopen

REPO = "Fogiku/VpnGuard_linux"
URL = f"https://github.com/{REPO}.git"
API = f"https://api.github.com/repos/{REPO}/actions/workflows/linux-release-checks.yml/runs"


def git(directory, *args):
    return subprocess.check_output(["git", *args], cwd=directory, text=True).strip()


def wait_checks(branch, sha):
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        query = urlencode(dict(branch=branch, event="push", head_sha=sha, per_page=1,
                               t=int(time.time())))
        with urlopen(API + "?" + query, timeout=20) as response:
            runs = json.load(response)["workflow_runs"]
        if runs and runs[0]["head_sha"] == sha and runs[0]["status"] == "completed":
            if runs[0]["conclusion"] != "success":
                raise RuntimeError(f"release checks failed: {runs[0]['html_url']}")
            print("CI:", runs[0]["html_url"], flush=True)
            return
        time.sleep(30)
    raise RuntimeError("release checks did not complete within 20 minutes")


def promote(source, version, sha, binary_sha, publish):
    refs = [sha + ":refs/heads/main", binary_sha + ":refs/heads/releases",
            "refs/tags/v" + version, "refs/tags/bin-v" + version]
    git(source, "push", "--atomic", *([] if publish else ["--dry-run"]), "origin", *refs)


def prepare(branch, version, sha, publish):
    wait_checks(branch, sha)
    with tempfile.TemporaryDirectory(prefix="vpnguard-release-", ignore_cleanup_errors=True) as tmp:
        root = Path(tmp)
        git(root, "-c", "core.autocrlf=false", "clone", "--quiet", "--filter=blob:none", "--no-checkout", URL, "source")
        source, binaries = root / "source", root / "binaries"
        git(source, "config", "core.autocrlf", "false")
        if git(source, "rev-parse", "origin/" + branch) != sha:
            raise RuntimeError("candidate branch changed since this checkout")
        git(source, "merge-base", "--is-ancestor", "origin/main", sha)
        previous = json.loads(git(source, "show", "origin/releases:manifest.json"))["version"]
        if tuple(map(int, previous.split("."))) >= tuple(map(int, version.split("."))):
            raise RuntimeError("version already published or superseded")
        git(source, "checkout", "--detach", "--quiet", sha)
        git(source, "tag", "v" + version, sha)
        git(source, "worktree", "add", "--quiet", "--detach", str(binaries), "origin/releases")
        subprocess.run([sys.executable, "-X", "utf8", str(source / "deploy/build_release.py"),
                        str(binaries)], cwd=source, check=True)
        manifest = json.loads((binaries / "manifest.json").read_bytes())
        if manifest["source"] != sha or manifest["version"] != version or not manifest["changes"]:
            raise RuntimeError("manifest does not describe candidate")
        files = ["manifest.json"]
        for arch in ("amd64", "arm64"):
            name = "vpnguard-linux-" + arch
            if hashlib.sha256((binaries / name).read_bytes()).hexdigest() != manifest["sha256"][arch]:
                raise RuntimeError(f"invalid {arch} checksum")
            files.append(name)
        for name in ("guarded_update.py", "route_guard.py"):
            if hashlib.sha256((source / "deploy" / name).read_bytes()).hexdigest() != manifest["helpers"][name]:
                raise RuntimeError(f"invalid helper checksum: {name}")
        git(binaries, "add", "--", *files)
        git(binaries, "-c", "user.name=VpnGuard Release", "-c", "user.email=release@localhost",
            "commit", "-m", "Publish VpnGuard Linux " + version)
        binary_sha = git(binaries, "rev-parse", "HEAD")
        git(source, "tag", "bin-v" + version, binary_sha)
        promote(source, version, sha, binary_sha, publish)
        print("Published" if publish else "Dry run passed", version, sha, binary_sha, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("branch", help="Pushed release/* candidate branch for the current HEAD")
    parser.add_argument("--publish", action="store_true", help="Publish both branches and tags atomically")
    args = parser.parse_args()
    if not args.branch.startswith("release/"):
        parser.error("expected a release/* branch")
    repo = Path(__file__).resolve().parent.parent
    git(repo, "check-ref-format", "--branch", args.branch)
    sha = git(repo, "rev-parse", "HEAD")
    version = re.search(r'^const Version = "([0-9]+\.[0-9]+\.[0-9]+)"$',
                        git(repo, "show", "HEAD:core.go"), re.M).group(1)
    prepare(args.branch, version, sha, args.publish)
