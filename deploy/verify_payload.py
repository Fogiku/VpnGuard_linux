#!/usr/bin/env python3
"""Verify installation payload without executing its contents."""
import hashlib
import json
from pathlib import Path
import sys

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def verify(root):
    root = Path(root).resolve()
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    for name, expected in manifest.items():
        p = root / name
        if Path(name).is_absolute() or ".." in Path(name).parts or not p.resolve().is_relative_to(root) or p.is_symlink():
            raise ValueError("Unsafe payload path")
        if not p.is_file() or sha256(p) != expected:
            raise ValueError("Payload checksum mismatch: " + name)

if __name__ == "__main__":
    verify(sys.argv[1])
