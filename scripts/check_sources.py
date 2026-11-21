#!/usr/bin/env python3
"""Verify the bundled Nickeling source against its committed source lock (offline)."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


def check(root: Path) -> None:
    lock = json.loads((root / "sources/nickeling.json").read_text())
    if lock["schema_version"] != 1 or not re.fullmatch(r"[0-9a-f]{40}", lock["revision"]):
        raise ValueError("Expected source lock v1 and a complete Git commit")
    if lock["repository"] != "https://github.com/f1b0-gh/nickeling":
        raise ValueError("Unexpected Nickeling repository")
    if lock["bundled_path"] != "vendor/nickel-util":
        raise ValueError("Unexpected bundle location")
    bundle = root / lock["bundled_path"]
    if bundle.is_symlink() or bundle.parent.is_symlink():
        raise ValueError("Source bundle must not be a symlink")
    actual = {}
    for path in sorted(bundle.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Symlink in source bundle: {path}")
        if path.is_file():
            actual[path.relative_to(bundle).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        elif not path.is_dir():
            raise ValueError(f"Non-regular source entry: {path}")
    if actual != lock["files_sha256"]:
        changed = sorted(key for key in actual.keys() | lock["files_sha256"].keys()
                         if actual.get(key) != lock["files_sha256"].get(key))
        raise ValueError(f"Source files missing, added or changed: {', '.join(changed)}")
    if "LICENSE" not in actual or "Cargo.toml" not in actual or "src/lib.rs" not in actual:
        raise ValueError("Incomplete source bundle")
    package = tomllib.loads((bundle / "Cargo.toml").read_text())["package"]
    if (package["name"], package["version"]) != (lock["package"], lock["version"]):
        raise ValueError("Package identity differs from the source lock")
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    dependency = workspace["workspace"]["dependencies"]["nickel-util"]
    if dependency != {"path": lock["bundled_path"], "version": "=" + lock["version"]}:
        raise ValueError("Workspace dependency differs from the source lock")
    print(f"Verified {len(actual)} files: {lock['package']} {lock['version']} at {lock['revision']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        check(args.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Source verification failed: {error}", file=sys.stderr)
        sys.exit(1)
