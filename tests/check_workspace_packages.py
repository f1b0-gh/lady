"""Verify all release archives and the non-Ladybom packages outside the checkout."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]
NAMES = {
    "ladybom", "ladybom-graph", "ladybom-cli", "ladyshell",
    "ladyshell-cli", "ladyboot", "ladyhost",
}
CONSUMERS = ("ladyshell", "ladyshell-cli", "ladyboot", "ladyhost")


def run(*args, cwd=ROOT, capture=False):
    print(f"{cwd}$ {shlex.join(map(str, args))}", flush=True)
    return subprocess.run(
        list(map(str, args)), cwd=cwd, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


def registry_inputs(path):
    with path.open("rb") as stream:
        lock = tomllib.load(stream)
    return {
        (p["name"], p["version"], p["source"], p["checksum"])
        for p in lock["package"] if "source" in p and p["name"] not in NAMES
    }


def archives(target, scratch):
    metadata = json.loads(run(
        "cargo", "metadata", "--offline", "--locked", "--no-deps",
        "--format-version", "1", capture=True,
    ))
    members = {p["name"]: p for p in metadata["packages"]}
    assert set(members) == NAMES, set(members)
    run("cargo", "package", "--workspace", "--offline", "--locked", "--allow-dirty", "--no-verify")
    expected_inputs = registry_inputs(ROOT / "Cargo.lock")
    packages, receipts = {}, {}
    for name, metadata in sorted(members.items()):
        version = metadata["version"]
        source = Path(metadata["manifest_path"]).parent
        archive = target / "package" / f"{name}-{version}.crate"
        with tarfile.open(archive) as stream:
            for entry in stream.getmembers():
                parts = Path(entry.name).parts
                assert parts[0] == f"{name}-{version}", entry.name
                assert not {".local", ".git", ".jj", "target", ".aws", ".codex"} & set(parts), entry.name
                assert entry.isfile() or entry.isdir(), entry.name
            stream.extractall(scratch, filter="data")
        package = scratch / f"{name}-{version}"
        # Cargo archives carry old, reproducible mtimes. A shared target can
        # otherwise reuse a test binary with CARGO_MANIFEST_DIR pointing at a
        # previous, deleted extraction. Fresh mtimes invalidate that artifact
        # without changing package bytes or clearing the dependency cache.
        for extracted in package.rglob("*"):
            if extracted.is_file():
                os.utime(extracted, None)
        packages[name] = package
        assert (package / "Cargo.toml.orig").read_bytes() == Path(metadata["manifest_path"]).read_bytes()
        assert (package / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
        expected_license = "Apache-2.0 AND MIT" if name in {"ladyshell", "ladyshell-cli"} else "Apache-2.0"
        assert metadata["license"] == expected_license, (name, metadata["license"])
        assert registry_inputs(package / "Cargo.lock") <= expected_inputs, name
        for original in (source / "src").rglob("*"):
            if original.is_file():
                assert (package / original.relative_to(source)).read_bytes() == original.read_bytes(), original
        for shipped in package.rglob("*"):
            if not shipped.is_file():
                continue
            relative = shipped.relative_to(package)
            if str(relative) in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
                continue
            assert shipped.read_bytes() == (source / relative).read_bytes(), relative
        receipts[name] = {
            "version": version,
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "bytes": archive.stat().st_size,
            "registry_inputs": len(registry_inputs(package / "Cargo.lock")),
        }
    for name, relative in (
        ("ladyshell", "src/audit/validator/LICENSE-MIT"),
        ("ladyshell-cli", "LICENSE-MIT"),
    ):
        assert (packages[name] / relative).read_bytes() == (ROOT / "LICENSE-MIT").read_bytes()
    method = packages["ladyshell"] / "resources/audit/security-audit"
    for name in ("RECONNAISSANCE.md", "HUNTING.md", "VALIDATION-AND-REPORTING.md", "ATTACK-CLASSES.md", "report-schema.json"):
        assert (method / name).is_file(), name
    assert (packages["ladyshell"] / "resources/audit/provenance.json").is_file()
    for name in ("flake.nix", "flake.lock", "profiles/base.ncl", "nix/build.nix", "nix/image.nix", "profiles/schema.ncl"):
        assert (packages["ladyboot"] / name).is_file(), name
    return packages, receipts


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled; remove -O and unset PYTHONOPTIMIZE.")
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    os.environ["CARGO_TARGET_DIR"] = str(target)
    os.environ["CARGO_NET_OFFLINE"] = "true"
    temporary = Path("/tmp/lady")
    temporary.mkdir(exist_ok=True)
    assert not temporary.is_symlink() and temporary.stat().st_uid == os.getuid()
    with tempfile.TemporaryDirectory(prefix="workspace-packages-", dir=temporary) as directory:
        scratch = Path(directory)
        (scratch / "tmp").mkdir()
        os.environ["TMPDIR"] = str(scratch / "tmp")
        packages, receipts = archives(target, scratch)
        inputs = {p: p.read_bytes() for package in packages.values() for p in (package / "Cargo.toml", package / "Cargo.lock")}
        # Unpublished dependencies are resolved to their unmodified archives.
        # Cargo's staging verifier cannot yet resolve their checksums reliably.
        members = ", ".join(json.dumps(p.name) for p in packages.values())
        patches = "\n".join(f'{name} = {{ path = "{packages[name].name}" }}' for name in ("ladybom", "ladybom-graph", "ladyshell"))
        (scratch / "Cargo.toml").write_text(f'[workspace]\nmembers = [{members}]\nresolver = "2"\n\n[patch.crates-io]\n{patches}\n')
        shutil.copyfile(ROOT / "Cargo.lock", scratch / "Cargo.lock")
        run("cargo", "metadata", "--offline", "--all-features", "--format-version", "1", cwd=scratch, capture=True)
        assert registry_inputs(scratch / "Cargo.lock") == registry_inputs(ROOT / "Cargo.lock")
        selectors = [part for name in CONSUMERS for part in ("-p", name)]
        libraries = [part for name in CONSUMERS if name != "ladyshell-cli" for part in ("-p", name)]
        run("cargo", "test", "--offline", "--locked", "--all-features", *libraries, cwd=scratch)
        # The remaining CLI integration tests require the full versioned recipe
        # checkout and run in the source CI job before this archive gate.
        run("cargo", "test", "--offline", "--locked", "-p", "ladyshell-cli", "--test", "audit_validator_cli", cwd=scratch)
        run("cargo", "check", "--offline", "--locked", "-p", "ladyboot", "--no-default-features", cwd=scratch)
        run("cargo", "build", "--offline", "--locked", "--bins", *selectors, cwd=scratch)
        home = scratch / "empty-home"
        home.mkdir()
        env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home), "PATH": ""}
        for binary, argument in (("ladyshell", "--help"), ("audit-validator", "--version"), ("ladyboot", "--version"), ("ladyhost", "help")):
            subprocess.run([str(target / "debug" / binary), argument], cwd=scratch, env=env, check=True, stdout=subprocess.PIPE, text=True)
        compatibility = subprocess.run([str(target / "debug/ladyhost-jjpr")], cwd=scratch, env=env, capture_output=True, text=True)
        assert compatibility.returncode == 1 and "usage" in compatibility.stderr.lower(), compatibility
        for path, original in inputs.items():
            assert path.read_bytes() == original, path
        (target / "package/workspace-packages.json").write_text(json.dumps(receipts, indent=2) + "\n")
        print(json.dumps(receipts, indent=2))
    print("Archive builds and local fixture tests passed; native deployments and live forge operations were not performed.")


if __name__ == "__main__":
    main()
