"""Qualify the three Ladybom Cargo archives offline on Linux."""

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
PACKAGES = ("ladybom", "ladybom-graph", "ladybom-cli")
CRATES = ROOT / "crates"


def cargo(*args, cwd=ROOT, capture=False, env=None):
    command = ["cargo", args[0], "--offline", *map(str, args[1:])]
    print(f"{cwd}$ {shlex.join(command)}", flush=True)
    return subprocess.run(
        command, cwd=cwd, check=True, text=True, env=env,
        stdout=subprocess.PIPE if capture else None,
    ).stdout


def read_toml(path):
    with path.open("rb") as stream:
        return tomllib.load(stream)


def registry_inputs(lock, exclude=()):
    return {
        (p["name"], p["version"], p["source"], p["checksum"])
        for p in read_toml(lock)["package"]
        if "source" in p and p["name"] not in exclude
    }


def verify_assets(package, source):
    assets = [source / "README.md", source / "LICENSE"]
    for directory in (source / "schemas", source / "tests/fixtures"):
        assets.extend(sorted(path for path in directory.rglob("*") if path.is_file()))
    for path in assets:
        shipped = package / path.relative_to(source)
        assert shipped.read_bytes() == path.read_bytes(), shipped
    assert (package / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()
    if source.name == "ladybom":
        schema_dir = package / "schemas"
        provenance = json.loads((schema_dir / "manifest.json").read_text())
        for key in ("schema", "license"):
            content = (schema_dir / provenance[key]["file"]).read_bytes()
            assert hashlib.sha256(content).hexdigest() == provenance[key]["sha256"]


def extract_archives(target, scratch):
    names = [part for name in PACKAGES for part in ("-p", name)]
    # Cargo 1.99.1 verifies the core individually. Its multiple-package verifier
    # fails to look up an unpublished dependency's checksum in the staging registry.
    cargo("package", "--locked", "--allow-dirty", "-p", PACKAGES[0])
    cargo("package", "--locked", "--allow-dirty", "--no-verify", *names)
    packages = {}
    checksums = {}
    workspace_inputs = registry_inputs(ROOT / "Cargo.lock")
    for name in PACKAGES:
        source = CRATES / name
        version = read_toml(source / "Cargo.toml")["package"]["version"]
        name_version = f"{name}-{version}"
        archive = target / "package" / f"{name_version}.crate"
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        checksums[name] = (version, "registry+https://github.com/rust-lang/crates.io-index", checksum)
        print(f"Archive {archive.name} sha256 {checksum}", flush=True)
        with tarfile.open(archive) as stream:
            stream.extractall(scratch / name, filter="data")
        package = scratch / name / name_version
        packages[name] = package
        verify_assets(package, source)
        lock = package / "Cargo.lock"
        assert registry_inputs(lock, PACKAGES) <= workspace_inputs, lock
        for dependency, version, registry, digest in registry_inputs(lock):
            if dependency in checksums:
                assert (version, registry, digest) == checksums[dependency], lock

    cli_fixtures = packages["ladybom-cli"] / "tests/fixtures"
    core_fixtures = packages["ladybom"] / "tests/fixtures"
    for path in sorted(p for p in cli_fixtures.rglob("*") if p.is_file()):
        assert path.read_bytes() == (core_fixtures / path.relative_to(cli_fixtures)).read_bytes(), path
    return packages


def isolate(package, patches, *options):
    workspace = package.parent
    lines = ["[workspace]", f'members = ["{package.name}"]', 'resolver = "2"', "", "[patch.crates-io]"]
    for name, dependency in patches.items():
        lines.append(f"{name} = {{ path = {json.dumps(str(dependency))} }}")
    (workspace / "Cargo.toml").write_text("\n".join(lines) + "\n")
    archive_lock = package / "Cargo.lock"
    isolated_lock = workspace / "Cargo.lock"
    original = archive_lock.read_bytes()
    isolated_lock.write_bytes(original)
    cargo("metadata", "--format-version", "1", *options, cwd=workspace, capture=True)
    assert archive_lock.read_bytes() == original, archive_lock
    assert registry_inputs(isolated_lock) == registry_inputs(archive_lock, patches), isolated_lock


def prepare_minimal_install(scratch, target, core, graph, cli):
    # Cargo resolves the optional graph dependency for the lock, then prunes it
    # from the minimal install graph. Supply it from a directory source so the
    # lock can be resolved without an unused graph patch.
    stage = scratch / "staged-registry"
    shutil.copytree(target / "package/tmp-registry", stage)
    name, version, _, checksum = next(
        entry for entry in registry_inputs(cli / "Cargo.lock") if entry[0] == "ladybom-graph"
    )
    staged_archive = stage / f"{name}-{version}.crate"
    assert hashlib.sha256(staged_archive.read_bytes()).hexdigest() == checksum, staged_archive
    index = (stage / "index").as_uri()
    stage_config = scratch / "stage.toml"
    stage_config.write_text(
        f'[registries.staged]\nindex = "{index}"\n'
        f'[source.staged]\nregistry = "{index}"\nreplace-with = "native-staging"\n'
        f'[source.native-staging]\nlocal-registry = {json.dumps(str(stage))}\n'
    )
    inputs = scratch / "vendor-inputs"
    inputs.mkdir()
    (inputs / "empty.rs").touch()
    (inputs / "Cargo.toml").write_text(
        '[package]\nname = "qualification-inputs"\nversion = "0.0.0"\nedition = "2021"\n'
        '[lib]\npath = "empty.rs"\n'
        f'[dependencies]\n{name} = {{ version = "={version}", registry = "staged" }}\n'
        f'[patch.crates-io]\nladybom = {{ path = {json.dumps(str(core))} }}\n'
    )
    lock = inputs / "Cargo.lock"
    shutil.copyfile(graph / "Cargo.lock", lock)
    cargo("metadata", "--config", stage_config, "--format-version", "1", cwd=inputs, capture=True)
    expected = registry_inputs(graph / "Cargo.lock", ("ladybom",))
    expected.add((name, version, f"registry+{index}", checksum))
    assert registry_inputs(lock) == expected, lock

    vendor_config = scratch / "vendor.toml"
    vendor_config.write_text(cargo(
        "vendor", "--locked", "--respect-source-config", "--versioned-dirs", "--config", stage_config,
        "--sync", cli / "Cargo.toml", scratch / "vendor", cwd=inputs, capture=True,
    ))
    minimal = scratch / "minimal-source" / cli.name
    shutil.copytree(cli, minimal)
    isolate(minimal, {"ladybom": core}, "--config", vendor_config)
    return minimal, vendor_config


def closure(package, *features):
    metadata = json.loads(cargo(
        "metadata", "--locked", "--format-version", "1", *features, cwd=package, capture=True,
    ))
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {p["id"]: p for p in metadata["resolve"]["nodes"]}
    pending = [metadata["resolve"]["root"]]
    visited = set()
    result = {}
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        node = packages[key]
        result.setdefault(node["name"], set()).add(Path(node["manifest_path"]).parent)
        for dep in nodes[key]["deps"]:
            if any(kind["kind"] in (None, "build") for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    print(f"{package.name} {features} normal and build dependencies: {len(result)} names", flush=True)
    return result


def check_ladyshell(scratch, core):
    workspace = scratch / "admission"
    crates = workspace / "crates"
    consumer = crates / "ladyshell"
    (consumer / "tests").mkdir(parents=True)
    shutil.copytree(CRATES / "ladyshell/src", consumer / "src")
    shutil.copyfile(CRATES / "ladyshell/Cargo.toml", consumer / "Cargo.toml")
    shutil.copyfile(CRATES / "ladyshell/tests/ladybom_input.rs", consumer / "tests/ladybom_input.rs")
    shutil.copytree(CRATES / "ladyshell/resources", consumer / "resources")
    shutil.copytree(core, crates / "ladybom")
    # Preserve Ladyshell's declarations. Its existing relative path now selects
    # the unmodified archive source inside this disposable test workspace.
    manifest = (ROOT / "Cargo.toml").read_text()
    marker = "\n[workspace.dependencies]\n"
    _, separator, dependencies = manifest.partition(marker)
    assert separator and "\n[" not in dependencies
    (workspace / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["crates/ladyshell", "crates/ladybom"]\nresolver = "2"\n'
        + marker + dependencies
    )
    checkout_lock = ROOT / "Cargo.lock"
    isolated_lock = workspace / "Cargo.lock"
    shutil.copyfile(checkout_lock, isolated_lock)
    cargo("metadata", "--format-version", "1", cwd=workspace, capture=True)
    assert registry_inputs(isolated_lock) <= registry_inputs(checkout_lock), isolated_lock
    resolved = closure(consumer)
    assert resolved["ladybom"] == {crates / "ladybom"}
    assert not {"clap", "ladybom-graph", "parquet"} & resolved.keys()
    cargo("test", "--locked", "--test", "ladybom_input", cwd=consumer)


def check_scans(binaries, scratch):
    project = scratch / "sample-project"
    project.mkdir()
    empty_path = scratch / "empty-path"
    empty_path.mkdir()
    dependencies = {"sample-lib": "1.0.0"}
    manifest = {"name": "sample-project", "version": "1.0.0", "dependencies": dependencies}
    lock = {
        **manifest,
        "lockfileVersion": 3,
        "packages": {
            "": manifest,
            "node_modules/sample-lib": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/sample-lib/-/sample-lib-1.0.0.tgz",
            },
        },
    }
    (project / "package.json").write_text(json.dumps({
        **manifest, "scripts": {"preinstall": ": > NEVER_EXECUTE"},
    }))
    (project / "package-lock.json").write_text(json.dumps(lock))
    original = {p.name: p.read_bytes() for p in project.iterdir()}
    expected_purl = "pkg:npm/sample-lib@1.0.0"
    reports, boms = [], []
    for binary in binaries:
        def scan(option):
            command = [str(binary), "scan", "--project", str(project), option]
            print(f"{project}$ {shlex.join(command)} (empty PATH directory)", flush=True)
            return json.loads(subprocess.check_output(command, cwd=project, env={"PATH": str(empty_path)}))

        report = scan("--json")
        assert report["schema_version"] == 2 and report["complete"] is True, report
        assert any(p.get("purl") == expected_purl for p in report["projects"][0]["components"]), report
        bom = scan("--cyclonedx")
        assert (bom["bomFormat"], bom["specVersion"]) == ("CycloneDX", "1.5"), bom
        assert any(p.get("purl") == expected_purl for p in bom["components"]), bom
        reports.append(report)
        boms.append(bom)
    assert reports[0] == reports[1] and boms[0] == boms[1]
    assert {p.name: p.read_bytes() for p in project.iterdir()} == original


def main():
    if not __debug__:
        raise SystemExit("Run this check with assertions enabled by removing -O and unsetting PYTHONOPTIMIZE.")
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    os.environ["CARGO_TARGET_DIR"] = str(target)
    os.environ["CARGO_NET_OFFLINE"] = "true"
    with tempfile.TemporaryDirectory(prefix="ladybom-packages-", dir="/tmp") as temp:
        scratch = Path(temp)
        packages = extract_archives(target, scratch)
        core, graph, cli = (packages[name] for name in PACKAGES)
        archive_inputs = {
            path: path.read_bytes()
            for package in packages.values()
            for path in (package / "Cargo.toml", package / "Cargo.lock")
        }
        isolate(graph, {"ladybom": core})
        isolate(cli, {"ladybom": core, "ladybom-graph": graph})
        unavailable = {"openshell", "ladyshell", "ladyshell-cli", "ladyboot", "ladyhost"}
        persistence = {"ladybom-graph", "parquet"}
        assert not (unavailable | persistence | {"clap"}) & closure(core).keys()
        resolved_graph = closure(graph)
        assert not (unavailable | {"clap"}) & resolved_graph.keys()
        assert "parquet" in resolved_graph and resolved_graph["ladybom"] == {core}
        for package in (core, graph):
            cargo("test", "--locked", cwd=package)
        binaries = []
        for flavor, features in (("minimal", ("--no-default-features",)), ("default", ())):
            resolved = closure(cli, *features)
            assert resolved["ladybom"] == {core}
            assert "clap" in resolved
            assert not unavailable & resolved.keys()
            if features:
                assert not persistence & resolved.keys()
            else:
                assert persistence <= resolved.keys() and resolved["ladybom-graph"] == {graph}
            cargo("test", "--locked", *features, cwd=cli)
            install = scratch / flavor
            install_source, options = cli, ()
            if features:
                install_source, vendor_config = prepare_minimal_install(
                    scratch, target, core, graph, cli,
                )
                options = ("--config", vendor_config)
                install_closure = closure(install_source, *features, *options)
                assert install_closure.keys() == resolved.keys()
                assert install_closure["ladybom"] == {core}
            path = os.pathsep.join((str(install / "bin"), os.environ.get("PATH", os.defpath)))
            cargo(
                "install", "--locked", "--debug", "--path", install_source, "--root", install,
                *features, *options, cwd=scratch, env={**os.environ, "PATH": path},
            )
            for name in ("Cargo.toml", "Cargo.lock"):
                assert (install_source / name).read_bytes() == (cli / name).read_bytes()
            binaries.append(install / "bin/ladybom")
        check_scans(binaries, scratch)
        check_ladyshell(scratch, core)
        for path, before in archive_inputs.items():
            assert path.read_bytes() == before, path
    print("Native LadybugDB, live services and native artifact collectors were outside this check.")


if __name__ == "__main__":
    main()
