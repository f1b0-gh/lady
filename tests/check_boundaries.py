"""Verify Cargo dependency boundaries between Lady components."""

import argparse
import json
from pathlib import Path
import subprocess


def graph(manifest, no_default_features=False, all_features=False):
    command = ["cargo", "metadata", "--offline", "--locked", "--format-version=1", "--manifest-path", str(manifest)]
    if no_default_features:
        command.append("--no-default-features")
    if all_features:
        command.append("--all-features")
    result = subprocess.run(
        command,
        check=True, text=True, capture_output=True, timeout=60,
    )
    data = json.loads(result.stdout)
    packages = {package["id"]: package for package in data["packages"]}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}

    def dependencies(name, normal_only=False):
        roots = [key for key, package in packages.items() if package["name"] == name]
        assert len(roots) == 1, (name, roots)
        edge_kinds = {None} if normal_only else {None, "build"}
        pending = roots[:]
        seen = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            for dep in nodes[key]["deps"]:
                kinds = {kind["kind"] for kind in dep["dep_kinds"]}
                if kinds & edge_kinds:
                    pending.append(dep["pkg"])
        return {packages[key]["name"] for key in seen}

    return dependencies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootc", type=Path, required=True)
    parser.add_argument("--k8s", type=Path)
    parser.add_argument("--tf", type=Path)
    parser.add_argument("--plane", type=Path)
    args = parser.parse_args()
    lady = graph(Path(__file__).resolve().parents[1] / "Cargo.toml", no_default_features=True)
    common = lady("nickel-util")
    domains = {"ladybom", "ladybom-graph", "ladybom-cli", "ladyshell", "ladyshell-cli", "ladyboot", "nickel-plane", "nickel-k8s", "nickel-tf", "audit-validator"}
    assert not common & (domains | {"clap"}), f"Domain dependencies in core: {common}"
    crates = Path(__file__).resolve().parents[1] / "crates"
    graph_packages = {"ladybom-graph", "parquet"}
    assert not graph_packages & lady("ladybom", normal_only=True)
    analysis = lady("ladybom")
    analysis_normal = graph(crates / "ladybom/Cargo.toml", all_features=True)("ladybom", normal_only=True)
    assert not graph_packages & analysis_normal
    minimal = graph(crates / "ladybom-cli/Cargo.toml", no_default_features=True)("ladybom-cli", normal_only=True)
    full = graph(crates / "ladybom-cli/Cargo.toml")("ladybom-cli", normal_only=True)
    assert not graph_packages & minimal
    assert graph_packages <= full
    extension = graph(crates / "ladybom-graph/Cargo.toml")("ladybom-graph", normal_only=True)
    assert {"ladybom", "parquet"} <= extension
    assert not extension & {"clap", "openshell", "ladyshell", "ladyshell-cli", "ladyboot", "ladyhost"}
    for closure in (analysis, analysis_normal):
        assert "nickel-util" in closure
        assert not closure & {"clap", "ladyshell", "ladyshell-cli", "ladyboot", "audit-validator"}
    application = lady("ladyshell")
    assert not {name for name in application if name.startswith(("lo-", "lo_"))}, "Application dependencies in Ladyshell"
    assert not graph_packages & lady("ladyshell", normal_only=True)
    assert {"nickel-util", "ladybom"} <= application
    assert not application & {"clap", "ladyboot", "nickel-plane", "nickel-k8s", "nickel-tf", "audit-validator"}, "Audit validation belongs to Ladyshell"
    bootc = graph(args.bootc.resolve() / "Cargo.toml", no_default_features=True)("ladyboot")
    assert "nickel-util" in bootc
    assert not bootc & {"clap", "ladyshell", "ladyshell-cli", "ladybom", "audit-validator", "nickel-plane", "nickel-k8s", "nickel-tf"}
    result = {"core": sorted(common), "analysis": sorted(analysis), "analysis-normal": sorted(analysis_normal), "graph": sorted(extension), "minimal-cli": sorted(minimal), "full-cli": sorted(full), "openshell": sorted(application), "bootc": sorted(bootc)}
    if args.k8s:
        k8s = graph(args.k8s.resolve() / "Cargo.toml", no_default_features=True)("nickel-k8s")
        assert "nickel-util" in k8s
        assert not k8s & {"nickel-plane", "clap", "ladyshell", "ladyshell", "audit-validator", "ladyboot", "nickel-tf"}
        result["k8s-library"] = sorted(k8s)
    if args.tf:
        tf = graph(args.tf.resolve() / "Cargo.toml", no_default_features=True)("nickel-tf")
        assert "nickel-util" in tf
        assert not tf & {"nickel-plane", "clap", "ladyshell", "ladyshell", "audit-validator", "ladyboot", "nickel-k8s"}
        result["tf-library"] = sorted(tf)
    if args.plane:
        plane = graph(args.plane.resolve() / "Cargo.toml", no_default_features=True)("nickel-plane")
        assert "nickel-util" in plane
        assert not plane & {"clap", "ureq", "nickel-k8s", "nickel-tf", "ladyshell", "ladyshell", "libladyshell"}
        complete = graph(args.plane.resolve() / "Cargo.toml")("nickel-plane")
        assert {"nickel-util", "nickel-k8s", "nickel-tf"} <= complete
        result["plane-core"] = sorted(plane)
        result["plane-adapters"] = sorted(complete)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
