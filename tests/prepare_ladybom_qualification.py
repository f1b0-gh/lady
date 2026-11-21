#!/usr/bin/env python3
"""Prepare synthetic inputs for the explicit Docker qualification, without network."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import uuid

from check_ladybom_interop import read, references, validators

DATE = "2026-11-05T12:00:00Z"
FIXTURE = Path(__file__).parent / "fixtures" / "interop" / "qualification" / "project"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ladybom", type=Path, default=Path("target/debug/ladybom"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    executable = args.ladybom.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    refusals = []

    def run(*arguments, code=0):
        result = subprocess.run([str(executable), *map(str, arguments)], capture_output=True, timeout=30)
        if result.returncode != code:
            raise ValueError(f"Ladybom: exit code {result.returncode}, expected {code}: {result.stderr.decode()}")
        if code != 0:
            if result.stdout:
                raise ValueError("Expected refusal without a partial document on stdout")
            refusals.append({"arguments": list(map(str, arguments)), "exit_code": code,
                             "diagnostic": result.stderr.decode()})
        return result.stdout

    def write(name, value):
        (output / name).write_text(json.dumps(value, indent=2) + "\n")

    scoped = output / "scoped-project"
    shutil.copytree(FIXTURE, scoped)
    lock = read(scoped / "package-lock.json")
    lock["packages"]["node_modules/interop-right"]["dependencies"]["interop-leaf"] = "2.0.0"
    lock["packages"]["node_modules/interop-right/node_modules/interop-leaf"] = {
        "version": "2.0.0", "resolved": "https://registry.npmjs.org/interop-leaf/-/interop-leaf-2.0.0.tgz",
    }
    (scoped / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
    duplicate = output / "duplicate-project"
    for name in ["first", "second"]:
        shutil.copytree(FIXTURE, duplicate / name)
    for prefix, project in [("scoped", scoped), ("duplicate", duplicate)]:
        for flag, suffix in [("--json", "report.json"), ("--cyclonedx", "sbom.cdx.json")]:
            (output / f"{prefix}-{suffix}").write_bytes(run("scan", "--project", project, flag))
    for ecosystem in ["cargo", "uv"]:
        project = output / f"{ecosystem}-project"
        shutil.copytree(FIXTURE.parent / ecosystem, project)
        for flag, suffix in [("--json", "report.json"), ("--cyclonedx", "sbom.cdx.json")]:
            (output / f"{ecosystem}-{suffix}").write_bytes(run("scan", "--project", project, flag))
    corrected = output / "corrected-project"
    shutil.copytree(scoped, corrected)
    fixed_lock = read(corrected / "package-lock.json")
    fixed_lock["packages"]["node_modules/interop-left"]["dependencies"]["interop-leaf"] = "3.0.0"
    fixed_lock["packages"]["node_modules/interop-leaf"]["version"] = "3.0.0"
    fixed_lock["packages"]["node_modules/interop-leaf"]["resolved"] = "https://registry.npmjs.org/interop-leaf/-/interop-leaf-3.0.0.tgz"
    (corrected / "package-lock.json").write_text(json.dumps(fixed_lock, indent=2) + "\n")
    for flag, suffix in [("--json", "report.json"), ("--cyclonedx", "sbom.cdx.json")]:
        (output / f"corrected-{suffix}").write_bytes(run("scan", "--project", corrected, flag))
    write("internal-osv.json", {
        "schema_version": "1.6.0", "id": "LADYBOM-SYNTHETIC", "modified": DATE, "published": DATE,
        "affected": [{"package": {"ecosystem": "npm", "name": "interop-leaf"}, "versions": ["1.0.0", "2.0.0"]}],
    })
    run("vuln", "import", "--input", output / "internal-osv.json", "--source", "INTERNAL",
        "--fetched-at", DATE, "--ecosystem", "npm", "--complete", "--output", output / "internal-snapshot.json")
    inputs = ["--report", output / "scoped-report.json", "--snapshot", output / "internal-snapshot.json"]
    assessment = json.loads(run("vuln", "assess", *inputs, "--as-of", DATE))
    write("scoped-assessment.json", assessment)
    if len(assessment["findings"]) != 2:
        raise ValueError("Two synthetic findings expected")
    for state in ["in_triage", "exploitable", "not_affected", "false_positive", "resolved"]:
        decisions = []
        for finding in assessment["findings"]:
            effective = state if finding["version"] == "1.0.0" else "exploitable"
            decisions.append({
                "finding_id": finding["id"], "state": effective,
                "justification": "code_not_reachable" if effective == "not_affected" else None,
                "detail": "Synthetic interoperability test only; no real vulnerability assessment.",
                "author": "ladybom-synthetic-qualification",
                "evidence": ["synthetic-fixture:no-exploitation-claim"],
                "issued_at": DATE, "expires_at": "2026-11-06T12:00:00Z",
            })
        write(f"decisions-{state}.json", {
            "schema_version": 1, "report_digest": assessment["report_digest"],
            "snapshot_digest": assessment["snapshot_digest"], "decisions": decisions,
        })
        document = run("vuln", "vex", *inputs, "--as-of", DATE, "--profile", "local-components",
                       "--decisions", output / f"decisions-{state}.json", code=2 if state == "resolved" else 0)
        if state != "resolved":
            (output / f"scoped-vex-{state}.cdx.json").write_bytes(document)
    expired = run("vuln", "vex", *inputs, "--as-of", "2026-11-07T12:00:00Z", "--profile", "local-components",
                  "--decisions", output / "decisions-not_affected.json")
    (output / "scoped-vex-expired.cdx.json").write_bytes(expired)
    conflicting = read(output / "decisions-not_affected.json")
    contradictory = dict(conflicting["decisions"][0])
    contradictory["state"] = "false_positive"
    conflicting["decisions"].append(contradictory)
    write("decisions-conflicting.json", conflicting)
    run("vuln", "vex", *inputs, "--as-of", DATE, "--profile", "local-components",
        "--decisions", output / "decisions-conflicting.json", code=2)
    corrected_inputs = ["--report", output / "corrected-report.json", "--snapshot", output / "internal-snapshot.json"]
    corrected_assessment = json.loads(run("vuln", "assess", *corrected_inputs, "--as-of", DATE))
    write("corrected-assessment.json", corrected_assessment)
    if [finding["version"] for finding in corrected_assessment["findings"]] != ["2.0.0"]:
        raise ValueError("Corrected component 3.0.0 must no longer match the synthetic advisory")
    run("vuln", "vex", *corrected_inputs, "--as-of", DATE, "--profile", "local-components",
        "--decisions", output / "decisions-not_affected.json", code=2)
    run("vuln", "vex", "--report", output / "duplicate-report.json", "--snapshot", output / "internal-snapshot.json",
        "--as-of", DATE, "--profile", "local-components", code=2)
    write("local-refusals.json", refusals)
    run("interop", "bundle", "--report", output / "duplicate-report.json",
        "--repository", "https://example.invalid/ladybom-synthetic/" + uuid.uuid4().hex,
        "--revision", "synthetic-fixture-revision", "--target-profile", "static-all-platforms",
        "--output", output / "duplicate-bundle")
    check = validators()["cyclonedx"]
    for path in output.glob("*.cdx.json"):
        value = read(path)
        check.validate(value)
        references(value)
    print(f"Synthetic fixtures prepared and validated: {output}")


if __name__ == "__main__":
    main()
