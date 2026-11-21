#!/usr/bin/env python3
"""Explicit negative test: a stale local VEX must not affect a remaining component.

Uses a new synthetic project/advisory and preserves every response. The raw
consumer experiment deliberately imports a stale fixture AFTER demonstrating
its offline rejection. This is not a production upload command. Target presence
alone does not verify report, snapshot, project or reviewed decision scope.
"""
import argparse
import json
from pathlib import Path
import urllib.parse
import uuid

from check_ladybom_interop import read, references, validators
from qualify_dependency_track import Api, finding_states
from qualify_dependency_track_extended import document_identity, external_vex


def check_current_local_targets(vex, current):
    by_ref = {c["bom-ref"]: c for c in vex.get("components", [])}
    if len(by_ref) != len(vex.get("components", [])):
        raise ValueError("Ambiguous local reference")
    for finding in vex.get("vulnerabilities", []):
        for target in finding.get("affects", []):
            component = by_ref.get(target["ref"])
            if component is None or not component.get("purl"):
                raise ValueError("Local reference missing or lacking a qualified identity")
            matches = [c for c in current.get("components", []) if c.get("purl") == component["purl"]]
            if len(matches) != 1:
                raise ValueError("Local target missing or ambiguous in the current inventory")
            if any(matches[0].get(field) != component.get(field) for field in ("name", "version", "group")):
                raise ValueError("Local target identity mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, exist_ok=False)
    api = Api(args.credentials, args.output)
    check = validators()["cyclonedx"]

    def save(name, document):
        (args.output / name).write_text(json.dumps(document, indent=2) + "\n")
        return document

    def validate(document):
        check.validate(document)
        references(document)

    version = api.call("GET", "/api/version")
    if version.get("version") != "5.2.1":
        raise ValueError("Version differs from the qualified consumer")
    old = read(args.inputs / "scoped-sbom.cdx.json")
    fixed = read(args.inputs / "corrected-sbom.cdx.json")
    validate(old)
    validate(fixed)
    leaf1, leaf2, leaf3 = (f"pkg:npm/interop-leaf@{n}.0.0" for n in (1, 2, 3))
    fixed_purls = {c.get("purl") for c in fixed["components"]}
    if leaf1 in fixed_purls or not {leaf2, leaf3}.issubset(fixed_purls):
        raise ValueError("Corrected fixture differs from the expected scenario")
    save("input-current-sbom.cdx.json", fixed)
    project = api.call("PUT", "/api/v1/project", {
        "name": "ladybom-inventory", "version": "synthetic-stale-only-" + uuid.uuid4().hex,
        "classifier": "APPLICATION", "description": "Ladybom negative stale-target experiment; retain evidence",
    })
    api.upload("bom", project["uuid"], fixed)
    current = api.call("GET", f"/api/v1/bom/cyclonedx/project/{project['uuid']}?format=JSON&version=1.5")
    validate(current)
    save("downloaded-current-sbom.cdx.json", current)
    if {c.get("purl") for c in current["components"]} != fixed_purls:
        raise ValueError("Current inventory differs before the experiment")
    advisory = api.call("PUT", "/api/v1/vulnerability", {
        "vulnId": "LADYBOM-SYNTHETIC-STALE-" + uuid.uuid4().hex, "source": "INTERNAL",
        "title": "Synthetic stale-target qualification", "severity": "LOW",
        "description": "Synthetic negative consumer test only; no real vulnerability assertion.",
    }, allowed=(201,))
    rows = api.call("GET", f"/api/v1/component/project/{project['uuid']}?pageSize=1000")
    matched = [c for c in rows if c.get("purl") == leaf2]
    if len(matched) != 1:
        raise ValueError("Ambiguous synthetic affected target")
    component = matched[0]
    api.call("POST", f"/api/v1/vulnerability/{advisory['uuid']}/component/{component['uuid']}")
    baseline = document_identity(external_vex(fixed, advisory["vulnId"], {leaf2: "exploitable"}))
    validate(baseline)
    save("input-baseline-vex.cdx.json", baseline)
    api.upload("vex", project["uuid"], baseline)
    before = api.call("GET", f"/api/v1/vex/cyclonedx/project/{project['uuid']}?version=1.5")
    validate(before)
    save("downloaded-before.cdx.json", before)
    key = ("INTERNAL", advisory["vulnId"], leaf2)
    if finding_states(before).get(key) != "exploitable":
        raise ValueError("Exploitable baseline not applied")
    stale = document_identity(external_vex(old, advisory["vulnId"], {leaf1: "not_affected"}))
    validate(stale)
    save("input-stale-only-vex.cdx.json", stale)
    try:
        check_current_local_targets(stale, current)
    except ValueError as error:
        rejection = str(error)
    else:
        raise ValueError("Preflight check did not reject the stale target")
    # Deliberate raw negative experiment, scoped to this new synthetic project.
    api.upload("vex", project["uuid"], stale)
    after = api.call("GET", f"/api/v1/vex/cyclonedx/project/{project['uuid']}?version=1.5")
    validate(after)
    save("downloaded-after.cdx.json", after)
    states = finding_states(after)
    query = urllib.parse.urlencode({"project": project["uuid"], "component": component["uuid"], "vulnerability": advisory["uuid"]})
    trail = api.call("GET", "/api/v1/analysis?" + query)
    propagated = states.get(key) != "exploitable" or trail.get("isSuppressed") is not False
    created = ("INTERNAL", advisory["vulnId"], leaf3) in states
    result = {
        "qualification": "unsafe_consumer_behavior_observed" if propagated or created else "stale_target_ignored_in_tested_scope",
        "server_version": version, "project": project["uuid"], "advisory": advisory["vulnId"],
        "offline_target_preflight_rejected": True, "offline_rejection": rejection,
        "raw_stale_import_was_deliberate_negative_test": True,
        "unrelated_remaining_component_state": states.get(key), "analysis": trail,
        "stale_decision_propagated": propagated, "new_finding_created_for_corrected_version": created,
        "scope": "Only stale local occurrence1 asserted not_affected; remaining occurrence2 has no competing entry in that document.",
        "limitations": ["Target preflight is necessary but not a substitute for exact report/snapshot/project/decision verification.",
                        "No implicit cleanup; project, advisory, imports and responses preserved."],
    }
    save("summary.json", result)
    print(json.dumps({"evidence": str(args.output), "qualification": result["qualification"]}))
    return 2 if propagated or created else 0


if __name__ == "__main__":
    raise SystemExit(main())
