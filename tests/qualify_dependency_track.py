#!/usr/bin/env python3
"""Explicit synthetic API qualification against the local pinned Docker server.

This script writes only to new synthetic projects and synthetic custom advisories. It never runs during scan,
does not execute project code, and retains responses without authentication data.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from check_ladybom_interop import compare, read, references, validators


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("API redirect rejected")


class Api:
    def __init__(self, credentials, output):
        path = Path(credentials)
        if path.stat().st_mode & 0o077:
            raise ValueError("Private authentication file required (0600)")
        auth = read(path)
        self.url = auth["base_url"].rstrip("/")
        url = urllib.parse.urlsplit(self.url)
        if url.scheme != "http" or url.hostname != "127.0.0.1" or url.port != 18081 or url.path or url.query or url.fragment or url.username:
            raise ValueError("This qualification requires http://127.0.0.1:18081")
        if auth.get("api_key"):
            self.auth = {"X-Api-Key": auth["api_key"]}
        else:
            self.auth = {"Authorization": "Bearer " + auth["bearer_token"]}
        self.output = output
        self.receipts = []
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, route, body=None, allowed=(200, 201, 204)):
        payload = None if body is None else json.dumps(body).encode()
        accept = "application/vnd.cyclonedx+json" if "/cyclonedx/" in route else "application/json"
        headers = {**self.auth, "Content-Type": "application/json", "Accept": accept}
        request = urllib.request.Request(self.url + route, data=payload, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(16 * 1024 * 1024 + 1)
            status = response.code
        if len(data) > 16 * 1024 * 1024:
            raise ValueError("API response too large")
        name = f"response-{len(self.receipts):03d}.json"
        (self.output / name).write_bytes(data)
        receipt = {"method": method, "route": route, "status": status,
                   "response_file": name, "response_sha256": hashlib.sha256(data).hexdigest()}
        if payload is not None:
            receipt["request_sha256"] = hashlib.sha256(payload).hexdigest()
        self.receipts.append(receipt)
        (self.output / "receipts.json").write_text(json.dumps(self.receipts, indent=2) + "\n")
        if status not in allowed:
            raise ValueError(f"API {method} {route} : HTTP {status}, voir {name}")
        if not data:
            return None
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return data.decode()

    def upload(self, kind, project, document):
        response = self.call("PUT", f"/api/v1/{kind}", {
            "project": project,
            kind: base64.b64encode(json.dumps(document).encode()).decode(),
        })
        token = response["token"]
        uuid.UUID(token)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = self.call("GET", f"/api/v1/bom/token/{token}")
            if state.get("processing") is False and state.get("status") == "COMPLETED":
                return token
            if state.get("status") == "FAILED":
                raise ValueError(f"{kind} import failed: {token}")
            time.sleep(1)
        raise ValueError(f"{kind} import incomplete after 180 s: {token}")


def component_identity(component):
    """Consumer identity for this fixture, without inventing a local-package PURL."""
    return component.get("purl") or "local:" + json.dumps(
        [component.get(field) for field in ["type", "group", "name", "version"]], separators=(",", ":"))


def graph_projection(document):
    root = document["metadata"]["component"]["bom-ref"]
    refs = {c["bom-ref"]: component_identity(c) for c in document["components"]}
    if len(set(refs.values())) != len(refs):
        raise ValueError("Ambiguous consumer identity in the graph")
    refs[root] = "@declared-project"
    edges = {(refs[e["ref"]], refs[target]) for e in document.get("dependencies", [])
             for target in e.get("dependsOn", [])}
    empty = {refs[e["ref"]] for e in document.get("dependencies", []) if not e.get("dependsOn")}
    return edges, empty


def finding_states(document):
    """Keep authority and component identity; never hide a duplicate decision."""
    by_ref = {c["bom-ref"]: component_identity(c) for c in document.get("components", [])}
    states = {}
    for finding in document.get("vulnerabilities", []):
        for target in finding.get("affects", []):
            key = (finding.get("source", {}).get("name"), finding["id"], by_ref[target["ref"]])
            if key in states:
                raise ValueError("Duplicate VEX decision in the server result")
            states[key] = finding.get("analysis", {}).get("state")
    return states


def vex_states(document):
    by_ref = {c["bom-ref"]: c for c in document.get("components", [])}
    states = {}
    for finding in document.get("vulnerabilities", []):
        if finding.get("id") != "LADYBOM-SYNTHETIC":
            continue
        for target in finding.get("affects", []):
            states[by_ref[target["ref"]]["version"]] = finding.get("analysis", {}).get("state")
    return states


def inverse_ancestors(edges, target):
    visited = set()
    pending = [target]
    while pending:
        child = pending.pop()
        for parent, dependency in edges:
            if dependency == child and parent not in visited:
                visited.add(parent)
                pending.append(parent)
    return sorted(visited)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--extended-only", action="store_true", help="New Cargo/uv scenarios, authorities, corrections and scope changes")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    api = Api(args.credentials, args.output)
    check = validators()["cyclonedx"]
    if args.extended_only:
        from qualify_dependency_track_extended import qualify_extended
        result = qualify_extended(api, args.inputs, check)
        (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"evidence": str(args.output), "qualification": result["qualification"]}))
        return
    source = read(args.inputs / "scoped-sbom.cdx.json")
    check.validate(source)
    references(source)
    (args.output / "input-sbom.cdx.json").write_text(json.dumps(source, indent=2) + "\n")
    version = api.call("GET", "/api/version")
    if not isinstance(version, dict) or version.get("version") != "5.2.1":
        raise ValueError("Server version differs from 5.2.1")
    project = api.call("PUT", "/api/v1/project", {
        "name": "ladybom-inventory", "version": "synthetic-" + uuid.uuid4().hex,
        "classifier": "APPLICATION", "description": "Ladybom isolated synthetic interoperability qualification",
    })
    project_id = project["uuid"]
    api.upload("bom", project_id, source)
    actual = api.call("GET", f"/api/v1/bom/cyclonedx/project/{project_id}?format=JSON&version=1.5")
    check.validate(actual)
    references(actual)
    (args.output / "downloaded-sbom.cdx.json").write_text(json.dumps(actual, indent=2) + "\n")
    comparison = compare(source, actual)
    components = api.call("GET", f"/api/v1/component/project/{project_id}?pageSize=1000")
    expected_purls = sorted(c["purl"] for c in source["components"])
    actual_purls = sorted(c["purl"] for c in components)
    if expected_purls != actual_purls:
        raise ValueError("Components read through the API differ from the SBOM")
    result = {"server_version": version, "project": project_id,
              "sbom_comparison": comparison, "component_purls_preserved": True,
              "vex_states": {}, "qualification": "partial"}
    expected_edges, expected_empty = graph_projection(source)
    actual_edges, actual_empty = graph_projection(actual)
    root = actual["metadata"]["component"]
    if root.get("name") != project["name"] or root.get("version") != project["version"]:
        raise ValueError("Root differs from the explicitly declared project/version")
    if expected_edges != actual_edges:
        raise ValueError("Positive relationships differ after root/project mapping")
    result["positive_relations_preserved_under_declared_project_mapping"] = True
    result["inverse_paths"] = {}
    for leaf in ["pkg:npm/interop-leaf@1.0.0", "pkg:npm/interop-leaf@2.0.0"]:
        parents = inverse_ancestors(actual_edges, leaf)
        if parents != inverse_ancestors(expected_edges, leaf) or "@declared-project" not in parents:
            raise ValueError("Reverse traversal mismatch")
        result["inverse_paths"][leaf] = parents
    result["root_project_mapping"] = {"name": root["name"], "version": root["version"]}
    result["server_added_empty_dependency_entries"] = sorted(actual_empty - expected_empty)

    # Import before creating the synthetic advisory: VEX must not invent findings.
    vex = read(args.inputs / "scoped-vex-not_affected.cdx.json")
    api.upload("vex", project_id, vex)
    absent = api.call("GET", f"/api/v1/vulnerability/project/{project_id}?suppressed=true")
    if absent:
        raise ValueError("Unexpected finding before synthetic advisory preparation")
    result["missing_finding_import_created_no_findings"] = True

    vulnerability = api.call("PUT", "/api/v1/vulnerability", {
        "vulnId": "LADYBOM-SYNTHETIC", "title": "Ladybom synthetic interoperability test",
        "description": "Synthetic only; does not describe a real vulnerability.", "severity": "LOW",
    }, allowed=(201, 409))
    if api.receipts[-1]["status"] == 409:
        vulnerability = api.call("GET", "/api/v1/vulnerability/source/INTERNAL/vuln/LADYBOM-SYNTHETIC")
    if vulnerability.get("title") != "Ladybom synthetic interoperability test":
        raise ValueError("Collision with an advisory outside the qualification scope")
    leaves = [c for c in components if c.get("name") == "interop-leaf"]
    if len(leaves) != 2:
        raise ValueError("Two synthetic versions expected")
    for component in leaves:
        api.call("POST", f"/api/v1/vulnerability/source/INTERNAL/vuln/LADYBOM-SYNTHETIC/component/{component['uuid']}")
    for state in ["in_triage", "exploitable", "not_affected", "false_positive", "not_affected"]:
        vex = read(args.inputs / f"scoped-vex-{state}.cdx.json")
        check.validate(vex)
        references(vex)
        (args.output / f"input-vex-{state}.cdx.json").write_text(json.dumps(vex, indent=2) + "\n")
        api.upload("vex", project_id, vex)
        observed = api.call("GET", f"/api/v1/vex/cyclonedx/project/{project_id}?version=1.5")
        check.validate(observed)
        references(observed)
        states = vex_states(observed)
        expected = {"1.0.0": state, "2.0.0": "exploitable"}
        if states != expected:
            raise ValueError(f"VEX scope/state mismatch: {states!r}, expected {expected!r}")
        analysis = {}
        for component in leaves:
            query = urllib.parse.urlencode({"project": project_id, "component": component["uuid"], "vulnerability": vulnerability["uuid"]})
            analysis[component["version"]] = api.call("GET", "/api/v1/analysis?" + query)
        result["vex_states"][state] = {"states": states, "analysis": analysis}
    result["reimport_preserves_scope"] = True
    expired = read(args.inputs / "scoped-vex-expired.cdx.json")
    check.validate(expired)
    references(expired)
    (args.output / "input-vex-expired.cdx.json").write_text(json.dumps(expired, indent=2) + "\n")
    api.upload("vex", project_id, expired)
    expired_actual = api.call("GET", f"/api/v1/vex/cyclonedx/project/{project_id}?version=1.5")
    if vex_states(expired_actual) != {"1.0.0": "in_triage", "2.0.0": "in_triage"}:
        raise ValueError("Explicit reimport of expired decisions does not restore in_triage")
    for component in leaves:
        query = urllib.parse.urlencode({"component": component["uuid"], "vulnerability": vulnerability["uuid"]})
        trail = api.call("GET", "/api/v1/analysis?" + query)
        if trail.get("isSuppressed") is not False:
            raise ValueError("Suppression retained after explicit in_triage reimport")
    result["explicit_expired_decision_reimport_clears_suppression"] = True
    duplicate = read(args.inputs / "duplicate-sbom.cdx.json")
    check.validate(duplicate)
    references(duplicate)
    (args.output / "input-duplicate-sbom.cdx.json").write_text(json.dumps(duplicate, indent=2) + "\n")
    duplicate_project = api.call("PUT", "/api/v1/project", {
        "name": "ladybom-inventory", "version": "duplicate-contexts-" + uuid.uuid4().hex,
        "classifier": "APPLICATION", "description": "Ladybom synthetic duplicate-context qualification",
    })
    api.upload("bom", duplicate_project["uuid"], duplicate)
    imported_duplicates = api.call("GET", f"/api/v1/component/project/{duplicate_project['uuid']}?pageSize=1000")
    result["duplicate_contexts"] = {
        "project": duplicate_project["uuid"],
        "input_occurrences": len(duplicate["components"]),
        "stored_components": len(imported_duplicates),
        "input_unique_purls": len({c["purl"] for c in duplicate["components"]}),
        "stored_unique_purls": len({c["purl"] for c in imported_duplicates}),
        "requires_separate_projects": len(imported_duplicates) != len(duplicate["components"]),
    }
    result["limitations"] = ["Only synthetic npm fixtures and INTERNAL findings exercised",
                             "No automatic expiration established; explicit reimport tested with a synthetic evaluation date",
                             "Resolved, project migration, version replacement and source merging not fully qualified",
                             "Metadata/coverage losses remain as listed; no vulnerability truth established"]
    (args.output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"project": project_id, "evidence": str(args.output), "qualification": "partial"}))


if __name__ == "__main__":
    main()
