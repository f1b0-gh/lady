"""Extended explicit, synthetic server scenarios; never imported by the scanner.

All projects and custom advisories are new. No deletion requests are sent;
BOM replacement may remove obsolete component records, which is measured.
External VEX fixtures test consumer behavior and are never represented as
Ladybom decisions or as verified real vulnerabilities.
"""
import copy
import hashlib
import json
from pathlib import Path
import urllib.parse
import uuid

from check_ladybom_interop import compare, read, references, unique_pairs
from qualify_dependency_track import component_identity, finding_states, graph_projection


def synthetic_aliases(seed):
    digest = hashlib.sha256(seed.encode()).digest()
    alphabet = "23456789cfghjmpqrvwx"
    ghsa = "".join(alphabet[byte % len(alphabet)] for byte in digest[:12])
    return {"cveId": "CVE-2099-" + str(int.from_bytes(digest[:12], "big")),
            "ghsaId": "GHSA-" + "-".join(ghsa[index:index + 4] for index in (0, 4, 8)),
            "osvId": "OSV-LADYBOM-SYNTHETIC-" + digest.hex()[:24]}


def analysis_response(response, status, allow_absent=False):
    if status == 404 and allow_absent and response == "No analysis exists.":
        return {"analysis_absent": True, "http_status": 404}
    if status != 200 or not isinstance(response, dict):
        raise ValueError("Analyse serveur absente ou invalide hors état initial explicitement vérifié")
    return response


def public_bundle_artifact(root, descriptor):
    path = Path(descriptor["path"])
    if len(path.parts) != 2 or path.parts[0] != "public" or path.name in (".", ".."):
        raise ValueError("Seuls les artefacts publics explicites peuvent être publiés")
    full = root / path
    if full.is_symlink() or full.parent.is_symlink():
        raise ValueError("Lien symbolique d’artefact refusé")
    with full.open("rb") as stream:
        data = stream.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024 or len(data) != descriptor["bytes"] or hashlib.sha256(data).hexdigest() != descriptor["sha256"]:
        raise ValueError("Empreinte ou longueur de l’artefact divergente")
    return json.loads(data, object_pairs_hook=unique_pairs)


def coverage_readback(source, actual):
    actual_by_id = {component_identity(c): c for c in actual["components"]}
    coverage = []
    for component in source["components"]:
        properties = {p["name"]: p["value"] for p in component.get("properties", []) if p["name"].startswith("ladybom:coverage")}
        if not properties or "ladybom:coverage:sha256" not in properties:
            raise ValueError("Recompiler Ladybom : les propriétés publiques de couverture sont absentes")
        observed = {p["name"]: p["value"] for p in actual_by_id[component_identity(component)].get("properties", [])}
        if any(observed.get(key) != value for key, value in properties.items()):
            raise ValueError("Perte des propriétés de couverture répliquées sur les composants")
        coverage.append({"component": component_identity(component), "properties": properties})
    return coverage


def external_vex(sbom, advisory, states, source="INTERNAL", aliases=()):
    components = [copy.deepcopy(c) for c in sbom["components"] if c.get("purl") in states]
    if len(components) != len(states):
        raise ValueError("Composants de la fixture VEX absents ou ambigus")
    findings = []
    for component in components:
        finding = {
            "bom-ref": "assertion:" + component["bom-ref"], "id": advisory,
            "source": {"name": source}, "affects": [{"ref": component["bom-ref"]}],
            "analysis": {"state": states[component["purl"]],
                         "detail": "Synthetic consumer-behavior fixture; no real vulnerability assertion."},
        }
        if finding["analysis"]["state"] == "not_affected":
            finding["analysis"]["justification"] = "code_not_reachable"
        if aliases:
            finding["references"] = list(aliases)
        findings.append(finding)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": components, "vulnerabilities": findings,
        "properties": [{"name": "ladybom:qualification:fixture", "value": "external consumer-behavior fixture, not a Ladybom decision"}],
    }


def document_identity(document):
    """Content-derived UUIDv8 for external fixtures, excluding only their serial."""
    unsigned = {key: value for key, value in document.items() if key != "serialNumber"}
    digest = bytearray(hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).digest()[:16])
    digest[6] = (digest[6] & 15) | 128
    digest[8] = (digest[8] & 63) | 128
    document["serialNumber"] = "urn:uuid:" + str(uuid.UUID(bytes=bytes(digest)))
    return document


def qualify_extended(api, inputs, check):
    def save(name, value):
        (api.output / name).write_text(json.dumps(value, indent=2) + "\n")
        return value

    def validate(document):
        check.validate(document)
        references(document)

    def read_bom(project):
        document = api.call("GET", f"/api/v1/bom/cyclonedx/project/{project['uuid']}?format=JSON&version=1.5")
        validate(document)
        return document

    def read_vex(project):
        document = api.call("GET", f"/api/v1/vex/cyclonedx/project/{project['uuid']}?version=1.5")
        validate(document)
        return document

    def components(project):
        rows = api.call("GET", f"/api/v1/component/project/{project['uuid']}?pageSize=1000")
        if not isinstance(rows, list) or len(rows) >= 1000:
            raise ValueError("Pagination de composants non qualifiée")
        return rows

    def new_project(label, document):
        validate(document)
        save(f"input-{label}.cdx.json", document)
        project = api.call("PUT", "/api/v1/project", {
            "name": "ladybom-inventory", "version": f"synthetic-{label}-{uuid.uuid4().hex}",
            "classifier": "APPLICATION", "description": "Ladybom extended synthetic qualification; preserve this project",
        })
        uuid.UUID(project["uuid"])
        api.upload("bom", project["uuid"], document)
        return project

    def upload_vex(label, project, document):
        document_identity(document)
        validate(document)
        save(f"input-vex-{label}.cdx.json", document)
        api.upload("vex", project["uuid"], document)
        return save(f"downloaded-vex-{label}.cdx.json", read_vex(project))

    def advisory(label, aliases=()):
        identifier = "LADYBOM-SYNTHETIC-" + label.upper() + "-" + uuid.uuid4().hex
        record = api.call("PUT", "/api/v1/vulnerability", {
            "vulnId": identifier, "source": "INTERNAL", "title": "Ladybom synthetic interoperability test",
            "description": "Synthetic test only, no real vulnerability. Retain as qualification evidence.",
            "severity": "LOW", "aliases": list(aliases),
        }, allowed=(201,))
        if record.get("source") != "INTERNAL" or record.get("vulnId") != identifier:
            raise ValueError("Avis synthétique créé sous une identité inattendue")
        return record

    def associate(project, vulnerability, purls):
        rows = components(project)
        targets = [row for row in rows if row.get("purl") in purls]
        if len(targets) != len(purls):
            raise ValueError("Périmètre synthétique d’association ambigu")
        for component in targets:
            api.call("POST", f"/api/v1/vulnerability/{vulnerability['uuid']}/component/{component['uuid']}")
        return targets

    def analysis(project, component, vulnerability, allow_absent=False):
        query = urllib.parse.urlencode({"project": project["uuid"], "component": component["uuid"], "vulnerability": vulnerability["uuid"]})
        response = api.call("GET", "/api/v1/analysis?" + query, allowed=(200, 404) if allow_absent else (200,))
        return analysis_response(response, api.receipts[-1]["status"], allow_absent)

    def state_for(document, vulnerability, purl):
        return finding_states(document).get(("INTERNAL", vulnerability["vulnId"], purl))

    version = api.call("GET", "/api/version")
    if version.get("version") != "5.2.1":
        raise ValueError("Version serveur différente de 5.2.1")
    result = {"qualification": "partial", "server_version": version, "inventories": {}, "projects": [],
              "limitations": ["Synthetic fixtures only; no real vulnerability or runtime activation established.",
                              "External consumer-behavior VEX fixtures are distinct from Ladybom exports.",
                              "No automatic expiration or cross-authority advisory feed synchronization is inferred."]}

    bundle_root = inputs / "duplicate-bundle"
    bundle = read(bundle_root / "manifest.json")
    save("partition-bundle-manifest.json", bundle)
    if len(bundle["partitions"]) != 2:
        raise ValueError("Deux partitions de verrous attendues dans le dossier synthétique")
    partition_results = []
    for index, partition in enumerate(bundle["partitions"]):
        source = public_bundle_artifact(bundle_root, partition["sbom"])
        coverage = public_bundle_artifact(bundle_root, partition["coverage"])
        validate(source)
        save(f"input-partition-{index}.cdx.json", source)
        save(f"input-partition-{index}.coverage.json", coverage)
        project = api.call("PUT", "/api/v1/project", {
            "name": partition["project_name"], "version": partition["project_version"],
            "classifier": "APPLICATION", "description": "Ladybom synthetic partition bundle qualification",
        })
        result["projects"].append(project["uuid"])
        api.upload("bom", project["uuid"], source)
        actual = save(f"downloaded-partition-{index}.cdx.json", read_bom(project))
        expected = sorted(component_identity(c) for c in source["components"])
        observed = sorted(component_identity(c) for c in actual["components"])
        if expected != observed or len(observed) != 3 or graph_projection(source)[0] != graph_projection(actual)[0]:
            raise ValueError("Composants ou relations d’une partition perdus")
        if actual["metadata"]["component"]["name"] != partition["project_name"] or actual["metadata"]["component"].get("version") != partition["project_version"]:
            raise ValueError("Identité projet/version différente du manifeste du dossier")
        partition_results.append({"partition_id": partition["partition_id"], "project": project["uuid"],
                                  "project_name": project["name"], "project_version": project["version"],
                                  "input_components": len(expected), "stored_components": len(observed),
                                  "component_identities": observed, "positive_relations_preserved": True,
                                  "coverage_properties_preserved": coverage_readback(source, actual)})
    result["partitioned_independent_locks"] = {"partitions": partition_results,
                                              "six_occurrences_preserved_in_two_projects": sum(p["stored_components"] for p in partition_results) == 6,
                                              "private_artifacts_uploaded": False}

    # Retain the exact native refusals and assessment of the corrected fixture.
    for name in ["local-refusals.json", "scoped-assessment.json", "corrected-assessment.json"]:
        save(name, read(inputs / name))
    for ecosystem in ["cargo", "uv", "scoped"]:
        source = read(inputs / f"{ecosystem}-sbom.cdx.json")
        project = new_project(ecosystem, source)
        result["projects"].append(project["uuid"])
        actual = save(f"downloaded-{ecosystem}.cdx.json", read_bom(project))
        expected_ids = sorted(component_identity(c) for c in source["components"])
        actual_ids = sorted(component_identity(c) for c in actual["components"])
        if expected_ids != actual_ids:
            raise ValueError(f"Composants {ecosystem} différents après import")
        expected_edges, expected_empty = graph_projection(source)
        actual_edges, actual_empty = graph_projection(actual)
        if expected_edges != actual_edges:
            raise ValueError(f"Relations {ecosystem} différentes après correspondance racine/projet")
        coverage = coverage_readback(source, actual)
        result["inventories"][ecosystem] = {
            "project": project["uuid"], "components_preserved": True, "positive_relations_preserved": True,
            "positive_edge_count": len(expected_edges), "coverage_properties_preserved": coverage,
            "server_added_empty_entries": sorted(actual_empty - expected_empty), "comparison": compare(source, actual),
        }

    # Every following scenario gets a dedicated project, preserving earlier evidence.
    source = read(inputs / "scoped-sbom.cdx.json")
    leaf1, leaf2, leaf3 = (f"pkg:npm/interop-leaf@{n}.0.0" for n in (1, 2, 3))
    original = new_project("lifecycle-original", source)
    migrated = new_project("lifecycle-other-project", source)
    result["projects"].extend([original["uuid"], migrated["uuid"]])
    vulnerability = advisory("lifecycle")
    original_components = associate(original, vulnerability, {leaf1, leaf2})
    migrated_components = associate(migrated, vulnerability, {leaf1, leaf2})
    scoped_vex = external_vex(source, vulnerability["vulnId"], {leaf1: "not_affected", leaf2: "exploitable"})
    observed = upload_vex("original-scope", original, scoped_vex)
    if state_for(observed, vulnerability, leaf1) != "not_affected" or state_for(observed, vulnerability, leaf2) != "exploitable":
        raise ValueError("Portée de décision originale divergente")
    other_before = save("downloaded-vex-other-before.cdx.json", read_vex(migrated))
    initial_findings = finding_states(other_before)
    for purl in [leaf1, leaf2]:
        if ("INTERNAL", vulnerability["vulnId"], purl) not in initial_findings:
            raise ValueError("Finding initial absent : absence d’analyse non qualifiable")
    before = [analysis(migrated, c, vulnerability, allow_absent=True) for c in migrated_components]
    if any(row.get("analysisState") not in (None, "NOT_SET") or row.get("isSuppressed") is True for row in before):
        raise ValueError("Décision propagée implicitement au second projet")
    same_document = upload_vex("explicit-cross-project", migrated, copy.deepcopy(scoped_vex))
    transferred = state_for(same_document, vulnerability, leaf1) == "not_affected"
    result["project_scope"] = {
        "original": original["uuid"], "other": migrated["uuid"], "no_implicit_propagation": True,
        "explicit_old_document_applies_to_other_project": transferred,
        "before": before, "after": [analysis(migrated, c, vulnerability) for c in migrated_components],
        "requires_operator_project_binding": transferred,
    }

    # Contradictory external entries test the consumer; Ladybom rejects these locally.
    conflict = external_vex(source, vulnerability["vulnId"], {leaf1: "not_affected", leaf2: "exploitable"})
    extra = copy.deepcopy(next(f for f in conflict["vulnerabilities"] if f["analysis"]["state"] == "not_affected"))
    extra["bom-ref"] += ":contradictory"
    extra["analysis"] = {"state": "exploitable", "detail": "Deliberately contradictory synthetic external assertion"}
    conflict["vulnerabilities"].append(extra)
    conflict_observed = upload_vex("conflict-order-one", original, conflict)
    reversed_conflict = copy.deepcopy(conflict)
    reversed_conflict["vulnerabilities"].reverse()
    reverse_observed = upload_vex("conflict-order-two", original, reversed_conflict)
    result["external_contradictions"] = {
        "local_refusal_recorded": True, "consumer_order_one": state_for(conflict_observed, vulnerability, leaf1),
        "consumer_order_two": state_for(reverse_observed, vulnerability, leaf1),
        "consumer_conflict_resolution_is_not_an_approved_decision": True,
    }

    # Replace only this newly-created project's BOM. Keep a separate fixed project too.
    fixed = read(inputs / "corrected-sbom.cdx.json")
    save("input-version-replacement.cdx.json", fixed)
    api.upload("bom", original["uuid"], fixed)
    replaced = save("downloaded-version-replacement.cdx.json", read_bom(original))
    replaced_ids = {c.get("purl") for c in replaced["components"]}
    if leaf1 in replaced_ids or leaf3 not in replaced_ids:
        raise ValueError("Remplacement de version non enregistré")
    api.upload("vex", original["uuid"], copy.deepcopy(scoped_vex))
    after_stale = save("downloaded-vex-after-stale-version.cdx.json", read_vex(original))
    if state_for(after_stale, vulnerability, leaf3) == "not_affected":
        raise ValueError("Ancienne décision propagée à la nouvelle version")
    result["version_replacement"] = {
        "project": original["uuid"], "old_component_removed_from_current_sbom": True,
        "old_decision_not_transferred_to_new_version": True,
        "history_retention": "Previous BOM inputs, API results and analysis trails remain in this evidence directory; server retention is reported separately.",
        "old_component_uuids": [c["uuid"] for c in original_components if c.get("purl") == leaf1],
    }
    retained = []
    for component in original_components:
        if component.get("purl") == leaf1:
            record = api.call("GET", f"/api/v1/component/{component['uuid']}", allowed=(200, 404))
            retained.append({"component": component["uuid"], "lookup_status": api.receipts[-1]["status"],
                             "still_retrievable": api.receipts[-1]["status"] == 200})
    result["version_replacement"]["old_component_retention"] = retained
    fixed_project = new_project("fixed-resolved", fixed)
    result["projects"].append(fixed_project["uuid"])
    fixed_components = associate(fixed_project, vulnerability, {leaf3, leaf2})
    resolved = external_vex(fixed, vulnerability["vulnId"], {leaf3: "resolved", leaf2: "exploitable"})
    for finding in resolved["vulnerabilities"]:
        if finding["analysis"]["state"] == "resolved":
            finding["analysis"]["detail"] = "Synthetic reviewed correction: fixture leaf version 3.0.0 is absent from the explicit affected versions [1.0.0, 2.0.0]. Historical association seeded only to exercise consumer RESOLVED. Not a Ladybom current-match decision."
    resolved_observed = upload_vex("resolved-corrected-version", fixed_project, resolved)
    if state_for(resolved_observed, vulnerability, leaf3) != "resolved" or state_for(resolved_observed, vulnerability, leaf2) != "exploitable":
        raise ValueError("État resolved ou portée du composant non corrigé divergents")
    result["resolved"] = {"project": fixed_project["uuid"], "fixture_kind": "external reviewed synthetic correction",
                          "ladybom_corrected_assessment": "corrected-assessment.json", "states_preserved": True,
                          "analysis": [analysis(fixed_project, c, vulnerability) for c in fixed_components]}

    # Known source versus wrong source, then explicit namespace aliases. The API
    # may not persist aliases for INTERNAL records: report the readback honestly.
    authorities = new_project("authority-aliases", source)
    result["projects"].append(authorities["uuid"])
    alias_values = synthetic_aliases(authorities["uuid"])
    rustsec_alias = "RUSTSEC-2099-LADYBOM-" + authorities["uuid"].replace("-", "")
    alias_vulnerability = advisory("aliases", [alias_values])
    alias_components = associate(authorities, alias_vulnerability, {leaf1})
    stored = api.call("GET", f"/api/v1/vulnerability/{alias_vulnerability['uuid']}")
    observations = []
    variants = [
        ("wrong-source", alias_vulnerability["vulnId"], "GITHUB", []),
        ("cve", alias_values["cveId"], "CVE", []),
        ("ghsa", alias_values["ghsaId"], "GITHUB", []),
        ("osv", alias_values["osvId"], "OSV", []),
        ("rustsec", rustsec_alias, "RUSTSEC", []),
        ("explicit-internal-reference", alias_values["ghsaId"], "GITHUB", [{"id": alias_vulnerability["vulnId"], "source": {"name": "INTERNAL"}}]),
        ("exact-internal", alias_vulnerability["vulnId"], "INTERNAL", [{"id": value, "source": {"name": namespace}} for value, namespace in [(alias_values["cveId"], "CVE"), (alias_values["ghsaId"], "GITHUB"), (alias_values["osvId"], "OSV"), (rustsec_alias, "RUSTSEC")]]),
    ]
    for label, identifier, namespace, aliases in variants:
        baseline = external_vex(source, alias_vulnerability["vulnId"], {leaf1: "in_triage"})
        upload_vex("alias-baseline-" + label, authorities, baseline)
        candidate = external_vex(source, identifier, {leaf1: "not_affected"}, source=namespace, aliases=aliases)
        observed = upload_vex("alias-" + label, authorities, candidate)
        trail = analysis(authorities, alias_components[0], alias_vulnerability)
        observations.append({"variant": label, "claimed_source": namespace, "claimed_id": identifier,
                             "stored_state": state_for(observed, alias_vulnerability, leaf1), "analysis": trail})
    if observations[-1]["stored_state"] != "not_affected":
        raise ValueError("La référence INTERNAL exacte ne retrouve pas son finding")
    result["authorities_and_aliases"] = {"project": authorities["uuid"], "requested_aliases": alias_values,
                                        "persisted_advisory": stored, "observations": observations,
                                        "cross_authority_equivalence_not_inferred": True}
    result["local_fail_closed_refusals"] = [entry["diagnostic"] for entry in read(inputs / "local-refusals.json")]
    result["preservation"] = "No project, advisory, container or volume deleted. All imported documents, readbacks and response digests retained."
    return result
