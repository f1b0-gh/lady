#!/usr/bin/env python3
"""Explicit offline qualification helper; never contacts a server or resolves URLs."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import jsonschema

FIXTURES = Path(__file__).parent / "fixtures" / "interop"
MAX_BYTES = 64 * 1024 * 1024


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Clé JSON dupliquée : {key}")
        result[key] = value
    return result


def read(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("Document supérieur à 64 Mio")
    return json.loads(data, object_pairs_hook=unique_pairs)


def validators():
    manifest = read(FIXTURES / "manifest.json")
    store = {}
    schemas = {}
    for entry in manifest["resources"]:
        path = FIXTURES / entry["file"]
        if path.parent != FIXTURES:
            raise ValueError("Chemin de ressource invalide")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            raise ValueError(f"Empreinte divergente : {path.name}")
        if path.suffix != ".json":
            continue
        schema = read(path)
        schemas[path.name] = schema
        for uri in [schema.get("$id"), schema.get("id"), path.name,
                    "http://cyclonedx.org/schema/" + path.name,
                    "https://cyclonedx.org/schema/" + path.name]:
            if uri:
                store[uri] = schema

    formats = set()

    def required_formats(value):
        if isinstance(value, dict):
            if isinstance(value.get("format"), str):
                formats.add(value["format"])
            for child in value.values():
                required_formats(child)
        elif isinstance(value, list):
            for child in value:
                required_formats(child)

    for schema in schemas.values():
        required_formats(schema)
    checker = jsonschema.FormatChecker()
    missing = formats - set(checker.checkers)
    if missing:
        raise ValueError("Validation des formats indisponible : " + ", ".join(sorted(missing))
                         + "; utiliser les dépendances épinglées de tests/requirements-interop.txt")

    def unavailable(uri):
        raise ValueError(f"Résolution externe interdite : {uri}")

    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    registry = Registry(retrieve=unavailable).with_resources(
        (uri, Resource.from_contents(schema, default_specification=DRAFT7))
        for uri, schema in store.items()
    )
    result = {}
    for name, filename in [("cyclonedx", "bom-1.5.schema.json"),
                           ("vxdf", "vxdf-0.0.1.schema.json")]:
        schema = schemas[filename]
        cls = jsonschema.validators.validator_for(schema)
        cls.check_schema(schema)
        result[name] = cls(schema, registry=registry, format_checker=checker)
    return result


def references(document):
    refs = set()

    def visit(component):
        ref = component.get("bom-ref")
        if ref is not None:
            if ref in refs:
                raise ValueError(f"Référence dupliquée : {ref}")
            refs.add(ref)
        for child in component.get("components", []):
            visit(child)

    if document.get("metadata", {}).get("component"):
        visit(document["metadata"]["component"])
    for component in document.get("components", []):
        visit(component)
    for edge in document.get("dependencies", []):
        if edge["ref"] not in refs or any(ref not in refs for ref in edge.get("dependsOn", [])):
            raise ValueError("Relation vers un composant absent")
    for finding in document.get("vulnerabilities", []):
        for target in finding.get("affects", []):
            if target["ref"] not in refs and not target["ref"].startswith("urn:cdx:"):
                raise ValueError("VEX : référence locale absente")


def compare(expected, actual):
    """Conservative loss report from a server's downloaded CycloneDX SBOM.

    Server-assigned bom-ref values may change. Identity collisions are blocking,
    never resolved by arbitrary pairing. This does not attest server execution.
    """
    def identity(component):
        return tuple(component.get(field) for field in ["type", "group", "name", "version", "purl"])

    def index(document):
        def descendants(components):
            for component in components:
                yield component
                yield from descendants(component.get("components", []))

        components = list(document.get("components", []))
        root = document.get("metadata", {}).get("component")
        if root:
            components.append(root)
        by_identity, by_ref = {}, {}
        for component in descendants(components):
            key = identity(component)
            if key in by_identity:
                raise ValueError("Identité consommateur ambiguë ; séparer les inventaires")
            by_identity[key] = component
            if "bom-ref" in component:
                by_ref[component["bom-ref"]] = key
        return by_identity, by_ref

    left, left_refs = index(expected)
    right, right_refs = index(actual)
    losses = []
    if identity(expected.get("metadata", {}).get("component", {})) != identity(actual.get("metadata", {}).get("component", {})):
        losses.append("Racine applicative absente ou différente")
    if left.keys() != right.keys():
        losses.append("Composants, racine ou versions différents")
    for identity in left.keys() & right.keys():
        for field in ["hashes", "licenses", "externalReferences", "properties"]:
            canonical = lambda value: sorted(json.dumps(item, sort_keys=True) for item in value)
            if canonical(left[identity].get(field, [])) != canonical(right[identity].get(field, [])):
                losses.append(f"Métadonnées différentes : {identity!r} / {field}")

    def edges(document, refs):
        return {(refs[entry["ref"]], refs[target])
                for entry in document.get("dependencies", [])
                for target in entry.get("dependsOn", [])}

    if edges(expected, left_refs) != edges(actual, right_refs):
        losses.append("Relations différentes après import")
    for field in ["compositions", "properties"]:
        if expected.get(field) != actual.get(field):
            losses.append(f"Couverture ou diagnostics différents : {field}")
    if expected.get("vulnerabilities") or actual.get("vulnerabilities"):
        losses.append("Comparaison des décisions VEX non qualifiée par cet outil")
    return {"losses": losses, "equivalent_in_checked_scope": not losses,
            "server_qualification": "not_attested"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", choices=["cyclonedx", "vxdf"], default="cyclonedx")
    parser.add_argument("--compare", type=Path, help="SBOM relu depuis le serveur à comparer")
    parser.add_argument("documents", nargs="*", type=Path)
    args = parser.parse_args()
    checks = validators()
    if args.compare and (args.schema != "cyclonedx" or len(args.documents) != 1):
        parser.error("--compare exige un seul SBOM CycloneDX attendu")
    for path in args.documents + ([args.compare] if args.compare else []):
        value = read(path)
        checks[args.schema].validate(value)
        if args.schema == "cyclonedx":
            references(value)
        if args.schema == "cyclonedx":
            print(f"Schéma valide et références locales vérifiées : {path}")
        else:
            print(f"Schéma et formats VXDF valides ; références et preuves non qualifiées par ce contrôle : {path}")
        if args.schema == "cyclonedx" and any(
            target["ref"].startswith("urn:cdx:")
            for finding in value.get("vulnerabilities", [])
            for target in finding.get("affects", [])
        ):
            print("BOM-Link externes non résolus par ce contrôle.")
    if args.compare:
        result = compare(read(args.documents[0]), read(args.compare))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 2 if result["losses"] else 0
    print("Empreintes des schémas vérifiées ; aucun serveur contacté.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, RecursionError, jsonschema.exceptions.ValidationError) as error:
        print(f"Échec de validation : {error}", file=sys.stderr)
        sys.exit(2)
