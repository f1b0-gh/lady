"""Offline regressions for semantic assertions used by explicit server tests."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from qualify_dependency_track import component_identity, graph_projection, finding_states
from qualify_dependency_track_extended import public_bundle_artifact, analysis_response, synthetic_aliases


class QualificationAssertions(unittest.TestCase):
    def test_synthetic_aliases_do_not_join_advisories_from_different_runs(self):
        first = synthetic_aliases("first-run")
        second = synthetic_aliases("second-run")
        self.assertEqual(first, synthetic_aliases("first-run"))
        for key in first:
            self.assertNotEqual(first[key], second[key])
        self.assertRegex(first["cveId"], r"^CVE-2099-[0-9]{4,}$")
        self.assertRegex(first["ghsaId"], r"^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$")

    def test_only_explicit_no_analysis_404_is_accepted_as_initial_state(self):
        self.assertEqual(analysis_response("No analysis exists.", 404, allow_absent=True),
                         {"analysis_absent": True, "http_status": 404})
        for response, allowed in [("No analysis exists.", False), ("The component does not exist", True)]:
            with self.assertRaises(ValueError):
                analysis_response(response, 404, allow_absent=allowed)

    def document(self):
        return {
            "metadata": {"component": {"bom-ref": "root"}},
            "components": [
                {"bom-ref": "local", "type": "library", "name": "workspace", "version": "1.0.0"},
                {"bom-ref": "public", "type": "library", "name": "leaf", "version": "1.0.0", "purl": "pkg:cargo/leaf@1.0.0"},
            ],
            "dependencies": [{"ref": "root", "dependsOn": ["local"]}, {"ref": "local", "dependsOn": ["public"]}],
        }

    def test_graph_preserves_local_components_without_fabricating_purls(self):
        doc = self.document()
        edges, _ = graph_projection(doc)
        local = component_identity(doc["components"][0])
        self.assertIn(("@declared-project", local), edges)
        self.assertIn((local, "pkg:cargo/leaf@1.0.0"), edges)

    def test_graph_refuses_ambiguous_consumer_identity(self):
        doc = self.document()
        duplicate = copy.deepcopy(doc["components"][1])
        duplicate["bom-ref"] = "second-occurrence"
        doc["components"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "ambigu"):
            graph_projection(doc)

    def test_vex_state_keys_include_source_and_component_not_only_version(self):
        doc = self.document()
        doc["vulnerabilities"] = [{
            "id": "TEST", "source": {"name": "INTERNAL"},
            "analysis": {"state": "not_affected"}, "affects": [{"ref": "public"}],
        }, {
            "id": "TEST", "source": {"name": "GITHUB"},
            "analysis": {"state": "exploitable"}, "affects": [{"ref": "local"}],
        }]
        states = finding_states(doc)
        self.assertEqual(len(states), 2)
        self.assertEqual(states[("INTERNAL", "TEST", "pkg:cargo/leaf@1.0.0")], "not_affected")

    def test_duplicate_vex_state_cannot_be_silently_overwritten(self):
        doc = self.document()
        finding = {"id": "TEST", "source": {"name": "INTERNAL"},
                   "analysis": {"state": "not_affected"}, "affects": [{"ref": "public"}]}
        doc["vulnerabilities"] = [finding, copy.deepcopy(finding)]
        with self.assertRaisesRegex(ValueError, "dupliqu"):
            finding_states(doc)

    def test_bundle_upload_reads_only_digest_verified_public_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "public").mkdir()
            data = b'{"synthetic":true}'
            (root / "public" / "part.json").write_bytes(data)
            descriptor = {"path": "public/part.json", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            self.assertEqual(public_bundle_artifact(root, descriptor), json.loads(data))
            for mutation in [{"path": "private/part.json"}, {"path": "public/../part.json"}, {"sha256": "0" * 64}, {"bytes": 0}]:
                with self.assertRaises(ValueError):
                    public_bundle_artifact(root, {**descriptor, **mutation})


if __name__ == "__main__":
    unittest.main()
