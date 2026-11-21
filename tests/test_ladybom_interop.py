"""Regression tests for the explicit offline qualification helper."""
import copy
import io
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response

from check_ladybom_interop import compare, references, validators


def bom():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "root"}},
        "components": [{"type": "library", "name": "package", "version": "1", "bom-ref": "a"}],
        "dependencies": [{"ref": "root", "dependsOn": ["a"]}],
    }


class InteropTests(unittest.TestCase):
    def test_missing_format_checker_is_a_blocking_validation_gap(self):
        import jsonschema
        supported = dict(jsonschema.FormatChecker.checkers)
        supported.pop("uri", None)
        with patch.object(jsonschema.FormatChecker, "checkers", supported):
            with self.assertRaisesRegex(ValueError, "formats"):
                validators()

    def test_pinned_schema_rejects_invalid_date_and_uri_formats(self):
        import jsonschema
        check = validators()["cyclonedx"]
        document = bom()
        document["metadata"]["timestamp"] = "not-a-date"
        with self.assertRaises(jsonschema.ValidationError):
            check.validate(document)
        document = bom()
        document["components"][0]["externalReferences"] = [{"type": "distribution", "url": "not a uri"}]
        with self.assertRaises(jsonschema.ValidationError):
            check.validate(document)

    def bootstrap_with_transport(self, transport, proxy=True):
        script = Path(__file__).parents[1] / "qualification" / "dependency-track" / "bootstrap-admin.py"
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
            "http_proxy": "http://proxy.example.invalid:8080" if proxy else "", "no_proxy": "",
        }, clear=True), patch.object(urllib.request, "_opener", None), patch.object(
            urllib.request.HTTPHandler, "http_open", transport,
        ), patch.object(sys, "argv", [str(script), "--credentials", str(Path(directory) / "private.json")]):
            runpy.run_path(str(script), run_name="__main__")

    def test_bootstrap_does_not_send_password_to_environment_proxy(self):
        hosts = []
        responses = []

        def transport(handler, request):
            hosts.append(request.host)
            response = urllib.response.addinfourl(io.BytesIO(b"synthetic-token"), {}, request.full_url, 200)
            response.msg = "OK"
            responses.append(response)
            self.addCleanup(response.close)
            return response

        self.bootstrap_with_transport(transport)
        self.assertEqual(hosts, ["127.0.0.1:18081", "127.0.0.1:18081"])
        self.assertTrue(all(response.closed for response in responses))

    def test_bootstrap_refuses_redirect_before_credentials_leave_loopback(self):
        responses = []

        def transport(handler, request):
            redirect = request.host.endswith("18081")
            headers = {"location": "http://elsewhere.example.invalid/login"} if redirect else {}
            response = urllib.response.addinfourl(io.BytesIO(b"synthetic-token"), headers, request.full_url, 302 if redirect else 200)
            response.msg = "Found" if redirect else "OK"
            responses.append(response)
            self.addCleanup(response.close)
            return response

        with self.assertRaises(ValueError):
            self.bootstrap_with_transport(transport, proxy=False)
        self.assertEqual(len(responses), 1)
        self.assertTrue(responses[0].closed)

    def test_bootstrap_closes_http_refusal_response(self):
        responses = []

        def transport(handler, request):
            response = urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, io.BytesIO(b"refused"))
            responses.append(response)
            self.addCleanup(response.close)
            raise response

        with self.assertRaisesRegex(SystemExit, "HTTP 403"):
            self.bootstrap_with_transport(transport, proxy=False)
        self.assertEqual(len(responses), 1)
        self.assertTrue(responses[0].closed)

    def test_added_nested_component_is_a_loss(self):
        expected = bom()
        actual = copy.deepcopy(expected)
        actual["components"][0]["components"] = [{"type": "library", "name": "extra", "version": "9"}]
        self.assertFalse(compare(expected, actual)["equivalent_in_checked_scope"])

    def test_changed_root_role_is_a_loss(self):
        expected = bom()
        actual = copy.deepcopy(expected)
        actual["metadata"]["component"], actual["components"][0] = (
            actual["components"][0], actual["metadata"]["component"])
        self.assertFalse(compare(expected, actual)["equivalent_in_checked_scope"])

    def test_server_reference_renaming_preserves_edges(self):
        expected = bom()
        actual = copy.deepcopy(expected)
        actual["components"][0]["bom-ref"] = "server-component"
        actual["metadata"]["component"]["bom-ref"] = "server-root"
        actual["dependencies"] = [{"ref": "server-root", "dependsOn": ["server-component"]}]
        self.assertTrue(compare(expected, actual)["equivalent_in_checked_scope"])

    def test_ambiguous_occurrences_cannot_be_matched(self):
        expected = bom()
        expected["components"].append({"type": "library", "name": "package", "version": "1", "bom-ref": "b"})
        with self.assertRaises(ValueError):
            compare(expected, expected)

    def test_schema_and_dangling_references_are_separate_checks(self):
        document = bom()
        validators()["cyclonedx"].validate(document)
        document["dependencies"][0]["dependsOn"] = ["missing"]
        validators()["cyclonedx"].validate(document)
        with self.assertRaises(ValueError):
            references(document)

    def test_nested_duplicate_reference_rejected(self):
        document = bom()
        document["components"][0]["components"] = [{"name": "nested", "bom-ref": "a"}]
        with self.assertRaises(ValueError):
            references(document)


if __name__ == "__main__":
    unittest.main()
