"""Offline regressions for the explicit stale-target consumer experiment."""
import copy
import unittest

from qualify_dependency_track_stale import check_current_local_targets


class StaleTargets(unittest.TestCase):
    def fixtures(self):
        component = {"bom-ref": "leaf", "name": "leaf", "version": "1.0.0", "purl": "pkg:npm/leaf@1.0.0"}
        return {"components": [component], "vulnerabilities": [{"id": "SYNTHETIC", "affects": [{"ref": "leaf"}]}]}, {"components": [copy.deepcopy(component)]}

    def test_removed_target_is_refused_before_any_upload(self):
        vex, current = self.fixtures()
        current["components"][0]["purl"] = "pkg:npm/leaf@3.0.0"
        current["components"][0]["version"] = "3.0.0"
        with self.assertRaisesRegex(ValueError, "absente"):
            check_current_local_targets(vex, current)

    def test_current_target_must_be_unique_and_identity_consistent(self):
        vex, current = self.fixtures()
        check_current_local_targets(vex, current)
        current["components"].append(copy.deepcopy(current["components"][0]))
        with self.assertRaises(ValueError):
            check_current_local_targets(vex, current)
        current["components"].pop()
        vex["components"][0]["version"] = "2.0.0"
        with self.assertRaises(ValueError):
            check_current_local_targets(vex, current)

    def test_unresolved_bom_link_is_not_a_local_target(self):
        vex, current = self.fixtures()
        vex["vulnerabilities"][0]["affects"][0]["ref"] = "urn:cdx:00000000-0000-4000-8000-000000000001/1#absent"
        with self.assertRaises(ValueError):
            check_current_local_targets(vex, current)


if __name__ == "__main__":
    unittest.main()
