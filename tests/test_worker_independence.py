"""The shipped sandbox carrier must not select an application framework."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkerIndependence(unittest.TestCase):
    def test_worker_runtime_does_not_select_lo(self):
        forbidden = re.compile(r"lo-executor|lo-broker|lo_tasks|lo_executor|lo_promise")
        paths = list((ROOT / "crates/ladyshell/src").rglob("*.rs"))
        paths += list((ROOT / "nix").glob("broker*.nix"))
        found = [str(p.relative_to(ROOT)) for p in paths if forbidden.search(p.read_text())]
        self.assertEqual(found, [], "application-specific runtime coupling")

    def test_cargo_lock_has_no_lo_dependency(self):
        import tomllib
        packages = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        self.assertEqual([
            p["name"] for p in packages
            if p["name"].startswith(("lo-", "lo_"))
            or "github.com/f1b0-gh/lo." in p.get("source", "")
        ], [])


if __name__ == "__main__":
    unittest.main()
