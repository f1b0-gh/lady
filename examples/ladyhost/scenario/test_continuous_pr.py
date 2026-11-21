"""Bound the live conflict scenario's allowed file changes."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).parents[1]))
from continuous_pr import validate_scope

class ConflictScopeTests(unittest.TestCase):
    def test_only_metrics_and_lane_test_may_change(self):
        before = {'metrics.py': {'sha256': 'old', 'executable': False},
                  '.github/workflows/ci.yml': {'sha256': 'workflow', 'executable': False}}
        after = dict(before, **{'metrics.py': {'sha256': 'new', 'executable': False},
                               'tests/test_start.py': {'sha256': 'test', 'executable': False}})
        validate_scope(before, after, 'start')
        for path in ('.github/workflows/ci.yml', 'tests/test_accuracy.py', 'other.py'):
            bad = dict(after, **{path: {'sha256': 'bad', 'executable': False}})
            with self.assertRaises(RuntimeError):
                validate_scope(before, bad, 'start')
        bad = dict(after); del bad['metrics.py']
        with self.assertRaises(RuntimeError): validate_scope(before, bad, 'start')
        bad = dict(after); bad['metrics.py'] = {'sha256': 'new', 'executable': True}
        with self.assertRaises(RuntimeError): validate_scope(before, bad, 'start')

if __name__ == '__main__': unittest.main()
