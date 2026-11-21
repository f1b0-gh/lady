"""Exercise real jj history; JJPR_TEST_JJ selects the qualified local binary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NativeRestackTests(unittest.TestCase):
    def test_rewrite_conflict_refusal_and_resolved_signed_history(self):
        jj = os.environ.get('JJPR_TEST_JJ')
        if not jj:
            self.skipTest('set JJPR_TEST_JJ to run the native jj qualification')
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'trial'
            result = subprocess.run([
                sys.executable, str(Path(__file__).parents[1] / 'restack_conflict.py'),
                '--state', str(state), '--jj', jj,
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            evidence = json.loads((state / 'result.json').read_text())
            self.assertEqual(evidence['model_runs'], 0)
            self.assertEqual(evidence['signed_commit_count'], 6)
            self.assertEqual(evidence['final_checks'], 'passed')
            self.assertEqual(evidence['main_before'], evidence['main_after'])
            for before, after in zip(evidence['rewrite']['before'], evidence['rewrite']['after']):
                self.assertEqual(before['change_id'], after['change_id'])
                self.assertNotEqual(before['oid'], after['oid'])
            refusal = evidence['conflict_refusal']
            self.assertNotEqual(refusal['exit_code'], 0)
            self.assertEqual(refusal['refs_before'], refusal['refs_after'])
            self.assertIn('conflict', refusal['stderr'].lower())
            ancestor = evidence['ancestor_refusal']
            self.assertEqual(ancestor['parent']['conflict'], 'true')
            self.assertEqual(ancestor['child']['conflict'], 'false')
            self.assertNotEqual(ancestor['exit_code'], 0)
            self.assertIn(ancestor['parent']['oid'][:12], ancestor['stderr'])
            self.assertEqual(ancestor['refs_before'], ancestor['refs_after'])
            self.assertEqual([item['conflict'] for item in evidence['resolution_restack']],
                             ['false', 'true'])
            self.assertEqual(evidence['final_change_ids'], evidence['original_change_ids'])
            # Existing evidence is never silently overwritten or replayed.
            again = subprocess.run([
                sys.executable, str(Path(__file__).parents[1] / 'restack_conflict.py'),
                '--state', str(state), '--jj', jj,
            ], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(json.loads((state / 'result.json').read_text()), evidence)


if __name__ == '__main__':
    unittest.main()
