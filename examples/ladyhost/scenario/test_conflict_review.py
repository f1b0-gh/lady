"""The host supplies conflict observations and check selection; agents supply prose."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).parents[1]))
from conflict_review import package
from handoff import RESOLUTION_INSTRUCTION, extract_report

class PackageTests(unittest.TestCase):
    def test_host_observations_and_check_coverage_are_not_taken_from_agent_prose(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);export=root/'export';export.mkdir()
            for file in (export/'manifest.json',export/'checks.json',root/'policy.json'):file.write_text('{}')
            context=dict(repository='owner/project',target='main',change_id='change',original_base='1'*40,previous_head='2'*40,upstream_head='3'*40,
                         task_intent='Accuracy',upstream_intent='Starting value',conflict_paths=['metrics.py'],
                         independent_checks=[dict(command_index=1,covers=['task','upstream','interaction'],purpose='Combined behavior')])
            report=dict(schema_version=2,resolution=dict(decisions=[dict(path='metrics.py',resolution='Both',preserved=['iterators'],changed=['buffering'])],uncertainties=['Not benchmarked']),
                        independent_checks=['Agent claims success'],upstream_head='0'*40)
            result=package(context,report,export,root/'policy.json','4'*40)
            self.assertEqual(result['independent_checks'],context['independent_checks'])
            self.assertEqual(result['upstream_head'],context['upstream_head'])
            self.assertEqual(result['uncertainties'],['Not benchmarked'])
            self.assertEqual(len(result['checks']['sha256']),64)
            report['resolution']['decisions'][0]['path']='other.py'
            with self.assertRaises(RuntimeError):package(context,report,export,root/'policy.json','4'*40)
    def test_conflict_instruction_requires_decisions_and_excludes_agent_authority(self):
        for phrase in ('schema_version (2)','resolution object','uncertainties','host supplies those'):
            self.assertIn(phrase,RESOLUTION_INSTRUCTION)

if __name__=='__main__':unittest.main()
