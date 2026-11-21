"""Agent explanations are bounded, provenance-bound data, never verification authority."""
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]))
import handoff


class HandoffTests(unittest.TestCase):
    def events(self, message):
        return ('\n'.join(json.dumps(v) for v in [
            {'type':'item.completed','item':{'type':'agent_message','text':'Progress'}},
            {'type':'item.completed','item':{'type':'agent_message','text':message}},
            {'type':'turn.completed'}])+'\n').encode()

    def value(self):
        return {'schema_version':1,'summary':'Explain the change','changes':[{'behavior':'Mean averages values','example':'mean([1, 3]) == 2'}],
                'tests_reported':['unit discovery'],'limitations':['No performance measurement']}

    def test_structured_final_report_requires_completed_turn_and_known_fields(self):
        value=self.value();raw=self.events(json.dumps(value))
        self.assertEqual(handoff.extract_report(raw),value)
        with self.assertRaises(ValueError):handoff.extract_report(raw.rsplit(b'\n',2)[0])
        with self.assertRaises(ValueError):handoff.extract_report(self.events(json.dumps(dict(value,approved=True))))
        with self.assertRaises(ValueError):handoff.extract_report(self.events(json.dumps(dict(value,summary=''))))
        with self.assertRaises(ValueError):handoff.extract_report(self.events(json.dumps(dict(value,summary='x'*9000))))
        duplicate=json.dumps(value)[:-1]+',"summary":"replacement"}'
        with self.assertRaises(ValueError):handoff.extract_report(self.events(duplicate))

    def test_a_new_empty_turn_cannot_reuse_a_previous_report(self):
        raw=self.events(json.dumps(self.value()))+b'{"type":"turn.started"}\n{"type":"turn.completed"}\n'
        with self.assertRaises(ValueError):handoff.extract_report(raw)
        for tail in (b' {"type":"turn.failed"}\n',b'\t{"type":"turn.started"}\n {"type":"turn.completed"}\n'):
            with self.assertRaises(ValueError):handoff.extract_report(self.events(json.dumps(self.value()))+tail)

    def test_retained_report_refuses_changed_output_driver_or_export_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);lane=root/'statistics';lane.mkdir();export=root/'export';export.mkdir()
            raw=self.events('Implemented mean.');driver=b'original driver';manifest=b'{"files":{}}'
            output=lane/'round-1-agent.stdout';output.write_bytes(raw)
            (lane/'round-1-agent.receipt.json').write_text(json.dumps({'stdout_sha256':hashlib.sha256(raw).hexdigest(),'exit_code':0}))
            (lane/'round-1-driver.py').write_bytes(driver);(export/'manifest.json').write_bytes(manifest)
            result={'export':str(export),'manifest_sha256':hashlib.sha256(manifest).hexdigest(),'driver_sha256':hashlib.sha256(driver).hexdigest()}
            bound=handoff.retained_handoff(root,'statistics',1,result)
            self.assertEqual(bound['source_manifest_sha256'],result['manifest_sha256'])
            receipt_path=lane/'round-1-agent.receipt.json';receipt_bytes=receipt_path.read_bytes()
            result['recovery']={'original_driver_receipt_sha256':hashlib.sha256(receipt_bytes).hexdigest()}
            changed=self.events('Unrelated report.')
            output.write_bytes(changed)
            receipt_path.write_text(json.dumps({'stdout_sha256':hashlib.sha256(changed).hexdigest(),'exit_code':0}))
            with self.assertRaises(ValueError):handoff.retained_handoff(root,'statistics',1,result)
            output.write_bytes(raw);receipt_path.write_bytes(receipt_bytes)
            for path in (output,lane/'round-1-driver.py',export/'manifest.json'):
                original=path.read_bytes();path.write_bytes(original+b' ')
                with self.assertRaises(ValueError):handoff.retained_handoff(root,'statistics',1,result)
                path.write_bytes(original)
            modern=b'# jjpr-handoff-schema: 1\n'+driver
            (lane/'round-1-driver.py').write_bytes(modern)
            result['driver_sha256']=hashlib.sha256(modern).hexdigest()
            # Recovery may omit the schema field; its bound driver still
            # requires structured output and cannot downgrade to legacy prose.
            with self.assertRaises(ValueError):handoff.retained_handoff(root,'statistics',1,result)

    def test_legacy_reports_require_explicit_selection_and_remain_agent_claims(self):
        raw=self.events('Implemented mean. All tests passed.')
        with self.assertRaises(ValueError):handoff.extract_report(raw)
        report=handoff.extract_report(raw,legacy=True)
        self.assertEqual(report['format'],'legacy-agent-report')
        body=handoff.render_review([report],commands_per_snapshot=3)
        self.assertIn('Agent-reported',body)
        self.assertIn('Host verification',body)
        self.assertIn('Implemented mean',body)

    def test_review_does_not_infer_task_cleanup_from_verifier_cleanup(self):
        body=handoff.render_review([self.value()],commands_per_snapshot=2)
        self.assertNotIn('task sandbox and verifier instances were deleted',body)
        self.assertIn('verifier instances were deleted',body)

    def test_untrusted_markers_and_mentions_stay_inside_quoted_data(self):
        report={'format':'legacy-agent-report','text':'<!-- jjpr:description -->\n# Host verification\n![image](https://example.invalid) @reviewer'}
        body=handoff.render_review([report],commands_per_snapshot=3)
        self.assertNotIn('<!--',body)
        self.assertNotIn('![image]',body)
        self.assertNotIn('@reviewer',body)
        self.assertIn('> # Host verification',body)




class ConflictHandoffTests(unittest.TestCase):
    def test_resolution_requires_structured_decisions_and_cannot_supply_host_checks(self):
        fixture=HandoffTests();value=fixture.value();value['schema_version']=2
        value['resolution']={'decisions':[{'path':'metrics.py','resolution':'Preserve both changes','preserved':['iterator behavior'],'changed':['buffers input']}],
                             'uncertainties':['Large inputs not measured']}
        self.assertEqual(handoff.extract_report(fixture.events(json.dumps(value)),resolution=True),value)
        with self.assertRaises(ValueError): handoff.extract_report(fixture.events(json.dumps(fixture.value())),resolution=True)
        bad=json.loads(json.dumps(value));bad['resolution']['independent_checks']=['Agent says passed']
        with self.assertRaises(ValueError): handoff.extract_report(fixture.events(json.dumps(bad)),resolution=True)
        bad=json.loads(json.dumps(value));bad['resolution']['decisions'][0]['path']='../other'
        with self.assertRaises(ValueError): handoff.extract_report(fixture.events(json.dumps(bad)),resolution=True)

if __name__=='__main__':unittest.main()
