"""CI scenario preserves fixture code and revises one bound PR."""
import hashlib
import json
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parents[1]))
import ci_trial

class CiTrialTests(unittest.TestCase):
    def test_candidates_preserve_base_and_only_remove_failure_marker(self):
        base={'code.py':{'sha256':'a'*64,'executable':True}}
        first,second=ci_trial.snapshots(base,b'name: example\n')
        self.assertEqual(first['code.py'],base['code.py'])
        self.assertEqual(second['code.py'],base['code.py'])
        self.assertEqual(set(first)-set(second),{ci_trial.MARKER})
        self.assertEqual({k:v for k,v in first.items() if k!=ci_trial.MARKER},second)
        self.assertEqual(second[ci_trial.WORKFLOW]['sha256'],hashlib.sha256(b'name: example\n').hexdigest())
        for conflict in (ci_trial.MARKER,ci_trial.WORKFLOW,'.github/workflows/unrelated.yml'):
            with self.assertRaises(RuntimeError):ci_trial.snapshots(dict(base,**{conflict:{}}),b'workflow')

    def test_revision_stays_on_same_open_pr_and_exact_previous_head(self):
        prepared={'bookmark':'agent/ci-v1/verify','base':'b'*40,'commits':['a'*40,'c'*40]}
        config={'owner':'owner','repository':'repo','expected_repository_id':42,'expected_actor':'publisher[bot]','stack_base':'base'}
        pr={'number':11,'state':'open','merged':False,'draft':False,'user':{'login':'publisher[bot]','type':'Bot'},'head':{'ref':prepared['bookmark'],'sha':'a'*40,'repo':{'id':42}},'base':{'ref':'base','repo':{'id':42}}}
        ci_trial.validate_revision(config,prepared,11,pr)
        for change in ({'state':'closed'},{'merged':True},{'number':12},{'head':dict(pr['head'],sha='d'*40)},{'head':dict(pr['head'],repo={'id':43})},{'user':{'login':'human','type':'User'}}):
            with self.assertRaises(RuntimeError):ci_trial.validate_revision(config,prepared,11,dict(pr,**change))

    def test_failed_or_replaced_evidence_cannot_reach_publication(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);attempt=root/'round-1';attempt.mkdir();export=root/'export';export.mkdir();(export/'project').mkdir()
            manifest=b'{"files":{}}';(export/'manifest.json').write_bytes(manifest)
            policy=b'{}';(attempt/'checks.json').write_bytes(policy)
            prepared={'checkout':str(root/'checkout'),'base':'b'*40,'bookmark':'agent/ci-test','commits':['a'*40,'c'*40],'native_cleanup_confirmed':True}
            config={'workspace':str(root/'checkout'),'owner':'owner','repository':'repo','stack_base':'base','expected_actor':'publisher[bot]','expected_repository_id':42}
            result={'round':1,'export':str(export),'manifest_sha256':hashlib.sha256(manifest).hexdigest(),'files':{},'host_check_policy_sha256':hashlib.sha256(policy).hexdigest(),'checks':{'passed':True,'cleanup_confirmed':True,'policy_sha256':'e'*64}}
            mapping=dict(result,oid='a'*40,bookmark=prepared['bookmark'])
            args=SimpleNamespace(root=root,round=1,jj=Path('/unused/jj'),adapter=Path('/unused/adapter'),gh=Path('/unused/gh'))
            for mutation in ('failed','receipt','oid','bookmark','round','workspace','cleanup','signature'):
                values=json.loads(json.dumps([prepared,config,result,mapping]));p,c,r,m=values
                native=r['checks'].copy()
                if mutation=='failed':r['checks']['passed']=False;native=r['checks'].copy()
                elif mutation=='receipt':native['passed']=False
                elif mutation=='oid':m['oid']='d'*40
                elif mutation=='bookmark':m['bookmark']='agent/other'
                elif mutation=='round':m['round']=2
                elif mutation=='workspace':c['workspace']=str(root/'other')
                elif mutation=='cleanup':p['native_cleanup_confirmed']=False
                for path,value in zip((root/'prepared.json',root/'auth.json',attempt/'result.json',attempt/'mapping.json'),values):path.write_text(json.dumps(value))
                (export/'checks.json').write_text(json.dumps(native))
                def command(argv,*unused):
                    if 'verify-commit' in argv and mutation=='signature':raise RuntimeError('signature invalid')
                    if 'rev-parse' in argv:return 'b'*40
                    return 'b'*40+' refs/heads/base'
                with patch.object(ci_trial,'environment',return_value={}),patch.object(ci_trial,'inventory',return_value={}),patch.object(ci_trial,'commit_inventory',return_value={}),patch.object(ci_trial,'api_environment',return_value={}),patch.object(ci_trial,'run',side_effect=command),patch.object(ci_trial,'call',side_effect=RuntimeError('submit reached')) as submit:
                    with self.assertRaises(RuntimeError):ci_trial.publish(args)
                    self.assertFalse(submit.called,mutation)

if __name__=='__main__':unittest.main()
