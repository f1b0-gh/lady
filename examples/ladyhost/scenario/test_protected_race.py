"""Pairing constraints complement, but do not replace, native integration gates."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]))
import protected_race


class ProtectedRaceTests(unittest.TestCase):
    def pair(self):
        config={'provider':'github','endpoint':'https://api.github.com','owner':'owner',
                'repository':'repo','visibility':'public','expected_repository_id':1,
                'expected_actor':'host[bot]','github_app':{'app_id':2},
                'stack_base':'app-experiment-base'}
        request={'expected_target':'a'*40,'target':'app-experiment-base','reviewer':{'id':3},
                 'update_ruleset_id':4,'quality_ruleset_id':5,'allowed_signers':'/trust',
                 'ci':{'check_name':'ci/verify','app_id':6,'workflow_path':'.github/workflows/ci-verify.yml'}}
        configs=[dict(config,workspace='/work/'+str(n)) for n in (1,2)]
        requests=[dict(request,task=str(n),pr_number=n,source='agent/'+str(n),
                       expected_head=str(n)*40,receipt_dir='/receipts/'+str(n)) for n in (1,2)]
        return configs,requests

    def test_requires_two_distinct_candidates_for_same_protected_scope(self):
        configs,requests=self.pair()
        protected_race.validate_pair(configs,requests)
        mutations=[('config','owner','other'),('config','github_app',{'app_id':9}),
                   ('config','workspace','/work/1'),('request','expected_target','b'*40),
                   ('request','expected_head','1'*40),('request','source','agent/1'),
                   ('request','pr_number',1),('request','receipt_dir','/receipts/1/nested'),
                   ('request','receipt_dir','/work/1/other-candidate-receipts'),
                   ('request','ci',None),('request','quality_ruleset_id',9)]
        for kind,key,value in mutations:
            with self.subTest(kind=kind,key=key):
                c,r=copy.deepcopy((configs,requests))
                (c if kind=='config' else r)[1][key]=value
                with self.assertRaises(RuntimeError):protected_race.validate_pair(c,r)
        for c,r in ((configs[:1],requests[:1]),(configs,requests[:1])):
            with self.assertRaises(RuntimeError):protected_race.validate_pair(c,r)

    def test_unknown_loser_is_not_reported_as_a_verified_refusal(self):
        _,requests=self.pair()
        winner={'outcome':'integrated','oid':requests[0]['expected_head']}
        for loser,expected in (({'outcome':'refused'},True),({'outcome':'unknown'},False)):
            result=protected_race.classify([winner,loser],requests,winner['oid'])
            self.assertEqual(result['qualified_one_winner_and_refusal'],expected)
        for outcomes in ([winner,winner],[{'outcome':'unknown'},{'outcome':'refused'}]):
            with self.assertRaises(RuntimeError):protected_race.classify(outcomes,requests,winner['oid'])
        with self.assertRaises(RuntimeError):protected_race.classify([winner,{'outcome':'refused'}],requests,'f'*40)


if __name__=='__main__':unittest.main()
