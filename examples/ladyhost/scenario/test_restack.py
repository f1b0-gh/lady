"""Restacking may reuse snapshot checks only when both input and output match."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]))
import restack


class RestackTests(unittest.TestCase):
    def test_closed_child_cannot_become_a_new_publication(self):
        config={'expected_repository_id':42,'expected_actor':'publisher[bot]'}
        mapping={'oid':'c'*40,'bookmark':'agent/child'}
        parent={'bookmark':'agent/parent'}
        pr={'number':5,'state':'open','merged':False,'draft':False,'user':{'login':'publisher[bot]'},
            'head':{'sha':'c'*40,'ref':'agent/child','repo':{'id':42}},
            'base':{'ref':'agent/parent','repo':{'id':42}}}
        restack.validate_child(pr,5,mapping,parent,config)
        for key,value in [('state','closed'),('number',6),('merged',True),('draft',True)]:
            with self.assertRaises(RuntimeError):
                restack.validate_child(dict(pr,**{key:value}),5,mapping,parent,config)

    def test_only_the_observed_merged_parent_and_unchanged_input_are_admitted(self):
        config={'expected_repository_id':42,'expected_actor':'publisher[bot]','stack_base':'test-base'}
        parent={'oid':'a'*40,'bookmark':'agent/parent','files':{'a':'hash'}}
        pr={'number':4,'merged':True,'state':'closed','merge_commit_sha':'b'*40,
            'user':{'login':'publisher[bot]'},
            'head':{'sha':'a'*40,'ref':'agent/parent','repo':{'id':42}},
            'base':{'ref':'test-base','repo':{'id':42}}}
        restack.validate_parent(pr,4,parent,config,'b'*40,{'a':'hash'})
        mutations=[('merged',False),('merge_commit_sha','c'*40),('number',6),('state','open')]
        for key,value in mutations:
            with self.assertRaises(RuntimeError):
                restack.validate_parent(dict(pr,**{key:value}),4,parent,config,'b'*40,{'a':'hash'})
        for section,key,value in [('head','sha','d'*40),('head','ref','other'),
                                  ('base','ref','main'),('user','login','human'),
                                  ('head','repo',{'id':9}),('base','repo',{'id':9})]:
            bad=copy.deepcopy(pr);bad[section][key]=value
            with self.assertRaises(RuntimeError):
                restack.validate_parent(bad,4,parent,config,'b'*40,{'a':'hash'})
        with self.assertRaises(RuntimeError):
            restack.validate_parent(pr,4,parent,config,'b'*40,{'a':'changed'})

    def test_attempt_names_cannot_escape_or_reuse_publication_round(self):
        self.assertEqual(restack.attempt_name('restack-1'),'restack-1')
        for name in ('../x','round-2','restack-/x','restack-', '/x'):
            with self.assertRaises(ValueError):restack.attempt_name(name)


if __name__=='__main__':unittest.main()
