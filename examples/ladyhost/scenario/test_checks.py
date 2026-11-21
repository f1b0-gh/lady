"""A success status requires the exact retained, checked tree and publication."""
import sys
import hashlib
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]))
import checks


class CheckBindingTests(unittest.TestCase):
    def test_restack_status_requires_explicit_original_round_binding(self):
        checks.validate_source_round({'round':2,'source_round':2,'previous_oid':'a'*40,'target_oid':'b'*40},2,True)
        for mapping,number in (({'round':1,'source_round':1},2),({'round':2},2),
                               ({'round':2,'source_round':2,'previous_oid':'a'*40},2)):
            with self.assertRaises(RuntimeError):checks.validate_source_round(mapping,number,True)
        checks.validate_source_round({'round':1},1,False)
        with self.assertRaises(RuntimeError):checks.validate_source_round({'round':2},1,False)

    def test_success_is_bound_to_export_tree_manifest_and_confirmed_commit(self):
        files={'a.py':{'sha256':'a'*64,'executable':False}}
        mapping={'oid':'b'*40,'export':'/host/export','manifest_sha256':'c'*64,'files':files}
        result={'export':'/host/export','manifest_sha256':'c'*64,'files':files,
                'host_check_policy_sha256':'d'*64,'checks':{'passed':True,'cleanup_confirmed':True,'policy_sha256':'e'*64}}
        confirmed={'oid':'b'*40,'remote_oid':'b'*40}
        checks.validate_check_binding(mapping,result,confirmed,files)
        for field,value in [('passed',False),('cleanup_confirmed',False),('policy_sha256',None)]:
            bad=dict(result,checks=dict(result['checks'],**{field:value}))
            with self.assertRaises(RuntimeError):checks.validate_check_binding(mapping,bad,confirmed,files)
        for bad in (dict(mapping,manifest_sha256='e'*64),dict(mapping,export='/other'),dict(mapping,oid='e'*40)):
            with self.assertRaises(RuntimeError):checks.validate_check_binding(bad,result,confirmed,files)
        with self.assertRaises(RuntimeError):checks.validate_check_binding(mapping,result,confirmed,{})

    def test_raw_policy_file_digest_is_distinct_from_native_normalized_digest(self):
        raw=b'{"schema_version":1,"checks":{"commands":[],"timeout":60}}\n'
        result={'host_check_policy_sha256':hashlib.sha256(raw).hexdigest(),
                'checks':{'policy_sha256':'e'*64}}
        checks.validate_policy_file(result,raw)
        with self.assertRaises(RuntimeError):checks.validate_policy_file(result,raw+b' ')

    def test_app_helper_output_is_not_a_user_credential_or_ambiguous(self):
        self.assertEqual(checks.app_password('username=x-access-token\npassword=token\n\n'),'token')
        for output in ('username=human\npassword=token\n','password=token\n',
                       'username=x-access-token\npassword=one\npassword=two\n'):
            with self.assertRaises(RuntimeError):checks.app_password(output)


if __name__=='__main__':unittest.main()
