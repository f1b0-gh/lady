"""Independent Git-tree and parent-publication checks for file-only imports."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import shlex

sys.path.insert(0,str(Path(__file__).parents[1]))
import publish


class ImportTests(unittest.TestCase):
    def test_app_git_helper_never_uses_personal_cli(self):
        config={'github_app':{'slug':'publisher'}}
        helper=publish.host_git_helper(config,Path("/host/config's file.json"),Path('/host/bin/adapter'))
        self.assertEqual(shlex.split(helper[1:]),['/host/bin/adapter','credential',"/host/config's file.json"])
        config['gh_cli']='/host/gh'
        with self.assertRaisesRegex(RuntimeError,'exactly one'):
            publish.host_git_helper(config,Path('/host/config.json'),Path('/host/adapter'))

    def test_publication_namespace_separates_prior_user_prs(self):
        self.assertEqual(publish.publication_names('ranges',None),('stack-ranges','publication-ranges','agent/ranges'))
        self.assertEqual(publish.publication_names('ranges','app-v1'),('stack-app-v1-ranges','publication-app-v1-ranges','agent/app-v1/ranges'))
        for invalid in ('../old','/abs','', 'a/b','a b'):
            with self.assertRaises(ValueError):publish.publication_names('ranges',invalid)

    def test_commit_inventory_detects_extra_tracked_content(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            def git(*args):
                return subprocess.check_output(['git','-C',name,'-c','user.name=test','-c','user.email=test@example.invalid','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',*args],stderr=subprocess.DEVNULL).decode().strip()
            git('init');(root/'expected.py').write_bytes(b'pass\n');(root/'extra').write_bytes(b'unchecked\n')
            git('add','.');git('commit','-m','fixture')
            actual=publish.commit_inventory(root,git('rev-parse','HEAD'),None)
            expected={'expected.py':{'sha256':hashlib.sha256(b'pass\n').hexdigest(),'executable':False}}
            self.assertNotEqual(actual,expected)
            self.assertEqual(set(actual),{'expected.py','extra'})

    def test_child_requires_confirmed_exact_parent(self):
        parent={'oid':'a'*40}
        for receipt,remote in [({},'a'*40),({'oid':'a'*40,'remote_oid':'b'*40},'a'*40),({'oid':'a'*40,'remote_oid':'a'*40},'b'*40)]:
            with self.assertRaises(RuntimeError):publish.confirmed_parent(parent,receipt,remote)
        publish.confirmed_parent(parent,{'oid':'a'*40,'remote_oid':'a'*40},'a'*40)


if __name__=='__main__':unittest.main()
