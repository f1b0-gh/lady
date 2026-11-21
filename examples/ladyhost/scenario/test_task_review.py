"""A task review combines dependent agent changes without losing current-base work."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).parents[1]))
import task_review


class TaskReviewTests(unittest.TestCase):
    def test_task_titles_match_selected_contribution(self):
        self.assertIn('moving averages',task_review.task_titles('rolling')[1])
        self.assertIn('total change',task_review.task_titles('changes')[1])
        self.assertIn('variance',task_review.task_titles('statistics')[1])
        with self.assertRaises(ValueError):task_review.task_titles('../other')

    def retained_fixture(self, root, task_name, declared_state=True):
        directory = root / 'statistics'
        export = directory / task_name / 'state/exports/snapshot'
        (export / 'project').mkdir(parents=True)
        (export / 'project/module.py').write_text('value = 1\n')
        files = task_review.inventory(export / 'project')
        checks = {'passed': True, 'cleanup_confirmed': True}
        (export / 'manifest.json').write_text(json.dumps({'files': files}))
        (export / 'checks.json').write_text(json.dumps(checks))
        result = {'export': str(export), 'manifest_sha256': task_review.sha(export / 'manifest.json'),
                  'files': files, 'checks': checks}
        if declared_state:
            result['source_task_state'] = str(export.parent.parent)
        (directory / 'round-2-result.json').write_text(json.dumps(result))
        return result

    def test_retained_child_accepts_same_task_and_explicit_child_task_exports(self):
        for name in ('task', 'child-task'):
            for declared in (False, True):
                with self.subTest(name=name, declared=declared), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result = self.retained_fixture(root, name, declared)
                    self.assertEqual(task_review.retained_source(root, 'statistics', 2), result)

    def test_retained_child_refuses_other_task_and_mismatched_declared_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.retained_fixture(root, 'other-task')
            with self.assertRaises(RuntimeError):
                task_review.retained_source(root, 'statistics', 2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.retained_fixture(root, 'task')
            result['source_task_state'] = str(root / 'statistics/child-task/state')
            (root / 'statistics/round-2-result.json').write_text(json.dumps(result))
            with self.assertRaises(RuntimeError):
                task_review.retained_source(root, 'statistics', 2)

    def test_source_chain_must_start_at_the_retained_campaign_seed(self):
        seed={'seed':{}}
        first={'export':'/first','parent_export':None,'input_files':seed,'files':{'first':{}}}
        second={'parent_export':'/first','input_files':first['files']}
        task_review.validate_source_chain([first,second],seed)
        for bad in (dict(first,parent_export='/other'),dict(first,input_files={})):
            with self.assertRaises(RuntimeError):task_review.validate_source_chain([bad,second],seed)

    def test_checkout_creation_refuses_existing_directories_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);existing=root/'existing';existing.mkdir()
            sentinel=existing/'config';sentinel.write_text('retain')
            alias=root/'alias';alias.symlink_to(existing,target_is_directory=True)
            for path in (existing,alias):
                with self.assertRaises(FileExistsError):task_review.initialize_checkout(path,{})
            self.assertEqual(sentinel.read_text(),'retain')
            self.assertFalse((existing/'.git').exists())

    def test_composition_preserves_unrelated_current_base_and_refuses_drift(self):
        original={'metrics.py':{'sha256':'a'*64,'executable':False}}
        additions={name:{'sha256':'b'*64,'executable':False} for name in
                   ('stream_statistics.py','tests/test_stream_statistics.py')}
        result={'input_files':original,'files':dict(original,**additions)}
        base=dict(original,other={'sha256':'c'*64,'executable':False})
        actual=task_review.compose_snapshot(base,result,'statistics')
        self.assertEqual(actual,dict(base,**additions))
        changed=copy.deepcopy(base);changed['metrics.py']['sha256']='d'*64
        with self.assertRaises(RuntimeError):task_review.compose_snapshot(changed,result,'statistics')
        with self.assertRaises(RuntimeError):task_review.compose_snapshot(dict(base,**additions),result,'statistics')
        bad=copy.deepcopy(result);bad['files']['metrics.py']['sha256']='e'*64
        with self.assertRaises(RuntimeError):task_review.compose_snapshot(base,bad,'statistics')

    def test_dependent_snapshot_requires_exact_parent_files(self):
        parent={name:{'sha256':'b'*64,'executable':False} for name in
                ('stream_statistics.py','tests/test_stream_statistics.py')}
        child={name:{'sha256':'c'*64,'executable':False} for name in parent}
        result={'input_files':parent,'files':child}
        self.assertEqual(task_review.compose_snapshot(dict(parent,other={}),result,'statistics'),dict(child,other={}))
        with self.assertRaises(RuntimeError):task_review.compose_snapshot(child,result,'statistics')

    def test_task_history_is_two_linear_commits_ending_at_checked_tip(self):
        task_review.validate_history('a'*40,['b'*40,'c'*40],['a'*40,'b'*40],'c'*40)
        for commits,parents,tip in [(['c'*40],['a'*40],'c'*40),
                                    (['b'*40,'c'*40],['a'*40,'a'*40],'c'*40),
                                    (['b'*40,'c'*40],['a'*40,'b'*40],'d'*40)]:
            with self.assertRaises(RuntimeError):task_review.validate_history('a'*40,commits,parents,tip)


if __name__=='__main__':unittest.main()
