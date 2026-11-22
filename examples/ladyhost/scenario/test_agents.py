"""Focused refusal tests for the scenario's host-side evidence checks."""
import importlib.util
import contextlib
import io
import json
import sys
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

sys.path.insert(0,str(Path(__file__).parents[1]))
spec = importlib.util.spec_from_file_location('jjpr_agents', Path(__file__).parents[1] / 'agents.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class EvidenceTests(unittest.TestCase):
    def test_selected_lanes_keep_original_default_and_refuse_duplicates(self):
        self.assertEqual(module.selected_lanes(None), ('statistics','ranges','rolling'))
        self.assertEqual(module.selected_lanes(['changes']), ('changes',))
        for value in ([], ['ranges','ranges'], ['../outside']):
            with self.assertRaises(ValueError):module.selected_lanes(value)

    def test_staged_seed_preserves_files_and_refuses_repository_metadata_or_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'existing.py').write_text('value = 1\n')
            self.assertEqual(module.seed_inventory(root), module.inventory(root))
            for reserved in ('.git','.jj'):
                path=root/reserved;path.mkdir()
                with self.assertRaises(RuntimeError):module.seed_inventory(root)
                path.rmdir()
            (root/'alias').symlink_to(root/'existing.py')
            with self.assertRaises(RuntimeError):module.seed_inventory(root)

    def test_staged_seed_refuses_root_alias_and_nested_repository_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp);root=parent/'seed';root.mkdir()
            (root/'file.py').write_text('value = 1\n')
            alias=parent/'alias';alias.symlink_to(root,target_is_directory=True)
            with self.assertRaises(RuntimeError):module.seed_inventory(alias)
            nested=root/'nested/.git';nested.mkdir(parents=True)
            (nested/'config').write_text('host metadata')
            with self.assertRaises(RuntimeError):module.seed_inventory(root)

    def test_legacy_recovery_requires_original_selection_and_seed(self):
        original={'seed':module.inventory(module.HERE/'scenario/seed')}
        module.require_legacy_recovery(original)
        module.require_legacy_recovery(dict(original,lanes=list(module.DEFAULT_LANES)))
        for changed in (dict(original,lanes=['changes']),
                        dict(original,lanes=list(module.LANES)),dict(original,seed={'other':{}})):
            with self.assertRaises(RuntimeError):module.require_legacy_recovery(changed)

    def test_staged_seed_cannot_contain_its_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'file.py').write_text('value = 1\n')
            with self.assertRaises(RuntimeError):module.seed_inventory(root,root/'run')
            self.assertFalse((root/'run').exists())

    def test_current_target_configuration_includes_every_frozen_input(self):
        names=['.github/workflows/ci-verify.yml','metrics.py','stream_statistics.py','tests/test_metrics.py']
        config=module.configuration(include=names)
        for name in names:self.assertIn(json.dumps(name),config)

    def test_changes_oracle_rejects_wrong_result_and_missing_parent_dependency(self):
        import types
        fixture=types.ModuleType('stream_changes')
        def differences(values):
            values=list(values)
            return [b-a for a,b in zip(values,values[1:])]
        fixture.differences=differences
        fixture.total_change=lambda values: sum(fixture.differences(values))
        with patch.dict(sys.modules,stream_changes=fixture):
            exec(module.assertions('changes','children'),{})
            fixture.total_change=lambda values: (v[-1]-v[0]) if (v:=list(values)) else 0
            with self.assertRaises(AssertionError):exec(module.assertions('changes','children'),{})
            fixture.differences=lambda values: []
            with self.assertRaises(AssertionError):exec(module.assertions('changes','roots'),{})

    def test_export_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'escape').symlink_to('/etc/passwd')
            with self.assertRaises(RuntimeError):
                module.inventory(Path(root))

    def test_scope_rejects_modified_baseline_and_extra_file(self):
        before = {'README.md': {'sha256': 'a', 'executable': False}}
        for after in ({'README.md': {'sha256': 'b', 'executable': False}, 'lane.py': {}},
                      {**before, 'lane.py': {}, '.git/config': {}}):
            with self.assertRaises(RuntimeError):
                module.scoped(before, after, {'lane.py'})

    def test_dependency_must_call_parent(self):
        with self.assertRaises(RuntimeError):
            module.dependency('def mean(v): return sum(v)/len(v)\ndef variance(v): return 0\n', 'mean', 'variance')
        module.dependency('def mean(v): return sum(v)/len(v)\ndef variance(v): return mean(v)\n', 'mean', 'variance')

    def test_parent_definition_cannot_change_in_child(self):
        with self.assertRaises(RuntimeError):
            module.retained_definitions('def parent(): return 1\n', 'def parent(): return 2\n', ['parent'])

    def test_github_repository_rejects_source_and_url_injection(self):
        for repository in ('', 'owner', 'owner/repo/extra', '../repo', 'owner/..',
                           'owner/repo?token=x', 'owner/repo#fragment', 'owner/repo%2fother',
                           'owner/repo\nprint(123)', "owner/repo';print(123)#", 'owner@evil/repo',
                           'https://github.com/owner/repo', 'owner\\evil/repo', 'owner/répo'):
            with self.subTest(repository=repository), self.assertRaises(ValueError):
                module.probe_source(repository)
        source = module.probe_source('f1b0-oss/jjpr-lab')
        compile(source, '<github-probe>', 'exec')
        self.assertIn('https://api.github.com/repos/f1b0-oss/jjpr-lab', source)
        self.assertIn('https://github.com/f1b0-oss/jjpr-lab.git', source)

    def probe(self, api_error, git_error=b'fatal: could not read Username', api_response=None):
        opener = Mock()
        opener.open.side_effect = api_error
        opener.open.return_value = api_response
        output = io.StringIO()
        git = subprocess.CompletedProcess([], 128, b'', git_error)
        with patch.dict('os.environ', {}, clear=True), patch('pathlib.Path.exists', return_value=False), \
             patch('urllib.request.build_opener', return_value=opener), \
             patch('subprocess.run', return_value=git), contextlib.redirect_stdout(output):
            exec(module.probe_source('f1b0-oss/jjpr-lab'), {})
        return json.loads(output.getvalue())

    def test_http_refusal_does_not_establish_repository_existence_or_privacy(self):
        for status in (401, 403, 404):
            error = urllib.error.HTTPError('https://api.github.com', status, 'refused', {}, None)
            self.addCleanup(error.close)
            result = self.probe(error)
            self.assertTrue(error.closed)
            self.assertEqual(result['direct_api']['outcome'], 'http-refusal')
            self.assertEqual(result['direct_api']['status'], status)
            self.assertFalse(result['privacy_established'])
            self.assertTrue(result['requires_authenticated_host_repository_evidence'])

    def test_network_failure_is_unknown_not_http_refusal(self):
        result = self.probe(urllib.error.URLError('unavailable'), b'fatal: Could not resolve host: github.com')
        self.assertEqual(result['direct_api']['outcome'], 'network-unavailable')
        self.assertEqual(result['direct_git']['outcome'], 'network-unavailable')
        self.assertFalse(result['privacy_established'])

    def test_successful_anonymous_api_access_refuses_campaign(self):
        response = io.BytesIO(b'{}')
        self.addCleanup(response.close)
        with self.assertRaisesRegex(AssertionError, 'direct API'):
            self.probe(None, api_response=response)
        self.assertTrue(response.closed)

    def test_successful_anonymous_git_access_refuses_campaign(self):
        opener = Mock()
        opener.open.side_effect = urllib.error.HTTPError('https://api.github.com', 404, 'missing', {}, None)
        self.addCleanup(opener.open.side_effect.close)
        with patch.dict('os.environ', {}, clear=True), patch('pathlib.Path.exists', return_value=False), \
             patch('urllib.request.build_opener', return_value=opener), \
             patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            with self.assertRaisesRegex(AssertionError, 'direct Git'):
                exec(module.probe_source('f1b0-oss/jjpr-lab'), {})
        self.assertTrue(opener.open.side_effect.closed)

    def test_probe_refuses_credential_environment_before_network(self):
        with patch.dict('os.environ', {'GITHUB_TOKEN': 'test-only'}, clear=True), \
             patch('urllib.request.build_opener') as opener:
            with self.assertRaisesRegex(AssertionError, 'credential environment'):
                exec(module.probe_source('f1b0-oss/jjpr-lab'), {})
            opener.assert_not_called()

    def test_default_profile_preserves_loopback_endpoint(self):
        source = module.probe_source()
        compile(source, '<loopback-probe>', 'exec')
        self.assertIn('http://127.0.0.1:34080/api/v1/repos/owner/stack-lab', source)
        self.assertNotIn('https://api.github.com/repos/', source)

    def test_public_github_accepts_anonymous_reads_without_claiming_write_test(self):
        opener = Mock()
        opener.open.return_value = io.BytesIO(b'{"full_name":"f1b0-oss/jjpr-lab","private":false}')
        self.addCleanup(opener.open.return_value.close)
        output = io.StringIO()
        with patch.dict('os.environ', {}, clear=True), patch('pathlib.Path.exists', return_value=False), \
             patch('urllib.request.build_opener', return_value=opener), \
             patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, b'', b'')), \
             contextlib.redirect_stdout(output):
            exec(module.probe_source('f1b0-oss/jjpr-lab', public=True), {})
        self.assertTrue(opener.open.return_value.closed)
        result = json.loads(output.getvalue())
        self.assertEqual(result['direct_api']['outcome'], 'public-read-access')
        self.assertEqual(result['direct_git']['outcome'], 'public-read-access')
        self.assertFalse(result['anonymous_write_tested'])
        self.assertFalse(result['privacy_established'])

    def test_public_profile_requires_github_repository(self):
        with self.assertRaises(ValueError):
            module.probe_source(public=True)

    def test_prepared_resume_rejects_any_prior_agent_or_probe_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            for lane in module.LANES:
                (root / lane).mkdir()
            for filename in ('round-1-driver.py', 'round-1-agent.stdout', 'isolation-probe.stdout'):
                marker = root / 'statistics' / filename
                marker.write_text('retained')
                with self.assertRaises(RuntimeError):
                    module.require_pre_model(root)
                marker.unlink()
            module.require_pre_model(root)

    def test_retained_ladyshell_relocation_requires_original_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            retained = Path(root) / 'retained'
            retained.write_bytes(b'original fixture executable')
            recorded = {'path': str(Path(root) / 'old-path'), 'sha256': module.sha(retained)}
            relocated = module.verify_artifact('ladyshell', retained, recorded)
            self.assertEqual(relocated['from'], recorded['path'])
            self.assertEqual(relocated['to'], str(retained))
            retained.write_bytes(b'replacement executable')
            with self.assertRaises(RuntimeError):
                module.verify_artifact('ladyshell', retained, recorded)

    def test_codex_path_cannot_be_relocated_outside_pinned_sandbox_image(self):
        with tempfile.TemporaryDirectory() as root:
            retained = Path(root) / 'retained'
            retained.write_bytes(b'fixture')
            recorded = {'path': str(Path(root) / 'old-path'), 'sha256': module.sha(retained)}
            with self.assertRaises(RuntimeError):
                module.verify_artifact('codex', retained, recorded)

    def test_nonexecutable_cli_refused_before_creating_state(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cli = root / 'staged'
            cli.write_bytes(b'not executable')
            args = SimpleNamespace(state=root/'state', ladyshell=cli,
                                   github_repository='f1b0-oss/jjpr-lab', github_public=True)
            with self.assertRaisesRegex(RuntimeError, 'executable'):
                module.Campaign(args)
            self.assertFalse(args.state.exists())

    def test_driver_accepts_native_entry_size_but_refuses_changed_baseline_hash(self):
        before = {'README.md': {'sha256': 'seed', 'executable': False}}
        current = {'README.md': {'sha256': 'seed', 'executable': False, 'size': 42},
                   'stream_ranges.py': {'sha256': 'code', 'executable': False, 'size': 99},
                   'tests/test_stream_ranges.py': {'sha256': 'tests', 'executable': False, 'size': 88}}
        driver = module.agent_driver(Path('/fake/codex'), 'ranges', 'roots', 'routing', before)
        initial = {'README.md': current['README.md'].copy()}
        with patch.dict('os.environ', {}, clear=True), patch('subprocess.run'), \
             patch('subprocess.check_output', side_effect=[json.dumps(initial).encode(), json.dumps(current).encode()]):
            exec(driver, {})
        current['README.md']['sha256'] = 'changed'
        with patch.dict('os.environ', {}, clear=True), patch('subprocess.run'), \
             patch('subprocess.check_output', side_effect=[json.dumps(initial).encode(), json.dumps(current).encode()]):
            with self.assertRaisesRegex(AssertionError, 'Unauthorized fixture edits'):
                exec(driver, {})

    def test_driver_refuses_substituted_parent_before_model_or_auth(self):
        before = {'README.md': {'sha256': 'seed', 'executable': False}}
        driver = module.agent_driver(Path('/fake/codex'), 'ranges', 'children', 'routing', before)
        with patch.dict('os.environ', {}, clear=True), patch('subprocess.run') as run, \
             patch('subprocess.check_output', return_value=b'{}'):
            with self.assertRaisesRegex(AssertionError, 'Initial sandbox snapshot'):
                exec(driver, {})
            run.assert_not_called()

    def test_verifier_retry_requires_confirmed_cleanup_and_no_started_checks(self):
        failed = {'passed': False, 'cleanup_confirmed': True, 'results': [], 'error': 'database is locked'}
        self.assertTrue(module.retryable_verifier_creation(failed))
        for changed in ({'cleanup_confirmed': False}, {'results': [{'passed': True}]},
                        {'error': 'unknown timeout'}, {'passed': True}):
            self.assertFalse(module.retryable_verifier_creation({**failed, **changed}))

    def test_child_configuration_includes_its_retained_parent_module(self):
        for lane in module.LANES:
            self.assertIn('"stream_' + lane + '.py"', module.configuration(lane))
        with self.assertRaises(RuntimeError):
            module.configuration('../injected')

if __name__ == '__main__':
    unittest.main()
