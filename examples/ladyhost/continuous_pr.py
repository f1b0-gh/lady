#!/usr/bin/env python3
"""Live two-PR conflict trial using native Ladyshell CS and the Rust forge gate.

Agents edit and test in OpenShell; host jj owns signing and history. This driver
retains create-only scenario evidence, never supplies human approval, and keeps
all App credentials outside exported projects. Phases are explicit: an unknown
remote effect must be inspected before another attempt.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import threading

from agents import configuration, durable, inventory, require, sha
from continuous import Trial
from handoff import render_review
from publish import commit_inventory
from task_review import environment, initialize_checkout
from github import run

TARGET = 'app-experiment-base'
LANES = ('start', 'accuracy')
INSTRUCTIONS = {
    'start': ('Extend metrics.total(values, *, start=0) with a keyword-only starting value. '
              'Keep Python sum semantics, support empty inputs and one-shot iterators, and add '
              'tests/test_start.py. This lets callers accumulate onto an existing total.'),
    'accuracy': ('Change metrics.total(values) to use math.fsum so cancellation such as '
                 '[1e16, 1.0, -1e16] returns 1.0. Support empty inputs and one-shot iterators. '
                 'Document floating-point result semantics and add tests/test_accuracy.py.'),
}


def validate_scope(before, after, lane):
    require(lane in LANES, 'Unknown conflict task')
    allowed = {'metrics.py', f'tests/test_{lane}.py'}
    require(set(before) <= set(after) and set(after) <= set(before) | allowed,
            'Conflict task deleted or introduced an unscoped file')
    require(all(after[p] == value for p, value in before.items() if p not in allowed),
            'Conflict task changed unrelated source or workflow')
    require(all(p in after and not after[p]['executable'] for p in allowed),
            'Expected regular non-executable task files')
    require(after['metrics.py'] != before['metrics.py'], 'Task did not modify metrics')


def copy_tree(source, destination):
    """Copy the validated source inventory; never copy Git/jj metadata."""
    files = inventory(source)
    require(not any(part in ('.git', '.jj') for path in files for part in Path(path).parts),
            'Source contains host history metadata')
    destination.mkdir(parents=True, exist_ok=True)
    for name in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
        target.chmod(0o755 if files[name]['executable'] else 0o644)
    return files


class ConflictTrial(Trial):
    def __init__(self, args):
        if args.phase == 'prepare':
            super().__init__(args)
            shutil.copyfile(Path(__file__), self.root / 'conflict-scenario.py')
            durable(self.root / 'trial.json', {
                'base': args.expected_base, 'seed_host': str(args.seed_host),
                'signing_source': str(args.signing_source), 'jj': str(args.jj),
                'codex': str(args.codex), 'codex_code_mode_host': str(args.codex_code_mode_host),
                'ladyshell_sha256': sha(self.cli), 'resources': inventory(self.resources),
                'scenario_sha256': sha(Path(__file__)), 'continuous_sha256': sha(Path(__file__).with_name('continuous.py')),
            })
        else:
            self.args = args
            self.root = args.state.resolve()
            saved = json.loads((self.root / 'trial.json').read_text())
            for key in ('seed_host', 'signing_source', 'jj', 'codex', 'codex_code_mode_host'):
                setattr(args, key, Path(saved[key]))
            args.expected_base = saved['base']
            self.logs = self.root / 'commands'
            self.sequence = max(int(p.name.split('-')[0]) for p in self.logs.glob('*.intent.json'))
            self.command_lock = threading.Lock()
            self.cli = self.root / 'ladyshell'
            self.resources = self.root / 'resources'
            require(sha(self.cli) == saved['ladyshell_sha256'] and inventory(self.resources) == saved['resources'],
                    'Retained native binary or resources changed')
        self.env = environment(args.jj)

    def git(self, lane, *args):
        return self.call(lane.name + '-git', ['git', *args], cwd=lane / 'history').decode().strip()

    def provision(self, name):
        lane = self.root / name
        lane.mkdir()
        history = lane / 'history'
        initialize_checkout(history, self.env)
        self.git(lane, 'remote', 'add', 'origin', 'https://github.com/f1b0-oss/jjpr-lab.git')
        self.git(lane, 'fetch', 'origin', f'refs/heads/{TARGET}:refs/remotes/origin/{TARGET}')
        actual = self.git(lane, 'rev-parse', f'refs/remotes/origin/{TARGET}')
        require(actual == self.args.expected_base, 'Live base moved before provisioning')
        self.git(lane, 'checkout', '--detach', actual)
        before = commit_inventory(history, actual, self.env)
        project = lane / 'project'
        project.mkdir()
        for path, item in before.items():
            require(not item['executable'], 'Fixture requires ordinary source files')
            target = project / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(history / path, target)
            target.chmod(0o644)
        require(inventory(project) == before, 'Copied base differs')
        signing = {key: run(['git', 'config', '--local', key], self.env, self.args.signing_source)
                   for key in ('user.name', 'user.email', 'user.signingkey', 'gpg.format', 'gpg.ssh.allowedSignersFile')}
        for key, value in signing.items():
            self.git(lane, 'config', '--local', key, value)
        self.history(lane, 'git', 'init', '--colocate')
        for key, value in {'user.name': signing['user.name'], 'user.email': signing['user.email'],
                           'signing.backend': 'ssh', 'signing.key': signing['user.signingkey'],
                           'signing.behavior': 'own'}.items():
            self.history(lane, 'config', 'set', '--repo', key, value)
        self.history(lane, 'bookmark', 'track', TARGET + '@origin')
        self.history(lane, 'new', '-r', actual, '-m', 'Prepare ' + name + ' task')
        include = sorted({Path(p).parts[0] for p in before})
        (lane / 'config.ncl').write_text(configuration(include=include).replace(
            'checks = []', 'checks = [["python", "-m", "unittest", "discover", "-s", "tests", "-v"]]'))
        durable(lane / 'base.json', {'oid': actual, 'files': before})
        for action in ('lock', 'plan', 'apply'):
            self.native(name + '-' + action, action, *self.inputs(lane))
        self.native(name + '-init', 'cs', 'init', '--state', lane / 'state', '--task', 'conflict-' + name)
        durable(lane / 'initial-sandbox.json', {'sandbox_id': self.current(lane)['sandbox_id']})
        return lane

    def run_agent(self, lane, label, instruction, resolution=False):
        return self.agent(lane, label, instruction, constraints=(
            f'Change only metrics.py and tests/test_{lane.name}.py. Preserve all other files. '
            'Do not change dependencies. Run python -m unittest discover -s tests -v. '
            'Do not use Git or contact any forge.'), resolution=resolution)

    def checked_commit(self, lane, number, report, parent, before):
        attempt = lane / f'round-{number}'
        attempt.mkdir()
        self.native(lane.name + '-export', 'sync', '--state', lane / 'state', '--export')
        export = Path(self.current(lane)['last_sync'])
        files = inventory(export / 'project')
        validate_scope(before, files, lane.name)
        oracle = 'from metrics import total\nassert total(iter([3,-2,8])) == 9\nassert total([]) == 0\n'
        if lane.name == 'start' or number > 1:
            oracle += 'assert total(iter([1,2]), start=10) == 13\nassert total([], start=7) == 7\n'
        if lane.name == 'accuracy':
            oracle += 'assert total(iter([1e16,1.0,-1e16])) == 1.0\n'
        if number > 1:
            oracle += 'assert total(iter([1e16,1.0,-1e16]), start=2.0) == 3.0\n'
        policy = attempt / 'checks-policy.json'
        durable(policy, {'schema_version': 1, 'checks': {'commands': [
            ['python', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
            ['python', '-c', oracle]], 'timeout': 60}})
        self.native(lane.name + '-independent-check', 'publication', 'check', '--state', lane / 'state',
                    '--export', export, '--policy', policy)
        checks = json.loads((export / 'checks.json').read_text())
        require(checks['passed'] and checks['cleanup_confirmed'], 'Independent verifier or cleanup failed')
        copy_tree(export / 'project', lane / 'history')
        review_body = render_review([report], commands_per_snapshot=2)
        review_binding = None
        if number > 1:
            from conflict_review import package
            context = json.loads((lane / 'conflict-context.json').read_text())
            preliminary = self.revision(lane, '@')
            tree = self.git(lane, 'rev-parse', preliminary['commit'] + '^{tree}')
            review_package = package(context, report, export, policy, tree)
            review_path = attempt / 'conflict-review.json'
            durable(review_path, review_package)
            review_binding = {'path': str(review_path), 'sha256': sha(review_path)}
            config = json.loads(self.args.config.read_text())
            config.pop('publication', None)
            config.update(workspace=str(lane / 'history'), conflict_review=review_binding)
            durable(attempt / 'review-config.json', config)
            review_body = self.call('render-conflict-review', [self.args.adapter, 'render-conflict',
                attempt / 'review-config.json', preliminary['commit']]).decode()
            durable(attempt / 'conflict-review-display.json', {'body': review_body, 'package': review_binding})
        self.history(lane, 'describe', '-m', report['summary'].splitlines()[0], '-m', review_body)
        revision = self.revision(lane, '@')
        require(revision['conflict'] == 'false', 'Unresolved conflict remains')
        branch = 'agent/ladyhost-1/' + lane.name
        self.history(lane, 'bookmark', 'create' if number == 1 else 'set', branch, '-r', '@')
        self.git(lane, 'verify-commit', revision['commit'])
        require(self.git(lane, 'rev-parse', revision['commit'] + '^') == parent, 'Unexpected history parent')
        require(commit_inventory(lane / 'history', revision['commit'], self.env) == files, 'Signed tree differs from checked export')
        result = dict(revision, oid=revision['commit'], change_id=revision['change'], bookmark=branch,
                      export=str(export), files=files, checks=checks, parent=parent, round=number,
                      manifest_sha256=sha(export / 'manifest.json'), host_check_policy_sha256=sha(policy),
                      report=report, sandbox_id=self.current(lane)['sandbox_id'], conflict_review=review_binding)
        durable(attempt / 'result.json', result)
        return result

    def prepare(self):
        lanes = [self.provision(name) for name in LANES]
        def first(lane):
            report = self.run_agent(lane, lane.name + '-first', INSTRUCTIONS[lane.name])
            before = json.loads((lane / 'base.json').read_text())
            return self.checked_commit(lane, 1, report, before['oid'], before['files'])
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(first, lanes))
        durable(self.root / 'prepared.json', {'tasks': dict(zip(LANES, results)), 'forge_publication': False})

    def resolve(self):
        from ci_trial import api_environment
        lane = self.root / 'accuracy'
        old = json.loads((lane / 'round-1/result.json').read_text())
        first = json.loads((self.root / 'start/round-1/result.json').read_text())
        published = json.loads((self.root / 'start/round-1/publication.json').read_text())
        api_env = api_environment(self.args.adapter, self.args.config, self.env)
        pr = json.loads(run([self.args.gh, 'api', f'repos/f1b0-oss/jjpr-lab/pulls/{published["pr"]}'], api_env))
        require(pr['merged'] is True and pr['merge_commit_sha'] == first['oid']
                and pr['head']['sha'] == first['oid'] and pr['base']['ref'] == TARGET,
                'First PR has not integrated the exact signed candidate')
        require(self.revision(lane, old['bookmark'])['commit'] == old['oid'], 'Accuracy task moved locally')
        self.history(lane, 'git', 'fetch', '--remote', 'origin')
        upstream = self.git(lane, 'rev-parse', 'refs/remotes/origin/' + TARGET)
        require(upstream == first['oid'], 'Live target differs from the first checked candidate')
        checkpoint = self.checkpoint(lane, 1)
        require(inventory(checkpoint) == old['files'], 'Sandbox changed since the first checked export')
        intent = lane / 'resolve.intent.json'
        durable(intent, {'previous_oid': old['oid'], 'target_oid': upstream, 'change_id': old['change_id']})
        self.history(lane, 'rebase', '-r', old['bookmark'], '-d', TARGET + '@origin')
        self.history(lane, 'edit', old['bookmark'])
        conflicted = self.revision(lane, '@')
        require(conflicted['change'] == old['change_id'] and conflicted['conflict'] == 'true',
                'Expected an actual jj conflict with preserved task identity')
        before = commit_inventory(lane / 'history', upstream, self.env)
        candidate = lane / 'conflict-candidate'
        candidate.mkdir()
        for name in sorted(set(before) | set(old['files'])):
            source = lane / 'history' / name
            require(source.is_file() and not source.is_symlink(), 'Unexpected conflict materialization')
            target = candidate / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o644)
        conflict_listing = self.history(lane, 'resolve', '--list')
        # This fixture changes one shared function; refuse any wider conflict scope.
        conflict_paths = [line.split()[0] for line in conflict_listing.splitlines() if line.strip()]
        require(conflict_paths == ['metrics.py'], 'Unexpected observed conflict paths')
        durable(lane / 'conflict-observed.json', {'revision': conflicted, 'files': inventory(candidate), 'paths': conflict_paths})
        durable(lane / 'conflict-context.json', {
            'repository': 'f1b0-oss/jjpr-lab', 'target': TARGET, 'change_id': old['change_id'],
            'original_base': old['parent'], 'previous_head': old['oid'], 'upstream_head': upstream,
            'task_intent': INSTRUCTIONS['accuracy'], 'upstream_intent': INSTRUCTIONS['start'],
            'conflict_paths': conflict_paths, 'independent_checks': [{'command_index': 1,
                'covers': ['task', 'upstream', 'interaction'],
                'purpose': 'Host-selected assertions include total([1e16,1,-1e16], start=2) == 3, total([], start=7) == 7, and one-shot iterator cases.'}]})
        refreshed = self.refresh(lane, candidate, {
            'objective': 'Resolve the PR conflict after the starting-value task was integrated',
            'previous_agent_report': old['report'], 'upstream_agent_report': first['report'],
            'upstream_commit': upstream, 'previous_commit': old['oid'], 'jj_change_id': old['change_id'],
            'next_steps': ['Resolve all conflict markers in metrics.py.',
                'Preserve upstream total(values, *, start=0), empty inputs, and one-shot iterators.',
                'Preserve math.fsum accuracy; total([1e16,1,-1e16], start=2) must equal 3.',
                'Preserve tests/test_start.py unchanged. Extend tests/test_accuracy.py for combined behavior.',
                'Run the complete unittest suite. Do not change dependencies.'],
        }, 1)
        require(refreshed['sandbox_id'] == old['sandbox_id'], 'Expected warm continuation, not replacement')
        report = self.run_agent(lane, 'accuracy-resolve',
            'Read /sandbox/workspace/.ladyshell-cs/context.json. Resolve the real jj conflict '
            'in the refreshed source, combining both tasks as instructed.', resolution=True)
        result = self.checked_commit(lane, 2, report, upstream, before)
        require(result['change_id'] == old['change_id'], 'Resolution lost task identity')
        durable(lane / 'resolved.json', {'old': old['oid'], 'new': result['oid'], 'change_id': result['change_id'],
                                      'sandbox_reused': True, 'forge_publication': False})

    def cleanup_all(self):
        for name in LANES:
            lane = self.root / name
            if (lane / 'state/state.json').exists() and not (lane / 'state/destroy.json').exists():
                self.cleanup(lane)


    def publish(self):
        from checks import validate_check_binding, validate_policy_file
        from ci_trial import api_environment, validate_revision
        lane = self.root / self.args.lane
        attempt = lane / f'round-{self.args.round}'
        result = json.loads((attempt / 'result.json').read_text())
        export = Path(result['export'])
        require(sha(export / 'manifest.json') == result['manifest_sha256']
                and inventory(export / 'project') == result['files']
                and json.loads((export / 'checks.json').read_text()) == result['checks'],
                'Retained export or independent evidence changed')
        validate_policy_file(result, (attempt / 'checks-policy.json').read_bytes())
        require(self.revision(lane, result['bookmark'])['commit'] == result['oid'], 'Local bookmark changed')
        require(self.git(lane, 'ls-remote', 'origin', 'refs/heads/' + TARGET).split()[0] == result['parent'],
                'Target moved; reconcile and recheck before publishing')
        self.git(lane, 'verify-commit', result['oid'])
        tree = commit_inventory(lane / 'history', result['oid'], self.env)
        require(tree == result['files'], 'Signed tree changed')
        config = json.loads(self.args.config.read_text())
        require(config['github_app']['slug'] == 'ladyhost-1' and config['owner'] == 'f1b0-oss'
                and config['repository'] == 'jjpr-lab' and config['expected_repository_id'] == 1447552368
                and config['stack_base'] == TARGET, 'Unexpected live experiment binding')
        config.pop('publication', None)
        config['workspace'] = str(lane / 'history')
        if self.args.round > 1:
            require((lane / 'conflict-context.json').is_file() and result.get('conflict_review'),
                    'Observed conflict lacks host-bound review context; refusing publication')
            config['conflict_review'] = result['conflict_review']
        auth = attempt / 'auth.json'
        durable(auth, config)
        self.call('app-preflight', [self.args.adapter, 'preflight', auth])
        self.call('app-git-helper', [self.args.adapter, 'git-helper', auth])
        api_env = api_environment(self.args.adapter, auth, self.env)
        endpoint = 'repos/f1b0-oss/jjpr-lab'
        previous = lane / 'round-1'
        prior, revision, pr_number = [], {}, None
        if self.args.round > 1:
            old = json.loads((previous / 'result.json').read_text())
            pr_number = json.loads((previous / 'publication.json').read_text())['pr']
            pr = json.loads(run([self.args.gh, 'api', f'{endpoint}/pulls/{pr_number}'], api_env))
            validate_revision(config, {'bookmark': old['bookmark'], 'commits': [old['oid']]}, pr_number, pr)
            require(self.git(lane, 'ls-remote', 'origin', 'refs/heads/' + old['bookmark']).split()[0] == old['oid'],
                    'Previously published source changed')
            reviews = json.loads(run([self.args.gh, 'api', f'{endpoint}/pulls/{pr_number}/reviews?per_page=100'], api_env))
            require(len(reviews) < 100, 'Review list needs explicit pagination')
            durable(attempt / 'superseded-reviews.json', [r['id'] for r in reviews])
            prior = [str(previous / 'effects')]
            revision = {result['bookmark']: pr_number}
        config['publication'] = {'task': 'conflict-' + lane.name, 'receipt_dir': str(attempt / 'effects'),
                                 'prior_receipts': prior, 'bookmarks': {result['bookmark']: result['oid']},
                                 'revision_prs': revision}
        durable(attempt / 'config.json', config)
        self.call(lane.name + '-publish', [self.args.adapter, 'submit', attempt / 'config.json', result['bookmark']])
        if pr_number is None:
            matches = []
            for path in (attempt / 'effects').glob('*.ok.json'):
                item = json.loads(path.read_text()).get('result')
                if isinstance(item, dict) and item.get('head') == result['bookmark'] and item.get('oid') == result['oid'] and type(item.get('pr')) is int:
                    matches.append(item['pr'])
            require(len(matches) == 1, 'Unique publication acknowledgement missing; reconcile')
            pr_number = matches[0]
        remote = self.git(lane, 'ls-remote', 'origin', 'refs/heads/' + result['bookmark']).split()[0]
        confirmed = {'oid': result['oid'], 'remote_oid': remote}
        validate_check_binding(result, result, confirmed, tree)
        pr = json.loads(run([self.args.gh, 'api', f'{endpoint}/pulls/{pr_number}'], api_env))
        validate_revision(config, {'bookmark': result['bookmark'], 'commits': [result['oid']]}, pr_number, pr)
        durable(attempt / 'confirmed.json', confirmed)
        durable(attempt / 'publication.json', {'pr': pr_number, 'oid': remote, 'url': pr['html_url']})
        body = {'context': 'fixture/verify', 'state': 'success',
                'description': 'Independent Ladyshell verifier passed on these exact file bytes'}
        durable(attempt / 'status.intent.json', {'oid': remote, 'body': body,
                'manifest_sha256': result['manifest_sha256'], 'policy_sha256': result['checks']['policy_sha256']})
        durable(attempt / 'status-body.json', body)
        status = json.loads(run([self.args.gh, 'api', f'{endpoint}/statuses/{remote}', '--method', 'POST',
                                 '--input', attempt / 'status-body.json'], api_env))
        require(status.get('state') == 'success' and status.get('context') == 'fixture/verify'
                and status.get('creator', {}).get('login') == config['expected_actor'], 'Status outcome uncertain')
        durable(attempt / 'status.ok.json', status)
        print(json.dumps({'pr': pr_number, 'url': pr['html_url'], 'oid': remote}), flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['prepare', 'publish', 'resolve', 'cleanup_all'])
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--expected-base')
    parser.add_argument('--seed-host', type=Path)
    parser.add_argument('--signing-source', type=Path)
    parser.add_argument('--ladyshell', type=Path)
    parser.add_argument('--lady-source', type=Path)
    parser.add_argument('--jj', type=Path)
    parser.add_argument('--codex', type=Path)
    parser.add_argument('--codex-code-mode-host', type=Path)
    parser.add_argument('--lane', choices=LANES)
    parser.add_argument('--round', type=int, choices=(1, 2), default=1)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--adapter', type=Path)
    parser.add_argument('--gh', type=Path)
    args = parser.parse_args()
    if args.phase == 'prepare':
        required = ('expected_base', 'seed_host', 'signing_source', 'ladyshell',
                    'lady_source', 'jj', 'codex', 'codex_code_mode_host')
        missing = [name.replace('_', '-') for name in required if getattr(args, name) is None]
        if missing:
            parser.error('prepare requires: ' + ', '.join('--' + name for name in missing))
    args.mode = 'github-conflict'
    trial = ConflictTrial(args)
    getattr(trial, args.phase)()

if __name__ == '__main__':
    main()
