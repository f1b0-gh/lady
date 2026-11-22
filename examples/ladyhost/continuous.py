#!/usr/bin/env python3
"""Reproduce Ladyshell CS and the Ladyhost/jj handoff on disposable fixtures.

This is scenario orchestration, not a protocol controller: native Ladyshell owns
compatibility, epochs, transfers, recovery and deletion. jj owns history. Project
code and models run only in the sandbox; no forge credentials enter this trial.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from agents import clean_environment, configuration, durable, require, sha

SEED = {'app/calc.py': 'def total(values):\n    return sum(values)\n',
        'app/test_calc.py': 'import unittest\nfrom calc import total\nclass Tests(unittest.TestCase):\n    def test_total(self):\n        self.assertEqual(total([1, 2]), 3)\n'}


class Trial:
    def __init__(self, args):
        self.args = args
        self.root = args.state.absolute()
        self.root.mkdir(mode=0o700)
        self.logs = self.root / 'commands'
        self.logs.mkdir()
        shutil.copyfile(Path(__file__), self.root / 'scenario.py')
        self.sequence = 0
        self.command_lock = threading.Lock()
        self.env = clean_environment()
        self.cli = self.root / 'ladyshell'
        shutil.copyfile(args.ladyshell, self.cli)
        self.cli.chmod(0o700)
        # Freeze the maintained resource subset used by the normal image profile.
        self.resources = self.root / 'resources'
        for name in ('config/schema.ncl', 'nix/flake.nix', 'nix/flake.lock',
                     'nix/build.nix', 'nix/image.nix', 'nix/dependencies.nix', 'nix/openssl.nix'):
            target = self.resources / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(args.lady_source / name, target)
        shutil.copytree(args.lady_source / 'crates/ladyshell/resources/audit', self.resources / 'crates/ladyshell/resources/audit')
        durable(self.root / 'inputs.json', {'schema_version': 1,
                'scenario_sha256': sha(Path(__file__)), 'ladyshell_sha256': sha(self.cli),
                'codex_sha256': sha(args.codex), 'profile': 'local-docker-openshell',
                'mode': args.mode, 'forge_publication': False})

    def call(self, label, argv, cwd=None, expected=0, timeout=1800):
        with self.command_lock:
            self.sequence += 1
            stem = self.logs / f'{self.sequence:04d}-{label}'
        argv = list(map(str, argv))
        durable(stem.with_suffix('.intent.json'), {'argv': argv, 'cwd': str(cwd) if cwd else None})
        started = time.monotonic()
        result = subprocess.run(argv, cwd=cwd, env=self.env, capture_output=True, timeout=timeout)
        seconds = round(time.monotonic() - started, 3)
        stem.with_suffix('.stdout').write_bytes(result.stdout)
        stem.with_suffix('.stderr').write_bytes(result.stderr)
        durable(stem.with_suffix('.receipt.json'), {'exit_code': result.returncode, 'seconds': seconds})
        print(f'{label}: exit={result.returncode}, seconds={seconds}', flush=True)
        require(result.returncode == expected, f'{label} failed; inspect {stem}.stderr')
        return result.stdout

    def agent(self, lane, label, instruction, constraints=None, resolution=False):
        from handoff import HANDOFF_INSTRUCTION, RESOLUTION_INSTRUCTION, extract_report
        # Only a non-secret account routing identifier enters the guest.
        with (Path.home() / '.codex/auth.json').open() as stream:
            routing = json.load(stream)['tokens']['account_id']
        argv = [str(self.args.codex), '--no-daemon', '--ask-for-approval', 'never', 'exec',
                '--ephemeral', '--ignore-user-config', '--ignore-rules', '--strict-config',
                '--skip-git-repo-check', '--sandbox', 'danger-full-access', '--cd',
                '/sandbox/workspace/project', '--json', '--color', 'never']
        for option in ('web_search="disabled"', 'analytics.enabled=false', 'features.apps=false',
                       'features.plugins=false', 'features.remote_plugin=false', 'features.hooks=false',
                       'features.multi_agent=false', 'history.persistence="none"'):
            argv += ['-c', option]
        if constraints is None:
            constraints = ('Change only regular files under app. Do not change dependencies. '
                           'Run python -m unittest discover -s app. Do not use Git or contact any forge.')
        argv += [instruction + ' ' + constraints + ' ' + (RESOLUTION_INSTRUCTION if resolution else HANDOFF_INSTRUCTION)]
        driver = ('import os,subprocess\n'
                  'assert "SSH_AUTH_SOCK" not in os.environ\n'
                  'os.environ["CODEX_HOME"]="/sandbox/.codex"\n'
                  'os.environ["CODEX_ACCOUNT_ID"]=' + repr(routing) + '\n'
                  'subprocess.run(["/usr/local/bin/ladyshell","remote-auth"],check=True)\n'
                  'subprocess.run(' + repr(argv) + ',check=True)\n')
        output = self.native(label, 'run', '--state', lane / 'state', '--timeout', '900', '--', 'python', '-c', driver, timeout=960)
        report = extract_report(output, resolution=resolution)
        durable(lane / (label + '-handoff.json'), report)
        self.check(lane, label + '-check')
        return report

    def native(self, label, *args, **kwargs):
        return self.call(label, [self.cli, *args], **kwargs)

    def current(self, lane):
        return json.loads((lane / 'state/state.json').read_text())

    def inputs(self, lane, project=None):
        return ['--config', lane / 'config.ncl', '--project', project or lane / 'project',
                '--state', lane / 'state', '--resources', self.resources,
                '--codex', self.args.codex, '--codex-code-mode-host', self.args.codex_code_mode_host]

    def provision(self, name):
        lane = self.root / name
        lane.mkdir()
        for path, text in SEED.items():
            target = lane / 'project' / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        (lane / 'config.ncl').write_text(configuration(include=['app']).replace(
            'checks = []', 'checks = [["python", "-m", "unittest", "discover", "-s", "app"]]'))
        for action in ('lock', 'plan', 'apply'):
            self.native(name + '-' + action, action, *self.inputs(lane))
        self.native(name + '-init', 'cs', 'init', '--state', lane / 'state', '--task', 'cs-' + name)
        return lane

    def checkpoint(self, lane, number):
        epoch = self.current(lane)['continuous']['epoch']
        self.native(lane.name + '-checkpoint-' + str(number), 'cs', 'checkpoint', '--state', lane / 'state',
                    '--attempt', 'checkpoint-' + str(number), '--epoch', epoch)
        current = self.current(lane)
        require(current['continuous']['phase'] == 'checkpointed', 'checkpoint not confirmed')
        return Path(current['last_sync']) / 'project'

    def refresh(self, lane, candidate, context, number):
        context_path = lane / f'context-{number}.json'
        durable(context_path, context)
        self.native(lane.name + '-refresh-' + str(number), 'cs', 'refresh', *self.inputs(lane, candidate),
                    '--attempt', 'refresh-' + str(number), '--context', context_path)
        current = self.current(lane)
        if current['continuous']['phase'] == 'replacement_required':
            self.native(lane.name + '-replace-' + str(number), 'cs', 'replace', '--state', lane / 'state')
        else:
            require(current['continuous']['phase'] == 'refreshed', 'refresh not acknowledged')
            self.native(lane.name + '-resume-' + str(number), 'cs', 'resume', '--state', lane / 'state',
                        '--epoch', current['continuous']['acknowledgement']['epoch'])
        return self.current(lane)

    def check(self, lane, label):
        self.native(label, 'check', '--state', lane / 'state')

    def cleanup(self, lane):
        self.native(lane.name + '-cleanup', 'destroy', '--state', lane / 'state')
        receipt = json.loads((lane / 'state/destroy.json').read_text())
        require(receipt['deleted'] is True, 'owned cleanup not confirmed')

    def smoke(self):
        lane = self.provision('lifecycle')
        initial = self.current(lane)
        self.check(lane, 'initial-check')
        writer = ("mkdir -p /sandbox/workspace/cache; echo retained > /sandbox/workspace/cache/cs-sentinel; "
                  "nohup /bin/bash -c 'while :; do date +%s%N > /sandbox/workspace/cache/cs-heartbeat; "
                  "sleep 0.1; done' >/sandbox/workspace/cache/cs-writer.log 2>&1 </dev/null &")
        self.native('detached-writer', 'run', '--state', lane / 'state', '--', '/bin/bash', '-c', writer)
        export = self.checkpoint(lane, 1)
        checkpoint = self.current(lane)
        require(checkpoint['sandbox_id'] == initial['sandbox_id'], 'checkpoint replaced sandbox')
        require(checkpoint['continuous']['runtime'] != initial['continuous']['runtime'], 'restart not observed')
        self.native('pending-execution-refused', 'run', '--state', lane / 'state', '--', '/bin/true', expected=2)
        # Read-only observation while the managed application is fenced.
        output = self.call('writer-termination', ['openshell', '--gateway', 'openshell', '--workspace', 'default',
            'sandbox', 'exec', '--no-tty', '--no-login-shell', checkpoint['sandbox_name'], '--', '/bin/bash', '-c',
            'cat /sandbox/workspace/cache/cs-sentinel; cat /sandbox/workspace/cache/cs-heartbeat; '
            'sleep 1; cat /sandbox/workspace/cache/cs-heartbeat']).decode().splitlines()
        require(len(output) == 3 and output[0] == 'retained' and output[1] == output[2], 'old writer survived or cache lost')
        candidate = lane / 'candidate-1'
        shutil.copytree(export, candidate)
        (candidate / 'app/calc.py').write_text('def total(values):\n    return sum(values) + 1\n')
        (candidate / 'app/test_calc.py').write_text(SEED['app/test_calc.py'].replace(']), 3)', ']), 4)'))
        warm = self.refresh(lane, candidate, {'objective': 'Continue after a source-only update',
                'upstream': 'Fixture adds one to the total', 'next_steps': ['Run the existing tests']}, 1)
        require(warm['sandbox_id'] == initial['sandbox_id'] and warm['continuous']['epoch'] == 1, 'source-only update was not warm')
        self.check(lane, 'warm-check')
        self.native('context-delivered', 'run', '--state', lane / 'state', '--', 'python', '-c',
                    'import json; v=json.load(open("/sandbox/workspace/.ladyshell-cs/context.json")); '
                    'assert v["binding"]["epoch"] == 1; assert v["context"]["objective"]')
        export = self.checkpoint(lane, 2)
        cold_candidate = lane / 'candidate-2'
        shutil.copytree(export, cold_candidate)
        (cold_candidate / 'app/pyproject.toml').write_text(
            '[project]\nname = "continuous-fixture"\nversion = "0.1.0"\nrequires-python = ">=3.12"\ndependencies = []\n')
        cold = self.refresh(lane, cold_candidate, {'objective': 'Continue with a newly declared project environment',
                'next_steps': ['Run tests and inspect the retained context']}, 2)
        require(cold['sandbox_id'] != warm['sandbox_id'] and cold['continuous']['epoch'] == 2, 'dependency input did not replace incarnation')
        require(cold['continuous']['task'] == warm['continuous']['task'], 'task identity lost')
        require(cold['continuous_replacement']['stage'] == 'complete', 'old incarnation not retired')
        self.check(lane, 'replacement-check')
        self.native('replacement-context', 'run', '--state', lane / 'state', '--', 'python', '-c',
                    'import json; v=json.load(open("/sandbox/workspace/.ladyshell-cs/context.json")); '
                    'assert v["binding"]["epoch"] == 2; assert v["context"]["objective"]')
        self.cleanup(lane)
        durable(self.root / 'results.json', {'passed': True, 'initial_id': initial['sandbox_id'],
                'warm_id': warm['sandbox_id'], 'replacement_id': cold['sandbox_id'], 'final_epoch': 2,
                'writer_terminated': True, 'cache_preserved': True, 'owned_cleanup_confirmed': True,
                'limits': ['Local Docker OpenShell only', 'No model or forge operation in smoke mode']})

    def history(self, lane, *args):
        return self.call(lane.name + '-jj', [self.args.jj, '--no-pager', *args], cwd=lane / 'history').decode().strip()

    def revision(self, lane, rev):
        result = self.history(lane, 'log', '--no-graph', '-r', rev, '-T',
                              'commit_id ++ " " ++ change_id ++ " " ++ conflict').split()
        require(len(result) == 3, 'expected one jj revision')
        return dict(zip(('commit', 'change', 'conflict'), result))

    def import_source(self, lane, source):
        # This controlled fixture selects app only; native exports have already
        # rejected links, special files, metadata paths and oversized payloads.
        require(set(p.name for p in source.iterdir()) == {'app'}, 'unexpected fixture export scope')
        target = lane / 'history/app'
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source / 'app', target)

    def setup_history(self, lane):
        self.call(lane.name + '-history-init', [self.args.jj, 'git', 'init', '--colocate', lane / 'history'])
        key = self.root / 'signing'
        for name, value in {'user.name': 'Ladyhost CS trial', 'user.email': 'cs@example.invalid',
                            'signing.backend': 'ssh', 'signing.key': str(key), 'signing.behavior': 'own'}.items():
            self.history(lane, 'config', 'set', '--repo', name, value)
        for name, value in {'gpg.format': 'ssh', 'gpg.ssh.allowedSignersFile': str(self.root / 'allowed_signers'),
                            'core.hooksPath': '/dev/null'}.items():
            self.call(lane.name + '-git-config', ['git', '-C', lane / 'history', 'config', '--local', name, value])
        self.import_source(lane, lane / 'project')
        self.history(lane, 'describe', '-m', 'Seed continuous sandboxing fixture')
        base = self.revision(lane, '@')
        self.history(lane, 'bookmark', 'create', 'base', '-r', '@')
        self.history(lane, 'new', '-m', lane.name + ': first iteration')
        return base

    def agents(self):
        self.env['JJ_CONFIG'] = '/dev/null'
        self.call('host-signing-key', ['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.root / 'signing'])
        (self.root / 'allowed_signers').write_text('cs@example.invalid ' + (self.root / 'signing.pub').read_text())
        lanes = [self.provision(name) for name in ('statistics', 'ranges', 'rolling')]
        initial = {lane.name: self.current(lane)['sandbox_id'] for lane in lanes}
        bases = {lane.name: self.setup_history(lane) for lane in lanes}
        parents = {
            'statistics': 'mean(values): arithmetic mean, ValueError for empty input; consume generators once',
            'ranges': 'bounds(values): (minimum, maximum), ValueError for empty input; consume generators once',
            'rolling': 'windows(values, width): yield full consecutive tuples; width must be a positive integer excluding bool, reject wrong types with TypeError and nonpositive widths with ValueError',
        }
        children = {
            'statistics': 'population_variance(values): population variance, ValueError for empty input; call mean directly',
            'ranges': 'normalize(values): values scaled to [0,1], all zeros for a constant sequence, ValueError for empty input; call bounds directly',
            'rolling': 'moving_average(values, width): list of averages of full windows; call windows directly and preserve its width validation',
        }
        def first(lane):
            return self.agent(lane, lane.name + '-first', 'In app/calc.py rewrite total using an explicit accumulation loop '
                '(same behavior), then implement ' + parents[lane.name] + '. Add focused unittest coverage in app/test_calc.py.')
        with ThreadPoolExecutor(max_workers=3) as pool:
            reports = dict(zip((lane.name for lane in lanes), pool.map(first, lanes)))
        before = {}
        for lane in lanes:
            export = self.checkpoint(lane, 1)
            self.import_source(lane, export)
            self.history(lane, 'describe', '-m', reports[lane.name]['summary'])
            self.history(lane, 'bookmark', 'create', 'task', '-r', '@')
            before[lane.name] = self.revision(lane, 'task')
            self.history(lane, 'new', '-r', 'base', '-m', 'Upstream requires stable floating point summation')
            (lane / 'history/app/calc.py').write_text('import math\ndef total(values):\n    return math.fsum(values)\n')
            (lane / 'history/app/test_calc.py').write_text(SEED['app/test_calc.py'] +
                '    def test_cancellation(self):\n        self.assertEqual(total([1e16, 1, -1e16]), 1)\n')
            upstream = self.revision(lane, '@')
            self.history(lane, 'rebase', '-s', 'task', '-d', upstream['commit'])
            self.history(lane, 'edit', 'task')
            conflicted = self.revision(lane, '@')
            require(conflicted['change'] == before[lane.name]['change'] and conflicted['conflict'] == 'true',
                    'expected a real jj conflict with stable task identity')
            candidate = lane / 'conflict-candidate'
            candidate.mkdir()
            shutil.copytree(lane / 'history/app', candidate / 'app')
            self.refresh(lane, candidate, {'objective': 'Resolve the task after upstream movement',
                    'agent_previous_report': reports[lane.name], 'jj_change_id': conflicted['change'],
                    'upstream_commit': upstream['commit'], 'conflicted_commit': conflicted['commit'],
                    'next_steps': ['Resolve all conflict markers in app without losing the first API or its tests',
                        'Preserve upstream math.fsum behavior and cancellation test; it supersedes the old loop request',
                        'Do not add the second API yet; run the full unittest suite']}, 1)
        def resolve(lane):
            return self.agent(lane, lane.name + '-resolve', 'Read /sandbox/workspace/.ladyshell-cs/context.json '
                    'and follow the task-specific reconciliation instructions. Resolve the actual jj conflict in the current source.')
        with ThreadPoolExecutor(max_workers=3) as pool:
            resolved_reports = dict(zip((lane.name for lane in lanes), pool.map(resolve, lanes)))
        resolved = {}
        for lane in lanes:
            export = self.checkpoint(lane, 2)
            self.import_source(lane, export)
            self.history(lane, 'describe', '-m', resolved_reports[lane.name]['summary'])
            resolved[lane.name] = self.revision(lane, 'task')
            require(resolved[lane.name]['change'] == before[lane.name]['change']
                    and resolved[lane.name]['conflict'] == 'false', 'resolved export lost task identity or retains conflict')
            self.history(lane, 'new', '-r', 'task', '-m', lane.name + ': dependent iteration')
            self.history(lane, 'bookmark', 'create', 'child', '-r', '@')
            self.refresh(lane, export, {'objective': 'Continue the second dependent iteration',
                    'agent_previous_report': resolved_reports[lane.name],
                    'parent_commit': resolved[lane.name]['commit'], 'parent_change_id': resolved[lane.name]['change'],
                    'next_steps': ['Implement ' + children[lane.name], 'Preserve all existing APIs and tests',
                        'Add tests for the new API and run the full unittest suite']}, 2)
        def child(lane):
            return self.agent(lane, lane.name + '-child', 'Read /sandbox/workspace/.ladyshell-cs/context.json '
                    'and implement the specified dependent iteration in app/calc.py with focused tests.')
        with ThreadPoolExecutor(max_workers=3) as pool:
            child_reports = dict(zip((lane.name for lane in lanes), pool.map(child, lanes)))
        results = {}
        for lane in lanes:
            # Host-selected oracle supplements model-authored tests, inside the sandbox.
            from agents import assertions
            oracle = assertions(lane.name, 'children').replace('import stream_' + lane.name + ' as m', 'import calc as m')
            oracle = 'import sys; sys.path.insert(0,"app")\n' + oracle + '\nassert m.total([1e16,1,-1e16]) == 1\n'
            self.native(lane.name + '-independent-oracle', 'run', '--state', lane / 'state', '--', 'python', '-c', oracle)
            export = self.checkpoint(lane, 3)
            self.import_source(lane, export)
            self.history(lane, 'describe', '-m', child_reports[lane.name]['summary'])
            final = self.revision(lane, 'child')
            require(final['conflict'] == 'false', 'dependent result remains conflicted')
            require(self.current(lane)['sandbox_id'] == initial[lane.name], 'source continuation rebuilt the sandbox')
            for revision in (resolved[lane.name], final):
                self.call(lane.name + '-signature', ['git', '-C', lane / 'history', 'verify-commit', revision['commit']])
            self.call(lane.name + '-ancestry', ['git', '-C', lane / 'history', 'merge-base', '--is-ancestor',
                      resolved[lane.name]['commit'], final['commit']])
            durable(lane / 'checked-candidate.json', {'schema_version': 1, 'export': str(export.parent),
                    'continuous': self.current(lane)['continuous'], 'parent': resolved[lane.name], 'child': final,
                    'agent_explanation': child_reports[lane.name], 'forge_publication': False})
            results[lane.name] = {'initial_task': before[lane.name], 'resolved_task': resolved[lane.name],
                    'child': final, 'sandbox_id': initial[lane.name], 'epochs': 2, 'model_turns': 3}
            self.cleanup(lane)
        durable(self.root / 'results.json', {'passed': True, 'tasks': results, 'owned_cleanup_confirmed': True,
                'limits': ['Local jj signing/history integration; no new GitHub PR or approval',
                           'Nine bounded model turns; not a large-project benchmark']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--ladyshell', type=Path, required=True)
    parser.add_argument('--lady-source', type=Path, required=True)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--codex-code-mode-host', type=Path, required=True)
    parser.add_argument('--mode', choices=['smoke', 'agents'], default='smoke')
    parser.add_argument('--jj', type=Path, help='Pinned jj executable; required in agents mode')
    args = parser.parse_args()
    if args.mode == 'agents' and args.jj is None:
        parser.error("--jj is required in agents mode")
    trial = Trial(args)
    getattr(trial, args.mode)()


if __name__ == '__main__':
    main()
