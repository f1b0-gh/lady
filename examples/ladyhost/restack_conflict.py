#!/usr/bin/env python3
"""Local native jj history trial; no models, sandboxes or forge credentials.

All repositories and an ephemeral signing key live in a new private state path.
The fixed source edits are scenario inputs, never imported untrusted exports.
Interrupted attempts retain evidence and must be inspected, not replayed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from agents import require, sha
from github import save


EMAIL = 'jjpr-local@example.invalid'
SQUARES = 'def sum_squares(values):\n    return sum(v * v for v in values)\n'
REWRITTEN_SQUARES = 'def sum_squares(values):\n    return sum(pow(v, 2) for v in values)\n'
RMS = '''from squares import sum_squares
def root_mean_square(values):
    values = list(values)
    if not values:
        raise ValueError('empty input')
    return (sum_squares(values) / len(values)) ** 0.5
'''
COUNT = '''from metrics import total
def count(values):
    return total(1 for _ in values)
'''
EMPTY = '''from metrics import total
def is_empty(values):
    return total(1 for _ in values) == 0
'''
LOOP = '    result = 0\n    for value in values:\n        result += value\n    return result\n'
ORACLE = '''import math
from metrics import total
from squares import sum_squares
from rms import root_mean_square
for values in ([], [0], [3, -2, 8], [1.5, -4, 2.25]):
    assert total(iter(values)) == sum(values)
    assert math.isclose(sum_squares(iter(values)), math.fsum(v ** 2 for v in values))
    if values:
        assert math.isclose(root_mean_square(iter(values)), math.sqrt(math.fsum(v ** 2 for v in values) / len(values)))
    else:
        try:
            root_mean_square(iter(values))
        except ValueError:
            pass
        else:
            raise AssertionError('empty RMS accepted')
'''


class Trial:
    def __init__(self, state, jj):
        # Do not resolve the final path: an existing symlink must also refuse.
        state.mkdir(mode=0o700)
        self.state = state.resolve()
        self.jj = jj.resolve(strict=True)
        self.sequence = 0
        self.logs = self.state / 'commands'
        self.logs.mkdir()
        # Only non-secret process prerequisites enter this deterministic trial.
        self.env = {k: os.environ[k] for k in ('PATH', 'SYSTEMROOT') if k in os.environ}
        self.env.update(HOME=str(self.state), XDG_CONFIG_HOME=str(self.state / 'config'),
                        JJ_CONFIG='/dev/null', GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                        GIT_ALLOW_PROTOCOL='file', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
        self.remote = self.state / 'remote.git'

    def command(self, cwd, *args, allow_failure=False):
        self.sequence += 1
        stem = self.logs / f'{self.sequence:04d}'
        command = list(map(str, args))
        save(stem.with_suffix('.intent.json'), {'cwd': str(cwd), 'argv': command})
        result = subprocess.run(command, cwd=cwd, env=self.env, capture_output=True,
                                text=True, timeout=60)
        save(stem.with_suffix('.result.json'), {'exit_code': result.returncode,
             'stdout': result.stdout, 'stderr': result.stderr})
        if not allow_failure:
            require(result.returncode == 0, f'command {self.sequence} failed; inspect {stem}.result.json')
        return result

    def git(self, cwd, *args):
        return self.command(cwd, 'git', '-c', 'core.hooksPath=/dev/null', *args).stdout.strip()

    def j(self, cwd, *args):
        return self.command(cwd, self.jj, '--no-pager', *args).stdout.strip()

    def revision(self, cwd, rev):
        fields = self.j(cwd, 'log', '--no-graph', '-r', rev, '-T',
                        'commit_id ++ " " ++ change_id ++ " " ++ conflict').split()
        require(len(fields) == 3, 'expected exactly one revision')
        return dict(zip(('oid', 'change_id', 'conflict'), fields))

    def pair(self, cwd):
        return [self.revision(cwd, name) for name in ('parent', 'task')]

    def refs(self):
        return self.git(self.state, '--git-dir', self.remote, 'show-ref')

    def configure_git(self, checkout):
        for name, value in {'user.name': 'Local jjpr trial', 'user.email': EMAIL,
                            'gpg.format': 'ssh', 'user.signingkey': str(self.key),
                            'gpg.ssh.allowedSignersFile': str(self.trust),
                            'commit.gpgsign': 'true', 'core.hooksPath': '/dev/null'}.items():
            self.git(checkout, 'config', '--local', name, value)

    def setup(self):
        version = self.command(self.state, self.jj, '--version').stdout.strip()
        require(version.split()[1].split('-')[0] == '0.47.1', 'this trial requires jj 0.47.1')
        save(self.state / 'inputs.json', {'jj_version': version, 'jj_sha256': sha(self.jj),
             'scenario_sha256': sha(Path(__file__)), 'model_runs': 0})
        self.key = self.state / 'signing'
        self.trust = self.state / 'allowed_signers'
        self.command(self.state, 'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.key)
        self.trust.write_text(EMAIL + ' ' + self.key.with_suffix('.pub').read_text())
        self.git(self.state, 'init', '--bare', self.remote)
        seed = self.state / 'seed'
        self.git(self.state, 'init', '-b', 'main', seed)
        self.configure_git(seed)
        source = Path(__file__).parent / 'scenario/seed'
        for name in ('metrics.py', 'tests/test_metrics.py'):
            target = seed / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
        self.baseline = (seed / 'metrics.py').read_text()
        self.git(seed, 'add', '.')
        self.git(seed, 'commit', '-m', 'Seed local history trial')
        self.base = self.git(seed, 'rev-parse', 'HEAD')
        self.git(seed, 'remote', 'add', 'origin', self.remote)
        self.git(seed, 'push', 'origin', 'HEAD:refs/heads/main', 'HEAD:refs/heads/trial')

    def stack(self, lane, parent_file, parent_text, child_file, child_text):
        checkout = self.state / lane
        self.git(self.state, 'clone', '--branch', 'main', self.remote, checkout)
        self.configure_git(checkout)
        self.j(checkout, 'git', 'init', '--colocate')
        for name, value in {'user.name': 'Local jjpr trial', 'user.email': EMAIL,
                            'signing.backend': 'ssh', 'signing.key': str(self.key),
                            'signing.behavior': 'own'}.items():
            self.j(checkout, 'config', 'set', '--repo', name, value)
        (checkout / parent_file).write_text(parent_text)
        self.j(checkout, 'describe', '-m', f'{lane}: parent')
        self.j(checkout, 'bookmark', 'create', 'parent', '-r', '@')
        self.j(checkout, 'new', '-m', f'{lane}: child')
        (checkout / child_file).write_text(child_text)
        self.j(checkout, 'bookmark', 'create', 'task', '-r', '@')
        return checkout

    def check(self, checkout, lane):
        self.j(checkout, 'edit', 'task')
        self.command(checkout, sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v')
        oracle = ORACLE
        if lane in ('b', 'c'):
            oracle += '\nfrom count import count\nassert count(iter([0, -1, 5])) == 3\nassert count(iter([])) == 0\n'
        if lane == 'c':
            oracle += '\nfrom empty import is_empty\nassert is_empty(iter([]))\nassert not is_empty(iter([0]))\n'
        self.command(checkout, sys.executable, '-B', '-c', oracle)

    def integrate(self, checkout, expected):
        pair = self.pair(checkout)
        require(all(item['conflict'] == 'false' for item in pair), 'conflicted integration candidate')
        head = pair[-1]['oid']
        self.git(checkout, 'merge-base', '--is-ancestor', expected, head)
        for item in pair:
            self.git(checkout, 'verify-commit', item['oid'])
        self.git(checkout, 'push', f'--force-with-lease=refs/heads/trial:{expected}',
                 'origin', f'{head}:refs/heads/trial')
        require(self.git(self.state, '--git-dir', self.remote, 'rev-parse', 'trial') == head,
                'integration readback mismatch')
        return head

    def run(self):
        self.setup()
        a = self.stack('a', 'squares.py', SQUARES, 'rms.py', RMS)
        b = self.stack('b', 'metrics.py', self.baseline.replace('sum(values)', 'sum(iter(values))'), 'count.py', COUNT)
        c = self.stack('c', 'metrics.py', self.baseline.replace('    return sum(values)\n', LOOP), 'empty.py', EMPTY)
        originals = [item['change_id'] for checkout in (a, b, c) for item in self.pair(checkout)]
        before = self.pair(a)
        self.j(a, 'edit', 'parent')
        (a / 'squares.py').write_text(REWRITTEN_SQUARES)
        after = self.pair(a)
        require(all(old['change_id'] == new['change_id'] and old['oid'] != new['oid']
                    for old, new in zip(before, after)), 'parent rewrite did not restack child')
        self.check(a, 'a')
        target = self.integrate(a, self.base)
        for checkout, lane in ((b, 'b'), (c, 'c')):
            self.j(checkout, 'git', 'fetch', '--remote', 'origin')
            self.j(checkout, 'rebase', '-s', 'parent', '-o', target)
            if lane == 'c':
                require(self.revision(c, 'parent')['conflict'] == 'true', 'expected real code conflict')
                refs_before = self.refs()
                denied = self.command(c, self.jj, 'git', 'push', '--remote', 'origin',
                                      '--bookmark', 'task', allow_failure=True)
                refusal = {'exit_code': denied.returncode, 'stderr': denied.stderr,
                           'refs_before': refs_before, 'refs_after': self.refs()}
                save(self.state / 'conflict-refusal.json', refusal)
                require(denied.returncode != 0 and 'conflict' in denied.stderr.lower()
                        and refusal['refs_before'] == refusal['refs_after'], 'conflicted push did not refuse safely')
                # A clean tip alone is insufficient: the parent still contains
                # the conflict. Exercise jj's ancestry check before fixing it.
                self.j(c, 'edit', 'task')
                (c / 'metrics.py').write_text(self.baseline.replace('    return sum(values)\n', LOOP))
                parent, child = self.pair(c)
                require(parent['conflict'] == 'true' and child['conflict'] == 'false',
                        'expected a clean child above a conflicted parent')
                refs_before = self.refs()
                denied = self.command(c, self.jj, 'git', 'push', '--remote', 'origin',
                                      '--bookmark', 'task', allow_failure=True)
                ancestor_refusal = {'parent': parent, 'child': child,
                                    'exit_code': denied.returncode, 'stderr': denied.stderr,
                                    'refs_before': refs_before, 'refs_after': self.refs()}
                save(self.state / 'ancestor-refusal.json', ancestor_refusal)
                require(denied.returncode != 0 and parent['oid'][:12] in denied.stderr
                        and 'conflict' in denied.stderr.lower()
                        and ancestor_refusal['refs_before'] == ancestor_refusal['refs_after'],
                        'conflicted ancestor was not refused safely')
                # Explicit scenario decision: retain C's loop implementation;
                # all shared total() behavior and B's dependent count must pass.
                self.j(c, 'edit', 'parent')
                (c / 'metrics.py').write_text(self.baseline.replace('    return sum(values)\n', LOOP))
                self.j(c, 'status')
                resolution_restack = self.pair(c)
                require(resolution_restack[0]['conflict'] == 'false'
                        and resolution_restack[1]['conflict'] == 'true',
                        'expected child resolution to need reconciliation after parent edit')
                # Resolving the tip first recorded its own resolution delta.
                # The parent rewrite rebases that delta and conflicts again;
                # explicitly settle the descendant before running checks.
                self.j(c, 'edit', 'task')
                (c / 'metrics.py').write_text(self.baseline.replace('    return sum(values)\n', LOOP))
                require(all(item['conflict'] == 'false' for item in self.pair(c)),
                        'explicit descendant resolution left a conflict')
            self.check(checkout, lane)
            target = self.integrate(checkout, target)
        audit = self.state / 'audit'
        self.git(self.state, 'clone', '--branch', 'trial', self.remote, audit)
        self.configure_git(audit)
        commits = self.git(audit, 'rev-list', '--reverse', f'{self.base}..HEAD').splitlines()
        require(len(commits) == 6, 'expected six retained commits')
        parent = self.base
        for oid in commits:
            require(self.git(audit, 'rev-parse', oid + '^@') == parent, 'nonlinear final history')
            self.git(audit, 'verify-commit', oid)
            parent = oid
        # Fresh Git fetch is independent of jj's worktree and operation state.
        require(self.git(audit, 'rev-parse', 'HEAD') == target, 'final fetch mismatch')
        expected_files = {'metrics.py': self.baseline.replace('    return sum(values)\n', LOOP),
                          'squares.py': REWRITTEN_SQUARES, 'rms.py': RMS, 'count.py': COUNT, 'empty.py': EMPTY}
        for name, content in expected_files.items():
            require((audit / name).read_text() == content, 'resolved contribution mismatch: ' + name)
        self.command(audit, sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v')
        self.command(audit, sys.executable, '-B', '-c', ORACLE + '\nfrom count import count\nfrom empty import is_empty\nassert count(iter([0, 1, -1])) == 3\nassert count(iter([])) == 0\nassert is_empty(iter([])) and not is_empty(iter([0]))\n')
        final_ids = [item['change_id'] for checkout in (a, b, c) for item in self.pair(checkout)]
        main = self.git(audit, 'rev-parse', 'origin/main')
        require(originals == final_ids and main == self.base, 'change identities or main changed')
        result = {'model_runs': 0, 'signed_commit_count': len(commits), 'commits': commits,
                  'final_checks': 'passed', 'main_before': self.base, 'main_after': main,
                  'rewrite': {'before': before, 'after': after}, 'conflict_refusal': refusal,
                  'ancestor_refusal': ancestor_refusal,
                  'resolution_restack': resolution_restack,
                  'original_change_ids': originals, 'final_change_ids': final_ids}
        save(self.state / 'result.json', result)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--jj', type=Path, required=True)
    args = parser.parse_args()
    result = Trial(args.state, args.jj).run()
    print(json.dumps({'state': str(args.state), 'signed_commits': result['signed_commit_count'],
                      'checks': result['final_checks']}))
