#!/usr/bin/env python3
"""Run selected OpenShell agents and retain two checked file exports each.

Scenario orchestration only: maintained Ladyshell owns sandbox identity, exports,
verification and cleanup. No forge client, signing key or history import is used.
Run with a new private --state directory. Interrupted phases are retained; reruns
refuse rather than silently replaying an agent or replacing its evidence.
The default remains the original three tasks; explicit selections are new runs.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from handoff import HANDOFF_DRIVER_HEADER, HANDOFF_INSTRUCTION

HERE = Path(__file__).resolve().parent
LANES = {'statistics': ('mean', 'population_variance'),
         'ranges': ('bounds', 'normalize'), 'rolling': ('windows', 'moving_average'),
         'changes': ('differences', 'total_change')}
DEFAULT_LANES = ('statistics', 'ranges', 'rolling')
OS = ['openshell', '--gateway', 'openshell', '--workspace', 'default', '--color', 'never']

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def selected_lanes(value):
    lanes=DEFAULT_LANES if value is None else tuple(value)
    if not lanes or len(set(lanes))!=len(lanes) or any(lane not in LANES for lane in lanes):
        raise ValueError('Select distinct known tasks')
    return lanes

def seed_inventory(root, destination=None):
    require(root.is_dir() and not root.is_symlink(), 'Staged source must be a directory, not a link')
    if destination is not None:
        require(not destination.resolve().is_relative_to(root.resolve())
                and not root.resolve().is_relative_to(destination.resolve()),
                'Staged source and campaign output must be separate trees')
    require(not any(path.name in ('.git','.jj') for path in root.rglob('*')),
            'Staged source must not contain repository metadata')
    files=inventory(root)
    require(bool(files), 'Staged source is empty')
    return files

def require_legacy_recovery(recorded):
    require(recorded.get('lanes',list(DEFAULT_LANES))==list(DEFAULT_LANES)
            and recorded.get('seed')==inventory(HERE/'scenario/seed'),
            'Legacy recovery requires the original three tasks and fixture seed; reconcile selected campaigns explicitly')

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def load(path):
    return json.loads(Path(path).read_bytes())

def durable(path, value):
    """Create-only controller evidence, then persist its containing directory."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def paths(lane):
    return {'stream_' + lane + '.py', 'tests/test_stream_' + lane + '.py'}

def inventory(root):
    result = {}
    for p in sorted(Path(root).rglob('*')):
        require(not p.is_symlink(), 'Retained source contains a link')
        if p.is_file():
            result[p.relative_to(root).as_posix()] = {
                'sha256': sha(p), 'executable': bool(p.stat().st_mode & 0o111)}
    return result

def scoped(before, after, allowed):
    require(set(after) == set(before) | allowed, 'Unexpected fixture file set')
    require(all(after[p] == item for p, item in before.items() if p not in allowed),
            'Unscoped fixture bytes or modes changed')
    require(all(not after[p]['executable'] for p in allowed), 'Fixture Python must not be executable')
    require(all(before.get(p) != after[p] for p in allowed), 'Both lane files must change')

def retained_definitions(before, after, names=None):
    """Compare syntax without importing or executing fixture code on the host."""
    def definitions(source):
        found = {}
        for node in ast.parse(source).body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found[node.name] = ast.dump(node)
            elif isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        found[node.name + '.' + method.name] = ast.dump(method)
        return found
    old, new = definitions(before), definitions(after)
    selected = names if names is not None else old.keys()
    require(all(name in old and old[name] == new.get(name) for name in selected),
            'Retained parent API/test definition changed')

def dependency(source, parent, child):
    module = ast.parse(source)
    functions = {n.name: n for n in module.body if isinstance(n, ast.FunctionDef)}
    require(parent in functions and child in functions, 'Missing required parent/child API')
    require(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == parent
                for n in ast.walk(functions[child])), 'Child must directly consume parent API')

def assertions(lane, layer):
    """Host-selected behavior; this text is only executed by the native verifier."""
    common = '''import math
from unittest.mock import patch
def close(actual, expected):
    assert math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12), (actual, expected)
def raises(error, function, *args):
    try:
        function(*args)
    except error:
        return
    raise AssertionError('Expected ' + error.__name__)
'''
    checks = {
        'changes': '''import stream_changes as m
assert list(m.differences(iter([3, -2, 8]))) == [-5, 10]
assert list(m.differences(iter([]))) == []
assert list(m.differences(iter([4]))) == []
assert list(m.differences(x for x in [1.5, -2, 4.5])) == [-3.5, 6.5]
''',
        'statistics': '''import stream_statistics as m
close(m.mean(iter([1, 2, 6])), 3)
close(m.mean(x for x in [-4, -2]), -3)
close(m.mean(iter([2.5])), 2.5)
raises(ValueError, m.mean, iter([]))
''',
        'ranges': '''import stream_ranges as m
assert m.bounds(iter([3, -2, 8, 1])) == (-2, 8)
assert m.bounds(x for x in [2.5]) == (2.5, 2.5)
raises(ValueError, m.bounds, iter([]))
''',
        'rolling': '''import stream_rolling as m
assert list(m.windows(iter([1, 2, 3, 4]), 2)) == [(1, 2), (2, 3), (3, 4)]
assert list(m.windows(iter([1, 2]), 1)) == [(1,), (2,)]
assert list(m.windows(iter([]), 2)) == []
assert list(m.windows(iter([1]), 2)) == []
for width in (0, -1):
    raises(ValueError, lambda: list(m.windows(iter([1]), width)))
for width in (True, 1.5, '2', None):
    raises(TypeError, lambda: list(m.windows(iter([1]), width)))
'''}
    children = {
        'changes': '''close(m.total_change(iter([3, -2, 8])), 5)
close(m.total_change(iter([])), 0)
close(m.total_change(iter([7])), 0)
close(m.total_change(x for x in [1.5, -2, 4.5]), 3)
with patch.object(m, 'differences', wraps=m.differences) as parent:
    close(m.total_change(iter([3, 8])), 5)
    assert parent.called, 'total_change must call differences'
with patch.object(m, 'differences', return_value=iter([10, -4])):
    close(m.total_change(iter([3, 8])), 6)
''',
        'statistics': '''close(m.population_variance(iter([1, 2, 6])), 14 / 3)
close(m.population_variance(x for x in [-4, -2]), 1)
close(m.population_variance(iter([7])), 0)
close(m.population_variance(iter([2, 2, 2])), 0)
raises(ValueError, m.population_variance, iter([]))
with patch.object(m, 'mean', wraps=m.mean) as parent:
    close(m.population_variance(iter([1, 3])), 1)
    assert parent.called, 'population_variance must call mean'
with patch.object(m, 'mean', return_value=0):
    close(m.population_variance(iter([1, 3])), 5)
''',
        'ranges': '''assert m.normalize(iter([-2, 0, 2])) == [0.0, 0.5, 1.0]
assert m.normalize(x for x in [4, 4]) == [0.0, 0.0]
assert m.normalize(iter([2.5])) == [0.0]
raises(ValueError, m.normalize, iter([]))
with patch.object(m, 'bounds', wraps=m.bounds) as parent:
    assert m.normalize(iter([1, 3])) == [0.0, 1.0]
    assert parent.called, 'normalize must call bounds'
with patch.object(m, 'bounds', return_value=(0, 4)):
    assert m.normalize(iter([1, 3])) == [0.25, 0.75]
''',
        'rolling': '''assert m.moving_average(iter([1, 3, 5, 7]), 2) == [2.0, 4.0, 6.0]
assert m.moving_average((x for x in [-2, 2]), 1) == [-2.0, 2.0]
assert m.moving_average(iter([]), 2) == []
assert m.moving_average(iter([1]), 2) == []
for width in (0, -1):
    raises(ValueError, m.moving_average, iter([]), width)
for width in (True, 1.5, '2', None):
    raises(TypeError, m.moving_average, iter([]), width)
with patch.object(m, 'windows', wraps=m.windows) as parent:
    assert m.moving_average(iter([1, 3]), 2) == [2.0]
    assert parent.called, 'moving_average must call windows'
with patch.object(m, 'windows', return_value=iter([(10, 20), (4, 8)])):
    assert m.moving_average(iter([1, 3]), 2) == [15.0, 6.0]
'''}
    return common + checks[lane] + (children[lane] if layer == 'children' else '') + "print('Independent streaming assertions passed')\n"

def prompt(lane, layer):
    contracts = {
        'changes': ('differences(values) returns successive differences (next minus previous), in input order; empty or singleton input produces no differences.',
                    'total_change(values) returns the sum of successive differences by consuming differences(values); empty or singleton input returns zero.'),
        'statistics': ('mean(values) returns the arithmetic mean; empty input raises ValueError.',
                       'population_variance(values) returns sum((x-mean)^2)/n, not sample variance; '
                       'empty input raises ValueError; singleton and constant input return zero.'),
        'ranges': ('bounds(values) returns the (minimum, maximum) tuple; empty input raises ValueError.',
                   'normalize(values) returns a list of (x-minimum)/(maximum-minimum) in input order; '
                   'empty input raises ValueError; a constant range returns one 0.0 per input item.'),
        'rolling': ('windows(values, width) returns an iterable of consecutive full-width tuples, '
                    'with stride one; empty or shorter-than-width input produces no windows. '
                    'width must be a positive integer: bool or non-int raises TypeError; zero or negative raises ValueError, including for empty input.',
                    'moving_average(values, width) returns a list of arithmetic means of consecutive '
                    'full-width windows; empty or shorter-than-width input returns []; preserve the '
                    'exact windows width errors, including for empty input.')}
    root, child = LANES[lane]
    task = contracts[lane][0]
    if layer == 'children':
        task = ('Preserve the exact existing ' + root + ' function definition and every existing test definition. '
                + contracts[lane][1] + ' The new ' + child + ' function must directly call ' + root
                + ' by its module global name to compute its result; do not duplicate that operation.')
    return ('Extend the tiny calculator fixture with streaming numeric analysis. ' + task
            + ' Support finite int/float numeric inputs, negative numbers and single-pass iterables/generators. '
            + 'Only create or revise ' + ', '.join(sorted(paths(lane)))
            + '. Preserve every other file byte-for-byte and retain existing APIs/tests. '
            + 'Use only the Python standard library, add useful unittest coverage, and run full unittest '
            + 'discovery. Do not access Git, credentials or network services. Finish after implementation and tests.'
            + HANDOFF_INSTRUCTION)


def configuration(lane=None, include=None):
    include = list(include) if include is not None else ['README.md', 'metrics.py', 'tests']
    if lane is not None:
        require(lane in LANES, 'Unknown child lane')
        include.append('stream_' + lane + '.py')
    return '''{ schema_version = 1, name = "jjpr-agents",
sources = { include = ''' + json.dumps(include) + ''', exclude = [] },
tools = { python = { version = "3.12.16" } },
missions.dev = { tools = ["python"], include = [], depends_on = [], checks = [] },
sandbox = { gateway = "openshell", workspace = "default", provider = "ladyshell-lo-native" } }
'''


def clean_environment():
    # Credentials for model routing stay in the provider. Host Git/forge state
    # is neither copied into the environment nor required for this scenario.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('GIT_', 'OPENSHELL_', 'FORGEJO_', 'TANGLED_', 'GH_', 'GITHUB_'))}
    env.pop('SSH_AUTH_SOCK', None)
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0')
    return env


def github_repository(value):
    """Validate a repository path before embedding it in fixed-origin URLs/code."""
    parts = value.split('/')
    if (len(parts) != 2
            or re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', parts[0]) is None
            or re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', parts[1]) is None
            or parts[1] in ('.', '..')):
        raise ValueError('GitHub repository must be a safe owner/name path')
    return value


def probe_source(repository=None, public=False):
    if public and repository is None:
        raise ValueError('Public probe mode requires a GitHub repository')
    if repository is None:
        settings = {'profile': 'forgejo-loopback', 'public': False,
                    'api': 'http://127.0.0.1:34080/api/v1/repos/owner/stack-lab',
                    'git': 'http://127.0.0.1:34080/owner/stack-lab.git'}
    else:
        repository = github_repository(repository)
        settings = {'profile': 'github', 'repository': repository, 'public': public,
                    'api': 'https://api.github.com/repos/' + repository,
                    'git': 'https://github.com/' + repository + '.git'}
    # Only validated, nonsecret identifiers enter the generated sandbox program.
    return 'settings = ' + repr(settings) + '\n' + '''import json,os,pathlib,subprocess,urllib.request,urllib.error
names = ('SSH_AUTH_SOCK','FORGEJO_TOKEN','GITHUB_TOKEN','GH_TOKEN','GIT_ASKPASS',
         'GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')
assert not any(os.environ.get(n) for n in names), 'Forge/signing credential environment exposed'
for p in ('/home/fimbault/codex/.state/jjpr/baseline-v3',
          '/home/fimbault/codex/.state/jjpr/github-v1', '/var/run/docker.sock',
          str(pathlib.Path.home()/'.git-credentials'), str(pathlib.Path.home()/'.netrc'),
          str(pathlib.Path.home()/'.config/gh/hosts.yml')):
    assert not pathlib.Path(p).exists(), 'Host credential directory or Docker socket exposed'
request=urllib.request.Request(settings['api'], headers={'Accept':'application/json','User-Agent':'jjpr-anonymous-probe'})
try:
    response=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request,timeout=8)
except urllib.error.HTTPError as e:
    e.close()
    api_result={'outcome':'http-refusal' if e.code in (401,403,404) else 'unexpected-http-status','status':e.code}
except (urllib.error.URLError,TimeoutError,OSError):
    api_result={'outcome':'network-unavailable'}
else:
    with response:
        if not settings['public']:
            raise AssertionError('Sandbox obtained private repository through direct API')
        raw=response.read(1048577)
        assert len(raw)<=1048576, 'Public repository response exceeds bound'
        metadata=json.loads(raw)
        assert metadata.get('full_name','').lower()==settings['repository'].lower() and metadata.get('private') is False, 'Public repository identity or visibility differs'
        api_result={'outcome':'public-read-access','status':200}
env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','GH_','GITHUB_','FORGEJO_'))}
env.update(GIT_TERMINAL_PROMPT='0',GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',LC_ALL='C')
try:
    p=subprocess.run(['git','-c','credential.helper=','-c','http.extraHeader=',
                      'ls-remote',settings['git']],capture_output=True,timeout=12,env=env,cwd='/tmp')
    if p.returncode == 0:
        assert settings['public'], 'Sandbox obtained private repository through direct Git'
    diagnostic=p.stderr.lower()
    if p.returncode == 0:
        outcome='public-read-access'
    elif any(marker in diagnostic for marker in (b'could not resolve',b'failed to connect',b'network is unreachable',b'timed out',b'ssl certificate')):
        outcome='network-unavailable'
    elif any(marker in diagnostic for marker in (b'could not read username',b'authentication failed',b'repository not found',b'returned error: 403',b'returned error: 404')):
        outcome='access-refused-or-repository-missing'
    else:
        outcome='unclassified-failure'
    git_result={'outcome':outcome,'exit_code':p.returncode}
except FileNotFoundError:
    git_result={'outcome':'git-not-installed'}
except subprocess.TimeoutExpired:
    git_result={'outcome':'network-timeout'}
print(json.dumps({'profile':settings['profile'],'credential_environment_absent':True,'host_paths_absent':True,
                  'direct_api':api_result,'direct_git':git_result,'privacy_established':False,
                  'expected_public_reads':settings['public'],'anonymous_write_tested':False,
                  'requires_authenticated_host_repository_evidence':True,
                  'scope':'Anonymous sandbox probes only; 404 can mean missing repository, 403 can mean rate limit, and network failure proves no server policy'}))
'''


def agent_driver(codex, lane, layer, routing, before):
    args = [str(codex), '--no-daemon', '--ask-for-approval', 'never', 'exec',
            '--ephemeral', '--ignore-user-config', '--ignore-rules', '--strict-config',
            '--skip-git-repo-check', '--sandbox', 'danger-full-access', '--cd',
            '/sandbox/workspace/project', '--json', '--color', 'never']
    for option in ('web_search="disabled"', 'analytics.enabled=false', 'features.apps=false',
                   'features.plugins=false', 'features.remote_plugin=false', 'features.hooks=false',
                   'features.multi_agent=false', 'history.persistence="none"'):
        args += ['-c', option]
    args += [prompt(lane, layer)]
    return (HANDOFF_DRIVER_HEADER + "import os,subprocess,json\nassert 'SSH_AUTH_SOCK' not in os.environ\n"
            'before=' + repr(before) + '\nallowed=set(' + repr(sorted(paths(lane))) + ')\n'
            "initial=json.loads(subprocess.check_output(['/usr/local/bin/ladyshell','snapshot-list']))\n"
            "assert set(initial)==set(before) and all(all(initial[p].get(k)==v[k] for k in ('sha256','executable')) for p,v in before.items()), 'Initial sandbox snapshot differs from exact parent input'\n"
            "os.environ['CODEX_HOME']='/sandbox/.codex'\n"
            "os.environ['CODEX_ACCOUNT_ID']=" + repr(routing) + '\n'
            "subprocess.run(['/usr/local/bin/ladyshell','remote-auth'],check=True)\n"
            'subprocess.run(' + repr(args) + ',check=True)\n'
            "subprocess.run(['python3','-m','unittest','discover','-s','tests','-v'],check=True)\n"
            "current=json.loads(subprocess.check_output(['/usr/local/bin/ladyshell','snapshot-list']))\n"
            "assert set(current)==set(before)|allowed, 'Unauthorized fixture paths'\n"
            "assert all(all(current[p].get(k)==v[k] for k in ('sha256','executable')) for p,v in before.items() if p not in allowed), 'Unauthorized fixture edits'\n")


def require_pre_model(run):
    """This scenario may resume provisioning only before its first probe/model."""
    for lane in DEFAULT_LANES:
        directory = run / lane
        require(directory.is_dir(), 'Prepared lane is missing')
        require(not list(directory.glob('round-*'))
                and not list(directory.glob('isolation-probe.*'))
                and not (directory / 'results.json').exists(),
                'Prepared resume refuses existing probe/model evidence; reconcile it explicitly')


def verify_artifact(name, path, recorded):
    require(sha(path) == recorded['sha256'], 'Native executable changed since provisioning: ' + name)
    require(name == 'ladyshell' or str(path) == recorded['path'],
            'Sandbox executable path changed since provisioning: ' + name)
    return {'from': recorded['path'], 'to': str(path), 'sha256': recorded['sha256']}


class Campaign:
    def __init__(self, args):
        self.args = args
        self.run = args.state.resolve()
        self.cli = args.ladyshell.resolve()
        require(self.cli.is_file() and os.access(self.cli, os.X_OK), 'Native CLI must be executable')
        self.env = clean_environment()
        self.lanes = selected_lanes(getattr(args,'lanes',None))
        self.github_repository = github_repository(args.github_repository) if args.github_repository is not None else None
        require(not args.github_public or self.github_repository is not None, 'Public mode requires a GitHub repository')

    def call(self, args, directory, label, timeout=300):
        started = time.monotonic()
        result = subprocess.run([str(a) for a in args], capture_output=True,
                                timeout=timeout, env=self.env)
        (directory / (label + '.stdout')).write_bytes(result.stdout)
        (directory / (label + '.stderr')).write_bytes(result.stderr)
        durable(directory / (label + '.receipt.json'),
                {'exit_code': result.returncode, 'elapsed_seconds': round(time.monotonic()-started, 3),
                 'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                 'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
        require(result.returncode == 0, f'{label} failed ({result.returncode}); inspect retained private logs')
        return result.stdout

    def initialize(self):
        origin = getattr(self.args,'seed_directory',None) or HERE / 'scenario/seed'
        expected = seed_inventory(origin, self.run)
        self.run.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(self.run, 0o700)
        source = self.run / 'source'
        shutil.copytree(origin, source)
        self.baseline = inventory(source)
        require(self.baseline==expected, 'Staged source changed during copying')
        for path in ('config', 'nix', 'crates/ladyshell/resources/audit'):
            shutil.copytree(self.args.lady_source / path, self.run / 'resources' / path)
        self.call(['git', 'init', '-b', 'main', source], self.run, 'git-init')
        self.call(['git', '-C', source, 'add', '.'], self.run, 'git-add')
        self.call(['git', '-C', source, '-c', 'user.name=jjpr fixture', '-c',
                   'user.email=fixture@jjpr.invalid', '-c', 'commit.gpgsign=false',
                   '-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'Seed isolated streaming tasks'], self.run, 'git-seed')
        self.base = self.call(['git', '-C', source, 'rev-parse', 'HEAD'], self.run, 'git-base').decode().strip()
        durable(self.run / 'campaign.json', {
            'schema_version': 1, 'seed': self.baseline, 'seed_git_commit': self.base,
            'ladyshell': {'path': str(self.cli), 'sha256': sha(self.cli)},
            'codex': {'path': str(self.args.codex), 'sha256': sha(self.args.codex)},
            'codex_code_mode_host': {'path': str(self.args.codex_code_mode_host), 'sha256': sha(self.args.codex_code_mode_host)},
            'resources': inventory(self.run / 'resources'),
            'agent_count': len(self.lanes), 'lanes': list(self.lanes),
            'seed_directory': str(origin.resolve()), 'exports_per_agent': 2, 'history_import': False,
            'probe_profile': 'github' if self.github_repository is not None else 'forgejo-loopback',
            'github_repository': self.github_repository,
            'github_public': self.args.github_public})
        # Only the account routing UUID is selected. No token is copied or printed.
        with (Path.home() / '.codex/auth.json').open() as auth:
            self.routing = str(uuid.UUID(json.load(auth)['tokens']['account_id']))

    def restore_prepared(self):
        require_pre_model(self.run)
        recorded = load(self.run / 'campaign.json')
        require_legacy_recovery(recorded)
        require(recorded['github_repository'] == self.github_repository, 'Repository binding changed')
        require(inventory(HERE / 'scenario/seed') == recorded['seed'], 'Seed changed since provisioning')
        require(inventory(self.run / 'resources') == recorded['resources'], 'Resources changed since provisioning')
        artifact_paths = {}
        for name, path in [('ladyshell', self.cli), ('codex', self.args.codex),
                           ('codex_code_mode_host', self.args.codex_code_mode_host)]:
            artifact_paths[name] = verify_artifact(name, path, recorded[name])
        for lane in DEFAULT_LANES:
            taskdir = self.run / lane / 'task'
            task = load(taskdir / 'task.json')
            current = load(taskdir / 'state/state.json')
            require(task['phase'] == 'active' and task['base'] == recorded['seed_git_commit']
                    and task['branch'] == 'agent/' + lane
                    and task['project'] == str(taskdir / 'project')
                    and task['state'] == str(taskdir / 'state')
                    and task['sandbox_id'] == current['sandbox_id'], 'Prepared native task binding differs')
            require(current.get('last_sync') is None, 'Prepared task already has an export')
        self.baseline, self.base = recorded['seed'], recorded['seed_git_commit']
        with (Path.home() / '.codex/auth.json').open() as auth:
            self.routing = str(uuid.UUID(json.load(auth)['tokens']['account_id']))
        resume_path = self.run / 'resume-prepared.json'
        if resume_path.exists():
            # Only pre-model retries reach here; require_pre_model rejects every
            # probe/model marker. Retain each failed setup attempt independently.
            resume_path = self.run / ('resume-prepared-' + uuid.uuid4().hex + '.json')
        durable(resume_path, {
            'original_campaign_sha256': sha(self.run / 'campaign.json'),
            'reason': 'Resume before any model/probe with explicitly selected repository visibility',
            'prior_github_public': recorded.get('github_public', False),
            'github_public': self.args.github_public, 'github_repository': self.github_repository,
            'runner_sha256': sha(__file__), 'original_start_receipts_recreated': False,
            'verified_artifact_paths': artifact_paths})

    def lane(self, lane):
        directory = self.run / lane
        if not self.args.resume_prepared:
            directory.mkdir(mode=0o700)
        taskdir = directory / 'task'
        state = taskdir / 'state'
        inputs = directory / 'configuration'
        config, lock = inputs / 'config.ncl', inputs / 'environment.lock.json'
        if not self.args.resume_prepared:
            inputs.mkdir()
            config.write_text(configuration(include=sorted(self.baseline)))
        common = ['--config', config, '--lock', lock, '--resources', self.run / 'resources',
                  '--codex', self.args.codex, '--codex-code-mode-host', self.args.codex_code_mode_host,
                  '--mission', 'dev']
        results = []
        try:
            if self.args.resume_prepared:
                self.call([self.cli, 'status', '--state', state], directory, 'resume-native-status', 180)
            else:
                self.call([self.cli, 'lock', '--project', self.run / 'source', '--state', state, *common], directory, 'lock', 600)
                self.call([self.cli, 'task', 'start', '--repository', self.run / 'source',
                           '--directory', taskdir, '--branch', 'agent/' + lane, '--base', self.base,
                           *common], directory, 'start', 1800)
            self.call([self.cli, 'run', '--state', state, '--timeout', '45', '--', 'python3', '-c',
                       probe_source(self.github_repository, public=self.args.github_public)], directory, 'isolation-probe', 90)
            before = self.baseline
            parent_export = None
            for number, layer in enumerate(('roots', 'children'), 1):
                driver = agent_driver(self.args.codex, lane, layer, self.routing, before)
                compile(driver, lane + '-driver', 'exec')
                (directory / f'round-{number}-driver.py').write_text(driver)
                self.call([self.cli, 'run', '--state', state, '--sync', '--timeout', '300',
                           '--', 'python3', '-c', driver], directory, f'round-{number}-agent', 900)
                export = Path(load(state / 'state.json')['last_sync'])
                after = inventory(export / 'project')
                scoped(before, after, paths(lane))
                require(load(export / 'manifest.json')['files'] == after, 'Export manifest mismatch')
                if parent_export is not None:
                    module = 'stream_' + lane + '.py'
                    retained_definitions((parent_export / 'project' / module).read_text(),
                                         (export / 'project' / module).read_text(), [LANES[lane][0]])
                    test = 'tests/test_stream_' + lane + '.py'
                    retained_definitions((parent_export / 'project' / test).read_text(),
                                         (export / 'project' / test).read_text())
                    dependency((export / 'project' / module).read_text(), *LANES[lane])
                policy = directory / f'round-{number}-checks.json'
                durable(policy, {'schema_version': 1, 'checks': {
                    'commands': [['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                                 ['python3', '-c', assertions(lane, layer)]], 'timeout': 60}})
                self.call([self.cli, 'publication', 'check', '--state', state, '--export', export,
                           '--policy', policy], directory, f'round-{number}-verify', 600)
                checks = load(export / 'checks.json')
                require(checks['passed'] and checks['cleanup_confirmed'], 'Verifier did not pass and clean up')
                result = {'lane': lane, 'layer': layer, 'round': number, 'export': str(export),
                          'parent_export': str(parent_export) if parent_export else None,
                          'input_files': before, 'files': after, 'checks': checks,
                          'manifest_sha256': sha(export / 'manifest.json'),
                          'driver_sha256': sha(directory / f'round-{number}-driver.py'),
                          'agent_receipt_sha256': sha(directory / f'round-{number}-agent.receipt.json'),
                          'host_check_policy_sha256': sha(policy),'handoff_schema':1}
                durable(directory / f'round-{number}-result.json', result)
                results.append(result)
                before, parent_export = after, export
            durable(directory / 'results.json', results)
            return {'lane': lane, 'results': results}
        finally:
            if (state / 'state.json').exists():
                # Native destroy verifies ownership, exports first and retains all
                # original snapshots. It never deletes task workspaces or evidence.
                self.call([self.cli, 'destroy', '--state', state], directory, 'cleanup', 300)

    def execute(self):
        if self.args.resume_prepared:
            self.restore_prepared()
        else:
            self.initialize()
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(self.lane, self.lanes))
        durable(self.run / 'results.json', {'actual_agents': len(self.lanes), 'snapshots': 2*len(self.lanes), 'lanes': results,
                                           'history_imported': False, 'forge_publication': False})
        return {'state': str(self.run), 'actual_agents': len(self.lanes), 'checked_exports': 2*len(self.lanes)}


def retryable_verifier_creation(receipt):
    return (receipt.get('passed') is False and receipt.get('cleanup_confirmed') is True
            and receipt.get('results') == [] and 'database is locked' in receipt.get('error', ''))


def recover_roots(args):
    """Check explicitly selected retained roots; never repeat model execution."""
    campaign = Campaign(args)
    run = campaign.run
    recorded = load(run / 'campaign.json')
    require_legacy_recovery(recorded)
    verify_artifact('ladyshell', campaign.cli, recorded['ladyshell'])
    require(inventory(run / 'resources') == recorded['resources'], 'Retained resources changed')
    selected = load(args.recover_roots)
    require(set(selected) == set(DEFAULT_LANES), 'Select exactly one original export per lane')

    def recover(lane):
        directory = run / lane
        state = directory / 'task/state'
        export = Path(selected[lane]).resolve()
        require(export.parent == (state / 'exports').resolve(), 'Export is outside its native task')
        require(not (directory / 'round-1-result.json').exists(), 'Root already checked; do not replay verification')
        original = load(directory / 'round-1-agent.receipt.json')
        require(original['exit_code'] == 1, 'Recovery expects the retained failed harness check')
        require('AssertionError: Unauthorized fixture edits' in (directory / 'round-1-agent.stderr').read_text(),
                'Original failure differs; inspect before recovery')
        after = inventory(export / 'project')
        scoped(recorded['seed'], after, paths(lane))
        manifest = load(export / 'manifest.json')
        require(manifest['files'] == after and manifest['sandbox_id'] == load(state / 'state.json')['sandbox_id'],
                'Retained export binding differs')
        policy = directory / 'round-1-checks.json'
        policy_value = {'schema_version': 1, 'checks': {
            'commands': [['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                         ['python3', '-c', assertions(lane, 'roots')]], 'timeout': 60}}
        label = 'round-1-verify-recovered'
        if args.retry_root_verifier:
            failed = load(export / 'checks.json')
            require(retryable_verifier_creation(failed), 'Verifier attempt is not a reconciled creation failure')
            require(load(policy) == policy_value, 'Retained verifier policy changed')
            durable(directory / 'round-1-verifier-creation-failure.json', failed)
            label += '-retry'
        else:
            durable(policy, policy_value)
        campaign.call([campaign.cli, 'publication', 'check', '--state', state, '--export', export,
                       '--policy', policy], directory, label, 600)
        checks = load(export / 'checks.json')
        require(checks['passed'] and checks['cleanup_confirmed'], 'Recovered root verification incomplete')
        result = {'lane': lane, 'layer': 'roots', 'round': 1, 'export': str(export),
                  'parent_export': None, 'input_files': recorded['seed'], 'files': after,
                  'checks': checks, 'manifest_sha256': sha(export / 'manifest.json'),
                  'driver_sha256': sha(directory / 'round-1-driver.py'),
                  'host_check_policy_sha256': sha(policy),
                  'recovery': {'model_rerun': False, 'original_driver_exit_code': 1,
                               'original_driver_receipt_sha256': sha(directory / 'round-1-agent.receipt.json'),
                               'reason': 'Driver compared native size metadata with a hash/mode-only baseline; original failed receipt retained'}}
        durable(directory / 'round-1-result.json', result)
        print(json.dumps({'lane': lane, 'recovered_checked_root': str(export)}), flush=True)
        return result

    if args.retry_root_verifier:
        recover(args.retry_root_verifier)
        roots = [load(run / lane / 'round-1-result.json') for lane in DEFAULT_LANES]
    else:
        with ThreadPoolExecutor(max_workers=3) as pool:
            roots = list(pool.map(recover, DEFAULT_LANES))
    durable(run / 'recovered-roots.json', {'model_reruns': 0, 'roots': roots})
    return {'state': str(run), 'checked_roots': 3, 'child_work_pending': True, 'model_reruns': 0}


def continue_children(args):
    """Continue three logical lanes from exact checked parents in new sandboxes."""
    campaign = Campaign(args)
    run = campaign.run
    recorded = load(run / 'campaign.json')
    require_legacy_recovery(recorded)
    require(recorded['github_repository'] == campaign.github_repository, 'Repository binding changed')
    verify_artifact('ladyshell', campaign.cli, recorded['ladyshell'])
    require(inventory(run / 'resources') == recorded['resources'], 'Resources changed since provisioning')
    parents = {}
    for lane in DEFAULT_LANES:
        directory = run / lane
        parent = load(directory / 'round-1-result.json')
        export = Path(parent['export'])
        require(export.parent == directory / 'task/state/exports', 'Parent export is outside its native task')
        require(inventory(export / 'project') == parent['files']
                and sha(export / 'manifest.json') == parent['manifest_sha256']
                and load(export / 'checks.json') == parent['checks']
                and parent['checks']['passed'] and parent['checks']['cleanup_confirmed'], 'Checked parent evidence changed')
        require(not (directory / 'child-source').exists() and not (directory / 'child-task').exists()
                and not list(directory.glob('round-2-*')), 'Child work already exists; do not replay agents')
        parents[lane] = parent
    with (Path.home() / '.codex/auth.json').open() as auth:
        routing = str(uuid.UUID(json.load(auth)['tokens']['account_id']))
    durable(run / 'children-intent.json', {
        'root_model_reruns': 0, 'logical_lanes': 3, 'new_physical_agent_sandboxes': 3,
        'parent_receipts': {lane: sha(run / lane / 'round-1-result.json') for lane in DEFAULT_LANES},
        'github_public': args.github_public, 'runner_sha256': sha(__file__)})

    def child(lane):
        directory = run / lane
        parent = parents[lane]
        source = directory / 'child-source'
        shutil.copytree(Path(parent['export']) / 'project', source)
        require(inventory(source) == parent['files'], 'Child source differs from checked parent')
        campaign.call(['git', 'init', '-b', 'main', source], directory, 'child-source-init')
        campaign.call(['git', '-C', source, 'add', '.'], directory, 'child-source-add')
        campaign.call(['git', '-C', source, '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                       '-c', 'user.name=jjpr fixture', '-c', 'user.email=fixture@jjpr.invalid',
                       'commit', '-m', 'Seed child task from checked parent export'], directory, 'child-source-commit')
        base = campaign.call(['git', '-C', source, 'rev-parse', 'HEAD'], directory, 'child-source-base').decode().strip()
        task = directory / 'child-task'
        state = task / 'state'
        configdir = directory / 'child-configuration'
        configdir.mkdir()
        config, lock = configdir / 'config.ncl', configdir / 'environment.lock.json'
        config.write_text(configuration(lane))
        common = ['--config', config, '--lock', lock, '--resources', run / 'resources',
                  '--codex', args.codex, '--codex-code-mode-host', args.codex_code_mode_host, '--mission', 'dev']
        try:
            campaign.call([campaign.cli, 'lock', '--project', source, '--state', state, *common], directory, 'child-lock', 600)
            campaign.call([campaign.cli, 'task', 'start', '--repository', source, '--directory', task,
                           '--branch', 'agent/' + lane + '-child', '--base', base, *common], directory, 'child-start', 1800)
            durable(directory / 'child-input-binding.json', {
                'logical_lane': lane, 'parent_export': parent['export'], 'files': parent['files'],
                'local_seed_commit': base, 'history_imported': False,
                'source_task_state': str(state), 'config_sha256': sha(config), 'lock_sha256': sha(lock)})
            campaign.call([campaign.cli, 'run', '--state', state, '--timeout', '45', '--', 'python3', '-c',
                           probe_source(campaign.github_repository, public=args.github_public)], directory, 'child-isolation-probe', 90)
            driver = agent_driver(args.codex, lane, 'children', routing, parent['files'])
            (directory / 'round-2-driver.py').write_text(driver)
            campaign.call([campaign.cli, 'run', '--state', state, '--sync', '--timeout', '300', '--',
                           'python3', '-c', driver], directory, 'round-2-agent', 900)
            export = Path(load(state / 'state.json')['last_sync'])
            after = inventory(export / 'project')
            scoped(parent['files'], after, paths(lane))
            require(load(export / 'manifest.json')['files'] == after, 'Child export manifest differs')
            module = 'stream_' + lane + '.py'
            test = 'tests/test_stream_' + lane + '.py'
            old = Path(parent['export']) / 'project'
            retained_definitions((old / module).read_text(), (export / 'project' / module).read_text(), [LANES[lane][0]])
            retained_definitions((old / test).read_text(), (export / 'project' / test).read_text())
            dependency((export / 'project' / module).read_text(), *LANES[lane])
            policy = directory / 'round-2-checks.json'
            durable(policy, {'schema_version': 1, 'checks': {
                'commands': [['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                             ['python3', '-c', assertions(lane, 'children')]], 'timeout': 60}})
            campaign.call([campaign.cli, 'publication', 'check', '--state', state, '--export', export,
                           '--policy', policy], directory, 'round-2-verify', 600)
            checks = load(export / 'checks.json')
            require(checks['passed'] and checks['cleanup_confirmed'], 'Child verification incomplete')
            result = {'lane': lane, 'layer': 'children', 'round': 2, 'export': str(export),
                      'source_task_state': str(state), 'parent_export': parent['export'],
                      'input_files': parent['files'], 'files': after, 'checks': checks,
                      'manifest_sha256': sha(export / 'manifest.json'),
                      'driver_sha256': sha(directory / 'round-2-driver.py'),
                      'agent_receipt_sha256': sha(directory / 'round-2-agent.receipt.json'),
                      'host_check_policy_sha256': sha(policy),'handoff_schema':1,
                      'recovery': {'root_model_rerun': False, 'new_physical_sandbox': True,
                                   'child_input_binding_sha256': sha(directory / 'child-input-binding.json')}}
            durable(directory / 'round-2-result.json', result)
            print(json.dumps({'lane': lane, 'checked_child': str(export)}), flush=True)
            return {'lane': lane, 'results': [parent, result]}
        finally:
            if (state / 'state.json').exists():
                campaign.call([campaign.cli, 'destroy', '--state', state], directory, 'child-cleanup', 300)

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(child, DEFAULT_LANES))
    durable(run / 'results.json', {'logical_lanes': 3, 'model_invocations': 6,
                                  'physical_agent_sandboxes': 6, 'checked_exports': 6,
                                  'root_model_reruns': 0, 'history_imported': False,
                                  'forge_publication': False, 'lanes': results})
    return {'state': str(run), 'checked_exports': 6, 'model_invocations': 6, 'root_model_reruns': 0}


def recover_child(args):
    """Reconcile pending cleanup, then obtain a native check receipt for one child."""
    campaign = Campaign(args)
    run, lane = campaign.run, args.recover_child
    directory = run / lane
    state = directory / 'child-task/state'
    export = args.child_export.resolve()
    require(export.parent == (state / 'exports').resolve(), 'Child export is outside its native task')
    require(not (directory / 'round-2-result.json').exists(), 'Child already checked; do not repeat verification')
    recorded = load(run / 'campaign.json')
    require_legacy_recovery(recorded)
    verify_artifact('ladyshell', campaign.cli, recorded['ladyshell'])
    parent = load(directory / 'round-1-result.json')
    binding = load(directory / 'child-input-binding.json')
    require(binding['parent_export'] == parent['export'] and binding['files'] == parent['files']
            and binding['source_task_state'] == str(state), 'Child input binding changed')
    require(load(directory / 'round-2-agent.receipt.json')['exit_code'] == 0, 'Child model session did not finish successfully')
    after = inventory(export / 'project')
    scoped(parent['files'], after, paths(lane))
    manifest = load(export / 'manifest.json')
    require(manifest['files'] == after and manifest['sandbox_id'] == load(state / 'state.json')['sandbox_id'],
            'Child export binding differs')
    module, test = 'stream_' + lane + '.py', 'tests/test_stream_' + lane + '.py'
    old = Path(parent['export']) / 'project'
    retained_definitions((old / module).read_text(), (export / 'project' / module).read_text(), [LANES[lane][0]])
    retained_definitions((old / test).read_text(), (export / 'project' / test).read_text())
    dependency((export / 'project' / module).read_text(), *LANES[lane])
    failed = load(export / 'checks.json')
    require(failed['passed'] is False and failed['cleanup_confirmed'] is False
            and failed.get('error') is None and len(failed['results']) == len(failed['commands'])
            and len(failed['results']) > 0 and all(r['exit_code'] == 0 for r in failed['results']),
            'Expected completed checks with pending cleanup; reconcile other outcomes separately')
    durable(directory / 'round-2-verifier-cleanup-pending.json', failed)
    campaign.call([campaign.cli, 'task', 'complete', '--state', state], directory, 'child-cleanup-reconciled', 300)
    require(load(state / 'destroy.json')['deleted'] is True, 'Agent cleanup remains pending')
    policy = directory / 'round-2-checks.json'
    require(load(policy) == {'schema_version': 1, 'checks': {
        'commands': [['python3', '-m', 'unittest', 'discover', '-s', 'tests', '-v'],
                     ['python3', '-c', assertions(lane, 'children')]], 'timeout': 60}}, 'Child check policy changed')
    # The native interface retains the original failed receipt but offers no
    # promotion after cleanup-only recovery. Rechecking is explicit and recorded.
    campaign.call([campaign.cli, 'publication', 'check', '--state', state, '--export', export,
                   '--policy', policy], directory, 'round-2-verify-after-cleanup', 600)
    checks = load(export / 'checks.json')
    require(checks['passed'] and checks['cleanup_confirmed'], 'Child verification still incomplete')
    result = {'lane': lane, 'layer': 'children', 'round': 2, 'export': str(export),
              'source_task_state': str(state), 'parent_export': parent['export'],
              'input_files': parent['files'], 'files': after, 'checks': checks,
              'manifest_sha256': sha(export / 'manifest.json'),
              'driver_sha256': sha(directory / 'round-2-driver.py'),
              'agent_receipt_sha256': sha(directory / 'round-2-agent.receipt.json'),
              'host_check_policy_sha256': sha(policy),
              'recovery': {'root_model_rerun': False, 'child_model_rerun': False,
                           'new_physical_sandbox': True, 'independent_checks_repeated_after_cleanup': True,
                           'failed_verifier_receipt_sha256': sha(directory / 'round-2-verifier-cleanup-pending.json'),
                           'child_input_binding_sha256': sha(directory / 'child-input-binding.json')}}
    durable(directory / 'round-2-result.json', result)
    results = [{'lane': selected, 'results': [load(run / selected / f'round-{n}-result.json') for n in (1, 2)]}
               for selected in DEFAULT_LANES]
    durable(run / 'results.json', {'logical_lanes': 3, 'model_invocations': 6,
                                  'physical_agent_sandboxes': 6, 'checked_exports': 6,
                                  'root_model_reruns': 0, 'history_imported': False,
                                  'forge_publication': False, 'lanes': results})
    return {'state': str(run), 'checked_exports': 6, 'model_invocations': 6, 'model_reruns': 0}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, type=Path)
    parser.add_argument('--lanes', nargs='+', choices=tuple(LANES),
                        help='Explicit tasks for a new campaign; defaults to the original three')
    parser.add_argument('--seed-directory', type=Path,
                        help='Host-staged source tree without Git/jj metadata; freeze and verify it before selection')
    parser.add_argument('--github-repository', type=github_repository,
                        help='Probe this owner/name anonymously on GitHub; default probes the local Forgejo fixture')
    parser.add_argument('--github-public', action='store_true',
                        help='Expect anonymous reads of the selected public GitHub repository; never attempt anonymous writes')
    parser.add_argument('--resume-prepared', action='store_true',
                        help='Reuse completed native provisioning only before any probe/model; retain original evidence')
    parser.add_argument('--recover-roots', type=Path,
                        help='Verify explicitly selected retained root exports after the metadata-shape harness failure; no model rerun')
    parser.add_argument('--retry-root-verifier', choices=DEFAULT_LANES,
                        help='Retry only a selected verifier creation that failed with a database lock and confirmed cleanup')
    parser.add_argument('--continue-children', action='store_true',
                        help='Continue from checked retained roots in three new physical sandboxes; no root model rerun')
    parser.add_argument('--recover-child', choices=DEFAULT_LANES,
                        help='Reconcile one child verifier/agent cleanup and recheck its original export without rerunning models')
    parser.add_argument('--child-export', type=Path,
                        help='Exact retained export for --recover-child')
    parser.add_argument('--ladyshell', type=Path, required=True)
    parser.add_argument('--lady-source', type=Path, required=True)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--codex-code-mode-host', type=Path, required=True)
    args = parser.parse_args()
    require(not (args.lanes or args.seed_directory) or not
            (args.resume_prepared or args.recover_roots or args.continue_children or args.recover_child),
            'Selected tasks/staged seeds are supported for new campaigns only; preserve legacy recovery bindings')
    require(not (args.resume_prepared and args.recover_roots), 'Choose one recovery phase')
    require(not args.continue_children or not (args.resume_prepared or args.recover_roots), 'Choose one recovery phase')
    require(not args.recover_child or not (args.resume_prepared or args.recover_roots or args.continue_children), 'Choose one recovery phase')
    require(bool(args.recover_child) == (args.child_export is not None), 'Child recovery needs one lane and exact export')
    require(not args.retry_root_verifier or args.recover_roots is not None, 'Verifier retry needs selected retained roots')
    result = (recover_child(args) if args.recover_child else continue_children(args) if args.continue_children else
              recover_roots(args) if args.recover_roots else Campaign(args).execute())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
