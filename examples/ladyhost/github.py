#!/usr/bin/env python3
"""Prepare this experiment's private GitHub repository using host GitHub CLI.

Host scenario orchestration only. The Rust adapter owns publication checks.
The provider account and private repository must match the retained configuration.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(argv, env=None, cwd=None):
    result = subprocess.run(list(map(str, argv)), env=env, cwd=cwd, capture_output=True, timeout=120)
    if result.returncode:
        # Credential helpers can write diagnostics; keep them out of reports.
        raise RuntimeError(f'{Path(argv[0]).name} failed with exit {result.returncode}; no command output disclosed')
    return result.stdout.decode().strip()


def prepare(state):
    config = json.loads((state/'config.json').read_text())
    if config.get('provider') != 'github' or config.get('endpoint') != 'https://api.github.com':
        raise RuntimeError('not a GitHub host configuration')
    visibility=config.get('visibility','private')
    if visibility not in ('private','public'):
        raise RuntimeError('invalid visibility selection')
    private=visibility=='private'
    gh = Path(config['gh_cli'])
    env = {k:v for k,v in os.environ.items() if not k.startswith(('GIT_','JJ_')) and k not in
           ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')}
    env.pop('SSH_AUTH_SOCK',None)
    env.update(GH_HOST='github.com',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0')
    identity = json.loads(run([gh, 'api', '--hostname', 'github.com', 'user'],env))
    if identity['login'].lower() != config['expected_actor'].lower() or config['owner'].lower() != identity['login'].lower():
        raise RuntimeError('fixture provisioning requires the explicitly selected personal account')
    full_name = config['owner']+'/'+config['repository']
    if any(not part or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._' for c in part) for part in full_name.split('/')):
        raise RuntimeError('invalid repository identity')
    if (state/'repository.json').exists():
        repo = json.loads(run([gh,'api','--hostname','github.com','repos/'+full_name],env))
        retained = json.loads((state/'repository.json').read_text())
        if repo['private'] != private or repo['id'] != retained['id']:
            raise RuntimeError('retained repository identity changed')
        if not (state/'seed.ok.json').exists() or not (state/'config.bound.json').exists():
            raise RuntimeError('repository setup is incomplete; reconcile retained files before continuing')
        seed=json.loads((state/'seed.ok.json').read_text())
        remote=json.loads(run([gh,'api','--hostname','github.com','repos/'+full_name+'/git/ref/heads/main'],env))
        if seed.get('oid') != remote['object']['sha']:
            raise RuntimeError('seed target changed; inspect current experiment state instead of replaying setup')
        run(['git','verify-commit',seed['oid']],env,Path(config['workspace']))
        return {'repository':full_name,'prepared':True,'retained':True,'seed_oid':seed['oid']}
    # Use a complete account-owned repository inventory to distinguish absence
    # from an authentication/network failure, which must never trigger creation.
    repositories = json.loads(run([gh,'api','--hostname','github.com','--paginate','--slurp','user/repos?affiliation=owner&per_page=100'],env))
    found = [r for page in repositories for r in page if r['full_name'].lower() == full_name.lower()]
    if found:
        raise RuntimeError('repository already exists without a retained fixture receipt; do not overwrite it')
    save(state/'create-repository.intent.json',{'account':identity['login'],'repository':full_name,'private':private})
    run([gh,'repo','create',full_name,'--'+visibility,'--description','Disposable jjpr signed stacked-PR experiment'],env)
    repo = json.loads(run([gh,'api','--hostname','github.com','repos/'+full_name],env))
    if repo['private'] != private or repo['full_name'].lower() != full_name.lower():
        raise RuntimeError('created repository does not match the selected fixture')
    save(state/'repository.json',{'id':repo['id'],'full_name':repo['full_name'],'private':private,'account_id':identity['id']})
    workspace = Path(config['workspace'])
    if workspace.exists():
        raise RuntimeError('workspace already exists; retain and reconcile it')
    key = state/'host-signing'
    run(['ssh-keygen','-q','-t','ed25519','-N','','-C',full_name,'-f',key])
    email = f"{identity['id']}+{identity['login']}@users.noreply.github.com"
    (state/'allowed_signers').write_text(email+' '+key.with_suffix('.pub').read_text())
    helper='!'+shlex.quote(str(gh))+' auth git-credential'
    run(['git','-c','credential.helper='+helper,'clone','https://github.com/'+full_name+'.git',workspace],env)
    for name,value in {'credential.helper':helper,'credential.useHttpPath':'true','core.hooksPath':'/dev/null','user.name':identity['login'],'user.email':email,'gpg.format':'ssh','user.signingkey':str(key),'gpg.ssh.allowedSignersFile':str(state/'allowed_signers'),'commit.gpgsign':'true'}.items():
        run(['git','config','--local',name,value],env,workspace)
    seed = HERE/'scenario/seed'
    files = ['README.md','metrics.py','tests/test_metrics.py']
    for name in files:
        destination=workspace/name;destination.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(seed/name,destination)
    run(['git','checkout','-b','main'],env,workspace)
    run(['git','add','--',*files],env,workspace)
    run(['git','commit','-m','Seed the isolated jjpr stacking experiment'],env,workspace)
    oid=run(['git','rev-parse','HEAD'],env,workspace)
    run(['git','verify-commit',oid],env,workspace)
    save(state/'seed.intent.json',{'oid':oid,'branch':'main','signature_verified_locally':True,'github_signature_registration':'pending'})
    run(['git','push','origin','HEAD:refs/heads/main'],env,workspace)
    actual=run(['git','ls-remote','origin','refs/heads/main'],env,workspace).split()[0]
    if actual != oid:
        raise RuntimeError('seed ref changed; reconcile retained intent')
    save(state/'seed.ok.json',{'oid':oid,'readback':actual})
    config['expected_repository_id']=repo['id']
    save(state/'config.bound.json',config)
    return {'repository':full_name,'seed_oid':oid,'signature_verified_locally':True,'github_signature_registration':'pending'}


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=('prepare',))
    parser.add_argument('--state',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.state.resolve())))


if __name__ == '__main__':
    main()
