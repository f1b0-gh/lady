#!/usr/bin/env python3
"""Create a host jj stack element from one retained, independently checked export.

Run parent then child for each lane. Import file bytes only: sandbox Git/jj
history, configuration, credentials and executables are never imported.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess

from agents import LANES, inventory, scoped
from github import run, save

HERE=Path(__file__).resolve().parent


def host_git_helper(config, config_path, adapter):
    sources=[key for key in ('github_app','gh_cli','token_file') if config.get(key) is not None]
    if len(sources)!=1:
        raise RuntimeError('select exactly one host authentication source')
    if sources[0]=='gh_cli':
        return '!'+shlex.quote(str(config['gh_cli']))+' auth git-credential'
    if sources[0]=='github_app':
        return '!'+shlex.quote(str(adapter))+' credential '+shlex.quote(str(config_path))
    raise RuntimeError('scenario Git publication requires gh_cli or github_app authentication')


def publication_names(lane, publication_id):
    if lane not in LANES:
        raise ValueError('invalid lane')
    if publication_id is None:
        return 'stack-'+lane,'publication-'+lane,'agent/'+lane
    if not publication_id or len(publication_id)>48 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in publication_id):
        raise ValueError('invalid publication ID')
    return 'stack-'+publication_id+'-'+lane,'publication-'+publication_id+'-'+lane,'agent/'+publication_id+'/'+lane


def commit_inventory(checkout, oid, env):
    raw=subprocess.check_output(['git','ls-tree','--full-tree','-r','-z',oid],cwd=checkout,env=env)
    entries={}
    for record in raw.split(b'\0'):
        if not record: continue
        header,sep,name=record.partition(b'\t')
        mode,kind,blob=header.split()
        if not sep or kind!=b'blob' or mode not in (b'100644',b'100755'):
            raise RuntimeError('signed tree contains unsupported objects or modes')
        content=subprocess.check_output(['git','cat-file','blob',blob.decode('ascii')],cwd=checkout,env=env)
        entries[name.decode('utf-8')]={'sha256':hashlib.sha256(content).hexdigest(),'executable':mode==b'100755'}
    return entries


def confirmed_parent(parent, receipt, remote):
    if receipt.get('oid')!=parent['oid'] or receipt.get('remote_oid')!=parent['oid'] or remote!=parent['oid']:
        raise RuntimeError('parent publication is unconfirmed or changed; reconcile it before publishing a child')


def publish(state, campaign, lane, number, jj, adapter, config_path=None, publication_id=None):
    config=json.loads((config_path or state/'config.bound.json').read_text())
    if config.get('github_app') and publication_id is None:
        raise RuntimeError('App publication requires a fresh publication ID; preserve user-authored PRs')
    checkout_name,output_name,branch_prefix=publication_names(lane,publication_id)
    result=json.loads((campaign/lane/f'round-{number}-result.json').read_text())
    export=Path(result['export'])
    task_name='task' if number==1 else 'child-task'
    expected_state=campaign/lane/task_name/'state'
    if result.get('source_task_state',str(expected_state))!=str(expected_state):
        raise RuntimeError('source task binding differs from selected lane and layer')
    if not export.resolve().is_relative_to((expected_state/'exports').resolve()):
        raise RuntimeError('export outside retained lane')
    manifest=export/'manifest.json'
    if hashlib.sha256(manifest.read_bytes()).hexdigest()!=result['manifest_sha256']:
        raise RuntimeError('export manifest changed')
    actual=inventory(export/'project')
    if actual!=result['files'] or json.loads(manifest.read_bytes())['files']!=actual:
        raise RuntimeError('export content or mode changed')
    checks=json.loads((export/'checks.json').read_bytes())
    if checks!=result['checks'] or not checks['passed'] or not checks['cleanup_confirmed']:
        raise RuntimeError('missing retained verifier success')
    allowed={'stream_'+lane+'.py','tests/test_stream_'+lane+'.py'}
    scoped(result['input_files'],actual,allowed)
    checkout=state/checkout_name
    output=state/output_name
    output.mkdir(exist_ok=True,mode=0o700)
    attempt=output/('round-'+str(number))
    attempt.mkdir(mode=0o700)  # create-only: uncertain publication is not replayed
    env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','JJ_')) and k not in ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')}
    env.pop('SSH_AUTH_SOCK',None)
    env.update(PATH=str(jj.parent)+':'+env.get('PATH','/usr/bin:/bin'),GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',JJ_CONFIG=str(state/'jj-host.toml'))
    auth_config=dict(config,workspace=str(checkout))
    auth_config.pop('publication',None)
    auth_path=attempt/'auth.json'
    save(auth_path,auth_config)
    helper=host_git_helper(auth_config,auth_path,adapter)
    if config.get('github_app'):
        # Authenticate installation/repository before even cloning a public repo.
        run([adapter,'preflight',auth_path],env)
    if number==1:
        selected_base=config.get('stack_base') or 'main'
        if result['parent_export'] is not None:
            raise RuntimeError('root export unexpectedly has a parent')
        if result['input_files']!=json.loads((campaign/'campaign.json').read_text())['seed']:
            raise RuntimeError('parent export is not based on the declared seed')
        run(['git','-c','credential.helper=','-c','credential.helper='+helper,'-c','credential.useHttpPath=true','clone','--branch',selected_base,'https://github.com/'+config['owner']+'/'+config['repository']+'.git',checkout],env)
        expected_seed=json.loads((state/'seed.ok.json').read_text())['oid']
        if run(['git','rev-parse','HEAD'],env,checkout)!=expected_seed:
            raise RuntimeError('selected base moved; rebase and recheck exports explicitly')
        if commit_inventory(checkout,expected_seed,env)!=result['input_files']:
            raise RuntimeError('root Git base tree differs from the checked snapshot input')
        seed_checkout=Path(config['workspace'])
        for key in ('user.name','user.email','user.signingkey','gpg.format','gpg.ssh.allowedSignersFile'):
            value=run(['git','config','--local',key],env,seed_checkout)
            run(['git','config','--local',key,value],env,checkout)
        for key,value in {'credential.helper':helper,'credential.useHttpPath':'true','core.hooksPath':'/dev/null','commit.gpgsign':'true'}.items():
            run(['git','config','--local',key,value],env,checkout)
        if config.get('github_app'):
            run([adapter,'git-helper',auth_path],env)
        run([jj,'git','init','--colocate'],env,checkout)
        run([jj,'bookmark','track',selected_base+'@origin'],env,checkout)
        for key,value in {'user.name':run(['git','config','user.name'],env,checkout),'user.email':run(['git','config','user.email'],env,checkout),'signing.backend':'ssh','signing.key':str(state/'host-signing'),'signing.behavior':'own'}.items():
            run([jj,'config','set','--repo',key,value],env,checkout)
        base=selected_base+'@origin'
        prior=[]
        expected_bookmarks={}
    else:
        parent=json.loads((output/'round-1/mapping.json').read_text())
        if result['parent_export']!=parent['export'] or result['input_files']!=parent['files']:
            raise RuntimeError('child snapshot does not extend the retained parent snapshot')
        base=branch_prefix+'/parent'
        if config.get('github_app'):
            run([adapter,'git-helper',auth_path],env)
        confirmed=json.loads((output/'round-1/confirmed.json').read_text())
        remote=run(['git','ls-remote','origin','refs/heads/'+base],env,checkout).split()[0]
        confirmed_parent(parent,confirmed,remote)
        expected_bookmarks={base:parent['oid']}
        if run([jj,'log','--no-graph','-r',base,'-T','commit_id'],env,checkout)!=parent['oid']:
            raise RuntimeError('parent was rewritten; child needs explicit restack and recheck')
        prior=[str(output/'round-1/effects')]
    run([jj,'new',base],env,checkout)
    # Capture and hash each file again before writing these exact bytes.
    captured={}
    for name,item in actual.items():
        source=export/'project'/name
        data=source.read_bytes()
        if hashlib.sha256(data).hexdigest()!=item['sha256']:
            raise RuntimeError('export changed during import')
        captured[name]=data
    for name,data in captured.items():
        path=checkout/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o644)
    description='Add '+LANES[lane][number-1]+' through the isolated '+lane+' agent'
    run([jj,'describe','-m',description],env,checkout)
    branch=branch_prefix+('/parent' if number==1 else '/child')
    run([jj,'bookmark','create',branch,'-r','@'],env,checkout)
    oid=run([jj,'log','--no-graph','-r',branch,'-T','commit_id'],env,checkout)
    change=run([jj,'log','--no-graph','-r',branch,'-T','change_id'],env,checkout)
    run(['git','verify-commit',oid],env,checkout)
    if commit_inventory(checkout,oid,env)!=actual:
        raise RuntimeError('final signed Git tree differs from the checked export')
    expected_bookmarks[branch]=oid
    config['workspace']=str(checkout)
    config['publication']={'task':lane,'receipt_dir':str(attempt/'effects'),'prior_receipts':prior,'bookmarks':expected_bookmarks}
    save(attempt/'config.json',config)
    save(attempt/'mapping.json',{'task':lane,'round':number,'export':str(export),'manifest_sha256':result['manifest_sha256'],'files':actual,'change_id':change,'oid':oid,'bookmark':branch,'signature_verified_locally':True,'publisher_actor':config['expected_actor'],'commit_author':run(['git','show','-s','--format=%an <%ae>',oid],env,checkout)})
    completed=subprocess.run([str(adapter),'submit',str(attempt/'config.json'),branch],env=env,capture_output=True,timeout=240)
    (attempt/'submit.stdout').write_bytes(completed.stdout);(attempt/'submit.stderr').write_bytes(completed.stderr)
    if completed.returncode:
        raise RuntimeError('publication failed or uncertain; retain mapping and effects, do not rerun this attempt')
    remote=run(['git','ls-remote','origin','refs/heads/'+branch],env,checkout).split()[0]
    if remote!=oid:
        raise RuntimeError('remote head differs; reconcile without overwriting')
    save(attempt/'confirmed.json',{'oid':oid,'remote_oid':remote})
    return {'task':lane,'round':number,'oid':oid,'bookmark':branch,'publication_confirmed':True}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state',type=Path,required=True);p.add_argument('--agents',type=Path,required=True)
    p.add_argument('--lane',choices=LANES,required=True);p.add_argument('--round',type=int,choices=(1,2),required=True)
    p.add_argument('--jj',type=Path,required=True);p.add_argument('--adapter',type=Path,required=True)
    p.add_argument('--config',type=Path,help='Explicit host App configuration; defaults to retained personal configuration')
    p.add_argument('--publication-id',help='Fresh namespace, for example app-v1; required for App publication')
    a=p.parse_args()
    print(json.dumps(publish(a.state.resolve(),a.agents.resolve(),a.lane,a.round,a.jj.resolve(),a.adapter.resolve(),a.config.resolve() if a.config else None,a.publication_id)))


if __name__=='__main__':
    main()
