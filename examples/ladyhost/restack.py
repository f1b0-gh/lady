#!/usr/bin/env python3
"""Restack one owned child after a same-tree GitHub UI merge of its parent.

This bounded scenario reuses snapshot checks only for unchanged input/output
files. It never reuses review approval and never integrates the target branch.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from checks import app_password, validate_check_binding
from github import run, save
from publish import commit_inventory, confirmed_parent, publication_names


def attempt_name(value):
    suffix=value.removeprefix('restack-')
    if not value.startswith('restack-') or not suffix or len(value)>48 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in suffix):
        raise ValueError('select a fresh restack-N attempt name')
    return value


def validate_parent(pr, number, parent, config, target, tree):
    expected_repo=config['expected_repository_id']
    if (pr.get('number')!=number or pr.get('merged') is not True or pr.get('state')!='closed'
            or pr.get('merge_commit_sha')!=target
            or pr.get('user',{}).get('login')!=config['expected_actor']
            or pr.get('head',{}).get('sha')!=parent['oid']
            or pr.get('head',{}).get('ref')!=parent['bookmark']
            or pr.get('head',{}).get('repo',{}).get('id')!=expected_repo
            or pr.get('base',{}).get('repo',{}).get('id')!=expected_repo
            or pr.get('base',{}).get('ref')!=config['stack_base']):
        raise RuntimeError('merged parent identity or selected target changed')
    if tree!=parent['files']:
        raise RuntimeError('integrated parent tree differs; new snapshot verification is required')


def validate_child(pr, number, mapping, parent, config):
    if (pr.get('number')!=number or pr.get('state')!='open' or pr.get('merged') is not False
            or pr.get('draft') is not False or pr.get('user',{}).get('login')!=config['expected_actor']
            or pr.get('head',{}).get('ref')!=mapping['bookmark']
            or pr.get('head',{}).get('sha')!=mapping['oid']
            or pr.get('base',{}).get('ref')!=parent['bookmark']
            or any(pr.get(side,{}).get('repo',{}).get('id')!=config['expected_repository_id']
                   for side in ('head','base'))):
        raise RuntimeError('original child PR changed or closed; replacement publication refused')


def retained_child_pr(previous, mapping):
    matches=[]
    for path in (previous/'effects').glob('*.ok.json'):
        result=json.loads(path.read_text()).get('result')
        if isinstance(result,dict) and result.get('head')==mapping['bookmark'] and result.get('oid')==mapping['oid']:
            number=result.get('pr')
            if type(number) is int and number>0:
                matches.append(number)
    if len(matches)!=1:
        raise RuntimeError('unique original child PR acknowledgement is required')
    return matches[0]


def restack(args):
    state=args.state.resolve()
    checkout_name,output_name,_=publication_names(args.lane,args.publication_id)
    checkout=state/checkout_name;output=state/output_name
    previous=output/'round-2'
    parent=json.loads((output/'round-1/mapping.json').read_text())
    mapping=json.loads((previous/'mapping.json').read_text())
    child_number=retained_child_pr(previous,mapping)
    confirmed=json.loads((previous/'confirmed.json').read_text())
    config=json.loads((previous/'config.json').read_text())
    if not config.get('github_app') or config.get('stack_base')!='app-experiment-base':
        raise RuntimeError('this restack scenario requires the App and disposable test base')
    if Path(config['workspace']).resolve()!=checkout:
        raise RuntimeError('publication checkout changed')
    if len(args.expected_target)!=40 or any(c not in '0123456789abcdef' for c in args.expected_target):
        raise ValueError('expected target must be a full commit OID')
    result=json.loads((args.agents/args.lane/'round-2-result.json').read_text())
    if result['parent_export']!=parent['export'] or result['input_files']!=parent['files']:
        raise RuntimeError('checked child does not extend the recorded parent')
    env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','JJ_')) and k not in
         ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN','SSH_AUTH_SOCK')}
    env.update(PATH=str(args.jj.resolve().parent)+':'+env.get('PATH','/usr/bin:/bin'),
               GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',
               JJ_CONFIG=str(state/'jj-host.toml'),GH_HOST='github.com')
    validate_check_binding(mapping,result,confirmed,commit_inventory(checkout,mapping['oid'],env))
    attempt=output/attempt_name(args.attempt)
    attempt.mkdir(mode=0o700)
    auth=dict(config);auth.pop('publication',None)
    auth_path=attempt/'auth.json';save(auth_path,auth)
    adapter=args.adapter.resolve();jj=args.jj.resolve()
    run([adapter,'preflight',auth_path],env)
    request=f"protocol=https\nhost=github.com\npath={config['owner']}/{config['repository']}.git\n\n"
    response=subprocess.run([str(adapter),'credential',str(auth_path),'get'],input=request,
                            text=True,capture_output=True,env=env,timeout=180)
    if response.returncode:
        raise RuntimeError('App authentication failed; no credential output disclosed')
    api_env=dict(env,GH_TOKEN=app_password(response.stdout))
    endpoint=f"repos/{config['owner']}/{config['repository']}/pulls/{args.parent_pr}"
    pr=json.loads(run([args.gh.resolve(),'api','--hostname','github.com',endpoint],api_env))
    save(attempt/'parent-observed.json',pr)
    endpoint=f"repos/{config['owner']}/{config['repository']}/pulls/{child_number}"
    child=json.loads(run([args.gh.resolve(),'api','--hostname','github.com',endpoint],api_env))
    save(attempt/'child-observed.json',child)
    validate_child(child,child_number,mapping,parent,config)
    run([adapter,'git-helper',auth_path],env)
    run([jj,'git','fetch','--remote','origin'],env,checkout)
    target=config['stack_base'];branch=mapping['bookmark']
    remote=run(['git','ls-remote','origin','refs/heads/'+branch],env,checkout).split()[0]
    confirmed_parent(mapping,confirmed,remote)
    if run([jj,'log','--no-graph','-r',branch,'-T','commit_id'],env,checkout)!=mapping['oid']:
        raise RuntimeError('local child changed; reconcile before restacking')
    actual_target=run(['git','rev-parse','refs/remotes/origin/'+target],env,checkout)
    if actual_target!=args.expected_target:
        raise RuntimeError('target changed; reconcile before restacking')
    validate_parent(pr,args.parent_pr,parent,config,args.expected_target,
                    commit_inventory(checkout,args.expected_target,env))
    save(attempt/'restack.intent.json',{'old_oid':mapping['oid'],'target_oid':args.expected_target,
                                      'source_mapping':str(previous/'mapping.json'),
                                      'source_round':2,'review_reused':False})
    run([jj,'rebase','-r',branch,'-d',target+'@origin'],env,checkout)
    oid=run([jj,'log','--no-graph','-r',branch,'-T','commit_id'],env,checkout)
    change=run([jj,'log','--no-graph','-r',branch,'-T','change_id'],env,checkout)
    if change!=mapping['change_id'] or oid==mapping['oid']:
        raise RuntimeError('restack did not preserve the change identity with a new commit')
    run(['git','verify-commit',oid],env,checkout)
    if commit_inventory(checkout,oid,env)!=mapping['files']:
        raise RuntimeError('restacked tree differs; new snapshot verification is required')
    if run(['git','rev-parse',oid+'^'],env,checkout)!=args.expected_target:
        raise RuntimeError('restacked commit does not directly extend the selected target')
    config['publication']={'task':args.lane,'receipt_dir':str(attempt/'effects'),
                           'prior_receipts':[str(output/f'round-{n}'/'effects') for n in (1,2)],
                           'bookmarks':{branch:oid},'revision_prs':{branch:child_number}}
    save(attempt/'config.json',config)
    save(attempt/'mapping.json',dict(mapping,oid=oid,change_id=change,
                                   source_round=2,previous_oid=mapping['oid'],target_oid=args.expected_target))
    completed=subprocess.run([str(adapter),'submit',str(attempt/'config.json'),branch],
                             env=env,capture_output=True,timeout=240)
    (attempt/'submit.stdout').write_bytes(completed.stdout)
    (attempt/'submit.stderr').write_bytes(completed.stderr)
    if completed.returncode:
        raise RuntimeError('restack publication failed or uncertain; preserve attempt and reconcile')
    remote=run(['git','ls-remote','origin','refs/heads/'+branch],env,checkout).split()[0]
    if remote!=oid:
        raise RuntimeError('published child differs; reconcile without overwriting')
    save(attempt/'confirmed.json',{'oid':oid,'remote_oid':remote})
    return {'oid':oid,'previous_oid':mapping['oid'],'attempt':str(attempt),
            'snapshot_unchanged':True,'native_approval_required':True}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('state','agents','jj','adapter','gh'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--lane',choices=('ranges','statistics','rolling'),required=True)
    p.add_argument('--publication-id',required=True)
    p.add_argument('--parent-pr',type=int,required=True)
    p.add_argument('--expected-target',required=True)
    p.add_argument('--attempt',required=True)
    print(json.dumps(restack(p.parse_args())))


if __name__=='__main__':main()
