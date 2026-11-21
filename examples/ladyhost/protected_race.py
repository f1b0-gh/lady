#!/usr/bin/env python3
"""Race two reviewed task candidates through the existing native host gate.

This public-fixture scenario grants no approval and implements no replacement
admission protocol. Unknown native outcomes retain their original journals.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from agents import clean_environment, require, sha
from github import run, save
from task_review import initialize_checkout


def validate_pair(configs, requests):
    require(len(configs)==len(requests)==2, 'Select exactly two candidates')
    for key in ('provider','endpoint','owner','repository','visibility','expected_repository_id',
                'expected_actor','github_app','stack_base'):
        require(configs[0].get(key)==configs[1].get(key), 'Candidate host scopes differ: '+key)
    require(configs[0].get('visibility')=='public' and configs[0].get('github_app'),
            'This observer supports the public App fixture only')
    require(configs[0].get('stack_base')=='app-experiment-base', 'Select the disposable protected target')
    for key in ('expected_target','target','reviewer','update_ruleset_id','quality_ruleset_id','allowed_signers','ci'):
        require(requests[0].get(key)==requests[1].get(key), 'Candidate integration scopes differ: '+key)
    require(requests[0].get('target')==configs[0]['stack_base'] and requests[0].get('ci'),
            'Require the protected target and exact-commit CI')
    for key in ('task','pr_number','source','expected_head'):
        require(requests[0].get(key)!=requests[1].get(key), 'Candidates must differ: '+key)
    for values,key in ((configs,'workspace'),(requests,'receipt_dir')):
        a,b=(Path(v[key]).resolve() for v in values)
        require(not a.is_relative_to(b) and not b.is_relative_to(a), 'Candidate paths overlap: '+key)
    for request in requests:
        receipt=Path(request['receipt_dir']).resolve()
        for config in configs:
            workspace=Path(config['workspace']).resolve()
            require(not receipt.is_relative_to(workspace) and not workspace.is_relative_to(receipt),
                    'Every journal must be separate from both candidate workspaces')


def classify(outcomes, requests, observed):
    winners=[n for n,value in enumerate(outcomes) if value.get('outcome')=='integrated']
    require(len(outcomes)==2 and len(winners)==1, 'Race needs reconciliation: not exactly one acknowledged integration')
    winner=winners[0];loser=1-winner
    require(outcomes[winner].get('oid')==requests[winner]['expected_head']==observed,
            'Acknowledged winner differs from target readback')
    require(outcomes[loser].get('outcome') in ('refused','unknown'), 'Unexpected competing outcome')
    return {'winner_pr':requests[winner]['pr_number'],'winner_oid':observed,
            'loser_pr':requests[loser]['pr_number'],'loser_outcome':outcomes[loser]['outcome'],
            'qualified_one_winner_and_refusal':outcomes[loser]['outcome']=='refused'}


def race(args):
    config_paths=[p.resolve(strict=True) for p in args.config]
    request_paths=[p.resolve(strict=True) for p in args.request]
    raw={str(p):p.read_bytes() for p in (*config_paths,*request_paths)}
    configs=[json.loads(raw[str(p)]) for p in config_paths]
    requests=[json.loads(raw[str(p)]) for p in request_paths]
    validate_pair(configs,requests)
    for request in requests:
        receipt=Path(request['receipt_dir'])
        require(not receipt.exists() and not receipt.is_symlink(),
                'Original integration journal exists; reconcile it before any new attempt')
    root=args.state.absolute()
    for config in configs:
        require(not root.resolve().is_relative_to(Path(config['workspace']).resolve()),
                'Race evidence must remain outside candidate workspaces')
    root.mkdir(mode=0o700)
    adapter=args.adapter.resolve(strict=True)
    frozen={p:hashlib.sha256(data).hexdigest() for p,data in raw.items()}
    frozen[str(adapter)]=sha(adapter)
    save(root/'inputs.json',{'config_paths':list(map(str,config_paths)),
         'request_paths':list(map(str,request_paths)),'sha256':frozen,
         'requests':requests,'scope':'two native integrations; observations are not atomic'})
    env=clean_environment()

    def invoke(number, operation):
        label=f'{number+1}-{operation}'
        for path in (config_paths[number],request_paths[number],adapter):
            require(sha(path)==frozen[str(path)], 'Frozen host input changed')
        save(root/(label+'.intent.json'),{'operation':operation,'request':str(request_paths[number])})
        started=time.monotonic()
        try:
            result=subprocess.run([str(adapter),operation,str(config_paths[number]),str(request_paths[number])],
                                  capture_output=True,text=True,env=env,timeout=900)
        except subprocess.TimeoutExpired:
            value={'outcome':'unknown','reason':'controller timeout; inspect native journal and active processes'}
            save(root/(label+'.result.json'),{'exit_code':None,'result':value,
                 'started_monotonic':started,'finished_monotonic':time.monotonic()})
            return value
        (root/(label+'.stdout')).write_text(result.stdout)
        (root/(label+'.stderr')).write_text(result.stderr)
        try:value=json.loads(result.stdout)
        except (ValueError,TypeError):value={'outcome':'unknown','reason':'native result unavailable'}
        if not isinstance(value,dict) or (result.returncode and value.get('outcome') in ('observed','integrated')):
            value={'outcome':'unknown','reason':'native result and exit code disagree'}
        save(root/(label+'.result.json'),{'exit_code':result.returncode,'result':value,
             'started_monotonic':started,'finished_monotonic':time.monotonic()})
        return value

    # Missing approval/checks stop both candidates before any integration call.
    for number in (0,1):
        require(invoke(number,'inspect-integration').get('outcome')=='observed',
                'Both candidates need current native admission before the race')
    observer=root/'observer';initialize_checkout(observer,env)
    remote='https://github.com/'+configs[0]['owner']+'/'+configs[0]['repository']+'.git'
    run(['git','remote','add','origin',remote],env,observer)
    def heads():
        rows=run(['git','-c','credential.helper=','ls-remote','--heads','origin'],env,observer)
        return {line.split()[1]:line.split()[0] for line in rows.splitlines()}
    before=heads();target='refs/heads/'+requests[0]['target']
    require(before.get(target)==requests[0]['expected_target'], 'Target advanced before race dispatch')
    save(root/'before-heads.json',before)
    barrier=threading.Barrier(2)
    def dispatch(number):
        barrier.wait(timeout=30)
        return invoke(number,'integrate')
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes=list(pool.map(dispatch,(0,1)))
    save(root/'native-outcomes.json',outcomes)
    after=heads();save(root/'after-heads.json',after)
    result=classify(outcomes,requests,after.get(target))
    calls=[json.loads((root/f'{n}-integrate.result.json').read_text()) for n in (1,2)]
    overlap=max(v['started_monotonic'] for v in calls)<min(v['finished_monotonic'] for v in calls)
    result['concurrent_native_calls_observed']=overlap
    result['qualified_protected_race']=result['qualified_one_winner_and_refusal'] and overlap
    require({k:v for k,v in before.items() if k!=target}=={k:v for k,v in after.items() if k!=target},
            'Unrelated refs changed; inspect retained observations')
    run(['git','fetch','origin',target],env,observer)
    observed=run(['git','rev-parse','FETCH_HEAD'],env,observer)
    require(observed==result['winner_oid'],'Independent fetch differs from acknowledged winner')
    commits=run(['git','rev-list','--reverse',requests[0]['expected_target']+'..'+observed],env,observer).splitlines()
    require(bool(commits),'No candidate commits in independent fetch')
    parent=requests[0]['expected_target']
    for oid in commits:
        require(run(['git','rev-parse',oid+'^@'],env,observer)==parent,'Nonlinear integrated history')
        run(['git','-c','gpg.format=ssh','-c','gpg.ssh.allowedSignersFile='+requests[0]['allowed_signers'],
             'verify-commit',oid],env,observer)
        parent=oid
    save(root/'result.json',dict(result,commits=commits,signatures_verified_independently=True,
                               unrelated_branch_heads_unchanged=True,automatic_retries=0,
                               unknown_outcome_policy='retain original journal; never infer refusal from timeout'))
    return result


if __name__=='__main__':
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--adapter',type=Path,required=True)
    parser.add_argument('--config',type=Path,action='append',required=True)
    parser.add_argument('--request',type=Path,action='append',required=True)
    print(json.dumps(race(parser.parse_args())))
