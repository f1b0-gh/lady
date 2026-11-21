#!/usr/bin/env python3
"""Try one reviewed task containing two retained agent changes and signed commits.

Prepare rechecks both composed snapshots through native Ladyshell. Publish uses
the existing Rust App/Journal boundary and exposes only the final task bookmark.
No model is rerun and no approval is synthesized. Attempts are create-only.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess

from agents import (LANES, assertions, clean_environment, inventory, paths, scoped, sha,
                    verify_artifact)
from github import run, save
from handoff import retained_handoff, render_review
from publish import commit_inventory, publication_names


def task_titles(lane):
    titles={
        'statistics': ('Add streaming mean','Add streaming mean and population variance'),
        'ranges': ('Add streaming bounds','Add bounds and normalization'),
        'rolling': ('Add rolling windows','Add rolling windows and moving averages'),
        'changes': ('Add successive differences','Add total change from successive differences'),
    }
    if lane not in titles:raise ValueError('Unknown task')
    return titles[lane]


def compose_snapshot(base, result, lane):
    allowed=paths(lane)
    scoped(result['input_files'],result['files'],allowed)
    if any(base.get(name)!=item for name,item in result['input_files'].items()):
        raise RuntimeError('shared input or parent changed; composition requires new work')
    if any(name in base and name not in result['input_files'] for name in allowed):
        raise RuntimeError('task overlaps existing base work')
    return dict(base,**{name:result['files'][name] for name in allowed})


def validate_history(base, commits, parents, tip):
    if len(commits)!=2 or parents!=[base,commits[0]] or tip!=commits[-1] or len(set([base,*commits]))!=3:
        raise RuntimeError('task must retain exactly two dependent commits at the checked tip')


def validate_source_chain(sources, seed):
    if (len(sources)!=2 or sources[0]['parent_export'] is not None
            or sources[0]['input_files']!=seed
            or sources[1]['parent_export']!=sources[0]['export']
            or sources[1]['input_files']!=sources[0]['files']):
        raise RuntimeError('source changes are not one dependent task from the campaign seed')


def retained_source(campaign, lane, number):
    result=json.loads((campaign/lane/f'round-{number}-result.json').read_text())
    export=Path(result['export'])
    # Normal runs retain both rounds in one task. Recovery may provision a
    # separate child task; neither path permits arbitrary task-state selection.
    task_names=('task',) if number==1 else ('task','child-task')
    candidates=[(campaign/lane/name/'state').resolve() for name in task_names]
    matching=[state for state in candidates
              if state.is_relative_to(campaign.resolve())
              and export.resolve().parent==state/'exports']
    if len(matching)!=1:
        raise RuntimeError('source export outside retained task')
    if ('source_task_state' in result
            and Path(result['source_task_state']).resolve()!=matching[0]):
        raise RuntimeError('explicit source task binding differs from selected lane')
    if (sha(export/'manifest.json')!=result['manifest_sha256']
            or inventory(export/'project')!=result['files']
            or json.loads((export/'manifest.json').read_text())['files']!=result['files']
            or json.loads((export/'checks.json').read_text())!=result['checks']
            or not result['checks']['passed'] or not result['checks']['cleanup_confirmed']):
        raise RuntimeError('retained agent evidence changed')
    return result


def environment(jj):
    env=clean_environment()
    env={k:v for k,v in env.items() if not k.startswith('JJ_')}
    env.update(PATH=str(jj.parent)+':'+env.get('PATH','/usr/bin:/bin'),JJ_CONFIG='/dev/null')
    return env


def initialize_checkout(path, env):
    # Git init alone accepts existing repositories, including their local hooks
    # and configuration. Reserve the new host directory before invoking Git.
    path.mkdir(mode=0o700)
    run(['git','-c','core.hooksPath=/dev/null','init',path],env)
    run(['git','config','--local','core.hooksPath','/dev/null'],env,path)


def call(command, env, directory, label, timeout=900):
    print(label,flush=True)
    save(directory/(label+'.intent.json'),{'operation':label})
    result=subprocess.run(list(map(str,command)),env=env,capture_output=True,timeout=timeout)
    (directory/(label+'.stdout')).write_bytes(result.stdout)
    (directory/(label+'.stderr')).write_bytes(result.stderr)
    save(directory/(label+'.result.json'),{'exit_code':result.returncode})
    if result.returncode:
        raise RuntimeError(label+' failed; inspect retained private logs without replaying')
    return result.stdout


def prepare(args):
    state=args.state.resolve();campaign=args.agents.resolve();lane=args.lane
    checkout_name,output_name,branch_prefix=publication_names(lane,args.publication_id)
    root=state/('task-review-'+args.publication_id)
    root.mkdir(mode=0o700)
    checkout=state/checkout_name;output=state/output_name
    output.mkdir(mode=0o700)
    config=json.loads(args.config.read_text())
    if not config.get('github_app') or config.get('stack_base')!='app-experiment-base':
        raise RuntimeError('task review requires the App and disposable test base')
    jj=args.jj.resolve();adapter=args.adapter.resolve();native=args.ladyshell.resolve()
    env=environment(jj)
    recorded=json.loads((campaign/'campaign.json').read_text())
    verify_artifact('ladyshell',native,recorded['ladyshell'])
    for key in ('codex','codex_code_mode_host'):
        verify_artifact(key,Path(recorded[key]['path']),recorded[key])
    if inventory(campaign/'resources')!=recorded['resources']:
        raise RuntimeError('retained native resources changed')
    sources=[retained_source(campaign,lane,n) for n in (1,2)]
    validate_source_chain(sources,recorded['seed'])
    handoffs=[retained_handoff(campaign,lane,n,source) for n,source in enumerate(sources,1)]
    save(root/'agent-handoffs.json',handoffs)
    config=dict(config,workspace=str(checkout));config.pop('publication',None)
    auth=root/'auth.json';save(auth,config)
    # Public Git fetch has no personal authentication fallback. App scope is
    # independently established before any outward publication.
    initialize_checkout(checkout,env)
    remote='https://github.com/'+config['owner']+'/'+config['repository']+'.git'
    run(['git','remote','add','origin',remote],env,checkout)
    run([adapter,'preflight',auth],env)
    run([adapter,'git-helper',auth],env)
    base=config['stack_base']
    run(['git','fetch','origin',f'refs/heads/{base}:refs/remotes/origin/{base}'],env,checkout)
    actual_base=run(['git','rev-parse','refs/remotes/origin/'+base],env,checkout)
    if actual_base!=args.expected_base:
        raise RuntimeError('selected base changed; reconcile before preparing this task')
    run(['git','checkout','--detach',actual_base],env,checkout)
    before=commit_inventory(checkout,actual_base,env)
    snapshots=[]
    for source in sources:
        before=compose_snapshot(before,source,lane);snapshots.append(before)
    save(root/'composition.json',{'base':actual_base,'source_exports':[s['export'] for s in sources],
                                 'snapshots':snapshots,'new_model_runs':0})
    task=root/'native-task';native_state=task/'state'
    inputs=root/'configuration';inputs.mkdir()
    # The current base contains the ranges work; new task files enter via run.
    include=sorted(commit_inventory(checkout,actual_base,env))
    (inputs/'config.ncl').write_text('{ schema_version = 1, name = "jjpr-task-review", sources = { include = '+json.dumps(include)+', exclude = [] }, tools = { python = { version = "3.12.15" } }, missions.dev = { tools = ["python"], include = [], depends_on = [], checks = [] }, sandbox = { gateway = "openshell", workspace = "default", provider = "ladyshell-lo-native" } }\n')
    common=['--config',inputs/'config.ncl','--lock',inputs/'environment.lock.json',
            '--resources',campaign/'resources','--codex',recorded['codex']['path'],
            '--codex-code-mode-host',recorded['codex_code_mode_host']['path'],'--mission','dev']
    results=[];agent_output=root/'agents'/lane;agent_output.mkdir(parents=True)
    try:
        call([native,'lock','--project',checkout,'--state',native_state,*common],env,root,'native-lock')
        call([native,'task','start','--repository',checkout,'--directory',task,
              '--branch','verify/'+args.publication_id,'--base',actual_base,*common],env,root,'native-start',1800)
        prior=commit_inventory(checkout,actual_base,env)
        for number,(source,expected) in enumerate(zip(sources,snapshots),1):
            captured={name:base64.b64encode((Path(source['export'])/'project'/name).read_bytes()).decode('ascii') for name in paths(lane)}
            program='import base64,pathlib\nfiles='+repr(captured)+'\nfor name,data in files.items():\n p=pathlib.Path(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode(data));p.chmod(0o644)\n'
            call([native,'run','--state',native_state,'--sync','--timeout','60','--','python3','-c',program],env,root,f'round-{number}-compose')
            export=Path(json.loads((native_state/'state.json').read_text())['last_sync'])
            if inventory(export/'project')!=expected:
                raise RuntimeError('composed native export differs from exact selected files')
            policy=agent_output/f'round-{number}-checks.json'
            save(policy,{'schema_version':1,'checks':{'commands':[
                ['python3','-m','unittest','discover','-s','tests','-v'],
                ['python3','-c',assertions('ranges','children')],
                ['python3','-c',assertions(lane,'roots' if number==1 else 'children')]],'timeout':60}})
            call([native,'publication','check','--state',native_state,'--export',export,'--policy',policy],env,root,f'round-{number}-verify')
            checks=json.loads((export/'checks.json').read_text())
            if not checks['passed'] or not checks['cleanup_confirmed']:
                raise RuntimeError('composed checks or verifier cleanup incomplete')
            result={'lane':lane,'round':number,'export':str(export),'files':expected,'input_files':prior,
                    'parent_export':results[-1]['export'] if results else None,'checks':checks,
                    'manifest_sha256':sha(export/'manifest.json'),'host_check_policy_sha256':sha(policy),
                    'source_agent_export':source['export'],'model_rerun':False}
            save(agent_output/f'round-{number}-result.json',result)
            results.append(result);prior=expected
    finally:
        if (native_state/'state.json').exists():
            call([native,'destroy','--state',native_state],env,root,'native-cleanup',600)
    for key in ('user.name','user.email','user.signingkey','gpg.format','gpg.ssh.allowedSignersFile'):
        value=run(['git','config','--local',key],env,Path(json.loads(args.config.read_text())['workspace']))
        run(['git','config','--local',key,value],env,checkout)
    run(['git','config','--local','commit.gpgsign','true'],env,checkout)
    run(['git','config','--local','core.hooksPath','/dev/null'],env,checkout)
    commits=[]
    titles=task_titles(lane)
    for number,(result,title) in enumerate(zip(results,titles),1):
        for name in paths(lane):
            data=(Path(result['export'])/'project'/name).read_bytes()
            p=checkout/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o644)
        run(['git','add','--',*sorted(paths(lane))],env,checkout)
        description=render_review([item['report'] for item in handoffs[:number]],commands_per_snapshot=3)
        run(['git','commit','-m',title,'-m',description],env,checkout)
        oid=run(['git','rev-parse','HEAD'],env,checkout)
        run(['git','verify-commit',oid],env,checkout)
        if commit_inventory(checkout,oid,env)!=result['files']:
            raise RuntimeError('signed commit differs from composed checked snapshot')
        commits.append(oid)
    parents=[run(['git','rev-parse',oid+'^'],env,checkout) for oid in commits]
    validate_history(actual_base,commits,parents,run(['git','rev-parse','HEAD'],env,checkout))
    run([jj,'git','init','--colocate'],env,checkout)
    # jjpr selects mine()-owned bookmarks. Git commit authorship alone does
    # not configure jj's current user when ambient jj configuration is disabled.
    for key in ('user.name','user.email'):
        run([jj,'config','set','--repo',key,run(['git','config','--local',key],env,checkout)],env,checkout)
    run([jj,'bookmark','track',base+'@origin'],env,checkout)
    branch=branch_prefix+'/task'
    run([jj,'bookmark','create',branch,'-r',commits[-1]],env,checkout)
    attempt=output/'round-2';attempt.mkdir(mode=0o700)
    config['publication']={'task':lane,'receipt_dir':str(attempt/'effects'),'prior_receipts':[],
                           'bookmarks':{branch:commits[-1]}}
    save(attempt/'config.json',config)
    final=results[-1]
    save(attempt/'mapping.json',dict(final,oid=commits[-1],bookmark=branch,
                                   change_id=run([jj,'log','--no-graph','-r',branch,'-T','change_id'],env,checkout),
                                   task=lane,signature_verified_locally=True,publisher_actor=config['expected_actor'],
                                   internal_commits=commits,task_base=actual_base))
    prepared={'base':actual_base,'commits':commits,'bookmark':branch,'attempt':str(attempt),
              'checkout':str(checkout),'agents':str(root/'agents'),'native_cleanup_confirmed':True}
    save(root/'prepared.json',prepared)
    return prepared


def publish(args):
    state=args.state.resolve();root=state/('task-review-'+args.publication_id)
    prepared=json.loads((root/'prepared.json').read_text());attempt=Path(prepared['attempt'])
    env=environment(args.jj.resolve());checkout=Path(prepared['checkout'])
    if run(['git','ls-remote','origin','refs/heads/app-experiment-base'],env,checkout).split()[0]!=prepared['base']:
        raise RuntimeError('base changed after checks; recompose explicitly')
    call([args.adapter.resolve(),'submit',attempt/'config.json',prepared['bookmark']],env,root,'publish')
    created=[]
    for receipt in (attempt/'effects').glob('*.ok.json'):
        item=json.loads(receipt.read_text()).get('result')
        if isinstance(item,dict) and item.get('head')==prepared['bookmark'] and 'pr' in item:
            created.append(item)
    if len(created)!=1 or created[0]['oid']!=prepared['commits'][-1]:
        raise RuntimeError('expected exactly one task PR acknowledgement; reconcile')
    remote=run(['git','ls-remote','origin','refs/heads/'+prepared['bookmark']],env,checkout).split()[0]
    if remote!=prepared['commits'][-1]:raise RuntimeError('published head changed; reconcile')
    save(attempt/'confirmed.json',{'oid':remote,'remote_oid':remote})
    save(root/'publication.json',{'pr':created[0]['pr'],'oid':remote,'internal_commits':prepared['commits']})
    return {'pr':created[0]['pr'],'oid':remote,'review_units':1,'internal_commits':2}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=('prepare','publish'))
    for name in ('state','agents','config','jj','adapter','ladyshell'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--lane',choices=tuple(LANES),default='statistics')
    p.add_argument('--publication-id',required=True)
    p.add_argument('--expected-base',required=True)
    args=p.parse_args()
    print(json.dumps(prepare(args) if args.operation=='prepare' else publish(args)))


if __name__=='__main__':main()
