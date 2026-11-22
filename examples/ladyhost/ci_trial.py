#!/usr/bin/env python3
"""Prepare two checked CI revisions, then publish them to one App-authored PR.

Host scenario code: no model invocation, credentials in the sandbox, synthesized
CI result, human approval or target merge. Every write attempt is create-only.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

from agents import assertions, inventory, sha, verify_artifact
from checks import app_password, validate_check_binding, validate_policy_file
from github import run, save
from publish import commit_inventory
from task_review import call, environment, initialize_checkout, validate_history

HERE=Path(__file__).resolve().parent
WORKFLOW='.github/workflows/ci-verify.yml'
MARKER='.ci/deliberate-failure'
MARKER_BYTES=b'Expected CI failure injection. Remove this marker in the fixed revision.\n'


def snapshots(base, workflow):
    if any(p==MARKER or p.startswith('.github/workflows/') for p in base):
        raise RuntimeError('CI trial requires an unused workflow namespace and failure marker')
    def item(data):return {'sha256':hashlib.sha256(data).hexdigest(),'executable':False}
    fixed=dict(base,**{WORKFLOW:item(workflow)})
    return dict(fixed,**{MARKER:item(MARKER_BYTES)}),fixed


def validate_revision(config, prepared, number, pr):
    if (pr.get('number')!=number or pr.get('state')!='open' or pr.get('merged') is not False
            or pr.get('draft') is not False or pr.get('user',{}).get('login')!=config['expected_actor']
            or pr.get('user',{}).get('type')!='Bot'
            or pr.get('head',{}).get('ref')!=prepared['bookmark']
            or pr.get('head',{}).get('sha')!=prepared['commits'][0]
            or pr.get('base',{}).get('ref')!=config['stack_base']
            or any(pr.get(side,{}).get('repo',{}).get('id')!=config['expected_repository_id'] for side in ('head','base'))):
        raise RuntimeError('CI revision requires the same open PR and original exact head')


def api_environment(adapter, config_path, env):
    config=json.loads(config_path.read_text())
    request=f"protocol=https\nhost=github.com\npath={config['owner']}/{config['repository']}.git\n\n"
    result=subprocess.run([str(adapter),'credential',str(config_path),'get'],input=request,text=True,capture_output=True,env=env,timeout=180)
    if result.returncode:raise RuntimeError('Host App credential unavailable; output withheld')
    return dict(env,GH_TOKEN=app_password(result.stdout),GH_HOST='github.com')


def prepare(args):
    root=args.root.resolve();root.mkdir(mode=0o700)
    config=json.loads(args.config.read_text());config.pop('publication',None)
    if (not config.get('github_app',{}).get('workflow_write') or config.get('stack_base')!='app-experiment-base'
            or config.get('visibility')!='public'):
        raise RuntimeError('CI fixture requires explicit workflow scope, public visibility and disposable target')
    if (not args.branch.startswith('agent/') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-/' for c in args.branch)
            or any(not p for p in args.branch.split('/'))):
        raise ValueError('select a bounded agent branch')
    jj=args.jj.resolve();native=args.ladyshell.resolve();adapter=args.adapter.resolve()
    env=environment(jj);campaign=args.agents.resolve();recorded=json.loads((campaign/'campaign.json').read_text())
    verify_artifact('ladyshell',native,recorded['ladyshell'])
    for name in ('codex','codex_code_mode_host'):verify_artifact(name,Path(recorded[name]['path']),recorded[name])
    if inventory(campaign/'resources')!=recorded['resources']:raise RuntimeError('native resources changed')
    template=Path(config['workspace'])
    signing={key:run(['git','config','--local',key],env,template) for key in
             ('user.name','user.email','user.signingkey','gpg.format','gpg.ssh.allowedSignersFile')}
    checkout=root/'checkout';initialize_checkout(checkout,env)
    config['workspace']=str(checkout);save(root/'auth.json',config)
    run([adapter,'preflight',root/'auth.json'],env)
    run(['git','remote','add','origin',f"https://github.com/{config['owner']}/{config['repository']}.git"],env,checkout)
    run([adapter,'git-helper',root/'auth.json'],env)
    target=config['stack_base']
    run(['git','fetch','origin',f'refs/heads/{target}:refs/remotes/origin/{target}'],env,checkout)
    base=run(['git','rev-parse','refs/remotes/origin/'+target],env,checkout)
    if base!=args.expected_base:raise RuntimeError('CI target changed before preparation')
    run(['git','checkout','--detach',base],env,checkout)
    before=commit_inventory(checkout,base,env);workflow=(HERE/'scenario/ci-verify.yml').read_bytes()
    expected=snapshots(before,workflow)
    save(root/'inputs.json',{'base':base,'files':before,'workflow_sha256':hashlib.sha256(workflow).hexdigest(),'model_runs':0})
    inputs=root/'configuration';inputs.mkdir()
    (inputs/'config.ncl').write_text('{ schema_version = 1, name = "jjpr-ci-trial", sources = { include = '+json.dumps(sorted(before))+', exclude = [] }, tools = { python = { version = "3.12.16" } }, missions.dev = { tools = ["python"], include = [], depends_on = [], checks = [] }, sandbox = { gateway = "openshell", workspace = "default", provider = "ladyshell-lo-native" } }\n')
    common=['--config',inputs/'config.ncl','--lock',inputs/'environment.lock.json','--resources',campaign/'resources',
            '--codex',recorded['codex']['path'],'--codex-code-mode-host',recorded['codex_code_mode_host']['path'],'--mission','dev']
    task=root/'native-task';state=task/'state';results=[]
    try:
        call([native,'lock','--project',checkout,'--state',state,*common],env,root,'native-lock')
        call([native,'task','start','--repository',checkout,'--directory',task,'--branch','verify/ci-trial','--base',base,*common],env,root,'native-start',1800)
        for number,files in enumerate(expected,1):
            attempt=root/f'round-{number}';attempt.mkdir(mode=0o700)
            program='import pathlib,base64\np=pathlib.Path('+repr(WORKFLOW)+');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode('+repr(base64.b64encode(workflow).decode())+'));p.chmod(0o644)\nm=pathlib.Path('+repr(MARKER)+')\n'
            program+=('m.parent.mkdir(parents=True,exist_ok=True);m.write_bytes('+repr(MARKER_BYTES)+');m.chmod(0o644)\n' if number==1 else 'm.unlink()\n')
            call([native,'run','--state',state,'--sync','--timeout','60','--','python3','-c',program],env,root,f'round-{number}-compose')
            export=Path(json.loads((state/'state.json').read_text())['last_sync'])
            if inventory(export/'project')!=files:raise RuntimeError('CI export differs from expected full tree')
            policy=attempt/'checks.json';save(policy,{'schema_version':1,'checks':{'commands':[
                ['python3','-m','unittest','discover','-s','tests','-v'],
                ['python3','-c',assertions('ranges','children')],
                ['python3','-c',assertions('statistics','children')]],'timeout':60}})
            call([native,'publication','check','--state',state,'--export',export,'--policy',policy],env,root,f'round-{number}-verify')
            checks=json.loads((export/'checks.json').read_text())
            if not checks['passed'] or not checks['cleanup_confirmed']:raise RuntimeError('CI snapshot verification or cleanup incomplete')
            result={'round':number,'export':str(export),'files':files,'input_files':before if number==1 else expected[0],
                    'manifest_sha256':sha(export/'manifest.json'),'host_check_policy_sha256':sha(policy),'checks':checks}
            save(attempt/'result.json',result);results.append(result)
    finally:
        if (state/'state.json').exists():call([native,'destroy','--state',state],env,root,'native-cleanup',600)
    for key,value in signing.items():
        run(['git','config','--local',key,value],env,checkout)
    run(['git','config','--local','commit.gpgsign','true'],env,checkout)
    commits=[]
    for number,result in enumerate(results,1):
        for name in (WORKFLOW,MARKER):
            path=checkout/name
            if name in result['files']:
                data=(Path(result['export'])/'project'/name).read_bytes()
                if hashlib.sha256(data).hexdigest()!=result['files'][name]['sha256']:raise RuntimeError('checked CI bytes changed')
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o644)
            elif path.exists():path.unlink()
        run(['git','add','--',WORKFLOW,MARKER],env,checkout)
        title='Exercise required CI with a deliberate failure' if number==1 else 'Enable exact-commit CI after testing failure refusal'
        body=('Host-prepared CI experiment; existing sandbox-agent code stays unchanged. GitHub Actions fetches the pushed SHA and runs repository tests. '
              'The .ci/deliberate-failure marker makes the first revision fail deliberately. The second removes only that marker. '
              'Both snapshots passed three independent Ladyshell checks and are signed on the host. This snapshot status is separate from Actions CI. '
              'Review the final revision after real CI succeeds; the host preserves both signed objects.')
        run(['git','commit','-m',title,'-m',body],env,checkout)
        oid=run(['git','rev-parse','HEAD'],env,checkout);run(['git','verify-commit',oid],env,checkout)
        if commit_inventory(checkout,oid,env)!=result['files']:raise RuntimeError('signed CI tree differs from checked export')
        save(root/f'round-{number}'/'mapping.json',dict(result,oid=oid,bookmark=args.branch));commits.append(oid)
    validate_history(base,commits,[run(['git','rev-parse',oid+'^'],env,checkout) for oid in commits],commits[-1])
    run([jj,'git','init','--colocate'],env,checkout)
    for key in ('user.name','user.email'):run([jj,'config','set','--repo',key,run(['git','config','--local',key],env,checkout)],env,checkout)
    run([jj,'bookmark','track',target+'@origin'],env,checkout)
    run([jj,'bookmark','create',args.branch,'-r',commits[0]],env,checkout)
    prepared={'base':base,'bookmark':args.branch,'commits':commits,'checkout':str(checkout),'native_cleanup_confirmed':True}
    save(root/'prepared.json',prepared);return prepared


def publish(args):
    root=args.root.resolve();number=args.round
    prepared=json.loads((root/'prepared.json').read_text());checkout=Path(prepared['checkout']);attempt=root/f'round-{number}'
    config=json.loads((root/'auth.json').read_text());env=environment(args.jj.resolve());adapter=args.adapter.resolve()
    mapping=json.loads((attempt/'mapping.json').read_text());result=json.loads((attempt/'result.json').read_text())
    if (checkout.resolve()!=root/'checkout' or Path(config['workspace']).resolve()!=checkout.resolve()
            or prepared.get('native_cleanup_confirmed') is not True
            or len(prepared['commits'])!=2 or mapping.get('oid')!=prepared['commits'][number-1]
            or mapping.get('bookmark')!=prepared['bookmark']
            or mapping.get('round')!=number or result.get('round')!=number):
        raise RuntimeError('CI workspace, prepared revision or cleanup binding changed')
    # This is local admission, not a claim that remote publication happened.
    validate_check_binding(mapping,result,{'oid':mapping['oid'],'remote_oid':mapping['oid']},
                           commit_inventory(checkout,mapping['oid'],env))
    if (sha(Path(result['export'])/'manifest.json')!=result['manifest_sha256'] or inventory(Path(result['export'])/'project')!=result['files']
            or json.loads((Path(result['export'])/'manifest.json').read_text())['files']!=result['files']
            or json.loads((Path(result['export'])/'checks.json').read_text())!=result['checks']):
        raise RuntimeError('CI retained export or check evidence changed')
    validate_policy_file(result,(attempt/'checks.json').read_bytes())
    run(['git','verify-commit',mapping['oid']],env,checkout)
    parent=prepared['base'] if number==1 else prepared['commits'][0]
    if run(['git','rev-parse',mapping['oid']+'^'],env,checkout)!=parent:
        raise RuntimeError('CI prepared history changed')
    if run(['git','ls-remote','origin','refs/heads/'+config['stack_base']],env,checkout).split()[0]!=prepared['base']:raise RuntimeError('CI target advanced; recheck explicitly')
    api_env=api_environment(adapter,root/'auth.json',env);endpoint=f"repos/{config['owner']}/{config['repository']}/pulls"
    prior=[];revision={}
    if number==2:
        previous=json.loads((root/'round-1/publication.json').read_text());pr=previous['pr']
        current=json.loads(run([args.gh.resolve(),'api',endpoint+'/'+str(pr)],api_env));validate_revision(config,prepared,pr,current)
        if run(['git','ls-remote','origin','refs/heads/'+prepared['bookmark']],env,checkout).split()[0]!=prepared['commits'][0]:raise RuntimeError('CI source advanced')
        prior=[str(root/'round-1/effects')];revision={prepared['bookmark']:pr}
        run([args.jj.resolve(),'bookmark','set',prepared['bookmark'],'-r',mapping['oid']],env,checkout)
    config['publication']={'task':'ci-trial','receipt_dir':str(attempt/'effects'),'prior_receipts':prior,'bookmarks':{prepared['bookmark']:mapping['oid']},'revision_prs':revision}
    save(attempt/'config.json',config)
    call([adapter,'submit',attempt/'config.json',prepared['bookmark']],env,attempt,'publish',300)
    if number==1:
        matches=[]
        for receipt in (attempt/'effects').glob('*.ok.json'):
            item=json.loads(receipt.read_text()).get('result')
            if isinstance(item,dict) and item.get('head')==prepared['bookmark'] and item.get('oid')==mapping['oid'] and type(item.get('pr')) is int:matches.append(item['pr'])
        if len(matches)!=1:raise RuntimeError('unique CI PR acknowledgement missing; reconcile')
        pr=matches[0]
    remote=run(['git','ls-remote','origin','refs/heads/'+prepared['bookmark']],env,checkout).split()[0]
    confirmed={'oid':mapping['oid'],'remote_oid':remote};validate_check_binding(mapping,result,confirmed,commit_inventory(checkout,mapping['oid'],env))
    run(['git','verify-commit',mapping['oid']],env,checkout)
    native=json.loads(run([args.gh.resolve(),'api',endpoint+'/'+str(pr)],api_env))
    revised=dict(prepared,commits=[mapping['oid']]);validate_revision(config,revised,pr,native)
    save(attempt/'confirmed.json',confirmed);save(attempt/'publication.json',{'pr':pr,'oid':remote})
    body={'context':'fixture/verify','state':'success','description':'Independent Ladyshell verifier passed on these exact file bytes'}
    save(attempt/'status.intent.json',{'oid':remote,'body':body,'manifest_sha256':result['manifest_sha256']})
    save(attempt/'status-body.json',body)
    response=json.loads(run([args.gh.resolve(),'api',f"repos/{config['owner']}/{config['repository']}/statuses/{remote}",'--method','POST','--input',attempt/'status-body.json'],api_env))
    if response.get('state')!='success' or response.get('context')!='fixture/verify' or response.get('creator',{}).get('login')!=config['expected_actor']:raise RuntimeError('CI snapshot status outcome uncertain')
    save(attempt/'status.ok.json',response)
    return {'pr':pr,'oid':remote,'round':number,'repository_ci':'not inferred from snapshot status'}


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('prepare','publish'))
    for name in ('root','config','agents','jj','adapter','ladyshell','gh'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--branch',default='agent/ci-v1/verify');p.add_argument('--expected-base',required=True)
    p.add_argument('--round',type=int,choices=(1,2),default=1)
    args=p.parse_args();print(json.dumps(prepare(args) if args.operation=='prepare' else publish(args)))

if __name__=='__main__':main()
