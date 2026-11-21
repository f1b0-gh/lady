#!/usr/bin/env python3
"""Post fixture/verify for an exact, independently checked published export.

This is host scenario orchestration, not a GitHub Actions job or human review.
Retain intent before the status mutation; an unknown outcome is not replayed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from agents import LANES, inventory
from github import run, save
from publish import commit_inventory, publication_names


def validate_check_binding(mapping, result, confirmed, tree):
    for field in ('export','manifest_sha256','files'):
        if mapping.get(field)!=result.get(field):
            raise RuntimeError('check result differs from published export')
    if tree!=mapping['files']:
        raise RuntimeError('published tree differs from checked export')
    if not mapping.get('oid') or confirmed.get('oid')!=mapping['oid'] or confirmed.get('remote_oid')!=mapping['oid']:
        raise RuntimeError('publication is not confirmed for this commit')
    checks=result['checks']
    native_policy=checks.get('policy_sha256')
    if not checks.get('passed') or not checks.get('cleanup_confirmed') or not isinstance(native_policy,str) or len(native_policy)!=64 or any(c not in '0123456789abcdef' for c in native_policy):
        raise RuntimeError('missing exact successful check policy result')


def validate_policy_file(result, raw):
    # Native checks hash the Rust policy representation; the driver separately
    # retains the original policy file hash. These digests have different inputs.
    if hashlib.sha256(raw).hexdigest()!=result['host_check_policy_sha256']:
        raise RuntimeError('host check policy file changed')


def validate_source_round(mapping, number, restacked):
    if mapping.get('round')!=number:
        raise RuntimeError('check round differs from publication')
    if restacked:
        if mapping.get('source_round')!=number:
            raise RuntimeError('restacked publication lacks original check round')
        for key in ('previous_oid','target_oid'):
            oid=mapping.get(key,'')
            if len(oid)!=40 or any(c not in '0123456789abcdef' for c in oid):
                raise RuntimeError('restacked publication lacks exact prior and target OIDs')


def app_password(output):
    fields={}
    for line in output.splitlines():
        if not line:continue
        key,separator,value=line.partition('=')
        if not separator or key in fields:
            raise RuntimeError('invalid host App credential response')
        fields[key]=value
    if set(fields)!= {'username','password'} or fields['username']!='x-access-token' or not fields['password']:
        raise RuntimeError('invalid host App credential response')
    return fields['password']


def post(args):
    state=args.state.resolve()
    checkout_name,output_name,_=publication_names(args.lane,args.publication_id)
    checkout=state/checkout_name
    selected=getattr(args,'attempt',None)
    if selected:
        # Keep this local import out of the module cycle: restack uses check binding.
        from restack import attempt_name
        selected=attempt_name(selected)
    attempt=state/output_name/(selected or f'round-{args.round}')
    mapping=json.loads((attempt/'mapping.json').read_text())
    validate_source_round(mapping,args.round,bool(selected))
    confirmed=json.loads((attempt/'confirmed.json').read_text())
    result=json.loads((args.agents/args.lane/f'round-{args.round}-result.json').read_text())
    config=json.loads((attempt/'config.json').read_text())
    env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','JJ_')) and k not in ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')}
    env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',GH_HOST='github.com')
    run([args.adapter.resolve(),'preflight',attempt/'config.json'],env)
    validate_check_binding(mapping,result,confirmed,commit_inventory(checkout,mapping['oid'],env))
    validate_policy_file(result,(args.agents/args.lane/f'round-{args.round}-checks.json').read_bytes())
    export=Path(mapping['export'])
    if hashlib.sha256((export/'manifest.json').read_bytes()).hexdigest()!=mapping['manifest_sha256'] or inventory(export/'project')!=mapping['files']:
        raise RuntimeError('retained export changed')
    if json.loads((export/'checks.json').read_text())!=result['checks']:
        raise RuntimeError('retained check receipt changed')
    run(['git','verify-commit',mapping['oid']],env,checkout)
    if config.get('github_app'):
        request=f"protocol=https\nhost=github.com\npath={config['owner']}/{config['repository']}.git\n\n"
        response=subprocess.run([str(args.adapter.resolve()),'credential',str(attempt/'config.json'),'get'],input=request,text=True,capture_output=True,env=env,timeout=180)
        if response.returncode:
            raise RuntimeError('host App credential unavailable; no output disclosed')
        env['GH_TOKEN']=app_password(response.stdout)
    elif config.get('gh_cli')!=str(args.gh.resolve()):
        raise RuntimeError('GitHub CLI differs from selected host authentication')
    endpoint=f"repos/{config['owner']}/{config['repository']}/statuses/{mapping['oid']}"
    body={'context':'fixture/verify','state':'success','description':'Independent Ladyshell verifier passed on these exact file bytes'}
    # A prior intent, even without an acknowledgement, requires reconciliation.
    save(attempt/'status.intent.json',{'oid':mapping['oid'],'body':body,'manifest_sha256':mapping['manifest_sha256'],
                                     'host_policy_file_sha256':result['host_check_policy_sha256'],
                                     'native_policy_sha256':result['checks']['policy_sha256'],'actor':config['expected_actor']})
    body_path=attempt/'status-body.json'
    save(body_path,body)
    response=json.loads(run([args.gh.resolve(),'api','--hostname','github.com',endpoint,'--method','POST','--input',body_path],env))
    if response.get('state')!='success' or response.get('context')!='fixture/verify' or not response.get('id') or response.get('creator',{}).get('login','').lower()!=config['expected_actor'].lower():
        raise RuntimeError('status outcome uncertain; retain intent and reconcile')
    save(attempt/'status.ok.json',response)
    return {'oid':mapping['oid'],'context':'fixture/verify','status_id':response['id']}


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--agents',type=Path,required=True)
    parser.add_argument('--lane',choices=tuple(LANES),required=True)
    parser.add_argument('--round',type=int,choices=(1,2),required=True)
    parser.add_argument('--publication-id')
    parser.add_argument('--attempt',help='Explicit restack attempt; --round selects its retained check inputs')
    parser.add_argument('--adapter',type=Path,required=True)
    parser.add_argument('--gh',type=Path,required=True,help='Host CLI executable; App mode supplies its own token without a user login')
    print(json.dumps(post(parser.parse_args())))


if __name__=='__main__':main()
