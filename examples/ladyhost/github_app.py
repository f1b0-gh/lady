#!/usr/bin/env python3
"""Prepare GitHub App registration and bind host configuration after installation.

Scenario orchestration only: Rust authenticates the App and validates its scope.
This command does not register an App or change repository protection settings.
"""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlencode

from github import run, save


def registration_url(name, owner, repository, workflow_write=False):
    parameters={
        'name':name,
        'description':'Host publisher for the isolated jjpr experiment; human approval stays separate.',
        'url':f'https://github.com/{owner}/{repository}',
        'public':'false',
        'request_oauth_on_install':'false',
        'webhook_active':'false',
        'contents':'write',
        'pull_requests':'write',
        'statuses':'write',
    }
    if workflow_write:parameters['workflows']='write'
    return 'https://github.com/settings/apps/new?'+urlencode(parameters)


def app_config(original, app_id, installation_id, slug, private_key, openssl, workflow_write=False):
    if original.get('provider')!='github' or original.get('endpoint')!='https://api.github.com':
        raise ValueError('select a GitHub host configuration')
    if not original.get('expected_repository_id') or app_id<=0 or installation_id<=0:
        raise ValueError('numeric repository, App and installation IDs are required')
    config={k:v for k,v in original.items() if k not in ('token_file','gh_cli','github_app','publication')}
    config['expected_actor']=slug+'[bot]'
    config['github_app']={'app_id':app_id,'installation_id':installation_id,'slug':slug,
                          'private_key':str(private_key),'openssl':str(openssl),'workflow_write':workflow_write}
    return config


def integration_rulesets(config, ci_check=None, ci_app_id=None):
    """Prepare the two independent policies for this disposable experiment base."""
    if config.get('provider')!='github' or config.get('endpoint')!='https://api.github.com':
        raise ValueError('select a GitHub host configuration')
    base=config.get('stack_base')
    if base!='app-experiment-base':
        raise ValueError('ruleset preparation is limited to app-experiment-base')
    app_id=config.get('github_app',{}).get('app_id')
    if type(app_id) is not int or app_id<=0:
        raise ValueError('numeric publisher App ID is required')
    checks=[{'context':'fixture/verify','integration_id':app_id}]
    if ci_check is not None or ci_app_id is not None:
        if (not isinstance(ci_check,str) or not ci_check or len(ci_check)>100 or ci_check=='fixture/verify'
                or not ci_check.isascii() or any(not (c.isalnum() or c in '-_/ .') for c in ci_check)
                or type(ci_app_id) is not int or ci_app_id<=0 or ci_app_id==app_id):
            raise ValueError('select a distinct CI context and numeric source App ID')
        checks.append({'context':ci_check,'integration_id':ci_app_id})
    def policy(name,rules,bypass):
        return {'name':name,'target':'branch','enforcement':'active',
                'conditions':{'ref_name':{'include':['refs/heads/'+base],'exclude':[]}},
                'bypass_actors':bypass,'rules':rules}
    update=policy('jjpr-host-updates',
                  [{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}],
                  [{'actor_id':app_id,'actor_type':'Integration','bypass_mode':'always'}])
    quality=policy('jjpr-reviewed-signed-commits',[
        {'type':kind} for kind in ('deletion','non_fast_forward','required_linear_history','required_signatures')
    ]+[
        {'type':'pull_request','parameters':{
            'required_approving_review_count':1,'dismiss_stale_reviews_on_push':True,
            'require_code_owner_review':False,'require_last_push_approval':False,
            'required_review_thread_resolution':True}},
        {'type':'required_status_checks','parameters':{
            'required_status_checks':checks,
            'strict_required_status_checks_policy':True,'do_not_enforce_on_create':False}},
    ],[])
    return update,quality


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='operation',required=True)
    prepare=sub.add_parser('prepare')
    prepare.add_argument('--config',type=Path,required=True)
    prepare.add_argument('--output',type=Path,required=True)
    prepare.add_argument('--name',required=True)
    prepare.add_argument('--workflow-write',action='store_true',help='Include Workflows write for CI setup')
    rules=sub.add_parser('rulesets',help='Generate JSON for owner import; no remote mutation')
    rules.add_argument('--config',type=Path,required=True)
    rules.add_argument('--output',type=Path,required=True,help='New directory for the two import files')
    rules.add_argument('--ci-check',help='Required CI context observed on the selected repository')
    rules.add_argument('--ci-app-id',type=int,help='Native source App ID of that CI check')
    bind=sub.add_parser('bind')
    bind.add_argument('--config',type=Path,required=True)
    bind.add_argument('--output',type=Path,required=True)
    bind.add_argument('--app-id',type=int,required=True)
    bind.add_argument('--installation-id',type=int,required=True)
    bind.add_argument('--slug',required=True)
    bind.add_argument('--private-key',type=Path,required=True)
    bind.add_argument('--openssl',type=Path,default=Path('/usr/bin/openssl'))
    bind.add_argument('--adapter',type=Path,required=True)
    bind.add_argument('--workflow-write',action='store_true',help='Explicit workflow setup token scope; omitted for ordinary publication')
    args=parser.parse_args()
    original=json.loads(args.config.read_text())
    if args.operation=='prepare':
        url=registration_url(args.name,original['owner'],original['repository'],args.workflow_write)
        permissions={'contents':'write','pull_requests':'write','statuses':'write'}
        if args.workflow_write:permissions['workflows']='write'
        save(args.output,{'registration_url':url,'install_only_on':original['owner']+'/'+original['repository'],
                          'requested_permissions':permissions,
                          'registration_completed':False})
        print(url)
    elif args.operation=='rulesets':
        policies=integration_rulesets(original,args.ci_check,args.ci_app_id)
        args.output.mkdir(mode=0o700)
        paths=[]
        for policy in policies:
            path=args.output/(policy['name']+'.json')
            save(path,policy)
            paths.append(str(path.resolve()))
        print(json.dumps({'import_files':paths,'installed':False}))
    else:
        config=app_config(original,args.app_id,args.installation_id,args.slug,args.private_key.resolve(),args.openssl.resolve(),args.workflow_write)
        # Reject destinations within either existing or proposed exported workspace.
        if args.output.resolve().is_relative_to(Path(config['workspace']).resolve()):
            raise ValueError('host configuration must remain outside project')
        proposed=args.output.with_name(args.output.name+'.proposed')
        save(proposed,config)
        env={k:v for k,v in os.environ.items() if k not in ('GH_TOKEN','GITHUB_TOKEN','GH_ENTERPRISE_TOKEN','GITHUB_ENTERPRISE_TOKEN')}
        result=json.loads(run([args.adapter.resolve(),'preflight',proposed.resolve()],env))
        save(args.output,config)
        save(args.output.with_name(args.output.name+'.verified.json'),result)
        print(json.dumps({'config':str(args.output),'preflight':result}))


if __name__=='__main__':main()
