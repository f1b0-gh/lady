"""Registration preparation contains no credentials or remote mutations."""
import sys
from pathlib import Path
import unittest
from urllib.parse import parse_qs, urlparse

sys.path.insert(0,str(Path(__file__).parents[1]))
import github_app


class RegistrationTests(unittest.TestCase):
    def test_rules_keep_update_bypass_separate_from_review_and_signatures(self):
        config={'provider':'github','endpoint':'https://api.github.com',
                'stack_base':'app-experiment-base','github_app':{'app_id':5634658}}
        update,quality=github_app.integration_rulesets(config)
        for ruleset in (update,quality):
            self.assertEqual(ruleset['enforcement'],'active')
            self.assertEqual(ruleset['conditions']['ref_name'],
                             {'include':['refs/heads/app-experiment-base'],'exclude':[]})
        self.assertEqual(update['bypass_actors'],[{'actor_id':5634658,'actor_type':'Integration','bypass_mode':'always'}])
        self.assertEqual(update['rules'],[{'type':'update','parameters':{'update_allows_fetch_and_merge':False}}])
        self.assertEqual(quality['bypass_actors'],[])
        rules={rule['type']:rule.get('parameters') for rule in quality['rules']}
        self.assertTrue({'required_signatures','required_linear_history','deletion','non_fast_forward'}<=rules.keys())
        self.assertEqual(rules['pull_request']['required_approving_review_count'],1)
        self.assertTrue(rules['pull_request']['dismiss_stale_reviews_on_push'])
        self.assertTrue(rules['pull_request']['required_review_thread_resolution'])
        self.assertEqual(rules['required_status_checks']['required_status_checks'],
                         [{'context':'fixture/verify','integration_id':5634658}])
        for base in ('main','master','*','refs/heads/main','../base',''):
            with self.assertRaises(ValueError):
                github_app.integration_rulesets(dict(config,stack_base=base))

    def test_registration_selects_service_identity_and_only_required_permissions(self):
        url=github_app.registration_url('fixture-jjpr-host','owner','repo')
        parsed=urlparse(url)
        self.assertEqual(parsed.scheme,'https')
        self.assertEqual(parsed.netloc,'github.com')
        self.assertEqual(parsed.path,'/settings/apps/new')
        params=parse_qs(parsed.query)
        self.assertEqual({k:v for k,v in params.items() if v==['write']},
                         {'contents':['write'],'pull_requests':['write'],'statuses':['write']})
        self.assertEqual(params['public'],['false'])
        self.assertEqual(params['webhook_active'],['false'])
        self.assertEqual(params['request_oauth_on_install'],['false'])
        self.assertNotIn('administration',params)

    def test_app_config_does_not_inherit_personal_credentials_or_publication(self):
        original={'provider':'github','endpoint':'https://api.github.com','expected_actor':'owner',
                  'expected_repository_id':42,'owner':'owner','repository':'repo','workspace':'/host/project',
                  'gh_cli':'/host/gh','publication':{'task':'old'}}
        config=github_app.app_config(original,12,34,'fixture-host',Path('/host/app.pem'),Path('/usr/bin/openssl'))
        self.assertEqual(config['expected_actor'],'fixture-host[bot]')
        self.assertEqual(config['github_app']['app_id'],12)
        self.assertEqual(config['github_app']['installation_id'],34)
        self.assertEqual(config['expected_repository_id'],42)
        self.assertNotIn('gh_cli',config)
        self.assertNotIn('token_file',config)
        self.assertNotIn('publication',config)
        self.assertIn('gh_cli',original)
        for app_id,installation in ((0,34),(12,0),(-1,34)):
            with self.assertRaises(ValueError):
                github_app.app_config(original,app_id,installation,'fixture-host',Path('/host/app.pem'),Path('/usr/bin/openssl'))


    def test_workflow_scope_is_explicit_at_registration_and_token_binding(self):
        params=parse_qs(urlparse(github_app.registration_url('host','owner','repo',workflow_write=True)).query)
        self.assertEqual(params['workflows'],['write'])
        original={'provider':'github','endpoint':'https://api.github.com','expected_repository_id':42}
        ordinary=github_app.app_config(original,12,34,'host',Path('/host/key'),Path('/usr/bin/openssl'))
        setup=github_app.app_config(original,12,34,'host',Path('/host/key'),Path('/usr/bin/openssl'),workflow_write=True)
        self.assertFalse(ordinary['github_app'].get('workflow_write',False))
        self.assertTrue(setup['github_app']['workflow_write'])

    def test_ci_rules_bind_two_distinct_app_sources_without_extra_bypass(self):
        config={'provider':'github','endpoint':'https://api.github.com','stack_base':'app-experiment-base','github_app':{'app_id':123}}
        update,quality=github_app.integration_rulesets(config,ci_check='ci/verify',ci_app_id=456)
        rule=next(r for r in quality['rules'] if r['type']=='required_status_checks')
        self.assertEqual(rule['parameters']['required_status_checks'],[{'context':'fixture/verify','integration_id':123},{'context':'ci/verify','integration_id':456}])
        self.assertEqual(quality['bypass_actors'],[])
        for check,app in ((None,456),('ci/verify',None),('fixture/verify',456),('ci/verify',123),('ci/verify',True),('../bad?query',456)):
            with self.assertRaises(ValueError):github_app.integration_rulesets(config,ci_check=check,ci_app_id=app)

if __name__=='__main__':unittest.main()
