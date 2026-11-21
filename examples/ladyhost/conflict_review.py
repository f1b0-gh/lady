"""Compose host review metadata; Rust owns evidence and admission validation."""
from pathlib import Path
from agents import require, sha


def package(context, report, export, policy, tree):
    require(report.get('schema_version') == 2 and 'resolution' in report,
            'Conflict resolution requires a structured agent handoff')
    details = report['resolution']
    require(set(context['conflict_paths']) == {d['path'] for d in details['decisions']}
            and len(context['conflict_paths']) == len(details['decisions']),
            'Agent decisions do not cover the observed conflict paths')
    def artifact(path):
        path = Path(path).resolve()
        return {'path': str(path), 'sha256': sha(path)}
    return dict(schema_version=1, repository=context['repository'], target=context['target'],
                change_id=context['change_id'], original_base=context['original_base'],
                previous_head=context['previous_head'], upstream_head=context['upstream_head'],
                candidate_tree=tree, task_intent=context['task_intent'],
                upstream_intent=context['upstream_intent'], conflict_paths=context['conflict_paths'],
                decisions=details['decisions'], uncertainties=details['uncertainties'],
                manifest=artifact(export / 'manifest.json'), checks=artifact(export / 'checks.json'),
                policy=artifact(policy), independent_checks=context['independent_checks'])
