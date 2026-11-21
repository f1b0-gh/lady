"""Bound sandbox-authored review explanations to retained agent/export evidence.

This module renders scenario metadata. Agent statements grant no authority and
do not replace the Rust publication/integration boundary or native checks.
"""
import hashlib
import html
import json
from pathlib import Path

HANDOFF_DRIVER_HEADER = '# jjpr-handoff-schema: 1\n'

HANDOFF_INSTRUCTION = (
    ' End with one JSON object, without Markdown fences, containing exactly: '
    'schema_version (1), summary (why this change is useful), changes (an array '
    'of objects with behavior and example strings), tests_reported (an array of '
    'strings describing the checks you actually ran), and limitations (an array '
    'of known limits or untested cases). Explain your own contribution so a '
    'human can review it without reconstructing your reasoning from the diff. '
    'Do not claim host verification, signing, publication, approval or merging. '
    'Do not create a handoff file in the project; return it as your final response.'
)


RESOLUTION_INSTRUCTION = (
    HANDOFF_INSTRUCTION.replace('schema_version (1)', 'schema_version (2)').replace(
        'and limitations (an array', 'limitations (an array') +
    ' In schema 2 also include exactly one resolution object with decisions and '
    'uncertainties arrays. Each decision has exactly path, resolution (your choice '
    'and why), preserved (behavior strings), and changed (behavior/tradeoff strings). '
    'Cover every observed conflict path from the host context once. State what '
    'each competing change intended and how the combined behavior works. '
    'List untested combinations and remaining uncertainty honestly. Do not include '
    'independent_checks, host evidence, approval, or a readiness decision; the host supplies those.'
)


def _unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate handoff field')
        value[key]=item
    return value


def _text(value):
    if (not isinstance(value,str) or not value.strip() or len(value.encode())>8192
            or any(ord(c)<32 and c not in '\n\t' for c in value)
            or any(0x7f<=ord(c)<=0x9f for c in value)):
        raise ValueError('handoff text missing, oversized or contains controls')
    return value


def _strings(values):
    if not isinstance(values,list) or len(values)>16:
        raise ValueError('handoff list exceeds bound')
    for value in values:_text(value)


def extract_report(raw, legacy=False, resolution=False):
    if len(raw)>16*1024*1024:raise ValueError('agent event stream exceeds bound')
    last=None;completed=False
    for line in raw.decode('utf-8').splitlines():
        line=line.lstrip()
        if not line.startswith('{'):continue  # native run wrappers may add text
        event=json.loads(line,object_pairs_hook=_unique)
        if event.get('type') in ('turn.failed','error'):
            raise ValueError('agent turn failed; no completed explanation')
        if event.get('type')=='turn.started':last=None;completed=False
        if event.get('type')=='item.completed' and event.get('item',{}).get('type')=='agent_message':
            last=_text(event['item'].get('text'));completed=False
        if event.get('type')=='turn.completed':completed=True
    if last is None or not completed:raise ValueError('completed agent final report missing')
    try:report=json.loads(last,object_pairs_hook=_unique)
    except (ValueError,TypeError):
        if legacy and not last.lstrip().startswith('{'):
            return {'format':'legacy-agent-report','text':last}
        raise ValueError('agent final report must be structured JSON') from None
    required={'schema_version','summary','changes','tests_reported','limitations'}
    if resolution: required.add('resolution')
    if not isinstance(report,dict) or set(report)!=required or type(report['schema_version']) is not int or report['schema_version']!=(2 if resolution else 1):
        raise ValueError('unknown handoff fields or schema')
    _text(report['summary']);_strings(report['tests_reported']);_strings(report['limitations'])
    changes=report['changes']
    if not isinstance(changes,list) or not 1<=len(changes)<=16:
        raise ValueError('handoff requires bounded change explanations')
    for change in changes:
        if not isinstance(change,dict) or set(change)!={'behavior','example'}:
            raise ValueError('each change needs behavior and example')
        _text(change['behavior']);_text(change['example'])
    if resolution:
        details=report['resolution']
        if not isinstance(details,dict) or set(details)!={'decisions','uncertainties'}:
            raise ValueError('resolution needs decisions and uncertainty, not host evidence')
        _strings(details['uncertainties'])
        decisions=details['decisions']
        if not isinstance(decisions,list) or not 1<=len(decisions)<=64:
            raise ValueError('resolution requires bounded decisions')
        paths=set()
        for decision in decisions:
            if not isinstance(decision,dict) or set(decision)!={'path','resolution','preserved','changed'}:
                raise ValueError('invalid resolution decision fields')
            path=_text(decision['path'])
            if (path.startswith('/') or '\\' in path or any(ord(c)<32 for c in path)
                    or any(part in ('','.','..','.git','.jj') for part in path.split('/')) or path in paths):
                raise ValueError('invalid or duplicate resolution path')
            paths.add(path);_text(decision['resolution'])
            _strings(decision['preserved']);_strings(decision['changed'])
            if not decision['preserved'] and not decision['changed']:
                raise ValueError('resolution needs behavior context')
    return report


def retained_handoff(campaign, lane, number, result):
    directory=Path(campaign)/lane
    raw=(directory/f'round-{number}-agent.stdout').read_bytes()
    receipt_raw=(directory/f'round-{number}-agent.receipt.json').read_bytes()
    receipt_digest=hashlib.sha256(receipt_raw).hexdigest()
    anchors=[result.get('agent_receipt_sha256'),
             result.get('recovery',{}).get('original_driver_receipt_sha256')]
    for anchor in anchors:
        if anchor is not None and anchor!=receipt_digest:
            raise ValueError('retained agent receipt changed')
    receipt=json.loads(receipt_raw,object_pairs_hook=_unique)
    digest=hashlib.sha256(raw).hexdigest()
    if digest!=receipt['stdout_sha256']:
        raise ValueError('retained agent output changed')
    driver=directory/f'round-{number}-driver.py'
    driver_raw=driver.read_bytes()
    if hashlib.sha256(driver_raw).hexdigest()!=result['driver_sha256']:
        raise ValueError('retained agent driver changed')
    export=Path(result['export'])
    if hashlib.sha256((export/'manifest.json').read_bytes()).hexdigest()!=result['manifest_sha256']:
        raise ValueError('handoff export binding changed')
    schema=1 if driver_raw.startswith(HANDOFF_DRIVER_HEADER.encode()) else None
    declared=result.get('handoff_schema')
    if declared is not None and (type(declared) is not int or declared!=schema):
        raise ValueError('retained handoff schema disagrees with bound driver')
    report=extract_report(raw,legacy=schema is None)
    return {'report':report,'source_export':str(export),'source_manifest_sha256':result['manifest_sha256'],
            'source_output_sha256':digest,'source_driver_sha256':result['driver_sha256'],
            'source_receipt_sha256':receipt_digest,
            'receipt_binding':'result-anchored' if any(a is not None for a in anchors) else 'legacy receipt-only; no prior result anchor',
            'original_driver_exit_code':receipt['exit_code'],'authority':'agent-reported explanation only'}


def _quote(text):
    # Render untrusted prose as quoted data. No HTML markers, images, links or
    # account mentions from the agent become host-authored publishing controls.
    text=html.escape(_text(text),quote=False).replace('\\','\\\\')
    for character in ('[',']','!'):
        text=text.replace(character,'\\'+character)
    text=text.replace('@','@\u200b')
    return '\n'.join('> '+line for line in text.splitlines())


def render_review(reports, commands_per_snapshot):
    if not reports or len(reports)>16 or type(commands_per_snapshot) is not int or commands_per_snapshot<=0:
        raise ValueError('missing task reports or host check count')
    sections=['One task review covers the dependent commits below. The explanations come from the sandbox agents.',
              '## Agent-reported contributions',
              'Test claims in these reports describe the original agent runs; independent host verification is listed separately.']
    for index,report in enumerate(reports,1):
        sections.append(f'### Contribution {index}')
        if report.get('format')=='legacy-agent-report':
            sections.append(_quote(report['text']))
            continue
        sections.append(_quote(report['summary']))
        for change in report['changes']:
            sections.append(_quote(change['behavior']+'\nExample: '+change['example']))
        sections.append('Agent-reported tests:\n'+_quote('\n'.join(report['tests_reported']) or 'None reported.'))
        sections.append('Agent-reported limits:\n'+_quote('\n'.join(report['limitations']) or 'None reported; this does not establish absence of limitations.'))
    sections.extend(['## Host verification',
        f'Each of the {len(reports)} composed snapshots passed {commands_per_snapshot} host-selected commands in a separate native Ladyshell verifier. These include unit discovery and independent behavior assertions on the current combined files. The verifier instances were deleted. The host signs the commits and verifies that their trees match those checked snapshots.',
        'The host-reported `fixture/verify` status is separate from repository CI. One native human approval binds the final task head; the host integration path preserves the signed history.'])
    return '\n\n'.join(sections)+'\n'
