# Ladyhost scenarios

These drivers exercise publication, CI, restacking, conflicts, review and sandbox
iterations with synthetic projects. Product authority and durable control live
in [Ladyhost](../../crates/ladyhost/README.md) and
[Ladyshell](../../docs/usage.md); these Python scripts are test scenarios, not an
orchestration API. Keys, private state, exports and results stay outside sources.

## Offline regression checks

From the Lady repository root:

```sh
python3 -m unittest discover -s examples/ladyhost/scenario
JJPR_TEST_JJ=/absolute/path/to/pinned-jj \
  python3 -m unittest discover -s examples/ladyhost/scenario -p test_restack_conflict.py
```

Most checks use synthetic artifacts and fake process/forge boundaries. The real
jj history test skips unless `JJPR_TEST_JJ` selects a binary; a skip is not a
native history pass. These tests need no GitHub token or OpenShell gateway.

`pins.json` and `tool-locks/` retain tool provenance, including the amended GitHub
CLI module lock. They are not installers or current security advisory clearance.
Do not remove fixtures, schemas or locks as if they were disposable test outputs.

## Warm work and environment replacement

`continuous.py` checks that source-only changes retain a compatible sandbox and
that dependency changes replace it. Its embedded calculator seed is disposable.
Smoke mode checks checkpoint, refresh/context, replacement and owned cleanup.
Agents mode uses three tasks, nine bounded model turns, jj conflicts and two
signed iterations per task.

```sh
python3 examples/ladyhost/continuous.py --mode smoke \
  --state /absolute/private/new-cs-trial \
  --ladyshell /absolute/path/to/ladyshell --lady-source /absolute/path/to/lady \
  --codex /absolute/path/to/codex \
  --codex-code-mode-host /absolute/path/to/codex-code-mode-host
```

For agents mode, choose `--mode agents` and add `--jj /absolute/path/to/pinned-jj`.
Native paths are explicit. A compatible local Docker/OpenShell gateway, provider
and account routing must already be configured. The scenario's selected gateway
and provider must match that setup; do not broaden confinement to make it pass.
New runs require new private state directories. Failed runs retain evidence and
do not automatically restart model turns. Cleanup exports/deletes only owned
sandboxes; unrelated instances remain.

## Conflicting PRs and independent checks

`continuous_pr.py` exercises two overlapping changes to
`scenario/seed/metrics.py`: adding a starting value and improving summation.
Resolution must preserve both, including interaction checks such as
`total([1e16, 1, -1e16], start=2) == 3`.

This live fixture remains deliberately restricted to disposable
`f1b0-oss/jjpr-lab`, target `app-experiment-base`, and its retained App identity.
It is not generic project setup. Do not substitute credentials or loosen its
identity checks for another repository; use `ladyhost init` for new projects.

```sh
python3 examples/ladyhost/continuous_pr.py --help
```

Its explicit phases are `prepare`, `publish`, `resolve` and `cleanup_all`.
Preparation requires Ladyshell, jj, Codex, source root, seed checkout,
signing source and expected base. `--adapter` selects Lady's
`target/debug/ladyhost-jjpr` or the installed binary. A human provides native
GitHub approval; no scenario manufactures it. Unknown remote effects require
inspection before another attempt.

`handoff.py` and `conflict_review.py` compose scenario data; Rust verifies
inputs that carry authority. The host retains conflict observations, agent
choices, independent check receipts and canonical signed review text. Other
drivers cover staged PRs, restacking, combined tasks, CI and protected-target
races. Their explicit phases and scope guards remain part of the fixture.

## Qualification limits

Deterministic scenarios test refusal and recovery logic; they do not replay live
model/forge behavior. The conflict coverage campaign enumerates 300 parameterized
cases across eight states, not 300 distinct semantic scenarios. Synthetic verifier
receipts do not prove real independent execution or semantic correctness.

Historical live observations include a separate public fresh-project setup,
signed exact-candidate integration after native human approval, and warm/replaced
sandbox cleanup. Their private receipts are outside this source distribution.
They do not qualify private GitHub plans, other platforms, larger projects,
unattended merging or new conflict-package formats.

Keep maintained drivers, locks, fixtures and unique inputs. Before discarding
an experiment's generated outputs, retain a usable reproduction recipe and PDF
report outside the selected deletion. A source test pass is not a replay of the
historical experiment, and cleanup eligibility does not authorize deletion.
