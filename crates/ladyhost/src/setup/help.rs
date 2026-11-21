//! Offline help is handled before configuration, credentials or project access.
use anyhow::{Result, bail};
pub fn command(name: &str) -> Result<&'static str> {
    Ok(match name {
        "init" => {
            r#"Usage: ladyhost init --repo OWNER/REPO --app-name SLUG --workspace PATH --target BRANCH --check JSON_ARGV --state PRIVATE_PATH [--apply]
       ladyhost init --spec FILE --state PRIVATE_PATH [--apply]
       ladyhost init --state PRIVATE_PATH --apply

Configure the App, signing, project CI and split review/update rules. The initial
command previews a plan; repeat it with --apply to create resources. Owner browser
consent is required. Resume with the same private state after each pending step.

Required: --state outside the actual project checkout; a repository selection
and project checks for a new setup, or --spec containing the same selections.
Options: --gh PATH --jj PATH --signing-key PATH --ci-check NAME --workflow-path PATH
         --adopt-workflow --json. Repeat --check for sequential argv commands.

Example:
  ladyhost init --repo owner/project --app-name owner-project-host --workspace /work/project --target main --check '["python3","-m","unittest","discover"]' --state /private/project-host

The publisher App receives no administration authority. Existing protection is
preserved; a protected target may require an ordinary setup PR review.
"#
        }
        "doctor" => {
            r#"Usage: ladyhost doctor --state PRIVATE_PATH [--json]
       ladyhost doctor --config FILE --integration FILE [--workflow FILE] [--json]

Inspect signing custody, App scope, workflow bytes, rules and effective protection.
This does not repair settings or authorize a PR merge. Network access is needed
for diagnostics, but never for help. Hidden full bypass rosters remain a limit.
The external form requires retained integration rules/CI selections; --workflow
is JSON containing path and exact content, not a YAML workflow file.

Example:
  ladyhost doctor --state /private/project-host --json

Exit codes: 0 healthy, 2 incomplete/unknown, 1 failed. Configuration drift and
missing automatic signing are reported; inspect before resuming initialization.
"#
        }
        "uninstall" => {
            r#"Usage: ladyhost uninstall --state PRIVATE_PATH [--apply] [--json]

Preview owned resources, then use --apply to revoke the installation and remove
only unchanged owned rules. History, PRs, branches, workflows and signing keys
are preserved. Global App registration deletion remains an owner browser step;
the command prints its URL and distinguishes it from installation removal.

Example:
  ladyhost uninstall --state /private/project-host
  ladyhost uninstall --state /private/project-host --apply

Retain state after an uncertain outcome. Rerun against that state to inspect
receipts; do not delete intent files to force another destructive request.
"#
        }
        "review-conflict" => {
            r#"Usage: ladyhost review-conflict --config FILE --candidate FULL_OID [--render] [--json]

Read the host-selected conflict_review package in CONFIG. Verify its retained
policy/check receipts against the exact candidate tree, both intents, resolution
choices and uncertainty. Default inspection requires its digest and complete
review text in the candidate commit. --render emits the review text for inclusion
before signing; it never publishes, approves or merges. Partial coverage and
failed checks may be shown for review, but cannot satisfy integration admission.

Example:
  ladyhost review-conflict --config /private/task/config.json --candidate 0123456789012345678901234567890123456789 --render

The package is host-composed from the observed conflict and structured agent
handoff. It stays outside the project. Human review and CI remain separate.
"#
        }
        _ => bail!("Unknown help topic; use init, doctor, uninstall or review-conflict"),
    })
}
