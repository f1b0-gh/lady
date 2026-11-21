//! Explicit project checks in an exact-push workflow, without third-party actions.
use super::*;

pub fn render(spec: &Spec) -> Result<String> {
    spec.validate()?;
    ensure!(
        !spec.adopt_workflow,
        "An adopted workflow must not be regenerated"
    );
    let commands =
        serde_json::to_string(&serde_json::to_string(&serde_json::to_vec(&spec.checks)?)?)?;
    let replacements = [
        ("__TARGET__", serde_json::to_string(&spec.target)?),
        ("__CHECK_NAME__", serde_json::to_string(&spec.ci_check)?),
        ("__CHECKS__", commands),
    ];
    let mut slots = Vec::new();
    for (marker, value) in replacements {
        slots.push((
            TEMPLATE
                .find(marker)
                .context("Workflow template slot missing")?,
            marker.len(),
            value,
        ));
    }
    slots.sort_by_key(|slot| slot.0);
    let mut output = String::new();
    let mut cursor = 0;
    for (offset, length, value) in slots {
        output.push_str(&TEMPLATE[cursor..offset]);
        output.push_str(&value);
        cursor = offset + length;
    }
    output.push_str(&TEMPLATE[cursor..]);
    Ok(output)
}
const TEMPLATE: &str = r#"name: Ladyhost project checks

on:
  push:
    branches: ['agent/**', 'ladyhost/**', __TARGET__]

permissions:
  contents: read

jobs:
  verify:
    name: __CHECK_NAME__
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - name: Fetch the exact pushed source
        env:
          CANDIDATE_SHA: ${{ github.sha }}
          SOURCE_REPOSITORY: ${{ github.repository }}
          READ_TOKEN: ${{ github.token }}
        run: |
          git init .
          git config core.hooksPath /dev/null
          git remote add origin "https://github.com/${SOURCE_REPOSITORY}.git"
          export GIT_CONFIG_COUNT=1
          export GIT_CONFIG_KEY_0=http.https://github.com/.extraheader
          export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$READ_TOKEN" | base64 -w0)"
          git fetch --no-tags --depth=1 origin "$CANDIDATE_SHA"
          unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 READ_TOKEN
          git checkout --detach FETCH_HEAD
          test "$(git rev-parse HEAD)" = "$CANDIDATE_SHA"
      - name: Run selected project checks
        env:
          LADYHOST_CHECKS: __CHECKS__
        run: |
          python3 - <<'PY'
          import json, os, subprocess
          commands = json.loads(bytes(json.loads(os.environ['LADYHOST_CHECKS'])))
          if not commands:
              raise SystemExit('No project checks selected')
          for command in commands:
              subprocess.run(command, check=True)
          PY
"#;
