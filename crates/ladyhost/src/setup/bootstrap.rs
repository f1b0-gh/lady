//! Signed workflow bootstrap. Existing protection is never bypassed by setup.
use super::*;
use crate::{Config, app, ci};
use anyhow::bail;
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

fn read_ref(api: &mut impl Api, spec: &Spec, branch: &str) -> Result<Option<String>> {
    let response = match api.get(&format!("{}/git/ref/heads/{branch}", spec.endpoint())) {
        Ok(value) => value,
        Err(error)
            if error
                .downcast_ref::<jjpr::forge::http::HttpError>()
                .is_some_and(|http| http.status == 409) =>
        {
            // GitHub's Git database returns 409 before the first commit exists.
            // Confirm absence independently; other conflicts remain failures.
            let branches = api
                .get(&format!("{}/branches?per_page=1", spec.endpoint()))?
                .context("Empty-repository branch inventory unavailable")?;
            ensure!(
                branches.as_array().is_some_and(Vec::is_empty),
                "Git ref conflict without an authenticated empty branch inventory"
            );
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let Some(value) = response else {
        return Ok(None);
    };
    ensure!(
        value["ref"] == format!("refs/heads/{branch}") && value["object"]["type"] == "commit",
        "Git ref identity differs"
    );
    let oid = value["object"]["sha"]
        .as_str()
        .context("Git ref SHA missing")?;
    ensure!(crate::integration::full_oid(oid), "Invalid Git ref SHA");
    Ok(Some(oid.to_owned()))
}
fn safe_write(root: &Path, relative: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parts: Vec<_> = relative.split('/').collect();
    let mut current = root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        ensure!(
            !part.is_empty() && *part != "." && *part != "..",
            "Invalid source path"
        );
        current.push(part);
        if index + 1 == parts.len() {
            // Exclusive creation rejects even a dangling symlink. Existing files
            // are compared by the caller; setup never overwrites project content.
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&current)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        } else {
            match fs::symlink_metadata(&current) {
                Ok(meta) => ensure!(meta.is_dir(), "Workflow parent is not a regular directory"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(&current)?,
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(())
}
pub fn prepare(store: &Store, api: &mut impl Api, operation: &str) -> Result<Value> {
    if let Some(value) = store.read("bootstrap.json")? {
        let workspace = store.root.join("bootstrap");
        let oid = value["head"].as_str().context("Bootstrap SHA missing")?;
        native::git(&workspace, &["verify-commit", oid])?;
        return Ok(value);
    }
    let target = read_ref(api, &store.spec, &store.spec.target)?;
    let base = if let Some(oid) = &target {
        oid.clone()
    } else {
        native::git(&store.spec.workspace,&["rev-parse","HEAD"])
        .context("An empty remote requires a local initial commit; commit the selected project source first")?
    };
    ensure!(
        crate::integration::full_oid(&base),
        "Source commit identity invalid"
    );
    let selected = json!({"base":base,"expected_target":target,"source":format!("ladyhost/setup/{operation}"),"workflow":store.spec.workflow_path});
    store.record("bootstrap.intent.json", &selected)?;
    let workspace = store.directory("bootstrap")?;
    if !workspace.join(".git").exists() {
        native::git(&workspace, &["init"])?;
    }
    let config_value = flow::config_value(store, &workspace, true)?;
    store.record("workflow-config.json", &config_value)?;
    let config: Config = serde_json::from_value(config_value)?;
    flow::configure_signing(store, &workspace)?;
    app::install_git_helper(&config, &store.root.join("workflow-config.json"))?;
    let url = format!(
        "https://github.com/{}/{}.git",
        config.owner, config.repository
    );
    native::git(
        &workspace,
        &["config", "--local", "remote.origin.url", &url],
    )?;
    if target.is_some() {
        native::git(&workspace, &["fetch", "--no-tags", "origin", &base])?;
    } else {
        native::git(
            &workspace,
            &[
                "fetch",
                "--no-tags",
                store
                    .spec
                    .workspace
                    .to_str()
                    .context("Workspace must be UTF-8")?,
                &base,
            ],
        )?;
    }
    native::git(&workspace, &["checkout", "--detach", &base])?;
    let path = &store.spec.workflow_path;
    if store.spec.adopt_workflow {
        let content = String::from_utf8(native::git_bytes(
            &workspace,
            &["show", &format!("{base}:{path}")],
        )?)?;
        store.record(
            "workflow.json",
            &json!({"path":path,"content":content,"owned":false}),
        )?;
    } else {
        let content = workflow::render(&store.spec)?;
        let file = workspace.join(path);
        let preexisting =
            native::git_bytes(&workspace, &["show", &format!("{base}:{path}")]).is_ok();
        if file.exists() {
            ensure!(
                fs::symlink_metadata(&file)?.is_file() && fs::read(&file)? == content.as_bytes(),
                "Selected workflow already exists with different content; use --adopt-workflow or choose another path"
            );
        } else {
            safe_write(&workspace, path, content.as_bytes())?;
        }
        store.record(
            "workflow.json",
            &json!({"path":path,"content":content,"owned":!preexisting}),
        )?;
        native::git(&workspace, &["add", "--", path])?;
    }
    // A signed empty commit is deliberate when adopting existing bytes: it
    // creates an exact push candidate and verifies the selected host signer.
    native::git(
        &workspace,
        &[
            "commit",
            "--allow-empty",
            "-m",
            "Configure Ladyhost project checks",
        ],
    )?;
    let head = native::git(&workspace, &["rev-parse", "HEAD"])?;
    native::git(&workspace, &["verify-commit", &head])?;
    ensure!(
        native::git(&workspace, &["rev-parse", &format!("{head}^")])? == base,
        "Bootstrap parent differs"
    );
    let mut result = selected;
    result["head"] = json!(head);
    store.record("bootstrap.json", &result)?;
    Ok(result)
}

/// A retained intent plus exact readback resolves a lost push reply. An
/// unchanged old ref after an uncertain call does not authorize blind replay.
pub fn push(
    store: &Store,
    api: &mut impl Api,
    label: &str,
    branch: &str,
    head: &str,
    expected: Option<&str>,
) -> Result<()> {
    ensure!(
        crate::identifier(label, false)
            && crate::integration::branch(branch)
            && crate::integration::full_oid(head),
        "Invalid push binding"
    );
    let before = read_ref(api, &store.spec, branch)?;
    let intent_name = format!("push-{label}.intent.json");
    let intent = json!({"branch":branch,"head":head,"expected":expected});
    let prior = store.read(&intent_name)?;
    if let Some(value) = &prior {
        ensure!(value == &intent, "Push intent differs");
    }
    if before.as_deref() == Some(head) {
        ensure!(
            prior.is_some(),
            "Ref already exists without matching publication intent"
        );
        store.record(&format!("push-{label}.confirmed.json"), &intent)?;
        return Ok(());
    }
    ensure!(
        before.as_deref() == expected,
        "Target moved; preserving remote changes"
    );
    ensure!(
        prior.is_none(),
        "Prior push remains uncertain; inspect remote state before a new attempt"
    );
    let workspace = store.root.join("bootstrap");
    if let Some(parent) = expected {
        native::git(&workspace, &["merge-base", "--is-ancestor", parent, head])?;
    }
    store.record(&intent_name, &intent)?;
    let lease = format!(
        "--force-with-lease=refs/heads/{branch}:{}",
        expected.unwrap_or("")
    );
    let refspec = format!("{head}:refs/heads/{branch}");
    let pushed = native::git(
        &workspace,
        &["push", "--porcelain", &lease, "origin", &refspec],
    );
    let observed = read_ref(api, &store.spec, branch)?;
    if observed.as_deref() == Some(head) {
        store.record(&format!("push-{label}.confirmed.json"), &intent)?;
        return Ok(());
    }
    if pushed.is_err() {
        bail!("Bootstrap push refused or uncertain; retained intent requires inspection");
    }
    bail!("Bootstrap push readback differs; outcome unknown")
}

pub fn observe_ci(
    store: &Store,
    config: &Config,
    client: &mut native::Client,
    candidate: &Value,
) -> Result<Option<Value>> {
    let head = candidate["head"]
        .as_str()
        .context("Candidate SHA missing")?;
    let source = candidate["source"]
        .as_str()
        .context("Candidate source missing")?;
    let app = client
        .get("/apps/github-actions")?
        .context("Native GitHub Actions identity unavailable")?;
    ensure!(
        app["slug"] == "github-actions",
        "CI provider identity differs"
    );
    let app_id = app["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .context("CI App ID missing")?;
    let requirement = ci::Requirement {
        check_name: store.spec.ci_check.clone(),
        app_id,
        workflow_path: store.spec.workflow_path.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match ci::inspect_candidate(config, head, source, &requirement, &mut client.0) {
            Ok(evidence) => {
                if store.read(&format!("ci-{head}.json"))?.is_none() {
                    store.record(
                        &format!("ci-{head}.json"),
                        &json!({"requirement":requirement,"evidence":evidence}),
                    )?;
                }
                store.record("ci.json", &json!({"requirement":requirement}))?;
                return Ok(Some(evidence));
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_secs(3)),
            Err(_) => return Ok(None),
        }
    }
}

pub fn integrate(
    store: &Store,
    owner: &mut impl Api,
    publisher: &mut impl Api,
    candidate: &Value,
) -> Result<Option<Value>> {
    let head = candidate["head"]
        .as_str()
        .context("Bootstrap SHA missing")?;
    let source = candidate["source"]
        .as_str()
        .context("Bootstrap source missing")?;
    let expected = candidate["expected_target"].as_str();
    let intent_name = "bootstrap-pr.intent.json";
    if store.read(intent_name)?.is_some() && store.read("bootstrap-pr.json")?.is_none() {
        let pulls = resources::list(
            publisher,
            &format!("{}/pulls?state=all", store.spec.endpoint()),
        )?;
        let matches: Vec<_> = pulls
            .into_iter()
            .filter(|v| {
                v["head"]["ref"] == source
                    && v["head"]["sha"] == head
                    && v["base"]["ref"] == store.spec.target
                    && v["user"]["login"] == format!("{}[bot]", store.spec.app_name)
            })
            .collect();
        ensure!(
            matches.len() == 1,
            "Bootstrap PR creation uncertain or ambiguous; no replay"
        );
        store.record("bootstrap-pr.json", &matches[0])?;
    }
    let current = read_ref(owner, &store.spec, &store.spec.target)?;
    if let Some(previous) = store.read("bootstrap-pr.json")? {
        let id = previous["number"]
            .as_u64()
            .context("Bootstrap PR number missing")?;
        let pr = owner
            .get(&format!("{}/pulls/{id}", store.spec.endpoint()))?
            .context("Bootstrap PR unavailable")?;
        ensure!(
            pr["head"]["ref"] == source
                && pr["head"]["sha"] == head
                && pr["base"]["ref"] == store.spec.target,
            "Bootstrap PR binding changed"
        );
        if pr["merged"] != true {
            return Ok(None);
        }
        // Existing policy owns its merge method. Verify the resulting workflow
        // bytes instead of claiming the original signed object was retained.
        let target = current.context("Merged target disappeared")?;
        native::git(&store.root.join("bootstrap"), &["fetch", "origin", &target])?;
        let expected_workflow = store
            .read("workflow.json")?
            .context("Workflow binding missing")?;
        let content = String::from_utf8(native::git_bytes(
            &store.root.join("bootstrap"),
            &["show", &format!("{}:{}", target, store.spec.workflow_path)],
        )?)?;
        ensure!(
            content
                == expected_workflow["content"]
                    .as_str()
                    .context("Workflow content missing")?,
            "Integrated workflow differs"
        );
        return Ok(Some(
            json!({"target":target,"method":"existing protected workflow","original_signed_object_preserved":target==head}),
        ));
    }
    if current.as_deref() == Some(head) && store.read("push-target.intent.json")?.is_some() {
        push(store, owner, "target", &store.spec.target, head, expected)?;
        return Ok(Some(
            json!({"target":head,"method":"exact signed fast-forward","original_signed_object_preserved":true}),
        ));
    }
    ensure!(
        current.as_deref() == expected,
        "Target changed before bootstrap integration"
    );
    let protected = if current.is_some() {
        owner
            .get(&format!(
                "{}/branches/{}",
                store.spec.endpoint(),
                store.spec.target
            ))?
            .context("Target branch metadata unavailable")?["protected"]
            .as_bool()
            .context("Protection evidence missing")?
    } else {
        let rules = owner.get(&format!(
            "{}/rules/branches/{}",
            store.spec.endpoint(),
            store.spec.target
        ))?;
        rules.is_some_and(|v| v.as_array().is_none_or(|r| !r.is_empty()))
    };
    if protected {
        let body = json!({"title":"Configure Ladyhost project checks","head":source,"base":store.spec.target,
            "body":"Signed host setup candidate. Review the selected project checks and integrate through this repository's existing protected process. Ladyhost does not bypass existing rules."});
        store.record(intent_name, &body)?;
        let pr = publisher.post(&format!("{}/pulls", store.spec.endpoint()), &body)?;
        ensure!(
            pr["number"].as_u64().is_some_and(|id| id > 0)
                && pr["head"]["sha"] == head
                && pr["head"]["ref"] == source
                && pr["base"]["ref"] == store.spec.target
                && pr["user"]["login"] == format!("{}[bot]", store.spec.app_name),
            "Created bootstrap PR differs"
        );
        store.record("bootstrap-pr.json", &pr)?;
        return Ok(None);
    }
    push(store, owner, "target", &store.spec.target, head, expected)?;
    Ok(Some(
        json!({"target":head,"method":"exact signed fast-forward","original_signed_object_preserved":true}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_repository_requires_conflict_status_and_authenticated_empty_branches() {
        struct Fake {
            status: u16,
            branches: Option<Value>,
            listed: bool,
        }
        impl Api for Fake {
            fn get(&mut self, path: &str) -> Result<Option<Value>> {
                if path.ends_with("/git/ref/heads/main") {
                    return Err(jjpr::forge::http::HttpError {
                        status: self.status,
                        method: "GET".into(),
                        path: path.into(),
                        body: "withheld".into(),
                    }
                    .into());
                }
                assert!(path.ends_with("/branches?per_page=1"));
                self.listed = true;
                Ok(self.branches.clone())
            }
            fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
                panic!("read-only")
            }
            fn delete(&mut self, _: &str) -> Result<()> {
                panic!("read-only")
            }
        }
        let spec: Spec = serde_json::from_value(json!({"schema_version":1,"repository":"owner/project","workspace":"/fixture","target":"main","app_name":"host","checks":[["true"]],"gh":"/bin/gh","jj":"/bin/jj"})).unwrap();
        let mut empty = Fake {
            status: 409,
            branches: Some(json!([])),
            listed: false,
        };
        assert_eq!(read_ref(&mut empty, &spec, "main").unwrap(), None);
        assert!(empty.listed);
        for branches in [None, Some(json!({})), Some(json!([{"name":"other"}]))] {
            assert!(
                read_ref(
                    &mut Fake {
                        status: 409,
                        branches,
                        listed: false
                    },
                    &spec,
                    "main"
                )
                .is_err()
            );
        }
        for status in [401, 403, 429, 500] {
            let mut rejected = Fake {
                status,
                branches: Some(json!([])),
                listed: false,
            };
            assert!(read_ref(&mut rejected, &spec, "main").is_err());
            assert!(!rejected.listed);
        }
    }

    #[test]
    fn lost_pr_reply_recovers_a_merged_pr_and_preserves_workflow_newline() {
        struct Fake {
            head: String,
            pr: Value,
            list: bool,
        }
        impl Api for Fake {
            fn get(&mut self, path: &str) -> Result<Option<Value>> {
                if path.contains("pulls?") {
                    assert!(path.contains("state=all&per_page"));
                    self.list = true;
                    return Ok(Some(json!([self.pr])));
                }
                if path.ends_with("pulls/7") {
                    return Ok(Some(self.pr.clone()));
                }
                assert!(path.ends_with("git/ref/heads/main"));
                Ok(Some(
                    json!({"ref":"refs/heads/main","object":{"type":"commit","sha":self.head}}),
                ))
            }
            fn post(&mut self, _: &str, _: &Value) -> Result<Value> {
                panic!("Must not recreate merged PR")
            }
            fn delete(&mut self, _: &str) -> Result<()> {
                panic!("No removal")
            }
        }
        let root = std::env::temp_dir().join(format!("ladyhost-merged-pr-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        native::git(&project, &["init"]).unwrap();
        native::git(&project, &["config", "user.name", "Fixture"]).unwrap();
        native::git(
            &project,
            &["config", "user.email", "fixture@example.invalid"],
        )
        .unwrap();
        fs::create_dir_all(project.join(".github/workflows")).unwrap();
        let content = "name: preserved newline\n";
        fs::write(project.join(".github/workflows/ladyhost.yml"), content).unwrap();
        native::git(&project, &["add", "."]).unwrap();
        native::git(&project, &["commit", "-m", "fixture"]).unwrap();
        let head = native::git(&project, &["rev-parse", "HEAD"]).unwrap();
        let spec:Spec=serde_json::from_value(json!({"schema_version":1,"repository":"owner/project","workspace":project,"target":"main","app_name":"host","checks":[["true"]],"gh":"/usr/bin/gh","jj":"/usr/bin/jj"})).unwrap();
        let store = Store::open(&root.join("state"), &spec).unwrap();
        let checkout = store.directory("bootstrap").unwrap();
        native::git(&checkout, &["init"]).unwrap();
        native::git(
            &checkout,
            &["remote", "add", "origin", project.to_str().unwrap()],
        )
        .unwrap();
        store
            .record("bootstrap-pr.intent.json", &json!({}))
            .unwrap();
        store
            .record("workflow.json", &json!({"content":content}))
            .unwrap();
        let pr = json!({"number":7,"head":{"ref":"ladyhost/setup/one","sha":head},"base":{"ref":"main"},"user":{"login":"host[bot]"},"merged":true});
        let mut owner = Fake {
            head: head.clone(),
            pr: pr.clone(),
            list: false,
        };
        let mut publisher = Fake {
            head: head.clone(),
            pr,
            list: false,
        };
        let result=integrate(&store,&mut owner,&mut publisher,&json!({"head":head,"source":"ladyhost/setup/one","expected_target":"1111111111111111111111111111111111111111"})).unwrap().unwrap();
        assert_eq!(result["target"], head);
        assert!(publisher.list);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn workflow_write_refuses_dangling_symlink_without_creating_target() {
        let root = std::env::temp_dir().join(format!("ladyhost-dangling-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let outside = root.with_extension("outside");
        std::os::unix::fs::symlink(&outside, root.join("workflow.yml")).unwrap();
        assert!(safe_write(&root, "workflow.yml", b"unsafe").is_err());
        assert!(!outside.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
