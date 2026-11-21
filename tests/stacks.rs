use ladyshell::stacks;
use serde_json::json;
use std::{path::Path, process::Command};
// Child process creation briefly inherits other threads' flock descriptors
// until exec closes CLOEXEC fds. Keep Git fixtures separate while testing the
// actual retained-lock exclusion inside each fixture.
static GIT_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn git(p: &Path, a: &[&str]) -> Result<String> {
    let o = Command::new("git").arg("-C").arg(p).args(a).output()?;
    if !o.status.success() {
        return Err(String::from_utf8(o.stderr)?.into());
    }
    Ok(String::from_utf8(o.stdout)?.trim().into())
}
fn receipt(state: &Path, project: &Path, base: &str, head: &str) -> Result {
    ladyshell::state::create_directory(state)?;
    std::fs::write(
        state.join("publication.json"),
        serde_json::to_vec(
            &json!({"schema_version":2,"phase":"published","project":project,"base":base,"commit":head,"confirmed":true}),
        )?,
    )?;
    Ok(())
}
#[test]
fn parent_rewrite_invalidates_descendants_and_cycles_are_refused() -> Result {
    let _fixture = GIT_FIXTURE.lock().map_err(|_| "Fixture lock poisoned")?;
    let t = tempfile::tempdir()?;
    let repo = t.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("a"), "base")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let base = git(&repo, &["rev-parse", "HEAD"])?;
    std::fs::write(repo.join("a"), "parent")?;
    git(&repo, &["commit", "-am", "parent"])?;
    let parent = git(&repo, &["rev-parse", "HEAD"])?;
    std::fs::write(repo.join("b"), "child")?;
    git(&repo, &["add", "b"])?;
    git(&repo, &["commit", "-m", "child"])?;
    let child = git(&repo, &["rev-parse", "HEAD"])?;
    let p = t.path().join("parent");
    let c = t.path().join("child");
    let stack = t.path().join("stack");
    receipt(&p, &repo, &base, &parent)?;
    receipt(&c, &repo, &parent, &child)?;
    stacks::record(&stack, &p, None)?;
    stacks::record(&stack, &c, Some(&p))?;
    assert_eq!(stacks::status(&stack)?["ready"], true);
    assert!(stacks::record(&stack, &p, Some(&c)).is_err());
    receipt(&p, &repo, &parent, &child)?;
    assert_eq!(stacks::status(&stack)?["ready"], false);
    let result = stacks::status(&stack)?;
    assert_eq!(result["entries"][1]["stale_parent"], true);
    Ok(())
}
#[test]
fn restack_combines_disjoint_changes_and_refuses_real_conflict() -> Result {
    let _fixture = GIT_FIXTURE.lock().map_err(|_| "Fixture lock poisoned")?;
    for (conflict, root_source) in [(false, false), (true, false), (false, true)] {
        let t = tempfile::tempdir()?;
        let repo = t.path().join("repo");
        std::fs::create_dir(&repo)?;
        git(&repo, &["init", "-b", "main"])?;
        git(&repo, &["config", "user.name", "Fixture"])?;
        git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
        std::fs::write(repo.join("a"), "base")?;
        git(&repo, &["add", "."])?;
        git(&repo, &["commit", "-m", "base"])?;
        let base = git(&repo, &["rev-parse", "HEAD"])?;
        std::fs::write(repo.join("a"), "parent")?;
        git(&repo, &["commit", "-am", "parent"])?;
        let parent = git(&repo, &["rev-parse", "HEAD"])?;
        git(&repo, &["branch", "parent"])?;
        std::fs::write(repo.join("b"), "child")?;
        git(&repo, &["add", "b"])?;
        git(&repo, &["commit", "-m", "child"])?;
        let child = git(&repo, &["rev-parse", "HEAD"])?;
        let p = t.path().join("parent");
        let c = t.path().join("child");
        let stack = t.path().join("stack");
        receipt(&p, &repo, &base, &parent)?;
        receipt(&c, &repo, &parent, &child)?;
        stacks::record(&stack, &p, None)?;
        stacks::record(&stack, &c, if root_source { None } else { Some(&p) })?;
        std::fs::write(
            c.join("state.json"),
            serde_json::to_vec(
                &json!({"schema_version":2,"sandbox_name":"old-agent","sandbox_id":"old-agent","owner":"fixture","policy_hash":"fixture","codex_binary":"fixture","desired_hash":"fixture","image_id":"fixture","project_snapshot":repo,"build_dir":t.path(),"context":{"gateway":"fixture","workspace":"default"}}),
            )?,
        )?;
        git(&repo, &["checkout", "parent"])?;
        std::fs::write(repo.join(if conflict { "b" } else { "c" }), "parent update")?;
        git(&repo, &["add", "."])?;
        git(&repo, &["commit", "-m", "parent update"])?;
        let advanced = git(&repo, &["rev-parse", "HEAD"])?;
        receipt(&p, &repo, &parent, &advanced)?;
        let sentinel = t.path().join("filter-executed");
        let trap = t.path().join("filter-trap");
        std::fs::write(
            &trap,
            format!(
                "#!/bin/sh\nprintf executed > '{}'\ncat\n",
                sentinel.display()
            ),
        )?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&trap, std::fs::Permissions::from_mode(0o700))?;
        // Attributes live in host config so both the existing and newly created
        // worktree would select this executable filter during ordinary checkout.
        let attributes = t.path().join("attributes");
        std::fs::write(&attributes, "* filter=trap\n")?;
        git(
            &repo,
            &[
                "config",
                "core.attributesFile",
                attributes.to_str().ok_or("attributes")?,
            ],
        )?;
        for suffix in ["smudge", "process", "clean"] {
            git(
                &repo,
                &[
                    "config",
                    &format!("filter.trap.{suffix}"),
                    trap.to_str().ok_or("trap")?,
                ],
            )?;
        }
        let candidate = if root_source {
            stacks::restack_onto(&stack, &c, Some(&p))
        } else {
            stacks::restack(&stack, &c)
        };
        assert!(!sentinel.exists());
        if conflict {
            assert!(candidate.is_err());
            assert_eq!(git(&repo, &["rev-parse", "HEAD"])?, advanced);
        } else {
            let r = candidate?;
            let candidate_state =
                Path::new(r["candidate"]["state"].as_str().ok_or("candidate state")?);
            let candidate_lock = ladyshell::state::StateLock::acquire(candidate_state)?;
            let guards = stacks::guard(candidate_state)?;
            assert!(!guards.is_empty());
            drop(guards);
            drop(candidate_lock);
            let export = Path::new(r["export"].as_str().ok_or("export")?);
            assert_eq!(std::fs::read_to_string(export.join("project/a"))?, "parent");
            assert_eq!(std::fs::read_to_string(export.join("project/b"))?, "child");
            assert_eq!(
                std::fs::read_to_string(export.join("project/c"))?,
                "parent update"
            );
            assert_eq!(r["requires_new_review"], true);
            assert_eq!(r["requires_checks"], true);
        }
    }
    Ok(())
}
#[test]
fn retained_parent_guards_block_advancement_and_reject_transitive_staleness_and_cycles() -> Result {
    let _fixture = GIT_FIXTURE.lock().map_err(|_| "Fixture lock poisoned")?;
    let t = tempfile::tempdir()?;
    let repo = t.path().join("repo");
    std::fs::create_dir(&repo)?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Fixture"])?;
    git(&repo, &["config", "user.email", "fixture@example.invalid"])?;
    std::fs::write(repo.join("a"), "base")?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-m", "base"])?;
    let base = git(&repo, &["rev-parse", "HEAD"])?;
    let mut heads = Vec::new();
    for n in 0..4 {
        std::fs::write(repo.join("a"), format!("{n}"))?;
        git(&repo, &["commit", "-am", "advance"])?;
        heads.push(git(&repo, &["rev-parse", "HEAD"])?);
    }
    let p = t.path().join("parent");
    let c = t.path().join("child");
    let g = t.path().join("grandchild");
    let stack = t.path().join("stack");
    receipt(&p, &repo, &base, &heads[0])?;
    receipt(&c, &repo, &heads[0], &heads[1])?;
    receipt(&g, &repo, &heads[1], &heads[2])?;
    stacks::record(&stack, &p, None)?;
    stacks::record(&stack, &c, Some(&p))?;
    stacks::record(&stack, &g, Some(&c))?;
    let child_lock = ladyshell::state::StateLock::acquire(&g)?;
    let guards = stacks::guard(&g)?;
    assert_eq!(guards.len(), 2);
    assert!(std::thread::scope(|scope| scope
        .spawn(|| ladyshell::state::StateLock::acquire(&p).is_err())
        .join())
    .map_err(|_| "Parent lock assertion thread failed")?);
    assert!(ladyshell::state::StateLock::acquire(&c).is_err());
    drop(guards);
    receipt(&p, &repo, &heads[0], &heads[3])?;
    assert!(stacks::guard(&g).is_err());
    receipt(&p, &repo, &base, &heads[0])?;
    std::fs::write(
        p.join("stack-binding.json"),
        serde_json::to_vec(
            &json!({"schema_version":1,"stack":stack,"parent":g,"parent_head":heads[2]}),
        )?,
    )?;
    let error = stacks::guard(&g).err().ok_or("cycle admitted")?;
    assert!(error.to_string().contains("cycle"));
    drop(child_lock);
    Ok(())
}
