use crate::{
    environment_lock,
    error::{ensure, Error, Result},
    files, nickel,
    openshell::Backend,
    plan,
    request::Desired,
    scan, sources, state,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
pub fn lock_path(args: &Desired) -> PathBuf {
    args.lock.clone().unwrap_or_else(|| {
        args.config
            .with_extension(format!("{}.lock.json", args.mission))
    })
}
pub fn desired(args: &Desired) -> Result<Value> {
    let project = files::absolute(&args.project)?;
    files::open_directory(&project)?;
    let directory = files::absolute(&args.state)?;
    ensure!(
        !directory.starts_with(&project),
        "State must reside outside the project"
    );
    let resources = files::absolute(&args.resources)?;
    let evaluated = nickel::evaluate(&args.config, &args.mission, &resources)?;
    let mut receipt = environment_lock::create(
        evaluated.clone(),
        &resources,
        &args.codex,
        &args.codex_code_mode_host,
    )?;
    let source_files = sources::snapshot(&project, &evaluated.config.sources, None)?;
    let report = scan::scan(&project, &source_files, &evaluated.config)?;
    let (inventory, digest) = crate::deps::input::verified_report(
        &project,
        &evaluated.config.sources,
        &source_files,
        args.ladybom.as_deref(),
    )?;
    receipt.ladybom_sha256 = digest;
    environment_lock::verify(&lock_path(args), &receipt)?;
    let preparation = evaluated
        .config
        .dependencies
        .as_ref()
        .map(|config| {
            crate::deps::prepare::plan(&project, &source_files, config, &evaluated.config.tools)
        })
        .transpose()?;
    let runtime = std::env::current_exe()?;
    let mut artifacts = serde_json::Map::new();
    for (name, path) in [
        ("codex", &args.codex),
        ("codex-code-mode-host", &args.codex_code_mode_host),
        ("ladyshell", &runtime),
    ] {
        let path = files::absolute(path)?;
        let sha256 = if name == "ladyshell" {
            environment_lock::artifact_hash(&path)?
        } else {
            receipt
                .artifacts_sha256
                .get(name)
                .cloned()
                .ok_or_else(|| invalid("Missing artifact digest".into()))?
        };
        artifacts.insert(name.into(), json!({"path":path,"sha256":sha256}));
    }
    Ok(
        json!({"schema_version":2,"context":{"gateway":evaluated.config.sandbox.gateway,"workspace":evaluated.config.sandbox.workspace},"evaluated":evaluated,"environment_lock":receipt,"project":project,"resources":resources,"sources":source_files,"dependency_scan":report,"dependency_inventory":inventory,"dependency_preparation":preparation,"artifacts":artifacts}),
    )
}
pub fn make_plan(args: &Desired) -> Result<Value> {
    let desired = desired(args)?;
    let lock = state::StateLock::acquire(&args.state)?;
    let current = state::load(&lock.directory)?;
    let backend = Backend::new(&desired["context"])?;
    let observed = backend.observe(current.as_ref())?;
    let result = plan::plan(&desired, current.as_ref(), &observed)?;
    environment_lock::atomic_json(&lock.directory.join("plan.json"), &result)?;
    environment_lock::atomic_json(
        &lock.directory.join("dependency-scan.json"),
        &desired["dependency_scan"],
    )?;
    Ok(result)
}
pub fn apply(args: &Desired) -> Result<Value> {
    let desired = desired(args)?;
    let lock = state::StateLock::acquire(&args.state)?;
    let _lease = state::SessionLock::acquire(&lock.directory, true)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    if let Some(current) = state::load(&lock.directory)? {
        ensure!(
            crate::continuous::host::session(&current)?.is_none(),
            "Use cs refresh/replace for a continuous sandbox"
        );
    }
    let backend = Backend::new(&desired["context"])?;
    crate::apply::apply_with(
        &desired,
        &lock.directory,
        &mut crate::apply::NativeDriver { backend },
    )
}
pub fn status(directory: &Path) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    let backend = Backend::new(&current["context"])?;
    Ok(json!({"state":current,"observed":backend.observe(Some(&current))?}))
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

pub fn sync(args: &crate::request::SyncArgs) -> Result<Value> {
    let selected = crate::associations::resolve(args.state.as_deref())?;
    let lock = state::StateLock::acquire(&selected.directory)?;
    let _lease = state::SessionLock::acquire(&lock.directory, false)?;
    crate::continuous::host::execution_directory(&lock.directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    if let Some(expected) = selected.expected {
        expected.verify(&current)?;
    }
    crate::continuous::native::admit(&current)?;
    if lock.directory.join("checkout-pending.json").try_exists()? {
        ensure!(
            !args.export,
            "Checkout application interrupted: run sync again or inspect with --dry-run"
        );
        let result = crate::checkout::run(&current, &lock.directory, args.applies())?;
        return Ok(result);
    }
    sync_locked(&current, &lock.directory, args, None)
}

pub(crate) fn sync_after(
    directory: &Path,
    expected: &Value,
    apply: bool,
    publication: Option<&crate::publish::Prepared>,
) -> Result<Value> {
    let lock = state::StateLock::acquire(directory)?;
    let current =
        state::load(&lock.directory)?.ok_or_else(|| invalid("State is missing".into()))?;
    for field in [
        "sandbox_id",
        "owner",
        "desired_hash",
        "context",
        "policy_hash",
        "continuous",
    ] {
        ensure!(
            current[field] == expected[field],
            "Session state changed: {field}"
        );
    }
    ensure!(
        current["desired_inputs"]["project"] == expected["desired_inputs"]["project"],
        "Session checkout binding changed"
    );
    crate::run::ensure_no_pending(&lock.directory)?;
    sync_locked(
        &current,
        &lock.directory,
        &crate::request::SyncArgs {
            state: Some(lock.directory.clone()),
            dry_run: false,
            apply,
            export: !apply,
            json: false,
        },
        publication,
    )
}

fn sync_locked(
    current: &Value,
    directory: &Path,
    args: &crate::request::SyncArgs,
    publication: Option<&crate::publish::Prepared>,
) -> Result<Value> {
    let backend = Backend::new(&current["context"])?;
    let next = crate::sync::sync(current, directory, &backend, true)?;
    if args.state.is_some() {
        crate::associations::register(directory)?;
    }
    if !args.export {
        if let Some(prepared) = publication {
            prepared.before_apply()?;
            if let Some(checks) = prepared.policy().and_then(|p| p.checks.as_ref()) {
                crate::publication_checks::verify(
                    &next,
                    directory,
                    Path::new(state::text(&next, "last_sync")?),
                    checks,
                )?;
            }
        }
        let mut report = crate::checkout::run(&next, directory, args.applies())?;
        if let Some(prepared) = publication {
            report["publication"] = prepared.publish(&report, directory)?;
        }
        Ok(report)
    } else {
        let export = Path::new(state::text(&next, "last_sync")?);
        let manifest = crate::json::parse(&files::read_limited(
            &export.join("manifest.json"),
            2 * 1024 * 1024,
        )?)?;
        Ok(
            json!({"export":export,"changes":manifest["changes"],"deletions":manifest["deletions"],"applied":false}),
        )
    }
}
