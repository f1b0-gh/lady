//! Read-only planning. No project program or external runtime is invoked here.
use super::{config::AuditConfig, invalid, model::Profile, verify::check};
use crate::{config::Sources, error::Result, files, sources, state};
use serde_json::{json, Value};
use std::path::Path;

pub fn make(directory: &Path, profile: Option<Profile>, run_requested: bool) -> Result<Value> {
    // Unlike StateLock::acquire, this read-only path never creates a directory/lock.
    let current = state::load(directory)?
        .ok_or_else(|| invalid("État Ladyshell absent ; préparer un état natif avant l’audit"))?;
    let desired = &current["desired_inputs"];
    let mut config: AuditConfig=serde_json::from_value(desired.pointer("/evaluated/config/audit").filter(|v| !v.is_null()).ok_or_else(|| invalid("Configuration audit absente de l’état ; déclarer audit dans Nickel et réconcilier explicitement"))?.clone())?;
    if let Some(profile) = profile {
        config.profile = profile;
    }
    config.validate()?;
    let project = files::absolute(Path::new(state::text(desired, "project")?))?;
    let directory = files::absolute(directory)?;
    check(
        !directory.starts_with(&project),
        "État d’audit requis hors du projet",
    )?;
    let spec: Sources = serde_json::from_value(
        desired
            .pointer("/evaluated/config/sources")
            .ok_or_else(|| invalid("Périmètre source absent"))?
            .clone(),
    )?;
    let all = sources::snapshot(&project, &spec, None)?;
    let selected: sources::Snapshot = all
        .clone()
        .into_iter()
        .filter(|(path, _)| {
            config
                .scope_paths
                .iter()
                .any(|p| path == p || path.starts_with(&format!("{p}/")))
                && !config
                    .exclude_paths
                    .iter()
                    .any(|p| path == p || path.starts_with(&format!("{p}/")))
        })
        .collect();
    let mut blockers = Vec::new();
    if selected.is_empty() {
        blockers.push(json!({"code":"empty_scope","detail":"Aucun fichier sélectionné dans les sources autorisées"}));
    }
    if config.budget.invocations < 7 {
        blockers.push(json!({"code":"insufficient_budget","detail":"Méthode distribuée : quatre reconnaissances, une chasse, une critique et une vérification ; au moins sept invocations"}));
    }
    // Planning is pure. Only run may establish these live capabilities, using
    // a trusted synthetic command before any project command or model call.
    blockers.push(json!({"code":"runtime_preflight_required","detail":"Vérifier en direct identité, politique, provider, quotas, arrêt et nettoyage dans des ressources dédiées"}));
    if !desired["environment_lock"].is_object()
        || !desired["artifacts"].is_object()
        || !desired["resources"].is_string()
    {
        blockers.push(json!({"code":"native_state_incomplete","detail":"État natif verrouillé incomplet ; lock et apply explicites requis"}));
    }
    let inputs = json!({"config":config,"sources":selected,"source_snapshot":all,"state_sha256":crate::plan::digest(&current)?,"method_sha256":files::hash(include_bytes!("../../../../resources/audit/provenance.json"))});
    Ok(
        json!({"schema_version":1,"operation":if run_requested {"run"} else {"plan"},"blocked":true,"target_executed":false,"plan_sha256":crate::plan::digest(&inputs)?,"inputs":inputs,"budget_reserve":{"recon":4,"hunter":1,"critic":1,"verifier_minimum":1},"blockers":blockers}),
    )
}
