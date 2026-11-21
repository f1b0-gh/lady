//! Reconcile bounded named resources without replaying uncertain mutations.
use super::*;
use anyhow::bail;

pub trait Api {
    /// None means an authenticated HTTP 404, never a network or permission error.
    fn get(&mut self, path: &str) -> Result<Option<Value>>;
    fn post(&mut self, path: &str, body: &Value) -> Result<Value>;
    fn delete(&mut self, path: &str) -> Result<()>;
}

pub fn list(api: &mut impl Api, collection: &str) -> Result<Vec<Value>> {
    let mut values = Vec::new();
    for page in 1..=10 {
        let response = api
            .get(&format!(
                "{collection}{}per_page=100&page={page}",
                if collection.contains('?') { "&" } else { "?" }
            ))?
            .context("Resource collection unavailable")?;
        let items = response
            .as_array()
            .context("Resource list response differs")?;
        ensure!(items.len() <= 100, "Resource page exceeds bound");
        values.extend(items.iter().cloned());
        if items.len() < 100 {
            return Ok(values);
        }
    }
    bail!("Resource inventory exceeds 1000 entries; outcome unknown")
}

pub fn policy_view(value: &Value) -> Result<Value> {
    let mut result = json!({});
    for field in [
        "name",
        "target",
        "enforcement",
        "conditions",
        "rules",
        "bypass_actors",
    ] {
        result[field] = value
            .get(field)
            .context("Full ruleset policy unavailable")?
            .clone();
    }
    // GitHub may materialize documented defaults on readback. Unknown fields
    // remain significant and therefore produce drift instead of being ignored.
    for rule in result["rules"].as_array_mut().context("Rules missing")? {
        if rule["type"] == "update"
            && rule["parameters"] == json!({"update_allows_fetch_and_merge":false})
        {
            rule.as_object_mut()
                .context("Rule object missing")?
                .remove("parameters");
        }
        if rule["type"] == "pull_request" {
            let parameters = rule["parameters"]
                .as_object_mut()
                .context("Review policy missing")?;
            parameters.entry("required_reviewers").or_insert(json!([]));
            parameters
                .entry("allowed_merge_methods")
                .or_insert(json!(["merge", "squash", "rebase"]));
            parameters
                .entry("require_extra_approval_for_unattributed_changes")
                .or_insert(json!(true));
        }
    }
    Ok(result)
}
fn matches(store: &Store, desired: &Value, observed: &Value) -> Result<()> {
    ensure!(
        observed["source"]
            .as_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(&store.spec.repository))
            && observed["source_type"] == "Repository",
        "Ruleset source differs"
    );
    ensure!(
        policy_view(observed)? == policy_view(desired)?,
        "Ruleset drift detected; preserving current resource"
    );
    Ok(())
}
fn operation(kind: &str) -> Result<()> {
    ensure!(matches!(kind, "update" | "quality"), "Unknown ruleset role");
    Ok(())
}

pub fn ensure_ruleset(
    store: &Store,
    kind: &str,
    desired: &Value,
    api: &mut impl Api,
) -> Result<u64> {
    operation(kind)?;
    let collection = format!("{}/rulesets", store.spec.endpoint());
    let intent_name = format!("rules-{kind}.intent.json");
    let confirmed_name = format!("rules-{kind}.confirmed.json");
    let intent = json!({"collection":collection,"policy":desired});
    if let Some(confirmed) = store.read(&confirmed_name)? {
        ensure!(
            confirmed["intent"] == intent,
            "Confirmed rule binding differs"
        );
        let id = confirmed["id"].as_u64().context("Ruleset ID missing")?;
        let observed = api
            .get(&format!("{collection}/{id}"))?
            .context("Owned ruleset disappeared; do not recreate blindly")?;
        matches(store, desired, &observed)?;
        return Ok(id);
    }
    let prior = store.read(&intent_name)?;
    if let Some(prior) = &prior {
        ensure!(prior == &intent, "Ruleset intent differs");
    }
    let candidates: Vec<_> = list(api, &collection)?
        .into_iter()
        .filter(|v| v["name"] == desired["name"])
        .collect();
    let id = if prior.is_some() {
        ensure!(
            candidates.len() == 1,
            "Prior create outcome unresolved or ambiguous; no creation replayed"
        );
        candidates[0]["id"]
            .as_u64()
            .context("Candidate ruleset ID missing")?
    } else {
        ensure!(
            candidates.is_empty(),
            "Rule name already exists without ownership evidence"
        );
        store.record(&intent_name, &intent)?;
        let response = api.post(&collection, desired).map_err(|_| {
            anyhow::anyhow!("Ruleset creation outcome uncertain; resume to inspect, not repeat")
        })?;
        response["id"]
            .as_u64()
            .context("Created ruleset ID missing; outcome uncertain")?
    };
    ensure!(id > 0, "Invalid ruleset ID");
    let observed = api
        .get(&format!("{collection}/{id}"))?
        .context("Created ruleset readback unavailable")?;
    matches(store, desired, &observed)?;
    store.record(
        &confirmed_name,
        &json!({"id":id,"intent":intent,"policy":policy_view(&observed)?}),
    )?;
    Ok(id)
}

pub fn remove_ruleset(
    store: &Store,
    kind: &str,
    desired: &Value,
    api: &mut impl Api,
) -> Result<()> {
    operation(kind)?;
    let Some(confirmed) = store.read(&format!("rules-{kind}.confirmed.json"))? else {
        return Ok(());
    };
    ensure!(
        confirmed["policy"] == policy_view(desired)?,
        "Owned rule binding differs"
    );
    let id = confirmed["id"]
        .as_u64()
        .context("Owned ruleset ID missing")?;
    let path = format!("{}/rulesets/{id}", store.spec.endpoint());
    let intent_name = format!("remove-{kind}.intent.json");
    let done_name = format!("remove-{kind}.confirmed.json");
    let intent = json!({"id":id,"path":path,"policy":policy_view(desired)?});
    if let Some(prior) = store.read(&intent_name)? {
        ensure!(prior == intent, "Removal intent differs");
    }
    match api.get(&path)? {
        None => {
            ensure!(
                store.read(&intent_name)?.is_some(),
                "Owned ruleset vanished before removal intent"
            );
            store.record(&done_name, &json!({"id":id,"absent":true}))?;
        }
        Some(value) => {
            matches(store, desired, &value)?;
            ensure!(
                store.read(&intent_name)?.is_none(),
                "Prior removal remains uncertain; delete not replayed"
            );
            store.record(&intent_name, &intent)?;
            api.delete(&path).map_err(|_| {
                anyhow::anyhow!("Ruleset removal outcome uncertain; resume to inspect")
            })?;
            ensure!(
                api.get(&path)?.is_none(),
                "Removed ruleset still present; outcome unknown"
            );
            store.record(&done_name, &json!({"id":id,"absent":true}))?;
        }
    }
    Ok(())
}
