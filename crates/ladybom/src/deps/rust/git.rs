//! Static identity and source matching for locked Cargo Git packages.
//! This records Cargo's claim; it neither fetches nor authenticates the commit.
use crate::{
    deps::invalid,
    error::{ensure, Result},
};
use cargo_lock::SourceId;
use serde_json::Value;

// Use cargo-lock's URL parser without its GitReference normalization: that
// normalization conflates default/master and Display loses query encoding.
fn source_url(source: &str) -> Result<SourceId> {
    let url = source
        .strip_prefix("git+")
        .ok_or_else(|| invalid("Source Git Cargo requise".into()))?;
    let parsed = SourceId::from_url(&format!("registry+{url}"))
        .map_err(|_| invalid("URL de source Git Cargo invalide".into()))?;
    let mut pairs = parsed.url().query_pairs();
    let first = pairs.next();
    ensure!(
        pairs.next().is_none()
            && first.is_none_or(|(key, value)| {
                matches!(key.as_ref(), "branch" | "ref" | "tag" | "rev") && !value.is_empty()
            }),
        "Sélecteur de source Git Cargo ambigu ou non pris en charge"
    );
    Ok(parsed)
}

pub(super) fn validate_selector(source: &str) -> Result<()> {
    if source.starts_with("git+") {
        source_url(source)?;
    }
    Ok(())
}

fn locked_source(source: &str) -> Option<SourceId> {
    let source = source_url(source).ok()?;
    let url = source.url();
    let commit = url.fragment()?;
    (matches!(url.scheme(), "https" | "http" | "ssh" | "git")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && commit.len() == 40
        && commit.bytes().all(|b| b.is_ascii_hexdigit()))
    .then_some(source)
}

fn repository(source: &SourceId) -> String {
    let mut url = source.url().clone();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

pub(crate) fn purl(name: &str, version: &str, source: Option<&str>) -> Result<Option<String>> {
    let Some(source) = source.and_then(locked_source) else {
        return Ok(None);
    };
    let mut purl =
        packageurl::PackageUrl::new("cargo", name).map_err(|e| invalid(e.to_string()))?;
    purl.with_version(version)
        .map_err(|e| invalid(e.to_string()))?;
    purl.add_qualifier(
        "vcs_url",
        format!(
            "git+{}@{}",
            repository(&source),
            source.url().fragment().unwrap_or_default()
        ),
    )
    .map_err(|e| invalid(e.to_string()))?;
    Ok(Some(purl.to_string()))
}

// Used by static CycloneDX projection even when the optional graph feature is off.
pub(crate) fn validate_component(component: &crate::deps::Component) -> Result<()> {
    if component
        .source
        .as_str()
        .is_some_and(|s| s.starts_with("git+"))
        || component.metadata["source"]
            .as_str()
            .is_some_and(|s| s.starts_with("git+"))
        || component.purl.as_deref().is_some_and(|s| {
            s.parse::<packageurl::PackageUrl>()
                .is_ok_and(|p| p.qualifiers().contains_key("vcs_url"))
        })
    {
        ensure!(
            component.metadata["source"] == component.source,
            "Source Git divergente des métadonnées Cargo"
        );
        if let Some(identity) = &component.purl {
            ensure!(
                purl(
                    &component.name,
                    &component.version,
                    component.source.as_str()
                )?
                .as_ref()
                    == Some(identity),
                "PURL Git divergente de la source Cargo verrouillée"
            );
        }
    }
    Ok(())
}

fn selector(source: &SourceId) -> Option<(String, String)> {
    source.url().query_pairs().next().map(|(key, value)| {
        (
            (if key == "ref" { "branch" } else { &key }).into(),
            value.into_owned(),
        )
    })
}

// Keep unconditional: CycloneDX reuses the static graph projector without graph.
pub(crate) fn requirement_matches(requirement: &Value, source: &Value) -> bool {
    let Some(locked) = source.as_str().and_then(locked_source) else {
        return false;
    };
    let Some(repo) = requirement["git"].as_str() else {
        return false;
    };
    if ["path", "registry", "registry-index"]
        .iter()
        .any(|key| requirement.get(key).is_some())
    {
        return false;
    }
    let Ok(requested) = SourceId::from_url(&format!("registry+{repo}")) else {
        return false;
    };
    if requested.url().query().is_some()
        || requested.url().fragment().is_some()
        || requested.url().as_str() != repository(&locked)
    {
        return false;
    }
    let selectors: Vec<_> = ["branch", "tag", "rev"]
        .into_iter()
        .filter_map(|key| requirement.get(key).map(|value| (key, value)))
        .collect();
    let reference = match selectors.as_slice() {
        [] => None,
        [(key, Value::String(value))] if !value.is_empty() => Some(((*key).into(), value.clone())),
        _ => return false,
    };
    selector(&locked) == reference
}

// Keep unconditional: CycloneDX reuses the static graph projector without graph.
pub(crate) fn dependency_source_matches(actual: &Value, requested: &Value) -> bool {
    if actual == requested {
        return true;
    }
    let Some(actual) = actual.as_str().and_then(locked_source) else {
        return false;
    };
    let Some(requested) = requested.as_str().and_then(|s| source_url(s).ok()) else {
        return false;
    };
    if repository(&actual) != repository(&requested)
        || requested
            .url()
            .fragment()
            .is_some_and(|commit| Some(commit) != actual.url().fragment())
    {
        return false;
    }
    let actual_selector = selector(&actual);
    let requested_selector = selector(&requested);
    // Native dependency references may expand an abbreviated rev to the full
    // resolved commit; other selectors, including default/master, stay distinct.
    actual_selector == requested_selector
        || matches!((&actual_selector, &requested_selector), (Some((a, _)), Some((b, revision)))
            if a == "rev" && b == "rev" && Some(revision.as_str()) == actual.url().fragment())
}
