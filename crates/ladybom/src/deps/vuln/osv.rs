//! Bounded OSV validation and local version matching. Original records remain JSON values.
use super::{instant, invalid, MatchResult, MatchStatus, Snapshot, MAX_INPUT_BYTES, MAX_RECORDS};
use crate::error::Result;
use packageurl::PackageUrl;
use serde::Serialize;
use serde_json::{Map, Value};
use std::{collections::BTreeSet, io::Write};

const MAX_ARRAY: usize = 10_000;
const MAX_DEPTH: usize = 64;
const MAX_LABEL: usize = 4096;

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| invalid("Objet OSV attendu".into()))
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(format!("Chaîne OSV obligatoire invalide : {key}")))
}

fn optional_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>> {
    object
        .get(key)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid(format!("Chaîne OSV attendue : {key}")))
        })
        .transpose()
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value]> {
    match object.get(key) {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| invalid(format!("Tableau OSV attendu : {key}"))),
    }
}

fn label(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_LABEL || value.chars().any(char::is_control) {
        return Err(invalid(
            "Identité ou version OSV invalide ou trop longue".into(),
        ));
    }
    Ok(())
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":_.-".contains(&byte))
    {
        return Err(invalid("Identifiant OSV invalide".into()));
    }
    Ok(())
}

// Check unknown extension data too, without recursive traversal or an unbounded output buffer.
fn bounded_shape(value: &Value) -> Result<()> {
    let mut pending = vec![(value, 0)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(invalid("Imbrication OSV excessive".into()));
        }
        match value {
            Value::Array(values) => {
                if values.len() > MAX_ARRAY {
                    return Err(invalid("Tableau OSV supérieur à 10000 éléments".into()));
                }
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                if values.len() > MAX_ARRAY {
                    return Err(invalid("Objet OSV excessif".into()));
                }
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    Ok(())
}

struct SizeLimit(usize);
impl Write for SizeLimit {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_INPUT_BYTES.saturating_sub(self.0) {
            return Err(std::io::Error::other("Limite JSON de 64 Mio dépassée"));
        }
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_size(value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(SizeLimit(0), value)?;
    Ok(())
}

fn extension_objects(object: &Map<String, Value>) -> Result<()> {
    for key in ["database_specific", "ecosystem_specific"] {
        if let Some(value) = object.get(key) {
            self::object(value)?;
        }
    }
    Ok(())
}

fn severity(object: &Map<String, Value>) -> Result<()> {
    for entry in array(object, "severity")? {
        let entry = self::object(entry)?;
        text(entry, "type")?;
        text(entry, "score")?;
        optional_text(entry, "source")?;
    }
    Ok(())
}

/// Validate known OSV 1.x fields while preserving all extension fields as evidence.
pub fn validate_record(record: &Value) -> Result<()> {
    bounded_shape(record)?;
    bounded_size(record)?;
    let record = object(record)?;
    identifier(text(record, "id")?)?;
    if let Some(version) = optional_text(record, "schema_version")? {
        let version = version
            .parse::<semver::Version>()
            .map_err(|_| invalid("Version de schéma OSV invalide".into()))?;
        if version.major != 1 {
            return Err(invalid("Version majeure OSV non prise en charge".into()));
        }
    }
    instant(text(record, "modified")?)?;
    // OSV's effective publication/withdrawal dates are independent from the
    // last edit timestamp. RustSec exports may publish at noon after an edit.
    // Snapshot validation still rejects any timestamp after collection.
    for key in ["published", "withdrawn"] {
        if let Some(value) = optional_text(record, key)? {
            instant(value)?;
        }
    }
    for key in ["summary", "details"] {
        optional_text(record, key)?;
    }
    for key in ["aliases", "related", "upstream"] {
        for value in array(record, key)? {
            identifier(
                value
                    .as_str()
                    .ok_or_else(|| invalid("Identifiant OSV attendu".into()))?,
            )?;
        }
    }
    extension_objects(record)?;
    severity(record)?;
    for reference in array(record, "references")? {
        let reference = object(reference)?;
        text(reference, "type")?;
        text(reference, "url")?;
    }
    for credit in array(record, "credits")? {
        let credit = object(credit)?;
        text(credit, "name")?;
        optional_text(credit, "type")?;
        for contact in array(credit, "contact")? {
            if !contact.is_string() {
                return Err(invalid("Contact OSV invalide".into()));
            }
        }
    }
    for affected in array(record, "affected")? {
        let affected = object(affected)?;
        let package = object(
            affected
                .get("package")
                .ok_or_else(|| invalid("Paquet OSV absent".into()))?,
        )?;
        label(text(package, "ecosystem")?)?;
        label(text(package, "name")?)?;
        if let Some(purl) = optional_text(package, "purl")? {
            label(purl)?;
            purl.parse::<PackageUrl>()
                .map_err(|_| invalid("PURL OSV invalide".into()))?;
        }
        extension_objects(affected)?;
        severity(affected)?;
        for version in array(affected, "versions")? {
            label(
                version
                    .as_str()
                    .ok_or_else(|| invalid("Version OSV invalide".into()))?,
            )?;
        }
        for range in array(affected, "ranges")? {
            validate_range(range)?;
        }
    }
    Ok(())
}

fn validate_range(range: &Value) -> Result<()> {
    let range = object(range)?;
    let kind = text(range, "type")?;
    optional_text(range, "repo")?;
    if kind == "GIT" {
        label(text(range, "repo")?)?;
    }
    extension_objects(range)?;
    let mut introduced = false;
    let mut fixed = false;
    let mut last_affected = false;
    for event in array(range, "events")? {
        let event = object(event)?;
        let keys: Vec<_> = ["introduced", "fixed", "last_affected", "limit"]
            .into_iter()
            .filter(|key| event.contains_key(*key))
            .collect();
        if keys.len() != 1 {
            return Err(invalid(
                "Un événement OSV doit porter une seule borne".into(),
            ));
        }
        let key = keys[0];
        let value = text(event, key)?;
        label(value)?;
        introduced |= key == "introduced";
        fixed |= key == "fixed";
        last_affected |= key == "last_affected";
        if kind == "SEMVER"
            && !(key == "introduced" && value == "0" || key == "limit" && value.contains('*'))
            && parse_version("SEMVER", value).is_none()
        {
            return Err(invalid("Borne SEMVER OSV invalide".into()));
        }
    }
    if !introduced || fixed && last_affected {
        return Err(invalid(
            "Plage OSV sans introduction ou mélangeant fixed et last_affected".into(),
        ));
    }
    Ok(())
}

/// Validate snapshot provenance and limits; completeness is an explicit separate assertion.
pub fn validate_snapshot(snapshot: &Snapshot) -> Result<()> {
    if snapshot.schema_version != 1 {
        return Err(invalid(
            "Version d'instantané OSV non prise en charge".into(),
        ));
    }
    label(&snapshot.source)?;
    let fetched_at = instant(&snapshot.fetched_at)?;
    let ecosystems: BTreeSet<_> = snapshot.ecosystems.iter().collect();
    if ecosystems.is_empty()
        || ecosystems.len() != snapshot.ecosystems.len()
        || ecosystems.len() > 3
        || ecosystems
            .iter()
            .any(|ecosystem| !matches!(ecosystem.as_str(), "crates.io" | "npm" | "PyPI"))
    {
        return Err(invalid(
            "Écosystèmes d'instantané OSV invalides, absents ou dupliqués".into(),
        ));
    }
    if snapshot.advisories.len() > MAX_RECORDS {
        return Err(invalid("Trop d'avis OSV dans l'instantané".into()));
    }
    let mut ids = BTreeSet::new();
    for record in &snapshot.advisories {
        validate_record(record)?;
        for key in ["modified", "published", "withdrawn"] {
            if optional_text(object(record)?, key)?
                .map(instant)
                .transpose()?
                .is_some_and(|date| date > fetched_at)
            {
                return Err(invalid(
                    "Avis OSV postérieur à la date de collecte de l'instantané".into(),
                ));
            }
        }
        if !ids.insert(text(object(record)?, "id")?) {
            return Err(invalid("Identifiant OSV dupliqué dans l'instantané".into()));
        }
    }
    bounded_size(snapshot)?;
    Ok(())
}

/// PyPI folds case and consecutive '.', '-' and '_'; npm and crates.io are exact.
pub fn normalize_package(ecosystem: &str, name: &str) -> String {
    if ecosystem != "PyPI" {
        return name.to_owned();
    }
    let mut result = String::with_capacity(name.len());
    let mut separator = false;
    for character in name.chars() {
        if matches!(character, '.' | '-' | '_') {
            if !separator {
                result.push('-');
            }
            separator = true;
        } else {
            result.push(character.to_ascii_lowercase());
            separator = false;
        }
    }
    result
}

fn purl_key(purl: &PackageUrl<'_>) -> Option<(String, String)> {
    let ecosystem = match purl.ty() {
        "cargo" => "crates.io",
        "npm" => "npm",
        "pypi" => "PyPI",
        _ => return None,
    };
    let name = match purl.namespace() {
        Some(namespace) => format!("{namespace}/{}", purl.name()),
        None => purl.name().to_owned(),
    };
    Some((ecosystem.to_owned(), normalize_package(ecosystem, &name)))
}

/// Index both identities of a contradictory PURL so assessment cannot silently omit it.
pub fn index_keys(record: &Value) -> Vec<(String, String)> {
    let mut result = BTreeSet::new();
    if let Some(affected) = record.get("affected").and_then(Value::as_array) {
        for entry in affected {
            if let Some(package) = entry.get("package") {
                if let (Some(ecosystem), Some(name)) = (
                    package.get("ecosystem").and_then(Value::as_str),
                    package.get("name").and_then(Value::as_str),
                ) {
                    result.insert((ecosystem.to_owned(), normalize_package(ecosystem, name)));
                }
                if let Some(purl) = package
                    .get("purl")
                    .and_then(Value::as_str)
                    .and_then(|value| value.parse::<PackageUrl>().ok())
                {
                    if let Some(key) = purl_key(&purl) {
                        result.insert(key);
                    }
                }
            }
        }
    }
    result.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Version {
    Semver(semver::Version),
    Python(pep440_rs::Version),
}

fn parse_version(ordering: &str, value: &str) -> Option<Version> {
    match ordering {
        "SEMVER" | "crates.io" | "npm" => {
            value.parse::<semver::Version>().ok().map(|mut version| {
                version.build = semver::BuildMetadata::EMPTY;
                Version::Semver(version)
            })
        }
        "PyPI" => value.parse().ok().map(Version::Python),
        _ => None,
    }
}

pub(super) fn supported_version(ecosystem: &str, value: &str) -> bool {
    parse_version(ecosystem, value).is_some()
}

fn ordering<'a>(kind: &'a str, ecosystem: &'a str) -> Option<&'a str> {
    match kind {
        "SEMVER" => Some("SEMVER"),
        "ECOSYSTEM" if matches!(ecosystem, "crates.io" | "npm" | "PyPI") => Some(ecosystem),
        _ => None,
    }
}

// None means the range cannot be evaluated locally, never a negative match.
fn included_in_range(
    range: &Map<String, Value>,
    ecosystem: &str,
    version: &str,
) -> Result<Option<bool>> {
    let Some(ordering) = ordering(text(range, "type")?, ecosystem) else {
        return Ok(None);
    };
    let Some(version) = parse_version(ordering, version) else {
        return Ok(None);
    };
    let mut events = Vec::new();
    let mut has_limits = false;
    let mut before_limits = false;
    for event in array(range, "events")? {
        let event = object(event)?;
        for kind in ["introduced", "fixed", "last_affected", "limit"] {
            let Some(raw) = optional_text(event, kind)? else {
                continue;
            };
            if kind == "limit" && raw.contains('*') {
                has_limits = true;
                before_limits = true;
                continue;
            }
            let bound = if kind == "introduced" && raw == "0" {
                None
            } else if let Some(bound) = parse_version(ordering, raw) {
                Some(bound)
            } else {
                return Ok(None);
            };
            if kind == "limit" {
                has_limits = true;
                before_limits |= bound.as_ref().is_some_and(|bound| version < *bound);
            } else {
                // An introduction sorts before a closing event at the same version.
                events.push((bound, u8::from(kind != "introduced"), kind));
            }
        }
    }
    if has_limits && !before_limits {
        return Ok(Some(false));
    }
    events.sort();
    let mut vulnerable = false;
    for (bound, _, kind) in events {
        let at_or_after = bound.as_ref().is_none_or(|bound| version >= *bound);
        match kind {
            "introduced" if at_or_after => vulnerable = true,
            "fixed" if at_or_after => vulnerable = false,
            "last_affected" if bound.as_ref().is_some_and(|bound| version > *bound) => {
                vulnerable = false
            }
            _ => {}
        }
    }
    Ok(Some(vulnerable))
}

fn limitation(result: &mut MatchResult, value: &str) {
    if result.status != Some(MatchStatus::Matched) {
        result.status = Some(MatchStatus::Unknown);
    }
    result.limitations.push(value.to_owned());
}

/// Match one advisory against a package version without any registry or Git access.
pub fn match_record(
    record: &Value,
    ecosystem: &str,
    name: &str,
    version: &str,
) -> Result<MatchResult> {
    validate_record(record)?;
    let record = object(record)?;
    let mut result = MatchResult::default();
    if record.contains_key("withdrawn") {
        return Ok(result);
    }
    let key = (ecosystem.to_owned(), normalize_package(ecosystem, name));
    for affected in array(record, "affected")? {
        let affected = object(affected)?;
        let package = object(&affected["package"])?;
        let declared_ecosystem = text(package, "ecosystem")?;
        let declared_name = normalize_package(declared_ecosystem, text(package, "name")?);
        let declared_key = (declared_ecosystem.to_owned(), declared_name.clone());
        let wildcard = declared_ecosystem == ecosystem && declared_name == "*";
        let purl = optional_text(package, "purl")?
            .map(|raw| {
                raw.parse::<PackageUrl>()
                    .map_err(|_| invalid("PURL OSV invalide".into()))
            })
            .transpose()?;
        let purl_identity = purl.as_ref().and_then(purl_key);
        if declared_key != key && !wildcard && purl_identity.as_ref() != Some(&key) {
            continue;
        }
        if purl.as_ref().is_some_and(|purl| {
            purl_identity.as_ref() != Some(&declared_key)
                || purl.version().is_some()
                || purl.subpath().is_some()
                || !purl.qualifiers().is_empty()
        }) {
            limitation(
                &mut result,
                "Identité PURL OSV contradictoire ou qualifiée non prise en charge",
            );
            continue;
        }
        let versions = array(affected, "versions")?;
        let ranges = array(affected, "ranges")?;
        if versions.is_empty() && ranges.is_empty() {
            limitation(&mut result, "Avis OSV sans versions ni plages évaluables");
        }
        if parse_version(ecosystem, version).is_none() {
            limitation(
                &mut result,
                "Version de composant non prise en charge pour cet écosystème",
            );
        }
        for candidate in versions {
            let candidate = candidate
                .as_str()
                .ok_or_else(|| invalid("Version OSV invalide".into()))?;
            if candidate == version {
                result.status = Some(MatchStatus::Matched);
            } else {
                match (
                    parse_version(ecosystem, version),
                    parse_version(ecosystem, candidate),
                ) {
                    (Some(version), Some(candidate)) if version == candidate => {
                        result.status = Some(MatchStatus::Matched)
                    }
                    (_, None) => {
                        limitation(&mut result, "Version énumérée OSV non prise en charge")
                    }
                    _ => {}
                }
            }
        }
        for range in ranges {
            let range = object(range)?;
            if text(range, "type")? != "GIT" {
                for event in array(range, "events")? {
                    if let Some(fixed) = optional_text(object(event)?, "fixed")? {
                        result.fixed_versions.push(fixed.to_owned());
                    }
                }
            }
            match included_in_range(range, ecosystem, version)? {
                Some(true) => result.status = Some(MatchStatus::Matched),
                Some(false) => {}
                None => limitation(
                    &mut result,
                    "Plage ou borne OSV non prise en charge localement",
                ),
            }
        }
    }
    result.fixed_versions.sort();
    result.fixed_versions.dedup();
    result.limitations.sort();
    result.limitations.dedup();
    Ok(result)
}
