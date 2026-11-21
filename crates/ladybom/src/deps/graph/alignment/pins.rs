//! Direct declaration pin classification, independent of graph root resolution.
use crate::deps::{Report, Requirement};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinStatus {
    ExactVersion,
    Range,
    Unconstrained,
    SourceOverride,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct PinFinding {
    pub ecosystem: String,
    pub manifest: String,
    pub requirement: Requirement,
    pub status: PinStatus,
    pub pin: Option<String>,
    pub reason: Option<String>,
}

pub(super) fn audit_pins(report: &Report) -> Vec<PinFinding> {
    report
        .projects
        .iter()
        .flat_map(|project| {
            project.requirements.iter().map(move |requirement| {
                let (status, pin, reason) = classify(&project.ecosystem, requirement);
                PinFinding {
                    ecosystem: project.ecosystem.clone(),
                    manifest: project.manifest.clone(),
                    requirement: requirement.clone(),
                    status,
                    pin,
                    reason,
                }
            })
        })
        .collect()
}

type Classification = (PinStatus, Option<String>, Option<String>);

fn plain(status: PinStatus) -> Classification {
    (status, None, None)
}

fn exact(version: impl ToString) -> Classification {
    (PinStatus::ExactVersion, Some(version.to_string()), None)
}

fn unsupported(reason: impl Into<String>) -> Classification {
    (PinStatus::Unsupported, None, Some(reason.into()))
}

fn source_override() -> Classification {
    (
        PinStatus::SourceOverride,
        None,
        Some("La déclaration sélectionne une source spécifique, sans épinglage de version du registre".into()),
    )
}

fn classify(ecosystem: &str, requirement: &Requirement) -> Classification {
    if !matches!(ecosystem, "rust" | "npm" | "python") {
        return unsupported(format!(
            "Classification des épinglages indisponible pour {ecosystem}"
        ));
    }
    if requirement.kind.starts_with("group:") && requirement.kind.ends_with(":include") {
        return unsupported("L’inclusion d’un groupe ne déclare pas une version de paquet");
    }
    if let Some(classification) = classify_source(ecosystem, &requirement.source) {
        return classification;
    }
    let constraint = requirement.constraint.trim();
    match ecosystem {
        "rust" => cargo_pin(constraint),
        "npm" => npm_pin(constraint),
        "python" => python_pin(constraint),
        _ => unreachable!(),
    }
}

fn classify_source(ecosystem: &str, source: &Value) -> Option<Classification> {
    match source {
        Value::Null => None,
        Value::String(value) if ecosystem == "python" => Some(if value.trim().is_empty() {
            unsupported("Source directe Python vide")
        } else {
            source_override()
        }),
        Value::String(value) => {
            (ecosystem == "npm" && npm_source(value.trim())).then(source_override)
        }
        Value::Object(table) => {
            if table
                .get("version")
                .is_some_and(|version| !version.is_string())
            {
                return Some(unsupported(
                    "Le champ version de la déclaration doit être textuel",
                ));
            }
            let keys: &[&str] = match ecosystem {
                "rust" => &["path", "git", "registry", "registry-index"],
                "npm" => &["path", "git", "url", "registry"],
                "python" => &["path", "git", "url", "index", "registry"],
                _ => unreachable!(),
            };
            let mut selected = false;
            for key in keys {
                if let Some(value) = table.get(*key) {
                    if !value.as_str().is_some_and(|value| !value.trim().is_empty()) {
                        return Some(unsupported(format!("Sélecteur de source {key} invalide")));
                    }
                    selected = true;
                }
            }
            if let Some(workspace) = table.get("workspace") {
                if workspace != &Value::Bool(true) {
                    return Some(unsupported("Sélecteur de source workspace invalide"));
                }
                selected = true;
            }
            if selected {
                Some(source_override())
            } else if ecosystem == "python" {
                Some(unsupported("Table de source Python non reconnue"))
            } else {
                None
            }
        }
        Value::Array(sources) if ecosystem == "python" && !sources.is_empty() => {
            if sources.iter().all(|source| {
                source.is_object()
                    && matches!(
                        classify_source(ecosystem, source),
                        Some((PinStatus::SourceOverride, _, _))
                    )
            }) {
                Some(source_override())
            } else {
                Some(unsupported(
                    "Liste de sources conditionnelles Python invalide",
                ))
            }
        }
        _ => Some(unsupported("Format de source de déclaration non reconnu")),
    }
}

fn cargo_pin(constraint: &str) -> Classification {
    if constraint.is_empty() {
        return plain(PinStatus::Unconstrained);
    }
    let requirement = match semver::VersionReq::parse(constraint) {
        Ok(requirement) => requirement,
        Err(error) => {
            return unsupported(format!("Contrainte de version Cargo invalide : {error}"))
        }
    };
    if requirement.comparators.is_empty() {
        return plain(PinStatus::Unconstrained);
    }
    // A bare Cargo version is a caret range; partial equality is also a range.
    if let Some(version) = constraint.strip_prefix('=') {
        if let Ok(version) = semver::Version::parse(version.trim()) {
            return exact(version);
        }
    }
    plain(PinStatus::Range)
}

fn npm_source(constraint: &str) -> bool {
    [
        "workspace:",
        "file:",
        "link:",
        "http:",
        "https:",
        "git:",
        "git+",
        "git@",
        "ssh:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "./",
        "../",
        "/",
        "~/",
    ]
    .iter()
    .any(|prefix| constraint.starts_with(prefix))
        || (!constraint.contains(':')
            && !constraint.contains(char::is_whitespace)
            && constraint.split_once('/').is_some_and(|(owner, repo)| {
                !owner.is_empty() && !repo.is_empty() && !repo.contains('/')
            }))
}

fn npm_pin(constraint: &str) -> Classification {
    if let Some(alias) = constraint.strip_prefix("npm:") {
        let separator = if let Some(scoped_alias) = alias.strip_prefix('@') {
            scoped_alias.find('@').map(|index| index + 1)
        } else {
            alias.find('@')
        };
        let (name, version) = separator.map_or((alias, None), |index| {
            (&alias[..index], Some(&alias[index + 1..]))
        });
        let valid_part = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
        };
        let valid_name = if let Some(scoped) = name.strip_prefix('@') {
            scoped
                .split_once('/')
                .is_some_and(|(scope, name)| valid_part(scope) && valid_part(name))
        } else {
            valid_part(name)
        };
        if !valid_name || version.is_some_and(|version| version.trim().is_empty()) {
            return unsupported("Alias npm invalide");
        }
        return match version {
            None => plain(PinStatus::Unconstrained),
            Some(version) => npm_registry_pin(version.trim()),
        };
    }
    if npm_source(constraint) {
        return source_override();
    }
    npm_registry_pin(constraint)
}

fn npm_registry_pin(constraint: &str) -> Classification {
    if matches!(constraint, "" | "*" | "x" | "X") {
        return plain(PinStatus::Unconstrained);
    }
    let version = constraint.strip_prefix('=').unwrap_or(constraint).trim();
    let version = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version);
    if let Ok(version) = semver::Version::parse(version) {
        return exact(version);
    }
    match node_semver::Range::parse(constraint) {
        Ok(_) => plain(PinStatus::Range),
        Err(error) => unsupported(format!(
            "Sélecteur de version npm non pris en charge : {error}"
        )),
    }
}

fn python_pin(constraint: &str) -> Classification {
    if constraint.is_empty() {
        return plain(PinStatus::Unconstrained);
    }
    let specifiers = match constraint.parse::<pep440_rs::VersionSpecifiers>() {
        Ok(specifiers) => specifiers,
        Err(error) => {
            return unsupported(format!(
                "Spécificateur de version Python invalide : {error}"
            ))
        }
    };
    if specifiers
        .iter()
        .any(|specifier| *specifier.operator() == pep440_rs::Operator::ExactEqual)
    {
        return unsupported(
            "L’égalité arbitraire Python ne constitue pas un épinglage de version concret",
        );
    }
    if specifiers.len() == 1 && *specifiers[0].operator() == pep440_rs::Operator::Equal {
        return exact(specifiers[0].version());
    }
    plain(PinStatus::Range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Project;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    fn requirement(constraint: &str, source: Value) -> Requirement {
        Requirement {
            name: "example".into(),
            declared_name: None,
            constraint: constraint.into(),
            kind: "runtime".into(),
            marker: None,
            extras: Vec::new(),
            source,
        }
    }

    fn report(ecosystem: &str, requirements: Vec<Requirement>) -> Report {
        let mut project = Project::new(ecosystem, ecosystem, "project/manifest");
        project.requirements = requirements;
        Report {
            schema_version: 2,
            complete: false,
            inputs: BTreeMap::new(),
            projects: vec![project],
            diagnostics: Vec::new(),
        }
    }

    fn assert_classification(
        ecosystem: &str,
        constraint: &str,
        source: Value,
        status: PinStatus,
        pin: Option<&str>,
    ) {
        let findings = audit_pins(&report(ecosystem, vec![requirement(constraint, source)]));
        assert_eq!(findings.len(), 1, "{ecosystem}: {constraint}");
        assert_eq!(findings[0].status, status, "{ecosystem}: {constraint}");
        assert_eq!(findings[0].pin.as_deref(), pin, "{ecosystem}: {constraint}");
        if matches!(status, PinStatus::SourceOverride | PinStatus::Unsupported) {
            assert!(findings[0].reason.as_ref().is_some_and(|s| !s.is_empty()));
        }
    }

    // Catch treating Cargo's default caret requirements and partial equality as pins.
    #[test]
    fn cargo_requires_explicit_full_equality() {
        use PinStatus::*;
        for (constraint, status, pin) in [
            ("=1.2.3", ExactVersion, Some("1.2.3")),
            (
                " = 0.1.0-rc.1+build.4 ",
                ExactVersion,
                Some("0.1.0-rc.1+build.4"),
            ),
            ("1.2.3", Range, None),
            ("^1.2.3", Range, None),
            ("~1.2.3", Range, None),
            ("=1.2", Range, None),
            ("=1", Range, None),
            (">=1.2.3, <2", Range, None),
            ("=1.2.3, <2", Range, None),
            ("", Unconstrained, None),
            ("*", Unconstrained, None),
            ("=not-a-version", Unsupported, None),
            ("1.2.3 || 2.0.0", Unsupported, None),
        ] {
            assert_classification("rust", constraint, json!(constraint), status, pin);
        }
    }

    // Catch mistaking ordinary Cargo version/features/package tables for source overrides.
    #[test]
    fn cargo_distinguishes_version_tables_from_source_selection() {
        for source in [
            Value::Null,
            json!("=1.2.3"),
            json!({"version":"=1.2.3", "features":["derive"], "optional":true}),
            json!({"package":"actual-name", "version":"=1.2.3"}),
        ] {
            assert_classification(
                "rust",
                "=1.2.3",
                source,
                PinStatus::ExactVersion,
                Some("1.2.3"),
            );
        }
        for source in [
            json!({"path":"../local", "version":"=1.2.3"}),
            json!({"git":"https://example.invalid/repo", "rev":"0123456789abcdef0123456789abcdef01234567"}),
            json!({"git":"https://example.invalid/repo", "branch":"main"}),
            json!({"git":"https://example.invalid/repo", "tag":"v1.2.3"}),
            json!({"registry":"private", "version":"=1.2.3"}),
        ] {
            assert_classification("rust", "=1.2.3", source, PinStatus::SourceOverride, None);
        }
        assert_classification(
            "rust",
            "=1.2.3",
            json!({"path":null}),
            PinStatus::Unsupported,
            None,
        );
    }

    // Catch npm alias ranges or incomplete versions being reported as exact versions.
    #[test]
    fn npm_literal_versions_and_scoped_aliases_are_classified() {
        use PinStatus::*;
        for (constraint, status, pin) in [
            ("1.2.3", ExactVersion, Some("1.2.3")),
            ("=1.2.3", ExactVersion, Some("1.2.3")),
            (" v1.2.3 ", ExactVersion, Some("1.2.3")),
            (
                "1.2.3-rc.2+build.4",
                ExactVersion,
                Some("1.2.3-rc.2+build.4"),
            ),
            ("npm:actual-name@1.2.3", ExactVersion, Some("1.2.3")),
            ("npm:@scope/actual-name@1.2.3", ExactVersion, Some("1.2.3")),
            ("npm:@scope/actual-name@^1.2.3", Range, None),
            ("npm:actual-name", Unconstrained, None),
            ("npm:@scope/actual-name", Unconstrained, None),
            ("1.2", Range, None),
            ("^1.2.3", Range, None),
            ("~1.2.3", Range, None),
            ("1.2.3 || 2.0.0", Range, None),
            ("", Unconstrained, None),
            ("*", Unconstrained, None),
            ("latest", Unsupported, None),
            ("npm:@scope", Unsupported, None),
            ("npm:@scope/name@", Unsupported, None),
            ("npm:@scope/name@npm:other@1.2.3", Unsupported, None),
        ] {
            assert_classification("npm", constraint, Value::Null, status, pin);
        }
    }

    // Catch locations, branch/tag references and workspace selectors becoming immutable pins.
    #[test]
    fn npm_external_selectors_are_not_version_pins() {
        for constraint in [
            "workspace:*",
            "workspace:1.2.3",
            "file:../local",
            "link:../local",
            "./local",
            "../local",
            "/opt/local",
            "~/local",
            "https://example.invalid/archive-1.2.3.tgz",
            "git+https://example.invalid/repo#v1.2.3",
            "git://example.invalid/repo#main",
            "git@github.com:owner/repo.git#main",
            "github:owner/repo#v1.2.3",
            "owner/repo#v1.2.3",
        ] {
            assert_classification(
                "npm",
                constraint,
                Value::Null,
                PinStatus::SourceOverride,
                None,
            );
        }
        assert_classification(
            "npm",
            "catalog:default",
            Value::Null,
            PinStatus::Unsupported,
            None,
        );
        assert_classification(
            "npm",
            "1.2.3",
            json!({"path":"../local"}),
            PinStatus::SourceOverride,
            None,
        );
        assert_classification("npm", "1.2.3", json!(true), PinStatus::Unsupported, None);
    }

    // Catch PEP 440 wildcard/arbitrary equality and malformed specifiers being pinned.
    #[test]
    fn python_requires_one_concrete_pep440_equality() {
        use PinStatus::*;
        for (constraint, status, pin) in [
            ("==1.2.3", ExactVersion, Some("1.2.3")),
            (" == 1.2.3rc1 ", ExactVersion, Some("1.2.3rc1")),
            (
                "==1!2.3.4.post1+local",
                ExactVersion,
                Some("1!2.3.4.post1+local"),
            ),
            ("==1.2", ExactVersion, Some("1.2")),
            ("==1.2.*", Range, None),
            ("~=1.2.3", Range, None),
            (">=1.2.3,<2", Range, None),
            ("==1.2.3,!=1.2.4", Range, None),
            ("", Unconstrained, None),
            ("===1.2.3", Unsupported, None),
            ("===arbitrary", Unsupported, None),
            ("1.2.3", Unsupported, None),
            ("==", Unsupported, None),
        ] {
            assert_classification("python", constraint, Value::Null, status, pin);
        }
    }

    #[test]
    fn python_direct_and_uv_sources_remain_explicit_exceptions() {
        for source in [
            json!("https://example.invalid/example-1.2.3.whl"),
            json!({"path":"../local", "editable":true}),
            json!({"git":"https://example.invalid/repo", "branch":"main"}),
            json!({"index":"private"}),
            json!([{"path":"../local", "marker":"sys_platform == 'linux'"}]),
        ] {
            assert_classification("python", "==1.2.3", source, PinStatus::SourceOverride, None);
        }
        assert_classification(
            "python",
            "==1.2.3",
            json!(true),
            PinStatus::Unsupported,
            None,
        );
    }

    #[test]
    fn malformed_version_evidence_is_not_an_exact_pin() {
        for ecosystem in ["rust", "npm"] {
            assert_classification(
                ecosystem,
                "=1.2.3",
                json!({"version":true}),
                PinStatus::Unsupported,
                None,
            );
        }
    }

    #[test]
    fn nested_python_source_lists_are_not_valid_overrides() {
        assert_classification(
            "python",
            "==1.2.3",
            json!([[{"path":"../local"}]]),
            PinStatus::Unsupported,
            None,
        );
    }

    // Catch loss of unresolved declarations, duplicate kinds, aliases and report ordering.
    #[test]
    fn audit_keeps_every_declaration_and_its_evidence_in_report_order(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut declaration = requirement(
            "=1.2.3",
            json!({"package":"actual-name", "version":"=1.2.3"}),
        );
        declaration.name = "actual-name".into();
        declaration.declared_name = Some("renamed".into());
        declaration.kind = "dev".into();
        declaration.marker = Some("cfg(unix)".into());
        declaration.extras = vec!["derive".into()];
        let mut input = report("rust", vec![declaration.clone(), declaration.clone()]);
        input.projects[0].manifest = "z/Cargo.toml".into();
        let mut second = Project::new("npm", "npm", "a/package.json");
        second
            .requirements
            .push(requirement("npm:@scope/name@2.0.0", Value::Null));
        input.projects.push(second);
        let findings = audit_pins(&input);
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].manifest, "z/Cargo.toml");
        assert_eq!(findings[1].manifest, "z/Cargo.toml");
        assert_eq!(findings[2].manifest, "a/package.json");
        assert_eq!(findings[0].ecosystem, "rust");
        assert_eq!(findings[2].ecosystem, "npm");
        assert_eq!(
            serde_json::to_value(&findings[0].requirement)?,
            serde_json::to_value(declaration)?
        );
        assert_eq!(findings[2].requirement.constraint, "npm:@scope/name@2.0.0");
        assert_eq!(findings[2].pin.as_deref(), Some("2.0.0"));
        Ok(())
    }

    #[test]
    fn unknown_ecosystems_and_group_inclusions_are_not_unconstrained_packages() {
        assert_classification("go", "1.2.3", Value::Null, PinStatus::Unsupported, None);
        let mut include = requirement("", Value::Null);
        include.kind = "group:dev:include".into();
        let findings = audit_pins(&report("python", vec![include]));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, PinStatus::Unsupported);
        assert!(findings[0].reason.is_some());
        assert!(audit_pins(&report("rust", Vec::new())).is_empty());
    }
}
