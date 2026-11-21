use super::{super::invalid, syntax};
use crate::error::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Serialize)]
pub(super) struct Require {
    pub path: String,
    pub version: String,
    pub indirect: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Replacement {
    pub path: String,
    pub version: Option<String>,
    pub target: String,
    pub target_version: Option<String>,
}
#[derive(Default, Clone, Serialize)]
pub(super) struct Manifest {
    pub module: Option<String>,
    pub go: Option<String>,
    pub toolchain: Option<String>,
    pub requires: Vec<Require>,
    pub replacements: Vec<Replacement>,
    pub uses: Vec<String>,
    pub excludes: Vec<(String, String)>,
    pub directives: BTreeMap<String, Vec<Vec<String>>>,
}
pub(super) fn path(value: &str) -> Result<()> {
    if value.len() > 1024
        || value.is_empty()
        || value.starts_with('-')
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == ".." || p.ends_with('.'))
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~/".contains(&b))
    {
        return Err(invalid("Invalid Go module path".into()));
    }
    Ok(())
}
pub(super) fn version(value: &str) -> Result<()> {
    if value.len() > 128 {
        return Err(invalid("Go version length limit exceeded".into()));
    }
    let parsed = value
        .strip_prefix('v')
        .and_then(|v| v.parse::<semver::Version>().ok())
        .ok_or_else(|| invalid("Canonical Go module version required".into()))?;
    if !parsed.build.is_empty() && parsed.build.as_str() != "incompatible" {
        return Err(invalid("Invalid Go version build suffix".into()));
    }
    Ok(())
}
fn pair(words: &[String]) -> Result<(String, String)> {
    if words.len() != 2 {
        return Err(invalid("Go module/version pair required".into()));
    }
    path(&words[0])?;
    module_version(&words[0], &words[1])?;
    Ok((words[0].clone(), words[1].clone()))
}
pub(super) fn replacement(words: &[String]) -> Result<Replacement> {
    let arrow = words
        .iter()
        .position(|w| w == "=>")
        .ok_or_else(|| invalid("Go replacement arrow missing".into()))?;
    if !(1..=2).contains(&arrow) || !(1..=2).contains(&(words.len() - arrow - 1)) {
        return Err(invalid("Invalid Go replacement".into()));
    }
    path(&words[0])?;
    let version = if arrow == 2 {
        version(&words[1])?;
        Some(words[1].clone())
    } else {
        None
    };
    let target = words[arrow + 1].clone();
    let target_version = words.get(arrow + 2).cloned();
    if let Some(value) = &target_version {
        path(&target)?;
        self::version(value)?;
    } else if !(target.starts_with('.')
        || target.starts_with('/')
        || target.contains('\\')
        || target.as_bytes().get(1) == Some(&b':'))
    {
        return Err(invalid("Remote Go replacement requires a version".into()));
    }
    Ok(Replacement {
        path: words[0].clone(),
        version,
        target,
        target_version,
    })
}
pub(super) fn module_version(module: &str, value: &str) -> Result<()> {
    path(module)?;
    version(value)?;
    let parsed = value[1..]
        .parse::<semver::Version>()
        .map_err(|e| invalid(e.to_string()))?;
    let suffix = if module.starts_with("gopkg.in/") {
        module
            .rsplit_once(".v")
            .map(|(_, v)| v.trim_end_matches("-unstable"))
    } else {
        module
            .rsplit_once("/v")
            .map(|(_, v)| v)
            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
    };
    if let Some(suffix) = suffix {
        let major = suffix
            .parse::<u64>()
            .map_err(|_| invalid("Invalid Go module major suffix".into()))?;
        let legacy = module.starts_with("gopkg.in/") && major == 1 && value.starts_with("v0.0.0-");
        if !legacy && major != parsed.major || !module.starts_with("gopkg.in/") && major < 2 {
            return Err(invalid("Go module path and version major differ".into()));
        }
    } else if parsed.major >= 2 && parsed.build.as_str() != "incompatible" {
        return Err(invalid(
            "Go major version requires a matching module path suffix".into(),
        ));
    }
    Ok(())
}
pub(super) fn go_version(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    let suffix = value.split_once("rc").or_else(|| value.split_once("beta"));
    if suffix.is_some_and(|(_, s)| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    let base = suffix.map_or(value, |(base, _)| base);
    let parts: Vec<_> = base.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}
pub(super) fn parse(content: &str, workspace: bool) -> Result<Manifest> {
    let mut result = Manifest::default();
    let mut requires = BTreeSet::new();
    let mut replacements = BTreeSet::new();
    let mut uses = BTreeSet::new();
    for statement in syntax::parse(content)? {
        let words = statement.words;
        match statement.directive.as_str() {
            "module" if !workspace && words.len() == 1 && result.module.is_none() => {
                path(&words[0])?;
                result.module = Some(words[0].clone());
            }
            "go" if words.len() == 1 && result.go.is_none() && go_version(&words[0]) => {
                result.go = Some(words[0].clone())
            }
            "toolchain"
                if words.len() == 1
                    && result.toolchain.is_none()
                    && (words[0] == "default"
                        || words[0].strip_prefix("go").is_some_and(go_version)) =>
            {
                result.toolchain = Some(words[0].clone())
            }
            "require" if !workspace => {
                let (path, version) = pair(&words)?;
                if !requires.insert(path.clone()) {
                    return Err(invalid("Duplicate Go requirement".into()));
                }
                result.requires.push(Require {
                    path,
                    version,
                    indirect: statement.indirect,
                });
            }
            "replace" => {
                let replacement = replacement(&words)?;
                if !replacements.insert((replacement.path.clone(), replacement.version.clone())) {
                    return Err(invalid("Duplicate Go replacement".into()));
                }
                result.replacements.push(replacement);
            }
            "exclude" if !workspace => {
                let value = pair(&words)?;
                if result.excludes.contains(&value) {
                    return Err(invalid("Duplicate Go exclusion".into()));
                }
                result.excludes.push(value);
            }
            "use" if workspace && words.len() == 1 => {
                if !uses.insert(words[0].clone()) {
                    return Err(invalid("Duplicate Go workspace member".into()));
                }
                result.uses.push(words[0].clone());
            }
            "retract" if !workspace => {
                if words.len() == 1 {
                    version(&words[0])?;
                } else if words.len() == 5 && words[0] == "[" && words[2] == "," && words[4] == "]"
                {
                    version(&words[1])?;
                    version(&words[3])?;
                } else {
                    return Err(invalid("Invalid Go retraction".into()));
                }
                result
                    .directives
                    .entry("retract".into())
                    .or_default()
                    .push(words);
            }
            "tool" if !workspace && words.len() == 1 => {
                path(&words[0])?;
                result
                    .directives
                    .entry("tool".into())
                    .or_default()
                    .push(words);
            }
            "godebug"
                if words.len() == 1
                    && words[0]
                        .split_once('=')
                        .is_some_and(|(k, v)| !k.is_empty() && !v.is_empty()) =>
            {
                result
                    .directives
                    .entry("godebug".into())
                    .or_default()
                    .push(words);
            }
            _ => {
                return Err(invalid(format!(
                    "Unsupported, duplicate or malformed Go directive: {}",
                    statement.directive
                )))
            }
        }
    }
    if !workspace && result.module.is_none() {
        return Err(invalid("Missing Go module directive".into()));
    }
    if workspace && (result.go.is_none() || result.uses.is_empty()) {
        return Err(invalid(
            "Go workspace requires go and use directives".into(),
        ));
    }
    Ok(result)
}
