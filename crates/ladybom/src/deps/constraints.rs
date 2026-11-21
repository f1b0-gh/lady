//! Pure ecosystem version matching, independent of preparation authorization.
use super::invalid;
use crate::error::Result;

pub fn python_matches(version: &str, requirement: &str) -> Result<bool> {
    let version: pep440_rs::Version = version
        .parse()
        .map_err(|e| invalid(format!("Invalid Python version: {e}")))?;
    let range: pep440_rs::VersionSpecifiers = requirement
        .parse()
        .map_err(|e| invalid(format!("Invalid Python constraint: {e}")))?;
    Ok(range.contains(&version))
}
pub fn npm_matches(version: &str, requirement: &str) -> Result<bool> {
    let version = node_semver::Version::parse(version).map_err(|e| invalid(e.to_string()))?;
    let range = node_semver::Range::parse(requirement).map_err(|e| invalid(e.to_string()))?;
    Ok(version.satisfies(&range))
}
pub fn rust_matches(version: &str, requirement: &str) -> Result<bool> {
    let version = semver::Version::parse(version).map_err(|e| invalid(e.to_string()))?;
    let range = semver::VersionReq::parse(requirement).map_err(|e| invalid(e.to_string()))?;
    Ok(range.matches(&version))
}
