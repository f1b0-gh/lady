use crate::{
    error::{Error, Result},
    sources::Snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergedFile {
    pub sha256: String,
    pub executable: bool,
    pub origin: String,
}
pub fn merge_files(
    base: &Snapshot,
    local: &Snapshot,
    remote: &Snapshot,
) -> Result<BTreeMap<String, MergedFile>> {
    let keys: std::collections::BTreeSet<_> = base
        .keys()
        .chain(local.keys())
        .chain(remote.keys())
        .collect();
    let mut result = BTreeMap::new();
    for name in keys {
        let b = base.get(name);
        let l = local.get(name);
        let r = remote.get(name);
        let (selected, origin) = if l == r || r == b {
            (l, "host")
        } else if l == b {
            (r, "remote")
        } else {
            return Err(Error::InvalidInput {
                message: format!(
                    "Host/sandbox conflict: {name}; export retained, replacement refused"
                ),
            });
        };
        if let Some(record) = selected {
            result.insert(
                name.clone(),
                MergedFile {
                    sha256: record.sha256.clone(),
                    executable: record.executable,
                    origin: origin.into(),
                },
            );
        }
    }
    Ok(result)
}
