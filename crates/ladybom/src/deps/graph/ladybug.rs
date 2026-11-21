use super::*;
use crate::process;
use serde_json::json;
use std::{fs, os::unix::process::CommandExt, path::PathBuf, process::Command, time::Duration};

pub const ENGINE_VERSION: &str = "0.17.1";
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Dependencies,
    Dependants,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    /// Empty means all edge kinds. Applied before traversal.
    pub kinds: BTreeSet<String>,
    /// Empty means all contexts. Both endpoints must be in the selected contexts.
    pub graphs: BTreeSet<String>,
    pub include_conditional: bool,
}
impl Default for Filter {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            graphs: BTreeSet::new(),
            include_conditional: true,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub start: NodeRef,
    pub direction: Direction,
    pub target: Option<NodeRef>,
    pub max_depth: u32,
    pub filter: Filter,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hit {
    pub node: NodeRef,
    pub distance: u32,
    pub path: Vec<NodeRef>,
}
#[derive(Debug, Serialize)]
pub struct Analysis {
    pub engine: String,
    pub query: Query,
    pub complete: bool,
    pub truncated: bool,
    pub potential: bool,
    pub limitations: Vec<String>,
    pub nodes: Vec<Hit>,
    /// Project/root references directly entering the impacted closure, including the seed.
    pub roots: Vec<Root>,
}
#[derive(Debug, Clone)]
pub struct Ladybug {
    binary: PathBuf,
    timeout: Duration,
}
impl Ladybug {
    pub fn new(binary: PathBuf) -> Result<Self> {
        ensure!(
            binary.is_absolute(),
            "Absolute LadybugDB engine path required"
        );
        // Nix output paths can contain symlinks; resolve explicitly, never search project PATH.
        let binary = fs::canonicalize(binary)?;
        files::open_regular(&binary)?;
        Ok(Self {
            binary,
            timeout: Duration::from_secs(60),
        })
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        ensure!(
            !timeout.is_zero() && timeout <= Duration::from_secs(300),
            "LadybugDB timeout must be between 1 ms and 300 s"
        );
        self.timeout = timeout;
        Ok(self)
    }
    fn command(&self, directory: &std::path::Path) -> Command {
        let mut cmd = Command::new(&self.binary);
        cmd.env_clear()
            .env("HOME", directory)
            .env("TMPDIR", directory)
            .env("LC_ALL", "C")
            .current_dir(directory);
        // Independent process limits, including allocations outside the engine buffer pool.
        // SAFETY: pre_exec calls only async-signal-safe libc setrlimit; no allocation or locks.
        unsafe {
            cmd.pre_exec(|| {
                for (resource, value) in [
                    (libc::RLIMIT_AS, 4u64 * 1024 * 1024 * 1024),
                    (libc::RLIMIT_FSIZE, 256u64 * 1024 * 1024),
                    (libc::RLIMIT_CORE, 0),
                ] {
                    let limit = libc::rlimit {
                        rlim_cur: value,
                        rlim_max: value,
                    };
                    if libc::setrlimit(resource, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        cmd
    }
    /// Import only validated technical identifiers; all callers keep metadata out of Cypher.
    pub(super) fn execute_graph(
        &self,
        nodes: &[Vec<String>],
        relations: &[Vec<String>],
        depth: u32,
        queries: &[String],
    ) -> Result<Vec<Value>> {
        let scratch = tempfile::Builder::new()
            .prefix("ladybom-ladybug-")
            .tempdir()?;
        let mut version_cmd = self.command(scratch.path());
        version_cmd.arg("--version");
        let version = String::from_utf8(process::capture(
            version_cmd,
            self.timeout.min(Duration::from_secs(5)),
            4096,
        )?)?;
        ensure!(
            version
                .split_whitespace()
                .any(|v| v.trim_start_matches('v') == ENGINE_VERSION),
            "Unqualified LadybugDB version: {} (expected {ENGINE_VERSION})",
            version.trim()
        );
        super::snapshot::write_table(&scratch.path().join("nodes.parquet"), &["id"], nodes)?;
        super::snapshot::write_table(
            &scratch.path().join("edges.parquet"),
            &["from_id", "to_id"],
            relations,
        )?;
        fs::write(scratch.path().join("empty.cypher"), "")?;
        let mut script = format!("CALL threads=2;\nCALL timeout={};\nCALL var_length_extend_max_depth={depth};\nCREATE NODE TABLE Component(id STRING, PRIMARY KEY(id));\nCREATE REL TABLE Depends(FROM Component TO Component);\n", self.timeout.as_millis());
        if !nodes.is_empty() {
            script.push_str("COPY Component FROM 'nodes.parquet';\n");
        }
        if !relations.is_empty() {
            script.push_str("COPY Depends FROM 'edges.parquet';\n");
        }
        script.push_str("MATCH (a:Component) RETURN count(a) AS imported_nodes;\nMATCH (:Component)-[e:Depends]->(:Component) RETURN count(e) AS imported_edges;\n");
        for query in queries {
            script.push_str(query);
            script.push('\n');
        }
        let mut cmd = self.command(scratch.path());
        cmd.args([
            "--mode",
            "json",
            "--no_stats",
            "--no_progress_bar",
            "--defaultbpsize",
            "256",
            "--max_db_size",
            "1073741824",
            "--init",
            "empty.cypher",
            "--path_history",
            ".",
        ]);
        let stdout =
            process::capture_input(cmd, script.as_bytes(), self.timeout, 32 * 1024 * 1024)?;
        let stdout = stdout
            .strip_prefix(b"-- Processing: empty.cypher\n")
            .ok_or_else(|| invalid("LadybugDB initialization not confirmed".into()))?;
        let responses = serde_json::Deserializer::from_slice(stdout)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                invalid(format!(
                    "Invalid LadybugDB response: {e}; {}",
                    String::from_utf8_lossy(&stdout[..stdout.len().min(2048)])
                ))
            })?;
        let setup = 5 + usize::from(!nodes.is_empty()) + usize::from(!relations.is_empty());
        ensure!(
            responses.len() == setup + 2 + queries.len(),
            "Missing or unexpected LadybugDB responses"
        );
        ensure!(
            responses[setup] == json!([{"imported_nodes":nodes.len()}])
                && responses[setup + 1] == json!([{"imported_edges":relations.len()}]),
            "Import LadybugDB incomplet"
        );
        Ok(responses.into_iter().skip(setup + 2).collect())
    }
    pub fn query(&self, graph: &Graph, query: &Query) -> Result<Analysis> {
        graph.validate()?;
        ensure!(
            (1..=256).contains(&query.max_depth),
            "Depth must be between 1 and 256"
        );
        let mut keys = BTreeMap::new();
        for node in &graph.components {
            keys.insert(node.key.engine_key()?, node.key.clone());
        }
        ensure!(
            keys.values().any(|n| n == &query.start),
            "Missing starting component"
        );
        if let Some(target) = &query.target {
            ensure!(
                keys.values().any(|n| n == target),
                "Missing target component"
            );
        }
        for context in &query.filter.graphs {
            ensure!(
                graph.contexts.contains_key(context),
                "Missing filter context"
            );
        }
        let selected = |node: &NodeRef| {
            query.filter.graphs.is_empty() || query.filter.graphs.contains(&node.graph)
        };
        ensure!(
            selected(&query.start) && query.target.as_ref().is_none_or(selected),
            "Start or target excluded by the filter"
        );
        let edges: Vec<_> = graph
            .dependencies
            .iter()
            .filter(|e| {
                selected(&e.from)
                    && selected(&e.to)
                    && (query.filter.kinds.is_empty() || query.filter.kinds.contains(&e.kind))
                    && (query.filter.include_conditional || e.condition.is_null())
            })
            .collect();
        let nodes: Vec<Vec<String>> = keys.keys().map(|id| vec![id.clone()]).collect();
        let relations = edges
            .iter()
            .map(|e| Ok(vec![e.from.engine_key()?, e.to.engine_key()?]))
            .collect::<Result<Vec<_>>>()?;
        let start = query.start.engine_key()?;
        let depth = query.max_depth + 1;
        let pattern = match query.direction {
            Direction::Dependencies => {
                format!("(a:Component)-[e:Depends* SHORTEST 1..{depth}]->(b:Component)")
            }
            Direction::Dependants => {
                format!("(a:Component)<-[e:Depends* SHORTEST 1..{depth}]-(b:Component)")
            }
        };
        let cypher = format!("MATCH p={pattern} WHERE a.id='{start}' AND b.id <> a.id RETURN b.id AS id, length(e) AS distance, properties(nodes(p), 'id') AS path ORDER BY id;");
        let responses = self.execute_graph(&nodes, &relations, depth, &[cypher])?;
        let rows = responses[0]
            .as_array()
            .ok_or_else(|| invalid("LadybugDB result list required".into()))?;
        ensure!(
            rows.len() <= graph.components.len(),
            "Inconsistent traversal cardinality"
        );
        let mut hits = Vec::new();
        let adjacency: BTreeSet<_> = edges.iter().map(|e| (&e.from, &e.to)).collect();
        let mut seen = BTreeSet::new();
        let mut truncated = false;
        for row in rows {
            let lookup = |value: &Value| -> Result<NodeRef> {
                keys.get(
                    value
                        .as_str()
                        .ok_or_else(|| invalid("Invalid LadybugDB identifier".into()))?,
                )
                .cloned()
                .ok_or_else(|| invalid("Unknown LadybugDB identifier".into()))
            };
            let node = lookup(&row["id"])?;
            let distance = row["distance"]
                .as_u64()
                .ok_or_else(|| invalid("Missing distance".into()))?;
            ensure!(
                distance >= 1 && distance <= u64::from(depth) && seen.insert(node.clone()),
                "Invalid distance or duplicate result"
            );
            let path = row["path"]
                .as_array()
                .ok_or_else(|| invalid("Missing path".into()))?
                .iter()
                .map(lookup)
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                path.len() == distance as usize + 1
                    && path.first() == Some(&query.start)
                    && path.last() == Some(&node),
                "Inconsistent LadybugDB path"
            );
            for pair in path.windows(2) {
                let (from, to) = if query.direction == Direction::Dependencies {
                    (&pair[0], &pair[1])
                } else {
                    (&pair[1], &pair[0])
                };
                ensure!(
                    adjacency.contains(&(from, to)),
                    "Path outside the filtered graph"
                );
            }
            if distance > u64::from(query.max_depth) {
                truncated = true;
                continue;
            }
            if query.target.as_ref().is_none_or(|target| target == &node) {
                hits.push(Hit {
                    node,
                    distance: distance as u32,
                    path,
                });
            }
        }
        if query.target.as_ref() == Some(&query.start) {
            hits.push(Hit {
                node: query.start.clone(),
                distance: 0,
                path: vec![query.start.clone()],
            });
        }
        hits.sort_by(|a, b| a.node.cmp(&b.node));
        let impacted: BTreeSet<_> = hits
            .iter()
            .map(|h| &h.node)
            .chain(std::iter::once(&query.start))
            .collect();
        let roots = graph
            .roots
            .iter()
            .filter(|r| {
                impacted.contains(&r.to)
                    && (query.filter.kinds.is_empty() || query.filter.kinds.contains(&r.kind))
                    && (query.filter.include_conditional || r.condition.is_null())
            })
            .cloned()
            .collect();
        let mut limitations = graph.limitations.clone();
        if !graph.inventory.complete {
            limitations.push("Partial source inventory".into());
        }
        if truncated {
            limitations.push("Traversal truncated by maximum depth".into());
        }
        Ok(Analysis {
            engine: format!("ladybugdb/{ENGINE_VERSION}"),
            query: query.clone(),
            complete: graph.complete() && !truncated,
            truncated,
            potential: true,
            limitations,
            nodes: hits,
            roots,
        })
    }
}
