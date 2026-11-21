use super::*;
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub struct AlignmentAnalysis {
    pub graph_digest: String,
    pub alignment: Alignment,
    pub explanations: Option<AlignmentExplanations>,
}

impl AlignmentAnalysis {
    /// Coverage of the requested analyses, independent of policy compliance.
    pub fn complete(&self) -> bool {
        self.alignment.coverage.versions_complete
            && self.alignment.coverage.pin_audit_complete
            && self.explanations.as_ref().is_none_or(|e| e.complete)
    }

    pub fn policy_pass(&self) -> bool {
        self.complete()
            && self.alignment.aligned == Some(true)
            && self.alignment.pins_compliant == Some(true)
            && self.alignment.pin_lock_consistent == Some(true)
    }
}

pub fn analyze_alignment(graph: &Graph) -> Result<AlignmentAnalysis> {
    let report = AlignmentAnalysis {
        graph_digest: graph_digest(graph)?,
        alignment: alignment(graph)?,
        explanations: None,
    };
    ensure!(
        serde_json::to_vec(&report)?.len() <= MAX_BYTES,
        "Rapport d'alignement supérieur à 128 Mio"
    );
    Ok(report)
}

#[derive(Debug, Clone)]
pub struct AlignmentExplanationOptions {
    /// Canonical unversioned PURL; absent selects only same-domain duplicates.
    pub package: Option<String>,
    pub max_queries: usize,
    /// Total retained hits and root declarations across all queries.
    pub max_results: usize,
    pub max_depth: u32,
    pub timeout: Duration,
}

impl Default for AlignmentExplanationOptions {
    fn default() -> Self {
        Self {
            package: None,
            max_queries: 8,
            max_results: 4096,
            max_depth: 16,
            timeout: Duration::from_secs(60),
        }
    }
}

impl AlignmentExplanationOptions {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16).contains(&self.max_queries),
            "Nombre de parcours requis entre 1 et 16"
        );
        ensure!(
            (1..=4096).contains(&self.max_results),
            "Nombre de résultats requis entre 1 et 4096"
        );
        ensure!(
            (1..=64).contains(&self.max_depth),
            "Profondeur d'explication requise entre 1 et 64"
        );
        ensure!(
            !self.timeout.is_zero() && self.timeout <= Duration::from_secs(300),
            "Budget de temps requis entre 1 ms et 300 s"
        );
        if let Some(identity) = &self.package {
            ensure!(identity.len() <= 8192, "Identité de paquet trop longue");
            let parsed = identity
                .parse::<packageurl::PackageUrl>()
                .map_err(|e| invalid(format!("PURL d'explication invalide : {e}")))?;
            ensure!(
                parsed.version().is_none() && parsed.to_string() == *identity,
                "PURL canonique sans version requise pour --package"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub struct AlignmentExplanations {
    pub selected_occurrences: usize,
    pub queries_run: usize,
    pub complete: bool,
    pub truncated: bool,
    pub results: Vec<AlignmentExplanation>,
}

#[derive(Debug, Serialize)]
pub struct AlignmentExplanation {
    pub domain: String,
    pub engine: String,
    pub query: Query,
    pub complete: bool,
    pub truncated: bool,
    pub potential: bool,
    pub nodes: Vec<Hit>,
    pub roots: Vec<Root>,
    pub limitation_count: usize,
    pub limitations_sample: Vec<String>,
}

impl Ladybug {
    /// Explain locked occurrences with bounded reverse traversals. This cannot
    /// establish feature activation, upgrade compatibility or exploitability.
    pub fn explain_alignment(
        &self,
        graph: &Graph,
        options: &AlignmentExplanationOptions,
    ) -> Result<AlignmentAnalysis> {
        options.validate()?;
        let mut analysis = analyze_alignment(graph)?;
        let mut output_bytes = serde_json::to_vec(&analysis)?.len();
        let domains: BTreeMap<_, _> = analysis
            .alignment
            .domains
            .iter()
            .map(|domain| (domain.id.as_str(), domain))
            .collect();
        let mut selected = BTreeMap::new();
        let mut found = false;
        for group in &analysis.alignment.groups {
            if !options
                .package
                .as_ref()
                .map_or(group.duplicate, |p| *p == group.identity)
            {
                continue;
            }
            found = true;
            let domain = domains
                .get(group.domain.as_str())
                .ok_or_else(|| invalid("Domaine d'alignement absent".into()))?;
            for node in group.versions.iter().flat_map(|v| &v.nodes) {
                selected.insert(node.clone(), *domain);
            }
        }
        ensure!(
            options.package.is_none() || found,
            "Identité demandée absente de l'inventaire projeté"
        );
        let selected_occurrences = selected.len();
        let started = Instant::now();
        let mut results = Vec::new();
        let mut remaining_results = options.max_results;
        for (node, domain) in selected.into_iter().take(options.max_queries) {
            let remaining = options.timeout.saturating_sub(started.elapsed());
            if remaining < Duration::from_millis(2) || remaining_results == 0 {
                break;
            }
            let query = Query {
                start: node,
                target: None,
                direction: Direction::Dependants,
                max_depth: options.max_depth,
                filter: Filter {
                    graphs: domain.graphs.iter().cloned().collect(),
                    ..Filter::default()
                },
            };
            ensure!(
                !query.filter.graphs.is_empty(),
                "Contextes du domaine absents"
            );
            // Budget both the version probe and the query process. Each native
            // call also has independent memory, file-size and output limits.
            let result = self
                .clone()
                .with_timeout(remaining / 2)?
                .query(graph, &query)?;
            let kept_roots = result.roots.len().min(remaining_results);
            remaining_results -= kept_roots;
            let kept_nodes = result.nodes.len().min(remaining_results);
            remaining_results -= kept_nodes;
            let truncated = result.truncated
                || kept_roots < result.roots.len()
                || kept_nodes < result.nodes.len()
                || started.elapsed() > options.timeout;
            let explanation = AlignmentExplanation {
                domain: domain.id.clone(),
                engine: result.engine,
                query: result.query,
                complete: result.complete && !truncated,
                truncated,
                potential: result.potential,
                nodes: result.nodes.into_iter().take(kept_nodes).collect(),
                roots: result.roots.into_iter().take(kept_roots).collect(),
                limitation_count: result.limitations.len(),
                limitations_sample: result.limitations.into_iter().take(8).collect(),
            };
            output_bytes = output_bytes.saturating_add(serde_json::to_vec(&explanation)?.len());
            ensure!(
                output_bytes <= MAX_BYTES,
                "Explications d'alignement supérieures à 128 Mio"
            );
            results.push(explanation);
        }
        let truncated = results.len() < selected_occurrences || results.iter().any(|r| r.truncated);
        analysis.explanations = Some(AlignmentExplanations {
            selected_occurrences,
            queries_run: results.len(),
            complete: !truncated && results.iter().all(|r| r.complete),
            truncated,
            results,
        });
        ensure!(
            serde_json::to_vec(&analysis)?.len() <= MAX_BYTES,
            "Rapport d'alignement supérieur à 128 Mio"
        );
        Ok(analysis)
    }
}
