//! Offline investigation plans; observed versions never authorize a remediation.
use super::*;
use std::io::Write;

/// A versioned investigation plan tied to the exact input graph digest.
#[derive(Debug, Serialize)]
pub struct AlignmentPlan {
    pub schema_version: u32,
    pub graph_digest: String,
    pub scope: String,
    /// Inventory and direct-declaration coverage, not remediation feasibility.
    pub analysis_complete: bool,
    pub remediation_approved: bool,
    pub alignment: Alignment,
    pub contexts: BTreeMap<String, Context>,
    pub actions: Vec<AlignmentPlanAction>,
    pub occurrences: Vec<AlignmentPlanOccurrence>,
    /// Every gate applies before adopting any version or source change.
    pub gates: Vec<AlignmentPlanGate>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentPlanActionKind {
    CompleteCoverage,
    ReviewLockResolution,
    ReviewParentMigration,
    ReviewCrossDomain,
    ReviewSourceVariants,
}

#[derive(Debug, Serialize)]
pub struct AlignmentPlanAction {
    pub kind: AlignmentPlanActionKind,
    /// Indices into alignment.groups; identity, source and domain are preserved there.
    pub group_indices: Vec<usize>,
    pub source_variant_index: Option<usize>,
    pub instruction: String,
}

#[derive(Debug, Serialize)]
pub struct AlignmentPlanOccurrence {
    pub node: NodeRef,
    pub source: Value,
    pub native_context: String,
    /// Immediate incoming edges only; raw evidence is not a complete constraint set.
    pub parents: Vec<Edge>,
    pub roots: Vec<Root>,
    pub transitive_constraints_complete: bool,
}

#[derive(Debug, Serialize)]
pub struct AlignmentPlanGate {
    pub id: String,
    pub instruction: String,
}

/// Build a bounded static plan without a resolver, native engine or network access.
/// The graph must come from the intended source scope; its digest proves content,
/// not that the caller included every maintained project.
pub fn plan_alignment(graph: &Graph) -> Result<AlignmentPlan> {
    let analysis = analyze_alignment(graph)?;
    let analysis_complete = analysis.complete();
    let alignment = analysis.alignment;
    let locals = crate::deps::npm::local::LocalPackages::new(&graph.inventory);
    let python_locals = crate::deps::python::local::LocalPackages::new(&graph.inventory);
    let mut actions = Vec::new();
    if !analysis_complete {
        actions.push(action(
            AlignmentPlanActionKind::CompleteCoverage,
            Vec::new(),
            "Complete the scope, locked inventories, identities and unqualified declarations before drawing any overall conclusion.",
        ));
    }
    let mut identity_groups = BTreeMap::<(String, String), Vec<usize>>::new();
    let mut source_groups = BTreeMap::new();
    for (index, group) in alignment.groups.iter().enumerate() {
        identity_groups
            .entry((
                group.identity.clone(),
                serde_json::to_string(&group.source)?,
            ))
            .or_default()
            .push(index);
        source_groups.insert(
            (
                group.domain.clone(),
                group.identity.clone(),
                serde_json::to_string(&group.source)?,
            ),
            index,
        );
        if group.duplicate {
            actions.push(action(
                AlignmentPlanActionKind::ReviewLockResolution,
                vec![index],
                "Investigate a common resolution within this lockfile after collecting all constraints and reviewing current advisories. No observed version is selected or declared compatible.",
            ));
        }
    }
    // Review lock-only possibilities before considering parent/API migrations.
    for (index, _) in alignment
        .groups
        .iter()
        .enumerate()
        .filter(|(_, g)| g.duplicate)
    {
        actions.push(action(
            AlignmentPlanActionKind::ReviewParentMigration,
            vec![index],
            "If constraints prevent a common resolution, investigate parent updates and consumer changes. Verify their published manifests; prefer maintained updates and justify any fork or adapter by its recurring cost.",
        ));
    }
    for difference in &alignment.cross_domain {
        let indices = identity_groups
            .get(&(
                difference.identity.clone(),
                serde_json::to_string(&difference.source)?,
            ))
            .cloned()
            .unwrap_or_default();
        actions.push(action(
            AlignmentPlanActionKind::ReviewCrossDomain,
            indices,
            "Review each lockfile's constraints separately, then assess the benefit of convergence. This difference across domains is not a duplicate within one lockfile.",
        ));
    }
    let ecosystems: BTreeMap<_, _> = alignment
        .domains
        .iter()
        .map(|domain| (domain.id.as_str(), domain.ecosystem.as_str()))
        .collect();
    for (index, variant) in alignment.source_variants.iter().enumerate() {
        let ecosystem = ecosystems
            .get(variant.domain.as_str())
            .ok_or_else(|| invalid("Missing variant domain".into()))?;
        let mut indices = BTreeSet::new();
        // Native spellings and group display labels can differ for one PURL.
        // Join the authoritative domain/identity/source, including unprojected
        // evidence, with the same normalization as the alignment analysis.
        for evidence in &variant.sources {
            let Some(identity) = &evidence.identity else {
                continue;
            };
            let source = alignment
                .domains
                .iter()
                .find(|domain| domain.id == variant.domain)
                .and_then(|domain| domain.lockfile.as_deref())
                .and_then(|lock| {
                    locals
                        .evidence_source(lock, &evidence.context, &variant.name, &evidence.version)
                        .or_else(|| {
                            python_locals.evidence_source(
                                lock,
                                &evidence.context,
                                &variant.name,
                                &evidence.version,
                            )
                        })
                })
                .unwrap_or_else(|| {
                    alignment::normalized_source(
                        ecosystem,
                        &variant.name,
                        &evidence.version,
                        &evidence.source,
                    )
                });
            let group = source_groups
                .get(&(
                    variant.domain.clone(),
                    identity.clone(),
                    serde_json::to_string(&source)?,
                ))
                .ok_or_else(|| invalid("Missing source variant group".into()))?;
            indices.insert(*group);
        }
        let mut review = action(
            AlignmentPlanActionKind::ReviewSourceVariants,
            indices.into_iter().collect(),
            "Verify each provider's provenance and identity. Do not merge these sources solely because their names match or change providers to hide version debt.",
        );
        review.source_variant_index = Some(index);
        actions.push(review);
    }

    let selected: BTreeSet<_> = actions
        .iter()
        .flat_map(|a| &a.group_indices)
        .flat_map(|i| &alignment.groups[*i].versions)
        .flat_map(|v| &v.nodes)
        .collect();
    // Index incoming evidence once; no per-group whole-graph traversal or cloning
    // of the same edge for the lock and parent actions.
    let mut parents = BTreeMap::<&NodeRef, Vec<(String, &Edge)>>::new();
    for edge in &graph.dependencies {
        if selected.contains(&edge.to) {
            parents
                .entry(&edge.to)
                .or_default()
                .push((serde_json::to_string(edge)?, edge));
        }
    }
    let mut roots = BTreeMap::<&NodeRef, Vec<(String, &Root)>>::new();
    for root in &graph.roots {
        if selected.contains(&root.to) {
            roots
                .entry(&root.to)
                .or_default()
                .push((serde_json::to_string(root)?, root));
        }
    }
    let mut occurrences = Vec::new();
    for node in &graph.components {
        if !selected.contains(&node.key) {
            continue;
        }
        let mut incoming = parents.remove(&node.key).unwrap_or_default();
        incoming.sort_by(|a, b| a.0.cmp(&b.0));
        let mut declarations = roots.remove(&node.key).unwrap_or_default();
        declarations.sort_by(|a, b| a.0.cmp(&b.0));
        occurrences.push(AlignmentPlanOccurrence {
            node: node.key.clone(),
            source: node.component.source.clone(),
            native_context: node.component.context.clone(),
            parents: incoming.into_iter().map(|(_, e)| e.clone()).collect(),
            roots: declarations.into_iter().map(|(_, r)| r.clone()).collect(),
            transitive_constraints_complete: false,
        });
    }
    occurrences.sort_by(|a, b| a.node.cmp(&b.node));
    let limitations = alignment.limitations.iter().chain(&graph.limitations)
        .cloned().chain([
            "Complete transitive constraints are unknown: a locked edge and its native evidence do not replace parent manifests; no known parent does not establish the absence of dependents.".into(),
            "Only projected immediate parents and roots are included. Available direct declarations are retained in alignment.pins; their correspondence with a root may remain unknown.".into(),
            "Inventory of all locked versions, including build/test, optional dependencies and all platforms; no proof of activation or automatic version selection.".into(),
            "This plan evaluates no current security advisory or consumer test. No lockfile, baseline, debt or exception is modified.".into(),
            "Input and each output format are limited to 128 MiB; graph limits remain: 100000 components, 500000 edges and roots, 4096 contexts. Exceeding a limit is refused, without favorable truncation.".into(),
        ]).collect::<BTreeSet<_>>().into_iter().collect();
    let plan = AlignmentPlan {
        schema_version: 1,
        graph_digest: analysis.graph_digest,
        scope: "all_locked_versions".into(),
        analysis_complete,
        remediation_approved: false,
        alignment,
        contexts: graph.contexts.clone(),
        actions,
        occurrences,
        gates: gates(),
        limitations,
    };
    // Count serialization without allocating a second potentially large report.
    serde_json::to_writer(ByteBudget::default(), &plan)?;
    Ok(plan)
}

fn action(
    kind: AlignmentPlanActionKind,
    group_indices: Vec<usize>,
    instruction: &str,
) -> AlignmentPlanAction {
    AlignmentPlanAction {
        kind,
        group_indices,
        source_variant_index: None,
        instruction: instruction.into(),
    }
}

fn gates() -> Vec<AlignmentPlanGate> {
    [
        ("source_scope", "Independently establish maintained sources and lockfiles; retain scope, revision and digests. Verify each candidate's identity, source and context."),
        ("resolution_constraints", "Collect complete constraints for parents, aliases, features, targets, language versions and overrides; verify reproducible native resolution in each explicitly authorized context."),
        ("current_advisories", "Check candidates, then final lockfiles, against current advisories for each ecosystem: transitive, optional, build/test and all platforms, checking wrappers, bindings and native libraries separately. Retain provenance, freshness, parameters, results and existing findings. A missing, stale or unsupported source remains blocking; do not introduce a version known to be affected."),
        ("consumer_validation", "Validate maintained consumers, features and platforms with their tests, then compare new snapshots and their digests. Execution requires an authorized environment separate from scanning."),
        ("pins_and_policy", "Check pins separately with graph alignment --check, then check policy against the reviewed baseline and security advisories. Backlog debt is not approved. Every exception requires an owner, scope, versions, sources, evidence, maintenance cost and expiry; no automatic renewal of a baseline or exception."),
    ].into_iter().map(|(id, instruction)| AlignmentPlanGate { id: id.into(), instruction: instruction.into() }).collect()
}

#[derive(Default)]
struct ByteBudget {
    bytes: usize,
}
impl Write for ByteBudget {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        if self.bytes > MAX_BYTES {
            return Err(std::io::Error::other("Alignment plan exceeds 128 MiB"));
        }
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl AlignmentPlan {
    /// Render untrusted evidence as inert text, with the same 128 MiB output cap.
    pub fn to_markdown(&self) -> Result<String> {
        let mut out = Markdown::default();
        out.push("# Duplicate reduction plan\n\nGraph digest: ")?;
        out.text(&self.graph_digest)?;
        out.push(if self.analysis_complete {
            "\n\nAnalysis coverage: complete.\n"
        } else {
            "\n\nAnalysis coverage: incomplete, blocking.\n"
        })?;
        out.push("\nNo remediation approved. Versions are observed without selecting a compatible or fixed version. All checks below are required before adoption.\n\n## Ordered actions\n\n")?;
        if self.actions.is_empty() {
            out.push("No reduction action identified in the covered inventory.\n")?;
        }
        for (index, action) in self.actions.iter().enumerate() {
            out.push(&format!("{}. ", index + 1))?;
            out.text(&action.instruction)?;
            if !action.group_indices.is_empty() {
                out.push(" Groups: ")?;
                out.text(&serde_json::to_string(&action.group_indices)?)?;
                out.push(".")?;
            }
            if let Some(variant) = action.source_variant_index {
                out.push(&format!(" Source variant: {variant}."))?;
            }
            out.push("\n")?;
        }
        out.push("\n## Evidence for affected groups\n")?;
        let selected: BTreeSet<_> = self.actions.iter().flat_map(|a| &a.group_indices).collect();
        let domains: BTreeMap<_, _> = self
            .alignment
            .domains
            .iter()
            .map(|d| (d.id.as_str(), d))
            .collect();
        for index in selected {
            let group = self
                .alignment
                .groups
                .get(*index)
                .ok_or_else(|| invalid("Missing plan group".into()))?;
            out.push(&format!("\n### Group {index}\n\nIdentity: "))?;
            out.text(&group.identity)?;
            out.push("\n\nDomain: ")?;
            out.text(&group.domain)?;
            out.push("\n\nSource: ")?;
            out.text(&serde_json::to_string(&group.source)?)?;
            if let Some(domain) = domains.get(group.domain.as_str()) {
                out.push("\n\nManifests: ")?;
                out.text(&serde_json::to_string(&domain.manifests)?)?;
                out.push("\n\nLockfile: ")?;
                out.text(&serde_json::to_string(&domain.lockfile)?)?;
            }
            out.push("\n\n")?;
            for version in &group.versions {
                out.push("- Observed version: ")?;
                out.text(&version.version)?;
                out.push(&format!(
                    "; {} projected occurrence(s).\n",
                    version.nodes.len()
                ))?;
                for node in &version.nodes {
                    out.push("  Context: ")?;
                    out.text(&node.graph)?;
                    out.push("; PURL: ")?;
                    out.text(&node.purl)?;
                    out.push("\n")?;
                }
            }
        }
        out.push("\n## Contexts and immediate parents\n\n")?;
        for occurrence in &self.occurrences {
            out.push("- Occurrence: ")?;
            out.text(&serde_json::to_string(&occurrence.node)?)?;
            out.push("; native context: ")?;
            out.text(&occurrence.native_context)?;
            if let Some(context) = self.contexts.get(&occurrence.node.graph) {
                out.push("; projected context: ")?;
                out.text(&serde_json::to_string(context)?)?;
            }
            out.push("; source: ")?;
            out.text(&serde_json::to_string(&occurrence.source)?)?;
            out.push(". Complete transitive constraints: unknown.\n")?;
            for parent in &occurrence.parents {
                out.push("  Immediate parent and native evidence: ")?;
                out.text(&serde_json::to_string(parent)?)?;
                out.push("\n")?;
            }
            for root in &occurrence.roots {
                out.push("  Root: ")?;
                out.text(&serde_json::to_string(root)?)?;
                out.push("\n")?;
            }
        }
        out.push("\n## Source variants\n\n")?;
        for (index, variant) in self.alignment.source_variants.iter().enumerate() {
            out.push(&format!("- Variant {index}: "))?;
            out.text(&serde_json::to_string(variant)?)?;
            out.push("\n")?;
        }
        out.push("\n## Available direct declarations\n\n")?;
        for pin in &self.alignment.pins {
            out.push("- ")?;
            out.text(&serde_json::to_string(pin)?)?;
            out.push("\n")?;
        }
        out.push("\n## Required checks before adoption\n\n")?;
        for gate in &self.gates {
            out.push("- ")?;
            out.text(&gate.instruction)?;
            out.push("\n")?;
        }
        out.push("\n## Coverage and limitations\n\n")?;
        out.text(&serde_json::to_string(&self.alignment.coverage)?)?;
        out.push("\n\n")?;
        for limitation in &self.limitations {
            out.push("- ")?;
            out.text(limitation)?;
            out.push("\n")?;
        }
        Ok(out.output)
    }
}

#[derive(Default)]
struct Markdown {
    output: String,
}
impl Markdown {
    fn push(&mut self, text: &str) -> Result<()> {
        ensure!(
            self.output.len().saturating_add(text.len()) <= MAX_BYTES,
            "Markdown plan exceeds 128 MiB"
        );
        self.output.push_str(text);
        Ok(())
    }
    fn text(&mut self, text: &str) -> Result<()> {
        for c in text.chars() {
            if c.is_alphanumeric() || c == ' ' || c == '/' {
                self.push(c.encode_utf8(&mut [0; 4]))?;
            } else if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                self.push(&format!("[U+{:04X}]", u32::from(c)))?;
            } else {
                // Entities are decoded after Markdown parsing: no links, HTML,
                // tables, code fences or autolinks can originate in evidence.
                self.push(&format!("&#{};", u32::from(c)))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The serializer must stop at its byte cap even without allocating output.
    #[test]
    fn json_serialization_budget_refuses_the_first_excess_byte() -> Result<()> {
        let mut exact = ByteBudget {
            bytes: MAX_BYTES - 5,
        };
        serde_json::to_writer(&mut exact, "abc")?;
        assert_eq!(exact.bytes, MAX_BYTES);
        assert!(serde_json::to_writer(&mut exact, "").is_err());
        Ok(())
    }

    // Escaping expands evidence; the cap concerns rendered bytes, not input chars.
    #[test]
    fn markdown_output_refuses_escaping_beyond_the_budget() -> Result<()> {
        let mut markdown = Markdown {
            output: "x".repeat(MAX_BYTES - 5),
        };
        markdown.text("<")?;
        assert_eq!(markdown.output.len(), MAX_BYTES);
        assert!(markdown.text("<").is_err());
        assert_eq!(markdown.output.len(), MAX_BYTES);
        Ok(())
    }
}
