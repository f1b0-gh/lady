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
            "Compléter le périmètre, les inventaires verrouillés, les identités et les déclarations non qualifiées avant toute conclusion globale.",
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
                "Étudier une résolution commune dans ce verrou, après collecte de toutes les contraintes et revue des avis actuels. Aucune version observée n'est sélectionnée ou déclarée compatible.",
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
            "Si les contraintes empêchent une résolution commune, étudier la mise à jour des parents et les adaptations des consommateurs. Vérifier leurs manifests publiés ; préférer une évolution maintenue et justifier tout fork ou adaptateur par son coût récurrent.",
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
            "Examiner séparément les contraintes de chaque verrou, puis l'intérêt d'une convergence. Cet écart entre domaines ne constitue pas un doublon dans un même verrou.",
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
            .ok_or_else(|| invalid("Domaine de variante absent".into()))?;
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
                .ok_or_else(|| invalid("Groupe de variante de source absent".into()))?;
            indices.insert(*group);
        }
        let mut review = action(
            AlignmentPlanActionKind::ReviewSourceVariants,
            indices.into_iter().collect(),
            "Vérifier la provenance et l'identité de chaque fournisseur. Ne pas fusionner ces sources par simple égalité de nom et ne pas changer de fournisseur pour masquer une dette de versions.",
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
            "Contraintes transitives complètes inconnues : une arête verrouillée et ses preuves natives ne remplacent pas les manifests des parents ; aucun parent connu ne signifie pas absence de dépendant.".into(),
            "Seuls les parents immédiats et racines projetés sont joints. Les déclarations directes disponibles sont conservées dans alignment.pins ; leur correspondance avec une racine peut rester inconnue.".into(),
            "Inventaire de toutes les versions verrouillées, y compris build/test, optionnelles et toutes plateformes ; aucune preuve d'activation ni sélection automatique de version.".into(),
            "Aucun avis de sécurité actuel ni test consommateur n'est évalué par ce plan. Aucun verrou, référence, dette ou exception n'est modifié.".into(),
            "Entrée et chaque format de sortie limités à 128 Mio ; limites du graphe conservées : 100000 composants, 500000 arêtes et racines, 4096 contextes. Un dépassement est refusé, sans troncature favorable.".into(),
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
        ("source_scope", "Établir indépendamment les sources et verrous maintenus ; conserver périmètre, révision et empreintes. Vérifier identité, source et contexte de chaque candidat."),
        ("resolution_constraints", "Collecter les contraintes complètes des parents, alias, fonctionnalités, cibles, versions de langage et remplacements ; vérifier la résolution native reproductible dans chaque contexte explicitement autorisé."),
        ("current_advisories", "Contrôler les candidats puis les verrous finaux contre les avis actuels de chaque écosystème : transitives, optionnelles, build/test et toutes plateformes, wrappers, bindings et bibliothèques natives séparément. Conserver provenance, fraîcheur, paramètres, résultats et findings existants. Une source absente, périmée ou non prise en charge reste bloquante ; ne pas introduire de version connue affectée."),
        ("consumer_validation", "Valider les consommateurs, fonctionnalités et plateformes maintenus avec leurs tests, puis comparer de nouveaux snapshots et leurs empreintes. L'exécution exige un environnement autorisé distinct du scan."),
        ("pins_and_policy", "Contrôler séparément les pins avec graph alignment --check, puis la politique contre la référence revue et les avis de sécurité. Une dette backlog n'est pas approuvée. Toute exception exige responsable, périmètre, versions, sources, preuves, coût de maintenance et expiration ; aucun renouvellement automatique de référence ou exception."),
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
            return Err(std::io::Error::other(
                "Plan d'alignement supérieur à 128 Mio",
            ));
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
        out.push("# Plan de réduction des doublons\n\nEmpreinte du graphe : ")?;
        out.text(&self.graph_digest)?;
        out.push(if self.analysis_complete {
            "\n\nCouverture de l'analyse : complète.\n"
        } else {
            "\n\nCouverture de l'analyse : incomplète, bloquante.\n"
        })?;
        out.push("\nAucune remédiation approuvée. Les versions sont observées, sans choix de version compatible ou corrigée. Tous les contrôles ci-dessous sont requis avant adoption.\n\n## Actions ordonnées\n\n")?;
        if self.actions.is_empty() {
            out.push("Aucune action de réduction identifiée dans l'inventaire couvert.\n")?;
        }
        for (index, action) in self.actions.iter().enumerate() {
            out.push(&format!("{}. ", index + 1))?;
            out.text(&action.instruction)?;
            if !action.group_indices.is_empty() {
                out.push(" Groupes : ")?;
                out.text(&serde_json::to_string(&action.group_indices)?)?;
                out.push(".")?;
            }
            if let Some(variant) = action.source_variant_index {
                out.push(&format!(" Variante de source : {variant}."))?;
            }
            out.push("\n")?;
        }
        out.push("\n## Preuves des groupes concernés\n")?;
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
                .ok_or_else(|| invalid("Groupe du plan absent".into()))?;
            out.push(&format!("\n### Groupe {index}\n\nIdentité : "))?;
            out.text(&group.identity)?;
            out.push("\n\nDomaine : ")?;
            out.text(&group.domain)?;
            out.push("\n\nSource : ")?;
            out.text(&serde_json::to_string(&group.source)?)?;
            if let Some(domain) = domains.get(group.domain.as_str()) {
                out.push("\n\nManifests : ")?;
                out.text(&serde_json::to_string(&domain.manifests)?)?;
                out.push("\n\nVerrou : ")?;
                out.text(&serde_json::to_string(&domain.lockfile)?)?;
            }
            out.push("\n\n")?;
            for version in &group.versions {
                out.push("- Version observée : ")?;
                out.text(&version.version)?;
                out.push(&format!(
                    " ; {} occurrence(s) projetée(s).\n",
                    version.nodes.len()
                ))?;
                for node in &version.nodes {
                    out.push("  Contexte : ")?;
                    out.text(&node.graph)?;
                    out.push(" ; PURL : ")?;
                    out.text(&node.purl)?;
                    out.push("\n")?;
                }
            }
        }
        out.push("\n## Contextes et parents immédiats\n\n")?;
        for occurrence in &self.occurrences {
            out.push("- Occurrence : ")?;
            out.text(&serde_json::to_string(&occurrence.node)?)?;
            out.push(" ; contexte natif : ")?;
            out.text(&occurrence.native_context)?;
            if let Some(context) = self.contexts.get(&occurrence.node.graph) {
                out.push(" ; contexte projeté : ")?;
                out.text(&serde_json::to_string(context)?)?;
            }
            out.push(" ; source : ")?;
            out.text(&serde_json::to_string(&occurrence.source)?)?;
            out.push(". Contraintes transitives complètes : inconnues.\n")?;
            for parent in &occurrence.parents {
                out.push("  Parent immédiat et preuve native : ")?;
                out.text(&serde_json::to_string(parent)?)?;
                out.push("\n")?;
            }
            for root in &occurrence.roots {
                out.push("  Racine : ")?;
                out.text(&serde_json::to_string(root)?)?;
                out.push("\n")?;
            }
        }
        out.push("\n## Variantes de source\n\n")?;
        for (index, variant) in self.alignment.source_variants.iter().enumerate() {
            out.push(&format!("- Variante {index} : "))?;
            out.text(&serde_json::to_string(variant)?)?;
            out.push("\n")?;
        }
        out.push("\n## Déclarations directes disponibles\n\n")?;
        for pin in &self.alignment.pins {
            out.push("- ")?;
            out.text(&serde_json::to_string(pin)?)?;
            out.push("\n")?;
        }
        out.push("\n## Contrôles requis avant adoption\n\n")?;
        for gate in &self.gates {
            out.push("- ")?;
            out.text(&gate.instruction)?;
            out.push("\n")?;
        }
        out.push("\n## Couverture et limites\n\n")?;
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
            "Plan Markdown supérieur à 128 Mio"
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
