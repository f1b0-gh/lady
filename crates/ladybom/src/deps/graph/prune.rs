//! Counterfactual declaration removal. Packages shared by retained roots stay reachable.
use super::*;

pub fn graph_digest(graph: &Graph) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(graph)?))
}
pub fn root_catalog(graph: &Graph) -> Result<Vec<IdentifiedRoot>> {
    graph.validate()?;
    // Identical declarations are not individually distinguishable in this graph version.
    let mut roots = BTreeMap::new();
    for root in &graph.roots {
        let id = files::hash(&serde_json::to_vec(root)?);
        roots.entry(id.clone()).or_insert_with(|| IdentifiedRoot {
            id,
            root: root.clone(),
        });
    }
    Ok(roots.into_values().collect())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalRequest {
    pub schema_version: u32,
    pub graph_sha256: String,
    pub remove_roots: Vec<String>,
    /// Empty retains all projects. Selection is explicit and never inferred from source usage.
    #[serde(default)]
    pub retained_manifests: BTreeSet<String>,
    pub max_depth: u32,
    #[serde(default)]
    pub filter: Filter,
}
impl RemovalRequest {
    pub fn new(graph: &Graph, remove_roots: Vec<String>) -> Result<Self> {
        let request = Self {
            schema_version: 1,
            graph_sha256: graph_digest(graph)?,
            remove_roots,
            retained_manifests: BTreeSet::new(),
            max_depth: 32,
            filter: Filter::default(),
        };
        request.validate(graph)?;
        Ok(request)
    }
    pub fn validate(&self, graph: &Graph) -> Result<()> {
        graph.validate()?;
        ensure!(
            self.schema_version == 1 && self.graph_sha256 == graph_digest(graph)?,
            "Demande de retrait périmée ou version inconnue"
        );
        ensure!(
            (1..=256).contains(&self.max_depth),
            "Profondeur requise entre 1 et 256"
        );
        ensure!(
            !self.remove_roots.is_empty() && self.remove_roots.len() <= MAX_EDGES,
            "Retraits explicites requis (maximum 500000)"
        );
        ensure!(
            self.filter
                .graphs
                .iter()
                .all(|g| graph.contexts.contains_key(g)),
            "Contexte de filtre absent"
        );
        for manifest in &self.retained_manifests {
            crate::config::relative_path(manifest)?;
            ensure!(
                graph
                    .inventory
                    .projects
                    .iter()
                    .any(|p| &p.manifest == manifest),
                "Projet conservé absent : {manifest}"
            );
        }
        let catalog: BTreeMap<_, _> = root_catalog(graph)?
            .into_iter()
            .map(|r| (r.id, r.root))
            .collect();
        let mut counts = BTreeMap::new();
        for root in &graph.roots {
            *counts
                .entry(files::hash(&serde_json::to_vec(root)?))
                .or_insert(0usize) += 1;
        }
        let mut seen = BTreeSet::new();
        for id in &self.remove_roots {
            ensure!(seen.insert(id), "Retrait dupliqué");
            let root = catalog
                .get(id)
                .ok_or_else(|| invalid("Déclaration de retrait inconnue".into()))?;
            ensure!(
                self.includes_root(root),
                "Déclaration exclue du périmètre conservé"
            );
            ensure!(
                counts.get(id) == Some(&1),
                "Déclarations identiques ambiguës : retrait individuel impossible"
            );
        }
        Ok(())
    }
    fn includes_node(&self, node: &NodeRef) -> bool {
        self.filter.graphs.is_empty() || self.filter.graphs.contains(&node.graph)
    }
    fn includes_kind(&self, kind: &str, condition: &Value) -> bool {
        (self.filter.kinds.is_empty() || self.filter.kinds.contains(kind))
            && (self.filter.include_conditional || condition.is_null())
    }
    fn includes_root(&self, root: &Root) -> bool {
        (self.retained_manifests.is_empty() || self.retained_manifests.contains(&root.manifest))
            && self.includes_node(&root.to)
            && self.includes_kind(&root.kind, &root.condition)
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedTarget {
    pub node: NodeRef,
    pub via_roots: Vec<IdentifiedRoot>,
    pub path: Vec<NodeRef>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovalAnalysis {
    pub engine: String,
    pub request: RemovalRequest,
    pub potential: bool,
    pub complete: bool,
    pub truncated: bool,
    pub removed_declarations: Vec<IdentifiedRoot>,
    pub before_reachable: usize,
    pub after_reachable: usize,
    /// Empty on truncation; exact only within the declared static graph and retained scope.
    pub freed_in_model: Vec<NodeRef>,
    pub already_unreachable: Vec<NodeRef>,
    pub retained_removed_targets: Vec<RetainedTarget>,
    pub limitations: Vec<String>,
    pub validation: String,
}
impl Ladybug {
    pub fn simulate_removal(
        &self,
        graph: &Graph,
        request: &RemovalRequest,
    ) -> Result<RemovalAnalysis> {
        request.validate(graph)?;
        let catalog = root_catalog(graph)?;
        let removed: BTreeSet<_> = request.remove_roots.iter().collect();
        let before_roots: Vec<_> = catalog
            .iter()
            .filter(|r| request.includes_root(&r.root))
            .collect();
        let after_roots: Vec<_> = before_roots
            .iter()
            .copied()
            .filter(|r| !removed.contains(&r.id))
            .collect();
        let keys = graph
            .components
            .iter()
            .filter(|n| request.includes_node(&n.key))
            .map(|n| Ok((n.key.engine_key()?, n.key.clone())))
            .collect::<Result<BTreeMap<_, _>>>()?;
        // Non-hex temporary seed identifiers are not packages and never leave the engine model.
        let mut nodes: Vec<_> = keys.keys().map(|id| vec![id.clone()]).collect();
        nodes.extend([vec!["before".into()], vec!["after".into()]]);
        let adjacency: BTreeSet<_> = graph
            .dependencies
            .iter()
            .filter(|e| {
                request.includes_node(&e.from)
                    && request.includes_node(&e.to)
                    && request.includes_kind(&e.kind, &e.condition)
            })
            .map(|e| (&e.from, &e.to))
            .collect();
        let mut edges: Vec<_> = adjacency
            .iter()
            .map(|(a, b)| Ok(vec![a.engine_key()?, b.engine_key()?]))
            .collect::<Result<_>>()?;
        for (seed, roots) in [("before", &before_roots), ("after", &after_roots)] {
            let targets: BTreeSet<_> = roots.iter().map(|r| &r.root.to).collect();
            for to in targets {
                edges.push(vec![seed.into(), to.engine_key()?]);
            }
        }
        let depth = request.max_depth + 2;
        let queries = ["before","after"].map(|seed|format!("MATCH p=(a:Component)-[e:Depends* SHORTEST 1..{depth}]->(b:Component) WHERE a.id='{seed}' AND b.id <> a.id RETURN b.id AS id, length(e) AS distance, properties(nodes(p), 'id') AS path ORDER BY id;"));
        let values = self.execute_graph(&nodes, &edges, depth, &queries)?;
        let mut truncated = false;
        let mut parse = |value: &Value,
                         seed: &str,
                         roots: &[&IdentifiedRoot]|
         -> Result<BTreeMap<NodeRef, Vec<NodeRef>>> {
            let rows = value
                .as_array()
                .ok_or_else(|| invalid("Liste de résultats de retrait requise".into()))?;
            ensure!(
                rows.len() <= keys.len(),
                "Cardinalité de retrait incohérente"
            );
            let lookup = |value: &Value| -> Result<NodeRef> {
                keys.get(
                    value
                        .as_str()
                        .ok_or_else(|| invalid("Identifiant de retrait absent".into()))?,
                )
                .cloned()
                .ok_or_else(|| invalid("Composant de retrait inconnu".into()))
            };
            let mut result = BTreeMap::new();
            let mut seen = BTreeSet::new();
            for row in rows {
                let node = lookup(&row["id"])?;
                let distance = row["distance"]
                    .as_u64()
                    .ok_or_else(|| invalid("Distance de retrait absente".into()))?;
                ensure!(
                    (1..=u64::from(depth)).contains(&distance) && seen.insert(node.clone()),
                    "Distance ou doublon de retrait invalide"
                );
                let raw = row["path"]
                    .as_array()
                    .ok_or_else(|| invalid("Chemin de retrait absent".into()))?;
                ensure!(
                    raw.len() == distance as usize + 1
                        && raw.first().and_then(Value::as_str) == Some(seed),
                    "Chemin de retrait incohérent"
                );
                let path: Vec<_> = raw.iter().skip(1).map(lookup).collect::<Result<_>>()?;
                ensure!(
                    path.last() == Some(&node)
                        && roots.iter().any(|r| Some(&r.root.to) == path.first()),
                    "Chemin de retrait sans racine conservée"
                );
                for pair in path.windows(2) {
                    ensure!(
                        adjacency.contains(&(&pair[0], &pair[1])),
                        "Chemin de retrait hors graphe"
                    );
                }
                if distance > u64::from(request.max_depth) + 1 {
                    truncated = true;
                } else {
                    result.insert(node, path);
                }
            }
            Ok(result)
        };
        let before = parse(&values[0], "before", &before_roots)?;
        let after = parse(&values[1], "after", &after_roots)?;
        let freed = if truncated {
            vec![]
        } else {
            before
                .keys()
                .filter(|n| !after.contains_key(*n))
                .cloned()
                .collect()
        };
        let already_unreachable = if truncated {
            vec![]
        } else {
            keys.values()
                .filter(|n| !before.contains_key(*n))
                .cloned()
                .collect()
        };
        let removed_declarations: Vec<_> = catalog
            .into_iter()
            .filter(|r| removed.contains(&r.id))
            .collect();
        let mut retained_removed_targets = Vec::new();
        let targets: BTreeSet<_> = removed_declarations.iter().map(|r| &r.root.to).collect();
        for node in targets {
            if let Some(path) = after.get(node) {
                let via_roots = root_catalog(graph)?
                    .into_iter()
                    .filter(|r| {
                        !removed.contains(&r.id)
                            && request.includes_root(&r.root)
                            && Some(&r.root.to) == path.first()
                    })
                    .collect();
                retained_removed_targets.push(RetainedTarget {
                    node: node.clone(),
                    via_roots,
                    path: path.clone(),
                });
            }
        }
        let mut limitations = graph.limitations.clone();
        if !graph.inventory.complete {
            limitations.push("Inventaire source partiel".into());
        }
        if truncated {
            limitations.push("Parcours tronqué : aucun gain de composants affirmé".into());
        }
        limitations.push(
            "Simulation du graphe statique ; aucun retrait de manifest ni test projet exécuté"
                .into(),
        );
        Ok(RemovalAnalysis {
            engine: format!("ladybugdb/{ENGINE_VERSION}"),
            request: request.clone(),
            potential: true,
            complete: graph.complete() && !truncated,
            truncated,
            removed_declarations,
            before_reachable: before.len(),
            after_reachable: after.len(),
            freed_in_model: freed,
            already_unreachable,
            retained_removed_targets,
            limitations,
            validation: "not_run".into(),
        })
    }
}
