use super::*;
use crate::deps::{Project, Requirement};
use serde_json::json;

pub fn project(report: Report) -> Result<Graph> {
    Ok(project_with_origins(report)?.graph)
}

pub(crate) struct ProjectedGraph {
    pub graph: Graph,
    /// Original inventory owner and component index, before graph-only identities.
    pub origins: BTreeMap<NodeRef, (String, usize)>,
}

pub(crate) fn project_with_origins(report: Report) -> Result<ProjectedGraph> {
    report.validate()?;
    let mut count = 0usize;
    for project in &report.projects {
        count = count
            .checked_add(project.components.len())
            .ok_or_else(|| invalid("Limite de composants dépassée".into()))?;
        ensure!(count <= MAX_COMPONENTS, "Limite de composants dépassée");
    }
    let manifests = SelectedManifests::new(&report);
    let locals = LocalPackages {
        npm: crate::deps::npm::local::LocalPackages::new(&report),
        python: crate::deps::python::local::LocalPackages::new(&report),
    };
    let owners: BTreeMap<_, _> = report
        .projects
        .iter()
        .map(|project| (project.manifest.as_str(), project))
        .collect();
    let mut graph = Graph {
        schema_version: 1,
        inventory: report.clone(),
        contexts: BTreeMap::new(),
        components: Vec::new(),
        dependencies: Vec::new(),
        roots: Vec::new(),
        limitations: Vec::new(),
    };
    let mut nodes_seen = BTreeMap::new();
    let mut edges_seen = BTreeSet::new();
    let mut projections = BTreeMap::new();
    let mut origins = BTreeMap::new();
    for project in &report.projects {
        let owner_name = project
            .components_from
            .as_deref()
            .unwrap_or(&project.manifest);
        let owner = owners
            .get(owner_name)
            .ok_or_else(|| invalid("Propriétaire de verrou absent".into()))?;
        let projection_project = if matches!(project.ecosystem.as_str(), "rust" | "npm") {
            *owner
        } else {
            project
        };
        let cache_key = projection_project.manifest.as_str();
        if !projections.contains_key(cache_key) {
            let projection = project_components(
                &mut graph,
                projection_project,
                &owner.components,
                &mut nodes_seen,
                &mut edges_seen,
                &mut origins,
                &locals,
            )?;
            projections.insert(cache_key, projection);
        }
        let projection = projections
            .get(cache_key)
            .ok_or_else(|| invalid("Projection de verrou absente".into()))?;
        project_roots(
            &mut graph,
            project,
            &owner.components,
            projection,
            &manifests,
        )?;
    }
    for root in &graph.roots {
        if !root.condition.is_null() {
            graph.limitations.push(format!(
                "{} : conditions racines non évaluées pour {}",
                root.manifest, root.to.purl
            ));
        }
    }
    graph.canonicalize()?;
    graph.limitations.sort();
    graph.limitations.dedup();
    graph.validate()?;
    Ok(ProjectedGraph { graph, origins })
}
struct Projection {
    keys: Vec<Option<NodeRef>>,
    resolver: Resolver,
}

struct LocalPackages {
    npm: crate::deps::npm::local::LocalPackages,
    python: crate::deps::python::local::LocalPackages,
}

fn project_components(
    graph: &mut Graph,
    project: &Project,
    components: &[Component],
    nodes_seen: &mut BTreeMap<NodeRef, String>,
    edges_seen: &mut BTreeSet<String>,
    origins: &mut BTreeMap<NodeRef, (String, usize)>,
    locals: &LocalPackages,
) -> Result<Projection> {
    let mut local_nodes = BTreeSet::new();
    let mut local_edges = BTreeSet::new();
    let resolver = Resolver::new(components);
    let scope = project.lockfile.as_deref().unwrap_or(&project.manifest);
    if !project.locked {
        graph
            .limitations
            .push(format!("{} : verrou absent", project.manifest));
    }
    let mut keys = Vec::new();
    for (index, component) in components.iter().enumerate() {
        validate_metadata(project, component)?;
        if !node_condition(component).is_null() {
            graph.limitations.push(format!(
                "{} : conditions de paquet non évaluées pour {}",
                scope, component.name
            ));
        }
        let mut projected = component.clone();
        if project.ecosystem == "rust" && local_cargo(component) {
            let mut purl = packageurl::PackageUrl::new("generic", &component.name)
                .map_err(|e| invalid(e.to_string()))?;
            purl.with_namespace("cargo-local")
                .map_err(|e| invalid(e.to_string()))?;
            purl.with_version(&component.version)
                .map_err(|e| invalid(e.to_string()))?;
            projected.purl = Some(purl.to_string());
        }
        let local = locals.npm.qualified(project, component);
        if project.ecosystem == "npm" && crate::deps::npm::local::is_local(component) {
            projected.purl = local.map(|identity| identity.purl()).transpose()?;
        }
        let python_local = locals.python.qualified(project, component);
        if project.ecosystem == "python" && crate::deps::python::local::is_local(project, component)
        {
            projected.purl = python_local.map(|identity| identity.purl()).transpose()?;
        }
        let Some(purl) = &projected.purl else {
            keys.push(None);
            graph.limitations.push(format!(
                "{} : composant sans PURL {} ({}) conservé dans l'inventaire",
                scope, component.name, component.context
            ));
            continue;
        };
        let native = match project.ecosystem.as_str() {
            "npm" if local.is_some() => {
                let identity = local.ok_or_else(|| invalid("Identité locale absente".into()))?;
                json!({"local_source":identity.source,"installation_path":component.context})
            }
            "npm" => {
                let (scope, alias) = component
                    .context
                    .rsplit_once("node_modules/")
                    .unwrap_or(("", &component.context));
                json!({"installation_scope":scope,"alias":if alias == component.name {None} else {Some(alias)}})
            }
            "python" => {
                let mut native = json!({"source":component.source,"resolution_markers":component.metadata.get("resolution-markers")});
                if let Some(identity) = python_local {
                    native["local_source"] = Value::String(identity.source.clone());
                }
                native
            }
            _ => json!({"source":component.source}),
        };
        let context = Context {
            manifest: if matches!(project.ecosystem.as_str(), "rust" | "npm") {
                // Shared workspace locks form one graph; member requirements
                // remain separate roots, not duplicate copies of that graph.
                project
                    .lockfile
                    .as_deref()
                    .and_then(|p| p.rsplit_once('/').map(|(parent, _)| format!("{parent}/")))
                    .or_else(|| project.lockfile.as_ref().map(|_| String::new()))
                    .map(|parent| {
                        format!(
                            "{parent}{}",
                            if project.ecosystem == "rust" {
                                "Cargo.toml"
                            } else {
                                "package.json"
                            }
                        )
                    })
                    .unwrap_or_else(|| project.manifest.clone())
            } else {
                project.manifest.clone()
            },
            native,
        };
        let path = context.path()?;
        graph.contexts.insert(path.clone(), context);
        let key = NodeRef {
            graph: path,
            purl: purl.clone(),
        };
        origins.entry(key.clone()).or_insert_with(|| {
            (
                project
                    .components_from
                    .as_ref()
                    .unwrap_or(&project.manifest)
                    .clone(),
                index,
            )
        });
        keys.push(Some(key.clone()));
        ensure!(
            local_nodes.insert(key.clone()),
            "Composant dupliqué dans le projet"
        );
        let content = serde_json::to_string(&projected)?;
        if let Some(previous) = nodes_seen.get(&key) {
            ensure!(
                *previous == content,
                "Composant divergent dans un verrou partagé"
            );
        } else {
            nodes_seen.insert(key.clone(), content);
            ensure!(
                graph.components.len() < MAX_COMPONENTS,
                "Limite de composants dépassée"
            );
            graph.components.push(Node {
                key,
                component: projected,
            });
        }
    }
    for (i, component) in components.iter().enumerate() {
        if let Some(identity) = locals
            .npm
            .qualified(project, component)
            .filter(|identity| identity.link)
        {
            if let (Some(from), Some(to)) = (
                &keys[i],
                resolver
                    .paths
                    .get(&identity.target)
                    .and_then(|target| keys[*target].as_ref()),
            ) {
                let target = &components[resolver.paths[&identity.target]];
                let from_condition = node_condition(component);
                let to_condition = node_condition(target);
                let condition = if from_condition.is_null() && to_condition.is_null() {
                    Value::Null
                } else {
                    graph.limitations.push(format!(
                        "{scope} : conditions du lien local non évaluées {}",
                        component.context
                    ));
                    json!({"from":from_condition,"to":to_condition})
                };
                let edge = Edge {
                    from: from.clone(),
                    to: to.clone(),
                    kind: "link".into(),
                    condition,
                    evidence: component.metadata.clone(),
                };
                if edges_seen.insert(serde_json::to_string(&edge)?) {
                    ensure!(
                        graph.dependencies.len() < MAX_EDGES,
                        "Limite de relations dépassée"
                    );
                    graph.dependencies.push(edge);
                }
            }
            continue;
        }
        let mut requests = Vec::new();
        match project.ecosystem.as_str() {
            "npm" => {
                for (field, kind) in [
                    ("dependencies", "runtime"),
                    ("optionalDependencies", "optional"),
                    ("peerDependencies", "peer"),
                ] {
                    if let Some(deps) = component.metadata[field].as_object() {
                        for (name, constraint) in deps {
                            // optionalDependencies overrides dependencies in npm.
                            if field == "dependencies"
                                && component.metadata["optionalDependencies"]
                                    .get(name)
                                    .is_some()
                            {
                                continue;
                            }
                            requests.push((
                                name.clone(),
                                kind.to_owned(),
                                if kind == "optional"
                                    || component.metadata["peerDependenciesMeta"][name]["optional"]
                                        == true
                                {
                                    json!({"optional":true})
                                } else {
                                    Value::Null
                                },
                                json!({"name":name,"constraint":constraint}),
                            ));
                        }
                    }
                }
            }
            "rust" | "python" => {
                if let Some(deps) = component.metadata["dependencies"].as_array() {
                    for dep in deps {
                        let condition = if project.ecosystem == "rust" {
                            json!({"cargo_features_targets_kinds":"unresolved"})
                        } else {
                            python_condition(component, dep, None)
                        };
                        requests.push((
                            dep["name"].as_str().unwrap_or("").into(),
                            if project.ecosystem == "rust" {
                                "unknown"
                            } else {
                                "runtime"
                            }
                            .into(),
                            condition,
                            dep.clone(),
                        ));
                    }
                }
                if project.ecosystem == "python" {
                    for (field, kind) in [
                        ("optional-dependencies", "extra"),
                        ("dev-dependencies", "group"),
                    ] {
                        if let Some(groups) = component.metadata[field].as_object() {
                            for (group, deps) in groups {
                                if let Some(deps) = deps.as_array() {
                                    for dep in deps {
                                        requests.push((
                                            dep["name"].as_str().unwrap_or("").into(),
                                            format!("{kind}:{group}"),
                                            python_condition(component, dep, Some(group)),
                                            dep.clone(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            other => graph
                .limitations
                .push(format!("Projection non qualifiée : {other}")),
        }
        for (name, kind, mut condition, evidence) in requests {
            let targets = resolver.resolve(project, components, Some(i), &name, &evidence);
            if targets.len() != 1 || keys[targets[0]].is_none() {
                graph.limitations.push(format!(
                    "{} : référence non résolue sans ambiguïté {} -> {name}",
                    scope, component.name
                ));
                continue;
            }
            let Some(to) = keys[targets[0]].clone() else {
                continue;
            };
            if project.ecosystem == "npm"
                && !compatible(
                    "npm",
                    &components[targets[0]],
                    evidence["constraint"].as_str().unwrap_or(""),
                )
                .unwrap_or(false)
            {
                graph.limitations.push(format!(
                    "{} : contrainte non satisfaite ou non qualifiée pour {} -> {name}",
                    scope, component.name
                ));
                continue;
            }
            let from_condition = node_condition(component);
            let to_condition = node_condition(&components[targets[0]]);
            if !from_condition.is_null() || !to_condition.is_null() {
                condition = json!({"edge":condition,"from":from_condition,"to":to_condition});
            }
            if !condition.is_null() {
                graph.limitations.push(format!(
                    "{} : conditions non évaluées pour {} -> {name}",
                    scope, component.name
                ));
            }
            if let Some(from) = &keys[i] {
                let edge = Edge {
                    from: from.clone(),
                    to,
                    kind,
                    condition,
                    evidence,
                };
                let content = serde_json::to_string(&edge)?;
                ensure!(
                    local_edges.insert(content.clone()),
                    "Relation dupliquée dans le projet"
                );
                if edges_seen.insert(content) {
                    ensure!(
                        graph.dependencies.len() < MAX_EDGES,
                        "Limite de relations dépassée"
                    );
                    graph.dependencies.push(edge);
                }
            }
        }
    }
    Ok(Projection { keys, resolver })
}

fn project_roots(
    graph: &mut Graph,
    project: &Project,
    components: &[Component],
    projection: &Projection,
    manifests: &SelectedManifests<'_>,
) -> Result<()> {
    let Projection { keys, resolver } = projection;
    for requirement in &project.requirements {
        if requirement.kind.ends_with(":include") {
            graph.limitations.push(format!(
                "{} : inclusion de groupe non développée : {}",
                project.manifest, requirement.name
            ));
            continue;
        }
        if (project.ecosystem == "python" && !requirement.source.is_null())
            || (project.ecosystem == "rust"
                && ["registry", "registry-index"]
                    .iter()
                    .any(|field| requirement.source.get(*field).is_some()))
        {
            graph.limitations.push(format!(
                "{} : source d'exigence non qualifiée pour {}",
                project.manifest, requirement.name
            ));
            continue;
        }
        // Cargo aliases carry the actual package name in source.package.
        let name = requirement
            .source
            .get("package")
            .and_then(Value::as_str)
            .unwrap_or(&requirement.name);
        let targets: Vec<_> = if project.ecosystem == "rust"
            && requirement.source.get("git").is_some()
        {
            resolver
                .names
                .get(name)
                .into_iter()
                .flatten()
                .copied()
                .filter(|i| {
                    crate::deps::rust::git::requirement_matches(
                        &requirement.source,
                        &components[*i].source,
                    ) && (requirement.constraint.is_empty()
                        || compatible("rust", &components[*i], &requirement.constraint)
                            .unwrap_or(false))
                })
                .collect()
        } else if project.ecosystem == "rust" && requirement.source.get("path").is_some() {
            manifests.local_targets(project, requirement, components, resolver)
        } else {
            let evidence = if project.ecosystem == "rust" {
                json!({"name":name,"source":"registry+https://github.com/rust-lang/crates.io-index"})
            } else {
                json!({"name":name})
            };
            resolver
                .resolve(project, components, None, name, &evidence)
                .into_iter()
                .filter(|i| {
                    compatible(&project.ecosystem, &components[*i], &requirement.constraint)
                        .unwrap_or(false)
                })
                .collect()
        };
        if targets.len() == 1 {
            if let Some(to) = &keys[targets[0]] {
                ensure!(graph.roots.len() < MAX_EDGES, "Limite de racines dépassée");
                graph.roots.push(Root {
                    manifest: project.manifest.clone(),
                    native: None,
                    to: to.clone(),
                    kind: requirement.kind.clone(),
                    condition: if requirement.marker.is_some()
                        || !requirement.extras.is_empty()
                        || project.ecosystem == "rust"
                        || requirement.kind.starts_with("extra:")
                        || requirement.kind == "optional"
                    {
                        serde_json::to_value(requirement)?
                    } else {
                        node_condition(&components[targets[0]])
                    },
                });
                continue;
            }
        }
        graph.limitations.push(format!(
            "{} : exigence racine non résolue sans ambiguïté : {name}",
            project.manifest
        ));
    }
    Ok(())
}

fn local_cargo(component: &Component) -> bool {
    component.source.is_null()
        && component.context == "workspace"
        && component.metadata.get("source").is_none_or(Value::is_null)
        && component.metadata["name"] == component.name
        && component.metadata["version"] == component.version
}

struct SelectedManifests<'a> {
    paths: BTreeMap<&'a str, &'a Project>,
    identities: BTreeMap<(Option<&'a str>, &'a str, &'a str), usize>,
}
impl<'a> SelectedManifests<'a> {
    fn new(report: &'a Report) -> Self {
        let mut paths = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for project in &report.projects {
            if project.ecosystem != "rust" || !report.inputs.contains_key(&project.manifest) {
                continue;
            }
            paths.insert(project.manifest.as_str(), project);
            if let Some(package) = &project.manifest_package {
                *identities
                    .entry((
                        project.lockfile.as_deref(),
                        package.name.as_str(),
                        package.version.as_str(),
                    ))
                    .or_default() += 1;
            }
        }
        Self { paths, identities }
    }

    fn local_targets(
        &self,
        project: &Project,
        requirement: &Requirement,
        components: &[Component],
        resolver: &Resolver,
    ) -> Vec<usize> {
        let Some(origin) = requirement.source["_ladybom_declaration_manifest"].as_str() else {
            return Vec::new();
        };
        let Some(declaration) = self.paths.get(origin) else {
            return Vec::new();
        };
        // An inherited path must come from the selected workspace declaration,
        // not an arbitrary selected manifest named by opaque source metadata.
        if origin != project.manifest {
            let alias = requirement
                .declared_name
                .as_deref()
                .unwrap_or(&requirement.name);
            let inherited = &declaration.workspace["dependencies"][alias];
            if declaration.lockfile != project.lockfile
                || inherited.get("path") != requirement.source.get("path")
                || inherited.get("package") != requirement.source.get("package")
            {
                return Vec::new();
            }
        }
        let Some(path) = requirement.source["path"].as_str() else {
            return Vec::new();
        };
        let Some(manifest) = dependency_manifest(origin, path) else {
            return Vec::new();
        };
        let Some(target) = self.paths.get(manifest.as_str()) else {
            return Vec::new();
        };
        let Some(package) = &target.manifest_package else {
            return Vec::new();
        };
        if package.name != requirement.name
            || self
                .identities
                .get(&(
                    project.lockfile.as_deref(),
                    package.name.as_str(),
                    package.version.as_str(),
                ))
                .is_some_and(|count| *count > 1)
            || (!requirement.constraint.is_empty()
                && !crate::deps::constraints::rust_matches(
                    &package.version,
                    &requirement.constraint,
                )
                .unwrap_or(false))
        {
            return Vec::new();
        }
        resolver
            .resolve(
                project,
                components,
                None,
                &package.name,
                &json!({"name":package.name,"version":package.version,"source":null}),
            )
            .into_iter()
            .filter(|i| local_cargo(&components[*i]))
            .collect()
    }
}

/// Lexically resolve a Cargo path against its declaration, without accessing
/// files or executing Cargo. Only selected manifests can satisfy the result.
fn dependency_manifest(origin: &str, dependency: &str) -> Option<String> {
    if dependency.is_empty()
        || dependency.starts_with('/')
        || dependency.contains('\\')
        || dependency.contains(':')
        || dependency.chars().any(char::is_control)
    {
        return None;
    }
    let mut parts: Vec<_> = origin
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent)
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    for part in dependency.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    parts.push("Cargo.toml");
    Some(parts.join("/"))
}

fn compatible(ecosystem: &str, component: &Component, constraint: &str) -> Result<bool> {
    use crate::deps::constraints::{npm_matches, python_matches, rust_matches};
    match ecosystem {
        "rust" => rust_matches(&component.version, constraint),
        "python" => python_matches(&component.version, constraint),
        "npm" => {
            if let Some(alias) = constraint.strip_prefix("npm:") {
                let (name, range) = alias
                    .rsplit_once('@')
                    .filter(|(name, _)| !name.is_empty())
                    .unwrap_or((alias, "*"));
                Ok(component.name == name && npm_matches(&component.version, range)?)
            } else {
                npm_matches(&component.version, constraint)
            }
        }
        _ => Ok(false),
    }
}
fn python_condition(component: &Component, dep: &Value, group: Option<&str>) -> Value {
    let markers = component.metadata.get("resolution-markers");
    if dep.get("marker").is_none()
        && dep.get("extra").is_none()
        && markers.is_none()
        && group.is_none()
    {
        Value::Null
    } else {
        json!({"marker":dep.get("marker"),"extra":dep.get("extra"),"resolution_markers":markers,"group":group})
    }
}
struct Resolver {
    paths: BTreeMap<String, usize>,
    names: BTreeMap<String, Vec<usize>>,
}
impl Resolver {
    fn new(components: &[Component]) -> Self {
        let mut paths = BTreeMap::new();
        let mut names: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (i, c) in components.iter().enumerate() {
            paths.insert(c.context.clone(), i);
            names.entry(c.name.clone()).or_default().push(i);
        }
        Self { paths, names }
    }
    fn resolve(
        &self,
        project: &Project,
        components: &[Component],
        from: Option<usize>,
        name: &str,
        dep: &Value,
    ) -> Vec<usize> {
        if project.ecosystem == "npm" {
            let root_scope = project.lockfile.as_deref().map_or("", |lock| {
                let parent = lock.rsplit_once('/').map_or("", |(parent, _)| parent);
                if project.root == "." || project.root == parent {
                    ""
                } else if parent.is_empty() {
                    project.root.as_str()
                } else {
                    project
                        .root
                        .strip_prefix(parent)
                        .and_then(|rest| rest.strip_prefix('/'))
                        .unwrap_or("")
                }
            });
            let mut scope = from.map_or(root_scope, |i| components[i].context.as_str());
            loop {
                if !scope.ends_with("node_modules") {
                    let path = if scope.is_empty() {
                        format!("node_modules/{name}")
                    } else {
                        format!("{scope}/node_modules/{name}")
                    };
                    if let Some(i) = self.paths.get(&path) {
                        return vec![*i];
                    }
                }
                if scope.is_empty() {
                    break;
                }
                scope = scope.rsplit_once('/').map_or("", |(parent, _)| parent);
            }
            return Vec::new();
        }
        self.names
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|i| {
                let c = &components[*i];
                dep.get("version")
                    .and_then(Value::as_str)
                    .is_none_or(|v| c.version == v)
                    && dep
                        .get("source")
                        .filter(|v| project.ecosystem == "rust" || !v.is_null())
                        .is_none_or(|s| {
                            if project.ecosystem == "rust" {
                                crate::deps::rust::git::dependency_source_matches(&c.source, s)
                            } else {
                                c.source == *s
                            }
                        })
            })
            .collect()
    }
}
fn node_condition(component: &Component) -> Value {
    let mut conditions = serde_json::Map::new();
    for field in [
        "os",
        "cpu",
        "libc",
        "resolution-markers",
        "optional",
        "devOptional",
    ] {
        if let Some(value) = component.metadata.get(field) {
            if !value.is_null() && value != &Value::Bool(false) {
                conditions.insert(field.into(), value.clone());
            }
        }
    }
    if conditions.is_empty() {
        Value::Null
    } else {
        Value::Object(conditions)
    }
}
fn validate_metadata(project: &Project, component: &Component) -> Result<()> {
    ensure!(
        component.metadata.is_object(),
        "Métadonnées de paquet invalides"
    );
    if project.ecosystem == "rust" {
        crate::deps::rust::git::validate_component(component)?;
    }
    let fields: &[&str] = if project.ecosystem == "npm" {
        &["dependencies", "optionalDependencies", "peerDependencies"]
    } else {
        &["dependencies"]
    };
    for field in fields {
        if let Some(value) = component.metadata.get(*field) {
            if project.ecosystem == "npm" {
                ensure!(
                    value
                        .as_object()
                        .is_some_and(|v| v.values().all(Value::is_string)),
                    "Table de dépendances npm invalide"
                );
            } else {
                ensure!(
                    value.as_array().is_some_and(|v| v.iter().all(|d| d
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|n| !n.is_empty()))),
                    "Liste de dépendances invalide"
                );
            }
        }
    }
    for field in ["optional-dependencies", "dev-dependencies"] {
        if let Some(value) = component.metadata.get(field) {
            ensure!(
                value
                    .as_object()
                    .is_some_and(
                        |groups| groups
                            .values()
                            .all(|deps| deps.as_array().is_some_and(|items| items
                                .iter()
                                .all(|d| d.get("name").and_then(Value::as_str).is_some())))
                    ),
                "Groupes de dépendances invalides"
            );
        }
    }
    Ok(())
}
