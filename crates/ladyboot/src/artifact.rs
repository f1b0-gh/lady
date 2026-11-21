//! Explicit bootc artifact construction. Runtime deployment remains in its own adapter.
use nickel_util::{
    error::{Error, Result},
    evaluation::{self, EvaluationRequest},
    files, json,
    process::capture,
    sources,
    sources::Sources,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

macro_rules! ensure {
    ($condition:expr, $($message:tt)*) => {
        if !$condition { return Err(invalid(format!($($message)*))); }
    };
}

#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub config: PathBuf,
    /// Operator-selected trusted recipes, never selected by the Nickel document.
    pub resources: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLock {
    pub schema_version: u32,
    pub profile: String,
    pub configuration: Value,
    pub inputs_sha256: BTreeMap<String, String>,
    pub evaluator: String,
    pub modules_sha256: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    Rootfs,
    BootcImage,
    BootTestRootfs,
    Kernel,
    Initrd,
    Checks,
}
impl Target {
    fn nix_name(self) -> &'static str {
        match self {
            Self::Rootfs => "rootfs",
            Self::BootcImage => "image",
            Self::BootTestRootfs => "bootTestRootfs",
            Self::Kernel => "kernel",
            Self::Initrd => "initrd",
            Self::Checks => "checks",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReceipt {
    pub schema_version: u32,
    pub inputs: ArtifactLock,
    pub target: Target,
    pub store_path: PathBuf,
    pub nar_hash: String,
    #[serde(default)]
    pub rootfs: Option<RootfsReceipt>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsReceipt {
    pub store_path: PathBuf,
    pub nar_hash: String,
    pub inventory_sha256: String,
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
fn source_spec() -> Sources {
    Sources {
        include: ["flake.nix", "flake.lock", "nix", "profiles", "tests"]
            .map(String::from)
            .into(),
        exclude: vec![],
    }
}
fn input_hashes(snapshot: &sources::Snapshot) -> Result<BTreeMap<String, String>> {
    for name in [
        "flake.nix",
        "flake.lock",
        "nix/build.nix",
        "nix/image.nix",
        "profiles/schema.ncl",
    ] {
        ensure!(
            snapshot.contains_key(name),
            "Ressource bootc requise : {name}"
        );
    }
    snapshot
        .iter()
        .map(|(path, record)| Ok((path.clone(), files::hash(&serde_json::to_vec(record)?))))
        .collect()
}
/// Evaluate the public contract without building an image or changing a lock.
pub fn check(request: &ArtifactRequest) -> Result<ArtifactLock> {
    // Never pass the original tree to Nix: flakes copy their source to the public
    // store, including unrelated files that are absent from our input manifest.
    let temporary = tempfile::tempdir()?;
    let recipes = temporary.path().join("recipes");
    fs::create_dir(&recipes)?;
    let before = input_hashes(&sources::snapshot(
        &request.resources,
        &source_spec(),
        Some(&recipes),
    )?)?;
    let evaluated = evaluation::evaluate(&EvaluationRequest {
        entry: &request.config,
        contract: Some(&recipes.join("profiles/schema.ncl")),
        nix: &recipes,
    })?;
    let after = input_hashes(&sources::snapshot(
        &request.resources,
        &source_spec(),
        None,
    )?)?;
    ensure!(before == after, "Ressources modifiées pendant l’évaluation");
    crate::profile::validate(&evaluated.value)?;
    Ok(ArtifactLock {
        schema_version: 1,
        profile: "bootc".into(),
        configuration: evaluated.value,
        inputs_sha256: before,
        evaluator: evaluated.evaluator,
        modules_sha256: evaluated.modules_sha256,
    })
}
pub fn render(request: &ArtifactRequest) -> Result<Value> {
    Ok(check(request)?.configuration)
}
/// Publication is explicit; existing outputs require an explicit replacement request.
pub fn publish(path: &Path, value: &impl Serialize, replace: bool) -> Result<()> {
    files::publish_json(path, value, replace)
}

pub fn lock(request: &ArtifactRequest, destination: &Path, replace: bool) -> Result<ArtifactLock> {
    let value = check(request)?;
    publish(destination, &value, replace)?;
    Ok(value)
}
pub fn verify_lock(expected: &ArtifactLock, actual: &ArtifactLock) -> Result<()> {
    ensure!(
        expected.schema_version == 1 && expected.profile == "bootc",
        "Version/profil du verrou non supporté"
    );
    ensure!(
        expected == actual,
        "Verrou artefact divergent : examiner puis exécuter artifact lock explicitement"
    );
    Ok(())
}
fn selected(request: &ArtifactRequest, path: &Path) -> Result<ArtifactLock> {
    let expected: ArtifactLock =
        serde_json::from_value(json::parse(&files::read_limited(path, 8 * 1024 * 1024)?)?)?;
    let actual = check(request)?;
    verify_lock(&expected, &actual)?;
    Ok(actual)
}
pub fn plan(request: &ArtifactRequest, lock: &Path, target: Target) -> Result<Value> {
    let inputs = selected(request, lock)?;
    let planned = resolve(request, &inputs)?;
    Ok(
        json!({"schema_version":1,"profile":"bootc","target":target,"inputs":inputs,"planned":planned,
              "actions":["stage-verified-inputs","nix-build","record-store-identity"],
              "built":false,"deploys":false}),
    )
}
fn store_path(path: &Path) -> Result<()> {
    ensure!(
        path.starts_with("/nix/store") && path.components().count() == 4 && path.is_absolute(),
        "Chemin store Nix attendu"
    );
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| invalid("Nom store invalide".into()))?;
    ensure!(
        name.len() > 33
            && name.as_bytes()[32] == b'-'
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"+-._?=".contains(&c)),
        "Nom store invalide"
    );
    Ok(())
}
fn identity(path: &Path) -> Result<String> {
    store_path(path)?;
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "path-info",
            "--json",
            "--json-format",
            "1",
        ])
        .arg(path);
    let value = json::parse(&capture(command, Duration::from_secs(60), 1024 * 1024)?)?;
    let key = path
        .to_str()
        .ok_or_else(|| invalid("Chemin non UTF-8".into()))?;
    value[key]["narHash"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| invalid("Identité NAR absente".into()))
}
pub fn build(request: &ArtifactRequest, lock: &Path, target: Target) -> Result<BuildReceipt> {
    let inputs = selected(request, lock)?;
    let temporary = tempfile::tempdir()?;
    let recipes = temporary.path().join("recipes");
    fs::create_dir(&recipes)?;
    let snapshot = sources::snapshot(&request.resources, &source_spec(), Some(&recipes))?;
    ensure!(
        input_hashes(&snapshot)? == inputs.inputs_sha256,
        "Recettes modifiées depuis vérification"
    );
    let config = temporary.path().join("profile.json");
    publish(&config, &inputs.configuration, false)?;
    let store_path = realize(&recipes, &config, target)?;
    let nar_hash = identity(&store_path)?;
    let rootfs = if matches!(target, Target::Rootfs | Target::BootcImage) {
        let path = if target == Target::Rootfs {
            store_path.clone()
        } else {
            realize(&recipes, &config, Target::Rootfs)?
        };
        let observed = crate::inventory::verify(&path)?;
        ensure!(
            observed["resolved_plan"] == resolve(request, &inputs)?,
            "Built rootfs differs from the resolved locked plan"
        );
        Some(RootfsReceipt {
            nar_hash: identity(&path)?,
            store_path: path,
            inventory_sha256: observed["inventory_sha256"]
                .as_str()
                .ok_or_else(|| invalid("Missing inventory digest".into()))?
                .to_owned(),
        })
    } else {
        None
    };
    Ok(BuildReceipt {
        schema_version: 1,
        inputs,
        target,
        store_path,
        nar_hash,
        rootfs,
    })
}

fn realize(recipes: &Path, config: &Path, target: Target) -> Result<PathBuf> {
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--impure",
            "--no-link",
            "--json",
            "--no-write-lock-file",
            "--no-update-lock-file",
            "--file",
        ])
        .arg(recipes.join("nix/build.nix"));
    for (name, value) in [("flakePath", recipes), ("configPath", config)] {
        command.arg("--argstr").arg(name).arg(value);
    }
    command.args(["--argstr", "output", target.nix_name()]);
    let value = json::parse(&capture(
        command,
        Duration::from_secs(1800),
        8 * 1024 * 1024,
    )?)?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("Résultat build Nix invalide".into()))?;
    ensure!(rows.len() == 1, "Une sortie Nix requise");
    let path = rows
        .first()
        .and_then(|row| row["outputs"]["out"].as_str())
        .ok_or_else(|| invalid("Sortie Nix absente".into()))?;
    let store_path = PathBuf::from(path);
    Ok(store_path)
}

pub fn test(request: &ArtifactRequest, lock: &Path) -> Result<BuildReceipt> {
    build(request, lock, Target::Checks)
}
pub fn inspect(path: &Path) -> Result<Value> {
    let receipt: BuildReceipt =
        serde_json::from_value(json::parse(&files::read_limited(path, 8 * 1024 * 1024)?)?)?;
    ensure!(receipt.schema_version == 1, "Version de reçu non supportée");
    verify_lock(&receipt.inputs, &receipt.inputs)?;
    ensure!(
        identity(&receipt.store_path)? == receipt.nar_hash,
        "Identité du store divergente du reçu"
    );
    let observed = if matches!(receipt.target, Target::Rootfs | Target::BootcImage) {
        let rootfs = receipt
            .rootfs
            .as_ref()
            .ok_or_else(|| invalid("Associated rootfs receipt is required".into()))?;
        if receipt.target == Target::Rootfs {
            ensure!(
                rootfs.store_path == receipt.store_path && rootfs.nar_hash == receipt.nar_hash,
                "Rootfs receipt association differs from the primary artifact"
            );
        }
        ensure!(
            identity(&rootfs.store_path)? == rootfs.nar_hash,
            "Associated rootfs NAR identity differs from receipt"
        );
        let observed = crate::inventory::verify(&rootfs.store_path)?;
        ensure!(
            observed["inventory_sha256"].as_str() == Some(rootfs.inventory_sha256.as_str()),
            "Associated rootfs inventory digest differs from receipt"
        );
        ensure!(
            observed["resolved_plan"]["requested"] == receipt.inputs.configuration,
            "Associated rootfs plan differs from locked configuration"
        );
        Some(observed)
    } else {
        ensure!(
            receipt.rootfs.is_none(),
            "Unexpected rootfs association for artifact target"
        );
        None
    };
    Ok(
        json!({"receipt":receipt,"store_identity_matches":true,"observed":observed,"deployment_qualified":false}),
    )
}

/// Three distinct views: requested needs, Nix-resolved selections, verified observations.
pub fn explain(request: &ArtifactRequest, rootfs: Option<&Path>) -> Result<Value> {
    let inputs = check(request)?;
    let planned = resolve(request, &inputs)?;
    let observed = rootfs.map(crate::inventory::verify).transpose()?;
    if let Some(value) = &observed {
        ensure!(
            value["resolved_plan"] == planned,
            "Observed image belongs to a different resolved plan"
        );
    }
    Ok(
        json!({"schema_version":1,"requested":inputs.configuration,"planned":planned,"observed":observed}),
    )
}

fn resolve(request: &ArtifactRequest, inputs: &ArtifactLock) -> Result<Value> {
    let temporary = tempfile::tempdir()?;
    let recipes = temporary.path().join("recipes");
    fs::create_dir(&recipes)?;
    let snapshot = sources::snapshot(&request.resources, &source_spec(), Some(&recipes))?;
    ensure!(
        input_hashes(&snapshot)? == inputs.inputs_sha256,
        "Recipes changed during resolution"
    );
    let config = temporary.path().join("profile.json");
    publish(&config, &inputs.configuration, false)?;
    // These generated paths contain no user-controlled Nix syntax. JSON escaping
    // also quotes whitespace; reject interpolation instead of accepting Nix code.
    let nix_string = |path: &Path| -> Result<String> {
        let text = path
            .to_str()
            .ok_or_else(|| invalid("Non-UTF8 temporary path".into()))?;
        ensure!(
            !text.contains("${"),
            "Unsupported temporary directory interpolation"
        );
        Ok(serde_json::to_string(text)?)
    };
    let apply = format!(
        "f: f {{ flakePath = {}; configPath = {}; output = \"plan\"; }}",
        nix_string(&recipes)?,
        nix_string(&config)?
    );
    let mut command = Command::new("nix");
    command
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "eval",
            "--impure",
            "--json",
            "--option",
            "allow-import-from-derivation",
            "false",
            "--file",
        ])
        .arg(recipes.join("nix/build.nix"))
        .arg("--apply")
        .arg(apply);
    json::parse(&capture(
        command,
        Duration::from_secs(120),
        8 * 1024 * 1024,
    )?)
}
