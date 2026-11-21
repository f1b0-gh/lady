//! Controller-owned write-ahead audit journal. Recovery records interruption;
//! it never starts an invocation or adopts/deletes an external resource.
use super::{
    invalid,
    model::{Budget, InvocationStatus, Role, RunStatus},
};
use crate::{error::Result, files, state::StateLock};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{File, Metadata, Permissions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

const JOURNAL_FILE: &str = "audit-journal.json";
const JOURNAL_LIMIT: usize = 4 * 1024 * 1024;
const INVOCATION_LIMIT: usize = 4096;
const RESOURCE_LIMIT: usize = 1024;
const OBLIGATION_LIMIT: usize = 1024;
const TEXT_LIMIT: usize = 4096;
const CONTEXT_LIMIT: usize = 64 * 1024;
const RECOVERY_OBLIGATION: &str =
    "Exécution interrompue : réobserver les ressources et les garanties avant toute résolution";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalData {
    pub schema_version: u32,
    pub run_id: String,
    pub plan_sha256: String,
    pub status: RunStatus,
    pub budget: Budget,
    pub invocations: Vec<JournalInvocation>,
    pub resources: Vec<ResourceRecord>,
    pub open_obligations: Vec<String>,
    pub environment_verified: bool,
    pub cleanup_verified: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JournalInvocation {
    pub id: String,
    pub role: Role,
    #[serde(deserialize_with = "Option::deserialize")]
    pub status: Option<InvocationStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRecord {
    pub name: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub id: Option<String>,
    pub owner: String,
    pub context: Value,
    pub deleted: bool,
}

pub struct RunJournal {
    directory: PathBuf,
    root: File,
    _lock: StateLock,
    data: JournalData,
    // A failed fsync after rename leaves durability uncertain. No later effect
    // may rely on the old in-memory accounting; reopening is then mandatory.
    poisoned: bool,
}

impl RunJournal {
    /// Creates a new retained directory beneath an existing trusted parent.
    pub fn create(parent: &Path, plan_sha256: &str, budget: Budget) -> Result<Self> {
        validate_budget(&budget)?;
        validate_digest(plan_sha256)?;
        let parent = files::absolute(parent)?;
        let parent_fd = files::open_directory(&parent)?;
        trusted_directory(&parent_fd, false)?;
        let created = tempfile::Builder::new()
            .prefix("audit-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(fd_path(&parent_fd))?
            .keep();
        let name = created
            .file_name()
            .ok_or_else(|| invalid("Nom du dossier d’audit absent"))?;
        let directory = parent.join(name);
        let root = files::open_child(&parent_fd, name, true)?;
        parent_fd.sync_all()?;
        let lock = acquire_lock(&directory, &root)?;
        // tempfile names may contain uppercase letters, whereas published run
        // identifiers use the stricter controller identifier grammar. Hash the
        // complete case-sensitive name instead of folding distinct names.
        let run_id = format!("audit-{}", &files::hash(name.as_encoded_bytes())[..32]);
        crate::config::identifier(&run_id)?;
        let data = JournalData {
            schema_version: 1,
            run_id,
            plan_sha256: plan_sha256.to_owned(),
            status: RunStatus::Planned,
            budget,
            invocations: Vec::new(),
            resources: Vec::new(),
            open_obligations: Vec::new(),
            environment_verified: false,
            cleanup_verified: true,
        };
        validate(&data)?;
        let journal = Self {
            directory,
            root,
            _lock: lock,
            data,
            poisoned: false,
        };
        journal.persist(&journal.data, true)?;
        Ok(journal)
    }

    /// Loads strictly under the exclusive lock; a running journal becomes
    /// interrupted durably before this method returns. No effect is replayed.
    pub fn open(directory: &Path) -> Result<Self> {
        let directory = files::absolute(directory)?;
        let root = files::open_directory(&directory)?;
        let lock = acquire_lock(&directory, &root)?;
        let file = journal_file(&root)?;
        let bytes = files::read_file(file, JOURNAL_LIMIT)?;
        let data: JournalData = serde_json::from_value(crate::json::parse(&bytes)?)?;
        validate(&data)?;
        let mut journal = Self {
            directory,
            root,
            _lock: lock,
            data,
            poisoned: false,
        };
        if journal.data.status == RunStatus::Running {
            journal.commit(interrupted_snapshot(&journal.data))?;
        }
        Ok(journal)
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn data(&self) -> &JournalData {
        &self.data
    }

    pub fn start(&mut self) -> Result<()> {
        self.writable()?;
        if self.data.status != RunStatus::Planned {
            return Err(invalid("Seul un audit planifié peut démarrer"));
        }
        let mut next = self.data.clone();
        next.status = RunStatus::Running;
        self.commit(next)
    }

    /// Consumes one attempt durably before the controller may launch it.
    pub fn begin_invocation(&mut self, id: &str, role: Role) -> Result<()> {
        self.running()?;
        identifier(id)?;
        if self.data.invocations.len() >= self.data.budget.invocations as usize
            || self.data.invocations.iter().any(|item| item.id == id)
        {
            return Err(invalid(
                "Budget épuisé ou identifiant d’invocation réutilisé",
            ));
        }
        let mut next = self.data.clone();
        next.invocations.push(JournalInvocation {
            id: id.to_owned(),
            role,
            status: None,
        });
        self.commit(next)
    }

    pub fn finish_invocation(&mut self, id: &str, status: InvocationStatus) -> Result<()> {
        self.running()?;
        let mut next = self.data.clone();
        let invocation = next
            .invocations
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| invalid("Invocation inconnue"))?;
        if invocation.status.is_some() {
            return Err(invalid("Invocation déjà terminée"));
        }
        invocation.status = Some(status);
        self.commit(next)
    }

    /// Must return successfully before the controller creates the resource.
    pub fn resource_intent(&mut self, name: &str, owner: &str, context: Value) -> Result<()> {
        self.running()?;
        if self.data.resources.iter().any(|entry| entry.name == name) {
            return Err(invalid("Nom de ressource réutilisé"));
        }
        let mut next = self.data.clone();
        next.resources.push(ResourceRecord {
            name: name.to_owned(),
            id: None,
            owner: owner.to_owned(),
            context,
            deleted: false,
        });
        self.commit(next)
    }

    /// During recovery, the controller must reobserve the exact owner and
    /// context before assigning an ID to an existing unresolved intent.
    /// Failed, blocked and partial runs may still require explicit cleanup.
    pub fn resource_created(&mut self, name: &str, id: &str) -> Result<()> {
        self.writable()?;
        if !matches!(
            self.data.status,
            RunStatus::Running
                | RunStatus::Interrupted
                | RunStatus::Failed
                | RunStatus::Blocked
                | RunStatus::Partial
        ) {
            return Err(invalid("Intention active ou nettoyage explicite requis"));
        }
        let mut next = self.data.clone();
        let resource = resource_mut(&mut next, name)?;
        if resource.id.is_some() || resource.deleted {
            return Err(invalid(
                "Identité de ressource déjà attribuée ou intention résolue",
            ));
        }
        resource.id = Some(id.to_owned());
        self.commit(next)
    }

    /// Records the controller's verified deletion of this exact resource.
    /// Terminal interrupted/failed runs remain eligible for explicit cleanup.
    pub fn resource_deleted(&mut self, name: &str, id: &str) -> Result<()> {
        self.writable()?;
        let mut next = self.data.clone();
        let resource = resource_mut(&mut next, name)?;
        if resource.deleted || resource.id.as_deref() != Some(id) {
            return Err(invalid(
                "Suppression non vérifiée : identité de ressource divergente",
            ));
        }
        resource.deleted = true;
        self.commit(next)
    }

    /// The controller must first independently verify that the intended
    /// resource is absent. An unknown ID alone never establishes cleanup.
    pub fn resolve_absent_intent(&mut self, name: &str) -> Result<()> {
        self.writable()?;
        let mut next = self.data.clone();
        let resource = resource_mut(&mut next, name)?;
        if resource.id.is_some() || resource.deleted {
            return Err(invalid(
                "Résolution d’absence réservée aux intentions sans identité",
            ));
        }
        resource.deleted = true;
        self.commit(next)
    }

    pub fn add_obligation(&mut self, obligation: &str) -> Result<()> {
        self.writable()?;
        bounded_text(obligation)?;
        // Keep a slot for the recovery obligation even at the configured cap.
        if self.data.open_obligations.len() >= OBLIGATION_LIMIT - 1 {
            return Err(invalid("Trop d’obligations ouvertes"));
        }
        if self
            .data
            .open_obligations
            .iter()
            .any(|entry| entry == obligation)
        {
            return Err(invalid("Obligation déjà enregistrée"));
        }
        let mut next = self.data.clone();
        next.open_obligations.push(obligation.to_owned());
        self.commit(next)
    }

    /// Records a live controller observation, never a claim from agent output.
    pub fn observe_environment(&mut self) -> Result<()> {
        self.running()?;
        let mut next = self.data.clone();
        next.environment_verified = true;
        self.commit(next)
    }

    pub fn finish(&mut self, status: RunStatus) -> Result<()> {
        self.writable()?;
        if !matches!(self.data.status, RunStatus::Planned | RunStatus::Running)
            || matches!(status, RunStatus::Planned | RunStatus::Running)
        {
            return Err(invalid("Transition terminale d’audit interdite"));
        }
        if status == RunStatus::Complete && self.data.status != RunStatus::Running {
            return Err(invalid("Un audit non démarré ne peut pas être complet"));
        }
        let mut next = self.data.clone();
        next.status = status;
        if next.status != RunStatus::Complete {
            interrupt_pending(&mut next);
        }
        self.commit(next)
    }

    fn writable(&self) -> Result<()> {
        if self.poisoned {
            return Err(invalid(
                "Écriture incertaine du journal : fermer et réouvrir le run",
            ));
        }
        if self.data.status == RunStatus::Complete {
            return Err(invalid("Audit complet immuable"));
        }
        Ok(())
    }

    fn running(&self) -> Result<()> {
        self.writable()?;
        if self.data.status != RunStatus::Running {
            return Err(invalid("Audit en cours requis"));
        }
        Ok(())
    }

    fn commit(&mut self, mut next: JournalData) -> Result<()> {
        self.writable()?;
        next.cleanup_verified = next.resources.iter().all(|resource| resource.deleted);
        validate(&next)?;
        if let Err(error) = self.persist(&next, false) {
            self.poisoned = true;
            return Err(error);
        }
        self.data = next;
        Ok(())
    }

    fn persist(&self, next: &JournalData, initial: bool) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(next)?;
        bytes.push(b'\n');
        if bytes.len() > JOURNAL_LIMIT {
            return Err(invalid("Journal d’audit trop volumineux"));
        }
        if next.status == RunStatus::Running
            && serde_json::to_vec_pretty(&interrupted_snapshot(next))?.len() >= JOURNAL_LIMIT
        {
            return Err(invalid(
                "Journal trop volumineux pour enregistrer une interruption",
            ));
        }
        let directory = fd_path(&self.root);
        let destination = directory.join(JOURNAL_FILE);
        if !initial {
            // Inspect relative to the pinned directory; refuse special types,
            // links and permissive modes instead of replacing them silently.
            journal_file(&self.root)?;
        }
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        if initial {
            temporary.persist_noclobber(&destination)
        } else {
            journal_file(&self.root)?;
            temporary.persist(&destination)
        }
        .map_err(|error| crate::error::Error::PathIo {
            path: self.directory.join(JOURNAL_FILE),
            source: error.error,
        })?;
        self.root.sync_all()?;
        Ok(())
    }
}

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

fn trusted_directory(directory: &File, private: bool) -> Result<()> {
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        return Err(invalid(format!(
            "Dossier d’audit non privé ou propriétaire divergent (mode {:o}, uid {})",
            metadata.mode() & 0o777,
            metadata.uid()
        )));
    }
    Ok(())
}

fn private_regular(metadata: &Metadata) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(invalid(
            "Fichier d’audit non privé, partagé ou non régulier",
        ));
    }
    Ok(())
}

fn acquire_lock(directory: &Path, root: &File) -> Result<StateLock> {
    trusted_directory(root, true)?;
    let lock = StateLock::acquire(directory)?;
    let observed = files::open_directory(directory)?.metadata()?;
    let pinned = root.metadata()?;
    if observed.dev() != pinned.dev() || observed.ino() != pinned.ino() {
        return Err(invalid("Dossier d’audit remplacé pendant le verrouillage"));
    }
    private_regular(&files::open_child(root, ".lock".as_ref(), false)?.metadata()?)?;
    Ok(lock)
}

fn journal_file(root: &File) -> Result<File> {
    let file = files::open_child(root, JOURNAL_FILE.as_ref(), false)?;
    private_regular(&file.metadata()?)?;
    Ok(file)
}

fn resource_mut<'a>(data: &'a mut JournalData, name: &str) -> Result<&'a mut ResourceRecord> {
    data.resources
        .iter_mut()
        .find(|resource| resource.name == name)
        .ok_or_else(|| invalid("Ressource inconnue"))
}

fn interrupt_pending(data: &mut JournalData) {
    for invocation in &mut data.invocations {
        if invocation.status.is_none() {
            invocation.status = Some(InvocationStatus::Interrupted);
        }
    }
}

fn interrupted_snapshot(data: &JournalData) -> JournalData {
    let mut next = data.clone();
    next.status = RunStatus::Interrupted;
    interrupt_pending(&mut next);
    if !next
        .open_obligations
        .iter()
        .any(|entry| entry == RECOVERY_OBLIGATION)
    {
        next.open_obligations.push(RECOVERY_OBLIGATION.into());
    }
    next
}

fn identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(invalid("Identifiant d’audit invalide ou trop long"));
    }
    Ok(())
}

fn bounded_text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > TEXT_LIMIT || value.chars().any(char::is_control) {
        return Err(invalid(
            "Texte du journal vide, trop long ou contenant un contrôle",
        ));
    }
    Ok(())
}

fn validate_budget(budget: &Budget) -> Result<()> {
    if budget.invocations == 0
        || budget.invocations as usize > INVOCATION_LIMIT
        || budget.seconds == 0
    {
        return Err(invalid("Budget du journal nul ou dépassant le plafond"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("Empreinte de plan SHA-256 invalide"));
    }
    Ok(())
}

fn validate(data: &JournalData) -> Result<()> {
    if data.schema_version != 1 {
        return Err(invalid("Version du journal d’audit incompatible"));
    }
    identifier(&data.run_id)?;
    validate_digest(&data.plan_sha256)?;
    validate_budget(&data.budget)?;
    if data.invocations.len() > data.budget.invocations as usize
        || data.resources.len() > RESOURCE_LIMIT
        || data.open_obligations.len() > OBLIGATION_LIMIT
    {
        return Err(invalid(
            "Décompte du journal au-delà du budget ou des plafonds",
        ));
    }
    let mut invocations = BTreeSet::new();
    for invocation in &data.invocations {
        identifier(&invocation.id)?;
        if !invocations.insert(&invocation.id)
            || (invocation.status.is_none() && data.status != RunStatus::Running)
        {
            return Err(invalid(
                "Invocation dupliquée ou état d’invocation incohérent",
            ));
        }
    }
    let mut resources = BTreeSet::new();
    for resource in &data.resources {
        identifier(&resource.name)?;
        bounded_text(&resource.owner)?;
        if let Some(id) = &resource.id {
            bounded_text(id)?;
        }
        if !resources.insert(&resource.name) {
            return Err(invalid("Nom de ressource dupliqué"));
        }
        let context = serde_json::to_vec(&resource.context)?;
        if context.len() > CONTEXT_LIMIT {
            return Err(invalid("Contexte de ressource trop volumineux"));
        }
        crate::json::parse(&context)?;
    }
    let mut obligations = BTreeSet::new();
    for obligation in &data.open_obligations {
        bounded_text(obligation)?;
        if !obligations.insert(obligation) {
            return Err(invalid("Obligation dupliquée"));
        }
    }
    if data.status == RunStatus::Running
        && data.open_obligations.len() == OBLIGATION_LIMIT
        && !data
            .open_obligations
            .iter()
            .any(|entry| entry == RECOVERY_OBLIGATION)
    {
        return Err(invalid("Réserve d’obligation de reprise absente"));
    }
    if data.cleanup_verified != data.resources.iter().all(|resource| resource.deleted) {
        return Err(invalid("État de nettoyage incohérent avec les ressources"));
    }
    if data.status == RunStatus::Planned
        && (!data.invocations.is_empty() || !data.resources.is_empty() || data.environment_verified)
    {
        return Err(invalid("Effets enregistrés avant le démarrage du run"));
    }
    if data.status == RunStatus::Complete
        && (!data.environment_verified
            || !data.cleanup_verified
            || !data.open_obligations.is_empty()
            || data
                .invocations
                .iter()
                .any(|invocation| invocation.status != Some(InvocationStatus::Finished)))
    {
        return Err(invalid(
            "Audit complet interdit : exécution, environnement ou obligations non résolus",
        ));
    }
    Ok(())
}
