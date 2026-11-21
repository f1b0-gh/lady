//! Local management catalogue. Observations are cached evidence, never authority
//! for provider operations. Refresh is explicit; reads never create a database.
mod header;
mod model;
mod store;
use crate::{
    associations,
    error::{ensure, Error, Result},
    files, instances,
};
pub use model::*;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct Registry {
    path: PathBuf,
}
impl Registry {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            path: files::absolute(path.as_ref())?,
        })
    }
    pub fn local() -> Result<Self> {
        Self::new(default_path()?)
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Import validated Lady associations. The entire observation/write cycle is
    /// serialized, preventing an older concurrent refresh from overwriting a newer one.
    pub fn refresh(&self, source: &Path) -> Result<Refresh> {
        let source = files::absolute(source)?;
        let mut connection = store::connect(&self.path, true, true)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = last_refresh(&tx)?;
        ensure!(
            previous.as_ref().is_none_or(|r| r.registry == source),
            "Source du catalogue différente ; utiliser une base distincte"
        );
        let inventory = instances::inventory_at(&source, true)?;
        let observations: Vec<Observation> =
            serde_json::from_value(inventory["instances"].clone())?;
        let now = now()?;
        // Unseen is not deleted, including on partial inventories.
        tx.execute("UPDATE instances SET observed=0", [])?;
        let mut seen = BTreeSet::new();
        for observation in &observations {
            let id = identifier(observation)?;
            ensure!(
                seen.insert(id.clone()),
                "Identité dupliquée dans l’inventaire ; import annulé"
            );
            let old = get_optional(&tx, &id)?;
            let metadata = old.as_ref().map(|i| i.metadata.clone()).unwrap_or_default();
            let value = serde_json::to_string(observation)?;
            let metadata_text = serde_json::to_string(&metadata)?;
            tx.execute("INSERT INTO instances (id, observation, project, status, metadata, observed, first_seen, last_seen)
                VALUES (?1,?2,?3,?4,?5,1,?6,?6) ON CONFLICT(id) DO UPDATE SET
                observation=excluded.observation, project=excluded.project, status=excluded.status,
                observed=1, last_seen=excluded.last_seen",
                params![id,value,path_text(&observation.project)?,status_text(observation.recorded_status),metadata_text,now])?;
            if old.as_ref().is_none_or(|i| i.observation != *observation) {
                event(
                    &tx,
                    &id,
                    now,
                    if old.is_none() {
                        "imported"
                    } else {
                        "observation_changed"
                    },
                    observation,
                    &metadata,
                )?;
            }
        }
        let refresh = Refresh {
            schema_version: 1,
            registry: source,
            refreshed_at: now,
            provider_checked: false,
            complete: inventory["complete"] == true,
            observed: observations.len(),
            diagnostics: serde_json::from_value(inventory["diagnostics"].clone())?,
        };
        tx.execute(
            "INSERT INTO settings(key,value) VALUES ('last_refresh',?1)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [serde_json::to_string(&refresh)?],
        )?;
        tx.commit()?;
        Ok(refresh)
    }

    pub fn list(&self, filter: &Filter) -> Result<Inventory> {
        page_limit(filter.limit)?;
        if let Some((key, value)) = &filter.label {
            validate_label(key, value)?;
        }
        if let Some(id) = &filter.after {
            validate_id(id)?;
        }
        let mut connection = store::connect(&self.path, false, false)?;
        let tx = connection.transaction()?;
        let project = filter.project.as_deref().map(files::absolute).transpose()?;
        let project = project.as_deref().map(path_text).transpose()?;
        let label = filter.label.as_ref();
        let mut statement = tx.prepare("SELECT id,observation,metadata,observed,first_seen,last_seen FROM instances
            WHERE (?1 IS NULL OR project=?1) AND (?2 IS NULL OR status=?2)
            AND (?3 OR json_extract(metadata,'$.archived')=0)
            AND (?4 OR status!='deleted') AND (?5 IS NULL OR id>?5)
            AND (?6 IS NULL OR EXISTS (SELECT 1 FROM json_each(metadata,'$.labels') WHERE key=?6 AND value=?7))
            ORDER BY id LIMIT ?8")?;
        let mut rows = statement.query(params![
            project,
            filter.status.map(status_text),
            filter.include_archived,
            filter.include_deleted || filter.status == Some(RecordedStatus::Deleted),
            filter.after,
            label.map(|l| &l.0),
            label.map(|l| &l.1),
            i64::from(filter.limit) + 1
        ])?;
        let mut records = Vec::new();
        while let Some(row) = rows.next()? {
            records.push(instance(row)?);
        }
        let next = if records.len() > filter.limit as usize {
            records.pop();
            records.last().map(|i| i.id.clone())
        } else {
            None
        };
        Ok(Inventory {
            schema_version: 1,
            provider_checked: false,
            last_refresh: last_refresh(&tx)?,
            instances: records,
            next,
        })
    }

    pub fn get(&self, id: &str) -> Result<Instance> {
        validate_id(id)?;
        required(&store::connect(&self.path, false, false)?, id)
    }

    /// Merge labels and notes atomically. Archiving only affects catalogue views.
    pub fn annotate(&self, id: &str, update: &Annotation) -> Result<Instance> {
        validate_id(id)?;
        for (key, value) in &update.labels {
            validate_label(key, value)?;
        }
        for key in &update.remove_labels {
            validate_label(key, "")?;
        }
        ensure!(
            update.note.as_ref().is_none_or(|v| v.len() <= 4096),
            "Note limitée à 4096 octets"
        );
        ensure!(
            !update
                .remove_labels
                .iter()
                .any(|k| update.labels.contains_key(k)),
            "Label à la fois ajouté et retiré"
        );
        let mut connection = store::connect(&self.path, true, false)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = required(&tx, id)?;
        let previous = record.metadata.clone();
        for key in &update.remove_labels {
            record.metadata.labels.remove(key);
        }
        record.metadata.labels.extend(update.labels.clone());
        ensure!(
            record.metadata.labels.len() <= 32,
            "32 labels maximum par instance"
        );
        if let Some(note) = &update.note {
            record.metadata.note.clone_from(note);
        }
        if let Some(archived) = update.archived {
            record.metadata.archived = archived;
        }
        if record.metadata != previous {
            tx.execute(
                "UPDATE instances SET metadata=?1 WHERE id=?2",
                params![serde_json::to_string(&record.metadata)?, id],
            )?;
            event(
                &tx,
                id,
                now()?,
                "metadata_changed",
                &record.observation,
                &record.metadata,
            )?;
        }
        tx.commit()?;
        Ok(record)
    }

    pub fn history(&self, id: &str, after: i64, limit: u32) -> Result<History> {
        validate_id(id)?;
        page_limit(limit)?;
        ensure!(after >= 0, "Curseur négatif interdit");
        let connection = store::connect(&self.path, false, false)?;
        required(&connection, id)?;
        let mut statement = connection.prepare(
            "SELECT sequence,recorded_at,kind,observation,metadata FROM events
            WHERE instance_id=?1 AND sequence>?2 ORDER BY sequence LIMIT ?3",
        )?;
        let mut rows = statement.query(params![id, after, i64::from(limit) + 1])?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(Event {
                sequence: row.get(0)?,
                instance_id: id.into(),
                recorded_at: row.get(1)?,
                kind: row.get(2)?,
                observation: serde_json::from_str(&row.get::<_, String>(3)?)?,
                metadata: serde_json::from_str(&row.get::<_, String>(4)?)?,
            });
        }
        let next = if events.len() > limit as usize {
            events.pop();
            events.last().map(|e| e.sequence)
        } else {
            None
        };
        Ok(History {
            schema_version: 1,
            events,
            next,
        })
    }
}

pub fn default_path() -> Result<PathBuf> {
    Ok(associations::registry()?
        .parent()
        .ok_or_else(|| invalid("Dossier des associations absent".into()))?
        .join("management/catalog.sqlite3"))
}
fn identifier(o: &Observation) -> Result<String> {
    Ok(files::hash(&serde_json::to_vec(&(
        &o.directory,
        &o.gateway,
        &o.workspace,
        &o.sandbox_id,
    ))?))
}
fn get_optional(c: &Connection, id: &str) -> Result<Option<Instance>> {
    let mut stmt = c.prepare(
        "SELECT id,observation,metadata,observed,first_seen,last_seen FROM instances WHERE id=?1",
    )?;
    let mut rows = stmt.query([id])?;
    rows.next()?.map(instance).transpose()
}
fn required(c: &Connection, id: &str) -> Result<Instance> {
    get_optional(c, id)?.ok_or_else(|| invalid(format!("Instance inconnue : {id}")))
}
fn instance(row: &rusqlite::Row<'_>) -> Result<Instance> {
    Ok(Instance {
        id: row.get(0)?,
        observation: serde_json::from_str(&row.get::<_, String>(1)?)?,
        metadata: serde_json::from_str(&row.get::<_, String>(2)?)?,
        observed: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
    })
}
fn event(
    c: &Connection,
    id: &str,
    now: i64,
    kind: &str,
    o: &Observation,
    m: &Metadata,
) -> Result<()> {
    c.execute("INSERT INTO events(instance_id,recorded_at,kind,observation,metadata) VALUES (?1,?2,?3,?4,?5)",
        params![id,now,kind,serde_json::to_string(o)?,serde_json::to_string(m)?])?;
    Ok(())
}
fn last_refresh(c: &Connection) -> Result<Option<Refresh>> {
    let value: Option<String> = c
        .query_row(
            "SELECT value FROM settings WHERE key='last_refresh'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
fn status_text(status: RecordedStatus) -> &'static str {
    match status {
        RecordedStatus::Retained => "retained",
        RecordedStatus::DeletionPending => "deletion_pending",
        RecordedStatus::Deleted => "deleted",
    }
}
fn now() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("Horloge antérieure à Unix".into()))?;
    i64::try_from(duration.as_secs()).map_err(|_| invalid("Horloge hors limites".into()))
}
fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid("Chemin UTF-8 requis".into()))
}
fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "Identifiant de catalogue invalide"
    );
    Ok(())
}
fn page_limit(limit: u32) -> Result<()> {
    ensure!(
        (1..=1000).contains(&limit),
        "Limite de page requise : 1..1000"
    );
    Ok(())
}
fn validate_label(key: &str, value: &str) -> Result<()> {
    ensure!(
        !key.is_empty()
            && key.len() <= 64
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            && value.len() <= 256,
        "Label invalide : clé ASCII 1..64 (lettres, chiffres, ._-), valeur <=256 octets"
    );
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}

#[cfg(test)]
mod tests;
