use crate::{
    error::{ensure, Error, Result},
    files, state,
};
use rusqlite::{config::DbConfig, Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};

pub(super) const APPLICATION_ID: i32 = 0x4c44594d;

pub(super) fn connect(path: &Path, writable: bool, create: bool) -> Result<Connection> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Dossier de catalogue absent".into()))?;
    if create {
        state::create_directory(parent)?;
    }
    let directory = files::open_directory(parent)?;
    let meta = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
        "Le catalogue exige un dossier privé (0700), appartenant à l’utilisateur"
    );
    if create {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(file) => file.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
    }
    let pinned = fs::symlink_metadata(path)?;
    private_file(&pinned)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        match fs::symlink_metadata(Path::new(&sidecar)) {
            Ok(metadata) => {
                private_file(&metadata)?;
                ensure!(
                    suffix == "-journal",
                    "Catalogue WAL refusé ; journal classique requis"
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    } | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection = Connection::open_with_flags(path, flags)?;
    // Detect directory/database replacement during opening before querying any schema.
    let current = fs::symlink_metadata(path)?;
    private_file(&current)?;
    let parent_now = files::open_directory(parent)?.metadata()?;
    ensure!(
        current.dev() == pinned.dev()
            && current.ino() == pinned.ino()
            && parent_now.dev() == meta.dev()
            && parent_now.ino() == meta.ino(),
        "Catalogue remplacé pendant l’ouverture"
    );
    let mut moved = 0;
    connection.file_control(Some("main"), rusqlite::FileControl::HasMoved(&mut moved))?;
    ensure!(moved == 0, "Fichier SQLite remplacé pendant l’ouverture");
    super::header::validate(&mut connection, create)?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")?;
    if writable {
        connection.execute_batch("PRAGMA synchronous=FULL;")?;
    }
    let transaction = connection.transaction_with_behavior(if writable {
        TransactionBehavior::Immediate
    } else {
        TransactionBehavior::Deferred
    })?;
    let app: i32 = transaction.query_row("PRAGMA application_id", [], |r| r.get(0))?;
    let version: i32 = transaction.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let tables: i64 =
        transaction.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    if app == 0 && version == 0 && tables == 0 && create {
        transaction.execute_batch(
            "CREATE TABLE instances (
            id TEXT PRIMARY KEY, observation TEXT NOT NULL, project TEXT NOT NULL,
            status TEXT NOT NULL, metadata TEXT NOT NULL, observed INTEGER NOT NULL,
            first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
            CREATE INDEX instances_project ON instances(project, id);
            CREATE TABLE events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL REFERENCES instances(id), recorded_at INTEGER NOT NULL,
                kind TEXT NOT NULL, observation TEXT NOT NULL, metadata TEXT NOT NULL);
            CREATE INDEX events_instance ON events(instance_id, sequence);
            CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA application_id=1279547725; PRAGMA user_version=1;",
        )?;
    } else {
        ensure!(
            app == APPLICATION_ID && version == 1,
            "Catalogue étranger ou version incompatible ({version}) ; aucune migration implicite"
        );
    }
    transaction.commit()?;
    Ok(connection)
}
fn private_file(meta: &fs::Metadata) -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0,
        "Catalogue/journal privé régulier sans lien requis (0600)"
    );
    Ok(())
}
fn invalid(message: String) -> Error {
    Error::InvalidInput { message }
}
