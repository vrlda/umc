//! Backup and restore of the node's persisted state (storage.md §20-21):
//! the `SQLite` node database (WAL-checkpointed so the copy is standalone),
//! the keystore, and the bundle object store. The config file (`node.json`)
//! is user-owned and deliberately NOT part of a backup (storage.md §20.1).
use crate::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use umc_storage::keystore::Keystore;
use umc_storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use umc_storage::store::StoreError;

/// Backup format version; restores refuse manifests with a newer version
/// (storage.md §20.2, §21.2).
pub const FORMAT_VERSION: u64 = 1;

/// The backup manifest (storage.md §20.1-20.2): format + creation time +
/// data-dir binding + the list of files it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Manifest {
    format_version: u64,
    created_at_ms: u64,
    data_dir_name: String,
    files: Vec<String>,
}

/// Creates a fresh backup of the node's data dir at `out_dir`: a
/// WAL-checkpointed `node.db`, `keystore/keystore.ks`, the `objects/`
/// tree, and a `manifest.json`. An existing `out_dir` is replaced.
///
/// # Errors
/// Returns a message when the data dir has no database or keystore, the
/// WAL checkpoint fails, a copy fails, or the manifest cannot be written.
pub fn backup(config: &NodeConfig, out_dir: &Path) -> Result<(), String> {
    let data_dir = config.resolved_data_dir();
    let db_path = data_dir.join("node.db");
    if !db_path.exists() {
        return Err(format!(
            "backup: no node database at {} (start the daemon once first)",
            db_path.display()
        ));
    }
    let ks_path = config.resolved_keystore_dir().join("keystore.ks");
    if !ks_path.exists() {
        return Err(format!("backup: no keystore at {}", ks_path.display()));
    }
    // Refuse an output that aliases or contains the data dir: clearing it
    // would destroy the live database before the copy starts.
    let out_abs = out_dir
        .canonicalize()
        .unwrap_or_else(|_| out_dir.to_path_buf());
    let data_abs = data_dir.canonicalize().unwrap_or_else(|_| data_dir.clone());
    if out_abs == data_abs || data_abs.starts_with(&out_abs) {
        return Err("backup: output dir must not be the data dir or its ancestor".into());
    }
    // The output is a fresh directory; an existing one is replaced
    // (the operator names the destination, so an overwrite is the
    // point of the flag).
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir)
            .map_err(|e| format!("backup: clear output dir {}: {e}", out_dir.display()))?;
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("backup: create output dir {}: {e}", out_dir.display()))?;

    // Checkpoint the WAL (TRUNCATE) so the copied database is
    // self-contained: a restore must open it standalone (storage.md
    // §20.1: "Metadata database (validated)").
    let store = SqliteStore::open(&db_path).map_err(|e| format!("backup: open store: {e:?}"))?;
    store
        .connection()
        .lock()
        .expect("sqlite connection")
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(|e| format!("backup: wal checkpoint: {e}"))?;
    drop(store);

    let mut files = Vec::new();
    copy_file(
        &db_path,
        &out_dir.join("node.db"),
        "node.db",
        Some(&mut files),
    )?;
    copy_file(
        &ks_path,
        &out_dir.join("keystore/keystore.ks"),
        "keystore/keystore.ks",
        Some(&mut files),
    )?;
    copy_dir(
        &data_dir.join("objects"),
        &out_dir.join("objects"),
        Some(&mut files),
    )?;

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        created_at_ms: crate::state::wall_now().0,
        data_dir_name: data_dir.file_name().map_or_else(
            || "node".to_string(),
            |name| name.to_string_lossy().into_owned(),
        ),
        files,
    };
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("backup: serialize manifest: {e}"))?;
    std::fs::write(out_dir.join("manifest.json"), json)
        .map_err(|e| format!("backup: write manifest: {e}"))
}

pub fn restore(config: &NodeConfig, in_dir: &Path) -> Result<(), String> {
    // Hostile-input gate (storage.md §21.1): the manifest must exist,
    // parse, and use a format version this daemon understands.
    let manifest: Manifest = read_manifest(in_dir)?;
    if manifest.format_version > FORMAT_VERSION {
        return Err(format!(
            "restore refused: backup format v{} is newer than this daemon supports (v{FORMAT_VERSION})",
            manifest.format_version
        ));
    }

    // Validate the backup contents BEFORE anything in the data dir is
    // touched (§21.1 step 5: validate before swap): the database must
    // open with a matching schema, and the keystore must be a valid v2
    // file. Password verification is deliberately skipped here — the
    // daemon verifies the keystore at boot with the real password.
    let db_src = in_dir.join("node.db");
    if !db_src.exists() {
        return Err("restore refused: backup has no node.db".into());
    }
    let backup_schema = open_schema(&db_src, "backup node.db")?;
    if backup_schema != SCHEMA_VERSION {
        return Err(format!(
            "restore refused: backup node.db schema v{backup_schema}, expected v{SCHEMA_VERSION}"
        ));
    }
    let ks_src = in_dir.join("keystore").join("keystore.ks");
    if !ks_src.exists() {
        return Err("restore refused: backup has no keystore/keystore.ks".into());
    }
    if !Keystore::is_valid_format(&ks_src) {
        return Err("restore refused: backup keystore is not a valid v2 keystore".into());
    }

    // Downgrade protection (storage.md §21.4): never overwrite a target
    // database newer than the backup with the backup.
    let data_dir = config.resolved_data_dir();
    let target_db = data_dir.join("node.db");
    if target_db.exists() {
        let target_schema = open_schema(&target_db, "target node.db")?;
        if target_schema > backup_schema {
            return Err(format!(
                "restore refused: target node.db schema v{target_schema} is newer than the backup's v{backup_schema}"
            ));
        }
    }

    // Staged swap (§21.5): existing state moves to `.pre-restore` names,
    // the backup installs, and a verification pass decides whether the
    // swap sticks; any failure rolls the originals back.
    swap_in(config, in_dir)
}

/// Reads and parses the backup manifest.
///
/// # Errors
/// Returns a message when the manifest is missing or malformed.
fn read_manifest(in_dir: &Path) -> Result<Manifest, String> {
    let path = in_dir.join("manifest.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("restore refused: {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("restore refused: invalid manifest.json: {e}"))
}

/// Opens a database and returns its schema version. A database with an
/// unsupported (future) schema — the downgrade-protection signal — is
/// reported distinctly from a file that is not a database at all.
///
/// # Errors
/// Returns a message when the file cannot be opened or has a future schema.
fn open_schema(path: &Path, what: &str) -> Result<i64, String> {
    // Read-only probe: init/migrations must never touch the backup or the
    // target during validation (storage.md §21.1).
    match SqliteStore::read_only_schema_version(path) {
        Ok(version) => Ok(version),
        Err(StoreError::Corrupt(msg)) if msg.contains("schema") => Err(format!(
            "restore refused: {what} has an unsupported (newer) schema version: {msg}"
        )),
        Err(e) => Err(format!("restore refused: cannot open {what}: {e:?}")),
    }
}

/// Swaps the backup into the data dir (storage.md §21.5): existing
/// `node.db`, `keystore/keystore.ks`, and `objects/` are renamed to
/// `.pre-restore` names (and stale WAL sidecars removed), the backup is
/// installed, and the restored state is verified. Any failure rolls the
/// originals back into place.
///
/// # Errors
/// Returns a message when a rename, copy, or verification fails.
fn swap_in(config: &NodeConfig, in_dir: &Path) -> Result<(), String> {
    let data_dir = config.resolved_data_dir();
    let keystore_dir = config.resolved_keystore_dir();
    let targets = [
        (
            data_dir.join("node.db"),
            data_dir.join("node.db.pre-restore"),
            false,
        ),
        (
            keystore_dir.join("keystore.ks"),
            keystore_dir.join("keystore.ks.pre-restore"),
            false,
        ),
        (
            data_dir.join("objects"),
            data_dir.join("objects.pre-restore"),
            true,
        ),
    ];
    let mut renamed: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (original, staged, is_dir) in targets {
        if !original.exists() {
            continue;
        }
        if staged.exists() {
            let cleared = if is_dir {
                std::fs::remove_dir_all(&staged)
            } else {
                std::fs::remove_file(&staged)
            };
            cleared.map_err(|e| format!("restore: clear stale {}: {e}", staged.display()))?;
        }
        std::fs::rename(&original, &staged)
            .map_err(|e| format!("restore: stage {}: {e}", original.display()))?;
        renamed.push((original.clone(), staged));
    }
    // The WAL sidecars belong to the renamed-away database; a leftover
    // `node.db-wal` would confuse the freshly installed one.
    for sidecar in ["node.db-wal", "node.db-shm"] {
        let _ = std::fs::remove_file(data_dir.join(sidecar));
    }

    let result = install_backup(config, in_dir).and_then(|()| verify_restored(config));
    if let Err(e) = result {
        rollback(&renamed);
        return Err(format!("restore failed: {e}; existing state restored"));
    }
    Ok(())
}

/// Copies the backup's files into their runtime locations.
///
/// # Errors
/// Returns a message when a copy fails.
fn install_backup(config: &NodeConfig, in_dir: &Path) -> Result<(), String> {
    let data_dir = config.resolved_data_dir();
    let keystore_dir = config.resolved_keystore_dir();
    copy_file(
        &in_dir.join("node.db"),
        &data_dir.join("node.db"),
        "node.db",
        None,
    )?;
    std::fs::create_dir_all(&keystore_dir).map_err(|e| format!("restore: keystore dir: {e}"))?;
    copy_file(
        &in_dir.join("keystore").join("keystore.ks"),
        &keystore_dir.join("keystore.ks"),
        "keystore.ks",
        None,
    )?;
    copy_dir(&in_dir.join("objects"), &data_dir.join("objects"), None)
}

/// Verifies the freshly installed state: the database opens with the
/// current schema and the keystore file exists.
///
/// # Errors
/// Returns a message when the restored state does not verify.
fn verify_restored(config: &NodeConfig) -> Result<(), String> {
    let data_dir = config.resolved_data_dir();
    let store = SqliteStore::open(&data_dir.join("node.db"))
        .map_err(|e| format!("restored node.db does not open: {e:?}"))?;
    let version = store
        .schema_version()
        .map_err(|e| format!("restored node.db: {e:?}"))?;
    if version != SCHEMA_VERSION {
        return Err(format!(
            "restored node.db schema v{version}, expected v{SCHEMA_VERSION}"
        ));
    }
    if !config.resolved_keystore_dir().join("keystore.ks").exists() {
        return Err("restored keystore file is missing".into());
    }
    Ok(())
}

/// Puts every staged `.pre-restore` file back where it was, removing any
/// partial files the failed install left behind.
fn rollback(renamed: &[(PathBuf, PathBuf)]) {
    for (original, staged) in renamed {
        if original.exists() {
            let removed = if original.is_dir() {
                std::fs::remove_dir_all(original)
            } else {
                std::fs::remove_file(original)
            };
            if let Err(e) = removed {
                log::error!("[restore] rollback: clear {}: {e}", original.display());
            }
        }
        if let Err(e) = std::fs::rename(staged, original) {
            log::error!("[restore] rollback: {}: {e}", staged.display());
        }
    }
}

/// Copies one file, recording its relative path in `files` (backup
/// manifests) when given.
///
/// # Errors
/// Returns a message when the copy fails.
fn copy_file(
    src: &Path,
    dst: &Path,
    label: &str,
    files: Option<&mut Vec<String>>,
) -> Result<(), String> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{label}: create dir: {e}"))?;
    }
    std::fs::copy(src, dst).map_err(|e| format!("{label}: copy: {e}"))?;
    if let Some(files) = files {
        files.push(label.to_string());
    }
    Ok(())
}

/// Recursively copies `src` into `dst`, creating `dst` even when `src` is
/// absent (an empty object store is still part of the layout). Every
/// copied file's path relative to `src` is appended to `files` when given.
///
/// # Errors
/// Returns a message when a directory or file copy fails.
fn copy_dir(src: &Path, dst: &Path, mut files: Option<&mut Vec<String>>) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("copy dir {}: {e}", dst.display()))?;
    let Ok(entries) = std::fs::read_dir(src) else {
        return Ok(());
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("copy dir: {e}"))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(src)
            .expect("directory entry is under its source")
            .to_string_lossy()
            .replace('\\', "/");
        if path.is_dir() {
            copy_dir(&path, &dst.join(&rel), files.as_deref_mut())?;
        } else {
            let out_path = dst.join(&rel);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("copy dir: {e}"))?;
            }
            std::fs::copy(&path, &out_path).map_err(|e| format!("copy {}: {e}", path.display()))?;
            if let Some(files) = &mut files {
                files.push(rel);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::{DaemonEvent, DaemonEvents};
    use crate::state::KEYSTORE_FILE;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use umc_storage::objects::{blake2s, ObjectStore};
    use umc_storage::records::{list_routes, save_route, RouteRecordSnapshot};
    use umc_storage::store::{Namespace, Store};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh config pointing at a private temp data dir.
    fn seeded_config() -> NodeConfig {
        let dir = std::env::temp_dir().join(format!(
            "umcd-backup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "umcd-backup-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// The records seeded into a data dir for round-trip verification.
    #[derive(Clone)]
    struct Seed {
        keystore_bytes: Vec<u8>,
        route: RouteRecordSnapshot,
        object_id: [u8; 32],
        payload: Vec<u8>,
    }

    /// Builds a populated data dir the way the daemon would: `init_node`
    /// (dirs + keystore identity), a store open (`node.db`), a persisted
    /// route record, a persisted event, and one bundle object. No
    /// keystore-password verification happens here: restore flows must not
    /// depend on `UMC_KEYSTORE_PASSWORD` (the daemon verifies at boot), so
    /// the tests compare keystore bytes instead of decrypting.
    fn seed_data_dir(config: &NodeConfig) -> Seed {
        crate::init_node(config, None);
        let data_dir = config.resolved_data_dir();
        let store = SqliteStore::open(&data_dir.join("node.db")).expect("open store");
        let route = RouteRecordSnapshot {
            key_hash: vec![7u8; 32],
            next_hop: b"peer-a".to_vec(),
            lifetime_ms: 600_000,
            learned_at_ms: 42,
            scope: 3,
        };
        save_route(&store, &route).expect("save route");
        let mut events = DaemonEvents::new(100);
        events.attach_store(Arc::new(store));
        events.push(DaemonEvent {
            kind: "session_active".into(),
            at_ms: 10,
            detail: "backup round trip".into(),
        });
        drop(events);
        let objects = ObjectStore::open(data_dir.join("objects")).expect("object store");
        let payload = b"bundle payload".to_vec();
        let object_id = blake2s(&payload);
        objects.put(&object_id, &payload).expect("put object");
        let keystore_bytes =
            std::fs::read(data_dir.join("keystore").join(KEYSTORE_FILE)).expect("keystore bytes");
        Seed {
            keystore_bytes,
            route,
            object_id,
            payload,
        }
    }

    /// Removes the persisted state the way a wipe would: the database
    /// (plus WAL sidecars), the keystore, and the object store.
    fn wipe_data_dir(config: &NodeConfig) {
        let data_dir = config.resolved_data_dir();
        for name in ["node.db", "node.db-wal", "node.db-shm"] {
            let _ = std::fs::remove_file(data_dir.join(name));
        }
        let _ = std::fs::remove_dir_all(data_dir.join("keystore"));
        let _ = std::fs::remove_dir_all(data_dir.join("objects"));
    }

    /// Bumps the stored schema version of the data dir's database to a
    /// future value via the store's own connection accessor.
    fn bump_schema(config: &NodeConfig, version: i64) {
        let data_dir = config.resolved_data_dir();
        let store = SqliteStore::open(&data_dir.join("node.db")).expect("open store");
        store
            .connection()
            .lock()
            .unwrap()
            .execute_batch(&format!("UPDATE schema_version SET version = {version}"))
            .expect("bump schema");
        drop(store);
    }

    #[test]
    fn backup_then_restore_round_trip() {
        let config = seeded_config();
        let seed = seed_data_dir(&config);
        let data_dir = config.resolved_data_dir();
        let backup_dir = temp_dir("roundtrip");
        backup(&config, &backup_dir).unwrap();

        // The manifest records format, creation time, the data dir
        // binding, and the files it carries.
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(backup_dir.join("manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["format_version"], 1);
        assert_eq!(
            manifest["data_dir_name"],
            data_dir.file_name().unwrap().to_str().unwrap()
        );
        let files = manifest["files"].as_array().unwrap();
        assert!(files.iter().any(|f| f == "node.db"));
        assert!(files.iter().any(|f| f == "keystore/keystore.ks"));

        // Wipe and restore.
        wipe_data_dir(&config);
        restore(&config, &backup_dir).unwrap();

        // The database opens with a matching schema...
        let restored = SqliteStore::open(&data_dir.join("node.db")).unwrap();
        assert_eq!(restored.schema_version().unwrap(), SCHEMA_VERSION);
        // ...the route record survives...
        let routes = list_routes(&restored).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key_hash, seed.route.key_hash);
        assert_eq!(routes[0].next_hop, b"peer-a");
        // ...the persisted event survives...
        let mut events = DaemonEvents::new(100);
        events.restore_persisted(&restored);
        let recent = events.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].kind, "session_active");
        assert_eq!(recent[0].at_ms, 10);
        // ...the keystore exists as a valid v2 file with the identical
        // bytes (same identity + same password material; the daemon
        // verifies the password at boot, not restore)...
        let ks_path = data_dir.join("keystore").join(KEYSTORE_FILE);
        assert!(ks_path.exists());
        assert!(Keystore::is_valid_format(&ks_path));
        assert_eq!(
            std::fs::read(&ks_path).unwrap(),
            seed.keystore_bytes,
            "restored keystore must be byte-identical to the backed-up one"
        );
        // ...and the bundle object is intact.
        let objects = ObjectStore::open(data_dir.join("objects")).unwrap();
        assert_eq!(objects.get(&seed.object_id).unwrap(), seed.payload);
    }

    #[test]
    fn restore_refuses_missing_or_newer_manifest() {
        let config = seeded_config();
        let backup_dir = temp_dir("manifest");
        std::fs::create_dir_all(&backup_dir).unwrap();
        // No manifest at all: not a backup.
        assert!(restore(&config, &backup_dir).is_err());
        // A manifest from a newer daemon: unknown format version.
        std::fs::write(
            backup_dir.join("manifest.json"),
            r#"{"format_version": 99, "created_at_ms": 0, "data_dir_name": "x", "files": []}"#,
        )
        .unwrap();
        assert!(restore(&config, &backup_dir).is_err());
        // The refusal precedes any replacement: nothing was created or
        // staged in the (empty) data dir.
        assert!(!config.resolved_data_dir().join("node.db").exists());
        assert!(!config
            .resolved_data_dir()
            .join("node.db.pre-restore")
            .exists());
    }

    #[test]
    fn restore_refuses_newer_database_schema() {
        let config = seeded_config();
        seed_data_dir(&config);
        bump_schema(&config, 99);
        let data_dir = config.resolved_data_dir();
        // A hand-crafted backup with a future-schema database.
        let backup_dir = temp_dir("futuredb");
        std::fs::create_dir_all(backup_dir.join("keystore")).unwrap();
        std::fs::copy(data_dir.join("node.db"), backup_dir.join("node.db")).unwrap();
        std::fs::copy(
            data_dir.join("keystore").join(KEYSTORE_FILE),
            backup_dir.join("keystore").join(KEYSTORE_FILE),
        )
        .unwrap();
        std::fs::write(
            backup_dir.join("manifest.json"),
            r#"{"format_version": 1, "created_at_ms": 0, "data_dir_name": "x", "files": ["node.db"]}"#,
        )
        .unwrap();
        // The hostile database is refused before any replacement.
        assert!(restore(&config, &backup_dir).is_err());
        assert!(data_dir.join("node.db").exists());
        assert!(!data_dir.join("node.db.pre-restore").exists());
    }

    #[test]
    fn restore_refuses_when_target_db_is_newer() {
        // A healthy backup...
        let source = seeded_config();
        seed_data_dir(&source);
        let backup_dir = temp_dir("downgrade");
        backup(&source, &backup_dir).unwrap();
        // ...restored into a data dir whose database is NEWER than the
        // backup's: downgrade protection (storage.md §21.4).
        let target = seeded_config();
        seed_data_dir(&target);
        bump_schema(&target, 99);
        assert!(restore(&target, &backup_dir).is_err());
        assert!(target.resolved_data_dir().join("node.db").exists());
        assert!(!target
            .resolved_data_dir()
            .join("node.db.pre-restore")
            .exists());
    }

    #[test]
    fn restore_preserves_existing_on_failure() {
        let config = seeded_config();
        seed_data_dir(&config);
        let data_dir = config.resolved_data_dir();
        let store = SqliteStore::open(&data_dir.join("node.db")).unwrap();
        store
            .put(Namespace::Config, b"marker", b"original")
            .unwrap();
        let schema_before = store.schema_version().unwrap();
        drop(store);

        // A corrupt backup: garbage database bytes.
        let backup_dir = temp_dir("corrupt");
        std::fs::create_dir_all(&backup_dir).unwrap();
        std::fs::write(backup_dir.join("node.db"), b"not a sqlite database").unwrap();
        std::fs::write(
            backup_dir.join("manifest.json"),
            r#"{"format_version": 1, "created_at_ms": 0, "data_dir_name": "x", "files": ["node.db"]}"#,
        )
        .unwrap();

        assert!(restore(&config, &backup_dir).is_err());
        // The existing database is untouched: same schema, same data,
        // and nothing was staged or renamed.
        let reopened = SqliteStore::open(&data_dir.join("node.db")).unwrap();
        assert_eq!(reopened.schema_version().unwrap(), schema_before);
        assert_eq!(
            reopened.get(Namespace::Config, b"marker").unwrap(),
            Some(b"original".to_vec())
        );
        assert!(!data_dir.join("node.db.pre-restore").exists());
    }

    #[test]
    fn backup_db_is_standalone_after_checkpoint() {
        let config = seeded_config();
        seed_data_dir(&config);
        let backup_dir = temp_dir("checkpoint");
        backup(&config, &backup_dir).unwrap();
        // The backup carries no WAL sidecar: the copy is standalone.
        assert!(!backup_dir.join("node.db-wal").exists());
        // The copied database opens on its own — no -wal needed.
        let copied = SqliteStore::open(&backup_dir.join("node.db")).unwrap();
        assert_eq!(copied.schema_version().unwrap(), SCHEMA_VERSION);
        let routes = list_routes(&copied).unwrap();
        assert_eq!(routes.len(), 1);
    }
}

#[test]
fn schema_probe_is_read_only() {
    // A schema-v1 database must NOT be migrated by the probe: validation
    // never mutates the backup (storage.md §21.1).
    let dir = std::env::temp_dir().join(format!(
        "umcd-backup-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("node.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);
             INSERT INTO schema_version (version) VALUES (1);",
    )
    .unwrap();
    drop(conn);
    let version = umc_storage::sqlite::SqliteStore::read_only_schema_version(&path).unwrap();
    assert_eq!(version, 1);
    // Still v1 afterwards: no migrations ran.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let v: i64 = conn
        .query_row("SELECT version FROM schema_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, 1);
}
