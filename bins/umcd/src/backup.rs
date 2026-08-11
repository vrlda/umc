//! Backup and restore of the node's persisted state (storage.md §20-21):
//! the `SQLite` node database (WAL-checkpointed so the copy is standalone),
//! the keystore, and the bundle object store. The config file (`node.json`)
//! is user-owned and deliberately NOT part of a backup (storage.md §20.1).
use crate::config::NodeConfig;
use crate::state::KEYSTORE_FILE;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use umc_storage::keystore::{KeyClass, Keystore};
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
    #[serde(default)]
    file_hashes: BTreeMap<String, String>,
    #[serde(default)]
    storage_generation: u64,
    #[serde(default)]
    node_identity: Option<String>,
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
    let object_file_start = files.len();
    copy_dir(
        &data_dir.join("objects"),
        &out_dir.join("objects"),
        Some(&mut files),
    )?;
    files.truncate(object_file_start);
    collect_manifest_files(&out_dir.join("objects"), out_dir, &mut files)?;

    let file_hashes = hash_manifest_files(out_dir, &files)?;
    let node_identity = node_identity_fingerprint(&ks_path)?;

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        created_at_ms: crate::state::wall_now().0,
        data_dir_name: data_dir.file_name().map_or_else(
            || "node".to_string(),
            |name| name.to_string_lossy().into_owned(),
        ),
        files,
        file_hashes,
        storage_generation: crate::state::read_restore_anchor(&data_dir),
        node_identity: Some(node_identity),
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

    let data_dir = config.resolved_data_dir();
    validate_manifest(in_dir, &manifest)?;
    let current_generation = crate::state::read_restore_anchor(&data_dir);
    if manifest.storage_generation < current_generation {
        return Err(format!(
            "restore refused: backup generation {} is older than current generation {current_generation}",
            manifest.storage_generation
        ));
    }

    // Validate the backup contents BEFORE anything in the data dir is
    // touched (§21.1 step 5: validate before swap): the database must
    // open with a matching schema, and the keystore must be a recognized v2/v3
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
        return Err("restore refused: backup keystore is not a recognized v2/v3 keystore".into());
    }

    // Downgrade protection (storage.md §21.4): never overwrite a target
    // database newer than the backup with the backup.
    let target_db = data_dir.join("node.db");
    if target_db.exists() {
        let target_schema = open_schema(&target_db, "target node.db")?;
        if target_schema > backup_schema {
            return Err(format!(
                "restore refused: target node.db schema v{target_schema} is newer than the backup's v{backup_schema}"
            ));
        }
    }
    if let Some(expected_identity) = manifest.node_identity.as_deref() {
        let target_keystore = config.resolved_keystore_dir().join(KEYSTORE_FILE);
        if target_keystore.exists()
            && node_identity_fingerprint(&target_keystore)? != expected_identity
        {
            return Err("restore refused: backup belongs to a different node identity".into());
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

fn validate_manifest(in_dir: &Path, manifest: &Manifest) -> Result<(), String> {
    for relative in &manifest.files {
        let path = safe_manifest_path(in_dir, relative)?;
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("restore refused: manifest file {relative}: {e}"))?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "restore refused: manifest entry {relative} is not a regular file"
            ));
        }
    }
    if manifest.file_hashes.is_empty() {
        return Ok(());
    }
    for (relative, expected) in &manifest.file_hashes {
        if !manifest.files.iter().any(|entry| entry == relative) {
            return Err(format!(
                "restore refused: hash entry {relative} is absent from manifest files"
            ));
        }
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "restore refused: invalid hash for manifest file {relative}"
            ));
        }
        let path = safe_manifest_path(in_dir, relative)?;
        let actual = hex_bytes(&umc_storage::objects::blake2s(
            &std::fs::read(&path)
                .map_err(|e| format!("restore refused: read manifest file {relative}: {e}"))?,
        ));
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "restore refused: integrity hash mismatch for {relative}"
            ));
        }
    }
    for relative in &manifest.files {
        if !manifest.file_hashes.contains_key(relative) {
            return Err(format!(
                "restore refused: manifest file {relative} has no integrity hash"
            ));
        }
    }
    Ok(())
}

fn safe_manifest_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(format!("restore refused: unsafe manifest path {relative}"));
    }
    Ok(root.join(relative_path))
}

fn hash_manifest_files(root: &Path, files: &[String]) -> Result<BTreeMap<String, String>, String> {
    files
        .iter()
        .map(|relative| {
            let path = safe_manifest_path(root, relative)?;
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("backup: manifest file {relative}: {e}"))?;
            if !metadata.file_type().is_file() {
                return Err(format!("backup: manifest file {relative} is not regular"));
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("backup: read manifest file {relative}: {e}"))?;
            Ok((
                relative.clone(),
                hex_bytes(&umc_storage::objects::blake2s(&bytes)),
            ))
        })
        .collect()
}

fn collect_manifest_files(
    root: &Path,
    backup_root: &Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(root)
        .map_err(|e| format!("backup: enumerate {}: {e}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("backup: enumerate {}: {e}", root.display()))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("backup: inspect {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("backup: refusing symlink {}", path.display()));
        }
        if metadata.is_dir() {
            collect_manifest_files(&path, backup_root, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(backup_root)
                .map_err(|e| format!("backup: relative path {}: {e}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            files.push(relative);
        }
    }
    Ok(())
}

fn hex_bytes(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn node_identity_fingerprint(path: &Path) -> Result<String, String> {
    let keystore = Keystore::open(path.to_path_buf(), &crate::state::keystore_password())
        .map_err(|e| format!("keystore identity fingerprint: {e:?}"))?;
    let seed = keystore
        .load(
            KeyClass::IdentitySigning,
            crate::state::NODE_IDENTITY_RECORD,
        )
        .map_err(|e| format!("keystore identity fingerprint: {e:?}"))?;
    let identity_seed: [u8; 32] = seed
        .get(..32)
        .ok_or_else(|| "keystore identity fingerprint: malformed identity record".to_string())?
        .try_into()
        .map_err(|_| "keystore identity fingerprint: malformed identity record".to_string())?;
    let identity = umc_crypto::signatures::IdentityKeyPair::from_seed(identity_seed);
    let endpoint_id = umc_handshake::identity::endpoint_id(&identity.public());
    Ok(hex_bytes(&endpoint_id))
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

    let result = install_backup(config, in_dir)
        .and_then(|()| verify_restored(config))
        .and_then(|()| {
            crate::state::advance_restore_anchor(&data_dir)
                .map(|generation| log::info!("[restore] installed generation {generation}"))
        });
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
    let keystore_path = config.resolved_keystore_dir().join(KEYSTORE_FILE);
    if !Keystore::is_valid_format(&keystore_path) {
        return Err("restored keystore format is invalid".into());
    }
    node_identity_fingerprint(&keystore_path)?;
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
    let metadata =
        std::fs::symlink_metadata(src).map_err(|e| format!("{label}: inspect source: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label}: source is not a regular file"));
    }
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
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("copy dir: inspect {}: {e}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("copy dir: refusing symlink {}", path.display()));
        }
        let rel = path
            .strip_prefix(src)
            .expect("directory entry is under its source")
            .to_string_lossy()
            .replace('\\', "/");
        if metadata.is_dir() {
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
            metadata: Vec::new(),
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
        // ...the keystore exists as a valid v3 file with the identical
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
    fn restore_rejects_manifest_path_and_hash_tampering() {
        let source = seeded_config();
        seed_data_dir(&source);
        let backup_dir = temp_dir("manifest-integrity");
        backup(&source, &backup_dir).unwrap();

        let mut manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(backup_dir.join("manifest.json")).unwrap(),
        )
        .unwrap();
        manifest["files"] = serde_json::json!(["../escape"]);
        std::fs::write(
            backup_dir.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let target = seeded_config();
        assert!(restore(&target, &backup_dir)
            .unwrap_err()
            .contains("unsafe manifest path"));

        backup(&source, &backup_dir).unwrap();
        let db_path = backup_dir.join("node.db");
        let mut bytes = std::fs::read(&db_path).unwrap();
        bytes.push(0);
        std::fs::write(db_path, bytes).unwrap();
        assert!(restore(&target, &backup_dir)
            .unwrap_err()
            .contains("integrity hash mismatch"));
    }

    #[test]
    fn restore_rejects_older_storage_generation() {
        let config = seeded_config();
        seed_data_dir(&config);
        let backup_dir = temp_dir("generation");
        backup(&config, &backup_dir).unwrap();
        crate::state::advance_restore_anchor(&config.resolved_data_dir()).unwrap();
        let error = restore(&config, &backup_dir).unwrap_err();
        assert!(error.contains("older than current generation"));
    }

    #[test]
    fn restore_rejects_different_node_identity() {
        let source = seeded_config();
        seed_data_dir(&source);
        let backup_dir = temp_dir("identity-binding");
        backup(&source, &backup_dir).unwrap();
        let target = seeded_config();
        seed_data_dir(&target);
        let error = restore(&target, &backup_dir).unwrap_err();
        assert!(error.contains("different node identity"));
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
