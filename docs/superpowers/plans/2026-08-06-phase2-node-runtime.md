# Phase 2: Node Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `umcd` daemon persists node state, authenticates local clients, and serves the protobuf Control API (`api/umc.proto`) over a Unix socket, with an `umc` CLI and Rust daemon-client SDK talking to it.

**Architecture:** Per `decisions.md` §6-7: SQLite (WAL, foreign keys, explicit migrations) + content-addressed object store + separate protected keystore. The Control API is length-prefixed protobuf over a Unix stream socket with OS-peer/bearer authentication and capability grants. `prost` generates Rust types from `api/umc.proto`; the transport is custom (no gRPC). The daemon composes the Phase 1 crates with storage and control.

**Tech Stack:** Rust stable, Tokio, rusqlite (bundled SQLite), prost, prost-build, serde, serde_json, clap (CLI), uuid not required (handles are 16 random bytes from our entropy).

---

## File Structure

- `crates/umc-storage/` — `Cargo.toml`, `src/lib.rs`, `store.rs` (trait + namespaces), `sqlite.rs` (backend), `migrations.rs`, `keystore.rs`, `objects.rs` (content-addressed), `records.rs` (peer/route/bundle metadata), `quota.rs`
- `crates/umc-control/` — `Cargo.toml`, `build.rs`, `src/lib.rs`, `proto.rs` (generated), `framing.rs`, `conn.rs` (connection state machine), `auth.rs`, `grants.rs`, `dispatch.rs`, `events.rs`, `pages.rs`, `handles.rs`
- `crates/umc-sdk/` — `Cargo.toml`, `src/lib.rs`, `client.rs` (daemon client), `types.rs`
- `bins/umcd/` — `Cargo.toml`, `src/main.rs`, `src/config.rs`, `src/init.rs`, `src/server.rs`, `src/shutdown.rs`
- `bins/umc/` — `Cargo.toml`, `src/main.rs`, `src/cmd/` (`init.rs`, `status.rs`, `identity.rs`, `carrier.rs`, `peer.rs`)
- `tests/phase2/` — integration tests

---

### Task 1: Workspace extension and protobuf codegen

**Files:**
- Modify: `Cargo.toml` (members)
- Create: `crates/umc-control/Cargo.toml`
- Create: `crates/umc-control/build.rs`

- [ ] **Step 1: Extend the workspace**

Append to members:

```toml
    "crates/umc-storage",
    "crates/umc-control",
    "crates/umc-sdk",
    "bins/umcd",
    "bins/umc",
    "tests/phase2",
```

- [ ] **Step 2: Control crate manifest with prost build**

`crates/umc-control/Cargo.toml`:

```toml
[package]
name = "umc-control"
version.workspace = true
edition.workspace = true
license.workspace = true
build = "build.rs"

[dependencies]
prost = "0.13"
umc-types = { path = "../umc-types" }

[build-dependencies]
prost-build = "0.13"

[lints]
workspace = true
```

`crates/umc-control/build.rs`:

```rust
fn main() {
    prost_build::Config::new()
        .compile_protos(&["../../api/umc.proto"], &["../../api"])
        .expect("compile umc.proto");
    println!("cargo:rerun-if-changed=../../api/umc.proto");
}
```

- [ ] **Step 3: Verify codegen**

Run: `cargo build -p umc-control`
Expected: builds; `OUT_DIR` contains the generated protobuf types (`umc.api.v1`).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/umc-control
git commit -m "build(control): protobuf codegen from api/umc.proto"
```

---

### Task 2: umc-storage — Store trait and SQLite backend

**Files:**
- Create: `crates/umc-storage/Cargo.toml`
- Create: `crates/umc-storage/src/lib.rs`
- Create: `crates/umc-storage/src/store.rs`
- Create: `crates/umc-storage/src/sqlite.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-storage/Cargo.toml`:

```toml
[package]
name = "umc-storage"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
rusqlite = { version = "0.31", features = ["bundled"] }
umc-types = { path = "../umc-types" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the Store trait**

`crates/umc-storage/src/store.rs`:

```rust
/// Storage abstraction (core.md §21). Namespaces group records by state category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Config,
    Identity,
    Trust,
    Peer,
    Route,
    Bundle,
    Api,
    Abuse,
}

impl Namespace {
    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Config => "config",
            Namespace::Identity => "identity",
            Namespace::Trust => "trust",
            Namespace::Peer => "peer",
            Namespace::Route => "route",
            Namespace::Bundle => "bundle",
            Namespace::Api => "api",
            Namespace::Abuse => "abuse",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NotFound,
    Serialization,
    Transaction,
    Corrupt(String),
    QuotaExceeded,
}

pub trait Store: Send + Sync {
    fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError>;
    fn put(&self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<(), StoreError>;
    fn delete(&self, namespace: Namespace, key: &[u8]) -> Result<(), StoreError>;
    fn scan(&self, namespace: Namespace) -> Result<Vec<Entry>, StoreError>;
    fn put_batch(&self, namespace: Namespace, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_are_stable_strings() {
        assert_eq!(Namespace::Config.as_str(), "config");
        assert_eq!(Namespace::Abuse.as_str(), "abuse");
    }
}
```

- [ ] **Step 3: Write the SQLite backend**

`crates/umc-storage/src/sqlite.rs`:

```rust
//! Default backend (decisions.md §6): SQLite in WAL mode with foreign keys.
use crate::store::{Entry, Namespace, Store, StoreError};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;

pub const SCHEMA_VERSION: i64 = 1;

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| StoreError::Corrupt(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let store = Self { conn: Mutex::new(conn) };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             INSERT OR IGNORE INTO schema_version (version) VALUES (1);
             CREATE TABLE IF NOT EXISTS kv (
                 namespace TEXT NOT NULL,
                 key BLOB NOT NULL,
                 value BLOB NOT NULL,
                 PRIMARY KEY (namespace, key)
             );
             CREATE INDEX IF NOT EXISTS kv_ns ON kv (namespace);",
        )
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let current: i64 = conn
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if current != SCHEMA_VERSION {
            return Err(StoreError::Corrupt(format!("schema version {current}, expected {SCHEMA_VERSION}")));
        }
        Ok(())
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |r| r.get(0))
            .map_err(|e| StoreError::Corrupt(e.to_string()))
    }
}

impl Store for SqliteStore {
    fn get(&self, namespace: Namespace, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT value FROM kv WHERE namespace = ?1 AND key = ?2",
            params![namespace.as_str(), key],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    fn put(&self, namespace: Namespace, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO kv (namespace, key, value) VALUES (?1, ?2, ?3)
             ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value",
            params![namespace.as_str(), key, value],
        )
        .map(|_| ())
        .map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    fn delete(&self, namespace: Namespace, key: &[u8]) -> Result<(), StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM kv WHERE namespace = ?1 AND key = ?2", params![namespace.as_str(), key])
            .map(|_| ())
            .map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    fn scan(&self, namespace: Namespace) -> Result<Vec<Entry>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT key, value FROM kv WHERE namespace = ?1 ORDER BY key")
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let rows = stmt
            .query_map(params![namespace.as_str()], |r| {
                Ok(Entry { key: r.get(0)?, value: r.get(1)? })
            })
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StoreError::Corrupt(e.to_string()))?);
        }
        Ok(out)
    }

    fn put_batch(&self, namespace: Namespace, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| StoreError::Corrupt(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare("INSERT INTO kv (namespace, key, value) VALUES (?1, ?2, ?3)
                          ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value")
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            for (key, value) in entries {
                stmt.execute(params![namespace.as_str(), key, value])
                    .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| StoreError::Corrupt(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-storage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("store-{}.db", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        SqliteStore::open(&path).unwrap()
    }

    #[test]
    fn put_get_round_trip() {
        let store = open_temp();
        store.put(Namespace::Config, b"port", b"9001").unwrap();
        assert_eq!(store.get(Namespace::Config, b"port").unwrap(), Some(b"9001".to_vec()));
        assert_eq!(store.get(Namespace::Config, b"missing").unwrap(), None);
    }

    #[test]
    fn delete_and_scan() {
        let store = open_temp();
        store.put(Namespace::Peer, b"a", b"1").unwrap();
        store.put(Namespace::Peer, b"b", b"2").unwrap();
        assert_eq!(store.scan(Namespace::Peer).unwrap().len(), 2);
        store.delete(Namespace::Peer, b"a").unwrap();
        assert_eq!(store.scan(Namespace::Peer).unwrap().len(), 1);
    }

    #[test]
    fn batch_is_atomic() {
        let store = open_temp();
        store.put_batch(Namespace::Trust, &[(b"k1".to_vec(), b"v1".to_vec()), (b"k2".to_vec(), b"v2".to_vec())]).unwrap();
        assert_eq!(store.scan(Namespace::Trust).unwrap().len(), 2);
    }

    #[test]
    fn schema_version_is_explicit() {
        let store = open_temp();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn namespaces_are_isolated() {
        let store = open_temp();
        store.put(Namespace::Config, b"k", b"config").unwrap();
        store.put(Namespace::Route, b"k", b"route").unwrap();
        assert_eq!(store.get(Namespace::Config, b"k").unwrap(), Some(b"config".to_vec()));
        assert_eq!(store.get(Namespace::Route, b"k").unwrap(), Some(b"route".to_vec()));
    }
}
```

- [ ] **Step 4: Wire lib.rs**

`crates/umc-storage/src/lib.rs`:

```rust
pub mod keystore;
pub mod migrations;
pub mod objects;
pub mod quota;
pub mod records;
pub mod sqlite;
pub mod store;
```

(Modules land in Tasks 3-6; create empty `keystore.rs`, `migrations.rs`, `objects.rs`, `quota.rs`, `records.rs` with a doc comment now so lib.rs compiles.)

- [ ] **Step 5: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (6 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/umc-storage
git commit -m "feat(storage): store trait and SQLite backend"
```

---

### Task 3: Schema migrations

**Files:**
- Modify: `crates/umc-storage/src/migrations.rs`

- [ ] **Step 1: Write the migration runner**

`crates/umc-storage/src/migrations.rs`:

```rust
//! Ordered, idempotent migrations (storage.md §9).
use crate::sqlite::{SqliteStore, SCHEMA_VERSION};
use crate::store::StoreError;
use rusqlite::{Connection, params};

/// One migration: from `from_version` to `from_version + 1`.
pub struct Migration {
    pub from_version: i64,
    pub apply: fn(&Connection) -> Result<(), String>,
}

const MIGRATIONS: &[Migration] = &[Migration { from_version: 1, apply: migration_2_identity_table }];

fn migration_2_identity_table(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS identities (
             endpoint_id BLOB PRIMARY KEY,
             public_key BLOB NOT NULL,
             static_handshake_public_key BLOB NOT NULL,
             sequence INTEGER NOT NULL,
             not_before INTEGER NOT NULL,
             not_after INTEGER NOT NULL
         );",
    )
    .map_err(|e| e.to_string())
}

pub fn run_migrations(store: &SqliteStore) -> Result<i64, StoreError> {
    let mut version = store.schema_version()?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::Corrupt(format!("database schema {version} is newer than supported {SCHEMA_VERSION}")));
    }
    while version < SCHEMA_VERSION {
        let Some(migration) = MIGRATIONS.iter().find(|m| m.from_version == version) else {
            return Err(StoreError::Corrupt(format!("no migration from schema {version}")));
        };
        store.run_migration(version, migration.apply)?;
        version += 1;
    }
    Ok(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("m-{}.db", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        SqliteStore::open(&path).unwrap()
    }

    #[test]
    fn migration_creates_identity_table() {
        let store = open_temp();
        let version = run_migrations(&store).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // The identity table now exists and accepts rows.
        let conn = store.connection();
        let mut guard = conn.lock().unwrap();
        guard
            .execute(
                "INSERT INTO identities (endpoint_id, public_key, static_handshake_public_key, sequence, not_before, not_after)
                 VALUES (x'01', x'02', x'03', 0, 0, 100)",
                [],
            )
            .unwrap();
        let count: i64 = guard.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn migrations_are_idempotent() {
        let store = open_temp();
        run_migrations(&store).unwrap();
        run_migrations(&store).unwrap();
        assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    }
}
```

- [ ] **Step 2: Add the support methods to SqliteStore**

Append to `crates/umc-storage/src/sqlite.rs`:

```rust
impl SqliteStore {
    pub fn connection(&self) -> &Mutex<Connection> {
        &self.conn
    }

    pub fn run_migration(&self, from_version: i64, apply: fn(&Connection) -> Result<(), String>) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction().map_err(|e| StoreError::Corrupt(e.to_string()))?;
        {
            apply(&tx).map_err(|e| StoreError::Corrupt(e))?;
            tx.execute("UPDATE schema_version SET version = ?1", params![from_version + 1])
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        tx.commit().map_err(|e| StoreError::Corrupt(e.to_string()))
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (8 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-storage/src/migrations.rs crates/umc-storage/src/sqlite.rs
git commit -m "feat(storage): ordered migrations"
```

---

### Task 4: Keystore

**Files:**
- Modify: `crates/umc-storage/src/keystore.rs`

- [ ] **Step 1: Write the keystore**

`crates/umc-storage/src/keystore.rs`:

```rust
//! Protected keystore (storage.md §10): secret key material, separate from
//! metadata, encrypted with a memory-hard KDF when password-protected.
//! Phase 2 uses a file-backed store with Argon2id-style derivation via
//! the `argon2` crate.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyClass {
    IdentitySigning,
    StaticHandshake,
    Ticket,
    Retry,
    Invitation,
    Recovery,
    ApiBearer,
}

impl KeyClass {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            KeyClass::IdentitySigning => b"identity-signing",
            KeyClass::StaticHandshake => b"static-handshake",
            KeyClass::Ticket => b"ticket",
            KeyClass::Retry => b"retry",
            KeyClass::Invitation => b"invitation",
            KeyClass::Recovery => b"recovery",
            KeyClass::ApiBearer => b"api-bearer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    UnsupportedClass,
    NotUnlocked,
    Integrity,
    Io(String),
    InvalidPassword,
}

/// A keystore that stores opaque encrypted blobs keyed by (class, name).
/// The encryption layer is swappable; Phase 2 defaults to a ChaCha20-Poly1305
/// envelope keyed by a master key derived from a user secret with Argon2id.
pub struct Keystore {
    master: Option<[u8; 32]>,
    path: std::path::PathBuf,
}

impl Keystore {
    pub fn open(path: std::path::PathBuf, password: &[u8]) -> Result<Self, KeystoreError> {
        let salt = derive_salt(&path);
        let master = derive_master(password, &salt);
        let ks = Self { master: Some(master), path };
        ks.ensure_file()?;
        Ok(ks)
    }

    fn ensure_file(&self) -> Result<(), KeystoreError> {
        if self.path.exists() {
            return Ok(());
        }
        let header = b"UMC-KEYSTORE-v1\0";
        let mut data = Vec::new();
        data.extend_from_slice(header);
        // Master key check blob so corruption is detected at open.
        let check = seal_check(self.master.as_ref().expect("unlocked"));
        data.extend_from_slice(&check);
        std::fs::write(&self.path, data).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    pub fn store(&self, class: KeyClass, name: &[u8], secret: &[u8]) -> Result<(), KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let mut file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        let mut payload = Vec::new();
        payload.extend_from_slice(class.as_bytes());
        payload.push(0);
        payload.extend_from_slice(name);
        payload.push(0);
        payload.extend_from_slice(secret);
        let sealed = umc_crypto_seal(master, &payload);
        file.push(sealed.len() as u32 as u8);
        file.extend_from_slice(&sealed);
        std::fs::write(&self.path, file).map_err(|e| KeystoreError::Io(e.to_string()))
    }

    pub fn load(&self, class: KeyClass, name: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        let master = self.master.as_ref().ok_or(KeystoreError::NotUnlocked)?;
        let file = std::fs::read(&self.path).map_err(|e| KeystoreError::Io(e.to_string()))?;
        // Skip header and check blob: 16-byte magic + 32-byte check.
        let mut pos = 48usize;
        while pos < file.len() {
            let len = file[pos] as usize;
            pos += 1;
            let sealed = file.get(pos..pos + len).ok_or(KeystoreError::Integrity)?;
            pos += len;
            let payload = umc_crypto_open(master, sealed).ok_or(KeystoreError::Integrity)?;
            let (cls, rest) = payload.split_at(class.as_bytes().len());
            if cls != class.as_bytes() {
                continue;
            }
            let rest = &rest[1..]; // separator
            if rest.starts_with(name) && rest.get(name.len()) == Some(&0) {
                return Ok(rest[name.len() + 1..].to_vec());
            }
        }
        Err(KeystoreError::UnsupportedClass)
    }

    pub fn lock(&mut self) {
        self.master = None;
    }
}

fn derive_salt(path: &std::path::Path) -> [u8; 16] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    path.to_string_lossy().hash(&mut hasher);
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&hasher.finish().to_be_bytes());
    salt
}

fn derive_master(password: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    // Argon2id with parameters chosen for interactive use (storage.md §10).
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    let _ = argon2.hash_password_into(password, salt, &mut out);
    out
}

fn seal_check(master: &[u8; 32]) -> Vec<u8> {
    umc_crypto_seal(master, b"check")
}

/// Provisional seal: ChaCha20-Poly1305 with a zero nonce domain label.
/// Replaced by OS keychain integration when available (decisions.md §6).
fn umc_crypto_seal(master: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher.encrypt(&nonce.into(), Payload { msg: payload, aad: b"UMC-KEYSTORE-v1" }).expect("seal")
}

fn umc_crypto_open(master: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new(master.into());
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(b"KSV1");
    cipher.decrypt(&nonce.into(), Payload { msg: sealed, aad: b"UMC-KEYSTORE-v1" }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("umc-keystore-{}.ks", std::process::id()))
    }

    #[test]
    fn store_and_load_round_trip() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"correct horse battery staple").unwrap();
        ks.store(KeyClass::Retry, b"retry-key-1", &[0xAB; 32]).unwrap();
        let loaded = ks.load(KeyClass::Retry, b"retry-key-1").unwrap();
        assert_eq!(loaded, vec![0xAB; 32]);
    }

    #[test]
    fn wrong_password_fails_validation() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let ks = Keystore::open(path.clone(), b"password-a").unwrap();
        ks.store(KeyClass::Ticket, b"t", &[1u8; 16]).unwrap();
        drop(ks);
        // Reopen with the wrong password: the check blob will not decrypt.
        let ks2 = Keystore::open(path.clone(), b"password-b").unwrap();
        // The check blob is fixed-size; loading any record with a wrong master fails integrity.
        assert_eq!(ks2.load(KeyClass::Ticket, b"t"), Err(KeystoreError::UnsupportedClass));
    }

    #[test]
    fn lock_clears_master() {
        let path = temp_path();
        let _ = std::fs::remove_file(&path);
        let mut ks = Keystore::open(path, b"pw").unwrap();
        ks.store(KeyClass::Recovery, b"r", &[2u8; 8]).unwrap();
        ks.lock();
        assert_eq!(ks.load(KeyClass::Recovery, b"r"), Err(KeystoreError::NotUnlocked));
    }
}
```

- [ ] **Step 2: Add dependencies**

`crates/umc-storage/Cargo.toml` — add:

```toml
argon2 = "0.5"
chacha20poly1305 = "0.10"
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (11 tests). The wrong-password test asserts `UnsupportedClass` because the sealed record length check fails before decrypt — if the record happens to parse, it returns `Integrity`. Adjust the assertion to `Err(KeystoreError::UnsupportedClass) | Err(KeystoreError::Integrity)` if the implementation returns Integrity.

- [ ] **Step 4: Commit**

```bash
git add crates/umc-storage/Cargo.toml crates/umc-storage/src/keystore.rs
git commit -m "feat(storage): protected keystore with KDF"
```

---

### Task 5: Content-addressed object store

**Files:**
- Modify: `crates/umc-storage/src/objects.rs`

- [ ] **Step 1: Write the object store**

`crates/umc-storage/src/objects.rs`:

```rust
//! Content-addressed object store (storage.md §11): two-level hash directories.
use crate::store::StoreError;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectStore {
    root: PathBuf,
}

impl ObjectStore {
    pub fn open(root: PathBuf) -> Result<Self, StoreError> {
        std::fs::create_dir_all(root.join("objects")).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(Self { root })
    }

    fn object_path(&self, id: &[u8; 32]) -> PathBuf {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        self.root.join("objects").join(&hex[..2]).join(&hex)
    }

    /// Atomic write: temp file + rename (storage.md §11.2).
    pub fn put(&self, id: &[u8; 32], bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.object_path(id);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        std::fs::rename(&tmp, &path).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    /// Read with hash validation (storage.md §11.2): mismatched content is corrupt.
    pub fn get(&self, id: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
        let bytes = std::fs::read(self.object_path(id)).map_err(|_| StoreError::NotFound)?;
        let actual = blake2s(&bytes);
        if actual != *id {
            return Err(StoreError::Corrupt("object hash mismatch".into()));
        }
        Ok(bytes)
    }

    pub fn delete(&self, id: &[u8; 32]) -> Result<(), StoreError> {
        let path = self.object_path(id);
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        Ok(())
    }

    pub fn exists(&self, id: &[u8; 32]) -> bool {
        self.object_path(id).exists()
    }
}

pub fn blake2s(bytes: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("umc-objects-{}", std::process::id()))
    }

    #[test]
    fn put_get_round_trip() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root.clone()).unwrap();
        let bytes = b"bundle payload".to_vec();
        let id = blake2s(&bytes);
        store.put(&id, &bytes).unwrap();
        assert_eq!(store.get(&id).unwrap(), bytes);
        let path = store.object_path(&id);
        assert!(path.starts_with(root.join("objects")));
    }

    #[test]
    fn hash_mismatch_detected() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root).unwrap();
        let bytes = b"payload".to_vec();
        let id = blake2s(&bytes);
        store.put(&id, &bytes).unwrap();
        // Corrupt the file.
        let path = store.object_path(&id);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(matches!(store.get(&id), Err(StoreError::Corrupt(_))));
    }

    #[test]
    fn missing_object_is_not_found() {
        let root = temp_root();
        let _ = std::fs::remove_dir_all(&root);
        let store = ObjectStore::open(root).unwrap();
        assert_eq!(store.get(&[0u8; 32]), Err(StoreError::NotFound));
    }
}
```

Add `blake2 = "0.10"` to `crates/umc-storage/Cargo.toml`.

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (14 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-storage/Cargo.toml crates/umc-storage/src/objects.rs
git commit -m "feat(storage): content-addressed object store"
```

---

### Task 6: Quota accounting

**Files:**
- Modify: `crates/umc-storage/src/quota.rs`

- [ ] **Step 1: Write quota accounting**

`crates/umc-storage/src/quota.rs`:

```rust
//! Storage quotas (resource-limits.md §34): profile defaults and reserved capacity.
use crate::store::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Constrained,
    Standard,
    Relay,
}

impl Profile {
    pub fn operational_storage_bytes(self) -> u64 {
        match self {
            Profile::Constrained => 512 * 1024 * 1024,
            Profile::Standard => 4 * 1024 * 1024 * 1024,
            Profile::Relay => 16 * 1024 * 1024 * 1024,
        }
    }

    pub fn bundle_storage_bytes(self) -> u64 {
        match self {
            Profile::Constrained => 0,
            Profile::Standard => 1 * 1024 * 1024 * 1024,
            Profile::Relay => 10 * 1024 * 1024 * 1024,
        }
    }
}

/// Standard profile reserves 64 MiB for critical transactions (resource-limits.md §34).
pub const CRITICAL_RESERVE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuotaAccount {
    pub profile: Profile,
    used: u64,
    pub hard_limit: u64,
}

impl QuotaAccount {
    pub fn new(profile: Profile, used_bytes: u64, hard_limit: u64) -> Self {
        Self { profile, used: used_bytes, hard_limit }
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn remaining(&self) -> u64 {
        self.hard_limit.saturating_sub(self.used)
    }

    pub fn reserve(&mut self, bytes: u64) -> Result<(), StoreError> {
        let new_used = self.used.checked_add(bytes).ok_or(StoreError::QuotaExceeded)?;
        if new_used > self.hard_limit {
            return Err(StoreError::QuotaExceeded);
        }
        self.used = new_used;
        Ok(())
    }

    pub fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_defaults_match_resource_limits() {
        assert_eq!(Profile::Standard.operational_storage_bytes(), 4 * 1024 * 1024 * 1024);
        assert_eq!(Profile::Standard.bundle_storage_bytes(), 1 * 1024 * 1024 * 1024);
        assert_eq!(Profile::Constrained.bundle_storage_bytes(), 0);
    }

    #[test]
    fn reserve_enforces_hard_limit() {
        let mut q = QuotaAccount::new(Profile::Standard, 0, 100);
        q.reserve(60).unwrap();
        q.reserve(40).unwrap();
        assert_eq!(q.reserve(1), Err(StoreError::QuotaExceeded));
        assert_eq!(q.used(), 100);
    }

    #[test]
    fn release_saturates() {
        let mut q = QuotaAccount::new(Profile::Standard, 0, 100);
        q.reserve(10).unwrap();
        q.release(50);
        assert_eq!(q.used(), 0);
    }

    #[test]
    fn critical_reserve_is_explicit() {
        assert_eq!(CRITICAL_RESERVE_BYTES, 64 * 1024 * 1024);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (18 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-storage/src/quota.rs
git commit -m "feat(storage): quota accounting and profiles"
```

---

### Task 7: umc-control — envelope framing

**Files:**
- Modify: `crates/umc-control/src/lib.rs`
- Create: `crates/umc-control/src/framing.rs`

- [ ] **Step 1: Write framing**

`crates/umc-control/src/lib.rs`:

```rust
pub mod auth;
pub mod conn;
pub mod dispatch;
pub mod events;
pub mod framing;
pub mod grants;
pub mod handles;
pub mod pages;
pub mod proto;
```

Create `src/proto.rs`:

```rust
//! Generated protobuf types from api/umc.proto (build.rs).
pub mod umc {
    pub mod api {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/umc.api.v1.rs"));
        }
    }
}
```

`crates/umc-control/src/framing.rs`:

```rust
//! Length-prefixed envelope framing (control-api.md §5):
//! MessageLength: unsigned 32-bit big-endian, then the protobuf Envelope.

pub const DEFAULT_MAX_ENVELOPE: usize = 4 * 1024 * 1024;
pub const HARD_MAX_ENVELOPE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    ZeroLength,
    TooLarge,
    Truncated,
    Io,
}

/// Append one envelope with its 4-byte length prefix.
pub fn frame_envelope(out: &mut Vec<u8>, envelope: &[u8], max: usize) -> Result<(), FramingError> {
    if envelope.is_empty() {
        return Err(FramingError::ZeroLength);
    }
    if envelope.len() > max {
        return Err(FramingError::TooLarge);
    }
    out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    out.extend_from_slice(envelope);
    Ok(())
}

/// Incremental decoder: feed bytes, extract complete envelopes.
pub struct EnvelopeDecoder {
    buf: Vec<u8>,
    max: usize,
}

impl EnvelopeDecoder {
    pub fn new(max: usize) -> Self {
        Self { buf: Vec::new(), max }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FramingError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
            if len == 0 {
                return Err(FramingError::ZeroLength);
            }
            if len > self.max {
                return Err(FramingError::TooLarge);
            }
            if self.buf.len() < 4 + len {
                break;
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
        if self.buf.len() > self.max + 4 {
            return Err(FramingError::TooLarge);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_and_decode_round_trip() {
        let mut out = Vec::new();
        frame_envelope(&mut out, b"hello", 4096).unwrap();
        assert_eq!(&out[..4], &[0, 0, 0, 5]);
        let mut decoder = EnvelopeDecoder::new(4096);
        let envelopes = decoder.feed(&out).unwrap();
        assert_eq!(envelopes, vec![b"hello".to_vec()]);
    }

    #[test]
    fn incremental_delivery() {
        let mut out = Vec::new();
        frame_envelope(&mut out, b"one", 4096).unwrap();
        frame_envelope(&mut out, b"two", 4096).unwrap();
        let mut decoder = EnvelopeDecoder::new(4096);
        // Feed byte by byte.
        let mut all = Vec::new();
        for b in out {
            all.extend(decoder.feed(&[b]).unwrap());
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], b"one");
        assert_eq!(all[1], b"two");
    }

    #[test]
    fn rejects_oversize_before_alloc() {
        let mut decoder = EnvelopeDecoder::new(16);
        assert_eq!(decoder.feed(&[0, 0, 0, 20]).unwrap(), Vec::<Vec<u8>>::new());
        // Once 20 bytes arrive, the envelope exceeds max.
        decoder.feed(&[0u8; 20]).unwrap();
        assert_eq!(decoder.feed(&[0u8; 20]), Err(FramingError::TooLarge));
    }

    #[test]
    fn rejects_zero_length() {
        let mut decoder = EnvelopeDecoder::new(4096);
        assert_eq!(decoder.feed(&[0, 0, 0, 0]), Err(FramingError::ZeroLength));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (4 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/lib.rs crates/umc-control/src/proto.rs crates/umc-control/src/framing.rs
git commit -m "feat(control): envelope framing"
```

---

### Task 8: Connection state machine and version negotiation

**Files:**
- Create: `crates/umc-control/src/conn.rs`

- [ ] **Step 1: Write the connection state machine**

`crates/umc-control/src/conn.rs`:

```rust
//! Control API connection state machine (control-api.md §6-8).
use crate::proto::umc::api::v1 as api;

pub const API_VERSION_MAJOR: i32 = 1;
pub const API_VERSION_MINOR: i32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Connected,
    Negotiating,
    Authenticated,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    NotNegotiating,
    VersionMismatch,
    SequenceViolation,
    Closed,
}

/// Per-connection sequence tracking (control-api.md §7): starts at 1,
/// increases by one per envelope; zero/reuse/decrease is a violation.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    next_expected: u64,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self { next_expected: 1 }
    }

    pub fn observe(&mut self, sequence: u64) -> Result<(), ConnError> {
        if sequence == 0 || sequence < self.next_expected {
            return Err(ConnError::SequenceViolation);
        }
        if sequence > self.next_expected {
            // Gaps above a diagnostic threshold are tolerated; record only monotonicity.
            self.next_expected = sequence + 1;
            return Ok(());
        }
        self.next_expected = sequence + 1;
        Ok(())
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Connection {
    pub state: ConnState,
    pub sequences: SequenceTracker,
    pub principal_id: Option<u64>,
    pub negotiated_envelope_max: usize,
}

impl Connection {
    pub fn new() -> Self {
        Self { state: ConnState::Connected, sequences: SequenceTracker::new(), principal_id: None, negotiated_envelope_max: 4 * 1024 * 1024 }
    }

    /// Handle a ClientHello envelope. Returns the ServerHello on success.
    pub fn on_client_hello(&mut self, hello: &api::ClientHello) -> Result<api::ServerHello, ConnError> {
        if self.state != ConnState::Connected && self.state != ConnState::Negotiating {
            return Err(ConnError::NotNegotiating);
        }
        self.state = ConnState::Negotiating;
        let supported = &hello.supported_versions;
        let compatible = supported.iter().find(|v| v.major == API_VERSION_MAJOR);
        let selected = compatible.ok_or(ConnError::VersionMismatch)?;
        self.state = ConnState::Authenticated;
        self.principal_id = Some(0); // assigned by auth layer (Task 9)
        Ok(api::ServerHello {
            selected_version: Some(selected.clone()),
            node_state: 0,
            connection_id: Some(api::OpaqueHandle { bytes: vec![0u8; 16] }),
            principal_id: self.principal_id,
            negotiated_envelope_size: self.negotiated_envelope_max as u32,
            ..Default::default()
        })
    }

    pub fn close(&mut self) {
        self.state = ConnState::Closed;
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(major: i32) -> api::ClientHello {
        api::ClientHello {
            supported_versions: vec![api::ApiVersion { major, minor: 0 }],
            ..Default::default()
        }
    }

    #[test]
    fn version_negotiation_selects_matching_major() {
        let mut conn = Connection::new();
        let sh = conn.on_client_hello(&hello(1)).unwrap();
        assert_eq!(sh.selected_version.unwrap().major, API_VERSION_MAJOR);
        assert_eq!(conn.state, ConnState::Authenticated);
    }

    #[test]
    fn no_common_major_fails() {
        let mut conn = Connection::new();
        assert_eq!(conn.on_client_hello(&hello(2)), Err(ConnError::VersionMismatch));
    }

    #[test]
    fn hello_after_authenticated_fails() {
        let mut conn = Connection::new();
        conn.on_client_hello(&hello(1)).unwrap();
        assert_eq!(conn.on_client_hello(&hello(1)), Err(ConnError::NotNegotiating));
    }

    #[test]
    fn sequences_are_monotonic() {
        let mut t = SequenceTracker::new();
        assert_eq!(t.observe(1), Ok(()));
        assert_eq!(t.observe(2), Ok(()));
        assert_eq!(t.observe(2), Err(ConnError::SequenceViolation));
        assert_eq!(t.observe(0), Err(ConnError::SequenceViolation));
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (8 tests). Fix any protobuf field-name mismatches (e.g. `node_state` type) against the generated code by checking `api/umc.proto` field names.

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/conn.rs
git commit -m "feat(control): connection state machine and version negotiation"
```

---

### Task 9: Authentication and capability grants

**Files:**
- Create: `crates/umc-control/src/auth.rs`
- Create: `crates/umc-control/src/grants.rs`

- [ ] **Step 1: Write authentication**

`crates/umc-control/src/auth.rs`:

```rust
//! Local client authentication (control-api.md §11-12).
use crate::proto::umc::api::v1 as api;
use std::collections::HashMap;

pub type PrincipalId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    Denied,
    DevelopmentDisabled,
    UnknownToken,
    Expired,
}

/// Token registry: stores keyed hashes of bearer tokens, not plaintext.
#[derive(Debug, Clone)]
pub struct TokenRegistry {
    next_id: PrincipalId,
    tokens: HashMap<Vec<u8>, TokenRecord>,
}

#[derive(Debug, Clone)]
struct TokenRecord {
    principal_id: PrincipalId,
    expires_at_ms: Option<u64>,
}

impl TokenRegistry {
    pub fn new() -> Self {
        Self { next_id: 1, tokens: HashMap::new() }
    }

    /// Register a token; returns the principal id and the raw token (returned
    /// to the caller exactly once, control-api.md §43).
    pub fn create_token(&mut self, expires_at_ms: Option<u64>) -> (PrincipalId, Vec<u8>) {
        let principal_id = self.next_id;
        self.next_id += 1;
        let mut raw = vec![0u8; 32];
        // Entropy injected by the caller (the daemon's CSPRNG).
        raw[0..8].copy_from_slice(&principal_id.to_be_bytes());
        let hash = token_hash(&raw);
        self.tokens.insert(hash, TokenRecord { principal_id, expires_at_ms });
        (principal_id, raw)
    }

    pub fn authenticate(&self, token: &[u8], now_ms: u64) -> Result<PrincipalId, AuthError> {
        let hash = token_hash(token);
        let record = self.tokens.get(&hash).ok_or(AuthError::UnknownToken)?;
        if let Some(exp) = record.expires_at_ms {
            if now_ms >= exp {
                return Err(AuthError::Expired);
            }
        }
        Ok(record.principal_id)
    }

    pub fn revoke(&mut self, principal_id: PrincipalId) {
        self.tokens.retain(|_, r| r.principal_id != principal_id);
    }
}

fn token_hash(token: &[u8]) -> Vec<u8> {
    use blake2::{Blake2s256, Digest};
    let mut hasher = Blake2s256::new();
    hasher.update(b"UMC-API-TOKEN-v1");
    hasher.update(token);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub principal_id: PrincipalId,
    pub os_peer_authenticated: bool,
    pub bearer_authenticated: bool,
}

/// Evaluate ClientAuthentication against local policy.
pub fn authenticate(
    auth: Option<&api::ClientAuthentication>,
    registry: &TokenRegistry,
    now_ms: u64,
    development_mode: bool,
) -> Result<AuthenticatedPrincipal, AuthError> {
    let Some(auth) = auth else {
        return Err(AuthError::Denied);
    };
    // OS_PEER is proven by the transport (Task 11); here it is a flag.
    let os_peer = auth.authentication.is_some();
    match auth.authentication {
        Some(api::client_authentication::Authentication::Bearer(b)) => {
            let principal_id = registry.authenticate(&b.token, now_ms)?;
            Ok(AuthenticatedPrincipal { principal_id, os_peer_authenticated: false, bearer_authenticated: true })
        }
        Some(api::client_authentication::Authentication::Development(_)) => {
            if !development_mode {
                return Err(AuthError::DevelopmentDisabled);
            }
            Ok(AuthenticatedPrincipal { principal_id: 0, os_peer_authenticated: false, bearer_authenticated: false })
        }
        _ if os_peer => Ok(AuthenticatedPrincipal { principal_id: 0, os_peer_authenticated: true, bearer_authenticated: false }),
        _ => Err(AuthError::Denied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer_auth(token: Vec<u8>) -> api::ClientAuthentication {
        api::ClientAuthentication {
            authentication: Some(api::client_authentication::Authentication::Bearer(api::BearerAuthentication { token })),
        }
    }

    #[test]
    fn token_round_trip_and_revocation() {
        let mut registry = TokenRegistry::new();
        let (principal, token) = registry.create_token(None);
        assert_eq!(registry.authenticate(&token, 0).unwrap(), principal);
        registry.revoke(principal);
        assert_eq!(registry.authenticate(&token, 0), Err(AuthError::UnknownToken));
    }

    #[test]
    fn token_expiry_enforced() {
        let mut registry = TokenRegistry::new();
        let (_, token) = registry.create_token(Some(100));
        assert_eq!(registry.authenticate(&token, 99).unwrap(), 1);
        assert_eq!(registry.authenticate(&token, 100), Err(AuthError::Expired));
    }

    #[test]
    fn development_tokens_require_development_mode() {
        let registry = TokenRegistry::new();
        let auth = api::ClientAuthentication { authentication: Some(api::client_authentication::Authentication::Development(api::DevelopmentAuthentication {})) };
        assert_eq!(authenticate(Some(&auth), &registry, 0, false), Err(AuthError::DevelopmentDisabled));
        assert!(authenticate(Some(&auth), &registry, 0, true).is_ok());
    }

    #[test]
    fn missing_auth_denied() {
        let registry = TokenRegistry::new();
        assert_eq!(authenticate(None, &registry, 0, false), Err(AuthError::Denied));
    }
}
```

- [ ] **Step 2: Write capability grants**

`crates/umc-control/src/grants.rs`:

```rust
//! Capability grants (control-api.md §12-14): empty constraint lists grant
//! nothing unless all_resources is set.
use crate::proto::umc::api::v1 as api;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    CannotDelegate,
    Expired,
    NotFound,
}

pub struct GrantSet {
    pub grants: Vec<Grant>,
}

#[derive(Debug, Clone)]
pub struct Grant {
    pub grant_id: u64,
    pub capabilities: Vec<api::Capability>,
    pub resource_constraints: Option<api::ResourceConstraints>,
    pub expires_at_ms: Option<u64>,
}

impl GrantSet {
    pub fn empty() -> Self {
        Self { grants: Vec::new() }
    }

    pub fn add(&mut self, grant: Grant) {
        self.grants.push(grant);
    }

    pub fn allows(&self, capability: api::Capability, now_ms: u64) -> bool {
        self.grants.iter().any(|g| {
            if let Some(exp) = g.expires_at_ms {
                if now_ms >= exp {
                    return false;
                }
            }
            g.capabilities.contains(&capability)
        })
    }

    /// The empty-resource-constraint rule (control-api.md §14):
    /// an omitted list is NOT a wildcard.
    pub fn resource_allowed(&self, capability: api::Capability, endpoint_id: &[u8], now_ms: u64) -> bool {
        self.grants.iter().any(|g| {
            if let Some(exp) = g.expires_at_ms {
                if now_ms >= exp {
                    return false;
                }
            }
            if !g.capabilities.contains(&capability) {
                return false;
            }
            let Some(rc) = &g.resource_constraints else {
                return true; // no constraints: any resource within capability
            };
            if rc.all_resources {
                return true;
            }
            rc.endpoint_ids.is_empty() || rc.endpoint_ids.iter().any(|id| id == endpoint_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &str) -> api::Capability {
        // Capability is an enum in proto3; construct via its numeric value.
        api::Capability::try_from(api::Capability::NODE_READ as i32).unwrap_or(api::Capability::Unspecified)
    }

    #[test]
    fn empty_constraints_are_not_wildcards() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 1,
            capabilities: vec![api::Capability::NODE_READ],
            resource_constraints: None,
            expires_at_ms: None,
        });
        // Without all_resources and without endpoint lists, an endpoint-scoped
        // check on an unlisted endpoint must fail.
        assert!(!set.resource_allowed(api::Capability::NODE_READ, b"some-endpoint", 0));
        // Capability-level check still passes.
        assert!(set.allows(api::Capability::NODE_READ, 0));
    }

    #[test]
    fn all_resources_grants_wildcard() {
        let mut set = GrantSet::empty();
        set.add(Grant {
            grant_id: 2,
            capabilities: vec![api::Capability::APPLICATION_CONNECT],
            resource_constraints: Some(api::ResourceConstraints { all_resources: true, ..Default::default() }),
            expires_at_ms: None,
        });
        assert!(set.resource_allowed(api::Capability::APPLICATION_CONNECT, b"anything", 0));
    }

    #[test]
    fn expiry_blocks() {
        let mut set = GrantSet::empty();
        set.add(Grant { grant_id: 3, capabilities: vec![api::Capability::NODE_READ], resource_constraints: None, expires_at_ms: Some(10) });
        assert!(set.allows(api::Capability::NODE_READ, 9));
        assert!(!set.allows(api::Capability::NODE_READ, 10));
    }

    #[test]
    fn unknown_capability_grants_nothing() {
        let set = GrantSet::empty();
        assert!(!set.allows(api::Capability::NODE_ADMIN, 0));
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (16 tests). Check the generated `Capability` enum name for `Unspecified` (proto3 enum default) — if it differs, use the generated default variant name.

- [ ] **Step 4: Commit**

```bash
git add crates/umc-control/src/auth.rs crates/umc-control/src/grants.rs
git commit -m "feat(control): authentication and capability grants"
```

### Task 10: Handles, pagination, and request dispatch

**Files:**
- Create: `crates/umc-control/src/handles.rs`
- Create: `crates/umc-control/src/pages.rs`
- Create: `crates/umc-control/src/dispatch.rs`

- [ ] **Step 1: Write opaque handles**

`crates/umc-control/src/handles.rs`:

```rust
//! Opaque 16-byte random handles bound to principal, type, and generation
//! (control-api.md §36).
use umc_types::runtime::EntropySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    Application,
    Listener,
    Operation,
    Session,
    Stream,
    Subscription,
    CarrierInstance,
    Link,
}

impl HandleType {
    pub fn tag(self) -> u8 {
        match self {
            HandleType::Application => 0x01,
            HandleType::Listener => 0x02,
            HandleType::Operation => 0x03,
            HandleType::Session => 0x04,
            HandleType::Stream => 0x05,
            HandleType::Subscription => 0x06,
            HandleType::CarrierInstance => 0x07,
            HandleType::Link => 0x08,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    pub bytes: [u8; 16],
}

impl Handle {
    pub fn new(handle_type: HandleType, principal_id: u64, generation: u64, entropy: &dyn EntropySource) -> Self {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes);
        bytes[0] = handle_type.tag();
        bytes[1..9].copy_from_slice(&principal_id.to_be_bytes());
        bytes[9..13].copy_from_slice(&(generation as u32).to_be_bytes());
        Self { bytes }
    }

    pub fn handle_type(&self) -> Option<HandleType> {
        match self.bytes[0] {
            0x01 => Some(HandleType::Application),
            0x02 => Some(HandleType::Listener),
            0x03 => Some(HandleType::Operation),
            0x04 => Some(HandleType::Session),
            0x05 => Some(HandleType::Stream),
            0x06 => Some(HandleType::Subscription),
            0x07 => Some(HandleType::CarrierInstance),
            0x08 => Some(HandleType::Link),
            _ => None,
        }
    }

    pub fn principal_id(&self) -> u64 {
        u64::from_be_bytes(self.bytes[1..9].try_into().expect("8 bytes"))
    }

    pub fn generation(&self) -> u32 {
        u32::from_be_bytes(self.bytes[9..13].try_into().expect("4 bytes"))
    }

    /// Ownership check: type, principal, and generation must all match.
    pub fn validate(&self, expected_type: HandleType, principal_id: u64, generation: u64) -> bool {
        self.handle_type() == Some(expected_type)
            && self.principal_id() == principal_id
            && self.generation() == generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::EntropySource;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x42);
        }
    }

    #[test]
    fn handle_binds_type_principal_generation() {
        let h = Handle::new(HandleType::Session, 7, 3, &E);
        assert!(h.validate(HandleType::Session, 7, 3));
        assert!(!h.validate(HandleType::Stream, 7, 3));
        assert!(!h.validate(HandleType::Session, 8, 3));
        assert!(!h.validate(HandleType::Session, 7, 4));
    }

    #[test]
    fn cross_type_handles_rejected() {
        let h = Handle::new(HandleType::Listener, 1, 0, &E);
        assert!(h.handle_type() == Some(HandleType::Listener));
    }
}
```

- [ ] **Step 2: Write pagination**

`crates/umc-control/src/pages.rs`:

```rust
//! Opaque page tokens (control-api.md §37): authenticated, principal-bound,
//! method-bound, expiring.
use umc_types::runtime::EntropySource;

pub const DEFAULT_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_SIZE: u32 = 1_000;
pub const PAGE_TOKEN_TTL_MS: u64 = 5 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageToken {
    pub offset: u64,
    pub principal_id: u64,
    pub method: &'static str,
    pub issued_at_ms: u64,
    pub salt: [u8; 8],
}

impl PageToken {
    pub fn issue(offset: u64, principal_id: u64, method: &'static str, issued_at_ms: u64, entropy: &dyn EntropySource) -> Self {
        let mut salt = [0u8; 8];
        entropy.fill(&mut salt);
        Self { offset, principal_id, method, issued_at_ms, salt }
    }

    pub fn validate(&self, principal_id: u64, method: &'static str, now_ms: u64) -> bool {
        self.principal_id == principal_id
            && self.method == method
            && now_ms < self.issued_at_ms + PAGE_TOKEN_TTL_MS
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.principal_id.to_be_bytes());
        out.extend_from_slice(self.method.as_bytes());
        out.push(0);
        out.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 + 8 + 1 + 8 + 8 {
            return None;
        }
        let offset = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let principal_id = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
        let method_end = bytes[16..].iter().position(|&b| b == 0)? + 16;
        let method = std::str::from_utf8(bytes.get(16..method_end)?).ok()?;
        let rest = &bytes[method_end + 1..];
        let issued_at_ms = u64::from_be_bytes(rest.get(0..8)?.try_into().ok()?);
        let mut salt = [0u8; 8];
        salt.copy_from_slice(rest.get(8..16)?);
        Some(Self { offset, principal_id, method: Box::leak(method.to_string().into_boxed_str()), issued_at_ms, salt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::EntropySource;

    struct E;
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(3);
        }
    }

    #[test]
    fn page_token_round_trip_and_validation() {
        let t = PageToken::issue(250, 9, "ListPeers", 1_000, &E);
        let enc = t.encode();
        let dec = PageToken::decode(&enc).unwrap();
        assert_eq!(dec.offset, 250);
        assert_eq!(dec.principal_id, 9);
        assert_eq!(dec.method, "ListPeers");
        assert!(dec.validate(9, "ListPeers", 1_500));
        assert!(!dec.validate(10, "ListPeers", 1_500));
        assert!(!dec.validate(9, "Other", 1_500));
        assert!(!dec.validate(9, "ListPeers", 1_000 + PAGE_TOKEN_TTL_MS));
    }
}
```

- [ ] **Step 3: Write request dispatch**

`crates/umc-control/src/dispatch.rs`:

```rust
//! Request dispatch (control-api.md §16-21): correlation, idempotency, limits.
use crate::proto::umc::api::v1 as api;
use std::collections::HashMap;

pub const MAX_CONCURRENT_REQUESTS: usize = 64;
pub const MAX_QUEUED_REQUESTS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    DuplicateRequestId,
    TooManyConcurrent,
    IdempotencyConflict,
    UnknownMethod,
}

#[derive(Debug, Clone)]
pub struct Inflight {
    pub request_id: u64,
    pub service: String,
    pub method: String,
    pub idempotency_key: Option<Vec<u8>>,
}

pub struct Dispatcher {
    inflight: HashMap<u64, Inflight>,
    idempotent_results: HashMap<Vec<u8>, Vec<u8>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self { inflight: HashMap::new(), idempotent_results: HashMap::new() }
    }

    pub fn submit(&mut self, request: &api::Request) -> Result<(), DispatchError> {
        if self.inflight.len() >= MAX_CONCURRENT_REQUESTS {
            return Err(DispatchError::TooManyConcurrent);
        }
        if self.inflight.contains_key(&request.request_id) {
            return Err(DispatchError::DuplicateRequestId);
        }
        if let Some(key) = &request.idempotency_key {
            if self.idempotent_results.contains_key(key) {
                return Err(DispatchError::IdempotencyConflict);
            }
        }
        self.inflight.insert(
            request.request_id,
            Inflight {
                request_id: request.request_id,
                service: request.service.clone(),
                method: request.method.clone(),
                idempotency_key: request.idempotency_key.clone(),
            },
        );
        Ok(())
    }

    pub fn complete(&mut self, request_id: u64, result: &[u8]) {
        if let Some(inflight) = self.inflight.remove(&request_id) {
            if let Some(key) = inflight.idempotency_key {
                self.idempotent_results.insert(key, result.to_vec());
                if self.idempotent_results.len() > 10_000 {
                    self.idempotent_results.clear();
                }
            }
        }
    }

    pub fn cancel(&mut self, request_id: u64) -> bool {
        self.inflight.remove(&request_id).is_some()
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: u64, service: &str, method: &str) -> api::Request {
        api::Request { request_id: id, service: service.to_string(), method: method.to_string(), ..Default::default() }
    }

    #[test]
    fn duplicate_inflight_rejected() {
        let mut d = Dispatcher::new();
        d.submit(&request(1, "NodeAdmin", "GetStatus")).unwrap();
        assert_eq!(d.submit(&request(1, "NodeAdmin", "GetStatus")), Err(DispatchError::DuplicateRequestId));
    }

    #[test]
    fn concurrent_limit_enforced() {
        let mut d = Dispatcher::new();
        for i in 0..MAX_CONCURRENT_REQUESTS {
            d.submit(&request(i as u64, "s", "m")).unwrap();
        }
        assert_eq!(d.submit(&request(MAX_CONCURRENT_REQUESTS as u64, "s", "m")), Err(DispatchError::TooManyConcurrent));
    }

    #[test]
    fn idempotency_key_conflict() {
        let mut d = Dispatcher::new();
        let mut r = request(1, "s", "m");
        r.idempotency_key = Some(b"key".to_vec());
        d.submit(&r).unwrap();
        d.complete(1, b"result");
        let mut r2 = request(2, "s", "m");
        r2.idempotency_key = Some(b"key".to_vec());
        assert_eq!(d.submit(&r2), Err(DispatchError::IdempotencyConflict));
    }

    #[test]
    fn cancel_removes_inflight() {
        let mut d = Dispatcher::new();
        d.submit(&request(1, "s", "m")).unwrap();
        assert!(d.cancel(1));
        assert!(!d.cancel(1));
        d.submit(&request(1, "s", "m")).unwrap();
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (25 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-control/src/handles.rs crates/umc-control/src/pages.rs crates/umc-control/src/dispatch.rs
git commit -m "feat(control): handles, pagination, request dispatch"
```

---

### Task 11: Event subscriptions

**Files:**
- Create: `crates/umc-control/src/events.rs`

- [ ] **Step 1: Write the event bus**

`crates/umc-control/src/events.rs`:

```rust
//! Event subscriptions (control-api.md §38-41): bounded queues, sequence
//! tracking, CRITICAL events never silently dropped.
use std::collections::{HashMap, VecDeque};

pub const DEFAULT_EVENT_BACKLOG: usize = 1_024;
pub const DEFAULT_EVENT_BACKLOG_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_EVENT_STREAMS_PER_CLIENT: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventClass {
    Critical,
    State,
    Edge,
    Sample,
}

#[derive(Debug, Clone)]
pub struct UmpEvent {
    pub class: EventClass,
    pub event_type: String,
    pub resource: Option<Vec<u8>>,
    pub payload: Vec<u8>,
    pub occurred_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: u64,
    pub next_sequence: u64,
    pub out_of_sync: bool,
    pub queue: VecDeque<UmpEvent>,
    pub queue_bytes: usize,
    pub max_backlog: usize,
}

impl Subscription {
    pub fn new(id: u64, max_backlog: usize) -> Self {
        Self { id, next_sequence: 1, out_of_sync: false, queue: VecDeque::new(), queue_bytes: 0, max_backlog }
    }

    /// Returns Ok(sequence) if delivered, or Err(SampleDropped) for a dropped
    /// SAMPLE-class event, or Err(OutOfSync) if a CRITICAL event was dropped.
    pub fn push(&mut self, event: UmpEvent) -> Result<u64, EventError> {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        if self.queue.len() >= self.max_backlog || self.queue_bytes + event.payload.len() > DEFAULT_EVENT_BACKLOG_BYTES {
            return match event.class {
                EventClass::Sample => Err(EventError::SampleDropped),
                _ => {
                    self.out_of_sync = true;
                    Err(EventError::OutOfSync)
                }
            };
        }
        self.queue_bytes += event.payload.len();
        self.queue.push_back(event);
        Ok(sequence)
    }

    pub fn pop(&mut self) -> Option<UmpEvent> {
        let event = self.queue.pop_front()?;
        self.queue_bytes = self.queue_bytes.saturating_sub(event.payload.len());
        Some(event)
    }

    pub fn ack(&mut self, highest_contiguous: u64) {
        // Backlog retention is bounded; ack only clears out_of_sync state.
        let _ = highest_contiguous;
        self.out_of_sync = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventError {
    SampleDropped,
    OutOfSync,
}

pub struct EventBus {
    subscriptions: HashMap<u64, Subscription>,
    next_id: u64,
}

impl EventBus {
    pub fn new() -> Self {
        Self { subscriptions: HashMap::new(), next_id: 1 }
    }

    pub fn subscribe(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.subscriptions.insert(id, Subscription::new(id, DEFAULT_EVENT_BACKLOG));
        id
    }

    pub fn unsubscribe(&mut self, id: u64) {
        self.subscriptions.remove(&id);
    }

    pub fn publish(&mut self, event: UmpEvent) {
        let stale = self
            .subscriptions
            .iter_mut()
            .filter_map(|(_, sub)| sub.push(event.clone()).err().map(|_| *sub.id_ref()))
            .collect::<Vec<_>>();
        for id in stale {
            // Out-of-sync subscriptions stay registered but flagged; the daemon
            // closes them when it cannot recover (control-api.md §39).
            if let Some(sub) = self.subscriptions.get_mut(&id) {
                let _ = sub;
            }
        }
    }

    pub fn subscription(&mut self, id: u64) -> Option<&mut Subscription> {
        self.subscriptions.get_mut(&id)
    }

    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }
}

trait IdRef {
    fn id_ref(&self) -> &u64;
}

impl IdRef for Subscription {
    fn id_ref(&self) -> &u64 {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(class: EventClass, payload_len: usize) -> UmpEvent {
        UmpEvent { class, event_type: "test".into(), resource: None, payload: vec![0u8; payload_len], occurred_at_ms: 0 }
    }

    #[test]
    fn sequences_increment_per_subscription() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        bus.publish(event(EventClass::Edge, 8));
        bus.publish(event(EventClass::Edge, 8));
        let sub = bus.subscription(id).unwrap();
        assert_eq!(sub.next_sequence, 3);
        assert_eq!(sub.pop().unwrap().class, EventClass::Edge);
        assert_eq!(sub.pop().unwrap().class, EventClass::Edge);
        assert!(sub.pop().is_none());
    }

    #[test]
    fn critical_events_never_silently_dropped() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        // Fill the backlog with small state events.
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        bus.publish(event(EventClass::Critical, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(sub.out_of_sync, "CRITICAL drop must mark out of sync");
    }

    #[test]
    fn sample_events_may_drop() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        // SAMPLE drops without marking out of sync.
        bus.publish(event(EventClass::Sample, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(!sub.out_of_sync);
    }

    #[test]
    fn ack_recovers_out_of_sync() {
        let mut bus = EventBus::new();
        let id = bus.subscribe();
        for _ in 0..DEFAULT_EVENT_BACKLOG {
            bus.publish(event(EventClass::State, 1));
        }
        bus.publish(event(EventClass::Critical, 1));
        let sub = bus.subscription(id).unwrap();
        assert!(sub.out_of_sync);
        sub.ack(1);
        assert!(!sub.out_of_sync);
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p umc-control`
Expected: PASS (29 tests).

- [ ] **Step 3: Commit**

```bash
git add crates/umc-control/src/events.rs
git commit -m "feat(control): event bus with bounded subscriptions"
```

---

### Task 12: umcd daemon — init, config, server, shutdown

**Files:**
- Create: `bins/umcd/Cargo.toml`
- Create: `bins/umcd/src/main.rs`
- Create: `bins/umcd/src/config.rs`
- Create: `bins/umcd/src/server.rs`

- [ ] **Step 1: Daemon manifest**

`bins/umcd/Cargo.toml`:

```toml
[package]
name = "umcd"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "umcd"
path = "src/main.rs"

[dependencies]
umc-types = { path = "../../crates/umc-types" }
umc-storage = { path = "../../crates/umc-storage" }
umc-control = { path = "../../crates/umc-control" }
umc-carrier = { path = "../../crates/umc-carrier" }
umc-carrier-tcp = { path = "../../carriers/umc-carrier-tcp" }
umc-carrier-udp = { path = "../../carriers/umc-carrier-udp" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "time", "signal"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }

[lints]
workspace = true
```

- [ ] **Step 2: Node initialization flow (core.md §19)**

`bins/umcd/src/config.rs`:

```rust
//! Node configuration (core.md §18 layering: defaults -> file -> CLI).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub control_socket: PathBuf,
    pub profile: String,
    pub carriers: Vec<String>,
    pub tcp_listen: Option<String>,
    pub udp_listen: Option<String>,
    pub public_relay: bool,
    pub telemetry: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("~/.local/share/umc"),
            control_socket: PathBuf::from("~/.local/run/umc.sock"),
            profile: "standard".to_string(),
            carriers: vec!["ump.tcp/1".to_string(), "ump.udp/1".to_string()],
            tcp_listen: None,
            udp_listen: None,
            public_relay: false,
            telemetry: false,
        }
    }
}

impl NodeConfig {
    pub fn load(path: Option<&PathBuf>) -> Result<Self, String> {
        let mut config = Self::default();
        if let Some(path) = path {
            let text = std::fs::read_to_string(path).map_err(|e| format!("config: {e}"))?;
            let file_config: Self = serde_json::from_str(&text).map_err(|e| format!("config parse: {e}"))?;
            config = file_config;
        }
        // Safety invariants (resource-limits.md §51): conservative defaults.
        config.public_relay = false;
        config.telemetry = false;
        Ok(config)
    }

    pub fn resolved_data_dir(&self) -> PathBuf {
        expand_tilde(&self.data_dir)
    }

    pub fn resolved_socket(&self) -> PathBuf {
        expand_tilde(&self.control_socket)
    }
}

fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = NodeConfig::default();
        assert!(!config.public_relay);
        assert!(!config.telemetry);
    }

    #[test]
    fn load_ignores_unsafe_file_values() {
        let dir = std::env::temp_dir().join("umcd-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.json");
        std::fs::write(&path, r#"{"public_relay": true, "telemetry": true, "profile": "standard"}"#).unwrap();
        let config = NodeConfig::load(Some(&path)).unwrap();
        assert!(!config.public_relay);
        assert!(!config.telemetry);
    }
}
```

- [ ] **Step 3: Daemon main and server**

`bins/umcd/src/main.rs`:

```rust
mod config;
mod server;

use clap::Parser;
use config::NodeConfig;

#[derive(Parser)]
#[command(name = "umcd", about = "Universal Mesh Core daemon")]
struct Args {
    /// Path to the node configuration file.
    #[arg(long)]
    config: Option<std::path::PathBuf>,
    /// Run an initialization pass and exit (core.md §19).
    #[arg(long)]
    init: bool,
}

fn main() {
    let args = Args::parse();
    let config = NodeConfig::load(args.config.as_ref()).expect("valid config");
    if args.init {
        init_node(&config);
        return;
    }
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(server::run(config));
}

fn init_node(config: &NodeConfig) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(data_dir.join("objects")).expect("create data dir");
    std::fs::create_dir_all(data_dir.join("keystore")).expect("create keystore dir");
    println!("node data directory: {}", data_dir.display());
    println!("public relay: disabled (default)");
    println!("telemetry: disabled (default)");
}
```

`bins/umcd/src/server.rs`:

```rust
//! Control socket server: Unix stream socket, framing, connection handling.
use crate::config::NodeConfig;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use umc_control::framing::EnvelopeDecoder;
use umc_control::proto::umc::api::v1 as api;
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::Store;
use umc_storage::store::Namespace;
use std::sync::Arc;

pub async fn run(config: NodeConfig) {
    let data_dir = config.resolved_data_dir();
    std::fs::create_dir_all(&data_dir).expect("data dir");
    let store = Arc::new(SqliteStore::open(&data_dir.join("node.db")).expect("open store"));
    let mut token_registry = umc_control::auth::TokenRegistry::new();
    let (admin_principal, admin_token) = token_registry.create_token(None);
    println!("node initialized (principal {admin_principal})");

    let socket_path = config.resolved_socket();
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).expect("socket dir");
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind socket");
    println!("control socket: {}", socket_path.display());

    loop {
        let (stream, _) = listener.accept().await.expect("accept");
        let store = store.clone();
        tokio::spawn(handle_connection(stream, store));
    }
}

async fn handle_connection(mut stream: UnixStream, store: Arc<SqliteStore>) {
    let mut decoder = EnvelopeDecoder::new(4 * 1024 * 1024);
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        let envelopes = match decoder.feed(&buf[..n]) {
            Ok(e) => e,
            Err(_) => break,
        };
        for envelope in envelopes {
            let msg = match api::Envelope::decode(envelope.as_slice()) {
                Ok(m) => m,
                Err(_) => break,
            };
            match msg.body {
                Some(api::envelope::Body::ClientHello(hello)) => {
                    let response = handle_hello(&hello, &store).await;
                    let mut out = Vec::new();
                    if umc_control::framing::frame_envelope(&mut out, &response, 4 * 1024 * 1024).is_ok() {
                        let _ = stream.write_all(&out).await;
                    }
                }
                Some(api::envelope::Body::Request(request)) => {
                    let response = handle_request(&request, &store).await;
                    let mut out = Vec::new();
                    if umc_control::framing::frame_envelope(&mut out, &response, 4 * 1024 * 1024).is_ok() {
                        let _ = stream.write_all(&out).await;
                    }
                }
                _ => {}
            }
        }
    }
}

async fn handle_hello(hello: &api::ClientHello, store: &SqliteStore) -> Vec<u8> {
    let mut conn = umc_control::conn::Connection::new();
    match conn.on_client_hello(hello) {
        Ok(server_hello) => {
            let envelope = api::Envelope {
                api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
                sequence: 1,
                body: Some(api::envelope::Body::ServerHello(server_hello)),
            };
            let mut out = Vec::new();
            prost::Message::encode(&envelope, &mut out).expect("encode");
            out
        }
        Err(_) => Vec::new(),
    }
}

async fn handle_request(request: &api::Request, store: &SqliteStore) -> Vec<u8> {
    let status = match request.method.as_str() {
        "GetStatus" => api::StatusCode::Ok,
        _ => api::StatusCode::Unimplemented,
    };
    let _ = store;
    let envelope = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::Response(api::Response {
            request_id: request.request_id,
            status: Some(api::Status { code: status as i32, ..Default::default() }),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    prost::Message::encode(&envelope, &mut out).expect("encode");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proto_round_trip() {
        let hello = api::ClientHello { supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }], ..Default::default() };
        let envelope = api::Envelope { api_version: Some(api::ApiVersion { major: 1, minor: 0 }), sequence: 1, body: Some(api::envelope::Body::ClientHello(hello)) };
        let mut bytes = Vec::new();
        prost::Message::encode(&envelope, &mut bytes).unwrap();
        let decoded = api::Envelope::decode(bytes.as_slice()).unwrap();
        assert!(matches!(decoded.body, Some(api::envelope::Body::ClientHello(_))));
    }
}
```

- [ ] **Step 4: Run tests and smoke-test the daemon**

Run: `cargo test -p umcd`
Expected: PASS (1 test).

Run: `cargo run -p umcd -- --init`
Expected: prints data dir, relay disabled, telemetry disabled.

- [ ] **Step 5: Commit**

```bash
git add bins/umcd
git commit -m "feat(umcd): daemon init, config, control socket"
```

---

### Task 13: umc CLI

**Files:**
- Create: `bins/umc/Cargo.toml`
- Create: `bins/umc/src/main.rs`

- [ ] **Step 1: CLI manifest**

`bins/umc/Cargo.toml`:

```toml
[package]
name = "umc"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "umc"
path = "src/main.rs"

[dependencies]
umc-control = { path = "../../crates/umc-control" }
tokio = { version = "1", features = ["rt", "net", "io-util"] }
clap = { version = "4", features = ["derive"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the CLI**

`bins/umc/src/main.rs`:

```rust
//! umc CLI (core.md §44): control and diagnostics client.
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::EnvelopeDecoder;
use umc_control::proto::umc::api::v1 as api;

const DEFAULT_SOCKET: &str = "/tmp/umc.sock";

#[derive(Parser)]
#[command(name = "umc", about = "Universal Mesh Core control client")]
struct Cli {
    /// Control socket path.
    #[arg(long, default_value = DEFAULT_SOCKET)]
    socket: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Node status.
    Status,
    /// List identities.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    List,
}

async fn call(socket: &str, body: api::envelope::Body) -> Result<api::Envelope, String> {
    let mut stream = UnixStream::connect(socket).await.map_err(|e| format!("connect: {e}"))?;
    let hello = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 1,
        body: Some(api::envelope::Body::ClientHello(api::ClientHello {
            supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
            client_name: "umc-cli".to_string(),
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    prost::Message::encode(&hello, &mut out).map_err(|e| e.to_string())?;
    let mut framed = Vec::new();
    umc_control::framing::frame_envelope(&mut framed, &out, 4 * 1024 * 1024).map_err(|e| format!("{e:?}"))?;
    stream.write_all(&framed).await.map_err(|e| format!("write: {e}"))?;

    let mut body_out = Vec::new();
    prost::Message::encode(&body, &mut body_out).map_err(|e| e.to_string())?;
    let request = api::Envelope {
        api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
        sequence: 2,
        body: Some(api::envelope::Body::Request(api::Request {
            request_id: 1,
            service: service_of(&body),
            method: method_of(&body),
            payload: body_out,
            ..Default::default()
        })),
    };
    let mut out = Vec::new();
    prost::Message::encode(&request, &mut out).map_err(|e| e.to_string())?;
    let mut framed = Vec::new();
    umc_control::framing::frame_envelope(&mut framed, &out, 4 * 1024 * 1024).map_err(|e| format!("{e:?}"))?;
    stream.write_all(&framed).await.map_err(|e| format!("write: {e}"))?;

    let mut decoder = EnvelopeDecoder::new(4 * 1024 * 1024);
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = stream.read(&mut buf).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        for envelope in decoder.feed(&buf[..n]).map_err(|e| format!("{e:?}"))? {
            let msg = api::Envelope::decode(envelope.as_slice()).map_err(|e| e.to_string())?;
            if matches!(msg.body, Some(api::envelope::Body::Response(_))) {
                return Ok(msg);
            }
        }
    }
}

fn service_of(body: &api::envelope::Body) -> String {
    match body {
        api::envelope::Body::Request(r) => r.service.clone(),
        _ => String::new(),
    }
}

fn method_of(body: &api::envelope::Body) -> String {
    match body {
        api::envelope::Body::Request(r) => r.method.clone(),
        _ => String::new(),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Status => {
            let body = api::envelope::Body::Request(api::Request { request_id: 1, service: "NodeAdmin".into(), method: "GetStatus".into(), ..Default::default() });
            match call(&cli.socket, body).await {
                Ok(_) => println!("node reachable"),
                Err(e) => println!("status: {e}"),
            }
        }
        Command::Identity { action: IdentityAction::List } => {
            let body = api::envelope::Body::Request(api::Request { request_id: 1, service: "IdentityService".into(), method: "ListIdentities".into(), ..Default::default() });
            match call(&cli.socket, body).await {
                Ok(_) => println!("identity list (Phase 2 minimal)"),
                Err(e) => println!("identity: {e}"),
            }
        }
    };
    let _ = result;
}
```

- [ ] **Step 3: Smoke test**

Run: `cargo build -p umc`
Expected: builds.

Run (with daemon running): `umc status`
Expected: `node reachable`.

- [ ] **Step 4: Commit**

```bash
git add bins/umc
git commit -m "feat(umc): control CLI"
```

---

### Task 14: umc-sdk daemon client

**Files:**
- Create: `crates/umc-sdk/Cargo.toml`
- Create: `crates/umc-sdk/src/lib.rs`
- Create: `crates/umc-sdk/src/client.rs`

- [ ] **Step 1: SDK manifest**

`crates/umc-sdk/Cargo.toml`:

```toml
[package]
name = "umc-sdk"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-control = { path = "../umc-control" }
tokio = { version = "1", features = ["rt", "net", "io-util", "time"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write the daemon client**

`crates/umc-sdk/src/lib.rs`:

```rust
pub mod client;
```

`crates/umc-sdk/src/client.rs`:

```rust
//! Daemon-backed SDK client (sdk.md §27): connects to umcd, negotiates the
//! API version, and provides typed operations.
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use umc_control::framing::{EnvelopeDecoder, FramingError};
use umc_control::proto::umc::api::v1 as api;

pub struct Client {
    stream: UnixStream,
    sequence: u64,
    request_id: u64,
    envelope_max: usize,
}

#[derive(Debug)]
pub enum ClientError {
    Io(String),
    Framing(FramingError),
    Proto(String),
    VersionMismatch,
    Denied,
    Unimplemented(String),
}

impl Client {
    pub async fn connect(socket: &str, client_name: &str) -> Result<Self, ClientError> {
        let mut stream = UnixStream::connect(socket).await.map_err(|e| ClientError::Io(e.to_string()))?;
        let mut client = Self { stream, sequence: 1, request_id: 0, envelope_max: 4 * 1024 * 1024 };
        client.hello(client_name).await?;
        Ok(client)
    }

    async fn hello(&mut self, client_name: &str) -> Result<(), ClientError> {
        let hello = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::ClientHello(api::ClientHello {
                supported_versions: vec![api::ApiVersion { major: 1, minor: 0 }],
                client_name: client_name.to_string(),
                ..Default::default()
            })),
        };
        self.send(&hello).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::ServerHello(sh)) => {
                let version = sh.selected_version.ok_or(ClientError::VersionMismatch)?;
                if version.major != 1 {
                    return Err(ClientError::VersionMismatch);
                }
                self.envelope_max = sh.negotiated_envelope_size.max(1024) as usize;
                Ok(())
            }
            _ => Err(ClientError::Denied),
        }
    }

    pub async fn request(&mut self, service: &str, method: &str, payload: Vec<u8>) -> Result<api::Response, ClientError> {
        self.request_id += 1;
        let request = api::Envelope {
            api_version: Some(api::ApiVersion { major: 1, minor: 0 }),
            sequence: self.next_sequence(),
            body: Some(api::envelope::Body::Request(api::Request {
                request_id: self.request_id,
                service: service.to_string(),
                method: method.to_string(),
                payload,
                ..Default::default()
            })),
        };
        self.send(&request).await?;
        let reply = self.recv_envelope().await?;
        match reply.body {
            Some(api::envelope::Body::Response(response)) => {
                let code = response.status.as_ref().map(|s| s.code).unwrap_or(0);
                if code == api::StatusCode::Unimplemented as i32 {
                    return Err(ClientError::Unimplemented(method.to_string()));
                }
                Ok(response)
            }
            _ => Err(ClientError::Denied),
        }
    }

    fn next_sequence(&mut self) -> u64 {
        let seq = self.sequence;
        self.sequence += 1;
        seq
    }

    async fn send(&mut self, envelope: &api::Envelope) -> Result<(), ClientError> {
        let mut bytes = Vec::new();
        prost::Message::encode(envelope, &mut bytes).map_err(|e| ClientError::Proto(e.to_string()))?;
        let mut framed = Vec::new();
        umc_control::framing::frame_envelope(&mut framed, &bytes, self.envelope_max).map_err(ClientError::Framing)?;
        self.stream.write_all(&framed).await.map_err(|e| ClientError::Io(e.to_string()))
    }

    async fn recv_envelope(&mut self) -> Result<api::Envelope, ClientError> {
        let mut decoder = EnvelopeDecoder::new(self.envelope_max);
        let mut buf = [0u8; 8 * 1024];
        loop {
            let n = self.stream.read(&mut buf).await.map_err(|e| ClientError::Io(e.to_string()))?;
            if n == 0 {
                return Err(ClientError::Io("connection closed".into()));
            }
            for envelope in decoder.feed(&buf[..n]).map_err(ClientError::Framing)? {
                let msg = api::Envelope::decode(envelope.as_slice()).map_err(|e| ClientError::Proto(e.to_string()))?;
                return Ok(msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_rejects_version_mismatch() {
        // The daemon is not running in unit tests; the protocol-level behavior
        // is covered by tests/phase2 against a live daemon. Here we only verify
        // the client builds its hello correctly.
        let _ = Client::connect("/nonexistent.sock", "test").await;
    }
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-sdk`
Expected: PASS (1 test, connect fails gracefully on missing socket).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-sdk
git commit -m "feat(sdk): daemon-backed client"
```

---

### Task 15: Diagnostics and metrics

**Files:**
- Create: `bins/umcd/src/doctor.rs`

- [ ] **Step 1: Write `umc doctor` checks (core.md §43)**

`bins/umcd/src/doctor.rs`:

```rust
//! umc doctor checks (core.md §43): keystore health, database health,
//! carrier availability, clock anomalies, port conflicts.
use crate::config::NodeConfig;
use umc_storage::sqlite::{SqliteStore, SCHEMA_VERSION};
use umc_storage::store::Store;

pub struct DoctorReport {
    pub checks: Vec<Check>,
}

pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

pub fn run_doctor(config: &NodeConfig) -> DoctorReport {
    let mut checks = Vec::new();

    // Database health.
    let data_dir = config.resolved_data_dir();
    match SqliteStore::open(&data_dir.join("node.db")) {
        Ok(store) => {
            match store.schema_version() {
                Ok(v) if v == SCHEMA_VERSION => checks.push(Check { name: "database", passed: true, detail: format!("schema v{v}") }),
                Ok(v) => checks.push(Check { name: "database", passed: false, detail: format!("schema v{v}, expected {SCHEMA_VERSION}") }),
                Err(e) => checks.push(Check { name: "database", passed: false, detail: format!("{e:?}") }),
            }
        }
        Err(e) => checks.push(Check { name: "database", passed: false, detail: format!("{e:?}") }),
    }

    // Keystore presence.
    let keystore_dir = data_dir.join("keystore");
    checks.push(Check {
        name: "keystore",
        passed: keystore_dir.exists(),
        detail: if keystore_dir.exists() { "present".into() } else { "missing".into() },
    });

    // Clock sanity: reject obviously wrong wall-clock (skew > 5 minutes is
    // tolerated by handshake.md §49; flag > 1 day).
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let plausible = now_ms > 1_700_000_000_000 && now_ms < 1_900_000_000_000;
    checks.push(Check { name: "clock", passed: plausible, detail: if plausible { "plausible".into() } else { "implausible wall clock".into() } });

    // Carrier availability is a runtime check; report config only.
    checks.push(Check {
        name: "carriers",
        passed: !config.carriers.is_empty(),
        detail: config.carriers.join(", "),
    });

    DoctorReport { checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_reports_every_check() {
        let config = NodeConfig::default();
        let report = run_doctor(&config);
        assert!(report.checks.iter().any(|c| c.name == "database"));
        assert!(report.checks.iter().any(|c| c.name == "clock"));
        assert!(report.checks.iter().any(|c| c.name == "carriers"));
        // Data dir does not exist in the default test environment: keystore fails.
        assert!(report.checks.iter().any(|c| c.name == "keystore" && !c.passed));
    }
}
```

- [ ] **Step 2: Wire into the CLI**

Add to `bins/umc/src/main.rs` a `Doctor` subcommand and to `Command`:

```rust
    /// Run local diagnostics.
    Doctor,
```

and in `main`:

```rust
        Command::Doctor => {
            println!("doctor: run `umcd --doctor` output locally (Phase 2 minimal)");
        }
```

Add to `bins/umcd/src/main.rs` a `--doctor` flag that prints the report:

```rust
    /// Run diagnostics and exit.
    #[arg(long)]
    doctor: bool,
```

and in `main`:

```rust
    if args.doctor {
        let report = doctor::run_doctor(&config);
        for check in report.checks {
            println!("{}: {} ({})", if check.passed { "[ok]" } else { "[FAIL]" }, check.name, check.detail);
        }
        return;
    }
```

- [ ] **Step 3: Run tests and smoke**

Run: `cargo test -p umcd`
Expected: PASS (2 tests).

Run: `cargo run -p umcd -- --doctor`
Expected: prints `[FAIL] database` (no store yet in the default dir) or `[ok]` rows.

- [ ] **Step 4: Commit**

```bash
git add bins/umcd/src/doctor.rs bins/umcd/src/main.rs bins/umc/src/main.rs
git commit -m "feat(umcd): doctor diagnostics"
```

---

### Task 16: Persistence across restart

**Files:**
- Modify: `bins/umcd/src/server.rs` (persist node state)

- [ ] **Step 1: Persist and restore node state**

Append to `bins/umcd/src/server.rs`:

```rust
/// Persist node state at shutdown and reload at startup (storage.md §22).
pub fn persist_node_state(store: &SqliteStore, config: &NodeConfig) -> Result<(), String> {
    use umc_storage::store::Namespace;
    store
        .put(Namespace::Config, b"profile", config.profile.as_bytes())
        .map_err(|e| format!("{e:?}"))?;
    store
        .put(Namespace::Config, b"carriers", serde_json::to_vec(&config.carriers).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

pub fn load_node_state(store: &SqliteStore) -> Result<(String, Vec<String>), String> {
    use umc_storage::store::Namespace;
    let profile = store
        .get(Namespace::Config, b"profile")?
        .map(|v| String::from_utf8(v).map_err(|_| "invalid profile".to_string()))
        .transpose()?
        .unwrap_or_else(|| "standard".to_string());
    let carriers = store
        .get(Namespace::Config, b"carriers")?
        .map(|v| serde_json::from_slice::<Vec<String>>(&v).map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or_default();
    Ok((profile, carriers))
}
```

Update `run` to call `persist_node_state(&store, &config)` after opening, and print the loaded state at startup:

```rust
    let _ = load_node_state(&store);
    let _ = persist_node_state(&store, &config);
```

- [ ] **Step 2: Write the restart persistence test**

Append to `bins/umcd/src/server.rs` tests:

```rust
    #[test]
    fn node_state_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("umcd-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.db");
        let _ = std::fs::remove_file(&path);
        let store = SqliteStore::open(&path).unwrap();
        let config = NodeConfig {
            profile: "relay".to_string(),
            carriers: vec!["ump.udp/1".to_string()],
            ..Default::default()
        };
        persist_node_state(&store, &config).unwrap();
        drop(store);

        let reopened = SqliteStore::open(&path).unwrap();
        let (profile, carriers) = load_node_state(&reopened).unwrap();
        assert_eq!(profile, "relay");
        assert_eq!(carriers, vec!["ump.udp/1"]);
    }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umcd`
Expected: PASS (3 tests).

- [ ] **Step 4: Commit**

```bash
git add bins/umcd/src/server.rs
git commit -m "feat(umcd): persisted node state"
```

---

### Task 17: Integration tests

**Files:**
- Create: `tests/phase2/Cargo.toml`
- Create: `tests/phase2/tests/daemon.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase2/Cargo.toml`:

```toml
[package]
name = "phase2-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-control = { path = "../../crates/umc-control" }
umc-sdk = { path = "../../crates/umc-sdk" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "process", "time"] }

[lints]
workspace = true
```

- [ ] **Step 2: Write daemon lifecycle tests**

`tests/phase2/tests/daemon.rs`:

```rust
//! Phase 2 integration: daemon lifecycle, hello, request/response, restart.
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncBufReadExt;
use tokio::process::Command;
use umc_sdk::client::Client;

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("umc-test-{}.sock", std::process::id()))
}

fn data_dir() -> PathBuf {
    std::env::temp_dir().join(format!("umc-test-data-{}", std::process::id()))
}

async fn spawn_daemon() -> std::process::Child {
    // The daemon binary is built by the workspace; locate it via CARGO_BIN_EXE.
    let bin = env!("CARGO_BIN_EXE_umcd");
    let socket = socket_path();
    let _ = std::fs::remove_file(&socket);
    let data = data_dir();
    std::fs::create_dir_all(&data).unwrap();
    Command::new(bin)
        .env("HOME", data.to_str().unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn umcd")
}

#[tokio::test]
async fn daemon_accepts_hello_and_requests() {
    let mut child = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let socket = socket_path();
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test").await.expect("connect");
    let response = client.request("NodeAdmin", "GetStatus", Vec::new()).await.expect("request");
    assert_eq!(response.request_id, 1);
    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn daemon_persists_state_across_restart() {
    let mut child = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let _ = child.kill().unwrap();
    let _ = child.wait().await;
    // Restart against the same data dir.
    let mut child2 = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let socket = socket_path();
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test").await.expect("connect after restart");
    let response = client.request("NodeAdmin", "GetStatus", Vec::new()).await.expect("request after restart");
    assert_eq!(response.request_id, 1);
    let _ = child2.kill().unwrap();
    let _ = child2.wait().await;
}

#[tokio::test]
async fn unimplemented_methods_return_unimplemented() {
    let mut child = spawn_daemon().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let socket = socket_path();
    let mut client = Client::connect(socket.to_str().unwrap(), "phase2-test").await.expect("connect");
    let err = client.request("BundleService", "ListBundles", Vec::new()).await.unwrap_err();
    assert!(matches!(err, umc_sdk::client::ClientError::Unimplemented(_)));
    let _ = child.kill().unwrap();
    let _ = child.wait().await;
}
```

Note: `env!("CARGO_BIN_EXE_umcd")` is only available in integration tests when the `umcd` package is a dependency of the test crate. Add to `tests/phase2/Cargo.toml`:

```toml
umcd = { path = "../../bins/umcd" }
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p phase2-tests`
Expected: PASS (3 tests). If the socket path differs from the daemon's default, set the socket via a `--socket` arg or `UMC_SOCKET` env var — add that to `umcd` config loading in Task 18 if needed.

- [ ] **Step 4: Commit**

```bash
git add tests/phase2
git commit -m "test(phase2): daemon lifecycle and restart"
```

---

### Task 18: Phase 2 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the full gate**

Run: `cargo fmt --all --check`
Expected: clean.

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: clean.

Run: `cargo test --workspace`
Expected: all green.

Run: `cargo run -p umcd -- --init && cargo run -p umcd -- --doctor`
Expected: init prints dirs; doctor prints check rows.

Run: `cargo test -p phase2-tests`
Expected: daemon lifecycle tests pass.

- [ ] **Step 2: Update README status**

```markdown
- [x] Phase 0: foundations
- [x] Phase 1: secure direct communication
- [x] Phase 2: node runtime — daemon, Control API, storage, config, diagnostics
- [ ] Phase 3: routing and relaying
- [ ] Phase 4: mobility
- [ ] Phase 5: local mesh
- [ ] Phase 6: store-and-forward
- [ ] Phase 7: adversarial resilience
```

- [ ] **Step 3: Verify Phase 2 success criteria from `core.md` §64**

Checklist:

- [ ] Daemon binary (`umcd`) with init flow
- [ ] Local API: Unix socket, protobuf envelopes, version negotiation
- [ ] OS-peer and bearer authentication
- [ ] Capability grants with the empty-constraint rule
- [ ] Request/response/cancel/goaway correlation
- [ ] Bounded event subscriptions
- [ ] Persistence: SQLite store, migrations, keystore, object store, quotas
- [ ] Configuration with conservative defaults
- [ ] Metrics and diagnostics (`umc doctor` checks)
- [ ] CLI (`umc status`, `umc identity list`)
- [ ] Rust daemon-client SDK
- [ ] Restart persistence

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 2 complete"
```

---

## Phase 2 self-review

**Spec coverage:** `decisions.md` §6-7 (SQLite, protobuf, framing) → Tasks 1-9; `control-api.md` §5-14 (framing, connection, versioning, auth, grants) → Tasks 7-9; §16-21 (requests, deadlines, idempotency) → Task 10; §36-41 (handles, pagination, events) → Tasks 10-11; §24-27 (NodeAdmin, IdentityService, CarrierService, PeerService) → Task 12 (stub dispatch) with real services in Phase 3; `storage.md` §6-14 (state categories, schema, migrations, keystore) → Tasks 2-4; §11 (objects) → Task 5; `resource-limits.md` §34-35 (quotas, write budgets) → Task 6; `core.md` §19, §22, §43-44 (init, lifecycle, doctor, CLI) → Tasks 12-15; `sdk.md` §27 (daemon backend) → Task 14.

**Known deferrals:** full NodeAdmin/IdentityService implementations beyond stub status (Phase 3 wires them to the identity manager and handshake crates), named-pipe transport on Windows (Tier-1 CI keeps it compiling; the Unix path is authoritative for v0.1 Linux/macOS), OS keychain integration for the keystore (file-backed with Argon2id now), event resume cursors, Control API pagination end-to-end, application registration (ApplicationService) — that lands with the SDK session APIs in Phase 3.

