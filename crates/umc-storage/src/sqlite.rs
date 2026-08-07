//! Default backend (`decisions.md` §6): `SQLite` in `WAL` mode with foreign keys.
use crate::store::{Entry, Namespace, Store, StoreError};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub const SCHEMA_VERSION: i64 = 2;

#[allow(missing_debug_implementations)] // rusqlite::Connection has no Debug impl
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Opens (creating if needed) a `SQLite` store at `path`.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the database cannot be opened,
    /// configured, or initialized.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        crate::migrations::run_migrations(&store)?;
        Ok(store)
    }

    /// Creates the schema tables and verifies the stored schema version.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the schema cannot be created or the
    /// stored version does not match [`SCHEMA_VERSION`].
    ///
    /// # Panics
    /// Panics if the connection mutex is poisoned.
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
            .query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
                r.get(0)
            })
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if current > SCHEMA_VERSION {
            return Err(StoreError::Corrupt(format!(
                "schema version {current}, expected {SCHEMA_VERSION}"
            )));
        }
        Ok(())
    }

    /// Returns the persisted schema version.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the schema version row cannot be read.
    ///
    /// # Panics
    /// Panics if the connection mutex is poisoned.
    /// Opens a database READ-ONLY and returns its schema version without
    /// running init/migrations (storage.md §21.1: restore validation must
    /// not mutate the backup).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when the file cannot be opened as
    /// SQLite or the version row is absent.
    ///
    /// # Panics
    ///
    /// Never panics; all failure modes map to [`StoreError::Corrupt`].
    pub fn read_only_schema_version(path: &Path) -> Result<i64, StoreError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    pub fn schema_version(&self) -> Result<i64, StoreError> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT version FROM schema_version LIMIT 1", [], |r| {
            r.get(0)
        })
        .map_err(|e| StoreError::Corrupt(e.to_string()))
    }
}

impl SqliteStore {
    pub fn connection(&self) -> &Mutex<Connection> {
        &self.conn
    }

    /// Applies one migration and advances the stored schema version.
    ///
    /// # Errors
    /// Returns [`StoreError::Corrupt`] if the migration or version bump fails.
    ///
    /// # Panics
    /// Panics if the connection mutex is poisoned.
    pub fn run_migration(
        &self,
        from_version: i64,
        apply: fn(&Connection) -> Result<(), String>,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        {
            apply(&tx).map_err(StoreError::Corrupt)?;
            tx.execute(
                "UPDATE schema_version SET version = ?1",
                params![from_version + 1],
            )
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        }
        tx.commit().map_err(|e| StoreError::Corrupt(e.to_string()))
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
        conn.execute(
            "DELETE FROM kv WHERE namespace = ?1 AND key = ?2",
            params![namespace.as_str(), key],
        )
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
                Ok(Entry {
                    key: r.get(0)?,
                    value: r.get(1)?,
                })
            })
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StoreError::Corrupt(e.to_string()))?);
        }
        Ok(out)
    }

    fn put_batch(
        &self,
        namespace: Namespace,
        entries: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO kv (namespace, key, value) VALUES (?1, ?2, ?3)
                          ON CONFLICT(namespace, key) DO UPDATE SET value = excluded.value",
                )
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn open_temp() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-storage-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("store-{n}-{c}.db"));
        SqliteStore::open(&path).unwrap()
    }

    #[test]
    fn put_get_round_trip() {
        let store = open_temp();
        store.put(Namespace::Config, b"port", b"9001").unwrap();
        assert_eq!(
            store.get(Namespace::Config, b"port").unwrap(),
            Some(b"9001".to_vec())
        );
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
        store
            .put_batch(
                Namespace::Trust,
                &[
                    (b"k1".to_vec(), b"v1".to_vec()),
                    (b"k2".to_vec(), b"v2".to_vec()),
                ],
            )
            .unwrap();
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
        assert_eq!(
            store.get(Namespace::Config, b"k").unwrap(),
            Some(b"config".to_vec())
        );
        assert_eq!(
            store.get(Namespace::Route, b"k").unwrap(),
            Some(b"route".to_vec())
        );
    }
}
