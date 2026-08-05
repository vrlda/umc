//! Ordered, idempotent migrations (storage.md §9).
use crate::sqlite::{SqliteStore, SCHEMA_VERSION};
use crate::store::StoreError;
use rusqlite::Connection;

/// One migration: from `from_version` to `from_version + 1`.
#[allow(missing_debug_implementations)] // `apply` is a fn pointer with no Debug impl
pub struct Migration {
    pub from_version: i64,
    pub apply: fn(&Connection) -> Result<(), String>,
}

const MIGRATIONS: &[Migration] = &[Migration {
    from_version: 1,
    apply: migration_2_identity_table,
}];

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

/// Brings the store's schema up to [`SCHEMA_VERSION`], applying each missing
/// migration in order. Idempotent: a fully migrated store is a no-op.
///
/// # Errors
/// Returns [`StoreError::Corrupt`] if the stored version is newer than
/// supported, no migration exists for the stored version, or a migration
/// fails.
pub fn run_migrations(store: &SqliteStore) -> Result<i64, StoreError> {
    let mut version = store.schema_version()?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::Corrupt(format!(
            "database schema {version} is newer than supported {SCHEMA_VERSION}"
        )));
    }
    while version < SCHEMA_VERSION {
        let Some(migration) = MIGRATIONS.iter().find(|m| m.from_version == version) else {
            return Err(StoreError::Corrupt(format!(
                "no migration from schema {version}"
            )));
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
        let path = dir.join(format!(
            "m-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        SqliteStore::open(&path).unwrap()
    }

    #[test]
    fn migration_creates_identity_table() {
        let store = open_temp();
        let version = run_migrations(&store).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let conn = store.connection();
        let guard = conn.lock().unwrap();
        guard
            .execute(
                "INSERT INTO identities (endpoint_id, public_key, static_handshake_public_key, sequence, not_before, not_after)
                 VALUES (x'01', x'02', x'03', 0, 0, 100)",
                [],
            )
            .unwrap();
        let count: i64 = guard
            .query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0))
            .unwrap();
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
