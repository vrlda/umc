#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;

fuzz_target!(|data: &[u8]| {
    // Exercise the read-only schema probe and normal open/migration path with
    // arbitrary bytes standing in for a damaged or truncated database. Keep
    // the file and input bounded so the target measures recovery behavior.
    if data.len() > 64 * 1024 {
        return;
    }
    let path = PathBuf::from(std::env::temp_dir()).join(format!(
        "umc-storage-fuzz-{}.db",
        std::process::id()
    ));
    let _ = std::fs::write(&path, data);
    let _ = umc_storage::sqlite::SqliteStore::read_only_schema_version(&path);
    let _ = umc_storage::sqlite::SqliteStore::open(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
});
