#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Keep arbitrary SQL inputs bounded: this target is for SQLite parser and
    // integrity-check recovery behavior, not unbounded query benchmarking.
    if data.len() > 4 * 1024 {
        return;
    }
    if let Ok(connection) = rusqlite::Connection::open_in_memory() {
        let sql = String::from_utf8_lossy(data);
        // Prepare only: arbitrary fuzz input must not execute ATTACH/pragma
        // statements or write outside the in-memory recovery fixture.
        let _ = connection.prepare(&sql);
        let _ = connection.execute_batch("PRAGMA integrity_check");
    }
});
