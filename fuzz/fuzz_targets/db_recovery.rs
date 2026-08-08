#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(connection) = rusqlite::Connection::open_in_memory() {
        let sql = String::from_utf8_lossy(data);
        let _ = connection.execute_batch(&sql);
        let _ = connection.execute_batch("PRAGMA integrity_check");
    }
});
