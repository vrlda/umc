//! Opt-in telemetry dump (core.md §61, privacy.md §38): telemetry is off
//! by default; with `telemetry_enabled: true` the daemon spawns a task
//! that appends one JSONL metrics line per 60 s to `<data_dir>/telemetry.jsonl`.
//!
//! The file is bounded: once it exceeds [`MAX_TELEMETRY_FILE_BYTES`] the
//! next append rotates it to `telemetry.jsonl.1` (rename, fresh file) and
//! then writes the new line.
use crate::state::wall_now;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use umc_metrics::Registry;
use umc_types::runtime::Clock;

/// JSONL rotation bound (privacy.md §38): a telemetry file over this size
/// rotates to `.1` before the next append.
pub const MAX_TELEMETRY_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Spawn the telemetry dump task: every 60 s, append one metrics snapshot
/// line to `path` (see [`dump_once`]). The task lives for the daemon's
/// lifetime; a failed append is logged, never fatal.
///
/// The clock is used to stamp the startup log line; the JSONL line itself
/// is wall-clock stamped by [`wall_now`].
pub fn spawn_telemetry_dump(metrics: Arc<Registry>, path: PathBuf, clock: Arc<dyn Clock>) {
    spawn_telemetry_dump_at(metrics, path, clock, Duration::from_secs(60));
}

/// Reactive enable path (core.md §61): spawns the dump without a clock
/// (used by the runtime `SetConfig` handler when the flag flips true).
pub fn spawn_telemetry_dump_no_clock(metrics: Arc<Registry>, path: PathBuf) {
    spawn_telemetry_dump_at(
        metrics,
        path,
        crate::runtime_adapters::TokioAdaptor,
        Duration::from_secs(60),
    );
}

/// Interval-parameterized spawn, used by [`spawn_telemetry_dump`] with the
/// production 60 s cadence and by tests with a short interval.
fn spawn_telemetry_dump_at(
    metrics: Arc<Registry>,
    path: PathBuf,
    clock: Arc<dyn Clock>,
    interval: Duration,
) {
    tokio::spawn(async move {
        let started_at_ms = clock.now().0;
        log::info!(
            "[telemetry] dump task started at {started_at_ms}ms; first append after {interval:?}"
        );
        loop {
            tokio::time::sleep(interval).await;
            if let Err(e) = dump_once(&metrics, &path) {
                log::error!("[telemetry] dump failed: {e}");
            }
        }
    });
}

/// Append one JSONL line `{"at_ms": <wall ms>, "metrics": {name: value}}`
/// for the registry snapshot to `path`. When the existing file exceeds
/// [`MAX_TELEMETRY_FILE_BYTES`], it rotates to `path.1` first (an existing
/// `.1` archive is replaced) so the file never grows unbounded.
///
/// # Errors
///
/// Returns a message when the parent directory cannot be created, the
/// rotation rename fails, or the file cannot be opened or written.
pub fn dump_once(metrics: &Registry, path: &Path) -> Result<(), String> {
    use std::io::Write as _;
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() > MAX_TELEMETRY_FILE_BYTES {
            rotate(path)?;
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("telemetry dir: {e}"))?;
    }
    let snapshot = metrics.snapshot();
    let mut metrics_obj = serde_json::Map::new();
    for (name, value) in snapshot {
        metrics_obj.insert(name, serde_json::Value::from(value));
    }
    let line = serde_json::json!({
        "at_ms": wall_now().0,
        "metrics": metrics_obj,
    });
    let mut out = serde_json::to_string(&line).map_err(|e| e.to_string())?;
    out.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("telemetry append: {e}"))?;
    file.write_all(out.as_bytes())
        .map_err(|e| format!("telemetry write: {e}"))
}

/// Rename `path` to `path.1`, replacing any previous archive.
///
/// # Errors
///
/// Returns a message when the rename fails.
fn rotate(path: &Path) -> Result<(), String> {
    let archived = PathBuf::from(format!("{}.1", path.display()));
    let _ = std::fs::remove_file(&archived);
    std::fs::rename(path, &archived).map_err(|e| format!("telemetry rotate: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Fixed-time clock for the dump task (epoch ms).
    #[derive(Debug)]
    struct FakeClock(AtomicU64);

    impl FakeClock {
        fn new(ms: u64) -> Self {
            Self(AtomicU64::new(ms))
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> umc_types::runtime::Instant {
            umc_types::runtime::Instant(self.0.load(Ordering::Relaxed))
        }
    }

    fn fresh_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "umcd-telemetry-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        dir
    }

    #[test]
    fn telemetry_dump_appends_and_rotates() {
        let dir = fresh_dir();
        let metrics = Registry::new();
        metrics.incr("sessions_total", 2);
        metrics.set("sessions_active", 1);
        let path = dir.join("telemetry.jsonl");

        // Two dumps produce two parseable JSONL lines with the registry
        // snapshot and a wall-clock timestamp.
        dump_once(&metrics, &path).expect("first dump");
        dump_once(&metrics, &path).expect("second dump");
        let text = std::fs::read_to_string(&path).expect("read back");
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).expect("parseable JSON line"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["metrics"]["sessions_total"], 2);
        assert_eq!(lines[1]["metrics"]["sessions_active"], 1);
        assert!(
            lines[0]["at_ms"].as_u64().expect("at_ms") > 1_700_000_000_000,
            "at_ms must be wall-clock epoch ms"
        );

        // A file past the bound rotates to `.1` and the append starts a
        // fresh file.
        let big = vec![b'x'; usize::try_from(MAX_TELEMETRY_FILE_BYTES).expect("fits usize") + 1];
        std::fs::write(&path, &big).expect("oversize file");
        dump_once(&metrics, &path).expect("dump after rotation");
        let archived = std::fs::read(format!("{}.1", path.display())).expect("archive exists");
        assert_eq!(archived.len(), big.len(), "archive keeps the old content");
        let text = std::fs::read_to_string(&path).expect("fresh file");
        assert_eq!(text.lines().count(), 1, "rotation starts a fresh file");

        // Subsequent dumps append to the fresh file.
        dump_once(&metrics, &path).expect("append after rotation");
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("fresh file")
                .lines()
                .count(),
            2
        );
    }

    /// The spawned task waits the interval, then appends the snapshot.
    /// Real-time with a short interval: paused-clock tests cannot rely on
    /// tokio waking spawned tasks under `time::advance` (flaky driver
    /// races), so the cadence test drives the real task on real time.
    #[tokio::test]
    async fn spawned_task_dumps_on_the_interval() {
        let dir = fresh_dir();
        let metrics = Arc::new(Registry::new());
        metrics.incr("packets_received", 7);
        let path = dir.join("telemetry.jsonl");
        spawn_telemetry_dump_at(
            metrics.clone(),
            path.clone(),
            Arc::new(FakeClock::new(0)),
            Duration::from_millis(50),
        );

        // The first dump lands after one interval.
        let mut first_lines = 0;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(text) = std::fs::read_to_string(&path) {
                let count = text.lines().count();
                if count > 0 {
                    first_lines = count;
                    break;
                }
            }
        }
        assert!(first_lines > 0, "spawned task must dump after the interval");
        let line: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&path)
                .expect("file")
                .lines()
                .next()
                .expect("line"),
        )
        .expect("JSON line");
        assert_eq!(line["metrics"]["packets_received"], 7);

        // A second dump lands on the next interval.
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let count = std::fs::read_to_string(&path)
                .expect("file")
                .lines()
                .count();
            if count > first_lines {
                assert_eq!(count, first_lines + 1, "one line per interval");
                return;
            }
        }
        panic!("spawned task must dump again on the next interval");
    }
}
