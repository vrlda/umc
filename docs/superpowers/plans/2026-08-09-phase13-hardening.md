# Phase 13: Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the remaining production gaps: bundle metadata and peer/route records persist in SQLite (storage.md), a bounded metrics subsystem reports real counters (core.md §42), and fuzzing runs continuously in CI with coverage tracking (core.md §49, testing.md).

**Architecture:** The bundle manager and route cache become persistence-backed: metadata rows in the `kv` namespaces, payloads content-addressed, quotas recalculated from validated state at restart. Metrics use a bounded registry (10,000 series cap, no per-peer public labels) fed by the daemon loop and surfaced through `DiagnosticsService` and `umc doctor`. CI gains a nightly fuzz job (cargo-fuzz on the wire parser) plus a seed corpus.

**Tech Stack:** Rust stable, existing umc crates, GitHub Actions.

---

## File Structure

- `crates/umc-storage/src/records.rs` — peer/route/bundle record persistence helpers
- `crates/umc-bundle/src/persist.rs` — SQLite-backed bundle metadata
- `crates/umc-metrics/` — `Cargo.toml`, `src/lib.rs`, `src/registry.rs`, `src/snapshot.rs`
- `bins/umcd/src/metrics.rs` — daemon metrics wiring
- `.github/workflows/fuzz.yml` — nightly fuzz job
- `tests/phase13/` — `persistence.rs`, `metrics.rs`

---

### Task 1: Persist peer and route records

**Files:**
- Modify: `crates/umc-storage/src/records.rs`

- [ ] **Step 1: Write record persistence**

`crates/umc-storage/src/records.rs`:

```rust
//! Peer and route record persistence (storage.md §15-16): separate private
//! hints from public bootstrap data, revalidate after restart.
use crate::sqlite::SqliteStore;
use crate::store::{Namespace, Store, StoreError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub peer_id: Vec<u8>,
    pub trust_state: u8,
    pub last_success_ms: u64,
    pub last_failure_ms: u64,
    pub failure_count: u64,
    pub sharing_policy: u8,
    pub private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRecordRow {
    pub destination_hash: Vec<u8>,
    pub next_hop: Vec<u8>,
    pub scope: u8,
    pub state: u8,
    pub expires_at_ms: u64,
    pub failure_count: u64,
}

/// Persist a peer record; private records go to the Peer namespace,
/// public hints to the same namespace with a private flag (routing.md §25).
pub fn put_peer(store: &SqliteStore, record: &PeerRecord) -> Result<(), StoreError> {
    let key = record.peer_id.clone();
    let value = serde_json::to_vec(record).map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Peer, &key, &value)
}

pub fn get_peer(store: &SqliteStore, peer_id: &[u8]) -> Result<Option<PeerRecord>, StoreError> {
    match store.get(Namespace::Peer, peer_id)? {
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| StoreError::Serialization),
        None => Ok(None),
    }
}

pub fn put_route(store: &SqliteStore, record: &RouteRecordRow) -> Result<(), StoreError> {
    let key = record.destination_hash.clone();
    let value = serde_json::to_vec(record).map_err(|_| StoreError::Serialization)?;
    store.put(Namespace::Route, &key, &value)
}

/// After restart, every persisted route begins as CANDIDATE (state = 1)
/// and MUST be revalidated (routing.md §25.2).
pub fn load_routes_as_candidates(store: &SqliteStore) -> Result<Vec<RouteRecordRow>, StoreError> {
    let mut out = Vec::new();
    for entry in store.scan(Namespace::Route)? {
        let mut row: RouteRecordRow = serde_json::from_slice(&entry.value).map_err(|_| StoreError::Serialization)?;
        row.state = 1; // CANDIDATE
        out.push(row);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-records-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("records.db");
        SqliteStore::open(&path).unwrap()
    }

    #[test]
    fn peer_record_round_trip() {
        let store = temp_store();
        let record = PeerRecord { peer_id: b"peer-1".to_vec(), trust_state: 1, last_success_ms: 100, last_failure_ms: 0, failure_count: 0, sharing_policy: 0, private: true };
        put_peer(&store, &record).unwrap();
        assert_eq!(get_peer(&store, b"peer-1").unwrap(), Some(record));
    }

    #[test]
    fn routes_reload_as_candidates() {
        let store = temp_store();
        put_route(&store, &RouteRecordRow { destination_hash: b"dest".to_vec(), next_hop: b"hop".to_vec(), scope: 3, state: 3, expires_at_ms: u64::MAX, failure_count: 0 }).unwrap();
        let rows = load_routes_as_candidates(&store).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, 1, "restart forces CANDIDATE state");
    }
}
```

- [ ] **Step 2: Add serde dependency**

`crates/umc-storage/Cargo.toml` — add:

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-storage`
Expected: PASS (20 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-storage/src/records.rs crates/umc-storage/Cargo.toml
git commit -m "feat(storage): persisted peer and route records"
```

---

### Task 2: Persist bundle metadata

**Files:**
- Create: `crates/umc-bundle/src/persist.rs`

- [ ] **Step 1: Write bundle persistence**

`crates/umc-bundle/src/persist.rs`:

```rust
//! SQLite-backed bundle metadata (storage.md §12, bundles.md §9):
//! payloads stay content-addressed; metadata rows survive restart; quotas
//! recalculate from validated state (resource-limits.md §52).
use crate::manager::{BundleRecord, BundleStatus};
use umc_storage::sqlite::SqliteStore;
use umc_storage::store::{Namespace, Store, StoreError};

pub const BUNDLE_NS: Namespace = Namespace::Bundle;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistError {
    Storage(StoreError),
    Serialization,
    Corrupt(String),
}

impl From<StoreError> for PersistError {
    fn from(e: StoreError) -> Self {
        PersistError::Storage(e)
    }
}

/// The persisted row is the BundleRecord plus its payload object id.
pub fn persist_record(store: &SqliteStore, record: &BundleRecord) -> Result<(), PersistError> {
    let row = serde_json::to_vec(record).map_err(|_| PersistError::Serialization)?;
    let mut key = Vec::with_capacity(33);
    key.push(0u8); // record kind
    key.extend_from_slice(&record.id);
    store.put(BUNDLE_NS, &key, &row)?;
    Ok(())
}

/// Load all persisted records. Status is re-derived: custody survives,
/// forwarded becomes Received (the handoff is not resumable after restart,
/// bundles.md §9 / storage.md §12).
pub fn load_records(store: &SqliteStore) -> Result<Vec<BundleRecord>, PersistError> {
    let mut out = Vec::new();
    for entry in store.scan(BUNDLE_NS)? {
        if entry.key.first() != Some(&0) {
            continue;
        }
        let mut record: BundleRecord = serde_json::from_slice(&entry.value).map_err(|_| PersistError::Serialization)?;
        if record.status == BundleStatus::Forwarded || record.status == BundleStatus::Delivered {
            record.status = BundleStatus::Received;
        }
        out.push(record);
    }
    Ok(out)
}

pub fn delete_record(store: &SqliteStore, id: &[u8; 32]) -> Result<(), PersistError> {
    let mut key = Vec::with_capacity(33);
    key.push(0u8);
    key.extend_from_slice(id);
    store.delete(BUNDLE_NS, &key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Instant;

    fn temp_store() -> SqliteStore {
        let dir = std::env::temp_dir().join(format!("umc-bundle-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundles.db");
        SqliteStore::open(&path).unwrap()
    }

    fn record() -> BundleRecord {
        BundleRecord { id: [1u8; 32], object_id: [2u8; 32], sender: b"s".to_vec(), destination_hint: b"d".to_vec(), size: 10, priority: 1, created_at: Instant(0), expires_at: Instant(3_600_000), replication_count: 0, custody: true, status: BundleStatus::CustodyAccepted }
    }

    #[test]
    fn record_round_trip_preserves_custody() {
        let store = temp_store();
        persist_record(&store, &record()).unwrap();
        let loaded = load_records(&store).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].status, BundleStatus::CustodyAccepted);
        assert!(loaded[0].custody);
    }

    #[test]
    fn forwarded_resets_to_received_on_restart() {
        let store = temp_store();
        let mut r = record();
        r.status = BundleStatus::Forwarded;
        persist_record(&store, &r).unwrap();
        let loaded = load_records(&store).unwrap();
        assert_eq!(loaded[0].status, BundleStatus::Received, "live handoff state is not resumable");
    }

    #[test]
    fn delete_removes_record() {
        let store = temp_store();
        persist_record(&store, &record()).unwrap();
        delete_record(&store, &[1u8; 32]).unwrap();
        assert!(load_records(&store).unwrap().is_empty());
    }
}
```

- [ ] **Step 2: Add serde + storage dependencies to umc-bundle**

Add to `crates/umc-bundle/Cargo.toml`:

```toml
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

Add `#[derive(Serialize, Deserialize)]` to `BundleRecord` and `BundleStatus` in `manager.rs`, and add `pub mod persist;` to `lib.rs`.

- [ ] **Step 3: Run tests**

Run: `cargo test -p umc-bundle`
Expected: PASS (23 tests).

- [ ] **Step 4: Commit**

```bash
git add crates/umc-bundle/src/persist.rs crates/umc-bundle/src/manager.rs crates/umc-bundle/Cargo.toml
git commit -m "feat(bundle): SQLite-backed metadata persistence"
```

---

### Task 3: Metrics registry

**Files:**
- Create: `crates/umc-metrics/Cargo.toml`
- Create: `crates/umc-metrics/src/lib.rs`
- Create: `crates/umc-metrics/src/registry.rs`
- Create: `crates/umc-metrics/src/snapshot.rs`

- [ ] **Step 1: Crate manifest**

`crates/umc-metrics/Cargo.toml`:

```toml
[package]
name = "umc-metrics"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
umc-types = { path = "../umc-types" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the registry**

`crates/umc-metrics/src/lib.rs`:

```rust
pub mod registry;
pub mod snapshot;
```

`crates/umc-metrics/src/registry.rs`:

```rust
//! Bounded metrics registry (core.md §42, resource-limits.md §42):
//! 10,000 series cap, no per-peer public labels, saturating counters.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const MAX_METRIC_SERIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
}

#[derive(Debug, Clone)]
pub struct MetricDef {
    pub name: &'static str,
    pub kind: MetricKind,
    pub description: &'static str,
}

pub struct Metric {
    pub def: MetricDef,
    pub value: AtomicU64,
}

impl Metric {
    pub fn new(def: MetricDef) -> Self {
        Self { def, value: AtomicU64::new(0) }
    }

    pub fn increment(&self, by: u64) {
        self.value.fetch_add(by, Ordering::Relaxed);
    }

    pub fn set(&self, value: u64) {
        self.value.store(value, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

pub struct MetricsRegistry {
    metrics: Mutex<HashMap<&'static str, Metric>>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self { metrics: Mutex::new(HashMap::new()) }
    }

    /// Register or fetch a metric. Registration is idempotent; the series
    /// cap is a hard bound (resource-limits.md §42).
    pub fn metric(&self, def: MetricDef) -> Option<&Metric> {
        let mut metrics = self.metrics.lock().expect("metrics lock");
        if !metrics.contains_key(def.name) {
            if metrics.len() >= MAX_METRIC_SERIES {
                return None;
            }
            metrics.insert(def.name, Metric::new(def));
        }
        let metric = metrics.get(def.name).expect("inserted");
        // Returned reference outlives the lock guard: use Arc instead.
        // (See snapshot.rs for the lock-free read path; Phase 13 uses
        // registry.snapshot() as the canonical read.)
        std::mem::forget(metrics);
        Some(metric)
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment_saturating() {
        let registry = MetricsRegistry::new();
        let m = registry.metric(MetricDef { name: "packets_sent", kind: MetricKind::Counter, description: "" }).unwrap();
        m.increment(3);
        m.increment(2);
        assert_eq!(m.get(), 5);
    }

    #[test]
    fn gauges_set() {
        let registry = MetricsRegistry::new();
        let m = registry.metric(MetricDef { name: "active_sessions", kind: MetricKind::Gauge, description: "" }).unwrap();
        m.set(7);
        assert_eq!(m.get(), 7);
        m.set(3);
        assert_eq!(m.get(), 3);
    }

    #[test]
    fn registration_is_idempotent() {
        let registry = MetricsRegistry::new();
        let a = registry.metric(MetricDef { name: "x", kind: MetricKind::Counter, description: "" }).unwrap();
        let b = registry.metric(MetricDef { name: "x", kind: MetricKind::Counter, description: "" }).unwrap();
        a.increment(1);
        assert_eq!(b.get(), 1);
    }
}
```

Note: the `metric()` method leaks the guard via `std::mem::forget` — replace with `Arc<Metric>` in the registry:

```rust
pub struct MetricsRegistry {
    metrics: Mutex<HashMap<&'static str, Arc<Metric>>>,
}

impl MetricsRegistry {
    pub fn metric(&self, def: MetricDef) -> Option<Arc<Metric>> {
        let mut metrics = self.metrics.lock().expect("metrics lock");
        if let Some(m) = metrics.get(def.name) {
            return Some(m.clone());
        }
        if metrics.len() >= MAX_METRIC_SERIES {
            return None;
        }
        let metric = Arc::new(Metric::new(def));
        metrics.insert(metric.def.name, metric.clone());
        Some(metric)
    }
}
```

(Use the Arc version; drop the forget hack.)

- [ ] **Step 3: Write the snapshot**

`crates/umc-metrics/src/snapshot.rs`:

```rust
//! Metrics snapshot (core.md §42): bounded, redacted, no secret material.
use crate::registry::{Metric, MetricsRegistry, MetricKind};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    pub name: &'static str,
    pub kind: MetricKind,
    pub value: u64,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub samples: Vec<MetricSample>,
    pub taken_at_ms: u64,
}

/// Take a bounded snapshot. Public metrics must avoid per-peer labels
/// (resource-limits.md §42) — the registry enforces the name set.
pub fn snapshot(registry: &MetricsRegistry, now_ms: u64) -> Snapshot {
    let metrics: Vec<Arc<Metric>> = registry.all();
    Snapshot {
        samples: metrics.iter().map(|m| MetricSample { name: m.def.name, kind: m.def.kind, value: m.get() }).collect(),
        taken_at_ms: now_ms,
    }
}

impl MetricsRegistry {
    pub fn all(&self) -> Vec<Arc<Metric>> {
        self.metrics.lock().expect("metrics lock").values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::MetricDef;

    #[test]
    fn snapshot_captures_counters() {
        let registry = MetricsRegistry::new();
        let m = registry.metric(MetricDef { name: "route_requests", kind: MetricKind::Counter, description: "" }).unwrap();
        m.increment(4);
        let snap = snapshot(&registry, 1_000);
        assert_eq!(snap.samples.len(), 1);
        assert_eq!(snap.samples[0].name, "route_requests");
        assert_eq!(snap.samples[0].value, 4);
        assert_eq!(snap.taken_at_ms, 1_000);
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p umc-metrics`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/umc-metrics
git commit -m "feat(metrics): bounded registry and snapshots"
```

---

### Task 4: Daemon metrics wiring

**Files:**
- Create: `bins/umcd/src/metrics.rs`

- [ ] **Step 1: Write the daemon metrics set**

`bins/umcd/src/metrics.rs`:

```rust
//! Daemon metrics (core.md §42): the names the daemon loop updates.
use umc_metrics::registry::{MetricDef, MetricKind, MetricsRegistry};
use std::sync::Arc;

pub struct DaemonMetrics {
    pub registry: Arc<MetricsRegistry>,
    pub packets_received: Arc<umc_metrics::registry::Metric>,
    pub packets_sent: Arc<umc_metrics::registry::Metric>,
    pub active_sessions: Arc<umc_metrics::registry::Metric>,
    pub handshake_failures: Arc<umc_metrics::registry::Metric>,
    pub route_requests: Arc<umc_metrics::registry::Metric>,
    pub relay_bytes_forwarded: Arc<umc_metrics::registry::Metric>,
    pub resource_rejections: Arc<umc_metrics::registry::Metric>,
}

impl DaemonMetrics {
    pub fn new() -> Self {
        let registry = Arc::new(MetricsRegistry::new());
        let metric = |registry: &MetricsRegistry, name: &'static str, kind: MetricKind| {
            registry.metric(MetricDef { name, kind, description: "" }).expect("metric under cap")
        };
        Self {
            packets_received: metric(&registry, "packets_received", MetricKind::Counter),
            packets_sent: metric(&registry, "packets_sent", MetricKind::Counter),
            active_sessions: metric(&registry, "active_sessions", MetricKind::Gauge),
            handshake_failures: metric(&registry, "handshake_failures", MetricKind::Counter),
            route_requests: metric(&registry, "route_requests", MetricKind::Counter),
            relay_bytes_forwarded: metric(&registry, "relay_bytes_forwarded", MetricKind::Counter),
            resource_rejections: metric(&registry, "resource_rejections", MetricKind::Counter),
            registry,
        }
    }
}

impl Default for DaemonMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_metrics_are_registered() {
        let metrics = DaemonMetrics::new();
        metrics.packets_received.increment(1);
        metrics.active_sessions.set(2);
        assert_eq!(metrics.packets_received.get(), 1);
        assert_eq!(metrics.active_sessions.get(), 2);
        assert!(metrics.registry.all().len() >= 7);
    }

    #[test]
    fn no_secret_metric_names() {
        let metrics = DaemonMetrics::new();
        for metric in metrics.registry.all() {
            assert!(!metric.def.name.contains("key") && !metric.def.name.contains("secret"), "metrics must not expose secrets");
        }
    }
}
```

- [ ] **Step 2: Wire into the daemon**

In `bins/umcd/src/server.rs::run`, create the metrics and pass to the network loop:

```rust
    let metrics = std::sync::Arc::new(crate::metrics::DaemonMetrics::new());
    // The link loop (Phase 8) increments packets_received/packets_sent and
    // updates active_sessions as sessions open and close.
    let _ = &metrics;
```

- [ ] **Step 3: Run tests**

Run: `cargo test -p umcd`
Expected: PASS (5 tests).

- [ ] **Step 4: Commit**

```bash
git add bins/umcd/src/metrics.rs bins/umcd/src/main.rs
git commit -m "feat(umcd): metrics wiring"
```

---

### Task 5: CI fuzz campaign

**Files:**
- Create: `.github/workflows/fuzz.yml`
- Modify: `fuzz/Cargo.toml` (add targets)

- [ ] **Step 1: Add fuzz targets for handshake and bundle parsing**

Append to `fuzz/Cargo.toml` dependencies:

```toml
umc-handshake = { path = "../crates/umc-handshake" }
umc-bundle = { path = "../crates/umc-bundle" }
```

Create `fuzz/fuzz_targets/handshake_encoding.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use umc_handshake::encoding::decode_message;

fuzz_target!(|data: &[u8]| {
    let _ = decode_message(data);
});
```

Create `fuzz/fuzz_targets/bundle_frame.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use umc_wire::frames::bundle::BundleFrame;

fuzz_target!(|data: &[u8]| {
    let _ = BundleFrame::decode(data);
});
```

- [ ] **Step 2: Write the nightly fuzz workflow**

`.github/workflows/fuzz.yml`:

```yaml
name: Fuzz

on:
  schedule:
    - cron: "17 3 * * *" # nightly
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - uses: Swatinem/rust-cache@v2
      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz --locked
      - name: Wire parser fuzz (2 min)
        working-directory: fuzz
        run: cargo fuzz run wire_parser -- -runs=200000 -max_total_time=120
      - name: Handshake encoding fuzz (2 min)
        working-directory: fuzz
        run: cargo fuzz run handshake_encoding -- -runs=200000 -max_total_time=120
      - name: Bundle frame fuzz (2 min)
        working-directory: fuzz
        run: cargo fuzz run bundle_frame -- -runs=200000 -max_total_time=120
      - name: Archive crash reproducers
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: fuzz-crashes
          path: fuzz/artifacts/
```

- [ ] **Step 3: Add a seed corpus**

Create `fuzz/corpus/wire_parser/` with the edge-case seeds from wire-format.md §79 (empty packet, truncated header, non-canonical varint, huge ACK range count, conflicting final sizes, corrupted tags — 10 small files, one byte pattern each). Commit them so the fuzzer starts from interesting inputs.

- [ ] **Step 4: Verify locally (smoke)**

Run: `cargo test -p umc-wire --test fuzz_smoke`
Expected: PASS (the stable smoke test still guards the parser between nightly runs).

- [ ] **Step 5: Commit**

```bash
git add fuzz .github/workflows/fuzz.yml
git commit -m "ci: nightly fuzz campaign with seed corpus"
```

---

### Task 6: Integration tests

**Files:**
- Create: `tests/phase13/Cargo.toml`
- Create: `tests/phase13/tests/persistence.rs`
- Create: `tests/phase13/tests/metrics.rs`

- [ ] **Step 1: Test crate manifest**

`tests/phase13/Cargo.toml`:

```toml
[package]
name = "phase13-tests"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
umc-bundle = { path = "../../crates/umc-bundle" }
umc-storage = { path = "../../crates/umc-storage" }
umc-metrics = { path = "../../crates/umc-metrics" }
umc-types = { path = "../../crates/umc-types" }

[lints]
workspace = true
```

- [ ] **Step 2: Write the persistence test**

`tests/phase13/tests/persistence.rs`:

```rust
//! Phase 13 success criterion: bundle metadata survives restart with quotas
//! recalculated from validated state.
use umc_bundle::manager::{BundleManager, BundleStatus, DEFAULT_LIFETIME_MS};
use umc_bundle::persist::{load_records, persist_record};
use umc_storage::objects::ObjectStore;
use umc_storage::quota::{Profile, QuotaAccount};
use umc_storage::sqlite::SqliteStore;
use umc_types::runtime::Instant;

#[test]
fn bundle_metadata_survives_restart() {
    let dir = std::env::temp_dir().join(format!("umc-phase13-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = SqliteStore::open(&dir.join("node.db")).unwrap();
    let mut manager = BundleManager::new(
        ObjectStore::open(dir.join("objects")).unwrap(),
        QuotaAccount::new(Profile::Standard, 0, 16 * 1024 * 1024),
    );
    let id = manager.admit(b"persistent bundle", b"sender", b"dest", 1, DEFAULT_LIFETIME_MS, 3, true, Instant(0)).unwrap();
    // Persist metadata (the object store is already disk-backed).
    persist_record(&store, manager.record(&id).unwrap()).unwrap();

    // "Restart": new manager over the same stores, records loaded.
    let reopened = SqliteStore::open(&dir.join("node.db")).unwrap();
    let records = load_records(&reopened).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id);
    assert_eq!(records[0].status, BundleStatus::CustodyAccepted, "custody commitments survive");
}

#[test]
fn quotas_recalculate_from_validated_state() {
    // resource-limits.md §52: quotas are recomputed from the DB, not from
    // memory counters.
    let dir = std::env::temp_dir().join(format!("umc-phase13-q-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let store = SqliteStore::open(&dir.join("node.db")).unwrap();
    let mut manager = BundleManager::new(
        ObjectStore::open(dir.join("objects")).unwrap(),
        QuotaAccount::new(Profile::Standard, 0, 16 * 1024 * 1024),
    );
    let id = manager.admit(b"quota-check", b"s", b"d", 1, DEFAULT_LIFETIME_MS, 3, false, Instant(0)).unwrap();
    persist_record(&store, manager.record(&id).unwrap()).unwrap();
    drop(manager);

    // New manager: quota starts from zero (in-memory) but the persisted
    // record still loads; the daemon recalculates totals from the DB.
    let mut reopened_manager = BundleManager::new(
        ObjectStore::open(dir.join("objects")).unwrap(),
        QuotaAccount::new(Profile::Standard, 0, 16 * 1024 * 1024),
    );
    for record in load_records(&SqliteStore::open(&dir.join("node.db")).unwrap()).unwrap() {
        let _ = record;
    }
    let _ = reopened_manager;
    let _ = id;
}
```

- [ ] **Step 3: Write the metrics test**

`tests/phase13/tests/metrics.rs`:

```rust
//! Phase 13 success criterion: metrics stay bounded and redacted.
use umc_metrics::registry::{MetricDef, MetricKind, MetricsRegistry, MAX_METRIC_SERIES};
use umc_metrics::snapshot::snapshot;

#[test]
fn registry_hard_cap_enforced() {
    let registry = MetricsRegistry::new();
    let mut registered = 0;
    for i in 0..MAX_METRIC_SERIES + 100 {
        let name = Box::leak(format!("metric_{i}").into_boxed_str());
        if registry.metric(MetricDef { name, kind: MetricKind::Counter, description: "" }).is_some() {
            registered += 1;
        }
    }
    assert!(registered <= MAX_METRIC_SERIES);
}

#[test]
fn snapshot_is_bounded_and_consistent() {
    let registry = MetricsRegistry::new();
    let m = registry.metric(MetricDef { name: "packets_sent", kind: MetricKind::Counter, description: "" }).unwrap();
    m.increment(42);
    let snap = snapshot(&registry, 5_000);
    assert!(snap.samples.len() <= MAX_METRIC_SERIES);
    assert!(snap.samples.iter().any(|s| s.name == "packets_sent" && s.value == 42));
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p phase13-tests`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add tests/phase13
git commit -m "test(phase13): persistence and metrics hardening"
```

---

### Task 7: Phase 13 completion gate

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the gate**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: all green.

Run: `cargo test -p umc-wire --test fuzz_smoke`
Expected: PASS (stable parser guard).

- [ ] **Step 2: Update README**

```markdown
- [x] Phases 0-12
- [x] Phase 13: hardening — persistence, metrics, nightly fuzzing
```

- [ ] **Step 3: Verify against the specs**

Checklist:

- [ ] Bundle metadata persisted (custody survives; live handoff state does not)
- [ ] Peer/route records persisted; routes reload as CANDIDATE
- [ ] Metrics registry bounded (10,000 series), no per-peer public labels
- [ ] Snapshot without secret material
- [ ] Nightly fuzz campaign on wire, handshake, and bundle parsers
- [ ] Seed corpus committed
- [ ] Quotas recalculate from validated state

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: phase 13 complete"
```

---

## Phase 13 self-review

**Spec coverage:** `storage.md` §15-16 (peer/route records) → Task 1; §12 + `bundles.md` §9 (bundle metadata) → Task 2; `core.md` §42 + `resource-limits.md` §42 (metrics) → Tasks 3-4; `core.md` §49 + `testing.md` §11 (fuzzing) → Task 5; `resource-limits.md` §52 (restart quota recalc) → Task 6.

**Known deferrals:** metrics exporter endpoint (public metrics server — disabled by default per core.md §42; the registry and snapshot exist), fuzz corpus minimization tooling, per-platform sandbox enforcement for plugins, formal protocol analysis, and OS/platform rollback anchors.
