//! Bounded metrics registry (core.md §42): flat counter names (callers bake
//! labels into the name — `control_requests_nodeadmin` not
//! `control_requests{service=NodeAdmin}`), a hard cardinality cap, and
//! snapshots sorted by name. Counters are `u64` and saturate at `u64::MAX`.
//!
//! The registry never grows unbounded (resource-limits.md §42): a name
//! beyond [`MAX_NAMES`] is refused with a warning on stderr and the update
//! is dropped.
use std::collections::HashMap;
use std::sync::Mutex;

/// Hard cap on distinct metric names (core.md §42): the 1,025th distinct
/// name is refused with a warning — the registry never grows unbounded.
pub const MAX_NAMES: usize = 1_024;

/// Thread-safe bounded counter registry.
#[derive(Debug)]
pub struct Registry {
    inner: Mutex<RegistryInner>,
}

/// Registry contents behind the lock: values by name plus the admitted
/// names in first-seen order. The literal plan shape
/// (`Mutex<HashMap<String, u64>>` + bare `Vec<String>`) would race across
/// threads, so both live under one lock (SANCTIONED deviation).
#[derive(Debug, Default)]
struct RegistryInner {
    /// Current counter values by name.
    counters: HashMap<String, u64>,
    /// Admitted names in first-seen order: keeps the snapshot aligned with
    /// admitted series before the by-name sort.
    order: Vec<String>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment `name` by `n`, saturating at `u64::MAX`. A name beyond
    /// [`MAX_NAMES`] is refused with a warning.
    ///
    /// # Panics
    ///
    /// Panics when the registry mutex is poisoned (a panic held it).
    pub fn incr(&self, name: &str, n: u64) {
        let mut inner = self.inner.lock().expect("metrics registry");
        if let Some(value) = inner.counters.get_mut(name) {
            *value = value.saturating_add(n);
            return;
        }
        if inner.counters.len() >= MAX_NAMES {
            eprintln!("[metrics] dropped series {name}: at the {MAX_NAMES} series cap");
            return;
        }
        inner.counters.insert(name.to_string(), n);
        inner.order.push(name.to_string());
    }

    /// Set `name` to `v` (gauge semantics). A name beyond [`MAX_NAMES`] is
    /// refused with a warning.
    ///
    /// # Panics
    ///
    /// Panics when the registry mutex is poisoned (a panic held it).
    pub fn set(&self, name: &str, v: u64) {
        let mut inner = self.inner.lock().expect("metrics registry");
        if let Some(value) = inner.counters.get_mut(name) {
            *value = v;
            return;
        }
        if inner.counters.len() >= MAX_NAMES {
            eprintln!("[metrics] dropped series {name}: at the {MAX_NAMES} series cap");
            return;
        }
        inner.counters.insert(name.to_string(), v);
        inner.order.push(name.to_string());
    }

    /// Current value of `name`, if the series exists.
    ///
    /// # Panics
    ///
    /// Panics when the registry mutex is poisoned (a panic held it).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.inner
            .lock()
            .expect("metrics registry")
            .counters
            .get(name)
            .copied()
    }

    /// Snapshot of every live series, sorted by name (core.md §42).
    ///
    /// # Panics
    ///
    /// Panics when the registry mutex is poisoned (a panic held it).
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, u64)> {
        let inner = self.inner.lock().expect("metrics registry");
        let mut entries: Vec<(String, u64)> = inner
            .order
            .iter()
            .filter_map(|name| inner.counters.get(name).map(|value| (name.clone(), *value)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    /// Clear every series.
    ///
    /// # Panics
    ///
    /// Panics when the registry mutex is poisoned (a panic held it).
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("metrics registry");
        inner.counters.clear();
        inner.order.clear();
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RegistryInner::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incr_set_get_round_trip() {
        let registry = Registry::new();
        assert_eq!(registry.get("sessions_total"), None);
        registry.incr("sessions_total", 1);
        registry.incr("sessions_total", 2);
        assert_eq!(registry.get("sessions_total"), Some(3));
        registry.set("sessions_total", 7);
        assert_eq!(registry.get("sessions_total"), Some(7));
    }

    #[test]
    fn incr_saturates_at_u64_max() {
        let registry = Registry::new();
        registry.set("counter", u64::MAX);
        registry.incr("counter", 1);
        assert_eq!(registry.get("counter"), Some(u64::MAX));
    }

    #[test]
    fn snapshot_is_sorted_by_name() {
        let registry = Registry::new();
        registry.incr("zebra", 1);
        registry.incr("alpha", 2);
        registry.incr("mango", 3);
        assert_eq!(
            registry.snapshot(),
            vec![
                ("alpha".to_string(), 2),
                ("mango".to_string(), 3),
                ("zebra".to_string(), 1),
            ]
        );
    }

    #[test]
    fn reset_clears_all_series() {
        let registry = Registry::new();
        registry.incr("a", 1);
        registry.set("b", 2);
        registry.reset();
        assert!(registry.snapshot().is_empty());
        assert_eq!(registry.get("a"), None);
    }

    #[test]
    fn cap_refuses_new_names_beyond_limit() {
        let registry = Registry::new();
        for i in 0..MAX_NAMES {
            registry.incr(&format!("series_{i}"), 1);
        }
        assert_eq!(registry.snapshot().len(), MAX_NAMES);
        // The 1,025th distinct name is dropped with a warning.
        registry.incr("series_overflow", 1);
        assert_eq!(registry.get("series_overflow"), None);
        assert_eq!(registry.snapshot().len(), MAX_NAMES);
        // Existing series keep counting at the cap.
        registry.incr("series_0", 1);
        assert_eq!(registry.get("series_0"), Some(2));
    }
}
