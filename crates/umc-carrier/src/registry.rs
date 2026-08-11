//! Carrier registry (carriers/registry.md).

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierStatus {
    Stable,
    Experimental,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierRegistration {
    pub type_id: String,
    pub status: CarrierStatus,
}

#[derive(Debug, Clone)]
pub struct CarrierRegistry {
    entries: BTreeMap<String, CarrierStatus>,
}

impl Default for CarrierRegistry {
    fn default() -> Self {
        let mut registry = Self::new();
        registry
            .register("ump.tcp/1", CarrierStatus::Stable)
            .expect("built-in carrier id");
        registry
            .register("ump.udp/1", CarrierStatus::Stable)
            .expect("built-in carrier id");
        registry
            .register("ump.lan-discovery/1", CarrierStatus::Experimental)
            .expect("built-in carrier id");
        // Registered before the implementation is enabled so operators can
        // explicitly opt in without an unknown-type configuration failure.
        registry
            .register("ump.tls-stream/1", CarrierStatus::Experimental)
            .expect("built-in carrier id");
        registry
    }
}

impl CarrierRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Registers a unique carrier type.
    ///
    /// # Errors
    ///
    /// Returns an error when the type id is empty or already registered.
    pub fn register(&mut self, type_id: &str, status: CarrierStatus) -> Result<(), String> {
        if type_id.trim().is_empty() {
            return Err("carrier type id is empty".into());
        }
        if self.entries.contains_key(type_id) {
            return Err(format!("carrier type already registered: {type_id}"));
        }
        self.entries.insert(type_id.to_string(), status);
        Ok(())
    }

    #[must_use]
    pub fn status(&self, type_id: &str) -> Option<CarrierStatus> {
        self.entries.get(type_id).copied()
    }

    #[must_use]
    pub fn contains(&self, type_id: &str) -> bool {
        self.entries.contains_key(type_id)
    }

    #[must_use]
    pub fn list(&self) -> Vec<CarrierRegistration> {
        self.entries
            .iter()
            .map(|(type_id, status)| CarrierRegistration {
                type_id: type_id.clone(),
                status: *status,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_include_experimental_tls() {
        let registry = CarrierRegistry::default();
        assert_eq!(registry.status("ump.tcp/1"), Some(CarrierStatus::Stable));
        assert_eq!(
            registry.status("ump.tls-stream/1"),
            Some(CarrierStatus::Experimental)
        );
    }

    #[test]
    fn lifecycle_rejects_duplicates_and_lists_sorted() {
        let mut registry = CarrierRegistry::new();
        registry
            .register("ump.z/1", CarrierStatus::Experimental)
            .unwrap();
        assert!(registry.register("ump.z/1", CarrierStatus::Stable).is_err());
        assert!(registry.register("", CarrierStatus::Stable).is_err());
        assert_eq!(registry.list()[0].type_id, "ump.z/1");
    }
}
