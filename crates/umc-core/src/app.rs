//! Application registry (core.md §9.6): registered protocol IDs map to
//! application handles, and the daemon dispatches inbound streams by
//! protocol ID.
use std::collections::HashMap;

/// Maximum length of a registered protocol ID.
pub const MAX_PROTOCOL_ID_LEN: usize = 64;

/// Default MTU hint for applications that do not advertise one.
pub const DEFAULT_MTU_HINT: usize = 1200;

/// A registered application: the protocol ID it listens on plus its
/// registration metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppHandle {
    pub protocol_id: Vec<u8>,
    pub service_name: String,
    pub metadata: HashMap<String, String>,
    pub mtu_hint: usize,
}

/// Registration failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    /// The protocol ID is already registered.
    AlreadyRegistered,
    /// The protocol ID exceeds [`MAX_PROTOCOL_ID_LEN`].
    InvalidProtocolId,
    /// No application is registered under the protocol ID.
    NotFound,
}

/// The daemon's application registry: one handle per registered protocol ID.
#[derive(Debug, Default, Clone)]
pub struct AppRegistry {
    apps: HashMap<Vec<u8>, AppHandle>,
}

impl AppRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an application under `protocol_id`.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidProtocolId`] when the ID exceeds
    /// [`MAX_PROTOCOL_ID_LEN`] bytes and [`AppError::AlreadyRegistered`]
    /// when the ID is already taken.
    pub fn register(&mut self, protocol_id: Vec<u8>, service_name: String) -> Result<(), AppError> {
        if protocol_id.len() > MAX_PROTOCOL_ID_LEN {
            return Err(AppError::InvalidProtocolId);
        }
        if self.apps.contains_key(&protocol_id) {
            return Err(AppError::AlreadyRegistered);
        }
        self.apps.insert(
            protocol_id.clone(),
            AppHandle {
                protocol_id,
                service_name,
                metadata: HashMap::new(),
                mtu_hint: DEFAULT_MTU_HINT,
            },
        );
        Ok(())
    }

    #[must_use]
    pub fn lookup(&self, protocol_id: &[u8]) -> Option<&AppHandle> {
        self.apps.get(protocol_id)
    }

    /// Remove the application registered under `protocol_id`; returns
    /// whether an application was removed.
    #[must_use]
    pub fn unregister(&mut self, protocol_id: &[u8]) -> bool {
        self.apps.remove(protocol_id).is_some()
    }

    /// Snapshot of all registered applications.
    #[must_use]
    pub fn list(&self) -> Vec<AppHandle> {
        self.apps.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_and_list() {
        let mut registry = AppRegistry::new();
        registry
            .register(b"org.example.echo/1".to_vec(), "echo".to_string())
            .expect("register");
        let handle = registry.lookup(b"org.example.echo/1").expect("lookup");
        assert_eq!(handle.service_name, "echo");
        assert_eq!(handle.mtu_hint, DEFAULT_MTU_HINT);
        assert!(handle.metadata.is_empty());
        assert_eq!(registry.list().len(), 1);
        assert!(registry.lookup(b"org.example.other/1").is_none());
    }

    #[test]
    fn duplicate_register_rejected() {
        let mut registry = AppRegistry::new();
        registry
            .register(b"org.example.echo/1".to_vec(), "echo".to_string())
            .expect("first register");
        assert_eq!(
            registry.register(b"org.example.echo/1".to_vec(), "echo-2".to_string()),
            Err(AppError::AlreadyRegistered)
        );
        assert_eq!(registry.list().len(), 1, "duplicate must not replace");
    }

    #[test]
    fn unregister_removes() {
        let mut registry = AppRegistry::new();
        registry
            .register(b"org.example.echo/1".to_vec(), "echo".to_string())
            .expect("register");
        assert!(registry.unregister(b"org.example.echo/1"));
        assert!(!registry.unregister(b"org.example.echo/1"), "idempotent");
        assert!(registry.lookup(b"org.example.echo/1").is_none());
        assert!(registry.list().is_empty());
    }

    #[test]
    fn protocol_id_length_capped() {
        let mut registry = AppRegistry::new();
        let id = vec![b'x'; MAX_PROTOCOL_ID_LEN];
        registry
            .register(id.clone(), "at-limit".to_string())
            .expect("at-limit accepted");
        assert_eq!(
            registry.register(
                vec![b'x'; MAX_PROTOCOL_ID_LEN + 1],
                "over-limit".to_string()
            ),
            Err(AppError::InvalidProtocolId)
        );
        assert_eq!(registry.list().len(), 1);
    }
}
