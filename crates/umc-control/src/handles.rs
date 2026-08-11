//! Opaque 16-byte random handles (control-api.md §36): every byte comes from
//! the entropy source; the type/principal/generation binding lives in the
//! `HandleRegistry`, not in the handle bytes themselves.
use std::collections::HashMap;
use umc_types::runtime::EntropySource;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleType {
    Application,
    Listener,
    Operation,
    Session,
    Stream,
    Subscription,
    CarrierInstance,
    Link,
}

impl HandleType {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            HandleType::Application => 0x01,
            HandleType::Listener => 0x02,
            HandleType::Operation => 0x03,
            HandleType::Session => 0x04,
            HandleType::Stream => 0x05,
            HandleType::Subscription => 0x06,
            HandleType::CarrierInstance => 0x07,
            HandleType::Link => 0x08,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    pub bytes: [u8; 16],
}

impl Handle {
    /// All 16 bytes are filled from the entropy source (control-api.md §36).
    #[must_use]
    pub fn new(entropy: &dyn EntropySource) -> Self {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes);
        Self { bytes }
    }
}

/// Registry binding each handle to its type, principal, and generation.
#[derive(Debug, Default)]
pub struct HandleRegistry {
    handles: HashMap<[u8; 16], (HandleType, u64, u64)>,
}

impl HandleRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handles: HashMap::new(),
        }
    }

    /// Create a handle and bind it to a type, principal, and generation.
    #[must_use]
    pub fn create(
        &mut self,
        handle_type: HandleType,
        principal_id: u64,
        generation: u64,
        entropy: &dyn EntropySource,
    ) -> Handle {
        let handle = Handle::new(entropy);
        self.handles
            .insert(handle.bytes, (handle_type, principal_id, generation));
        handle
    }

    /// Look up the binding for a handle.
    #[must_use]
    pub fn lookup(&self, handle: &Handle) -> Option<(HandleType, u64, u64)> {
        self.handles.get(&handle.bytes).copied()
    }

    /// Ownership check: type, principal, and generation must all match.
    #[must_use]
    pub fn validate(
        &self,
        handle: &Handle,
        expected_type: HandleType,
        principal_id: u64,
        generation: u64,
    ) -> bool {
        self.lookup(handle) == Some((expected_type, principal_id, generation))
    }

    /// Remove a handle from the registry; returns whether it was bound.
    #[must_use]
    pub fn revoke(&mut self, handle: &Handle) -> bool {
        self.handles.remove(&handle.bytes).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct E(u8);
    impl EntropySource for E {
        fn fill(&self, out: &mut [u8]) {
            out.fill(self.0);
        }
    }

    #[test]
    fn handle_binds_type_principal_generation() {
        let mut registry = HandleRegistry::new();
        let h = registry.create(HandleType::Session, 7, 3, &E(0x42));
        assert!(registry.validate(&h, HandleType::Session, 7, 3));
        assert!(!registry.validate(&h, HandleType::Stream, 7, 3));
        assert!(!registry.validate(&h, HandleType::Session, 8, 3));
        assert!(!registry.validate(&h, HandleType::Session, 7, 4));
        assert_eq!(registry.lookup(&h), Some((HandleType::Session, 7, 3)));
    }

    #[test]
    fn cross_type_handles_rejected() {
        let mut registry = HandleRegistry::new();
        let listener = registry.create(HandleType::Listener, 1, 0, &E(0x11));
        let stream = registry.create(HandleType::Stream, 1, 0, &E(0x22));
        assert!(registry.validate(&listener, HandleType::Listener, 1, 0));
        assert!(!registry.validate(&stream, HandleType::Listener, 1, 0));
        assert!(registry.revoke(&stream));
        assert_eq!(registry.lookup(&stream), None);
    }
}
