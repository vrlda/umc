//! Capability enforcement: the registry grants a plugin the capabilities its
//! manifest declares, and [`CapsContext`] wraps the daemon context to deny
//! every call the grant does not cover. This is robustness/defense-in-depth,
//! not a sandbox: a malicious plugin compiled into the binary is trusted
//! native code and must be reviewed as part of the deployment trust boundary.
use crate::contract::{Capability, ManifestError, PluginContext, PluginError};

/// Bitmask of granted capabilities (one bit per [`Capability`] variant).
///
/// `Capability::ALL` is the closed set, so the mask is fixed at 10 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    bits: u64,
}

fn bit(cap: Capability) -> u64 {
    1u64 << (cap as usize)
}

impl CapabilitySet {
    /// The empty grant: deny by default.
    pub const EMPTY: CapabilitySet = CapabilitySet { bits: 0 };

    /// Builds a grant from manifest `permissions` strings.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::UnknownPermission`] for any string that is
    /// not a canonical capability string.
    pub fn from_manifest(permissions: &[String]) -> Result<CapabilitySet, ManifestError> {
        let mut bits = 0u64;
        for permission in permissions {
            let cap = Capability::from_str(permission)
                .ok_or_else(|| ManifestError::UnknownPermission(permission.clone()))?;
            bits |= bit(cap);
        }
        Ok(CapabilitySet { bits })
    }

    /// Grants `cap` in addition to any already granted.
    pub fn grant(&mut self, cap: Capability) {
        self.bits |= bit(cap);
    }

    /// Whether `cap` is granted.
    #[must_use]
    pub fn contains(self, cap: Capability) -> bool {
        self.bits & bit(cap) != 0
    }

    /// Whether any capability in `caps` is granted.
    #[must_use]
    pub fn has_any(self, caps: &[Capability]) -> bool {
        caps.iter().any(|cap| self.contains(*cap))
    }

    /// Whether no capability is granted.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// Context wrapper that enforces the plugin's capability grant.
///
/// Every error-returning method first requires the capability that gates it
/// and fails with [`PluginError::PermissionDenied`] before the inner
/// context is touched; granted calls delegate straight through. `log` is
/// not part of the capability surface (there is no `log` capability and the
/// signature cannot surface a denial), so it delegates unconditionally.
pub struct CapsContext<'a> {
    caps: CapabilitySet,
    inner: &'a dyn PluginContext,
}

impl std::fmt::Debug for CapsContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapsContext")
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl<'a> CapsContext<'a> {
    /// Wraps `inner`, granting only the capabilities in `caps`.
    #[must_use]
    pub const fn new(caps: CapabilitySet, inner: &'a dyn PluginContext) -> Self {
        Self { caps, inner }
    }

    fn require(&self, capability: Capability, operation: &'static str) -> Result<(), PluginError> {
        if self.caps.contains(capability) {
            Ok(())
        } else {
            Err(PluginError::PermissionDenied {
                capability,
                operation,
            })
        }
    }
}

impl PluginContext for CapsContext<'_> {
    fn log(&self, message: &str) {
        self.inner.log(message);
    }

    fn get_config(&self, key: &str) -> Option<String> {
        match self.require(Capability::ConfigRead, "get_config") {
            Ok(()) => self.inner.get_config(key),
            Err(_) => None,
        }
    }

    fn register_app(&self, protocol_id: Vec<u8>, service_name: String) -> Result<(), PluginError> {
        self.require(Capability::AppRegister, "register_app")?;
        self.inner.register_app(protocol_id, service_name)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::contract::{Capability, PluginError};

    #[derive(Default)]
    struct RecordingContext {
        calls: RefCell<Vec<&'static str>>,
        config: std::collections::HashMap<String, String>,
    }

    impl PluginContext for RecordingContext {
        fn log(&self, _message: &str) {
            self.calls.borrow_mut().push("log");
        }

        fn get_config(&self, key: &str) -> Option<String> {
            self.calls.borrow_mut().push("get_config");
            self.config.get(key).cloned()
        }

        fn register_app(
            &self,
            _protocol_id: Vec<u8>,
            _service_name: String,
        ) -> Result<(), PluginError> {
            self.calls.borrow_mut().push("register_app");
            Ok(())
        }
    }

    fn caps(permissions: &[&str]) -> CapabilitySet {
        let strings: Vec<String> = permissions.iter().copied().map(str::to_string).collect();
        CapabilitySet::from_manifest(&strings).expect("valid manifest caps")
    }

    #[test]
    fn from_manifest_maps_strings_to_bits() {
        let set = caps(&["app.register", "config.read"]);
        assert!(set.contains(Capability::AppRegister));
        assert!(set.contains(Capability::ConfigRead));
        assert!(!set.contains(Capability::StorageWrite));
        assert!(!set.is_empty());
    }

    #[test]
    fn from_manifest_empty_is_empty() {
        let set = caps(&[]);
        assert!(set.is_empty());
        assert!(!set.contains(Capability::AppRegister));
    }

    #[test]
    fn from_manifest_unknown_permission_errors() {
        let strings = vec!["app.own".to_string()];
        assert_eq!(
            CapabilitySet::from_manifest(&strings),
            Err(ManifestError::UnknownPermission("app.own".into()))
        );
    }

    #[test]
    fn contains_has_any_is_empty_semantics() {
        let set = caps(&["network.listen", "storage.read"]);
        assert!(set.contains(Capability::NetworkListen));
        assert!(!set.contains(Capability::NetworkDial));
        assert!(set.has_any(&[Capability::NetworkDial, Capability::StorageRead]));
        assert!(!set.has_any(&[Capability::ControlEvents, Capability::ConfigWrite]));
        assert!(!set.is_empty());
        assert!(CapabilitySet::EMPTY.is_empty());
    }

    #[test]
    fn every_all_member_maps_to_distinct_bit() {
        let strings: Vec<String> = Capability::ALL
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        let set = CapabilitySet::from_manifest(&strings).expect("all valid");
        for cap in Capability::ALL {
            assert!(set.contains(*cap));
        }
    }

    #[test]
    fn register_app_without_app_register_is_permission_denied() {
        let inner = RecordingContext::default();
        let ctx = CapsContext::new(caps(&["config.read"]), &inner);
        let result = ctx.register_app(b"org.example/1".to_vec(), "x".to_string());
        assert_eq!(
            result,
            Err(PluginError::PermissionDenied {
                capability: Capability::AppRegister,
                operation: "register_app",
            })
        );
        assert!(inner.calls.borrow().is_empty(), "inner must not be called");
    }

    #[test]
    fn register_app_with_app_register_delegates_to_inner() {
        let inner = RecordingContext::default();
        let ctx = CapsContext::new(caps(&["app.register"]), &inner);
        ctx.register_app(b"org.example/1".to_vec(), "x".to_string())
            .expect("granted");
        assert_eq!(*inner.calls.borrow(), vec!["register_app"]);
    }

    #[test]
    fn get_config_requires_config_read() {
        let inner = RecordingContext::default();
        let ctx = CapsContext::new(caps(&["app.register"]), &inner);
        assert_eq!(ctx.get_config("daemon.port"), None);
        assert!(inner.calls.borrow().is_empty());
    }

    #[test]
    fn log_delegates_without_capability() {
        let inner = RecordingContext::default();
        let ctx = CapsContext::new(CapabilitySet::EMPTY, &inner);
        ctx.log("hello");
        assert_eq!(*inner.calls.borrow(), vec!["log"]);
    }
}
