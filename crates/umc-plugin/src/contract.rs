//! Plugin contract (Phase 11 decision): in-process plugins only.
//!
//! Dynamic loading via `dlopen` is a hard problem and the plugin security
//! model is an open spec decision, so v0.1 plugins are compiled into the
//! binary and bound to a manifest at registry load time. Out-of-process or
//! dlopen-based loading lands after the spec freezes the security model.

/// A plugin's declared identity, read from its manifest JSON file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginManifest {
    /// Unique plugin id; the registry keys plugins by this.
    pub id: String,
    /// Semantic version as `(major, minor, patch)`; serializes as `[m, n, p]`.
    pub version: (u32, u32, u32),
    /// Symbol or binary path that would be loaded once dynamic loading
    /// lands; kept in the manifest so the contract is stable.
    pub entry_point: String,
    /// Capability grants the plugin declares it needs.
    pub permissions: Vec<String>,
}

impl PluginManifest {
    /// Validates the manifest's capability grants and structural rules.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::UnknownPermission`] when a `permissions`
    /// entry is not a known capability string and
    /// [`ManifestError::Malformed`] when `entry_point` is empty or longer
    /// than 256 bytes or `version` is zero.
    pub fn validate(&self) -> Result<(), ManifestError> {
        for permission in &self.permissions {
            if Capability::from_str(permission).is_none() {
                return Err(ManifestError::UnknownPermission(permission.clone()));
            }
        }
        if self.entry_point.is_empty() {
            return Err(ManifestError::Malformed(
                "entry_point must not be empty".into(),
            ));
        }
        if self.entry_point.len() > 256 {
            return Err(ManifestError::Malformed(
                "entry_point exceeds 256 bytes".into(),
            ));
        }
        if self.version == (0, 0, 0) {
            return Err(ManifestError::Malformed("version must not be 0.0.0".into()));
        }
        Ok(())
    }
}

/// A closed set of capabilities a plugin may be granted. Each variant has a
/// canonical manifest string; plugins declare grants via those strings and
/// the loader maps them back to bits. This set is intentionally small and
/// fixed: any new surface the daemon exposes to plugins must first add a
/// capability here (deny by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    NetworkListen,
    NetworkDial,
    StorageRead,
    StorageWrite,
    IdentityUse,
    AppRegister,
    ControlEvents,
    BundleAdmit,
    ConfigRead,
    ConfigWrite,
}

impl Capability {
    /// All capabilities in the closed set, in bit order.
    pub const ALL: &'static [Capability] = &[
        Capability::NetworkListen,
        Capability::NetworkDial,
        Capability::StorageRead,
        Capability::StorageWrite,
        Capability::IdentityUse,
        Capability::AppRegister,
        Capability::ControlEvents,
        Capability::BundleAdmit,
        Capability::ConfigRead,
        Capability::ConfigWrite,
    ];

    /// The canonical manifest string for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::NetworkListen => "network.listen",
            Capability::NetworkDial => "network.dial",
            Capability::StorageRead => "storage.read",
            Capability::StorageWrite => "storage.write",
            Capability::IdentityUse => "identity.use",
            Capability::AppRegister => "app.register",
            Capability::ControlEvents => "control.events",
            Capability::BundleAdmit => "bundle.admit",
            Capability::ConfigRead => "config.read",
            Capability::ConfigWrite => "config.write",
        }
    }

    /// Exact-match lookup of a manifest string; unknown strings are `None`
    /// so unknown grants fail validation instead of being silently ignored.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Capability> {
        Capability::ALL.iter().copied().find(|c| c.as_str() == s)
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Manifest validation failures, surfaced as [`PluginError::Manifest`] by
/// the loader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// A `permissions` entry does not match any known capability.
    UnknownPermission(String),
    /// The manifest violates a structural rule (empty/oversized entry point,
    /// zero version).
    Malformed(String),
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestError::UnknownPermission(p) => {
                write!(f, "unknown permission in manifest: {p}")
            }
            ManifestError::Malformed(reason) => write!(f, "malformed manifest: {reason}"),
        }
    }
}

/// Plugin lifecycle failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginError {
    /// The manifest file is missing, not valid JSON, or fails validation.
    Manifest(String),
    /// No plugin is registered under the requested id.
    NotFound(String),
    /// A plugin with the same id is already registered.
    Duplicate(String),
    /// The plugin rejected initialization.
    Init(String),
    /// A plugin call was rejected by the context (e.g. duplicate app
    /// registration).
    Context(String),
    /// The plugin called a context method its manifest did not grant; the
    /// capability and the denied operation are reported.
    PermissionDenied {
        /// The capability the plugin lacked.
        capability: Capability,
        /// The context operation that required the capability.
        operation: &'static str,
    },
}

/// An in-process plugin: lifecycle hooks driven by the registry.
pub trait Plugin {
    /// Initializes the plugin; the context grants daemon capabilities.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Init`] when the plugin cannot start and
    /// [`PluginError::Context`] when a context call is rejected.
    fn init(&mut self, ctx: &dyn PluginContext) -> Result<(), PluginError>;

    /// Stops the plugin, releasing daemon resources.
    fn shutdown(&mut self);
}

/// The daemon surface a plugin may touch during its lifetime (minimal).
pub trait PluginContext {
    /// Appends a line to the daemon's log.
    fn log(&self, message: &str);

    /// Reads a daemon config value.
    #[must_use]
    fn get_config(&self, key: &str) -> Option<String>;

    /// Registers an application under `protocol_id` for stream dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Context`] when the id is already registered or
    /// otherwise rejected.
    fn register_app(&self, protocol_id: Vec<u8>, service_name: String) -> Result<(), PluginError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips_through_json() {
        let manifest = PluginManifest {
            id: "org.example.echo".to_string(),
            version: (1, 2, 3),
            entry_point: "org_example_echo::plugin_entry".to_string(),
            permissions: vec!["app.register".to_string(), "config.read".to_string()],
        };
        let json = serde_json::to_string(&manifest).expect("serialize");
        assert_eq!(
            json,
            r#"{"id":"org.example.echo","version":[1,2,3],"entry_point":"org_example_echo::plugin_entry","permissions":["app.register","config.read"]}"#
        );
        let decoded: PluginManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn manifest_accepts_empty_permissions() {
        let manifest = PluginManifest {
            id: "org.example.min".to_string(),
            version: (0, 1, 0),
            entry_point: "min".to_string(),
            permissions: Vec::new(),
        };
        let json = serde_json::to_string(&manifest).expect("serialize");
        let decoded: PluginManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, manifest);
    }

    #[test]
    fn capability_round_trips_for_every_all_member() {
        for cap in Capability::ALL {
            assert_eq!(Capability::from_str(cap.as_str()), Some(*cap));
            assert_eq!(Capability::from_str(&cap.to_string()), Some(*cap));
        }
    }

    #[test]
    fn capability_unknown_string_is_none() {
        assert_eq!(Capability::from_str("net.listen"), None);
        assert_eq!(Capability::from_str(""), None);
        assert_eq!(Capability::from_str("app.register "), None);
        assert_eq!(Capability::from_str("bundle.admit.extra"), None);
    }

    fn valid_manifest() -> PluginManifest {
        PluginManifest {
            id: "org.example.echo".to_string(),
            version: (1, 0, 0),
            entry_point: "org_example_echo::plugin_entry".to_string(),
            permissions: vec!["app.register".to_string(), "config.read".to_string()],
        }
    }

    #[test]
    fn validate_accepts_valid_manifest() {
        assert_eq!(valid_manifest().validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_unknown_permission() {
        let manifest = PluginManifest {
            permissions: vec!["app.own".to_string()],
            ..valid_manifest()
        };
        assert_eq!(
            manifest.validate(),
            Err(ManifestError::UnknownPermission("app.own".into()))
        );
    }

    #[test]
    fn validate_rejects_empty_entry_point() {
        let manifest = PluginManifest {
            entry_point: String::new(),
            ..valid_manifest()
        };
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::Malformed(_))
        ));
    }

    #[test]
    fn validate_rejects_oversized_entry_point() {
        let manifest = PluginManifest {
            entry_point: "x".repeat(257),
            ..valid_manifest()
        };
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::Malformed(_))
        ));
    }

    #[test]
    fn validate_rejects_zero_version() {
        let manifest = PluginManifest {
            version: (0, 0, 0),
            ..valid_manifest()
        };
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::Malformed(_))
        ));
    }
}
