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
}
