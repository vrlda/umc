//! Plugin registry (Phase 11 decision): binds in-process plugin
//! implementations to manifests and drives the plugin lifecycle.
use std::collections::HashMap;
use std::path::Path;

use crate::contract::{Plugin, PluginContext, PluginError, PluginManifest};
use crate::loader;

/// Registered plugins, keyed by manifest id.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn Plugin>>,
    manifests: HashMap<String, PluginManifest>,
}

impl std::fmt::Debug for PluginRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginRegistry")
            .field("plugins", &self.manifests.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PluginRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads and validates the manifest at `path`, then binds the in-process
    /// `plugin` implementation to it under the manifest's id.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Manifest`] when the file is missing, not valid
    /// JSON, or fails validation, and [`PluginError::Duplicate`] when the
    /// manifest id is already registered.
    pub fn load_manifest(
        &mut self,
        path: &Path,
        plugin: Box<dyn Plugin>,
    ) -> Result<(), PluginError> {
        let manifest = loader::load_manifest(path)?;
        if self.manifests.contains_key(&manifest.id) {
            return Err(PluginError::Duplicate(manifest.id));
        }
        let id = manifest.id.clone();
        self.manifests.insert(id.clone(), manifest);
        self.plugins.insert(id, plugin);
        Ok(())
    }

    /// Snapshot of all registered manifests.
    #[must_use]
    pub fn list(&self) -> Vec<&PluginManifest> {
        self.manifests.values().collect()
    }

    /// Runs the plugin's `init` with the given context.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::NotFound`] when no plugin is registered under
    /// `id`, and the plugin's own error when `init` fails.
    pub fn invoke_init(&mut self, id: &str, ctx: &dyn PluginContext) -> Result<(), PluginError> {
        let plugin = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;
        plugin.init(ctx)
    }

    /// Runs the plugin's `shutdown`.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::NotFound`] when no plugin is registered under
    /// `id`.
    pub fn shutdown(&mut self, id: &str) -> Result<(), PluginError> {
        let plugin = self
            .plugins
            .get_mut(id)
            .ok_or_else(|| PluginError::NotFound(id.to_string()))?;
        plugin.shutdown();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Default)]
    struct DummyState {
        inited: bool,
        config_repeat: Option<String>,
        registered: Vec<Vec<u8>>,
    }

    #[derive(Debug, Default)]
    struct DummyPlugin {
        state: Arc<Mutex<DummyState>>,
    }

    impl Plugin for DummyPlugin {
        fn init(&mut self, ctx: &dyn PluginContext) -> Result<(), PluginError> {
            let mut state = self.state.lock().expect("state");
            state.config_repeat = ctx.get_config("echo.repeat");
            let protocol_id = ctx
                .get_config("dummy.register")
                .unwrap_or_else(|| "org.example.echo/1".to_string());
            ctx.register_app(protocol_id.as_bytes().to_vec(), "dummy".to_string())?;
            state.registered.push(protocol_id.as_bytes().to_vec());
            state.inited = true;
            Ok(())
        }

        fn shutdown(&mut self) {
            self.state.lock().expect("state").inited = false;
        }
    }

    impl DummyPlugin {
        fn new() -> (Self, Arc<Mutex<DummyState>>) {
            let state = Arc::new(Mutex::new(DummyState::default()));
            (
                Self {
                    state: Arc::clone(&state),
                },
                state,
            )
        }
    }

    #[derive(Default)]
    struct TestContext {
        config: HashMap<String, String>,
        logs: RefCell<Vec<String>>,
    }

    impl PluginContext for TestContext {
        fn log(&self, message: &str) {
            self.logs.borrow_mut().push(message.to_string());
        }

        fn get_config(&self, key: &str) -> Option<String> {
            self.config.get(key).cloned()
        }

        fn register_app(
            &self,
            protocol_id: Vec<u8>,
            service_name: String,
        ) -> Result<(), PluginError> {
            if protocol_id == b"org.example.taken/1".to_vec() {
                return Err(PluginError::Context(format!(
                    "protocol id already registered: {}",
                    String::from_utf8_lossy(&protocol_id)
                )));
            }
            self.log(&format!("app {service_name}"));
            Ok(())
        }
    }

    fn manifest_json(id: &str) -> String {
        format!(
            r#"{{"id":"{id}","version":[1,0,0],"entry_point":"dummy::entry","permissions":["app.register"]}}"#
        )
    }

    fn temp_manifest(name: &str, contents: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("umc-plugin-{}-{name}.json", std::process::id()));
        fs::write(&path, contents).expect("write manifest");
        path
    }

    fn load_with_state(
        registry: &mut PluginRegistry,
        path: &std::path::Path,
    ) -> Arc<Mutex<DummyState>> {
        let (plugin, state) = DummyPlugin::new();
        registry
            .load_manifest(path, Box::new(plugin))
            .expect("load");
        state
    }

    #[test]
    fn load_manifest_registers_and_lists() {
        let path = temp_manifest("load", &manifest_json("org.example.echo"));
        let mut registry = PluginRegistry::new();
        let _ = load_with_state(&mut registry, &path);
        let _ = fs::remove_file(&path);
        assert_eq!(registry.list().len(), 1);
        assert_eq!(registry.list()[0].id, "org.example.echo");
        assert_eq!(registry.list()[0].version, (1, 0, 0));
    }

    #[test]
    fn duplicate_manifest_id_rejected() {
        let first = temp_manifest("dup1", &manifest_json("org.example.echo"));
        let second = temp_manifest("dup2", &manifest_json("org.example.echo"));
        let mut registry = PluginRegistry::new();
        let _ = load_with_state(&mut registry, &first);
        let (plugin, _) = DummyPlugin::new();
        let result = registry.load_manifest(&second, Box::new(plugin));
        let _ = fs::remove_file(&first);
        let _ = fs::remove_file(&second);
        assert_eq!(
            result,
            Err(PluginError::Duplicate("org.example.echo".into()))
        );
        assert_eq!(registry.list().len(), 1, "duplicate must not replace");
    }

    #[test]
    fn missing_manifest_file_errors() {
        let mut registry = PluginRegistry::new();
        let (plugin, _) = DummyPlugin::new();
        let result = registry.load_manifest(
            Path::new("/nonexistent/umc-plugin-manifest.json"),
            Box::new(plugin),
        );
        assert!(matches!(result, Err(PluginError::Manifest(_))));
    }

    #[test]
    fn invalid_manifest_json_errors() {
        let path = temp_manifest("bad-json", "not json");
        let mut registry = PluginRegistry::new();
        let (plugin, _) = DummyPlugin::new();
        let result = registry.load_manifest(&path, Box::new(plugin));
        let _ = fs::remove_file(&path);
        assert!(matches!(result, Err(PluginError::Manifest(_))));
    }

    #[test]
    fn empty_id_rejected() {
        let path = temp_manifest("empty-id", &manifest_json(""));
        let mut registry = PluginRegistry::new();
        let (plugin, _) = DummyPlugin::new();
        let result = registry.load_manifest(&path, Box::new(plugin));
        let _ = fs::remove_file(&path);
        assert!(matches!(result, Err(PluginError::Manifest(_))));
    }

    #[test]
    fn invoke_init_runs_dummy_plugin() {
        let path = temp_manifest("init", &manifest_json("org.example.echo"));
        let mut registry = PluginRegistry::new();
        let state = load_with_state(&mut registry, &path);
        let _ = fs::remove_file(&path);
        let ctx = TestContext {
            config: HashMap::from([("echo.repeat".to_string(), "3".to_string())]),
            ..Default::default()
        };
        registry
            .invoke_init("org.example.echo", &ctx)
            .expect("init");
        ctx.log("after init");
        {
            let state = state.lock().expect("state");
            assert!(state.inited);
            assert_eq!(state.config_repeat.as_deref(), Some("3"));
            assert_eq!(state.registered.len(), 1);
        }
        assert_eq!(ctx.logs.borrow().len(), 2, "register_app + explicit log");
        registry.shutdown("org.example.echo").expect("shutdown");
        assert!(!state.lock().expect("state").inited);
    }

    #[test]
    fn invoke_init_unknown_id_not_found() {
        let mut registry = PluginRegistry::new();
        let ctx = TestContext::default();
        assert_eq!(
            registry.invoke_init("org.example.missing", &ctx),
            Err(PluginError::NotFound("org.example.missing".into()))
        );
        assert_eq!(
            registry.shutdown("org.example.missing"),
            Err(PluginError::NotFound("org.example.missing".into()))
        );
    }

    #[test]
    fn context_can_reject_registration() {
        let path = temp_manifest("ctx", &manifest_json("org.example.echo"));
        let mut registry = PluginRegistry::new();
        let _ = load_with_state(&mut registry, &path);
        let _ = fs::remove_file(&path);
        let ctx = TestContext {
            config: HashMap::from([(
                "dummy.register".to_string(),
                "org.example.taken/1".to_string(),
            )]),
            ..Default::default()
        };
        let result = registry.invoke_init("org.example.echo", &ctx);
        assert_eq!(
            result,
            Err(PluginError::Context(
                "protocol id already registered: org.example.taken/1".into()
            ))
        );
    }
}
