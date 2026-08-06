//! Node configuration (core.md §18 layering: defaults -> file -> CLI).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub control_socket: PathBuf,
    pub profile: String,
    pub carriers: Vec<String>,
    pub tcp_listen: Option<String>,
    pub udp_listen: Option<String>,
    /// Local mesh mode (core.md §23.3). Conservative default: off
    /// (decisions.md §3.2).
    pub mesh: bool,
    /// Keystore directory; defaults to `<data_dir>/keystore`.
    pub keystore: Option<PathBuf>,
    pub public_relay: bool,
    pub telemetry: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("~/.local/share/umc"),
            control_socket: PathBuf::from("~/.local/run/umc.sock"),
            profile: "standard".to_string(),
            carriers: vec!["ump.tcp/1".to_string(), "ump.udp/1".to_string()],
            tcp_listen: None,
            udp_listen: None,
            mesh: false,
            keystore: None,
            public_relay: false,
            telemetry: false,
        }
    }
}

impl NodeConfig {
    pub fn load(path: Option<&PathBuf>) -> Result<Self, String> {
        let mut config = Self::default();
        if let Some(path) = path {
            let text = std::fs::read_to_string(path).map_err(|e| format!("config: {e}"))?;
            let file_config: Self =
                serde_json::from_str(&text).map_err(|e| format!("config parse: {e}"))?;
            config = file_config;
        }
        // Safety invariants (resource-limits.md §51): conservative defaults.
        config.public_relay = false;
        config.telemetry = false;
        Ok(config)
    }

    pub fn resolved_data_dir(&self) -> PathBuf {
        expand_tilde(&self.data_dir)
    }

    pub fn resolved_socket(&self) -> PathBuf {
        expand_tilde(&self.control_socket)
    }

    pub fn resolved_keystore_dir(&self) -> PathBuf {
        match &self.keystore {
            Some(path) => expand_tilde(path),
            None => self.resolved_data_dir().join("keystore"),
        }
    }
}

fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = NodeConfig::default();
        assert!(!config.public_relay);
        assert!(!config.telemetry);
        assert!(!config.mesh);
        assert!(config.keystore.is_none());
    }

    #[test]
    fn resolved_keystore_defaults_under_data_dir() {
        let config = NodeConfig {
            data_dir: PathBuf::from("~/tmp/umc-node"),
            ..NodeConfig::default()
        };
        assert!(config.resolved_keystore_dir().ends_with("keystore"));
    }

    #[test]
    fn load_ignores_unsafe_file_values() {
        let dir = std::env::temp_dir().join("umcd-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.json");
        std::fs::write(
            &path,
            r#"{"public_relay": true, "telemetry": true, "profile": "standard"}"#,
        )
        .unwrap();
        let config = NodeConfig::load(Some(&path)).unwrap();
        assert!(!config.public_relay);
        assert!(!config.telemetry);
    }
}
