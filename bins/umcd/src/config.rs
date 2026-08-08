//! Node configuration (core.md §18 layering: defaults -> file -> CLI).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use umc_core::privacy::PrivacyProfile;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
// The four bools are independent flat config flags (mesh mode, relay,
// telemetry, secret export), not a state machine.
#[allow(clippy::struct_excessive_bools)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub control_socket: PathBuf,
    pub profile: String,
    /// Requested privacy profile. P0 is the secure-by-default baseline.
    pub privacy_profile: String,
    /// Optional local policy floor. It can raise, but never lower, the
    /// requested profile (privacy.md §43).
    pub privacy_policy_override: Option<String>,
    /// Pad application data packets to a fixed target size. This is an
    /// explicit opt-in because P3 traffic-analysis resistance is not the
    /// secure-by-default profile (privacy.md §P3).
    pub traffic_padding: bool,
    pub carriers: Vec<String>,
    pub tcp_listen: Option<String>,
    pub udp_listen: Option<String>,
    /// Experimental TLS-stream listener address (disabled unless set).
    pub tls_listen: Option<String>,
    /// Local mesh mode (core.md §23.3). Conservative default: off
    /// (decisions.md §3.2).
    pub mesh: bool,
    /// Optional membership secret for authenticated local-mesh peer hints.
    /// The value is operator-provided and is never included in status output.
    pub mesh_secret: Option<String>,
    /// Keystore directory; defaults to `<data_dir>/keystore`.
    pub keystore: Option<PathBuf>,
    pub public_relay: bool,
    /// Emergency protocol kill-switches. Values are comma-separated through
    /// `SetConfig` and are intentionally independent of the normal carrier
    /// and relay enablement flags (security-operations.md §15.2).
    pub disabled_protocol_versions: Vec<String>,
    pub disabled_crypto_profiles: Vec<String>,
    pub disabled_carriers: Vec<String>,
    /// Immediately refuses new public-relay circuit admission. Existing
    /// circuits are drained by their normal lifetime/close path.
    pub disable_public_relay: bool,
    /// Peers to dial at startup and on the bounded retry interval
    /// (discovery.md §15). Endpoint ids are lowercase/uppercase hex.
    pub static_peers: Vec<StaticPeerConfig>,
    /// Telemetry opt-in (core.md §61, privacy.md §38): off by default. The
    /// daemon dumps a bounded JSONL metrics file only when enabled.
    pub telemetry_enabled: bool,
    /// Permits `IdentityService.ExportSecretIdentity` (raw seed export) on
    /// the control socket. Off by default: without this flag the method
    /// answers `PermissionDenied` (control-api.md §32.7 — secret material
    /// leaves the keystore only when an operator opts in).
    pub allow_secret_export: bool,
    /// Bearer credential for the control API (control-api.md §11.3).
    /// Development-only: honored when set, never persisted or exposed.
    pub development_token: Option<String>,
    /// The config file this node was loaded from; `SetConfig` persists back
    /// to it (defaults to `<data_dir>/node.json`). Never serialized.
    #[serde(skip)]
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticPeerConfig {
    pub endpoint_id: String,
    pub carrier: String,
    pub address: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("~/.local/share/umc"),
            control_socket: PathBuf::from("~/.local/run/umc.sock"),
            profile: "standard".to_string(),
            privacy_profile: PrivacyProfile::P0.as_str().to_string(),
            privacy_policy_override: None,
            traffic_padding: false,
            carriers: vec!["ump.tcp/1".to_string(), "ump.udp/1".to_string()],
            tcp_listen: None,
            udp_listen: None,
            tls_listen: None,
            mesh: false,
            mesh_secret: None,
            keystore: None,
            public_relay: false,
            disabled_protocol_versions: Vec::new(),
            disabled_crypto_profiles: Vec::new(),
            disabled_carriers: Vec::new(),
            disable_public_relay: false,
            static_peers: Vec::new(),
            telemetry_enabled: false,
            allow_secret_export: false,
            development_token: None,
            config_path: None,
        }
    }
}

/// Profiles accepted by `SetConfig` (resource-limits.md §7).
pub const SUPPORTED_PROFILES: &[&str] = &["constrained", "standard", "relay"];

impl NodeConfig {
    pub fn load(path: Option<&PathBuf>) -> Result<Self, String> {
        let mut config = Self::default();
        if let Some(path) = path {
            let text = std::fs::read_to_string(path).map_err(|e| format!("config: {e}"))?;
            let file_config: Self =
                serde_json::from_str(&text).map_err(|e| format!("config parse: {e}"))?;
            config = file_config;
        }
        config.config_path = path.cloned();
        config.normalize_privacy_profiles()?;
        // Safety invariants (resource-limits.md §51): conservative defaults.
        config.public_relay = false;
        config.telemetry_enabled = false;
        Ok(config)
    }

    /// The file `SetConfig` persists to: the loaded config path, or
    /// `<data_dir>/node.json` when the daemon started without `--config`.
    #[must_use]
    pub fn resolved_config_path(&self) -> PathBuf {
        match &self.config_path {
            Some(path) => expand_tilde(path),
            None => self.resolved_data_dir().join("node.json"),
        }
    }

    /// Apply one `SetConfig` entry to the in-memory config. Only the
    /// documented keys are accepted; anything else is unsupported.
    ///
    /// # Errors
    ///
    /// Returns a message for unknown keys and values that do not parse.
    pub fn set_entry(&mut self, key: &str, value: &str) -> Result<(), String> {
        match key {
            "profile" => {
                if !SUPPORTED_PROFILES.contains(&value) {
                    return Err(format!(
                        "profile must be one of {SUPPORTED_PROFILES:?}, got {value:?}"
                    ));
                }
                self.profile = value.to_string();
            }
            "privacy_profile" => {
                let profile =
                    PrivacyProfile::from_str(value).map_err(|e| format!("privacy_profile: {e}"))?;
                self.privacy_profile = profile.as_str().to_string();
            }
            "privacy_policy_override" => {
                self.privacy_policy_override = if value.trim().is_empty() {
                    None
                } else {
                    let profile = PrivacyProfile::from_str(value)
                        .map_err(|e| format!("privacy_policy_override: {e}"))?;
                    Some(profile.as_str().to_string())
                };
            }
            "traffic_padding" => {
                self.traffic_padding = value
                    .parse::<bool>()
                    .map_err(|_| format!("traffic_padding must be a bool, got {value:?}"))?;
            }
            "public_relay" => {
                self.public_relay = value
                    .parse::<bool>()
                    .map_err(|_| format!("public_relay must be a bool, got {value:?}"))?;
            }
            "disable_public_relay" => {
                self.disable_public_relay = value
                    .parse::<bool>()
                    .map_err(|_| format!("disable_public_relay must be a bool, got {value:?}"))?;
            }
            "mesh" => {
                self.mesh = value
                    .parse::<bool>()
                    .map_err(|_| format!("mesh must be a bool, got {value:?}"))?;
            }
            "mesh_secret" => {
                self.mesh_secret = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "telemetry_enabled" | "telemetry" => {
                self.telemetry_enabled = value
                    .parse::<bool>()
                    .map_err(|_| format!("telemetry_enabled must be a bool, got {value:?}"))?;
            }
            "allow_secret_export" => {
                self.allow_secret_export = value
                    .parse::<bool>()
                    .map_err(|_| format!("allow_secret_export must be a bool, got {value:?}"))?;
            }
            "carriers" => {
                let carriers: Vec<String> = value
                    .split(',')
                    .map(|c| c.trim().to_string())
                    .filter(|c| !c.is_empty())
                    .collect();
                if carriers.is_empty() {
                    return Err("carriers must name at least one carrier".into());
                }
                self.carriers = carriers;
            }
            "tls_listen" => {
                self.tls_listen = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim().to_string())
                };
            }
            "disabled_protocol_versions" => {
                self.disabled_protocol_versions = parse_csv(value);
            }
            "disabled_crypto_profiles" => {
                self.disabled_crypto_profiles = parse_csv(value);
            }
            "disabled_carriers" => {
                self.disabled_carriers = parse_csv(value);
            }
            "static_peers" => {
                self.static_peers = serde_json::from_str(value)
                    .map_err(|e| format!("static_peers must be a JSON array: {e}"))?;
            }
            other => return Err(format!("unsupported config key {other:?}")),
        }
        Ok(())
    }

    /// Returns the configured privacy profile, falling back to P0 for an
    /// invalid value on an in-memory configuration assembled by a caller.
    #[must_use]
    pub fn privacy_profile_value(&self) -> PrivacyProfile {
        PrivacyProfile::from_str(&self.privacy_profile).unwrap_or(PrivacyProfile::P0)
    }

    /// Returns the effective profile after applying the local policy floor.
    #[must_use]
    pub fn effective_privacy_profile(&self) -> PrivacyProfile {
        let policy = self
            .privacy_policy_override
            .as_deref()
            .and_then(|value| PrivacyProfile::from_str(value).ok());
        self.privacy_profile_value().effective(policy)
    }

    fn normalize_privacy_profiles(&mut self) -> Result<(), String> {
        let requested =
            PrivacyProfile::from_str(&self.privacy_profile).map_err(|e| format!("config: {e}"))?;
        self.privacy_profile = requested.as_str().to_string();
        if let Some(value) = self.privacy_policy_override.as_deref() {
            let policy = PrivacyProfile::from_str(value)
                .map_err(|e| format!("config privacy_policy_override: {e}"))?;
            self.privacy_policy_override = Some(policy.as_str().to_string());
        }
        Ok(())
    }

    /// Whether a protocol version is disabled by the emergency kill-switch.
    /// Decimal and common hexadecimal spellings are accepted so operators can
    /// copy values from wire traces or compatibility tables.
    #[must_use]
    pub fn protocol_version_disabled(&self, version: u32) -> bool {
        let decimal = version.to_string();
        let hex = format!("0x{version:x}");
        let hex_padded = format!("0x{version:08x}");
        self.disabled_protocol_versions.iter().any(|entry| {
            let entry = entry.trim();
            entry == decimal
                || entry.eq_ignore_ascii_case(&hex)
                || entry.eq_ignore_ascii_case(&hex_padded)
                || entry.eq_ignore_ascii_case(&format!("ump/{version}"))
        })
    }

    /// Whether the exact crypto profile identifier has been disabled.
    #[must_use]
    pub fn crypto_profile_disabled(&self, profile: &[u8]) -> bool {
        self.disabled_crypto_profiles.iter().any(|entry| {
            entry.trim().as_bytes() == profile
                || entry
                    .trim()
                    .eq_ignore_ascii_case(&String::from_utf8_lossy(profile))
        })
    }

    /// Whether a carrier type is disabled by the emergency kill-switch.
    #[must_use]
    pub fn carrier_disabled(&self, carrier: &str) -> bool {
        self.disabled_carriers
            .iter()
            .any(|entry| entry.trim() == carrier)
    }

    /// Persist the current config to [`Self::resolved_config_path`].
    ///
    /// # Errors
    ///
    /// Returns a message when the file cannot be written.
    pub fn persist(&self) -> Result<(), String> {
        let path = self.resolved_config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("config dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, json).map_err(|e| format!("config write: {e}"))
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

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = NodeConfig::default();
        assert!(!config.public_relay);
        assert!(!config.telemetry_enabled);
        assert!(!config.mesh);
        assert!(config.mesh_secret.is_none());
        assert_eq!(config.privacy_profile_value(), PrivacyProfile::P0);
        assert_eq!(config.effective_privacy_profile(), PrivacyProfile::P0);
        assert!(!config.traffic_padding);
        assert!(
            !config.allow_secret_export,
            "secret export is off by default"
        );
        assert!(config.keystore.is_none());
        assert!(config.disabled_protocol_versions.is_empty());
        assert!(config.disabled_crypto_profiles.is_empty());
        assert!(config.disabled_carriers.is_empty());
        assert!(!config.disable_public_relay);
        assert!(config.static_peers.is_empty());
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
            r#"{"public_relay": true, "telemetry_enabled": true, "profile": "standard", "disabled_protocol_versions": ["1"], "disabled_crypto_profiles": ["UMP-CRYPTO-1"], "disabled_carriers": ["ump.tcp/1"], "disable_public_relay": true}"#,
        )
        .unwrap();
        let config = NodeConfig::load(Some(&path)).unwrap();
        assert!(!config.public_relay);
        assert!(!config.telemetry_enabled);
        assert!(config.protocol_version_disabled(1));
        assert!(config.crypto_profile_disabled(b"UMP-CRYPTO-1"));
        assert!(config.carrier_disabled("ump.tcp/1"));
        assert!(config.disable_public_relay);
    }

    #[test]
    fn load_records_the_config_path() {
        let dir = std::env::temp_dir().join("umcd-config-path-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.json");
        std::fs::write(&path, r#"{"profile": "standard"}"#).unwrap();
        let config = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(config.config_path, Some(path.clone()));
        assert_eq!(config.resolved_config_path(), path);
        // Without --config the file defaults under the data dir.
        let plain = NodeConfig::default();
        assert!(plain.resolved_config_path().ends_with("node.json"));
    }

    #[test]
    fn set_entry_validates_and_applies() {
        let mut config = NodeConfig::default();
        config.set_entry("profile", "relay").unwrap();
        assert_eq!(config.profile, "relay");
        config
            .set_entry(
                "static_peers",
                r#"[{"endpoint_id":"0000000000000000000000000000000000000000000000000000000000000001","carrier":"ump.tcp/1","address":"127.0.0.1:9001"}]"#,
            )
            .unwrap();
        assert_eq!(config.static_peers.len(), 1);
        config.set_entry("mesh", "true").unwrap();
        assert!(config.mesh);
        config.set_entry("mesh_secret", "mesh-secret").unwrap();
        assert_eq!(config.mesh_secret.as_deref(), Some("mesh-secret"));
        config.set_entry("mesh_secret", "").unwrap();
        assert!(config.mesh_secret.is_none());
        config.set_entry("privacy_profile", "P1").unwrap();
        assert_eq!(config.privacy_profile, "p1");
        config.set_entry("privacy_policy_override", "p2").unwrap();
        assert_eq!(config.effective_privacy_profile(), PrivacyProfile::P2);
        config.set_entry("privacy_policy_override", "p0").unwrap();
        assert_eq!(config.effective_privacy_profile(), PrivacyProfile::P1);
        config.set_entry("privacy_policy_override", "").unwrap();
        assert!(config.privacy_policy_override.is_none());
        config.set_entry("traffic_padding", "true").unwrap();
        assert!(config.traffic_padding);
        assert!(config.set_entry("traffic_padding", "maybe").is_err());
        config.set_entry("public_relay", "false").unwrap();
        assert!(!config.public_relay);
        config.set_entry("telemetry_enabled", "true").unwrap();
        assert!(config.telemetry_enabled);
        config.set_entry("telemetry", "false").unwrap();
        assert!(
            !config.telemetry_enabled,
            "legacy `telemetry` key aliases the same field"
        );
        config.set_entry("allow_secret_export", "true").unwrap();
        assert!(config.allow_secret_export);
        assert!(config.set_entry("allow_secret_export", "maybe").is_err());
        config
            .set_entry("carriers", "ump.tcp/1, ump.udp/1")
            .unwrap();
        assert_eq!(config.carriers, vec!["ump.tcp/1", "ump.udp/1"]);

        assert!(config.set_entry("profile", "bogus").is_err());
        assert!(config.set_entry("profile", "STANDARD").is_err());
        assert!(config.set_entry("privacy_profile", "p4").is_err());
        assert!(config.set_entry("privacy_policy_override", "p4").is_err());
        assert!(config.set_entry("mesh", "maybe").is_err());
        assert!(config.set_entry("carriers", ",").is_err());
        assert!(config.set_entry("no_such_key", "x").is_err());
        // A failed entry leaves the previous value intact.
        assert_eq!(config.profile, "relay");
    }

    #[test]
    fn emergency_disablement_entries_round_trip() {
        let mut config = NodeConfig::default();
        config
            .set_entry("disabled_protocol_versions", "1, 0x00000002")
            .unwrap();
        config
            .set_entry("disabled_crypto_profiles", "UMP-CRYPTO-1,legacy")
            .unwrap();
        config
            .set_entry("disabled_carriers", "ump.tcp/1, ump.udp/1")
            .unwrap();
        config.set_entry("disable_public_relay", "true").unwrap();

        assert!(config.protocol_version_disabled(1));
        assert!(config.protocol_version_disabled(2));
        assert!(!config.protocol_version_disabled(3));
        assert!(config.crypto_profile_disabled(b"UMP-CRYPTO-1"));
        assert!(config.carrier_disabled("ump.udp/1"));
        assert!(config.disable_public_relay);

        config.set_entry("disabled_carriers", "").unwrap();
        assert!(config.disabled_carriers.is_empty());
        assert!(config.set_entry("disable_public_relay", "maybe").is_err());
    }

    #[test]
    fn persist_round_trips_reload() {
        let dir = std::env::temp_dir().join("umcd-config-persist-test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.json");
        let mut config = NodeConfig {
            data_dir: dir.join("data"),
            config_path: Some(path.clone()),
            ..NodeConfig::default()
        };
        config.set_entry("profile", "constrained").unwrap();
        config.set_entry("mesh", "true").unwrap();
        config.persist().unwrap();

        let reloaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(reloaded.profile, "constrained");
        assert!(reloaded.mesh);

        let privacy_path = dir.join("privacy-node.json");
        std::fs::write(
            &privacy_path,
            r#"{"privacy_profile":"P1","privacy_policy_override":"P2"}"#,
        )
        .unwrap();
        let privacy = NodeConfig::load(Some(&privacy_path)).unwrap();
        assert_eq!(privacy.privacy_profile, "p1");
        assert_eq!(privacy.privacy_policy_override.as_deref(), Some("p2"));
        assert_eq!(privacy.effective_privacy_profile(), PrivacyProfile::P2);

        let invalid_path = dir.join("invalid-privacy-node.json");
        std::fs::write(&invalid_path, r#"{"privacy_profile":"p9"}"#).unwrap();
        assert!(NodeConfig::load(Some(&invalid_path)).is_err());
    }
}
