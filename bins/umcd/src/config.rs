//! Node configuration (core.md §18 layering: defaults -> file -> CLI).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use umc_core::privacy::PrivacyProfile;
use umc_storage::quota::Profile;

#[cfg(unix)]
const DEFAULT_CONTROL_SOCKET: &str = "~/.local/run/umc.sock";
#[cfg(windows)]
const DEFAULT_CONTROL_SOCKET: &str = r"\\.\pipe\umc";
#[cfg(not(any(unix, windows)))]
const DEFAULT_CONTROL_SOCKET: &str = "~/.local/run/umc.sock";

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
    /// explicit opt-in for P0-P2; P3 enables it automatically.
    pub traffic_padding: bool,
    /// Maximum randomized application-send delay under P3. Zero disables
    /// timing jitter for constrained deployments (privacy.md §27).
    pub timing_jitter_ms: u64,
    /// Permit authenticated, locally-budgeted cover packets under P3.
    pub cover_traffic: bool,
    /// Cover packet cadence. Values are clamped to the bounded 100 ms–60 s
    /// policy range before a session is started.
    pub cover_interval_ms: u64,
    /// Per-session cover bandwidth ceiling in bytes per second.
    pub cover_budget_bps: u64,
    /// Privacy identifier/path rotation cadence. Route replacement remains
    /// session-preserving; the live daemon rotates advertised CIDs on this
    /// schedule until a topology-aware route manager is available.
    pub route_rotation_interval_ms: u64,
    pub carriers: Vec<String>,
    pub tcp_listen: Option<String>,
    pub udp_listen: Option<String>,
    /// Experimental TLS-stream listener address (disabled unless set).
    pub tls_listen: Option<String>,
    /// DER-encoded TLS server certificate used when TLS material is
    /// provisioned for daemon deployment.
    pub tls_certificate: Option<PathBuf>,
    /// DER-encoded PKCS#8 TLS private key. Never exposed through status.
    pub tls_private_key: Option<PathBuf>,
    /// DER-encoded CA or pinned certificate roots trusted by TLS dials.
    pub tls_trust_roots: Vec<PathBuf>,
    /// DNS name presented to the TLS connector when dialing.
    pub tls_server_name: String,
    /// Local mesh mode (core.md §23.3). Conservative default: off
    /// (decisions.md §3.2).
    pub mesh: bool,
    /// Optional membership secret for authenticated local-mesh peer hints.
    /// The value is operator-provided and is never included in status output.
    pub mesh_secret: Option<String>,
    /// Network realm admission mode. Public is the default open mesh;
    /// private requires a matching network id and membership secret.
    pub network_mode: String,
    /// Operator-chosen namespace for a private corporate mesh.
    pub network_id: Option<String>,
    /// Keystore directory; defaults to `<data_dir>/keystore`.
    pub keystore: Option<PathBuf>,
    pub public_relay: bool,
    /// Emergency protocol kill-switches. Values are comma-separated through
    /// `SetConfig` and are intentionally independent of the normal carrier
    /// and relay enablement flags (security-operations.md §15.2).
    pub disabled_protocol_versions: Vec<String>,
    pub disabled_crypto_profiles: Vec<String>,
    pub disabled_carriers: Vec<String>,
    /// Require a stateless Retry before expensive public-key work. Disabled
    /// by default for compatibility (handshake.md §21).
    pub require_retry: bool,
    /// Immediately refuses new public-relay circuit admission. Existing
    /// circuits are drained by their normal lifetime/close path.
    pub disable_public_relay: bool,
    /// Peers to dial at startup and on the bounded retry interval
    /// (discovery.md §15). Endpoint ids are lowercase/uppercase hex.
    pub static_peers: Vec<StaticPeerConfig>,
    /// Initial rendezvous contacts. These are only a bootstrap seed: once a
    /// session is established, learned and advertised candidates are dialed
    /// automatically and the seed is no longer a central dependency.
    pub bootstrap_peers: Vec<BootstrapPeerConfig>,
    /// Publicly reachable addresses this node may introduce to other peers.
    /// An empty list is intentional for nodes behind NAT or firewalls.
    pub advertised_endpoints: Vec<AdvertisedEndpointConfig>,
    /// Telemetry opt-in (core.md §61, privacy.md §38): off by default. The
    /// daemon dumps a bounded JSONL metrics file only when enabled.
    pub telemetry_enabled: bool,
    /// Optional Prometheus-compatible metrics listener. Disabled by default.
    /// Non-loopback listeners require `metrics_bearer_token`.
    pub metrics_listen: Option<String>,
    /// Bearer credential for a non-loopback metrics listener. Never logged.
    pub metrics_bearer_token: Option<String>,
    /// Permits `IdentityService.ExportSecretIdentity` on the control socket.
    /// Off by default: without this flag the method answers
    /// `PermissionDenied`; when enabled, callers must still provide a
    /// passphrase protection and the explicit `EXPORT` confirmation
    /// (control-api.md §32.7).
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapPeerConfig {
    /// Optional expected endpoint id. Empty/omitted permits any authenticated
    /// UMC endpoint at the rendezvous address.
    #[serde(default)]
    pub endpoint_id: Option<String>,
    pub carrier: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedEndpointConfig {
    pub carrier: String,
    pub address: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("~/.local/share/umc"),
            control_socket: PathBuf::from(DEFAULT_CONTROL_SOCKET),
            profile: "standard".to_string(),
            privacy_profile: PrivacyProfile::P0.as_str().to_string(),
            privacy_policy_override: None,
            traffic_padding: false,
            timing_jitter_ms: 25,
            cover_traffic: false,
            cover_interval_ms: 1_000,
            cover_budget_bps: 4 * 1_024,
            route_rotation_interval_ms: 10 * 60 * 1_000,
            carriers: vec!["ump.tcp/1".to_string(), "ump.udp/1".to_string()],
            tcp_listen: None,
            udp_listen: None,
            tls_listen: None,
            tls_certificate: None,
            tls_private_key: None,
            tls_trust_roots: Vec::new(),
            tls_server_name: "localhost".to_string(),
            mesh: false,
            mesh_secret: None,
            network_mode: "public".to_string(),
            network_id: None,
            keystore: None,
            public_relay: false,
            disabled_protocol_versions: Vec::new(),
            disabled_crypto_profiles: Vec::new(),
            disabled_carriers: Vec::new(),
            require_retry: false,
            disable_public_relay: false,
            static_peers: Vec::new(),
            bootstrap_peers: Vec::new(),
            advertised_endpoints: Vec::new(),
            telemetry_enabled: false,
            metrics_listen: None,
            metrics_bearer_token: None,
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
        if Profile::from_name(&config.profile).is_none() {
            return Err(format!(
                "config profile must be one of {SUPPORTED_PROFILES:?}, got {:?}",
                config.profile
            ));
        }
        config.config_path = path.cloned();
        config.normalize_privacy_profiles()?;
        config.normalize_privacy_controls()?;
        config.validate_metrics_config()?;
        config.validate_network_realm()?;
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
    #[allow(clippy::too_many_lines)]
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
            "timing_jitter_ms" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("timing_jitter_ms must be an integer, got {value:?}"))?;
                let previous = self.timing_jitter_ms;
                self.timing_jitter_ms = parsed;
                if let Err(error) = self.normalize_privacy_controls() {
                    self.timing_jitter_ms = previous;
                    return Err(error);
                }
            }
            "cover_traffic" => {
                self.cover_traffic = value
                    .parse::<bool>()
                    .map_err(|_| format!("cover_traffic must be a bool, got {value:?}"))?;
            }
            "cover_interval_ms" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("cover_interval_ms must be an integer, got {value:?}"))?;
                let previous = self.cover_interval_ms;
                self.cover_interval_ms = parsed;
                if let Err(error) = self.normalize_privacy_controls() {
                    self.cover_interval_ms = previous;
                    return Err(error);
                }
            }
            "cover_budget_bps" => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| format!("cover_budget_bps must be an integer, got {value:?}"))?;
                let previous = self.cover_budget_bps;
                self.cover_budget_bps = parsed;
                if let Err(error) = self.normalize_privacy_controls() {
                    self.cover_budget_bps = previous;
                    return Err(error);
                }
            }
            "route_rotation_interval_ms" => {
                let parsed = value.parse::<u64>().map_err(|_| {
                    format!("route_rotation_interval_ms must be an integer, got {value:?}")
                })?;
                let previous = self.route_rotation_interval_ms;
                self.route_rotation_interval_ms = parsed;
                if let Err(error) = self.normalize_privacy_controls() {
                    self.route_rotation_interval_ms = previous;
                    return Err(error);
                }
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
            "network_mode" => {
                let mode = value.trim().to_ascii_lowercase();
                if mode != "public" && mode != "private" {
                    return Err("network_mode must be public or private".into());
                }
                self.network_mode = mode;
            }
            "network_id" => {
                if self.is_private_network() && value.trim().is_empty() {
                    return Err("private network requires a non-empty network_id".into());
                }
                self.network_id = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim().to_string())
                };
            }
            "telemetry_enabled" | "telemetry" => {
                self.telemetry_enabled = value
                    .parse::<bool>()
                    .map_err(|_| format!("telemetry_enabled must be a bool, got {value:?}"))?;
            }
            "metrics_listen" => {
                let previous = self.metrics_listen.clone();
                self.metrics_listen = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim().to_string())
                };
                if let Err(error) = self.validate_metrics_config() {
                    self.metrics_listen = previous;
                    return Err(error);
                }
            }
            "metrics_bearer_token" => {
                let previous = self.metrics_bearer_token.clone();
                self.metrics_bearer_token = if value.trim().is_empty() {
                    None
                } else {
                    Some(value.trim().to_string())
                };
                if let Err(error) = self.validate_metrics_config() {
                    self.metrics_bearer_token = previous;
                    return Err(error);
                }
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
            "tls_certificate" => {
                self.tls_certificate = optional_path(value);
            }
            "tls_private_key" => {
                self.tls_private_key = optional_path(value);
            }
            "tls_trust_roots" => {
                self.tls_trust_roots = parse_csv(value).into_iter().map(PathBuf::from).collect();
            }
            "tls_server_name" => {
                let name = value.trim();
                if name.is_empty() {
                    return Err("tls_server_name must not be empty".into());
                }
                self.tls_server_name = name.to_string();
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
            "require_retry" => {
                self.require_retry = value
                    .parse::<bool>()
                    .map_err(|_| format!("require_retry must be a bool, got {value:?}"))?;
            }
            "static_peers" => {
                self.static_peers = serde_json::from_str(value)
                    .map_err(|e| format!("static_peers must be a JSON array: {e}"))?;
            }
            "bootstrap_peers" => {
                self.bootstrap_peers = serde_json::from_str(value)
                    .map_err(|e| format!("bootstrap_peers must be a JSON array: {e}"))?;
            }
            "advertised_endpoints" => {
                self.advertised_endpoints = serde_json::from_str(value)
                    .map_err(|e| format!("advertised_endpoints must be a JSON array: {e}"))?;
            }
            other => return Err(format!("unsupported config key {other:?}")),
        }
        Ok(())
    }

    /// Validates the fail-closed private realm admission configuration.
    pub fn validate_network_realm(&self) -> Result<(), String> {
        if self.network_mode.eq_ignore_ascii_case("public") {
            return Ok(());
        }
        if !self.network_mode.eq_ignore_ascii_case("private") {
            return Err("network_mode must be public or private".into());
        }
        if self.network_id.as_deref().map_or(true, |value| value.trim().is_empty()) {
            return Err("private network requires a non-empty network_id".into());
        }
        if self.mesh_secret.as_deref().map_or(true, |value| value.trim().is_empty()) {
            return Err("private network requires mesh_secret membership key".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn is_private_network(&self) -> bool {
        self.network_mode.eq_ignore_ascii_case("private")
    }

    #[must_use]
    pub fn realm_marker(&self) -> [u8; 32] {
        umc_handshake::xx::realm_marker(
            &self.network_mode,
            self.network_id.as_deref(),
            self.mesh_secret.as_deref().map(str::as_bytes),
        )
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

    /// Returns the validated resource profile, falling back to the standard
    /// profile for an in-memory configuration assembled by a caller.
    #[must_use]
    pub fn resource_profile(&self) -> Profile {
        Profile::from_name(&self.profile).unwrap_or(Profile::Standard)
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

    fn normalize_privacy_controls(&mut self) -> Result<(), String> {
        const MAX_TIMING_JITTER_MS: u64 = 10_000;
        const MIN_INTERVAL_MS: u64 = 100;
        const MAX_INTERVAL_MS: u64 = 60_000;
        const MAX_COVER_BUDGET_BPS: u64 = 64 * 1_024;
        const MIN_ROUTE_ROTATION_MS: u64 = 60_000;
        const MAX_ROUTE_ROTATION_MS: u64 = 24 * 60 * 60 * 1_000;
        if self.timing_jitter_ms > MAX_TIMING_JITTER_MS {
            return Err(format!(
                "config timing_jitter_ms exceeds {MAX_TIMING_JITTER_MS}"
            ));
        }
        if !(MIN_INTERVAL_MS..=MAX_INTERVAL_MS).contains(&self.cover_interval_ms) {
            return Err(format!(
                "config cover_interval_ms must be between {MIN_INTERVAL_MS} and {MAX_INTERVAL_MS}"
            ));
        }
        if self.cover_budget_bps > MAX_COVER_BUDGET_BPS {
            return Err(format!(
                "config cover_budget_bps exceeds {MAX_COVER_BUDGET_BPS}"
            ));
        }
        if !(MIN_ROUTE_ROTATION_MS..=MAX_ROUTE_ROTATION_MS)
            .contains(&self.route_rotation_interval_ms)
        {
            return Err(format!(
                "config route_rotation_interval_ms must be between {MIN_ROUTE_ROTATION_MS} and {MAX_ROUTE_ROTATION_MS}"
            ));
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

    fn validate_metrics_config(&self) -> Result<(), String> {
        let Some(bind) = self.metrics_listen.as_deref() else {
            return Ok(());
        };
        let address = bind
            .parse::<std::net::SocketAddr>()
            .map_err(|_| format!("metrics_listen must be a socket address, got {bind:?}"))?;
        let token_missing = match self.metrics_bearer_token.as_deref() {
            None => true,
            Some(token) => token.is_empty() || token.chars().any(char::is_whitespace),
        };
        if !address.ip().is_loopback() && token_missing {
            return Err(
                "non-loopback metrics_listen requires a non-empty metrics_bearer_token without whitespace"
                    .into(),
            );
        }
        if let Some(token) = self.metrics_bearer_token.as_deref() {
            if token.is_empty() || token.len() > 256 || token.chars().any(char::is_whitespace) {
                return Err(
                    "metrics_bearer_token must be 1-256 non-whitespace bytes when configured"
                        .into(),
                );
            }
        }
        Ok(())
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

    /// Resolves the configured TLS certificate path, if any.
    #[must_use]
    pub fn resolved_tls_certificate(&self) -> Option<PathBuf> {
        self.tls_certificate.as_deref().map(expand_tilde)
    }

    /// Resolves the configured TLS private-key path, if any.
    #[must_use]
    pub fn resolved_tls_private_key(&self) -> Option<PathBuf> {
        self.tls_private_key.as_deref().map(expand_tilde)
    }

    /// Resolves all configured TLS trust-root paths.
    #[must_use]
    pub fn resolved_tls_trust_roots(&self) -> Vec<PathBuf> {
        self.tls_trust_roots
            .iter()
            .map(|path| expand_tilde(path))
            .collect()
    }
}

fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = home_directory() {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

fn home_directory() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn optional_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let config = NodeConfig::default();
        assert!(!config.public_relay);
        assert!(!config.telemetry_enabled);
        assert!(config.metrics_listen.is_none());
        assert!(config.metrics_bearer_token.is_none());
        assert!(!config.mesh);
        assert!(config.mesh_secret.is_none());
        assert_eq!(config.privacy_profile_value(), PrivacyProfile::P0);
        assert_eq!(config.effective_privacy_profile(), PrivacyProfile::P0);
        assert!(!config.traffic_padding);
        assert_eq!(config.timing_jitter_ms, 25);
        assert!(!config.cover_traffic);
        assert_eq!(config.cover_interval_ms, 1_000);
        assert_eq!(config.cover_budget_bps, 4 * 1_024);
        assert_eq!(config.route_rotation_interval_ms, 10 * 60 * 1_000);
        assert!(
            !config.allow_secret_export,
            "secret export is off by default"
        );
        assert!(config.keystore.is_none());
        assert!(config.tls_certificate.is_none());
        assert!(config.tls_private_key.is_none());
        assert!(config.tls_trust_roots.is_empty());
        assert_eq!(config.tls_server_name, "localhost");
        assert!(config.disabled_protocol_versions.is_empty());
        assert!(config.disabled_crypto_profiles.is_empty());
        assert!(config.disabled_carriers.is_empty());
        assert!(!config.disable_public_relay);
        assert!(config.static_peers.is_empty());
        assert!(config.bootstrap_peers.is_empty());
        assert!(config.advertised_endpoints.is_empty());
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
    #[allow(clippy::too_many_lines)]
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
        config
            .set_entry(
                "bootstrap_peers",
                r#"[{"carrier":"ump.tcp/1","address":"seed.example:9001"}]"#,
            )
            .unwrap();
        assert_eq!(config.bootstrap_peers.len(), 1);
        assert!(config.bootstrap_peers[0].endpoint_id.is_none());
        config
            .set_entry(
                "advertised_endpoints",
                r#"[{"carrier":"ump.tcp/1","address":"node.example:9001"}]"#,
            )
            .unwrap();
        assert_eq!(config.advertised_endpoints.len(), 1);
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
        config.set_entry("timing_jitter_ms", "40").unwrap();
        assert_eq!(config.timing_jitter_ms, 40);
        config.set_entry("cover_traffic", "true").unwrap();
        assert!(config.cover_traffic);
        config.set_entry("cover_interval_ms", "500").unwrap();
        assert_eq!(config.cover_interval_ms, 500);
        config.set_entry("cover_budget_bps", "2048").unwrap();
        assert_eq!(config.cover_budget_bps, 2048);
        config
            .set_entry("route_rotation_interval_ms", "120000")
            .unwrap();
        assert_eq!(config.route_rotation_interval_ms, 120_000);
        assert!(config.set_entry("cover_interval_ms", "1").is_err());
        assert_eq!(config.cover_interval_ms, 500);
        assert!(config.set_entry("timing_jitter_ms", "10001").is_err());
        assert_eq!(config.timing_jitter_ms, 40);
        config.set_entry("public_relay", "false").unwrap();
        assert!(!config.public_relay);
        config.set_entry("telemetry_enabled", "true").unwrap();
        assert!(config.telemetry_enabled);
        config.set_entry("telemetry", "false").unwrap();
        assert!(
            !config.telemetry_enabled,
            "legacy `telemetry` key aliases the same field"
        );
        config.set_entry("metrics_listen", "127.0.0.1:9464").unwrap();
        assert_eq!(config.metrics_listen.as_deref(), Some("127.0.0.1:9464"));
        config
            .set_entry("metrics_bearer_token", "local-token")
            .unwrap();
        assert_eq!(config.metrics_bearer_token.as_deref(), Some("local-token"));
        assert!(config
            .set_entry("metrics_bearer_token", "bad token")
            .is_err());
        assert_eq!(config.metrics_bearer_token.as_deref(), Some("local-token"));
        config.set_entry("metrics_listen", "0.0.0.0:9464").unwrap();
        assert_eq!(config.metrics_listen.as_deref(), Some("0.0.0.0:9464"));
        config.set_entry("metrics_listen", "127.0.0.1:9464").unwrap();
        config.set_entry("metrics_bearer_token", "").unwrap();
        assert!(config.set_entry("metrics_listen", "0.0.0.0:9464").is_err());
        assert_eq!(config.metrics_listen.as_deref(), Some("127.0.0.1:9464"));
        config.set_entry("allow_secret_export", "true").unwrap();
        assert!(config.allow_secret_export);
        assert!(config.set_entry("allow_secret_export", "maybe").is_err());
        config.set_entry("require_retry", "true").unwrap();
        assert!(config.require_retry);
        config
            .set_entry("tls_certificate", "~/mesh/server.der")
            .unwrap();
        config
            .set_entry("tls_private_key", "~/mesh/server.key")
            .unwrap();
        config
            .set_entry("tls_trust_roots", "~/mesh/root.der, /etc/mesh/root2.der")
            .unwrap();
        config.set_entry("tls_server_name", "mesh.example").unwrap();
        assert!(config
            .resolved_tls_certificate()
            .expect("certificate path")
            .ends_with("mesh/server.der"));
        assert_eq!(config.tls_trust_roots.len(), 2);
        assert!(config.set_entry("tls_server_name", "").is_err());
        assert!(config.set_entry("require_retry", "maybe").is_err());
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
    fn private_network_requires_realm_id_and_membership_secret() {
        let mut config = NodeConfig {
            network_mode: "private".into(),
            ..NodeConfig::default()
        };
        assert!(config.validate_network_realm().is_err());

        config.network_id = Some("acme-prod".into());
        assert!(config.validate_network_realm().is_err());

        config.mesh_secret = Some("correct horse battery staple".into());
        config.validate_network_realm().expect("complete private realm");

        config.mesh_secret = None;
        assert!(config.validate_network_realm().is_err());
    }

    #[test]
    fn network_realm_config_entries_are_validated() {
        let mut config = NodeConfig::default();
        config.set_entry("network_mode", "private").unwrap();
        config.set_entry("network_id", "acme-prod").unwrap();
        assert!(config.set_entry("network_mode", "sideways").is_err());
        assert!(config.set_entry("network_id", " ").is_err());
        config.set_entry("mesh_secret", "shared-secret").unwrap();
        config.validate_network_realm().unwrap();
    }

    #[test]
    fn resource_profile_maps_to_shared_limit_table() {
        let mut config = NodeConfig {
            profile: "constrained".into(),
            ..NodeConfig::default()
        };
        assert_eq!(
            config.resource_profile(),
            umc_storage::quota::Profile::Constrained
        );
        config.profile = "relay".into();
        assert_eq!(
            config.resource_profile(),
            umc_storage::quota::Profile::Relay
        );
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
        std::fs::write(&invalid_path, r#"{"profile":"unknown"}"#).unwrap();
        assert!(NodeConfig::load(Some(&invalid_path)).is_err());
    }
}
