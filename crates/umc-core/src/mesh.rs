//! Local mesh operating mode (core.md §23.3): LAN discovery on, local carriers
//! prioritized, no internet assumptions.
use umc_types::runtime::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // mode presets are inherently flag sets
pub struct MeshConfig {
    pub enable_lan_discovery: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub prefer_local_paths: bool,
    pub allow_internet_carriers: bool,
    pub local_only_scope: bool,
    pub route_lifetime_ms: u64,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enable_lan_discovery: true,
            enable_udp: true,
            enable_tcp: true,
            prefer_local_paths: true,
            allow_internet_carriers: false,
            local_only_scope: true,
            route_lifetime_ms: 10 * 60 * 1000,
        }
    }
}

impl MeshConfig {
    /// Local mesh mode: prioritizes local carriers, enables LAN discovery,
    /// allows disconnected bundles, avoids internet assumptions (core.md §23.3).
    #[must_use]
    pub fn local_mesh() -> Self {
        Self::default()
    }

    /// Endpoint mode: no public relaying, limited discovery, normal outgoing
    /// connections (core.md §23.1).
    #[must_use]
    pub fn endpoint() -> Self {
        Self {
            enable_lan_discovery: false,
            prefer_local_paths: false,
            allow_internet_carriers: true,
            local_only_scope: false,
            ..Self::default()
        }
    }

    /// Validate the preset: local-only scope forbids internet carriers.
    ///
    /// # Errors
    ///
    /// Returns an error when `local_only_scope` and `allow_internet_carriers`
    /// are both set.
    pub fn validate(&self) -> Result<(), String> {
        if self.local_only_scope && self.allow_internet_carriers {
            return Err("local_only_scope conflicts with allow_internet_carriers".into());
        }
        Ok(())
    }

    #[must_use]
    pub fn effective_route_lifetime(&self) -> Duration {
        Duration::from_millis(self.route_lifetime_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_mesh_defaults_are_disconnected_safe() {
        let config = MeshConfig::local_mesh();
        assert!(config.enable_lan_discovery);
        assert!(config.prefer_local_paths);
        assert!(!config.allow_internet_carriers);
        assert!(config.local_only_scope);
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn invalid_combination_rejected() {
        let config = MeshConfig {
            local_only_scope: true,
            allow_internet_carriers: true,
            ..MeshConfig::local_mesh()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn endpoint_mode_allows_internet() {
        let config = MeshConfig::endpoint();
        assert!(config.allow_internet_carriers);
        assert!(!config.enable_lan_discovery);
    }
}
