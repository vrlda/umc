use std::str::FromStr;

/// Product feature edition. Editions share one UMP mesh; they only change the
/// locally compiled/activated capability set and resource policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoreEdition {
    Lite,
    Standard,
    Extended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditionError {
    Unknown,
}

impl CoreEdition {
    /// Stable configuration and artifact name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Standard => "standard",
            Self::Extended => "extended",
        }
    }

    /// Capabilities currently guaranteed by this edition. The list is ordered
    /// and cumulative so a higher edition can communicate with a lower one.
    #[must_use]
    pub const fn capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Lite => &[
                "core.identity-v1",
                "core.session-v1",
                "carrier.tcp-v1",
                "carrier.udp-v1",
            ],
            Self::Standard | Self::Extended => &[
                "core.identity-v1",
                "core.session-v1",
                "carrier.tcp-v1",
                "carrier.udp-v1",
                "carrier.tls-v1",
                "discovery.overlay-v1",
                "discovery.lan-v1",
                "relay.bounded-v1",
                "routing.multihop-v1",
                "bundle.bounded-v1",
                "privacy.p0-p3-v1",
                "sdk.daemon-v1",
                "sdk.embedded-v1",
            ],
        }
    }

    /// Planned capabilities reserved for Extended implementation slices.
    /// Planned capabilities are never advertised during negotiation.
    #[must_use]
    pub const fn planned_capabilities(self) -> &'static [&'static str] {
        match self {
            Self::Lite | Self::Standard => &[],
            Self::Extended => &[
                "relay.persistent-v1",
                "relay.multipath-v1",
                "carrier.external-plugin-v1",
                "privacy.anonymous-auth-v1",
                "privacy.mix-v1",
                "sdk.c-v1",
                "sdk.python-high-level-v1",
            ],
        }
    }

    #[must_use]
    pub fn supports(self, capability: &str) -> bool {
        let capabilities = self.capabilities();
        let mut index = 0;
        while index < capabilities.len() {
            if capabilities[index] == capability {
                return true;
            }
            index += 1;
        }
        false
    }

    /// Maps built-in carrier identifiers to the capability they require.
    /// Unknown identifiers are left available for future supervised modules;
    /// they are never implied by an edition's built-in capability set.
    #[must_use]
    pub fn supports_carrier(self, carrier: &str) -> bool {
        match carrier {
            "ump.tcp/1" => self.supports("carrier.tcp-v1"),
            "ump.udp/1" => self.supports("carrier.udp-v1"),
            "ump.tls-stream/1" => self.supports("carrier.tls-v1"),
            "ump.lan-discovery/1" => self.supports("discovery.lan-v1"),
            // External carriers run out-of-process and are part of the
            // Extended profile only. Keep the prefix match here so every
            // plugin identifier receives the same edition gate.
            value if value.starts_with("plugin:") => self == Self::Extended,
            _ => true,
        }
    }

    /// Capabilities usable after authenticating both peers' editions.
    #[must_use]
    pub fn common_capabilities(self, peer: Self) -> Vec<&'static str> {
        self.capabilities()
            .iter()
            .copied()
            .filter(|capability| peer.supports(capability))
            .collect()
    }

    /// Whether one capability is available at both ends of a session.
    #[must_use]
    pub fn supports_with_peer(self, peer: Self, capability: &str) -> bool {
        self.supports(capability) && peer.supports(capability)
    }

    /// Returns whether an optional daemon service is available in this
    /// edition. Core identity/session/control operations are shared by all
    /// editions and are intentionally not listed here.
    #[must_use]
    pub fn supports_optional_service(self, service: &str) -> bool {
        match service {
            "DiscoveryService" => self.supports("discovery.overlay-v1"),
            "BundleService" => self.supports("bundle.bounded-v1"),
            "RelayService" => self.supports("relay.bounded-v1"),
            _ => true,
        }
    }

    /// Whether two editions can share the same UMP mesh. Edition differences
    /// never create separate realms; feature-specific operations negotiate
    /// against the intersection of both capability sets.
    #[must_use]
    pub const fn interoperates_with(self, _peer: Self) -> bool {
        true
    }
}

impl FromStr for CoreEdition {
    type Err = EditionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "lite" => Ok(Self::Lite),
            "standard" => Ok(Self::Standard),
            "extended" => Ok(Self::Extended),
            _ => Err(EditionError::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edition_names_round_trip() {
        for edition in [
            CoreEdition::Lite,
            CoreEdition::Standard,
            CoreEdition::Extended,
        ] {
            assert_eq!(edition.as_str().parse::<CoreEdition>(), Ok(edition));
        }
    }

    #[test]
    fn editions_are_ordered_and_capabilities_are_monotonic() {
        assert!(CoreEdition::Lite < CoreEdition::Standard);
        assert!(CoreEdition::Standard < CoreEdition::Extended);
        assert!(CoreEdition::Lite
            .capabilities()
            .iter()
            .all(|capability| CoreEdition::Standard.capabilities().contains(capability)));
        assert!(CoreEdition::Standard
            .capabilities()
            .iter()
            .all(|capability| CoreEdition::Extended.capabilities().contains(capability)));
        assert!(CoreEdition::Extended
            .planned_capabilities()
            .iter()
            .all(|capability| !CoreEdition::Extended.capabilities().contains(capability)));
        assert!(CoreEdition::Lite.interoperates_with(CoreEdition::Extended));
        assert!(!CoreEdition::Lite.supports_carrier("ump.tls-stream/1"));
        assert!(CoreEdition::Standard.supports_carrier("ump.tls-stream/1"));
        assert!(!CoreEdition::Lite.supports_optional_service("RelayService"));
        assert!(CoreEdition::Standard.supports_optional_service("RelayService"));
    }

    #[test]
    fn edition_gates_external_carriers_and_intersects_capabilities() {
        assert!(!CoreEdition::Lite.supports_carrier("plugin:example"));
        assert!(!CoreEdition::Standard.supports_carrier("plugin:example"));
        assert!(CoreEdition::Extended.supports_carrier("plugin:example"));
        assert!(CoreEdition::Lite.supports_carrier("future.carrier/1"));

        let lite_standard = CoreEdition::Lite.common_capabilities(CoreEdition::Standard);
        assert_eq!(lite_standard, CoreEdition::Lite.capabilities());
        assert_eq!(
            CoreEdition::Standard.common_capabilities(CoreEdition::Extended),
            CoreEdition::Standard.capabilities()
        );
        assert!(!CoreEdition::Lite.supports_with_peer(CoreEdition::Standard, "privacy.p0-p3-v1"));
    }

    #[test]
    fn unknown_edition_is_rejected() {
        assert_eq!("relay".parse::<CoreEdition>(), Err(EditionError::Unknown));
    }
}
