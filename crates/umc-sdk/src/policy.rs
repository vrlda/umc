//! Constraint-only communication policy (sdk.md §22).
use umc_control::proto::umc::api::v1;

/// Compiled path preference. Applications select a preference; they do not
/// provide executable route-scoring code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStrategy {
    Balanced,
    LowLatency,
    LowBandwidth,
    LocalFirst,
    HighDiversity,
    RestrictedNetwork,
}

/// Connection constraints shared by embedded and daemon backends.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub require_end_to_end_encryption: bool,
    pub allow_relay: bool,
    pub allow_store_and_forward: bool,
    pub allow_local_carriers: bool,
    pub allow_internet_carriers: bool,
    pub maximum_hops: u64,
    pub maximum_latency_ms: u64,
    pub maximum_bundle_lifetime_ms: u64,
    pub minimum_trust: v1::TrustState,
    pub prefer_low_cost: bool,
    pub prefer_low_energy: bool,
    pub path_strategy: PathStrategy,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_end_to_end_encryption: true,
            allow_relay: true,
            allow_store_and_forward: false,
            allow_local_carriers: true,
            allow_internet_carriers: true,
            maximum_hops: 8,
            maximum_latency_ms: 30_000,
            maximum_bundle_lifetime_ms: 86_400_000,
            minimum_trust: v1::TrustState::Observed,
            prefer_low_cost: false,
            prefer_low_energy: false,
            path_strategy: PathStrategy::Balanced,
        }
    }
}

impl Policy {
    /// Serializes the subset understood by the v1 Control API.
    #[must_use]
    pub fn to_route_policy(&self) -> v1::RoutePolicy {
        v1::RoutePolicy {
            scope: match self.path_strategy {
                PathStrategy::LocalFirst => v1::RouteScope::LocalMesh as i32,
                PathStrategy::RestrictedNetwork => v1::RouteScope::Introduced as i32,
                PathStrategy::Balanced
                | PathStrategy::LowLatency
                | PathStrategy::LowBandwidth
                | PathStrategy::HighDiversity => v1::RouteScope::General as i32,
            },
            maximum_hops: u32::try_from(self.maximum_hops).unwrap_or(u32::MAX),
            maximum_relays: u32::try_from(self.maximum_hops).unwrap_or(u32::MAX),
            allow_relay: self.allow_relay,
            allow_store_forward: self.allow_store_and_forward,
            minimum_trust: self.minimum_trust as i32,
            ..Default::default()
        }
    }

    /// Serializes connection-level limits and route constraints.
    #[must_use]
    pub fn to_connection_policy(&self) -> v1::ConnectionPolicy {
        v1::ConnectionPolicy {
            route: Some(self.to_route_policy()),
            maximum_streams: 256,
            idle_timeout_ms: self.maximum_latency_ms,
            allow_datagrams: true,
            allow_multipath: true,
            allow_early_data: false,
        }
    }
}
