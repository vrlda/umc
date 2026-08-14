//! Bounded multi-hop path construction (routing.md §§12–15, 27).
//!
//! This module deliberately constructs only an opaque sequence of adjacent
//! peer hops.  It does not expose a complete topology or grant relay
//! authorization; the session/relay layers still validate each adjacent leg.

use crate::types::RouteScope;

/// Stable v0.1 route default; the protocol hard maximum remains 16.
pub const DEFAULT_MAX_RELAYS: usize = 4;
pub const MAX_PATH_HOPS: usize = 32;
pub const MAX_PATH_EXCLUSIONS: usize = 32;
pub const MAX_PEER_ID: usize = 64;
pub const MAX_FAILURE_DOMAIN: usize = 64;
pub const MAX_PATH_BYTES: usize = 8 * 1024;
/// Canonical marker for the bounded route-path metadata carried in
/// `ROUTE_RESPONSE.route_metadata`. The marker keeps legacy opaque metadata
/// distinguishable from the path representation.
pub const PATH_METADATA_MAGIC: &[u8; 8] = b"UMP-PATH";
pub const PATH_METADATA_VERSION: u8 = 1;

/// Local construction policy.  Diversity is opt-in because an opaque peer
/// list cannot prove independent failure domains without explicit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicy {
    pub max_hops: usize,
    pub max_relays: usize,
    pub minimum_distinct_failure_domains: usize,
    pub allow_direct: bool,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            max_hops: MAX_PATH_HOPS,
            max_relays: DEFAULT_MAX_RELAYS,
            minimum_distinct_failure_domains: 0,
            allow_direct: true,
        }
    }
}

/// One adjacent hop in a route candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathHop {
    pub peer: Vec<u8>,
    pub scope: RouteScope,
    /// Empty means the caller has no independent-domain evidence.
    pub failure_domain: Vec<u8>,
    pub relay: bool,
}

/// A validated opaque route path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePath {
    pub hops: Vec<PathHop>,
    pub effective_scope: RouteScope,
    pub relay_count: usize,
    pub distinct_failure_domains: usize,
}

/// Path construction failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    TooManyExclusions,
    ExclusionTooLong,
    InvalidPeer,
    FailureDomainTooLong,
    ExcludedPeer,
    LoopDetected,
    ScopeBroadened,
    HopLimitExceeded,
    RelayLimitExceeded,
    PathTooLarge,
    EmptyPath,
    InsufficientDiversity { required: usize, actual: usize },
}

/// Structural failures while decoding canonical route-path metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMetadataError {
    InvalidMarker,
    UnsupportedVersion,
    TooManyHops,
    Truncated,
    InvalidScope,
    InvalidFlags,
    InvalidPeer,
    InvalidFailureDomain,
    PathTooLarge,
    TrailingBytes,
}

/// Encode an ordered route path for `ROUTE_RESPONSE.route_metadata`.
///
/// The encoding is deliberately fixed-width for counts and lengths: all
/// fields are bounded by the path builder before they can reach the wire, and
/// decoding rejects non-canonical trailing bytes. The final hop is normally
/// the destination (`relay = false`); intermediate hops are relays.
///
/// # Errors
///
/// Returns a [`PathMetadataError`] when a hop or the encoded path exceeds the
/// frozen bounds.
pub fn encode_path_metadata(hops: &[PathHop]) -> Result<Vec<u8>, PathMetadataError> {
    if hops.len() > MAX_PATH_HOPS {
        return Err(PathMetadataError::TooManyHops);
    }
    let mut out = Vec::with_capacity(10);
    out.extend_from_slice(PATH_METADATA_MAGIC);
    out.push(PATH_METADATA_VERSION);
    out.push(u8::try_from(hops.len()).map_err(|_| PathMetadataError::TooManyHops)?);
    for hop in hops {
        if hop.peer.is_empty() || hop.peer.len() > MAX_PEER_ID {
            return Err(PathMetadataError::InvalidPeer);
        }
        if hop.failure_domain.len() > MAX_FAILURE_DOMAIN {
            return Err(PathMetadataError::InvalidFailureDomain);
        }
        out.push(u8::try_from(hop.peer.len()).map_err(|_| PathMetadataError::InvalidPeer)?);
        out.extend_from_slice(&hop.peer);
        out.push(scope_code(hop.scope));
        out.push(u8::from(hop.relay));
        out.push(
            u8::try_from(hop.failure_domain.len())
                .map_err(|_| PathMetadataError::InvalidFailureDomain)?,
        );
        out.extend_from_slice(&hop.failure_domain);
        if out.len() > MAX_PATH_BYTES {
            return Err(PathMetadataError::PathTooLarge);
        }
    }
    Ok(out)
}

/// Decode canonical route-path metadata. Empty metadata is treated as an
/// absent path and returns an empty list for legacy direct-route vectors.
///
/// # Errors
///
/// Returns a [`PathMetadataError`] for a non-canonical marker, malformed
/// fields, unsupported versions, or trailing bytes.
pub fn decode_path_metadata(bytes: &[u8]) -> Result<Vec<PathHop>, PathMetadataError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_PATH_BYTES {
        return Err(PathMetadataError::PathTooLarge);
    }
    if bytes.len() < PATH_METADATA_MAGIC.len() + 2
        || &bytes[..PATH_METADATA_MAGIC.len()] != PATH_METADATA_MAGIC
    {
        return Err(PathMetadataError::InvalidMarker);
    }
    let mut pos = PATH_METADATA_MAGIC.len();
    if bytes[pos] != PATH_METADATA_VERSION {
        return Err(PathMetadataError::UnsupportedVersion);
    }
    pos += 1;
    let count = usize::from(bytes[pos]);
    pos += 1;
    if count > MAX_PATH_HOPS {
        return Err(PathMetadataError::TooManyHops);
    }
    let mut hops = Vec::with_capacity(count);
    for _ in 0..count {
        let peer_len = usize::from(*bytes.get(pos).ok_or(PathMetadataError::Truncated)?);
        pos += 1;
        if peer_len == 0 || peer_len > MAX_PEER_ID {
            return Err(PathMetadataError::InvalidPeer);
        }
        let peer_end = pos
            .checked_add(peer_len)
            .ok_or(PathMetadataError::Truncated)?;
        let peer = bytes
            .get(pos..peer_end)
            .ok_or(PathMetadataError::Truncated)?
            .to_vec();
        pos = peer_end;
        let scope = scope_from_code(*bytes.get(pos).ok_or(PathMetadataError::Truncated)?)
            .ok_or(PathMetadataError::InvalidScope)?;
        pos += 1;
        let flags = *bytes.get(pos).ok_or(PathMetadataError::Truncated)?;
        pos += 1;
        if flags & !1 != 0 {
            return Err(PathMetadataError::InvalidFlags);
        }
        let domain_len = usize::from(*bytes.get(pos).ok_or(PathMetadataError::Truncated)?);
        pos += 1;
        if domain_len > MAX_FAILURE_DOMAIN {
            return Err(PathMetadataError::InvalidFailureDomain);
        }
        let domain_end = pos
            .checked_add(domain_len)
            .ok_or(PathMetadataError::Truncated)?;
        let failure_domain = bytes
            .get(pos..domain_end)
            .ok_or(PathMetadataError::Truncated)?
            .to_vec();
        pos = domain_end;
        hops.push(PathHop {
            peer,
            scope,
            failure_domain,
            relay: flags & 1 != 0,
        });
    }
    if pos != bytes.len() {
        return Err(PathMetadataError::TrailingBytes);
    }
    Ok(hops)
}

/// Add the current forwarder to the front of a canonical response path.
///
/// # Errors
///
/// Returns a [`PathMetadataError`] when the existing metadata or the new hop
/// cannot be represented within the frozen bounds.
pub fn prepend_path_metadata(metadata: &[u8], hop: PathHop) -> Result<Vec<u8>, PathMetadataError> {
    let mut hops = decode_path_metadata(metadata)?;
    hops.insert(0, hop);
    encode_path_metadata(&hops)
}

fn scope_code(scope: RouteScope) -> u8 {
    match scope {
        RouteScope::LinkLocal => 0,
        RouteScope::LocalMesh => 1,
        RouteScope::Introduced => 2,
        RouteScope::General => 3,
    }
}

fn scope_from_code(code: u8) -> Option<RouteScope> {
    match code {
        0 => Some(RouteScope::LinkLocal),
        1 => Some(RouteScope::LocalMesh),
        2 => Some(RouteScope::Introduced),
        3 => Some(RouteScope::General),
        _ => None,
    }
}

/// Incrementally validates a route path as each adjacent hop is selected.
#[derive(Debug, Clone)]
pub struct PathBuilder {
    request_scope: RouteScope,
    effective_scope: RouteScope,
    exclusions: Vec<Vec<u8>>,
    policy: PathPolicy,
    hops: Vec<PathHop>,
    relay_count: usize,
    encoded_bytes: usize,
}

impl PathBuilder {
    /// Creates a builder for one route request.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when exclusions exceed the bounded profile.
    pub fn new(
        request_scope: RouteScope,
        exclusions: &[Vec<u8>],
        policy: PathPolicy,
    ) -> Result<Self, PathError> {
        if exclusions.len() > MAX_PATH_EXCLUSIONS {
            return Err(PathError::TooManyExclusions);
        }
        if exclusions.iter().any(|entry| entry.len() > MAX_PEER_ID) {
            return Err(PathError::ExclusionTooLong);
        }
        let max_hops = policy.max_hops.min(MAX_PATH_HOPS);
        let max_relays = policy.max_relays.min(MAX_PATH_HOPS);
        Ok(Self {
            request_scope,
            effective_scope: request_scope,
            exclusions: exclusions.to_vec(),
            policy: PathPolicy {
                max_hops,
                max_relays,
                minimum_distinct_failure_domains: policy.minimum_distinct_failure_domains,
                allow_direct: policy.allow_direct,
            },
            hops: Vec::new(),
            relay_count: 0,
            encoded_bytes: 0,
        })
    }

    /// Appends one adjacent hop after applying loop, exclusion, scope, and
    /// resource checks.
    ///
    /// # Errors
    ///
    /// Returns [`PathError`] when the hop violates request policy.
    pub fn push(&mut self, hop: PathHop) -> Result<(), PathError> {
        if hop.peer.is_empty() || hop.peer.len() > MAX_PEER_ID {
            return Err(PathError::InvalidPeer);
        }
        if hop.failure_domain.len() > MAX_FAILURE_DOMAIN {
            return Err(PathError::FailureDomainTooLong);
        }
        if self.exclusions.iter().any(|excluded| excluded == &hop.peer) {
            return Err(PathError::ExcludedPeer);
        }
        if self.hops.iter().any(|existing| existing.peer == hop.peer) {
            return Err(PathError::LoopDetected);
        }
        if !self.effective_scope.narrows_to(hop.scope) {
            return Err(PathError::ScopeBroadened);
        }
        if self.hops.len() >= self.policy.max_hops {
            return Err(PathError::HopLimitExceeded);
        }
        if hop.relay && self.relay_count >= self.policy.max_relays {
            return Err(PathError::RelayLimitExceeded);
        }
        let hop_bytes = 2usize
            .saturating_add(hop.peer.len())
            .saturating_add(hop.failure_domain.len());
        if self.encoded_bytes.saturating_add(hop_bytes) > MAX_PATH_BYTES {
            return Err(PathError::PathTooLarge);
        }
        if hop.relay {
            self.relay_count += 1;
        }
        self.encoded_bytes += hop_bytes;
        self.effective_scope = hop.scope;
        self.hops.push(hop);
        Ok(())
    }

    /// Finishes construction and enforces the explicit diversity policy.
    ///
    /// # Errors
    ///
    /// Returns [`PathError::EmptyPath`] when direct paths are disabled, or
    /// [`PathError::InsufficientDiversity`] when the requested number of
    /// independent domains is not evidenced by the selected hops.
    pub fn finish(self) -> Result<RoutePath, PathError> {
        if self.hops.is_empty() && !self.policy.allow_direct {
            return Err(PathError::EmptyPath);
        }
        let mut domains: Vec<&[u8]> = Vec::new();
        for hop in &self.hops {
            if !hop.failure_domain.is_empty()
                && !domains.iter().any(|domain| *domain == hop.failure_domain)
            {
                domains.push(&hop.failure_domain);
            }
        }
        let distinct_failure_domains = domains.len();
        if distinct_failure_domains < self.policy.minimum_distinct_failure_domains {
            return Err(PathError::InsufficientDiversity {
                required: self.policy.minimum_distinct_failure_domains,
                actual: distinct_failure_domains,
            });
        }
        Ok(RoutePath {
            hops: self.hops,
            effective_scope: self.effective_scope,
            relay_count: self.relay_count,
            distinct_failure_domains,
        })
    }

    /// The request scope used to initialize this path.
    #[must_use]
    pub const fn request_scope(&self) -> RouteScope {
        self.request_scope
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_relay_count_matches_v01_contract() {
        assert_eq!(DEFAULT_MAX_RELAYS, 4);
        assert_eq!(PathPolicy::default().max_relays, 4);
    }

    fn hop(peer: u8, scope: RouteScope, domain: u8, relay: bool) -> PathHop {
        PathHop {
            peer: vec![peer],
            scope,
            failure_domain: vec![domain],
            relay,
        }
    }

    #[test]
    fn path_narrows_scope_and_reports_diversity() {
        let mut builder = PathBuilder::new(
            RouteScope::General,
            &[],
            PathPolicy {
                minimum_distinct_failure_domains: 2,
                ..PathPolicy::default()
            },
        )
        .unwrap();
        builder
            .push(hop(1, RouteScope::Introduced, 10, true))
            .unwrap();
        builder
            .push(hop(2, RouteScope::LocalMesh, 11, true))
            .unwrap();
        let path = builder.finish().unwrap();
        assert_eq!(path.effective_scope, RouteScope::LocalMesh);
        assert_eq!(path.relay_count, 2);
        assert_eq!(path.distinct_failure_domains, 2);
    }

    #[test]
    fn loops_exclusions_and_scope_broadening_are_rejected() {
        let exclusions = vec![vec![9]];
        let mut builder =
            PathBuilder::new(RouteScope::General, &exclusions, PathPolicy::default()).unwrap();
        assert_eq!(
            builder.push(hop(9, RouteScope::General, 1, true)),
            Err(PathError::ExcludedPeer)
        );
        builder
            .push(hop(1, RouteScope::Introduced, 1, true))
            .unwrap();
        assert_eq!(
            builder.push(hop(1, RouteScope::Introduced, 2, true)),
            Err(PathError::LoopDetected)
        );
        assert_eq!(
            builder.push(hop(2, RouteScope::General, 3, true)),
            Err(PathError::ScopeBroadened)
        );
    }

    #[test]
    fn hop_and_relay_limits_are_bounded() {
        let mut builder = PathBuilder::new(
            RouteScope::General,
            &[],
            PathPolicy {
                max_hops: 2,
                max_relays: 1,
                ..PathPolicy::default()
            },
        )
        .unwrap();
        builder.push(hop(1, RouteScope::General, 1, true)).unwrap();
        assert_eq!(
            builder.push(hop(2, RouteScope::General, 2, true)),
            Err(PathError::RelayLimitExceeded)
        );
        builder.push(hop(2, RouteScope::General, 2, false)).unwrap();
        assert_eq!(
            builder.push(hop(3, RouteScope::General, 3, false)),
            Err(PathError::HopLimitExceeded)
        );
    }

    #[test]
    fn direct_path_is_allowed_by_default_but_can_be_disabled() {
        assert!(
            PathBuilder::new(RouteScope::General, &[], PathPolicy::default())
                .unwrap()
                .finish()
                .unwrap()
                .hops
                .is_empty()
        );
        let error = PathBuilder::new(
            RouteScope::General,
            &[],
            PathPolicy {
                allow_direct: false,
                ..PathPolicy::default()
            },
        )
        .unwrap()
        .finish()
        .unwrap_err();
        assert_eq!(error, PathError::EmptyPath);
    }

    #[test]
    fn diversity_requires_explicit_failure_domains() {
        let mut builder = PathBuilder::new(
            RouteScope::General,
            &[],
            PathPolicy {
                minimum_distinct_failure_domains: 1,
                ..PathPolicy::default()
            },
        )
        .unwrap();
        builder
            .push(PathHop {
                peer: vec![1],
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            })
            .unwrap();
        assert_eq!(
            builder.finish(),
            Err(PathError::InsufficientDiversity {
                required: 1,
                actual: 0
            })
        );
    }

    #[test]
    fn canonical_path_metadata_round_trips_and_prepends() {
        let hops = vec![
            hop(1, RouteScope::General, 10, true),
            hop(2, RouteScope::LocalMesh, 11, false),
        ];
        let encoded = encode_path_metadata(&hops).expect("metadata");
        assert_eq!(decode_path_metadata(&encoded).expect("decode"), hops);
        let prepended = prepend_path_metadata(
            &encoded,
            PathHop {
                peer: vec![3],
                scope: RouteScope::General,
                failure_domain: Vec::new(),
                relay: true,
            },
        )
        .expect("prepend");
        let decoded = decode_path_metadata(&prepended).expect("decode prepended");
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].peer, vec![3]);
    }

    #[test]
    fn path_metadata_rejects_noncanonical_or_oversized_input() {
        assert_eq!(
            decode_path_metadata(b"legacy"),
            Err(PathMetadataError::InvalidMarker)
        );
        let mut encoded =
            encode_path_metadata(&[hop(1, RouteScope::General, 1, true)]).expect("metadata");
        encoded.push(0);
        assert_eq!(
            decode_path_metadata(&encoded),
            Err(PathMetadataError::TrailingBytes)
        );
    }
}
