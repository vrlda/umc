//! Route response validation and forwarding (routing.md §17-19).

use umc_wire::frames::routing::RouteResponseFrame;

/// Structural and policy failures for a `ROUTE_RESPONSE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseError {
    /// A route with no lifetime cannot become a usable candidate.
    ZeroLifetime,
    /// The response exceeds the stable local route-cache maximum.
    LifetimeTooLong,
    /// The response outlives the request branch that carried it.
    ExceedsRequestLifetime,
    /// A route leg cannot be both direct and relay-required.
    ConflictingFlags,
}

/// Validate the fields that a forwarder can check before touching route
/// cache or reverse-path state. Wire decoding already enforces bounded
/// lengths and reserved bits; this helper enforces routing policy
/// (routing.md §§16.2-16.3).
///
/// # Errors
///
/// Returns an error when the response has conflicting flags, an unusable
/// lifetime, or exceeds the request branch's remaining lifetime.
pub fn validate_response(
    response: &RouteResponseFrame,
    remaining_request_lifetime_ms: u64,
) -> Result<(), ResponseError> {
    if response.direct && response.relay_required {
        return Err(ResponseError::ConflictingFlags);
    }
    if response.route_lifetime == 0 {
        return Err(ResponseError::ZeroLifetime);
    }
    if response.route_lifetime > crate::types::MAX_REQUEST_LIFETIME_MS {
        return Err(ResponseError::LifetimeTooLong);
    }
    if response.route_lifetime > remaining_request_lifetime_ms {
        return Err(ResponseError::ExceedsRequestLifetime);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(lifetime: u64) -> RouteResponseFrame {
        RouteResponseFrame {
            request_id: 1,
            response_sequence: 0,
            direct: true,
            relay_required: false,
            store_forward_available: false,
            local_path: true,
            gateway_path: false,
            route_lifetime: lifetime,
            next_hop_hint: b"next-hop".to_vec(),
            route_metadata: Vec::new(),
            authentication: Vec::new(),
        }
    }

    #[test]
    fn rejects_zero_lifetime() {
        assert_eq!(
            validate_response(&response(0), 30_000),
            Err(ResponseError::ZeroLifetime)
        );
    }

    #[test]
    fn rejects_lifetime_beyond_request_branch() {
        assert_eq!(
            validate_response(&response(30_001), 30_000),
            Err(ResponseError::ExceedsRequestLifetime)
        );
    }

    #[test]
    fn rejects_lifetime_beyond_local_maximum() {
        assert_eq!(
            validate_response(
                &response(crate::types::MAX_REQUEST_LIFETIME_MS + 1),
                u64::MAX
            ),
            Err(ResponseError::LifetimeTooLong)
        );
    }

    #[test]
    fn rejects_direct_and_relay_flags_together() {
        let mut route = response(1_000);
        route.relay_required = true;
        assert_eq!(
            validate_response(&route, 30_000),
            Err(ResponseError::ConflictingFlags)
        );
    }

    #[test]
    fn accepts_bounded_response() {
        assert_eq!(validate_response(&response(30_000), 30_000), Ok(()));
    }
}
