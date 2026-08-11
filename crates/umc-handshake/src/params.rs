//! Transport-parameter negotiation (handshake.md §30, session.md §7).
//!
//! The wire handshake carries these values in the negotiated capabilities
//! block.  This module keeps validation and intersection policy independent
//! from a particular carrier or daemon runtime.

/// Bounded transport parameters offered by one endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_bidirectional_streams: u64,
    pub initial_max_unidirectional_streams: u64,
    pub maximum_datagram_size: u64,
    /// Zero means that this endpoint does not impose an idle timeout.
    pub idle_timeout_ms: u64,
    pub maximum_ack_delay_ms: u64,
    pub ack_delay_exponent: u64,
    pub active_connection_id_limit: u64,
    pub maximum_paths: u64,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            initial_max_data: 4 * 1024 * 1024,
            initial_max_stream_data_bidi_local: 256 * 1024,
            initial_max_stream_data_bidi_remote: 256 * 1024,
            initial_max_stream_data_uni: 256 * 1024,
            initial_max_bidirectional_streams: 16,
            initial_max_unidirectional_streams: 16,
            maximum_datagram_size: 1_200,
            idle_timeout_ms: 30_000,
            maximum_ack_delay_ms: 25,
            ack_delay_exponent: 3,
            active_connection_id_limit: 4,
            maximum_paths: 1,
        }
    }
}

/// Maximum values accepted by the stable profile.
pub const MAX_ACK_DELAY_EXPONENT: u64 = 20;
pub const MAX_ACK_DELAY_MS: u64 = 1_000;
pub const MAX_ACTIVE_CONNECTION_ID_LIMIT: u64 = 8;
pub const MAX_PATHS: u64 = 8;
pub const MAX_DATAGRAM_SIZE: u64 = 65_535;

/// Validation failure for a received parameter set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// Reserved/unknown critical parameters are rejected by the enclosing
    /// capability decoder before this typed structure is constructed.
    UnknownCritical,
    /// Duplicate parameters are rejected by the enclosing decoder.
    Duplicate,
    ValueTooLarge,
    InvalidValue,
}

/// Validates one endpoint's bounded transport parameters.
///
/// # Errors
///
/// Returns [`ParamError::ValueTooLarge`] for values outside profile caps and
/// [`ParamError::InvalidValue`] for values that would make the transport
/// unusable.
pub fn validate_parameters(params: &TransportParameters) -> Result<(), ParamError> {
    if params.ack_delay_exponent > MAX_ACK_DELAY_EXPONENT
        || params.maximum_ack_delay_ms > MAX_ACK_DELAY_MS
        || params.active_connection_id_limit > MAX_ACTIVE_CONNECTION_ID_LIMIT
        || params.maximum_paths > MAX_PATHS
        || params.maximum_datagram_size > MAX_DATAGRAM_SIZE
    {
        return Err(ParamError::ValueTooLarge);
    }
    if params.active_connection_id_limit < 2
        || params.maximum_paths == 0
        || (params.maximum_datagram_size != 0 && params.maximum_datagram_size < 1_200)
    {
        return Err(ParamError::InvalidValue);
    }
    Ok(())
}

fn min_nonzero(left: u64, right: u64) -> u64 {
    match (left, right) {
        (0, value) | (value, 0) => value,
        (left, right) => left.min(right),
    }
}

/// Computes the effective intersection of two validated offers.
///
/// The result is the smaller resource allowance for every bounded counter.
/// A zero idle timeout means “no timeout” and therefore yields the non-zero
/// peer value when only one endpoint supplied a timeout.
///
/// # Panics
///
/// Panics if either offer fails [`validate_parameters`]. Callers receiving
/// untrusted wire data should validate before invoking this helper.
#[must_use]
pub fn effective_parameters(
    local: &TransportParameters,
    remote: &TransportParameters,
) -> TransportParameters {
    assert!(
        validate_parameters(local).is_ok(),
        "local parameters are invalid"
    );
    assert!(
        validate_parameters(remote).is_ok(),
        "remote parameters are invalid"
    );
    TransportParameters {
        initial_max_data: local.initial_max_data.min(remote.initial_max_data),
        initial_max_stream_data_bidi_local: local
            .initial_max_stream_data_bidi_local
            .min(remote.initial_max_stream_data_bidi_local),
        initial_max_stream_data_bidi_remote: local
            .initial_max_stream_data_bidi_remote
            .min(remote.initial_max_stream_data_bidi_remote),
        initial_max_stream_data_uni: local
            .initial_max_stream_data_uni
            .min(remote.initial_max_stream_data_uni),
        initial_max_bidirectional_streams: local
            .initial_max_bidirectional_streams
            .min(remote.initial_max_bidirectional_streams),
        initial_max_unidirectional_streams: local
            .initial_max_unidirectional_streams
            .min(remote.initial_max_unidirectional_streams),
        maximum_datagram_size: local
            .maximum_datagram_size
            .min(remote.maximum_datagram_size),
        idle_timeout_ms: min_nonzero(local.idle_timeout_ms, remote.idle_timeout_ms),
        maximum_ack_delay_ms: local.maximum_ack_delay_ms.min(remote.maximum_ack_delay_ms),
        ack_delay_exponent: local.ack_delay_exponent.min(remote.ack_delay_exponent),
        active_connection_id_limit: local
            .active_connection_id_limit
            .min(remote.active_connection_id_limit),
        maximum_paths: local.maximum_paths.min(remote.maximum_paths),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert_eq!(validate_parameters(&TransportParameters::default()), Ok(()));
    }

    #[test]
    fn effective_limits_take_the_minimum() {
        let local = TransportParameters {
            initial_max_data: 1_000,
            ..Default::default()
        };
        let remote = TransportParameters {
            initial_max_data: 2_000,
            ..Default::default()
        };
        assert_eq!(
            effective_parameters(&local, &remote).initial_max_data,
            1_000
        );
    }

    #[test]
    fn zero_idle_timeout_uses_the_peer_limit() {
        let local = TransportParameters {
            idle_timeout_ms: 0,
            ..Default::default()
        };
        let remote = TransportParameters {
            idle_timeout_ms: 2_000,
            ..Default::default()
        };
        assert_eq!(effective_parameters(&local, &remote).idle_timeout_ms, 2_000);
    }

    #[test]
    fn oversized_and_unusable_values_are_rejected() {
        let params = TransportParameters {
            maximum_ack_delay_ms: MAX_ACK_DELAY_MS + 1,
            ..Default::default()
        };
        assert_eq!(validate_parameters(&params), Err(ParamError::ValueTooLarge));
        let params = TransportParameters {
            active_connection_id_limit: 1,
            ..Default::default()
        };
        assert_eq!(validate_parameters(&params), Err(ParamError::InvalidValue));
        let params = TransportParameters {
            maximum_datagram_size: 1_000,
            ..Default::default()
        };
        assert_eq!(validate_parameters(&params), Err(ParamError::InvalidValue));
    }
}
