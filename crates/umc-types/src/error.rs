#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportError(pub u64);

impl TransportError {
    pub const NO_ERROR: Self = Self(0x00);
    pub const INTERNAL_ERROR: Self = Self(0x01);
    pub const PROTOCOL_VIOLATION: Self = Self(0x02);
    pub const FRAME_ENCODING_ERROR: Self = Self(0x03);
    pub const UNSUPPORTED_VERSION: Self = Self(0x04);
    pub const UNSUPPORTED_FRAME: Self = Self(0x05);
    pub const CRYPTO_ERROR: Self = Self(0x06);
    pub const AUTHENTICATION_FAILED: Self = Self(0x07);
    pub const REPLAY_DETECTED: Self = Self(0x08);
    pub const FLOW_CONTROL_ERROR: Self = Self(0x09);
    pub const STREAM_LIMIT_ERROR: Self = Self(0x0A);
    pub const CONNECTION_ID_ERROR: Self = Self(0x0B);
    pub const PATH_VALIDATION_FAILED: Self = Self(0x0C);
    pub const ROUTE_NOT_FOUND: Self = Self(0x0D);
    pub const ROUTE_LOOP: Self = Self(0x0E);
    pub const RELAY_REFUSED: Self = Self(0x0F);
    pub const RESOURCE_LIMIT: Self = Self(0x10);
    pub const STORAGE_LIMIT: Self = Self(0x11);
    pub const EXPIRED: Self = Self(0x12);
    pub const POLICY_REJECTED: Self = Self(0x13);
    pub const CARRIER_FAILURE: Self = Self(0x14);
    pub const HANDSHAKE_TIMEOUT: Self = Self(0x15);
    pub const IDLE_TIMEOUT: Self = Self(0x16);
    pub const KEY_UPDATE_ERROR: Self = Self(0x17);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_match_wire_format_registry() {
        assert_eq!(TransportError::NO_ERROR.0, 0x00);
        assert_eq!(TransportError::PROTOCOL_VIOLATION.0, 0x02);
        assert_eq!(TransportError::KEY_UPDATE_ERROR.0, 0x17);
    }
}
