#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameType(pub u64);

impl FrameType {
    pub const PADDING: Self = Self(0x00);
    pub const PING: Self = Self(0x04);
    pub const ACK: Self = Self(0x08);
    pub const CONNECTION_CLOSE: Self = Self(0x0C);
    pub const STREAM: Self = Self(0x10);
    pub const RESET_STREAM: Self = Self(0x14);
    pub const STOP_SENDING: Self = Self(0x18);
    pub const MAX_DATA: Self = Self(0x1C);
    pub const MAX_STREAM_DATA: Self = Self(0x20);
    pub const MAX_STREAMS: Self = Self(0x24);
    pub const DATAGRAM: Self = Self(0x28);
    pub const NEW_CONNECTION_ID: Self = Self(0x2C);
    pub const RETIRE_CONNECTION_ID: Self = Self(0x30);
    pub const PATH_CHALLENGE: Self = Self(0x34);
    pub const PATH_RESPONSE: Self = Self(0x38);
    pub const PATH_STATUS: Self = Self(0x3C);
    pub const MIGRATE: Self = Self(0x40);
    pub const KEY_UPDATE: Self = Self(0x44);
    pub const ROUTE_REQUEST: Self = Self(0x48);
    pub const ROUTE_RESPONSE: Self = Self(0x4C);
    pub const ROUTE_ERROR: Self = Self(0x50);
    pub const RELAY_OPEN: Self = Self(0x54);
    pub const RELAY_DATA: Self = Self(0x58);
    pub const RELAY_CLOSE: Self = Self(0x5C);
    pub const BUNDLE: Self = Self(0x60);
    pub const BUNDLE_ACK: Self = Self(0x64);
    pub const PEER_HINT: Self = Self(0x68);
    pub const CAPABILITIES: Self = Self(0x6C);
    pub const AUTH: Self = Self(0x70);
    pub const HANDSHAKE_DATA: Self = Self(0x74);
    pub const SESSION_TICKET: Self = Self(0x78);
    pub const SERVICE_HINT: Self = Self(0x7C);
    pub const RELAY_STATUS: Self = Self(0x82);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionBehavior {
    CriticalFixed,
    OptionalFixed,
    CriticalLengthDelimited,
    OptionalLengthDelimited,
}

impl FrameType {
    #[must_use]
    pub fn behavior(self) -> ExtensionBehavior {
        match self.0 & 0b11 {
            0b00 => ExtensionBehavior::CriticalFixed,
            0b01 => ExtensionBehavior::OptionalFixed,
            0b10 => ExtensionBehavior::CriticalLengthDelimited,
            _ => ExtensionBehavior::OptionalLengthDelimited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_frame_types_are_critical_fixed_layout() {
        assert_eq!(
            FrameType::PADDING.behavior(),
            ExtensionBehavior::CriticalFixed
        );
        assert_eq!(FrameType::PING.behavior(), ExtensionBehavior::CriticalFixed);
        assert_eq!(FrameType::ACK.behavior(), ExtensionBehavior::CriticalFixed);
        assert_eq!(
            FrameType::ROUTE_REQUEST.behavior(),
            ExtensionBehavior::CriticalFixed
        );
        assert_eq!(
            FrameType::RELAY_STATUS.behavior(),
            ExtensionBehavior::CriticalLengthDelimited
        );
        assert_eq!(
            FrameType::BUNDLE.behavior(),
            ExtensionBehavior::CriticalFixed
        );
    }

    #[test]
    fn all_registered_frame_types_have_exact_values() {
        let table: &[(FrameType, u64)] = &[
            (FrameType::PADDING, 0x00),
            (FrameType::PING, 0x04),
            (FrameType::ACK, 0x08),
            (FrameType::CONNECTION_CLOSE, 0x0C),
            (FrameType::STREAM, 0x10),
            (FrameType::RESET_STREAM, 0x14),
            (FrameType::STOP_SENDING, 0x18),
            (FrameType::MAX_DATA, 0x1C),
            (FrameType::MAX_STREAM_DATA, 0x20),
            (FrameType::MAX_STREAMS, 0x24),
            (FrameType::DATAGRAM, 0x28),
            (FrameType::NEW_CONNECTION_ID, 0x2C),
            (FrameType::RETIRE_CONNECTION_ID, 0x30),
            (FrameType::PATH_CHALLENGE, 0x34),
            (FrameType::PATH_RESPONSE, 0x38),
            (FrameType::PATH_STATUS, 0x3C),
            (FrameType::MIGRATE, 0x40),
            (FrameType::KEY_UPDATE, 0x44),
            (FrameType::ROUTE_REQUEST, 0x48),
            (FrameType::ROUTE_RESPONSE, 0x4C),
            (FrameType::ROUTE_ERROR, 0x50),
            (FrameType::RELAY_OPEN, 0x54),
            (FrameType::RELAY_DATA, 0x58),
            (FrameType::RELAY_CLOSE, 0x5C),
            (FrameType::BUNDLE, 0x60),
            (FrameType::BUNDLE_ACK, 0x64),
            (FrameType::PEER_HINT, 0x68),
            (FrameType::CAPABILITIES, 0x6C),
            (FrameType::AUTH, 0x70),
            (FrameType::HANDSHAKE_DATA, 0x74),
            (FrameType::SESSION_TICKET, 0x78),
            (FrameType::SERVICE_HINT, 0x7C),
            (FrameType::RELAY_STATUS, 0x82),
        ];
        for (frame_type, expected) in table {
            assert_eq!(frame_type.0, *expected, "{frame_type:?}");
        }
    }

    #[test]
    fn unknown_optional_length_delimited_is_skippable() {
        let t = FrameType(0x0F);
        assert_eq!(t.behavior(), ExtensionBehavior::OptionalLengthDelimited);
        let t = FrameType(0x01);
        assert_eq!(t.behavior(), ExtensionBehavior::OptionalFixed);
    }
}
