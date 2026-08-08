use umc_types::version::{MAX_CONNECTION_ID_LEN, MAX_TOKEN_LEN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    Long,
    Short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    Initial,
    Retry,
    Handshake,
    VersionNegotiation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortPacketSpace {
    SessionData,
    PathControl,
    RelayData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    ReservedBits,
    InvalidType,
    InvalidSpace,
    ConnectionIdTooLong,
    TokenTooLong,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderByte {
    pub long: bool,
    pub kind: u8,
    pub key_phase: bool,
    pub pn_bits: u32,
}

impl HeaderByte {
    pub const LONG_INITIAL: Self = Self {
        long: true,
        kind: 0,
        key_phase: false,
        pn_bits: 8,
    };
    pub const LONG_RETRY: Self = Self {
        long: true,
        kind: 1,
        key_phase: false,
        pn_bits: 8,
    };
    pub const LONG_HANDSHAKE: Self = Self {
        long: true,
        kind: 2,
        key_phase: false,
        pn_bits: 8,
    };
    pub const LONG_VERSION_NEGOTIATION: Self = Self {
        long: true,
        kind: 3,
        key_phase: false,
        pn_bits: 8,
    };
    pub const SHORT_SESSION: Self = Self {
        long: false,
        kind: 0,
        key_phase: false,
        pn_bits: 8,
    };
    pub const SHORT_PATH: Self = Self {
        long: false,
        kind: 1,
        key_phase: false,
        pn_bits: 8,
    };
    pub const SHORT_RELAY: Self = Self {
        long: false,
        kind: 2,
        key_phase: false,
        pn_bits: 8,
    };

    /// Encodes the header-form byte.
    #[must_use]
    pub fn encode(&self) -> u8 {
        let mut b = 0u8;
        if self.long {
            b |= 0x80;
        }
        b |= (self.kind & 0x03) << 5;
        if self.key_phase {
            b |= 0x10;
        }
        let pn_field = match self.pn_bits {
            8 => 0,
            16 => 1,
            32 => 2,
            64 => 3,
            _ => (self.pn_bits & 0x03) as u8,
        };
        b |= pn_field << 2;
        b
    }

    /// Decodes a header-form byte.
    ///
    /// # Errors
    ///
    /// Returns `ReservedBits` if any reserved bit is set.
    pub fn decode(b: u8) -> Result<Self, HeaderError> {
        if b & 0x03 != 0 {
            return Err(HeaderError::ReservedBits);
        }
        let pn_bits = match (b >> 2) & 0x03 {
            0 => 8u32,
            1 => 16,
            2 => 32,
            _ => 64,
        };
        Ok(Self {
            long: b & 0x80 != 0,
            kind: (b >> 5) & 0x03,
            key_phase: b & 0x10 != 0,
            pn_bits,
        })
    }

    /// Maps a long-header form byte to its packet type.
    #[must_use]
    pub fn long_type(&self) -> Option<LongPacketType> {
        if !self.long {
            return None;
        }
        match self.kind {
            0 => Some(LongPacketType::Initial),
            1 => Some(LongPacketType::Retry),
            2 => Some(LongPacketType::Handshake),
            _ => Some(LongPacketType::VersionNegotiation),
        }
    }

    /// Maps a short-header form byte to its packet space.
    #[must_use]
    pub fn short_space(&self) -> Option<ShortPacketSpace> {
        if self.long {
            return None;
        }
        match self.kind {
            0 => Some(ShortPacketSpace::SessionData),
            1 => Some(ShortPacketSpace::PathControl),
            2 => Some(ShortPacketSpace::RelayData),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongHeader {
    pub ptype: LongPacketType,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token: Vec<u8>,
    pub payload_len: u64,
    pub packet_number: u64,
    pub pn_bits: u32,
}

impl LongHeader {
    /// Encodes the long header into its wire representation.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionIdTooLong` if either connection ID exceeds the
    /// protocol limit, `TokenTooLong` if the token is oversized, or
    /// `Truncated` if a varint cannot be encoded.
    #[allow(clippy::cast_possible_truncation)]
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        if self.dcid.len() > MAX_CONNECTION_ID_LEN || self.scid.len() > MAX_CONNECTION_ID_LEN {
            return Err(HeaderError::ConnectionIdTooLong);
        }
        if self.token.len() > MAX_TOKEN_LEN {
            return Err(HeaderError::TokenTooLong);
        }
        let mut out = Vec::new();
        let hb = match self.ptype {
            LongPacketType::Initial => HeaderByte::LONG_INITIAL,
            LongPacketType::Retry => HeaderByte::LONG_RETRY,
            LongPacketType::Handshake => HeaderByte::LONG_HANDSHAKE,
            // Version-Negotiation is intentionally NOT supported by the
            // wire crate's LongHeader builder: its layout (no token/payload
            // length, versions as BE u32 list) differs from the normal long
            // header, and umc-handshake owns the minimal VN builder/parser
            // pair (xx.rs build_version_negotiation/parse_version_negotiation).
            LongPacketType::VersionNegotiation => HeaderByte::LONG_VERSION_NEGOTIATION,
        };
        out.push(hb.encode());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(&self.dcid);
        out.push(self.scid.len() as u8);
        out.extend_from_slice(&self.scid);
        crate::varint::encode_into(&mut out, self.token.len() as u64)
            .map_err(|_| HeaderError::Truncated)?;
        out.extend_from_slice(&self.token);
        crate::varint::encode_into(&mut out, self.payload_len)
            .map_err(|_| HeaderError::Truncated)?;
        let pn_bytes = (self.pn_bits as usize) / 8;
        out.extend_from_slice(&self.packet_number.to_be_bytes()[8 - pn_bytes..]);
        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortHeader {
    pub space: ShortPacketSpace,
    pub dcid: Vec<u8>,
    pub path_id: u64,
    pub packet_number: u64,
    pub pn_bits: u32,
    pub key_phase: bool,
}

impl ShortHeader {
    /// Encodes the short header into its wire representation.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionIdTooLong` if the destination connection ID exceeds
    /// the protocol limit, or `Truncated` if a varint cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderError> {
        if self.dcid.len() > MAX_CONNECTION_ID_LEN {
            return Err(HeaderError::ConnectionIdTooLong);
        }
        let mut out = Vec::new();
        let mut hb = match self.space {
            ShortPacketSpace::SessionData => HeaderByte::SHORT_SESSION,
            ShortPacketSpace::PathControl => HeaderByte::SHORT_PATH,
            ShortPacketSpace::RelayData => HeaderByte::SHORT_RELAY,
        };
        hb.key_phase = self.key_phase;
        hb.pn_bits = self.pn_bits;
        out.push(hb.encode());
        out.extend_from_slice(&self.dcid);
        crate::varint::encode_into(&mut out, self.path_id).map_err(|_| HeaderError::Truncated)?;
        let pn_bytes = (self.pn_bits as usize) / 8;
        out.extend_from_slice(&self.packet_number.to_be_bytes()[8 - pn_bytes..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::version::PROTOCOL_VERSION;

    #[test]
    fn header_byte_round_trip() {
        for hb in [
            HeaderByte::LONG_INITIAL,
            HeaderByte::LONG_HANDSHAKE,
            HeaderByte::SHORT_SESSION,
            HeaderByte::SHORT_PATH,
            HeaderByte::SHORT_RELAY,
        ] {
            assert_eq!(HeaderByte::decode(hb.encode()).unwrap(), hb);
        }
    }

    #[test]
    fn rejects_reserved_bits() {
        assert_eq!(HeaderByte::decode(0x01), Err(HeaderError::ReservedBits));
    }

    #[test]
    fn pn_bits_map_to_byte_lengths() {
        let hb = HeaderByte::decode(0b0000_0000).unwrap();
        assert_eq!(hb.pn_bits, 8);
        let hb = HeaderByte::decode(0b0000_0100).unwrap();
        assert_eq!(hb.pn_bits, 16);
    }

    #[test]
    fn long_header_round_trip() {
        let h = LongHeader {
            ptype: LongPacketType::Initial,
            version: PROTOCOL_VERSION,
            dcid: vec![1, 2, 3, 4, 5, 6, 7, 8],
            scid: vec![9, 10, 11, 12, 13, 14, 15, 16],
            token: vec![],
            payload_len: 64,
            packet_number: 42,
            pn_bits: 16,
        };
        let enc = h.encode().unwrap();
        assert_eq!(enc[0], 0b1000_0000);
        assert_eq!(&enc[1..5], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(enc[5], 8);
        assert_eq!(enc[6 + 8], 8);
    }

    #[test]
    fn rejects_oversized_ids() {
        let h = LongHeader {
            ptype: LongPacketType::Initial,
            version: PROTOCOL_VERSION,
            dcid: vec![0u8; 21],
            scid: vec![],
            token: vec![],
            payload_len: 0,
            packet_number: 0,
            pn_bits: 8,
        };
        assert_eq!(h.encode(), Err(HeaderError::ConnectionIdTooLong));
    }

    #[test]
    fn short_header_round_trip() {
        let h = ShortHeader {
            space: ShortPacketSpace::SessionData,
            dcid: vec![1, 2, 3, 4, 5, 6, 7, 8],
            path_id: 1,
            packet_number: 4021,
            pn_bits: 16,
            key_phase: false,
        };
        let enc = h.encode().unwrap();
        assert_eq!(enc[0], 0b0000_0100);
        // Layout: header byte (1) + dcid (8) + path id varint (1) + pn 2 bytes.
        assert_eq!(&enc[9..], &[0x01, 0x0F, 0xB5]);
        let space = HeaderByte::decode(enc[0]).unwrap().short_space().unwrap();
        assert_eq!(space, ShortPacketSpace::SessionData);
    }

    #[test]
    fn short_header_rejects_oversized_dcid() {
        let h = ShortHeader {
            space: ShortPacketSpace::SessionData,
            dcid: vec![0u8; 21],
            path_id: 0,
            packet_number: 0,
            pn_bits: 8,
            key_phase: false,
        };
        assert_eq!(h.encode(), Err(HeaderError::ConnectionIdTooLong));
    }
}
