use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HANDSHAKE_TRANSCRIPT: usize = 65_536;
pub const MAX_HANDSHAKE_MESSAGE: usize = 16_384;
pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_CAPABILITY_VALUE: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFrame {
    pub method: u64,
    pub data: Vec<u8>,
}

impl AuthFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the data is longer than
    /// [`MAX_HANDSHAKE_MESSAGE`], and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::AUTH.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.method).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.data, MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes an `AUTH` body (bytes after the type varint), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the data length exceeds the remaining buffer,
    /// and `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (method, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (data, n2) = crate::bytes::decode(&body[n1..], MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::Truncated)?;
        Ok((Self { method, data: data.to_vec() }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeDataFrame {
    pub offset: u64,
    pub data: Vec<u8>,
}

impl HandshakeDataFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the data is longer than
    /// [`MAX_HANDSHAKE_MESSAGE`], and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::HANDSHAKE_DATA.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.offset).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.data, MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `HANDSHAKE_DATA` body (bytes after the type varint),
    /// returning the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the data length exceeds the remaining buffer,
    /// and `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (offset, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (data, n2) = crate::bytes::decode(&body[n1..], MAX_HANDSHAKE_MESSAGE).map_err(|_| FrameError::Truncated)?;
        Ok((Self { offset, data: data.to_vec() }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitiesFrame {
    pub entries: Vec<Capability>,
}

impl CapabilitiesFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if there are more than [`MAX_CAPABILITIES`]
    /// entries or a value is longer than [`MAX_CAPABILITY_VALUE`], and
    /// `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.entries.len() > MAX_CAPABILITIES {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::CAPABILITIES.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.entries.len() as u64).map_err(FrameError::VarintEncode)?;
        for e in &self.entries {
            crate::varint::encode_into(&mut out, e.id).map_err(FrameError::VarintEncode)?;
            crate::bytes::encode(&mut out, &e.value, MAX_CAPABILITY_VALUE).map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    /// Decodes a `CAPABILITIES` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the entry count exceeds
    /// [`MAX_CAPABILITIES`], `Truncated` if a value length exceeds the
    /// remaining buffer, and `Varint` if a field is malformed or truncated.
    #[allow(clippy::cast_possible_truncation)]
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (count, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if count as usize > MAX_CAPABILITIES {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut pos = n1;
        let mut entries = Vec::new();
        for _ in 0..count {
            let (id, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
            pos += n;
            let (value, n) = crate::bytes::decode(&body[pos..], MAX_CAPABILITY_VALUE).map_err(|_| FrameError::Truncated)?;
            pos += n;
            entries.push(Capability { id, value: value.to_vec() });
        }
        Ok((Self { entries }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionTicketFrame {
    pub lifetime: u64,
    pub age_add: u64,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
}

impl SessionTicketFrame {
    pub const MAX_TICKET: usize = 16_384;

    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the nonce is longer than 256 bytes or
    /// the ticket is longer than [`Self::MAX_TICKET`], and `VarintEncode` if a
    /// field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::SESSION_TICKET.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.lifetime).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.age_add).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.nonce, 256).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.ticket, Self::MAX_TICKET).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `SESSION_TICKET` body (bytes after the type varint),
    /// returning the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if a length exceeds the remaining buffer, and
    /// `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let lifetime = read_varint(&mut pos)?;
        let age_add = read_varint(&mut pos)?;
        let (nonce, n) = crate::bytes::decode(&body[pos..], 256).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (ticket, n) = crate::bytes::decode(&body[pos..], Self::MAX_TICKET).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { lifetime, age_add, nonce: nonce.to_vec(), ticket: ticket.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_round_trip() {
        let f = AuthFrame { method: 1, data: b"invitation-proof".to_vec() };
        let enc = f.encode().unwrap();
        let type_len = crate::varint::encode(FrameType::AUTH.0).unwrap().len();
        let (dec, _) = AuthFrame::decode(&enc[type_len..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn handshake_data_round_trip() {
        let f = HandshakeDataFrame { offset: 0, data: b"client hello bytes".to_vec() };
        let enc = f.encode().unwrap();
        let type_len = crate::varint::encode(FrameType::HANDSHAKE_DATA.0).unwrap().len();
        let (dec, _) = HandshakeDataFrame::decode(&enc[type_len..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn capabilities_round_trip() {
        let f = CapabilitiesFrame { entries: vec![Capability { id: 1, value: b"1200".to_vec() }] };
        let enc = f.encode().unwrap();
        let type_len = crate::varint::encode(FrameType::CAPABILITIES.0).unwrap().len();
        let (dec, _) = CapabilitiesFrame::decode(&enc[type_len..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn session_ticket_round_trip() {
        let f = SessionTicketFrame { lifetime: 86_400, age_add: 7, nonce: vec![1, 2, 3], ticket: vec![9; 64] };
        let enc = f.encode().unwrap();
        let type_len = crate::varint::encode(FrameType::SESSION_TICKET.0).unwrap().len();
        let (dec, _) = SessionTicketFrame::decode(&enc[type_len..]).unwrap();
        assert_eq!(dec, f);
    }
}
