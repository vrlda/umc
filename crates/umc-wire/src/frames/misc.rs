use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_HINTS: usize = 32;
pub const MAX_PEER_ID: usize = 64;
pub const MAX_CARRIER_TYPE: usize = 64;
pub const MAX_CONNECTION_HINT: usize = 1_024;
pub const MAX_AUTHENTICATOR: usize = 1_024;
pub const MAX_PROTOCOL_ID: usize = 255;
// AUDIT FIX: wire-format.md §56 caps SERVICE_HINT endpoint hint at 512 bytes.
pub const MAX_ENDPOINT_HINT: usize = 512;
pub const MAX_SERVICE_METADATA: usize = 4_096;
pub const MAX_SIGNATURE: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct PeerHintEntry {
    pub temporary_peer_id: Vec<u8>,
    pub carrier_type: Vec<u8>,
    pub connection_hint: Vec<u8>,
    pub expiration_time: u64,
    pub public: bool,
    pub introduced: bool,
    pub local: bool,
    pub ephemeral: bool,
    pub do_not_reshare: bool,
    pub authenticator: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerHintFrame {
    pub entries: Vec<PeerHintEntry>,
}

impl PeerHintFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the entry count or a field exceeds its
    /// limit, and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.entries.len() > MAX_HINTS {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::PEER_HINT.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.entries.len() as u64).map_err(FrameError::VarintEncode)?;
        for e in &self.entries {
            crate::bytes::encode(&mut out, &e.temporary_peer_id, MAX_PEER_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &e.carrier_type, MAX_CARRIER_TYPE).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &e.connection_hint, MAX_CONNECTION_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::varint::encode_into(&mut out, e.expiration_time).map_err(FrameError::VarintEncode)?;
            let mut flags = 0u8;
            if e.public { flags |= 0x01; }
            if e.introduced { flags |= 0x02; }
            if e.local { flags |= 0x04; }
            if e.ephemeral { flags |= 0x08; }
            if e.do_not_reshare { flags |= 0x10; }
            out.push(flags);
            crate::bytes::encode(&mut out, &e.authenticator, MAX_AUTHENTICATOR).map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    /// Decodes a `PEER_HINT` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the entry count exceeds [`MAX_HINTS`],
    /// `InvalidPadding` if reserved flag bits are set, and `Truncated` or
    /// `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (count, mut pos) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if count > MAX_HINTS as u64 {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_PEER_ID).map_err(|_| FrameError::Truncated)?;
            let temp_peer_id = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_CARRIER_TYPE).map_err(|_| FrameError::Truncated)?;
            let carrier_type = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_CONNECTION_HINT).map_err(|_| FrameError::Truncated)?;
            let connection_hint = v.to_vec();
            pos += n;
            let (expiration, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
            pos += n;
            let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
            pos += 1;
            if flags & 0xE0 != 0 {
                return Err(FrameError::InvalidPadding);
            }
            let (auth, n) = crate::bytes::decode(&body[pos..], MAX_AUTHENTICATOR).map_err(|_| FrameError::Truncated)?;
            pos += n;
            entries.push(PeerHintEntry {
                temporary_peer_id: temp_peer_id,
                carrier_type,
                connection_hint,
                expiration_time: expiration,
                public: flags & 0x01 != 0,
                introduced: flags & 0x02 != 0,
                local: flags & 0x04 != 0,
                ephemeral: flags & 0x08 != 0,
                do_not_reshare: flags & 0x10 != 0,
                authenticator: auth.to_vec(),
            });
        }
        Ok((Self { entries }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceHintFrame {
    pub protocol_id: Vec<u8>,
    pub endpoint_hint: Vec<u8>,
    pub metadata: Vec<u8>,
    pub expiration_time: u64,
    pub signature: Vec<u8>,
}

impl ServiceHintFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if a field exceeds its limit, and
    /// `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::SERVICE_HINT.0).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.protocol_id, MAX_PROTOCOL_ID).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.endpoint_hint, MAX_ENDPOINT_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.metadata, MAX_SERVICE_METADATA).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.expiration_time).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.signature, MAX_SIGNATURE).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `SERVICE_HINT` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let (protocol_id, n) = crate::bytes::decode(&body[pos..], MAX_PROTOCOL_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (endpoint_hint, n) = crate::bytes::decode(&body[pos..], MAX_ENDPOINT_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (metadata, n) = crate::bytes::decode(&body[pos..], MAX_SERVICE_METADATA).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (expiration_time, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (signature, n) = crate::bytes::decode(&body[pos..], MAX_SIGNATURE).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((Self { protocol_id: protocol_id.to_vec(), endpoint_hint: endpoint_hint.to_vec(), metadata: metadata.to_vec(), expiration_time, signature: signature.to_vec() }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_len(ty: u64) -> usize {
        crate::varint::encode(ty).unwrap().len()
    }

    #[test]
    fn peer_hint_round_trip() {
        let f = PeerHintFrame { entries: vec![PeerHintEntry { temporary_peer_id: b"peer-1".to_vec(), carrier_type: b"ump.udp/1".to_vec(), connection_hint: b"1.2.3.4:5678".to_vec(), expiration_time: 1_700_000_000_000, public: true, introduced: false, local: false, ephemeral: false, do_not_reshare: false, authenticator: vec![] }] };
        let enc = f.encode().unwrap();
        let (dec, _) = PeerHintFrame::decode(&enc[type_len(FrameType::PEER_HINT.0)..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn service_hint_round_trip() {
        let f = ServiceHintFrame { protocol_id: b"org.example.echo/1".to_vec(), endpoint_hint: b"token".to_vec(), metadata: vec![], expiration_time: 1_700_000_000_000, signature: b"sig".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = ServiceHintFrame::decode(&enc[type_len(FrameType::SERVICE_HINT.0)..]).unwrap();
        assert_eq!(dec, f);
    }
}
