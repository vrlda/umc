use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_RELAY_PAYLOAD: usize = 64 * 1024;
pub const MAX_RELAY_DIAGNOSTIC: usize = 256;
pub const MAX_RELAY_AUTH: usize = 1_024;
pub const MAX_REQUESTED_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RelayOpenFrame {
    pub circuit_id: u64,
    pub bidirectional: bool,
    pub store_forward_allowed: bool,
    pub private_circuit: bool,
    pub multipath_allowed: bool,
    pub requested_lifetime: u64,
    pub requested_byte_quota: u64,
    pub next_hop_hint: Vec<u8>,
    pub authorization: Vec<u8>,
}

impl RelayOpenFrame {
    pub const MAX_NEXT_HOP_HINT: usize = 1_024;

    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if the requested lifetime is neither zero nor
    /// within [`MAX_REQUESTED_LIFETIME_MS`], `LengthExceedsLimit` if a field
    /// exceeds its limit, and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.requested_lifetime != 0 && !(1_000..=MAX_REQUESTED_LIFETIME_MS).contains(&self.requested_lifetime) {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_OPEN.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.bidirectional { flags |= 0x01; }
        if self.store_forward_allowed { flags |= 0x02; }
        if self.private_circuit { flags |= 0x04; }
        if self.multipath_allowed { flags |= 0x08; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.requested_lifetime).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.requested_byte_quota).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.next_hop_hint, Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authorization, MAX_RELAY_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `RELAY_OPEN` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set or the requested
    /// lifetime is out of range, and `Truncated` or `Varint` if the body is
    /// malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        if lifetime != 0 && !(1_000..=MAX_REQUESTED_LIFETIME_MS).contains(&lifetime) {
            return Err(FrameError::InvalidPadding);
        }
        let quota = read_varint(&mut pos)?;
        let (nh, n) = crate::bytes::decode(&body[pos..], Self::MAX_NEXT_HOP_HINT).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                circuit_id,
                bidirectional: flags & 0x01 != 0,
                store_forward_allowed: flags & 0x02 != 0,
                private_circuit: flags & 0x04 != 0,
                multipath_allowed: flags & 0x08 != 0,
                requested_lifetime: lifetime,
                requested_byte_quota: quota,
                next_hop_hint: nh.to_vec(),
                authorization: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct RelayStatusFrame {
    pub circuit_id: u64,
    pub status_sequence: u64,
    pub status_code: u64,
    pub bidirectional_granted: bool,
    pub private_handling_granted: bool,
    pub multipath_granted: bool,
    pub downstream_authenticated: bool,
    pub retryable: bool,
    pub granted_lifetime: u64,
    pub granted_byte_quota: u64,
    pub maximum_relay_payload: u64,
    pub diagnostic: Vec<u8>,
    pub authentication: Vec<u8>,
}

impl RelayStatusFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the diagnostic or authentication
    /// exceeds its limit, and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_STATUS.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.status_sequence).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.status_code).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.bidirectional_granted { flags |= 0x01; }
        if self.private_handling_granted { flags |= 0x02; }
        if self.multipath_granted { flags |= 0x04; }
        if self.downstream_authenticated { flags |= 0x08; }
        if self.retryable { flags |= 0x10; }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.granted_lifetime).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.granted_byte_quota).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.maximum_relay_payload).map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.diagnostic, MAX_RELAY_DIAGNOSTIC).map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_RELAY_AUTH).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `RELAY_STATUS` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set, and `Truncated`
    /// or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let lifetime = read_varint(&mut pos)?;
        let quota = read_varint(&mut pos)?;
        let max_payload = read_varint(&mut pos)?;
        let (diag, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_DIAGNOSTIC).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_AUTH).map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                circuit_id,
                status_sequence: seq,
                status_code: code,
                bidirectional_granted: flags & 0x01 != 0,
                private_handling_granted: flags & 0x02 != 0,
                multipath_granted: flags & 0x04 != 0,
                downstream_authenticated: flags & 0x08 != 0,
                retryable: flags & 0x10 != 0,
                granted_lifetime: lifetime,
                granted_byte_quota: quota,
                maximum_relay_payload: max_payload,
                diagnostic: diag.to_vec(),
                authentication: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDataFrame {
    pub circuit_id: u64,
    pub relay_sequence: u64,
    pub fin: bool,
    pub ack_requested: bool,
    pub high_priority: bool,
    pub data: Vec<u8>,
}

impl RelayDataFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the data exceeds
    /// [`MAX_RELAY_PAYLOAD`], `InvalidPadding` if the data is empty without
    /// `fin`, and `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_RELAY_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        if self.data.is_empty() && !self.fin {
            return Err(FrameError::InvalidPadding);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_DATA.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.relay_sequence).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.ack_requested { flags |= 0x02; }
        if self.high_priority { flags |= 0x04; }
        out.push(flags);
        crate::bytes::encode(&mut out, &self.data, MAX_RELAY_PAYLOAD).map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `RELAY_DATA` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set or the data is
    /// empty without `fin`, and `Truncated` or `Varint` if the body is
    /// malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let seq = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let (data, n) = crate::bytes::decode(&body[pos..], MAX_RELAY_PAYLOAD).map_err(|_| FrameError::Truncated)?;
        pos += n;
        if data.is_empty() && flags & 0x01 == 0 {
            return Err(FrameError::InvalidPadding);
        }
        Ok((
            Self {
                circuit_id,
                relay_sequence: seq,
                fin: flags & 0x01 != 0,
                ack_requested: flags & 0x02 != 0,
                high_priority: flags & 0x04 != 0,
                data: data.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCloseFrame {
    pub circuit_id: u64,
    pub reason_code: u64,
    pub final_relay_sequence: u64,
}

impl RelayCloseFrame {
    pub const NO_SEQUENCE: u64 = u64::MAX;

    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RELAY_CLOSE.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.circuit_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.reason_code).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.final_relay_sequence).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `RELAY_CLOSE` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let circuit_id = read_varint(&mut pos)?;
        let reason = read_varint(&mut pos)?;
        let final_seq = read_varint(&mut pos)?;
        Ok((Self { circuit_id, reason_code: reason, final_relay_sequence: final_seq }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_len(ty: u64) -> usize {
        crate::varint::encode(ty).unwrap().len()
    }

    #[test]
    fn relay_open_round_trip() {
        let f = RelayOpenFrame { circuit_id: 7, bidirectional: true, store_forward_allowed: false, private_circuit: true, multipath_allowed: false, requested_lifetime: 600_000, requested_byte_quota: 1_048_576, next_hop_hint: b"peer-candidate".to_vec(), authorization: b"proof".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, used) = RelayOpenFrame::decode(&enc[type_len(FrameType::RELAY_OPEN.0)..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - type_len(FrameType::RELAY_OPEN.0));
    }

    #[test]
    fn relay_open_rejects_out_of_range_lifetime() {
        let mut f = RelayOpenFrame { circuit_id: 1, bidirectional: false, store_forward_allowed: false, private_circuit: false, multipath_allowed: false, requested_lifetime: 100, requested_byte_quota: 0, next_hop_hint: vec![], authorization: vec![] };
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
        f.requested_lifetime = MAX_REQUESTED_LIFETIME_MS + 1;
        assert_eq!(f.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn relay_status_round_trip() {
        let f = RelayStatusFrame { circuit_id: 3, status_sequence: 0, status_code: 1, bidirectional_granted: true, private_handling_granted: false, multipath_granted: false, downstream_authenticated: true, retryable: false, granted_lifetime: 600_000, granted_byte_quota: 1_048_576, maximum_relay_payload: 65_536, diagnostic: vec![], authentication: vec![] };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayStatusFrame::decode(&enc[type_len(FrameType::RELAY_STATUS.0)..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn relay_data_round_trip_and_empty_rule() {
        let f = RelayDataFrame { circuit_id: 5, relay_sequence: 0, fin: false, ack_requested: true, high_priority: false, data: b"inner-packet".to_vec() };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayDataFrame::decode(&enc[type_len(FrameType::RELAY_DATA.0)..]).unwrap();
        assert_eq!(dec, f);
        let empty = RelayDataFrame { circuit_id: 5, relay_sequence: 1, fin: false, ack_requested: false, high_priority: false, data: vec![] };
        assert_eq!(empty.encode(), Err(FrameError::InvalidPadding));
    }

    #[test]
    fn relay_close_round_trip() {
        let f = RelayCloseFrame { circuit_id: 9, reason_code: 6, final_relay_sequence: 100 };
        let enc = f.encode().unwrap();
        let (dec, _) = RelayCloseFrame::decode(&enc[type_len(FrameType::RELAY_CLOSE.0)..]).unwrap();
        assert_eq!(dec, f);
    }
}
