use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_BUNDLE_ID: usize = 64;
pub const MAX_BUNDLE_DESTINATION_HINT: usize = 512;
pub const MAX_BUNDLE_AUTH: usize = 1_024;
pub const MAX_BUNDLE_PAYLOAD: usize = 65_535 - 128; // one base frame, headers/tags excluded

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct BundleFrame {
    pub bundle_id: Vec<u8>,
    pub custody_requested: bool,
    pub delivery_ack_requested: bool,
    pub do_not_replicate: bool,
    pub local_scope_only: bool,
    pub high_sensitivity: bool,
    pub priority: u64,
    pub creation_time: u64,
    pub expiration_time: u64,
    pub replication_limit: u64,
    pub destination_hint: Vec<u8>,
    pub payload: Vec<u8>,
    pub bundle_auth: Vec<u8>,
}

impl BundleFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if a field exceeds its limit, and
    /// `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.payload.len() > MAX_BUNDLE_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::BUNDLE.0)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.bundle_id, MAX_BUNDLE_ID)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        let mut flags = 0u8;
        if self.custody_requested {
            flags |= 0x01;
        }
        if self.delivery_ack_requested {
            flags |= 0x02;
        }
        if self.do_not_replicate {
            flags |= 0x04;
        }
        if self.local_scope_only {
            flags |= 0x08;
        }
        if self.high_sensitivity {
            flags |= 0x10;
        }
        out.push(flags);
        crate::varint::encode_into(&mut out, self.priority).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.creation_time)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.expiration_time)
            .map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.replication_limit)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(
            &mut out,
            &self.destination_hint,
            MAX_BUNDLE_DESTINATION_HINT,
        )
        .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.payload, MAX_BUNDLE_PAYLOAD)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::bytes::encode(&mut out, &self.bundle_auth, MAX_BUNDLE_AUTH)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `BUNDLE` body (bytes after the type varint), returning the
    /// frame and the number of body bytes consumed.
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
        let (id, n) =
            crate::bytes::decode(&body[pos..], MAX_BUNDLE_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let priority = read_varint(&mut pos)?;
        let created = read_varint(&mut pos)?;
        let expires = read_varint(&mut pos)?;
        let replication = read_varint(&mut pos)?;
        let (dh, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_DESTINATION_HINT)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (payload, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_PAYLOAD)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_AUTH)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                bundle_id: id.to_vec(),
                custody_requested: flags & 0x01 != 0,
                delivery_ack_requested: flags & 0x02 != 0,
                do_not_replicate: flags & 0x04 != 0,
                local_scope_only: flags & 0x08 != 0,
                high_sensitivity: flags & 0x10 != 0,
                priority,
                creation_time: created,
                expiration_time: expires,
                replication_limit: replication,
                destination_hint: dh.to_vec(),
                payload: payload.to_vec(),
                bundle_auth: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleAckFrame {
    pub bundle_id: Vec<u8>,
    pub status: u64,
    pub stored_until: u64,
    pub authentication: Vec<u8>,
}

impl BundleAckFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if a field exceeds its limit, and
    /// `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::BUNDLE_ACK.0)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.bundle_id, MAX_BUNDLE_ID)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        crate::varint::encode_into(&mut out, self.status).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.stored_until)
            .map_err(FrameError::VarintEncode)?;
        crate::bytes::encode(&mut out, &self.authentication, MAX_BUNDLE_AUTH)
            .map_err(|_| FrameError::LengthExceedsLimit)?;
        Ok(out)
    }

    /// Decodes a `BUNDLE_ACK` body (bytes after the type varint), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Truncated` or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let (id, n) =
            crate::bytes::decode(&body[pos..], MAX_BUNDLE_ID).map_err(|_| FrameError::Truncated)?;
        pos += n;
        let (status, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (stored_until, n) = crate::varint::decode(&body[pos..]).map_err(FrameError::Varint)?;
        pos += n;
        let (auth, n) = crate::bytes::decode(&body[pos..], MAX_BUNDLE_AUTH)
            .map_err(|_| FrameError::Truncated)?;
        pos += n;
        Ok((
            Self {
                bundle_id: id.to_vec(),
                status,
                stored_until,
                authentication: auth.to_vec(),
            },
            pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_len(ty: u64) -> usize {
        crate::varint::encode(ty).unwrap().len()
    }

    #[test]
    fn bundle_round_trip() {
        let f = BundleFrame {
            bundle_id: vec![1, 2, 3],
            custody_requested: false,
            delivery_ack_requested: true,
            do_not_replicate: true,
            local_scope_only: false,
            high_sensitivity: false,
            priority: 1,
            creation_time: 1_700_000_000_000,
            expiration_time: 1_700_086_400_000,
            replication_limit: 3,
            destination_hint: b"dest-token".to_vec(),
            payload: vec![0xAA; 256],
            bundle_auth: b"sig".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = BundleFrame::decode(&enc[type_len(FrameType::BUNDLE.0)..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - type_len(FrameType::BUNDLE.0));
    }

    #[test]
    fn bundle_ack_round_trip() {
        let f = BundleAckFrame {
            bundle_id: vec![1, 2, 3],
            status: 1,
            stored_until: 1_700_086_400_000,
            authentication: vec![],
        };
        let enc = f.encode().unwrap();
        let (dec, _) = BundleAckFrame::decode(&enc[type_len(FrameType::BUNDLE_ACK.0)..]).unwrap();
        assert_eq!(dec, f);
    }
}
