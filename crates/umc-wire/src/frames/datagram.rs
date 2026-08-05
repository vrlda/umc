use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_DATAGRAM_PAYLOAD: usize = 1_200; // initial path-safe bound

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    pub context_id: u64,
    pub ack_requested: bool,
    pub duplicate_suppression: bool,
    pub expiration_delta: Option<u64>,
    pub data: Vec<u8>,
}

impl DatagramFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the payload exceeds
    /// [`MAX_DATAGRAM_PAYLOAD`], and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.data.len() > MAX_DATAGRAM_PAYLOAD {
            return Err(FrameError::LengthExceedsLimit);
        }
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::DATAGRAM.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.context_id).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.ack_requested { flags |= 0x01; }
        if self.duplicate_suppression { flags |= 0x02; }
        if self.expiration_delta.is_some() { flags |= 0x04; }
        out.push(flags);
        if let Some(d) = self.expiration_delta {
            crate::varint::encode_into(&mut out, d).map_err(FrameError::VarintEncode)?;
        }
        crate::varint::encode_into(&mut out, self.data.len() as u64).map_err(FrameError::VarintEncode)?;
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decodes a `DATAGRAM` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set,
    /// `LengthExceedsLimit` if the payload exceeds [`MAX_DATAGRAM_PAYLOAD`],
    /// and `Truncated` or `Varint` if the body is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let context_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xF8 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let expiration_delta = if flags & 0x04 != 0 { Some(read_varint(&mut pos)?) } else { None };
        let data_len = read_varint(&mut pos)?;
        if data_len > MAX_DATAGRAM_PAYLOAD as u64 {
            return Err(FrameError::LengthExceedsLimit);
        }
        let end = pos.checked_add(usize::try_from(data_len).map_err(|_| FrameError::Truncated)?)
            .ok_or(FrameError::Truncated)?;
        let data = body.get(pos..end).ok_or(FrameError::Truncated)?.to_vec();
        Ok((
            Self {
                context_id,
                ack_requested: flags & 0x01 != 0,
                duplicate_suppression: flags & 0x02 != 0,
                expiration_delta,
                data,
            },
            end,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_round_trip_with_expiration() {
        let f = DatagramFrame {
            context_id: 7,
            ack_requested: true,
            duplicate_suppression: false,
            expiration_delta: Some(500),
            data: b"ping".to_vec(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = DatagramFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn rejects_oversize_datagram() {
        let f = DatagramFrame {
            context_id: 0,
            ack_requested: false,
            duplicate_suppression: false,
            expiration_delta: None,
            data: vec![0u8; MAX_DATAGRAM_PAYLOAD + 1],
        };
        assert_eq!(f.encode(), Err(FrameError::LengthExceedsLimit));
    }
}
