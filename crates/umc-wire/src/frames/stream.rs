use crate::frame::FrameError;
use umc_types::frame::FrameType;

pub const MAX_PROTOCOL_ID_LEN: usize = 255;
pub const MAX_STREAM_METADATA_LEN: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct StreamFrame {
    pub stream_id: u64,
    pub fin: bool,
    pub offset_present: bool,
    pub len_present: bool,
    pub open: bool,
    pub unidirectional: bool,
    pub offset: u64,
    pub data: Vec<u8>,
    pub protocol_id: Vec<u8>,
    pub metadata: Vec<u8>,
}

impl StreamFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `LengthExceedsLimit` if the protocol id exceeds
    /// [`MAX_PROTOCOL_ID_LEN`] or the metadata exceeds
    /// [`MAX_STREAM_METADATA_LEN`], and `VarintEncode` if a field cannot be
    /// encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::STREAM.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::VarintEncode)?;
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.offset_present { flags |= 0x02; }
        if self.len_present { flags |= 0x04; }
        if self.open { flags |= 0x08; }
        if self.unidirectional { flags |= 0x10; }
        out.push(flags);
        if self.offset_present {
            crate::varint::encode_into(&mut out, self.offset).map_err(FrameError::VarintEncode)?;
        }
        if self.len_present {
            crate::varint::encode_into(&mut out, self.data.len() as u64).map_err(FrameError::VarintEncode)?;
        }
        out.extend_from_slice(&self.data);
        if self.open {
            crate::bytes::encode(&mut out, &self.protocol_id, MAX_PROTOCOL_ID_LEN)
                .map_err(|_| FrameError::LengthExceedsLimit)?;
            crate::bytes::encode(&mut out, &self.metadata, MAX_STREAM_METADATA_LEN)
                .map_err(|_| FrameError::LengthExceedsLimit)?;
        }
        Ok(out)
    }

    /// Decodes a `STREAM` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if reserved flag bits are set,
    /// `LengthExceedsLimit` if the data length exceeds `u32::MAX` or the
    /// open fields exceed their limits, and `Varint` or `Truncated` if a
    /// field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let mut pos = 0usize;
        let read_varint = |p: &mut usize| -> Result<u64, FrameError> {
            let (v, n) = crate::varint::decode(&body[*p..]).map_err(FrameError::Varint)?;
            *p += n;
            Ok(v)
        };
        let stream_id = read_varint(&mut pos)?;
        let flags = *body.get(pos).ok_or(FrameError::Truncated)?;
        pos += 1;
        if flags & 0xE0 != 0 {
            return Err(FrameError::InvalidPadding);
        }
        let offset_present = flags & 0x02 != 0;
        let len_present = flags & 0x04 != 0;
        let offset = if offset_present { read_varint(&mut pos)? } else { 0 };
        let data_len = if len_present {
            let l = read_varint(&mut pos)?;
            u32::try_from(l).map_err(|_| FrameError::LengthExceedsLimit)? as usize
        } else {
            body.len() - pos
        };
        let end = pos.checked_add(data_len).ok_or(FrameError::Truncated)?;
        let data = body.get(pos..end).ok_or(FrameError::Truncated)?.to_vec();
        pos = end;
        let mut protocol_id = Vec::new();
        let mut metadata = Vec::new();
        if flags & 0x08 != 0 {
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_PROTOCOL_ID_LEN).map_err(|_| FrameError::Truncated)?;
            protocol_id = v.to_vec();
            pos += n;
            let (v, n) = crate::bytes::decode(&body[pos..], MAX_STREAM_METADATA_LEN).map_err(|_| FrameError::Truncated)?;
            metadata = v.to_vec();
            pos += n;
        }
        Ok((
            Self {
                stream_id,
                fin: flags & 0x01 != 0,
                offset_present,
                len_present,
                open: flags & 0x08 != 0,
                unidirectional: flags & 0x10 != 0,
                offset,
                data,
                protocol_id,
                metadata,
            },
            pos,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetStreamFrame {
    pub stream_id: u64,
    pub app_error_code: u64,
    pub final_size: u64,
}

impl ResetStreamFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::RESET_STREAM.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.app_error_code).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.final_size).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `RESET_STREAM` body (bytes after the type byte), returning
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
        let stream_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        let final_size = read_varint(&mut pos)?;
        Ok((Self { stream_id, app_error_code: code, final_size }, pos))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopSendingFrame {
    pub stream_id: u64,
    pub app_error_code: u64,
}

impl StopSendingFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::STOP_SENDING.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.app_error_code).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `STOP_SENDING` body (bytes after the type byte), returning
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
        let stream_id = read_varint(&mut pos)?;
        let code = read_varint(&mut pos)?;
        Ok((Self { stream_id, app_error_code: code }, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_round_trip_with_open() {
        let f = StreamFrame {
            stream_id: 0,
            fin: true,
            offset_present: true,
            len_present: true,
            open: true,
            unidirectional: false,
            offset: 0,
            data: b"hello".to_vec(),
            protocol_id: b"org.example.echo/1".to_vec(),
            metadata: Vec::new(),
        };
        let enc = f.encode().unwrap();
        let (dec, used) = StreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(used, enc.len() - 1);
    }

    #[test]
    fn stream_data_to_end_of_packet() {
        // LEN_PRESENT = 0: data extends to packet end.
        let enc = [0x10, 0x00, 0x00, 0x61, 0x62, 0x63];
        let (dec, used) = StreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec.data, b"abc");
        assert_eq!(used, enc.len() - 1);
        assert!(!dec.len_present);
    }

    #[test]
    fn reset_stream_round_trip() {
        let f = ResetStreamFrame { stream_id: 4, app_error_code: 7, final_size: 100 };
        let enc = f.encode().unwrap();
        let (dec, _) = ResetStreamFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn stop_sending_round_trip() {
        let f = StopSendingFrame { stream_id: 5, app_error_code: 1 };
        let enc = f.encode().unwrap();
        let (dec, _) = StopSendingFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }
}
