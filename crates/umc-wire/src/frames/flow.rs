use crate::frame::FrameError;
use umc_types::frame::FrameType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxDataFrame {
    pub maximum_data: u64,
}

impl MaxDataFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_DATA.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.maximum_data).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `MAX_DATA` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Varint` if the field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (v, n) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        Ok((Self { maximum_data: v }, n))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamDataFrame {
    pub stream_id: u64,
    pub maximum_stream_data: u64,
}

impl MaxStreamDataFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_STREAM_DATA.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.stream_id).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.maximum_stream_data).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `MAX_STREAM_DATA` body (bytes after the type byte), returning
    /// the frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (sid, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        let (max, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        Ok((Self { stream_id: sid, maximum_stream_data: max }, n1 + n2))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamsFrame {
    pub bidirectional: bool,
    pub maximum_streams: u64,
}

impl MaxStreamsFrame {
    /// Encodes the frame including the type byte.
    ///
    /// # Errors
    ///
    /// Returns `VarintEncode` if a field cannot be encoded.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = Vec::new();
        crate::varint::encode_into(&mut out, FrameType::MAX_STREAMS.0).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, u64::from(!self.bidirectional)).map_err(FrameError::VarintEncode)?;
        crate::varint::encode_into(&mut out, self.maximum_streams).map_err(FrameError::VarintEncode)?;
        Ok(out)
    }

    /// Decodes a `MAX_STREAMS` body (bytes after the type byte), returning the
    /// frame and the number of body bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPadding` if the direction field is not 0 or 1, and
    /// `Varint` if a field is malformed or truncated.
    pub fn decode(body: &[u8]) -> Result<(Self, usize), FrameError> {
        let (dir, n1) = crate::varint::decode(body).map_err(FrameError::Varint)?;
        if dir > 1 {
            return Err(FrameError::InvalidPadding);
        }
        let (max, n2) = crate::varint::decode(&body[n1..]).map_err(FrameError::Varint)?;
        Ok((Self { bidirectional: dir == 0, maximum_streams: max }, n1 + n2))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_data_round_trip() {
        let f = MaxDataFrame { maximum_data: 4 * 1024 * 1024 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn max_stream_data_round_trip() {
        let f = MaxStreamDataFrame { stream_id: 3, maximum_stream_data: 256 * 1024 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxStreamDataFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn max_streams_round_trip_and_direction_validation() {
        let f = MaxStreamsFrame { bidirectional: true, maximum_streams: 16 };
        let enc = f.encode().unwrap();
        let (dec, _) = MaxStreamsFrame::decode(&enc[1..]).unwrap();
        assert_eq!(dec, f);
        assert_eq!(MaxStreamsFrame::decode(&[0x02, 0x10]).unwrap_err(), FrameError::InvalidPadding);
    }
}
