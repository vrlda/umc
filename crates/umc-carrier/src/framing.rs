#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// The encoded length cannot be represented by the framing format.
    LengthOverflow,
    /// The encoded or requested payload exceeds the configured bound.
    TooLarge,
}

/// Encodes one bounded stream-frame length using the UMP varint layout.
///
/// # Errors
///
/// Returns [`FramingError::TooLarge`] when `len` exceeds `max_len` and
/// [`FramingError::LengthOverflow`] when it cannot fit the UMP varint.
pub fn push_length(out: &mut Vec<u8>, len: usize, max_len: usize) -> Result<(), FramingError> {
    if len > max_len {
        return Err(FramingError::TooLarge);
    }
    let len = u64::try_from(len).map_err(|_| FramingError::LengthOverflow)?;
    if len > 0x3fff_ffff_ffff_ffff {
        return Err(FramingError::LengthOverflow);
    }
    if len <= 63 {
        out.push(u8::try_from(len).map_err(|_| FramingError::LengthOverflow)?);
    } else if len <= 16_383 {
        let value = u16::try_from(len).map_err(|_| FramingError::LengthOverflow)? | 0x4000;
        out.extend_from_slice(&value.to_be_bytes());
    } else if len <= 1_073_741_823 {
        let value = u32::try_from(len).map_err(|_| FramingError::LengthOverflow)? | 0x8000_0000;
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(0xc0 | u8::try_from(len >> 56).map_err(|_| FramingError::LengthOverflow)?);
        out.extend_from_slice(&len.to_be_bytes()[1..]);
    }
    Ok(())
}

/// Reads a bounded stream-frame length prefix.
///
/// # Errors
///
/// Returns [`FramingError::TooLarge`] when the peer declares a payload
/// above `max_len` and [`FramingError::LengthOverflow`] when conversion to
/// `usize` is impossible.
pub fn read_length(prefix: &[u8], max_len: usize) -> Result<Option<(usize, usize)>, FramingError> {
    let Some(&first) = prefix.first() else {
        return Ok(None);
    };
    let width = match first >> 6 {
        0 => 1usize,
        1 => 2usize,
        2 => 4usize,
        _ => 8usize,
    };
    if prefix.len() < width {
        return Ok(None);
    }
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(&prefix[..width]);
    raw[0] &= 0x3f;
    let length = u64::from_be_bytes(raw) >> ((8 - width) * 8);
    if length > max_len as u64 {
        return Err(FramingError::TooLarge);
    }
    Ok(Some((
        usize::try_from(length).map_err(|_| FramingError::LengthOverflow)?,
        width,
    )))
}

/// Encodes one payload with its bounded stream-frame length prefix.
///
/// # Errors
///
/// Returns the framing error from [`push_length`] when the payload is
/// above the configured bound.
pub fn frame_packet(payload: &[u8], max_len: usize) -> Result<Vec<u8>, FramingError> {
    let mut framed = Vec::with_capacity(payload.len().saturating_add(8));
    push_length(&mut framed, payload.len(), max_len)?;
    framed.extend_from_slice(payload);
    Ok(framed)
}

/// Decodes the first complete bounded stream frame in `buf`.
///
/// # Errors
///
/// Returns [`FramingError::TooLarge`] for an over-bound prefix and
/// [`FramingError::LengthOverflow`] for arithmetic/conversion overflow.
pub fn decode_frame(buf: &[u8], max_len: usize) -> Result<Option<&[u8]>, FramingError> {
    let Some((length, prefix_len)) = read_length(buf, max_len)? else {
        return Ok(None);
    };
    let end = prefix_len
        .checked_add(length)
        .ok_or(FramingError::LengthOverflow)?;
    if buf.len() < end {
        return Ok(None);
    }
    Ok(Some(&buf[prefix_len..end]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_round_trip_covers_length_boundaries() {
        for length in [0usize, 1, 63, 64, 16_383, 16_384, 65_535] {
            let payload = vec![0x5a; length];
            let framed = frame_packet(&payload, 65_535).expect("frame");
            assert_eq!(decode_frame(&framed, 65_535), Ok(Some(payload.as_slice())));
        }
    }

    #[test]
    fn stream_frame_parser_rejects_truncation_and_oversize() {
        assert_eq!(decode_frame(&[], 65_535), Ok(None));
        assert_eq!(decode_frame(&[0x40], 65_535), Ok(None));
        assert_eq!(decode_frame(&[0x40, 0x01], 65_535), Ok(None));
        assert_eq!(
            decode_frame(&[0xff; 8], 65_535),
            Err(FramingError::TooLarge)
        );
        assert_eq!(
            frame_packet(&vec![0u8; 65_536], 65_535),
            Err(FramingError::TooLarge)
        );
    }
}
