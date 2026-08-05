use crate::varint::{decode as decode_varint, encode_into};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesError {
    VarintTooLarge,
    LengthExceedsLimit,
    Truncated,
}

/// Encode a length-prefixed byte string (wire-format §6).
///
/// # Errors
///
/// Returns `LengthExceedsLimit` if `value` is longer than `limit`, and
/// `VarintTooLarge` if the length does not fit a canonical varint.
pub fn encode(out: &mut Vec<u8>, value: &[u8], limit: usize) -> Result<(), BytesError> {
    if value.len() > limit {
        return Err(BytesError::LengthExceedsLimit);
    }
    encode_into(out, value.len() as u64).map_err(|_| BytesError::VarintTooLarge)?;
    out.extend_from_slice(value);
    Ok(())
}

/// Decode a length-prefixed byte string. Returns (value, `bytes_consumed`).
///
/// # Errors
///
/// Returns `Truncated` if the buffer ends before the declared length is
/// present, and `LengthExceedsLimit` if the declared length exceeds `limit`.
#[allow(clippy::cast_possible_truncation)]
pub fn decode(buf: &[u8], limit: usize) -> Result<(&[u8], usize), BytesError> {
    let (len, n) = decode_varint(buf).map_err(|_| BytesError::Truncated)?;
    if len > limit as u64 {
        return Err(BytesError::LengthExceedsLimit);
    }
    let len = len as usize;
    let total = n.checked_add(len).ok_or(BytesError::Truncated)?;
    if buf.len() < total {
        return Err(BytesError::Truncated);
    }
    Ok((&buf[n..total], total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut out = Vec::new();
        encode(&mut out, b"hello", 1024).unwrap();
        let (v, n) = decode(&out, 1024).unwrap();
        assert_eq!((v, n), (&b"hello"[..], out.len()));
    }

    #[test]
    fn empty_string_is_valid() {
        let mut out = Vec::new();
        encode(&mut out, b"", 1024).unwrap();
        assert_eq!(out, vec![0x00]);
        let (v, _) = decode(&out, 1024).unwrap();
        assert!(v.is_empty());
    }

    #[test]
    fn rejects_oversize_before_allocation() {
        let mut out = Vec::new();
        assert_eq!(encode(&mut out, &[0u8; 5], 4), Err(BytesError::LengthExceedsLimit));
        // Declared length larger than the buffer and larger than limit.
        assert_eq!(decode(&[0x40, 0x40], 3), Err(BytesError::LengthExceedsLimit));
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(decode(&[0x40, 0x40, 0x01], 1024), Err(BytesError::Truncated));
        assert_eq!(decode(&[], 1024), Err(BytesError::Truncated));
    }
}
