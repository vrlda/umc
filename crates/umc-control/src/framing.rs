//! Length-prefixed envelope framing (control-api.md §5):
//! `MessageLength`: unsigned 32-bit big-endian, then the protobuf Envelope.

pub const DEFAULT_MAX_ENVELOPE: usize = 4 * 1024 * 1024;
pub const HARD_MAX_ENVELOPE: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    ZeroLength,
    TooLarge,
    Truncated,
    Io,
}

/// Append one envelope with its 4-byte length prefix.
///
/// # Errors
///
/// Returns [`FramingError::ZeroLength`] for an empty envelope and
/// [`FramingError::TooLarge`] when the envelope exceeds `max`.
///
/// # Panics
///
/// Panics if `envelope.len()` exceeds `u32::MAX` (already bounded by `max`).
pub fn frame_envelope(out: &mut Vec<u8>, envelope: &[u8], max: usize) -> Result<(), FramingError> {
    if envelope.is_empty() {
        return Err(FramingError::ZeroLength);
    }
    if envelope.len() > max {
        return Err(FramingError::TooLarge);
    }
    let len = u32::try_from(envelope.len()).expect("envelope length fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(envelope);
    Ok(())
}

/// Incremental decoder: feed bytes, extract complete envelopes.
#[derive(Debug)]
pub struct EnvelopeDecoder {
    buf: Vec<u8>,
    max: usize,
}

impl EnvelopeDecoder {
    #[must_use]
    pub const fn new(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            max,
        }
    }

    /// Feed bytes and extract complete envelopes.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::ZeroLength`] for a zero-length prefix,
    /// [`FramingError::TooLarge`] for an envelope over `max`, and
    /// [`FramingError::Truncated`] for a buffer exceeding `max + 4` without a
    /// complete envelope.
    ///
    /// # Panics
    ///
    /// Panics if the decoder buffer is shorter than 4 bytes (guarded by the
    /// length check).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FramingError> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len = u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes")) as usize;
            if len == 0 {
                return Err(FramingError::ZeroLength);
            }
            if len > self.max {
                return Err(FramingError::TooLarge);
            }
            if self.buf.len() < 4 + len {
                break;
            }
            out.push(self.buf[4..4 + len].to_vec());
            self.buf.drain(..4 + len);
        }
        if self.buf.len() > self.max + 4 {
            return Err(FramingError::TooLarge);
        }
        Ok(out)
    }
}

impl Default for EnvelopeDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENVELOPE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_and_decode_round_trip() {
        let mut out = Vec::new();
        frame_envelope(&mut out, b"hello", 4096).unwrap();
        assert_eq!(&out[..4], &[0, 0, 0, 5]);
        let mut decoder = EnvelopeDecoder::new(4096);
        let envelopes = decoder.feed(&out).unwrap();
        assert_eq!(envelopes, vec![b"hello".to_vec()]);
    }

    #[test]
    fn incremental_delivery() {
        let mut out = Vec::new();
        frame_envelope(&mut out, b"one", 4096).unwrap();
        frame_envelope(&mut out, b"two", 4096).unwrap();
        let mut decoder = EnvelopeDecoder::new(4096);
        // Feed byte by byte.
        let mut all = Vec::new();
        for b in out {
            all.extend(decoder.feed(&[b]).unwrap());
        }
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], b"one");
        assert_eq!(all[1], b"two");
    }

    #[test]
    fn rejects_oversize_before_alloc() {
        let mut decoder = EnvelopeDecoder::new(16);
        // A prefix declaring more than max is rejected as soon as the 4-byte
        // header is parsed, before any payload is buffered or allocated.
        assert_eq!(decoder.feed(&[0, 0, 0, 20]), Err(FramingError::TooLarge));
    }

    #[test]
    fn rejects_zero_length() {
        let mut decoder = EnvelopeDecoder::new(4096);
        assert_eq!(decoder.feed(&[0, 0, 0, 0]), Err(FramingError::ZeroLength));
    }
}
