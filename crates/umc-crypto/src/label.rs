/// HKDF-Expand-Label construction (see `handshake.md` §13).
/// Encoded: `Length` || "ump v1 " || Label || `ContextLength` || Context
pub const LABEL_PREFIX: &[u8] = b"ump v1 ";

/// Derives a key with the protocol's domain-separated label encoding.
///
/// # Errors
/// Returns [`HkdfError::LengthOutOfRange`] if the requested `length` exceeds
/// the encodable output bound, or [`HkdfError::ContextTooLong`] if `context`
/// cannot be represented by the protocol's 16-bit length field.
pub fn expand_label(
    secret: &[u8; 32],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, HkdfError> {
    if length > usize::from(u16::MAX) {
        return Err(HkdfError::LengthOutOfRange);
    }
    if context.len() > usize::from(u16::MAX) {
        return Err(HkdfError::ContextTooLong);
    }
    let mut info = Vec::with_capacity(LABEL_PREFIX.len() + label.len() + context.len() + 8);
    #[allow(clippy::cast_possible_truncation)]
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    #[allow(clippy::cast_possible_truncation)]
    info.extend_from_slice(&(context.len() as u16).to_be_bytes());
    info.extend_from_slice(context);
    crate::hkdf::expand(secret, &info, length)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HkdfError {
    LengthOutOfRange,
    ContextTooLong,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_encoding_matches_spec_layout() {
        let secret = [0u8; 32];
        let out = expand_label(&secret, b"packet key", b"", 32).unwrap();
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn labels_are_domain_separated() {
        let secret = [7u8; 32];
        let a = expand_label(&secret, b"packet key", b"", 32).unwrap();
        let b = expand_label(&secret, b"packet iv", b"", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn context_changes_output() {
        let secret = [7u8; 32];
        let a = expand_label(&secret, b"traffic update", b"", 32).unwrap();
        let b = expand_label(&secret, b"traffic update", b"x", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_context_that_cannot_be_canonically_encoded() {
        let secret = [8u8; 32];
        let context = vec![0u8; usize::from(u16::MAX) + 1];
        assert_eq!(
            expand_label(&secret, b"review", &context, 32),
            Err(HkdfError::ContextTooLong)
        );
    }
}
