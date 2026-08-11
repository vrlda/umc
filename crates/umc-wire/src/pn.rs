pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

/// Reconstructs a truncated packet number (session.md §8.1).
///
/// `expected` is `largest_received + 1` in the same space. The candidate
/// nearest to `expected` within the encoded window is returned.
///
/// # Errors
///
/// Returns `InvalidBits` if `bits` is 0 or greater than 62,
/// `TruncatedTooLarge` if `truncated` does not fit in `bits` bits, and
/// `Overflow` if `expected` lies within half a window of the packet-number
/// ceiling or the reconstructed value exceeds [`MAX_PACKET_NUMBER`].
pub fn reconstruct(truncated: u64, bits: u32, expected: u64) -> Result<u64, PnError> {
    if bits == 0 || bits > 62 {
        return Err(PnError::InvalidBits);
    }
    if truncated >= (1u64 << bits) {
        return Err(PnError::TruncatedTooLarge);
    }
    let window = 1u64 << bits;
    let half = window >> 1;
    if expected > MAX_PACKET_NUMBER - half {
        return Err(PnError::Overflow);
    }
    let mask = window - 1;
    let mut candidate = (expected & !mask) | truncated;
    if candidate.saturating_add(half) < expected
        && candidate.saturating_add(window) <= MAX_PACKET_NUMBER
    {
        candidate = candidate.saturating_add(window);
    } else if candidate > expected.saturating_add(half) && candidate >= window {
        candidate = candidate.saturating_sub(window);
    }
    if candidate > MAX_PACKET_NUMBER {
        return Err(PnError::Overflow);
    }
    Ok(candidate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PnError {
    InvalidBits,
    TruncatedTooLarge,
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_when_in_window() {
        assert_eq!(reconstruct(100, 8, 101).unwrap(), 100);
        assert_eq!(reconstruct(0, 1, 1).unwrap(), 0);
    }

    #[test]
    fn rolls_forward_across_window_boundary() {
        // expected 255, truncated 1 (8 bits): candidate 257 is nearest.
        assert_eq!(reconstruct(1, 8, 255).unwrap(), 257);
        // expected 100, truncated 90: 90 is nearer than 346.
        assert_eq!(reconstruct(90, 8, 100).unwrap(), 90);
    }

    #[test]
    fn rolls_back_when_behind() {
        // expected 400, truncated 200: 456 is nearer than 200.
        assert_eq!(reconstruct(200, 8, 400).unwrap(), 456);
    }

    #[test]
    fn rolls_back_across_window_boundary() {
        // expected 300, truncated 255 (8 bits): 255 is nearer than 511.
        assert_eq!(reconstruct(255, 8, 300).unwrap(), 255);
    }

    #[test]
    fn rejects_invalid_input() {
        assert_eq!(reconstruct(0, 0, 1), Err(PnError::InvalidBits));
        assert_eq!(reconstruct(2, 1, 1), Err(PnError::TruncatedTooLarge));
        assert_eq!(reconstruct(0, 63, 0), Err(PnError::InvalidBits));
    }

    #[test]
    fn rejects_overflow() {
        assert_eq!(
            reconstruct(MAX_PACKET_NUMBER, 62, MAX_PACKET_NUMBER),
            Err(PnError::Overflow)
        );
    }
}
