//! Stateless reset (session.md §31).
//!
//! When a packet arrives for a connection that no longer exists (or whose
//! keys were discarded), the endpoint MAY answer with a stateless reset: a
//! short-header-shaped packet carrying the connection's reset token, so the
//! peer can authenticate the reset without any session state.
//!
//! Canonical reset layout (SANCTIONED, session.md §31):
//!
//! ```text
//! byte 0          short-header byte 0x00 (session-data space, lowest pn bits)
//! bytes 1..9      zero destination connection ID (8 bytes)
//! bytes 9..25     the 16-byte stateless-reset token
//! bytes 25..41    16+ bytes of random tail (total >= 32 bytes)
//! ```
//!
//! The token slot is fixed at `bytes[9..25]`: the receiver scans that slot
//! of any packet that fails authentication with a constant-time compare. The
//! token is the first 16 bytes of the 32-byte `stateless reset` session
//! secret derived in the handshake (handshake.md §26).
use umc_types::runtime::EntropySource;

/// Length of the stateless-reset token (session.md §30.1, §31).
pub const RESET_TOKEN_LEN: usize = 16;
/// Bytes of random tail appended after the token: the reset must be at least
/// as long as the smallest protected packet and the tail hides the token
/// from off-path observers (session.md §31).
const RANDOM_TAIL_LEN: usize = 16;

/// The reset token: the first 16 bytes of the 32-byte `stateless reset`
/// session secret (handshake.md §26).
#[must_use]
pub fn reset_token(stateless_reset_secret: &[u8; 32]) -> [u8; RESET_TOKEN_LEN] {
    let mut token = [0u8; RESET_TOKEN_LEN];
    token.copy_from_slice(&stateless_reset_secret[..RESET_TOKEN_LEN]);
    token
}

/// Build a stateless-reset packet (session.md §31): a short-header-shaped
/// blob — header byte `0x00`, 8 zero DCID bytes, the 16-byte token at
/// `bytes[9..25]`, then 16 random bytes — indistinguishable in length and
/// leading bytes from protected traffic, 41 bytes total.
#[must_use]
pub fn build_stateless_reset(token: &[u8; RESET_TOKEN_LEN], random: &dyn EntropySource) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + RESET_TOKEN_LEN + RANDOM_TAIL_LEN);
    out.push(0x00);
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(token);
    let mut tail = [0u8; RANDOM_TAIL_LEN];
    random.fill(&mut tail);
    out.extend_from_slice(&tail);
    out
}

/// Whether `bytes` carries `token` at the fixed reset slot of the canonical
/// layout: a short-header packet (long bit clear, valid header byte) with
/// the token at `bytes[9..25]`. The compare is a fixed-length XOR fold, so
/// a token mismatch does not leak a byte-by-byte timing signal
/// (session.md §31).
#[must_use]
pub fn token_matches(bytes: &[u8], token: &[u8; RESET_TOKEN_LEN]) -> bool {
    let Some(slot) = bytes.get(9..9 + RESET_TOKEN_LEN) else {
        return false;
    };
    let Ok(header) = umc_wire::header::HeaderByte::decode(bytes[0]) else {
        return false;
    };
    if header.long {
        return false;
    }
    slot.iter()
        .zip(token.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FillEntropy(u8);

    impl EntropySource for FillEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(self.0);
        }
    }

    #[test]
    fn token_is_first_16_of_secret() {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            {
                *b = i as u8; // distinct byte values; i < 32 fits u8
            }
        }
        let token = reset_token(&secret);
        assert_eq!(
            token,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        // The token must NOT be the second half of the secret: the derivation
        // is a documented prefix cut, and the test pins it.
        assert_ne!(&token[..], &secret[16..]);
    }

    #[test]
    fn reset_packet_looks_like_short_header() {
        let token = [0xAB; 16];
        let pkt = build_stateless_reset(&token, &FillEntropy(7));
        assert!(
            pkt.len() >= 32,
            "reset is at least as long as the smallest packet"
        );
        let hb = umc_wire::header::HeaderByte::decode(pkt[0]).expect("valid header byte");
        assert!(!hb.long, "first byte is a short-header form");
        assert_eq!(pkt[0], 0x00);
        assert_eq!(&pkt[1..9], &[0u8; 8], "zero DCID slot");
        assert_eq!(&pkt[9..25], &token, "token at the fixed slot");
    }

    #[test]
    fn token_matches_finds_the_token() {
        let token = [0x42; 16];
        let pkt = build_stateless_reset(&token, &FillEntropy(7));
        assert!(token_matches(&pkt, &token));
    }

    #[test]
    fn tampered_packet_does_not_match() {
        let token = [0x42; 16];
        let mut pkt = build_stateless_reset(&token, &FillEntropy(7));
        pkt[12] ^= 0x01;
        assert!(!token_matches(&pkt, &token));
        assert!(!token_matches(&pkt, &[0x43; 16]));
    }

    #[test]
    fn long_header_packet_does_not_match() {
        let token = [0x42; 16];
        let mut pkt = build_stateless_reset(&token, &FillEntropy(7));
        pkt[0] |= 0x80;
        assert!(!token_matches(&pkt, &token));
    }

    #[test]
    fn short_packet_cannot_match() {
        let token = [0x42; 16];
        assert!(!token_matches(&[0u8; 10], &token));
        assert!(!token_matches(&[], &token));
    }
}
