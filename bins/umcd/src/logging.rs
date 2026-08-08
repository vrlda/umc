//! Leveled, privacy-aware logging (privacy.md §37, plan E1).
//!
//! The daemon logs through the `log` facade with an `env_logger` sink
//! configured from `RUST_LOG` (default `info`). Identity material —
//! endpoint ids, peer ids, session DCIDs — is truncated to the last four
//! bytes as lowercase hex at `info` and below (e.g. `…a1b2c3d4`); full
//! values appear only at `debug`. Carrier listen addresses are public
//! operator config and stay logged in full.

use std::fmt::Write as _;

/// Initializes the leveled logger from `RUST_LOG`, defaulting to `info`.
/// Idempotent-safe: a second call (e.g. under test) is a no-op, so it is
/// safe to call once at the top of `main` and again from test setup.
pub fn init_logging() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();
}

/// Truncates `prefix` to its last four bytes as lowercase hex, e.g.
/// `…a1b2c3d4`. Inputs shorter than four bytes return the hex of the
/// bytes they have (never panics).
pub fn redact(prefix: &[u8]) -> String {
    let start = prefix.len().saturating_sub(4);
    let mut out = String::with_capacity(prefix.len() * 2 + 1);
    out.push('…');
    for byte in &prefix[start..] {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The `[session] active` line (the daemon's session-established log):
/// the peer endpoint id is truncated so `info` logs never carry a full
/// peer id.
pub fn session_active_line(peer: &[u8]) -> String {
    format!("[session] active with peer {}", redact(peer))
}

/// Carrier listen addresses are public operator config (the addresses the
/// node advertises for inbound connections) and are logged in full; only
/// peer/endpoint/DCID material is redacted. This is the designated seam
/// should a future policy require address truncation.
pub fn redact_addr(addr: &str) -> String {
    addr.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_truncates_to_last_four_bytes() {
        assert_eq!(redact(&[0xAB; 32]), "…abababab");
    }

    #[test]
    fn redact_short_input() {
        assert_eq!(redact(&[0xAB, 0xCD]), "…abcd");
        assert_eq!(redact(&[0x12]), "…12");
        assert_eq!(redact(&[]), "…");
    }

    #[test]
    fn session_active_line_has_no_full_peer_id() {
        let peer = [0xAB; 32];
        let mut full_hex = String::with_capacity(64);
        for byte in &peer {
            let _ = write!(full_hex, "{byte:02x}");
        }
        let line = session_active_line(&peer);
        assert_eq!(line, "[session] active with peer …abababab");
        assert!(!line.contains(&full_hex));
    }

    #[test]
    fn init_logging_is_idempotent() {
        init_logging();
        init_logging();
    }

    #[test]
    fn redact_addr_keeps_listen_addresses_full() {
        assert_eq!(redact_addr("127.0.0.1:9001"), "127.0.0.1:9001");
    }
}
