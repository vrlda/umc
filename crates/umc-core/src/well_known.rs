//! Well-known protocol IDs (wire-format.md §63): the daemon's built-in
//! services, all living under the `org.umc.` namespace.
use crate::app::MAX_PROTOCOL_ID_LEN;

/// The echo application: the daemon's reference application.
pub const WELL_KNOWN_APP: &[u8] = b"org.umc.app/1";
/// The control channel protocol.
pub const WELL_KNOWN_CONTROL: &[u8] = b"org.umc.control/1";
/// The bundle protocol.
pub const WELL_KNOWN_BUNDLE: &[u8] = b"org.umc.bundle/1";
/// The relay protocol.
pub const WELL_KNOWN_RELAY: &[u8] = b"org.umc.relay/1";
/// The routing protocol.
pub const WELL_KNOWN_ROUTING: &[u8] = b"org.umc.routing/1";

/// The namespace prefix every well-known protocol ID starts with.
pub const WELL_KNOWN_PREFIX: &[u8] = b"org.umc.";

/// Whether a protocol ID belongs to the daemon's well-known namespace.
///
/// Well-known IDs are reserved: applications cannot register them unless
/// the daemon explicitly backs the ID with an application (the echo app
/// registers `org.umc.app/1` at startup).
#[must_use]
pub fn is_well_known(id: &[u8]) -> bool {
    id.starts_with(WELL_KNOWN_PREFIX) && id.len() <= MAX_PROTOCOL_ID_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constant_matches_the_prefix_rule() {
        for id in [
            WELL_KNOWN_APP,
            WELL_KNOWN_CONTROL,
            WELL_KNOWN_BUNDLE,
            WELL_KNOWN_RELAY,
            WELL_KNOWN_ROUTING,
        ] {
            assert!(is_well_known(id), "{id:?} must be well-known");
            assert!(
                id.starts_with(WELL_KNOWN_PREFIX),
                "{id:?} must start with the namespace prefix"
            );
        }
    }

    #[test]
    fn foreign_ids_are_not_well_known() {
        assert!(!is_well_known(b"org.example.echo/1"));
        assert!(!is_well_known(b"echo"));
        assert!(!is_well_known(b"org.umc"));
        assert!(!is_well_known(b""));
    }

    #[test]
    fn oversize_well_known_ids_rejected() {
        let mut id = WELL_KNOWN_PREFIX.to_vec();
        id.extend_from_slice(&[b'x'; MAX_PROTOCOL_ID_LEN + 1]);
        assert!(!is_well_known(&id));
    }
}
