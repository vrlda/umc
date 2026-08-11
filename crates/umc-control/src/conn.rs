//! Control API connection state machine (control-api.md §6-8).
use crate::proto::umc::api::v1 as api;

pub const API_VERSION_MAJOR: u32 = 1;
pub const API_VERSION_MINOR: u32 = 0;
/// Gaps at or below this size are tolerated for diagnostics; larger gaps
/// indicate a desynchronized control stream.
pub const SEQUENCE_GAP_THRESHOLD: u64 = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    Connected,
    Negotiating,
    Authenticated,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    NotNegotiating,
    VersionMismatch,
    SequenceViolation,
    Closed,
}

/// Per-connection sequence tracking (control-api.md §7): starts at 1,
/// increases by one per envelope; zero/reuse/decrease and gaps above
/// [`SEQUENCE_GAP_THRESHOLD`] are violations.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    next_expected: u64,
}

impl SequenceTracker {
    #[must_use]
    pub const fn new() -> Self {
        Self { next_expected: 1 }
    }

    /// Record an observed sequence number.
    ///
    /// # Errors
    ///
    /// Returns [`ConnError::SequenceViolation`] for zero, reuse, decrease,
    /// or a gap above [`SEQUENCE_GAP_THRESHOLD`].
    pub fn observe(&mut self, sequence: u64) -> Result<(), ConnError> {
        if sequence == 0 || sequence < self.next_expected {
            return Err(ConnError::SequenceViolation);
        }
        if sequence > self.next_expected.saturating_add(SEQUENCE_GAP_THRESHOLD) {
            return Err(ConnError::SequenceViolation);
        }
        if sequence > self.next_expected {
            // Small gaps are tolerated for diagnostics.
            self.next_expected = sequence.saturating_add(1);
            return Ok(());
        }
        self.next_expected = sequence.saturating_add(1);
        Ok(())
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Connection {
    pub state: ConnState,
    pub sequences: SequenceTracker,
    pub principal_id: Option<u64>,
    pub negotiated_envelope_max: usize,
}

impl Connection {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: ConnState::Connected,
            sequences: SequenceTracker::new(),
            principal_id: None,
            negotiated_envelope_max: 4 * 1024 * 1024,
        }
    }

    /// Handle a `ClientHello` envelope. Returns the `ServerHello` on success.
    ///
    /// # Errors
    ///
    /// Returns [`ConnError::NotNegotiating`] when the connection is not in a
    /// negotiating state and [`ConnError::VersionMismatch`] when no supported
    /// major version matches.
    ///
    /// # Panics
    ///
    /// Panics if the negotiated envelope maximum exceeds `u32::MAX`.
    pub fn on_client_hello(
        &mut self,
        hello: &api::ClientHello,
    ) -> Result<api::ServerHello, ConnError> {
        if self.state != ConnState::Connected && self.state != ConnState::Negotiating {
            return Err(ConnError::NotNegotiating);
        }
        self.state = ConnState::Negotiating;
        let supported = &hello.supported_versions;
        let compatible = supported
            .iter()
            .find(|v| v.major == API_VERSION_MAJOR && v.minor == API_VERSION_MINOR);
        let selected = compatible.ok_or(ConnError::VersionMismatch)?;
        self.state = ConnState::Authenticated;
        self.principal_id = Some(0); // assigned by auth layer (Task 9)
        Ok(api::ServerHello {
            selected_version: Some(*selected),
            node_state: 0,
            connection_id: vec![0u8; 16],
            principal_id: self
                .principal_id
                .map(|p| p.to_be_bytes().to_vec())
                .unwrap_or_default(),
            negotiated_envelope_size: u32::try_from(self.negotiated_envelope_max)
                .expect("envelope max fits in u32"),
            ..Default::default()
        })
    }

    pub fn close(&mut self) {
        self.state = ConnState::Closed;
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(major: u32) -> api::ClientHello {
        hello_version(major, 0)
    }

    fn hello_version(major: u32, minor: u32) -> api::ClientHello {
        api::ClientHello {
            supported_versions: vec![api::ApiVersion { major, minor }],
            ..Default::default()
        }
    }

    #[test]
    fn version_negotiation_selects_matching_major() {
        let mut conn = Connection::new();
        let sh = conn.on_client_hello(&hello(1)).unwrap();
        assert_eq!(sh.selected_version.unwrap().major, API_VERSION_MAJOR);
        assert_eq!(conn.state, ConnState::Authenticated);
    }

    #[test]
    fn no_common_major_fails() {
        let mut conn = Connection::new();
        assert_eq!(
            conn.on_client_hello(&hello(2)),
            Err(ConnError::VersionMismatch)
        );
    }

    #[test]
    fn unsupported_minor_fails_exact_version_negotiation() {
        let mut conn = Connection::new();
        assert_eq!(
            conn.on_client_hello(&hello_version(1, 1)),
            Err(ConnError::VersionMismatch)
        );
    }

    #[test]
    fn hello_after_authenticated_fails() {
        let mut conn = Connection::new();
        conn.on_client_hello(&hello(1)).unwrap();
        assert_eq!(
            conn.on_client_hello(&hello(1)),
            Err(ConnError::NotNegotiating)
        );
    }

    #[test]
    fn sequences_are_monotonic() {
        let mut t = SequenceTracker::new();
        assert_eq!(t.observe(1), Ok(()));
        assert_eq!(t.observe(2), Ok(()));
        assert_eq!(t.observe(2), Err(ConnError::SequenceViolation));
        assert_eq!(t.observe(0), Err(ConnError::SequenceViolation));
        let mut gapped = SequenceTracker::new();
        assert_eq!(gapped.observe(1 + SEQUENCE_GAP_THRESHOLD), Ok(()));
        assert_eq!(
            gapped.observe(2 + SEQUENCE_GAP_THRESHOLD + SEQUENCE_GAP_THRESHOLD + 1),
            Err(ConnError::SequenceViolation)
        );
    }
}
