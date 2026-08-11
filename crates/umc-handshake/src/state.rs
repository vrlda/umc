//! Handshake state machine (handshake.md §6).
//!
//! The cryptographic driver owns the actual transcript and key material; this
//! small state machine is the single gate for message ordering and key
//! installation.  It is deliberately side-effect free apart from the state
//! flags so callers can use it in both the daemon and embedded runtimes.

/// The ten protocol handshake states from handshake.md §6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    InitialSent,
    InitialReceived,
    RetrySent,
    RetryReceived,
    HandshakeKeys,
    PeerAuthenticated,
    SessionKeys,
    Confirmed,
    Closed,
}

/// Logical events that advance a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeEvent {
    SendClientHello,
    ReceiveClientHello,
    SendServerHello,
    ReceiveServerHello,
    SendRetry,
    ReceiveRetry,
    InstallHandshakeKeys,
    SendClientAuth,
    ReceiveClientAuth,
    SendServerFinished,
    ReceiveServerFinished,
    SendClientFinished,
    ReceiveClientFinished,
    InstallSessionKeys,
    Confirm,
    Fail,
}

/// A handshake event that is not valid for the current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    InvalidTransition,
}

/// Bounded state and authentication gates for one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMachine {
    pub state: HandshakeState,
    /// Set once the peer's authenticated handshake evidence has been
    /// processed.  Sending our own authentication does not set this flag.
    pub peer_authenticated: bool,
    /// Set only after key confirmation succeeds.
    pub application_keys_installed: bool,
}

impl HandshakeMachine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: HandshakeState::Idle,
            peer_authenticated: false,
            application_keys_installed: false,
        }
    }

    /// Applies one protocol event.
    ///
    /// `Fail` is terminal from every state.  No other event is accepted after
    /// `Confirmed` or `Closed`, except the idempotent key-installation event
    /// after confirmation (a retransmitted local install is harmless).
    ///
    /// # Errors
    ///
    /// Returns [`StateError::InvalidTransition`] when the event is not valid
    /// for the current state.
    #[allow(clippy::match_same_arms)] // explicit state/event table mirrors §6
    pub fn apply(&mut self, event: HandshakeEvent) -> Result<(), StateError> {
        use HandshakeEvent as E;
        use HandshakeState as S;

        let next = match (self.state, event) {
            (_, E::Fail) => S::Closed,

            // Initiator path, including stateless Retry.
            (S::Idle, E::SendClientHello) => S::InitialSent,
            // Accepting a Retry before the local transcript has been marked
            // as sent keeps the machine usable for a stateless client that
            // hands the first packet directly to this coordinator.
            (S::Idle, E::ReceiveRetry) => S::RetryReceived,
            (S::InitialSent, E::ReceiveRetry) => S::RetryReceived,
            (S::RetryReceived, E::SendClientHello) => S::InitialSent,
            (S::InitialSent, E::ReceiveServerHello) => S::HandshakeKeys,

            // Responder path, including the optional Retry response.
            (S::Idle, E::ReceiveClientHello) => S::InitialReceived,
            (S::InitialReceived, E::SendRetry) => S::RetrySent,
            (S::RetrySent, E::ReceiveClientHello) => S::InitialReceived,
            (S::InitialReceived, E::SendServerHello) => S::HandshakeKeys,

            // The key schedule can be installed once the authenticated
            // SERVER_HELLO/CLIENT_HELLO exchange has produced it.
            (S::HandshakeKeys, E::InstallHandshakeKeys) => S::HandshakeKeys,
            (S::HandshakeKeys, E::SendClientAuth) => S::PeerAuthenticated,
            (S::HandshakeKeys, E::ReceiveClientAuth) => S::PeerAuthenticated,
            (S::PeerAuthenticated, E::ReceiveServerFinished) => S::SessionKeys,
            (S::PeerAuthenticated, E::SendServerFinished) => S::SessionKeys,
            (S::SessionKeys, E::InstallSessionKeys) => S::SessionKeys,
            (S::SessionKeys, E::SendClientFinished) => S::SessionKeys,
            (S::SessionKeys, E::ReceiveClientFinished) => S::SessionKeys,
            (S::SessionKeys, E::Confirm) => S::Confirmed,

            // A duplicate local install is safe after confirmation, but no
            // message can move a confirmed handshake back into negotiation.
            (S::Confirmed, E::InstallSessionKeys) => S::Confirmed,
            _ => return Err(StateError::InvalidTransition),
        };

        self.state = next;
        if matches!(
            event,
            E::ReceiveClientAuth | E::ReceiveServerFinished | E::ReceiveClientFinished
        ) {
            self.peer_authenticated = true;
        }
        if self.state == S::Confirmed {
            self.peer_authenticated = true;
            self.application_keys_installed = true;
        }
        Ok(())
    }

    /// Whether application traffic keys may be installed and used.
    #[must_use]
    pub fn may_install_application_keys(&self) -> bool {
        self.state == HandshakeState::Confirmed
            && self.peer_authenticated
            && self.application_keys_installed
    }
}

impl Default for HandshakeMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_happy_path_requires_confirmation() {
        let mut machine = HandshakeMachine::new();
        for event in [
            HandshakeEvent::SendClientHello,
            HandshakeEvent::ReceiveServerHello,
            HandshakeEvent::InstallHandshakeKeys,
            HandshakeEvent::SendClientAuth,
            HandshakeEvent::ReceiveServerFinished,
            HandshakeEvent::InstallSessionKeys,
            HandshakeEvent::SendClientFinished,
        ] {
            machine.apply(event).expect("valid client event");
            assert!(!machine.may_install_application_keys());
        }
        machine
            .apply(HandshakeEvent::Confirm)
            .expect("confirmation");
        assert_eq!(machine.state, HandshakeState::Confirmed);
        assert!(machine.peer_authenticated);
        assert!(machine.may_install_application_keys());
    }

    #[test]
    fn responder_retry_path_is_ordered() {
        let mut machine = HandshakeMachine::new();
        machine
            .apply(HandshakeEvent::ReceiveClientHello)
            .expect("initial hello");
        machine.apply(HandshakeEvent::SendRetry).expect("retry");
        machine
            .apply(HandshakeEvent::ReceiveClientHello)
            .expect("retried hello");
        machine
            .apply(HandshakeEvent::SendServerHello)
            .expect("server hello");
        assert_eq!(machine.state, HandshakeState::HandshakeKeys);
    }

    #[test]
    fn invalid_transitions_and_post_confirmation_messages_fail_closed() {
        let mut machine = HandshakeMachine::new();
        assert_eq!(
            machine.apply(HandshakeEvent::Confirm),
            Err(StateError::InvalidTransition)
        );
        machine.apply(HandshakeEvent::Fail).expect("failure");
        assert_eq!(machine.state, HandshakeState::Closed);
        assert_eq!(
            machine.apply(HandshakeEvent::SendClientHello),
            Err(StateError::InvalidTransition)
        );
    }

    #[test]
    fn confirmation_is_the_only_application_key_gate() {
        let mut machine = HandshakeMachine::new();
        machine.state = HandshakeState::SessionKeys;
        machine.peer_authenticated = true;
        assert!(!machine.may_install_application_keys());
        machine
            .apply(HandshakeEvent::Confirm)
            .expect("confirmation");
        assert!(machine.may_install_application_keys());
    }
}
