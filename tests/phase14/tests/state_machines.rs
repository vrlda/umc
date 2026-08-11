//! Phase-14 conformance state-machine checks (testing.md §7).

use umc_handshake::state::{HandshakeEvent, HandshakeMachine, HandshakeState};
use umc_relay::circuit::{Circuit, CircuitState};
use umc_relay::close::{close_circuit, drain_circuit, RelayReason, DRAIN_PERIOD_MS};
use umc_types::runtime::{Duration, Instant};

#[test]
fn handshake_machine_reaches_confirmed_only_after_peer_evidence() {
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
        machine.apply(event).expect("valid client transition");
        assert!(!machine.may_install_application_keys());
    }
    machine
        .apply(HandshakeEvent::Confirm)
        .expect("confirmation transition");
    assert_eq!(machine.state, HandshakeState::Confirmed);
    assert!(machine.peer_authenticated);
    assert!(machine.may_install_application_keys());
    assert_eq!(
        machine.apply(HandshakeEvent::ReceiveClientAuth),
        Err(umc_handshake::state::StateError::InvalidTransition)
    );
}

#[test]
fn relay_circuit_reaches_closed_through_bounded_drain() {
    let now = Instant(0);
    let mut circuit = Circuit::new(1, now, 600_000, 100, true, false);
    circuit.accept(now);
    close_circuit(&mut circuit, RelayReason::NoError, now, None);
    assert_eq!(circuit.state, CircuitState::Closing);
    drain_circuit(&mut circuit, now + Duration::from_millis(DRAIN_PERIOD_MS));
    assert_eq!(circuit.state, CircuitState::Draining);
    drain_circuit(
        &mut circuit,
        now + Duration::from_millis(2 * DRAIN_PERIOD_MS),
    );
    assert_eq!(circuit.state, CircuitState::Closed);
}
