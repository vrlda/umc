//! Single-relay circuit: originator opens a circuit, relay grants bounded
//! quota, opaque bytes flow, quota exhaustion closes the circuit.
use umc_relay::admission::{evaluate_open, AdmissionDecision, AdmissionLimits, RelayPolicy};
use umc_relay::circuit::{Circuit, CircuitState, QuotaError};
use umc_relay::close::{close_circuit, RelayReason};
use umc_relay::forward::{accept_upstream_data, ForwardError};
use umc_types::runtime::Instant;

#[test]
fn single_relay_circuit_flow() {
    let now = Instant(0);
    let limits = AdmissionLimits {
        policy: RelayPolicy::Community,
        ..AdmissionLimits::default()
    };

    // Open.
    let decision = evaluate_open(&limits, 0, 600_000, 1_048_576, 0x01);
    let (lifetime, quota, payload) = match decision {
        AdmissionDecision::Accepted {
            granted_lifetime_ms,
            granted_byte_quota,
            maximum_relay_payload,
        } => (
            granted_lifetime_ms,
            granted_byte_quota,
            maximum_relay_payload,
        ),
        other => panic!("expected accepted, got {other:?}"),
    };

    // Circuit created and accepted.
    let mut circuit = Circuit::new(7, now, lifetime, quota, true, false);
    circuit.downstream = Some(b"destination".to_vec());
    circuit.accept(now);

    // Opaque traffic flows.
    let first = accept_upstream_data(&mut circuit, 0, false, b"inner-packet-1", payload).unwrap();
    assert_eq!(first.downstream.as_deref(), Some(b"destination".as_slice()));
    assert_eq!(first.sequence, 0);

    // Quota is bounded: fill the rest with max-payload frames, ending exactly
    // at the granted quota (admission caps the grant at max_byte_quota).
    let mut remaining = quota - b"inner-packet-1".len() as u64;
    let mut sequence = 1u64;
    while remaining > 0 {
        let frame = remaining.min(payload as u64);
        let data = vec![0u8; usize::try_from(frame).unwrap()];
        accept_upstream_data(&mut circuit, sequence, false, &data, payload).unwrap();
        remaining -= frame;
        sequence += 1;
    }
    assert_eq!(
        accept_upstream_data(&mut circuit, sequence, false, b"x", payload).unwrap_err(),
        ForwardError::Quota(QuotaError::Exhausted)
    );

    // Close with reason.
    close_circuit(&mut circuit, RelayReason::QuotaExhausted, now, Some(1));
    assert_eq!(circuit.state, CircuitState::Closing);
}

#[test]
fn disabled_relay_refuses() {
    let limits = AdmissionLimits::default();
    assert_eq!(
        evaluate_open(&limits, 0, 600_000, 0, 0),
        AdmissionDecision::Refused
    );
}

#[test]
fn malformed_relay_data_rejected() {
    let now = Instant(0);
    let mut circuit = Circuit::new(1, now, 600_000, 1_048_576, true, false);
    circuit.accept(now);
    // Payload over grant.
    let oversized = vec![0u8; 65_537];
    assert_eq!(
        accept_upstream_data(&mut circuit, 0, false, &oversized, 64 * 1024).unwrap_err(),
        ForwardError::PayloadTooLarge
    );
    // Empty data without FIN is rejected.
    assert_eq!(
        accept_upstream_data(&mut circuit, 0, false, &[], 64 * 1024).unwrap_err(),
        ForwardError::EmptyData
    );
}
