//! `RELAY_DATA` forwarding (relay.md §16-18): opaque bytes, sequence tracking,
//! no inner inspection.
use crate::circuit::{Circuit, QuotaError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    UnknownCircuit,
    Closed,
    SequenceConflict,
    DuplicateDiscarded,
    PayloadTooLarge,
    Quota(QuotaError),
    EmptyData,
    FinalSequenceExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardResult {
    pub circuit_id: u64,
    pub sequence: u64,
    pub data: Vec<u8>,
    pub fin: bool,
    pub downstream: Option<Vec<u8>>,
}

/// Accept one `RELAY_DATA` from the upstream peer.
/// Returns the opaque bytes to forward downstream (relay.md §16).
///
/// # Errors
///
/// Returns `ForwardError` for oversized or empty payloads, traffic on closed
/// circuits, replayed sequences, and quota exhaustion.
pub fn accept_upstream_data(
    circuit: &mut Circuit,
    sequence: u64,
    fin: bool,
    data: &[u8],
    max_payload: usize,
) -> Result<ForwardResult, ForwardError> {
    if data.len() > max_payload {
        return Err(ForwardError::PayloadTooLarge);
    }
    if data.is_empty() && !fin {
        return Err(ForwardError::EmptyData);
    }
    if circuit.state == crate::circuit::CircuitState::Closed
        || circuit.state == crate::circuit::CircuitState::Draining
    {
        return Err(ForwardError::Closed);
    }
    match sequence.cmp(&circuit.next_relay_sequence) {
        std::cmp::Ordering::Equal => {
            circuit.next_relay_sequence += 1;
        }
        std::cmp::Ordering::Less => {
            // An exact duplicate (same sequence, identical bytes) is discarded
            // (relay.md §17); different bytes at a replayed sequence conflict.
            if circuit.last_accepted_data.as_deref() == Some(data) {
                return Err(ForwardError::DuplicateDiscarded);
            }
            return Err(ForwardError::SequenceConflict);
        }
        std::cmp::Ordering::Greater => {
            // Gaps do not close the circuit (relay.md §17); the inner session recovers.
            circuit.next_relay_sequence = sequence + 1;
        }
    }
    circuit
        .charge(data.len() as u64)
        .map_err(ForwardError::Quota)?;
    circuit.last_accepted_data = Some(data.to_vec());
    let downstream = circuit.downstream.clone();
    Ok(ForwardResult {
        circuit_id: circuit.circuit_id,
        sequence,
        data: data.to_vec(),
        fin,
        downstream,
    })
}

/// Handle a downstream FIN: half-close tracking (relay.md §22).
///
/// # Errors
///
/// Returns `ForwardError::FinalSequenceExceeded` when the same direction is
/// closed twice.
pub fn apply_fin(circuit: &mut Circuit, from_upstream: bool) -> Result<(), ForwardError> {
    if from_upstream {
        if circuit.state == crate::circuit::CircuitState::HalfClosedUpstream {
            return Err(ForwardError::FinalSequenceExceeded);
        }
        if circuit.state == crate::circuit::CircuitState::Active {
            circuit.state = crate::circuit::CircuitState::HalfClosedUpstream;
        }
    } else if circuit.state == crate::circuit::CircuitState::HalfClosedDownstream {
        return Err(ForwardError::FinalSequenceExceeded);
    } else if circuit.state == crate::circuit::CircuitState::Active {
        circuit.state = crate::circuit::CircuitState::HalfClosedDownstream;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::Instant;

    fn circuit(id: u64) -> Circuit {
        Circuit::new(id, Instant(0), 600_000, 1_048_576, true, false)
    }

    #[test]
    fn forward_preserves_opacity() {
        let mut c = circuit(1);
        c.downstream = Some(b"peer-b".to_vec());
        c.accept(Instant(0));
        let result =
            accept_upstream_data(&mut c, 0, false, b"inner-ump-packet", 64 * 1024).unwrap();
        assert_eq!(result.data, b"inner-ump-packet");
        assert_eq!(result.downstream.as_deref(), Some(b"peer-b".as_slice()));
        assert_eq!(result.sequence, 0);
    }

    #[test]
    fn sequence_conflict_detected() {
        let mut c = circuit(2);
        c.accept(Instant(0));
        accept_upstream_data(&mut c, 0, false, b"a", 64 * 1024).unwrap();
        // Exact duplicate (same sequence, identical bytes) is discarded, not an error.
        assert_eq!(
            accept_upstream_data(&mut c, 0, false, b"a", 64 * 1024),
            Err(ForwardError::DuplicateDiscarded)
        );
        // Different bytes at a replayed sequence close the circuit.
        assert_eq!(
            accept_upstream_data(&mut c, 0, false, b"b", 64 * 1024),
            Err(ForwardError::SequenceConflict)
        );
    }

    #[test]
    fn sequence_gaps_do_not_close() {
        let mut c = circuit(3);
        c.accept(Instant(0));
        // Gap: jump from 0 to 5.
        accept_upstream_data(&mut c, 5, false, b"x", 64 * 1024).unwrap();
        assert_eq!(c.next_relay_sequence, 6);
    }

    #[test]
    fn empty_data_requires_fin() {
        let mut c = circuit(4);
        c.accept(Instant(0));
        assert_eq!(
            accept_upstream_data(&mut c, 0, false, b"", 64 * 1024),
            Err(ForwardError::EmptyData)
        );
        assert!(accept_upstream_data(&mut c, 0, true, b"", 64 * 1024).is_ok());
    }

    #[test]
    fn fin_half_closes() {
        let mut c = circuit(5);
        c.accept(Instant(0));
        apply_fin(&mut c, true).unwrap();
        assert_eq!(c.state, crate::circuit::CircuitState::HalfClosedUpstream);
        assert_eq!(
            apply_fin(&mut c, true),
            Err(ForwardError::FinalSequenceExceeded)
        );
    }

    #[test]
    fn quota_charges_forwarded_bytes() {
        let mut c = Circuit::new(6, Instant(0), 600_000, 10, true, false);
        c.accept(Instant(0));
        accept_upstream_data(&mut c, 0, false, b"0123456789", 64 * 1024).unwrap();
        assert_eq!(
            accept_upstream_data(&mut c, 1, false, b"x", 64 * 1024),
            Err(ForwardError::Quota(QuotaError::Exhausted))
        );
    }

    #[test]
    fn per_direction_sequences_advance_independently() {
        let mut c = Circuit::new(7, Instant(0), 600_000, 1_048_576, true, false);
        c.accept(Instant(0));
        // Sending N times advances only the sent counter.
        assert_eq!(c.allocate_sequence(), 0);
        assert_eq!(c.allocate_sequence(), 1);
        assert_eq!(c.peer_next_relay_sequence, 2);
        assert_eq!(
            c.next_relay_sequence, 0,
            "sending never moves the seen counter"
        );
        // Receiving advances only the seen counter.
        accept_upstream_data(&mut c, 0, false, b"a", 64 * 1024).unwrap();
        assert_eq!(c.next_relay_sequence, 1);
        assert_eq!(
            c.peer_next_relay_sequence, 2,
            "receiving never moves the sent counter"
        );
        // A receive may not clobber the sent counter even across a gap.
        accept_upstream_data(&mut c, 7, false, b"b", 64 * 1024).unwrap();
        assert_eq!(c.next_relay_sequence, 8);
        assert_eq!(c.peer_next_relay_sequence, 2);
    }
}
