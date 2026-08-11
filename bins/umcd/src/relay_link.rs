//! Carrier-link adapter for an authenticated relay circuit.

use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex};

use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    InboundPacket, LinkEvent, LinkProperties, Ordering, OutboundPacket, QueueState, Reliability,
    SendResult,
};
use umc_carrier::Link;
use umc_wire::frames::relay::{RelayCloseFrame, RelayDataFrame, RelayOpenFrame};

use crate::session_bus::SessionBus;

const MAX_RELAY_LINK_QUEUE: usize = 16;

/// One side of an endpoint-to-endpoint session carried inside `RELAY_DATA`.
/// The adapter deliberately exposes only packet boundaries; the relay never
/// receives or interprets the inner protected packets.
pub struct RelayLink {
    bus: Arc<Mutex<SessionBus>>,
    relay_peer: Vec<u8>,
    circuit_id: u64,
    destination_hint: Vec<u8>,
    incoming: Mutex<Receiver<Vec<u8>>>,
    next_sequence: Mutex<u64>,
    opened: AtomicBool,
}

impl std::fmt::Debug for RelayLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayLink")
            .field("relay_peer", &self.relay_peer)
            .field("circuit_id", &self.circuit_id)
            .field("destination_hint", &self.destination_hint)
            .field("opened", &self.opened.load(AtomicOrdering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RelayLink {
    /// Build an origin-side adapter. The first `send` emits `RELAY_OPEN`
    /// before the first opaque packet; later sends emit only `RELAY_DATA`.
    pub fn origin(
        bus: Arc<Mutex<SessionBus>>,
        relay_peer: Vec<u8>,
        circuit_id: u64,
        destination_hint: Vec<u8>,
    ) -> (Self, SyncSender<Vec<u8>>) {
        Self::new(bus, relay_peer, circuit_id, destination_hint, false)
    }

    pub fn from_incoming(
        bus: Arc<Mutex<SessionBus>>,
        relay_peer: Vec<u8>,
        circuit_id: u64,
        incoming: Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            bus,
            relay_peer,
            circuit_id,
            destination_hint: Vec::new(),
            incoming: Mutex::new(incoming),
            next_sequence: Mutex::new(0),
            opened: AtomicBool::new(true),
        }
    }

    fn new(
        bus: Arc<Mutex<SessionBus>>,
        relay_peer: Vec<u8>,
        circuit_id: u64,
        destination_hint: Vec<u8>,
        opened: bool,
    ) -> (Self, SyncSender<Vec<u8>>) {
        let (incoming_tx, incoming_rx) = std::sync::mpsc::sync_channel(MAX_RELAY_LINK_QUEUE);
        (
            Self {
                bus,
                relay_peer,
                circuit_id,
                destination_hint,
                incoming: Mutex::new(incoming_rx),
                next_sequence: Mutex::new(0),
                opened: AtomicBool::new(opened),
            },
            incoming_tx,
        )
    }

    fn inject(&self, bytes: Vec<u8>) -> Result<(), CarrierError> {
        self.bus
            .lock()
            .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "relay bus"))?
            .inject_outbound(&self.relay_peer, bytes)
            .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "relay bus"))
    }

    fn encode_open(&self) -> Result<Vec<u8>, CarrierError> {
        RelayOpenFrame {
            circuit_id: self.circuit_id,
            bidirectional: true,
            store_forward_allowed: false,
            private_circuit: true,
            multipath_allowed: false,
            requested_lifetime: 10 * 60 * 1_000,
            requested_byte_quota: 64 * 1024 * 1024,
            next_hop_hint: self.destination_hint.clone(),
            authorization: Vec::new(),
        }
        .encode()
        .map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "relay open"))
    }
}

impl Link for RelayLink {
    fn properties(&self) -> LinkProperties {
        LinkProperties {
            reliability: Reliability::ReliableUntilLinkFailure,
            ordering: Ordering::Ordered,
            current_mtu: umc_types::version::MAX_PACKET_SIZE,
            queue_bytes: 0,
            queue_capacity: MAX_RELAY_LINK_QUEUE * umc_types::version::MAX_PACKET_SIZE,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        if !self.opened.swap(true, AtomicOrdering::AcqRel) {
            self.inject(self.encode_open()?)?;
        }
        let mut sequence = self
            .next_sequence
            .lock()
            .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "sequence"))?;
        let frame = RelayDataFrame {
            circuit_id: self.circuit_id,
            relay_sequence: *sequence,
            fin: false,
            ack_requested: packet.control,
            high_priority: packet.control,
            data: packet.bytes,
        };
        *sequence = sequence.saturating_add(1);
        let encoded = frame
            .encode()
            .map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "relay data"))?;
        self.inject(encoded)?;
        Ok(SendResult::Accepted {
            queue_state: QueueState::SentToMedium,
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let receiver = self
            .incoming
            .lock()
            .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "incoming poisoned"))?;
        match receiver.try_recv() {
            Ok(bytes) => Ok(InboundPacket {
                bytes,
                received_at: umc_types::runtime::Instant(0),
            }),
            Err(TryRecvError::Empty) => Err(CarrierError::new(
                CarrierErrorKind::WouldBlock,
                "relay link",
            )),
            Err(TryRecvError::Disconnected) => Err(CarrierError::new(
                CarrierErrorKind::LinkClosed,
                "relay link",
            )),
        }
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        Err(CarrierError::new(
            CarrierErrorKind::WouldBlock,
            "relay link",
        ))
    }

    fn close(&self, reason: &str) -> Result<(), CarrierError> {
        let frame = RelayCloseFrame {
            circuit_id: self.circuit_id,
            reason_code: 0,
            final_relay_sequence: self
                .next_sequence
                .lock()
                .map_err(|_| CarrierError::new(CarrierErrorKind::LinkFailed, "sequence"))?
                .saturating_sub(1),
        };
        let _ = reason;
        self.inject(
            frame
                .encode()
                .map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "relay close"))?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn origin_emits_open_then_opaque_data() {
        let mut bus = SessionBus::new();
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel();
        bus.register(b"relay".to_vec(), 7, in_tx, out_tx);
        let bus = Arc::new(Mutex::new(bus));
        let (link, _incoming) =
            RelayLink::origin(bus, b"relay".to_vec(), 41, b"destination".to_vec());

        link.send(OutboundPacket {
            bytes: b"opaque-initial".to_vec(),
            control: true,
            deadline_ms: Some(3_000),
        })
        .expect("relay send");

        let open = out_rx.try_recv().expect("relay open");
        let data = out_rx.try_recv().expect("relay data");
        let (_, open_len) = umc_wire::varint::decode(&open).expect("open type");
        let (_, data_len) = umc_wire::varint::decode(&data).expect("data type");
        let (decoded_open, _) = RelayOpenFrame::decode(&open[open_len..]).expect("decode open");
        let (decoded_data, _) = RelayDataFrame::decode(&data[data_len..]).expect("decode data");
        assert_eq!(decoded_open.circuit_id, 41);
        assert_eq!(decoded_open.next_hop_hint, b"destination");
        assert_eq!(decoded_data.circuit_id, 41);
        assert_eq!(decoded_data.relay_sequence, 0);
        assert_eq!(decoded_data.data, b"opaque-initial");
    }
}
