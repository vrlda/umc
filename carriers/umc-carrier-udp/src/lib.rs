//! UDP carrier profile (carriers/udp.md): one datagram = one UMP packet.
use std::sync::Arc;
use tokio::net::UdpSocket;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_types::runtime::Instant;

pub const CARRIER_TYPE: &str = "ump.udp/1";
pub const INITIAL_MTU: usize = 1_200;
pub const MAX_QUEUED_DATAGRAMS: usize = 256;
pub const MAX_QUEUED_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub struct UdpCarrier;

impl Carrier for UdpCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.to_string())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::Datagram,
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            connection_model: ConnectionModel::ConnectionlessAssociation,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: false,
            minimum_packet_size: 1,
            maximum_packet_size: INITIAL_MTU,
            scope_classes: vec!["general_network".into()],
        }
    }

    fn listen(&self, bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let socket = Arc::new(
            rt.block_on(UdpSocket::bind(&bind))
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::AddressInUse,
                    operation: "listen",
                    retryable: false,
                    message: e.to_string(),
                })?,
        );
        Ok(Box::new(UdpListenerAdapter { socket }))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "dial"))?;
        let socket =
            Arc::new(
                rt.block_on(UdpSocket::bind("0.0.0.0:0"))
                    .map_err(|e| CarrierError {
                        kind: CarrierErrorKind::Internal,
                        operation: "dial",
                        retryable: true,
                        message: e.to_string(),
                    })?,
            );
        rt.block_on(socket.connect(&remote))
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::Unreachable,
                operation: "dial",
                retryable: true,
                message: e.to_string(),
            })?;
        Ok(Box::new(UdpLink {
            socket,
            remote: remote.clone(),
        }))
    }
}

#[derive(Debug)]
pub struct UdpListenerAdapter {
    socket: Arc<UdpSocket>,
}

impl Listener for UdpListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        // Connectionless: first datagram establishes the association.
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "accept"))?;
        let socket = self.socket.clone();
        let remote = rt.block_on(async move {
            let mut buf = [0u8; INITIAL_MTU];
            let (_n, addr) = socket.recv_from(&mut buf).await.map_err(|e| CarrierError {
                kind: CarrierErrorKind::Internal,
                operation: "accept",
                retryable: true,
                message: e.to_string(),
            })?;
            Ok::<_, CarrierError>(addr.to_string())
        })?;
        Ok(Box::new(UdpLink {
            socket: self.socket.clone(),
            remote,
        }))
    }

    fn close(&self) -> Result<(), CarrierError> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct UdpLink {
    socket: Arc<UdpSocket>,
    remote: String,
}

impl UdpLink {
    #[must_use]
    pub fn remote(&self) -> &str {
        &self.remote
    }

    #[must_use]
    pub fn socket_local_addr(&self) -> String {
        self.socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn from_parts(socket: Arc<UdpSocket>, remote: String) -> Self {
        Self { socket, remote }
    }
}

impl Link for UdpLink {
    fn properties(&self) -> LinkProperties {
        LinkProperties {
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            current_mtu: INITIAL_MTU,
            queue_bytes: 0,
            queue_capacity: MAX_QUEUED_BYTES,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        if packet.bytes.len() > INITIAL_MTU {
            return Err(CarrierError::new(CarrierErrorKind::PacketTooLarge, "send"));
        }
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "send"))?;
        let socket = self.socket.clone();
        let remote = self.remote.clone();
        rt.block_on(async move {
            let n = socket
                .send_to(&packet.bytes, &remote)
                .await
                .map_err(|e| CarrierError {
                    kind: CarrierErrorKind::Internal,
                    operation: "send",
                    retryable: true,
                    message: e.to_string(),
                })?;
            if n != packet.bytes.len() {
                return Err(CarrierError::new(CarrierErrorKind::Internal, "send"));
            }
            Ok(SendResult::Accepted {
                queue_state: QueueState::SentToMedium,
            })
        })
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "recv"))?;
        let socket = self.socket.clone();
        let remote = self.remote.clone();
        let bytes = rt.block_on(async move {
            let mut buf = [0u8; INITIAL_MTU];
            loop {
                let (n, addr) = socket.recv_from(&mut buf).await.map_err(|e| CarrierError {
                    kind: CarrierErrorKind::Internal,
                    operation: "recv",
                    retryable: true,
                    message: e.to_string(),
                })?;
                if addr.to_string() == remote {
                    return Ok(buf[..n].to_vec());
                }
            }
        })?;
        Ok(InboundPacket {
            bytes,
            received_at: Instant(0),
        })
    }

    fn events(&self) -> Result<LinkEvent, CarrierError> {
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "events"))
    }

    fn close(&self, _reason: &str) -> Result<(), CarrierError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_match_profile() {
        let c = UdpCarrier;
        assert_eq!(c.type_id().0, "ump.udp/1");
        assert_eq!(c.capabilities().packet_mode, PacketMode::Datagram);
        assert_eq!(c.capabilities().maximum_packet_size, 1_200);
    }

    #[test]
    fn datagram_round_trip_between_two_links() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.handle().enter();
        let server_socket = Arc::new(rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let server_addr = server_socket.local_addr().unwrap().to_string();
        let client_socket = Arc::new(rt.block_on(UdpSocket::bind("127.0.0.1:0")).unwrap());
        let client_addr = client_socket.local_addr().unwrap().to_string();
        let client = UdpLink {
            socket: client_socket,
            remote: server_addr.clone(),
        };
        let server_link = UdpLink {
            socket: server_socket.clone(),
            remote: client_addr,
        };

        client
            .send(OutboundPacket {
                bytes: b"ping".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let pkt = server_link.recv().unwrap();
        assert_eq!(pkt.bytes, b"ping");

        server_link
            .send(OutboundPacket {
                bytes: b"pong".to_vec(),
                control: false,
                deadline_ms: None,
            })
            .unwrap();
        let reply = client.recv().unwrap();
        assert_eq!(reply.bytes, b"pong");
    }
}
