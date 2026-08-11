//! LAN discovery carrier (carriers/lan-discovery.md): announcements and
//! candidate exchange only. Never carries UMP data packets.
//!
//! Announcement format (carriers/lan-discovery.md §4.10; decision in
//! discovery.md open decision #5): a single version byte (0x01), followed by
//! a varint payload length, followed by the opaque node hint. The varint is
//! width-tagged in the top two bits of the first byte (1/2/4/8-byte payload
//! widths), mirroring umc-wire framing without depending on it.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, Ordering, PacketMode, Reliability,
};
use umc_carrier::{BoxLink, Carrier, Listener};

pub const CARRIER_TYPE: &str = "ump.lan-discovery/1";
pub const DEFAULT_ANNOUNCE_GROUP: &str = "224.0.0.251";
pub const DEFAULT_ANNOUNCE_PORT: u16 = 53_555;
pub const MAX_ANNOUNCEMENT: usize = 1_024;
pub const DEFAULT_ANNOUNCE_INTERVAL_MS: u64 = 5_000;
pub const MAX_RESPONSES_PER_MINUTE: u32 = 20;

#[derive(Debug, Clone)]
pub struct LanDiscoveryConfig {
    pub group: SocketAddr,
    pub interface: Option<String>,
    pub announce_interval_ms: u64,
    pub node_hint: Vec<u8>,
}

impl Default for LanDiscoveryConfig {
    fn default() -> Self {
        Self {
            group: SocketAddr::new(Ipv4Addr::new(224, 0, 0, 251).into(), DEFAULT_ANNOUNCE_PORT),
            interface: None,
            announce_interval_ms: DEFAULT_ANNOUNCE_INTERVAL_MS,
            node_hint: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct LanDiscoveryCarrier {
    pub config: LanDiscoveryConfig,
}

impl Carrier for LanDiscoveryCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(CARRIER_TYPE.to_string())
    }

    fn capabilities(&self) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: self.type_id(),
            packet_mode: PacketMode::Message,
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            connection_model: ConnectionModel::SharedChannel,
            supports_listen: true,
            supports_dial: true,
            supports_discovery: true,
            minimum_packet_size: 1,
            maximum_packet_size: MAX_ANNOUNCEMENT,
            scope_classes: vec!["link_local".into(), "local_network".into()],
        }
    }

    fn listen(&self, _bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| CarrierError::new(CarrierErrorKind::NotRunning, "listen"))?;
        let socket = Arc::new(
            rt.block_on(UdpSocket::bind(format!(
                "0.0.0.0:{}",
                self.config.group.port()
            )))
            .map_err(|e| CarrierError {
                kind: CarrierErrorKind::AddressInUse,
                operation: "listen",
                retryable: false,
                message: e.to_string(),
            })?,
        );
        if let std::net::IpAddr::V4(multicast) = self.config.group.ip() {
            socket
                .join_multicast_v4(multicast, Ipv4Addr::UNSPECIFIED)
                .ok();
        }
        Ok(Box::new(LanListenerAdapter {
            socket,
            responses_per_minute: Arc::new(Mutex::new(0u32)),
        }))
    }

    fn dial(&self, _remote: String) -> Result<BoxLink, CarrierError> {
        // LAN discovery is discovery-only; there is nothing to dial for data.
        Err(CarrierError::new(CarrierErrorKind::Unsupported, "dial"))
    }
}

#[derive(Debug)]
#[allow(dead_code)] // fields reserved for the Phase 6 discovery loop wiring
pub struct LanListenerAdapter {
    socket: Arc<UdpSocket>,
    responses_per_minute: Arc<Mutex<u32>>,
}

impl Listener for LanListenerAdapter {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        // Phase 5: the listener is a discovery sink, not a link source.
        Err(CarrierError::new(CarrierErrorKind::Unsupported, "accept"))
    }

    fn close(&self) -> Result<(), CarrierError> {
        Ok(())
    }
}

/// Announcement format (carriers/lan-discovery.md §4.10):
/// version byte | payload length varint | opaque node hint.
///
/// # Errors
///
/// Returns `PacketTooLarge` when the node hint exceeds the announcement bound.
pub fn build_announcement(config: &LanDiscoveryConfig) -> Result<Vec<u8>, CarrierError> {
    if config.node_hint.len() > MAX_ANNOUNCEMENT - 3 {
        return Err(CarrierError::new(
            CarrierErrorKind::PacketTooLarge,
            "announce",
        ));
    }
    let mut out = Vec::with_capacity(config.node_hint.len() + 3);
    out.push(1u8); // version
    umc_framing::push_varint(&mut out, config.node_hint.len() as u64);
    out.extend_from_slice(&config.node_hint);
    Ok(out)
}

/// Decode an announcement back to its node hint.
///
/// # Errors
///
/// Returns `PacketTooLarge` for oversized input and `ProtocolError` for an
/// unknown version, malformed varint, or length/payload mismatch.
#[allow(clippy::cast_possible_truncation)] // len is bounded by MAX_ANNOUNCEMENT
pub fn parse_announcement(bytes: &[u8]) -> Result<Vec<u8>, CarrierError> {
    if bytes.len() > MAX_ANNOUNCEMENT {
        return Err(CarrierError::new(
            CarrierErrorKind::PacketTooLarge,
            "announce",
        ));
    }
    if bytes.first() != Some(&1) {
        return Err(CarrierError::new(
            CarrierErrorKind::ProtocolError,
            "announce",
        ));
    }
    let (len, used) = umc_framing::read_varint(&bytes[1..])
        .map_err(|()| CarrierError::new(CarrierErrorKind::ProtocolError, "announce"))?;
    if 1 + used + len as usize != bytes.len() {
        return Err(CarrierError::new(
            CarrierErrorKind::ProtocolError,
            "announce",
        ));
    }
    Ok(bytes[1 + used..].to_vec())
}

/// Internal varint helpers (no umc-wire dependency for the carrier).
///
/// Width is encoded in the top two bits of the first byte: 00 = 1 byte
/// (6 payload bits), 01 = 2 bytes (14 bits), 10 = 4 bytes (30 bits),
/// 11 = 8 bytes (62 bits). Values are big-endian with the prefix bits
/// cleared, so the decoded integer is the wide word shifted right by
/// `(8 - width) * 8`.
mod umc_framing {
    #[allow(clippy::cast_possible_truncation)] // branch bounds make every cast lossless
    pub fn push_varint(out: &mut Vec<u8>, v: u64) {
        if v <= 63 {
            out.push(v as u8);
        } else if v <= 16_383 {
            out.push(0b0100_0000 | ((v >> 8) as u8));
            out.push(v as u8);
        } else {
            out.push(0b1000_0000 | ((v >> 24) as u8));
            out.extend_from_slice(&(v as u32).to_be_bytes());
        }
    }

    pub fn read_varint(buf: &[u8]) -> Result<(u64, usize), ()> {
        let first = *buf.first().ok_or(())?;
        let width = match first >> 6 {
            0 => 1usize,
            1 => 2usize,
            2 => 4usize,
            _ => 8usize,
        };
        if buf.len() < width {
            return Err(());
        }
        let mut raw = [0u8; 8];
        raw[..width].copy_from_slice(&buf[..width]);
        raw[0] &= 0x3F;
        Ok((u64::from_be_bytes(raw) >> ((8 - width) * 8), width))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcement_round_trip() {
        let config = LanDiscoveryConfig {
            node_hint: b"node-42".to_vec(),
            ..Default::default()
        };
        let ann = build_announcement(&config).unwrap();
        assert!(ann.len() <= MAX_ANNOUNCEMENT);
        let hint = parse_announcement(&ann).unwrap();
        assert_eq!(hint, b"node-42");
    }

    #[test]
    fn oversize_announcement_rejected() {
        let config = LanDiscoveryConfig {
            node_hint: vec![0u8; MAX_ANNOUNCEMENT],
            ..Default::default()
        };
        assert_eq!(
            build_announcement(&config),
            Err(CarrierError::new(
                CarrierErrorKind::PacketTooLarge,
                "announce"
            ))
        );
    }

    #[test]
    fn malformed_announcement_rejected() {
        assert!(parse_announcement(&[0x02, 0x00]).is_err());
        assert!(
            parse_announcement(&[0x01, 0x05, 0x61]).is_err(),
            "declared length exceeds payload"
        );
    }

    #[test]
    fn capabilities_declare_discovery_only() {
        let c = LanDiscoveryCarrier {
            config: LanDiscoveryConfig::default(),
        };
        assert_eq!(c.type_id().0, "ump.lan-discovery/1");
        assert!(c.capabilities().supports_discovery);
        assert_eq!(
            c.capabilities().connection_model,
            ConnectionModel::SharedChannel
        );
    }
}
