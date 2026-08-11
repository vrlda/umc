use umc_types::runtime::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierTypeId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierInstanceId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketMode {
    Datagram,
    StreamFramed,
    Message,
    RawFramed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    Unreliable,
    ReliableUntilLinkFailure,
    ProfileDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordering {
    Unordered,
    Ordered,
    ProfileDefined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionModel {
    Connected,
    ConnectionlessAssociation,
    SharedChannel,
    Intermittent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierCapabilities {
    pub api_version: u64,
    pub carrier_type: CarrierTypeId,
    pub packet_mode: PacketMode,
    pub reliability: Reliability,
    pub ordering: Ordering,
    pub connection_model: ConnectionModel,
    pub supports_listen: bool,
    pub supports_dial: bool,
    pub supports_discovery: bool,
    pub minimum_packet_size: usize,
    pub maximum_packet_size: usize,
    pub scope_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    Active,
    Writable,
    MtuChanged { new_maximum: usize },
    QualityChanged,
    AddressRebound,
    Degraded,
    Closing,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkProperties {
    pub reliability: Reliability,
    pub ordering: Ordering,
    pub current_mtu: usize,
    pub queue_bytes: usize,
    pub queue_capacity: usize,
    pub estimated_rtt_ms: Option<u64>,
    pub estimated_loss: Option<u64>,
    pub metered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPacket {
    pub bytes: Vec<u8>,
    pub control: bool,
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundPacket {
    pub bytes: Vec<u8>,
    pub received_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendResult {
    Accepted { queue_state: QueueState },
    WouldBlock,
    QueueFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    SentToMedium,
    QueuedBounded,
}
