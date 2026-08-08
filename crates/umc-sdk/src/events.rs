//! Delivery, path, and lifecycle events (sdk.md §19-20).

/// Transport ownership outcome for reliable stream bytes. None of these
/// variants is an application-level receipt from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryEvent {
    Acknowledged { stream_id: u64, offset: u64 },
    Lost { stream_id: u64, offset: u64 },
    Reset { stream_id: u64, error_code: u64 },
    Cancelled { stream_id: u64 },
}

impl DeliveryEvent {
    #[must_use]
    pub fn stream_id(&self) -> Option<u64> {
        match self {
            Self::Acknowledged { stream_id, .. }
            | Self::Lost { stream_id, .. }
            | Self::Reset { stream_id, .. }
            | Self::Cancelled { stream_id } => Some(*stream_id),
        }
    }

    #[must_use]
    pub const fn is_application_receipt(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEvent {
    Added { path_id: u64, carrier_type: String },
    Validated { path_id: u64 },
    Degraded { path_id: u64 },
    Failed { path_id: u64 },
    Retired { path_id: u64 },
    Migrated { old_path_id: u64, new_path_id: u64 },
    CarrierChanged { path_id: u64, carrier_type: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Active,
    Suspended,
    Closing { clean: bool },
    Closed { reason: String },
}
