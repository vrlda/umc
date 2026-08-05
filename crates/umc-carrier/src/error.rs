#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierErrorKind {
    Cancelled,
    DeadlineExceeded,
    InvalidArgument,
    Unsupported,
    PolicyDenied,
    NotRunning,
    AddressInvalid,
    AddressInUse,
    Unreachable,
    AuthenticationFailed,
    PacketTooLarge,
    WouldBlock,
    QueueFull,
    LinkClosed,
    LinkFailed,
    DeviceUnavailable,
    PermissionDenied,
    ProtocolError,
    ResourceLimit,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierError {
    pub kind: CarrierErrorKind,
    pub operation: &'static str,
    pub retryable: bool,
    pub message: String,
}

impl CarrierError {
    #[must_use]
    pub fn new(kind: CarrierErrorKind, operation: &'static str) -> Self {
        Self {
            kind,
            operation,
            retryable: false,
            message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_construction() {
        let e = CarrierError::new(CarrierErrorKind::PacketTooLarge, "send");
        assert_eq!(e.kind, CarrierErrorKind::PacketTooLarge);
        assert_eq!(e.operation, "send");
    }
}
