pub mod error;
pub mod registry;
pub mod types;

use crate::types::{
    CarrierCapabilities, CarrierTypeId, InboundPacket, LinkEvent, LinkProperties, OutboundPacket,
    SendResult,
};
use umc_types::runtime::{Clock, EntropySource, Instant};

pub type BoxLink = Box<dyn Link + Send + Sync>;

pub trait Carrier: Send + Sync {
    fn type_id(&self) -> CarrierTypeId;
    fn capabilities(&self) -> CarrierCapabilities;

    /// Bind and accept incoming links on the given address.
    ///
    /// # Errors
    ///
    /// Returns `AddressInUse` when the bind address is taken, `Unsupported` when
    /// the carrier cannot listen, and `NotRunning` when the carrier is stopped.
    fn listen(&self, bind: String) -> Result<Box<dyn Listener + Send + Sync>, error::CarrierError>;

    /// Establish a link to the given remote address.
    ///
    /// # Errors
    ///
    /// Returns `AddressInvalid` for malformed addresses, `Unreachable` when no
    /// route exists, `AuthenticationFailed` on handshake rejection, and
    /// `NotRunning` when the carrier is stopped.
    fn dial(&self, remote: String) -> Result<BoxLink, error::CarrierError>;
}

pub trait Listener: Send + Sync {
    /// Accept the next incoming link.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` when no link is pending, `LinkFailed` when the
    /// accept handshake fails, and `LinkClosed` after the listener is closed.
    fn accept(&self) -> Result<BoxLink, error::CarrierError>;

    /// Stop accepting and release the bind address.
    ///
    /// # Errors
    ///
    /// Returns `NotRunning` when the listener is already closed.
    fn close(&self) -> Result<(), error::CarrierError>;
}

pub trait Link: Send + Sync {
    fn properties(&self) -> LinkProperties;

    /// Queue a packet for transmission.
    ///
    /// # Errors
    ///
    /// Returns `PacketTooLarge` when the packet exceeds the current MTU,
    /// `QueueFull` when the outbound queue is saturated, `WouldBlock` when the
    /// medium is not writable, and `LinkClosed` when the link is closing.
    fn send(&self, packet: OutboundPacket) -> Result<SendResult, error::CarrierError>;

    /// Receive the next inbound packet.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` when no packet is available and `LinkClosed` when
    /// the link has closed.
    fn recv(&self) -> Result<InboundPacket, error::CarrierError>;

    /// Poll the next link state event.
    ///
    /// # Errors
    ///
    /// Returns `WouldBlock` when no event is pending and `LinkFailed` when the
    /// link has failed.
    fn events(&self) -> Result<LinkEvent, error::CarrierError>;

    /// Close the link, flushing pending output when possible.
    ///
    /// # Errors
    ///
    /// Returns `LinkClosed` when the link is already closed.
    fn close(&self, reason: &str) -> Result<(), error::CarrierError>;
}

pub struct CarrierRuntime {
    pub clock: Box<dyn Clock>,
    pub entropy: Box<dyn EntropySource>,
}

impl std::fmt::Debug for CarrierRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CarrierRuntime").finish_non_exhaustive()
    }
}

impl CarrierRuntime {
    #[must_use]
    pub fn now(&self) -> Instant {
        self.clock.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopLink;

    impl Link for NoopLink {
        fn properties(&self) -> LinkProperties {
            LinkProperties {
                reliability: types::Reliability::ReliableUntilLinkFailure,
                ordering: types::Ordering::Ordered,
                current_mtu: 65_535,
                queue_bytes: 0,
                queue_capacity: 2 * 1024 * 1024,
                estimated_rtt_ms: None,
                estimated_loss: None,
                metered: false,
            }
        }
        fn send(&self, _p: OutboundPacket) -> Result<SendResult, error::CarrierError> {
            Ok(SendResult::Accepted {
                queue_state: types::QueueState::SentToMedium,
            })
        }
        fn recv(&self) -> Result<InboundPacket, error::CarrierError> {
            Err(error::CarrierError::new(
                error::CarrierErrorKind::WouldBlock,
                "recv",
            ))
        }
        fn events(&self) -> Result<LinkEvent, error::CarrierError> {
            Err(error::CarrierError::new(
                error::CarrierErrorKind::WouldBlock,
                "events",
            ))
        }
        fn close(&self, _r: &str) -> Result<(), error::CarrierError> {
            Ok(())
        }
    }

    #[test]
    fn link_trait_is_object_safe() {
        let l: BoxLink = Box::new(NoopLink);
        let props = l.properties();
        assert_eq!(props.current_mtu, 65_535);
    }
}
