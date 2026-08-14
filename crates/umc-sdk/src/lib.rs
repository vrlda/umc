pub mod app;
pub mod backpressure;
pub mod client;
pub mod config;
#[cfg(any(unix, windows))]
pub mod daemon;
#[cfg(not(any(unix, windows)))]
#[path = "daemon_stub.rs"]
pub mod daemon;
pub mod discovery;
pub mod embedded;
mod embedded_transport;
pub mod error;
pub mod events;
pub mod handles;
pub mod policy;
pub mod status;

#[cfg(test)]
mod f7_surface_tests;

pub use app::{
    ApplicationRegistration, Datagram, Delegation, DelegationSummary, Endpoint, Listener,
    ServiceRegistry,
};
pub use app::{SDK_CHUNK_SIZE, SDK_MAX_CHUNK_SIZE, SDK_MAX_DATAGRAM_SIZE};
pub use backpressure::BoundedSendQueue;
pub use client::{Client, ClientError};
pub use discovery::{DiscoveryCandidate, ServiceHint};
pub use embedded::{EmbeddedConfig, EmbeddedStorageBackend};
pub use embedded_transport::{LoopbackCarrier, LoopbackCarrierConfig};
pub use error::SdkError;
pub use events::{DeliveryEvent, Event, EventFilter, PathEvent, SessionEvent};
pub use handles::{
    AppHandle, EndpointHandle, ListenerHandle, SessionHandle, StreamHandle, SubscriptionHandle,
};
pub use policy::{PathStrategy, Policy};
pub use umc_types::edition::CoreEdition;

/// Alias for the explicit in-process backend constructor on [`Client`].
pub type EmbeddedClient = Client;
