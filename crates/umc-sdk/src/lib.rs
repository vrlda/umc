pub mod app;
pub mod backpressure;
pub mod client;
pub mod config;
#[cfg(any(unix, windows))]
pub mod daemon;
#[cfg(not(any(unix, windows)))]
#[path = "daemon_stub.rs"]
pub mod daemon;
pub mod embedded;
mod embedded_transport;
pub mod error;
pub mod events;
pub mod handles;
pub mod policy;
pub mod status;

#[cfg(test)]
mod f7_surface_tests;

pub use app::{Datagram, Endpoint, Listener, ServiceRegistry};
pub use backpressure::BoundedSendQueue;
pub use client::{Client, ClientError};
pub use embedded::EmbeddedConfig;
pub use embedded_transport::{LoopbackCarrier, LoopbackCarrierConfig};
pub use error::SdkError;
pub use events::{DeliveryEvent, Event, EventFilter, PathEvent, SessionEvent};
pub use handles::{
    AppHandle, EndpointHandle, ListenerHandle, SessionHandle, StreamHandle, SubscriptionHandle,
};
pub use policy::{PathStrategy, Policy};

/// Alias for the explicit in-process backend constructor on [`Client`].
pub type EmbeddedClient = Client;
