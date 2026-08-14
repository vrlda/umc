//! Carrier plugin contract, supervision, and process-isolated IPC.
pub mod contract;
pub mod handshake;
pub mod loader;
pub mod manifest;
pub mod process;
pub mod proto;
pub mod registry;
pub mod runtime;
pub mod sandbox;
pub mod security;
pub mod shared_memory;
pub mod supervisor;
pub mod transport;
