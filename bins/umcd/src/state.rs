//! Runtime state (core.md §8): the daemon's shared mutable runtime context,
//! built once at startup and shared (behind an `Arc`) with the control
//! socket and carrier tasks.
use crate::config::NodeConfig;
use crate::runtime_adapters::{OsClock, OsEntropy, TokioAdaptor};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;
use umc_carrier::Listener;
use umc_core::block::Blocklist;
use umc_core::mesh::MeshConfig;
use umc_core::node::{Node, NodeConfig as NodeRuntimeConfig, NodeIdentity};
use umc_core::rate_limiter::RateLimiter;
use umc_core::trust::{TrustLevel, TrustStore};
use umc_storage::sqlite::SqliteStore;
use umc_types::runtime::{Clock, Instant};

/// The daemon's shared runtime context.
pub struct RuntimeState {
    pub config: NodeConfig,
    /// Monotonic startup timestamp.
    pub started_at: Instant,
    /// Resolved control socket path.
    pub control_socket: PathBuf,
    /// Node database (namespaces: config, trust, records).
    pub store: Arc<SqliteStore>,
    /// Default trust level for unseen endpoints. Placeholder: trust queries
    /// wire into session admission in Task 20+.
    #[allow(dead_code)]
    pub trust_default_level: TrustLevel,
    /// Endpoint blocklist. Placeholder: wired into admission paths in Task 20+.
    #[allow(dead_code)]
    pub blocklist: Blocklist,
    /// Per-peer rate limiter. Placeholder: wired into admission paths in
    /// Task 20+.
    #[allow(dead_code)]
    pub rate_limiter: RateLimiter,
    /// Node identity. Placeholder: loaded from the keystore once keystore
    /// loading lands; a fresh identity is generated per process for now.
    pub node_identity: NodeIdentity,
    /// Operating mode profile (local mesh vs endpoint).
    pub mesh: MeshConfig,
    /// The runtime node: registered carriers, sessions (core.md §8).
    pub node: Node,
    /// Bound carrier listeners; held here so the sockets stay alive.
    pub listeners: Vec<Box<dyn Listener + Send + Sync>>,
    /// Set when a graceful shutdown was requested.
    pub shutdown_requested: Arc<AtomicBool>,
    /// Released once shutdown completes; the main task waits on it.
    pub shutdown_channel: mpsc::Sender<()>,
}

impl std::fmt::Debug for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeState")
            .field("started_at", &self.started_at)
            .field("control_socket", &self.control_socket)
            .field("listeners", &self.listeners.len())
            .finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// Builds the runtime state: data dir + keystore dir, node database,
    /// identity, security primitives, and the shutdown channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the data or keystore directory cannot be
    /// created or the node database cannot be opened.
    pub fn new(config: NodeConfig, shutdown_channel: mpsc::Sender<()>) -> Result<Self, String> {
        let data_dir = config.resolved_data_dir();
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("data dir: {e}"))?;
        std::fs::create_dir_all(config.resolved_keystore_dir())
            .map_err(|e| format!("keystore dir: {e}"))?;
        let store = Arc::new(
            SqliteStore::open(&data_dir.join("node.db")).map_err(|e| format!("store: {e:?}"))?,
        );

        let node_identity = NodeIdentity::generate(&OsEntropy);
        // The runtime node and the state share the same key material.
        let state_identity = NodeIdentity {
            identity: node_identity.identity.clone(),
            static_handshake: node_identity.static_handshake.clone(),
        };
        let dcid = node_identity.endpoint_id()[..8].to_vec();
        let node = Node::new(
            NodeRuntimeConfig {
                identity: node_identity,
                dcid,
            },
            Arc::new(TokioAdaptor),
            Arc::new(TokioAdaptor),
        );
        let mesh = if config.mesh {
            MeshConfig::local_mesh()
        } else {
            MeshConfig::endpoint()
        };

        Ok(Self {
            control_socket: config.resolved_socket(),
            started_at: OsClock.now(),
            config,
            store,
            trust_default_level: TrustLevel::Unknown,
            blocklist: Blocklist::new(60),
            rate_limiter: RateLimiter::new(1_024),
            node_identity: state_identity,
            mesh,
            node,
            listeners: Vec::new(),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_channel,
        })
    }

    /// Trust store over the shared node database. Placeholder: wired into
    /// session admission in Task 20+.
    #[must_use]
    #[allow(dead_code)]
    pub fn trust_store(&self) -> TrustStore<'_> {
        TrustStore::new(self.store.as_ref(), self.trust_default_level)
    }
}
