//! Runtime state (core.md §8): the daemon's shared mutable runtime context,
//! built once at startup and shared (behind an `Arc`) with the control
//! socket and carrier tasks.
use crate::bundle_service::BundleService;
use crate::config::NodeConfig;
use crate::discovery_service::DiscoveryService;
use crate::event_log::DaemonEvents;
use crate::relay_service::RelayService;
use crate::routing_service::RoutingService;
use crate::runtime_adapters::{OsClock, OsEntropy, TokioAdaptor};
use crate::session_bus::SessionBus;
use crate::session_manager::SessionManager;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use umc_carrier::Listener;
use umc_core::app::AppRegistry;
use umc_core::app_io::{AppRx, AppTx};
use umc_core::block::Blocklist;
use umc_core::mesh::MeshConfig;
use umc_core::node::{Node, NodeConfig as NodeRuntimeConfig, NodeIdentity};
use umc_core::rate_limiter::RateLimiter;
use umc_core::trust::{TrustLevel, TrustStore};
use umc_core::well_known::WELL_KNOWN_APP;
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_storage::keystore::{KeyClass, Keystore, KeystoreError};
use umc_storage::objects::ObjectStore;
use umc_storage::quota::{Profile, QuotaAccount};
use umc_storage::sqlite::SqliteStore;
use umc_types::runtime::{Clock, Instant};

/// Keystore file name inside the keystore directory (core.md §19).
pub(crate) const KEYSTORE_FILE: &str = "keystore.ks";
/// Record name for the node identity: one 64-byte record
/// `[identity_seed || static_seed]` under [`KeyClass::IdentitySigning`].
pub(crate) const NODE_IDENTITY_RECORD: &[u8] = b"node-identity";

/// Password for the node keystore (core.md §63). Read from the
/// `UMC_KEYSTORE_PASSWORD` environment variable; when unset, the
/// development default of an empty password is used (documented in
/// storage.md §10; never prompted).
#[must_use]
pub(crate) fn keystore_password() -> Vec<u8> {
    std::env::var("UMC_KEYSTORE_PASSWORD")
        .map(String::into_bytes)
        .unwrap_or_default()
}

/// Loads the node identity from the keystore, or generates a fresh one
/// and persists it (core.md §19/§63 — persistent endpoint identity).
/// Two runs against the same keystore with the same password produce the
/// same endpoint id; a wrong password fails loudly.
///
/// # Errors
/// Returns a message when the keystore cannot be opened, the identity
/// record is malformed, or the password is wrong.
pub(crate) fn load_or_create_identity(config: &NodeConfig) -> Result<NodeIdentity, String> {
    let path = config.resolved_keystore_dir().join(KEYSTORE_FILE);
    let ks = Keystore::open(path, &keystore_password()).map_err(|e| format!("keystore: {e:?}"))?;
    match ks.load(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD) {
        Ok(seeds) if seeds.len() == 64 => Ok(identity_from_seeds(&seeds)),
        Ok(_) => Err("keystore: malformed node-identity record (expected 64 bytes)".into()),
        Err(KeystoreError::UnsupportedClass) => {
            let identity = NodeIdentity::generate(&OsEntropy);
            let mut seeds = Vec::with_capacity(64);
            seeds.extend_from_slice(&identity.identity.to_seed());
            seeds.extend_from_slice(&identity.static_handshake.to_seed());
            ks.store(KeyClass::IdentitySigning, NODE_IDENTITY_RECORD, &seeds)
                .map_err(|e| format!("keystore store: {e:?}"))?;
            Ok(identity)
        }
        Err(e) => Err(format!("keystore load: {e:?}")),
    }
}

fn identity_from_seeds(seeds: &[u8]) -> NodeIdentity {
    let identity_seed: [u8; 32] = seeds[..32].try_into().expect("32-byte identity seed");
    let static_seed: [u8; 32] = seeds[32..].try_into().expect("32-byte static seed");
    NodeIdentity {
        identity: IdentityKeyPair::from_seed(identity_seed),
        static_handshake: StaticHandshakeKeyPair::from_seed(static_seed),
    }
}

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
    /// Node identity. Loaded from the keystore (core.md §19/§63), so the
    /// endpoint id survives restarts; a fresh identity is generated and
    /// persisted on first boot.
    pub node_identity: NodeIdentity,
    /// Operating mode profile (local mesh vs endpoint).
    pub mesh: MeshConfig,
    /// The runtime node: registered carriers, sessions (core.md §8).
    pub node: Node,
    /// Bound carrier listeners; held here so the sockets stay alive.
    pub listeners: Vec<Box<dyn Listener + Send + Sync>>,
    /// Live session registry (core.md §9.5); populated by the accept loops.
    pub sessions: Arc<SessionManager>,
    /// Session bus: cross-session delivery within one daemon (relay
    /// forwarding, future bundle delivery).
    pub bus: Arc<Mutex<SessionBus>>,
    /// Discovery service: candidate table + `PEER_HINT` builder.
    pub discovery: DiscoveryService,
    /// Relay service: circuit registry, admission, forwarding.
    pub relay: RelayService,
    /// Bundle service: object-store-backed bundle admission and expiry.
    pub bundle: BundleService,
    /// Routing service: request admission, reverse paths, route cache.
    #[allow(dead_code)] // route-request handling lands in Phase 12
    pub routing: RoutingService,
    /// Bounded daemon event log; services push transitions into it.
    pub events: Arc<Mutex<DaemonEvents>>,
    /// Registered applications (core.md §9.6); the echo application is
    /// installed at startup so `org.umc.app/1` streams dispatch end to end.
    #[allow(dead_code)] // app registration over the control API lands in Phase 10
    pub apps: AppRegistry,
    /// Per-application inbound stream channels: session tasks forward
    /// received stream data into the application's channel.
    pub app_channels: Arc<Mutex<HashMap<Vec<u8>, AppTx>>>,
    /// Per-application echo receivers: the application's outbound channel,
    /// drained by the session writers and sent back on the same stream.
    pub app_echo_rx: Arc<Mutex<HashMap<Vec<u8>, AppRx>>>,
    /// Development-only control API bearer credential (control-api.md
    /// §11.3). `None` in production: every request is accepted at hello.
    pub development_token: Option<Vec<u8>>,
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
    /// identity (persisted in the keystore), security primitives, and the
    /// shutdown channel.
    ///
    /// # Errors
    ///
    /// Returns an error when the data or keystore directory cannot be
    /// created, the node database cannot be opened, or the keystore cannot
    /// be opened with the configured password
    /// ([`UMC_KEYSTORE_PASSWORD`](keystore_password)).
    pub fn new(config: NodeConfig, shutdown_channel: mpsc::Sender<()>) -> Result<Self, String> {
        let data_dir = config.resolved_data_dir();
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("data dir: {e}"))?;
        std::fs::create_dir_all(config.resolved_keystore_dir())
            .map_err(|e| format!("keystore dir: {e}"))?;
        let store = Arc::new(
            SqliteStore::open(&data_dir.join("node.db")).map_err(|e| format!("store: {e:?}"))?,
        );

        let node_identity = load_or_create_identity(&config)?;
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

        let events = Arc::new(Mutex::new(DaemonEvents::new(200)));
        let development_token = config
            .development_token
            .as_deref()
            .map(|token| token.as_bytes().to_vec());
        let bundle_objects = ObjectStore::open(data_dir.join("objects"))
            .map_err(|e| format!("bundle object store: {e:?}"))?;
        let bundle_quota = QuotaAccount::new(
            Profile::Standard,
            0,
            Profile::Standard.bundle_storage_bytes(),
        );

        let mut apps = AppRegistry::new();
        apps.register(
            WELL_KNOWN_APP.to_vec(),
            crate::app_layer::ECHO_APP_NAME.to_string(),
        )
        .map_err(|e| format!("echo app registration: {e:?}"))?;

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
            sessions: Arc::new(SessionManager::new()),
            bus: Arc::new(Mutex::new(SessionBus::new())),
            discovery: DiscoveryService::new(umc_discovery::table::DEFAULT_TABLE_CAP),
            relay: RelayService::new(events.clone()),
            bundle: BundleService::new(bundle_objects, bundle_quota, events.clone()),
            routing: RoutingService::new(),
            events,
            apps,
            app_channels: Arc::new(Mutex::new(HashMap::new())),
            app_echo_rx: Arc::new(Mutex::new(HashMap::new())),
            development_token,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn fresh_config() -> NodeConfig {
        let dir = std::env::temp_dir().join(format!(
            "umcd-state-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        NodeConfig {
            data_dir: dir,
            ..NodeConfig::default()
        }
    }

    /// Runs `f` with `UMC_KEYSTORE_PASSWORD` set; env mutation is
    /// serialized so parallel tests cannot observe each other's password.
    fn with_password(password: &str, f: impl FnOnce()) {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::env::set_var("UMC_KEYSTORE_PASSWORD", password);
        f();
        std::env::remove_var("UMC_KEYSTORE_PASSWORD");
    }

    fn build(config: NodeConfig) -> RuntimeState {
        let (tx, _rx) = mpsc::channel(1);
        RuntimeState::new(config, tx).expect("runtime state")
    }

    #[test]
    fn identity_is_persistent_across_restarts() {
        with_password("test-password", || {
            let config = fresh_config();
            let first = build(config.clone());
            let endpoint_id = first.node_identity.endpoint_id();
            drop(first);
            let second = build(config);
            assert_eq!(endpoint_id, second.node_identity.endpoint_id());
        });
    }

    #[test]
    fn fresh_dir_generates_a_new_identity_and_persists_it() {
        with_password("test-password", || {
            let a = fresh_config();
            let b = fresh_config();
            let sa = build(a.clone());
            let id_a = sa.node_identity.endpoint_id();
            drop(sa);
            // The same dir reloads the persisted identity...
            let sa2 = build(a);
            assert_eq!(id_a, sa2.node_identity.endpoint_id());
            // ...while a fresh dir derives a different one.
            let sb = build(b);
            assert_ne!(id_a, sb.node_identity.endpoint_id());
        });
    }
}
