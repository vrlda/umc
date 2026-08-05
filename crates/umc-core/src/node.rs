//! Minimal Phase 1 Node: one identity, TCP/UDP carriers, direct sessions.
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use umc_carrier::error::CarrierError;
use umc_carrier::Carrier;
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::traffic::SessionSecrets;
use umc_types::runtime::{Clock, EntropySource};

#[derive(Debug)]
pub struct NodeIdentity {
    pub identity: IdentityKeyPair,
    pub static_handshake: StaticHandshakeKeyPair,
}

impl NodeIdentity {
    pub fn generate(entropy: &dyn EntropySource) -> Self {
        let _ = entropy;
        Self {
            identity: IdentityKeyPair::generate(),
            static_handshake: StaticHandshakeKeyPair::generate(),
        }
    }

    #[must_use]
    pub fn endpoint_id(&self) -> [u8; 32] {
        umc_handshake::identity::endpoint_id(&self.identity.public())
    }
}

#[derive(Debug)]
pub struct NodeConfig {
    pub identity: NodeIdentity,
    pub dcid: Vec<u8>,
}

pub struct Node {
    pub config: NodeConfig,
    pub clock: Arc<dyn Clock>,
    pub entropy: Arc<dyn EntropySource>,
    carriers: HashMap<String, Box<dyn Carrier + Send + Sync>>,
    sessions: Arc<Mutex<HashMap<u64, SessionEntry>>>,
    next_session: u64,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node").finish_non_exhaustive()
    }
}

// Fields are written by connect() and read by the Task 25 session wiring.
#[allow(dead_code)]
struct SessionEntry {
    pub secrets: SessionSecrets,
    pub peer_endpoint_id: [u8; 32],
}

impl Node {
    pub fn new(config: NodeConfig, clock: Arc<dyn Clock>, entropy: Arc<dyn EntropySource>) -> Self {
        Self {
            config,
            clock,
            entropy,
            carriers: HashMap::new(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session: 0,
        }
    }

    pub fn register_carrier(&mut self, carrier: Box<dyn Carrier + Send + Sync>) {
        self.carriers.insert(carrier.type_id().0.clone(), carrier);
    }

    #[must_use]
    pub fn carrier(&self, type_id: &str) -> Option<&(dyn Carrier + Send + Sync)> {
        self.carriers.get(type_id).map(AsRef::as_ref)
    }

    /// Complete an XX handshake with a remote over the given carrier. Phase 1
    /// Task 24: deterministic harness path (Task 25 replaces it with the live
    /// wire handshake).
    ///
    /// # Errors
    ///
    /// Returns [`NodeError::CarrierUnknown`] when no carrier of the given type
    /// is registered, [`NodeError::Carrier`] when dialing fails, and
    /// [`NodeError::Handshake`] when the XX handshake fails.
    pub async fn connect(
        &mut self,
        carrier_type: &str,
        remote: String,
        server_identity_public: &NodeIdentity,
    ) -> Result<u64, NodeError> {
        let carrier = self
            .carrier(carrier_type)
            .ok_or(NodeError::CarrierUnknown)?;
        let link = carrier.dial(remote).map_err(NodeError::Carrier)?;
        let _ = link;
        let client_secrets = self.handshake_secrets(server_identity_public)?;
        let id = self.next_session;
        self.next_session += 1;
        self.sessions.lock().await.insert(
            id,
            SessionEntry {
                secrets: client_secrets,
                peer_endpoint_id: server_identity_public.endpoint_id(),
            },
        );
        Ok(id)
    }

    fn handshake_secrets(
        &self,
        server_identity_public: &NodeIdentity,
    ) -> Result<SessionSecrets, NodeError> {
        let (client, _) = umc_handshake::xx::run_xx_handshake(
            &self.config.identity.identity,
            &self.config.identity.static_handshake,
            &server_identity_public.identity,
            &server_identity_public.static_handshake,
            self.entropy.as_ref(),
            b"ump.udp/1",
            0,
        )
        .map_err(NodeError::Handshake)?;
        Ok(client)
    }
}

#[derive(Debug)]
pub enum NodeError {
    CarrierUnknown,
    Carrier(CarrierError),
    Handshake(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NodeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use umc_types::runtime::{EntropySource, Instant};

    struct TestEntropy;

    impl EntropySource for TestEntropy {
        fn fill(&self, out: &mut [u8]) {
            out.fill(0x5A);
        }
    }

    struct TestClock;

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            Instant(0)
        }
    }

    #[test]
    fn node_identity_generates_distinct_ids() {
        let a = NodeIdentity::generate(&TestEntropy);
        let b = NodeIdentity::generate(&TestEntropy);
        assert_ne!(a.endpoint_id(), b.endpoint_id());
    }

    #[test]
    fn node_registers_and_looks_up_carriers() {
        let mut node = Node::new(
            NodeConfig {
                identity: NodeIdentity::generate(&TestEntropy),
                dcid: vec![1u8; 8],
            },
            Arc::new(TestClock),
            Arc::new(TestEntropy),
        );
        assert!(node.carrier("ump.tcp/1").is_none());
        node.register_carrier(Box::new(umc_carrier_tcp::TcpCarrier));
        assert!(node.carrier("ump.tcp/1").is_some());
        assert!(node.carrier("ump.udp/1").is_none());
    }
}
