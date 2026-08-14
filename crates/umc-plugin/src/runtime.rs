//! Logical carrier adapter for a supervised external plugin.
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use crate::process::{ProcessConfig, ProcessError, ProcessSupervisor};
use crate::supervisor::PluginLimits;
use prost::Message;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};
use umc_carrier::error::{CarrierError, CarrierErrorKind};
use umc_carrier::types::{
    CarrierCapabilities, CarrierTypeId, ConnectionModel, InboundPacket, LinkEvent, LinkProperties,
    Ordering, OutboundPacket, PacketMode, QueueState, Reliability, SendResult,
};
use umc_carrier::{BoxLink, Carrier, Link, Listener};
use umc_discovery::provider::{CandidateAuth, CandidateSource, PeerCandidate, SharingPolicy};
use umc_types::runtime::{Duration as CoreDuration, Instant as CoreInstant};

#[derive(Debug)]
struct ExternalRuntime {
    runtime: Option<Arc<Runtime>>,
    supervisor: ProcessSupervisor,
    generation: crate::supervisor::PluginGeneration,
    listen_handle: Option<u64>,
}

/// A `Carrier` backed by one supervised external plugin process. Calls are
/// serialized through the private runtime because the legacy carrier trait is
/// synchronous; operation deadlines remain enforced by the plugin protocol.
#[derive(Clone, Debug)]
pub struct ExternalCarrier {
    type_id: String,
    capabilities: CarrierCapabilities,
    inner: Arc<Mutex<ExternalRuntime>>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DiscoveryBatch {
    pub candidates: Vec<PeerCandidate>,
    pub removed: Vec<u64>,
}

impl ExternalCarrier {
    /// Launch an external carrier and complete its authenticated startup.
    pub fn launch(
        type_id: String,
        process: ProcessConfig,
        capabilities: CarrierCapabilities,
    ) -> Result<Self, ExternalCarrierError> {
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| ExternalCarrierError::Runtime(error.to_string()))?;
        let mut supervisor = ProcessSupervisor::new(type_id.clone(), PluginLimits::default())
            .map_err(|error| ExternalCarrierError::Supervisor(error.to_string()))?;
        let (runtime, supervisor, result) = std::thread::spawn(move || {
            let result = runtime.block_on(supervisor.start(process));
            (runtime, supervisor, result)
        })
        .join()
        .map_err(|_| ExternalCarrierError::Runtime("plugin startup worker panicked".into()))?;
        let generation = result.map_err(ExternalCarrierError::Process)?;
        Ok(Self {
            type_id,
            capabilities,
            inner: Arc::new(Mutex::new(ExternalRuntime {
                runtime: Some(Arc::new(runtime)),
                supervisor,
                generation,
                listen_handle: None,
            })),
        })
    }

    /// Stop the process generation and invalidate all plugin-owned state.
    pub fn shutdown(&self) -> Result<(), ExternalCarrierError> {
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut inner = inner.lock().expect("external carrier runtime");
            let generation = inner.generation;
            let Some(runtime) = inner.runtime.take() else {
                return Ok(());
            };
            runtime
                .block_on(inner.supervisor.shutdown(generation))
                .map_err(ExternalCarrierError::Process)
        })
        .join()
        .map_err(|_| ExternalCarrierError::Runtime("plugin shutdown worker panicked".into()))?
    }

    #[must_use]
    pub fn capabilities_for(
        type_id: &str,
        supports_listen: bool,
        supports_dial: bool,
    ) -> CarrierCapabilities {
        Self::capabilities_for_with_discovery(type_id, supports_listen, supports_dial, false)
    }

    #[must_use]
    pub fn capabilities_for_with_discovery(
        type_id: &str,
        supports_listen: bool,
        supports_dial: bool,
        supports_discovery: bool,
    ) -> CarrierCapabilities {
        CarrierCapabilities {
            api_version: 1,
            carrier_type: CarrierTypeId(type_id.to_string()),
            packet_mode: PacketMode::Datagram,
            reliability: Reliability::Unreliable,
            ordering: Ordering::Unordered,
            connection_model: ConnectionModel::Connected,
            supports_listen,
            supports_dial,
            supports_discovery,
            minimum_packet_size: 1,
            maximum_packet_size: 64 * 1024,
            scope_classes: vec!["external".into()],
        }
    }

    fn call_operation(
        &self,
        op_type: crate::proto::umc::plugin::v1::OpType,
        handle: u64,
        arguments: Vec<u8>,
    ) -> Result<crate::proto::umc::plugin::v1::OpResp, ExternalCarrierError> {
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut inner = inner.lock().expect("external carrier runtime");
            let runtime = inner.runtime.clone().ok_or(ProcessError::Exit)?;
            let process = inner
                .supervisor
                .process
                .as_mut()
                .ok_or(ProcessError::Exit)?;
            let result = runtime
                .block_on(process.operation_with_heartbeat(
                    op_type,
                    handle,
                    arguments,
                    Duration::from_secs(10),
                ))
                .map_err(ExternalCarrierError::Process);
            result
        })
        .join()
        .map_err(|_| ExternalCarrierError::Runtime("plugin operation worker panicked".into()))?
    }

    fn next_event(
        &self,
        wait: Duration,
        handle: Option<u64>,
        event_type: Option<crate::proto::umc::plugin::v1::EventType>,
    ) -> Result<crate::proto::umc::plugin::v1::PluginEvent, ExternalCarrierError> {
        let inner = Arc::clone(&self.inner);
        std::thread::spawn(move || {
            let mut inner = inner.lock().expect("external carrier runtime");
            let runtime = inner.runtime.clone().ok_or(ProcessError::Exit)?;
            let process = inner
                .supervisor
                .process
                .as_mut()
                .ok_or(ProcessError::Exit)?;
            runtime
                .block_on(process.next_event(wait, handle, event_type))
                .map_err(ExternalCarrierError::Process)
        })
        .join()
        .map_err(|_| ExternalCarrierError::Runtime("plugin event worker panicked".into()))?
    }

    /// Run one bounded discovery operation and consume its candidate events.
    /// Candidate events are returned only after `DISCOVERY_COMPLETE`; malformed
    /// or failed streams are rejected without changing daemon discovery state.
    pub fn discover(
        &self,
        scope: String,
        deadline: Duration,
        maximum_candidates: usize,
    ) -> Result<DiscoveryBatch, ExternalCarrierError> {
        if !self.capabilities.supports_discovery {
            return Err(ExternalCarrierError::Unsupported);
        }
        let inner = Arc::clone(&self.inner);
        let maximum_candidates = maximum_candidates.min(256);
        std::thread::spawn(move || {
            let mut inner = inner.lock().expect("external carrier runtime");
            let runtime = inner.runtime.clone().ok_or(ProcessError::Exit)?;
            let process = inner
                .supervisor
                .process
                .as_mut()
                .ok_or(ProcessError::Exit)?;
            runtime
                .block_on(async {
                    let request = crate::proto::umc::plugin::v1::DiscoveryRequest {
                        scope,
                        deadline_ms: u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                        maximum_candidates: u32::try_from(maximum_candidates).unwrap_or(u32::MAX),
                    };
                    let response = process
                        .operation_with_heartbeat(
                            crate::proto::umc::plugin::v1::OpType::Discover,
                            0,
                            request.encode_to_vec(),
                            deadline,
                        )
                        .await?;
                    if response.status != crate::proto::umc::plugin::v1::OpStatus::Ok as i32 {
                        return Err(ProcessError::Transport(
                            crate::transport::TransportError::Decode,
                        ));
                    }
                    let now = CoreInstant(
                        umc_types::runtime::Monotonic::try_from(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis(),
                        )
                        .unwrap_or(u64::MAX),
                    );
                    let mut batch = DiscoveryBatch::default();
                    let event_types = [
                        crate::proto::umc::plugin::v1::EventType::CandidateFound,
                        crate::proto::umc::plugin::v1::EventType::CandidateUpdated,
                        crate::proto::umc::plugin::v1::EventType::CandidateExpired,
                        crate::proto::umc::plugin::v1::EventType::CandidateRemoved,
                        crate::proto::umc::plugin::v1::EventType::DiscoveryComplete,
                        crate::proto::umc::plugin::v1::EventType::Failed,
                    ];
                    let finish = tokio::time::Instant::now() + deadline;
                    loop {
                        let remaining =
                            finish.saturating_duration_since(tokio::time::Instant::now());
                        let event = process
                            .next_event_types(remaining, None, &event_types)
                            .await?;
                        match crate::proto::umc::plugin::v1::EventType::try_from(event.event_type)
                            .map_err(|_| {
                            ProcessError::Transport(crate::transport::TransportError::Decode)
                        })? {
                            crate::proto::umc::plugin::v1::EventType::DiscoveryComplete => {
                                return Ok(batch)
                            }
                            crate::proto::umc::plugin::v1::EventType::CandidateExpired
                            | crate::proto::umc::plugin::v1::EventType::CandidateRemoved => {
                                if event.handle != 0 {
                                    batch.removed.push(event.handle);
                                }
                            }
                            crate::proto::umc::plugin::v1::EventType::CandidateFound
                            | crate::proto::umc::plugin::v1::EventType::CandidateUpdated => {
                                if batch.candidates.len() >= maximum_candidates {
                                    continue;
                                }
                                if let Some(candidate) = decode_candidate(&event.payload, now) {
                                    batch.candidates.push(candidate);
                                } else {
                                    return Err(ProcessError::Transport(
                                        crate::transport::TransportError::Decode,
                                    ));
                                }
                            }
                            crate::proto::umc::plugin::v1::EventType::Failed => {
                                return Err(ProcessError::Transport(
                                    crate::transport::TransportError::Decode,
                                ))
                            }
                            _ => unreachable!(),
                        }
                    }
                })
                .map_err(ExternalCarrierError::Process)
        })
        .join()
        .map_err(|_| ExternalCarrierError::Runtime("plugin discovery worker panicked".into()))?
    }
}

fn decode_candidate(payload: &[u8], now: CoreInstant) -> Option<PeerCandidate> {
    let candidate = crate::proto::umc::plugin::v1::Candidate::decode(payload).ok()?;
    if candidate.candidate_id == 0 || candidate.carrier_type.is_empty() {
        return None;
    }
    let authentication = match candidate.authentication {
        0 => CandidateAuth::Unauthenticated,
        1 => CandidateAuth::CarrierAuthenticated,
        2 => CandidateAuth::IntroductionAuthenticated,
        3 => CandidateAuth::InvitationAuthenticated,
        4 => CandidateAuth::PreviousSessionBound,
        5 => CandidateAuth::SignedBootstrap,
        _ => return None,
    };
    let sharing_policy = match candidate.sharing_policy {
        0 => SharingPolicy::LocalUseOnly,
        1 => SharingPolicy::ShareSelected,
        2 => SharingPolicy::ShareLocalScope,
        3 => SharingPolicy::ShareGeneral,
        4 => SharingPolicy::DoNotReshare,
        _ => return None,
    };
    let lifetime = candidate
        .lifetime_ms
        .min(umc_discovery::provider::MAX_CANDIDATE_LIFETIME_MS);
    Some(PeerCandidate {
        candidate_id: candidate.candidate_id,
        carrier_type: candidate.carrier_type,
        connection_hint: candidate.connection_hint,
        source: CandidateSource::CarrierNative,
        created_at: now,
        expires_at: now + CoreDuration::from_millis(lifetime),
        sharing_policy,
        authentication,
        local: candidate.local,
    })
}

impl Carrier for ExternalCarrier {
    fn type_id(&self) -> CarrierTypeId {
        CarrierTypeId(self.type_id.clone())
    }
    fn capabilities(&self) -> CarrierCapabilities {
        self.capabilities.clone()
    }

    fn listen(&self, bind: String) -> Result<Box<dyn Listener + Send + Sync>, CarrierError> {
        if !self.capabilities.supports_listen {
            return Err(CarrierError::new(CarrierErrorKind::Unsupported, "listen"));
        }
        let response = self
            .call_operation(
                crate::proto::umc::plugin::v1::OpType::Listen,
                0,
                bind.into_bytes(),
            )
            .map_err(|error| error.carrier("listen"))?;
        if response.status != crate::proto::umc::plugin::v1::OpStatus::Ok as i32 {
            return Err(CarrierError::new(CarrierErrorKind::Internal, "listen"));
        }
        self.inner
            .lock()
            .expect("external carrier runtime")
            .listen_handle = Some(response.result_handle);
        Ok(Box::new(ExternalListener {
            carrier: self.clone(),
        }))
    }

    fn dial(&self, remote: String) -> Result<BoxLink, CarrierError> {
        if !self.capabilities.supports_dial {
            return Err(CarrierError::new(CarrierErrorKind::Unsupported, "dial"));
        }
        let response = self
            .call_operation(
                crate::proto::umc::plugin::v1::OpType::Dial,
                0,
                remote.into_bytes(),
            )
            .map_err(|error| error.carrier("dial"))?;
        if response.status != crate::proto::umc::plugin::v1::OpStatus::Ok as i32 {
            return Err(CarrierError::new(CarrierErrorKind::Unreachable, "dial"));
        }
        Ok(Box::new(ExternalLink {
            carrier: self.clone(),
            handle: response.result_handle,
        }))
    }
}

#[derive(Debug, Clone)]
struct ExternalListener {
    carrier: ExternalCarrier,
}

impl Listener for ExternalListener {
    fn accept(&self) -> Result<BoxLink, CarrierError> {
        let event = self
            .carrier
            .next_event(
                Duration::from_millis(25),
                None,
                Some(crate::proto::umc::plugin::v1::EventType::LinkAccepted),
            )
            .map_err(|error| error.accept_error("accept"))?;
        let event_type = crate::proto::umc::plugin::v1::EventType::try_from(event.event_type)
            .map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "accept"))?;
        if event_type != crate::proto::umc::plugin::v1::EventType::LinkAccepted || event.handle == 0
        {
            return Err(CarrierError::new(CarrierErrorKind::ProtocolError, "accept"));
        }
        Ok(Box::new(ExternalLink {
            carrier: self.carrier.clone(),
            handle: event.handle,
        }))
    }
    fn close(&self) -> Result<(), CarrierError> {
        let handle = self
            .carrier
            .inner
            .lock()
            .expect("external carrier runtime")
            .listen_handle;
        if let Some(handle) = handle {
            self.carrier
                .call_operation(
                    crate::proto::umc::plugin::v1::OpType::CloseListener,
                    handle,
                    Vec::new(),
                )
                .map_err(|error| error.carrier("close_listener"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ExternalLink {
    carrier: ExternalCarrier,
    handle: u64,
}

impl Link for ExternalLink {
    fn properties(&self) -> LinkProperties {
        LinkProperties {
            reliability: self.carrier.capabilities.reliability,
            ordering: self.carrier.capabilities.ordering,
            current_mtu: self.carrier.capabilities.maximum_packet_size,
            queue_bytes: 0,
            queue_capacity: 64 * 1024,
            estimated_rtt_ms: None,
            estimated_loss: None,
            metered: false,
        }
    }

    fn send(&self, packet: OutboundPacket) -> Result<SendResult, CarrierError> {
        let response = self
            .carrier
            .call_operation(
                crate::proto::umc::plugin::v1::OpType::Send,
                self.handle,
                packet.bytes,
            )
            .map_err(|error| error.carrier("send"))?;
        match crate::proto::umc::plugin::v1::OpStatus::try_from(response.status)
            .unwrap_or(crate::proto::umc::plugin::v1::OpStatus::Error)
        {
            crate::proto::umc::plugin::v1::OpStatus::Ok => Ok(SendResult::Accepted {
                queue_state: QueueState::QueuedBounded,
            }),
            crate::proto::umc::plugin::v1::OpStatus::WouldBlock => Ok(SendResult::WouldBlock),
            crate::proto::umc::plugin::v1::OpStatus::QueueFull => Ok(SendResult::QueueFull),
            _ => Err(CarrierError::new(CarrierErrorKind::LinkFailed, "send")),
        }
    }

    fn recv(&self) -> Result<InboundPacket, CarrierError> {
        Err(CarrierError::new(CarrierErrorKind::WouldBlock, "recv"))
    }
    fn events(&self) -> Result<LinkEvent, CarrierError> {
        let event = self
            .carrier
            .next_event(Duration::from_millis(25), Some(self.handle), None)
            .map_err(|error| error.accept_error("events"))?;
        let event_type = crate::proto::umc::plugin::v1::EventType::try_from(event.event_type)
            .map_err(|_| CarrierError::new(CarrierErrorKind::ProtocolError, "events"))?;
        match event_type {
            crate::proto::umc::plugin::v1::EventType::LinkActive => Ok(LinkEvent::Active),
            crate::proto::umc::plugin::v1::EventType::Writable => Ok(LinkEvent::Writable),
            crate::proto::umc::plugin::v1::EventType::MtuChanged => {
                let bytes: [u8; 4] =
                    event.payload.as_slice().try_into().map_err(|_| {
                        CarrierError::new(CarrierErrorKind::ProtocolError, "events")
                    })?;
                Ok(LinkEvent::MtuChanged {
                    new_maximum: u32::from_le_bytes(bytes) as usize,
                })
            }
            crate::proto::umc::plugin::v1::EventType::QualityChanged => {
                Ok(LinkEvent::QualityChanged)
            }
            crate::proto::umc::plugin::v1::EventType::AddressRebound => {
                Ok(LinkEvent::AddressRebound)
            }
            crate::proto::umc::plugin::v1::EventType::LinkDegraded => Ok(LinkEvent::Degraded),
            crate::proto::umc::plugin::v1::EventType::Closing => Ok(LinkEvent::Closing),
            crate::proto::umc::plugin::v1::EventType::Closed => Ok(LinkEvent::Closed),
            crate::proto::umc::plugin::v1::EventType::Failed => Ok(LinkEvent::Failed),
            _ => Err(CarrierError::new(CarrierErrorKind::ProtocolError, "events")),
        }
    }
    fn close(&self, reason: &str) -> Result<(), CarrierError> {
        self.carrier
            .call_operation(
                crate::proto::umc::plugin::v1::OpType::CloseLink,
                self.handle,
                reason.as_bytes().to_vec(),
            )
            .map_err(|error| error.carrier("close_link"))?;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ExternalCarrierError {
    Unsupported,
    Runtime(String),
    Supervisor(String),
    Process(ProcessError),
}

impl From<ProcessError> for ExternalCarrierError {
    fn from(error: ProcessError) -> Self {
        Self::Process(error)
    }
}

impl ExternalCarrierError {
    fn carrier(&self, operation: &'static str) -> CarrierError {
        let kind = match self {
            Self::Process(ProcessError::StartupTimeout) => CarrierErrorKind::DeadlineExceeded,
            Self::Unsupported | Self::Process(ProcessError::UnsupportedPlatform) => {
                CarrierErrorKind::Unsupported
            }
            _ => CarrierErrorKind::LinkFailed,
        };
        let mut error = CarrierError::new(kind, operation);
        error.message = format!("external plugin: {self:?}");
        error
    }

    fn accept_error(&self, operation: &'static str) -> CarrierError {
        let kind = match self {
            Self::Process(ProcessError::StartupTimeout) => CarrierErrorKind::WouldBlock,
            Self::Unsupported | Self::Process(ProcessError::UnsupportedPlatform) => {
                CarrierErrorKind::Unsupported
            }
            _ => CarrierErrorKind::LinkFailed,
        };
        let mut error = CarrierError::new(kind, operation);
        error.message = format!("external plugin: {self:?}");
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_capabilities_are_conservative() {
        let caps = ExternalCarrier::capabilities_for("ump.test/1", true, false);
        assert!(!caps.supports_dial);
        assert!(caps.supports_listen);
        assert!(!caps.supports_discovery);
    }
}
