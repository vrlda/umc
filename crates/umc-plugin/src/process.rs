//! Process-isolated external carrier launcher (carrier-plugin-api.md §6-8,
//! §19-23). The daemon owns the private local IPC endpoint and process
//! generation (Unix socket or Windows named pipe).
#![allow(clippy::missing_errors_doc)]
use crate::handshake::{accept_plugin_hello, HandshakeError, MAX_MESSAGE_SIZE};
use crate::manifest::ExternalPluginManifest;
use crate::proto::umc::plugin::v1 as p;
use crate::sandbox::{SandboxMode, SandboxPlan};
use crate::shared_memory::{SharedRegion, DEFAULT_THRESHOLD};
use crate::supervisor::{
    PluginFailure, PluginGeneration, PluginLimits, PluginSupervisor, RestartDecision,
};
use crate::transport::{read_envelope, write_envelope, TransportError};
use rand_core::RngCore;
use std::collections::VecDeque;
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};
use tokio::time::{timeout, Instant};
use umc_crypto::signatures::IdentityPublicKey;

#[derive(Debug)]
pub enum ProcessError {
    UnsupportedPlatform,
    Io(String),
    Handshake(HandshakeError),
    Transport(TransportError),
    StartupTimeout,
    InvalidStartAck,
    EventQueueFull,
    Exit,
}

impl From<TransportError> for ProcessError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Configuration for one process generation. The command receives only the
/// socket, token, and plugin name in a cleared environment.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub plugin_name: String,
    pub granted_capabilities: Vec<String>,
    pub config_blob: Vec<u8>,
    pub maximum_packet_size: u32,
    pub startup_deadline: Duration,
    pub max_message_size: usize,
    /// Optional safe file-backed shared region for large payloads.
    pub shared_memory_size: Option<usize>,
    pub shared_memory_threshold: usize,
    pub sandbox_mode: SandboxMode,
    pub manifest: Option<ExternalPluginManifest>,
    pub trusted_manifest_keys: Vec<IdentityPublicKey>,
    pub require_signed_manifest: bool,
}

#[cfg(unix)]
struct SocketGuard {
    path: PathBuf,
    directory: PathBuf,
    keep: bool,
}

struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.start_kill();
        }
    }
}

#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

#[cfg(windows)]
struct DirectoryGuard {
    path: PathBuf,
    keep: bool,
}

#[cfg(windows)]
impl Drop for DirectoryGuard {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(self.path.join("m"));
            let _ = std::fs::remove_dir(&self.path);
        }
    }
}

/// Binds a real child process to the generation/quota supervisor. The
/// supervisor remains the authority for restart backoff and all generation
/// invalidation; the process object only owns IPC and OS resources.
#[derive(Debug)]
pub struct ProcessSupervisor {
    pub id: String,
    pub policy: PluginSupervisor,
    pub process: Option<PluginProcess>,
}

impl ProcessSupervisor {
    pub fn new(
        id: impl Into<String>,
        limits: PluginLimits,
    ) -> Result<Self, crate::supervisor::SupervisorError> {
        let id = id.into();
        let mut policy = PluginSupervisor::default();
        policy.register(id.clone(), limits)?;
        Ok(Self {
            id,
            policy,
            process: None,
        })
    }

    /// Launch one generation and attach the authenticated process.
    pub async fn start(&mut self, config: ProcessConfig) -> Result<PluginGeneration, ProcessError> {
        let generation = self
            .policy
            .start(&self.id)
            .map_err(|error| ProcessError::Io(error.to_string()))?;
        match PluginProcess::spawn(config, generation.number).await {
            Ok(process) => {
                self.policy
                    .ready(&self.id, generation)
                    .map_err(|error| ProcessError::Io(error.to_string()))?;
                self.process = Some(process);
                Ok(generation)
            }
            Err(error) => {
                let _ = self.policy.fail_at(
                    &self.id,
                    generation,
                    PluginFailure::InitFailure,
                    crate::supervisor::monotonic_now_ms(),
                    0,
                );
                Err(error)
            }
        }
    }

    /// Record a heartbeat; an IPC failure invalidates this generation.
    pub async fn heartbeat(&mut self, generation: PluginGeneration) -> Result<(), ProcessError> {
        let result = self
            .process
            .as_mut()
            .ok_or(ProcessError::Exit)?
            .heartbeat()
            .await;
        match result {
            Ok(()) => {
                self.policy
                    .heartbeat(&self.id, generation, crate::supervisor::monotonic_now_ms())
                    .map_err(|error| ProcessError::Io(error.to_string()))?;
                Ok(())
            }
            Err(error) => {
                let _ = self.policy.fail_at(
                    &self.id,
                    generation,
                    PluginFailure::IpcClosed,
                    crate::supervisor::monotonic_now_ms(),
                    0,
                );
                Err(error)
            }
        }
    }

    /// Reap a crashed child and invalidate every resource in its generation.
    pub fn poll_failure(
        &mut self,
        generation: PluginGeneration,
    ) -> Result<Option<RestartDecision>, ProcessError> {
        let Some(process) = self.process.as_mut() else {
            return Ok(None);
        };
        if process.exited()? {
            self.process = None;
            return self
                .policy
                .fail_at(
                    &self.id,
                    generation,
                    PluginFailure::ProcessExit,
                    crate::supervisor::monotonic_now_ms(),
                    0,
                )
                .map(Some)
                .map_err(|error| ProcessError::Io(error.to_string()));
        }
        Ok(None)
    }

    pub async fn shutdown(&mut self, generation: PluginGeneration) -> Result<(), ProcessError> {
        if let Some(mut process) = self.process.take() {
            process.shutdown(Duration::from_secs(1)).await?;
        }
        self.policy
            .stop(&self.id, generation)
            .map_err(|error| ProcessError::Io(error.to_string()))?;
        Ok(())
    }
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            command: PathBuf::new(),
            args: Vec::new(),
            plugin_name: "external-carrier".into(),
            granted_capabilities: Vec::new(),
            config_blob: Vec::new(),
            maximum_packet_size: 1_200,
            startup_deadline: Duration::from_secs(10),
            max_message_size: MAX_MESSAGE_SIZE as usize,
            shared_memory_size: None,
            shared_memory_threshold: DEFAULT_THRESHOLD,
            sandbox_mode: SandboxMode::Disabled,
            manifest: None,
            trusted_manifest_keys: Vec::new(),
            require_signed_manifest: false,
        }
    }
}

trait PluginIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> PluginIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

type PluginStream = Box<dyn PluginIo>;

pub struct PluginProcess {
    child: Child,
    stream: PluginStream,
    endpoint: PathBuf,
    endpoint_dir: Option<PathBuf>,
    token: Vec<u8>,
    pub generation: u64,
    pub max_message_size: usize,
    last_heartbeat: Instant,
    next_operation: u64,
    events: VecDeque<p::PluginEvent>,
    shared_region: Option<SharedRegion>,
    shared_memory_threshold: usize,
}

impl std::fmt::Debug for PluginProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginProcess")
            .field("generation", &self.generation)
            .field("max_message_size", &self.max_message_size)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl PluginProcess {
    /// Launches and authenticates one generation using the native local IPC
    /// endpoint for the host operating system.
    pub async fn spawn(config: ProcessConfig, generation: u64) -> Result<Self, ProcessError> {
        #[cfg(unix)]
        {
            Self::spawn_unix(config, generation).await
        }
        #[cfg(windows)]
        {
            Self::spawn_windows(config, generation).await
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (config, generation);
            Err(ProcessError::UnsupportedPlatform)
        }
    }

    /// Launches and authenticates one generation over a private socket.
    #[allow(clippy::too_many_lines)]
    #[cfg(unix)]
    async fn spawn_unix(config: ProcessConfig, generation: u64) -> Result<Self, ProcessError> {
        if config.command.as_os_str().is_empty() {
            return Err(ProcessError::Io("plugin command is empty".into()));
        }
        let max_message_size = config.max_message_size.min(MAX_MESSAGE_SIZE as usize);
        if max_message_size == 0 {
            return Err(ProcessError::Io("plugin message limit is zero".into()));
        }
        if config.require_signed_manifest && config.manifest.is_none() {
            return Err(ProcessError::Io(
                "signed plugin manifest is required".into(),
            ));
        }
        if let Some(manifest) = &config.manifest {
            let digest = ExternalPluginManifest::executable_digest(&config.command)
                .map_err(|error| ProcessError::Io(format!("manifest: {error:?}")))?;
            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX);
            manifest
                .verify(
                    &config.trusted_manifest_keys,
                    &config.plugin_name,
                    digest,
                    &config.granted_capabilities,
                    config.sandbox_mode.as_str(),
                    now_ms,
                )
                .map_err(|error| ProcessError::Io(format!("manifest: {error:?}")))?;
        }
        let mut token = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut token);
        // Keep the sockaddr below SUN_LEN on macOS/Linux. The randomly named
        // directory is created with mode 0700 before the socket exists, so a
        // hostile local process cannot pre-create or replace our endpoint.
        let (socket_dir, socket_path) = private_socket_paths(generation)?;
        let shared_region = config
            .shared_memory_size
            .filter(|_| {
                config
                    .granted_capabilities
                    .iter()
                    .any(|capability| capability == "shared-memory")
            })
            .map(|size| SharedRegion::create(socket_dir.join("m"), size))
            .transpose()
            .map_err(|error| ProcessError::Io(format!("shared memory: {error:?}")))?;
        if let Some(region) = &shared_region {
            set_private_permissions(&region.descriptor().path)?;
        }
        let mut socket_guard = SocketGuard {
            path: socket_path.clone(),
            directory: socket_dir.clone(),
            keep: false,
        };
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .map_err(|error| ProcessError::Io(error.to_string()))?;
        set_private_permissions(&socket_path)?;

        let sandbox = SandboxPlan::prepare(
            config.command.clone(),
            config.args.clone(),
            &socket_dir,
            config.sandbox_mode,
        )
        .map_err(|error| ProcessError::Io(format!("sandbox: {error:?}")))?;
        let mut command = Command::new(&sandbox.program);
        command
            .args(&sandbox.args)
            .stderr(Stdio::inherit())
            .env_clear()
            .env("UMC_PLUGIN_SOCKET", &socket_path)
            .env("UMC_PLUGIN_TOKEN", hex_token(&token))
            .env("UMC_PLUGIN_NAME", &config.plugin_name)
            .kill_on_drop(true);
        let mut child_guard = ChildGuard(Some(
            command
                .spawn()
                .map_err(|error| ProcessError::Io(error.to_string()))?,
        ));
        let accepted = timeout(config.startup_deadline, listener.accept())
            .await
            .map_err(|_| ProcessError::StartupTimeout)?
            .map_err(|error| ProcessError::Io(error.to_string()));
        let (mut stream, _) = match accepted {
            Ok(value) => value,
            Err(error) => {
                return Err(error);
            }
        };
        let hello = read_envelope(&mut stream, max_message_size).await?;
        let Some(p::plugin_envelope::Body::PluginHello(plugin_hello)) = hello.body else {
            return Err(ProcessError::Handshake(HandshakeError::Protocol(
                "first message is not PLUGIN_HELLO".into(),
            )));
        };
        let daemon_hello = accept_plugin_hello(&plugin_hello, &token, &config.granted_capabilities)
            .map_err(ProcessError::Handshake)?;
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: daemon_hello.selected_version,
                sequence: hello.sequence,
                body: Some(p::plugin_envelope::Body::DaemonHello(daemon_hello.clone())),
            },
            max_message_size,
        )
        .await?;
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: daemon_hello.selected_version,
                sequence: hello.sequence.saturating_add(1),
                body: Some(p::plugin_envelope::Body::Config(p::PluginConfig {
                    config_blob: config.config_blob,
                    maximum_packet_size: config.maximum_packet_size,
                    shared_memory: shared_region
                        .as_ref()
                        .filter(|_| {
                            daemon_hello
                                .granted_capabilities
                                .iter()
                                .any(|capability| capability == "shared-memory")
                        })
                        .map(|region| {
                            let descriptor = region.descriptor();
                            p::SharedMemory {
                                path: descriptor.path.to_string_lossy().into_owned(),
                                size: descriptor.size as u64,
                                token: descriptor.token,
                            }
                        }),
                })),
            },
            max_message_size,
        )
        .await?;
        let ack = timeout(
            config.startup_deadline,
            read_envelope(&mut stream, max_message_size),
        )
        .await
        .map_err(|_| ProcessError::StartupTimeout)??;
        match ack.body {
            Some(p::plugin_envelope::Body::StartAck(value)) if value.started => {}
            _ => return Err(ProcessError::InvalidStartAck),
        }
        socket_guard.keep = true;
        let Some(child) = child_guard.0.take() else {
            return Err(ProcessError::Exit);
        };
        Ok(Self {
            child,
            stream: Box::new(stream),
            endpoint: socket_path,
            endpoint_dir: Some(socket_dir),
            token,
            generation,
            max_message_size,
            last_heartbeat: Instant::now(),
            next_operation: 1,
            events: VecDeque::new(),
            shared_region,
            shared_memory_threshold: config.shared_memory_threshold.max(1),
        })
    }

    /// Windows counterpart to `spawn_unix`, using a reject-remote named pipe.
    /// The random pipe name is only a locator; the launch-token proof remains
    /// mandatory authentication for every plugin generation.
    #[cfg(windows)]
    #[allow(clippy::too_many_lines)]
    async fn spawn_windows(config: ProcessConfig, generation: u64) -> Result<Self, ProcessError> {
        if config.command.as_os_str().is_empty() {
            return Err(ProcessError::Io("plugin command is empty".into()));
        }
        let max_message_size = config.max_message_size.min(MAX_MESSAGE_SIZE as usize);
        if max_message_size == 0 {
            return Err(ProcessError::Io("plugin message limit is zero".into()));
        }
        if config.require_signed_manifest && config.manifest.is_none() {
            return Err(ProcessError::Io(
                "signed plugin manifest is required".into(),
            ));
        }
        if let Some(manifest) = &config.manifest {
            let digest = ExternalPluginManifest::executable_digest(&config.command)
                .map_err(|error| ProcessError::Io(format!("manifest: {error:?}")))?;
            let now_ms = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
            )
            .unwrap_or(u64::MAX);
            manifest
                .verify(
                    &config.trusted_manifest_keys,
                    &config.plugin_name,
                    digest,
                    &config.granted_capabilities,
                    config.sandbox_mode.as_str(),
                    now_ms,
                )
                .map_err(|error| ProcessError::Io(format!("manifest: {error:?}")))?;
        }

        let mut token = vec![0u8; 32];
        rand_core::OsRng.fill_bytes(&mut token);
        let pipe_name = format!(
            r"\\.\pipe\umc-plugin-{}-{generation}",
            hex_token(&token[..12])
        );
        let private_root =
            std::env::temp_dir().join(format!("umc-plugin-{}", hex_token(&token[..8])));
        std::fs::create_dir(&private_root).map_err(|error| ProcessError::Io(error.to_string()))?;
        let mut root_guard = DirectoryGuard {
            path: private_root.clone(),
            keep: false,
        };
        let shared_region = config
            .shared_memory_size
            .filter(|_| {
                config
                    .granted_capabilities
                    .iter()
                    .any(|capability| capability == "shared-memory")
            })
            .map(|size| SharedRegion::create(private_root.join("m"), size))
            .transpose()
            .map_err(|error| ProcessError::Io(format!("shared memory: {error:?}")))?;
        let sandbox = SandboxPlan::prepare(
            config.command.clone(),
            config.args.clone(),
            &private_root,
            config.sandbox_mode,
        )
        .map_err(|error| ProcessError::Io(format!("sandbox: {error:?}")))?;
        let mut server = tokio::net::windows::named_pipe::ServerOptions::new();
        server.first_pipe_instance(true).reject_remote_clients(true);
        let server = server
            .create(&pipe_name)
            .map_err(|error| ProcessError::Io(error.to_string()))?;
        let mut command = Command::new(&sandbox.program);
        command
            .args(&sandbox.args)
            .env_clear()
            .env("UMC_PLUGIN_PIPE", &pipe_name)
            .env("UMC_PLUGIN_SOCKET", &pipe_name)
            .env("UMC_PLUGIN_TOKEN", hex_token(&token))
            .env("UMC_PLUGIN_NAME", &config.plugin_name)
            .kill_on_drop(true);
        let mut child_guard = ChildGuard(Some(
            command
                .spawn()
                .map_err(|error| ProcessError::Io(error.to_string()))?,
        ));
        let mut stream = server;
        timeout(config.startup_deadline, stream.connect())
            .await
            .map_err(|_| ProcessError::StartupTimeout)?
            .map_err(|error| ProcessError::Io(error.to_string()))?;
        let hello = read_envelope(&mut stream, max_message_size).await?;
        let Some(p::plugin_envelope::Body::PluginHello(plugin_hello)) = hello.body else {
            return Err(ProcessError::Handshake(HandshakeError::Protocol(
                "first message is not PLUGIN_HELLO".into(),
            )));
        };
        let daemon_hello = accept_plugin_hello(&plugin_hello, &token, &config.granted_capabilities)
            .map_err(ProcessError::Handshake)?;
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: daemon_hello.selected_version,
                sequence: hello.sequence,
                body: Some(p::plugin_envelope::Body::DaemonHello(daemon_hello.clone())),
            },
            max_message_size,
        )
        .await?;
        write_envelope(
            &mut stream,
            &p::PluginEnvelope {
                api_version: daemon_hello.selected_version,
                sequence: hello.sequence.saturating_add(1),
                body: Some(p::plugin_envelope::Body::Config(p::PluginConfig {
                    config_blob: config.config_blob,
                    maximum_packet_size: config.maximum_packet_size,
                    shared_memory: shared_region
                        .as_ref()
                        .filter(|_| {
                            daemon_hello
                                .granted_capabilities
                                .iter()
                                .any(|capability| capability == "shared-memory")
                        })
                        .map(|region| {
                            let descriptor = region.descriptor();
                            p::SharedMemory {
                                path: descriptor.path.to_string_lossy().into_owned(),
                                size: descriptor.size as u64,
                                token: descriptor.token,
                            }
                        }),
                })),
            },
            max_message_size,
        )
        .await?;
        let ack = timeout(
            config.startup_deadline,
            read_envelope(&mut stream, max_message_size),
        )
        .await
        .map_err(|_| ProcessError::StartupTimeout)??;
        match ack.body {
            Some(p::plugin_envelope::Body::StartAck(value)) if value.started => {}
            _ => return Err(ProcessError::InvalidStartAck),
        }
        root_guard.keep = true;
        let Some(child) = child_guard.0.take() else {
            return Err(ProcessError::Exit);
        };
        Ok(Self {
            child,
            stream: Box::new(stream),
            endpoint: PathBuf::from(pipe_name),
            endpoint_dir: Some(private_root),
            token,
            generation,
            max_message_size,
            last_heartbeat: Instant::now(),
            next_operation: 1,
            events: VecDeque::new(),
            shared_region,
            shared_memory_threshold: config.shared_memory_threshold.max(1),
        })
    }

    /// Send one heartbeat and require the matching acknowledgement.
    pub async fn heartbeat(&mut self) -> Result<(), ProcessError> {
        let sequence = self.generation;
        write_envelope(
            &mut self.stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                sequence,
                body: Some(p::plugin_envelope::Body::Heartbeat(p::Heartbeat {
                    sequence,
                })),
            },
            self.max_message_size,
        )
        .await?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProcessError::StartupTimeout);
            }
            let response = timeout(
                remaining,
                read_envelope(&mut self.stream, self.max_message_size),
            )
            .await
            .map_err(|_| ProcessError::StartupTimeout)??;
            match response.body {
                Some(p::plugin_envelope::Body::HeartbeatAck(value))
                    if value.sequence == sequence =>
                {
                    self.last_heartbeat = Instant::now();
                    return Ok(());
                }
                Some(p::plugin_envelope::Body::Event(event)) => self.queue_event(event)?,
                Some(p::plugin_envelope::Body::Heartbeat(heartbeat)) => {
                    self.write_heartbeat_ack(heartbeat.sequence).await?;
                }
                _ => return Err(ProcessError::Transport(TransportError::Decode)),
            }
        }
    }

    /// Issue one bounded operation after refreshing the process heartbeat.
    pub async fn operation_with_heartbeat(
        &mut self,
        op_type: p::OpType,
        handle: u64,
        arguments: Vec<u8>,
        deadline: Duration,
    ) -> Result<p::OpResp, ProcessError> {
        self.heartbeat().await?;
        self.operation(op_type, handle, arguments, deadline).await
    }

    #[must_use]
    pub fn heartbeat_expired(&self, timeout: Duration) -> bool {
        self.last_heartbeat.elapsed() >= timeout
    }

    /// Issue one bounded inline carrier operation and wait for its response.
    /// Event and heartbeat messages are consumed while waiting; a response
    /// with another operation id is a protocol error because this adapter is
    /// deliberately sequential and never permits unbounded in-flight work.
    pub async fn operation(
        &mut self,
        op_type: p::OpType,
        handle: u64,
        arguments: Vec<u8>,
        deadline: Duration,
    ) -> Result<p::OpResp, ProcessError> {
        let operation_id = self.next_operation;
        self.next_operation = self.next_operation.saturating_add(1);
        let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
        let mut arguments = arguments;
        let payload_ref = if arguments.len() >= self.shared_memory_threshold {
            if let Some(region) = self.shared_region.as_mut() {
                let reference = region
                    .write_reference(&arguments)
                    .map_err(|error| ProcessError::Io(format!("shared memory: {error:?}")))?;
                arguments.clear();
                Some(reference)
            } else {
                None
            }
        } else {
            None
        };
        write_envelope(
            &mut self.stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                sequence: operation_id,
                body: Some(p::plugin_envelope::Body::OpReq(p::OpReq {
                    operation_id,
                    op_type: op_type as i32,
                    handle,
                    arguments,
                    deadline_ms,
                    payload_ref,
                })),
            },
            self.max_message_size,
        )
        .await?;
        let deadline_at = Instant::now() + deadline;
        loop {
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProcessError::StartupTimeout);
            }
            let envelope = timeout(
                remaining,
                read_envelope(&mut self.stream, self.max_message_size),
            )
            .await
            .map_err(|_| ProcessError::StartupTimeout)??;
            match envelope.body {
                Some(p::plugin_envelope::Body::OpResp(mut response))
                    if response.operation_id == operation_id =>
                {
                    if response.result.is_empty() {
                        if let Some(reference) = response.payload_ref.take() {
                            let region = self.shared_region.as_ref().ok_or_else(|| {
                                ProcessError::Io(
                                    "plugin returned shared payload without region".into(),
                                )
                            })?;
                            response.result =
                                region.read_reference(&reference).map_err(|error| {
                                    ProcessError::Io(format!("shared memory: {error:?}"))
                                })?;
                        }
                    }
                    return Ok(response);
                }
                Some(p::plugin_envelope::Body::Event(event)) => self.queue_event(event)?,
                Some(p::plugin_envelope::Body::Heartbeat(heartbeat)) => {
                    self.write_heartbeat_ack(heartbeat.sequence).await?;
                }
                _ => return Err(ProcessError::Transport(TransportError::Decode)),
            }
        }
    }

    /// Wait for one plugin event, optionally filtering by link handle. Events
    /// are bounded so a malfunctioning plugin cannot grow daemon memory.
    pub async fn next_event(
        &mut self,
        wait: Duration,
        handle: Option<u64>,
        event_type: Option<p::EventType>,
    ) -> Result<p::PluginEvent, ProcessError> {
        let types = event_type.into_iter().collect::<Vec<_>>();
        self.next_event_types(wait, handle, &types).await
    }

    /// Wait for one event from an allow-list of event types. Events outside
    /// the allow-list remain queued for their owning listener/link/provider.
    pub async fn next_event_types(
        &mut self,
        wait: Duration,
        handle: Option<u64>,
        event_types: &[p::EventType],
    ) -> Result<p::PluginEvent, ProcessError> {
        let deadline = Instant::now() + wait;
        let matches_type = |event: &p::PluginEvent| {
            event_types.is_empty()
                || event_types
                    .iter()
                    .any(|expected| event.event_type == *expected as i32)
        };
        loop {
            if let Some(position) = self.events.iter().position(|event| {
                handle.map_or(true, |expected| event.handle == expected) && matches_type(event)
            }) {
                return self.events.remove(position).ok_or(ProcessError::Exit);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProcessError::StartupTimeout);
            }
            let envelope = timeout(
                remaining,
                read_envelope(&mut self.stream, self.max_message_size),
            )
            .await
            .map_err(|_| ProcessError::StartupTimeout)??;
            match envelope.body {
                Some(p::plugin_envelope::Body::Event(event)) => {
                    if handle.map_or(true, |expected| event.handle == expected)
                        && matches_type(&event)
                    {
                        return Ok(event);
                    }
                    self.queue_event(event)?;
                }
                Some(p::plugin_envelope::Body::Heartbeat(heartbeat)) => {
                    self.write_heartbeat_ack(heartbeat.sequence).await?;
                }
                _ => return Err(ProcessError::Transport(TransportError::Decode)),
            }
        }
    }

    fn queue_event(&mut self, event: p::PluginEvent) -> Result<(), ProcessError> {
        const MAX_EVENT_QUEUE: usize = 1024;
        if self.events.len() >= MAX_EVENT_QUEUE {
            return Err(ProcessError::EventQueueFull);
        }
        self.events.push_back(event);
        Ok(())
    }

    async fn write_heartbeat_ack(&mut self, sequence: u64) -> Result<(), ProcessError> {
        write_envelope(
            &mut self.stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                sequence,
                body: Some(p::plugin_envelope::Body::HeartbeatAck(p::HeartbeatAck {
                    sequence,
                })),
            },
            self.max_message_size,
        )
        .await
        .map_err(ProcessError::from)
    }

    /// Graceful GOAWAY/SHUTDOWN, followed by bounded process termination.
    pub async fn shutdown(&mut self, drain: Duration) -> Result<(), ProcessError> {
        let deadline = Instant::now() + drain;
        let _ = write_envelope(
            &mut self.stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                sequence: 0,
                body: Some(p::plugin_envelope::Body::Goaway(p::GoAway {
                    reason: "daemon shutdown".into(),
                    drain_deadline_ms: u64::try_from(drain.as_millis()).unwrap_or(u64::MAX),
                })),
            },
            self.max_message_size,
        )
        .await;
        let _ = write_envelope(
            &mut self.stream,
            &p::PluginEnvelope {
                api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                sequence: 1,
                body: Some(p::plugin_envelope::Body::Shutdown(p::Shutdown {})),
            },
            self.max_message_size,
        )
        .await;
        while Instant::now() < deadline {
            if self
                .child
                .try_wait()
                .map_err(|e| ProcessError::Io(e.to_string()))?
                .is_some()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.child
            .start_kill()
            .map_err(|e| ProcessError::Io(e.to_string()))?;
        Ok(())
    }

    /// Detect process/IPC failure without reviving old generation state.
    pub fn exited(&mut self) -> Result<bool, ProcessError> {
        self.child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(|error| ProcessError::Io(error.to_string()))
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.endpoint);
        }
        if let Some(region) = self.shared_region.take() {
            let path = region.descriptor().path;
            drop(region);
            let _ = std::fs::remove_file(path);
        }
        if let Some(directory) = &self.endpoint_dir {
            let _ = std::fs::remove_dir(directory);
        }
        self.token.fill(0);
    }
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<(), ProcessError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| ProcessError::Io(error.to_string()))
}

fn hex_token(token: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(token.len() * 2);
    for byte in token {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

#[cfg(unix)]
fn private_socket_paths(generation: u64) -> Result<(PathBuf, PathBuf), ProcessError> {
    use std::os::unix::fs::PermissionsExt;
    for _ in 0..8 {
        let mut random = [0u8; 6];
        rand_core::OsRng.fill_bytes(&mut random);
        let directory = PathBuf::from(format!("/tmp/umc-{}-{}", hex_token(&random), generation));
        match std::fs::create_dir(&directory) {
            Ok(()) => {
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .map_err(|error| ProcessError::Io(error.to_string()))?;
                return Ok((directory.clone(), directory.join("s")));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(ProcessError::Io(error.to_string())),
        }
    }
    Err(ProcessError::Io(
        "could not allocate private plugin socket".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_encoding_is_fixed_and_nonempty() {
        assert_eq!(hex_token(&[0xab, 0x01]), "ab01");
    }

    #[cfg(not(any(unix, windows)))]
    #[tokio::test]
    async fn unsupported_platform_fails_closed() {
        let result = PluginProcess::spawn(ProcessConfig::default(), 1).await;
        assert!(matches!(result, Err(ProcessError::UnsupportedPlatform)));
    }
}
