//! Bounded lifecycle and resource supervision for carrier plugins.
//!
//! The supervisor is deliberately transport-independent.  It is the daemon's
//! admission and cleanup contract for both the current trusted in-process
//! registry and a future subprocess/IPC loader: every generation gets fresh
//! handles and reservations, failures invalidate the whole generation, and
//! restart attempts are bounded by exponential backoff and a finite burst.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::OnceLock;
use std::time::Instant;

/// Default maximum framed IPC message from the carrier-plugin specification.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Default startup deadline from the carrier-plugin specification.
pub const DEFAULT_STARTUP_DEADLINE_MS: u64 = 10_000;
/// Default heartbeat timeout from the carrier-plugin specification.
pub const DEFAULT_HEARTBEAT_TIMEOUT_MS: u64 = 15_000;
/// Default maximum outstanding requests per plugin process.
pub const DEFAULT_MAX_OUTSTANDING_REQUESTS: u32 = 1_024;
/// Default maximum handles per plugin process.
pub const DEFAULT_MAX_HANDLES: u32 = 65_536;
/// Default shared-memory packet budget per plugin process.
pub const DEFAULT_MAX_SHARED_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
/// Default plugin log rate.
pub const DEFAULT_MAX_LOG_EVENTS_PER_SECOND: u32 = 100;
/// Default plugin log burst.
pub const DEFAULT_LOG_BURST: u32 = 1_000;
/// Default property-event rate per plugin process.
pub const DEFAULT_MAX_PROPERTY_EVENTS_PER_SECOND: u32 = 10_000;
/// Default consecutive restart burst.
pub const DEFAULT_RESTART_BURST: u32 = 3;
/// Default restart backoff cap (five minutes).
pub const DEFAULT_RESTART_BACKOFF_CAP_MS: u64 = 5 * 60 * 1_000;

/// Monotonic milliseconds suitable for lifecycle deadlines and backoff.
#[must_use]
pub fn monotonic_now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Per-plugin hard limits from `carrier-plugin-api.md` §26.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginLimits {
    pub max_message_bytes: usize,
    pub startup_deadline_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub max_outstanding_requests: u32,
    pub max_handles: u32,
    pub max_shared_memory_bytes: u64,
    pub max_log_events_per_second: u32,
    pub log_burst: u32,
    pub max_property_events_per_second: u32,
    pub restart_burst: u32,
    pub restart_backoff_cap_ms: u64,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            startup_deadline_ms: DEFAULT_STARTUP_DEADLINE_MS,
            heartbeat_timeout_ms: DEFAULT_HEARTBEAT_TIMEOUT_MS,
            max_outstanding_requests: DEFAULT_MAX_OUTSTANDING_REQUESTS,
            max_handles: DEFAULT_MAX_HANDLES,
            max_shared_memory_bytes: DEFAULT_MAX_SHARED_MEMORY_BYTES,
            max_log_events_per_second: DEFAULT_MAX_LOG_EVENTS_PER_SECOND,
            log_burst: DEFAULT_LOG_BURST,
            max_property_events_per_second: DEFAULT_MAX_PROPERTY_EVENTS_PER_SECOND,
            restart_burst: DEFAULT_RESTART_BURST,
            restart_backoff_cap_ms: DEFAULT_RESTART_BACKOFF_CAP_MS,
        }
    }
}

impl PluginLimits {
    /// Validates a hard-limit configuration before it becomes active.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::InvalidLimits`] when a limit is zero or the
    /// log burst is below the sustained rate.
    pub fn validate(self) -> Result<(), SupervisorError> {
        if self.max_message_bytes == 0
            || self.startup_deadline_ms == 0
            || self.heartbeat_timeout_ms == 0
            || self.max_outstanding_requests == 0
            || self.max_handles == 0
            || self.max_shared_memory_bytes == 0
            || self.max_log_events_per_second == 0
            || self.log_burst == 0
            || self.max_property_events_per_second == 0
            || self.restart_burst == 0
            || self.restart_backoff_cap_ms == 0
        {
            return Err(SupervisorError::InvalidLimits(
                "plugin limits must all be non-zero".into(),
            ));
        }
        if self.max_message_bytes > DEFAULT_MAX_MESSAGE_BYTES {
            return Err(SupervisorError::InvalidLimits(
                "message limit exceeds the protocol hard maximum".into(),
            ));
        }
        if self.log_burst < self.max_log_events_per_second {
            return Err(SupervisorError::InvalidLimits(
                "log burst must be at least the sustained log rate".into(),
            ));
        }
        Ok(())
    }
}

/// A process generation. Handles and operation permits cannot cross it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PluginGeneration {
    pub number: u64,
}

/// A generation-scoped opaque plugin handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PluginHandle {
    pub generation: PluginGeneration,
    pub value: u32,
}

/// A permit for one admitted operation. Dropping a permit does not release it;
/// callers must complete or cancel it explicitly so leaks remain observable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationPermit {
    plugin_id: String,
    generation: PluginGeneration,
    id: u64,
}

/// Lifecycle state exposed to diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    Registered,
    Starting,
    Running,
    Unhealthy,
    Restarting,
    Stopped,
    Disabled,
}

/// Failure classes that invalidate a plugin generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginFailure {
    ProcessExit,
    IpcClosed,
    HeartbeatTimeout,
    InvalidFraming,
    HandleConflict,
    DeadlineViolation,
    FatalError,
    InitFailure,
}

impl fmt::Display for PluginFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ProcessExit => "process_exit",
            Self::IpcClosed => "ipc_closed",
            Self::HeartbeatTimeout => "heartbeat_timeout",
            Self::InvalidFraming => "invalid_framing",
            Self::HandleConflict => "handle_conflict",
            Self::DeadlineViolation => "deadline_violation",
            Self::FatalError => "fatal_error",
            Self::InitFailure => "init_failure",
        };
        f.write_str(label)
    }
}

/// Resources for which a plugin can be denied before allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginResource {
    MessageBytes,
    OutstandingRequests,
    Handles,
    SharedMemoryBytes,
    LogEvents,
    PropertyEvents,
}

impl fmt::Display for PluginResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::MessageBytes => "message_bytes",
            Self::OutstandingRequests => "outstanding_requests",
            Self::Handles => "handles",
            Self::SharedMemoryBytes => "shared_memory_bytes",
            Self::LogEvents => "log_events",
            Self::PropertyEvents => "property_events",
        };
        f.write_str(label)
    }
}

/// Supervisor failures are intentionally non-sensitive and safe for logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorError {
    NotFound(String),
    AlreadyRegistered(String),
    InvalidLimits(String),
    InvalidState {
        expected: PluginState,
        actual: PluginState,
    },
    Disabled,
    Backoff {
        retry_at_ms: u64,
    },
    GenerationMismatch {
        expected: PluginGeneration,
        actual: PluginGeneration,
    },
    QuotaExceeded {
        resource: PluginResource,
        limit: u64,
    },
    MessageTooLarge {
        size: usize,
        limit: usize,
    },
    UnknownPermit,
    UnknownHandle,
    GenerationExhausted,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "plugin not found: {id}"),
            Self::AlreadyRegistered(id) => write!(f, "plugin already registered: {id}"),
            Self::InvalidLimits(reason) => write!(f, "invalid plugin limits: {reason}"),
            Self::InvalidState { expected, actual } => {
                write!(
                    f,
                    "invalid plugin state: expected {expected:?}, got {actual:?}"
                )
            }
            Self::Disabled => f.write_str("plugin disabled after repeated failures"),
            Self::Backoff { retry_at_ms } => {
                write!(f, "plugin restart backoff until {retry_at_ms}")
            }
            Self::GenerationMismatch { expected, actual } => {
                write!(
                    f,
                    "stale plugin generation: expected {expected:?}, got {actual:?}"
                )
            }
            Self::QuotaExceeded { resource, limit } => {
                write!(f, "plugin {resource} quota exceeded (limit {limit})")
            }
            Self::MessageTooLarge { size, limit } => {
                write!(f, "plugin message too large: {size} > {limit}")
            }
            Self::UnknownPermit => f.write_str("unknown or already completed operation permit"),
            Self::UnknownHandle => f.write_str("unknown or released plugin handle"),
            Self::GenerationExhausted => f.write_str("plugin generation counter exhausted"),
        }
    }
}

/// Result of a failure transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    Restart {
        attempt: u32,
        retry_at_ms: u64,
        backoff_ms: u64,
    },
    Disabled {
        attempts: u32,
    },
}

/// Bounded diagnostic snapshot for one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHealth {
    pub state: PluginState,
    pub generation: PluginGeneration,
    pub restart_attempts: u32,
    pub retry_at_ms: Option<u64>,
    pub outstanding_requests: u32,
    pub handles: u32,
    pub shared_memory_bytes: u64,
    pub last_failure: Option<PluginFailure>,
}

#[derive(Debug)]
struct PluginInstance {
    limits: PluginLimits,
    state: PluginState,
    generation: PluginGeneration,
    restart_attempts: u32,
    retry_at_ms: Option<u64>,
    outstanding_requests: u32,
    permits: HashSet<u64>,
    next_permit: u64,
    handles: HashSet<u32>,
    next_handle: u32,
    shared_memory_bytes: u64,
    started_at_ms: Option<u64>,
    last_heartbeat_ms: Option<u64>,
    log_tokens: u32,
    log_last_ms: u64,
    log_remainder: u64,
    property_window_ms: u64,
    property_events: u32,
    last_failure: Option<PluginFailure>,
}

impl PluginInstance {
    fn new(limits: PluginLimits) -> Self {
        Self {
            log_tokens: limits.log_burst,
            limits,
            state: PluginState::Registered,
            generation: PluginGeneration { number: 0 },
            restart_attempts: 0,
            retry_at_ms: None,
            outstanding_requests: 0,
            permits: HashSet::new(),
            next_permit: 0,
            handles: HashSet::new(),
            next_handle: 0,
            shared_memory_bytes: 0,
            started_at_ms: None,
            last_heartbeat_ms: None,
            log_last_ms: 0,
            log_remainder: 0,
            property_window_ms: 0,
            property_events: 0,
            last_failure: None,
        }
    }

    fn clear_generation_resources(&mut self) {
        self.outstanding_requests = 0;
        self.permits.clear();
        self.handles.clear();
        self.shared_memory_bytes = 0;
        self.started_at_ms = None;
        self.last_heartbeat_ms = None;
        self.next_handle = 0;
        self.log_tokens = self.limits.log_burst;
        self.log_last_ms = 0;
        self.log_remainder = 0;
        self.property_window_ms = 0;
        self.property_events = 0;
    }

    fn health(&self) -> PluginHealth {
        PluginHealth {
            state: self.state,
            generation: self.generation,
            restart_attempts: self.restart_attempts,
            retry_at_ms: self.retry_at_ms,
            outstanding_requests: self.outstanding_requests,
            handles: u32::try_from(self.handles.len()).unwrap_or(u32::MAX),
            shared_memory_bytes: self.shared_memory_bytes,
            last_failure: self.last_failure,
        }
    }
}

/// Daemon-owned supervisor for plugin generations and quotas.
#[derive(Debug, Default)]
pub struct PluginSupervisor {
    plugins: HashMap<String, PluginInstance>,
}

impl PluginSupervisor {
    /// Registers a plugin before its first generation is launched.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::InvalidLimits`] for an invalid quota set or
    /// [`SupervisorError::AlreadyRegistered`] for a duplicate id.
    pub fn register(
        &mut self,
        id: impl Into<String>,
        limits: PluginLimits,
    ) -> Result<(), SupervisorError> {
        limits.validate()?;
        let id = id.into();
        if self.plugins.contains_key(&id) {
            return Err(SupervisorError::AlreadyRegistered(id));
        }
        self.plugins.insert(id, PluginInstance::new(limits));
        Ok(())
    }

    /// Starts a generation using the supervisor's monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, backoff, or generation error when the plugin is
    /// not ready to start.
    pub fn start(&mut self, id: &str) -> Result<PluginGeneration, SupervisorError> {
        self.start_at(id, monotonic_now_ms())
    }

    /// Starts a generation at a caller-supplied monotonic millisecond time.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle, backoff, disabled, or generation error when the
    /// plugin is not ready to start.
    pub fn start_at(&mut self, id: &str, now_ms: u64) -> Result<PluginGeneration, SupervisorError> {
        let instance = self.instance_mut(id)?;
        match instance.state {
            PluginState::Disabled => return Err(SupervisorError::Disabled),
            PluginState::Starting | PluginState::Running => {
                return Err(SupervisorError::InvalidState {
                    expected: PluginState::Stopped,
                    actual: instance.state,
                });
            }
            PluginState::Restarting => {
                if now_ms < instance.retry_at_ms.unwrap_or(now_ms) {
                    return Err(SupervisorError::Backoff {
                        retry_at_ms: instance.retry_at_ms.unwrap_or(now_ms),
                    });
                }
            }
            PluginState::Registered | PluginState::Unhealthy | PluginState::Stopped => {}
        }
        let next = instance
            .generation
            .number
            .checked_add(1)
            .ok_or(SupervisorError::GenerationExhausted)?;
        instance.generation = PluginGeneration { number: next };
        instance.clear_generation_resources();
        instance.started_at_ms = Some(now_ms);
        instance.last_heartbeat_ms = Some(now_ms);
        instance.retry_at_ms = None;
        instance.state = PluginState::Starting;
        Ok(instance.generation)
    }

    /// Marks a started generation ready to receive operations.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::GenerationMismatch`] or
    /// [`SupervisorError::InvalidState`] when the generation is stale or was
    /// not in startup.
    pub fn ready(&mut self, id: &str, generation: PluginGeneration) -> Result<(), SupervisorError> {
        self.ready_at(id, generation, monotonic_now_ms())
    }

    /// Marks a started generation ready at a caller-supplied monotonic time.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::GenerationMismatch`] or
    /// [`SupervisorError::InvalidState`] when the generation is stale or was
    /// not in startup.
    pub fn ready_at(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        now_ms: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, generation)?;
        if instance.state != PluginState::Starting {
            return Err(SupervisorError::InvalidState {
                expected: PluginState::Starting,
                actual: instance.state,
            });
        }
        instance.state = PluginState::Running;
        instance.started_at_ms = None;
        instance.last_heartbeat_ms = Some(now_ms);
        Ok(())
    }

    /// Stops a generation and releases every live reservation and handle.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::GenerationMismatch`] when the generation is
    /// stale or unknown.
    pub fn stop(&mut self, id: &str, generation: PluginGeneration) -> Result<(), SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, generation)?;
        instance.clear_generation_resources();
        instance.retry_at_ms = None;
        instance.state = PluginState::Stopped;
        Ok(())
    }

    /// Records a heartbeat from a running generation.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error for a stale or non-running generation.
    pub fn heartbeat(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        now_ms: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        instance.last_heartbeat_ms = Some(now_ms);
        Ok(())
    }

    /// Checks startup and heartbeat deadlines and invalidates an unhealthy
    /// generation. The caller supplies restart jitter from its entropy source.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle error for a stale generation or a restart-policy
    /// error if failure handling cannot proceed.
    pub fn poll_at(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        now_ms: u64,
        jitter_ms: u64,
    ) -> Result<Option<RestartDecision>, SupervisorError> {
        let (failure, expired) = {
            let instance = self.instance(id)?;
            Self::check_generation(instance, generation)?;
            match instance.state {
                PluginState::Starting => (
                    PluginFailure::DeadlineViolation,
                    instance.started_at_ms.is_some_and(|started| {
                        now_ms.saturating_sub(started) >= instance.limits.startup_deadline_ms
                    }),
                ),
                PluginState::Running => (
                    PluginFailure::HeartbeatTimeout,
                    instance.last_heartbeat_ms.is_some_and(|heartbeat| {
                        now_ms.saturating_sub(heartbeat) >= instance.limits.heartbeat_timeout_ms
                    }),
                ),
                _ => return Ok(None),
            }
        };
        if expired {
            return self
                .fail_at(id, generation, failure, now_ms, jitter_ms)
                .map(Some);
        }
        Ok(None)
    }

    /// Invalidates all generation-owned state after a process or protocol failure.
    /// `jitter_ms` is supplied by the daemon's entropy source and is capped by
    /// the configured backoff cap.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::GenerationMismatch`] or
    /// [`SupervisorError::InvalidState`] when the failed generation is stale
    /// or already stopped.
    pub fn fail_at(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        failure: PluginFailure,
        now_ms: u64,
        jitter_ms: u64,
    ) -> Result<RestartDecision, SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, generation)?;
        if !matches!(instance.state, PluginState::Starting | PluginState::Running) {
            return Err(SupervisorError::InvalidState {
                expected: PluginState::Running,
                actual: instance.state,
            });
        }
        instance.state = PluginState::Unhealthy;
        instance.last_failure = Some(failure);
        instance.clear_generation_resources();
        instance.restart_attempts = instance.restart_attempts.saturating_add(1);
        if instance.restart_attempts > instance.limits.restart_burst {
            instance.retry_at_ms = None;
            instance.state = PluginState::Disabled;
            return Ok(RestartDecision::Disabled {
                attempts: instance.restart_attempts,
            });
        }
        let exponent = instance.restart_attempts.saturating_sub(1).min(62);
        let base = 1_000_u64.saturating_mul(1_u64 << exponent);
        let backoff_ms = base
            .saturating_add(jitter_ms)
            .min(instance.limits.restart_backoff_cap_ms);
        let retry_at_ms = now_ms.saturating_add(backoff_ms);
        instance.retry_at_ms = Some(retry_at_ms);
        instance.state = PluginState::Restarting;
        Ok(RestartDecision::Restart {
            attempt: instance.restart_attempts,
            retry_at_ms,
            backoff_ms,
        })
    }

    /// Admits one bounded IPC operation and returns a generation-scoped permit.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::MessageTooLarge`],
    /// [`SupervisorError::QuotaExceeded`], or a lifecycle error before any
    /// reservation is made.
    pub fn begin_operation(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        message_bytes: usize,
    ) -> Result<OperationPermit, SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        if message_bytes > instance.limits.max_message_bytes {
            return Err(SupervisorError::MessageTooLarge {
                size: message_bytes,
                limit: instance.limits.max_message_bytes,
            });
        }
        if instance.outstanding_requests >= instance.limits.max_outstanding_requests {
            return Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::OutstandingRequests,
                limit: u64::from(instance.limits.max_outstanding_requests),
            });
        }
        let permit_id = instance.next_permit;
        instance.next_permit = instance
            .next_permit
            .checked_add(1)
            .ok_or(SupervisorError::GenerationExhausted)?;
        instance.permits.insert(permit_id);
        instance.outstanding_requests += 1;
        Ok(OperationPermit {
            plugin_id: id.to_string(),
            generation,
            id: permit_id,
        })
    }

    /// Completes or cancels one operation permit.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::UnknownPermit`] for a duplicate completion
    /// or [`SupervisorError::GenerationMismatch`] after a crash/restart.
    pub fn finish_operation(&mut self, permit: &OperationPermit) -> Result<(), SupervisorError> {
        let instance = self.instance_mut(&permit.plugin_id)?;
        Self::check_generation(instance, permit.generation)?;
        if !instance.permits.remove(&permit.id) {
            return Err(SupervisorError::UnknownPermit);
        }
        instance.outstanding_requests = instance.outstanding_requests.saturating_sub(1);
        Ok(())
    }

    /// Reserves shared-memory packet bytes before handing them to a plugin.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::QuotaExceeded`] when the hard byte budget
    /// would be exceeded, or a lifecycle error for a stale generation.
    pub fn reserve_shared_memory(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        bytes: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        let next = instance.shared_memory_bytes.saturating_add(bytes);
        if next > instance.limits.max_shared_memory_bytes {
            return Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::SharedMemoryBytes,
                limit: instance.limits.max_shared_memory_bytes,
            });
        }
        instance.shared_memory_bytes = next;
        Ok(())
    }

    /// Releases previously reserved shared-memory bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::GenerationMismatch`] for a stale
    /// generation.
    pub fn release_shared_memory(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        bytes: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, generation)?;
        instance.shared_memory_bytes = instance.shared_memory_bytes.saturating_sub(bytes);
        Ok(())
    }

    /// Allocates a generation-scoped handle.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::QuotaExceeded`] when the handle budget is
    /// full, or a lifecycle error for a stale generation.
    pub fn allocate_handle(
        &mut self,
        id: &str,
        generation: PluginGeneration,
    ) -> Result<PluginHandle, SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        if u32::try_from(instance.handles.len()).unwrap_or(u32::MAX) >= instance.limits.max_handles
        {
            return Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::Handles,
                limit: u64::from(instance.limits.max_handles),
            });
        }
        let value = instance
            .next_handle
            .checked_add(1)
            .ok_or(SupervisorError::UnknownHandle)?;
        instance.next_handle = value;
        instance.handles.insert(value);
        Ok(PluginHandle { generation, value })
    }

    /// Releases a handle. Old-generation handles fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::UnknownHandle`] for an already released
    /// handle or [`SupervisorError::GenerationMismatch`] for an old one.
    pub fn release_handle(
        &mut self,
        id: &str,
        handle: PluginHandle,
    ) -> Result<(), SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, handle.generation)?;
        if !instance.handles.remove(&handle.value) {
            return Err(SupervisorError::UnknownHandle);
        }
        Ok(())
    }

    /// Checks that a handle is live in the current generation.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::UnknownHandle`] or
    /// [`SupervisorError::GenerationMismatch`] when the handle is not live.
    pub fn validate_handle(&self, id: &str, handle: PluginHandle) -> Result<(), SupervisorError> {
        let instance = self.instance(id)?;
        Self::check_generation(instance, handle.generation)?;
        if !instance.handles.contains(&handle.value) {
            return Err(SupervisorError::UnknownHandle);
        }
        Ok(())
    }

    /// Accounts one plugin log event using a bounded token bucket.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::QuotaExceeded`] when the burst is empty or
    /// a lifecycle error for a stale generation.
    pub fn record_log_event(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        now_ms: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        let elapsed = now_ms.saturating_sub(instance.log_last_ms);
        let produced = elapsed
            .saturating_mul(u64::from(instance.limits.max_log_events_per_second))
            .saturating_add(instance.log_remainder);
        let refill = produced / 1_000;
        instance.log_remainder = produced % 1_000;
        instance.log_tokens = instance
            .log_tokens
            .saturating_add(u32::try_from(refill).unwrap_or(u32::MAX))
            .min(instance.limits.log_burst);
        instance.log_last_ms = now_ms;
        if instance.log_tokens == 0 {
            return Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::LogEvents,
                limit: u64::from(instance.limits.log_burst),
            });
        }
        instance.log_tokens -= 1;
        Ok(())
    }

    /// Accounts one property event against the per-second process cap.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::QuotaExceeded`] when the one-second cap is
    /// exhausted, or a lifecycle error for a stale generation.
    pub fn record_property_event(
        &mut self,
        id: &str,
        generation: PluginGeneration,
        now_ms: u64,
    ) -> Result<(), SupervisorError> {
        let instance = self.running_instance(id, generation)?;
        if now_ms.saturating_sub(instance.property_window_ms) >= 1_000 {
            instance.property_window_ms = now_ms;
            instance.property_events = 0;
        }
        if instance.property_events >= instance.limits.max_property_events_per_second {
            return Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::PropertyEvents,
                limit: u64::from(instance.limits.max_property_events_per_second),
            });
        }
        instance.property_events += 1;
        Ok(())
    }

    /// Returns bounded diagnostics for one plugin.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorError::NotFound`] when the id is not registered.
    pub fn health(&self, id: &str) -> Result<PluginHealth, SupervisorError> {
        Ok(self.instance(id)?.health())
    }

    /// Returns whether a plugin is registered.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.plugins.contains_key(id)
    }

    fn instance(&self, id: &str) -> Result<&PluginInstance, SupervisorError> {
        self.plugins
            .get(id)
            .ok_or_else(|| SupervisorError::NotFound(id.to_string()))
    }

    fn instance_mut(&mut self, id: &str) -> Result<&mut PluginInstance, SupervisorError> {
        self.plugins
            .get_mut(id)
            .ok_or_else(|| SupervisorError::NotFound(id.to_string()))
    }

    fn check_generation(
        instance: &PluginInstance,
        generation: PluginGeneration,
    ) -> Result<(), SupervisorError> {
        if instance.generation != generation {
            return Err(SupervisorError::GenerationMismatch {
                expected: instance.generation,
                actual: generation,
            });
        }
        Ok(())
    }

    fn running_instance(
        &mut self,
        id: &str,
        generation: PluginGeneration,
    ) -> Result<&mut PluginInstance, SupervisorError> {
        let instance = self.instance_mut(id)?;
        Self::check_generation(instance, generation)?;
        if instance.state != PluginState::Running {
            return Err(SupervisorError::InvalidState {
                expected: PluginState::Running,
                actual: instance.state,
            });
        }
        Ok(instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supervisor_with_limits(limits: PluginLimits) -> (PluginSupervisor, PluginGeneration) {
        let mut supervisor = PluginSupervisor::default();
        supervisor
            .register("carrier.test", limits)
            .expect("register");
        let generation = supervisor.start_at("carrier.test", 0).expect("start");
        supervisor.ready("carrier.test", generation).expect("ready");
        (supervisor, generation)
    }

    #[test]
    fn generation_failure_invalidates_permits_handles_and_bytes() {
        let (mut supervisor, generation) = supervisor_with_limits(PluginLimits::default());
        let permit = supervisor
            .begin_operation("carrier.test", generation, 8)
            .expect("permit");
        let handle = supervisor
            .allocate_handle("carrier.test", generation)
            .expect("handle");
        supervisor
            .reserve_shared_memory("carrier.test", generation, 64)
            .expect("bytes");

        let decision = supervisor
            .fail_at(
                "carrier.test",
                generation,
                PluginFailure::ProcessExit,
                10,
                25,
            )
            .expect("failure");
        assert_eq!(
            decision,
            RestartDecision::Restart {
                attempt: 1,
                retry_at_ms: 1_035,
                backoff_ms: 1_025,
            }
        );
        assert_eq!(
            supervisor.health("carrier.test").expect("health"),
            PluginHealth {
                state: PluginState::Restarting,
                generation,
                restart_attempts: 1,
                retry_at_ms: Some(1_035),
                outstanding_requests: 0,
                handles: 0,
                shared_memory_bytes: 0,
                last_failure: Some(PluginFailure::ProcessExit),
            }
        );
        assert!(matches!(
            supervisor.finish_operation(&permit),
            Err(SupervisorError::UnknownPermit)
        ));
        assert!(matches!(
            supervisor.validate_handle("carrier.test", handle),
            Err(SupervisorError::UnknownHandle)
        ));
    }

    #[test]
    fn restart_backoff_and_burst_disable_repeated_crashes() {
        let limits = PluginLimits {
            restart_burst: 2,
            ..PluginLimits::default()
        };
        let (mut supervisor, mut generation) = supervisor_with_limits(limits);
        let first = supervisor
            .fail_at("carrier.test", generation, PluginFailure::IpcClosed, 0, 0)
            .expect("first failure");
        assert!(matches!(
            first,
            RestartDecision::Restart {
                backoff_ms: 1_000,
                ..
            }
        ));
        assert!(matches!(
            supervisor.start_at("carrier.test", 999),
            Err(SupervisorError::Backoff { retry_at_ms: 1_000 })
        ));
        generation = supervisor.start_at("carrier.test", 1_000).expect("restart");
        supervisor.ready("carrier.test", generation).expect("ready");
        let second = supervisor
            .fail_at(
                "carrier.test",
                generation,
                PluginFailure::IpcClosed,
                1_000,
                0,
            )
            .expect("second failure");
        assert!(matches!(
            second,
            RestartDecision::Restart {
                backoff_ms: 2_000,
                ..
            }
        ));
        generation = supervisor.start_at("carrier.test", 3_000).expect("restart");
        supervisor.ready("carrier.test", generation).expect("ready");
        let third = supervisor
            .fail_at(
                "carrier.test",
                generation,
                PluginFailure::IpcClosed,
                3_000,
                0,
            )
            .expect("third failure");
        assert_eq!(third, RestartDecision::Disabled { attempts: 3 });
        assert_eq!(
            supervisor.health("carrier.test").expect("health").state,
            PluginState::Disabled
        );
    }

    #[test]
    fn operation_and_handle_quotas_reject_before_growth() {
        let limits = PluginLimits {
            max_message_bytes: 4,
            max_outstanding_requests: 1,
            max_handles: 1,
            max_shared_memory_bytes: 8,
            ..PluginLimits::default()
        };
        let (mut supervisor, generation) = supervisor_with_limits(limits);
        let permit = supervisor
            .begin_operation("carrier.test", generation, 4)
            .expect("first operation");
        assert!(matches!(
            supervisor.begin_operation("carrier.test", generation, 1),
            Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::OutstandingRequests,
                limit: 1
            })
        ));
        assert!(matches!(
            supervisor.begin_operation("carrier.test", generation, 5),
            Err(SupervisorError::MessageTooLarge { size: 5, limit: 4 })
        ));
        supervisor.finish_operation(&permit).expect("finish");
        supervisor
            .allocate_handle("carrier.test", generation)
            .expect("handle");
        assert!(matches!(
            supervisor.allocate_handle("carrier.test", generation),
            Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::Handles,
                limit: 1
            })
        ));
        supervisor
            .reserve_shared_memory("carrier.test", generation, 8)
            .expect("bytes");
        assert!(matches!(
            supervisor.reserve_shared_memory("carrier.test", generation, 1),
            Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::SharedMemoryBytes,
                limit: 8
            })
        ));
    }

    #[test]
    fn restarted_generation_rejects_old_handles() {
        let (mut supervisor, generation) = supervisor_with_limits(PluginLimits::default());
        let handle = supervisor
            .allocate_handle("carrier.test", generation)
            .expect("handle");
        supervisor
            .fail_at(
                "carrier.test",
                generation,
                PluginFailure::HeartbeatTimeout,
                0,
                0,
            )
            .expect("failure");
        let restarted = supervisor.start_at("carrier.test", 1_000).expect("restart");
        supervisor.ready("carrier.test", restarted).expect("ready");
        assert_ne!(generation, restarted);
        assert!(matches!(
            supervisor.validate_handle("carrier.test", handle),
            Err(SupervisorError::GenerationMismatch { .. })
        ));
    }

    #[test]
    fn limits_cannot_raise_protocol_message_maximum() {
        let limits = PluginLimits {
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES + 1,
            ..PluginLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(SupervisorError::InvalidLimits(reason))
                if reason.contains("protocol hard maximum")
        ));
    }

    #[test]
    fn startup_and_heartbeat_deadlines_fail_closed() {
        let limits = PluginLimits {
            startup_deadline_ms: 10,
            heartbeat_timeout_ms: 20,
            ..PluginLimits::default()
        };
        let mut supervisor = PluginSupervisor::default();
        supervisor
            .register("carrier.test", limits)
            .expect("register");
        let generation = supervisor.start_at("carrier.test", 100).expect("start");
        assert_eq!(
            supervisor
                .poll_at("carrier.test", generation, 109, 0)
                .expect("poll"),
            None
        );
        let decision = supervisor
            .poll_at("carrier.test", generation, 110, 0)
            .expect("startup timeout")
            .expect("restart decision");
        assert!(matches!(decision, RestartDecision::Restart { .. }));

        let restarted = supervisor.start_at("carrier.test", 1_110).expect("restart");
        supervisor
            .ready_at("carrier.test", restarted, 1_110)
            .expect("ready");
        supervisor
            .heartbeat("carrier.test", restarted, 1_120)
            .expect("heartbeat");
        assert_eq!(
            supervisor
                .poll_at("carrier.test", restarted, 1_139, 0)
                .expect("poll"),
            None
        );
        let decision = supervisor
            .poll_at("carrier.test", restarted, 1_140, 0)
            .expect("heartbeat timeout")
            .expect("restart decision");
        assert!(matches!(decision, RestartDecision::Restart { .. }));
    }

    #[test]
    fn log_and_property_rates_are_bounded_and_refill() {
        let limits = PluginLimits {
            max_log_events_per_second: 2,
            log_burst: 2,
            max_property_events_per_second: 2,
            ..PluginLimits::default()
        };
        let (mut supervisor, generation) = supervisor_with_limits(limits);
        supervisor
            .record_log_event("carrier.test", generation, 0)
            .expect("log");
        supervisor
            .record_log_event("carrier.test", generation, 0)
            .expect("log");
        assert!(matches!(
            supervisor.record_log_event("carrier.test", generation, 0),
            Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::LogEvents,
                ..
            })
        ));
        supervisor
            .record_log_event("carrier.test", generation, 1_000)
            .expect("refill");
        supervisor
            .record_property_event("carrier.test", generation, 0)
            .expect("property");
        supervisor
            .record_property_event("carrier.test", generation, 0)
            .expect("property");
        assert!(matches!(
            supervisor.record_property_event("carrier.test", generation, 0),
            Err(SupervisorError::QuotaExceeded {
                resource: PluginResource::PropertyEvents,
                ..
            })
        ));
        supervisor
            .record_property_event("carrier.test", generation, 1_000)
            .expect("refill");
    }
}
