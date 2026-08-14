//! Bounded application-owned session, stream, and datagram state.
//!
//! The wire session remains authoritative for transport state. This module
//! owns only the local API view: opaque handles, ownership, pending accepts,
//! and bounded application queues.

use std::collections::{HashMap, VecDeque};

pub const MAX_APPLICATION_STREAM_BUFFER_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_APPLICATION_DATAGRAM_QUEUE: usize = 256;
pub const MAX_APPLICATION_DATAGRAM_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_APPLICATION_PENDING_SESSIONS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationDataError {
    NotFound,
    PermissionDenied,
    Pending,
    AlreadyAccepted,
    QueueFull,
    InvalidArgument,
    WouldBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRead {
    pub data: Vec<u8>,
    pub eof: bool,
    pub reset: bool,
    pub application_error_code: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramRead {
    pub context_id: u64,
    pub data: Vec<u8>,
    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSnapshot {
    pub handle: Vec<u8>,
    pub session_id: u64,
    pub stream_id: u64,
    pub principal_id: u64,
    pub pending: bool,
    pub send_closed: bool,
    pub eof: bool,
    pub reset_error: Option<u64>,
    pub queued_bytes: usize,
}

#[derive(Debug, Clone)]
struct ListenerRecord {
    protocol_id: Vec<u8>,
    application_handle: Vec<u8>,
    principal_id: u64,
    connection_id: Vec<u8>,
    max_pending_sessions: usize,
}

#[derive(Debug, Clone)]
struct SessionRecord {
    application_handle: Vec<u8>,
    principal_id: u64,
    connection_id: Vec<u8>,
    pending: bool,
}

#[derive(Debug, Clone)]
struct StreamRecord {
    session_id: u64,
    stream_id: u64,
    application_handle: Vec<u8>,
    principal_id: u64,
    connection_id: Vec<u8>,
    protocol_id: Vec<u8>,
    pending: bool,
    send_closed: bool,
    eof: bool,
    reset_error: Option<u64>,
    queued_bytes: usize,
    queued: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct DatagramRecord {
    context_id: u64,
    data: Vec<u8>,
    expired: bool,
}

#[derive(Debug, Clone, Default)]
struct DatagramQueue {
    bytes: usize,
    entries: VecDeque<DatagramRecord>,
}

/// Local application data-plane registry. Every mutating operation checks the
/// principal and control-connection generation supplied by the dispatcher.
#[derive(Debug, Default)]
pub struct ApplicationDataPlane {
    listeners: Vec<ListenerRecord>,
    sessions: HashMap<u64, SessionRecord>,
    streams: HashMap<Vec<u8>, StreamRecord>,
    stream_by_session_id: HashMap<(u64, u64), Vec<u8>>,
    pending_sessions: VecDeque<u64>,
    pending_streams: VecDeque<Vec<u8>>,
    datagrams: HashMap<u64, DatagramQueue>,
    next_handle: u64,
    next_datagram_id: u64,
}

impl ApplicationDataPlane {
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_handle: 1,
            next_datagram_id: 1,
            ..Self::default()
        }
    }

    /// Register one open listener. Duplicate bindings are rejected by the
    /// outer application registry; this table retains ownership metadata.
    #[cfg(test)]
    pub fn register_listener(
        &mut self,
        protocol_id: Vec<u8>,
        application_handle: Vec<u8>,
        principal_id: u64,
        connection_id: Vec<u8>,
    ) {
        self.register_listener_with_limit(
            protocol_id,
            application_handle,
            principal_id,
            connection_id,
            MAX_APPLICATION_PENDING_SESSIONS,
        );
    }

    /// Register a listener with an application-requested pending-session
    /// bound. A zero limit is invalid at the API layer; this table clamps
    /// excessively large requests to the daemon-wide resource maximum.
    pub fn register_listener_with_limit(
        &mut self,
        protocol_id: Vec<u8>,
        application_handle: Vec<u8>,
        principal_id: u64,
        connection_id: Vec<u8>,
        max_pending_sessions: usize,
    ) {
        self.listeners.retain(|listener| {
            listener.application_handle != application_handle || listener.protocol_id != protocol_id
        });
        self.listeners.push(ListenerRecord {
            protocol_id,
            application_handle,
            principal_id,
            connection_id,
            max_pending_sessions: max_pending_sessions.clamp(1, MAX_APPLICATION_PENDING_SESSIONS),
        });
    }

    pub fn remove_listener(&mut self, application_handle: &[u8]) {
        self.listeners
            .retain(|listener| listener.application_handle.as_slice() != application_handle);
    }

    pub fn remove_application(&mut self, application_handle: &[u8]) {
        self.remove_listener(application_handle);
        self.streams
            .retain(|_, stream| stream.application_handle.as_slice() != application_handle);
        self.stream_by_session_id
            .retain(|_, handle| self.streams.contains_key(handle));
        let sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.application_handle.as_slice() == application_handle)
            .map(|(session_id, _)| *session_id)
            .collect();
        for session_id in sessions {
            self.remove_session(session_id);
        }
    }

    /// Return sessions owned by an application before its registration is
    /// removed. The caller uses these ids to cancel transport tasks according
    /// to the registration/connection cleanup policy.
    pub fn session_ids_for_application(&self, application_handle: &[u8]) -> Vec<u64> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.application_handle.as_slice() == application_handle)
            .map(|(session_id, _)| *session_id)
            .collect()
    }

    pub fn remove_connection(&mut self, connection_id: &[u8]) {
        let apps: Vec<Vec<u8>> = self
            .listeners
            .iter()
            .filter(|listener| listener.connection_id.as_slice() == connection_id)
            .map(|listener| listener.application_handle.clone())
            .collect();
        for app in apps {
            self.remove_application(&app);
        }
        let sessions: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.connection_id.as_slice() == connection_id)
            .map(|(id, _)| *id)
            .collect();
        for session_id in sessions {
            self.remove_session(session_id);
        }
    }

    /// Rebind every local data-plane record owned by an application to a new
    /// control connection. This is used only after the registration layer has
    /// authenticated a resumable principal and instance id.
    pub fn rebind_application(
        &mut self,
        application_handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        if self.listeners.iter().any(|listener| {
            listener.application_handle.as_slice() == application_handle
                && listener.principal_id != principal_id
        }) || self.sessions.values().any(|session| {
            session.application_handle.as_slice() == application_handle
                && session.principal_id != principal_id
        }) || self.streams.values().any(|stream| {
            stream.application_handle.as_slice() == application_handle
                && stream.principal_id != principal_id
        }) {
            return Err(ApplicationDataError::PermissionDenied);
        }
        for listener in &mut self.listeners {
            if listener.application_handle.as_slice() == application_handle {
                listener.connection_id = connection_id.to_vec();
            }
        }
        for session in self.sessions.values_mut() {
            if session.application_handle.as_slice() == application_handle {
                session.connection_id = connection_id.to_vec();
            }
        }
        for stream in self.streams.values_mut() {
            if stream.application_handle.as_slice() == application_handle {
                stream.connection_id = connection_id.to_vec();
            }
        }
        Ok(())
    }

    pub fn remove_session(&mut self, session_id: u64) {
        self.sessions.remove(&session_id);
        self.datagrams.remove(&session_id);
        let handles: Vec<Vec<u8>> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.session_id == session_id)
            .map(|(handle, _)| handle.clone())
            .collect();
        for handle in handles {
            self.streams.remove(&handle);
        }
        self.stream_by_session_id
            .retain(|(id, _), _| *id != session_id);
        self.pending_sessions.retain(|id| *id != session_id);
        self.pending_streams
            .retain(|handle| self.streams.contains_key(handle));
    }

    /// Bind a live session to an application. A second owner is rejected.
    #[cfg(test)]
    pub fn bind_session(
        &mut self,
        session_id: u64,
        connection_id: Vec<u8>,
        application_handle: Vec<u8>,
    ) {
        self.sessions.insert(
            session_id,
            SessionRecord {
                application_handle,
                principal_id: 0,
                connection_id,
                pending: false,
            },
        );
    }

    pub fn bind_session_owned(
        &mut self,
        session_id: u64,
        connection_id: Vec<u8>,
        application_handle: Vec<u8>,
        principal_id: u64,
        pending: bool,
    ) -> Result<(), ApplicationDataError> {
        if let Some(existing) = self.sessions.get(&session_id) {
            if existing.application_handle != application_handle
                || existing.principal_id != principal_id
                || existing.connection_id != connection_id
            {
                return Err(ApplicationDataError::PermissionDenied);
            }
            return Ok(());
        }
        self.sessions.insert(
            session_id,
            SessionRecord {
                application_handle,
                principal_id,
                connection_id,
                pending,
            },
        );
        if pending {
            self.pending_sessions.push_back(session_id);
        }
        Ok(())
    }

    /// Open an application-owned stream record for a live session.
    pub fn open_stream(
        &mut self,
        principal_id: u64,
        connection_id: Vec<u8>,
        application_handle: Vec<u8>,
        session_id: u64,
        stream_id: u64,
        protocol_id: Vec<u8>,
    ) -> Result<Vec<u8>, ApplicationDataError> {
        self.bind_session_owned(
            session_id,
            connection_id.clone(),
            application_handle.clone(),
            principal_id,
            false,
        )?;
        let key = (session_id, stream_id);
        if self.stream_by_session_id.contains_key(&key) {
            return Err(ApplicationDataError::AlreadyAccepted);
        }
        let handle = self.allocate_handle();
        self.stream_by_session_id.insert(key, handle.clone());
        self.streams.insert(
            handle.clone(),
            StreamRecord {
                session_id,
                stream_id,
                application_handle,
                principal_id,
                connection_id,
                protocol_id,
                pending: false,
                send_closed: false,
                eof: false,
                reset_error: None,
                queued_bytes: 0,
                queued: VecDeque::new(),
            },
        );
        Ok(handle)
    }

    /// Match an inbound stream to an open listener and make it pending.
    pub fn route_incoming_stream(
        &mut self,
        session_id: u64,
        stream_id: u64,
        protocol_id: &[u8],
        data: Vec<u8>,
        eof: bool,
    ) -> Result<Vec<u8>, ApplicationDataError> {
        let listener = self
            .listeners
            .iter()
            .find(|listener| listener.protocol_id.as_slice() == protocol_id)
            .cloned()
            .ok_or(ApplicationDataError::NotFound)?;
        if !self.sessions.contains_key(&session_id) {
            let pending_for_listener = self
                .sessions
                .values()
                .filter(|session| {
                    session.pending && session.application_handle == listener.application_handle
                })
                .count();
            if pending_for_listener >= listener.max_pending_sessions {
                return Err(ApplicationDataError::QueueFull);
            }
            self.pending_sessions.push_back(session_id);
            self.sessions.insert(
                session_id,
                SessionRecord {
                    application_handle: listener.application_handle.clone(),
                    principal_id: listener.principal_id,
                    connection_id: listener.connection_id.clone(),
                    pending: true,
                },
            );
        }
        let session = self
            .sessions
            .get(&session_id)
            .expect("session inserted or already present");
        if session.application_handle != listener.application_handle {
            return Err(ApplicationDataError::PermissionDenied);
        }
        let key = (session_id, stream_id);
        let handle = if let Some(handle) = self.stream_by_session_id.get(&key) {
            handle.clone()
        } else {
            let handle = self.allocate_handle();
            self.stream_by_session_id.insert(key, handle.clone());
            self.streams.insert(
                handle.clone(),
                StreamRecord {
                    session_id,
                    stream_id,
                    application_handle: listener.application_handle,
                    principal_id: listener.principal_id,
                    connection_id: listener.connection_id,
                    protocol_id: protocol_id.to_vec(),
                    pending: true,
                    send_closed: false,
                    eof: false,
                    reset_error: None,
                    queued_bytes: 0,
                    queued: VecDeque::new(),
                },
            );
            self.pending_streams.push_back(handle.clone());
            handle
        };
        self.push_stream_data(&handle, data, eof)?;
        Ok(handle)
    }

    /// Route a contiguous session read into an existing control stream, or
    /// create a pending stream for a matching listener. `Ok(false)` means the
    /// protocol is not owned by an `ApplicationService` listener and lets the
    /// legacy in-process application channel handle it.
    pub fn route_stream_data(
        &mut self,
        session_id: u64,
        stream_id: u64,
        protocol_id: &[u8],
        data: Vec<u8>,
        eof: bool,
    ) -> Result<bool, ApplicationDataError> {
        if let Some(handle) = self
            .stream_by_session_id
            .get(&(session_id, stream_id))
            .cloned()
        {
            let existing_protocol = self
                .streams
                .get(&handle)
                .map(|stream| stream.protocol_id.as_slice())
                .ok_or(ApplicationDataError::NotFound)?;
            if existing_protocol != protocol_id {
                return Err(ApplicationDataError::PermissionDenied);
            }
            self.push_stream_data(&handle, data, eof)?;
            return Ok(true);
        }
        if self
            .listeners
            .iter()
            .any(|listener| listener.protocol_id.as_slice() == protocol_id)
        {
            self.route_incoming_stream(session_id, stream_id, protocol_id, data, eof)?;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    #[cfg(test)]
    pub fn pending_streams(&self) -> Vec<Vec<u8>> {
        self.pending_streams.iter().cloned().collect()
    }

    pub fn accept_session(
        &mut self,
        session_id: u64,
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(ApplicationDataError::NotFound)?;
        if session.principal_id != principal_id || session.connection_id.as_slice() != connection_id
        {
            return Err(ApplicationDataError::PermissionDenied);
        }
        if !session.pending {
            return Err(ApplicationDataError::AlreadyAccepted);
        }
        session.pending = false;
        self.pending_sessions.retain(|id| *id != session_id);
        Ok(())
    }

    pub fn reject_session(
        &mut self,
        session_id: u64,
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(ApplicationDataError::NotFound)?;
        if session.principal_id != principal_id || session.connection_id.as_slice() != connection_id
        {
            return Err(ApplicationDataError::PermissionDenied);
        }
        self.remove_session(session_id);
        Ok(())
    }

    pub fn accept_stream(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        let stream = self.authorized_stream_mut(handle, principal_id, connection_id)?;
        if !stream.pending {
            return Err(ApplicationDataError::AlreadyAccepted);
        }
        stream.pending = false;
        self.pending_streams
            .retain(|pending| pending.as_slice() != handle);
        Ok(())
    }

    pub fn reject_stream(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        self.authorized_stream(handle, principal_id, connection_id)?;
        let stream = self
            .streams
            .remove(handle)
            .ok_or(ApplicationDataError::NotFound)?;
        self.stream_by_session_id
            .remove(&(stream.session_id, stream.stream_id));
        self.pending_streams
            .retain(|pending| pending.as_slice() != handle);
        Ok(())
    }

    pub fn push_stream_data(
        &mut self,
        handle: &[u8],
        data: Vec<u8>,
        eof: bool,
    ) -> Result<(), ApplicationDataError> {
        let stream = self
            .streams
            .get_mut(handle)
            .ok_or(ApplicationDataError::NotFound)?;
        if stream.queued_bytes.saturating_add(data.len()) > MAX_APPLICATION_STREAM_BUFFER_BYTES {
            return Err(ApplicationDataError::QueueFull);
        }
        stream.queued_bytes = stream.queued_bytes.saturating_add(data.len());
        if eof {
            stream.eof = true;
        }
        if !data.is_empty() {
            stream.queued.push_back(data);
        }
        Ok(())
    }

    pub fn mark_stream_reset(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
        error_code: u64,
    ) -> Result<(), ApplicationDataError> {
        let stream = self.authorized_stream_mut(handle, principal_id, connection_id)?;
        stream.reset_error = Some(error_code);
        stream.queued.clear();
        stream.queued_bytes = 0;
        Ok(())
    }

    /// Mark a stream reset observed by the transport task. The task already
    /// owns the authenticated session, so it supplies the session/stream
    /// tuple rather than an API principal. The returned boolean is false when
    /// the stream is not represented by an `ApplicationService` handle.
    pub fn mark_stream_reset_for_session(
        &mut self,
        session_id: u64,
        stream_id: u64,
        error_code: u64,
    ) -> Result<bool, ApplicationDataError> {
        let Some(handle) = self
            .stream_by_session_id
            .get(&(session_id, stream_id))
            .cloned()
        else {
            return Ok(false);
        };
        let stream = self
            .streams
            .get_mut(&handle)
            .ok_or(ApplicationDataError::NotFound)?;
        stream.reset_error = Some(error_code);
        stream.queued.clear();
        stream.queued_bytes = 0;
        Ok(true)
    }

    pub fn read_stream(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Option<StreamRead>, ApplicationDataError> {
        let stream = self.authorized_stream_mut(handle, principal_id, connection_id)?;
        if stream.pending {
            return Err(ApplicationDataError::Pending);
        }
        if let Some(error_code) = stream.reset_error {
            return Ok(Some(StreamRead {
                data: Vec::new(),
                eof: false,
                reset: true,
                application_error_code: error_code,
            }));
        }
        if maximum_bytes == 0 {
            return Err(ApplicationDataError::InvalidArgument);
        }
        let Some(mut data) = stream.queued.pop_front() else {
            if stream.eof {
                return Ok(Some(StreamRead {
                    data: Vec::new(),
                    eof: true,
                    reset: false,
                    application_error_code: 0,
                }));
            }
            return if wait_for_data {
                Err(ApplicationDataError::WouldBlock)
            } else {
                Ok(None)
            };
        };
        stream.queued_bytes = stream.queued_bytes.saturating_sub(data.len());
        let eof = stream.eof && stream.queued.is_empty();
        if data.len() > maximum_bytes {
            let tail = data.split_off(maximum_bytes);
            stream.queued_bytes = stream.queued_bytes.saturating_add(tail.len());
            stream.queued.push_front(tail);
        }
        Ok(Some(StreamRead {
            data,
            eof,
            reset: false,
            application_error_code: 0,
        }))
    }

    pub fn close_stream_send(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<(), ApplicationDataError> {
        self.authorized_stream_mut(handle, principal_id, connection_id)?
            .send_closed = true;
        Ok(())
    }

    pub fn stream_metadata(&self, handle: &[u8]) -> Option<(u64, u64, Vec<u8>)> {
        self.streams.get(handle).map(|stream| {
            (
                stream.session_id,
                stream.stream_id,
                stream.protocol_id.clone(),
            )
        })
    }

    /// Return the bounded local view of application streams for one session.
    /// The order is stable by transport stream id, so callers can paginate or
    /// compare snapshots without exposing the internal hash-map order.
    pub fn stream_snapshots(&self, session_id: u64) -> Vec<StreamSnapshot> {
        let mut snapshots: Vec<StreamSnapshot> = self
            .streams
            .iter()
            .filter(|(_, stream)| stream.session_id == session_id)
            .map(|(handle, stream)| StreamSnapshot {
                handle: handle.clone(),
                session_id,
                stream_id: stream.stream_id,
                principal_id: stream.principal_id,
                pending: stream.pending,
                send_closed: stream.send_closed,
                eof: stream.eof,
                reset_error: stream.reset_error,
                queued_bytes: stream.queued_bytes,
            })
            .collect();
        snapshots.sort_by_key(|snapshot| snapshot.stream_id);
        snapshots
    }

    pub fn stream_owner(&self, handle: &[u8]) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        self.streams.get(handle).map(|stream| {
            (
                stream.principal_id,
                stream.connection_id.clone(),
                stream.application_handle.clone(),
            )
        })
    }

    pub fn session_owner(&self, session_id: u64) -> Option<(u64, Vec<u8>, Vec<u8>, bool)> {
        self.sessions.get(&session_id).map(|session| {
            (
                session.principal_id,
                session.connection_id.clone(),
                session.application_handle.clone(),
                session.pending,
            )
        })
    }

    pub fn push_datagram(
        &mut self,
        session_id: u64,
        context_id: u64,
        data: Vec<u8>,
        expired: bool,
    ) -> Result<(), ApplicationDataError> {
        let queue = self.datagrams.entry(session_id).or_default();
        if queue.entries.len() >= MAX_APPLICATION_DATAGRAM_QUEUE
            || queue.bytes.saturating_add(data.len()) > MAX_APPLICATION_DATAGRAM_BYTES
        {
            return Err(ApplicationDataError::QueueFull);
        }
        queue.bytes = queue.bytes.saturating_add(data.len());
        queue.entries.push_back(DatagramRecord {
            context_id,
            data,
            expired,
        });
        Ok(())
    }

    pub fn allocate_datagram_id(&mut self) -> u64 {
        let id = self.next_datagram_id;
        self.next_datagram_id = self.next_datagram_id.saturating_add(1);
        id
    }

    pub fn receive_datagram(
        &mut self,
        session_id: u64,
        connection_id: &[u8],
        maximum_bytes: usize,
        wait_for_data: bool,
    ) -> Result<Option<DatagramRead>, ApplicationDataError> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(ApplicationDataError::NotFound)?;
        if session.connection_id.as_slice() != connection_id {
            return Err(ApplicationDataError::PermissionDenied);
        }
        if maximum_bytes == 0 {
            return Err(ApplicationDataError::InvalidArgument);
        }
        let queue = self.datagrams.entry(session_id).or_default();
        let Some(datagram) = queue.entries.front() else {
            return if wait_for_data {
                Err(ApplicationDataError::WouldBlock)
            } else {
                Ok(None)
            };
        };
        if datagram.data.len() > maximum_bytes {
            return Err(ApplicationDataError::InvalidArgument);
        }
        let datagram = queue.entries.pop_front().expect("front entry exists");
        queue.bytes = queue.bytes.saturating_sub(datagram.data.len());
        Ok(Some(DatagramRead {
            context_id: datagram.context_id,
            data: datagram.data,
            expired: datagram.expired,
        }))
    }

    fn authorized_stream(
        &self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<&StreamRecord, ApplicationDataError> {
        let stream = self
            .streams
            .get(handle)
            .ok_or(ApplicationDataError::NotFound)?;
        if stream.principal_id != principal_id || stream.connection_id.as_slice() != connection_id {
            return Err(ApplicationDataError::PermissionDenied);
        }
        Ok(stream)
    }

    fn authorized_stream_mut(
        &mut self,
        handle: &[u8],
        principal_id: u64,
        connection_id: &[u8],
    ) -> Result<&mut StreamRecord, ApplicationDataError> {
        let stream = self
            .streams
            .get_mut(handle)
            .ok_or(ApplicationDataError::NotFound)?;
        if stream.principal_id != principal_id || stream.connection_id.as_slice() != connection_id {
            return Err(ApplicationDataError::PermissionDenied);
        }
        Ok(stream)
    }

    fn allocate_handle(&mut self) -> Vec<u8> {
        let id = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        let mut handle = Vec::with_capacity(16);
        handle.extend_from_slice(&id.to_be_bytes());
        handle.extend_from_slice(&self.next_handle.to_be_bytes());
        handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_handles_are_owner_scoped_and_bounded() {
        let mut data = ApplicationDataPlane::new();
        let app = b"app".to_vec();
        let handle = data
            .open_stream(
                7,
                b"connection".to_vec(),
                app.clone(),
                11,
                3,
                b"proto/1".to_vec(),
            )
            .expect("stream");

        assert!(data
            .read_stream(&handle, 7, b"connection", 64, false)
            .expect("owner read")
            .is_none());
        assert!(matches!(
            data.read_stream(&handle, 8, b"connection", 64, false),
            Err(ApplicationDataError::PermissionDenied)
        ));
        assert_eq!(
            data.push_stream_data(&handle, vec![1, 2, 3, 4], false),
            Ok(())
        );
        let read = data
            .read_stream(&handle, 7, b"connection", 2, false)
            .expect("read")
            .expect("data");
        assert_eq!(read.data, vec![1, 2]);
        assert!(!read.eof);
    }

    #[test]
    fn incoming_stream_becomes_pending_and_accept_is_explicit() {
        let mut data = ApplicationDataPlane::new();
        data.register_listener(b"proto/1".to_vec(), b"app".to_vec(), 7, b"conn".to_vec());
        let pending = data
            .route_incoming_stream(9, 3, b"proto/1", vec![9], false)
            .expect("pending stream");
        assert_eq!(data.pending_streams().len(), 1);
        assert!(matches!(
            data.read_stream(&pending, 7, b"conn", 64, false),
            Err(ApplicationDataError::Pending)
        ));
        data.accept_stream(&pending, 7, b"conn").expect("accept");
        let read = data
            .read_stream(&pending, 7, b"conn", 64, false)
            .expect("read")
            .expect("payload");
        assert_eq!(read.data, vec![9]);
    }

    #[test]
    fn datagram_queue_is_bounded_and_owner_scoped() {
        let mut data = ApplicationDataPlane::new();
        data.bind_session(7, b"conn".to_vec(), b"app".to_vec());
        data.push_datagram(7, 4, vec![1, 2], false).expect("queue");
        assert!(matches!(
            data.receive_datagram(7, b"conn", 8, false),
            Ok(Some(datagram)) if datagram.data == vec![1, 2]
        ));
        assert!(matches!(
            data.receive_datagram(7, b"other", 8, false),
            Err(ApplicationDataError::PermissionDenied)
        ));
    }

    #[test]
    fn pending_session_limit_rejects_new_sessions_without_losing_existing_state() {
        let mut data = ApplicationDataPlane::new();
        data.register_listener_with_limit(
            b"proto/1".to_vec(),
            b"app".to_vec(),
            7,
            b"conn".to_vec(),
            1,
        );
        data.route_incoming_stream(1, 0, b"proto/1", b"one".to_vec(), false)
            .expect("first pending session");
        assert!(matches!(
            data.route_incoming_stream(2, 0, b"proto/1", b"two".to_vec(), false),
            Err(ApplicationDataError::QueueFull)
        ));
        assert!(data.session_owner(1).is_some());
        assert!(data.session_owner(2).is_none());
    }

    #[test]
    fn oversized_datagram_read_keeps_queue_entry_for_retry() {
        let mut data = ApplicationDataPlane::new();
        data.bind_session(7, b"conn".to_vec(), b"app".to_vec());
        data.push_datagram(7, 4, vec![1, 2, 3], false)
            .expect("queue");
        assert_eq!(
            data.receive_datagram(7, b"conn", 2, false),
            Err(ApplicationDataError::InvalidArgument)
        );
        assert_eq!(
            data.receive_datagram(7, b"conn", 3, false)
                .expect("retry")
                .expect("datagram")
                .data,
            vec![1, 2, 3]
        );
    }

    #[test]
    fn resumable_application_rebinds_all_owned_records() {
        let mut data = ApplicationDataPlane::new();
        data.register_listener(
            b"proto/1".to_vec(),
            b"app".to_vec(),
            7,
            b"old-connection".to_vec(),
        );
        let stream = data
            .open_stream(
                7,
                b"old-connection".to_vec(),
                b"app".to_vec(),
                11,
                3,
                b"proto/1".to_vec(),
            )
            .expect("stream");
        data.rebind_application(b"app", 7, b"new-connection")
            .expect("rebind");
        data.push_stream_data(&stream, b"ok".to_vec(), false)
            .expect("data");
        assert!(data
            .read_stream(&stream, 7, b"new-connection", 8, false)
            .expect("read")
            .is_some());
        assert!(matches!(
            data.read_stream(&stream, 7, b"old-connection", 8, false),
            Err(ApplicationDataError::PermissionDenied)
        ));
    }
}
