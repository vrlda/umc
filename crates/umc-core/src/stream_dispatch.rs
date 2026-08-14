//! Stream dispatch (core.md §9.6): map a stream's protocol ID to the
//! application that owns it, falling back to the daemon's well-known
//! services.
use crate::app::AppRegistry;
use crate::well_known::is_well_known;
use std::collections::HashMap;

/// Where a stream's data must be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchTarget {
    /// The stream belongs to a well-known daemon service.
    WellKnown(Vec<u8>),
    /// The stream belongs to a registered application.
    Application(String),
}

/// Dispatch failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchError {
    /// No well-known service or registered application owns the protocol ID.
    NoApplication,
    /// The first frame did not carry a protocol identifier.
    MissingProtocol,
    /// A stream attempted to change its protocol after opening.
    ProtocolMismatch,
}

/// Pure dispatch logic: the daemon consults this for every inbound STREAM
/// frame before touching an application channel.
#[derive(Debug, Default)]
pub struct StreamDispatcher {
    streams: HashMap<(u64, u64), StreamBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamBinding {
    protocol_id: Vec<u8>,
    target: DispatchTarget,
}

impl StreamDispatcher {
    /// Classify and bind one stream opening. The compatibility `dispatch`
    /// entry point uses session zero; callers handling multiple sessions
    /// should use [`Self::dispatch_for_session`].
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::NoApplication`] when the protocol ID is
    /// neither well-known nor registered.
    pub fn dispatch(
        &mut self,
        registry: &AppRegistry,
        stream_id: u64,
        protocol_id: &[u8],
    ) -> Result<DispatchTarget, DispatchError> {
        self.dispatch_for_session(registry, 0, stream_id, protocol_id, true)
    }

    /// Classify the first frame and remember its owner for the lifetime of a
    /// `(session_id, stream_id)` pair. Later frames MUST pass an empty protocol
    /// identifier and resolve to the original owner; a non-empty conflicting
    /// identifier is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError`] when the opening is missing a protocol, the
    /// protocol is unknown, or a later frame changes the stream binding.
    pub fn dispatch_for_session(
        &mut self,
        registry: &AppRegistry,
        session_id: u64,
        stream_id: u64,
        protocol_id: &[u8],
        opening: bool,
    ) -> Result<DispatchTarget, DispatchError> {
        let key = (session_id, stream_id);
        if opening {
            if protocol_id.is_empty() {
                return Err(DispatchError::MissingProtocol);
            }
            let target = Self::classify(registry, stream_id, protocol_id)?;
            if let Some(existing) = self.streams.get(&key) {
                if existing.protocol_id != protocol_id || existing.target != target {
                    return Err(DispatchError::ProtocolMismatch);
                }
            } else {
                self.streams.insert(
                    key,
                    StreamBinding {
                        protocol_id: protocol_id.to_vec(),
                        target: target.clone(),
                    },
                );
            }
            return Ok(target);
        }
        if !protocol_id.is_empty() {
            let Some(binding) = self.streams.get(&key) else {
                return Err(DispatchError::NoApplication);
            };
            if binding.protocol_id != protocol_id {
                return Err(DispatchError::ProtocolMismatch);
            }
        }
        self.streams
            .get(&key)
            .map(|binding| binding.target.clone())
            .ok_or(DispatchError::NoApplication)
    }

    /// Remove dispatch state after a stream is closed or reset.
    pub fn forget_stream(&mut self, session_id: u64, stream_id: u64) {
        self.streams.remove(&(session_id, stream_id));
    }

    /// Returns whether a stream already has a protocol binding.
    #[must_use]
    pub fn contains(&self, session_id: u64, stream_id: u64) -> bool {
        self.streams.contains_key(&(session_id, stream_id))
    }

    /// Remove all bindings owned by one session during session teardown.
    pub fn forget_session(&mut self, session_id: u64) {
        self.streams
            .retain(|(bound_session, _), _| *bound_session != session_id);
    }

    fn classify(
        registry: &AppRegistry,
        _stream_id: u64,
        protocol_id: &[u8],
    ) -> Result<DispatchTarget, DispatchError> {
        if is_well_known(protocol_id) {
            return Ok(DispatchTarget::WellKnown(protocol_id.to_vec()));
        }
        if let Some(handle) = registry.lookup(protocol_id) {
            return Ok(DispatchTarget::Application(handle.service_name.clone()));
        }
        Err(DispatchError::NoApplication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_with_echo() -> AppRegistry {
        let mut registry = AppRegistry::new();
        registry
            .register(b"org.example.echo/1".to_vec(), "echo".to_string())
            .expect("register");
        registry
    }

    #[test]
    fn well_known_ids_dispatch_to_well_known() {
        let mut dispatcher = StreamDispatcher::default();
        let registry = AppRegistry::new();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, crate::well_known::WELL_KNOWN_APP),
            Ok(DispatchTarget::WellKnown(
                crate::well_known::WELL_KNOWN_APP.to_vec()
            ))
        );
        assert_eq!(
            dispatcher.dispatch(&registry, 1, crate::well_known::WELL_KNOWN_RELAY),
            Ok(DispatchTarget::WellKnown(
                crate::well_known::WELL_KNOWN_RELAY.to_vec()
            ))
        );
    }

    #[test]
    fn registered_ids_dispatch_to_the_application() {
        let mut dispatcher = StreamDispatcher::default();
        let registry = registry_with_echo();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b"org.example.echo/1"),
            Ok(DispatchTarget::Application("echo".to_string()))
        );
    }

    #[test]
    fn unknown_ids_are_rejected() {
        let mut dispatcher = StreamDispatcher::default();
        let registry = registry_with_echo();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b"org.example.unknown/1"),
            Err(DispatchError::NoApplication)
        );
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b""),
            Err(DispatchError::MissingProtocol)
        );
    }

    #[test]
    fn stream_binding_uses_session_and_stream_id() {
        let mut dispatcher = StreamDispatcher::default();
        let registry = registry_with_echo();
        let first = dispatcher
            .dispatch_for_session(&registry, 1, 7, b"org.example.echo/1", true)
            .expect("opening dispatch");
        assert_eq!(
            dispatcher.dispatch_for_session(&registry, 1, 7, &[], false),
            Ok(first.clone())
        );
        assert_eq!(
            dispatcher.dispatch_for_session(&registry, 2, 7, &[], false),
            Err(DispatchError::NoApplication)
        );
        dispatcher.forget_stream(1, 7);
        assert_eq!(
            dispatcher.dispatch_for_session(&registry, 1, 7, &[], false),
            Err(DispatchError::NoApplication)
        );
    }

    #[test]
    fn stream_binding_rejects_missing_and_changed_openings() {
        let mut dispatcher = StreamDispatcher::default();
        let registry = registry_with_echo();
        assert_eq!(
            dispatcher.dispatch_for_session(&registry, 1, 1, &[], true),
            Err(DispatchError::MissingProtocol)
        );
        dispatcher
            .dispatch_for_session(&registry, 1, 1, b"org.example.echo/1", true)
            .expect("opening dispatch");
        assert_eq!(
            dispatcher.dispatch_for_session(&registry, 1, 1, b"org.unknown/1", false),
            Err(DispatchError::ProtocolMismatch)
        );
    }
}
