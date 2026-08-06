//! Stream dispatch (core.md §9.6): map a stream's protocol ID to the
//! application that owns it, falling back to the daemon's well-known
//! services.
use crate::app::AppRegistry;
use crate::well_known::is_well_known;

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
}

/// Pure dispatch logic: the daemon consults this for every inbound STREAM
/// frame before touching an application channel.
#[derive(Debug, Default)]
pub struct StreamDispatcher;

impl StreamDispatcher {
    /// Classify a stream by its protocol ID.
    ///
    /// `stream_id` is reserved for per-session dispatch state in later
    /// phases; the classification itself only needs the protocol ID.
    ///
    /// # Errors
    ///
    /// Returns [`DispatchError::NoApplication`] when the protocol ID is
    /// neither well-known nor registered.
    #[allow(clippy::unused_self)] // stateless classifier; state arrives with sessions
    pub fn dispatch(
        &self,
        registry: &AppRegistry,
        stream_id: u64,
        protocol_id: &[u8],
    ) -> Result<DispatchTarget, DispatchError> {
        let _ = stream_id;
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
        let dispatcher = StreamDispatcher;
        let registry = AppRegistry::new();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, crate::well_known::WELL_KNOWN_APP),
            Ok(DispatchTarget::WellKnown(crate::well_known::WELL_KNOWN_APP.to_vec()))
        );
        assert_eq!(
            dispatcher.dispatch(&registry, 1, crate::well_known::WELL_KNOWN_RELAY),
            Ok(DispatchTarget::WellKnown(crate::well_known::WELL_KNOWN_RELAY.to_vec()))
        );
    }

    #[test]
    fn registered_ids_dispatch_to_the_application() {
        let dispatcher = StreamDispatcher;
        let registry = registry_with_echo();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b"org.example.echo/1"),
            Ok(DispatchTarget::Application("echo".to_string()))
        );
    }

    #[test]
    fn unknown_ids_are_rejected() {
        let dispatcher = StreamDispatcher;
        let registry = registry_with_echo();
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b"org.example.unknown/1"),
            Err(DispatchError::NoApplication)
        );
        assert_eq!(
            dispatcher.dispatch(&registry, 0, b""),
            Err(DispatchError::NoApplication)
        );
    }
}
