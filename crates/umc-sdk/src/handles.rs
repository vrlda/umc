//! Opaque SDK handles with generation validation (sdk.md §11).
#![allow(clippy::missing_errors_doc)]
use crate::client::ClientError;

/// Resource kind carried by a local SDK handle. Separate Rust wrapper types
/// prevent accidental cross-resource use at compile time; this tag protects
/// dynamically decoded handles as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleKind {
    Endpoint,
    Application,
    Listener,
    Session,
    Stream,
    Subscription,
    Operation,
}

pub(crate) trait GenerationBound {
    fn validate_backend_generation(&self, expected: u64) -> Result<(), ClientError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpaqueValue {
    bytes: Vec<u8>,
    generation: u64,
}

impl OpaqueValue {
    fn new(bytes: impl Into<Vec<u8>>, generation: u64) -> Self {
        Self {
            bytes: bytes.into(),
            generation,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn validate_generation(&self, expected: u64) -> Result<(), ClientError> {
        if self.generation == expected {
            Ok(())
        } else {
            Err(ClientError::HandleGenerationMismatch {
                expected,
                actual: self.generation,
            })
        }
    }
}

macro_rules! opaque_handle {
    ($name:ident, $kind:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(OpaqueValue);

        impl $name {
            /// Creates a handle from backend bytes. The generation is owned
            /// by the SDK connection and is never inferred from the bytes.
            #[must_use]
            pub fn with_generation(bytes: impl Into<Vec<u8>>, generation: u64) -> Self {
                Self(OpaqueValue::new(bytes, generation))
            }

            /// Creates a handle for a fresh connection generation.
            #[must_use]
            pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
                Self::with_generation(bytes, 0)
            }

            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            #[must_use]
            pub fn generation(&self) -> u64 {
                self.0.generation
            }

            #[must_use]
            pub const fn kind(&self) -> HandleKind {
                $kind
            }

            /// Rejects a handle from another daemon instance or generation.
            pub fn validate_generation(&self, expected: u64) -> Result<(), ClientError> {
                self.0.validate_generation(expected)
            }

            pub(crate) fn from_proto_with_generation(
                value: &umc_control::proto::umc::api::v1::OpaqueHandle,
                generation: u64,
            ) -> Self {
                Self::with_generation(value.value.clone(), generation)
            }

            #[allow(dead_code)]
            pub(crate) fn to_proto(&self) -> umc_control::proto::umc::api::v1::OpaqueHandle {
                umc_control::proto::umc::api::v1::OpaqueHandle {
                    value: self.as_bytes().to_vec(),
                }
            }
        }

        impl GenerationBound for $name {
            fn validate_backend_generation(&self, expected: u64) -> Result<(), ClientError> {
                self.validate_generation(expected)
            }
        }
    };
}

opaque_handle!(EndpointHandle, HandleKind::Endpoint);
opaque_handle!(AppHandle, HandleKind::Application);
opaque_handle!(ListenerHandle, HandleKind::Listener);
opaque_handle!(SessionHandle, HandleKind::Session);
opaque_handle!(StreamHandle, HandleKind::Stream);
opaque_handle!(SubscriptionHandle, HandleKind::Subscription);

#[cfg(test)]
mod tests {
    use super::*;
    use umc_control::proto::umc::api::v1::OpaqueHandle;

    #[test]
    fn proto_handles_preserve_backend_generation() {
        let handle = OpaqueHandle {
            value: b"session".to_vec(),
        };
        let decoded = SessionHandle::from_proto_with_generation(&handle, 42);
        assert_eq!(decoded.as_bytes(), b"session");
        assert_eq!(decoded.generation(), 42);
        assert!(decoded.validate_generation(42).is_ok());
        assert!(matches!(
            decoded.validate_generation(7),
            Err(ClientError::HandleGenerationMismatch {
                expected: 7,
                actual: 42
            })
        ));
    }
}
