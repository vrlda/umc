//! Carrier Plugin Protocol handshake (carrier-plugin-api.md §8-10).
#![allow(clippy::missing_errors_doc)]
use crate::proto::umc::plugin::v1 as p;

pub const API_VERSION_MAJOR: i32 = 1;
pub const API_VERSION_MINOR: i32 = 0;
pub const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    BadLaunchToken,
    VersionMismatch,
    MissingHelloVersion,
    MissingCapability,
    Protocol(String),
}

/// Verify a plugin hello and select the strongest version supported by both
/// sides. Capability grants are intersected with the daemon policy.
pub fn accept_plugin_hello(
    hello: &p::PluginHello,
    expected_launch_token: &[u8],
    granted_capabilities: &[String],
) -> Result<p::DaemonHello, HandshakeError> {
    if hello.launch_token_proof != expected_launch_token {
        return Err(HandshakeError::BadLaunchToken);
    }
    let offered = hello
        .supported_versions
        .iter()
        .filter(|version| version.major == API_VERSION_MAJOR)
        .max_by_key(|version| version.minor)
        .ok_or(HandshakeError::VersionMismatch)?;
    if hello.api_version.is_none() {
        return Err(HandshakeError::MissingHelloVersion);
    }
    if hello.capabilities.is_empty() {
        return Err(HandshakeError::MissingCapability);
    }
    let granted_capabilities = granted_capabilities
        .iter()
        .filter(|capability| {
            hello
                .capabilities
                .iter()
                .any(|offered| offered == *capability)
        })
        .cloned()
        .collect();
    Ok(p::DaemonHello {
        selected_version: Some(p::ApiVersion {
            major: offered.major,
            minor: offered.minor.min(API_VERSION_MINOR),
        }),
        daemon_identity: "umcd".into(),
        granted_capabilities,
        max_message_size: MAX_MESSAGE_SIZE,
    })
}

/// Verify the daemon's selected version and message limit.
pub fn verify_daemon_hello(hello: &p::DaemonHello) -> Result<(), HandshakeError> {
    let Some(version) = &hello.selected_version else {
        return Err(HandshakeError::Protocol("missing selected version".into()));
    };
    if version.major != API_VERSION_MAJOR || version.minor > API_VERSION_MINOR {
        return Err(HandshakeError::VersionMismatch);
    }
    if hello.max_message_size == 0 || hello.max_message_size > MAX_MESSAGE_SIZE {
        return Err(HandshakeError::Protocol("invalid message limit".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(token: &[u8]) -> p::PluginHello {
        p::PluginHello {
            api_version: Some(p::ApiVersion { major: 1, minor: 0 }),
            plugin_name: "loopback".into(),
            supported_versions: vec![
                p::ApiVersion { major: 1, minor: 0 },
                p::ApiVersion { major: 2, minor: 0 },
            ],
            capabilities: vec!["datagram".into(), "listen".into()],
            launch_token_proof: token.to_vec(),
        }
    }

    #[test]
    fn valid_hello_selects_intersection() {
        let reply = accept_plugin_hello(&hello(b"token"), b"token", &["datagram".into()])
            .expect("valid hello");
        assert_eq!(reply.selected_version.expect("version").major, 1);
        assert_eq!(reply.granted_capabilities, vec!["datagram"]);
    }

    #[test]
    fn wrong_token_rejected() {
        assert_eq!(
            accept_plugin_hello(&hello(b"wrong"), b"token", &["datagram".into()]),
            Err(HandshakeError::BadLaunchToken)
        );
    }

    #[test]
    fn no_common_version_rejected() {
        let mut value = hello(b"token");
        value.supported_versions = vec![p::ApiVersion { major: 2, minor: 0 }];
        assert_eq!(
            accept_plugin_hello(&value, b"token", &["datagram".into()]),
            Err(HandshakeError::VersionMismatch)
        );
    }

    #[test]
    fn daemon_rejects_oversized_limit() {
        assert_eq!(
            verify_daemon_hello(&p::DaemonHello {
                selected_version: Some(p::ApiVersion { major: 1, minor: 0 }),
                max_message_size: MAX_MESSAGE_SIZE + 1,
                ..Default::default()
            }),
            Err(HandshakeError::Protocol("invalid message limit".into()))
        );
    }
}
