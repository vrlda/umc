//! Deterministic end-to-end XX handshake.
use umc_crypto::signatures::{IdentityKeyPair, StaticHandshakeKeyPair};
use umc_handshake::xx::run_xx_handshake;
use umc_types::runtime::EntropySource;

struct TestEntropy;

#[allow(clippy::cast_possible_truncation)]
impl EntropySource for TestEntropy {
    fn fill(&self, out: &mut [u8]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }
    }
}

#[test]
fn xx_handshake_derives_matching_session_secrets() {
    let client_identity = IdentityKeyPair::generate();
    let client_static = StaticHandshakeKeyPair::generate();
    let server_identity = IdentityKeyPair::generate();
    let server_static = StaticHandshakeKeyPair::generate();
    let (client_secrets, server_secrets) = run_xx_handshake(
        &client_identity,
        &client_static,
        &server_identity,
        &server_static,
        &TestEntropy,
        b"ump.udp/1",
        1_700_000_000_000,
    )
    .expect("handshake succeeds");
    assert_eq!(client_secrets.client, server_secrets.client);
    assert_eq!(client_secrets.server, server_secrets.server);
    assert_eq!(
        client_secrets.path_validation,
        server_secrets.path_validation
    );
    assert_eq!(
        client_secrets.stateless_reset,
        server_secrets.stateless_reset
    );
    assert_ne!(client_secrets.client, client_secrets.server);
}

#[test]
fn xx_handshake_binds_carrier() {
    let (a, _) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.tcp/1",
        0,
    )
    .expect("handshake succeeds");
    let (b, _) = run_xx_handshake(
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &IdentityKeyPair::generate(),
        &StaticHandshakeKeyPair::generate(),
        &TestEntropy,
        b"ump.udp/1",
        0,
    )
    .expect("handshake succeeds");
    assert_ne!(
        a.client, b.client,
        "carrier binding must change the transcript"
    );
}
